#!/usr/bin/python3

#################################################################################
#
# Licence: GPL v2
# 2021 - Raider700
#
# This script is used to parse and combine the 389-ds logs.
# As data store a local redis db on the default port is used.
#
# Output can be:
#   * stdout
#   * local file
#   * syslog server
#
# Additional the last success binds can be also recorded to file
#
# To see all params: <scipt> -h
#
#################################################################################

# import needed libs
import sys
import getopt
import shlex
import time
import datetime
import signal
import socket
import redis  # python-redis redis

#################################################################################

# servername for logging
__servername = "localhost"
__stage = "p"

# needed logging targets for syslog
__syslogsocket = None
__sysloghost = "127.0.0.1"
__syslogport = 514

# FACILITY
# 'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
# 'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
# 'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
# 'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
# 'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
# LEVEL
# 'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
# 'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
__syslogvalue = 165  # (local4=20) * 8 + (notice=5) = 165

# input logfile
__inlogfile = False

# output logfile (disabled on default)
__outlogfile = False
__outlastbindfile = False

# output on stdout
__stdout = True

# redis objects
__redishost = "localhost"
__redisport = 6379
__redislogs = None
__redislastbind = None

#################################################################################

# class to close script on "strg+c"
class GracefulKiller:
    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True


# define the redis server params
def redis_open_connection(stage, usage):
    db = 7
    if stage == "p" and usage == "lastbind":
        db = 1
    if stage == "v" and usage == "lastbind":
        db = 2
    if stage == "d" and usage == "lastbind":
        db = 3
    if stage == "p" and usage == "logs":
        db = 4
    if stage == "v" and usage == "logs":
        db = 5
    if stage == "d" and usage == "logs":
        db = 6
    global __redishost
    global __redisport
    redisdb = db
    return redis.Redis(host=__redishost, port=__redisport, db=redisdb)


# function to get current time in ldap format
def get_current_time_ldap():
    return time.strftime("[%d/%b/%Y:%H:%M:%S.000000000 %z]", time.gmtime())


# function the get current time in syslog format
def get_current_time_syslog():
    # get the current local time
    timenow = time.localtime()

    # get the time offset to send correct syslog time
    daylightsaving = time.daylight and timenow.tm_isdst > 0
    tzoffset = time.altzone if daylightsaving else time.timezone

    # convert the current time and return it
    date = datetime.datetime.fromtimestamp(time.mktime(timenow))
    return date.strftime("%Y-%m-%dT%H:%M:%S") + "%+03d:00" % (tzoffset / 60 / 60 * - 1)


# translate error code to name
def get_error_code_by_name(reserr):
    errortranslate = {
        "err=0": "errname=success",
        "err=1": "errname=operation_error",
        "err=2": "errname=protocol_error",
        "err=3": "errname=time_limit_exceeded",
        "err=4": "errname=size_limit_exceeded",
        "err=5": "errname=compare_false",
        "err=6": "errname=compare_true",
        "err=7": "errname=auth_method_not_supported",
        "err=8": "errname=strong_auth_required",
        "err=9": "errname=ldap_partial_results",
        "err=10": "errname=referral",
        "err=11": "errname=admin_limit_exceeded",
        "err=12": "errname=unavailable_critical_extension",
        "err=13": "errname=confidentiality_required",
        "err=14": "errname=sasl_bind_in_progress",
        "err=16": "errname=no_such_attribute",
        "err=17": "errname=undefined_attribute_type",
        "err=18": "errname=inappropriate_matching",
        "err=19": "errname=constraint_violation",
        "err=20": "errname=attribute_or_value_exists",
        "err=21": "errname=invalid_attribute_syntax",
        "err=32": "errname=no_such_object",
        "err=33": "errname=alias_problem",
        "err=34": "errname=invalid_dn_syntax",
        "err=35": "errname=is_leaf",
        "err=36": "errname=alias_dereferencing_problem",
        "err=48": "errname=inappropriate_authentication",
        "err=49": "errname=invalid_credentials",
        "err=50": "errname=insufficient_access_rights",
        "err=51": "errname=busy",
        "err=52": "errname=unavailable",
        "err=53": "errname=unwilling_to_perform",
        "err=54": "errname=loop_defect",
        "err=64": "errname=naming_violation",
        "err=65": "errname=object_class_violation",
        "err=66": "errname=not_allowed_on_nonleaf",
        "err=67": "errname=not_allowed_on_rdn",
        "err=68": "errname=entry_already_exists",
        "err=69": "errname=object_class_mods_prohibited",
        "err=71": "errname=affects_multiple_dsas",
        "err=80": "errname=other",
        "err=81": "errname=server_down",
        "err=85": "errname=ldap_timeout",
        "err=89": "errname=param_error",
        "err=91": "errname=connect_error",
        "err=92": "errname=ldap_not_supported",
        "err=93": "errname=control_not_found",
        "err=94": "errname=no_results_returned",
        "err=95": "errname=more_results_to_return",
        "err=96": "errname=client_loop",
        "err=97": "errname=referral_limit_exceeded"
    }
    return errortranslate[reserr]


# store the last successful bind into the redis
def record_last_success_bind(servername, user, time):
    # try to parse tle line
    try:
        # get the global redis connection
        global __redislastbind
        try:
            __redislastbind.ping()
        except:
            global __stage
            __redislastbind = redis_open_connection(__stage, "lastbind")

        # insert new connection to redis db
        __redislastbind.set(user, time)
        __redislastbind.expire(user, 93600)  # expire in 26h

        # create line to record
        logline = "%s INFO: %s - RECORD - Success Bind from \"%s\" at \"%s\" on server \"%s\"" % \
                  (get_current_time_syslog(), servername[0], user, time, servername)

        # append info to the lastbind logfile
        try:

            # append to lastbind file
            global __outlastbindfile
            if __outlastbindfile:
                outlastbindfile = open(__outlastbindfile, "a+")
                outlastbindfile.write("%s %s\n" % (get_current_time_syslog(), logline))
                outlastbindfile.flush()
                outlastbindfile.close()
        except Exception as e:
            print("ERROR writing local lastbind line! (%s)" % logline)
            print(e)

    except Exception as e:
        print("ERROR on record_last_success_bind function! (%s %s %s)" % (servername, user, time))
        print(e)


# send the logline to syslog
def send_syslog_message(string, servername):
    # check if the line should be send
    global __sysloghost
    if not __sysloghost:
        return

    # generate the send line
    global __syslogvalue
    line = "<%s>1 %s gdcc01 rhds-log-combi - - -  %s\n" % (str(__syslogvalue), get_current_time_syslog(), string)

    # define the send socket for syslog lines
    global __syslogsocket
    try:
        try:
            # send the logline
            __syslogsocket.send(line.encode())
        except:
            # open socket on error and try to send againv
            global __syslogport
            __syslogsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            __syslogsocket.connect((__sysloghost, __syslogport))
            __syslogsocket.send(line.encode())
    except Exception as e:
        print("ERROR sending syslog message! (%s - %s)" % (servername, line))
        print(e)


# write the logline to a local file
def write_local_logfile(string, logfile):
    try:
        # direct write to logfile to avoid journald
        global __outlogfile
        if __outlogfile:
            logfile.write("%s %s\n" % (get_current_time_syslog(), string))

    except Exception as e:
        print("ERROR writing local syslog line to file! (%s - %s)" % (logfile, string))
        print(e)


# log a connection
def log_line(servername, line, logfile):
    try:
        # build the string with all possible options
        string = ("%s %s" % (servername, line))

        # write log to syslog and local file
        send_syslog_message(string, servername)
        write_local_logfile(string, logfile)

        # write to stdout if defined
        global __stdout
        if __stdout:
            print(string)

    except Exception as e:
        print("ERROR on log_line function!")
        print(e)


# log a error
def log_error(source, servername, line, error, logfile):
    try:
        # show the original line as error string
        string = str("%s %s conn=-1 %s %s" % (servername, get_current_time_ldap(), error, line.rstrip()))

        # write log to syslog and local file
        send_syslog_message(string, servername)
        write_local_logfile(string, logfile)

        # on error always write to stdout
        print("%s: %s" % (source, string))

    except Exception as e:
        print("ERROR on log_error function!")
        print(e)


# create entry for new connection in the redis
def new_connection(servername, con, conhash, line, redislogs, logfile):
    # time for later los usage
    linetime = "%s]" % line.split('] ')[0]

    # prepare line to be added to redis
    line = line.replace(('%s ' % con), '')
    line = line.replace('SSL connection', 'tls=true starttls=false port=636')
    line = line.replace('connection', 'tls=false starttls=false port=389')
    line = line.replace('from ', 'from=')
    line = line.replace('to ', 'to=')
    line = line.split('] ')[-1]
    line = "CONNECTION connectioninfo=true %s autobind=false binddn=none" % line

    # insert information into redis
    try:
        redislogs.hset(str(conhash), "connection", line)
    except Exception as a:
        log_error("new_connection", servername, line, ("ERROR(%s)" % str(a)), logfile)

    # generate the logline
    logline = str("%s %s op=-1 OPEN type=open RESULT err=0 errname=success %s" % (linetime, con, line))

    # send the logline
    log_line(servername, logline, logfile)


# update connection information for starttls
def update_connection_tls(servername, con, conhash, line, redislogs, logfile):
    # prepare the tls info
    tlsinfo = line.replace(('%s ' % con), '')
    tlsinfo = tlsinfo.split('] ')[-1]
    tlsinfo = tlsinfo.replace(' ', ',')
    tlsinfo = "starttls=\"%s\"" % tlsinfo

    # append info to redis entry
    try:
        try:
            # get the connection information from redis
            entry = redislogs.hget(str(conhash), "connection")
            entry = entry.decode()
            entry = entry.replace('tls=false', 'tls=true')
            entry = entry.replace('starttls=false', ('starttls=%s' % tlsinfo))
            # replace updated entry in the redis
            redislogs.hset(str(conhash), "connection", entry)
        except:
            # add new entry to redis and add information for missing fields
            entry = "connectioninfo=false fd=0 slot=0 tls=true %s port=0 from=0.0.0.0 to=0.0.0.0 autobind=none binddn=none" % (tlsinfo)
            redislogs.hset(str(conhash), "connection", entry)
    except Exception as a:
        log_error("update_connection_tls", servername, line, ("ERROR(%s)" % str(a)), logfile)


# update connection information for autobind user
def update_connection_autobind(servername, con, conhash, line, redislogs, logfile):
    # prepare the tls info
    line = line.replace(('%s ' % con), '')
    line = line.replace('AUTOBIND dn=', 'autobind=')
    line = line.split('] ')[-1]

    # append info to redis entry
    try:
        try:
            # get the connection information from redis
            entry = redislogs.hget(str(conhash), "connection")
            entry = entry.decode()
            entry = entry.replace('autobind=false', line)
            # replace updated entry in the redis
            redislogs.hset(str(conhash), "connection", entry)
        except:
            # add new entry to redis and add information for missing fields
            entry = "connectioninfo=false fd=0 slot=0 tls=false starttls=false port=0 from=0.0.0.0 to=0.0.0.0 %s binddn=none" % (line)
            redislogs.hset(str(conhash), "connection", entry)
    except Exception as a:
        log_error("update_connection_autobind", servername, line, ("ERROR(%s)" % str(a)), logfile)


# update connection information for bind user
def update_connection_bind(servername, con, conhash, opnumber, line, redislogs, logfile):
    # prepare the tls info
    line = line.replace(('%s ' % con), '')
    line = line.replace('BIND dn=', 'binddn=')
    line = line.replace(('%s ' % opnumber), '')
    line = line.split('] ')[-1]

    # append info to redis entry
    try:
        try:
            # get the connection information from redis
            entry = redislogs.hget(str(conhash), "connection")
            entry = entry.decode()
            entry = entry.replace('binddn=none', line)
            # replace updated entry in the redis
            redislogs.hset(str(conhash), "connection", entry)
        except:
            # add new entry to redis and add information for missing fields
            entry = "connectioninfo=false fd=0 slot=0 tls=false starttls=false port=0 from=0.0.0.0 to=0.0.0.0 autobind=none %s" % (line)
            redislogs.hset(str(conhash), "connection", entry)
    except Exception as a:
        log_error("update_connection_bind", servername, line, ("ERROR(%s)" % str(a)), logfile)


# write the current operation into the redis
def new_operation(servername, conhash, opnumber, operation, line, redislogs, logfile):
    # prepare the line
    line = line.replace(('%s' % operation), ('%s type=\"%s\"' % (operation, operation.lower())))

    # add the line to the redis
    try:
        # replace updated entry in the redis
        redislogs.hset(str(conhash), opnumber, line)
    except Exception as a:
        log_error("new_operation", servername, line, ("ERROR(%s)" % str(a)), logfile)


# log result with operation and connection data from redis
def log_operation(servername, con, conhash, opnumber, errorcode, line, redislogs, logfile):
    # prepare the tls info
    line = line.replace(('%s ' % con), '')
    line = line.replace(('%s ' % opnumber), '')
    line = line.replace(('%s ' % errorcode), ('%s %s ' % (errorcode, get_error_code_by_name(errorcode))))
    line = line.split('] ')[-1]

    # get infos from redis
    redisconnection = ""
    redisoperation = ""
    try:
        # get the connection information from redis
        redisconnection = redislogs.hget(str(conhash), "connection")
        if redisconnection is None:
            redisconnection = "CONNECTION connectioninfo=false fd=0 slot=0 tls=false starttls=false port=0 from=0.0.0.0 to=0.0.0.0 autobind=none binddn=none"
        else:
            redisconnection = redisconnection.decode()

        # get the operation information from redis
        redisoperation = redislogs.hget(str(conhash), str(opnumber))
        if redisoperation is None:
            redisoperation = "%s %s %s UNKNOWN(Operation not found in redis!) operationmissing=true" % \
                             (get_current_time_ldap(), con, opnumber)
        else:
            redisoperation = redisoperation.decode()
    except Exception as a:
        log_error("log_operation", servername, line, ("ERROR(%s)" % str(a)), logfile)

    # check if it was the result of a successfull bind
    try:
        if errorcode == "err=0" and " dn=" in line:
            # extract the needed values from the strings
            user = line.split(' dn=')[-1]
            user = user.replace('"', '')
            time = "%s]" % redisoperation.split('] ')[0]
            # insert the bind into the redis
            record_last_success_bind(servername, user, time)
    except Exception as a:
        log_error("log_operation_lastbind", servername, line, ("ERROR(%s)" % str(a)), logfile)

    # generate the logline
    logline = str("%s %s %s" % (redisoperation, line, redisconnection))

    # send the logline
    log_line(servername, logline, logfile)

    # clean up opnumber in redis
    try:
        redislogs.hdel(str(conhash), str(opnumber))
    except:
        pass


# log the closing connection
def close_connection(servername, conhash, opnumber, fdnumber, line, redislogs, logfile):
    # prepare the additional info
    closeinfo = line.split("%s " % fdnumber)[-1]
    closeinfo = closeinfo.replace(' - ', '=')
    closeinfo = closeinfo.replace(' ', '_')

    # get infos from redis
    redisconnection = ""
    redisoperation = ""
    try:
        # get the connection information from redis
        redisconnection = redislogs.hget(str(conhash), "connection")
        if redisconnection is None:
            redisconnection = "CONNECTION %s connectioninfo=false fd=0 slot=0 tls=false starttls=false port=0 from=0.0.0.0 to=0.0.0.0 autobind=none binddn=none" % fdnumber
        else:
            redisconnection = redisconnection.decode()

        # get the operation information from redis
        redisoperation = redislogs.hget(str(conhash), str(opnumber))
        if redisoperation is None or opnumber == "op=-1":
            redisoperation = "%s CLOSE type=\"close\" note=\"close without unbind\"" % (line.split(" %s" % fdnumber)[0])
        else:
            redisoperation = redisoperation.decode()
    except Exception as a:
        log_error("close_connection", servername, line, ("ERROR(%s)" % str(a)), logfile)

    # generate the logline
    logline = str("%s RESULT err=0 errname=success %s %s" % (redisoperation, closeinfo, redisconnection))

    # send the logline
    log_line(servername, logline, logfile)

    # mark entry deletion in redis in 5min = 300
    try:
        redislogs.expire(str(conhash), 300)
    except:
        pass


# parse the given logline
def parse_current_log_line(servername, line, logfile):
    try:
        # skip empty lines
        if not line.strip():
            return
        # remove all null values from string
        line = line.replace('\x00', '')
        # add starting [ if needed
        if line[0].isdigit() and line[36] == ']':
            line = "[%s" % line
        # check if line seams to be correct with initial time
        if not (line[0] == "[" and line[37] == "]" and line[43] == "="):
            print("IGNORING BAD LINE (%s): %s" % (servername, line.encode()))
            return
    except:
        print("IGNORING BROKEN LINE (%s): %s" % (servername, line.encode()))
        return

    # try to parse tle line
    try:
        # split the line to usable args
        args = shlex.split(line)

        # get infos about the current line
        con = str(args[2])
        conhash = ("%s:%s" % (servername, con))
        opnumber = str(args[3])

        # get the global redis connection
        global __redislogs
        try:
            __redislogs.ping()
        except:
            global __stage
            __redislogs = redis_open_connection(__stage, "logs")

        # if there is no redis object create one with max age in seconds
        # 1h ... 3600, 6h ... 21600, 12h ... 43200, 24h ... 86400
        try:
            __redislogs.expire(str(conhash), 86400)
        except:
            pass

        # check the next step for the logline
        if opnumber.startswith("op="):
            # get the operation from the line
            operation = str(args[4])
            if operation == "RESULT":
                # get the error code from the line
                errorcode = str(args[5])
                # result should send a logine
                log_operation(servername, con, conhash, opnumber, errorcode, line, __redislogs, logfile)
            elif operation == "BIND":
                # bind user should be stored to redis as soon as possible
                update_connection_bind(servername, con, conhash, opnumber, line, __redislogs, logfile)
                # also log this line to redis db
                new_operation(servername, conhash, opnumber, operation, line, __redislogs, logfile)
            elif operation.startswith("fd="):
                # send log line on connection close
                close_connection(servername, conhash, opnumber, operation, line, __redislogs, logfile)
            else:
                # normal operation should be stored to redis
                new_operation(servername, conhash, opnumber, operation, line, __redislogs, logfile)
        elif opnumber.startswith("fd="):
            # log new connection
            new_connection(servername, con, conhash, line, __redislogs, logfile)
        elif opnumber.startswith("TLS"):
            # update connection status to starttls
            update_connection_tls(servername, con, conhash, line, __redislogs, logfile)
        elif opnumber.startswith("AUTOBIND"):
            # update connection to show autobind usage
            update_connection_autobind(servername, con, conhash, line, __redislogs, logfile)
        else:
            # unknown line should be logged with information about that
            log_error("parse_current_log_line", servername, line.encode(), "UNKNOWN(TYPE OF LOG LINE!)", logfile)

    except Exception as e:
        # log the wrong line
        log_error("parse_current_log_line", servername, line.encode(), ("ERROR(%s)" % str(e)), logfile)


# funktion for tailing the logfile
def file_seeker_loop(servername, logfile, killer):
    # start reading line (tail -f) from the initial position
    position = 0
    while True:
        # stop application if there is the signal
        if killer.kill_now:
            break

        # try to open logfile and read the lines
        global __outlogfile
        try:
            # open the source logfile
            filereader = open(logfile, 'r')
            # open the destination logfile
            if __outlogfile:
                outlogfile = open(__outlogfile, "a+")
            else:
                outlogfile = None

            # read the next lines in the file
            try:
                # get current filesize
                filereader.seek(0, 2)
                currentsize = filereader.tell()

                # on start set position to currentsize
                if position == 0:
                    position = currentsize
                # on logrotate start from beginning
                if position > currentsize:
                    position = 0

                # read the data starting from the position
                filereader.seek(position, 0)
                logblock = filereader.read()

                # get the position of the last linebreak and skip last line (maybe incomplete -> next round)
                lastlinebreak = logblock.rfind("\n")

                # continue if there is a linebreak
                if lastlinebreak > 0:

                    # read data only to last linebreak
                    logblock = logblock[0:lastlinebreak]
                    for logline in logblock.splitlines():

                        # parse the logline
                        parse_current_log_line(servername, logline, outlogfile)

                    # save position of last linebreak
                    position = position + lastlinebreak

            except Exception as ae:
                print("ERROR reading new data from the logfile (%s)!" % logfile)
                print(ae)

            # close the filereader
            filereader.close()

            # flush and close the filewriter
            if __outlogfile:
                outlogfile.flush()
                outlogfile.close()
        except Exception as ae:
            print("ERROR reading or writing the logs files (IN=%s, OUT=%s)! ... Exiting" % (logfile, str(__outlogfile)))
            print(ae)
            sys.exit(1)

        # stop application if there is the signal
        if killer.kill_now:
            break

        # sleep some time before next read
        time.sleep(0.1)


# help function for script execution
def show_help():
    global __servername
    print(""
          "There are needed params missing!"
          "Use: <script> <params>"
          ""
          "Possible params:"
          "-i | --log_input     ... Input log file from 389-ds (needed)"
          "-o | --log_output    ... Output log file for combined log (default: False)"
          "-l | --log_lastbind  ... Logfile for last successful binds (default: False)"
          "-s | --servername    ... Name of the server for the log lines (default: %s)"
          "-e | --stage         ... Define the server environment p, v or d (default: p ... production)"
          "-d | --syslog_host   ... Destination server for the syslog message (default: 127.0.0.1)"
          "-p | --syslog_port   ... Destination port for the syslog message (default: 514)"
          "-v | --syslog_value  ... Facility and level for the syslog message (default: 165)"
          "-t | --stdout        ... Display combined log on stdout (default: True)"
          "-h | --help          ... This message :)"
          ""
          "To disable a output function use:"
          "--log_output=False    ... Write no combined logfile"
          "--log_lastbind=False  ... Write no lastbind logfile"
          "--syslog_host=False   ... Do not send a syslog message"
          "" % __servername)
    sys.exit(1)


# define the main funktion
def main(argv):
    # initialize a signal handler
    killer = GracefulKiller()

    # read the servername
    global __servername
    try:
        __servername = socket.gethostname().split('.')[0]
    except:
        pass

    # read the given option
    try:
        opts, args = getopt.getopt(argv, "i:o:l:s:e:d:p:v:t:h", ["log_input=", "log_output=", "log_lastbind=",
                                                                 "servername=", "stage=", "syslog_host=",
                                                                 "syslog_port=", "syslog_value=", "stdout=", "help="])
    except:
        show_help()
        sys.exit(1)

    # store the given params
    for opt, arg in opts:
        if opt in ("-i", "--log_input"):
            global __inlogfile
            __inlogfile = arg
        if opt in ("-o", "--log_output"):
            global __outlogfile
            if arg == "False" or arg == "None":
                __outlogfile = False
            else:
                __outlogfile = arg
        if opt in ("-l", "--log_lastbind"):
            global __outlastbindfile
            if arg == "False" or arg == "None":
                __outlastbindfile = False
            else:
                __outlastbindfile = arg
        if opt in ("-s", "--servername"):
            __servername = arg
        if opt in ("-e", "--stage"):
            if arg == "p" or arg == "v" or arg == "d":
                global __stage
                __stage = arg
            else:
                show_help()
        if opt in ("-d", "--syslog_host"):
            global __sysloghost
            if arg == "False" or arg == "None":
                __sysloghost = False
            else:
                __sysloghost = arg
        if opt in ("-p", "--syslog_port"):
            global __syslogport
            __syslogport = arg
        if opt in ("-v", "--syslog_value"):
            global __syslogvalue
            __syslogvalue = arg
        if opt in ("-t", "--stdout"):
            if opt == "False" or "false":
                global __stdout
                __stdout = False
            else:
                show_help()
        if opt in ("-h", "--help"):
            show_help()

    # check if needed logfile was defined
    if not __inlogfile:
        show_help()

    # enter the seeker loop
    file_seeker_loop(__servername, __inlogfile, killer)


# open main after start
if __name__ == "__main__":
    main(sys.argv[1:])
