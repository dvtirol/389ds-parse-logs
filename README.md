# 389ds-parse-logs

Script for parsing and combining 389-ds log lines.

It is also working with RedHat Directory Server 11 (389-ds-base-1.4.3.22).

## Installation

There is no installation needed, you only have to start the script.
But before check the following dependencies:
* Local installed redis (localhost) on default port (6379)
* Installed python3 with following modules:
  * sys
  * getopt
  * redis
  * shlex
  * time
  * datetime
  * signal
  * socket

Important:
Script was only tested against python 3.6

## Usage

Execute: ./parse-logs.py <params>
```bash
Possible params:
-i | --log_input     ... Input log file from 389-ds (needed)
-o | --log_output    ... Output log file for combined log (default: False)
-l | --log_lastbind  ... Logfile for last successful binds (default: False)
-s | --servername    ... Name of the server for the log lines (default: %s)
-e | --stage         ... Define the server environment p, v or d (default: p ... production)
-d | --syslog_host   ... Destination server for the syslog message (default: 127.0.0.1)
-p | --syslog_port   ... Destination port for the syslog message (default: 514)
-v | --syslog_value  ... Facility and level for the syslog message (default: 165)
-t | --stdout        ... Display combined log on stdout (default: True)
-h | --help... This message :)

To disable a output function use:
--log_output=False    ... Write no combined logfile
--log_lastbind=False  ... Write no lastbind logfile
--syslog_host=False   ... Do not send a syslog message
--stdout=False        ... Do not write to stdout
```
  
## Example

Original 389-ds log lines:
```python
[28/Sep/2021:13:30:39.061117647 +0200] conn=123 fd=4096 slot=4096 SSL connection from 10.10.10.20 to 10.10.10.10
[28/Sep/2021:13:30:39.312732156 +0200] conn=123 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[28/Sep/2021:13:30:39.313621178 +0200] conn=123 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.050183451 optime=0.000902082 etime=0.051082291 dn="cn=directory manager"
[28/Sep/2021:13:30:39.321295649 +0200] conn=123 op=1 SRCH base="cn=monitor" scope=0 filter="(objectClass=*)" attrs="* aci"
[28/Sep/2021:13:30:39.322509856 +0200] conn=123 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.001051741 optime=0.174392170 etime=0.175441291
[28/Sep/2021:13:30:40.617683492 +0200] conn=123 op=-1 fd=4096 closed error - B1
```

Execution command:
```bash
./parse-logs.py --log_input=/var/log/dirsrv/sldapd-userroot/access --servername=ldapserver01
```

Output of parse-logs.py:
```python
ldapserver01 [28/Sep/2021:13:30:39.061117647 +0200] conn=123 op=-1 OPEN type=open RESULT err=0 errname=success CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn=none
ldapserver01 [28/Sep/2021:13:30:39.312732156 +0200] conn=123 op=0 BIND type="bind" dn="cn=Directory Manager" method=128 version=3 RESULT err=0 errname=success tag=97 nentries=0 wtime=0.050183451 optime=0.000902082 etime=0.051082291 dn="cn=directory manager" CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn="cn=Directory Manager" method=128 version=3
ldapserver01 [28/Sep/2021:13:30:39.321295649 +0200] conn=123 op=1 SRCH type="srch" base="cn=monitor" scope=0 filter="(objectClass=*)" attrs="* aci" RESULT err=0 errname=success tag=101 nentries=1 wtime=0.001051741 optime=0.174392170 etime=0.175441291 CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn="cn=Directory Manager" method=128 version=3
ldapserver01 [28/Sep/2021:13:30:40.617683492 +0200] conn=123 op=-1 CLOSE type="close" note="close without unbind" RESULT err=0 errname=success closed_error=B1 CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn="cn=Directory Manager" method=128 version=3
```

## Contributing

Pull requests are always welcome.
 
Known possible improvments:
* Input hardening for some params
* Error handling to fine grade exceptions
* Code improvement for function params
* Add params for redis and redis db
* Add debugging options
  
## License
GNU General Public License v2.0
