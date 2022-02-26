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



$ 



# User

# Root

# Secrets
