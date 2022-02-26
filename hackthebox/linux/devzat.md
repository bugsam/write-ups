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
