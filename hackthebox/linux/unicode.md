# Unicode

# Enumeration

````
nmap -sCV -p22,80 --min-rate 1000 10.10.11.126 -oA nmap-10.10.11.126-sCV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-23 06:18 EDT
Nmap scan report for unicode.htb (10.10.11.126)
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fd:a0:f7:93:9e:d3:cc:bd:c2:3c:7f:92:35:70:d7:77 (RSA)
|   256 8b:b6:98:2d:fa:00:e5:e2:9c:8f:af:0f:44:99:03:b1 (ECDSA)
|_  256 c9:89:27:3e:91:cb:51:27:6f:39:89:36:10:41:df:7c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-generator: Hugo 0.83.1
|_http-title: Hackmedia
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.45 seconds
````

````
# wfuzz -u 'http://unicode.htb/FUZZ' -w /root/Downloads/subdomains-top1million-110000.txt --hl 514
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://unicode.htb/FUZZ
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                 
=====================================================================

000000107:   308        3 L      24 W       258 Ch      "upload"                                                                                             
000000468:   308        3 L      24 W       262 Ch      "register"                                                                                          
000002707:   308        3 L      24 W       256 Ch      "debug"                                                                                              
000009283:   308        3 L      24 W       258 Ch      "logout"                                                                                             
000025933:   308        3 L      24 W       260 Ch      "pricing"                                                                                             
000047706:   200        68 L     162 W      2078 Ch     "#smtp"
````

Create a user and login
````
POST /login/ HTTP/1.1
Host: unicode.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://unicode.htb
Connection: close
Referer: http://unicode.htb/login/
Upgrade-Insecure-Requests: 1

username=blah&password=bugsam
````

````
HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 23 Mar 2022 10:22:11 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 228
Connection: close
Location: http://unicode.htb/dashboard/
Set-Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYmxhaCJ9.g1K_hychzS7mTBSAnra1_WY1iMWs9SpzFsBsvEapubKQXIg6bG5zBnTyicFZ7v3nMf7VD0mBUoor2G8Sc5255OT-yGCDATs-xCo5z_9Q0rX2aVcjslpY0YjOdkvBztXI76tBEOtfYwjs2VQ2GWzdvA_r1H8vkIR2Qw3lpQ4MJVAHldqoL23uCu1KMQYhYeh6EuRMiI697PGCo4BCojLYVugfzgJhkWWyEH7jRDOu4C05JW3RMsJryAvM2om_ndv8SVj8NFNZBf1HMjiltUNtFgRI1708xRfxK-yUS3F1P0eWoEIDWdM01S6CzIuKWYnYAQlJHiDS3mPzx6wfsLfiqA; Path=/

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/dashboard/">/dashboard/</a>. If not click the link.
````


[pyjwt](https://pyjwt.readthedocs.io/en/stable/usage.html)
````python
>>> import jwt
>>> payload =
'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYmxhaCJ9.g1K_hychzS7mTBSAnra1_WY1iMWs9SpzFsBsvEapubKQXIg6bG5zBnTyicFZ7v3nMf7VD0mBUoor2G8Sc5255OT-yGCDATs-xCo5z_9Q0rX2aVcjslpY0YjOdkvBztXI76tBEOtfYwjs2VQ2GWzdvA_r1H8vkIR2Qw3lpQ4MJVAHldqoL23uCu1KMQYhYeh6EuRMiI697PGCo4BCojLYVugfzgJhkWWyEH7jRDOu4C05JW3RMsJryAvM2om_ndv8SVj8NFNZBf1HMjiltUNtFgRI1708xRfxK-yUS3F1P0eWoEIDWdM01S6CzIuKWYnYAQlJHiDS3mPzx6wfsLfiqA'
>>> jwt.get_unverified_header(payload)
{'typ': 'JWT', 'alg': 'RS256', 'jku': 'http://hackmedia.htb/static/jwks.json'}
>>> jwt.decode(payload, options={"verify_signature": False})
{'user': 'blah'}
````

# User


# Root

# Secrets
