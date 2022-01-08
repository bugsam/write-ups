# Exercises

## Linux

### Secret

1. Criar usuario
````http
POST /api/user/register HTTP/1.1
Host: 10.10.11.120
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 88

{
	"name": "bugsam",
	"email": "bugsam@dasith.works",
	"password": "Kekc8swFgD6zU"
}
````

2. Obter JWT
````http
POST /api/user/login HTTP/1.1
Host: 10.10.11.120
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 68

{
	"email": "bugsam@dasith.works",
	"password": "Kekc8swFgD6zU"
}
````

````http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 07 Jan 2022 00:55:22 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWQ3OGY0YzMyNGI3MjA0NjA3ZjNmNmMiLCJuYW1lIjoiYnVnc2FtIiwiZW1haWwiOiJidWdzYW1AZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQxNTE2OTIyfQ.MQch40J_dLaoCAsmnfFBVkRa9I7lPTOqxI5ZOR-YnVs
ETag: W/"d3-3iO+pY4L4lsm4uW7A1qn02jy1Ys"
Content-Length: 211

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWQ3OGY0YzMyNGI3MjA0NjA3ZjNmNmMiLCJuYW1lIjoiYnVnc2FtIiwiZW1haWwiOiJidWdzYW1AZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQxNTE2OTIyfQ.MQch40J_dLaoCAsmnfFBVkRa9I7lPTOqxI5ZOR-YnVs
````

3. Testar JWT
````http
GET /api/priv HTTP/1.1
Host: 10.10.11.120
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 23
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWQ3OGY0YzMyNGI3MjA0NjA3ZjNmNmMiLCJuYW1lIjoiYnVnc2FtIiwiZW1haWwiOiJidWdzYW1AZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQxNTE4MDU4fQ.pb7GNWqYyZR58PiPMzen4CKXnL6vjc2_xBpuDJF0Rmc


````

https://lmammino.github.io/jwt-cracker/

## Windows


