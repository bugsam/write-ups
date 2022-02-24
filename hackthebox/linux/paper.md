# Paper

# Finding backend server

````shell
# curl -I http://10.10.11.143
HTTP/1.1 403 Forbidden
Date: Thu, 24 Feb 2022 00:50:52 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
````
`office.paper`

Add office.paper `/etc/paper`
