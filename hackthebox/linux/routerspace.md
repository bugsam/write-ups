# RouterSpace

# Enumeration

# User

````
com.routerspace on (samsung: 11) [usb] # memory search "htb" --string
Searching for: 68 74 62

com.routerspace on (samsung: 11) [usb] # memory dump from_base 0x12e01354 1000 ./dump_2
Dumping 1000.0 B from 0x12e01354 to ./dump_2
Memory dumped to file: ./dump_2

# hexdump -C dump_2 | less
40  00 00 00 00 68 74 74 70  3a 2f 2f 72 6f 75 74 65  |....http://route|
00000350  72 73 70 61 63 65 2e 68  74 62 2f 61 70 69 2f 76  |rspace.htb/api/v|
00000360  34 2f 6d 6f 6e 69 74 6f  72 69 6e 67 2f 72 6f 75  |4/monitoring/rou|
00000370  74 65 72 2f 64 65 76 2f  63 68 65 63 6b 2f 64 65  |ter/dev/check/de|
00000380  76 69 63 65 41 63 63 65  73 73 00 00 58 dd 13 70  |viceAccess..X..p|
````
`http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess`

# Root

`https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py`

# Secrets
