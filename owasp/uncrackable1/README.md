# OWASP - UnCrackable Level 1

[![image](https://user-images.githubusercontent.com/44240720/162812993-b4b3038e-cb3b-404a-96b8-00ee3fc0b3e9.png)](https://github.com/OWASP/owasp-mstg)


# Tools

* Apktool:

[![image](https://user-images.githubusercontent.com/44240720/130667779-c16910bc-fa14-4c8d-89fe-c53991ce0abc.png)](https://ibotpeaches.github.io/Apktool/documentation/)


* Frida

[![image](https://user-images.githubusercontent.com/44240720/130668692-7a4f9339-05c8-43b2-b97f-1eb0c613b246.png)](https://frida.re/)


* Objection

[![image](https://user-images.githubusercontent.com/44240720/162812350-a68b2dcb-45ec-49f4-a4c2-cf6c41a3779f.png)](https://github.com/sensepost/objection)

# Environment

Android Virtual Device:
* Nexus X
* x86 Images: R API 29 | x86
* Target: Android 10.0
* Google API: none


Check:
````
> adb devices
List of devices attached
emulator-5554   device
> adb root
> adb shell getprop ro.product.cpu.abilist
x86_64
````

# Application
````
> adb install .\UnCrackable-Level1.apk
````

![image](https://user-images.githubusercontent.com/44240720/162916922-2d5007da-c60a-4298-a749-6b364da687aa.png)


# Decode

````
> apktool decode .\UnCrackable-Level1.apk -o base
I: Using Apktool 2.6.1 on UnCrackable-Level1.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: C:\Users\samue\AppData\Local\apktool\framework\1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
````

# Static analyze

sg.vantagepoint.uncrackable1.MainActivity.onCreate()
| method | desc |
|---|---|
| c.a()  | check_su |
| c.b()  | check_signKey  |
| c.c()  | check_binaries  |
| b.a()  | check_isDebuggable |


![image](https://user-images.githubusercontent.com/44240720/162810400-42ee8c7e-351b-4127-8cf1-ff421cceb856.png)

# Method 1: Root Detection bypass

````typescript
function securityBypass(){
    var b = Java.use("sg.vantagepoint.a.b");    
    var c = Java.use("sg.vantagepoint.a.c");
    
    b.a.overload('android.content.Context').implementation = function(v1){
        console.log("isDebuggable bypass");
        return false;
    }

    c.a.overload().implementation = function(){
        console.log("suExist bypass");
        return false;
    }

    c.b.overload().implementation = function(){
        console.log("signKey bypass");
        return false;
    }

    c.c.overload().implementation = function(){
        console.log("binariesExist bypass");
        return false;
    }
};

Java.perform(function () {
    securityBypass();
})
````

🔗 https://github.com/frida/frida/releases/download/15.1.17/frida-server-15.1.17-android-x86.xz
````
> adb push .\frida-server-15.1.17-android-x86 /data/media/
.\frida-server-15.1.17-android-x86: 1 file pushed, 0 skipped. 141.4 MB/s (99288680 bytes in 0.670s)

> adb shell "/data/media/frida-server-15.1.17-android-x86 &"
[1] 2486

> adb shell ss -nlpt
State      Recv-Q Send-Q  Local Address:Port         Peer Address:Port
LISTEN     0      10      127.0.0.1:27042            0.0.0.0:*                   users:(("frida-server-15",pid=2486,fd=7))
LISTEN     0      4       *:5037                     *:*                         users:(("adbd",pid=2459,fd=8))
````

````
> frida -U -f "owasp.mstg.uncrackable1" -l .\hooking.ts
````
![image](https://user-images.githubusercontent.com/44240720/162917186-a8f9e240-3d32-4e09-b18b-593c6569181f.png)


# Secret

![image](https://user-images.githubusercontent.com/44240720/162917949-a4550576-1bb6-40ac-af35-7949d6afa60a.png)

# Static analyze (again)

sg.vantagepoint.a.a.a(p0,p1)
| method | desc |
|---|---|
| Cipher.doFinal()  | Finishes a multiple-part encryption or decryption operation, depending on how this cipher was initialized. |
🔗 https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html#doFinal(byte[],%20int)

![image](https://user-images.githubusercontent.com/44240720/162810809-4153bfa0-c313-4d0e-a8f3-4891c0afb87c.png)

````
frida-ps -Uai
 PID  Name           Identifier
----  -------------  --------------------------
2891  Calendar       com.android.calendar
2547  Clock          com.android.deskclock
3384  Email          com.android.email
3433  Gallery        com.android.gallery3d
3079  Phone          com.android.dialer
2426  Settings       com.android.settings
3970  Uncrackable1   owasp.mstg.uncrackable1
   -  Camera         com.android.camera2
   -  Contacts       com.android.contacts
   -  Files          com.android.documentsui
   -  Messaging      com.android.messaging
   -  Search         com.android.quicksearchbox
   -  WebView Shell  org.chromium.webview_shell
````

````
 frida-trace -U -p 3970 -j "*Cipher*!*doFinal*"
Instrumenting...
AndroidKeyStoreAuthenticatedAESCipherSpi$BufferAllOutputUntilDoFinalStreamer.doFinal: Auto-generated handler at "C:\\Users\\samue\\__handlers__\\android.security.keystore.AndroidKeyStoreAuthenticatedAESCipherSpi_BufferAllOutputUntilDoFinalStreamer\\doFinal.js"
PaddedBufferedBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\samue\\__handlers__\\com.android.org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher\\doFinal.js"
BufferedBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\samue\\__handlers__\\com.android.org.bouncycastle.crypto.BufferedBlockCipher\\doFinal.js"
BaseBlockCipher$BufferedGenericBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\samue\\__handlers__\\com.android.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher_BufferedGenericBlockCipher\\doFinal.js"
BaseBlockCipher$GenericBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\samue\\__handlers__\\com.android.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher_GenericBlockCipher\\doFinal.js"
BaseBlockCipher$AEADGenericBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\samue\\__handlers__\\com.android.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher_AEADGenericBlockCipher\\doFinal.js"
Cipher.doFinal: Auto-generated handler at "C:\\Users\\samue\\__handlers__\\javax.crypto.Cipher\\doFinal.js"
Started tracing 7 functions. Press Ctrl+C to stop.
           /* TID 0xf82 */
  6688 ms  Cipher.doFinal([-27,66,98,21,-53,91,-102,6,-61,-96,-75,-26,-92,-67,118,-102,73,-24,-16,116,-8,46,-1,29,-107,-85,124,23,20,118,24,-25])
  6688 ms     | BaseBlockCipher$BufferedGenericBlockCipher.doFinal([73,32,119,97,110,116,32,116,111,32,98,101,108,105,101,118,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 16)
  6689 ms     |    | PaddedBufferedBlockCipher.doFinal([73,32,119,97,110,116,32,116,111,32,98,101,108,105,101,118,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 16)
  6689 ms     |    | <= 1
  6690 ms     | <= 1
  6690 ms  <= [73,32,119,97,110,116,32,116,111,32,98,101,108,105,101,118,101]
````

![image](https://user-images.githubusercontent.com/44240720/162920948-5c1196c4-cecd-437c-a519-3b80ed78251f.png)

![image](https://user-images.githubusercontent.com/44240720/162921015-556e25f0-db67-4d9e-9299-db9e1a9dab17.png)

# Beyond Secret

````
`objection -g 3970 explore
Using USB device `Android Emulator 5554`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v1.11.0

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
owasp.mstg.uncrackable1 on (Android: 10) [usb] # memory search "I want to believe" --string
Searching for: 49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76 65
12c9ad5c  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12c9ad6c  65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  e...............
12c9ad7c  00 00 00 00 88 78 fb 6f 00 00 00 00 11 00 00 00  .....x.o........
12c9ad8c  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12c9ad9c  65 00 00 00 08 43 00 70 00 00 00 00 00 00 00 00  e....C.p........
12c9adac  00 00 00 00 68 9e 00 70 00 00 00 00 11 00 00 00  ....h..p........
12c9adf0  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12c9ae00  65 00 00 00 00 00 00 00 08 43 00 70 00 00 00 00  e........C.p....
12c9ae10  0e 00 00 00 18 df e8 e1 4e 6f 70 65 2e 2e 2e 00  ........Nope....
12d8a91c  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12d8a92c  65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  e...............
12d8a93c  00 00 00 00 88 78 fb 6f 00 00 00 00 11 00 00 00  .....x.o........
12d8a94c  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12d8a95c  65 00 00 00 08 43 00 70 00 00 00 00 00 00 00 00  e....C.p........
12d8a96c  00 00 00 00 68 9e 00 70 00 00 00 00 11 00 00 00  ....h..p........
12d8a9b0  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12d8a9c0  65 00 00 00 00 00 00 00 48 af c9 12 00 00 00 00  e.......H.......
12d8a9d0  20 46 12 16 00 00 00 00 b8 d5 2c 70 02 e7 27 8c   F........,p..'.
12daa48c  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12daa49c  65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  e...............
12daa4ac  00 00 00 00 88 78 fb 6f 00 00 00 00 11 00 00 00  .....x.o........
12daa4bc  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12daa4cc  65 00 00 00 08 43 00 70 00 00 00 00 00 00 00 00  e....C.p........
12daa4dc  00 00 00 00 68 9e 00 70 00 00 00 00 11 00 00 00  ....h..p........
12daa520  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12daa530  65 00 00 00 00 00 00 00 48 af c9 12 00 00 00 00  e.......H.......
12daa540  20 46 12 16 00 00 00 00 b8 d5 2c 70 b9 81 8b 8a   F........,p....
12e4b6cc  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12e4b6dc  65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  e...............
12e4b6ec  00 00 00 00 88 78 fb 6f 00 00 00 00 11 00 00 00  .....x.o........
12e4b6fc  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12e4b70c  65 00 00 00 08 43 00 70 00 00 00 00 00 00 00 00  e....C.p........
12e4b71c  00 00 00 00 68 9e 00 70 00 00 00 00 11 00 00 00  ....h..p........
12e4b760  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
12e4b770  65 00 00 00 00 00 00 00 48 af c9 12 00 00 00 00  e.......H.......
12e4b780  20 46 12 16 00 00 00 00 b8 d5 2c 70 dc 67 7f 86   F........,p.g..
13118a58  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
13118a68  65 00 00 00 00 00 00 00 38 57 c8 12 00 00 00 00  e.......8W......
13118a78  02 00 00 00 60 47 c8 12 70 2d 13 16 00 00 00 00  ....`G..p-......
13119b78  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
13119b88  65 00 00 00 00 00 00 00 58 ca 03 70 00 00 00 00  e.......X..p....
13119b98  7e 27 00 00 00 00 00 00 20 a1 10 16 00 00 00 00  ~'...... .......
1311a060  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
1311a070  65 00 00 00 00 00 00 00 50 99 fb 6f 00 00 00 00  e.......P..o....
1311a080  01 00 00 00 e0 87 c8 12 58 ca 03 70 00 00 00 00  ........X..p....
1311aef8  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
1311af08  65 0a 00 00 00 00 00 00 38 57 c8 12 00 00 00 00  e.......8W......
1311af18  02 00 00 00 60 47 c8 12 70 2d 13 16 00 00 00 00  ....`G..p-......
1311bb88  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
1311bb98  65 00 00 00 00 00 00 00 50 99 fb 6f 00 00 00 00  e.......P..o....
1311bba8  01 00 00 00 a8 93 c8 12 20 a1 10 16 00 00 00 00  ........ .......
1311dc48  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
1311dc58  65 0a 00 00 00 00 00 00 f0 dd 4a 70 00 00 00 00  e.........Jp....
1311dc68  18 83 2e 70 f8 dd 11 13 58 dd 11 13 88 dd 11 13  ...p....X.......
13120160  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
13120170  65 00 00 00 00 00 00 00 78 a0 c8 12 00 00 00 00  e.......x.......
13120180  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
13120378  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
13120388  65 00 00 00 00 00 00 00 58 ca 03 70 00 00 00 00  e.......X..p....
13120398  7e 27 00 00 00 00 00 00 f0 dd 4a 70 00 00 00 00  ~'........Jp....
13123eb0  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
13123ec0  65 00 00 00 00 00 00 00 a0 7d 3b 70 00 00 00 00  e........};p....
13123ed0  00 3f 12 13 00 00 00 00 50 ad 3f 70 00 00 00 00  .?......P.?p....
131250c4  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
131250d4  65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  e...............
131250e4  00 00 00 00 88 78 fb 6f 00 00 00 00 11 00 00 00  .....x.o........
131250f4  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
13125104  65 00 00 00 08 43 00 70 00 00 00 00 00 00 00 00  e....C.p........
13125114  00 00 00 00 68 9e 00 70 00 00 00 00 11 00 00 00  ....h..p........
13125158  49 20 77 61 6e 74 20 74 6f 20 62 65 6c 69 65 76  I want to believ
13125168  65 00 00 00 00 00 00 00 08 43 00 70 00 00 00 00  e........C.p....
13125178  36 00 00 00 c5 0b cd 46 54 68 69 73 20 69 73 20  6......FThis is
Pattern matched at 24 addresses
````

# Method 2: Root Detection bypass

![image](https://user-images.githubusercontent.com/44240720/162924838-72623794-9a9a-4b04-bf91-6e6ce98dbe99.png)






:link: http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html





