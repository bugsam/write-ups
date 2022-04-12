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

# Root Detection bypass

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





