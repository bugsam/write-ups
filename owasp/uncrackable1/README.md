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
* Nexus 6
* x86 Images: R API 30
* Target: Android 11.0
* Google API: none

Remove wait for debug
````
1. Go to Settings -> About emulated device
2. Click Build number 7 times (or till it says that you're a developer now).
3. Go back and go to System -> Advanced -> Developer options
4. Developer options > Wait for debugger (uncheck)
````

Check:
````
> adb devices
List of devices attached
emulator-5554   device
> adb root
> adb shell getprop ro.product.cpu.abilist
x86_64
````

````
> adb push .\frida-server-15.1.17-android-x86_64 /data/media/
.\frida-server-15.1.17-android-x86_64: 1 file pushed, 0 skipped. 141.4 MB/s (99288680 bytes in 0.670s)

> adb shell "/data/media/frida-server-15.1.17-android-x86_64 &"
[1] 2486

> adb shell ss -nlpt
State      Recv-Q Send-Q  Local Address:Port         Peer Address:Port
LISTEN     0      10      127.0.0.1:27042            0.0.0.0:*                   users:(("frida-server-15",pid=2486,fd=7))
LISTEN     0      4       *:5037                     *:*                         users:(("adbd",pid=2459,fd=8))
````

# Application
````
> adb install .\UnCrackable-Level1.apk
````

![image](https://user-images.githubusercontent.com/44240720/162827148-f3031296-ca4e-4332-9f97-29e3769ab729.png)


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










![image](https://user-images.githubusercontent.com/44240720/162810809-4153bfa0-c313-4d0e-a8f3-4891c0afb87c.png)






````
$ frida-trace -U -p 18207 -j "*Cipher*!*doFinal*"
Instrumenting...
AndroidKeyStoreAuthenticatedAESCipherSpi$BufferAllOutputUntilDoFinalStreamer.doFinal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\android.security.keystore.AndroidKeyStoreAuthenticatedAESCipherSpi_BufferAllOutputUntilDoFinalStreamer\\doFinal.js"
PaddedBufferedBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher\\doFinal.js"
BufferedBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.bouncycastle.crypto.BufferedBlockCipher\\doFinal.js"
BaseBlockCipher$BufferedGenericBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher_BufferedGenericBlockCipher\\doFinal.js"
BaseBlockCipher$GenericBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher_GenericBlockCipher\\doFinal.js"
BaseBlockCipher$AEADGenericBlockCipher.doFinal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher_AEADGenericBlockCipher\\doFinal.js"
Cipher.doFinal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\javax.crypto.Cipher\\doFinal.js"
OpenSSLEvpCipher.doFinalInternal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.conscrypt.OpenSSLEvpCipher\\doFinalInternal.js"
OpenSSLCipherChaCha20.doFinalInternal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.conscrypt.OpenSSLCipherChaCha20\\doFinalInternal.js"
OpenSSLCipher.doFinalInternal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.conscrypt.OpenSSLCipher\\doFinalInternal.js"
OpenSSLAeadCipher.doFinalInternal: Auto-generated handler at "C:\\Users\\offsec\\Documents\\android\\owasp.mstg.uncrackable1\\frida\\__handlers__\\com.android.org.conscrypt.OpenSSLAeadCipher\\doFinalInternal.js"
Started tracing 11 functions. Press Ctrl+C to stop.
           /* TID 0x471f */
  5466 ms  Cipher.doFinal([-27,66,98,21,-53,91,-102,6,-61,-96,-75,-26,-92,-67,118,-102,73,-24,-16,116,-8,46,-1,29,-107,-85,124,23,20,118,24,-25])
  5467 ms     | BaseBlockCipher$BufferedGenericBlockCipher.doFinal([73,32,119,97,110,116,32,116,111,32,98,101,108,105,101,118,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 16)
  5468 ms     |    | PaddedBufferedBlockCipher.doFinal([73,32,119,97,110,116,32,116,111,32,98,101,108,105,101,118,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 16)
  5469 ms     |    | <= 1
  5469 ms     | <= 1
  5469 ms  <= [73,32,119,97,110,116,32,116,111,32,98,101,108,105,101,118,101]
````
