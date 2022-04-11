# README

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
