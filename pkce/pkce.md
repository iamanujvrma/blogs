When clients like mobile, desktop, single page applications allows the user to sign-in using a third party application (google, facebook, twitter etc), one of the first choice is to use OAuth 2.0 standard with authorization code flow.

In Authorization code flow, authorization request is made via ***browser*** and an authorization code is returned to the redirect URL registered by the client. This authorization code is used by public clients to request for an access token to get access to resources.

![Intercept Attack](https://dev-to-uploads.s3.amazonaws.com/i/qfiblk0b346te5777e35.png)

Protecting this authorization code is thus critical but in most cases the public clients make use of custom URL scheme to capture redirects (e.g myapp://callback) thus having the risk of malicious applications to receive the authorization code.

Malicious apps can register the same custom URL scheme (myapp://callback) and mobile OS does not stops them to do so. As `authorization_code` is always sent back to redirect URL (in this case myapp://callback), the OS on reception of a redirect to custom URL scheme launches apps matching the scheme randomly. So the code may be sent to your app or may be the hacker app. You cannot prevent this.

#### Authorization code flow request
```
https://authorization-server.com/auth
 ?response_type=code
 &client_id=example-client-id
 &redirect_uri=myapp://callback
 &scope=openid
 &state=example-state
```
#### Authorization code flow response
```
myapp://callback
 ?code=hu831dsdsf23121
 &state=example-state
```
#### Authorization token request
```
https://authorization-server.com/token?
grant_type=authorization_code
&code=hu831dsdsf23121
&redirect_uri=myapp://callback
&client_id=xxxxxxxxxx
&client_secret=xxxxxxxxxx
```

Well, even if they get access to the authorisation code, there is no risk as such because the attacker will not be having the client credentials (client_id, client_secret) to request for an access token. What if they have it too ?

In case of mobile applications, credentials are mostly hardcoded into the app and decompiling it will reveal those. Thus, for public clients it is not recommended to use client secret as it may be compromised.

To mitigate the risk, OAuth 2.0 provides a version of the Authorization code flow which makes use of a Proof Key for Code Exchange (PKCE, pronounced pixie).

## When to use PKCE ?

You have a native client, such as an app on a mobile device, or a desktop app and it does not have a secure way to store client credentials for authenticating at the token endpoint.

## How it works ?

![PKCE Flow](https://dev-to-uploads.s3.amazonaws.com/i/jfpzv8yvkh2s1yeern9h.png)

When the public clients makes the authorization request

* They first need to create a secret known as `code_verifier`. This is a cryptographically random string between 43 - 128 characters.

```
function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

var code_verifier = base64URLEncode(crypto.randomBytes(32));
```

* Then use the `code_verifier` to generate a `code_challenge`. For clients that can perform a SHA256 hash, the `code_challenge` is base64 URL encoded string of the SHA256 hash of `code_verifier`, otherwise plain `code_verifier` can be used as a challenge.

```
function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest();
}
var code_challenge = base64URLEncode(sha256(verifier));
```

* Then it includes the `code_challenge` and a parameter to indicate method used to generate the `code_challenge` (plain or S256).

```
https://authorization-server.com/auth
 ?response_type=code
 &client_id=example-client-id
 &redirect_uri=myapp://callback
 &scope=openid
 &state=example-state
 &code_challenge=XXXXXXXXX
 &code_challenge_method=S256
```

* The authorization server then remembers the `code_challenge`, `code_challenge_method` against the authorization code it generates and then redirects the user back to the application with an authorization code.

* When exchanging the authorization code for a token, client app need not send the `client_secret` in request, instead it sends the `code_verifier` generated before making the initial authorization request. This way even if an attacker gets the authorization code they will not have access to `code_verifier`, hence authorization code is of no use for malicious apps.
```
https://authorization-server.com/token?
grant_type=authorization_code
&code=hu831dsdsf23121
&redirect_uri=myapp://callback
&client_id=xxxxxxxxxx
&code_verifier=xxxxxxxxxx
```
* Authorization server verifies the `code_verifier` parameter in request by generating the `code_challenge` as per the `code_challenge_method` stored against the authorization code. If the verification is successful, server responds with an ID and Access token.

## Summary
* Do not store client credentials in native and single page applications.
* Use PKCE security extension of OAuth 2.0 to securely exchange an authorisation code with access token.

## References
* https://tools.ietf.org/html/rfc7636

If you have any questions, feel free to comment, I’d love to hear your feedback! Thanks for reading!

