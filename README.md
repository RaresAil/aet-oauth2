# @adr-express-ts/oauth2

This is an **OAuth2 Server Wrapper** with support for **PKCE**

### Content

1. [Code Challenge Method `S256`](#Code%20Challenge%20Method%20S256)
2. [Code Challenge Method `plain`](#Code%20Challenge%20Method%20plain)

## PKCE Support

To use the PKCE:

- `code_challenge` and `code_challenge_method` (Which defaults to `plain`) must be included in the **Authorization Code Grant**.
- `code_verifier` must be sent in the Token Grant. The `client_secret` is ignored when `code_verifier` is present.

### Code Challenge Method `S256`

For S256, when sending the request from the client, the `codeChallenge` must be saved as `SHA256` in `Base64` according to [RFC7637 Page 17](https://tools.ietf.org/html/rfc7636#page-17).

When the token is generated, the `code_verifier` must not be encoded, the wrapper will hash it and validate it with the `codeChallenge`.

Example in NodeJS for `codeChallenge`:

```ts
import crypto from 'crypto';
const codeVerifier: string = 'some string';

const base64URLEncode = (buffer: Buffer) => {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

const hash = base64URLEncode(
  crypto.createHash('sha256').update(codeVerifier).digest()
);
```

### Code Challenge Method `plain`

For plain, when sending the request from the client, the `codeChallenge` must be validated by this regex `/^([A-Za-z0-9\.\-\_\~]){43,128}$/` according to [RFC7637 Section 4.1](https://tools.ietf.org/html/rfc7636#section-4).

When the token is generated, the `code_verifier` must be the same as `codeChallenge`.

### Request model for `Authorize`

The `code verifier` is `some-hash`.

The `code challenge` is `xtZ07fkhEB8SBPd1I5DLKo1_4OsA8GXYR328wpqfNms`.

The `Authorization` header is required and can be generated from Password Grant to know which user is which.

The parameters for the request body as `application/x-www-form-urlencoded` are:

```json
{
  "client_id": "123456789",
  "grant_type": "authorization_code",
  "state": "some_state",
  "response_type": "code",
  "scope": "some_scope",
  "code_challenge_method": "S256",
  "code_challenge": "xtZ07fkhEB8SBPd1I5DLKo1_4OsA8GXYR328wpqfNms"
}
```

```curl
curl --location --request POST 'http://127.0.0.1/api/v1/oauth2/authorize' \
--header 'Authorization: Bearer some-access-token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=123456789' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'state=some_state' \
--data-urlencode 'response_type=code' \
--data-urlencode 'scope=some_scope' \
--data-urlencode 'code_challenge_method=S256' \
--data-urlencode 'code_challenge=xtZ07fkhEB8SBPd1I5DLKo1_4OsA8GXYR328wpqfNms'
```
