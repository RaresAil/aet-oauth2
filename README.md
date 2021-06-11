# @adr-express-ts/oauth2

This is an **OAuth2 Server Wrapper** with support for **PKCE**

[![Build/Testing CI/CD](https://github.com/RaresAil/aet-oauth2/actions/workflows/node.js.yml/badge.svg)](https://github.com/RaresAil/aet-oauth2/actions/workflows/node.js.yml)

[NPM](https://www.npmjs.com/package/@adr-express-ts/oauth2)

### Content

1. [Code Challenge Method `S256`](#code-challenge-method-s256)
2. [Code Challenge Method `plain`](#code-challenge-method-plain)

### Templates

1. [Password Grant](https://github.com/RaresAil/express-oauth-password-grant-example)
2. Authorization Code Grant (Coming Soon)

## PKCE Support

To use the PKCE:

- `code_challenge` and `code_challenge_method` (Which defaults to `plain`) must be included in the **Authorization Code Grant**.
- `code_verifier` must be sent in the Token Grant. The `client_secret` is ignored when `code_verifier` is present.

### Code Challenge Method `S256`

For S256, when sending the request from the client, the `codeChallenge` must be saved as `SHA256` in `Base64` according to [RFC7637 Page 17](https://tools.ietf.org/html/rfc7636#page-17).

When the token is generated, the `code_verifier` must not be encoded, the wrapper will hash it and validate it with the `codeChallenge`.

Example in NodeJS for `codeChallenge`:

```js
import crypto from 'crypto';
const codeVerifier: string = 'some-hash';

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

### Request model for `Authorize` and `Authorization Code Grant`

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

Response:

```json
{
  "code": "248ebd408a963cf3c66eecd22146ec35ac11384f",
  "state": "some_state"
}
```

### Request model for `Token` and `Authorization Code Grant`

The parameters for the request body as `application/x-www-form-urlencoded` are:

```json
{
  "client_id": "123456789",
  "grant_type": "authorization_code",
  "code": "248ebd408a963cf3c66eecd22146ec35ac11384f",
  "redirect_uri": "http://url",
  "code_verifier": "some-hash"
}
```

```curl
curl --location --request POST 'http://127.0.0.1/api/v1/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=123456789' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'code=248ebd408a963cf3c66eecd22146ec35ac11384f' \
--data-urlencode 'redirect_uri=http://url' \
--data-urlencode 'code_verifier=some-hash'
```

Response:

```json
{
  "access_token": "25202a95c58ffaead0d423a75c7b89e3a4e71046",
  "token_type": "Bearer",
  "expires_in": 3599,
  "refresh_token": "1a54d25aafe6cc54a486680c1ec538c3731ba74a",
  "scope": "some_scope"
}
```
