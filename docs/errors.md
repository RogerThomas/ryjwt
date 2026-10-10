# Errors

ryjwt's exceptions fall into three groups:

| group | means | respond |
| :-- | :-- | :-- |
| [`InvalidTokenError`][ryjwt.InvalidTokenError] | the token can't be trusted | 401 |
| [`JWKSFetchError`][ryjwt.JWKSFetchError] | a `JWKSClient` has no keys to check tokens with | 503 |
| [`InvalidKeyError`][ryjwt.InvalidKeyError] | a key you configured can't be used | fix the configuration |

All of them are [`RYJWTError`][ryjwt.RYJWTError]s:

```text
RYJWTError
├── InvalidKeyError
├── JWKSFetchError
└── InvalidTokenError
    ├── DecodeError
    │   └── InvalidSignatureError
    ├── InvalidAlgorithmError
    ├── UnknownKeyError
    ├── ExpiredSignatureError
    ├── ImmatureSignatureError
    ├── InvalidAudienceError
    ├── InvalidIssuerError
    └── ClaimsValidationError
```

## Rejected tokens

Every rejected token raises an `InvalidTokenError`, usually all you need to catch. Catch a
subclass to tell the reasons apart:

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")

try:
    claims = key.decode("not-a-token")
except ryjwt.ExpiredSignatureError:
    print("expired: get a new token")
except ryjwt.InvalidTokenError as e:
    print(type(e).__name__)  # DecodeError: respond 401
```

| exception | the token is rejected because |
| :-- | :-- |
| [`DecodeError`][ryjwt.DecodeError] | it's malformed: not three dot-separated base64url parts; header or payload not a JSON object; a header with a repeated field, over 64 fields, or a non-string `kid` (when the keys have `kid`s); `exp` or `nbf` not a number |
| [`InvalidSignatureError`][ryjwt.InvalidSignatureError] | its signature doesn't match (a kind of `DecodeError`) |
| [`InvalidAlgorithmError`][ryjwt.InvalidAlgorithmError] | its `alg` is missing, not a string, or not in the key's `algorithms`. In a JWKS, the key it picked may also be limited to other algorithms |
| [`UnknownKeyError`][ryjwt.UnknownKeyError] | its `kid` isn't in the JWKS; or the JWKS has several keys and it can't pick one (no `kid`, or the keys have none) |
| [`ExpiredSignatureError`][ryjwt.ExpiredSignatureError] | it has expired (`exp`) |
| [`ImmatureSignatureError`][ryjwt.ImmatureSignatureError] | it isn't valid yet (`nbf`) |
| [`InvalidAudienceError`][ryjwt.InvalidAudienceError] | its `aud` is missing, doesn't match `audience`, or isn't a string or list of strings; or it has an `aud` and you set no `audience` |
| [`InvalidIssuerError`][ryjwt.InvalidIssuerError] | you set `issuer`, and its `iss` is missing, doesn't match, or isn't a string |
| [`ClaimsValidationError`][ryjwt.ClaimsValidationError] | its claims don't fit your `type`: a field is missing, of the wrong type or out of range. Its `__cause__` is msgspec's or pydantic's `ValidationError` |
| `InvalidTokenError` itself | its header has a `crit` field, which ryjwt must reject |

The message gives details.

## Keys you configured: `InvalidKeyError`

Raised when you create a key object from:

- a PEM that doesn't parse, holds no key or several, or the wrong kind (public for `PrivateKey`,
  private for `PublicKey`);
- a weak key: RSA outside 2048 to 8192 bits, or a small-order Ed25519 key;
- an HMAC secret that's empty, too short, or looks like a public key;
- a JWKS document that [breaks the rules](keys.md#documents-that-are-rejected).

## JWKS URLs: `JWKSFetchError`

A [`JWKSClient`](jwks-urls.md) raises it when it has no usable keys because fetching failed. Not
the token's fault, so not an `InvalidTokenError`: respond 503.

## Python's own exceptions

Calling ryjwt wrongly raises Python's own exceptions. A type checker catches most first.

`ValueError`:

- `algorithms` is empty, names one the class doesn't support, or mixes ones a key can't serve;
- a key's `kid` is empty;
- `encode` has no `algorithm` but the key has several, or one the key doesn't have; or its
  `header` sets `alg`, `crit` or `b64`, sets `kid` when the key has one, or has over 64 fields;
- [`jwks`](keys.md#publishing-your-keys) has no keys, or several keys that don't each have their
  own `kid`;
- `jwk` is called on a `PublicKey` holding several keys (use `jwks`);
- a `datetime` claim has no timezone;
- `leeway` is negative or infinite;
- a `JWKSClient`'s URL isn't [allowed](jwks-urls.md#allowed-urls), or a time is negative.

`TypeError`:

- `type` isn't a msgspec `Struct` or pydantic `BaseModel` class;
- `claims` isn't a dict, `Struct` or `BaseModel`;
- `token` isn't a `str` or `bytes`;
- `audience` or `issuer` (on a key, client or `decode` call) isn't a `str` or iterable of them;
- `leeway` isn't a number or a `timedelta`;
- a key's `kid`, or one in `encode`'s `header`, isn't a `str`;
- `jwks` is given something other than a `PrivateKey` or `PublicKey`, such as a `SecretKey`.

`OSError` (`FileNotFoundError`, `PermissionError`, ...): `from_path` couldn't read the file.
