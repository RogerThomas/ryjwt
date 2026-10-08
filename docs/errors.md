# Errors

ryjwt's exceptions fall into three groups. Each tells you how to respond:

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

Every reason `decode` rejects a token is an `InvalidTokenError`. Usually that's all you need to
catch. Catch a subclass when you want to tell the reasons apart, e.g. to tell a client its token
has expired:

```python
import secrets
from typing import Any

import ryjwt

key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")


def authenticate(authorization: str) -> dict[str, Any] | None:
    """The claims of the bearer token in an Authorization header, or None (respond 401)."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    try:
        return key.decode(token)
    except ryjwt.ExpiredSignatureError:
        return None  # the client should get a new token
    except ryjwt.InvalidTokenError:
        return None


assert authenticate("Bearer not-a-token") is None
```

| exception | the token is rejected because |
| :-- | :-- |
| [`DecodeError`][ryjwt.DecodeError] | it's malformed (see below) |
| [`InvalidSignatureError`][ryjwt.InvalidSignatureError] | its signature doesn't match. It's a kind of `DecodeError` |
| [`InvalidAlgorithmError`][ryjwt.InvalidAlgorithmError] | its algorithm isn't one you allowed, or isn't one its key can be used with |
| [`UnknownKeyError`][ryjwt.UnknownKeyError] | it names a key (`kid`) that isn't in the JWKS |
| [`ExpiredSignatureError`][ryjwt.ExpiredSignatureError] | it has expired (`exp`) |
| [`ImmatureSignatureError`][ryjwt.ImmatureSignatureError] | it isn't valid yet (`nbf`) |
| [`InvalidAudienceError`][ryjwt.InvalidAudienceError] | its audience (`aud`) is wrong or missing |
| [`InvalidIssuerError`][ryjwt.InvalidIssuerError] | its issuer (`iss`) is wrong or missing |
| [`ClaimsValidationError`][ryjwt.ClaimsValidationError] | its claims don't fit the `type` you asked for |
| `InvalidTokenError` itself | its header has a `crit` field, which ryjwt must reject |

Each message says more. The details:

- **`DecodeError`**: the token isn't three dot-separated parts, or a part isn't valid base64url.
  Or the header or payload isn't a JSON object, or the header repeats a field, has more than 64,
  or has a `kid` that isn't a string (when the keys have `kid`s to pick from). Or `exp` or `nbf`
  isn't a number.
- **`InvalidAlgorithmError`**: the header has no `alg`, or one that isn't a string, or isn't in
  the key's `algorithms`. With a JWKS, the key the token picked may also be limited to other
  algorithms.
- **`UnknownKeyError`**: also raised when the JWKS has several keys and the token can't pick one:
  it has no `kid`, or the keys have none.
- **`InvalidAudienceError`**: the token's `aud` doesn't match `audience`, is missing, or isn't a
  string or list of strings. Or the token has an `aud` but you set no `audience`, on the key or
  the call.
- **`InvalidIssuerError`**: you set `issuer`, and the token's `iss` doesn't match it, is missing,
  or isn't a string.
- **`ClaimsValidationError`**: a required field is missing, or a value has the wrong type or is
  out of range. msgspec's or pydantic's `ValidationError` is its `__cause__`.

## Keys you configured: `InvalidKeyError`

`InvalidKeyError` is raised when you create a key object with a key it can't use:

- a PEM that doesn't parse, holds no key or several, or holds the wrong kind (a public key for
  `PrivateKey`, a private one for `PublicKey`);
- a weak key: RSA outside 2048 to 8192 bits, or a small-order Ed25519 key;
- an HMAC secret that's empty, too short, or looks like a public key;
- a JWKS document that [breaks the rules](keys.md#documents-that-are-rejected).

## JWKS URLs: `JWKSFetchError`

A [`JWKSClient`](jwks-urls.md) raises `JWKSFetchError` when it has no usable keys, because
fetching them failed. It's not the token's fault, so it isn't an `InvalidTokenError`: respond 503.

## Python's own exceptions

Calling ryjwt the wrong way raises Python's own exceptions. A type checker catches most of these
before you run anything.

`ValueError`:

- `algorithms` is empty, has a name the class doesn't support, or mixes algorithms one key can't
  serve;
- `encode` has no `algorithm` but the key has several, or one the key doesn't have, or `alg` in
  `headers`;
- a `datetime` claim has no timezone;
- `leeway` is negative or infinite;
- a `JWKSClient`'s URL isn't [allowed](jwks-urls.md#allowed-urls), or one of its times is
  negative.

`TypeError`:

- `type` isn't a msgspec `Struct` or pydantic `BaseModel` class;
- `claims` isn't a dict, `Struct` or `BaseModel`;
- `token` isn't a `str` or `bytes`;
- `audience` or `issuer`, on a key, a client or a `decode` call, isn't a `str` or an iterable of
  them;
- `leeway` isn't a number or a `timedelta`.

`OSError` (`FileNotFoundError`, `PermissionError`, ...): from `from_path`, reading the file.
