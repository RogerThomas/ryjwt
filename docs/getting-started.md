# Getting started

## Pick a key class

ryjwt has a class per kind of key. You give it the key, and the algorithms it may be used with.
It checks them once, when you create it. Create it at startup, and use it for every token.

| class | key | algorithms | can |
| :-- | :-- | :-- | :-- |
| [`SecretKey`][ryjwt.SecretKey] | a shared secret, `str` or `bytes` | `HS256` `HS384` `HS512` | `encode`, `decode` |
| [`PrivateKey`][ryjwt.PrivateKey] | a private key PEM, `str` or `bytes` | `RS*` `PS*` `ES256` `ES256K` `ES384` `ES512` `ES521` `EdDSA` | `encode`, `decode` |
| [`PublicKey`][ryjwt.PublicKey] | a public key PEM, `str` or `bytes`, or a JWKS | as `PrivateKey` | `decode` |
| [`JWKSClient`][ryjwt.JWKSClient] | a JWKS URL | as `PrivateKey` | `decode` |

[Keys and algorithms](keys.md) has the details of each.

## Encode and decode

With a shared secret, the same `SecretKey` object signs and verifies. The claims can be a msgspec
`Struct`, a pydantic `BaseModel` ([typed claims](#typed-claims)) or a dict:

=== "msgspec"

    ```python {data-uv-extra="msgspec"}
    import secrets
    from datetime import UTC, datetime, timedelta

    import msgspec
    import ryjwt


    class Claims(msgspec.Struct):
        sub: str
        exp: datetime


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])

    # Tokens store exp in whole seconds, so round it for the round trip to compare equal.
    expires = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=15)
    claims_in = Claims(sub="user-1", exp=expires)

    token = key.encode(claims_in)
    claims_out = key.decode(token, type=Claims)
    assert claims_in == claims_out
    ```

=== "pydantic"

    ```python {data-uv-extra="pydantic"}
    import secrets
    from datetime import UTC, datetime, timedelta

    import pydantic
    import ryjwt


    class Claims(pydantic.BaseModel):
        sub: str
        exp: datetime


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])

    # Tokens store exp in whole seconds, so round it for the round trip to compare equal.
    expires = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=15)
    claims_in = Claims(sub="user-1", exp=expires)

    token = key.encode(claims_in)
    claims_out = key.decode(token, type=Claims)
    assert claims_in == claims_out
    ```

=== "dict"

    ```python {data-uv-extra=""}
    import secrets
    import time

    import ryjwt

    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])

    token = key.encode({"sub": "user-1", "exp": int(time.time()) + 900})
    claims = key.decode(token)
    assert claims["sub"] == "user-1"
    ```

In a real service, the secret comes from your configuration, and is at least 32 bytes long for
`HS256` (see [HMAC secrets](keys.md#secretkey-hmac-secrets)).

`decode` checks the signature. Then it checks the token's times: it mustn't have expired (its
`exp` claim), or be used too early (its `nbf` claim). Set `audience` and `issuer` on the key to
check who the token is for (`aud`) and who issued it (`iss`) as well:

```python
import secrets
import time

import ryjwt

key = ryjwt.SecretKey(
    secrets.token_bytes(32),
    algorithms=["HS256"],
    audience="my-api",
    issuer="https://issuer.example/",
)
token = key.encode({
    "sub": "user-1",
    "aud": "my-api",
    "iss": "https://issuer.example/",
    "exp": int(time.time()) + 900,
})

claims = key.decode(token)
```

A token with an `aud` claim is rejected unless you set `audience`. It's meant for a particular
service, and ryjwt won't assume it's yours. `decode` can also take its own `audience` and
`issuer`, which replace the key's for that call. [Encoding and decoding](encoding-and-decoding.md)
covers every check.

## Handle invalid tokens

Every reason `decode` rejects a token is an [`InvalidTokenError`][ryjwt.InvalidTokenError].
Catch it, and respond 401.

```python
import secrets
import time

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
expired = key.encode({"sub": "user-1", "exp": int(time.time()) - 60})

try:
    key.decode(expired)
except ryjwt.InvalidTokenError as e:
    print(f"401: {e}")  # 401: Signature has expired
```

[Errors](errors.md) lists the subclasses, for when you need to tell the reasons apart.

## Typed claims

With `type=Claims`, as in the msgspec and pydantic tabs [above](#encode-and-decode), `decode`
returns a `Claims` instead of a dict, and your type checker knows it.

The class also checks the claims. A token whose claims don't fit it is rejected with
[`ClaimsValidationError`][ryjwt.ClaimsValidationError]. So a required field makes its claim
required: here, a token without `exp` is rejected. Decoded to a dict, it would be accepted, and
never expire.

=== "msgspec"

    ```python {data-uv-extra="msgspec"}
    import secrets

    import msgspec
    import ryjwt


    class Claims(msgspec.Struct):
        sub: str
        exp: int


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
    token = key.encode({"sub": "user-1"})  # no exp

    try:
        key.decode(token, type=Claims)
    except ryjwt.ClaimsValidationError as e:
        print(e)  # Claims don't match Claims: Object missing required field `exp`
    ```

=== "pydantic"

    ```python {data-uv-extra="pydantic"}
    import secrets

    import pydantic
    import ryjwt


    class Claims(pydantic.BaseModel):
        sub: str
        exp: int


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
    token = key.encode({"sub": "user-1"})  # no exp

    try:
        key.decode(token, type=Claims)
    except ryjwt.ClaimsValidationError as e:
        print(e)  # Claims don't match Claims: Field required - at `exp`
    ```

## Public-key signatures

When one service issues tokens and others verify them, sign with a private key and verify with
its public key. Make a key pair, for instance with OpenSSL:

```console
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

The issuer signs with a `PrivateKey`. The services that check tokens only get the `PublicKey`,
which can't sign:

<!-- test: with-key-files -->
```python
import ryjwt

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"])
token = signer.encode({"sub": "user-1"})

verifier = ryjwt.PublicKey.from_path("public.pem", algorithms=["ES256"])
claims = verifier.decode(token)
```

If your tokens come from an identity provider (Auth0, Okta, Entra ID, Google, Keycloak, ...),
verify them with a [`JWKSClient`](jwks-urls.md) instead. It fetches the provider's public keys,
and keeps them up to date when the provider changes them.

## Let the type checker help

`algorithms` is typed with Literals ([`HMACAlgorithm`][ryjwt.HMACAlgorithm] and
[`AsymmetricAlgorithm`][ryjwt.AsymmetricAlgorithm], which you can use in your own annotations),
so a type checker catches an algorithm that doesn't fit the key, or a typo. `PublicKey` has no
`encode` at all, and `decode(token, type=Claims)` is typed to return a `Claims`. Untyped callers
get the same mistakes as runtime errors.
