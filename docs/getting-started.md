# Getting started

## Pick a key class

Each kind of key has a class. It takes the key and the algorithms it may use, and checks them
once, when created. Create it at startup and reuse it for every token.

| class | key | algorithms | can |
| :-- | :-- | :-- | :-- |
| [`SecretKey`][ryjwt.SecretKey] | a shared secret, `str` or `bytes` | `HS256` `HS384` `HS512` | `encode`, `decode` |
| [`PrivateKey`][ryjwt.PrivateKey] | a private key PEM, `str` or `bytes` | `RS*` `PS*` `ES256` `ES256K` `ES384` `ES512` `ES521` `EdDSA` | `encode`, `decode` |
| [`PublicKey`][ryjwt.PublicKey] | a public key PEM, `str` or `bytes`, or a JWKS | as `PrivateKey` | `decode` |
| [`JWKSClient`][ryjwt.JWKSClient] | a JWKS URL | as `PrivateKey` | `decode` |

[Keys and algorithms](keys.md) has the details.

## Encode and decode

A `SecretKey` signs and verifies. The claims can be a `Struct`, a `BaseModel`
([typed claims](#typed-claims)) or a dict:

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
    claims = key.decode(token)  # a dict
    ```

A real service loads the secret from its configuration: at least 32 bytes for `HS256`
([HMAC secrets](keys.md#secretkey-hmac-secrets)).

`decode` checks the signature, then that the token hasn't expired (`exp`) and isn't used too early
(`nbf`). Set `audience` and `issuer` to also check who it's for (`aud`) and who issued it (`iss`):

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

A token with an `aud` claim is rejected unless you set `audience`: ryjwt won't assume it's for
you. `decode` also takes `audience` and `issuer`, replacing the key's for that call.
[Encoding and decoding](encoding-and-decoding.md) covers every check.

## Handle invalid tokens

Every rejection raises an [`InvalidTokenError`][ryjwt.InvalidTokenError]. Respond 401:

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

Its subclasses, in [Errors](errors.md), tell the reasons apart.

## Typed claims

With `type=Claims` ([above](#encode-and-decode)), `decode` returns a `Claims`, and your type
checker knows it.

The class also validates the claims, raising
[`ClaimsValidationError`][ryjwt.ClaimsValidationError] if they don't fit. So a required field
makes its claim required: here, a token without `exp` is rejected. As a dict, it would be accepted,
and never expire.

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

When one service issues tokens and others verify them, use a key pair. For instance, with
OpenSSL:

```console
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

The issuer signs with the `PrivateKey`. Verifiers get only the `PublicKey`, which can't sign:

<!-- test: with-key-files -->
```python
import ryjwt

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"])
token = signer.encode({"sub": "user-1"})

verifier = ryjwt.PublicKey.from_path("public.pem", algorithms=["ES256"])
claims = verifier.decode(token)
```

For tokens from an identity provider (Auth0, Okta, Entra ID, Google, Keycloak, ...), use a
[`JWKSClient`](jwks-urls.md). It fetches the provider's public keys and keeps them up to date.

## Let the type checker help

`algorithms` takes Literals, so a type checker catches a typo or an algorithm that doesn't fit
the key. Use [`HMACAlgorithm`][ryjwt.HMACAlgorithm] and
[`AsymmetricAlgorithm`][ryjwt.AsymmetricAlgorithm] in your own annotations. `PublicKey` has no
`encode`, and `decode(token, type=Claims)` returns a `Claims`. Untyped code gets runtime errors
instead.
