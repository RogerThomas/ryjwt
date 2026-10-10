# Encoding and decoding

`SecretKey` and `PrivateKey` can `encode` and `decode`; `PublicKey` and `JWKSClient` can only
`decode`. The arguments are the same everywhere.

## Encoding

`encode(claims, *, algorithm=None, header=None)` signs `claims` and returns the token as a `str`.

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(64), algorithms=["HS256", "HS512"])

token = key.encode({"sub": "user-1"}, algorithm="HS512", header={"kid": "key-1"})
```

- **`claims`**: a dict, a msgspec `Struct` or a pydantic `BaseModel`. A Struct or model is
  serialised by its own library and must give a JSON object. Models use field aliases unless
  their config sets `serialize_by_alias=False`.
- **`algorithm`**: one of the key's `algorithms`. Optional if the key has only one.
- **`header`**: extra header fields, such as a `kid` (must be a str). Singular, as a token has one
  header (PyJWT says `headers`).

ryjwt sets `alg` itself, and `"typ": "JWT"` unless `header` sets `typ`. It won't make a token `decode` would
reject: `alg`, `crit` or `b64` in `header`, or over 64 fields, is a `ValueError`.

## Decoding

`decode(token, *, type=None, audience=None, issuer=None, leeway=0)` verifies `token` (`str` or
`bytes`) and returns its claims. `audience` and `issuer` usually go [on the
key](#on-the-key-or-for-one-call) instead.

=== "msgspec"

    ```python {data-uv-extra="msgspec"}
    import secrets
    import time

    import msgspec
    import ryjwt


    class Claims(msgspec.Struct):
        sub: str
        aud: str
        exp: int


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")
    token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})

    claims = key.decode(token, type=Claims)
    assert claims.sub == "user-1"
    ```

=== "pydantic"

    ```python {data-uv-extra="pydantic"}
    import secrets
    import time

    import pydantic
    import ryjwt


    class Claims(pydantic.BaseModel):
        sub: str
        aud: str
        exp: int


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")
    token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})

    claims = key.decode(token, type=Claims)
    assert claims.sub == "user-1"
    ```

=== "dict"

    ```python {data-uv-extra=""}
    import secrets
    import time

    import ryjwt

    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")
    token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})

    claims = key.decode(token)
    assert claims["sub"] == "user-1"
    ```

`decode` checks the header's `alg` is one of the key's `algorithms`, then the signature. Only then
does it read the payload, into a dict or a [`type`](#typed-claims), and check the claims below.
Any failure is an [`InvalidTokenError`][ryjwt.InvalidTokenError] ([Errors](errors.md) lists the
kinds).

### Claims checks

| claim | checked | rejected when | raises |
| :-- | :-- | :-- | :-- |
| `exp` (expiry) | if present | it has passed | [`ExpiredSignatureError`][ryjwt.ExpiredSignatureError] |
| `nbf` ("not before") | if present | it's still to come | [`ImmatureSignatureError`][ryjwt.ImmatureSignatureError] |
| `aud` (who it's for) | always | it doesn't match `audience` | [`InvalidAudienceError`][ryjwt.InvalidAudienceError] |
| `iss` (who issued it) | only if you set `issuer` | it doesn't match `issuer` | [`InvalidIssuerError`][ryjwt.InvalidIssuerError] |

**`exp` and `nbf`** are seconds since 1970 (UTC); a non-number is rejected too. Neither is
required, so a token without `exp` never expires. To require them, make them required fields of a
[`type`](#typed-claims).

**`aud`** is a string or list of strings. With an `audience`, the token must have a matching `aud`.
Without one, a token with an `aud` is rejected: it's meant for some service, and ryjwt won't
assume it's yours.

**`iss`** is a string. `audience` and `issuer` may also be lists (any iterable): any one may match.

**`leeway`** allows for clock skew between the issuer and you: seconds or a `timedelta`, added to
both `exp` and `nbf`. Negative or infinite is a `ValueError`.

```python
import secrets
import time
from datetime import timedelta

import ryjwt

key = ryjwt.SecretKey(
    secrets.token_bytes(32),
    algorithms=["HS256"],
    audience="my-api",
    issuer=["https://issuer.example/", "https://old-issuer.example/"],
)
token = key.encode({
    "sub": "user-1",
    "aud": ["my-api", "other-api"],
    "iss": "https://issuer.example/",
    "exp": int(time.time()) - 5,  # expired 5 seconds ago
})

claims = key.decode(token, leeway=timedelta(seconds=30))  # so still accepted
```

Other claims, such as `sub`, `iat` or `jti`, aren't checked: check the ones you rely on.

#### On the key, or for one call

`audience` and `issuer` set on the key, as above, apply to every `decode`. Passed to `decode`, they
replace the key's for that call; they aren't added:

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")
token = key.encode({"sub": "user-1", "aud": "admin-api"})

claims = key.decode(token, audience="admin-api")  # checked against "admin-api" only
```

Leaving them out, or passing `None`, uses the key's. You can't switch a check off for one call: use
a second key object for tokens that need different checks.

#### Why `issuer` is optional, but `aud` is strict

The JWT standard requires rejecting a token whose `aud` doesn't name you, but leaves `iss` up to
you. A trusted key usually belongs to one issuer, so a valid signature already says who made the
token.

Not always: some identity providers serve many customers (tenants), each its own issuer, with one
set of keys. A valid signature then proves only the provider made the token, not which tenant. Set
`issuer` whenever you know it, and always when one key or JWKS serves several issuers.

### Headers

`decode` reads two header fields: `alg`, and `kid` (which picks the key in a
[JWKS](keys.md#jwks-documents)). It ignores the rest, including `typ`. It rejects a header that:

- isn't a JSON object, repeats a field, or has over 64 fields;
- has no `alg`, or a non-string one;
- has a non-string `kid`, when the keys have `kid`s to pick from;
- has `crit`, which lists extensions the reader must understand. ryjwt understands none, so the
  standard says to reject the token.

## Inspecting a token without verifying it

`unverified_header`, `unverified_claims` and `unverified_token` read a token without checking the
signature, `exp`, `nbf`, `aud` or `iss`. Anyone can make a token say anything, so what they return
is a claim, not a fact.

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
token = key.encode({"sub": "user-1", "iss": "https://tenant-1.example/"}, header={"kid": "key-1"})

header, claims = ryjwt.unverified_token(token)
assert header["kid"] == "key-1"
assert claims["iss"] == "https://tenant-1.example/"

claims = key.decode(token)  # verified: now you can trust it
```

Use them for debugging and logging, or to pick which key or tenant to verify with: say, reading
`iss` when each tenant has its own keys. Then `decode` with that key, `issuer` set, so the `iss`
you picked by is checked too. Never use them to decide, say, who the user is from `sub`: only
`decode` tells you that. To pick a key by `kid`, [`PublicKey.from_jwks`](keys.md#jwks-documents)
and [`JWKSClient`](jwks-urls.md) already do it.

The token must still be well formed: three base64url parts, with a JSON object as header and
payload. If not, they raise [`DecodeError`][ryjwt.DecodeError]. They return dicts (no `type`).

## Typed claims

Pass a msgspec `Struct` or pydantic `BaseModel` class as `type`, and `decode` returns an instance
of it instead of a dict:

=== "msgspec"

    ```python {data-uv-extra="msgspec"}
    import secrets
    import time

    import msgspec
    import ryjwt


    class Claims(msgspec.Struct):
        sub: str
        exp: int
        roles: list[str] = []


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
    token = key.encode(Claims(sub="user-1", exp=int(time.time()) + 900, roles=["admin"]))

    claims = key.decode(token, type=Claims)
    assert claims.roles == ["admin"]
    ```

=== "pydantic"

    ```python {data-uv-extra="pydantic"}
    import secrets
    import time

    import pydantic
    import ryjwt


    class Claims(pydantic.BaseModel):
        sub: str
        exp: int
        roles: list[str] = []


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
    token = key.encode(Claims(sub="user-1", exp=int(time.time()) + 900, roles=["admin"]))

    claims = key.decode(token, type=Claims)
    assert claims.roles == ["admin"]
    ```

A parametrised generic Struct works too (`type=Claims[int]`). Any other `type` is a `TypeError`.

If the claims don't fit (a missing required field, or a value of the wrong type or out of range),
`decode` raises [`ClaimsValidationError`][ryjwt.ClaimsValidationError]. The message names the
claim; `__cause__` is the msgspec or pydantic `ValidationError`:

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
        assert isinstance(e.__cause__, msgspec.ValidationError)
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
        assert isinstance(e.__cause__, pydantic.ValidationError)
    ```

Your class's own code (a msgspec `__post_init__`, a pydantic validator) runs only after the `exp`,
`nbf`, `aud` and `iss` checks pass.

## Datetime claims

A Struct or model can declare `exp`, `nbf` and `iat` as `datetime` (or `datetime | None`) rather
than seconds since 1970:

=== "msgspec"

    ```python {data-uv-extra="msgspec"}
    import secrets
    from datetime import UTC, datetime, timedelta

    import msgspec
    import ryjwt


    class Claims(msgspec.Struct):
        sub: str
        exp: datetime
        iat: datetime


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
    now = datetime.now(UTC)
    token = key.encode(Claims(sub="user-1", exp=now + timedelta(minutes=15), iat=now))

    claims = key.decode(token, type=Claims)
    assert claims.exp.tzinfo is not None  # a datetime, in UTC
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
        iat: datetime


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
    now = datetime.now(UTC)
    token = key.encode(Claims(sub="user-1", exp=now + timedelta(minutes=15), iat=now))

    claims = key.decode(token, type=Claims)
    assert claims.exp.tzinfo is not None  # a datetime, in UTC
    ```

**Encoding.** A `datetime` in `exp`, `nbf` or `iat` (in a Struct, a model, or at a dict's top
level) is written as whole seconds.

- A naive `datetime` is a `ValueError`: ryjwt won't guess its timezone.
- `datetime`s in other fields are written as usual: a date string from msgspec and pydantic, a
  `TypeError` in a dict.
- `None` is written as `null`, which `decode` rejects for `exp` and `nbf`. To omit it, use
  `omit_defaults=True` on a Struct, or `Field(exclude_if=lambda v: v is None)` in pydantic.

**Decoding.** A `datetime` field gets a UTC `datetime`, fraction included. A dict keeps numbers.

??? note "pydantic and very large times"

    pydantic alone reads numbers from 2e10 on (past the year 2603) as milliseconds, or all numbers
    if the model's `val_temporal_unit` says so. ryjwt passes times to datetime fields in a form
    pydantic can't misread, so they're always seconds. That covers `datetime`, `AwareDatetime` and
    the like, optional or `Annotated`.

## Decoding to a dict: msgspec or jiter

Dicts are read with [msgspec](https://jcristharif.com/msgspec/) if it's installed
(`uv add 'ryjwt[msgspec]'`), as it's faster for typical tokens, else with the built-in
[jiter](https://github.com/pydantic/jiter). Each key picks when created; `unverified_claims` and
`unverified_token` pick at each call.

Both give the same dict for any valid payload and reject the same malformed ones. They differ only
on payloads no real token contains:

- a number too big for a float (`1e400`): msgspec rejects it, jiter reads `inf`;
- nesting over about 200 levels: jiter rejects it, msgspec reads it (up to Python's recursion
  limit).
