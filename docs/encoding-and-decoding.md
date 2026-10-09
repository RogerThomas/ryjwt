# Encoding and decoding

`SecretKey` and `PrivateKey` can `encode` and `decode`. `PublicKey` and `JWKSClient` can only
`decode`. The arguments are the same everywhere.

## Encoding

`encode(claims, *, algorithm=None, header=None)` signs `claims` and returns the token, as a
`str`.

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(64), algorithms=["HS256", "HS512"])

token = key.encode({"sub": "user-1"}, algorithm="HS512", header={"kid": "key-1"})
```

- **`claims`** is a dict, a msgspec `Struct` or a pydantic `BaseModel`. A Struct or model is
  turned into JSON by its own library, and must come out as a JSON object. A model uses its
  fields' aliases, unless its config sets `serialize_by_alias=False`.
- **`algorithm`** is the algorithm to sign with. It must be one of the key's `algorithms`. You can
  leave it out when the key has only one.
- **`header`** holds extra fields for the token's header, such as a `kid`. ryjwt always sets `alg`
  itself; setting it in `header` is a `ValueError`. It also adds `"typ": "JWT"`, unless `header`
  sets `typ`.

`header` is singular: a token has one header, and these are fields added to it (PyJWT calls this
argument `headers`).

## Decoding

`decode(token, *, type=None, audience=None, issuer=None, leeway=0)` verifies `token` and returns
its claims. The token is a `str` or `bytes`. You'd usually set `audience` and `issuer` [on the
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

`decode` works in this order:

1. It reads the header, and checks its `alg` is one of the key's `algorithms`.
2. It checks the signature.
3. It reads the payload, into a dict or an instance of [`type`](#typed-claims).
4. It checks the claims below.

The payload is only read once the signature has checked out. Anything wrong is an
[`InvalidTokenError`][ryjwt.InvalidTokenError]; [Errors](errors.md) lists the kinds.

### Claims checks

| claim | what it is | checked |
| :-- | :-- | :-- |
| `exp` | when the token expires | if the token has one |
| `nbf` | when the token becomes valid ("not before") | if the token has one |
| `aud` | who the token is for (the audience) | always |
| `iss` | who issued the token | only if you set `issuer` |

**`exp` and `nbf`** are times, as numbers of seconds since 1970 (UTC). A token is rejected once
`exp` has passed ([`ExpiredSignatureError`][ryjwt.ExpiredSignatureError]), or while `nbf` is
still to come ([`ImmatureSignatureError`][ryjwt.ImmatureSignatureError]). If either isn't a
number, the token is rejected too.

Neither is required: a token without `exp` never expires. To require them, make them required
fields of a [`type`](#typed-claims).

**`aud`** is a string, or a list of strings. Set the audience you expect as `audience`:

- with an `audience`, the token must have an `aud`, and one of its values must match;
- without one, a token that has an `aud` is rejected. It's meant for some particular service,
  and ryjwt won't assume it's yours.

**`iss`** is a string. Set the issuer you expect as `issuer`, and the token must have a matching
`iss`. Without an `issuer`, `iss` isn't checked.

`audience` and `issuer` can also be lists (any iterable): then any one of them may match. A
mismatch raises [`InvalidAudienceError`][ryjwt.InvalidAudienceError] or
[`InvalidIssuerError`][ryjwt.InvalidIssuerError].

#### On the key, or for one call

Set `audience` and `issuer` once, when you create the key. Every `decode` then checks them:

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

`decode` takes `audience` and `issuer` too. A value you pass there replaces the key's for that
call. It isn't added to it:

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")
token = key.encode({"sub": "user-1", "aud": "admin-api"})

claims = key.decode(token, audience="admin-api")  # checked against "admin-api" only
```

Leaving them out, or passing `None`, uses the key's. You can't switch a check off for one call.
If some tokens need different checks, create a second key object for them.

#### Why `issuer` is optional, but `aud` is strict

The JWT standard says a service must reject a token whose `aud` doesn't name it. It leaves
checking `iss` up to you. And a key you trust usually belongs to one issuer: if the signature is
valid, that issuer made the token.

That isn't always true. Some identity providers serve many customers (tenants) with one set of
keys, and each tenant is its own issuer. A valid signature then only tells you the provider made
the token, not which tenant it's from. Set `issuer` whenever you know it, and always when one key
or JWKS serves several issuers.

**`leeway`** allows for clocks that differ a little between the token's issuer and you. It's in
seconds, or a `timedelta`, and extends both `exp` and `nbf`. A negative or infinite `leeway` is a
`ValueError`.

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

Other claims, such as `sub`, `iat` or `jti`, aren't checked: check the ones you rely on yourself.

### Headers

`decode` uses two fields of the token's header: `alg`, the algorithm, and `kid`, which picks the
key in a [JWKS](keys.md#jwks-documents). It rejects a header that:

- isn't a JSON object, or repeats a field;
- has more than 64 fields;
- has no `alg`, or an `alg` that isn't a string;
- has a `kid` that isn't a string, when the keys have `kid`s to pick from;
- has a `crit` field. `crit` lists extensions the token requires its reader to understand. ryjwt
  understands none, so the standard says it must reject the token.

It ignores any other fields, including `typ`.

## Inspecting a token without verifying it

`unverified_header`, `unverified_claims` and `unverified_token` read a token without checking
anything: not the signature, and not `exp`, `nbf`, `aud` or `iss`. Anyone can make a token that
says anything, so treat what they return as a claim the token makes, not a fact.

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

They're fine for:

- debugging and logging;
- picking which key or tenant to verify with: for example, reading `iss` when each tenant of a
  multi-tenant service has its own keys. Then verify the token with that key's `decode`, and set
  `issuer` on it, so the `iss` you picked by is checked too.

Never use anything they return as a fact, such as `sub` to decide who the user is. Only `decode`
tells you that.

You don't need them to pick a key by `kid`: [`PublicKey.from_jwks`](keys.md#jwks-documents) and
[`JWKSClient`](jwks-urls.md) already do that.

The token must still be well formed, as for `decode`: three parts of base64url, with a JSON object
in both the header and the payload. If it isn't, they raise
[`DecodeError`][ryjwt.DecodeError]. They return dicts: there's no `type` argument.

## Typed claims

By default, `decode` returns a dict. Pass a msgspec `Struct` or a pydantic `BaseModel` class as
`type`, and it returns an instance of that class instead:

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

A generic Struct works too, parametrised: `type=Claims[int]`. Any other `type` is a `TypeError`.

If the claims don't fit the class, `decode` raises
[`ClaimsValidationError`][ryjwt.ClaimsValidationError]. That happens when a required field is
missing, or a value has the wrong type or is out of range. The message names the claim. The
original msgspec or pydantic `ValidationError` is its `__cause__`:

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

Your class's own code (a msgspec `__post_init__`, a pydantic validator) only runs for tokens
whose `exp`, `nbf`, `aud` and `iss` checks passed.

## Datetime claims

`exp`, `nbf` and `iat` are times. In the token, they're numbers of seconds since 1970. In a
Struct or model, you can declare them as `datetime`s instead (or `datetime | None`):

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

**Encoding.** A `datetime` in `exp`, `nbf` or `iat` is written as a number of seconds. That's in
a Struct or model, or at the top level of a dict. Fractions of a second are dropped.

- The `datetime` must have a timezone: a naive one is a `ValueError`. ryjwt won't guess its
  timezone.
- `datetime`s in other fields are written as usual: as a date string by msgspec and pydantic, or
  a `TypeError` in a dict.
- A `None` is written as `null`, and `decode` rejects a `null` `exp` or `nbf`. To leave out a
  claim that's `None`, use `omit_defaults=True` on a Struct, or
  `Field(exclude_if=lambda v: v is None)` in pydantic.

**Decoding.** A `datetime` field gets the token's number as a UTC `datetime`, fraction included.
In a dict, the claims stay numbers.

??? note "pydantic and very large times"

    pydantic on its own reads a number from 2e10 on (past the year 2603) as milliseconds, not
    seconds, or reads every number that way if the model's `val_temporal_unit` setting says so.
    ryjwt passes the time to a model's datetime fields in a form pydantic can't misread, so it's
    always seconds. That holds for `datetime`, pydantic's `AwareDatetime` and the like, optional
    or `Annotated`.

## Decoding to a dict: msgspec or jiter

`decode` reads the payload into a dict with [msgspec](https://jcristharif.com/msgspec/) if it's
installed (`uv add 'ryjwt[msgspec]'`), as it's faster for typical tokens. Otherwise it uses
[jiter](https://github.com/pydantic/jiter), which is built into ryjwt. Each key object picks one
when you create it. `unverified_claims` and `unverified_token` read the payload the same way,
picking at each call.

Both give the same dict for every valid payload, and reject the same malformed ones. They only
differ on payloads no real token contains:

- a number too large for a float (`1e400`): msgspec rejects the token, jiter reads it as `inf`;
- nesting more than about 200 levels deep: jiter rejects the token, msgspec reads it (up to
  Python's recursion limit).
