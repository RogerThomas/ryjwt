# Encoding and decoding

`HMAC` and `PrivateKey` can `encode` and `decode`. `PublicKey` and `JWKSClient` can only
`decode`. The arguments are the same everywhere.

## Encoding

`encode(claims, *, algorithm=None, headers=None)` signs `claims` and returns the token, as a
`str`.

```python
import secrets

import ryjwt

key = ryjwt.HMAC(secrets.token_bytes(64), algorithms=["HS256", "HS512"])

token = key.encode({"sub": "user-1"}, algorithm="HS512", headers={"kid": "key-1"})
```

- **`claims`** is a dict, a msgspec `Struct` or a pydantic `BaseModel`. A Struct or model is
  turned into JSON by its own library, and must come out as a JSON object. A model uses its
  fields' aliases, unless its config sets `serialize_by_alias=False`.
- **`algorithm`** is the algorithm to sign with. It must be one of the key's `algorithms`. You can
  leave it out when the key has only one.
- **`headers`** are extra fields for the token's header, such as a `kid`. ryjwt always sets `alg`
  itself; setting it in `headers` is a `ValueError`. It also adds `"typ": "JWT"`, unless `headers`
  sets `typ`.

## Decoding

`decode(token, *, type=None, audience=None, issuer=None, leeway=0)` verifies `token` and returns
its claims. The token is a `str` or `bytes`.

```python
import secrets
import time

import ryjwt

key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"])
token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})

claims = key.decode(token, audience="my-api")
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
| `iss` | who issued the token | only if you pass `issuer` |

**`exp` and `nbf`** are times, as numbers of seconds since 1970 (UTC). A token is rejected once
`exp` has passed ([`ExpiredSignatureError`][ryjwt.ExpiredSignatureError]), or while `nbf` is
still to come ([`ImmatureSignatureError`][ryjwt.ImmatureSignatureError]). If either isn't a
number, the token is rejected too.

Neither is required: a token without `exp` never expires. To require them, make them required
fields of a [`type`](#typed-claims).

**`aud`** is a string, or a list of strings. Pass the audience you expect as `audience`:

- with `audience`, the token must have an `aud`, and one of its values must match;
- without `audience`, a token that has an `aud` is rejected. It's meant for some particular
  service, and ryjwt won't assume it's yours.

**`iss`** is a string. Pass the issuer you expect as `issuer`, and the token must have a
matching `iss`.

`audience` and `issuer` can also be lists (any iterable): then any one of them may match. A
mismatch raises [`InvalidAudienceError`][ryjwt.InvalidAudienceError] or
[`InvalidIssuerError`][ryjwt.InvalidIssuerError].

**`leeway`** allows for clocks that differ a little between the token's issuer and you. It's in
seconds, or a `timedelta`, and extends both `exp` and `nbf`. A negative or infinite `leeway` is a
`ValueError`.

```python
import secrets
import time
from datetime import timedelta

import ryjwt

key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"])
token = key.encode({
    "sub": "user-1",
    "aud": ["my-api", "other-api"],
    "iss": "https://issuer.example/",
    "exp": int(time.time()) - 5,  # expired 5 seconds ago
})

claims = key.decode(
    token,
    audience="my-api",
    issuer=["https://issuer.example/", "https://old-issuer.example/"],
    leeway=timedelta(seconds=30),  # so still accepted
)
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

There's no way to read a token's header or claims without verifying it.

## Typed claims

By default, `decode` returns a dict. Pass a msgspec `Struct` or a pydantic `BaseModel` class as
`type`, and it returns an instance of that class instead:

```python
import secrets
import time

import pydantic
import ryjwt


class Claims(pydantic.BaseModel):
    sub: str
    exp: int
    roles: list[str] = []


key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"])
token = key.encode(Claims(sub="user-1", exp=int(time.time()) + 900, roles=["admin"]))

claims = key.decode(token, type=Claims)
assert claims.roles == ["admin"]
```

A generic Struct works too, parametrised: `type=Claims[int]`. Any other `type` is a `TypeError`.

If the claims don't fit the class, `decode` raises
[`ClaimsValidationError`][ryjwt.ClaimsValidationError]. That happens when a required field is
missing, or a value has the wrong type or is out of range. The message names the claim. The
original msgspec or pydantic `ValidationError` is its `__cause__`:

```python
import secrets

import msgspec
import ryjwt


class Claims(msgspec.Struct):
    sub: str
    exp: int


key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"])
token = key.encode({"sub": "user-1"})  # no exp

try:
    key.decode(token, type=Claims)
except ryjwt.ClaimsValidationError as e:
    print(e)  # Claims don't match Claims: Object missing required field `exp`
    assert isinstance(e.__cause__, msgspec.ValidationError)
```

Your class's own code (a msgspec `__post_init__`, a pydantic validator) only runs for tokens
whose `exp`, `nbf`, `aud` and `iss` checks passed.

## Datetime claims

`exp`, `nbf` and `iat` are times. In the token, they're numbers of seconds since 1970. In a
Struct or model, you can declare them as `datetime`s instead (or `datetime | None`):

```python
import secrets
from datetime import UTC, datetime, timedelta

import msgspec
import ryjwt


class Claims(msgspec.Struct):
    sub: str
    exp: datetime
    iat: datetime


key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"])
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
when you create it.

Both give the same dict for every valid payload, and reject the same malformed ones. They only
differ on payloads no real token contains:

- a number too large for a float (`1e400`): msgspec rejects the token, jiter reads it as `inf`;
- nesting more than about 200 levels deep: jiter rejects the token, msgspec reads it (up to
  Python's recursion limit).
