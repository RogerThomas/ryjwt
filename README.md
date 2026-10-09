<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/RogerThomas/ryjwt/main/assets/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/RogerThomas/ryjwt/main/assets/logo-light.svg" alt="ryjwt" width="300">
  </picture>
</p>

# ryjwt

[![PyPI](https://img.shields.io/pypi/v/ryjwt)](https://pypi.org/project/ryjwt/)
[![CI](https://github.com/RogerThomas/ryjwt/actions/workflows/ci.yml/badge.svg)](https://github.com/RogerThomas/ryjwt/actions/workflows/ci.yml)
[![Python versions](https://img.shields.io/pypi/pyversions/ryjwt)](https://pypi.org/project/ryjwt/)
[![License](https://img.shields.io/pypi/l/ryjwt)](https://github.com/RogerThomas/ryjwt/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-rogerthomas.github.io%2Fryjwt-blue)](https://rogerthomas.github.io/ryjwt/)

Fast, strictly typed JSON Web Tokens for Python, written in Rust.

**Documentation: [rogerthomas.github.io/ryjwt](https://rogerthomas.github.io/ryjwt/)**

ryjwt signs and verifies JWTs, checks their claims, and decodes them into a dict, a msgspec
`Struct` or a pydantic `BaseModel`. It also fetches and caches the keys an identity provider publishes
at a JWKS URL.

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about a tenth of a second, the Rust and Bun libraries take three to ten times as long, and the other Python libraries from about one and a half to over four seconds](https://raw.githubusercontent.com/RogerThomas/ryjwt/main/assets/perf-race.svg)

Each bar is one library decoding 100,000 HS256 tokens, in real time. See the
[benchmarks](https://rogerthomas.github.io/ryjwt/benchmarks/) for how they were measured.

## Install

```console
uv add ryjwt
```

ryjwt supports Python 3.12, 3.13 and 3.14, including free-threaded 3.14t.

## Example

```python
import secrets
import time

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")

token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})
claims = key.decode(token)  # signature, exp and aud checked
assert claims["sub"] == "user-1"
```

### Into a msgspec Struct

With `uv add 'ryjwt[msgspec]'`:

```python
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
claims_out = key.decode(token, type=Claims)  # a Claims, with exp checked
assert claims_in == claims_out
```

### Into a pydantic `BaseModel`

With `uv add 'ryjwt[pydantic]'`:

```python
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
claims_out = key.decode(token, type=Claims)  # a Claims, with exp checked
assert claims_in == claims_out
```

## Highlights

- **Fast.** A typical HS256 token decodes around 30 times faster than with PyJWT 2.15, on one core.
- **Every common algorithm.** HMAC, RSA, RSA-PSS, ECDSA and Ed25519 (`HS*`, `RS*`, `PS*`, `ES*`,
  `EdDSA`).
- **Typed.** Algorithm names are Literals, and `decode(token, type=Claims)` returns a `Claims`. A
  type checker catches the mistakes.
- **Safe defaults.** Each key only accepts the algorithms you give it. Weak keys, short secrets
  and malformed tokens are rejected.
- **JWKS URLs.** `JWKSClient` keeps an identity provider's keys up to date, from sync or async
  code, and rides out provider outages.
- **Free-threaded.** Objects are safe to share between threads, and on Python 3.14t they decode in
  parallel.

Read the [documentation](https://rogerthomas.github.io/ryjwt/) to get started.
