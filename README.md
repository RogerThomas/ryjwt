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

It signs and verifies JWTs, checks their claims, and decodes them into a dict, msgspec `Struct` or
pydantic `BaseModel`. It also fetches and caches keys from JWKS URLs.

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about 0.15 seconds, jsonwebtoken (Rust) and fast-jwt (Bun) take two to three and a half times as long, and the other libraries from about 1.8 to over 6 seconds](https://raw.githubusercontent.com/RogerThomas/ryjwt/main/assets/perf-race.svg)

One bar per library, decoding 100,000 HS256 tokens in real time
([benchmarks](https://rogerthomas.github.io/ryjwt/benchmarks/)).

## Install

```console
uv add ryjwt
```

Python 3.12 to 3.14, including free-threaded 3.14t.

## Example

```python
import secrets
import time

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")

token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})
claims = key.decode(token)  # signature, exp and aud checked
```

Into a `Struct`, with `uv add 'ryjwt[msgspec]'`:

```python
import secrets
from datetime import UTC, datetime, timedelta

import msgspec
import ryjwt


class Claims(msgspec.Struct):
    sub: str
    exp: datetime


key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])

token = key.encode(Claims(sub="user-1", exp=datetime.now(UTC) + timedelta(minutes=15)))
claims = key.decode(token, type=Claims)  # a Claims, with exp checked
```

A pydantic `BaseModel` works the same, with `uv add 'ryjwt[pydantic]'`.

## Highlights

- **Fast:** over 20 times faster than PyJWT 2.15 on a typical HS256 token, on one core.
- **Every common algorithm:** HMAC, RSA, RSA-PSS, ECDSA and Ed25519 (`HS*`, `RS*`, `PS*`, `ES*`,
  `EdDSA`).
- **Typed:** Literal algorithm names, and `decode(token, type=Claims)` returns a `Claims`.
- **Safe defaults:** keys accept only the algorithms you give them. Weak keys, short secrets and
  malformed tokens are rejected.
- **JWKS URLs:** `JWKSClient` keeps a provider's keys current, from sync or async code, through
  outages.
- **Free-threaded:** objects are thread-safe, and decode in parallel on 3.14t.
