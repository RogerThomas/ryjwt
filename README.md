# ryjwt

Fast, strictly typed JSON Web Tokens for Python, written in Rust.

**Documentation: [rogerthomas.github.io/ryjwt](https://rogerthomas.github.io/ryjwt/)**

ryjwt signs and verifies JWTs, checks their claims, and decodes them into a dict, a msgspec
`Struct` or a pydantic model. It also fetches and caches the keys an identity provider publishes
at a JWKS URL.

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about a tenth of a second, the Rust and Bun libraries take three to ten times as long, and PyJWT over three seconds](https://raw.githubusercontent.com/RogerThomas/ryjwt/main/assets/perf-race.svg)

Each bar is one library decoding 100,000 HS256 tokens, in real time. See the
[benchmarks](https://rogerthomas.github.io/ryjwt/benchmarks/) for how they were measured.

> **Alpha.** The API may still change between releases.

## Install

```console
uv add --prerelease allow ryjwt
```

ryjwt supports Python 3.12, 3.13 and 3.14, including free-threaded 3.14t.

## Example

```python
import secrets
import time

import ryjwt

key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"])

token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})
claims = key.decode(token, audience="my-api")  # signature, exp and aud checked
assert claims["sub"] == "user-1"
```

## Highlights

- **Fast.** HS256 tokens decode around 30 times faster than with PyJWT.
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
