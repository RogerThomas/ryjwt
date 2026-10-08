<p align="center">
  <img src="assets/logo-light.svg#only-light" alt="ryjwt" width="300">
  <img src="assets/logo-dark.svg#only-dark" alt="ryjwt" width="300">
</p>

# ryjwt

Fast, strictly typed JSON Web Tokens for Python, written in Rust.

ryjwt signs and verifies JWTs with HMAC, RSA, RSA-PSS, ECDSA and EdDSA keys, checks the
registered claims (`exp`, `nbf`, `aud`, `iss`), and decodes the claims into a dict, a
[msgspec](https://jcristharif.com/msgspec/) `Struct` or a [pydantic](https://docs.pydantic.dev/)
model. It also fetches, caches and refreshes the keys an identity provider publishes at a JWKS URL.

!!! warning "Alpha"

    The API may still change between releases.

## Install

```console
uv add --prerelease allow ryjwt
```

ryjwt supports Python 3.12, 3.13 and 3.14, including free-threaded 3.14t
([threads](threads.md)). It has no runtime dependencies. Wheels are built for
Linux (glibc and musl, x86_64 and aarch64), macOS (x86_64 and arm64) and Windows (x64).

Two optional extras: `ryjwt[msgspec]` makes decoding to a dict faster, and lets you decode to
`Struct`s; `ryjwt[pydantic]` installs pydantic, to decode to models.

## A first token

```python
import secrets
import time

import ryjwt

key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")

token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})
claims = key.decode(token)  # signature, exp and aud checked
assert claims["sub"] == "user-1"
```

[Getting started](getting-started.md) goes on from there.

## Why it's fast

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about a tenth of a second, the Rust and Bun libraries take three to ten times as long, and PyJWT over three seconds](assets/perf-race.svg)

Each bar is one library decoding 100,000 HS256 tokens, in real time. The
[benchmarks](benchmarks/index.md) say how they were measured.

ryjwt is fast because:

- **The work happens in Rust.** Signatures are checked with
  [aws-lc-rs](https://github.com/aws/aws-lc-rs). The token is split and decoded in Rust too.
- **Keys are prepared once.** A key object parses its key when you create it, then reuses it for
  every token.
- **Repeat headers are free.** Tokens from one issuer share a header. After the first, ryjwt
  remembers which key that header picks, and skips reading it again.
- **Typed claims skip the dict.** With `type=`, your msgspec `Struct` or pydantic model is built
  straight from the payload, with no dict in between. Dicts are built by msgspec if it's
  installed, or by [jiter](https://github.com/pydantic/jiter), which is built in.

With RSA, ECDSA and EdDSA keys, most of the time goes into checking the signature itself, so the
gaps are smaller. For ES256, ryjwt decodes about twice as fast as PyJWT, and a little faster than
the Rust and Bun libraries.
