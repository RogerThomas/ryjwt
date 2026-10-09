<p align="center">
  <img src="assets/logo-light.svg#only-light" alt="ryjwt" width="300">
  <img src="assets/logo-dark.svg#only-dark" alt="ryjwt" width="300">
</p>

# ryjwt

Fast, strictly typed JSON Web Tokens for Python, written in Rust.

ryjwt signs and verifies JWTs with HMAC, RSA, RSA-PSS, ECDSA and EdDSA keys, checks the
registered claims (`exp`, `nbf`, `aud`, `iss`), and decodes the claims into a dict, a
[msgspec](https://jcristharif.com/msgspec/) `Struct` or a [pydantic](https://docs.pydantic.dev/)
`BaseModel`. It also fetches, caches and refreshes the keys an identity provider publishes at a JWKS URL.

## Install

```console
uv add ryjwt
```

ryjwt supports Python 3.12, 3.13 and 3.14, including free-threaded 3.14t
([threads](threads.md)). It has no runtime dependencies. Wheels are built for
Linux (glibc and musl, x86_64 and aarch64), macOS (x86_64 and arm64) and Windows (x64).

Two optional extras: `ryjwt[msgspec]` makes decoding to a dict faster, and lets you decode to
`Struct`s; `ryjwt[pydantic]` installs pydantic, to decode to models.

## A first token

Decode the claims into a msgspec `Struct`, a pydantic `BaseModel` or a dict. Pick a tab: the others on
the site follow it. Each example is a whole script, and **Copy for uv** above it copies a command
that runs it, extra and all, with nothing installed first.

=== "msgspec"

    ```python {data-uv-extra="msgspec"}
    import secrets
    from datetime import UTC, datetime, timedelta

    import msgspec
    import ryjwt


    class Claims(msgspec.Struct):
        sub: str
        aud: str
        exp: datetime


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")

    # Tokens store exp in whole seconds, so round it for the round trip to compare equal.
    expires = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=15)
    claims_in = Claims(sub="user-1", aud="my-api", exp=expires)

    token = key.encode(claims_in)
    claims_out = key.decode(token, type=Claims)  # a Claims: signature, exp and aud checked
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
        aud: str
        exp: datetime


    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")

    # Tokens store exp in whole seconds, so round it for the round trip to compare equal.
    expires = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=15)
    claims_in = Claims(sub="user-1", aud="my-api", exp=expires)

    token = key.encode(claims_in)
    claims_out = key.decode(token, type=Claims)  # a Claims: signature, exp and aud checked
    assert claims_in == claims_out
    ```

=== "dict"

    ```python {data-uv-extra=""}
    import secrets
    import time

    import ryjwt

    key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"], audience="my-api")

    token = key.encode({"sub": "user-1", "aud": "my-api", "exp": int(time.time()) + 900})
    claims = key.decode(token)  # a dict: signature, exp and aud checked
    assert claims["sub"] == "user-1"
    ```

[Getting started](getting-started.md) goes on from there.

## Why it's fast

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about a tenth of a second, the Rust and Bun libraries take three to ten times as long, and the other Python libraries from about one and a half to over four seconds](assets/perf-race.svg)

Each bar is one library decoding 100,000 HS256 tokens, in real time. The
[benchmarks](benchmarks/index.md) say how they were measured.

ryjwt is fast because:

- **The work happens in Rust.** Signatures are checked with
  [aws-lc-rs](https://github.com/aws/aws-lc-rs). The token is split and decoded in Rust too.
- **Keys are prepared once.** A key object parses its key when you create it, then reuses it for
  every token.
- **Repeat headers are free.** Tokens from one issuer share a header. After the first verifies,
  ryjwt remembers which key that header picks, so it doesn't parse it again. The signature and
  claims are still checked on every token.
- **Typed claims skip the dict.** With `type=`, your msgspec `Struct` or pydantic `BaseModel` is built
  straight from the payload, with no dict in between. Dicts are built by msgspec if it's
  installed, or by [jiter](https://github.com/pydantic/jiter), which is built in.

With RSA, ECDSA and EdDSA keys, most of the time goes into checking the signature itself, so the
gaps are smaller. For ES256, ryjwt decodes about twice as fast as PyJWT, and a little faster than
the Rust and Bun libraries.
