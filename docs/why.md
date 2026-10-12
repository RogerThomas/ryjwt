# Why ryjwt

## From the author

The vision and design of ryjwt are the author's, but AI has been used for nearly 100% of the
implementation, both code and docs (except for this note). It's driven by three modern
developments in the Python ecosystem:

1. Python's modern type system, especially around generics (for example:
   `def decode[T](token: str, *, into: type[T]) -> T`), allows us to build elegant, generic and
   still strictly typed libraries in Python.
2. PyO3 and maturin have changed the game. Writing Python libraries in Rust is now (especially
   with AI) relatively easy, so we get the speed and safety of Rust with the high-level
   abstractions and beauty of a Python interface (pyreqwest, Polars, Daft, etc.).
3. Fast, highly optimised serialisation and validation libraries (msgspec, pydantic) mean data
   crossing an I/O boundary can become a typed object (a `Struct` or `BaseModel`), validated on
   the way in, at very little cost.

JWT encoding/decoding is a near-perfect fit for this. Verifying a token is small, self-contained,
CPU-bound work: split it, base64-decode it, check a signature, parse some small(ish) JSON and check
a few claims. It's pure computation: no network calls, no disk, no locks. It also sits on the hot
path of nearly every authenticated request, so every microsecond saved is saved on every call.
That's exactly where Rust shines, and it all fits behind one typed call: `key.decode(token,
into=Claims)`.

## Compared with PyJWT

- **Faster.** With HS256, ryjwt decodes a typical token over 27 times faster than PyJWT into a
  dict, and over 28 times faster into a `Struct` ([benchmarks](benchmarks/index.md)).
- **Typed claims.** `decode(token, into=Claims)` returns your msgspec `Struct` or pydantic
  `BaseModel`, and your type checker knows it; PyJWT returns a dict
  ([typed claims](encoding-and-decoding.md#typed-claims)).
- **A JWKS client that decodes.** `JWKSClient` keeps a provider's keys current, from sync or async
  code, through outages, and verifies tokens itself; PyJWT's `PyJWKClient` only fetches the
  signing key ([JWKS URLs](jwks-urls.md)). ryjwt also publishes your own keys as a JWKS
  ([publishing your keys](keys.md#publishing-your-keys)).
- **Safe by default.** A key accepts only the algorithms you give it, there's no `none`
  algorithm, and short secrets and weak keys are rejected ([security notes](security.md)).
- **Free-threaded Python.** It's thread-safe and decodes in parallel on 3.14t and 3.15t
  ([threads](threads.md)), with wheels for Linux, macOS and Windows.
