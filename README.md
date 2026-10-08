# ryjwt

Fast, strictly typed JWTs for Python, written in Rust.

> **Alpha.** The API may still change between releases. Install it with
> `pip install --pre ryjwt` (or `uv add --prerelease allow ryjwt`). It supports Python 3.12, 3.13
> and 3.14, including free-threaded 3.14t ([threads](#threads-and-free-threaded-python)).

## Usage

Pick the class for the key you have. Each takes the key and the algorithms it may be used with,
checks them once, and is then reused for every token:

| class | key | algorithms | can |
| :-- | :-- | :-- | :-- |
| `HMAC` | shared secret, `str` or `bytes` | `HS256` `HS384` `HS512` | `encode`, `decode` |
| `PrivateKey` | private key PEM, `str` or `bytes` | `RS*` `PS*` `ES256` `ES256K` `ES384` `ES512` `ES521` `EdDSA` | `encode`, `decode` |
| `PublicKey` | public key PEM, `str` or `bytes`, or a JWKS | as `PrivateKey` | `decode` |

```python
import os

import ryjwt

hmac = ryjwt.HMAC(os.environ["JWT_SECRET"], algorithms=["HS256"])
token = hmac.encode({"sub": "sub", "aud": "aud", "exp": 4102444800})
claims = hmac.decode(token, audience="aud")  # dict

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"])
verifier = ryjwt.PublicKey.from_path("public.pem", algorithms=["ES256"])
claims = verifier.decode(signer.encode({"sub": "sub"}))
```

`algorithms` is typed with Literals (`ryjwt.HMACAlgorithm`, `ryjwt.AsymmetricAlgorithm`, also usable
in your own annotations), so type checkers catch an algorithm that doesn't fit the key (or a typo),
and `PublicKey` has no `encode` at all. The same mistakes are runtime errors for untyped callers.

- `encode(claims, *, algorithm=None, headers=None)`: `claims` is a dict, a msgspec `Struct` or a
  pydantic `BaseModel`. `algorithm` is required when several are configured.
- `decode(token, *, type=None, audience=None, issuer=None, leeway=0)`: verifies the signature and
  the `exp`/`nbf`/`aud`/`iss` claims, and returns a dict (`type=None`, the default), or an
  instance of `type`: a msgspec `Struct` (a generic one parametrised, e.g. `Claims[int]`) or a
  pydantic `BaseModel`. Any other `type` is a `TypeError`. Claims that don't fit `type` raise
  `ClaimsValidationError`. `leeway` (seconds or a `timedelta`) must be finite and not negative,
  else `ValueError`. Token headers with more than 64 parameters are rejected (`DecodeError`).
- `algorithms`: the configured algorithm names.

### Datetime claims

`exp`, `nbf` and `iat` are NumericDates (RFC 7519): numbers of seconds since the epoch. A Struct or
BaseModel can declare them as `datetime` (or `datetime | None`):

```python
from datetime import UTC, datetime, timedelta

import msgspec


class Claims(msgspec.Struct):
    sub: str
    exp: datetime
    iat: datetime


now = datetime.now(UTC)
token = hmac.encode(Claims(sub="sub", exp=now + timedelta(minutes=15), iat=now))
claims = hmac.decode(token, type=Claims)  # claims.exp is a datetime, in UTC
```

- `encode` writes such a field (and a `datetime` under `exp`, `nbf` or `iat` in a dict's top level)
  as whole seconds, dropping the sub-second part (rounding down). A naive `datetime` (no timezone)
  is a `ValueError`: ryjwt won't guess its timezone. Other `datetime`s keep their usual encoding:
  an RFC 3339 string from msgspec/pydantic, a `TypeError` in a dict.
- `decode` turns the token's number into a timezone-aware UTC `datetime` (keeping any fraction).
  `exp` and `nbf` are validated as before, on the token's numbers, and must still be numbers.
  Decoding to a dict leaves them as numbers.
- A `None` claim is written as `null`, which `decode` rejects for `exp` and `nbf`: leave it out
  with `omit_defaults=True` on the Struct, or `Field(exclude_if=lambda v: v is None)` in pydantic.
- A BaseModel's datetime fields (`datetime`, pydantic's `AwareDatetime` and the like, optional or
  `Annotated`) get the token's number as seconds, however large: pydantic alone would read one
  from 2e10 on (past the year 2603) as milliseconds, or every one, as `val_temporal_unit` says.

### Errors

Every reason `decode` rejects a token is an `InvalidTokenError` (respond 401): `DecodeError`
(malformed, or `InvalidSignatureError`), `InvalidAlgorithmError`, `UnknownKeyError`,
`ExpiredSignatureError`, `ImmatureSignatureError`, `InvalidAudienceError`, `InvalidIssuerError`,
and `ClaimsValidationError`: the claims of a validly signed token don't fit `type` (a required
claim is missing, or one has the wrong type or is out of range). Its message says which claim, and
msgspec's or pydantic's `ValidationError` is chained as its `__cause__`. Unusable keys raise
`InvalidKeyError`, and the JWKS client `JWKSFetchError` (see below). All are `RYJWTError`s.

### Keys

- PEMs: a PEM must hold exactly one key; `EC PARAMETERS` blocks (as `openssl ecparam -genkey` writes)
  are skipped. `PrivateKey` takes an unencrypted PKCS#8 (`BEGIN PRIVATE KEY`), PKCS#1
  (`BEGIN RSA PRIVATE KEY`) or SEC 1 (`BEGIN EC PRIVATE KEY`) key; `PublicKey` a
  SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`) or PKCS#1 (`BEGIN RSA PUBLIC KEY`) key. Each rejects the
  other kind: `PublicKey` won't take a private key and use its public half, because a private key
  should never sit where only a public one is needed.
- `from_path(path, *, algorithms)` reads the PEM from a file. OS errors (`FileNotFoundError`, ...)
  propagate as usual; a file that isn't a usable key raises `InvalidKeyError`.
- cryptography key objects aren't accepted; export them as PEM first, e.g.
  `key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)`.
- RSA keys must be 2048 to 8192 bits (smaller ones are rejected when the key is created, not when
  every token then fails to verify).
- Small-order Ed25519 public keys (the identity point and the other points of order 1, 2, 4 or 8,
  in any encoding) are rejected, from a PEM or a JWKS: anyone could forge signatures they verify.
- `HMAC` secrets mustn't be empty, and are rejected if they look like a public key: a PEM, an SSH
  key (OpenSSH or RFC 4716) or a JWK (which would let anyone holding the public key forge tokens).
- `HMAC` secrets must be at least as long as the hash's output (RFC 7518 §3.2): 32 bytes for
  `HS256`, 48 for `HS384`, 64 for `HS512`, and the longest of these when several algorithms are
  allowed. A `str` is measured in UTF-8 bytes. Anyone holding a single token can brute-force a
  shorter secret offline, then forge tokens of their own. Make one with `secrets.token_bytes(32)`
  (64 for `HS512`). If you can't change a short secret, pass `allow_short_secret=True`, which skips
  only this check.

`HMAC` has no `from_path`: secret files usually end with a newline, and whether that's part of the
secret is your call, not something ryjwt should guess. Read the file yourself:

```python
from pathlib import Path

hmac = ryjwt.HMAC(Path("secret.txt").read_bytes().strip(), algorithms=["HS256"])
```

### JWKS

A JWKS (JSON Web Key Set) is the JSON document of public keys an identity provider (Auth0, Okta,
Entra ID, Google, ...) publishes for verifying its tokens. `PublicKey.from_jwks` takes one as JSON
`str`/`bytes` or an already-parsed `Mapping`, and picks each token's key by its `kid` header:

```python
verifier = ryjwt.PublicKey.from_jwks(jwks_json, algorithms=["RS256", "ES256"])
claims = verifier.decode(token, audience="aud", issuer="https://issuer.example/")
```

The rules are strict:

- Supported keys: `RSA` (`n`, `e`), `EC` (`crv` `P-256`, `P-384`, `P-521` or `secp256k1`, `x`, `y`)
  and `OKP` (`crv` `Ed25519`, `x`). Keys of other types or curves are ignored, as are keys marked
  `"use": "enc"` (any other `use`, or none, is taken for a signing key).
- Each key only verifies algorithms of its own type and curve (an RSA key never verifies an ES256
  token, so a set may safely mix key types). A key's own `alg`, if it has one, is enforced: it only
  verifies tokens with exactly that algorithm, which must also be in `algorithms` (else the key is
  ignored).
- Ignored keys play no part in the rest: an encryption key may share its `kid` with a signing key.
- A document holding private key material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k`, on any
  key, even an ignored one) is rejected, as are duplicate `kid`s among the keys used, entries that
  aren't JSON objects, malformed keys (duplicate members, a non-string `kty`, `kid`, `alg`, `use` or
  `crv`, bad base64url, wrong lengths, EC points not on their curve), RSA keys outside 2048 to 8192
  bits, small-order Ed25519 keys, and a document with no key usable with `algorithms`. All raise
  `InvalidKeyError`.
- A token's `kid` must name one of the keys, else `decode` raises `UnknownKeyError` (an
  `InvalidTokenError`). A token may only leave out its `kid` if the set holds a single usable key,
  and a key without a `kid` can only be picked if it's the only one.

Verifying is as fast as with a single PEM key: the key a token header selects is remembered once a
token with that header verified, so repeat tokens skip the `kid` lookup.

### JWKS URLs

Providers publish their JWKS at a URL and rotate the keys in it. `JWKSClient` fetches it with the
standard library (`urllib.request`, no extra dependencies), keeps it up to date, and decodes like a
`PublicKey.from_jwks`. One client serves sync and async code, used either way:

```python
client = ryjwt.JWKSClient("https://issuer/.well-known/jwks.json", algorithms=["RS256"])

# Automatic: fetches when needed
claims = client.decode(token)  # sync code
claims = await client.adecode(token)  # async code

# Manual: the caller decides when to fetch; decode_nowait never does I/O
if client.needs_refresh:
    client.refresh()  # or: await client.arefresh()
claims = client.decode_nowait(token)
```

All three decode methods take `decode`'s arguments (`type`, `audience`, `issuer`, `leeway`).
`decode` blocks while it waits for a fetch (the first one, or one for an unknown `kid`), so in
async code it would block the event loop: use `adecode` there, which lets the loop run meanwhile.
Call `refresh()` (or `await arefresh()`) at startup to warm the client up, so that the first
requests don't wait for the keys.

- `decode_nowait` decodes with the keys held, and never fetches or waits: it raises
  `JWKSFetchError` before the first successful fetch, or once the keys are over `max_stale` out of
  date (expired keys are used until then), and `UnknownKeyError` for an unknown `kid`, without
  refetching.
- `needs_refresh` is `True` when there are no keys yet, or they've expired. It stays `True` during
  the cooldown after a failed fetch; `refresh()` then returns at once.
- `refresh()` fetches now, joining the fetch in flight if any, unless a fetch failed under
  `cooldown` ago. It raises `JWKSFetchError` only if the client is left without usable keys: a
  failed fetch while the keys held are under `max_stale` out of date keeps them in use, so the
  manual pattern rides out a provider outage as `decode` does.

Create one client per URL and reuse it. Construction does no I/O; the first `decode` (or
`refresh()`) fetches the keys. The URL must be `https://`, or `http://` to `localhost`, `127.0.0.1`
or `[::1]`, without credentials, whitespace, control or non-ASCII characters, or backslashes (which
parsers read differently: `http://evil.example\@localhost/` is a request to `localhost` for some, to
`evil.example` for others). The host is checked as `urllib.request` parses it, the parser the fetch
then uses. Fetches verify the server's TLS certificate with Python's default SSL context (the
system's roots, or `SSL_CERT_FILE`), go through the proxy `HTTPS_PROXY`/`NO_PROXY` (or, on macOS
and Windows, the system's proxy settings) say for `https://` URLs (an `http://` URL is to this
machine, and never goes through a proxy), have 2.5 seconds in all (a server sending a byte now and then can't keep one going), and don't
follow redirects: a 3xx response is a failed fetch. Each fetch runs on a thread of its own.

A fetched JWKS is read as `PublicKey.from_jwks` reads one, except that keys that can't be used are
skipped instead of rejecting the whole set (one bad key in a provider's set mustn't take down the
others): besides the keys `from_jwks` ignores, malformed keys (as listed above), RSA keys outside
2048 to 8192 bits, small-order Ed25519 keys, entries that aren't JSON objects, and keys with a `use`
other than `"sig"` (keys without one are kept). The fetch still fails on invalid JSON, private key
material on any key, duplicate `kid`s among the keys kept, or no usable key at all.

Refresh policy (times are constructor arguments, in seconds or as `timedelta`s):

- Keys stay fresh for the response's `Cache-Control: max-age` less its `Age` (if any), clamped to
  `min_cache_lifetime` (60) and `max_cache_lifetime` (86400), or for `cache_lifetime` (900)
  without `max-age`; but never for less than `cooldown`, so even a zero lifetime fetches at most
  once per `cooldown`. Once they expire, `decode`/`adecode` keep using them while they're refreshed
  in the background: a slow or failing provider never holds up requests that have keys. Only the
  first fetch and unknown `kid`s make a decode wait.
- A token whose `kid` isn't among the keys makes `decode`/`adecode` refetch (the provider likely
  rotated its keys), unless the last fetch was under `cooldown` (30) ago.
- One fetch runs at a time: callers that need one share it, sync or async, on any thread or event
  loop. Callers stop waiting 2.5 seconds after it started (a hung DNS lookup included), and it then
  counts as failed (but if it still gets the keys, having read the response in time, they're
  used). With fresh keys held, `decode` is `PublicKey.decode` plus a time check, and
  `await client.adecode(...)` doesn't suspend, unless the token's `kid` is unknown: then it waits
  for the refetch.
- A failed refetch keeps the keys held and is retried after `cooldown`, but only for `max_stale`
  (86400): once the keys expired longer ago than that and refreshes still fail, decodes raise
  `JWKSFetchError` instead of trusting them.
- Background refreshes run on a thread, not on an event loop, so an event loop per request
  (`asyncio.run(...)` each time) doesn't stop them.

Errors: `UnknownKeyError` (an `InvalidTokenError`) is the token's problem: its `kid` isn't in the
keys, even refetched, so respond 401. `JWKSFetchError` (not an `InvalidTokenError`) means there are
no keys to verify with, because fetching them failed (network, HTTP status including redirects, an
unusable JWKS, or anything else going wrong in the fetch), with no keys cached or the cached ones
over `max_stale` out of date (or, from `decode_nowait`, none fetched yet): it's not the token's
fault, so respond 503. It's raised again, without a request, until `cooldown` is over. Its message
names the JWKS by `scheme://host[:port]` only (no credentials, path or query, which may hold
secrets); the exception the fetch failed with, if any, is chained as its `__cause__`, unchanged.

## Threads and free-threaded Python

`HMAC`, `PrivateKey`, `PublicKey` and `JWKSClient` objects are safe to share between threads:
create one per key (or JWKS URL) and use it from every thread. On free-threaded Python (3.14t, with
its own `cp314t` wheels), ryjwt doesn't need the GIL, and doesn't turn it back on: threads encode
and decode in parallel.

## Decoding to a dict: msgspec or jiter

`decode(token)` parses the payload with [msgspec](https://jcristharif.com/msgspec/) when it's
installed (`pip install ryjwt[msgspec]`, it's faster for typical token sizes), and with
[jiter](https://github.com/pydantic/jiter), built into ryjwt, otherwise. The choice is made once,
when the `HMAC`/`PrivateKey`/`PublicKey` is created.

Both parse every valid JSON payload to the same dict and reject the same malformed ones. They can
differ on exotic payloads that real tokens don't contain, for example:

- numbers too large for a float (`1e400`): msgspec rejects the token, jiter decodes them as `inf`
- nesting deeper than about 200 levels: jiter rejects the token, msgspec decodes it (up to
  Python's recursion limit, past which it's rejected too)

## Development

With [uv](https://docs.astral.sh/uv/), [Task](https://taskfile.dev) and rustup (Python and Rust
versions come from `.python-version` and `rust-toolchain.toml`):

- `task lint`: rustfmt, clippy and ruff, without changing files (`task rustfmt` and `task ruff` fix)
- `task typecheck`: pyright on the package, then the public interface under five type checkers
- `task test`: the test suite, building the extension first if the Rust sources changed. For
  another Python, use a venv of its own: `UV_PROJECT_ENVIRONMENT=.venv-312 uv run --python 3.12
  pytest` (and `.venv-313` with `3.13`, `.venv-314t` with `3.14t`)
- `task licenses`: regenerate `THIRD_PARTY_LICENSES` (with
  [cargo-about](https://github.com/EmbarkStudios/cargo-about)) after a `Cargo.lock` change

CI runs the same tasks, testing on each supported Python.

Releases use [Release Please](https://github.com/googleapis/release-please), so commits to `main`
follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat: …`, `fix: …`,
`feat!: …` for a breaking change). On every push to `main`, the Release workflow
(`.github/workflows/release.yml`) keeps a release PR open that bumps the version in `Cargo.toml`
(the package's version comes from it: `0.0.0-alpha.0` is `0.0.0a0`) and updates `CHANGELOG.md`.
Merging that PR tags the release, and the same workflow run builds the wheels (cp312, cp313, cp314
and cp314t, for each platform) and the sdist, tests each wheel on its own Python, in jobs of their
own, then publishes them to PyPI, checking by SHA-256 that they're the very files tested.
