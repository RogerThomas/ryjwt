# JWKS URLs

Identity providers (Auth0, Okta, Entra ID, Google, Keycloak, ...) publish the public keys for their
tokens as a [JWKS](keys.md#jwks-documents) at a URL, and replace the keys from time to time.
[`JWKSClient`][ryjwt.JWKSClient] verifies tokens with those keys. It fetches them, caches them,
and fetches them again when they change.

- **You pass** the JWKS URL, the algorithms to accept, and usually the `audience` and `issuer` to
  check tokens against.
- **You get** `decode` (for sync code), `adecode` (for async code) and `decode_nowait` (never
  fetches). They take the same arguments as [`PublicKey.decode`][ryjwt.PublicKey.decode], and
  check the same [claims](encoding-and-decoding.md#claims-checks).
- **What can go wrong:**
    - an invalid token raises an [`InvalidTokenError`][ryjwt.InvalidTokenError], as with any key:
      respond 401;
    - no keys to verify with, because fetching them failed, raises
      [`JWKSFetchError`][ryjwt.JWKSFetchError]: respond 503 (see [Errors](#errors)).

It fetches with Python's standard library, so it needs no extra dependencies.

## Using it

Create one client per URL, when your service starts, and use it for every request. It's safe to
share between threads and event loops. Creating it doesn't fetch anything.

<!-- test: skip, needs a JWKS URL and a token it signed -->
```python
import ryjwt

client = ryjwt.JWKSClient(
    "https://issuer.example/.well-known/jwks.json",
    algorithms=["RS256"],
    audience="my-api",
    issuer="https://issuer.example/",
)

claims = client.decode(token)  # in sync code
claims = await client.adecode(token)  # in async code
```

Every decode checks tokens against the client's `audience` and `issuer`. A decode can pass its
own, which replace the client's for that call: `client.decode(token, audience="admin-api")`.

Set `issuer` even though it's optional. Some providers sign tokens for many customers (tenants)
with the keys of one JWKS URL, and each tenant is its own issuer. Without `issuer`, a token from
any of them would be accepted. [Claims checks](encoding-and-decoding.md#why-issuer-is-optional-but-aud-is-strict)
explains more.

`decode` and `adecode` fetch the keys when they need to:

- **The first time.** The first decode waits for the keys. Call `refresh()` (or
  `await client.arefresh()`) at startup, so the first requests don't have to.
- **When a token names a `kid` the client hasn't got.** The provider has probably added a key, so
  the decode waits while the client fetches the keys again.
- **When the keys expire.** The decode doesn't wait: it uses the keys it has, while a background
  fetch gets new ones. A slow or failing provider never holds up requests while there are keys.

!!! warning "Use `adecode` in async code"

    `decode` blocks while it waits for a fetch, for up to 2.5 seconds. In async code, that blocks
    the event loop, and every other request with it. `adecode` lets the loop run meanwhile. When
    the client has fresh keys and knows the token's `kid`, `adecode` doesn't wait at all.

## Fetching on your own schedule

If you'd rather decide when the client fetches (from a background task, say), use
`decode_nowait`, `needs_refresh` and `refresh()`:

<!-- test: skip, needs a JWKS URL and a token it signed -->
```python
if client.needs_refresh:
    client.refresh()  # or: await client.arefresh()
claims = client.decode_nowait(token)
```

- `decode_nowait` decodes with the keys the client has. It never fetches, and never waits.
    - Before the first successful fetch, it raises `JWKSFetchError`.
    - For a token whose `kid` it doesn't know, it raises
      [`UnknownKeyError`][ryjwt.UnknownKeyError], without fetching.
    - It keeps using expired keys, up to `max_stale` (see [below](#when-the-provider-is-down)).
- `needs_refresh` is `True` when the client has no keys yet, or they've expired.
- `refresh()` fetches the keys now. If a fetch is already running, it waits for that one instead.
  It raises `JWKSFetchError` only if the client is left with no usable keys.

```python
import ryjwt

client = ryjwt.JWKSClient("https://issuer.example/.well-known/jwks.json", algorithms=["RS256"])
assert client.needs_refresh  # nothing fetched yet

try:
    client.decode_nowait("header.payload.signature")
except ryjwt.JWKSFetchError as e:
    print(e)  # No keys fetched from https://issuer.example yet: call refresh() first
```

## How long keys are kept

| setting | default | what it does |
| :-- | :-- | :-- |
| `cache_lifetime` | 15 minutes | how long fetched keys stay fresh, if the response doesn't say |
| `min_cache_lifetime` | 1 minute | the shortest time keys stay fresh, whatever the response says |
| `max_cache_lifetime` | 1 day | the longest time keys stay fresh, whatever the response says |
| `cooldown` | 30 seconds | the least time between fetches, after a failed fetch or for an unknown `kid` |
| `max_stale` | 1 day | how long expired keys stay in use while fetching new ones keeps failing |

Each is a number of seconds or a `timedelta`:

```python
from datetime import timedelta

import ryjwt

client = ryjwt.JWKSClient(
    "https://issuer.example/.well-known/jwks.json",
    algorithms=["RS256", "ES256"],
    cache_lifetime=timedelta(minutes=5),
    max_stale=timedelta(hours=6),
)
```

### Freshness

Most providers say how long to cache their keys, in the response's `Cache-Control: max-age`
header. The client uses that, less the response's `Age` header (how long a cache in between has
held it already). The result is kept between `min_cache_lifetime` and `max_cache_lifetime`.
Without `max-age`, keys stay fresh for `cache_lifetime`.

Keys always stay fresh for at least `cooldown`, so even a provider that says "don't cache" is
fetched at most once per `cooldown`.

### Unknown `kid`s

A token whose `kid` isn't among the keys makes `decode` and `adecode` fetch the keys again. But
not if the last fetch was less than `cooldown` ago: then the token is rejected with
`UnknownKeyError`, without a new fetch. So a flood of tokens with made-up `kid`s can't make the client
hammer the provider.

### When the provider is down

If a fetch fails, the client keeps using the keys it has, even once they've expired. It tries
again after `cooldown`. This goes on for up to `max_stale` after the keys expired. After that,
the keys are too old to trust, and decodes raise `JWKSFetchError` until a fetch succeeds.

`refresh()` works the same way. A failed fetch only raises when there are no keys to fall back
on. During the `cooldown` after a failed fetch, `refresh()` doesn't fetch: it returns at once, or
raises `JWKSFetchError` at once if there are no keys to fall back on. `needs_refresh` stays `True`
meanwhile.

### One fetch at a time

All callers that need a fetch share the one in progress: sync or async, on any thread or event
loop. Each fetch runs on a thread of its own, not on an event loop. Background refreshes keep
working even if you start a new event loop per request (`asyncio.run(...)` each time).

A fetch gets 2.5 seconds in all, DNS lookup included. Then the callers waiting for it give up, and
it counts as failed. A server can't stretch that by sending a byte now and then. (If the response
did arrive in time, and only reading the keys took longer, the keys are still used.)

## What it fetches

### Allowed URLs

The URL must be `https://`. The one exception is `http://` to this machine: `localhost`,
`127.0.0.1` or `[::1]`. Any other URL is a `ValueError` when you create the client:

```python
import ryjwt

try:
    ryjwt.JWKSClient("http://issuer.example/jwks.json", algorithms=["RS256"])
except ValueError as e:
    print(e)  # url must be https:// (or http:// to localhost, 127.0.0.1 or [::1]), ...
```

URLs that different parsers could read differently are rejected too: URLs with a user name or
password, spaces or other whitespace, control characters, non-ASCII characters, or backslashes.
For instance, `http://evil.example\@localhost/` points to `localhost` for some parsers, and to
`evil.example` for others. The client checks the host exactly as the fetch will read it.

### How it fetches

- It checks the server's TLS certificate, against your system's trusted certificates (or the
  ones `SSL_CERT_FILE` names).
- `https://` fetches go through a proxy if `HTTPS_PROXY` says so (unless `NO_PROXY` excludes the
  host). On macOS and Windows, the system's proxy settings apply too. `http://` fetches, to this
  machine, never use a proxy.
- It doesn't follow redirects. A redirect, like any status other than 2xx, is a failed fetch.

### Which documents it accepts

A fetched JWKS is read like [`PublicKey.from_jwks`](keys.md#jwks-documents) reads one, with one
difference: a key that can't be used is skipped, instead of failing the whole document. One bad
key in a provider's set mustn't take down the others. Skipped, besides the keys `from_jwks`
ignores, are:

- malformed keys;
- weak keys (RSA outside 2048 to 8192 bits, small-order Ed25519 keys);
- entries that aren't JSON objects;
- keys marked for any `use` other than signing (`"sig"`). Keys with no `use` are kept.

The fetch still fails if the document isn't valid JSON, contains a private key, has two kept keys
with the same `kid`, or has no usable key at all.

## Errors

| error | means | respond |
| :-- | :-- | :-- |
| `UnknownKeyError` | The token names a `kid` that isn't among the keys. (The client fetches the keys again first, unless it did so less than `cooldown` ago.) It's the token's problem. | 401 |
| `JWKSFetchError` | There are no keys to verify with: fetching them failed, and there are no cached keys, or they've been expired for over `max_stale`. It's not the token's fault. | 503 |

A fetch fails on a network error, a status other than 2xx (redirects included), an unusable JWKS,
or anything else going wrong. After a failure, `JWKSFetchError` is raised again without a new
request until the `cooldown` is over.

The error message names the JWKS by its scheme, host and port only, as in
`https://issuer.example`. It leaves out the rest of the URL, which may hold credentials or tokens.
The original exception, if there was one, is the `JWKSFetchError`'s `__cause__`.
