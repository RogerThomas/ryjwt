# JWKS URLs

Identity providers (Auth0, Okta, Entra ID, Google, Keycloak, ...) publish their tokens' public keys
as a [JWKS](keys.md#jwks-documents) at a URL, and replace them from time to time.
[`JWKSClient`][ryjwt.JWKSClient] fetches and caches those keys, refetches them when they change,
and verifies tokens with them. (PyJWT's `PyJWKClient` only fetches the signing key.)

- **You pass** the JWKS URL, the algorithms to accept, and usually `audience` and `issuer`.
- **You get** `decode` (sync), `adecode` (async) and `decode_nowait` (never fetches). They take
  [`PublicKey.decode`][ryjwt.PublicKey.decode]'s arguments and check the same
  [claims](encoding-and-decoding.md#claims-checks).
- **Errors:** a bad token raises [`InvalidTokenError`][ryjwt.InvalidTokenError] (respond 401);
  no keys, because fetching failed, raises [`JWKSFetchError`][ryjwt.JWKSFetchError] (respond
  503). See [Errors](#errors).

It needs no extra dependencies: it fetches with the standard library, sending
`User-Agent: ryjwt/<version>`, as some firewalls refuse urllib's default.

## Using it

Create one client per URL at startup and share it: it's safe across threads and event loops.
Creating it fetches nothing.

=== "msgspec"

    <!-- test: skip, needs a JWKS URL and a token it signed -->
    ```python
    import msgspec
    import ryjwt


    class Claims(msgspec.Struct):
        sub: str
        exp: int


    client = ryjwt.JWKSClient(
        "https://issuer.example/.well-known/jwks.json",
        algorithms=["RS256"],
        audience="my-api",
        issuer="https://issuer.example/",
    )

    claims = client.decode(token, type=Claims)  # in sync code
    claims = await client.adecode(token, type=Claims)  # in async code
    ```

=== "pydantic"

    <!-- test: skip, needs a JWKS URL and a token it signed -->
    ```python
    import pydantic
    import ryjwt


    class Claims(pydantic.BaseModel):
        sub: str
        exp: int


    client = ryjwt.JWKSClient(
        "https://issuer.example/.well-known/jwks.json",
        algorithms=["RS256"],
        audience="my-api",
        issuer="https://issuer.example/",
    )

    claims = client.decode(token, type=Claims)  # in sync code
    claims = await client.adecode(token, type=Claims)  # in async code
    ```

=== "dict"

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

A call's own `audience` or `issuer` replaces the client's: `client.decode(token, audience="admin-api")`.

Set `issuer`, though it's optional. Some providers sign tokens for many tenants with one JWKS URL,
each tenant its own issuer. Without `issuer`, any tenant's token passes. See
[Claims checks](encoding-and-decoding.md#why-issuer-is-optional-but-aud-is-strict).

`decode` and `adecode` fetch when they need to:

| when | the decode |
| :-- | :-- |
| first decode | waits. Call `refresh()` (or `await client.arefresh()`) at startup to spare requests |
| a token's `kid` is unknown (the provider probably added a key) | waits while it refetches |
| the keys have expired | doesn't wait: it uses the old keys while a background fetch runs |

So a slow or failing provider never holds up requests while there are keys.

!!! warning "Use `adecode` in async code"

    `decode` blocks for up to 2.5 seconds while it waits for a fetch, and with it the event loop.
    `adecode` lets the loop run. With fresh keys and a known `kid`, it doesn't wait at all.

## Fetching on your own schedule

To fetch on your own schedule (from a background task, say):

<!-- test: skip, needs a JWKS URL and a token it signed -->
```python
if client.needs_refresh:
    client.refresh()  # or: await client.arefresh()
claims = client.decode_nowait(token)
```

- `decode_nowait` never fetches or waits. Before the first successful fetch, it raises
  `JWKSFetchError`. For an unknown `kid`, it raises [`UnknownKeyError`][ryjwt.UnknownKeyError].
  It uses expired keys up to `max_stale` (see [below](#when-the-provider-is-down)).
- `needs_refresh` is `True` when there are no keys yet, or they've expired.
- `refresh()` fetches now, or joins the fetch already running. It raises `JWKSFetchError` only
  if left with no usable keys.

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
| `cache_lifetime` | 15 minutes | how long keys stay fresh if the response doesn't say |
| `min_cache_lifetime` | 1 minute | the shortest freshness, whatever the response says |
| `max_cache_lifetime` | 1 day | the longest freshness, whatever the response says |
| `cooldown` | 30 seconds | the least time between fetches, after a failure or for an unknown `kid`; also the shortest freshness |
| `max_stale` | 1 day | how long expired keys stay in use while fetches keep failing |

Each takes seconds or a `timedelta`:

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

The response's `Cache-Control: max-age`, less its `Age` (time already spent in a cache on the
way), sets how long keys stay fresh, within the bounds above. As that's at least `cooldown`, even
a "don't cache" provider is fetched at most once per `cooldown`.

### Unknown `kid`s

A token with an unknown `kid` makes `decode` and `adecode` refetch, unless the last fetch was
under `cooldown` ago: then it's rejected with `UnknownKeyError` at once. So a flood of made-up
`kid`s can't make the client hammer the provider.

### When the provider is down

If a fetch fails, the client keeps using its keys, even expired, and retries after `cooldown`, for
up to `max_stale` past their expiry. Then decodes raise `JWKSFetchError` until a fetch succeeds.

`refresh()` too raises only with no keys to fall back on. During the `cooldown` after a failure,
it doesn't fetch: it returns (or, with no keys, raises) at once, and `needs_refresh` stays `True`.

### One fetch at a time

All callers needing a fetch share the one in progress, sync or async, on any thread or event loop.
Fetches run on their own threads, so background refreshes work even with a new event loop per
request (`asyncio.run(...)` each time).

A fetch gets 2.5 seconds in all, DNS lookup included. Then its waiters give up, and it counts as
failed. Trickling bytes can't stretch that. (If the response arrived in time and only reading the
keys ran over, the keys are still used.)

## What it fetches

### Allowed URLs

The URL must be `https://`, or `http://` to `localhost`, `127.0.0.1` or `[::1]`. Anything else is
a `ValueError` when you create the client:

```python
import ryjwt

try:
    ryjwt.JWKSClient("http://issuer.example/jwks.json", algorithms=["RS256"])
except ValueError as e:
    print(e)  # url must be https:// (or http:// to localhost, 127.0.0.1 or [::1]), ...
```

Also rejected, as parsers may read them differently: a user name or password, whitespace, control
or non-ASCII characters, and backslashes. (Some parsers read `http://evil.example\@localhost/` as
`localhost`, others as `evil.example`.) The client checks the host exactly as the fetch reads it.

### How it fetches

- TLS certificates are checked against the system's trusted ones (or `SSL_CERT_FILE`'s).
- `https://` fetches use `HTTPS_PROXY` unless `NO_PROXY` excludes the host, and on macOS and
  Windows the system proxy settings. `http://` fetches (to this machine) never use a proxy.
- Redirects aren't followed: like any non-2xx status, a redirect is a failed fetch.

### Which documents it accepts

A fetched JWKS is read as by [`PublicKey.from_jwks`](keys.md#jwks-documents), except that an
unusable key is skipped rather than failing the document, so one bad key can't take down the rest.
Besides what `from_jwks` ignores, it skips:

- malformed keys;
- weak keys (RSA outside 2048 to 8192 bits, small-order Ed25519 keys);
- entries that aren't JSON objects;
- keys whose `use` isn't `"sig"` (signing). Keys with no `use` are kept.

The fetch still fails if the document isn't valid JSON, holds a private key, has two kept keys
with the same `kid`, or has no usable key.

## Errors

| error | means | respond |
| :-- | :-- | :-- |
| `UnknownKeyError` | the token's `kid` isn't among the keys, even after a refetch: the token's problem | 401 |
| `JWKSFetchError` | fetching failed and there are no keys, or they expired over `max_stale` ago: not the token's fault | 503 |

Any failure counts: a network error, a non-2xx status, an unusable JWKS. Until the `cooldown` is
over, `JWKSFetchError` is raised again without a new request.

The message shows only the URL's scheme, host and port (`https://issuer.example`): the rest may
hold credentials or tokens. The original exception, if any, is its `__cause__`.
