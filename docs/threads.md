# Threads and free-threaded Python

`HMAC`, `PrivateKey`, `PublicKey` and `JWKSClient` objects are safe to share between threads:
create one per key (or JWKS URL), and use it from every thread. The key classes are immutable
once created, apart from internal caches (of token headers, and of how to decode each `type`),
which threads may fill concurrently; a `JWKSClient` guards the keys it fetches with a lock.

```python
import secrets
from concurrent.futures import ThreadPoolExecutor

import ryjwt

key = ryjwt.HMAC(secrets.token_bytes(32), algorithms=["HS256"])
tokens = [key.encode({"sub": f"user-{i}"}) for i in range(100)]

with ThreadPoolExecutor(max_workers=4) as pool:
    claims = list(pool.map(key.decode, tokens))

assert claims[42] == {"sub": "user-42"}
```

## Free-threaded Python

On free-threaded Python (3.14t), ryjwt doesn't need the GIL, and doesn't turn it back on: threads
encode and decode in parallel. Install it as usual; uv picks the `cp314t` wheel.

On the regular, GIL build of Python, ryjwt holds the GIL while it encodes or decodes, so threads
take turns. Each call is short (about a microsecond for a typical HS256 token), so that rarely matters;
use processes, or the free-threaded build, to decode on several cores at once.

## JWKS clients

A [`JWKSClient`](jwks-urls.md) runs one fetch at a time, on a daemon thread of its own, and every
caller that needs the keys shares it, whether it's sync or async, and on whichever thread or event
loop. Background refreshes don't need an event loop at all, so they keep working with an event
loop per request (`asyncio.run(...)` each time), or with none.
