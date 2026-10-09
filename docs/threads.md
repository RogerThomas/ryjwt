# Threads and free-threaded Python

`SecretKey`, `PrivateKey`, `PublicKey` and `JWKSClient` objects are thread-safe: create one per
key or JWKS URL, and share it. Key objects are immutable, apart from caches (of token headers, and
of how to decode each `type`) that threads may fill concurrently. A `JWKSClient` guards its keys
with a lock.

```python
import secrets
from concurrent.futures import ThreadPoolExecutor

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])
tokens = [key.encode({"sub": f"user-{i}"}) for i in range(100)]

with ThreadPoolExecutor(max_workers=4) as pool:
    claims = list(pool.map(key.decode, tokens))

assert claims[42] == {"sub": "user-42"}
```

## Free-threaded Python

On free-threaded Python (3.14t), ryjwt doesn't turn the GIL back on: threads encode and decode
in parallel. Install as usual; uv picks the `cp314t` wheel.

On regular Python, ryjwt holds the GIL while it works, so threads take turns. A call takes about
a microsecond for a typical HS256 token, so this rarely matters. To use several cores, use
processes or the free-threaded build.

## JWKS clients

A [`JWKSClient`](jwks-urls.md) runs one fetch at a time, on its own daemon thread, shared by every
caller: sync or async, on any thread or event loop. Background refreshes need no event loop, so
they work with a loop per request (`asyncio.run(...)` each time) or none.
