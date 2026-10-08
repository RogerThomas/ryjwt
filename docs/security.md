# Security notes

## What ryjwt protects you from

### Algorithm confusion

A token's header says which algorithm signed it. If a library believes it, an attacker can pick
the algorithm. The classic attack: take a service that verifies RS256 tokens with a public key,
and send it an HS256 token "signed" with that public key as the HMAC secret. Anyone can do that,
because the key is public.

ryjwt doesn't let the token choose:

- Each key object only accepts the algorithms you gave it. A token with any other is rejected.
- An `HMAC` secret that looks like a public key is rejected when you create it.
- A `PrivateKey` or `PublicKey` only accepts algorithms for its own kind of key.
- In a JWKS, each key only verifies algorithms for its own kind of key, and only the one it names,
  if it names one.

### Unsigned tokens

There is no `none` algorithm. A token with `"alg": "none"` is rejected, and ryjwt can't make one.

### Malformed tokens

ryjwt only accepts tokens in exactly the expected format:

- three parts, in strict base64url: no padding, no whitespace, no other characters;
- a header that's a JSON object, with no repeated fields and at most 64 of them;
- no `crit` field in the header. It lists extensions a reader must understand, and ryjwt
  understands none.

### Reading before checking the signature

The payload isn't read until the signature has checked out. With [typed
claims](encoding-and-decoding.md#typed-claims), your class's own code (a msgspec `__post_init__`,
a pydantic validator) only runs once `exp`, `nbf`, `aud` and `iss` have passed too.

### Tokens meant for another service

A token with an audience (`aud`) is rejected unless you pass `audience`. A service that forgot to
check can't accept a token meant for another one.

### Weak keys

These are rejected when you create the key object:

- HMAC secrets shorter than the hash: an attacker with one token could guess them offline. (You
  can opt out with `allow_short_secret=True`.)
- RSA keys under 2048 bits (or over 8192).
- Small-order Ed25519 public keys, for which anyone can forge a signature.

### Bad JWKS documents

A JWKS document is rejected if:

- it contains a private key. A JWKS should only publish public keys, so one with a private key in
  it has leaked it;
- two of its keys share a `kid`, so a token's `kid` could pick either;
- an EC key's point isn't on its curve. Such keys are used in "invalid curve" attacks.

A `JWKSClient` skips bad keys rather than rejecting the whole document, but still rejects one
that contains a private key, or two keys that share a `kid`.

### JWKS URLs

A [`JWKSClient`](jwks-urls.md):

- only fetches over HTTPS, checking the server's certificate. The one exception is plain HTTP to
  this machine (`localhost`, `127.0.0.1` or `[::1]`), which never goes through a proxy;
- rejects URLs that different parsers could read as different hosts;
- doesn't follow redirects;
- gives up on a fetch after 2.5 seconds, even if the server keeps sending a byte now and then;
- fetches again for an unknown `kid` at most once per `cooldown`, so made-up `kid`s can't make
  it flood the provider;
- stops using expired keys after `max_stale`, if it can't fetch new ones;
- leaves the URL's path, query and any credentials out of its error messages, as they may hold
  secrets. Only the scheme, host and port are shown.

## What's up to you

- **Allow only the algorithms you use.** The shorter the list, the less there is to go wrong.
- **Keep secrets secret.** An HMAC secret or a private key lets whoever has it make tokens. When
  other services only need to check tokens, give them a public key instead.
- **Pass `audience`, and `issuer`.** Without `issuer`, a token's issuer isn't checked at all.
- **Get the JWKS URL right.** A `JWKSClient` trusts whatever keys its URL serves.
- **Require the claims you rely on.** `exp` and `nbf` are only checked if the token has them, so
  a token without `exp` never expires. Make them required fields of a [typed
  claims](encoding-and-decoding.md#typed-claims) class to reject tokens without them.
- **Check everything else you need.** ryjwt doesn't check `sub`, scopes or roles, `iat`, or `jti`.
  It doesn't keep track of tokens it has seen (to stop replays), or of tokens you've revoked. It
  ignores the header's `typ`.
- **Keep `leeway` small**, a minute at most. It makes every token last that much longer.
- **Limit request sizes.** ryjwt doesn't limit how big a token can be. Cap the size of the request
  headers your server accepts.
- **Keep the clock right.** `exp` and `nbf` are checked against the system clock.
