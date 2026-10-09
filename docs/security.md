# Security notes

## What ryjwt protects you from

### Algorithm confusion

If a library trusts the algorithm a token's header names, an attacker picks it. The classic
attack sends a service that verifies RS256 an HS256 token "signed" with its public key as the HMAC
secret. Anyone can, as the key is public.

ryjwt doesn't let the token choose:

- Each key object accepts only the algorithms you gave it.
- `PrivateKey`, `PublicKey` and JWKS keys accept only algorithms for their kind of key. A JWKS
  key that names an algorithm accepts only that one.
- A `SecretKey` whose secret looks like a public key is rejected when created.

### Unsigned tokens

ryjwt has no `none` algorithm: it rejects `"alg": "none"` tokens and can't make them.

### Malformed tokens

ryjwt accepts only:

- three parts, in strict base64url: no padding, whitespace or other characters;
- a header that's a JSON object, with at most 64 fields and none repeated;
- no `crit` header field. It lists extensions a reader must understand, and ryjwt understands none.

### Reading before checking the signature

The payload isn't read until the signature checks out. A [typed
claims](encoding-and-decoding.md#typed-claims) class's own code (a msgspec `__post_init__`, a
pydantic validator) runs only once `exp`, `nbf`, `aud` and `iss` have passed too.

### Tokens meant for another service

A token with an `aud` is rejected unless you set `audience` (on the key or `decode`), so a
service that forgot can't accept another service's token.

### Weak keys

Rejected when you create the key object:

- HMAC secrets shorter than the hash, which one token lets an attacker guess offline. Opt out
  with `allow_short_secret=True`.
- RSA keys under 2048 bits or over 8192.
- Small-order Ed25519 public keys, which let anyone forge a signature.

### Bad JWKS documents

A JWKS document is rejected if:

- it contains a private key. A JWKS should publish only public keys, so this one has leaked;
- two keys share a `kid`, so a token's `kid` could pick either;
- an EC key's point isn't on its curve, as in "invalid curve" attacks.

A `JWKSClient` skips bad keys instead, but still rejects the whole document for a private key or
a shared `kid`.

### JWKS URLs

A [`JWKSClient`](jwks-urls.md):

- fetches only over HTTPS, checking the certificate, except plain HTTP to this machine
  (`localhost`, `127.0.0.1` or `[::1]`), which never goes through a proxy;
- rejects URLs that different parsers could read as different hosts;
- doesn't follow redirects;
- gives up on a fetch after 2.5 seconds, even if the server keeps trickling bytes;
- refetches for an unknown `kid` at most once per `cooldown`, so made-up `kid`s can't flood the
  provider;
- stops using expired keys after `max_stale`, if it can't fetch new ones;
- shows only the URL's scheme, host and port in errors, as the path, query and credentials may
  hold secrets.

## What's up to you

- **Allow only the algorithms you use.** The shorter the list, the less can go wrong.
- **Keep secrets secret.** Whoever holds an HMAC secret or private key can make tokens. Give
  services that only check tokens a public key.
- **Set `audience`, and `issuer`.** Without `issuer`, the issuer isn't checked. That matters most
  when one key or JWKS serves several issuers, as with multi-tenant identity providers
  ([why](encoding-and-decoding.md#why-issuer-is-optional-but-aud-is-strict)).
- **Get the JWKS URL right.** A `JWKSClient` trusts whatever keys it serves.
- **Require the claims you rely on.** `exp` and `nbf` are checked only if present, so a token
  without `exp` never expires. Make them required in a [typed
  claims](encoding-and-decoding.md#typed-claims) class.
- **Check everything else you need.** ryjwt doesn't check `sub`, scopes, roles, `iat` or `jti`,
  or the header's `typ`. It doesn't track seen tokens (to stop replays) or revoked ones.
- **Keep `leeway` small**, a minute at most. It extends every token's life by that much.
- **Limit request sizes.** ryjwt doesn't cap token size, so cap your server's request headers.
- **Keep the clock right.** `exp` and `nbf` are checked against the system clock.
