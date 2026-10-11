# Keys and algorithms

A key object holds a key and the algorithms it may be used with. Create it once, at startup, and
reuse it. Pick the class by the key you have:

- [`SecretKey`](#secretkey-hmac-secrets): a shared secret, for `HS256` and friends. Whoever can
  verify a token with it can also make one.
- [`PrivateKey`](#private-and-public-keys): a private key, to sign and verify.
- [`PublicKey`](#private-and-public-keys): a public key, or a [JWKS document](#jwks-documents), to
  verify only.

For keys an identity provider publishes at a URL, use a [`JWKSClient`](jwks-urls.md): it fetches
them and keeps them up to date.

## Algorithms

| algorithm | signature | key |
| :-- | :-- | :-- |
| `HS256`, `HS384`, `HS512` | HMAC with SHA-256, -384, -512 | a shared secret |
| `RS256`, `RS384`, `RS512` | RSA (PKCS#1 v1.5) with SHA-256, -384, -512 | RSA |
| `PS256`, `PS384`, `PS512` | RSA-PSS with SHA-256, -384, -512 | RSA |
| `ES256` | ECDSA with SHA-256 | EC, P-256 curve |
| `ES256K` | ECDSA with SHA-256 | EC, secp256k1 curve |
| `ES384` | ECDSA with SHA-384 | EC, P-384 curve |
| `ES512`, `ES521` | ECDSA with SHA-512 | EC, P-521 curve |
| `EdDSA` | Ed25519 | Ed25519 |

`ES521` is an alias for `ES512`. `EdDSA` means Ed25519 only, not Ed448. There is no `none`
algorithm: every token ryjwt makes or accepts is signed.

### Choosing `algorithms`

Every key class takes `algorithms`: the ones your tokens use.

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(64), algorithms=["HS256", "HS512"])
```

- `decode` rejects any other algorithm, with [`InvalidAlgorithmError`][ryjwt.InvalidAlgorithmError].
- `encode` signs with `algorithm=`, one of them. It's optional when there's only one.
- A `PrivateKey` or `PublicKey` holds one key, so every algorithm must suit it: an RSA key takes
  `RS256` and `PS256`, not `ES256`. A mismatch, an empty list or an unknown name is a `ValueError`.

The names are Literal types, [`HMACAlgorithm`][ryjwt.HMACAlgorithm] and
[`AsymmetricAlgorithm`][ryjwt.AsymmetricAlgorithm], so a type checker catches typos. Annotate your
own lists with them, as a `list[str]` won't type-check:

```python
import ryjwt

ALGORITHMS: list[ryjwt.AsymmetricAlgorithm] = ["RS256", "PS256"]
```

### Setting `audience` and `issuer`

Every key class, and [`JWKSClient`](jwks-urls.md), also takes `audience` and `issuer`: who your
tokens are for, and who issues them. `decode` checks `aud` and `iss` against them:

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(
    secrets.token_bytes(32),
    algorithms=["HS256"],
    audience="my-api",
    issuer="https://issuer.example/",
)
```

- Each is a `str`, or an iterable of them, any one of which may match. Anything else, such as
  `audience=1`, is a `TypeError` when you create the key.
- Without `audience`, a token that has an `aud` is rejected. Without `issuer`, `iss` isn't
  checked, but [you should set it](encoding-and-decoding.md#claims-checks).
- A `decode` call's own `audience` or `issuer` replaces the key's for that call.

## SecretKey: HMAC secrets

[`SecretKey`][ryjwt.SecretKey] takes a shared secret, as `str` or `bytes`. It suits a service
that verifies its own tokens. When other services verify them, use a
[key pair](#private-and-public-keys).

### Secret length

The secret must be at least as long as the hash:

| algorithm | shortest secret |
| :-- | :-- |
| `HS256` | 32 bytes |
| `HS384` | 48 bytes |
| `HS512` | 64 bytes |

With several algorithms, it must suit the longest. A `str` counts in UTF-8 bytes. A shorter
secret is an [`InvalidKeyError`][ryjwt.InvalidKeyError]: anyone with one token could guess it
offline, then forge tokens. Make one with `secrets.token_bytes`:

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])

try:
    ryjwt.SecretKey(b"too short", algorithms=["HS256"])
except ryjwt.InvalidKeyError as e:
    print(e)  # "HS256" needs a secret of at least 32 bytes, got 9 (...)
```

If you're stuck with a short secret (say, from an identity provider), pass
`allow_short_secret=True`. It skips the length check, and only that:

```python
import ryjwt

key = ryjwt.SecretKey("legacy-secret", algorithms=["HS256"], allow_short_secret=True)
```

### Secrets that are rejected

These are an `InvalidKeyError` too:

- An empty secret.
- Anything that looks like a public key: a PEM, an SSH public key, a JWK or JWKS, or a public
  key's or certificate's binary (DER) form, raw or base64-encoded. As an HMAC secret, a public
  key lets anyone sign tokens: the classic "algorithm confusion" attack. The check sees through a
  byte-order mark, leading spaces, and UTF-16 or UTF-32 text.

### Reading a secret from a file

`SecretKey` has no `from_path`: secret files usually end with a newline, and only you know whether
it's part of the secret. Read the file yourself:

<!-- test: with-key-files -->
```python
from pathlib import Path

import ryjwt

key = ryjwt.SecretKey(Path("secret.txt").read_bytes().strip(), algorithms=["HS256"])
```

## Private and public keys

[`PrivateKey`][ryjwt.PrivateKey] signs and verifies. [`PublicKey`][ryjwt.PublicKey] only
verifies: it has no `encode`. Both take a PEM, as `str` or `bytes`, or read one with `from_path`:

<!-- test: with-key-files -->
```python
import ryjwt

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"])
verifier = ryjwt.PublicKey.from_path("public.pem", algorithms=["ES256"])

assert verifier.decode(signer.encode({"sub": "user-1"})) == {"sub": "user-1"}
```

`from_path` lets OS errors (`FileNotFoundError`, ...) through. An unusable key is an
[`InvalidKeyError`][ryjwt.InvalidKeyError].

### Which PEMs are accepted

| class | the PEM starts with |
| :-- | :-- |
| `PrivateKey` | `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` |
| `PublicKey` | `BEGIN PUBLIC KEY` or `BEGIN RSA PUBLIC KEY` |

- A PEM must hold exactly one key. The `EC PARAMETERS` block that `openssl ecparam -genkey`
  writes before the key is skipped.
- Encrypted private keys (`BEGIN ENCRYPTED PRIVATE KEY`) aren't supported.
- `PublicKey` rejects a private key, which shouldn't sit where a public one will do.
  `PrivateKey` rejects a public key: it can't sign with it.

### Keys from the cryptography library

ryjwt doesn't take [cryptography](https://cryptography.io/) key objects. Export them as PEM first:

```python
import ryjwt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

private_key = ed25519.Ed25519PrivateKey.generate()
private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
public_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

signer = ryjwt.PrivateKey(private_pem, algorithms=["EdDSA"])
verifier = ryjwt.PublicKey(public_pem, algorithms=["EdDSA"])
```

### Weak keys

These are rejected up front, rather than failing every token later or, worse, passing a forged
one:

- RSA keys under 2048 bits or over 8192.
- The few special ("small-order") Ed25519 public keys, which accept signatures anyone can make.

## JWKS documents

A JWKS (JSON Web Key Set) is a JSON list of public keys, each with an ID, its `kid`. A token's
header names the `kid` of the key that signed it.

[`PublicKey.from_jwks`][ryjwt.PublicKey.from_jwks] takes the document as JSON (`str` or `bytes`)
or parsed (a `Mapping`). The `PublicKey` it returns verifies each token with the key its `kid`
names:

<!-- test: with-key-files -->
```python
import ryjwt

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"], kid="key-1")
token = signer.encode({"sub": "user-1"})  # its header has the kid "key-1"

# What the issuer publishes: its public key, with the kid "key-1"
document = ryjwt.jwks([signer])
verifier = ryjwt.PublicKey.from_jwks(document, algorithms=["RS256", "ES256"])
claims = verifier.decode(token)
```

- An [unusable document](#documents-that-are-rejected) is an
  [`InvalidKeyError`][ryjwt.InvalidKeyError] from `from_jwks`.
- A token whose `kid` isn't in the document is an [`UnknownKeyError`][ryjwt.UnknownKeyError] from
  `decode`. Like every rejected token, that's an `InvalidTokenError`.

For a JWKS at a URL, use a [`JWKSClient`](jwks-urls.md): it refetches the document when the
provider changes its keys.

A JWKS is as fast as a single PEM key: ryjwt caches which key each token header picks (the
signature is still checked).

### Which keys are used

| key type | curve | used for |
| :-- | :-- | :-- |
| RSA | | `RS256` ... `PS512` |
| EC | P-256 | `ES256` |
| EC | secp256k1 | `ES256K` |
| EC | P-384 | `ES384` |
| EC | P-521 | `ES512`, `ES521` |
| OKP | Ed25519 | `EdDSA` |

- Keys of any other type or curve, and encryption keys (`"use": "enc"`), are ignored entirely:
  one may even share its `kid` with a signing key.
- A key only verifies the algorithms in its row, so a document can safely mix key types.
- A key with an `alg` is used only for that algorithm, and ignored if it isn't in your
  `algorithms`.

### Picking a token's key

- The token's `kid` must match the `kid` of a used key.
- A `kid` may be missing, from the token or from the key, only when the document has a single
  usable key.

### Documents that are rejected

`from_jwks` raises `InvalidKeyError` if the document:

- contains a private key, even in an ignored entry (that key has leaked);
- has two usable keys with the same `kid`;
- has an entry that isn't a valid key: not a JSON object, a field repeated or of the wrong type,
  invalid base64url, values of the wrong length, or an EC point off its curve;
- has a [weak key](#weak-keys);
- has no key usable with your `algorithms`.

??? info "How ryjwt spots a private key"

    A JWK holds a private key if it has any of these fields:

    | fields | what they are |
    | :-- | :-- |
    | `d` | the private part of an RSA, EC or Ed25519 key |
    | `p`, `q`, `dp`, `dq`, `qi`, `oth` | the private factors of an RSA key |
    | `k` | a symmetric (HMAC) secret |

## Publishing your keys

When other services verify your tokens, publish your public keys as a JWKS, usually at
`/.well-known/jwks.json`. They read it with [`PublicKey.from_jwks`][ryjwt.PublicKey.from_jwks] or a
[`JWKSClient`](jwks-urls.md).

Give each key a `kid` when you create it. `encode` writes it into every token's header, so
verifiers know which key to check it with. [`jwks`][ryjwt.jwks] returns the document to serve, as
a dict:

<!-- test: with-key-files -->
```python
import json

import ryjwt

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"], kid="key-1")

body = json.dumps(ryjwt.jwks([signer]))  # serve this, as application/json
```

The document holds only the public keys, never anything that can sign. To export a single key, as
a JWK, call its [`jwk`][ryjwt.PrivateKey.jwk] method.

### Rotating keys

To replace a key without breaking the tokens it has already signed, publish both keys, and sign
with the new one. Drop the old key from the document once its last tokens have expired:

<!-- test: with-key-files -->
```python
import json

import ryjwt

previous = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"], kid="key-1")
current = ryjwt.PrivateKey.from_path("new-private.pem", algorithms=["ES256"], kid="key-2")
old_token = previous.encode({"sub": "user-1"})  # signed before the switch

body = json.dumps(ryjwt.jwks([current, previous]))
new_token = current.encode({"sub": "user-2"})

# A verifier reading the document accepts tokens from both keys
verifier = ryjwt.PublicKey.from_jwks(body, algorithms=["ES256"])
assert verifier.decode(old_token) == {"sub": "user-1"}
assert verifier.decode(new_token) == {"sub": "user-2"}
```

### Keys that can't be published

`jwks` takes `PrivateKey`s and `PublicKey`s. It raises:

- a `ValueError` if it has no keys, or several keys that don't each have their own `kid`: a
  verifier couldn't tell which one signed a token;
- a `TypeError` for a [`SecretKey`](#secretkey-hmac-secrets): whoever has the secret can sign
  tokens, so it must never be published.
