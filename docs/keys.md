# Keys and algorithms

## Algorithms

| algorithm | signature | key | class |
| :-- | :-- | :-- | :-- |
| `HS256`, `HS384`, `HS512` | HMAC with SHA-256, -384, -512 | a shared secret | `SecretKey` |
| `RS256`, `RS384`, `RS512` | RSA (PKCS#1 v1.5) with SHA-256, -384, -512 | RSA | `PrivateKey`, `PublicKey` |
| `PS256`, `PS384`, `PS512` | RSA-PSS with SHA-256, -384, -512 | RSA | `PrivateKey`, `PublicKey` |
| `ES256` | ECDSA with SHA-256 | EC, P-256 curve | `PrivateKey`, `PublicKey` |
| `ES256K` | ECDSA with SHA-256 | EC, secp256k1 curve | `PrivateKey`, `PublicKey` |
| `ES384` | ECDSA with SHA-384 | EC, P-384 curve | `PrivateKey`, `PublicKey` |
| `ES512`, `ES521` | ECDSA with SHA-512 | EC, P-521 curve | `PrivateKey`, `PublicKey` |
| `EdDSA` | Ed25519 | Ed25519 | `PrivateKey`, `PublicKey` |

`ES512` is the standard name for ECDSA on the P-521 curve. `ES521` is accepted as another name
for it. `EdDSA` means Ed25519 only: Ed448 isn't supported.

There is no `none` algorithm. Every token ryjwt makes or accepts is signed.

### Choosing `algorithms`

Every key class takes `algorithms`: the algorithms the key may be used with. List only the ones
your tokens use.

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(64), algorithms=["HS256", "HS512"])
assert key.algorithms == ["HS256", "HS512"]
```

- `decode` rejects a token signed with any other algorithm, with
  [`InvalidAlgorithmError`][ryjwt.InvalidAlgorithmError].
- `encode` signs with `algorithm=`, which must be one of them. You can leave it out when there's
  only one.
- An empty list, or a name the class doesn't support, is a `ValueError`. Its message lists the
  supported names.
- A `PrivateKey` or `PublicKey` holds one key, so its algorithms must all suit that key. An RSA
  key can be used for both `RS256` and `PS256`, but not for `ES256`. A P-256 key can't be used for
  `ES384`. Asking for both is a `ValueError`.

The names are typed as Literals: [`HMACAlgorithm`][ryjwt.HMACAlgorithm] and
[`AsymmetricAlgorithm`][ryjwt.AsymmetricAlgorithm]. A type checker catches a name the class
doesn't take, or a typo. Use them in your own annotations too:

```python
import ryjwt

ALGORITHMS: list[ryjwt.AsymmetricAlgorithm] = ["RS256", "PS256"]
```

### Setting `audience` and `issuer`

Every key class (and [`JWKSClient`](jwks-urls.md)) also takes `audience` and `issuer`: who your
tokens are for, and who issues them. `decode` checks each token's `aud` and `iss` against them:

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

- Each is a `str`, or a list (any iterable) of them, any one of which may match.
- Without `audience`, a token that has an `aud` is rejected. Without `issuer`, `iss` isn't
  checked, but set it if you can. [Claims checks](encoding-and-decoding.md#claims-checks) says
  why.
- A `decode` call can pass its own `audience` or `issuer`, which replace the key's for that call.
- Anything else, such as `audience=1`, is a `TypeError`, raised when you create the key.

## SecretKey: HMAC secrets

[`SecretKey`][ryjwt.SecretKey] takes a shared secret for the HMAC algorithms (`HS256`, `HS384`,
`HS512`), as `str` or `bytes`. Whoever holds the secret can both sign and verify tokens. That
suits a service that verifies its own tokens. When other services need to verify them, use a
[key pair](#private-and-public-keys) instead.

### Secret length

The secret must be at least as long as the hash's output:

| algorithm | shortest secret |
| :-- | :-- |
| `HS256` | 32 bytes |
| `HS384` | 48 bytes |
| `HS512` | 64 bytes |

With several algorithms, the secret must suit the longest. A `str` secret is measured in UTF-8
bytes. A shorter secret is an [`InvalidKeyError`][ryjwt.InvalidKeyError]: anyone holding a single
token could guess it offline, then sign tokens of their own. Make one with `secrets.token_bytes`:

```python
import secrets

import ryjwt

key = ryjwt.SecretKey(secrets.token_bytes(32), algorithms=["HS256"])

try:
    ryjwt.SecretKey(b"too short", algorithms=["HS256"])
except ryjwt.InvalidKeyError as e:
    print(e)  # "HS256" needs a secret of at least 32 bytes, got 9 (...)
```

If you can't change a short secret (an identity provider gave it to you, say), pass
`allow_short_secret=True`. It skips the length check, and only that:

```python
import ryjwt

key = ryjwt.SecretKey("legacy-secret", algorithms=["HS256"], allow_short_secret=True)
```

### Secrets that are rejected

- An empty secret.
- A secret that looks like a public key: a PEM, an SSH public key, a JWK, or a public key's
  binary (DER) form, raw or base64-encoded. A public key is no secret: if it were used as an HMAC
  secret, anyone who has it could sign tokens. This is the classic "algorithm confusion" attack.

### Reading a secret from a file

`SecretKey` has no `from_path`. Secret files usually end with a newline, and only you know whether
it's part of the secret. Read the file yourself:

<!-- test: with-key-files -->
```python
from pathlib import Path

import ryjwt

key = ryjwt.SecretKey(Path("secret.txt").read_bytes().strip(), algorithms=["HS256"])
```

## Private and public keys

[`PrivateKey`][ryjwt.PrivateKey] signs and verifies. [`PublicKey`][ryjwt.PublicKey] only
verifies: it has no `encode`. Both take a PEM, as `str` or `bytes`, or read one from a file with
`from_path`:

<!-- test: with-key-files -->
```python
import ryjwt

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"])
verifier = ryjwt.PublicKey.from_path("public.pem", algorithms=["ES256"])

assert verifier.decode(signer.encode({"sub": "user-1"})) == {"sub": "user-1"}
```

`from_path` lets the usual OS errors through (`FileNotFoundError`, ...). A key that can't be used
raises [`InvalidKeyError`][ryjwt.InvalidKeyError], whether it came from a file or not.

### Which PEMs are accepted

| class | the PEM starts with |
| :-- | :-- |
| `PrivateKey` | `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` |
| `PublicKey` | `BEGIN PUBLIC KEY` or `BEGIN RSA PUBLIC KEY` |

- A PEM must hold exactly one key. ryjwt skips the `EC PARAMETERS` block that
  `openssl ecparam -genkey` writes before the key.
- Encrypted private keys (`BEGIN ENCRYPTED PRIVATE KEY`) aren't supported.
- `PublicKey` rejects a private key. It could use the key's public half, but a private key should
  never sit where only a public one is needed. Pass the public key instead.
- `PrivateKey` rejects a public key: it couldn't sign with it.

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

These keys are rejected when you create the key object. Otherwise every token would fail to
verify later, or worse, a forged one could pass:

- RSA keys smaller than 2048 bits, or larger than 8192.
- A handful of special Ed25519 public keys (the "small-order" points). Anyone can make a signature
  that such a key accepts.

## JWKS documents

Identity providers publish the public keys for their tokens as a JWKS (JSON Web Key Set): a JSON
document with a list of keys, each with an ID, its `kid`. A token's header names the `kid` of the
key that signed it.

[`PublicKey.from_jwks`][ryjwt.PublicKey.from_jwks] takes such a document, as JSON (`str` or
`bytes`) or already parsed (a `Mapping`). It returns a `PublicKey` that may hold several keys,
and verifies each token with the key its `kid` names:

<!-- test: with-key-files -->
```python
from pathlib import Path

import ryjwt

signer = ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"])
token = signer.encode({"sub": "user-1"}, header={"kid": "key-1"})

# jwks.json lists the public half of private.pem, with the kid "key-1"
verifier = ryjwt.PublicKey.from_jwks(Path("jwks.json").read_bytes(), algorithms=["RS256", "ES256"])
claims = verifier.decode(token)
```

What can go wrong:

- `from_jwks` raises [`InvalidKeyError`][ryjwt.InvalidKeyError] if the document is unusable (see
  [below](#documents-that-are-rejected)).
- `decode` raises [`UnknownKeyError`][ryjwt.UnknownKeyError] if the token's `kid` isn't in the
  document. It's an `InvalidTokenError`, like every other reason a token is rejected.

If the provider publishes its JWKS at a URL, as most do, use a [`JWKSClient`](jwks-urls.md). It
fetches the document for you, and fetches it again when the provider changes its keys.

Verifying with a JWKS is as fast as with a single PEM key. Once a token has verified, ryjwt
remembers which key its header picked, so the next token with the same header skips the lookup
(its signature is still checked).

### Which keys are used

| key type | curve | used for |
| :-- | :-- | :-- |
| RSA | | `RS256` ... `PS512` |
| EC | P-256 | `ES256` |
| EC | secp256k1 | `ES256K` |
| EC | P-384 | `ES384` |
| EC | P-521 | `ES512`, `ES521` |
| OKP | Ed25519 | `EdDSA` |

- Keys of any other type or curve are ignored.
- Keys marked for encryption (`"use": "enc"`) are ignored.
- A key only verifies algorithms that fit its own type and curve. An RSA key never verifies an
  `ES256` token, so one document can safely mix RSA, EC and Ed25519 keys.
- A key may name the one algorithm it's for (its `alg`). It's then only used for that algorithm,
  and ignored if that algorithm isn't in your `algorithms`.
- Ignored keys play no further part. For example, an encryption key may share its `kid` with a
  signing key.

### Picking a token's key

- The token's `kid` must match the `kid` of one of the keys used.
- A token without a `kid` is only accepted when the document has a single usable key.
- A key without a `kid` can only be picked when it's the only usable key.

### Documents that are rejected

`from_jwks` raises `InvalidKeyError` if the document:

- contains a private key, in any entry, even one that would be ignored. A JWKS should only
  publish public keys; one with a private key in it has leaked that key;
- has two usable keys with the same `kid`;
- has an entry that isn't a valid key: not a JSON object, a field repeated or of the wrong type,
  invalid base64url, values of the wrong length, or an EC point that isn't on its curve;
- has a weak key: RSA outside 2048 to 8192 bits, or a small-order Ed25519 key;
- has no key at all that can be used with your `algorithms`.

??? info "How ryjwt spots a private key"

    A JWK holds a private key if it has any of these fields:

    | fields | what they are |
    | :-- | :-- |
    | `d` | the private part of an RSA, EC or Ed25519 key |
    | `p`, `q`, `dp`, `dq`, `qi`, `oth` | the private factors of an RSA key |
    | `k` | a symmetric (HMAC) secret |
