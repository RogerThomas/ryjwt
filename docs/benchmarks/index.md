# Benchmarks

The benchmarks time decoding, which a service does on every request. They compare ryjwt with:

- [PyJWT](https://github.com/jpadilla/pyjwt), on Python;
- [python-jose](https://github.com/mpdavis/python-jose), [joserfc](https://github.com/authlib/joserfc)
  (Authlib's) and [jwcrypto](https://github.com/latchset/jwcrypto), also on Python;
- [jose](https://github.com/panva/jose) and [fast-jwt](https://github.com/nearform/fast-jwt), on
  Bun (JavaScript);
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken), in Rust.

ryjwt is timed decoding to a dict, to a msgspec `Struct`, and (on the HS256 page) to a pydantic
model.

There are two sets of results:

- [Full matrix](matrix.md): every algorithm and key size, four payload sizes, and four ways of
  getting the key (an HMAC secret, a PEM public key, a JWKS document, and a JWKS URL).
- [HS256 by token and key size](docker.md): HS256 only, with tokens from 231 bytes to 20 KB, and
  secrets from 32 bytes to 4 KB.

## The races

Each bar is one library decoding 100,000 tokens, filling in real time. A library's time is
100,000 times its mean time per decode, measured as the full matrix measures it, in a run of just
the races' two cases (`task bench-race`). So a race's times can differ a little from the same case
on the matrix page.

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about a tenth of a second, the Rust and Bun libraries take three to ten times as long, and the other Python libraries from about one and a half to over four seconds](../assets/perf-race.svg)

With HS256, ryjwt decodes a typical token around 30 times faster than PyJWT 2.15. It's about
three times faster than the fastest JavaScript and Rust libraries.

### Why it's faster than jsonwebtoken (Rust)

Both use the same token, the same checks and the same crypto library (aws-lc), so the gap comes
from the work done per token. Per token, jsonwebtoken 11 parses the header twice, sets up the HMAC
key again, and deserialises the claims twice: once for the result, once to check them. ryjwt sets
up the HMAC key once, when the key is created, skips headers it has already verified, and checks
the claims as it builds the result.

jsonwebtoken here decodes into a `serde_json::Value`, the nearest thing to a Python dict. Decoding
into a typed Rust struct would make it faster.

![A race to decode 100,000 ES256 tokens: ryjwt finishes first in about 3.2 seconds, just ahead of the Rust and Bun libraries, and the other Python libraries take from about five and a half to over eight seconds](../assets/perf-race-es256.svg)

With ES256, most of the time goes into checking the signature. Every library hands that to a
native crypto library, so the gaps are smaller. ryjwt is about twice as fast as PyJWT, and about as
fast as jsonwebtoken and fast-jwt: a little ahead, by less than 10%, which is close to how much
the numbers vary from one run to the next. The race uses ES256 because the
[Apple Silicon](#apple-silicon) slowdown doesn't affect it, so it's fair to every library.

### RS256

RS256 is what most identity providers sign with by default. In the published numbers, fast-jwt
and jose (on Bun) decode RS256 tokens faster than ryjwt does: see the
[full matrix](matrix.md#pem-public-key). Part of that is the [Apple Silicon](#apple-silicon)
slowdown, which affects ryjwt and jsonwebtoken but not Bun. There are no published numbers from a
machine without it yet.

## How they're measured

- Each decode checks the signature, and the `exp` and `aud` claims, as a real service would.
- Before timing, each library's result is checked against the token's claims, and each library is
  shown to reject an expired token and a token for another audience.
- Each library runs in its own Docker container, limited to one CPU (pinned to one of Docker's
  virtual CPUs) and 500 MB of memory. The containers run one after another, so they never compete.
- jose and fast-jwt run on [Bun](https://bun.sh), whose crypto is BoringSSL. On Node, which uses
  OpenSSL, their numbers could differ.
- The JWKS URL cases fetch the keys over HTTPS from a server in another container. They're timed
  once the keys are cached.
- Times are microseconds per decode: the mean over the fastest of five batches. Lower is better.
  Each row also shows the speed-up over PyJWT.

Some things to know when reading them:

- **The same token, every time.** Each case decodes one token over and over, so ryjwt's
  [header cache](../index.md#why-its-fast) always hits. That's what happens with tokens from one
  issuer, which share a header. The signature and claims are still checked on every decode.
- **ryjwt → dict runs with msgspec installed.** ryjwt builds dicts with msgspec when it's there.
  Without it (`uv add ryjwt`), it uses jiter, and a dict decode is up to about 10% slower.
- **The speed-ups are against PyJWT 2.15.** Much of PyJWT's time goes on its own Python code, such
  as checking each base64 character, so they'd change with another version.

Each results page says when it was made, and with which versions.

## Apple Silicon

The published results come from Docker on an Apple Silicon Mac. There, aws-lc, the crypto library
under ryjwt and jsonwebtoken, runs RSA, Ed25519, P-384 and P-521 checks slower than it does
natively. Linux on x86_64 or AWS Graviton isn't affected, and neither are HS256 and ES256. The
[full matrix](matrix.md#apple-silicon-caveat) has the details.

## Running them

The benchmarks are in the repository's `bench/` directory. You need Docker,
[uv](https://docs.astral.sh/uv/) and [Task](https://taskfile.dev):

```console
task bench-docker  # HS256: bench/results-docker.md
task bench-matrix  # the full matrix: bench/results-matrix.md
task bench-race    # just the races' two cases, then redraws the races
task race-svg      # redraws the races from bench-race's results
```

These pages show those files as they are, so rerunning the benchmarks updates the docs.

To run them on Linux instead, for any commit or tag, run the **Benchmarks** workflow from the
repository's Actions tab, choosing the ref, which benchmarks (`race` for just the races) and the
runner (x86_64 or arm64). It uploads the results as an artifact, with a note of the machine they
ran on; `task bench-download -- <run id>` puts them in place. GitHub's Linux runners don't have the [Apple Silicon](#apple-silicon) slowdown, but they're
shared machines, so compare runs on the same runner.
