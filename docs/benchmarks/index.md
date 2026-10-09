# Benchmarks

The benchmarks time decoding, which a service does on every request. They compare ryjwt with:

- [PyJWT](https://github.com/jpadilla/pyjwt), [python-jose](https://github.com/mpdavis/python-jose),
  [joserfc](https://github.com/authlib/joserfc) (Authlib's) and
  [jwcrypto](https://github.com/latchset/jwcrypto), on Python;
- [jose](https://github.com/panva/jose) and [fast-jwt](https://github.com/nearform/fast-jwt), on
  Bun (JavaScript);
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken), in Rust.

ryjwt is timed decoding to a dict, a msgspec `Struct`, and (on the HS256 page) a pydantic model.
There are two sets of results:

- [Full matrix](matrix.md): every algorithm and key size, four payload sizes, and four key sources
  (HMAC secret, PEM public key, JWKS document, JWKS URL).
- [HS256 by token and key size](docker.md): tokens from 231 bytes to 20 KB, secrets from 32 bytes
  to 4 KB.

## The races

Each bar is one library decoding 100,000 tokens, filling in real time. Its time is 100,000 times
its mean time per decode, measured as in the full matrix, but in a run of just the races' two cases
(`task bench-race`). So race times can differ a little from the matrix page.

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about a tenth of a second, the Rust and Bun libraries take three to ten times as long, and the other Python libraries from about one and a half to over four seconds](../assets/perf-race.svg)

With HS256, ryjwt decodes a typical token around 30 times faster than PyJWT 2.15, and about three
times faster than the fastest JavaScript and Rust libraries.

### Why it's faster than jsonwebtoken (Rust)

Both use the same token, checks and crypto library (aws-lc), so the gap is the work per token.
For each token, jsonwebtoken 11 parses the header twice, sets up the HMAC key again, and
deserialises the claims twice: for the result, and to check them. ryjwt sets up the HMAC key once,
when the key is created, skips headers it has already verified, and checks the claims while
building the result.

Here, jsonwebtoken decodes into a `serde_json::Value`, the nearest thing to a Python dict. A typed
Rust struct would be faster.

![A race to decode 100,000 ES256 tokens: ryjwt finishes first in about 3.2 seconds, just ahead of the Rust and Bun libraries, and the other Python libraries take from about five and a half to over eight seconds](../assets/perf-race-es256.svg)

With ES256, most of the time goes on the signature check, which every library hands to native
crypto, so the gaps are smaller. ryjwt is about twice as fast as PyJWT, and about as fast as
jsonwebtoken and fast-jwt: a little ahead, by under 10%, close to the run-to-run variation. The
race uses ES256 because the [Apple Silicon](#apple-silicon) slowdown doesn't affect it, so it's
fair to every library.

### RS256

Most identity providers sign with RS256 by default. In the published numbers, fast-jwt and jose
(on Bun) decode RS256 faster than ryjwt ([full matrix](matrix.md#pem-public-key)). Part of that is
the [Apple Silicon](#apple-silicon) slowdown, which affects ryjwt and jsonwebtoken but not Bun.
There are no published numbers from a machine without it yet.

## How they're measured

- Each decode checks the signature, `exp` and `aud`, as a real service would.
- Before timing, each library's result is checked against the token's claims, and each is shown
  to reject an expired token and one for another audience.
- Each library runs in its own Docker container, with one CPU (pinned to one of Docker's virtual
  CPUs) and 500 MB of memory. The containers run one after another, so they never compete.
- jose and fast-jwt run on [Bun](https://bun.sh), whose crypto is BoringSSL. On Node (OpenSSL),
  their numbers could differ.
- JWKS URL cases fetch the keys over HTTPS from another container, and are timed once the keys are
  cached.
- Times are microseconds per decode (lower is better): the mean over the fastest of five batches.
  Each row also shows the speed-up over PyJWT.

When reading them, note:

- **The same token, every time.** Each case decodes one token repeatedly, so ryjwt's
  [header cache](../index.md#why-its-fast) always hits, as it does for tokens from one issuer,
  which share a header. The signature and claims are still checked on every decode.
- **ryjwt → dict runs with msgspec installed.** Without it (`uv add ryjwt`), ryjwt builds dicts
  with jiter, and a dict decode is up to about 10% slower.
- **The speed-ups are against PyJWT 2.15.** Much of PyJWT's time goes on its own Python code, such
  as checking each base64 character, so another version would give different speed-ups.

Each results page says when it was made, and with which versions.

## Apple Silicon

The published results come from Docker on an Apple Silicon Mac. There, aws-lc (the crypto library
under ryjwt and jsonwebtoken) runs RSA, Ed25519, P-384 and P-521 checks slower than natively.
HS256 and ES256 aren't affected, and neither is Linux on x86_64 or AWS Graviton. The
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

These pages show those files as is, so rerunning the benchmarks updates the docs.

To run them on Linux, for any commit or tag, run the **Benchmarks** workflow from the repository's
Actions tab, choosing the ref, benchmarks (`race` for just the races) and runner (x86_64 or
arm64). It uploads the results, with a note of the machine, as an artifact;
`task bench-download -- <run id>` puts them in place. GitHub's Linux runners don't have the
[Apple Silicon](#apple-silicon) slowdown, but they're shared machines, so compare runs on the same
runner.
