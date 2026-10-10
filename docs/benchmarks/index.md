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
its mean time per decode, measured as in the full matrix, in a run of just the races' two cases
(`task bench-race`) on the same machine. So race times can differ a little from the matrix page.

![A race to decode 100,000 HS256 tokens: ryjwt finishes in about 0.2 seconds, jsonwebtoken (Rust) and fast-jwt (Bun) take two and a half to three times as long, and the other libraries from about 2 to over 10 seconds](../assets/perf-race.svg)

With HS256, ryjwt decodes a typical token about 28 times faster than PyJWT 2.15 (26 times into a
dict), about 2.4 times faster than jsonwebtoken (Rust) and 2.9 times faster than fast-jwt (Bun).

### Why it's faster than jsonwebtoken (Rust)

Both use the same token, checks and crypto library (aws-lc), so the gap is the work per token.
For each token, jsonwebtoken 11 parses the header twice, sets up the HMAC key again, and
deserialises the claims twice: for the result, and to check them. ryjwt sets up the HMAC key once,
when the key is created, skips headers it has already verified, and checks the claims while
building the result.

Here, jsonwebtoken decodes into a `serde_json::Value`, the nearest thing to a Python dict. A typed
Rust struct would be faster.

### RS256

![A race to decode 100,000 RS256 tokens with a 3072-bit RSA key: ryjwt finishes first in about 4.1 seconds, ahead of fast-jwt (Bun) and jsonwebtoken (Rust) at 4.6 and 4.8, and the other libraries take from about 6 to 15 seconds](../assets/perf-race-rs256.svg)

Most identity providers sign with RS256 by default. Most of the time goes on checking the
signature, which every library hands to native crypto, so the gaps are smaller: ryjwt is about 2.7
times faster than PyJWT, and a little ahead of fast-jwt and jsonwebtoken, by about 12% and 16%. On
an Apple Silicon Mac, in Docker, the [slowdown below](#apple-silicon) puts fast-jwt and jose
ahead.

ES256 is much the same: ryjwt is about twice as fast as PyJWT, and level with jsonwebtoken and
fast-jwt, ahead by 5% and 7% ([full matrix](matrix.md#pem-public-key)).

## How they're measured

- Each decode checks the signature, `exp` and `aud`, as a real service would.
- Before timing, each library's result is checked against the token's claims, and each is shown
  to reject an expired token and one for another audience.
- The published numbers come from one run of the [Benchmarks workflow](#running-them) on GitHub's
  x86_64 Linux runner. Its CPU varies from run to run (each results page names it), so the times
  change between runs more than the ratios do. It's a shared virtual machine, so expect a few
  percent of variation too.
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

In Docker on an Apple Silicon Mac, aws-lc (the crypto library under ryjwt and jsonwebtoken) runs
RSA, Ed25519, P-384 and P-521 checks about 1.6 to 1.8 times slower than natively, as it doesn't
recognise the CPU. HS256 and ES256 aren't affected. Neither is Linux on x86_64, where the
published numbers come from, or on Neoverse Arm servers such as AWS Graviton. Results made on a
Mac carry a note saying so.

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
`task bench-download -- <run id>` puts them in place. To update the published numbers, run `all`,
so the races and the tables come from the same machine. GitHub's Linux runners don't have the
[Apple Silicon](#apple-silicon) slowdown.
