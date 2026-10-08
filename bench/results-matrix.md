# JWT decode benchmarks: the full matrix

Generated 2026-10-08 from `bench/results-matrix/` by `bench/compare.py`.
Run in Docker, one container per library, each limited to 1 CPU core (pinned) and 500 MB with no swap; the JWKS server runs in a container of its own, outside that limit.
Runtimes: Bun 1.3.14, CPython 3.14.8, Rust (release, LTO).

Each decode verifies the signature and checks `exp` and `aud`, as a real
caller would, and each library's result is checked against the token's claims
before timing. Times are the mean µs per decode (lower is better); `(Nx)` is the
speed-up vs pyjwt 2.15.1. Each case runs about a second (a warm-up, then
the best of 5 batches), so slow ones (RSA 4096, P-521) run fewer iterations.
Fastest per row in bold; n/a where the library can't (see the end).

Key sources: an HMAC secret (HS256 only); a PEM public key, parsed once; a
JWKS document of 3 keys, the signing key in the middle, picked by the token's
`kid`; and that document fetched over HTTPS from a JWKS server
(static-web-server, in its own container), timed in the steady state with the
keys cached.

## Apple Silicon caveat

These numbers come from Docker on a Mac: Linux in a VM on Apple Silicon. There,
aws-lc (the crypto library under ryjwt and jsonwebtoken) doesn't recognise the
CPU: its Linux CPU detection knows only Arm's own cores. So it uses a big-number
multiply meant for CPUs with slow multipliers, which makes RSA, Ed25519, P-384
and P-521 verification about 1.6-1.8x slower than the same machine runs them
natively. ES256 and HMAC are unaffected, and so is Linux on x86_64 and on
Graviton 3/4, which aws-lc detects. BoringSSL (Bun's fast-jwt and jose) always
uses the fast multiply.

The same machine natively (macOS, M3 Max), RS256 decode in µs:

| key | ryjwt | fast-jwt |
| :-- | --: | --: |
| RSA 2048 | 10.5 | 15.1 |
| RSA 3072 | 21.8 | 27.1 |
| RSA 4096 | 37.4 | 43.5 |

## Headline: typical token, medium key

| key source | alg | key | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | **1.09 (31.0x)** | 1.17 (28.8x) | 3.33 (10.2x) | 3.47 (9.8x) | 11.38 (3.0x) | 33.85 (1.0x) |
| PEM public key | RS256 | RSA 3072 | 37.27 (1.8x) | 38.06 (1.8x) | 43.02 (1.6x) | **25.92 (2.6x)** | 32.42 (2.1x) | 68.64 (1.0x) |
| PEM public key | ES384 | P-384 | 148.90 (1.5x) | **148.46 (1.5x)** | 149.25 (1.5x) | 275.28 (0.8x) | 348.73 (0.6x) | 220.99 (1.0x) |
| PEM public key | EdDSA | Ed25519 | **32.13 (3.0x)** | 32.87 (2.9x) | 33.51 (2.9x) | 33.20 (2.9x) | 39.14 (2.4x) | 95.81 (1.0x) |
| JWKS document | RS256 | RSA 3072 | 37.50 (2.8x) | 38.82 (2.7x) | 43.38 (2.4x) | n/a | **33.97 (3.1x)** | 103.63 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | 37.83 (2.8x) | **37.67 (2.9x)** | n/a | n/a | n/a | 107.60 (1.0x) |
| JWKS URL, async client | RS256 | RSA 3072 | 37.88 (2.8x) | 37.90 (2.8x) | n/a | 58.94 (1.8x) | **31.97 (3.4x)** | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | 0.56 (35.2x) | **0.53 (37.0x)** | 1.60 (12.3x) | 2.16 (9.1x) | 12.11 (1.6x) | 19.71 (1.0x) |
| HS256 | 32 B | typical | 661 | **1.10 (30.1x)** | 1.13 (29.5x) | 3.26 (10.2x) | 3.72 (8.9x) | 12.12 (2.7x) | 33.17 (1.0x) |
| HS256 | 32 B | medium | 2244 | **2.14 (36.7x)** | 3.10 (25.4x) | 8.91 (8.8x) | 7.21 (10.9x) | 16.01 (4.9x) | 78.78 (1.0x) |
| HS256 | 32 B | large | 20884 | **16.87 (35.3x)** | 31.98 (18.6x) | 84.90 (7.0x) | 65.11 (9.2x) | 75.34 (7.9x) | 595.91 (1.0x) |
| HS256 | 64 B | small | 231 | 0.56 (35.8x) | **0.54 (37.2x)** | 1.62 (12.4x) | 2.19 (9.1x) | 9.76 (2.0x) | 19.99 (1.0x) |
| HS256 | 64 B | typical | 661 | **1.09 (31.0x)** | 1.17 (28.8x) | 3.33 (10.2x) | 3.47 (9.8x) | 11.38 (3.0x) | 33.85 (1.0x) |
| HS256 | 64 B | medium | 2244 | **2.16 (36.9x)** | 3.13 (25.5x) | 8.77 (9.1x) | 7.15 (11.2x) | 15.71 (5.1x) | 79.86 (1.0x) |
| HS256 | 64 B | large | 20884 | **16.75 (36.2x)** | 31.90 (19.0x) | 84.29 (7.2x) | 66.61 (9.1x) | 74.86 (8.1x) | 607.14 (1.0x) |
| HS256 | 256 B | small | 231 | 0.57 (36.8x) | **0.53 (39.4x)** | 1.74 (12.1x) | 2.30 (9.1x) | 9.84 (2.1x) | 20.99 (1.0x) |
| HS256 | 256 B | typical | 661 | **1.09 (31.6x)** | 1.14 (30.3x) | 3.42 (10.1x) | 3.76 (9.2x) | 11.14 (3.1x) | 34.48 (1.0x) |
| HS256 | 256 B | medium | 2244 | **2.14 (37.4x)** | 3.10 (25.9x) | 8.79 (9.1x) | 7.18 (11.1x) | 15.82 (5.1x) | 80.04 (1.0x) |
| HS256 | 256 B | large | 20884 | **16.76 (36.0x)** | 32.00 (18.8x) | 83.20 (7.2x) | 66.16 (9.1x) | 75.23 (8.0x) | 602.57 (1.0x) |
| HS256 | 4096 B | small | 231 | 0.56 (77.4x) | **0.54 (81.3x)** | 3.06 (14.2x) | 3.69 (11.8x) | 11.87 (3.7x) | 43.55 (1.0x) |
| HS256 | 4096 B | typical | 661 | **1.09 (52.7x)** | 1.13 (51.0x) | 4.74 (12.1x) | 5.03 (11.4x) | 13.45 (4.3x) | 57.44 (1.0x) |
| HS256 | 4096 B | medium | 2244 | **2.17 (47.5x)** | 3.11 (33.1x) | 10.10 (10.2x) | 8.88 (11.6x) | 17.90 (5.8x) | 102.94 (1.0x) |
| HS256 | 4096 B | large | 20884 | **16.74 (37.2x)** | 32.40 (19.2x) | 85.10 (7.3x) | 66.82 (9.3x) | 76.08 (8.2x) | 623.40 (1.0x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.12 (2.3x) | 16.13 (2.3x) | 19.41 (1.9x) | **14.20 (2.6x)** | 19.74 (1.9x) | 37.62 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 16.72 (3.0x) | 16.88 (3.0x) | 20.83 (2.4x) | **14.73 (3.4x)** | 20.48 (2.4x) | 49.96 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **17.67 (5.5x)** | 18.90 (5.1x) | 26.66 (3.6x) | 18.45 (5.2x) | 25.25 (3.8x) | 96.41 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **32.54 (18.9x)** | 48.19 (12.7x) | 101.76 (6.0x) | 77.88 (7.9x) | 83.91 (7.3x) | 613.74 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 36.81 (1.5x) | 37.30 (1.5x) | 41.57 (1.3x) | **25.42 (2.2x)** | 31.20 (1.8x) | 55.42 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | 37.27 (1.8x) | 38.06 (1.8x) | 43.02 (1.6x) | **25.92 (2.6x)** | 32.42 (2.1x) | 68.64 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 38.53 (3.0x) | 39.83 (2.9x) | 48.82 (2.4x) | **29.89 (3.9x)** | 36.93 (3.1x) | 115.34 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **53.38 (11.9x)** | 69.97 (9.1x) | 124.30 (5.1x) | 89.14 (7.1x) | 95.42 (6.7x) | 637.20 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 64.48 (1.2x) | 64.58 (1.2x) | 70.94 (1.1x) | **40.36 (1.9x)** | 47.02 (1.7x) | 77.63 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 65.03 (1.4x) | 65.14 (1.4x) | 72.32 (1.3x) | **41.69 (2.2x)** | 48.69 (1.9x) | 91.43 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 65.73 (2.1x) | 67.55 (2.0x) | 78.11 (1.8x) | **46.65 (3.0x)** | 53.39 (2.6x) | 137.83 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **80.29 (8.4x)** | 97.53 (6.9x) | 153.28 (4.4x) | 104.77 (6.5x) | 111.67 (6.1x) | 676.34 (1.0x) |
| ES256 | P-256 | small | 304 | **31.58 (1.9x)** | 31.67 (1.9x) | 32.78 (1.9x) | 35.22 (1.7x) | 41.32 (1.5x) | 60.90 (1.0x) |
| ES256 | P-256 | typical | 704 | 32.27 (2.3x) | **32.23 (2.3x)** | 34.48 (2.1x) | 35.48 (2.1x) | 42.93 (1.7x) | 73.40 (1.0x) |
| ES256 | P-256 | medium | 2317 | **33.13 (3.7x)** | 34.19 (3.6x) | 39.92 (3.1x) | 39.44 (3.1x) | 48.05 (2.6x) | 123.30 (1.0x) |
| ES256 | P-256 | large | 20957 | **47.78 (14.0x)** | 63.89 (10.4x) | 115.22 (5.8x) | 99.42 (6.7x) | 107.09 (6.2x) | 666.63 (1.0x) |
| ES384 | P-384 | small | 346 | 149.53 (1.4x) | **149.46 (1.4x)** | 149.87 (1.4x) | 274.87 (0.8x) | 347.71 (0.6x) | 214.21 (1.0x) |
| ES384 | P-384 | typical | 746 | 148.90 (1.5x) | **148.46 (1.5x)** | 149.25 (1.5x) | 275.28 (0.8x) | 348.73 (0.6x) | 220.99 (1.0x) |
| ES384 | P-384 | medium | 2359 | **151.43 (1.8x)** | 151.56 (1.8x) | 156.94 (1.7x) | 285.21 (1.0x) | 357.11 (0.8x) | 270.96 (1.0x) |
| ES384 | P-384 | large | 20999 | **171.72 (4.6x)** | 185.54 (4.3x) | 238.01 (3.3x) | 352.85 (2.2x) | 421.45 (1.9x) | 789.78 (1.0x) |
| ES512 | P-521 | small | 394 | 286.26 (1.1x) | **279.31 (1.1x)** | n/a | 689.88 (0.5x) | 853.39 (0.4x) | 313.77 (1.0x) |
| ES512 | P-521 | typical | 794 | **278.20 (1.2x)** | 278.22 (1.2x) | n/a | 688.77 (0.5x) | 836.78 (0.4x) | 327.03 (1.0x) |
| ES512 | P-521 | medium | 2407 | 284.56 (1.3x) | **283.79 (1.3x)** | n/a | 713.25 (0.5x) | 835.07 (0.4x) | 369.19 (1.0x) |
| ES512 | P-521 | large | 21047 | **304.70 (3.0x)** | 314.03 (2.9x) | n/a | 766.25 (1.2x) | 888.65 (1.0x) | 904.92 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 31.67 (2.7x) | 31.99 (2.6x) | 32.03 (2.6x) | **31.66 (2.7x)** | 37.88 (2.2x) | 84.56 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **32.13 (3.0x)** | 32.87 (2.9x) | 33.51 (2.9x) | 33.20 (2.9x) | 39.14 (2.4x) | 95.81 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **33.60 (4.3x)** | 34.83 (4.2x) | 40.63 (3.6x) | 37.26 (3.9x) | 44.05 (3.3x) | 145.06 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **52.78 (12.9x)** | 69.67 (9.7x) | 119.44 (5.7x) | 100.46 (6.8x) | 105.24 (6.4x) | 678.79 (1.0x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.41 (3.5x) | **16.10 (3.6x)** | 19.68 (2.9x) | n/a | 20.78 (2.8x) | 57.65 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 16.86 (4.8x) | **16.64 (4.9x)** | 21.29 (3.8x) | n/a | 22.76 (3.6x) | 81.42 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **17.98 (9.5x)** | 18.83 (9.1x) | 27.46 (6.3x) | n/a | 24.23 (7.1x) | 171.70 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **32.62 (36.5x)** | 48.66 (24.5x) | 109.17 (10.9x) | n/a | 91.23 (13.1x) | 1190.96 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 36.84 (2.2x) | 37.91 (2.1x) | 42.32 (1.9x) | n/a | **32.68 (2.4x)** | 79.84 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | 37.50 (2.8x) | 38.82 (2.7x) | 43.38 (2.4x) | n/a | **33.97 (3.1x)** | 103.63 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 38.37 (5.1x) | 39.68 (4.9x) | 50.29 (3.9x) | n/a | **35.50 (5.5x)** | 195.34 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **53.05 (22.7x)** | 69.77 (17.3x) | 133.26 (9.0x) | n/a | 91.95 (13.1x) | 1204.29 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 64.38 (1.7x) | 66.83 (1.6x) | 71.72 (1.5x) | n/a | **45.83 (2.4x)** | 109.60 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 64.58 (2.1x) | 65.25 (2.0x) | 73.91 (1.8x) | n/a | **47.71 (2.8x)** | 133.60 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 65.62 (3.4x) | 67.41 (3.3x) | 79.33 (2.8x) | n/a | **50.99 (4.4x)** | 225.30 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **83.34 (15.0x)** | 96.60 (12.9x) | 160.75 (7.8x) | n/a | 107.29 (11.6x) | 1246.32 (1.0x) |
| ES256 | P-256 | small | 304 | **31.59 (2.3x)** | 31.64 (2.3x) | 32.97 (2.2x) | n/a | 39.60 (1.9x) | 74.15 (1.0x) |
| ES256 | P-256 | typical | 704 | 32.43 (2.9x) | **32.20 (3.0x)** | 35.11 (2.7x) | n/a | 41.25 (2.3x) | 95.56 (1.0x) |
| ES256 | P-256 | medium | 2317 | **33.60 (5.6x)** | 34.28 (5.4x) | 41.97 (4.5x) | n/a | 45.35 (4.1x) | 186.76 (1.0x) |
| ES256 | P-256 | large | 20957 | **47.64 (25.0x)** | 63.20 (18.8x) | 122.15 (9.7x) | n/a | 100.28 (11.9x) | 1189.82 (1.0x) |
| ES384 | P-384 | small | 346 | **150.45 (1.5x)** | 150.83 (1.5x) | 150.77 (1.5x) | n/a | 336.04 (0.7x) | 225.16 (1.0x) |
| ES384 | P-384 | typical | 746 | **149.16 (1.6x)** | 149.73 (1.6x) | 151.17 (1.6x) | n/a | 336.07 (0.7x) | 244.04 (1.0x) |
| ES384 | P-384 | medium | 2359 | **151.49 (2.2x)** | 154.57 (2.2x) | 161.34 (2.1x) | n/a | 344.16 (1.0x) | 334.75 (1.0x) |
| ES384 | P-384 | large | 20999 | **171.20 (7.8x)** | 187.35 (7.1x) | 245.07 (5.4x) | n/a | 420.60 (3.2x) | 1332.98 (1.0x) |
| ES512 | P-521 | small | 394 | 283.83 (1.1x) | **280.42 (1.2x)** | n/a | n/a | 819.23 (0.4x) | 323.66 (1.0x) |
| ES512 | P-521 | typical | 794 | 277.71 (1.2x) | **277.33 (1.2x)** | n/a | n/a | 824.13 (0.4x) | 346.27 (1.0x) |
| ES512 | P-521 | medium | 2407 | 285.40 (1.5x) | **282.59 (1.6x)** | n/a | n/a | 869.58 (0.5x) | 438.90 (1.0x) |
| ES512 | P-521 | large | 21047 | **301.19 (4.8x)** | 323.92 (4.4x) | n/a | n/a | 908.50 (1.6x) | 1440.55 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 31.65 (3.1x) | **31.57 (3.1x)** | 32.48 (3.0x) | n/a | 39.14 (2.5x) | 96.94 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **32.14 (3.7x)** | 32.21 (3.7x) | 33.99 (3.5x) | n/a | 39.40 (3.0x) | 118.45 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **33.71 (6.3x)** | 34.77 (6.1x) | 40.53 (5.2x) | n/a | 44.34 (4.8x) | 210.88 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **52.84 (23.8x)** | 68.50 (18.4x) | 125.05 (10.1x) | n/a | 102.59 (12.3x) | 1259.76 (1.0x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.66 (3.7x) | **16.37 (3.7x)** | n/a | n/a | n/a | 60.94 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 17.13 (5.0x) | **17.13 (5.0x)** | n/a | n/a | n/a | 85.93 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **18.50 (9.8x)** | 18.99 (9.5x) | n/a | n/a | n/a | 180.83 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **32.79 (37.3x)** | 48.93 (25.0x) | n/a | n/a | n/a | 1222.15 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 37.20 (2.3x) | **37.14 (2.3x)** | n/a | n/a | n/a | 84.88 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | 37.83 (2.8x) | **37.67 (2.9x)** | n/a | n/a | n/a | 107.60 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **38.92 (5.2x)** | 40.08 (5.1x) | n/a | n/a | n/a | 203.35 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **53.40 (23.7x)** | 69.77 (18.2x) | n/a | n/a | n/a | 1267.96 (1.0x) |
| RS256 | RSA 4096 | small | 902 | **64.09 (1.7x)** | 64.67 (1.7x) | n/a | n/a | n/a | 110.29 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **64.52 (2.1x)** | 65.17 (2.1x) | n/a | n/a | n/a | 134.45 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **65.90 (3.5x)** | 67.73 (3.4x) | n/a | n/a | n/a | 231.26 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **80.40 (15.9x)** | 97.72 (13.1x) | n/a | n/a | n/a | 1275.46 (1.0x) |
| ES256 | P-256 | small | 304 | 32.19 (2.3x) | **31.91 (2.3x)** | n/a | n/a | n/a | 73.59 (1.0x) |
| ES256 | P-256 | typical | 704 | **32.35 (3.1x)** | 32.85 (3.0x) | n/a | n/a | n/a | 99.38 (1.0x) |
| ES256 | P-256 | medium | 2317 | **33.25 (5.8x)** | 34.74 (5.6x) | n/a | n/a | n/a | 193.63 (1.0x) |
| ES256 | P-256 | large | 20957 | **47.68 (25.9x)** | 64.49 (19.2x) | n/a | n/a | n/a | 1236.54 (1.0x) |
| ES384 | P-384 | small | 346 | **149.07 (1.5x)** | 150.50 (1.5x) | n/a | n/a | n/a | 223.56 (1.0x) |
| ES384 | P-384 | typical | 746 | **148.42 (1.7x)** | 149.14 (1.7x) | n/a | n/a | n/a | 249.25 (1.0x) |
| ES384 | P-384 | medium | 2359 | **151.19 (2.3x)** | 152.33 (2.2x) | n/a | n/a | n/a | 342.50 (1.0x) |
| ES384 | P-384 | large | 20999 | **171.21 (8.1x)** | 188.15 (7.4x) | n/a | n/a | n/a | 1394.33 (1.0x) |
| ES512 | P-521 | small | 394 | 282.59 (1.2x) | **280.00 (1.2x)** | n/a | n/a | n/a | 326.14 (1.0x) |
| ES512 | P-521 | typical | 794 | 281.93 (1.2x) | **279.26 (1.3x)** | n/a | n/a | n/a | 350.75 (1.0x) |
| ES512 | P-521 | medium | 2407 | 287.13 (1.6x) | **284.37 (1.6x)** | n/a | n/a | n/a | 446.76 (1.0x) |
| ES512 | P-521 | large | 21047 | **303.18 (4.9x)** | 312.79 (4.8x) | n/a | n/a | n/a | 1498.60 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 31.87 (3.1x) | **31.70 (3.1x)** | n/a | n/a | n/a | 99.66 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **32.10 (3.9x)** | 32.39 (3.8x) | n/a | n/a | n/a | 123.62 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **33.79 (6.5x)** | 35.10 (6.3x) | n/a | n/a | n/a | 219.54 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **52.88 (23.9x)** | 68.47 (18.5x) | n/a | n/a | n/a | 1263.89 (1.0x) |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.61 (3.7x) | **16.45 (3.7x)** | n/a | 36.60 (1.7x) | 19.59 (3.1x) | n/a |
| RS256 | RSA 2048 | typical | 961 | 17.05 (5.0x) | **17.01 (5.1x)** | n/a | 34.08 (2.5x) | 20.31 (4.2x) | n/a |
| RS256 | RSA 2048 | medium | 2574 | **18.20 (9.9x)** | 19.13 (9.5x) | n/a | 38.82 (4.7x) | 25.62 (7.1x) | n/a |
| RS256 | RSA 2048 | large | 21214 | **32.74 (37.3x)** | 48.71 (25.1x) | n/a | 98.03 (12.5x) | 80.45 (15.2x) | n/a |
| RS256 | RSA 3072 | small | 731 | 38.98 (2.2x) | 37.17 (2.3x) | n/a | 57.27 (1.5x) | **30.36 (2.8x)** | n/a |
| RS256 | RSA 3072 | typical | 1131 | 37.88 (2.8x) | 37.90 (2.8x) | n/a | 58.94 (1.8x) | **31.97 (3.4x)** | n/a |
| RS256 | RSA 3072 | medium | 2744 | 40.00 (5.1x) | 41.67 (4.9x) | n/a | 61.85 (3.3x) | **37.89 (5.4x)** | n/a |
| RS256 | RSA 3072 | large | 21384 | **54.65 (23.2x)** | 69.26 (18.3x) | n/a | 123.29 (10.3x) | 91.73 (13.8x) | n/a |
| RS256 | RSA 4096 | small | 902 | 65.32 (1.7x) | 68.39 (1.6x) | n/a | 88.06 (1.3x) | **47.10 (2.3x)** | n/a |
| RS256 | RSA 4096 | typical | 1302 | 69.30 (1.9x) | 65.58 (2.0x) | n/a | 89.50 (1.5x) | **48.49 (2.8x)** | n/a |
| RS256 | RSA 4096 | medium | 2915 | 67.16 (3.4x) | 66.75 (3.5x) | n/a | 93.76 (2.5x) | **56.38 (4.1x)** | n/a |
| RS256 | RSA 4096 | large | 21555 | **82.87 (15.4x)** | 96.27 (13.2x) | n/a | 154.89 (8.2x) | 115.34 (11.1x) | n/a |
| ES256 | P-256 | small | 304 | 32.99 (2.2x) | **31.87 (2.3x)** | n/a | 2062.38 (0.04x) | 40.87 (1.8x) | n/a |
| ES256 | P-256 | typical | 704 | **32.68 (3.0x)** | 32.76 (3.0x) | n/a | 2086.23 (0.05x) | 42.56 (2.3x) | n/a |
| ES256 | P-256 | medium | 2317 | **33.70 (5.7x)** | 34.76 (5.6x) | n/a | 2014.04 (0.10x) | 47.14 (4.1x) | n/a |
| ES256 | P-256 | large | 20957 | **49.17 (25.2x)** | 64.20 (19.3x) | n/a | 2069.70 (0.6x) | 107.10 (11.5x) | n/a |
| ES384 | P-384 | small | 346 | 151.71 (1.5x) | **150.94 (1.5x)** | n/a | 14803.80 (0.02x) | 339.60 (0.7x) | n/a |
| ES384 | P-384 | typical | 746 | **149.49 (1.7x)** | 150.40 (1.7x) | n/a | 14914.67 (0.02x) | 336.43 (0.7x) | n/a |
| ES384 | P-384 | medium | 2359 | **152.58 (2.2x)** | 152.86 (2.2x) | n/a | 14850.62 (0.02x) | 345.64 (1.0x) | n/a |
| ES384 | P-384 | large | 20999 | **175.24 (8.0x)** | 187.02 (7.5x) | n/a | 14830.14 (0.09x) | 411.20 (3.4x) | n/a |
| ES512 | P-521 | small | 394 | 288.82 (1.1x) | **276.69 (1.2x)** | n/a | 36078.70 (0.01x) | 824.41 (0.4x) | n/a |
| ES512 | P-521 | typical | 794 | 283.91 (1.2x) | **276.17 (1.3x)** | n/a | 35855.02 (0.01x) | 834.47 (0.4x) | n/a |
| ES512 | P-521 | medium | 2407 | 287.77 (1.6x) | **281.62 (1.6x)** | n/a | 35810.56 (0.01x) | 825.09 (0.5x) | n/a |
| ES512 | P-521 | large | 21047 | **304.25 (4.9x)** | 312.32 (4.8x) | n/a | 35979.11 (0.04x) | 882.15 (1.7x) | n/a |
| EdDSA | Ed25519 | small | 306 | 32.18 (3.1x) | **31.49 (3.2x)** | n/a | n/a | 38.46 (2.6x) | n/a |
| EdDSA | Ed25519 | typical | 706 | 32.86 (3.8x) | **32.31 (3.8x)** | n/a | n/a | 39.67 (3.1x) | n/a |
| EdDSA | Ed25519 | medium | 2319 | **34.36 (6.4x)** | 34.85 (6.3x) | n/a | n/a | 44.55 (4.9x) | n/a |
| EdDSA | Ed25519 | large | 20959 | **53.67 (23.5x)** | 69.04 (18.3x) | n/a | n/a | 106.92 (11.8x) | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 2.3 | 1.7 | n/a | n/a | n/a | 1.5 |
| JWKS URL, async client | 1.6 | 1.5 | n/a | 0.9 | 0.9 | n/a |

## Not applicable

- jsonwebtoken 11.1.0 (aws-lc-rs), every key source, ES512: jsonwebtoken has no ES512 (P-521).
- jsonwebtoken 11.1.0 (aws-lc-rs), JWKS URL, sync client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs), JWKS URL, async client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- fast-jwt 6.3.3, JWKS document: fast-jwt takes JWKS only from a URL (via get-jwks), not a document.
- fast-jwt 6.3.3, JWKS URL, sync client: fast-jwt's JWKS support (get-jwks) is async only.
- fast-jwt 6.3.3, JWKS URL, async client, EdDSA: get-jwks converts JWKs with jwk-to-pem, which doesn't support OKP (Ed25519) keys.
- jose 6.2.12, JWKS URL, sync client: jose's API is async only.
- pyjwt 2.15.1, JWKS URL, async client: PyJWT has no async JWKS client.

## Notes

- ryjwt 0.0.0a0 → Struct: `HMAC`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.0.0a0 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.0.0a0 → dict: `HMAC`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.0.0a0 → dict: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- jsonwebtoken 11.1.0 (aws-lc-rs): JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- fast-jwt 6.3.3: JWKS URL via get-jwks 11.0.3 (fast-jwt's documented integration): it converts the cached JWK to a PEM, which fast-jwt parses, on every verify.
- jose 6.2.12: `importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`.
- pyjwt 2.15.1: PEM: the key loaded once, with `load_pem_public_key`.
- pyjwt 2.15.1: JWKS document: `PyJWKSet`, picking the key by `get_unverified_header`'s `kid`.
- pyjwt 2.15.1: JWKS URL: `PyJWKClient(cache_keys=True)`, its `ssl_context` trusting the test CA.
