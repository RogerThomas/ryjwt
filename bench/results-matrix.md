# JWT decode benchmarks: the full matrix

Generated 2026-10-09 from `bench/results-matrix/` by `bench/compare.py`.
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

| key source | alg | key | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | 1.15 (29.5x) | **1.12 (30.2x)** | 2.18 (15.5x) | 3.17 (10.7x) | 3.48 (9.7x) | 10.21 (3.3x) | 13.56 (2.5x) | 14.81 (2.3x) | 33.86 (1.0x) | 42.13 (0.8x) |
| PEM public key | RS256 | RSA 3072 | 37.20 (1.9x) | 39.24 (1.8x) | 38.21 (1.8x) | 43.82 (1.6x) | **25.81 (2.7x)** | 31.21 (2.2x) | 39.56 (1.8x) | 40.45 (1.7x) | 70.19 (1.0x) | 68.08 (1.0x) |
| PEM public key | ES384 | P-384 | **146.91 (1.5x)** | 147.93 (1.5x) | 154.94 (1.4x) | 157.40 (1.4x) | 274.15 (0.8x) | 333.44 (0.7x) | 201.52 (1.1x) | 203.46 (1.1x) | 219.17 (1.0x) | 230.57 (1.0x) |
| PEM public key | EdDSA | Ed25519 | **31.87 (3.0x)** | 32.10 (3.0x) | 32.88 (2.9x) | 33.57 (2.8x) | 32.59 (2.9x) | 39.10 (2.4x) | n/a | 81.33 (1.2x) | 95.39 (1.0x) | 107.02 (0.9x) |
| JWKS document | RS256 | RSA 3072 | 37.10 (2.8x) | 37.49 (2.7x) | 38.39 (2.7x) | 45.06 (2.3x) | n/a | **31.96 (3.2x)** | 43.46 (2.4x) | 42.57 (2.4x) | 102.65 (1.0x) | 72.66 (1.4x) |
| JWKS URL, sync client | RS256 | RSA 3072 | 37.41 (2.8x) | **37.37 (2.8x)** | 38.48 (2.8x) | n/a | n/a | n/a | n/a | n/a | 106.47 (1.0x) | n/a |
| JWKS URL, async client | RS256 | RSA 3072 | 37.53 (2.8x) | 37.44 (2.8x) | 38.61 (2.8x) | n/a | 59.27 (1.8x) | **31.98 (3.3x)** | n/a | n/a | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | **0.56 (35.5x)** | 0.57 (34.9x) | 1.15 (17.4x) | 1.55 (12.9x) | 2.16 (9.3x) | 9.52 (2.1x) | 10.30 (1.9x) | 11.40 (1.8x) | 20.01 (1.0x) | 38.83 (0.5x) |
| HS256 | 32 B | typical | 661 | **1.14 (29.2x)** | 1.21 (27.5x) | 2.16 (15.4x) | 3.13 (10.6x) | 3.54 (9.4x) | 10.61 (3.1x) | 13.90 (2.4x) | 14.81 (2.2x) | 33.30 (1.0x) | 42.63 (0.8x) |
| HS256 | 32 B | medium | 2244 | 3.15 (24.9x) | **2.39 (32.9x)** | 3.48 (22.6x) | 8.57 (9.2x) | 7.20 (10.9x) | 14.46 (5.4x) | 19.70 (4.0x) | 24.18 (3.2x) | 78.49 (1.0x) | 53.20 (1.5x) |
| HS256 | 32 B | large | 20884 | 31.91 (18.7x) | **16.93 (35.2x)** | 25.72 (23.2x) | 82.86 (7.2x) | 65.37 (9.1x) | 70.08 (8.5x) | 101.62 (5.9x) | 134.66 (4.4x) | 596.47 (1.0x) | 177.44 (3.4x) |
| HS256 | 64 B | small | 231 | **0.55 (36.9x)** | 0.57 (35.5x) | 1.15 (17.6x) | 1.55 (13.1x) | 2.23 (9.1x) | 9.11 (2.2x) | 10.10 (2.0x) | 11.48 (1.8x) | 20.32 (1.0x) | 38.02 (0.5x) |
| HS256 | 64 B | typical | 661 | 1.15 (29.5x) | **1.12 (30.2x)** | 2.18 (15.5x) | 3.17 (10.7x) | 3.48 (9.7x) | 10.21 (3.3x) | 13.56 (2.5x) | 14.81 (2.3x) | 33.86 (1.0x) | 42.13 (0.8x) |
| HS256 | 64 B | medium | 2244 | 3.22 (24.8x) | **2.17 (36.8x)** | 3.62 (22.1x) | 8.76 (9.1x) | 7.08 (11.3x) | 14.63 (5.5x) | 19.68 (4.1x) | 24.02 (3.3x) | 79.95 (1.0x) | 52.65 (1.5x) |
| HS256 | 64 B | large | 20884 | 32.01 (18.6x) | **16.88 (35.3x)** | 24.86 (24.0x) | 83.36 (7.2x) | 65.83 (9.1x) | 70.46 (8.5x) | 101.38 (5.9x) | 135.07 (4.4x) | 596.53 (1.0x) | 178.73 (3.3x) |
| HS256 | 256 B | small | 231 | **0.54 (39.7x)** | 0.57 (37.3x) | 1.14 (18.8x) | 1.68 (12.7x) | 2.21 (9.7x) | 9.49 (2.3x) | 10.13 (2.1x) | 11.65 (1.8x) | 21.39 (1.0x) | 38.85 (0.6x) |
| HS256 | 256 B | typical | 661 | 1.22 (29.0x) | **1.12 (31.8x)** | 2.17 (16.4x) | 3.30 (10.8x) | 3.62 (9.8x) | 10.62 (3.3x) | 13.77 (2.6x) | 14.95 (2.4x) | 35.55 (1.0x) | 42.74 (0.8x) |
| HS256 | 256 B | medium | 2244 | 3.16 (26.0x) | **2.19 (37.5x)** | 3.62 (22.7x) | 8.82 (9.3x) | 7.17 (11.4x) | 14.51 (5.7x) | 19.71 (4.2x) | 24.21 (3.4x) | 82.07 (1.0x) | 52.93 (1.6x) |
| HS256 | 256 B | large | 20884 | 31.99 (18.7x) | **16.90 (35.5x)** | 24.84 (24.1x) | 83.20 (7.2x) | 64.77 (9.2x) | 70.52 (8.5x) | 101.52 (5.9x) | 135.92 (4.4x) | 598.95 (1.0x) | 179.16 (3.3x) |
| HS256 | 4096 B | small | 231 | **0.54 (81.3x)** | 0.57 (77.2x) | 1.14 (38.7x) | 3.00 (14.7x) | 3.67 (12.1x) | 11.04 (4.0x) | 11.58 (3.8x) | 12.94 (3.4x) | 44.24 (1.0x) | 44.82 (1.0x) |
| HS256 | 4096 B | typical | 661 | 1.16 (50.4x) | **1.12 (52.2x)** | 2.18 (26.9x) | 4.67 (12.6x) | 4.96 (11.8x) | 12.66 (4.6x) | 15.11 (3.9x) | 16.29 (3.6x) | 58.62 (1.0x) | 49.24 (1.2x) |
| HS256 | 4096 B | medium | 2244 | 3.20 (32.6x) | **2.20 (47.5x)** | 3.61 (28.9x) | 10.12 (10.3x) | 8.65 (12.1x) | 17.04 (6.1x) | 21.08 (5.0x) | 25.49 (4.1x) | 104.41 (1.0x) | 59.64 (1.8x) |
| HS256 | 4096 B | large | 20884 | 32.17 (19.5x) | **16.45 (38.1x)** | 24.85 (25.2x) | 84.53 (7.4x) | 66.31 (9.4x) | 72.75 (8.6x) | 104.02 (6.0x) | 136.21 (4.6x) | 626.50 (1.0x) | 187.75 (3.3x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.04 (2.4x) | 16.14 (2.4x) | 18.17 (2.1x) | 19.35 (2.0x) | **13.02 (2.9x)** | 18.61 (2.0x) | 23.56 (1.6x) | 24.74 (1.5x) | 37.93 (1.0x) | 51.79 (0.7x) |
| RS256 | RSA 2048 | typical | 961 | 16.60 (3.1x) | 16.66 (3.0x) | 17.72 (2.9x) | 20.86 (2.4x) | **14.46 (3.5x)** | 20.26 (2.5x) | 26.75 (1.9x) | 27.75 (1.8x) | 50.74 (1.0x) | 54.93 (0.9x) |
| RS256 | RSA 2048 | medium | 2574 | 19.02 (5.1x) | **17.83 (5.5x)** | 18.99 (5.2x) | 26.67 (3.7x) | 17.96 (5.5x) | 23.96 (4.1x) | 33.46 (2.9x) | 37.57 (2.6x) | 97.89 (1.0x) | 65.84 (1.5x) |
| RS256 | RSA 2048 | large | 21214 | 48.12 (12.9x) | **32.14 (19.3x)** | 40.59 (15.3x) | 101.72 (6.1x) | 75.94 (8.2x) | 79.09 (7.9x) | 115.39 (5.4x) | 147.32 (4.2x) | 621.20 (1.0x) | 190.98 (3.3x) |
| RS256 | RSA 3072 | small | 731 | 37.00 (1.5x) | 37.04 (1.5x) | 37.27 (1.5x) | 42.53 (1.3x) | **24.60 (2.3x)** | 29.86 (1.9x) | 36.42 (1.5x) | 37.55 (1.5x) | 55.38 (1.0x) | 64.66 (0.9x) |
| RS256 | RSA 3072 | typical | 1131 | 37.20 (1.9x) | 39.24 (1.8x) | 38.21 (1.8x) | 43.82 (1.6x) | **25.81 (2.7x)** | 31.21 (2.2x) | 39.56 (1.8x) | 40.45 (1.7x) | 70.19 (1.0x) | 68.08 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 39.15 (3.0x) | 38.33 (3.1x) | 39.71 (2.9x) | 49.87 (2.3x) | **29.64 (3.9x)** | 35.21 (3.3x) | 46.09 (2.5x) | 50.23 (2.3x) | 117.03 (1.0x) | 81.16 (1.4x) |
| RS256 | RSA 3072 | large | 21384 | 68.98 (9.2x) | **60.99 (10.4x)** | 61.15 (10.4x) | 124.78 (5.1x) | 87.59 (7.3x) | 90.52 (7.0x) | 128.35 (4.9x) | 161.07 (3.9x) | 635.24 (1.0x) | 206.16 (3.1x) |
| RS256 | RSA 4096 | small | 902 | 63.54 (1.2x) | 63.50 (1.2x) | 64.06 (1.2x) | 70.01 (1.1x) | **40.12 (1.9x)** | 45.32 (1.7x) | 53.97 (1.4x) | 55.30 (1.4x) | 77.18 (1.0x) | 82.50 (0.9x) |
| RS256 | RSA 4096 | typical | 1302 | 63.94 (1.4x) | 64.35 (1.4x) | 65.07 (1.4x) | 71.89 (1.2x) | **41.52 (2.2x)** | 46.84 (1.9x) | 57.14 (1.6x) | 58.08 (1.5x) | 89.56 (1.0x) | 85.31 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 67.13 (2.0x) | 65.04 (2.1x) | 66.69 (2.1x) | 77.58 (1.8x) | **45.35 (3.0x)** | 50.32 (2.7x) | 63.81 (2.2x) | 67.93 (2.0x) | 137.21 (1.0x) | 96.51 (1.4x) |
| RS256 | RSA 4096 | large | 21555 | 98.00 (6.6x) | **79.50 (8.2x)** | 87.93 (7.4x) | 152.92 (4.2x) | 112.08 (5.8x) | 107.49 (6.0x) | 146.80 (4.4x) | 181.35 (3.6x) | 648.57 (1.0x) | 222.87 (2.9x) |
| ES256 | P-256 | small | 304 | 31.35 (1.9x) | **31.30 (1.9x)** | 31.93 (1.8x) | 32.82 (1.8x) | 34.09 (1.7x) | 39.51 (1.5x) | 51.02 (1.1x) | 53.04 (1.1x) | 58.14 (1.0x) | 79.06 (0.7x) |
| ES256 | P-256 | typical | 704 | 32.10 (2.2x) | **31.92 (2.2x)** | 32.91 (2.1x) | 34.04 (2.1x) | 35.45 (2.0x) | 40.49 (1.7x) | 54.21 (1.3x) | 56.37 (1.3x) | 70.56 (1.0x) | 82.87 (0.9x) |
| ES256 | P-256 | medium | 2317 | 34.59 (3.4x) | **32.96 (3.6x)** | 34.24 (3.4x) | 40.12 (2.9x) | 38.30 (3.1x) | 45.09 (2.6x) | 60.90 (1.9x) | 66.40 (1.8x) | 117.80 (1.0x) | 93.75 (1.3x) |
| ES256 | P-256 | large | 20957 | 63.55 (9.9x) | **47.93 (13.1x)** | 55.62 (11.3x) | 115.76 (5.4x) | 97.41 (6.5x) | 100.53 (6.3x) | 142.97 (4.4x) | 175.80 (3.6x) | 629.94 (1.0x) | 219.32 (2.9x) |
| ES384 | P-384 | small | 346 | **147.62 (1.4x)** | 148.83 (1.4x) | 155.01 (1.3x) | 151.97 (1.4x) | 274.17 (0.8x) | 350.63 (0.6x) | 197.78 (1.0x) | 199.72 (1.0x) | 206.60 (1.0x) | 226.14 (0.9x) |
| ES384 | P-384 | typical | 746 | **146.91 (1.5x)** | 147.93 (1.5x) | 154.94 (1.4x) | 157.40 (1.4x) | 274.15 (0.8x) | 333.44 (0.7x) | 201.52 (1.1x) | 203.46 (1.1x) | 219.17 (1.0x) | 230.57 (1.0x) |
| ES384 | P-384 | medium | 2359 | **150.32 (1.8x)** | 151.36 (1.8x) | 156.08 (1.7x) | 159.56 (1.7x) | 283.88 (0.9x) | 344.15 (0.8x) | 208.34 (1.3x) | 213.74 (1.2x) | 265.57 (1.0x) | 241.70 (1.1x) |
| ES384 | P-384 | large | 20999 | 185.32 (4.3x) | **172.60 (4.6x)** | 183.34 (4.3x) | 240.10 (3.3x) | 351.98 (2.2x) | 410.00 (1.9x) | 295.50 (2.7x) | 328.42 (2.4x) | 788.18 (1.0x) | 371.92 (2.1x) |
| ES512 | P-521 | small | 394 | **276.32 (1.1x)** | 279.13 (1.1x) | 278.89 (1.1x) | n/a | 825.21 (0.4x) | 858.74 (0.4x) | 298.49 (1.0x) | 298.70 (1.0x) | 307.78 (1.0x) | 326.88 (0.9x) |
| ES512 | P-521 | typical | 794 | **276.81 (1.2x)** | 279.83 (1.1x) | 279.98 (1.1x) | n/a | 825.57 (0.4x) | 818.08 (0.4x) | 301.72 (1.1x) | 301.97 (1.1x) | 320.76 (1.0x) | 330.06 (1.0x) |
| ES512 | P-521 | medium | 2407 | **281.14 (1.3x)** | 281.14 (1.3x) | 282.61 (1.3x) | n/a | 831.42 (0.4x) | 822.63 (0.4x) | 308.78 (1.2x) | 311.66 (1.2x) | 368.02 (1.0x) | 341.11 (1.1x) |
| ES512 | P-521 | large | 21047 | 312.15 (2.9x) | **297.08 (3.0x)** | 306.06 (2.9x) | n/a | 891.73 (1.0x) | 880.76 (1.0x) | 393.74 (2.3x) | 426.30 (2.1x) | 892.91 (1.0x) | 470.11 (1.9x) |
| EdDSA | Ed25519 | small | 306 | 31.24 (2.7x) | **31.14 (2.7x)** | 31.77 (2.6x) | 32.10 (2.6x) | 31.34 (2.7x) | 37.99 (2.2x) | n/a | 79.00 (1.1x) | 83.31 (1.0x) | 104.02 (0.8x) |
| EdDSA | Ed25519 | typical | 706 | **31.87 (3.0x)** | 32.10 (3.0x) | 32.88 (2.9x) | 33.57 (2.8x) | 32.59 (2.9x) | 39.10 (2.4x) | n/a | 81.33 (1.2x) | 95.39 (1.0x) | 107.02 (0.9x) |
| EdDSA | Ed25519 | medium | 2319 | 34.35 (4.2x) | **33.27 (4.3x)** | 34.68 (4.1x) | 39.61 (3.6x) | 37.25 (3.8x) | 44.95 (3.2x) | n/a | 91.68 (1.6x) | 142.89 (1.0x) | 118.83 (1.2x) |
| EdDSA | Ed25519 | large | 20959 | 68.17 (9.7x) | **52.41 (12.6x)** | 60.58 (10.9x) | 119.17 (5.5x) | 99.74 (6.6x) | 103.57 (6.4x) | n/a | 207.30 (3.2x) | 661.36 (1.0x) | 249.83 (2.6x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **16.10 (3.5x)** | 16.27 (3.5x) | 18.00 (3.2x) | 19.85 (2.9x) | n/a | 18.27 (3.1x) | 26.58 (2.1x) | 26.95 (2.1x) | 56.89 (1.0x) | 56.97 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **16.62 (4.9x)** | 17.12 (4.7x) | 17.74 (4.6x) | 22.36 (3.6x) | n/a | 20.03 (4.0x) | 30.53 (2.6x) | 30.07 (2.7x) | 80.80 (1.0x) | 60.48 (1.3x) |
| RS256 | RSA 2048 | medium | 2574 | 18.71 (9.1x) | **18.65 (9.1x)** | 19.01 (8.9x) | 27.76 (6.1x) | n/a | 23.93 (7.1x) | 38.61 (4.4x) | 39.70 (4.3x) | 169.37 (1.0x) | 71.93 (2.4x) |
| RS256 | RSA 2048 | large | 21214 | 48.18 (24.1x) | **32.05 (36.2x)** | 40.48 (28.6x) | 109.98 (10.5x) | n/a | 80.05 (14.5x) | 138.98 (8.3x) | 153.01 (7.6x) | 1159.71 (1.0x) | 196.55 (5.9x) |
| RS256 | RSA 3072 | small | 731 | 36.51 (2.2x) | 36.74 (2.2x) | 37.39 (2.1x) | 42.74 (1.9x) | n/a | **30.04 (2.7x)** | 39.59 (2.0x) | 39.65 (2.0x) | 79.60 (1.0x) | 69.33 (1.1x) |
| RS256 | RSA 3072 | typical | 1131 | 37.10 (2.8x) | 37.49 (2.7x) | 38.39 (2.7x) | 45.06 (2.3x) | n/a | **31.96 (3.2x)** | 43.46 (2.4x) | 42.57 (2.4x) | 102.65 (1.0x) | 72.66 (1.4x) |
| RS256 | RSA 3072 | medium | 2744 | 39.38 (4.9x) | 38.73 (4.9x) | 39.84 (4.8x) | 50.28 (3.8x) | n/a | **35.63 (5.4x)** | 51.47 (3.7x) | 52.57 (3.6x) | 191.49 (1.0x) | 83.92 (2.3x) |
| RS256 | RSA 3072 | large | 21384 | 68.94 (17.1x) | **52.97 (22.3x)** | 61.07 (19.4x) | 134.27 (8.8x) | n/a | 91.12 (13.0x) | 151.90 (7.8x) | 163.78 (7.2x) | 1181.92 (1.0x) | 208.61 (5.7x) |
| RS256 | RSA 4096 | small | 902 | 63.14 (1.7x) | 63.72 (1.7x) | 63.95 (1.7x) | 73.88 (1.4x) | n/a | **45.78 (2.3x)** | 57.60 (1.8x) | 57.01 (1.9x) | 106.20 (1.0x) | 87.69 (1.2x) |
| RS256 | RSA 4096 | typical | 1302 | 63.81 (2.0x) | 63.74 (2.0x) | 64.84 (2.0x) | 74.20 (1.8x) | n/a | **46.52 (2.8x)** | 61.50 (2.1x) | 60.78 (2.1x) | 130.28 (1.0x) | 91.07 (1.4x) |
| RS256 | RSA 4096 | medium | 2915 | 66.23 (3.3x) | 67.47 (3.2x) | 66.54 (3.3x) | 79.86 (2.7x) | n/a | **50.52 (4.3x)** | 69.56 (3.1x) | 69.86 (3.1x) | 218.78 (1.0x) | 101.56 (2.2x) |
| RS256 | RSA 4096 | large | 21555 | 95.75 (12.5x) | **82.27 (14.5x)** | 87.59 (13.7x) | 161.44 (7.4x) | n/a | 107.89 (11.1x) | 170.35 (7.0x) | 183.30 (6.5x) | 1196.59 (1.0x) | 228.46 (5.2x) |
| ES256 | P-256 | small | 304 | **31.22 (2.2x)** | 31.34 (2.2x) | 32.09 (2.2x) | 33.98 (2.1x) | n/a | 39.91 (1.8x) | 53.82 (1.3x) | 55.11 (1.3x) | 70.05 (1.0x) | 84.36 (0.8x) |
| ES256 | P-256 | typical | 704 | 31.92 (3.0x) | **31.81 (3.0x)** | 32.93 (2.9x) | 35.39 (2.7x) | n/a | 40.90 (2.3x) | 57.48 (1.7x) | 59.81 (1.6x) | 95.03 (1.0x) | 87.25 (1.1x) |
| ES256 | P-256 | medium | 2317 | 33.93 (5.4x) | **32.90 (5.6x)** | 34.32 (5.3x) | 41.59 (4.4x) | n/a | 45.04 (4.1x) | 65.78 (2.8x) | 68.53 (2.7x) | 183.41 (1.0x) | 98.38 (1.9x) |
| ES256 | P-256 | large | 20957 | 63.59 (18.4x) | **47.25 (24.7x)** | 55.41 (21.1x) | 122.76 (9.5x) | n/a | 106.67 (11.0x) | 166.28 (7.0x) | 179.80 (6.5x) | 1169.36 (1.0x) | 224.48 (5.2x) |
| ES384 | P-384 | small | 346 | **148.22 (1.5x)** | 149.18 (1.5x) | 156.41 (1.4x) | 151.81 (1.4x) | n/a | 336.39 (0.7x) | 200.43 (1.1x) | 201.73 (1.1x) | 219.81 (1.0x) | 233.13 (0.9x) |
| ES384 | P-384 | typical | 746 | **146.39 (1.7x)** | 148.17 (1.6x) | 153.09 (1.6x) | 152.07 (1.6x) | n/a | 334.46 (0.7x) | 204.45 (1.2x) | 205.13 (1.2x) | 243.01 (1.0x) | 235.90 (1.0x) |
| ES384 | P-384 | medium | 2359 | 150.39 (2.2x) | **149.88 (2.2x)** | 157.52 (2.1x) | 158.46 (2.1x) | n/a | 345.14 (1.0x) | 213.03 (1.6x) | 215.01 (1.5x) | 332.12 (1.0x) | 246.40 (1.3x) |
| ES384 | P-384 | large | 20999 | 185.01 (7.1x) | **169.36 (7.8x)** | 183.74 (7.2x) | 251.74 (5.2x) | n/a | 417.83 (3.2x) | 318.63 (4.1x) | 333.05 (4.0x) | 1320.12 (1.0x) | 378.77 (3.5x) |
| ES512 | P-521 | small | 394 | **276.03 (1.2x)** | 276.69 (1.2x) | 280.38 (1.2x) | n/a | n/a | 817.38 (0.4x) | 300.26 (1.1x) | 300.24 (1.1x) | 327.81 (1.0x) | 331.40 (1.0x) |
| ES512 | P-521 | typical | 794 | **276.06 (1.3x)** | 278.14 (1.3x) | 278.63 (1.3x) | n/a | n/a | 822.18 (0.4x) | 303.76 (1.2x) | 305.16 (1.2x) | 352.99 (1.0x) | 334.81 (1.1x) |
| ES512 | P-521 | medium | 2407 | 282.69 (1.5x) | **280.04 (1.6x)** | 283.09 (1.5x) | n/a | n/a | 821.82 (0.5x) | 312.89 (1.4x) | 313.82 (1.4x) | 435.57 (1.0x) | 346.34 (1.3x) |
| ES512 | P-521 | large | 21047 | 312.09 (4.6x) | **297.71 (4.8x)** | 306.33 (4.7x) | n/a | n/a | 881.14 (1.6x) | 416.76 (3.5x) | 430.38 (3.3x) | 1440.74 (1.0x) | 479.86 (3.0x) |
| EdDSA | Ed25519 | small | 306 | 31.25 (3.1x) | **31.08 (3.1x)** | 31.78 (3.0x) | 33.32 (2.9x) | n/a | 38.46 (2.5x) | n/a | 80.42 (1.2x) | 95.78 (1.0x) | 109.18 (0.9x) |
| EdDSA | Ed25519 | typical | 706 | 31.93 (3.7x) | **31.79 (3.7x)** | 32.92 (3.6x) | 34.92 (3.4x) | n/a | 39.12 (3.0x) | n/a | 86.43 (1.4x) | 119.06 (1.0x) | 112.10 (1.1x) |
| EdDSA | Ed25519 | medium | 2319 | 35.11 (5.9x) | **33.46 (6.2x)** | 34.72 (6.0x) | 43.51 (4.8x) | n/a | 44.38 (4.7x) | n/a | 93.34 (2.2x) | 208.05 (1.0x) | 123.15 (1.7x) |
| EdDSA | Ed25519 | large | 20959 | 67.98 (17.7x) | **51.94 (23.1x)** | 60.32 (19.9x) | 127.40 (9.4x) | n/a | 104.30 (11.5x) | n/a | 210.65 (5.7x) | 1200.62 (1.0x) | 255.93 (4.7x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.29 (3.7x) | **16.28 (3.7x)** | 16.83 (3.6x) | n/a | n/a | n/a | n/a | n/a | 60.55 (1.0x) | n/a |
| RS256 | RSA 2048 | typical | 961 | 16.89 (5.0x) | **16.80 (5.0x)** | 19.30 (4.4x) | n/a | n/a | n/a | n/a | n/a | 84.29 (1.0x) | n/a |
| RS256 | RSA 2048 | medium | 2574 | 18.98 (9.4x) | **17.90 (9.9x)** | 19.29 (9.2x) | n/a | n/a | n/a | n/a | n/a | 177.71 (1.0x) | n/a |
| RS256 | RSA 2048 | large | 21214 | 48.79 (24.5x) | **32.11 (37.2x)** | 40.67 (29.4x) | n/a | n/a | n/a | n/a | n/a | 1195.60 (1.0x) | n/a |
| RS256 | RSA 3072 | small | 731 | 37.00 (2.2x) | **36.92 (2.2x)** | 37.61 (2.2x) | n/a | n/a | n/a | n/a | n/a | 82.20 (1.0x) | n/a |
| RS256 | RSA 3072 | typical | 1131 | 37.41 (2.8x) | **37.37 (2.8x)** | 38.48 (2.8x) | n/a | n/a | n/a | n/a | n/a | 106.47 (1.0x) | n/a |
| RS256 | RSA 3072 | medium | 2744 | 39.53 (5.0x) | **38.60 (5.2x)** | 40.05 (5.0x) | n/a | n/a | n/a | n/a | n/a | 199.39 (1.0x) | n/a |
| RS256 | RSA 3072 | large | 21384 | 69.36 (17.7x) | **53.01 (23.1x)** | 63.40 (19.3x) | n/a | n/a | n/a | n/a | n/a | 1225.23 (1.0x) | n/a |
| RS256 | RSA 4096 | small | 902 | 66.39 (1.6x) | **63.65 (1.7x)** | 64.43 (1.7x) | n/a | n/a | n/a | n/a | n/a | 108.57 (1.0x) | n/a |
| RS256 | RSA 4096 | typical | 1302 | **64.07 (2.1x)** | 66.63 (2.0x) | 65.41 (2.0x) | n/a | n/a | n/a | n/a | n/a | 133.19 (1.0x) | n/a |
| RS256 | RSA 4096 | medium | 2915 | 67.04 (3.4x) | **64.87 (3.5x)** | 67.15 (3.4x) | n/a | n/a | n/a | n/a | n/a | 227.96 (1.0x) | n/a |
| RS256 | RSA 4096 | large | 21555 | 95.80 (13.0x) | **79.06 (15.7x)** | 88.49 (14.0x) | n/a | n/a | n/a | n/a | n/a | 1241.56 (1.0x) | n/a |
| ES256 | P-256 | small | 304 | 31.76 (2.3x) | **31.49 (2.3x)** | 32.10 (2.3x) | n/a | n/a | n/a | n/a | n/a | 72.75 (1.0x) | n/a |
| ES256 | P-256 | typical | 704 | 32.05 (3.1x) | **31.99 (3.1x)** | 33.16 (3.0x) | n/a | n/a | n/a | n/a | n/a | 97.84 (1.0x) | n/a |
| ES256 | P-256 | medium | 2317 | 34.19 (5.6x) | **33.10 (5.7x)** | 34.58 (5.5x) | n/a | n/a | n/a | n/a | n/a | 189.80 (1.0x) | n/a |
| ES256 | P-256 | large | 20957 | 64.12 (18.9x) | **49.32 (24.6x)** | 56.10 (21.6x) | n/a | n/a | n/a | n/a | n/a | 1212.49 (1.0x) | n/a |
| ES384 | P-384 | small | 346 | **147.80 (1.5x)** | 148.06 (1.5x) | 148.55 (1.5x) | n/a | n/a | n/a | n/a | n/a | 223.60 (1.0x) | n/a |
| ES384 | P-384 | typical | 746 | 147.58 (1.7x) | **146.08 (1.7x)** | 147.63 (1.7x) | n/a | n/a | n/a | n/a | n/a | 246.53 (1.0x) | n/a |
| ES384 | P-384 | medium | 2359 | 151.47 (2.3x) | **149.00 (2.3x)** | 151.92 (2.2x) | n/a | n/a | n/a | n/a | n/a | 341.82 (1.0x) | n/a |
| ES384 | P-384 | large | 20999 | 185.59 (7.4x) | **169.62 (8.1x)** | 177.38 (7.7x) | n/a | n/a | n/a | n/a | n/a | 1373.45 (1.0x) | n/a |
| ES512 | P-521 | small | 394 | **276.91 (1.2x)** | 276.95 (1.2x) | 277.88 (1.2x) | n/a | n/a | n/a | n/a | n/a | 324.18 (1.0x) | n/a |
| ES512 | P-521 | typical | 794 | **276.71 (1.3x)** | 278.50 (1.3x) | 277.83 (1.3x) | n/a | n/a | n/a | n/a | n/a | 354.63 (1.0x) | n/a |
| ES512 | P-521 | medium | 2407 | **280.40 (1.6x)** | 280.86 (1.6x) | 281.53 (1.6x) | n/a | n/a | n/a | n/a | n/a | 442.57 (1.0x) | n/a |
| ES512 | P-521 | large | 21047 | 311.75 (4.8x) | **295.85 (5.1x)** | 305.23 (4.9x) | n/a | n/a | n/a | n/a | n/a | 1494.91 (1.0x) | n/a |
| EdDSA | Ed25519 | small | 306 | 31.45 (3.1x) | **31.29 (3.1x)** | 32.04 (3.1x) | n/a | n/a | n/a | n/a | n/a | 98.31 (1.0x) | n/a |
| EdDSA | Ed25519 | typical | 706 | 32.12 (3.8x) | **31.98 (3.8x)** | 33.17 (3.7x) | n/a | n/a | n/a | n/a | n/a | 121.85 (1.0x) | n/a |
| EdDSA | Ed25519 | medium | 2319 | 34.49 (6.3x) | **33.41 (6.5x)** | 35.02 (6.2x) | n/a | n/a | n/a | n/a | n/a | 216.27 (1.0x) | n/a |
| EdDSA | Ed25519 | large | 20959 | 68.73 (18.0x) | **52.11 (23.8x)** | 60.80 (20.4x) | n/a | n/a | n/a | n/a | n/a | 1240.16 (1.0x) | n/a |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.32 (3.7x) | **16.27 (3.7x)** | 16.90 (3.6x) | n/a | 38.78 (1.6x) | 18.77 (3.2x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | 16.96 (5.0x) | **16.78 (5.0x)** | 17.92 (4.7x) | n/a | 33.84 (2.5x) | 19.80 (4.3x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | 18.99 (9.4x) | **17.81 (10.0x)** | 19.37 (9.2x) | n/a | 38.07 (4.7x) | 24.15 (7.4x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | 49.18 (24.3x) | **32.17 (37.2x)** | 40.89 (29.2x) | n/a | 97.68 (12.2x) | 79.99 (14.9x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | 36.96 (2.2x) | 37.04 (2.2x) | 37.48 (2.2x) | n/a | 56.82 (1.4x) | **30.56 (2.7x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | 37.53 (2.8x) | 37.44 (2.8x) | 38.61 (2.8x) | n/a | 59.27 (1.8x) | **31.98 (3.3x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | 39.72 (5.0x) | 38.52 (5.2x) | 41.38 (4.8x) | n/a | 63.39 (3.1x) | **35.48 (5.6x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | 69.07 (17.7x) | **52.78 (23.2x)** | 63.93 (19.2x) | n/a | 122.19 (10.0x) | 90.93 (13.5x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | 63.81 (1.7x) | 63.59 (1.7x) | 66.98 (1.6x) | n/a | 88.72 (1.2x) | **46.13 (2.4x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | 64.20 (2.1x) | 66.78 (2.0x) | 65.45 (2.0x) | n/a | 89.71 (1.5x) | **46.96 (2.8x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | 66.95 (3.4x) | 68.61 (3.3x) | 68.37 (3.3x) | n/a | 94.14 (2.4x) | **51.12 (4.5x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | 98.72 (12.6x) | **82.02 (15.1x)** | 87.81 (14.1x) | n/a | 155.46 (8.0x) | 106.65 (11.6x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | small | 304 | **31.59 (2.3x)** | 31.81 (2.3x) | 32.03 (2.3x) | n/a | 2063.96 (0.04x) | 39.58 (1.8x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | typical | 704 | 32.46 (3.0x) | **32.14 (3.0x)** | 33.17 (2.9x) | n/a | 2070.27 (0.05x) | 40.84 (2.4x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | medium | 2317 | 34.43 (5.5x) | **33.18 (5.7x)** | 34.53 (5.5x) | n/a | 2087.81 (0.09x) | 45.31 (4.2x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | large | 20957 | 64.01 (18.9x) | **47.41 (25.6x)** | 56.10 (21.6x) | n/a | 2080.07 (0.6x) | 100.17 (12.1x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | small | 346 | **147.59 (1.5x)** | 148.26 (1.5x) | 153.69 (1.5x) | n/a | 15084.88 (0.01x) | 333.56 (0.7x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | typical | 746 | **146.61 (1.7x)** | 146.77 (1.7x) | 151.87 (1.6x) | n/a | 14840.32 (0.02x) | 335.12 (0.7x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | medium | 2359 | 150.19 (2.3x) | **149.59 (2.3x)** | 155.60 (2.2x) | n/a | 14948.03 (0.02x) | 356.61 (1.0x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | large | 20999 | 184.73 (7.4x) | **169.55 (8.1x)** | 181.46 (7.6x) | n/a | 15066.78 (0.09x) | 416.06 (3.3x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | small | 394 | 282.39 (1.1x) | **277.98 (1.2x)** | 289.63 (1.1x) | n/a | 36217.83 (0.01x) | 821.26 (0.4x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | typical | 794 | 280.62 (1.3x) | **276.26 (1.3x)** | 290.48 (1.2x) | n/a | 35897.09 (0.01x) | 817.78 (0.4x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | medium | 2407 | 284.60 (1.6x) | **279.86 (1.6x)** | 295.21 (1.5x) | n/a | 35924.63 (0.01x) | 824.83 (0.5x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | large | 21047 | 317.98 (4.7x) | **295.81 (5.1x)** | 318.00 (4.7x) | n/a | 35964.72 (0.04x) | 883.75 (1.7x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | 32.18 (3.1x) | **31.38 (3.1x)** | 32.01 (3.1x) | n/a | n/a | 38.42 (2.6x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | 32.65 (3.7x) | **31.99 (3.8x)** | 33.08 (3.7x) | n/a | n/a | 39.26 (3.1x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | 35.81 (6.0x) | **33.44 (6.5x)** | 34.87 (6.2x) | n/a | n/a | 44.43 (4.9x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | 72.59 (17.1x) | **52.11 (23.8x)** | 60.71 (20.4x) | n/a | n/a | 104.38 (11.9x) | n/a | n/a | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 1.5 | 1.6 | 1.4 | n/a | n/a | n/a | n/a | n/a | 1.6 | n/a |
| JWKS URL, async client | 1.5 | 1.6 | 1.5 | n/a | 1.1 | 0.8 | n/a | n/a | n/a | n/a |

## Not applicable

- jsonwebtoken 11.1.0 (aws-lc-rs), every key source, ES512: jsonwebtoken has no ES512 (P-521).
- jsonwebtoken 11.1.0 (aws-lc-rs), JWKS URL, sync client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs), JWKS URL, async client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- fast-jwt 6.3.3, JWKS document: fast-jwt takes JWKS only from a URL (via get-jwks), not a document.
- fast-jwt 6.3.3, JWKS URL, sync client: fast-jwt's JWKS support (get-jwks) is async only.
- fast-jwt 6.3.3, JWKS URL, async client, EdDSA: get-jwks converts JWKs with jwk-to-pem, which doesn't support OKP (Ed25519) keys.
- jose 6.2.12, JWKS URL, sync client: jose's API is async only.
- python-jose 3.5.0, JWKS URL, sync client: python-jose has no JWKS URL client.
- python-jose 3.5.0, JWKS URL, async client: python-jose has no JWKS URL client.
- python-jose 3.5.0, PEM public key, EdDSA: python-jose has no EdDSA.
- python-jose 3.5.0, JWKS document, EdDSA: python-jose has no EdDSA.
- joserfc 1.7.5, JWKS URL, sync client: joserfc has no JWKS URL client.
- joserfc 1.7.5, JWKS URL, async client: joserfc has no JWKS URL client.
- pyjwt 2.15.1, JWKS URL, async client: PyJWT has no async JWKS client.
- jwcrypto 1.6.1, JWKS URL, sync client: jwcrypto has no JWKS URL client.
- jwcrypto 1.6.1, JWKS URL, async client: jwcrypto has no JWKS URL client.

## Notes

- ryjwt 0.1.0 → dict: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.0 → dict: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.0 → Struct: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.0 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.0 → BaseModel: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.0 → BaseModel: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- jsonwebtoken 11.1.0 (aws-lc-rs): JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- fast-jwt 6.3.3: JWKS URL via get-jwks 11.0.3 (fast-jwt's documented integration): it converts the cached JWK to a PEM, which fast-jwt parses, on every verify.
- jose 6.2.12: `importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`.
- python-jose 3.5.0: `jose.jwt.decode(token, key, algorithms=[...], audience=...)`, the key built once with `jwk.construct` (from the secret or the PEM).
- python-jose 3.5.0: JWKS document: each key built once with `jwk.construct`, picking the key by `get_unverified_header`'s `kid` (given the document itself, python-jose tries each key in turn).
- joserfc 1.7.5: `jwt.decode(token, key, algorithms=[...])`, then `JWTClaimsRegistry(exp=..., aud=...).validate(token.claims)`, both essential.
- joserfc 1.7.5: keys imported once (`OctKey`, `RSAKey`, `ECKey`, `OKPKey`); JWKS document: a `KeySet`, which picks the key by `kid`.
- joserfc 1.7.5: EdDSA: joserfc warns on every decode (`SecurityWarning`: RFC 9864 deprecates `EdDSA`), as it does by default.
- pyjwt 2.15.1: PEM: the key loaded once, with `load_pem_public_key`.
- pyjwt 2.15.1: JWKS document: `PyJWKSet`, picking the key by `get_unverified_header`'s `kid`.
- pyjwt 2.15.1: JWKS URL: `PyJWKClient(cache_keys=True)`, its `ssl_context` trusting the test CA.
- jwcrypto 1.6.1: `jwt.JWT(jwt=token, key=key, algs=[...], check_claims={"exp": None, "aud": ...})`, then `json.loads` of its `claims`.
- jwcrypto 1.6.1: keys built once (`JWK.from_password`, `JWK.from_pem`); JWKS document: a `JWKSet`, which picks the key by `kid`.
