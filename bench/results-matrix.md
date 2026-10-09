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

| key source | alg | key | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | ryjwt 0.0.0a0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | **1.12 (30.3x)** | 1.17 (29.0x) | 2.18 (15.5x) | 3.33 (10.2x) | 3.47 (9.8x) | 11.38 (3.0x) | 13.64 (2.5x) | 14.71 (2.3x) | 33.85 (1.0x) | 42.44 (0.8x) |
| PEM public key | RS256 | RSA 3072 | 38.09 (1.8x) | 37.47 (1.8x) | 40.91 (1.7x) | 43.02 (1.6x) | **25.92 (2.6x)** | 32.42 (2.1x) | 39.50 (1.7x) | 40.64 (1.7x) | 68.64 (1.0x) | 68.46 (1.0x) |
| PEM public key | ES384 | P-384 | 148.49 (1.5x) | **147.79 (1.5x)** | 148.72 (1.5x) | 149.25 (1.5x) | 275.28 (0.8x) | 348.73 (0.6x) | 201.70 (1.1x) | 206.01 (1.1x) | 220.99 (1.0x) | 231.43 (1.0x) |
| PEM public key | EdDSA | Ed25519 | 32.33 (3.0x) | **31.93 (3.0x)** | 33.30 (2.9x) | 33.51 (2.9x) | 33.20 (2.9x) | 39.14 (2.4x) | n/a | 81.87 (1.2x) | 95.81 (1.0x) | 108.39 (0.9x) |
| JWKS document | RS256 | RSA 3072 | 37.42 (2.8x) | 37.68 (2.7x) | 38.81 (2.7x) | 43.38 (2.4x) | n/a | **33.97 (3.1x)** | 43.99 (2.4x) | 42.84 (2.4x) | 103.63 (1.0x) | 74.71 (1.4x) |
| JWKS URL, sync client | RS256 | RSA 3072 | 37.78 (2.8x) | **37.47 (2.9x)** | 39.48 (2.7x) | n/a | n/a | n/a | n/a | n/a | 107.60 (1.0x) | n/a |
| JWKS URL, async client | RS256 | RSA 3072 | 37.68 (2.9x) | 39.30 (2.7x) | 38.54 (2.8x) | n/a | 58.94 (1.8x) | **31.97 (3.4x)** | n/a | n/a | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | ryjwt 0.0.0a0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | 0.59 (33.5x) | **0.55 (35.8x)** | 1.21 (16.3x) | 1.60 (12.3x) | 2.16 (9.1x) | 12.11 (1.6x) | 10.07 (2.0x) | 11.55 (1.7x) | 19.71 (1.0x) | 38.71 (0.5x) |
| HS256 | 32 B | typical | 661 | **1.12 (29.7x)** | 1.18 (28.1x) | 2.19 (15.1x) | 3.26 (10.2x) | 3.72 (8.9x) | 12.12 (2.7x) | 13.84 (2.4x) | 14.57 (2.3x) | 33.17 (1.0x) | 42.71 (0.8x) |
| HS256 | 32 B | medium | 2244 | **2.13 (37.1x)** | 3.26 (24.2x) | 3.47 (22.7x) | 8.91 (8.8x) | 7.21 (10.9x) | 16.01 (4.9x) | 19.79 (4.0x) | 24.81 (3.2x) | 78.78 (1.0x) | 53.33 (1.5x) |
| HS256 | 32 B | large | 20884 | **17.28 (34.5x)** | 32.54 (18.3x) | 24.53 (24.3x) | 84.90 (7.0x) | 65.11 (9.2x) | 75.34 (7.9x) | 101.54 (5.9x) | 136.10 (4.4x) | 595.91 (1.0x) | 178.88 (3.3x) |
| HS256 | 64 B | small | 231 | 0.61 (33.0x) | **0.56 (35.8x)** | 1.18 (16.9x) | 1.62 (12.4x) | 2.19 (9.1x) | 9.76 (2.0x) | 10.16 (2.0x) | 11.55 (1.7x) | 19.99 (1.0x) | 38.30 (0.5x) |
| HS256 | 64 B | typical | 661 | **1.12 (30.3x)** | 1.17 (29.0x) | 2.18 (15.5x) | 3.33 (10.2x) | 3.47 (9.8x) | 11.38 (3.0x) | 13.64 (2.5x) | 14.71 (2.3x) | 33.85 (1.0x) | 42.44 (0.8x) |
| HS256 | 64 B | medium | 2244 | **2.19 (36.4x)** | 3.23 (24.7x) | 3.52 (22.7x) | 8.77 (9.1x) | 7.15 (11.2x) | 15.71 (5.1x) | 19.87 (4.0x) | 24.53 (3.3x) | 79.86 (1.0x) | 53.32 (1.5x) |
| HS256 | 64 B | large | 20884 | **16.70 (36.4x)** | 32.32 (18.8x) | 24.58 (24.7x) | 84.29 (7.2x) | 66.61 (9.1x) | 74.86 (8.1x) | 101.57 (6.0x) | 135.13 (4.5x) | 607.14 (1.0x) | 180.31 (3.4x) |
| HS256 | 256 B | small | 231 | 0.59 (35.6x) | **0.54 (38.8x)** | 1.18 (17.8x) | 1.74 (12.1x) | 2.30 (9.1x) | 9.84 (2.1x) | 10.20 (2.1x) | 11.52 (1.8x) | 20.99 (1.0x) | 38.85 (0.5x) |
| HS256 | 256 B | typical | 661 | **1.12 (30.8x)** | 1.15 (29.9x) | 2.17 (15.9x) | 3.42 (10.1x) | 3.76 (9.2x) | 11.14 (3.1x) | 13.72 (2.5x) | 14.82 (2.3x) | 34.48 (1.0x) | 43.02 (0.8x) |
| HS256 | 256 B | medium | 2244 | **2.16 (37.0x)** | 3.29 (24.3x) | 3.51 (22.8x) | 8.79 (9.1x) | 7.18 (11.1x) | 15.82 (5.1x) | 19.74 (4.1x) | 24.36 (3.3x) | 80.04 (1.0x) | 53.92 (1.5x) |
| HS256 | 256 B | large | 20884 | **16.73 (36.0x)** | 32.24 (18.7x) | 24.48 (24.6x) | 83.20 (7.2x) | 66.16 (9.1x) | 75.23 (8.0x) | 102.46 (5.9x) | 135.65 (4.4x) | 602.57 (1.0x) | 181.41 (3.3x) |
| HS256 | 4096 B | small | 231 | 0.57 (76.9x) | **0.54 (80.3x)** | 1.18 (37.0x) | 3.06 (14.2x) | 3.69 (11.8x) | 11.87 (3.7x) | 11.59 (3.8x) | 13.20 (3.3x) | 43.55 (1.0x) | 45.19 (1.0x) |
| HS256 | 4096 B | typical | 661 | **1.08 (53.0x)** | 1.16 (49.7x) | 2.19 (26.2x) | 4.74 (12.1x) | 5.03 (11.4x) | 13.45 (4.3x) | 15.07 (3.8x) | 16.26 (3.5x) | 57.44 (1.0x) | 49.40 (1.2x) |
| HS256 | 4096 B | medium | 2244 | **2.11 (48.8x)** | 3.20 (32.2x) | 3.54 (29.1x) | 10.10 (10.2x) | 8.88 (11.6x) | 17.90 (5.8x) | 21.25 (4.8x) | 25.66 (4.0x) | 102.94 (1.0x) | 59.79 (1.7x) |
| HS256 | 4096 B | large | 20884 | **16.38 (38.1x)** | 32.96 (18.9x) | 24.45 (25.5x) | 85.10 (7.3x) | 66.82 (9.3x) | 76.08 (8.2x) | 104.01 (6.0x) | 136.71 (4.6x) | 623.40 (1.0x) | 185.20 (3.4x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | ryjwt 0.0.0a0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.36 (2.3x) | 16.09 (2.3x) | 16.90 (2.2x) | 19.41 (1.9x) | **14.20 (2.6x)** | 19.74 (1.9x) | 23.91 (1.6x) | 24.91 (1.5x) | 37.62 (1.0x) | 51.88 (0.7x) |
| RS256 | RSA 2048 | typical | 961 | 16.82 (3.0x) | 16.85 (3.0x) | 17.98 (2.8x) | 20.83 (2.4x) | **14.73 (3.4x)** | 20.48 (2.4x) | 26.74 (1.9x) | 27.70 (1.8x) | 49.96 (1.0x) | 55.12 (0.9x) |
| RS256 | RSA 2048 | medium | 2574 | **17.84 (5.4x)** | 18.97 (5.1x) | 19.24 (5.0x) | 26.66 (3.6x) | 18.45 (5.2x) | 25.25 (3.8x) | 33.35 (2.9x) | 37.61 (2.6x) | 96.41 (1.0x) | 66.98 (1.4x) |
| RS256 | RSA 2048 | large | 21214 | **32.26 (19.0x)** | 48.72 (12.6x) | 40.20 (15.3x) | 101.76 (6.0x) | 77.88 (7.9x) | 83.91 (7.3x) | 116.40 (5.3x) | 147.30 (4.2x) | 613.74 (1.0x) | 193.79 (3.2x) |
| RS256 | RSA 3072 | small | 731 | 37.29 (1.5x) | 36.80 (1.5x) | 39.73 (1.4x) | 41.57 (1.3x) | **25.42 (2.2x)** | 31.20 (1.8x) | 36.16 (1.5x) | 37.69 (1.5x) | 55.42 (1.0x) | 65.03 (0.9x) |
| RS256 | RSA 3072 | typical | 1131 | 38.09 (1.8x) | 37.47 (1.8x) | 40.91 (1.7x) | 43.02 (1.6x) | **25.92 (2.6x)** | 32.42 (2.1x) | 39.50 (1.7x) | 40.64 (1.7x) | 68.64 (1.0x) | 68.46 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 39.00 (3.0x) | 39.44 (2.9x) | 42.09 (2.7x) | 48.82 (2.4x) | **29.89 (3.9x)** | 36.93 (3.1x) | 46.10 (2.5x) | 50.62 (2.3x) | 115.34 (1.0x) | 79.91 (1.4x) |
| RS256 | RSA 3072 | large | 21384 | **53.59 (11.9x)** | 69.90 (9.1x) | 63.11 (10.1x) | 124.30 (5.1x) | 89.14 (7.1x) | 95.42 (6.7x) | 129.65 (4.9x) | 161.09 (4.0x) | 637.20 (1.0x) | 206.44 (3.1x) |
| RS256 | RSA 4096 | small | 902 | 64.61 (1.2x) | 66.42 (1.2x) | 64.70 (1.2x) | 70.94 (1.1x) | **40.36 (1.9x)** | 47.02 (1.7x) | 55.43 (1.4x) | 55.21 (1.4x) | 77.63 (1.0x) | 82.27 (0.9x) |
| RS256 | RSA 4096 | typical | 1302 | 64.69 (1.4x) | 67.36 (1.4x) | 65.75 (1.4x) | 72.32 (1.3x) | **41.69 (2.2x)** | 48.69 (1.9x) | 57.25 (1.6x) | 58.30 (1.6x) | 91.43 (1.0x) | 85.92 (1.1x) |
| RS256 | RSA 4096 | medium | 2915 | 65.56 (2.1x) | 68.83 (2.0x) | 67.33 (2.0x) | 78.11 (1.8x) | **46.65 (3.0x)** | 53.39 (2.6x) | 64.14 (2.1x) | 69.57 (2.0x) | 137.83 (1.0x) | 96.87 (1.4x) |
| RS256 | RSA 4096 | large | 21555 | **80.61 (8.4x)** | 98.58 (6.9x) | 88.63 (7.6x) | 153.28 (4.4x) | 104.77 (6.5x) | 111.67 (6.1x) | 147.46 (4.6x) | 180.31 (3.8x) | 676.34 (1.0x) | 222.22 (3.0x) |
| ES256 | P-256 | small | 304 | 31.80 (1.9x) | **31.40 (1.9x)** | 32.13 (1.9x) | 32.78 (1.9x) | 35.22 (1.7x) | 41.32 (1.5x) | 51.22 (1.2x) | 54.50 (1.1x) | 60.90 (1.0x) | 80.37 (0.8x) |
| ES256 | P-256 | typical | 704 | **32.08 (2.3x)** | 32.18 (2.3x) | 33.47 (2.2x) | 34.48 (2.1x) | 35.48 (2.1x) | 42.93 (1.7x) | 54.42 (1.3x) | 57.70 (1.3x) | 73.40 (1.0x) | 83.38 (0.9x) |
| ES256 | P-256 | medium | 2317 | **33.21 (3.7x)** | 35.05 (3.5x) | 34.82 (3.5x) | 39.92 (3.1x) | 39.44 (3.1x) | 48.05 (2.6x) | 60.91 (2.0x) | 67.78 (1.8x) | 123.30 (1.0x) | 94.25 (1.3x) |
| ES256 | P-256 | large | 20957 | **47.67 (14.0x)** | 71.08 (9.4x) | 55.40 (12.0x) | 115.22 (5.8x) | 99.42 (6.7x) | 107.09 (6.2x) | 143.90 (4.6x) | 177.43 (3.8x) | 666.63 (1.0x) | 218.68 (3.0x) |
| ES384 | P-384 | small | 346 | 149.58 (1.4x) | **148.92 (1.4x)** | 150.34 (1.4x) | 149.87 (1.4x) | 274.87 (0.8x) | 347.71 (0.6x) | 197.87 (1.1x) | 203.34 (1.1x) | 214.21 (1.0x) | 227.67 (0.9x) |
| ES384 | P-384 | typical | 746 | 148.49 (1.5x) | **147.79 (1.5x)** | 148.72 (1.5x) | 149.25 (1.5x) | 275.28 (0.8x) | 348.73 (0.6x) | 201.70 (1.1x) | 206.01 (1.1x) | 220.99 (1.0x) | 231.43 (1.0x) |
| ES384 | P-384 | medium | 2359 | 153.23 (1.8x) | 156.96 (1.7x) | **152.40 (1.8x)** | 156.94 (1.7x) | 285.21 (1.0x) | 357.11 (0.8x) | 209.59 (1.3x) | 213.98 (1.3x) | 270.96 (1.0x) | 241.52 (1.1x) |
| ES384 | P-384 | large | 20999 | **172.42 (4.6x)** | 189.31 (4.2x) | 178.81 (4.4x) | 238.01 (3.3x) | 352.85 (2.2x) | 421.45 (1.9x) | 300.68 (2.6x) | 333.80 (2.4x) | 789.78 (1.0x) | 370.75 (2.1x) |
| ES512 | P-521 | small | 394 | 287.99 (1.1x) | **278.45 (1.1x)** | 280.97 (1.1x) | n/a | 689.88 (0.5x) | 853.39 (0.4x) | 300.06 (1.0x) | 303.64 (1.0x) | 313.77 (1.0x) | 327.05 (1.0x) |
| ES512 | P-521 | typical | 794 | 285.85 (1.1x) | **277.47 (1.2x)** | 279.21 (1.2x) | n/a | 688.77 (0.5x) | 836.78 (0.4x) | 301.08 (1.1x) | 308.96 (1.1x) | 327.03 (1.0x) | 330.10 (1.0x) |
| ES512 | P-521 | medium | 2407 | 290.39 (1.3x) | **281.96 (1.3x)** | 283.72 (1.3x) | n/a | 713.25 (0.5x) | 835.07 (0.4x) | 309.70 (1.2x) | 318.68 (1.2x) | 369.19 (1.0x) | 342.66 (1.1x) |
| ES512 | P-521 | large | 21047 | **305.84 (3.0x)** | 314.25 (2.9x) | 306.72 (3.0x) | n/a | 766.25 (1.2x) | 888.65 (1.0x) | 395.73 (2.3x) | 431.66 (2.1x) | 904.92 (1.0x) | 470.65 (1.9x) |
| EdDSA | Ed25519 | small | 306 | 31.77 (2.7x) | **31.49 (2.7x)** | 32.15 (2.6x) | 32.03 (2.6x) | 31.66 (2.7x) | 37.88 (2.2x) | n/a | 79.27 (1.1x) | 84.56 (1.0x) | 105.72 (0.8x) |
| EdDSA | Ed25519 | typical | 706 | 32.33 (3.0x) | **31.93 (3.0x)** | 33.30 (2.9x) | 33.51 (2.9x) | 33.20 (2.9x) | 39.14 (2.4x) | n/a | 81.87 (1.2x) | 95.81 (1.0x) | 108.39 (0.9x) |
| EdDSA | Ed25519 | medium | 2319 | **33.71 (4.3x)** | 34.64 (4.2x) | 35.26 (4.1x) | 40.63 (3.6x) | 37.26 (3.9x) | 44.05 (3.3x) | n/a | 92.58 (1.6x) | 145.06 (1.0x) | 119.42 (1.2x) |
| EdDSA | Ed25519 | large | 20959 | **52.17 (13.0x)** | 68.67 (9.9x) | 60.64 (11.2x) | 119.44 (5.7x) | 100.46 (6.8x) | 105.24 (6.4x) | n/a | 208.88 (3.2x) | 678.79 (1.0x) | 249.53 (2.7x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | ryjwt 0.0.0a0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **16.26 (3.5x)** | 16.43 (3.5x) | 16.86 (3.4x) | 19.68 (2.9x) | n/a | 20.78 (2.8x) | 27.11 (2.1x) | 27.12 (2.1x) | 57.65 (1.0x) | 57.25 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **16.62 (4.9x)** | 16.89 (4.8x) | 18.05 (4.5x) | 21.29 (3.8x) | n/a | 22.76 (3.6x) | 30.88 (2.6x) | 30.12 (2.7x) | 81.42 (1.0x) | 61.51 (1.3x) |
| RS256 | RSA 2048 | medium | 2574 | **17.76 (9.7x)** | 18.74 (9.2x) | 19.19 (8.9x) | 27.46 (6.3x) | n/a | 24.23 (7.1x) | 39.16 (4.4x) | 39.86 (4.3x) | 171.70 (1.0x) | 72.22 (2.4x) |
| RS256 | RSA 2048 | large | 21214 | **32.37 (36.8x)** | 48.28 (24.7x) | 40.11 (29.7x) | 109.17 (10.9x) | n/a | 91.23 (13.1x) | 139.40 (8.5x) | 151.57 (7.9x) | 1190.96 (1.0x) | 201.68 (5.9x) |
| RS256 | RSA 3072 | small | 731 | 37.02 (2.2x) | 36.91 (2.2x) | 40.12 (2.0x) | 42.32 (1.9x) | n/a | **32.68 (2.4x)** | 39.85 (2.0x) | 39.50 (2.0x) | 79.84 (1.0x) | 73.88 (1.1x) |
| RS256 | RSA 3072 | typical | 1131 | 37.42 (2.8x) | 37.68 (2.7x) | 38.81 (2.7x) | 43.38 (2.4x) | n/a | **33.97 (3.1x)** | 43.99 (2.4x) | 42.84 (2.4x) | 103.63 (1.0x) | 74.71 (1.4x) |
| RS256 | RSA 3072 | medium | 2744 | 38.32 (5.1x) | 40.54 (4.8x) | 40.08 (4.9x) | 50.29 (3.9x) | n/a | **35.50 (5.5x)** | 51.79 (3.8x) | 52.37 (3.7x) | 195.34 (1.0x) | 84.79 (2.3x) |
| RS256 | RSA 3072 | large | 21384 | **53.23 (22.6x)** | 71.13 (16.9x) | 60.89 (19.8x) | 133.26 (9.0x) | n/a | 91.95 (13.1x) | 152.61 (7.9x) | 164.55 (7.3x) | 1204.29 (1.0x) | 213.17 (5.6x) |
| RS256 | RSA 4096 | small | 902 | 64.18 (1.7x) | 66.23 (1.7x) | 64.44 (1.7x) | 71.72 (1.5x) | n/a | **45.83 (2.4x)** | 59.57 (1.8x) | 57.16 (1.9x) | 109.60 (1.0x) | 87.76 (1.2x) |
| RS256 | RSA 4096 | typical | 1302 | 64.48 (2.1x) | 66.68 (2.0x) | 68.38 (2.0x) | 73.91 (1.8x) | n/a | **47.71 (2.8x)** | 61.89 (2.2x) | 61.06 (2.2x) | 133.60 (1.0x) | 92.09 (1.5x) |
| RS256 | RSA 4096 | medium | 2915 | 65.14 (3.5x) | 66.73 (3.4x) | 66.98 (3.4x) | 79.33 (2.8x) | n/a | **50.99 (4.4x)** | 69.57 (3.2x) | 70.83 (3.2x) | 225.30 (1.0x) | 103.31 (2.2x) |
| RS256 | RSA 4096 | large | 21555 | **80.29 (15.5x)** | 96.34 (12.9x) | 87.73 (14.2x) | 160.75 (7.8x) | n/a | 107.29 (11.6x) | 171.17 (7.3x) | 186.42 (6.7x) | 1246.32 (1.0x) | 231.14 (5.4x) |
| ES256 | P-256 | small | 304 | 31.62 (2.3x) | **31.61 (2.3x)** | 32.21 (2.3x) | 32.97 (2.2x) | n/a | 39.60 (1.9x) | 53.74 (1.4x) | 55.51 (1.3x) | 74.15 (1.0x) | 84.85 (0.9x) |
| ES256 | P-256 | typical | 704 | **32.14 (3.0x)** | 33.18 (2.9x) | 33.37 (2.9x) | 35.11 (2.7x) | n/a | 41.25 (2.3x) | 57.66 (1.7x) | 58.76 (1.6x) | 95.56 (1.0x) | 89.73 (1.1x) |
| ES256 | P-256 | medium | 2317 | **32.98 (5.7x)** | 34.25 (5.5x) | 34.83 (5.4x) | 41.97 (4.5x) | n/a | 45.35 (4.1x) | 65.91 (2.8x) | 68.21 (2.7x) | 186.76 (1.0x) | 99.81 (1.9x) |
| ES256 | P-256 | large | 20957 | **47.38 (25.1x)** | 63.79 (18.7x) | 55.41 (21.5x) | 122.15 (9.7x) | n/a | 100.28 (11.9x) | 167.44 (7.1x) | 180.39 (6.6x) | 1189.82 (1.0x) | 227.80 (5.2x) |
| ES384 | P-384 | small | 346 | **148.92 (1.5x)** | 149.88 (1.5x) | 149.72 (1.5x) | 150.77 (1.5x) | n/a | 336.04 (0.7x) | 202.02 (1.1x) | 202.73 (1.1x) | 225.16 (1.0x) | 232.25 (1.0x) |
| ES384 | P-384 | typical | 746 | 148.33 (1.6x) | **147.05 (1.7x)** | 149.30 (1.6x) | 151.17 (1.6x) | n/a | 336.07 (0.7x) | 203.90 (1.2x) | 207.41 (1.2x) | 244.04 (1.0x) | 236.82 (1.0x) |
| ES384 | P-384 | medium | 2359 | **151.12 (2.2x)** | 151.24 (2.2x) | 152.46 (2.2x) | 161.34 (2.1x) | n/a | 344.16 (1.0x) | 213.19 (1.6x) | 215.75 (1.6x) | 334.75 (1.0x) | 249.87 (1.3x) |
| ES384 | P-384 | large | 20999 | **169.62 (7.9x)** | 186.62 (7.1x) | 180.46 (7.4x) | 245.07 (5.4x) | n/a | 420.60 (3.2x) | 319.52 (4.2x) | 333.81 (4.0x) | 1332.98 (1.0x) | 387.78 (3.4x) |
| ES512 | P-521 | small | 394 | 284.90 (1.1x) | **278.26 (1.2x)** | 285.41 (1.1x) | n/a | n/a | 819.23 (0.4x) | 300.95 (1.1x) | 301.11 (1.1x) | 323.66 (1.0x) | 333.51 (1.0x) |
| ES512 | P-521 | typical | 794 | 285.19 (1.2x) | **276.94 (1.3x)** | 282.67 (1.2x) | n/a | n/a | 824.13 (0.4x) | 305.63 (1.1x) | 304.35 (1.1x) | 346.27 (1.0x) | 335.33 (1.0x) |
| ES512 | P-521 | medium | 2407 | 288.60 (1.5x) | 290.08 (1.5x) | **285.80 (1.5x)** | n/a | n/a | 869.58 (0.5x) | 313.15 (1.4x) | 317.08 (1.4x) | 438.90 (1.0x) | 347.58 (1.3x) |
| ES512 | P-521 | large | 21047 | **304.38 (4.7x)** | 320.85 (4.5x) | 324.63 (4.4x) | n/a | n/a | 908.50 (1.6x) | 419.33 (3.4x) | 430.03 (3.3x) | 1440.55 (1.0x) | 479.62 (3.0x) |
| EdDSA | Ed25519 | small | 306 | 31.25 (3.1x) | **31.22 (3.1x)** | 33.64 (2.9x) | 32.48 (3.0x) | n/a | 39.14 (2.5x) | n/a | 80.65 (1.2x) | 96.94 (1.0x) | 109.81 (0.9x) |
| EdDSA | Ed25519 | typical | 706 | **32.02 (3.7x)** | 32.40 (3.7x) | 34.62 (3.4x) | 33.99 (3.5x) | n/a | 39.40 (3.0x) | n/a | 83.26 (1.4x) | 118.45 (1.0x) | 112.55 (1.1x) |
| EdDSA | Ed25519 | medium | 2319 | **33.53 (6.3x)** | 35.54 (5.9x) | 37.25 (5.7x) | 40.53 (5.2x) | n/a | 44.34 (4.8x) | n/a | 94.42 (2.2x) | 210.88 (1.0x) | 124.19 (1.7x) |
| EdDSA | Ed25519 | large | 20959 | **52.50 (24.0x)** | 69.32 (18.2x) | 65.26 (19.3x) | 125.05 (10.1x) | n/a | 102.59 (12.3x) | n/a | 211.78 (5.9x) | 1259.76 (1.0x) | 257.14 (4.9x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | ryjwt 0.0.0a0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.49 (3.7x) | **16.22 (3.8x)** | 18.44 (3.3x) | n/a | n/a | n/a | n/a | n/a | 60.94 (1.0x) | n/a |
| RS256 | RSA 2048 | typical | 961 | 17.02 (5.1x) | **16.89 (5.1x)** | 19.01 (4.5x) | n/a | n/a | n/a | n/a | n/a | 85.93 (1.0x) | n/a |
| RS256 | RSA 2048 | medium | 2574 | **18.09 (10.0x)** | 18.95 (9.5x) | 19.74 (9.2x) | n/a | n/a | n/a | n/a | n/a | 180.83 (1.0x) | n/a |
| RS256 | RSA 2048 | large | 21214 | **32.60 (37.5x)** | 51.54 (23.7x) | 41.35 (29.6x) | n/a | n/a | n/a | n/a | n/a | 1222.15 (1.0x) | n/a |
| RS256 | RSA 3072 | small | 731 | 37.25 (2.3x) | **36.96 (2.3x)** | 38.56 (2.2x) | n/a | n/a | n/a | n/a | n/a | 84.88 (1.0x) | n/a |
| RS256 | RSA 3072 | typical | 1131 | 37.78 (2.8x) | **37.47 (2.9x)** | 39.48 (2.7x) | n/a | n/a | n/a | n/a | n/a | 107.60 (1.0x) | n/a |
| RS256 | RSA 3072 | medium | 2744 | **38.74 (5.2x)** | 39.56 (5.1x) | 40.24 (5.1x) | n/a | n/a | n/a | n/a | n/a | 203.35 (1.0x) | n/a |
| RS256 | RSA 3072 | large | 21384 | **53.36 (23.8x)** | 69.43 (18.3x) | 63.70 (19.9x) | n/a | n/a | n/a | n/a | n/a | 1267.96 (1.0x) | n/a |
| RS256 | RSA 4096 | small | 902 | 64.05 (1.7x) | **63.68 (1.7x)** | 66.16 (1.7x) | n/a | n/a | n/a | n/a | n/a | 110.29 (1.0x) | n/a |
| RS256 | RSA 4096 | typical | 1302 | 64.72 (2.1x) | **64.21 (2.1x)** | 67.38 (2.0x) | n/a | n/a | n/a | n/a | n/a | 134.45 (1.0x) | n/a |
| RS256 | RSA 4096 | medium | 2915 | **65.39 (3.5x)** | 66.40 (3.5x) | 68.48 (3.4x) | n/a | n/a | n/a | n/a | n/a | 231.26 (1.0x) | n/a |
| RS256 | RSA 4096 | large | 21555 | **79.92 (16.0x)** | 96.02 (13.3x) | 90.26 (14.1x) | n/a | n/a | n/a | n/a | n/a | 1275.46 (1.0x) | n/a |
| ES256 | P-256 | small | 304 | 31.74 (2.3x) | **31.48 (2.3x)** | 33.02 (2.2x) | n/a | n/a | n/a | n/a | n/a | 73.59 (1.0x) | n/a |
| ES256 | P-256 | typical | 704 | 32.30 (3.1x) | **32.20 (3.1x)** | 34.34 (2.9x) | n/a | n/a | n/a | n/a | n/a | 99.38 (1.0x) | n/a |
| ES256 | P-256 | medium | 2317 | **33.44 (5.8x)** | 34.37 (5.6x) | 36.53 (5.3x) | n/a | n/a | n/a | n/a | n/a | 193.63 (1.0x) | n/a |
| ES256 | P-256 | large | 20957 | **47.71 (25.9x)** | 64.59 (19.1x) | 56.24 (22.0x) | n/a | n/a | n/a | n/a | n/a | 1236.54 (1.0x) | n/a |
| ES384 | P-384 | small | 346 | **149.34 (1.5x)** | 157.28 (1.4x) | 149.68 (1.5x) | n/a | n/a | n/a | n/a | n/a | 223.56 (1.0x) | n/a |
| ES384 | P-384 | typical | 746 | **147.86 (1.7x)** | 150.19 (1.7x) | 149.45 (1.7x) | n/a | n/a | n/a | n/a | n/a | 249.25 (1.0x) | n/a |
| ES384 | P-384 | medium | 2359 | **151.13 (2.3x)** | 154.59 (2.2x) | 152.74 (2.2x) | n/a | n/a | n/a | n/a | n/a | 342.50 (1.0x) | n/a |
| ES384 | P-384 | large | 20999 | **170.75 (8.2x)** | 189.08 (7.4x) | 178.54 (7.8x) | n/a | n/a | n/a | n/a | n/a | 1394.33 (1.0x) | n/a |
| ES512 | P-521 | small | 394 | **279.41 (1.2x)** | 292.57 (1.1x) | 279.88 (1.2x) | n/a | n/a | n/a | n/a | n/a | 326.14 (1.0x) | n/a |
| ES512 | P-521 | typical | 794 | **278.38 (1.3x)** | 290.00 (1.2x) | 280.36 (1.3x) | n/a | n/a | n/a | n/a | n/a | 350.75 (1.0x) | n/a |
| ES512 | P-521 | medium | 2407 | **282.20 (1.6x)** | 304.52 (1.5x) | 284.08 (1.6x) | n/a | n/a | n/a | n/a | n/a | 446.76 (1.0x) | n/a |
| ES512 | P-521 | large | 21047 | **298.43 (5.0x)** | 327.40 (4.6x) | 310.26 (4.8x) | n/a | n/a | n/a | n/a | n/a | 1498.60 (1.0x) | n/a |
| EdDSA | Ed25519 | small | 306 | 31.49 (3.2x) | **31.42 (3.2x)** | 32.34 (3.1x) | n/a | n/a | n/a | n/a | n/a | 99.66 (1.0x) | n/a |
| EdDSA | Ed25519 | typical | 706 | 32.14 (3.8x) | **32.14 (3.8x)** | 33.35 (3.7x) | n/a | n/a | n/a | n/a | n/a | 123.62 (1.0x) | n/a |
| EdDSA | Ed25519 | medium | 2319 | **33.63 (6.5x)** | 34.69 (6.3x) | 35.14 (6.2x) | n/a | n/a | n/a | n/a | n/a | 219.54 (1.0x) | n/a |
| EdDSA | Ed25519 | large | 20959 | **52.89 (23.9x)** | 69.93 (18.1x) | 60.55 (20.9x) | n/a | n/a | n/a | n/a | n/a | 1263.89 (1.0x) | n/a |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | ryjwt 0.0.0a0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 16.70 (3.6x) | **16.55 (3.7x)** | 17.10 (3.6x) | n/a | 36.60 (1.7x) | 19.59 (3.1x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | **17.05 (5.0x)** | 17.52 (4.9x) | 18.11 (4.7x) | n/a | 34.08 (2.5x) | 20.31 (4.2x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | **18.15 (10.0x)** | 19.55 (9.2x) | 19.46 (9.3x) | n/a | 38.82 (4.7x) | 25.62 (7.1x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | **32.55 (37.6x)** | 50.05 (24.4x) | 40.25 (30.4x) | n/a | 98.03 (12.5x) | 80.45 (15.2x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | 37.14 (2.3x) | 38.67 (2.2x) | 37.90 (2.2x) | n/a | 57.27 (1.5x) | **30.36 (2.8x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | 37.68 (2.9x) | 39.30 (2.7x) | 38.54 (2.8x) | n/a | 58.94 (1.8x) | **31.97 (3.4x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | 38.69 (5.3x) | 40.55 (5.0x) | 40.30 (5.0x) | n/a | 61.85 (3.3x) | **37.89 (5.4x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | **53.01 (23.9x)** | 69.97 (18.1x) | 61.04 (20.8x) | n/a | 123.29 (10.3x) | 91.73 (13.8x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | 63.90 (1.7x) | 64.11 (1.7x) | 64.89 (1.7x) | n/a | 88.06 (1.3x) | **47.10 (2.3x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | 64.82 (2.1x) | 65.46 (2.1x) | 65.40 (2.1x) | n/a | 89.50 (1.5x) | **48.49 (2.8x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | 68.45 (3.4x) | 66.98 (3.5x) | 67.22 (3.4x) | n/a | 93.76 (2.5x) | **56.38 (4.1x)** | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | **80.07 (15.9x)** | 98.68 (12.9x) | 87.78 (14.5x) | n/a | 154.89 (8.2x) | 115.34 (11.1x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | small | 304 | **31.77 (2.3x)** | 31.84 (2.3x) | 32.24 (2.3x) | n/a | 2062.38 (0.04x) | 40.87 (1.8x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | typical | 704 | 33.39 (3.0x) | **32.45 (3.1x)** | 33.64 (3.0x) | n/a | 2086.23 (0.05x) | 42.56 (2.3x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | medium | 2317 | **34.35 (5.6x)** | 34.51 (5.6x) | 34.73 (5.6x) | n/a | 2014.04 (0.10x) | 47.14 (4.1x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | large | 20957 | **48.55 (25.5x)** | 64.40 (19.2x) | 55.69 (22.2x) | n/a | 2069.70 (0.6x) | 107.10 (11.5x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | small | 346 | 157.62 (1.4x) | **149.83 (1.5x)** | 150.45 (1.5x) | n/a | 14803.80 (0.02x) | 339.60 (0.7x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | typical | 746 | 153.57 (1.6x) | **147.77 (1.7x)** | 148.70 (1.7x) | n/a | 14914.67 (0.02x) | 336.43 (0.7x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | medium | 2359 | 156.33 (2.2x) | 152.66 (2.2x) | **152.41 (2.2x)** | n/a | 14850.62 (0.02x) | 345.64 (1.0x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | large | 20999 | **176.02 (7.9x)** | 195.14 (7.1x) | 178.73 (7.8x) | n/a | 14830.14 (0.09x) | 411.20 (3.4x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | small | 394 | 291.32 (1.1x) | 288.38 (1.1x) | **280.53 (1.2x)** | n/a | 36078.70 (0.01x) | 824.41 (0.4x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | typical | 794 | 290.25 (1.2x) | 279.65 (1.3x) | **278.99 (1.3x)** | n/a | 35855.02 (0.01x) | 834.47 (0.4x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | medium | 2407 | 294.88 (1.5x) | **282.24 (1.6x)** | 283.59 (1.6x) | n/a | 35810.56 (0.01x) | 825.09 (0.5x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | large | 21047 | 310.81 (4.8x) | 313.61 (4.8x) | **307.12 (4.9x)** | n/a | 35979.11 (0.04x) | 882.15 (1.7x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | **31.69 (3.1x)** | 33.02 (3.0x) | 32.38 (3.1x) | n/a | n/a | 38.46 (2.6x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | **32.19 (3.8x)** | 33.50 (3.7x) | 33.35 (3.7x) | n/a | n/a | 39.67 (3.1x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | **33.74 (6.5x)** | 35.00 (6.3x) | 35.05 (6.3x) | n/a | n/a | 44.55 (4.9x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | **52.63 (24.0x)** | 69.15 (18.3x) | 60.32 (21.0x) | n/a | n/a | 106.92 (11.8x) | n/a | n/a | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.0.0a0 → Struct | ryjwt 0.0.0a0 → dict | ryjwt 0.0.0a0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 1.6 | 1.5 | 1.7 | n/a | n/a | n/a | n/a | n/a | 1.5 | n/a |
| JWKS URL, async client | 1.7 | 2.5 | 1.6 | n/a | 0.9 | 0.9 | n/a | n/a | n/a | n/a |

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

- ryjwt 0.0.0a0 → Struct: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.0.0a0 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.0.0a0 → dict: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.0.0a0 → dict: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.0.0a0 → BaseModel: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.0.0a0 → BaseModel: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
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
