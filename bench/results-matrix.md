# JWT decode benchmarks: the full matrix

Generated 2026-10-09 from `bench/results-matrix/` by `bench/compare.py`, on
AMD EPYC 9V45 96-Core Processor (x86_64), Linux.
Run in Docker, one container per library, each limited to 1 CPU (pinned) and 500 MB with no swap; the JWKS server runs in a container of its own, outside that limit.
Runtimes: Bun 1.3.14, CPython 3.14.8, Rust (release, LTO).

Each decode verifies the signature and checks `exp` and `aud`, as a real
caller would, and each library's result is checked against the token's claims
before timing. Times are µs per decode, the mean over the fastest of 5 batches
(lower is better); `(Nx)` is the speed-up vs pyjwt 2.15.1. Each case runs
about a second (a warm-up, then the 5 batches), so slow ones (RSA 4096, P-521)
run fewer iterations.
Fastest per row in bold; n/a where the library can't (see the end).

Key sources: an HMAC secret (HS256 only); a PEM public key, parsed once; a
JWKS document of 3 keys, the signing key in the middle, picked by the token's
`kid`; and that document fetched over HTTPS from a JWKS server
(static-web-server, in its own container), timed in the steady state with the
keys cached.

## Headline: typical token, medium key

| key source | alg | key | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | 1.54 (22.8x) | **1.45 (24.1x)** | 3.04 (11.5x) | 3.48 (10.1x) | 5.00 (7.0x) | 22.45 (1.6x) | 17.91 (2.0x) | 18.83 (1.9x) | 35.02 (1.0x) | 62.43 (0.6x) |
| PEM public key | RS256 | RSA 3072 | **25.29 (2.7x)** | 27.22 (2.6x) | 28.06 (2.5x) | 31.90 (2.2x) | 33.88 (2.1x) | 47.87 (1.5x) | 47.26 (1.5x) | 49.84 (1.4x) | 69.47 (1.0x) | 90.97 (0.8x) |
| PEM public key | ES384 | P-384 | **132.52 (2.8x)** | 136.55 (2.7x) | 139.42 (2.6x) | 143.74 (2.5x) | 332.48 (1.1x) | 344.25 (1.1x) | 342.31 (1.1x) | 356.16 (1.0x) | 366.18 (1.0x) | 389.08 (0.9x) |
| PEM public key | EdDSA | Ed25519 | **25.11 (3.6x)** | 25.15 (3.6x) | 27.15 (3.4x) | 27.99 (3.3x) | 41.27 (2.2x) | 60.27 (1.5x) | n/a | 80.12 (1.1x) | 91.42 (1.0x) | 116.01 (0.8x) |
| JWKS document | RS256 | RSA 3072 | 26.41 (3.7x) | **26.13 (3.8x)** | 28.16 (3.5x) | 32.61 (3.0x) | 38.76 (2.5x) | 49.86 (2.0x) | 50.52 (1.9x) | 49.82 (2.0x) | 98.44 (1.0x) | 100.45 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | **26.59 (4.0x)** | 27.04 (3.9x) | 28.58 (3.7x) | n/a | n/a | n/a | n/a | n/a | 105.98 (1.0x) | n/a |
| JWKS URL, async client | RS256 | RSA 3072 | 27.39 (3.9x) | **26.40 (4.0x)** | 28.37 (3.7x) | n/a | 68.56 (1.5x) | 48.67 (2.2x) | n/a | n/a | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | **0.80 (27.9x)** | 0.85 (26.0x) | 1.75 (12.7x) | 1.80 (12.4x) | 3.01 (7.4x) | 20.11 (1.1x) | 12.98 (1.7x) | 15.00 (1.5x) | 22.22 (1.0x) | 54.76 (0.4x) |
| HS256 | 32 B | typical | 661 | 1.49 (23.7x) | **1.44 (24.6x)** | 3.04 (11.6x) | 3.41 (10.4x) | 4.97 (7.1x) | 22.70 (1.6x) | 17.18 (2.1x) | 18.63 (1.9x) | 35.40 (1.0x) | 60.74 (0.6x) |
| HS256 | 32 B | medium | 2244 | 3.85 (21.2x) | **2.50 (32.6x)** | 4.76 (17.1x) | 8.86 (9.2x) | 10.32 (7.9x) | 27.60 (3.0x) | 23.90 (3.4x) | 29.91 (2.7x) | 81.56 (1.0x) | 71.48 (1.1x) |
| HS256 | 32 B | large | 20884 | 36.11 (15.9x) | **16.59 (34.7x)** | 30.68 (18.7x) | 89.15 (6.5x) | 90.65 (6.3x) | 94.46 (6.1x) | 116.40 (4.9x) | 162.37 (3.5x) | 575.28 (1.0x) | 197.21 (2.9x) |
| HS256 | 64 B | small | 231 | **0.78 (28.5x)** | 0.82 (27.2x) | 1.69 (13.2x) | 1.79 (12.5x) | 2.89 (7.7x) | 21.03 (1.1x) | 13.39 (1.7x) | 14.83 (1.5x) | 22.35 (1.0x) | 56.33 (0.4x) |
| HS256 | 64 B | typical | 661 | 1.54 (22.8x) | **1.45 (24.1x)** | 3.04 (11.5x) | 3.48 (10.1x) | 5.00 (7.0x) | 22.45 (1.6x) | 17.91 (2.0x) | 18.83 (1.9x) | 35.02 (1.0x) | 62.43 (0.6x) |
| HS256 | 64 B | medium | 2244 | 3.88 (19.7x) | **2.50 (30.6x)** | 4.77 (16.1x) | 9.02 (8.5x) | 9.77 (7.8x) | 26.94 (2.8x) | 24.91 (3.1x) | 29.71 (2.6x) | 76.56 (1.0x) | 73.86 (1.0x) |
| HS256 | 64 B | large | 20884 | 35.93 (17.0x) | **17.04 (35.8x)** | 29.63 (20.6x) | 86.79 (7.0x) | 90.35 (6.7x) | 92.45 (6.6x) | 117.03 (5.2x) | 164.35 (3.7x) | 609.44 (1.0x) | 206.49 (3.0x) |
| HS256 | 256 B | small | 231 | **0.85 (28.4x)** | 0.85 (28.0x) | 1.72 (13.9x) | 1.93 (12.4x) | 3.10 (7.7x) | 21.77 (1.1x) | 13.96 (1.7x) | 15.10 (1.6x) | 23.97 (1.0x) | 56.36 (0.4x) |
| HS256 | 256 B | typical | 661 | 1.50 (24.8x) | **1.45 (25.8x)** | 3.10 (12.0x) | 3.62 (10.3x) | 5.07 (7.3x) | 23.16 (1.6x) | 18.09 (2.1x) | 18.95 (2.0x) | 37.28 (1.0x) | 62.46 (0.6x) |
| HS256 | 256 B | medium | 2244 | 4.01 (20.0x) | **2.57 (31.3x)** | 4.74 (16.9x) | 9.06 (8.9x) | 10.12 (7.9x) | 27.39 (2.9x) | 24.33 (3.3x) | 30.35 (2.6x) | 80.23 (1.0x) | 73.51 (1.1x) |
| HS256 | 256 B | large | 20884 | 37.11 (16.8x) | **17.23 (36.1x)** | 30.77 (20.2x) | 87.25 (7.1x) | 91.33 (6.8x) | 96.08 (6.5x) | 118.57 (5.2x) | 149.48 (4.2x) | 621.78 (1.0x) | 209.32 (3.0x) |
| HS256 | 4096 B | small | 231 | **0.83 (54.5x)** | 0.84 (53.5x) | 1.76 (25.6x) | 3.79 (11.9x) | 5.07 (8.9x) | 23.22 (1.9x) | 14.96 (3.0x) | 16.26 (2.8x) | 45.18 (1.0x) | 64.84 (0.7x) |
| HS256 | 4096 B | typical | 661 | 1.55 (37.0x) | **1.44 (39.8x)** | 3.17 (18.1x) | 5.51 (10.4x) | 6.74 (8.5x) | 25.98 (2.2x) | 19.69 (2.9x) | 19.68 (2.9x) | 57.44 (1.0x) | 67.03 (0.9x) |
| HS256 | 4096 B | medium | 2244 | 3.84 (26.9x) | **2.48 (41.6x)** | 4.95 (20.8x) | 10.88 (9.5x) | 12.08 (8.5x) | 29.01 (3.6x) | 26.87 (3.8x) | 31.22 (3.3x) | 103.03 (1.0x) | 76.96 (1.3x) |
| HS256 | 4096 B | large | 20884 | 35.45 (17.9x) | **17.46 (36.3x)** | 32.49 (19.5x) | 89.16 (7.1x) | 92.13 (6.9x) | 100.17 (6.3x) | 118.33 (5.4x) | 153.69 (4.1x) | 634.29 (1.0x) | 203.92 (3.1x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **12.85 (3.2x)** | 12.90 (3.2x) | 14.08 (2.9x) | 15.55 (2.7x) | 16.41 (2.5x) | 35.09 (1.2x) | 28.83 (1.4x) | 28.52 (1.5x) | 41.36 (1.0x) | 70.97 (0.6x) |
| RS256 | RSA 2048 | typical | 961 | **13.33 (4.0x)** | 13.53 (3.9x) | 15.68 (3.4x) | 16.87 (3.1x) | 18.10 (2.9x) | 35.42 (1.5x) | 32.96 (1.6x) | 32.43 (1.6x) | 52.95 (1.0x) | 76.06 (0.7x) |
| RS256 | RSA 2048 | medium | 2574 | 15.74 (6.3x) | **14.50 (6.9x)** | 16.56 (6.0x) | 22.80 (4.4x) | 23.49 (4.2x) | 38.67 (2.6x) | 39.43 (2.5x) | 43.48 (2.3x) | 99.81 (1.0x) | 88.89 (1.1x) |
| RS256 | RSA 2048 | large | 21214 | 48.88 (12.2x) | **29.19 (20.3x)** | 41.86 (14.2x) | 101.49 (5.9x) | 105.62 (5.6x) | 112.19 (5.3x) | 123.63 (4.8x) | 163.71 (3.6x) | 593.90 (1.0x) | 222.67 (2.7x) |
| RS256 | RSA 3072 | small | 731 | **25.79 (2.3x)** | 26.71 (2.2x) | 27.13 (2.2x) | 30.38 (1.9x) | 30.90 (1.9x) | 47.29 (1.2x) | 43.72 (1.3x) | 41.73 (1.4x) | 58.82 (1.0x) | 86.90 (0.7x) |
| RS256 | RSA 3072 | typical | 1131 | **25.29 (2.7x)** | 27.22 (2.6x) | 28.06 (2.5x) | 31.90 (2.2x) | 33.88 (2.1x) | 47.87 (1.5x) | 47.26 (1.5x) | 49.84 (1.4x) | 69.47 (1.0x) | 90.97 (0.8x) |
| RS256 | RSA 3072 | medium | 2744 | 28.77 (3.8x) | **28.09 (3.9x)** | 29.53 (3.7x) | 37.68 (2.9x) | 38.98 (2.8x) | 54.48 (2.0x) | 53.68 (2.0x) | 60.89 (1.8x) | 109.97 (1.0x) | 102.98 (1.1x) |
| RS256 | RSA 3072 | large | 21384 | 61.96 (9.5x) | **42.97 (13.7x)** | 55.78 (10.5x) | 116.63 (5.0x) | 123.65 (4.7x) | 124.88 (4.7x) | 141.33 (4.2x) | 192.69 (3.0x) | 586.61 (1.0x) | 237.69 (2.5x) |
| RS256 | RSA 4096 | small | 902 | **43.78 (1.9x)** | 44.30 (1.9x) | 44.92 (1.9x) | 50.93 (1.7x) | 49.96 (1.7x) | 66.17 (1.3x) | 63.35 (1.3x) | 66.41 (1.3x) | 84.62 (1.0x) | 106.14 (0.8x) |
| RS256 | RSA 4096 | typical | 1302 | 44.70 (2.1x) | **44.12 (2.1x)** | 45.98 (2.0x) | 52.42 (1.8x) | 52.58 (1.8x) | 67.53 (1.4x) | 67.32 (1.4x) | 70.38 (1.3x) | 93.30 (1.0x) | 109.14 (0.9x) |
| RS256 | RSA 4096 | medium | 2915 | 47.99 (2.8x) | **45.83 (2.9x)** | 47.66 (2.8x) | 57.92 (2.3x) | 59.46 (2.2x) | 69.53 (1.9x) | 73.22 (1.8x) | 82.47 (1.6x) | 132.18 (1.0x) | 122.38 (1.1x) |
| RS256 | RSA 4096 | large | 21555 | 80.21 (7.4x) | **58.95 (10.1x)** | 74.52 (8.0x) | 137.94 (4.3x) | 141.23 (4.2x) | 143.79 (4.1x) | 163.69 (3.6x) | 214.50 (2.8x) | 595.38 (1.0x) | 257.12 (2.3x) |
| ES256 | P-256 | small | 304 | 34.40 (1.8x) | **33.48 (1.8x)** | 35.50 (1.7x) | 36.39 (1.7x) | 37.79 (1.6x) | 56.79 (1.1x) | 56.02 (1.1x) | 58.14 (1.0x) | 60.65 (1.0x) | 96.71 (0.6x) |
| ES256 | P-256 | typical | 704 | 34.97 (2.0x) | **34.40 (2.0x)** | 36.82 (1.9x) | 37.86 (1.9x) | 39.80 (1.8x) | 56.03 (1.3x) | 59.35 (1.2x) | 59.53 (1.2x) | 70.40 (1.0x) | 102.20 (0.7x) |
| ES256 | P-256 | medium | 2317 | 37.46 (3.2x) | **35.66 (3.4x)** | 38.99 (3.1x) | 43.93 (2.8x) | 45.50 (2.7x) | 62.99 (1.9x) | 67.27 (1.8x) | 71.59 (1.7x) | 121.36 (1.0x) | 117.70 (1.0x) |
| ES256 | P-256 | large | 20957 | 69.90 (8.6x) | **50.89 (11.8x)** | 65.80 (9.1x) | 124.60 (4.8x) | 127.19 (4.7x) | 131.99 (4.6x) | 154.55 (3.9x) | 198.95 (3.0x) | 601.01 (1.0x) | 250.70 (2.4x) |
| ES384 | P-384 | small | 346 | **129.93 (2.7x)** | 134.94 (2.6x) | 137.83 (2.6x) | 140.52 (2.5x) | 329.96 (1.1x) | 334.01 (1.1x) | 340.56 (1.0x) | 341.59 (1.0x) | 355.86 (1.0x) | 376.30 (0.9x) |
| ES384 | P-384 | typical | 746 | **132.52 (2.8x)** | 136.55 (2.7x) | 139.42 (2.6x) | 143.74 (2.5x) | 332.48 (1.1x) | 344.25 (1.1x) | 342.31 (1.1x) | 356.16 (1.0x) | 366.18 (1.0x) | 389.08 (0.9x) |
| ES384 | P-384 | medium | 2359 | **136.10 (3.0x)** | 139.02 (2.9x) | 141.04 (2.9x) | 148.60 (2.7x) | 339.25 (1.2x) | 348.67 (1.2x) | 345.84 (1.2x) | 373.88 (1.1x) | 406.90 (1.0x) | 400.23 (1.0x) |
| ES384 | P-384 | large | 20999 | 183.80 (4.9x) | **163.50 (5.5x)** | 179.52 (5.0x) | 242.78 (3.7x) | 433.08 (2.1x) | 427.24 (2.1x) | 443.62 (2.0x) | 518.55 (1.7x) | 905.75 (1.0x) | 526.26 (1.7x) |
| ES512 | P-521 | small | 394 | 242.17 (1.3x) | **236.90 (1.4x)** | 242.30 (1.3x) | n/a | 791.41 (0.4x) | 757.45 (0.4x) | 311.96 (1.0x) | 328.73 (1.0x) | 322.41 (1.0x) | 351.84 (0.9x) |
| ES512 | P-521 | typical | 794 | **237.99 (1.4x)** | 238.95 (1.4x) | 240.79 (1.4x) | n/a | 782.45 (0.4x) | 751.71 (0.4x) | 313.40 (1.1x) | 331.65 (1.0x) | 333.36 (1.0x) | 352.65 (0.9x) |
| ES512 | P-521 | medium | 2407 | 241.55 (1.6x) | **236.42 (1.6x)** | 244.61 (1.5x) | n/a | 779.26 (0.5x) | 776.25 (0.5x) | 321.99 (1.2x) | 344.63 (1.1x) | 378.24 (1.0x) | 367.53 (1.0x) |
| ES512 | P-521 | large | 21047 | 289.48 (3.0x) | **264.47 (3.3x)** | 286.12 (3.0x) | n/a | 894.97 (1.0x) | 887.53 (1.0x) | 410.44 (2.1x) | 484.62 (1.8x) | 865.40 (1.0x) | 505.94 (1.7x) |
| EdDSA | Ed25519 | small | 306 | **24.17 (3.3x)** | 24.28 (3.3x) | 25.50 (3.1x) | 25.82 (3.1x) | 39.67 (2.0x) | 58.57 (1.4x) | n/a | 77.38 (1.0x) | 80.01 (1.0x) | 112.96 (0.7x) |
| EdDSA | Ed25519 | typical | 706 | **25.11 (3.6x)** | 25.15 (3.6x) | 27.15 (3.4x) | 27.99 (3.3x) | 41.27 (2.2x) | 60.27 (1.5x) | n/a | 80.12 (1.1x) | 91.42 (1.0x) | 116.01 (0.8x) |
| EdDSA | Ed25519 | medium | 2319 | 28.40 (4.7x) | **27.21 (4.9x)** | 29.81 (4.5x) | 35.04 (3.8x) | 48.68 (2.8x) | 64.87 (2.1x) | n/a | 91.35 (1.5x) | 134.52 (1.0x) | 132.00 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | 73.86 (8.6x) | **51.43 (12.4x)** | 67.84 (9.4x) | 127.06 (5.0x) | 143.76 (4.4x) | 154.17 (4.1x) | n/a | 216.95 (2.9x) | 635.93 (1.0x) | 263.46 (2.4x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **12.04 (5.0x)** | 12.18 (5.0x) | 13.56 (4.5x) | 16.14 (3.7x) | 19.27 (3.1x) | 35.31 (1.7x) | 31.82 (1.9x) | 30.74 (2.0x) | 60.45 (1.0x) | 80.31 (0.8x) |
| RS256 | RSA 2048 | typical | 961 | 13.51 (6.0x) | **13.24 (6.1x)** | 15.09 (5.4x) | 17.50 (4.6x) | 22.42 (3.6x) | 34.95 (2.3x) | 36.07 (2.2x) | 34.91 (2.3x) | 80.96 (1.0x) | 85.20 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | 15.54 (10.5x) | **13.84 (11.8x)** | 16.66 (9.8x) | 23.73 (6.9x) | 32.85 (5.0x) | 38.87 (4.2x) | 44.42 (3.7x) | 46.22 (3.5x) | 162.75 (1.0x) | 98.65 (1.6x) |
| RS256 | RSA 2048 | large | 21214 | 48.05 (22.6x) | **28.00 (38.7x)** | 42.63 (25.4x) | 110.03 (9.8x) | 188.21 (5.8x) | 110.48 (9.8x) | 148.38 (7.3x) | 172.57 (6.3x) | 1083.65 (1.0x) | 234.64 (4.6x) |
| RS256 | RSA 3072 | small | 731 | **25.10 (3.2x)** | 25.13 (3.2x) | 26.82 (3.0x) | 30.93 (2.6x) | 34.56 (2.3x) | 47.42 (1.7x) | 47.54 (1.7x) | 45.83 (1.7x) | 79.97 (1.0x) | 95.86 (0.8x) |
| RS256 | RSA 3072 | typical | 1131 | 26.41 (3.7x) | **26.13 (3.8x)** | 28.16 (3.5x) | 32.61 (3.0x) | 38.76 (2.5x) | 49.86 (2.0x) | 50.52 (1.9x) | 49.82 (2.0x) | 98.44 (1.0x) | 100.45 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 28.89 (6.2x) | **27.19 (6.5x)** | 29.81 (6.0x) | 38.72 (4.6x) | 48.84 (3.6x) | 55.82 (3.2x) | 58.57 (3.0x) | 60.36 (3.0x) | 178.07 (1.0x) | 113.97 (1.6x) |
| RS256 | RSA 3072 | large | 21384 | 61.04 (17.9x) | **40.92 (26.7x)** | 56.11 (19.4x) | 125.08 (8.7x) | 206.42 (5.3x) | 125.73 (8.7x) | 162.86 (6.7x) | 186.58 (5.8x) | 1091.28 (1.0x) | 248.39 (4.4x) |
| RS256 | RSA 4096 | small | 902 | 43.34 (2.5x) | **43.09 (2.5x)** | 44.93 (2.4x) | 51.87 (2.1x) | 55.48 (2.0x) | 67.52 (1.6x) | 67.25 (1.6x) | 64.96 (1.7x) | 108.92 (1.0x) | 116.91 (0.9x) |
| RS256 | RSA 4096 | typical | 1302 | **43.56 (3.0x)** | 44.17 (2.9x) | 46.08 (2.8x) | 52.89 (2.4x) | 59.91 (2.2x) | 67.75 (1.9x) | 72.30 (1.8x) | 69.51 (1.9x) | 129.19 (1.0x) | 119.87 (1.1x) |
| RS256 | RSA 4096 | medium | 2915 | 45.47 (4.7x) | **43.84 (4.9x)** | 47.92 (4.5x) | 59.13 (3.6x) | 70.87 (3.0x) | 75.67 (2.8x) | 80.76 (2.7x) | 81.75 (2.6x) | 215.02 (1.0x) | 132.72 (1.6x) |
| RS256 | RSA 4096 | large | 21555 | 76.67 (14.5x) | **57.29 (19.4x)** | 73.90 (15.0x) | 145.15 (7.7x) | 229.73 (4.8x) | 140.92 (7.9x) | 189.77 (5.9x) | 200.63 (5.5x) | 1112.20 (1.0x) | 267.89 (4.2x) |
| ES256 | P-256 | small | 304 | 34.41 (2.1x) | **34.16 (2.2x)** | 35.35 (2.1x) | 36.63 (2.0x) | 40.67 (1.8x) | 58.70 (1.3x) | 59.82 (1.2x) | 57.20 (1.3x) | 73.65 (1.0x) | 108.12 (0.7x) |
| ES256 | P-256 | typical | 704 | **33.47 (2.8x)** | 34.89 (2.7x) | 37.06 (2.6x) | 38.49 (2.5x) | 44.81 (2.1x) | 58.92 (1.6x) | 64.65 (1.5x) | 61.51 (1.5x) | 94.97 (1.0x) | 114.19 (0.8x) |
| ES256 | P-256 | medium | 2317 | 35.59 (4.9x) | **34.76 (5.0x)** | 38.30 (4.5x) | 44.52 (3.9x) | 56.77 (3.1x) | 64.10 (2.7x) | 73.40 (2.4x) | 74.11 (2.3x) | 174.04 (1.0x) | 126.91 (1.4x) |
| ES256 | P-256 | large | 20957 | 69.67 (15.8x) | **48.37 (22.7x)** | 65.57 (16.8x) | 129.43 (8.5x) | 213.00 (5.2x) | 130.88 (8.4x) | 185.12 (5.9x) | 199.16 (5.5x) | 1098.89 (1.0x) | 264.88 (4.1x) |
| ES384 | P-384 | small | 346 | 134.88 (2.6x) | **134.57 (2.6x)** | 136.91 (2.6x) | 139.19 (2.6x) | 350.84 (1.0x) | 348.15 (1.0x) | 341.81 (1.0x) | 327.16 (1.1x) | 355.80 (1.0x) | 395.40 (0.9x) |
| ES384 | P-384 | typical | 746 | **132.29 (2.9x)** | 135.52 (2.8x) | 138.52 (2.7x) | 142.56 (2.7x) | 356.59 (1.1x) | 354.58 (1.1x) | 346.05 (1.1x) | 331.58 (1.1x) | 378.92 (1.0x) | 399.20 (0.9x) |
| ES384 | P-384 | medium | 2359 | **136.98 (3.4x)** | 141.44 (3.2x) | 142.00 (3.2x) | 148.46 (3.1x) | 369.27 (1.2x) | 352.74 (1.3x) | 356.79 (1.3x) | 343.66 (1.3x) | 458.98 (1.0x) | 415.95 (1.1x) |
| ES384 | P-384 | large | 20999 | 179.10 (7.6x) | **168.60 (8.1x)** | 180.88 (7.6x) | 246.75 (5.5x) | 544.97 (2.5x) | 442.41 (3.1x) | 467.47 (2.9x) | 475.24 (2.9x) | 1368.82 (1.0x) | 560.36 (2.4x) |
| ES512 | P-521 | small | 394 | 235.81 (1.4x) | 244.36 (1.3x) | **234.92 (1.4x)** | n/a | 845.70 (0.4x) | 812.91 (0.4x) | 308.86 (1.0x) | 302.88 (1.1x) | 321.71 (1.0x) | 371.85 (0.9x) |
| ES512 | P-521 | typical | 794 | **234.03 (1.5x)** | 244.24 (1.5x) | 237.91 (1.5x) | n/a | 843.68 (0.4x) | 800.97 (0.4x) | 305.95 (1.2x) | 308.68 (1.1x) | 354.32 (1.0x) | 374.97 (0.9x) |
| ES512 | P-521 | medium | 2407 | **236.56 (1.8x)** | 247.36 (1.8x) | 247.15 (1.8x) | n/a | 846.56 (0.5x) | 797.81 (0.5x) | 310.90 (1.4x) | 316.40 (1.4x) | 437.55 (1.0x) | 388.31 (1.1x) |
| ES512 | P-521 | large | 21047 | 274.71 (5.0x) | **272.21 (5.1x)** | 280.84 (4.9x) | n/a | 994.46 (1.4x) | 893.66 (1.6x) | 461.84 (3.0x) | 453.58 (3.1x) | 1387.08 (1.0x) | 535.32 (2.6x) |
| EdDSA | Ed25519 | small | 306 | **23.96 (3.8x)** | 24.94 (3.6x) | 25.76 (3.5x) | 25.88 (3.5x) | 41.79 (2.2x) | 59.63 (1.5x) | n/a | 76.65 (1.2x) | 90.81 (1.0x) | 126.02 (0.7x) |
| EdDSA | Ed25519 | typical | 706 | **24.89 (4.4x)** | 25.59 (4.3x) | 27.26 (4.1x) | 27.59 (4.0x) | 45.61 (2.4x) | 61.78 (1.8x) | n/a | 78.68 (1.4x) | 110.48 (1.0x) | 131.30 (0.8x) |
| EdDSA | Ed25519 | medium | 2319 | 28.71 (6.8x) | **27.53 (7.1x)** | 31.57 (6.2x) | 35.01 (5.6x) | 57.28 (3.4x) | 67.87 (2.9x) | n/a | 90.41 (2.2x) | 195.65 (1.0x) | 142.70 (1.4x) |
| EdDSA | Ed25519 | large | 20959 | 74.54 (16.1x) | **55.06 (21.8x)** | 70.67 (17.0x) | 132.61 (9.1x) | 226.47 (5.3x) | 151.68 (7.9x) | n/a | 229.07 (5.2x) | 1200.91 (1.0x) | 287.08 (4.2x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **12.69 (4.9x)** | 12.98 (4.8x) | 14.16 (4.4x) | n/a | n/a | n/a | n/a | n/a | 62.16 (1.0x) | n/a |
| RS256 | RSA 2048 | typical | 961 | **12.98 (6.5x)** | 13.62 (6.2x) | 15.67 (5.4x) | n/a | n/a | n/a | n/a | n/a | 84.70 (1.0x) | n/a |
| RS256 | RSA 2048 | medium | 2574 | 15.55 (10.9x) | **14.49 (11.7x)** | 17.52 (9.7x) | n/a | n/a | n/a | n/a | n/a | 170.23 (1.0x) | n/a |
| RS256 | RSA 2048 | large | 21214 | 48.16 (23.7x) | **29.20 (39.1x)** | 44.05 (25.9x) | n/a | n/a | n/a | n/a | n/a | 1140.76 (1.0x) | n/a |
| RS256 | RSA 3072 | small | 731 | **26.02 (3.3x)** | 26.30 (3.2x) | 27.52 (3.1x) | n/a | n/a | n/a | n/a | n/a | 85.44 (1.0x) | n/a |
| RS256 | RSA 3072 | typical | 1131 | **26.59 (4.0x)** | 27.04 (3.9x) | 28.58 (3.7x) | n/a | n/a | n/a | n/a | n/a | 105.98 (1.0x) | n/a |
| RS256 | RSA 3072 | medium | 2744 | 29.14 (6.5x) | **28.12 (6.7x)** | 30.34 (6.2x) | n/a | n/a | n/a | n/a | n/a | 189.30 (1.0x) | n/a |
| RS256 | RSA 3072 | large | 21384 | 60.77 (18.8x) | **42.77 (26.8x)** | 55.90 (20.5x) | n/a | n/a | n/a | n/a | n/a | 1144.63 (1.0x) | n/a |
| RS256 | RSA 4096 | small | 902 | **43.73 (2.5x)** | 45.02 (2.5x) | 45.28 (2.5x) | n/a | n/a | n/a | n/a | n/a | 111.22 (1.0x) | n/a |
| RS256 | RSA 4096 | typical | 1302 | **43.71 (3.2x)** | 45.78 (3.0x) | 46.61 (3.0x) | n/a | n/a | n/a | n/a | n/a | 138.05 (1.0x) | n/a |
| RS256 | RSA 4096 | medium | 2915 | **46.33 (4.6x)** | 47.66 (4.5x) | 48.13 (4.4x) | n/a | n/a | n/a | n/a | n/a | 214.04 (1.0x) | n/a |
| RS256 | RSA 4096 | large | 21555 | 78.87 (14.6x) | **62.13 (18.6x)** | 73.77 (15.6x) | n/a | n/a | n/a | n/a | n/a | 1152.77 (1.0x) | n/a |
| ES256 | P-256 | small | 304 | **34.69 (2.2x)** | 35.44 (2.1x) | 35.21 (2.2x) | n/a | n/a | n/a | n/a | n/a | 76.13 (1.0x) | n/a |
| ES256 | P-256 | typical | 704 | **34.42 (2.8x)** | 36.21 (2.7x) | 36.47 (2.7x) | n/a | n/a | n/a | n/a | n/a | 97.91 (1.0x) | n/a |
| ES256 | P-256 | medium | 2317 | **36.42 (5.0x)** | 37.01 (4.9x) | 38.42 (4.7x) | n/a | n/a | n/a | n/a | n/a | 181.78 (1.0x) | n/a |
| ES256 | P-256 | large | 20957 | 68.16 (16.5x) | **51.59 (21.9x)** | 64.14 (17.6x) | n/a | n/a | n/a | n/a | n/a | 1127.38 (1.0x) | n/a |
| ES384 | P-384 | small | 346 | **134.54 (2.7x)** | 138.05 (2.6x) | 135.82 (2.7x) | n/a | n/a | n/a | n/a | n/a | 364.43 (1.0x) | n/a |
| ES384 | P-384 | typical | 746 | **137.14 (2.9x)** | 139.12 (2.8x) | 139.03 (2.8x) | n/a | n/a | n/a | n/a | n/a | 392.80 (1.0x) | n/a |
| ES384 | P-384 | medium | 2359 | **138.43 (3.4x)** | 140.66 (3.4x) | 141.46 (3.4x) | n/a | n/a | n/a | n/a | n/a | 474.95 (1.0x) | n/a |
| ES384 | P-384 | large | 20999 | 183.88 (8.2x) | **168.26 (8.9x)** | 179.98 (8.4x) | n/a | n/a | n/a | n/a | n/a | 1502.92 (1.0x) | n/a |
| ES512 | P-521 | small | 394 | **236.46 (1.4x)** | 243.73 (1.4x) | 240.69 (1.4x) | n/a | n/a | n/a | n/a | n/a | 338.48 (1.0x) | n/a |
| ES512 | P-521 | typical | 794 | **235.44 (1.5x)** | 236.07 (1.5x) | 239.47 (1.5x) | n/a | n/a | n/a | n/a | n/a | 364.66 (1.0x) | n/a |
| ES512 | P-521 | medium | 2407 | **239.32 (1.9x)** | 246.17 (1.8x) | 244.18 (1.8x) | n/a | n/a | n/a | n/a | n/a | 448.54 (1.0x) | n/a |
| ES512 | P-521 | large | 21047 | 288.34 (4.9x) | **268.37 (5.2x)** | 283.03 (5.0x) | n/a | n/a | n/a | n/a | n/a | 1404.91 (1.0x) | n/a |
| EdDSA | Ed25519 | small | 306 | **24.47 (3.8x)** | 24.88 (3.8x) | 25.81 (3.6x) | n/a | n/a | n/a | n/a | n/a | 93.77 (1.0x) | n/a |
| EdDSA | Ed25519 | typical | 706 | 25.70 (4.6x) | **25.57 (4.6x)** | 27.70 (4.2x) | n/a | n/a | n/a | n/a | n/a | 117.33 (1.0x) | n/a |
| EdDSA | Ed25519 | medium | 2319 | 29.03 (7.1x) | **28.40 (7.3x)** | 30.23 (6.8x) | n/a | n/a | n/a | n/a | n/a | 206.40 (1.0x) | n/a |
| EdDSA | Ed25519 | large | 20959 | 74.89 (16.0x) | **55.09 (21.7x)** | 68.47 (17.5x) | n/a | n/a | n/a | n/a | n/a | 1196.60 (1.0x) | n/a |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **12.76 (4.9x)** | 13.00 (4.8x) | 13.79 (4.5x) | n/a | 49.28 (1.3x) | 36.89 (1.7x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | **13.54 (6.3x)** | 13.68 (6.2x) | 15.37 (5.5x) | n/a | 43.87 (1.9x) | 37.51 (2.3x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | 16.04 (10.6x) | **14.57 (11.7x)** | 17.01 (10.0x) | n/a | 48.15 (3.5x) | 40.10 (4.2x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | 48.76 (23.4x) | **28.97 (39.4x)** | 43.02 (26.5x) | n/a | 135.76 (8.4x) | 103.84 (11.0x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | **25.93 (3.3x)** | 26.28 (3.3x) | 27.25 (3.1x) | n/a | 67.02 (1.3x) | 47.47 (1.8x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | 27.39 (3.9x) | **26.40 (4.0x)** | 28.37 (3.7x) | n/a | 68.56 (1.5x) | 48.67 (2.2x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | 29.99 (6.3x) | **27.88 (6.8x)** | 30.13 (6.3x) | n/a | 76.03 (2.5x) | 53.76 (3.5x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | 63.61 (18.0x) | **42.26 (27.1x)** | 56.29 (20.3x) | n/a | 162.93 (7.0x) | 118.09 (9.7x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | 45.27 (2.5x) | **44.52 (2.5x)** | 45.44 (2.4x) | n/a | 105.50 (1.1x) | 66.57 (1.7x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | **44.69 (3.1x)** | 45.92 (3.0x) | 46.53 (3.0x) | n/a | 103.43 (1.3x) | 66.83 (2.1x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | **46.23 (4.6x)** | 46.29 (4.6x) | 48.22 (4.4x) | n/a | 110.02 (1.9x) | 72.21 (3.0x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | 78.93 (14.6x) | **60.61 (19.0x)** | 74.00 (15.6x) | n/a | 201.63 (5.7x) | 134.24 (8.6x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | small | 304 | **34.25 (2.2x)** | 34.35 (2.2x) | 36.94 (2.1x) | n/a | 3207.33 (0.02x) | 58.95 (1.3x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | typical | 704 | 35.69 (2.7x) | **35.50 (2.8x)** | 38.49 (2.5x) | n/a | 3178.86 (0.03x) | 60.76 (1.6x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | medium | 2317 | 37.89 (4.8x) | **36.54 (5.0x)** | 40.00 (4.5x) | n/a | 3131.02 (0.06x) | 64.60 (2.8x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | large | 20957 | 70.38 (16.0x) | **51.45 (21.9x)** | 67.02 (16.8x) | n/a | 3333.41 (0.3x) | 133.14 (8.5x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | small | 346 | **130.07 (2.8x)** | 135.66 (2.7x) | 141.78 (2.6x) | n/a | 17339.27 (0.02x) | 348.53 (1.0x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | typical | 746 | **130.38 (3.0x)** | 137.63 (2.9x) | 138.73 (2.8x) | n/a | 17090.25 (0.02x) | 345.14 (1.1x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | medium | 2359 | 140.21 (3.4x) | **138.96 (3.4x)** | 141.00 (3.4x) | n/a | 17055.18 (0.03x) | 355.27 (1.3x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | large | 20999 | 186.23 (8.1x) | **165.67 (9.1x)** | 178.68 (8.4x) | n/a | 17427.62 (0.09x) | 425.30 (3.5x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | small | 394 | 250.81 (1.3x) | **238.13 (1.4x)** | 246.36 (1.4x) | n/a | 42052.74 (0.01x) | 801.01 (0.4x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | typical | 794 | 249.31 (1.5x) | **236.28 (1.5x)** | 245.72 (1.5x) | n/a | 41496.16 (0.01x) | 804.71 (0.5x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | medium | 2407 | 253.94 (1.8x) | **238.36 (1.9x)** | 248.75 (1.8x) | n/a | 42246.67 (0.01x) | 787.31 (0.6x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | large | 21047 | 302.09 (4.7x) | **270.08 (5.2x)** | 288.82 (4.9x) | n/a | 41718.53 (0.03x) | 889.17 (1.6x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | 26.05 (3.6x) | **24.71 (3.8x)** | 25.81 (3.6x) | n/a | n/a | 60.27 (1.6x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | 27.18 (4.3x) | **25.57 (4.6x)** | 27.76 (4.2x) | n/a | n/a | 59.98 (2.0x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | 29.48 (7.0x) | **28.26 (7.3x)** | 29.93 (6.9x) | n/a | n/a | 66.42 (3.1x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | 74.20 (16.1x) | **55.95 (21.4x)** | 67.51 (17.7x) | n/a | n/a | 143.88 (8.3x) | n/a | n/a | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 1.9 | 2.3 | 2.5 | n/a | n/a | n/a | n/a | n/a | 1.6 | n/a |
| JWKS URL, async client | 1.8 | 2.0 | 2.1 | n/a | 1.4 | 1.4 | n/a | n/a | n/a | n/a |

## Not applicable

- jsonwebtoken 11.1.0 (aws-lc-rs), every key source, ES512: jsonwebtoken has no ES512 (P-521).
- jsonwebtoken 11.1.0 (aws-lc-rs), JWKS URL, sync client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs), JWKS URL, async client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
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
- fast-jwt 6.3.3: JWKS document: a verifier per key, made once, picked by the token's `kid` (read with `createDecoder`).
- fast-jwt 6.3.3: JWKS URL rows are fast-jwt + get-jwks 11.0.3 (fast-jwt's documented integration), so they time both: on every verify get-jwks converts the cached JWK to a PEM (with jwk-to-pem) and fast-jwt imports that PEM (`createPublicKey`), which is why they're slow.
- jose 6.2.12: HMAC secret imported once (`crypto.subtle.importKey`); `importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`.
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
