# JWT decode benchmarks: the full matrix

Generated 2026-10-16 from `bench/results-matrix/` by `bench/compare.py`, on
AWS c9g.2xlarge, Graviton5 (aarch64), Linux.
Run in Docker, one container per library, up to 7 at once, each limited to 1 CPU (pinned, a core of its own) and 500 MB with no swap; the JWKS server runs in a container of its own, outside that limit. Each case gets 1,000 untimed decodes, then 10,000 timed.
Runtimes: Bun 1.3.14, CPython 3.14.8, Rust (release, LTO).

Each decode verifies the signature and checks `exp` and `aud`, as a real
caller would, and each library's result is checked against the token's claims
before timing. Times are µs per decode: the mean over 10,000 decodes of the same
token, after 1,000 untimed (lower is better); `(Nx)` is the speed-up vs
pyjwt 2.15.1.
Fastest per row in bold; n/a where the library can't (see the end).

Key sources: an HMAC secret (HS256 only); a PEM public key, parsed once; a
JWKS document of 3 keys, the signing key in the middle, picked by the token's
`kid`; and that document fetched over HTTPS from a JWKS server
(static-web-server, in its own container), timed in the steady state with the
keys cached.

## Headline: typical token, medium key

| key source | alg | key | ryjwt 0.2.2 → Struct | ryjwt 0.2.2 → dict (msgspec) | ryjwt 0.2.2 → dict (jiter) | ryjwt 0.2.2 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | **1.49 (25.8x)** | 1.52 (25.3x) | 1.93 (19.9x) | 3.03 (12.7x) | 3.18 (12.1x) | 3.75 (10.3x) | 4.66 (8.2x) | 12.38 (3.1x) | 19.00 (2.0x) | 38.41 (1.0x) |
| PEM public key | RS256 | RSA 3072 | **29.13 (2.7x)** | 29.18 (2.7x) | 29.53 (2.7x) | 30.76 (2.6x) | 35.41 (2.2x) | 35.74 (2.2x) | 33.99 (2.3x) | 41.94 (1.9x) | 52.85 (1.5x) | 78.56 (1.0x) |
| PEM public key | ES384 | P-384 | 181.13 (1.6x) | **180.84 (1.6x)** | 182.26 (1.6x) | 182.53 (1.6x) | 183.58 (1.6x) | 184.04 (1.5x) | 344.94 (0.8x) | 365.70 (0.8x) | 268.95 (1.1x) | 284.55 (1.0x) |
| PEM public key | EdDSA | Ed25519 | **33.47 (2.8x)** | 33.51 (2.8x) | 33.95 (2.8x) | 35.12 (2.7x) | 34.90 (2.7x) | 35.38 (2.7x) | 41.84 (2.3x) | 51.18 (1.8x) | 80.94 (1.2x) | 94.21 (1.0x) |
| JWKS document | RS256 | RSA 3072 | **29.14 (4.0x)** | 29.19 (4.0x) | 29.56 (3.9x) | 30.74 (3.8x) | 35.83 (3.2x) | 36.47 (3.2x) | 37.09 (3.1x) | 42.14 (2.7x) | 55.12 (2.1x) | 115.62 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | **29.58 (4.1x)** | 29.67 (4.1x) | 30.06 (4.0x) | 31.19 (3.9x) | n/a | n/a | n/a | n/a | n/a | 121.03 (1.0x) |
| JWKS URL, async client | RS256 | RSA 3072 | **29.67 (4.1x)** | 29.76 (4.1x) | 30.19 (4.0x) | 31.27 (3.9x) | n/a | n/a | 69.33 (1.7x) | 42.51 (2.8x) | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.2.2 → Struct | ryjwt 0.2.2 → dict (msgspec) | ryjwt 0.2.2 → dict (jiter) | ryjwt 0.2.2 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | 0.76 (31.6x) | **0.74 (32.6x)** | 0.83 (28.8x) | 1.50 (16.0x) | 1.54 (15.6x) | 1.77 (13.5x) | 7.53 (3.2x) | 17.16 (1.4x) | 15.09 (1.6x) | 23.99 (1.0x) |
| HS256 | 32 B | typical | 661 | **1.49 (25.6x)** | 1.52 (25.2x) | 1.92 (19.9x) | 3.06 (12.5x) | 3.15 (12.1x) | 3.75 (10.2x) | 7.48 (5.1x) | 16.87 (2.3x) | 19.14 (2.0x) | 38.24 (1.0x) |
| HS256 | 32 B | medium | 2244 | **2.91 (30.2x)** | 4.17 (21.0x) | 5.40 (16.3x) | 4.75 (18.5x) | 6.74 (13.0x) | 10.16 (8.6x) | 9.12 (9.6x) | 18.28 (4.8x) | 30.07 (2.9x) | 87.84 (1.0x) |
| HS256 | 32 B | large | 20884 | **22.32 (32.5x)** | 38.88 (18.6x) | 48.65 (14.9x) | 33.09 (21.9x) | 54.82 (13.2x) | 94.54 (7.7x) | 79.62 (9.1x) | 100.11 (7.2x) | 162.48 (4.5x) | 724.74 (1.0x) |
| HS256 | 64 B | small | 231 | 0.76 (32.1x) | **0.73 (33.5x)** | 0.84 (29.2x) | 1.50 (16.3x) | 1.53 (16.0x) | 1.75 (13.9x) | 3.30 (7.4x) | 10.37 (2.4x) | 14.97 (1.6x) | 24.40 (1.0x) |
| HS256 | 64 B | typical | 661 | **1.49 (25.8x)** | 1.52 (25.3x) | 1.93 (19.9x) | 3.03 (12.7x) | 3.18 (12.1x) | 3.75 (10.3x) | 4.66 (8.2x) | 12.38 (3.1x) | 19.00 (2.0x) | 38.41 (1.0x) |
| HS256 | 64 B | medium | 2244 | **2.92 (30.2x)** | 4.22 (20.9x) | 5.38 (16.4x) | 4.74 (18.6x) | 6.82 (12.9x) | 10.17 (8.7x) | 9.18 (9.6x) | 17.87 (4.9x) | 29.86 (3.0x) | 88.18 (1.0x) |
| HS256 | 64 B | large | 20884 | **22.38 (32.4x)** | 39.02 (18.6x) | 48.61 (14.9x) | 32.86 (22.1x) | 54.91 (13.2x) | 94.57 (7.7x) | 74.83 (9.7x) | 93.68 (7.7x) | 162.95 (4.4x) | 724.95 (1.0x) |
| HS256 | 256 B | small | 231 | 0.77 (34.0x) | **0.74 (35.3x)** | 0.84 (31.1x) | 1.51 (17.2x) | 1.78 (14.6x) | 1.92 (13.6x) | 3.20 (8.1x) | 11.21 (2.3x) | 15.17 (1.7x) | 26.01 (1.0x) |
| HS256 | 256 B | typical | 661 | **1.47 (27.5x)** | 1.54 (26.2x) | 1.90 (21.3x) | 3.05 (13.3x) | 3.34 (12.1x) | 3.91 (10.3x) | 4.86 (8.3x) | 12.87 (3.1x) | 19.29 (2.1x) | 40.43 (1.0x) |
| HS256 | 256 B | medium | 2244 | **2.90 (31.0x)** | 4.22 (21.3x) | 5.43 (16.6x) | 4.74 (19.0x) | 7.02 (12.8x) | 10.30 (8.7x) | 8.60 (10.5x) | 17.91 (5.0x) | 30.23 (3.0x) | 90.00 (1.0x) |
| HS256 | 256 B | large | 20884 | **22.39 (32.4x)** | 38.91 (18.6x) | 48.68 (14.9x) | 32.85 (22.1x) | 54.87 (13.2x) | 94.72 (7.7x) | 75.14 (9.7x) | 93.98 (7.7x) | 163.22 (4.4x) | 725.47 (1.0x) |
| HS256 | 4096 B | small | 231 | 0.76 (74.2x) | **0.73 (77.2x)** | 0.83 (67.5x) | 1.51 (37.2x) | 3.59 (15.7x) | 3.75 (15.0x) | 5.05 (11.1x) | 13.67 (4.1x) | 17.03 (3.3x) | 56.28 (1.0x) |
| HS256 | 4096 B | typical | 661 | **1.48 (48.3x)** | 1.51 (47.2x) | 1.87 (38.3x) | 3.04 (23.5x) | 5.17 (13.8x) | 5.75 (12.4x) | 6.55 (10.9x) | 15.00 (4.8x) | 21.13 (3.4x) | 71.40 (1.0x) |
| HS256 | 4096 B | medium | 2244 | **2.91 (41.5x)** | 4.22 (28.6x) | 5.40 (22.4x) | 4.74 (25.5x) | 8.82 (13.7x) | 12.14 (10.0x) | 10.43 (11.6x) | 20.28 (6.0x) | 32.06 (3.8x) | 120.85 (1.0x) |
| HS256 | 4096 B | large | 20884 | **22.36 (33.8x)** | 39.02 (19.4x) | 48.71 (15.5x) | 32.85 (23.0x) | 56.77 (13.3x) | 96.81 (7.8x) | 77.80 (9.7x) | 96.45 (7.8x) | 165.27 (4.6x) | 756.29 (1.0x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.2.2 → Struct | ryjwt 0.2.2 → dict (msgspec) | ryjwt 0.2.2 → dict (jiter) | ryjwt 0.2.2 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 13.96 (3.2x) | **13.89 (3.2x)** | 13.98 (3.2x) | 14.67 (3.0x) | 17.50 (2.5x) | 17.60 (2.5x) | 18.27 (2.4x) | 25.39 (1.7x) | 32.55 (1.4x) | 44.42 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 15.05 (3.8x) | **14.70 (3.9x)** | 15.07 (3.8x) | 16.23 (3.5x) | 18.89 (3.0x) | 19.37 (3.0x) | 20.63 (2.8x) | 27.48 (2.1x) | 36.27 (1.6x) | 57.59 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **16.04 (6.8x)** | 17.35 (6.3x) | 18.57 (5.9x) | 17.90 (6.1x) | 22.72 (4.8x) | 26.08 (4.2x) | 23.84 (4.6x) | 37.47 (2.9x) | 47.70 (2.3x) | 108.82 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **35.57 (21.0x)** | 52.38 (14.3x) | 61.89 (12.1x) | 46.05 (16.2x) | 70.62 (10.6x) | 110.54 (6.8x) | 93.62 (8.0x) | 108.25 (6.9x) | 180.00 (4.2x) | 747.05 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.45 (2.3x) | **28.41 (2.3x)** | 28.46 (2.3x) | 29.43 (2.2x) | 34.00 (1.9x) | 34.01 (1.9x) | 32.99 (2.0x) | 40.58 (1.6x) | 48.98 (1.3x) | 65.32 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.13 (2.7x)** | 29.18 (2.7x) | 29.53 (2.7x) | 30.76 (2.6x) | 35.41 (2.2x) | 35.74 (2.2x) | 33.99 (2.3x) | 41.94 (1.9x) | 52.85 (1.5x) | 78.56 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.56 (4.3x)** | 32.38 (4.0x) | 33.08 (3.9x) | 32.38 (4.0x) | 39.26 (3.3x) | 42.37 (3.1x) | 38.06 (3.4x) | 46.79 (2.8x) | 64.09 (2.0x) | 129.98 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **50.33 (15.3x)** | 66.75 (11.5x) | 75.90 (10.1x) | 60.69 (12.7x) | 87.15 (8.8x) | 127.63 (6.0x) | 105.45 (7.3x) | 121.94 (6.3x) | 198.19 (3.9x) | 769.67 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.73 (1.9x) | 48.46 (1.9x) | **48.40 (1.9x)** | 49.13 (1.9x) | 57.07 (1.6x) | 56.97 (1.6x) | 53.08 (1.7x) | 61.01 (1.5x) | 71.57 (1.3x) | 92.59 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 49.42 (2.1x) | **49.18 (2.2x)** | 49.51 (2.1x) | 50.72 (2.1x) | 58.53 (1.8x) | 58.83 (1.8x) | 54.91 (1.9x) | 62.12 (1.7x) | 75.48 (1.4x) | 105.80 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **50.54 (3.1x)** | 51.89 (3.0x) | 53.01 (3.0x) | 52.46 (3.0x) | 62.34 (2.5x) | 65.30 (2.4x) | 58.37 (2.7x) | 67.61 (2.3x) | 86.84 (1.8x) | 157.76 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **70.05 (11.4x)** | 86.86 (9.2x) | 96.43 (8.3x) | 80.63 (9.9x) | 110.51 (7.2x) | 150.04 (5.3x) | 125.50 (6.4x) | 143.82 (5.5x) | 220.95 (3.6x) | 797.02 (1.0x) |
| ES256 | P-256 | small | 304 | 39.74 (1.8x) | **39.67 (1.8x)** | 40.10 (1.8x) | 40.49 (1.8x) | 41.04 (1.8x) | 41.17 (1.8x) | 43.08 (1.7x) | 51.27 (1.4x) | 67.95 (1.1x) | 73.03 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.59 (2.1x)** | 40.66 (2.1x) | 41.50 (2.1x) | 42.25 (2.0x) | 42.67 (2.0x) | 43.12 (2.0x) | 44.30 (1.9x) | 53.12 (1.6x) | 71.67 (1.2x) | 86.19 (1.0x) |
| ES256 | P-256 | medium | 2317 | **41.87 (3.3x)** | 43.25 (3.2x) | 44.77 (3.1x) | 43.80 (3.1x) | 46.31 (3.0x) | 49.58 (2.8x) | 47.59 (2.9x) | 58.37 (2.3x) | 83.03 (1.7x) | 137.09 (1.0x) |
| ES256 | P-256 | large | 20957 | **61.39 (12.6x)** | 78.31 (9.9x) | 88.58 (8.7x) | 72.31 (10.7x) | 94.90 (8.2x) | 134.66 (5.7x) | 115.98 (6.7x) | 134.21 (5.8x) | 216.31 (3.6x) | 773.85 (1.0x) |
| ES384 | P-384 | small | 346 | 179.48 (1.5x) | **179.29 (1.5x)** | 180.44 (1.5x) | 180.11 (1.5x) | 181.40 (1.5x) | 181.91 (1.5x) | 342.58 (0.8x) | 357.26 (0.8x) | 265.45 (1.0x) | 271.32 (1.0x) |
| ES384 | P-384 | typical | 746 | 181.13 (1.6x) | **180.84 (1.6x)** | 182.26 (1.6x) | 182.53 (1.6x) | 183.58 (1.6x) | 184.04 (1.5x) | 344.94 (0.8x) | 365.70 (0.8x) | 268.95 (1.1x) | 284.55 (1.0x) |
| ES384 | P-384 | medium | 2359 | **181.37 (1.9x)** | 182.56 (1.8x) | 184.72 (1.8x) | 183.23 (1.8x) | 186.42 (1.8x) | 189.65 (1.8x) | 348.86 (1.0x) | 366.00 (0.9x) | 281.24 (1.2x) | 335.68 (1.0x) |
| ES384 | P-384 | large | 20999 | **207.54 (4.7x)** | 224.42 (4.4x) | 235.29 (4.2x) | 218.17 (4.5x) | 240.91 (4.1x) | 281.09 (3.5x) | 419.76 (2.3x) | 446.54 (2.2x) | 419.95 (2.3x) | 978.58 (1.0x) |
| ES512 | P-521 | small | 394 | 287.78 (1.3x) | **287.50 (1.3x)** | 290.39 (1.3x) | 288.40 (1.3x) | n/a | n/a | 906.74 (0.4x) | 931.81 (0.4x) | 376.47 (1.0x) | 383.44 (1.0x) |
| ES512 | P-521 | typical | 794 | **285.51 (1.4x)** | 285.55 (1.4x) | 287.26 (1.4x) | 287.23 (1.4x) | n/a | n/a | 893.99 (0.4x) | 919.39 (0.4x) | 380.31 (1.0x) | 397.03 (1.0x) |
| ES512 | P-521 | medium | 2407 | **288.73 (1.6x)** | 289.80 (1.5x) | 292.58 (1.5x) | 290.50 (1.5x) | n/a | n/a | 889.97 (0.5x) | 917.36 (0.5x) | 392.97 (1.1x) | 448.22 (1.0x) |
| ES512 | P-521 | large | 21047 | **313.75 (3.5x)** | 330.41 (3.3x) | 341.30 (3.2x) | 324.11 (3.4x) | n/a | n/a | 976.10 (1.1x) | 1017.55 (1.1x) | 532.81 (2.0x) | 1089.34 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.64 (2.5x) | **32.55 (2.5x)** | 32.70 (2.5x) | 33.44 (2.4x) | 33.42 (2.4x) | 33.50 (2.4x) | 41.02 (2.0x) | 50.39 (1.6x) | 77.58 (1.1x) | 81.64 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.47 (2.8x)** | 33.51 (2.8x) | 33.95 (2.8x) | 35.12 (2.7x) | 34.90 (2.7x) | 35.38 (2.7x) | 41.84 (2.3x) | 51.18 (1.8x) | 80.94 (1.2x) | 94.21 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.49 (4.1x)** | 36.80 (4.0x) | 37.98 (3.8x) | 37.36 (3.9x) | 39.41 (3.7x) | 42.68 (3.4x) | 47.04 (3.1x) | 57.56 (2.5x) | 93.19 (1.6x) | 146.13 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **60.49 (13.1x)** | 77.11 (10.2x) | 87.53 (9.0x) | 71.03 (11.1x) | 92.82 (8.5x) | 133.96 (5.9x) | 119.40 (6.6x) | 139.15 (5.7x) | 233.51 (3.4x) | 790.15 (1.0x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.2.2 → Struct | ryjwt 0.2.2 → dict (msgspec) | ryjwt 0.2.2 → dict (jiter) | ryjwt 0.2.2 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 13.95 (4.7x) | **13.89 (4.7x)** | 13.96 (4.7x) | 14.72 (4.5x) | 17.82 (3.7x) | 17.91 (3.7x) | 20.37 (3.2x) | 28.68 (2.3x) | 34.84 (1.9x) | 65.52 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **14.65 (6.2x)** | 14.70 (6.1x) | 15.09 (6.0x) | 16.24 (5.5x) | 19.37 (4.7x) | 19.81 (4.5x) | 21.65 (4.2x) | 28.38 (3.2x) | 38.76 (2.3x) | 90.10 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **16.03 (11.7x)** | 17.37 (10.8x) | 18.57 (10.1x) | 17.95 (10.4x) | 23.68 (7.9x) | 27.33 (6.8x) | 28.77 (6.5x) | 33.64 (5.6x) | 49.99 (3.7x) | 186.98 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **35.52 (39.5x)** | 52.72 (26.6x) | 61.38 (22.9x) | 46.20 (30.4x) | 78.15 (18.0x) | 119.78 (11.7x) | 153.24 (9.2x) | 109.17 (12.9x) | 184.55 (7.6x) | 1404.03 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.45 (3.2x) | **28.35 (3.2x)** | 28.45 (3.2x) | 29.15 (3.1x) | 34.26 (2.7x) | 34.58 (2.6x) | 34.60 (2.6x) | 40.50 (2.2x) | 51.24 (1.8x) | 90.81 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.14 (4.0x)** | 29.19 (4.0x) | 29.56 (3.9x) | 30.74 (3.8x) | 35.83 (3.2x) | 36.47 (3.2x) | 37.09 (3.1x) | 42.14 (2.7x) | 55.12 (2.1x) | 115.62 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.55 (7.0x)** | 31.90 (6.7x) | 33.04 (6.5x) | 32.59 (6.6x) | 40.14 (5.3x) | 43.93 (4.9x) | 43.76 (4.9x) | 47.50 (4.5x) | 66.35 (3.2x) | 213.53 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **50.08 (28.6x)** | 67.16 (21.3x) | 76.45 (18.7x) | 60.61 (23.6x) | 94.86 (15.1x) | 136.43 (10.5x) | 166.95 (8.6x) | 123.62 (11.6x) | 201.15 (7.1x) | 1432.80 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.44 (2.5x) | **48.37 (2.5x)** | 48.44 (2.5x) | 49.16 (2.5x) | 57.27 (2.1x) | 57.66 (2.1x) | 55.51 (2.2x) | 61.20 (2.0x) | 73.94 (1.7x) | 122.96 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 49.20 (3.0x) | **49.18 (3.0x)** | 49.55 (3.0x) | 50.77 (2.9x) | 58.84 (2.5x) | 59.74 (2.5x) | 57.77 (2.6x) | 63.88 (2.3x) | 77.83 (1.9x) | 147.79 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **50.55 (4.9x)** | 51.92 (4.7x) | 53.43 (4.6x) | 52.44 (4.7x) | 63.17 (3.9x) | 66.67 (3.7x) | 64.65 (3.8x) | 68.65 (3.6x) | 89.02 (2.8x) | 246.50 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **70.16 (20.9x)** | 87.18 (16.8x) | 96.92 (15.1x) | 80.62 (18.2x) | 116.03 (12.6x) | 158.95 (9.2x) | 188.49 (7.8x) | 144.42 (10.2x) | 223.97 (6.6x) | 1467.26 (1.0x) |
| ES256 | P-256 | small | 304 | 39.71 (2.2x) | **39.69 (2.2x)** | 39.70 (2.2x) | 40.48 (2.1x) | 41.32 (2.1x) | 41.50 (2.1x) | 43.96 (2.0x) | 52.08 (1.7x) | 70.21 (1.2x) | 86.42 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.59 (2.7x)** | 40.66 (2.7x) | 41.49 (2.7x) | 42.23 (2.6x) | 43.34 (2.6x) | 43.58 (2.6x) | 47.10 (2.4x) | 55.28 (2.0x) | 73.99 (1.5x) | 111.20 (1.0x) |
| ES256 | P-256 | medium | 2317 | **41.85 (5.0x)** | 43.19 (4.8x) | 44.37 (4.7x) | 43.78 (4.7x) | 47.30 (4.4x) | 50.59 (4.1x) | 53.37 (3.9x) | 58.61 (3.5x) | 85.31 (2.4x) | 207.72 (1.0x) |
| ES256 | P-256 | large | 20957 | **61.72 (23.1x)** | 78.61 (18.1x) | 87.49 (16.3x) | 72.16 (19.7x) | 100.51 (14.2x) | 142.26 (10.0x) | 177.34 (8.0x) | 134.42 (10.6x) | 218.84 (6.5x) | 1423.89 (1.0x) |
| ES384 | P-384 | small | 346 | 179.46 (1.6x) | **179.28 (1.6x)** | 180.47 (1.6x) | 180.09 (1.6x) | 181.52 (1.6x) | 181.75 (1.6x) | 344.55 (0.8x) | 359.93 (0.8x) | 267.55 (1.1x) | 285.89 (1.0x) |
| ES384 | P-384 | typical | 746 | 181.13 (1.7x) | **180.86 (1.7x)** | 182.32 (1.7x) | 182.49 (1.7x) | 183.97 (1.7x) | 184.57 (1.7x) | 347.47 (0.9x) | 360.26 (0.9x) | 271.32 (1.1x) | 310.50 (1.0x) |
| ES384 | P-384 | medium | 2359 | **181.44 (2.2x)** | 182.65 (2.2x) | 184.74 (2.2x) | 183.32 (2.2x) | 187.23 (2.2x) | 190.77 (2.1x) | 354.75 (1.1x) | 366.88 (1.1x) | 283.12 (1.4x) | 407.01 (1.0x) |
| ES384 | P-384 | large | 20999 | **207.54 (7.8x)** | 225.02 (7.2x) | 234.90 (6.9x) | 218.05 (7.5x) | 247.68 (6.6x) | 289.60 (5.6x) | 481.48 (3.4x) | 449.14 (3.6x) | 424.66 (3.8x) | 1629.16 (1.0x) |
| ES512 | P-521 | small | 394 | 287.69 (1.4x) | **287.65 (1.4x)** | 288.94 (1.4x) | 288.49 (1.4x) | n/a | n/a | 909.03 (0.4x) | 932.53 (0.4x) | 378.55 (1.1x) | 401.34 (1.0x) |
| ES512 | P-521 | typical | 794 | 285.81 (1.5x) | **285.59 (1.5x)** | 287.35 (1.5x) | 287.29 (1.5x) | n/a | n/a | 897.61 (0.5x) | 922.05 (0.5x) | 382.42 (1.1x) | 425.84 (1.0x) |
| ES512 | P-521 | medium | 2407 | **288.57 (1.8x)** | 289.84 (1.8x) | 293.05 (1.8x) | 290.46 (1.8x) | n/a | n/a | 896.07 (0.6x) | 918.24 (0.6x) | 394.33 (1.3x) | 523.57 (1.0x) |
| ES512 | P-521 | large | 21047 | **313.75 (5.6x)** | 330.68 (5.3x) | 341.54 (5.1x) | 324.47 (5.4x) | n/a | n/a | 1038.04 (1.7x) | 1022.57 (1.7x) | 534.66 (3.3x) | 1745.02 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.68 (2.9x) | **32.58 (2.9x)** | 32.72 (2.9x) | 33.47 (2.8x) | 33.71 (2.8x) | 33.83 (2.8x) | 42.46 (2.2x) | 51.37 (1.8x) | 79.46 (1.2x) | 94.75 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.42 (3.6x)** | 33.52 (3.5x) | 34.37 (3.5x) | 35.11 (3.4x) | 35.35 (3.4x) | 35.85 (3.3x) | 44.68 (2.7x) | 51.82 (2.3x) | 82.84 (1.4x) | 118.86 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.46 (6.1x)** | 36.79 (5.9x) | 37.98 (5.7x) | 37.36 (5.8x) | 40.19 (5.4x) | 43.68 (5.0x) | 52.20 (4.1x) | 57.99 (3.7x) | 95.05 (2.3x) | 216.52 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **60.44 (23.8x)** | 77.55 (18.5x) | 87.30 (16.5x) | 70.95 (20.3x) | 98.83 (14.5x) | 141.75 (10.1x) | 181.21 (7.9x) | 139.81 (10.3x) | 235.78 (6.1x) | 1436.84 (1.0x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.2.2 → Struct | ryjwt 0.2.2 → dict (msgspec) | ryjwt 0.2.2 → dict (jiter) | ryjwt 0.2.2 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 14.23 (4.9x) | **14.18 (4.9x)** | 14.27 (4.9x) | 14.98 (4.6x) | n/a | n/a | n/a | n/a | n/a | 69.61 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **14.94 (6.4x)** | 15.05 (6.4x) | 15.39 (6.2x) | 16.54 (5.8x) | n/a | n/a | n/a | n/a | n/a | 95.63 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **16.34 (12.1x)** | 17.78 (11.1x) | 18.83 (10.5x) | 18.24 (10.8x) | n/a | n/a | n/a | n/a | n/a | 197.31 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **35.94 (40.7x)** | 53.16 (27.5x) | 62.04 (23.6x) | 46.68 (31.3x) | n/a | n/a | n/a | n/a | n/a | 1462.27 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.87 (3.3x) | **28.83 (3.3x)** | 28.94 (3.3x) | 29.64 (3.2x) | n/a | n/a | n/a | n/a | n/a | 94.99 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.58 (4.1x)** | 29.67 (4.1x) | 30.06 (4.0x) | 31.19 (3.9x) | n/a | n/a | n/a | n/a | n/a | 121.03 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.96 (7.2x)** | 32.38 (6.9x) | 33.46 (6.7x) | 32.92 (6.8x) | n/a | n/a | n/a | n/a | n/a | 223.02 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **50.52 (29.5x)** | 67.80 (22.0x) | 76.68 (19.5x) | 61.30 (24.3x) | n/a | n/a | n/a | n/a | n/a | 1491.54 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 49.00 (2.6x) | **48.95 (2.6x)** | 49.03 (2.6x) | 49.76 (2.5x) | n/a | n/a | n/a | n/a | n/a | 126.78 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **49.72 (3.1x)** | 49.81 (3.1x) | 50.94 (3.0x) | 51.39 (3.0x) | n/a | n/a | n/a | n/a | n/a | 152.71 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **51.12 (5.0x)** | 52.60 (4.9x) | 53.77 (4.8x) | 53.08 (4.8x) | n/a | n/a | n/a | n/a | n/a | 255.76 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **70.64 (21.6x)** | 88.06 (17.3x) | 96.35 (15.8x) | 81.41 (18.7x) | n/a | n/a | n/a | n/a | n/a | 1525.68 (1.0x) |
| ES256 | P-256 | small | 304 | 40.03 (2.3x) | **39.96 (2.3x)** | 40.05 (2.3x) | 40.86 (2.2x) | n/a | n/a | n/a | n/a | n/a | 90.41 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.90 (2.8x)** | 41.01 (2.8x) | 41.61 (2.8x) | 42.58 (2.7x) | n/a | n/a | n/a | n/a | n/a | 116.08 (1.0x) |
| ES256 | P-256 | medium | 2317 | **42.14 (5.2x)** | 43.60 (5.0x) | 44.69 (4.9x) | 44.04 (4.9x) | n/a | n/a | n/a | n/a | n/a | 217.13 (1.0x) |
| ES256 | P-256 | large | 20957 | **61.89 (23.9x)** | 79.14 (18.7x) | 87.74 (16.9x) | 72.54 (20.4x) | n/a | n/a | n/a | n/a | n/a | 1479.39 (1.0x) |
| ES384 | P-384 | small | 346 | **179.79 (1.6x)** | 179.87 (1.6x) | 181.28 (1.6x) | 180.71 (1.6x) | n/a | n/a | n/a | n/a | n/a | 289.65 (1.0x) |
| ES384 | P-384 | typical | 746 | **181.24 (1.7x)** | 181.54 (1.7x) | 182.59 (1.7x) | 183.08 (1.7x) | n/a | n/a | n/a | n/a | n/a | 315.53 (1.0x) |
| ES384 | P-384 | medium | 2359 | **181.63 (2.3x)** | 183.39 (2.3x) | 185.46 (2.2x) | 183.73 (2.3x) | n/a | n/a | n/a | n/a | n/a | 416.73 (1.0x) |
| ES384 | P-384 | large | 20999 | **208.02 (8.1x)** | 225.73 (7.5x) | 235.41 (7.2x) | 219.14 (7.7x) | n/a | n/a | n/a | n/a | n/a | 1690.93 (1.0x) |
| ES512 | P-521 | small | 394 | 288.28 (1.4x) | **287.75 (1.4x)** | 290.06 (1.4x) | 288.53 (1.4x) | n/a | n/a | n/a | n/a | n/a | 405.34 (1.0x) |
| ES512 | P-521 | typical | 794 | 285.97 (1.5x) | **285.82 (1.5x)** | 287.42 (1.5x) | 287.37 (1.5x) | n/a | n/a | n/a | n/a | n/a | 431.63 (1.0x) |
| ES512 | P-521 | medium | 2407 | **289.12 (1.8x)** | 290.15 (1.8x) | 292.84 (1.8x) | 290.63 (1.8x) | n/a | n/a | n/a | n/a | n/a | 532.45 (1.0x) |
| ES512 | P-521 | large | 21047 | **314.26 (5.7x)** | 331.36 (5.4x) | 340.90 (5.3x) | 324.44 (5.6x) | n/a | n/a | n/a | n/a | n/a | 1804.15 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.99 (3.0x) | **32.95 (3.0x)** | 33.04 (3.0x) | 33.75 (2.9x) | n/a | n/a | n/a | n/a | n/a | 98.85 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.78 (3.7x)** | 33.92 (3.7x) | 34.25 (3.6x) | 35.43 (3.5x) | n/a | n/a | n/a | n/a | n/a | 124.22 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.76 (6.3x)** | 37.29 (6.1x) | 38.27 (5.9x) | 37.62 (6.0x) | n/a | n/a | n/a | n/a | n/a | 226.03 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **60.85 (24.5x)** | 78.27 (19.1x) | 87.11 (17.1x) | 71.55 (20.9x) | n/a | n/a | n/a | n/a | n/a | 1492.95 (1.0x) |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.2.2 → Struct | ryjwt 0.2.2 → dict (msgspec) | ryjwt 0.2.2 → dict (jiter) | ryjwt 0.2.2 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 14.30 (4.9x) | **14.25 (4.9x)** | 14.35 (4.8x) | 15.06 (4.6x) | n/a | n/a | 52.00 (1.3x) | 26.52 (2.6x) | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | **14.99 (6.4x)** | 15.13 (6.3x) | 15.47 (6.2x) | 16.63 (5.8x) | n/a | n/a | 44.99 (2.1x) | 28.79 (3.3x) | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | **16.39 (12.0x)** | 17.83 (11.1x) | 18.94 (10.4x) | 18.35 (10.8x) | n/a | n/a | 46.57 (4.2x) | 33.13 (6.0x) | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | **35.97 (40.7x)** | 52.99 (27.6x) | 62.28 (23.5x) | 47.19 (31.0x) | n/a | n/a | 117.62 (12.4x) | 109.73 (13.3x) | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | 28.97 (3.3x) | **28.89 (3.3x)** | 29.03 (3.3x) | 29.70 (3.2x) | n/a | n/a | 68.94 (1.4x) | 43.18 (2.2x) | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | **29.67 (4.1x)** | 29.76 (4.1x) | 30.19 (4.0x) | 31.27 (3.9x) | n/a | n/a | 69.33 (1.7x) | 42.51 (2.8x) | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | **31.07 (7.2x)** | 32.42 (6.9x) | 33.62 (6.6x) | 32.98 (6.8x) | n/a | n/a | 73.01 (3.1x) | 47.89 (4.7x) | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | **50.60 (29.5x)** | 67.60 (22.1x) | 76.97 (19.4x) | 61.83 (24.1x) | n/a | n/a | 144.97 (10.3x) | 123.77 (12.1x) | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | 49.15 (2.6x) | **49.05 (2.6x)** | 49.79 (2.5x) | 49.90 (2.5x) | n/a | n/a | 105.90 (1.2x) | 61.92 (2.0x) | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | **49.85 (3.1x)** | 49.88 (3.1x) | 50.32 (3.0x) | 51.43 (3.0x) | n/a | n/a | 106.56 (1.4x) | 62.92 (2.4x) | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | **51.25 (5.0x)** | 52.70 (4.9x) | 54.08 (4.7x) | 53.13 (4.8x) | n/a | n/a | 110.97 (2.3x) | 68.42 (3.7x) | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | **70.84 (21.5x)** | 87.84 (17.4x) | 97.02 (15.7x) | 82.02 (18.6x) | n/a | n/a | 182.23 (8.4x) | 149.27 (10.2x) | n/a | n/a |
| ES256 | P-256 | small | 304 | 40.08 (2.3x) | **40.05 (2.3x)** | 40.86 (2.2x) | 40.88 (2.2x) | n/a | n/a | 2411.11 (0.04x) | 51.40 (1.8x) | n/a | n/a |
| ES256 | P-256 | typical | 704 | **40.98 (2.8x)** | 41.09 (2.8x) | 41.45 (2.8x) | 42.68 (2.7x) | n/a | n/a | 2405.05 (0.05x) | 53.97 (2.2x) | n/a | n/a |
| ES256 | P-256 | medium | 2317 | **42.24 (5.1x)** | 43.79 (5.0x) | 44.79 (4.8x) | 44.20 (4.9x) | n/a | n/a | 2409.31 (0.09x) | 58.57 (3.7x) | n/a | n/a |
| ES256 | P-256 | large | 20957 | **61.78 (23.9x)** | 79.19 (18.7x) | 87.92 (16.8x) | 73.11 (20.2x) | n/a | n/a | 2479.60 (0.6x) | 135.57 (10.9x) | n/a | n/a |
| ES384 | P-384 | small | 346 | 180.16 (1.6x) | **179.74 (1.6x)** | 180.61 (1.6x) | 180.67 (1.6x) | n/a | n/a | 11581.34 (0.03x) | 357.90 (0.8x) | n/a | n/a |
| ES384 | P-384 | typical | 746 | 181.63 (1.7x) | **181.44 (1.7x)** | 182.43 (1.7x) | 182.99 (1.7x) | n/a | n/a | 11607.91 (0.03x) | 360.23 (0.9x) | n/a | n/a |
| ES384 | P-384 | medium | 2359 | **182.02 (2.3x)** | 183.20 (2.3x) | 185.27 (2.2x) | 183.79 (2.3x) | n/a | n/a | 11591.31 (0.04x) | 367.86 (1.1x) | n/a | n/a |
| ES384 | P-384 | large | 20999 | **208.11 (8.1x)** | 225.30 (7.5x) | 235.29 (7.2x) | 219.24 (7.7x) | n/a | n/a | 11653.31 (0.1x) | 449.23 (3.8x) | n/a | n/a |
| ES512 | P-521 | small | 394 | **287.98 (1.4x)** | 288.58 (1.4x) | 289.32 (1.4x) | 289.16 (1.4x) | n/a | n/a | 27804.41 (0.01x) | 932.30 (0.4x) | n/a | n/a |
| ES512 | P-521 | typical | 794 | **285.85 (1.5x)** | 286.23 (1.5x) | 288.60 (1.5x) | 288.15 (1.5x) | n/a | n/a | 27798.83 (0.02x) | 920.24 (0.5x) | n/a | n/a |
| ES512 | P-521 | medium | 2407 | **288.90 (1.8x)** | 290.55 (1.8x) | 292.99 (1.8x) | 291.30 (1.8x) | n/a | n/a | 27773.61 (0.02x) | 920.95 (0.6x) | n/a | n/a |
| ES512 | P-521 | large | 21047 | **313.76 (5.8x)** | 331.25 (5.4x) | 341.94 (5.3x) | 325.61 (5.5x) | n/a | n/a | 27811.26 (0.06x) | 1019.48 (1.8x) | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | 33.09 (3.0x) | **33.02 (3.0x)** | 33.11 (3.0x) | 33.81 (2.9x) | n/a | n/a | n/a | 52.36 (1.9x) | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | **33.89 (3.7x)** | 33.96 (3.7x) | 34.36 (3.6x) | 35.53 (3.5x) | n/a | n/a | n/a | 52.15 (2.4x) | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | **36.00 (6.3x)** | 37.23 (6.1x) | 38.41 (5.9x) | 37.80 (6.0x) | n/a | n/a | n/a | 58.09 (3.9x) | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | **60.96 (24.5x)** | 78.09 (19.1x) | 87.17 (17.1x) | 72.03 (20.7x) | n/a | n/a | n/a | 139.62 (10.7x) | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.2.2 → Struct | ryjwt 0.2.2 → dict (msgspec) | ryjwt 0.2.2 → dict (jiter) | ryjwt 0.2.2 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 1.7 | 1.5 | 1.5 | 1.5 | n/a | n/a | n/a | n/a | n/a | 1.3 |
| JWKS URL, async client | 1.7 | 1.5 | 1.5 | 1.5 | n/a | n/a | 0.8 | 0.7 | n/a | n/a |

## Not applicable

- jsonwebtoken 11.1.0 (aws-lc-rs) → struct, every key source, ES512: jsonwebtoken has no ES512 (P-521).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct, JWKS URL, sync client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct, JWKS URL, async client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value, every key source, ES512: jsonwebtoken has no ES512 (P-521).
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value, JWKS URL, sync client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value, JWKS URL, async client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- fast-jwt 6.3.3, JWKS URL, sync client: fast-jwt's JWKS support (get-jwks) is async only.
- fast-jwt 6.3.3, JWKS URL, async client, EdDSA: get-jwks converts JWKs with jwk-to-pem, which doesn't support OKP (Ed25519) keys.
- jose 6.2.12, JWKS URL, sync client: jose's API is async only.
- joserfc 1.7.5, JWKS URL, sync client: joserfc has no JWKS URL client.
- joserfc 1.7.5, JWKS URL, async client: joserfc has no JWKS URL client.
- pyjwt 2.15.1, JWKS URL, async client: PyJWT has no async JWKS client.

## Notes

- ryjwt 0.2.2 → Struct: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.2.2 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.2.2 → dict (msgspec): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.2.2 → dict (msgspec): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.2.2 → dict (jiter): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.2.2 → dict (jiter): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.2.2 → BaseModel: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.2.2 → BaseModel: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: claims decoded into typed structs with the fields ryjwt's msgspec lane decodes; other claims ignored.
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value: JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- fast-jwt 6.3.3: JWKS document: a verifier per key, made once, picked by the token's `kid` (read with `createDecoder`).
- fast-jwt 6.3.3: JWKS URL rows are fast-jwt + get-jwks 11.0.3 (fast-jwt's documented integration), so they time both: on every verify get-jwks converts the cached JWK to a PEM (with jwk-to-pem) and fast-jwt imports that PEM (`createPublicKey`), which is why they're slow.
- jose 6.2.12: HMAC secret imported once (`crypto.subtle.importKey`); `importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`.
- joserfc 1.7.5: `jwt.decode(token, key, algorithms=[...])`, then `JWTClaimsRegistry(exp=..., aud=...).validate(token.claims)`, both essential.
- joserfc 1.7.5: keys imported once (`OctKey`, `RSAKey`, `ECKey`, `OKPKey`); JWKS document: a `KeySet`, which picks the key by `kid`.
- joserfc 1.7.5: EdDSA: joserfc warns on every decode (`SecurityWarning`: RFC 9864 deprecates `EdDSA`), as it does by default.
- pyjwt 2.15.1: PEM: the key loaded once, with `load_pem_public_key`.
- pyjwt 2.15.1: JWKS document: `PyJWKSet`, picking the key by `get_unverified_header`'s `kid`.
- pyjwt 2.15.1: JWKS URL: `PyJWKClient(cache_keys=True)`, its `ssl_context` trusting the test CA.
