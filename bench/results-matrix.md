# JWT decode benchmarks: the full matrix

Generated 2026-11-10 from `bench/results-matrix/` by `bench/compare.py`, on
AWS m9g.2xlarge, Graviton5 (aarch64), Linux.
Run in Docker, one container per library, on two instances, up to 5 at once on each, each limited to 1 CPU (pinned, a core of its own) and 500 MB with no swap; the JWKS server runs in a container of its own on each, outside that limit. Each case gets 1,000 untimed decodes, then 10,000 timed.
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

| key source | alg | key | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | **1.41 (27.5x)** | 1.44 (26.8x) | 1.67 (23.2x) | 2.75 (14.1x) | 3.24 (12.0x) | 3.72 (10.4x) | 4.78 (8.1x) | 12.36 (3.1x) | 19.10 (2.0x) | 38.74 (1.0x) |
| PEM public key | RS256 | RSA 3072 | **28.99 (2.7x)** | 29.04 (2.7x) | 29.94 (2.6x) | 30.47 (2.6x) | 35.26 (2.2x) | 35.63 (2.2x) | 34.07 (2.3x) | 42.27 (1.9x) | 52.67 (1.5x) | 78.91 (1.0x) |
| PEM public key | ES384 | P-384 | **180.44 (1.6x)** | 180.70 (1.6x) | 181.55 (1.6x) | 181.96 (1.6x) | 183.10 (1.6x) | 183.52 (1.5x) | 344.58 (0.8x) | 366.79 (0.8x) | 268.87 (1.1x) | 284.41 (1.0x) |
| PEM public key | EdDSA | Ed25519 | **33.42 (2.8x)** | 33.45 (2.8x) | 33.71 (2.8x) | 34.86 (2.7x) | 34.89 (2.7x) | 35.22 (2.7x) | 42.21 (2.2x) | 51.52 (1.8x) | 80.85 (1.2x) | 94.24 (1.0x) |
| JWKS document | RS256 | RSA 3072 | **29.00 (4.0x)** | 29.05 (4.0x) | 29.33 (4.0x) | 30.46 (3.8x) | 35.81 (3.2x) | 36.30 (3.2x) | 37.39 (3.1x) | 42.35 (2.7x) | 55.11 (2.1x) | 116.09 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | **29.44 (4.1x)** | 29.55 (4.1x) | 29.80 (4.1x) | 30.90 (3.9x) | n/a | n/a | n/a | n/a | n/a | 121.19 (1.0x) |
| JWKS URL, async client | RS256 | RSA 3072 | **29.51 (4.1x)** | 30.00 (4.0x) | 29.91 (4.1x) | 30.97 (3.9x) | n/a | n/a | 70.33 (1.7x) | 43.14 (2.8x) | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | 0.70 (34.0x) | **0.68 (35.5x)** | 0.75 (32.0x) | 1.32 (18.1x) | 1.54 (15.6x) | 1.74 (13.8x) | 7.98 (3.0x) | 17.95 (1.3x) | 15.09 (1.6x) | 23.97 (1.0x) |
| HS256 | 32 B | typical | 661 | **1.42 (27.1x)** | 1.45 (26.5x) | 1.70 (22.6x) | 2.78 (13.8x) | 3.24 (11.8x) | 3.68 (10.4x) | 8.37 (4.6x) | 17.48 (2.2x) | 19.15 (2.0x) | 38.38 (1.0x) |
| HS256 | 32 B | medium | 2244 | **2.83 (31.2x)** | 4.09 (21.6x) | 4.59 (19.3x) | 3.81 (23.2x) | 6.60 (13.4x) | 9.95 (8.9x) | 9.25 (9.6x) | 19.60 (4.5x) | 30.26 (2.9x) | 88.42 (1.0x) |
| HS256 | 32 B | large | 20884 | **22.26 (32.7x)** | 38.44 (18.9x) | 40.09 (18.1x) | 25.87 (28.1x) | 53.53 (13.6x) | 93.05 (7.8x) | 77.03 (9.4x) | 101.89 (7.1x) | 161.83 (4.5x) | 727.08 (1.0x) |
| HS256 | 64 B | small | 231 | 0.71 (34.2x) | **0.67 (36.5x)** | 0.75 (32.7x) | 1.32 (18.5x) | 1.59 (15.4x) | 1.73 (14.1x) | 3.43 (7.1x) | 11.17 (2.2x) | 14.99 (1.6x) | 24.35 (1.0x) |
| HS256 | 64 B | typical | 661 | **1.41 (27.5x)** | 1.44 (26.8x) | 1.67 (23.2x) | 2.75 (14.1x) | 3.24 (12.0x) | 3.72 (10.4x) | 4.78 (8.1x) | 12.36 (3.1x) | 19.10 (2.0x) | 38.74 (1.0x) |
| HS256 | 64 B | medium | 2244 | **2.82 (31.4x)** | 4.06 (21.8x) | 4.56 (19.5x) | 3.84 (23.1x) | 6.62 (13.4x) | 9.97 (8.9x) | 9.34 (9.5x) | 18.55 (4.8x) | 30.11 (2.9x) | 88.68 (1.0x) |
| HS256 | 64 B | large | 20884 | **22.20 (32.7x)** | 38.43 (18.9x) | 39.79 (18.2x) | 25.91 (28.0x) | 54.25 (13.4x) | 93.20 (7.8x) | 76.45 (9.5x) | 95.85 (7.6x) | 162.56 (4.5x) | 725.78 (1.0x) |
| HS256 | 256 B | small | 231 | 0.70 (37.0x) | **0.66 (39.1x)** | 0.74 (34.9x) | 1.32 (19.7x) | 1.69 (15.4x) | 1.90 (13.7x) | 3.15 (8.3x) | 11.40 (2.3x) | 15.16 (1.7x) | 25.98 (1.0x) |
| HS256 | 256 B | typical | 661 | **1.42 (28.6x)** | 1.47 (27.6x) | 1.71 (23.7x) | 2.76 (14.7x) | 3.40 (11.9x) | 3.88 (10.5x) | 5.04 (8.1x) | 13.56 (3.0x) | 19.32 (2.1x) | 40.62 (1.0x) |
| HS256 | 256 B | medium | 2244 | **2.83 (32.2x)** | 4.07 (22.3x) | 4.59 (19.8x) | 3.83 (23.7x) | 6.77 (13.4x) | 10.21 (8.9x) | 8.66 (10.5x) | 18.05 (5.0x) | 30.30 (3.0x) | 90.87 (1.0x) |
| HS256 | 256 B | large | 20884 | **22.24 (32.7x)** | 38.56 (18.9x) | 40.11 (18.2x) | 25.90 (28.1x) | 53.71 (13.6x) | 93.34 (7.8x) | 76.48 (9.5x) | 96.33 (7.6x) | 162.84 (4.5x) | 728.20 (1.0x) |
| HS256 | 4096 B | small | 231 | 0.71 (77.0x) | **0.67 (80.7x)** | 0.75 (72.8x) | 1.32 (41.2x) | 3.51 (15.5x) | 3.74 (14.5x) | 5.09 (10.7x) | 13.23 (4.1x) | 16.96 (3.2x) | 54.33 (1.0x) |
| HS256 | 4096 B | typical | 661 | **1.43 (48.1x)** | 1.44 (47.6x) | 1.67 (41.1x) | 2.77 (24.8x) | 5.25 (13.1x) | 5.72 (12.0x) | 6.96 (9.9x) | 14.91 (4.6x) | 21.19 (3.2x) | 68.78 (1.0x) |
| HS256 | 4096 B | medium | 2244 | **2.84 (41.7x)** | 4.06 (29.2x) | 4.59 (25.9x) | 3.83 (30.9x) | 8.69 (13.6x) | 12.15 (9.8x) | 10.66 (11.1x) | 20.82 (5.7x) | 31.88 (3.7x) | 118.53 (1.0x) |
| HS256 | 4096 B | large | 20884 | **22.20 (34.1x)** | 38.59 (19.6x) | 39.83 (19.0x) | 25.93 (29.2x) | 56.47 (13.4x) | 95.35 (7.9x) | 78.92 (9.6x) | 97.83 (7.7x) | 165.11 (4.6x) | 757.57 (1.0x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 13.83 (3.2x) | **13.82 (3.2x)** | 14.17 (3.1x) | 14.48 (3.1x) | 17.38 (2.6x) | 17.56 (2.5x) | 18.74 (2.4x) | 25.32 (1.8x) | 32.56 (1.4x) | 44.51 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **14.55 (4.0x)** | 14.74 (3.9x) | 14.88 (3.9x) | 15.98 (3.6x) | 18.90 (3.1x) | 19.28 (3.0x) | 23.13 (2.5x) | 28.21 (2.1x) | 36.31 (1.6x) | 57.84 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **15.97 (6.9x)** | 17.29 (6.3x) | 17.82 (6.1x) | 17.16 (6.4x) | 22.55 (4.9x) | 25.91 (4.2x) | 24.18 (4.5x) | 38.16 (2.9x) | 47.67 (2.3x) | 109.42 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **35.39 (21.2x)** | 51.92 (14.5x) | 53.51 (14.0x) | 39.09 (19.2x) | 69.63 (10.8x) | 109.87 (6.8x) | 92.22 (8.1x) | 110.75 (6.8x) | 180.40 (4.2x) | 751.15 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.22 (2.3x) | **28.19 (2.3x)** | 28.51 (2.3x) | 29.08 (2.2x) | 33.72 (1.9x) | 33.90 (1.9x) | 33.06 (2.0x) | 40.73 (1.6x) | 48.95 (1.3x) | 65.42 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **28.99 (2.7x)** | 29.04 (2.7x) | 29.94 (2.6x) | 30.47 (2.6x) | 35.26 (2.2x) | 35.63 (2.2x) | 34.07 (2.3x) | 42.27 (1.9x) | 52.67 (1.5x) | 78.91 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.41 (4.3x)** | 31.68 (4.1x) | 32.16 (4.1x) | 31.53 (4.1x) | 38.94 (3.4x) | 42.24 (3.1x) | 38.03 (3.4x) | 47.60 (2.7x) | 63.82 (2.0x) | 130.78 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **49.91 (15.5x)** | 66.41 (11.6x) | 67.68 (11.4x) | 53.55 (14.4x) | 86.70 (8.9x) | 126.26 (6.1x) | 107.37 (7.2x) | 125.40 (6.2x) | 197.37 (3.9x) | 771.82 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.22 (1.9x) | **48.13 (1.9x)** | 48.24 (1.9x) | 48.95 (1.9x) | 56.62 (1.6x) | 56.71 (1.6x) | 53.13 (1.7x) | 61.12 (1.5x) | 71.52 (1.3x) | 92.60 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **48.92 (2.2x)** | 49.00 (2.2x) | 49.29 (2.2x) | 50.38 (2.1x) | 58.32 (1.8x) | 58.59 (1.8x) | 54.87 (1.9x) | 62.59 (1.7x) | 75.33 (1.4x) | 106.10 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **50.34 (3.1x)** | 51.68 (3.1x) | 52.11 (3.0x) | 51.45 (3.1x) | 61.83 (2.6x) | 65.07 (2.4x) | 58.92 (2.7x) | 69.17 (2.3x) | 86.53 (1.8x) | 158.36 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **69.79 (11.5x)** | 86.48 (9.3x) | 87.93 (9.1x) | 73.74 (10.9x) | 109.08 (7.4x) | 148.80 (5.4x) | 128.91 (6.2x) | 147.14 (5.4x) | 218.77 (3.7x) | 801.80 (1.0x) |
| ES256 | P-256 | small | 304 | 39.56 (1.9x) | **39.55 (1.9x)** | 39.60 (1.8x) | 40.24 (1.8x) | 40.91 (1.8x) | 41.06 (1.8x) | 43.31 (1.7x) | 51.24 (1.4x) | 68.10 (1.1x) | 73.22 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.45 (2.1x)** | 40.57 (2.1x) | 40.87 (2.1x) | 41.93 (2.1x) | 42.58 (2.0x) | 42.96 (2.0x) | 44.50 (1.9x) | 53.55 (1.6x) | 71.89 (1.2x) | 86.47 (1.0x) |
| ES256 | P-256 | medium | 2317 | **41.74 (3.3x)** | 43.26 (3.2x) | 43.81 (3.1x) | 42.83 (3.2x) | 46.11 (3.0x) | 49.45 (2.8x) | 48.54 (2.8x) | 59.18 (2.3x) | 83.22 (1.7x) | 137.61 (1.0x) |
| ES256 | P-256 | large | 20957 | **61.29 (12.7x)** | 78.17 (9.9x) | 79.54 (9.8x) | 65.23 (11.9x) | 94.12 (8.3x) | 134.35 (5.8x) | 118.89 (6.5x) | 136.65 (5.7x) | 215.69 (3.6x) | 776.82 (1.0x) |
| ES384 | P-384 | small | 346 | **178.91 (1.5x)** | 179.09 (1.5x) | 180.03 (1.5x) | 179.55 (1.5x) | 180.77 (1.5x) | 180.96 (1.5x) | 345.89 (0.8x) | 357.26 (0.8x) | 264.88 (1.0x) | 271.18 (1.0x) |
| ES384 | P-384 | typical | 746 | **180.44 (1.6x)** | 180.70 (1.6x) | 181.55 (1.6x) | 181.96 (1.6x) | 183.10 (1.6x) | 183.52 (1.5x) | 344.58 (0.8x) | 366.79 (0.8x) | 268.87 (1.1x) | 284.41 (1.0x) |
| ES384 | P-384 | medium | 2359 | **180.84 (1.9x)** | 183.13 (1.8x) | 183.52 (1.8x) | 182.01 (1.8x) | 185.73 (1.8x) | 189.17 (1.8x) | 348.23 (1.0x) | 367.60 (0.9x) | 280.54 (1.2x) | 336.25 (1.0x) |
| ES384 | P-384 | large | 20999 | **206.81 (4.8x)** | 224.22 (4.4x) | 226.18 (4.4x) | 210.69 (4.7x) | 239.96 (4.1x) | 280.34 (3.5x) | 421.15 (2.3x) | 451.61 (2.2x) | 420.21 (2.3x) | 983.91 (1.0x) |
| ES512 | P-521 | small | 394 | **287.07 (1.3x)** | 287.69 (1.3x) | 288.34 (1.3x) | 288.12 (1.3x) | n/a | n/a | 905.87 (0.4x) | 931.15 (0.4x) | 375.73 (1.0x) | 383.10 (1.0x) |
| ES512 | P-521 | typical | 794 | **285.02 (1.4x)** | 285.91 (1.4x) | 287.07 (1.4x) | 286.66 (1.4x) | n/a | n/a | 892.64 (0.4x) | 919.88 (0.4x) | 379.78 (1.0x) | 396.18 (1.0x) |
| ES512 | P-521 | medium | 2407 | **288.01 (1.6x)** | 290.61 (1.5x) | 291.47 (1.5x) | 289.20 (1.5x) | n/a | n/a | 888.39 (0.5x) | 917.85 (0.5x) | 391.42 (1.1x) | 448.02 (1.0x) |
| ES512 | P-521 | large | 21047 | **312.69 (3.5x)** | 330.77 (3.3x) | 332.28 (3.3x) | 316.79 (3.5x) | n/a | n/a | 976.50 (1.1x) | 1024.83 (1.1x) | 532.11 (2.1x) | 1093.38 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.60 (2.5x) | **32.49 (2.5x)** | 32.58 (2.5x) | 33.27 (2.4x) | 33.24 (2.4x) | 33.38 (2.4x) | 40.99 (2.0x) | 50.05 (1.6x) | 77.63 (1.0x) | 81.42 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.42 (2.8x)** | 33.45 (2.8x) | 33.71 (2.8x) | 34.86 (2.7x) | 34.89 (2.7x) | 35.22 (2.7x) | 42.21 (2.2x) | 51.52 (1.8x) | 80.85 (1.2x) | 94.24 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.42 (4.1x)** | 36.62 (4.0x) | 37.08 (3.9x) | 36.42 (4.0x) | 39.13 (3.7x) | 42.47 (3.4x) | 47.33 (3.1x) | 58.38 (2.5x) | 92.91 (1.6x) | 146.41 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **60.88 (13.0x)** | 77.40 (10.2x) | 78.43 (10.1x) | 64.30 (12.3x) | 91.83 (8.6x) | 132.56 (6.0x) | 121.23 (6.5x) | 141.98 (5.6x) | 233.50 (3.4x) | 790.03 (1.0x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 13.84 (4.7x) | **13.82 (4.7x)** | 14.18 (4.6x) | 14.49 (4.5x) | 17.69 (3.7x) | 17.85 (3.7x) | 19.96 (3.3x) | 28.90 (2.3x) | 34.87 (1.9x) | 65.50 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **14.54 (6.2x)** | 14.63 (6.2x) | 14.88 (6.1x) | 15.98 (5.7x) | 19.26 (4.7x) | 19.76 (4.6x) | 22.11 (4.1x) | 28.99 (3.1x) | 38.78 (2.3x) | 90.45 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **15.98 (11.8x)** | 17.46 (10.8x) | 17.77 (10.6x) | 17.02 (11.1x) | 23.61 (8.0x) | 27.23 (7.0x) | 29.65 (6.4x) | 34.96 (5.4x) | 49.99 (3.8x) | 189.26 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **35.60 (39.7x)** | 52.09 (27.1x) | 53.56 (26.4x) | 39.25 (36.0x) | 76.80 (18.4x) | 118.99 (11.9x) | 156.87 (9.0x) | 111.64 (12.6x) | 184.49 (7.7x) | 1411.62 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.24 (3.2x) | **28.24 (3.2x)** | 28.28 (3.2x) | 28.99 (3.2x) | 34.23 (2.7x) | 34.41 (2.7x) | 35.06 (2.6x) | 40.94 (2.2x) | 51.24 (1.8x) | 91.38 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.00 (4.0x)** | 29.05 (4.0x) | 29.33 (4.0x) | 30.46 (3.8x) | 35.81 (3.2x) | 36.30 (3.2x) | 37.39 (3.1x) | 42.35 (2.7x) | 55.11 (2.1x) | 116.09 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.41 (7.1x)** | 31.69 (6.8x) | 32.12 (6.7x) | 31.55 (6.8x) | 40.21 (5.3x) | 43.67 (4.9x) | 44.73 (4.8x) | 48.28 (4.4x) | 66.17 (3.2x) | 214.63 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **49.86 (28.8x)** | 66.72 (21.5x) | 67.78 (21.2x) | 53.55 (26.8x) | 95.16 (15.1x) | 135.32 (10.6x) | 170.47 (8.4x) | 126.41 (11.4x) | 200.69 (7.2x) | 1437.24 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.19 (2.6x) | **48.18 (2.6x)** | 48.23 (2.6x) | 48.98 (2.5x) | 57.37 (2.2x) | 57.49 (2.1x) | 55.37 (2.2x) | 62.84 (2.0x) | 73.81 (1.7x) | 123.36 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **48.94 (3.0x)** | 49.03 (3.0x) | 49.24 (3.0x) | 50.38 (2.9x) | 58.90 (2.5x) | 59.59 (2.5x) | 57.97 (2.6x) | 63.55 (2.3x) | 77.66 (1.9x) | 148.53 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **50.34 (4.9x)** | 51.65 (4.8x) | 52.16 (4.7x) | 51.48 (4.8x) | 63.28 (3.9x) | 66.52 (3.7x) | 65.28 (3.8x) | 69.04 (3.6x) | 88.86 (2.8x) | 247.41 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **69.79 (21.1x)** | 86.52 (17.0x) | 87.75 (16.8x) | 73.51 (20.0x) | 118.43 (12.4x) | 157.57 (9.3x) | 190.63 (7.7x) | 147.68 (10.0x) | 222.91 (6.6x) | 1473.30 (1.0x) |
| ES256 | P-256 | small | 304 | 39.56 (2.2x) | **39.54 (2.2x)** | 39.63 (2.2x) | 40.26 (2.2x) | 41.22 (2.1x) | 41.36 (2.1x) | 43.83 (2.0x) | 52.20 (1.7x) | 70.26 (1.2x) | 86.88 (1.0x) |
| ES256 | P-256 | typical | 704 | 40.65 (2.7x) | **40.53 (2.7x)** | 41.17 (2.7x) | 41.93 (2.7x) | 42.99 (2.6x) | 43.42 (2.6x) | 47.09 (2.4x) | 55.17 (2.0x) | 74.17 (1.5x) | 111.44 (1.0x) |
| ES256 | P-256 | medium | 2317 | **41.76 (5.0x)** | 43.05 (4.9x) | 43.82 (4.8x) | 42.84 (4.9x) | 47.15 (4.4x) | 50.49 (4.1x) | 53.45 (3.9x) | 59.38 (3.5x) | 85.19 (2.5x) | 208.86 (1.0x) |
| ES256 | P-256 | large | 20957 | **61.30 (23.3x)** | 78.56 (18.2x) | 79.39 (18.0x) | 64.92 (22.0x) | 102.95 (13.9x) | 142.70 (10.0x) | 180.71 (7.9x) | 138.93 (10.3x) | 219.84 (6.5x) | 1430.65 (1.0x) |
| ES384 | P-384 | small | 346 | **178.89 (1.6x)** | 179.24 (1.6x) | 179.87 (1.6x) | 179.59 (1.6x) | 181.13 (1.6x) | 181.56 (1.6x) | 343.98 (0.8x) | 357.95 (0.8x) | 267.04 (1.1x) | 285.51 (1.0x) |
| ES384 | P-384 | typical | 746 | **180.45 (1.7x)** | 180.59 (1.7x) | 182.20 (1.7x) | 181.96 (1.7x) | 183.58 (1.7x) | 184.28 (1.7x) | 346.87 (0.9x) | 361.81 (0.9x) | 271.25 (1.1x) | 310.54 (1.0x) |
| ES384 | P-384 | medium | 2359 | **180.81 (2.3x)** | 183.29 (2.2x) | 183.55 (2.2x) | 182.01 (2.2x) | 186.88 (2.2x) | 190.54 (2.1x) | 354.70 (1.2x) | 369.74 (1.1x) | 282.83 (1.4x) | 408.19 (1.0x) |
| ES384 | P-384 | large | 20999 | **206.78 (7.9x)** | 224.28 (7.3x) | 225.91 (7.2x) | 210.67 (7.8x) | 247.24 (6.6x) | 289.11 (5.7x) | 484.23 (3.4x) | 454.16 (3.6x) | 423.60 (3.9x) | 1634.14 (1.0x) |
| ES512 | P-521 | small | 394 | **287.22 (1.4x)** | 288.33 (1.4x) | 288.46 (1.4x) | 287.88 (1.4x) | n/a | n/a | 907.40 (0.4x) | 933.79 (0.4x) | 377.84 (1.1x) | 399.14 (1.0x) |
| ES512 | P-521 | typical | 794 | **285.17 (1.5x)** | 286.43 (1.5x) | 286.62 (1.5x) | 286.61 (1.5x) | n/a | n/a | 896.54 (0.5x) | 920.77 (0.5x) | 381.80 (1.1x) | 424.06 (1.0x) |
| ES512 | P-521 | medium | 2407 | **287.98 (1.8x)** | 289.63 (1.8x) | 290.99 (1.8x) | 289.35 (1.8x) | n/a | n/a | 894.80 (0.6x) | 919.09 (0.6x) | 393.79 (1.3x) | 522.40 (1.0x) |
| ES512 | P-521 | large | 21047 | **312.70 (5.6x)** | 331.23 (5.3x) | 331.83 (5.3x) | 316.80 (5.5x) | n/a | n/a | 1041.72 (1.7x) | 1028.45 (1.7x) | 533.37 (3.3x) | 1751.65 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.60 (2.9x) | **32.50 (2.9x)** | 32.56 (2.9x) | 33.27 (2.9x) | 33.53 (2.8x) | 33.69 (2.8x) | 42.38 (2.2x) | 51.34 (1.8x) | 79.53 (1.2x) | 94.90 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.38 (3.6x)** | 33.59 (3.5x) | 34.01 (3.5x) | 34.86 (3.4x) | 35.23 (3.4x) | 35.68 (3.3x) | 45.16 (2.6x) | 52.20 (2.3x) | 82.89 (1.4x) | 119.20 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.43 (6.1x)** | 36.63 (5.9x) | 37.40 (5.8x) | 36.45 (6.0x) | 40.12 (5.4x) | 43.48 (5.0x) | 52.67 (4.1x) | 58.66 (3.7x) | 94.91 (2.3x) | 217.73 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **60.85 (23.7x)** | 76.97 (18.8x) | 78.52 (18.4x) | 64.01 (22.5x) | 100.82 (14.3x) | 141.03 (10.2x) | 183.98 (7.8x) | 142.78 (10.1x) | 235.97 (6.1x) | 1443.45 (1.0x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 14.10 (4.9x) | **14.07 (5.0x)** | 14.16 (4.9x) | 14.78 (4.7x) | n/a | n/a | n/a | n/a | n/a | 69.79 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **14.84 (6.5x)** | 14.94 (6.4x) | 15.19 (6.3x) | 16.30 (5.9x) | n/a | n/a | n/a | n/a | n/a | 96.10 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **16.33 (12.1x)** | 17.58 (11.3x) | 18.09 (11.0x) | 17.35 (11.4x) | n/a | n/a | n/a | n/a | n/a | 198.23 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **36.50 (40.1x)** | 52.12 (28.1x) | 54.37 (27.0x) | 39.72 (36.9x) | n/a | n/a | n/a | n/a | n/a | 1465.29 (1.0x) |
| RS256 | RSA 3072 | small | 731 | **28.68 (3.3x)** | 28.70 (3.3x) | 28.76 (3.3x) | 29.44 (3.2x) | n/a | n/a | n/a | n/a | n/a | 95.20 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.44 (4.1x)** | 29.55 (4.1x) | 29.80 (4.1x) | 30.90 (3.9x) | n/a | n/a | n/a | n/a | n/a | 121.19 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.95 (7.2x)** | 32.13 (7.0x) | 32.68 (6.9x) | 31.97 (7.0x) | n/a | n/a | n/a | n/a | n/a | 223.91 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **51.09 (29.2x)** | 67.13 (22.3x) | 68.64 (21.8x) | 54.37 (27.5x) | n/a | n/a | n/a | n/a | n/a | 1493.61 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.79 (2.6x) | **48.75 (2.6x)** | 49.06 (2.6x) | 49.54 (2.6x) | n/a | n/a | n/a | n/a | n/a | 126.97 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **49.53 (3.1x)** | 49.68 (3.1x) | 49.88 (3.1x) | 51.03 (3.0x) | n/a | n/a | n/a | n/a | n/a | 153.17 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **51.02 (5.0x)** | 52.28 (4.9x) | 52.79 (4.9x) | 52.11 (4.9x) | n/a | n/a | n/a | n/a | n/a | 256.24 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **71.19 (21.5x)** | 86.85 (17.6x) | 88.63 (17.3x) | 74.43 (20.6x) | n/a | n/a | n/a | n/a | n/a | 1530.72 (1.0x) |
| ES256 | P-256 | small | 304 | 39.83 (2.3x) | **39.83 (2.3x)** | 39.90 (2.3x) | 40.53 (2.2x) | n/a | n/a | n/a | n/a | n/a | 90.40 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.77 (2.9x)** | 40.96 (2.8x) | 41.13 (2.8x) | 42.26 (2.8x) | n/a | n/a | n/a | n/a | n/a | 116.45 (1.0x) |
| ES256 | P-256 | medium | 2317 | **42.08 (5.2x)** | 43.32 (5.0x) | 43.89 (5.0x) | 43.16 (5.0x) | n/a | n/a | n/a | n/a | n/a | 217.91 (1.0x) |
| ES256 | P-256 | large | 20957 | **62.36 (23.8x)** | 78.27 (19.0x) | 79.99 (18.5x) | 65.55 (22.6x) | n/a | n/a | n/a | n/a | n/a | 1483.87 (1.0x) |
| ES384 | P-384 | small | 346 | **179.21 (1.6x)** | 179.98 (1.6x) | 180.45 (1.6x) | 179.92 (1.6x) | n/a | n/a | n/a | n/a | n/a | 289.19 (1.0x) |
| ES384 | P-384 | typical | 746 | **180.73 (1.7x)** | 181.76 (1.7x) | 182.13 (1.7x) | 182.24 (1.7x) | n/a | n/a | n/a | n/a | n/a | 315.38 (1.0x) |
| ES384 | P-384 | medium | 2359 | **181.26 (2.3x)** | 183.47 (2.3x) | 183.33 (2.3x) | 182.31 (2.3x) | n/a | n/a | n/a | n/a | n/a | 417.08 (1.0x) |
| ES384 | P-384 | large | 20999 | **207.83 (8.1x)** | 225.21 (7.5x) | 226.53 (7.5x) | 211.39 (8.0x) | n/a | n/a | n/a | n/a | n/a | 1690.72 (1.0x) |
| ES512 | P-521 | small | 394 | **287.32 (1.4x)** | 287.67 (1.4x) | 288.34 (1.4x) | 288.17 (1.4x) | n/a | n/a | n/a | n/a | n/a | 403.00 (1.0x) |
| ES512 | P-521 | typical | 794 | **285.34 (1.5x)** | 286.00 (1.5x) | 286.35 (1.5x) | 286.90 (1.5x) | n/a | n/a | n/a | n/a | n/a | 429.43 (1.0x) |
| ES512 | P-521 | medium | 2407 | **288.24 (1.8x)** | 290.60 (1.8x) | 291.45 (1.8x) | 289.47 (1.8x) | n/a | n/a | n/a | n/a | n/a | 532.08 (1.0x) |
| ES512 | P-521 | large | 21047 | **313.80 (5.8x)** | 330.80 (5.5x) | 332.85 (5.4x) | 317.27 (5.7x) | n/a | n/a | n/a | n/a | n/a | 1812.59 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.86 (3.0x) | **32.83 (3.0x)** | 32.96 (3.0x) | 33.57 (2.9x) | n/a | n/a | n/a | n/a | n/a | 98.67 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.67 (3.7x)** | 33.78 (3.7x) | 34.14 (3.6x) | 35.17 (3.5x) | n/a | n/a | n/a | n/a | n/a | 124.36 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.72 (6.3x)** | 37.09 (6.1x) | 37.41 (6.1x) | 36.77 (6.2x) | n/a | n/a | n/a | n/a | n/a | 226.46 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **61.56 (24.3x)** | 77.23 (19.4x) | 79.09 (18.9x) | 64.62 (23.2x) | n/a | n/a | n/a | n/a | n/a | 1498.49 (1.0x) |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 14.18 (4.9x) | **14.14 (4.9x)** | 14.21 (4.9x) | 14.85 (4.7x) | n/a | n/a | 50.26 (1.4x) | 26.84 (2.6x) | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | **14.87 (6.5x)** | 15.01 (6.4x) | 15.28 (6.3x) | 16.35 (5.9x) | n/a | n/a | 45.82 (2.1x) | 28.85 (3.3x) | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | **16.31 (12.2x)** | 17.72 (11.2x) | 18.16 (10.9x) | 17.54 (11.3x) | n/a | n/a | 47.94 (4.1x) | 33.92 (5.8x) | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | **35.88 (40.8x)** | 53.63 (27.3x) | 53.99 (27.1x) | 39.67 (36.9x) | n/a | n/a | 120.87 (12.1x) | 112.28 (13.1x) | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | 28.81 (3.3x) | **28.77 (3.3x)** | 28.84 (3.3x) | 29.53 (3.2x) | n/a | n/a | 70.55 (1.3x) | 43.12 (2.2x) | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | **29.51 (4.1x)** | 30.00 (4.0x) | 29.91 (4.1x) | 30.97 (3.9x) | n/a | n/a | 70.33 (1.7x) | 43.14 (2.8x) | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | **30.94 (7.2x)** | 32.29 (6.9x) | 32.76 (6.8x) | 32.05 (7.0x) | n/a | n/a | 75.10 (3.0x) | 48.47 (4.6x) | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | **50.51 (29.6x)** | 67.96 (22.0x) | 68.37 (21.8x) | 54.36 (27.5x) | n/a | n/a | 150.07 (10.0x) | 126.52 (11.8x) | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | **48.84 (2.6x)** | 48.86 (2.6x) | 48.93 (2.6x) | 49.73 (2.6x) | n/a | n/a | 106.18 (1.2x) | 62.16 (2.0x) | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | **49.58 (3.1x)** | 49.69 (3.1x) | 50.40 (3.0x) | 51.16 (3.0x) | n/a | n/a | 109.80 (1.4x) | 63.15 (2.4x) | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | **51.01 (5.0x)** | 52.52 (4.9x) | 52.89 (4.8x) | 52.17 (4.9x) | n/a | n/a | 113.06 (2.3x) | 69.58 (3.7x) | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | **70.48 (21.7x)** | 87.83 (17.4x) | 89.08 (17.2x) | 74.48 (20.6x) | n/a | n/a | 185.70 (8.2x) | 153.23 (10.0x) | n/a | n/a |
| ES256 | P-256 | small | 304 | 39.93 (2.3x) | **39.88 (2.3x)** | 40.24 (2.2x) | 40.62 (2.2x) | n/a | n/a | 2470.97 (0.04x) | 52.12 (1.7x) | n/a | n/a |
| ES256 | P-256 | typical | 704 | **40.81 (2.9x)** | 40.97 (2.8x) | 41.24 (2.8x) | 42.29 (2.8x) | n/a | n/a | 2454.41 (0.05x) | 55.43 (2.1x) | n/a | n/a |
| ES256 | P-256 | medium | 2317 | **42.10 (5.2x)** | 43.53 (5.0x) | 44.04 (4.9x) | 43.21 (5.0x) | n/a | n/a | 2454.80 (0.09x) | 59.63 (3.7x) | n/a | n/a |
| ES256 | P-256 | large | 20957 | **61.73 (24.0x)** | 78.98 (18.8x) | 80.03 (18.5x) | 65.55 (22.6x) | n/a | n/a | 2541.56 (0.6x) | 138.79 (10.7x) | n/a | n/a |
| ES384 | P-384 | small | 346 | **179.56 (1.6x)** | 180.41 (1.6x) | 180.46 (1.6x) | 180.20 (1.6x) | n/a | n/a | 11640.43 (0.02x) | 358.42 (0.8x) | n/a | n/a |
| ES384 | P-384 | typical | 746 | **180.95 (1.7x)** | 181.76 (1.7x) | 182.10 (1.7x) | 182.50 (1.7x) | n/a | n/a | 11661.63 (0.03x) | 361.41 (0.9x) | n/a | n/a |
| ES384 | P-384 | medium | 2359 | **181.53 (2.3x)** | 183.47 (2.3x) | 183.31 (2.3x) | 182.59 (2.3x) | n/a | n/a | 11642.05 (0.04x) | 371.09 (1.1x) | n/a | n/a |
| ES384 | P-384 | large | 20999 | **207.45 (8.1x)** | 225.88 (7.5x) | 226.48 (7.5x) | 211.68 (8.0x) | n/a | n/a | 11717.25 (0.1x) | 453.88 (3.7x) | n/a | n/a |
| ES512 | P-521 | small | 394 | **287.12 (1.4x)** | 288.67 (1.4x) | 288.67 (1.4x) | 288.06 (1.4x) | n/a | n/a | 27900.04 (0.01x) | 933.19 (0.4x) | n/a | n/a |
| ES512 | P-521 | typical | 794 | **284.98 (1.5x)** | 285.83 (1.5x) | 287.39 (1.5x) | 286.62 (1.5x) | n/a | n/a | 27894.26 (0.02x) | 920.92 (0.5x) | n/a | n/a |
| ES512 | P-521 | medium | 2407 | **288.03 (1.8x)** | 291.42 (1.8x) | 292.04 (1.8x) | 289.19 (1.8x) | n/a | n/a | 27866.15 (0.02x) | 919.81 (0.6x) | n/a | n/a |
| ES512 | P-521 | large | 21047 | **312.86 (5.8x)** | 331.27 (5.5x) | 332.49 (5.5x) | 316.91 (5.7x) | n/a | n/a | 27878.67 (0.07x) | 1031.33 (1.8x) | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | 32.95 (3.0x) | **32.95 (3.0x)** | 32.97 (3.0x) | 33.66 (2.9x) | n/a | n/a | n/a | 50.90 (1.9x) | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | **33.73 (3.7x)** | 33.86 (3.7x) | 34.52 (3.6x) | 35.25 (3.5x) | n/a | n/a | n/a | 51.95 (2.4x) | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | **35.77 (6.3x)** | 37.16 (6.1x) | 37.51 (6.0x) | 36.86 (6.1x) | n/a | n/a | n/a | 58.62 (3.9x) | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | **60.98 (24.6x)** | 77.96 (19.2x) | 79.36 (18.9x) | 64.63 (23.2x) | n/a | n/a | n/a | 142.96 (10.5x) | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 1.9 | 1.6 | 1.5 | 1.7 | n/a | n/a | n/a | n/a | n/a | 1.5 |
| JWKS URL, async client | 1.9 | 1.7 | 1.7 | 1.6 | n/a | n/a | 0.8 | 0.9 | n/a | n/a |

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
- joserfc 1.7.7, JWKS URL, sync client: joserfc has no JWKS URL client.
- joserfc 1.7.7, JWKS URL, async client: joserfc has no JWKS URL client.
- pyjwt 2.15.1, JWKS URL, async client: PyJWT has no async JWKS client.

## Notes

- ryjwt 0.3.1 → Struct: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.3.1 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.3.1 → dict (msgspec): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.3.1 → dict (msgspec): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.3.1 → dict (jiter): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.3.1 → dict (jiter): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.3.1 → BaseModel: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.3.1 → BaseModel: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: claims decoded into typed structs with the fields ryjwt's msgspec lane decodes; other claims ignored.
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value: JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- fast-jwt 6.3.3: JWKS document: a verifier per key, made once, picked by the token's `kid` (read with `createDecoder`).
- fast-jwt 6.3.3: JWKS URL rows are fast-jwt + get-jwks 11.0.3 (fast-jwt's documented integration), so they time both: on every verify get-jwks converts the cached JWK to a PEM (with jwk-to-pem) and fast-jwt imports that PEM (`createPublicKey`), which is why they're slow.
- jose 6.2.12: HMAC secret imported once (`crypto.subtle.importKey`); `importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`.
- joserfc 1.7.7: `jwt.decode(token, key, algorithms=[...])`, then `JWTClaimsRegistry(exp=..., aud=...).validate(token.claims)`, both essential.
- joserfc 1.7.7: keys imported once (`OctKey`, `RSAKey`, `ECKey`, `OKPKey`); JWKS document: a `KeySet`, which picks the key by `kid`.
- joserfc 1.7.7: EdDSA: joserfc warns on every decode (`SecurityWarning`: RFC 9864 deprecates `EdDSA`), as it does by default.
- pyjwt 2.15.1: PEM: the key loaded once, with `load_pem_public_key`.
- pyjwt 2.15.1: JWKS document: `PyJWKSet`, picking the key by `get_unverified_header`'s `kid`.
- pyjwt 2.15.1: JWKS URL: `PyJWKClient(cache_keys=True)`, its `ssl_context` trusting the test CA.
