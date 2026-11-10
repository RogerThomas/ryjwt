# JWT decode benchmarks: the full matrix

Generated 2026-11-10 from `bench/results-matrix/` by `bench/compare.py`, on
AWS m9g.2xlarge, Graviton5 (aarch64), Linux.
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

| key source | alg | key | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | **1.42 (27.1x)** | 1.47 (26.3x) | 1.69 (22.9x) | 2.76 (14.0x) | 3.17 (12.2x) | 3.75 (10.3x) | 4.56 (8.5x) | 11.73 (3.3x) | 19.39 (2.0x) | 38.64 (1.0x) |
| PEM public key | RS256 | RSA 3072 | **29.16 (2.7x)** | 29.18 (2.7x) | 29.36 (2.7x) | 30.43 (2.6x) | 35.34 (2.2x) | 35.86 (2.2x) | 34.39 (2.3x) | 41.50 (1.9x) | 52.96 (1.5x) | 78.97 (1.0x) |
| PEM public key | ES384 | P-384 | 181.39 (1.6x) | 181.83 (1.6x) | **181.12 (1.6x)** | 182.48 (1.6x) | 183.23 (1.6x) | 183.74 (1.5x) | 344.22 (0.8x) | 364.88 (0.8x) | 269.04 (1.1x) | 284.66 (1.0x) |
| PEM public key | EdDSA | Ed25519 | **33.41 (2.8x)** | 33.47 (2.8x) | 33.73 (2.8x) | 34.79 (2.7x) | 34.84 (2.7x) | 35.31 (2.7x) | 41.79 (2.3x) | 51.19 (1.8x) | 80.91 (1.2x) | 94.39 (1.0x) |
| JWKS document | RS256 | RSA 3072 | **29.14 (4.0x)** | 29.16 (4.0x) | 29.40 (4.0x) | 30.46 (3.8x) | 35.76 (3.3x) | 36.28 (3.2x) | 36.96 (3.2x) | 42.02 (2.8x) | 55.36 (2.1x) | 116.74 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | **29.22 (4.2x)** | 29.39 (4.1x) | 29.78 (4.1x) | 30.87 (3.9x) | n/a | n/a | n/a | n/a | n/a | 121.42 (1.0x) |
| JWKS URL, async client | RS256 | RSA 3072 | **29.35 (4.1x)** | 29.46 (4.1x) | 29.88 (4.1x) | 31.02 (3.9x) | n/a | n/a | 68.81 (1.8x) | 42.28 (2.9x) | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | 0.71 (33.5x) | **0.68 (35.3x)** | 0.77 (30.9x) | 1.32 (18.1x) | 1.55 (15.5x) | 1.77 (13.6x) | 7.32 (3.3x) | 16.69 (1.4x) | 14.89 (1.6x) | 23.96 (1.0x) |
| HS256 | 32 B | typical | 661 | **1.43 (27.0x)** | 1.47 (26.1x) | 1.75 (22.0x) | 2.77 (13.9x) | 3.14 (12.3x) | 3.76 (10.3x) | 7.54 (5.1x) | 17.07 (2.3x) | 19.43 (2.0x) | 38.53 (1.0x) |
| HS256 | 32 B | medium | 2244 | **2.80 (31.6x)** | 4.22 (21.0x) | 4.60 (19.2x) | 3.80 (23.3x) | 6.76 (13.1x) | 10.13 (8.7x) | 9.05 (9.8x) | 18.65 (4.7x) | 30.03 (2.9x) | 88.53 (1.0x) |
| HS256 | 32 B | large | 20884 | **22.37 (32.6x)** | 39.09 (18.6x) | 39.58 (18.4x) | 25.74 (28.3x) | 55.22 (13.2x) | 94.26 (7.7x) | 80.17 (9.1x) | 98.82 (7.4x) | 162.89 (4.5x) | 728.47 (1.0x) |
| HS256 | 64 B | small | 231 | 0.70 (35.3x) | **0.67 (36.9x)** | 0.77 (32.3x) | 1.32 (18.7x) | 1.53 (16.2x) | 1.75 (14.1x) | 3.29 (7.5x) | 11.19 (2.2x) | 14.89 (1.7x) | 24.77 (1.0x) |
| HS256 | 64 B | typical | 661 | **1.42 (27.1x)** | 1.47 (26.3x) | 1.69 (22.9x) | 2.76 (14.0x) | 3.17 (12.2x) | 3.75 (10.3x) | 4.56 (8.5x) | 11.73 (3.3x) | 19.39 (2.0x) | 38.64 (1.0x) |
| HS256 | 64 B | medium | 2244 | **2.83 (31.4x)** | 4.25 (20.9x) | 4.61 (19.3x) | 3.80 (23.4x) | 6.84 (13.0x) | 10.19 (8.7x) | 8.97 (9.9x) | 17.15 (5.2x) | 30.03 (3.0x) | 88.98 (1.0x) |
| HS256 | 64 B | large | 20884 | **22.37 (32.6x)** | 39.33 (18.6x) | 39.58 (18.4x) | 25.76 (28.3x) | 54.91 (13.3x) | 93.96 (7.8x) | 75.59 (9.7x) | 92.40 (7.9x) | 164.18 (4.4x) | 730.02 (1.0x) |
| HS256 | 256 B | small | 231 | 0.71 (36.8x) | **0.66 (39.4x)** | 0.75 (34.6x) | 1.31 (19.8x) | 1.79 (14.5x) | 1.91 (13.6x) | 3.08 (8.5x) | 11.72 (2.2x) | 15.14 (1.7x) | 26.04 (1.0x) |
| HS256 | 256 B | typical | 661 | **1.41 (28.8x)** | 1.48 (27.4x) | 1.73 (23.4x) | 2.76 (14.7x) | 3.33 (12.2x) | 3.91 (10.4x) | 5.01 (8.1x) | 12.42 (3.3x) | 19.31 (2.1x) | 40.61 (1.0x) |
| HS256 | 256 B | medium | 2244 | **2.82 (32.4x)** | 4.24 (21.5x) | 4.61 (19.8x) | 3.84 (23.7x) | 7.01 (13.0x) | 10.31 (8.8x) | 8.43 (10.8x) | 18.13 (5.0x) | 30.27 (3.0x) | 91.14 (1.0x) |
| HS256 | 256 B | large | 20884 | **22.08 (33.1x)** | 39.66 (18.4x) | 39.57 (18.5x) | 25.79 (28.3x) | 55.10 (13.3x) | 94.10 (7.8x) | 75.17 (9.7x) | 93.24 (7.8x) | 162.99 (4.5x) | 730.76 (1.0x) |
| HS256 | 4096 B | small | 231 | 0.71 (78.7x) | **0.67 (83.0x)** | 0.76 (72.9x) | 1.32 (42.0x) | 3.59 (15.5x) | 3.75 (14.8x) | 5.00 (11.1x) | 13.44 (4.1x) | 16.95 (3.3x) | 55.57 (1.0x) |
| HS256 | 4096 B | typical | 661 | **1.40 (49.8x)** | 1.49 (47.0x) | 1.76 (39.8x) | 2.76 (25.4x) | 5.16 (13.6x) | 5.74 (12.2x) | 6.48 (10.8x) | 14.92 (4.7x) | 21.16 (3.3x) | 69.97 (1.0x) |
| HS256 | 4096 B | medium | 2244 | **2.83 (42.4x)** | 4.28 (28.1x) | 4.59 (26.2x) | 3.79 (31.7x) | 8.81 (13.6x) | 12.16 (9.9x) | 10.75 (11.2x) | 19.83 (6.1x) | 32.16 (3.7x) | 120.11 (1.0x) |
| HS256 | 4096 B | large | 20884 | **22.11 (34.4x)** | 39.29 (19.4x) | 39.59 (19.2x) | 25.81 (29.5x) | 56.84 (13.4x) | 96.15 (7.9x) | 76.76 (9.9x) | 95.10 (8.0x) | 165.58 (4.6x) | 761.47 (1.0x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 13.84 (3.2x) | **13.78 (3.2x)** | 13.90 (3.2x) | 14.49 (3.1x) | 17.48 (2.6x) | 17.56 (2.5x) | 18.18 (2.5x) | 25.45 (1.8x) | 32.56 (1.4x) | 44.63 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 14.88 (3.9x) | **14.62 (4.0x)** | 14.92 (3.9x) | 15.96 (3.6x) | 18.86 (3.1x) | 19.36 (3.0x) | 20.29 (2.9x) | 27.20 (2.1x) | 36.35 (1.6x) | 58.03 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **16.03 (6.9x)** | 17.36 (6.3x) | 17.76 (6.2x) | 17.06 (6.4x) | 22.73 (4.8x) | 26.10 (4.2x) | 23.63 (4.7x) | 37.09 (3.0x) | 47.64 (2.3x) | 110.03 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **36.05 (21.0x)** | 52.25 (14.5x) | 52.99 (14.3x) | 39.10 (19.4x) | 70.24 (10.8x) | 109.68 (6.9x) | 93.65 (8.1x) | 107.54 (7.1x) | 181.77 (4.2x) | 758.57 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.43 (2.3x) | 28.39 (2.3x) | **28.34 (2.3x)** | 28.99 (2.3x) | 33.94 (1.9x) | 34.11 (1.9x) | 32.73 (2.0x) | 40.47 (1.6x) | 49.09 (1.3x) | 65.61 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.16 (2.7x)** | 29.18 (2.7x) | 29.36 (2.7x) | 30.43 (2.6x) | 35.34 (2.2x) | 35.86 (2.2x) | 34.39 (2.3x) | 41.50 (1.9x) | 52.96 (1.5x) | 78.97 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.69 (4.3x)** | 31.87 (4.1x) | 32.16 (4.1x) | 31.56 (4.1x) | 39.21 (3.3x) | 42.61 (3.1x) | 37.65 (3.5x) | 46.51 (2.8x) | 64.15 (2.0x) | 130.84 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **50.62 (15.3x)** | 66.30 (11.7x) | 67.41 (11.5x) | 53.53 (14.5x) | 86.85 (8.9x) | 126.85 (6.1x) | 105.78 (7.3x) | 121.83 (6.4x) | 198.92 (3.9x) | 774.40 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.53 (1.9x) | 48.45 (1.9x) | **48.34 (1.9x)** | 48.98 (1.9x) | 56.98 (1.6x) | 57.15 (1.6x) | 53.05 (1.7x) | 60.43 (1.5x) | 71.61 (1.3x) | 92.79 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **49.22 (2.2x)** | 49.32 (2.2x) | 49.35 (2.2x) | 50.40 (2.1x) | 58.42 (1.8x) | 59.02 (1.8x) | 55.05 (1.9x) | 62.23 (1.7x) | 75.58 (1.4x) | 106.33 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **50.98 (3.1x)** | 51.98 (3.1x) | 52.23 (3.0x) | 51.57 (3.1x) | 62.22 (2.6x) | 65.60 (2.4x) | 58.49 (2.7x) | 67.79 (2.3x) | 86.63 (1.8x) | 158.81 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **71.10 (11.3x)** | 86.70 (9.3x) | 87.44 (9.2x) | 73.39 (10.9x) | 110.17 (7.3x) | 149.40 (5.4x) | 125.81 (6.4x) | 143.38 (5.6x) | 221.33 (3.6x) | 803.43 (1.0x) |
| ES256 | P-256 | small | 304 | 39.87 (1.8x) | **39.54 (1.8x)** | 39.59 (1.8x) | 40.25 (1.8x) | 40.95 (1.8x) | 41.19 (1.8x) | 43.75 (1.7x) | 50.98 (1.4x) | 68.07 (1.1x) | 73.07 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.73 (2.1x)** | 40.84 (2.1x) | 40.82 (2.1x) | 41.91 (2.1x) | 42.55 (2.0x) | 43.03 (2.0x) | 43.95 (2.0x) | 53.08 (1.6x) | 71.96 (1.2x) | 86.45 (1.0x) |
| ES256 | P-256 | medium | 2317 | **41.78 (3.3x)** | 43.13 (3.2x) | 43.56 (3.2x) | 42.83 (3.2x) | 46.18 (3.0x) | 49.57 (2.8x) | 47.72 (2.9x) | 58.20 (2.4x) | 83.16 (1.7x) | 137.76 (1.0x) |
| ES256 | P-256 | large | 20957 | **62.10 (12.6x)** | 77.93 (10.0x) | 79.27 (9.8x) | 65.22 (12.0x) | 93.95 (8.3x) | 134.22 (5.8x) | 116.04 (6.7x) | 134.01 (5.8x) | 217.09 (3.6x) | 779.91 (1.0x) |
| ES384 | P-384 | small | 346 | 179.52 (1.5x) | 179.45 (1.5x) | **179.20 (1.5x)** | 179.91 (1.5x) | 180.96 (1.5x) | 181.18 (1.5x) | 342.16 (0.8x) | 356.85 (0.8x) | 264.95 (1.0x) | 270.91 (1.0x) |
| ES384 | P-384 | typical | 746 | 181.39 (1.6x) | 181.83 (1.6x) | **181.12 (1.6x)** | 182.48 (1.6x) | 183.23 (1.6x) | 183.74 (1.5x) | 344.22 (0.8x) | 364.88 (0.8x) | 269.04 (1.1x) | 284.66 (1.0x) |
| ES384 | P-384 | medium | 2359 | **182.03 (1.9x)** | 183.35 (1.8x) | 183.27 (1.8x) | 182.56 (1.8x) | 186.07 (1.8x) | 189.25 (1.8x) | 348.78 (1.0x) | 365.46 (0.9x) | 281.45 (1.2x) | 337.27 (1.0x) |
| ES384 | P-384 | large | 20999 | **208.42 (4.7x)** | 224.42 (4.4x) | 225.62 (4.4x) | 210.88 (4.7x) | 240.45 (4.1x) | 280.75 (3.5x) | 419.86 (2.3x) | 446.33 (2.2x) | 419.54 (2.3x) | 985.44 (1.0x) |
| ES512 | P-521 | small | 394 | 288.46 (1.3x) | 288.02 (1.3x) | **287.82 (1.3x)** | 288.16 (1.3x) | n/a | n/a | 905.28 (0.4x) | 930.02 (0.4x) | 376.14 (1.0x) | 383.37 (1.0x) |
| ES512 | P-521 | typical | 794 | 286.60 (1.4x) | 286.05 (1.4x) | **285.76 (1.4x)** | 286.79 (1.4x) | n/a | n/a | 892.69 (0.4x) | 917.30 (0.4x) | 380.14 (1.0x) | 397.51 (1.0x) |
| ES512 | P-521 | medium | 2407 | **289.04 (1.6x)** | 290.14 (1.5x) | 291.11 (1.5x) | 289.71 (1.5x) | n/a | n/a | 888.93 (0.5x) | 915.81 (0.5x) | 392.56 (1.1x) | 448.86 (1.0x) |
| ES512 | P-521 | large | 21047 | **315.03 (3.5x)** | 331.40 (3.3x) | 331.99 (3.3x) | 316.77 (3.5x) | n/a | n/a | 974.87 (1.1x) | 1016.67 (1.1x) | 533.48 (2.1x) | 1098.97 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.62 (2.5x) | 32.80 (2.5x) | **32.60 (2.5x)** | 33.23 (2.5x) | 33.35 (2.4x) | 33.46 (2.4x) | 40.99 (2.0x) | 49.95 (1.6x) | 77.45 (1.1x) | 81.51 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.41 (2.8x)** | 33.47 (2.8x) | 33.73 (2.8x) | 34.79 (2.7x) | 34.84 (2.7x) | 35.31 (2.7x) | 41.79 (2.3x) | 51.19 (1.8x) | 80.91 (1.2x) | 94.39 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.47 (4.1x)** | 36.66 (4.0x) | 37.09 (4.0x) | 36.41 (4.0x) | 39.31 (3.7x) | 42.63 (3.4x) | 46.91 (3.1x) | 57.50 (2.6x) | 92.85 (1.6x) | 146.84 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **61.55 (12.9x)** | 77.06 (10.3x) | 77.93 (10.2x) | 64.27 (12.3x) | 92.45 (8.6x) | 133.21 (6.0x) | 119.57 (6.6x) | 139.05 (5.7x) | 233.09 (3.4x) | 793.67 (1.0x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **13.86 (4.8x)** | 14.10 (4.7x) | 13.90 (4.7x) | 14.51 (4.5x) | 17.80 (3.7x) | 17.90 (3.7x) | 20.17 (3.3x) | 29.00 (2.3x) | 34.98 (1.9x) | 65.84 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 15.36 (5.9x) | **14.63 (6.2x)** | 14.96 (6.0x) | 15.98 (5.7x) | 19.34 (4.7x) | 19.79 (4.6x) | 22.10 (4.1x) | 28.89 (3.1x) | 38.90 (2.3x) | 90.50 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **16.06 (11.8x)** | 17.31 (11.0x) | 17.79 (10.7x) | 17.05 (11.1x) | 23.60 (8.1x) | 27.32 (7.0x) | 28.49 (6.7x) | 33.73 (5.6x) | 50.09 (3.8x) | 189.97 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **36.04 (39.3x)** | 51.99 (27.2x) | 52.95 (26.8x) | 39.46 (35.9x) | 76.31 (18.6x) | 118.34 (12.0x) | 153.34 (9.2x) | 108.24 (13.1x) | 184.91 (7.7x) | 1416.56 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.43 (3.2x) | 28.36 (3.2x) | **28.32 (3.2x)** | 28.99 (3.2x) | 34.19 (2.7x) | 34.38 (2.7x) | 34.55 (2.6x) | 40.36 (2.3x) | 51.30 (1.8x) | 91.51 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.14 (4.0x)** | 29.16 (4.0x) | 29.40 (4.0x) | 30.46 (3.8x) | 35.76 (3.3x) | 36.28 (3.2x) | 36.96 (3.2x) | 42.02 (2.8x) | 55.36 (2.1x) | 116.74 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.61 (7.0x)** | 31.85 (6.7x) | 32.17 (6.7x) | 31.52 (6.8x) | 40.09 (5.4x) | 43.73 (4.9x) | 43.50 (4.9x) | 47.18 (4.6x) | 66.72 (3.2x) | 214.76 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **50.65 (28.4x)** | 67.12 (21.4x) | 67.39 (21.4x) | 53.47 (26.9x) | 92.80 (15.5x) | 134.66 (10.7x) | 166.23 (8.7x) | 122.83 (11.7x) | 201.49 (7.1x) | 1439.51 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.53 (2.5x) | 48.51 (2.5x) | **48.30 (2.6x)** | 48.97 (2.5x) | 57.17 (2.2x) | 57.35 (2.2x) | 55.06 (2.2x) | 61.09 (2.0x) | 73.92 (1.7x) | 123.40 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **49.24 (3.0x)** | 49.31 (3.0x) | 49.34 (3.0x) | 50.43 (2.9x) | 58.71 (2.5x) | 59.43 (2.5x) | 57.77 (2.6x) | 63.77 (2.3x) | 77.95 (1.9x) | 148.18 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **50.74 (4.9x)** | 52.19 (4.8x) | 52.18 (4.8x) | 51.51 (4.8x) | 63.06 (3.9x) | 66.39 (3.7x) | 64.22 (3.9x) | 68.56 (3.6x) | 89.23 (2.8x) | 247.91 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **70.74 (20.9x)** | 86.63 (17.1x) | 87.34 (16.9x) | 73.52 (20.1x) | 115.69 (12.8x) | 156.60 (9.4x) | 188.14 (7.9x) | 144.56 (10.2x) | 224.02 (6.6x) | 1477.58 (1.0x) |
| ES256 | P-256 | small | 304 | 39.88 (2.2x) | 39.86 (2.2x) | **39.61 (2.2x)** | 40.25 (2.2x) | 41.24 (2.1x) | 41.41 (2.1x) | 43.77 (2.0x) | 52.00 (1.7x) | 70.20 (1.2x) | 86.68 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.72 (2.7x)** | 40.82 (2.7x) | 40.83 (2.7x) | 42.20 (2.6x) | 43.03 (2.6x) | 43.50 (2.6x) | 46.86 (2.4x) | 55.05 (2.0x) | 74.02 (1.5x) | 111.50 (1.0x) |
| ES256 | P-256 | medium | 2317 | **41.81 (5.0x)** | 43.07 (4.9x) | 43.53 (4.8x) | 42.80 (4.9x) | 47.18 (4.4x) | 50.59 (4.1x) | 53.22 (3.9x) | 58.90 (3.6x) | 85.21 (2.5x) | 209.17 (1.0x) |
| ES256 | P-256 | large | 20957 | **61.99 (23.1x)** | 78.50 (18.2x) | 79.20 (18.1x) | 65.02 (22.0x) | 100.10 (14.3x) | 141.35 (10.1x) | 177.03 (8.1x) | 134.88 (10.6x) | 220.85 (6.5x) | 1430.44 (1.0x) |
| ES384 | P-384 | small | 346 | 179.98 (1.6x) | 180.35 (1.6x) | **179.20 (1.6x)** | 179.98 (1.6x) | 181.23 (1.6x) | 181.43 (1.6x) | 344.32 (0.8x) | 359.38 (0.8x) | 267.59 (1.1x) | 287.08 (1.0x) |
| ES384 | P-384 | typical | 746 | **180.87 (1.7x)** | 181.39 (1.7x) | 181.34 (1.7x) | 182.25 (1.7x) | 183.72 (1.7x) | 184.20 (1.7x) | 346.64 (0.9x) | 359.59 (0.9x) | 271.01 (1.2x) | 311.98 (1.0x) |
| ES384 | P-384 | medium | 2359 | 182.34 (2.2x) | 182.99 (2.2x) | 183.03 (2.2x) | **182.28 (2.3x)** | 186.87 (2.2x) | 190.43 (2.2x) | 354.24 (1.2x) | 365.82 (1.1x) | 283.02 (1.4x) | 410.24 (1.0x) |
| ES384 | P-384 | large | 20999 | **208.37 (7.9x)** | 225.00 (7.3x) | 225.81 (7.3x) | 210.96 (7.8x) | 246.26 (6.7x) | 288.15 (5.7x) | 480.50 (3.4x) | 449.29 (3.7x) | 422.36 (3.9x) | 1641.04 (1.0x) |
| ES512 | P-521 | small | 394 | 288.66 (1.4x) | 288.67 (1.4x) | **287.81 (1.4x)** | 288.23 (1.4x) | n/a | n/a | 906.97 (0.4x) | 930.97 (0.4x) | 378.94 (1.1x) | 399.32 (1.0x) |
| ES512 | P-521 | typical | 794 | 286.32 (1.5x) | **286.09 (1.5x)** | 286.30 (1.5x) | 286.88 (1.5x) | n/a | n/a | 896.18 (0.5x) | 920.70 (0.5x) | 382.12 (1.1x) | 423.83 (1.0x) |
| ES512 | P-521 | medium | 2407 | 289.85 (1.8x) | 290.54 (1.8x) | 290.08 (1.8x) | **289.47 (1.8x)** | n/a | n/a | 894.59 (0.6x) | 917.14 (0.6x) | 394.03 (1.3x) | 522.55 (1.0x) |
| ES512 | P-521 | large | 21047 | **314.76 (5.6x)** | 330.59 (5.3x) | 332.53 (5.3x) | 316.93 (5.5x) | n/a | n/a | 1037.84 (1.7x) | 1019.45 (1.7x) | 535.37 (3.3x) | 1750.53 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.89 (2.9x) | **32.49 (2.9x)** | 32.58 (2.9x) | 33.24 (2.9x) | 33.65 (2.8x) | 33.80 (2.8x) | 43.11 (2.2x) | 51.56 (1.9x) | 80.06 (1.2x) | 95.50 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **33.39 (3.6x)** | 33.46 (3.6x) | 33.74 (3.5x) | 34.81 (3.4x) | 35.31 (3.4x) | 35.80 (3.3x) | 44.41 (2.7x) | 51.62 (2.3x) | 82.66 (1.4x) | 119.29 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.45 (6.1x)** | 36.66 (5.9x) | 37.07 (5.9x) | 36.43 (6.0x) | 40.09 (5.4x) | 43.63 (5.0x) | 52.04 (4.2x) | 57.93 (3.8x) | 94.96 (2.3x) | 217.94 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **61.48 (23.6x)** | 77.27 (18.8x) | 77.73 (18.7x) | 64.39 (22.5x) | 98.50 (14.7x) | 140.76 (10.3x) | 180.83 (8.0x) | 139.97 (10.4x) | 235.82 (6.1x) | 1450.23 (1.0x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **14.09 (5.0x)** | 14.11 (5.0x) | 14.15 (4.9x) | 14.77 (4.7x) | n/a | n/a | n/a | n/a | n/a | 69.95 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **14.82 (6.5x)** | 14.98 (6.4x) | 15.19 (6.4x) | 16.30 (5.9x) | n/a | n/a | n/a | n/a | n/a | 96.54 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **16.20 (12.3x)** | 17.73 (11.2x) | 18.03 (11.1x) | 17.36 (11.5x) | n/a | n/a | n/a | n/a | n/a | 199.40 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **35.54 (41.5x)** | 52.12 (28.3x) | 53.92 (27.4x) | 39.52 (37.3x) | n/a | n/a | n/a | n/a | n/a | 1474.88 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 28.87 (3.3x) | **28.52 (3.3x)** | 29.07 (3.3x) | 29.43 (3.2x) | n/a | n/a | n/a | n/a | n/a | 95.42 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **29.22 (4.2x)** | 29.39 (4.1x) | 29.78 (4.1x) | 30.87 (3.9x) | n/a | n/a | n/a | n/a | n/a | 121.42 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **30.65 (7.3x)** | 32.02 (7.0x) | 32.64 (6.9x) | 31.93 (7.0x) | n/a | n/a | n/a | n/a | n/a | 224.72 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **49.94 (30.1x)** | 66.70 (22.6x) | 68.09 (22.1x) | 54.07 (27.8x) | n/a | n/a | n/a | n/a | n/a | 1504.21 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 48.71 (2.6x) | **48.47 (2.6x)** | 48.84 (2.6x) | 49.52 (2.6x) | n/a | n/a | n/a | n/a | n/a | 127.20 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 49.43 (3.1x) | **49.34 (3.1x)** | 49.94 (3.1x) | 50.97 (3.0x) | n/a | n/a | n/a | n/a | n/a | 153.77 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **50.82 (5.1x)** | 52.25 (4.9x) | 52.82 (4.9x) | 52.12 (4.9x) | n/a | n/a | n/a | n/a | n/a | 257.66 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **70.04 (22.0x)** | 87.09 (17.7x) | 88.18 (17.5x) | 74.22 (20.8x) | n/a | n/a | n/a | n/a | n/a | 1540.46 (1.0x) |
| ES256 | P-256 | small | 304 | 39.82 (2.3x) | **39.81 (2.3x)** | 39.90 (2.3x) | 40.54 (2.2x) | n/a | n/a | n/a | n/a | n/a | 90.63 (1.0x) |
| ES256 | P-256 | typical | 704 | **40.74 (2.9x)** | 40.86 (2.9x) | 41.14 (2.8x) | 42.28 (2.8x) | n/a | n/a | n/a | n/a | n/a | 116.88 (1.0x) |
| ES256 | P-256 | medium | 2317 | **42.00 (5.2x)** | 43.60 (5.0x) | 43.84 (5.0x) | 43.10 (5.1x) | n/a | n/a | n/a | n/a | n/a | 218.44 (1.0x) |
| ES256 | P-256 | large | 20957 | **61.64 (24.2x)** | 78.39 (19.0x) | 79.66 (18.7x) | 65.43 (22.8x) | n/a | n/a | n/a | n/a | n/a | 1492.29 (1.0x) |
| ES384 | P-384 | small | 346 | **179.49 (1.6x)** | 179.97 (1.6x) | 179.79 (1.6x) | 180.41 (1.6x) | n/a | n/a | n/a | n/a | n/a | 290.90 (1.0x) |
| ES384 | P-384 | typical | 746 | **181.71 (1.7x)** | 181.80 (1.7x) | 181.94 (1.7x) | 182.66 (1.7x) | n/a | n/a | n/a | n/a | n/a | 317.65 (1.0x) |
| ES384 | P-384 | medium | 2359 | **181.94 (2.3x)** | 183.36 (2.3x) | 183.67 (2.3x) | 182.60 (2.3x) | n/a | n/a | n/a | n/a | n/a | 420.14 (1.0x) |
| ES384 | P-384 | large | 20999 | **208.14 (8.2x)** | 224.70 (7.6x) | 226.26 (7.5x) | 211.41 (8.1x) | n/a | n/a | n/a | n/a | n/a | 1705.21 (1.0x) |
| ES512 | P-521 | small | 394 | 290.62 (1.4x) | 288.37 (1.4x) | **287.57 (1.4x)** | 287.91 (1.4x) | n/a | n/a | n/a | n/a | n/a | 403.22 (1.0x) |
| ES512 | P-521 | typical | 794 | 288.58 (1.5x) | 286.37 (1.5x) | **286.13 (1.5x)** | 286.49 (1.5x) | n/a | n/a | n/a | n/a | n/a | 429.60 (1.0x) |
| ES512 | P-521 | medium | 2407 | 291.36 (1.8x) | 291.38 (1.8x) | 291.58 (1.8x) | **289.33 (1.8x)** | n/a | n/a | n/a | n/a | n/a | 533.68 (1.0x) |
| ES512 | P-521 | large | 21047 | **316.19 (5.7x)** | 331.64 (5.5x) | 331.09 (5.5x) | 316.97 (5.7x) | n/a | n/a | n/a | n/a | n/a | 1815.96 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 32.93 (3.0x) | **32.84 (3.0x)** | 32.90 (3.0x) | 33.52 (3.0x) | n/a | n/a | n/a | n/a | n/a | 98.91 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | 33.92 (3.7x) | **33.75 (3.7x)** | 34.03 (3.7x) | 35.11 (3.6x) | n/a | n/a | n/a | n/a | n/a | 124.93 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **35.64 (6.4x)** | 37.04 (6.1x) | 37.86 (6.0x) | 36.71 (6.2x) | n/a | n/a | n/a | n/a | n/a | 227.64 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **61.20 (24.6x)** | 77.18 (19.5x) | 78.63 (19.2x) | 64.52 (23.4x) | n/a | n/a | n/a | n/a | n/a | 1507.97 (1.0x) |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 14.19 (4.9x) | **14.15 (4.9x)** | 14.25 (4.9x) | 14.87 (4.7x) | n/a | n/a | 50.09 (1.4x) | 26.51 (2.6x) | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | **14.89 (6.5x)** | 15.04 (6.4x) | 15.25 (6.3x) | 16.37 (5.9x) | n/a | n/a | 45.04 (2.1x) | 28.33 (3.4x) | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | **16.29 (12.2x)** | 17.72 (11.3x) | 18.06 (11.0x) | 17.38 (11.5x) | n/a | n/a | 46.62 (4.3x) | 33.19 (6.0x) | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | **35.68 (41.3x)** | 52.58 (28.1x) | 53.47 (27.6x) | 39.66 (37.2x) | n/a | n/a | 117.94 (12.5x) | 109.02 (13.5x) | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | **28.65 (3.3x)** | 28.85 (3.3x) | 28.86 (3.3x) | 29.48 (3.2x) | n/a | n/a | 68.32 (1.4x) | 42.92 (2.2x) | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | **29.35 (4.1x)** | 29.46 (4.1x) | 29.88 (4.1x) | 31.02 (3.9x) | n/a | n/a | 68.81 (1.8x) | 42.28 (2.9x) | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | **30.76 (7.3x)** | 32.17 (7.0x) | 32.70 (6.9x) | 32.03 (7.0x) | n/a | n/a | 73.77 (3.0x) | 47.60 (4.7x) | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | **50.10 (30.0x)** | 67.62 (22.2x) | 68.10 (22.1x) | 54.30 (27.7x) | n/a | n/a | 144.99 (10.4x) | 123.61 (12.2x) | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | 48.88 (2.6x) | **48.73 (2.6x)** | 48.93 (2.6x) | 49.58 (2.6x) | n/a | n/a | 105.68 (1.2x) | 61.44 (2.1x) | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | 49.55 (3.1x) | **49.41 (3.1x)** | 50.33 (3.1x) | 51.09 (3.0x) | n/a | n/a | 105.87 (1.5x) | 63.16 (2.4x) | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | **50.69 (5.1x)** | 52.15 (4.9x) | 52.83 (4.9x) | 52.12 (4.9x) | n/a | n/a | 110.73 (2.3x) | 68.39 (3.8x) | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | **70.21 (21.9x)** | 87.30 (17.6x) | 88.19 (17.5x) | 74.42 (20.7x) | n/a | n/a | 181.93 (8.5x) | 149.25 (10.3x) | n/a | n/a |
| ES256 | P-256 | small | 304 | **39.92 (2.3x)** | 39.95 (2.3x) | 39.99 (2.3x) | 40.64 (2.2x) | n/a | n/a | 2423.66 (0.04x) | 51.48 (1.8x) | n/a | n/a |
| ES256 | P-256 | typical | 704 | **40.79 (2.9x)** | 41.24 (2.8x) | 41.31 (2.8x) | 42.30 (2.8x) | n/a | n/a | 2405.65 (0.05x) | 54.14 (2.2x) | n/a | n/a |
| ES256 | P-256 | medium | 2317 | **42.19 (5.2x)** | 43.75 (5.0x) | 44.35 (4.9x) | 43.18 (5.1x) | n/a | n/a | 2408.01 (0.09x) | 58.54 (3.7x) | n/a | n/a |
| ES256 | P-256 | large | 20957 | **62.03 (24.1x)** | 78.45 (19.0x) | 79.64 (18.7x) | 65.59 (22.8x) | n/a | n/a | 2478.97 (0.6x) | 134.99 (11.1x) | n/a | n/a |
| ES384 | P-384 | small | 346 | 179.98 (1.6x) | **179.96 (1.6x)** | 179.97 (1.6x) | 180.44 (1.6x) | n/a | n/a | 11566.49 (0.03x) | 358.44 (0.8x) | n/a | n/a |
| ES384 | P-384 | typical | 746 | **181.72 (1.7x)** | 182.13 (1.7x) | 181.82 (1.7x) | 182.53 (1.7x) | n/a | n/a | 11588.94 (0.03x) | 359.58 (0.9x) | n/a | n/a |
| ES384 | P-384 | medium | 2359 | **181.68 (2.3x)** | 183.07 (2.3x) | 183.53 (2.3x) | 182.61 (2.3x) | n/a | n/a | 11567.30 (0.04x) | 366.64 (1.1x) | n/a | n/a |
| ES384 | P-384 | large | 20999 | **207.50 (8.2x)** | 226.07 (7.5x) | 226.13 (7.5x) | 211.52 (8.1x) | n/a | n/a | 11633.60 (0.1x) | 450.10 (3.8x) | n/a | n/a |
| ES512 | P-521 | small | 394 | 289.20 (1.4x) | 289.54 (1.4x) | **287.92 (1.4x)** | 288.51 (1.4x) | n/a | n/a | 27742.54 (0.01x) | 931.27 (0.4x) | n/a | n/a |
| ES512 | P-521 | typical | 794 | 286.49 (1.5x) | **286.49 (1.5x)** | 286.60 (1.5x) | 286.98 (1.5x) | n/a | n/a | 27727.78 (0.02x) | 919.31 (0.5x) | n/a | n/a |
| ES512 | P-521 | medium | 2407 | 290.11 (1.8x) | 291.70 (1.8x) | 290.67 (1.8x) | **289.71 (1.8x)** | n/a | n/a | 27703.13 (0.02x) | 916.43 (0.6x) | n/a | n/a |
| ES512 | P-521 | large | 21047 | **314.61 (5.8x)** | 331.98 (5.5x) | 333.34 (5.4x) | 317.23 (5.7x) | n/a | n/a | 27712.76 (0.07x) | 1020.48 (1.8x) | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | 32.95 (3.0x) | **32.93 (3.0x)** | 33.01 (3.0x) | 33.59 (2.9x) | n/a | n/a | n/a | 50.84 (1.9x) | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | 34.49 (3.6x) | **34.00 (3.7x)** | 34.14 (3.7x) | 35.19 (3.6x) | n/a | n/a | n/a | 51.55 (2.4x) | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | **35.85 (6.3x)** | 37.61 (6.1x) | 37.78 (6.0x) | 36.75 (6.2x) | n/a | n/a | n/a | 57.66 (3.9x) | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | **61.12 (24.7x)** | 77.52 (19.5x) | 78.31 (19.3x) | 64.66 (23.3x) | n/a | n/a | n/a | 139.79 (10.8x) | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.3.1 → Struct | ryjwt 0.3.1 → dict (msgspec) | ryjwt 0.3.1 → dict (jiter) | ryjwt 0.3.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.7 | pyjwt 2.15.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 1.7 | 1.3 | 1.4 | 1.5 | n/a | n/a | n/a | n/a | n/a | 1.3 |
| JWKS URL, async client | 1.6 | 1.4 | 1.5 | 1.5 | n/a | n/a | 0.7 | 0.8 | n/a | n/a |

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
