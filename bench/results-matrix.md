# JWT decode benchmarks: the full matrix

Generated 2026-10-10 from `bench/results-matrix/` by `bench/compare.py`, on
Neoverse-N2 (aarch64), Linux.
Run in Docker, one container per library, each limited to 1 CPU (pinned) and 500 MB with no swap; the JWKS server runs in a container of its own, outside that limit. Each case gets 1,000 untimed decodes, then 10,000 timed.
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

| key source | alg | key | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → dict (jiter) | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | joserfc 1.7.5 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | **2.07 (28.6x)** | 2.18 (27.2x) | 2.57 (23.1x) | 3.81 (15.5x) | 4.38 (13.5x) | 4.80 (12.4x) | 7.10 (8.3x) | 27.88 (2.1x) | 38.16 (1.6x) | 59.24 (1.0x) |
| PEM public key | RS256 | RSA 3072 | 70.29 (1.7x) | 70.50 (1.7x) | 70.71 (1.7x) | 77.02 (1.5x) | 72.67 (1.6x) | 77.81 (1.5x) | **48.93 (2.4x)** | 75.15 (1.6x) | 79.29 (1.5x) | 117.42 (1.0x) |
| PEM public key | ES384 | P-384 | **252.31 (1.5x)** | 252.81 (1.5x) | 252.42 (1.5x) | 255.26 (1.5x) | 254.39 (1.5x) | 256.52 (1.5x) | 485.72 (0.8x) | 354.61 (1.1x) | 542.04 (0.7x) | 382.31 (1.0x) |
| PEM public key | EdDSA | Ed25519 | 56.85 (2.3x) | 56.91 (2.3x) | 57.28 (2.3x) | 58.38 (2.2x) | 59.15 (2.2x) | 58.76 (2.2x) | **53.66 (2.4x)** | 108.03 (1.2x) | 87.45 (1.5x) | 129.51 (1.0x) |
| JWKS document | RS256 | RSA 3072 | 70.25 (2.5x) | 70.58 (2.5x) | 70.66 (2.5x) | 78.18 (2.2x) | 72.76 (2.4x) | 78.68 (2.2x) | **54.08 (3.2x)** | 79.72 (2.2x) | 81.91 (2.1x) | 175.08 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | **70.71 (2.6x)** | 71.47 (2.6x) | 71.46 (2.6x) | n/a | 73.07 (2.5x) | n/a | n/a | n/a | n/a | 183.54 (1.0x) |
| JWKS URL, async client | RS256 | RSA 3072 | **70.79 (2.6x)** | 71.11 (2.6x) | 71.35 (2.6x) | n/a | 73.21 (2.5x) | n/a | 105.41 (1.7x) | n/a | 82.46 (2.2x) | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → dict (jiter) | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | joserfc 1.7.5 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | 1.13 (32.0x) | **1.06 (34.2x)** | 1.18 (30.8x) | 1.94 (18.7x) | 2.30 (15.8x) | 2.29 (15.8x) | 11.23 (3.2x) | 21.84 (1.7x) | 45.00 (0.8x) | 36.22 (1.0x) |
| HS256 | 32 B | typical | 661 | **2.08 (28.2x)** | 2.19 (26.7x) | 2.61 (22.4x) | 3.76 (15.6x) | 4.38 (13.4x) | 4.71 (12.4x) | 10.05 (5.8x) | 27.90 (2.1x) | 45.49 (1.3x) | 58.57 (1.0x) |
| HS256 | 32 B | medium | 2244 | **3.72 (37.1x)** | 6.07 (22.7x) | 7.13 (19.3x) | 7.48 (18.4x) | 6.34 (21.7x) | 13.26 (10.4x) | 13.99 (9.9x) | 45.73 (3.0x) | 49.67 (2.8x) | 137.82 (1.0x) |
| HS256 | 32 B | large | 20884 | **26.83 (39.1x)** | 59.26 (17.7x) | 61.37 (17.1x) | 58.20 (18.0x) | 40.62 (25.8x) | 127.07 (8.3x) | 117.08 (9.0x) | 261.30 (4.0x) | 171.83 (6.1x) | 1048.89 (1.0x) |
| HS256 | 64 B | small | 231 | 1.12 (32.8x) | **1.07 (34.4x)** | 1.18 (31.3x) | 1.93 (19.1x) | 2.28 (16.1x) | 2.29 (16.1x) | 4.94 (7.5x) | 21.78 (1.7x) | 35.10 (1.0x) | 36.83 (1.0x) |
| HS256 | 64 B | typical | 661 | **2.07 (28.6x)** | 2.18 (27.2x) | 2.57 (23.1x) | 3.81 (15.5x) | 4.38 (13.5x) | 4.80 (12.4x) | 7.10 (8.3x) | 27.88 (2.1x) | 38.16 (1.6x) | 59.24 (1.0x) |
| HS256 | 64 B | medium | 2244 | **3.72 (37.1x)** | 6.07 (22.7x) | 7.15 (19.3x) | 7.53 (18.3x) | 6.33 (21.8x) | 13.34 (10.3x) | 19.68 (7.0x) | 45.34 (3.0x) | 48.08 (2.9x) | 137.93 (1.0x) |
| HS256 | 64 B | large | 20884 | **26.83 (39.0x)** | 59.44 (17.6x) | 61.90 (16.9x) | 58.25 (18.0x) | 40.68 (25.7x) | 126.89 (8.2x) | 113.57 (9.2x) | 262.18 (4.0x) | 165.49 (6.3x) | 1046.66 (1.0x) |
| HS256 | 256 B | small | 231 | 1.13 (34.4x) | **1.06 (36.6x)** | 1.17 (33.1x) | 2.22 (17.5x) | 2.28 (17.0x) | 2.45 (15.8x) | 4.65 (8.3x) | 21.77 (1.8x) | 33.34 (1.2x) | 38.76 (1.0x) |
| HS256 | 256 B | typical | 661 | **2.06 (29.8x)** | 2.19 (28.0x) | 2.59 (23.8x) | 3.97 (15.5x) | 4.36 (14.1x) | 4.95 (12.4x) | 7.11 (8.6x) | 28.09 (2.2x) | 38.78 (1.6x) | 61.41 (1.0x) |
| HS256 | 256 B | medium | 2244 | **3.71 (37.9x)** | 6.07 (23.1x) | 7.13 (19.7x) | 7.77 (18.1x) | 6.35 (22.1x) | 13.43 (10.5x) | 12.55 (11.2x) | 46.00 (3.1x) | 49.34 (2.8x) | 140.47 (1.0x) |
| HS256 | 256 B | large | 20884 | **26.81 (39.2x)** | 58.88 (17.9x) | 61.46 (17.1x) | 58.40 (18.0x) | 40.71 (25.8x) | 126.71 (8.3x) | 113.63 (9.3x) | 261.87 (4.0x) | 164.80 (6.4x) | 1051.55 (1.0x) |
| HS256 | 4096 B | small | 231 | 1.13 (67.9x) | **1.06 (72.3x)** | 1.17 (65.6x) | 3.94 (19.4x) | 2.29 (33.4x) | 4.24 (18.1x) | 6.43 (11.9x) | 23.73 (3.2x) | 38.80 (2.0x) | 76.57 (1.0x) |
| HS256 | 4096 B | typical | 661 | **2.08 (48.3x)** | 2.18 (46.0x) | 2.59 (38.7x) | 5.75 (17.5x) | 4.36 (23.0x) | 6.73 (14.9x) | 8.92 (11.3x) | 29.69 (3.4x) | 44.47 (2.3x) | 100.36 (1.0x) |
| HS256 | 4096 B | medium | 2244 | **3.71 (48.0x)** | 6.04 (29.5x) | 7.14 (24.9x) | 9.52 (18.7x) | 6.33 (28.2x) | 15.37 (11.6x) | 15.44 (11.5x) | 47.45 (3.8x) | 50.82 (3.5x) | 178.20 (1.0x) |
| HS256 | 4096 B | large | 20884 | **27.33 (39.9x)** | 59.08 (18.4x) | 61.37 (17.8x) | 60.15 (18.1x) | 40.69 (26.8x) | 129.00 (8.4x) | 114.84 (9.5x) | 263.70 (4.1x) | 166.46 (6.5x) | 1089.82 (1.0x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → dict (jiter) | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | joserfc 1.7.5 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 29.40 (2.2x) | 29.66 (2.2x) | 29.53 (2.2x) | 33.43 (2.0x) | 30.69 (2.2x) | 33.78 (2.0x) | **25.83 (2.6x)** | 45.99 (1.4x) | 54.62 (1.2x) | 66.03 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 30.36 (2.8x) | 30.53 (2.8x) | 31.14 (2.8x) | 35.02 (2.5x) | 32.84 (2.6x) | 35.75 (2.4x) | **29.06 (3.0x)** | 52.01 (1.7x) | 60.28 (1.4x) | 86.50 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **32.01 (5.1x)** | 34.54 (4.8x) | 35.48 (4.6x) | 39.05 (4.2x) | 34.78 (4.7x) | 44.92 (3.7x) | 36.03 (4.6x) | 70.36 (2.3x) | 77.94 (2.1x) | 164.66 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **55.15 (19.3x)** | 88.01 (12.1x) | 90.01 (11.8x) | 89.77 (11.9x) | 68.92 (15.4x) | 158.76 (6.7x) | 137.00 (7.8x) | 292.28 (3.6x) | 190.74 (5.6x) | 1063.92 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 69.31 (1.4x) | 69.19 (1.4x) | 69.51 (1.4x) | 76.00 (1.3x) | 70.56 (1.4x) | 75.93 (1.3x) | **46.32 (2.1x)** | 69.18 (1.4x) | 75.21 (1.3x) | 96.63 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | 70.29 (1.7x) | 70.50 (1.7x) | 70.71 (1.7x) | 77.02 (1.5x) | 72.67 (1.6x) | 77.81 (1.5x) | **48.93 (2.4x)** | 75.15 (1.6x) | 79.29 (1.5x) | 117.42 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 72.45 (2.7x) | 74.63 (2.6x) | 75.29 (2.6x) | 81.21 (2.4x) | 74.63 (2.6x) | 87.28 (2.2x) | **55.24 (3.5x)** | 93.26 (2.1x) | 90.73 (2.1x) | 194.78 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **95.20 (11.6x)** | 127.72 (8.7x) | 129.95 (8.5x) | 131.91 (8.4x) | 109.03 (10.1x) | 200.93 (5.5x) | 165.19 (6.7x) | 317.45 (3.5x) | 211.96 (5.2x) | 1104.98 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 119.49 (1.1x) | 118.79 (1.1x) | 118.52 (1.1x) | 127.94 (1.1x) | 119.85 (1.1x) | 128.71 (1.1x) | **76.05 (1.8x)** | 100.83 (1.3x) | 104.19 (1.3x) | 136.03 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 120.04 (1.3x) | 119.66 (1.3x) | 120.51 (1.3x) | 129.70 (1.2x) | 122.06 (1.3x) | 130.83 (1.2x) | **79.05 (2.0x)** | 106.65 (1.5x) | 108.49 (1.4x) | 156.48 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 121.33 (1.9x) | 123.80 (1.9x) | 125.00 (1.9x) | 133.88 (1.7x) | 124.01 (1.9x) | 139.44 (1.7x) | **85.13 (2.7x)** | 125.25 (1.9x) | 120.33 (1.9x) | 234.08 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **144.70 (7.8x)** | 177.77 (6.4x) | 179.68 (6.3x) | 184.45 (6.2x) | 158.61 (7.2x) | 253.52 (4.5x) | 188.51 (6.0x) | 352.70 (3.2x) | 243.74 (4.7x) | 1135.21 (1.0x) |
| ES256 | P-256 | small | 304 | 53.20 (2.0x) | **53.06 (2.0x)** | 53.30 (2.0x) | 54.68 (1.9x) | 54.43 (1.9x) | 54.99 (1.9x) | 59.67 (1.8x) | 94.11 (1.1x) | 91.15 (1.2x) | 105.83 (1.0x) |
| ES256 | P-256 | typical | 704 | **54.49 (2.3x)** | 54.50 (2.3x) | 55.33 (2.3x) | 56.56 (2.3x) | 56.88 (2.2x) | 57.59 (2.2x) | 61.19 (2.1x) | 100.29 (1.3x) | 96.09 (1.3x) | 127.85 (1.0x) |
| ES256 | P-256 | medium | 2317 | **55.86 (3.8x)** | 58.60 (3.6x) | 59.74 (3.5x) | 60.35 (3.5x) | 58.68 (3.6x) | 66.19 (3.2x) | 67.93 (3.1x) | 123.88 (1.7x) | 107.61 (2.0x) | 209.87 (1.0x) |
| ES256 | P-256 | large | 20957 | **79.22 (14.1x)** | 112.39 (9.9x) | 113.84 (9.8x) | 111.45 (10.0x) | 93.08 (12.0x) | 180.75 (6.2x) | 171.65 (6.5x) | 354.63 (3.1x) | 229.37 (4.9x) | 1115.08 (1.0x) |
| ES384 | P-384 | small | 346 | 250.52 (1.4x) | **250.15 (1.4x)** | 250.21 (1.4x) | 252.71 (1.4x) | 251.15 (1.4x) | 252.91 (1.4x) | 480.35 (0.7x) | 346.88 (1.0x) | 526.63 (0.7x) | 359.26 (1.0x) |
| ES384 | P-384 | typical | 746 | **252.31 (1.5x)** | 252.81 (1.5x) | 252.42 (1.5x) | 255.26 (1.5x) | 254.39 (1.5x) | 256.52 (1.5x) | 485.72 (0.8x) | 354.61 (1.1x) | 542.04 (0.7x) | 382.31 (1.0x) |
| ES384 | P-384 | medium | 2359 | **252.11 (1.8x)** | 254.62 (1.8x) | 256.03 (1.8x) | 258.03 (1.8x) | 254.71 (1.8x) | 264.22 (1.7x) | 492.61 (0.9x) | 374.29 (1.2x) | 544.59 (0.8x) | 459.46 (1.0x) |
| ES384 | P-384 | large | 20999 | **282.09 (4.9x)** | 315.65 (4.4x) | 317.16 (4.3x) | 315.11 (4.4x) | 296.07 (4.6x) | 385.94 (3.6x) | 606.53 (2.3x) | 618.67 (2.2x) | 674.60 (2.0x) | 1374.12 (1.0x) |
| ES512 | P-521 | small | 394 | 504.93 (1.0x) | 503.99 (1.0x) | 503.67 (1.0x) | n/a | 504.96 (1.0x) | n/a | 1255.92 (0.4x) | **492.20 (1.0x)** | 1321.00 (0.4x) | 499.10 (1.0x) |
| ES512 | P-521 | typical | 794 | 500.63 (1.0x) | 500.68 (1.0x) | 500.29 (1.0x) | n/a | 502.40 (1.0x) | n/a | 1242.05 (0.4x) | **498.71 (1.0x)** | 1311.14 (0.4x) | 522.52 (1.0x) |
| ES512 | P-521 | medium | 2407 | **504.45 (1.2x)** | 507.22 (1.2x) | 507.90 (1.2x) | n/a | 506.54 (1.2x) | n/a | 1237.75 (0.5x) | 521.38 (1.2x) | 1314.28 (0.5x) | 601.79 (1.0x) |
| ES512 | P-521 | large | 21047 | **532.41 (2.9x)** | 565.84 (2.7x) | 567.91 (2.7x) | n/a | 546.15 (2.8x) | n/a | 1380.91 (1.1x) | 763.47 (2.0x) | 1468.85 (1.0x) | 1518.28 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 55.73 (2.0x) | 55.83 (2.0x) | 56.16 (2.0x) | 56.66 (1.9x) | 56.92 (1.9x) | 56.79 (1.9x) | **51.23 (2.1x)** | 103.36 (1.1x) | 83.55 (1.3x) | 110.14 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | 56.85 (2.3x) | 56.91 (2.3x) | 57.28 (2.3x) | 58.38 (2.2x) | 59.15 (2.2x) | 58.76 (2.2x) | **53.66 (2.4x)** | 108.03 (1.2x) | 87.45 (1.5x) | 129.51 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **59.10 (3.5x)** | 61.35 (3.4x) | 62.39 (3.3x) | 62.72 (3.3x) | 61.61 (3.4x) | 68.34 (3.0x) | 61.98 (3.4x) | 127.64 (1.6x) | 98.92 (2.1x) | 207.70 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **87.49 (12.7x)** | 120.25 (9.3x) | 122.28 (9.1x) | 119.61 (9.3x) | 101.72 (10.9x) | 188.31 (5.9x) | 169.71 (6.6x) | 359.94 (3.1x) | 229.10 (4.9x) | 1113.81 (1.0x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → dict (jiter) | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | joserfc 1.7.5 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 29.40 (3.4x) | 29.79 (3.3x) | 29.42 (3.4x) | 34.11 (2.9x) | 30.72 (3.2x) | 34.13 (2.9x) | **28.96 (3.4x)** | 50.11 (2.0x) | 60.50 (1.6x) | 98.74 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 30.52 (4.5x) | **30.51 (4.5x)** | 30.84 (4.5x) | 35.50 (3.9x) | 32.82 (4.2x) | 36.55 (3.8x) | 31.65 (4.4x) | 55.70 (2.5x) | 65.25 (2.1x) | 138.31 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **32.01 (9.0x)** | 34.71 (8.3x) | 35.50 (8.1x) | 40.21 (7.1x) | 34.78 (8.2x) | 46.58 (6.2x) | 43.44 (6.6x) | 74.86 (3.8x) | 73.61 (3.9x) | 286.59 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **55.23 (36.0x)** | 88.43 (22.5x) | 90.35 (22.0x) | 97.50 (20.4x) | 68.94 (28.8x) | 166.50 (11.9x) | 239.92 (8.3x) | 306.80 (6.5x) | 197.40 (10.1x) | 1987.66 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 69.27 (2.0x) | 69.42 (2.0x) | 69.28 (2.0x) | 75.95 (1.8x) | 70.55 (1.9x) | 76.27 (1.8x) | **50.01 (2.7x)** | 73.21 (1.9x) | 76.12 (1.8x) | 137.16 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | 70.25 (2.5x) | 70.58 (2.5x) | 70.66 (2.5x) | 78.18 (2.2x) | 72.76 (2.4x) | 78.68 (2.2x) | **54.08 (3.2x)** | 79.72 (2.2x) | 81.91 (2.1x) | 175.08 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 72.37 (4.5x) | 74.32 (4.3x) | 75.32 (4.3x) | 82.57 (3.9x) | 74.62 (4.3x) | 88.53 (3.6x) | **65.20 (4.9x)** | 98.64 (3.3x) | 95.51 (3.4x) | 322.44 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **95.12 (21.2x)** | 128.01 (15.8x) | 129.84 (15.6x) | 139.59 (14.5x) | 109.16 (18.5x) | 209.44 (9.6x) | 260.80 (7.7x) | 333.97 (6.0x) | 217.28 (9.3x) | 2019.15 (1.0x) |
| RS256 | RSA 4096 | small | 902 | 118.66 (1.5x) | 118.54 (1.5x) | 118.65 (1.5x) | 128.66 (1.4x) | 119.91 (1.5x) | 129.36 (1.4x) | **80.32 (2.3x)** | 105.46 (1.7x) | 107.22 (1.7x) | 183.31 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 119.75 (1.9x) | 119.67 (1.9x) | 120.86 (1.8x) | 130.68 (1.7x) | 122.08 (1.8x) | 131.85 (1.7x) | **83.24 (2.7x)** | 111.41 (2.0x) | 112.73 (2.0x) | 222.11 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 121.32 (3.1x) | 123.84 (3.0x) | 124.77 (3.0x) | 135.36 (2.7x) | 123.97 (3.0x) | 141.23 (2.6x) | **96.18 (3.9x)** | 130.11 (2.8x) | 126.37 (2.9x) | 370.48 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **144.54 (14.3x)** | 177.63 (11.6x) | 179.21 (11.5x) | 192.97 (10.7x) | 158.50 (13.0x) | 260.95 (7.9x) | 292.07 (7.1x) | 366.34 (5.6x) | 249.68 (8.3x) | 2064.56 (1.0x) |
| ES256 | P-256 | small | 304 | 53.60 (2.4x) | **53.33 (2.4x)** | 53.46 (2.4x) | 55.08 (2.3x) | 54.49 (2.4x) | 55.49 (2.3x) | 61.25 (2.1x) | 99.18 (1.3x) | 93.64 (1.4x) | 128.39 (1.0x) |
| ES256 | P-256 | typical | 704 | 54.81 (3.1x) | **54.50 (3.1x)** | 54.84 (3.1x) | 57.08 (2.9x) | 56.84 (3.0x) | 57.87 (2.9x) | 66.04 (2.5x) | 108.01 (1.6x) | 99.49 (1.7x) | 168.37 (1.0x) |
| ES256 | P-256 | medium | 2317 | **55.85 (5.8x)** | 58.29 (5.5x) | 59.28 (5.4x) | 61.84 (5.2x) | 58.62 (5.5x) | 67.75 (4.7x) | 77.06 (4.2x) | 134.50 (2.4x) | 109.39 (2.9x) | 321.37 (1.0x) |
| ES256 | P-256 | large | 20957 | **79.49 (25.5x)** | 111.88 (18.1x) | 114.44 (17.7x) | 119.51 (17.0x) | 93.37 (21.7x) | 188.14 (10.8x) | 275.08 (7.4x) | 375.74 (5.4x) | 237.02 (8.6x) | 2027.49 (1.0x) |
| ES384 | P-384 | small | 346 | 251.00 (1.5x) | **250.15 (1.5x)** | 250.69 (1.5x) | 253.32 (1.5x) | 251.06 (1.5x) | 253.41 (1.5x) | 484.29 (0.8x) | 352.74 (1.1x) | 530.73 (0.7x) | 385.65 (1.0x) |
| ES384 | P-384 | typical | 746 | **252.49 (1.7x)** | 252.66 (1.7x) | 252.87 (1.7x) | 255.78 (1.7x) | 254.61 (1.7x) | 256.83 (1.7x) | 490.20 (0.9x) | 359.60 (1.2x) | 537.89 (0.8x) | 425.97 (1.0x) |
| ES384 | P-384 | medium | 2359 | **252.18 (2.3x)** | 254.87 (2.3x) | 255.55 (2.3x) | 259.82 (2.2x) | 254.75 (2.3x) | 264.45 (2.2x) | 502.72 (1.1x) | 380.72 (1.5x) | 553.13 (1.0x) | 576.51 (1.0x) |
| ES384 | P-384 | large | 20999 | **282.08 (8.1x)** | 315.26 (7.2x) | 316.92 (7.2x) | 322.57 (7.1x) | 296.12 (7.7x) | 391.87 (5.8x) | 706.07 (3.2x) | 634.95 (3.6x) | 681.46 (3.3x) | 2281.15 (1.0x) |
| ES512 | P-521 | small | 394 | 504.27 (1.0x) | 504.75 (1.0x) | 505.30 (1.0x) | n/a | 505.09 (1.0x) | n/a | 1261.06 (0.4x) | **495.65 (1.1x)** | 1329.69 (0.4x) | 529.13 (1.0x) |
| ES512 | P-521 | typical | 794 | 500.94 (1.1x) | 501.14 (1.1x) | **500.56 (1.1x)** | n/a | 502.19 (1.1x) | n/a | 1249.85 (0.5x) | 508.53 (1.1x) | 1315.93 (0.4x) | 565.86 (1.0x) |
| ES512 | P-521 | medium | 2407 | **505.33 (1.4x)** | 507.22 (1.4x) | 507.46 (1.4x) | n/a | 506.56 (1.4x) | n/a | 1250.06 (0.6x) | 528.03 (1.4x) | 1320.01 (0.5x) | 715.48 (1.0x) |
| ES512 | P-521 | large | 21047 | **532.90 (4.6x)** | 566.77 (4.3x) | 568.05 (4.3x) | n/a | 546.32 (4.4x) | n/a | 1480.23 (1.6x) | 777.81 (3.1x) | 1474.58 (1.6x) | 2424.82 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 55.91 (2.4x) | 56.09 (2.3x) | 55.73 (2.4x) | 57.20 (2.3x) | 56.94 (2.3x) | 57.16 (2.3x) | **54.47 (2.4x)** | 106.70 (1.2x) | 86.65 (1.5x) | 131.65 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **56.75 (3.0x)** | 56.90 (3.0x) | 57.29 (3.0x) | 59.11 (2.9x) | 59.13 (2.9x) | 59.82 (2.8x) | 57.69 (2.9x) | 111.60 (1.5x) | 90.12 (1.9x) | 169.11 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **59.00 (5.4x)** | 61.27 (5.2x) | 62.40 (5.1x) | 63.80 (5.0x) | 61.65 (5.2x) | 69.86 (4.5x) | 69.75 (4.6x) | 132.11 (2.4x) | 101.97 (3.1x) | 317.86 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **87.42 (23.1x)** | 121.22 (16.6x) | 122.55 (16.5x) | 126.72 (15.9x) | 101.68 (19.8x) | 196.72 (10.3x) | 270.15 (7.5x) | 370.72 (5.4x) | 233.37 (8.6x) | 2017.96 (1.0x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → dict (jiter) | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | joserfc 1.7.5 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 29.87 (3.5x) | **29.77 (3.5x)** | 29.84 (3.5x) | n/a | 31.04 (3.4x) | n/a | n/a | n/a | n/a | 104.95 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | **30.77 (4.7x)** | 30.94 (4.7x) | 31.76 (4.6x) | n/a | 33.16 (4.4x) | n/a | n/a | n/a | n/a | 145.09 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | **32.41 (9.2x)** | 34.93 (8.6x) | 36.12 (8.3x) | n/a | 35.17 (8.5x) | n/a | n/a | n/a | n/a | 299.54 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **55.71 (37.3x)** | 88.28 (23.5x) | 90.48 (23.0x) | n/a | 69.68 (29.8x) | n/a | n/a | n/a | n/a | 2078.67 (1.0x) |
| RS256 | RSA 3072 | small | 731 | 69.81 (2.0x) | **69.63 (2.0x)** | 69.81 (2.0x) | n/a | 70.89 (2.0x) | n/a | n/a | n/a | n/a | 142.64 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **70.71 (2.6x)** | 71.47 (2.6x) | 71.46 (2.6x) | n/a | 73.07 (2.5x) | n/a | n/a | n/a | n/a | 183.54 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **72.26 (4.7x)** | 74.89 (4.5x) | 75.88 (4.4x) | n/a | 75.03 (4.5x) | n/a | n/a | n/a | n/a | 336.50 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | **95.50 (22.1x)** | 128.41 (16.4x) | 130.43 (16.2x) | n/a | 109.51 (19.3x) | n/a | n/a | n/a | n/a | 2109.23 (1.0x) |
| RS256 | RSA 4096 | small | 902 | **119.10 (1.6x)** | 119.15 (1.6x) | 119.25 (1.6x) | n/a | 120.27 (1.6x) | n/a | n/a | n/a | n/a | 190.24 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **119.96 (1.9x)** | 120.13 (1.9x) | 120.61 (1.9x) | n/a | 122.45 (1.9x) | n/a | n/a | n/a | n/a | 229.80 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | **121.79 (3.1x)** | 124.28 (3.1x) | 125.35 (3.0x) | n/a | 124.33 (3.1x) | n/a | n/a | n/a | n/a | 380.35 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | **145.14 (14.9x)** | 177.40 (12.2x) | 180.39 (12.0x) | n/a | 158.85 (13.6x) | n/a | n/a | n/a | n/a | 2161.30 (1.0x) |
| ES256 | P-256 | small | 304 | 53.54 (2.5x) | **53.47 (2.5x)** | 53.58 (2.5x) | n/a | 54.83 (2.4x) | n/a | n/a | n/a | n/a | 131.28 (1.0x) |
| ES256 | P-256 | typical | 704 | **54.81 (3.2x)** | 55.12 (3.2x) | 55.31 (3.2x) | n/a | 57.25 (3.1x) | n/a | n/a | n/a | n/a | 174.96 (1.0x) |
| ES256 | P-256 | medium | 2317 | **56.26 (5.9x)** | 59.07 (5.7x) | 59.89 (5.6x) | n/a | 58.95 (5.7x) | n/a | n/a | n/a | n/a | 333.79 (1.0x) |
| ES256 | P-256 | large | 20957 | **79.70 (26.6x)** | 112.53 (18.9x) | 114.82 (18.5x) | n/a | 93.60 (22.7x) | n/a | n/a | n/a | n/a | 2122.78 (1.0x) |
| ES384 | P-384 | small | 346 | **250.29 (1.6x)** | 250.81 (1.6x) | 251.01 (1.6x) | n/a | 251.43 (1.6x) | n/a | n/a | n/a | n/a | 391.33 (1.0x) |
| ES384 | P-384 | typical | 746 | 253.29 (1.7x) | **252.26 (1.7x)** | 253.08 (1.7x) | n/a | 254.98 (1.7x) | n/a | n/a | n/a | n/a | 434.12 (1.0x) |
| ES384 | P-384 | medium | 2359 | **252.73 (2.3x)** | 255.22 (2.3x) | 255.92 (2.3x) | n/a | 255.06 (2.3x) | n/a | n/a | n/a | n/a | 588.93 (1.0x) |
| ES384 | P-384 | large | 20999 | **282.94 (8.4x)** | 316.31 (7.5x) | 317.50 (7.5x) | n/a | 296.52 (8.0x) | n/a | n/a | n/a | n/a | 2368.80 (1.0x) |
| ES512 | P-521 | small | 394 | 504.37 (1.1x) | **504.11 (1.1x)** | 504.45 (1.1x) | n/a | 505.13 (1.1x) | n/a | n/a | n/a | n/a | 538.10 (1.0x) |
| ES512 | P-521 | typical | 794 | **501.00 (1.2x)** | 501.21 (1.2x) | 501.15 (1.2x) | n/a | 502.51 (1.2x) | n/a | n/a | n/a | n/a | 582.76 (1.0x) |
| ES512 | P-521 | medium | 2407 | **505.06 (1.5x)** | 507.41 (1.5x) | 508.73 (1.4x) | n/a | 506.62 (1.5x) | n/a | n/a | n/a | n/a | 736.02 (1.0x) |
| ES512 | P-521 | large | 21047 | **533.50 (4.7x)** | 567.37 (4.5x) | 568.61 (4.5x) | n/a | 546.77 (4.6x) | n/a | n/a | n/a | n/a | 2533.26 (1.0x) |
| EdDSA | Ed25519 | small | 306 | 56.54 (2.4x) | **56.05 (2.4x)** | 56.06 (2.4x) | n/a | 57.33 (2.4x) | n/a | n/a | n/a | n/a | 136.97 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **57.19 (3.1x)** | 57.47 (3.1x) | 57.64 (3.1x) | n/a | 59.50 (3.0x) | n/a | n/a | n/a | n/a | 175.91 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | **59.40 (5.5x)** | 62.00 (5.3x) | 62.84 (5.2x) | n/a | 62.02 (5.3x) | n/a | n/a | n/a | n/a | 329.59 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **87.99 (23.9x)** | 121.72 (17.3x) | 122.85 (17.2x) | n/a | 102.25 (20.6x) | n/a | n/a | n/a | n/a | 2106.90 (1.0x) |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → dict (jiter) | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | joserfc 1.7.5 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 30.32 (3.5x) | **29.85 (3.5x)** | 29.91 (3.5x) | n/a | 31.16 (3.4x) | n/a | 78.98 (1.3x) | n/a | 58.27 (1.8x) | n/a |
| RS256 | RSA 2048 | typical | 961 | **30.91 (4.7x)** | 31.02 (4.7x) | 31.40 (4.6x) | n/a | 33.29 (4.4x) | n/a | 67.89 (2.1x) | n/a | 61.61 (2.4x) | n/a |
| RS256 | RSA 2048 | medium | 2574 | **32.50 (9.2x)** | 35.02 (8.6x) | 36.09 (8.3x) | n/a | 35.25 (8.5x) | n/a | 72.13 (4.2x) | n/a | 75.13 (4.0x) | n/a |
| RS256 | RSA 2048 | large | 21214 | **55.81 (37.2x)** | 88.92 (23.4x) | 90.61 (22.9x) | n/a | 69.89 (29.7x) | n/a | 197.28 (10.5x) | n/a | 198.50 (10.5x) | n/a |
| RS256 | RSA 3072 | small | 731 | **69.79 (2.0x)** | 69.90 (2.0x) | 69.81 (2.0x) | n/a | 71.00 (2.0x) | n/a | 99.67 (1.4x) | n/a | 77.94 (1.8x) | n/a |
| RS256 | RSA 3072 | typical | 1131 | **70.79 (2.6x)** | 71.11 (2.6x) | 71.35 (2.6x) | n/a | 73.21 (2.5x) | n/a | 105.41 (1.7x) | n/a | 82.46 (2.2x) | n/a |
| RS256 | RSA 3072 | medium | 2744 | **72.55 (4.6x)** | 75.04 (4.5x) | 75.83 (4.4x) | n/a | 75.10 (4.5x) | n/a | 116.73 (2.9x) | n/a | 96.97 (3.5x) | n/a |
| RS256 | RSA 3072 | large | 21384 | **95.60 (22.1x)** | 129.12 (16.3x) | 130.44 (16.2x) | n/a | 109.76 (19.2x) | n/a | 237.30 (8.9x) | n/a | 220.37 (9.6x) | n/a |
| RS256 | RSA 4096 | small | 902 | 119.52 (1.6x) | 119.10 (1.6x) | 119.31 (1.6x) | n/a | 120.38 (1.6x) | n/a | 154.68 (1.2x) | n/a | **108.69 (1.8x)** | n/a |
| RS256 | RSA 4096 | typical | 1302 | 121.07 (1.9x) | 120.58 (1.9x) | 120.65 (1.9x) | n/a | 122.61 (1.9x) | n/a | 159.15 (1.4x) | n/a | **112.55 (2.0x)** | n/a |
| RS256 | RSA 4096 | medium | 2915 | **121.85 (3.1x)** | 124.38 (3.1x) | 125.52 (3.0x) | n/a | 124.45 (3.1x) | n/a | 164.05 (2.3x) | n/a | 125.81 (3.0x) | n/a |
| RS256 | RSA 4096 | large | 21555 | **145.23 (14.9x)** | 178.72 (12.1x) | 179.96 (12.0x) | n/a | 159.22 (13.6x) | n/a | 289.43 (7.5x) | n/a | 259.68 (8.3x) | n/a |
| ES256 | P-256 | small | 304 | 53.69 (2.4x) | **53.56 (2.5x)** | 53.62 (2.4x) | n/a | 54.97 (2.4x) | n/a | 3551.20 (0.04x) | n/a | 91.56 (1.4x) | n/a |
| ES256 | P-256 | typical | 704 | **54.91 (3.2x)** | 55.14 (3.2x) | 55.37 (3.2x) | n/a | 57.40 (3.0x) | n/a | 3542.82 (0.05x) | n/a | 94.50 (1.9x) | n/a |
| ES256 | P-256 | medium | 2317 | **57.21 (5.8x)** | 58.86 (5.7x) | 59.80 (5.6x) | n/a | 59.17 (5.6x) | n/a | 3519.20 (0.09x) | n/a | 107.34 (3.1x) | n/a |
| ES256 | P-256 | large | 20957 | **79.81 (26.6x)** | 113.67 (18.7x) | 115.09 (18.4x) | n/a | 93.77 (22.6x) | n/a | 3610.72 (0.6x) | n/a | 236.19 (9.0x) | n/a |
| ES384 | P-384 | small | 346 | 250.97 (1.6x) | **250.68 (1.6x)** | 251.39 (1.6x) | n/a | 251.79 (1.6x) | n/a | 12313.10 (0.03x) | n/a | 528.34 (0.7x) | n/a |
| ES384 | P-384 | typical | 746 | 253.19 (1.7x) | **252.79 (1.7x)** | 253.09 (1.7x) | n/a | 255.01 (1.7x) | n/a | 12329.96 (0.04x) | n/a | 534.26 (0.8x) | n/a |
| ES384 | P-384 | medium | 2359 | **252.38 (2.3x)** | 255.47 (2.3x) | 256.91 (2.3x) | n/a | 255.55 (2.3x) | n/a | 12273.71 (0.05x) | n/a | 550.02 (1.1x) | n/a |
| ES384 | P-384 | large | 20999 | **282.71 (8.4x)** | 317.10 (7.5x) | 317.44 (7.5x) | n/a | 296.94 (8.0x) | n/a | 12346.25 (0.2x) | n/a | 684.75 (3.5x) | n/a |
| ES512 | P-521 | small | 394 | 505.56 (1.1x) | 505.46 (1.1x) | **505.02 (1.1x)** | n/a | 505.82 (1.1x) | n/a | 28790.14 (0.02x) | n/a | 1324.84 (0.4x) | n/a |
| ES512 | P-521 | typical | 794 | **500.82 (1.2x)** | 500.93 (1.2x) | 501.50 (1.2x) | n/a | 503.08 (1.2x) | n/a | 28730.05 (0.02x) | n/a | 1316.37 (0.4x) | n/a |
| ES512 | P-521 | medium | 2407 | **504.61 (1.5x)** | 508.37 (1.4x) | 508.62 (1.4x) | n/a | 507.07 (1.5x) | n/a | 28648.03 (0.03x) | n/a | 1316.22 (0.6x) | n/a |
| ES512 | P-521 | large | 21047 | **532.87 (4.8x)** | 568.48 (4.5x) | 568.89 (4.5x) | n/a | 546.80 (4.6x) | n/a | 28673.01 (0.09x) | n/a | 1479.09 (1.7x) | n/a |
| EdDSA | Ed25519 | small | 306 | 56.92 (2.4x) | 56.53 (2.4x) | **56.19 (2.4x)** | n/a | 57.44 (2.4x) | n/a | n/a | n/a | 85.39 (1.6x) | n/a |
| EdDSA | Ed25519 | typical | 706 | **57.29 (3.1x)** | 57.92 (3.0x) | 57.76 (3.0x) | n/a | 59.66 (2.9x) | n/a | n/a | n/a | 87.31 (2.0x) | n/a |
| EdDSA | Ed25519 | medium | 2319 | **59.52 (5.5x)** | 61.88 (5.3x) | 63.12 (5.2x) | n/a | 62.15 (5.3x) | n/a | n/a | n/a | 99.65 (3.3x) | n/a |
| EdDSA | Ed25519 | large | 20959 | **88.20 (23.9x)** | 120.81 (17.4x) | 122.82 (17.2x) | n/a | 102.45 (20.6x) | n/a | n/a | n/a | 234.94 (9.0x) | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → dict (jiter) | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | joserfc 1.7.5 | jose 6.2.12 | pyjwt 2.15.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 2.7 | 2.4 | 2.5 | n/a | 2.5 | n/a | n/a | n/a | n/a | 2.3 |
| JWKS URL, async client | 2.8 | 2.5 | 2.7 | n/a | 2.6 | n/a | 1.9 | n/a | 1.4 | n/a |

## Not applicable

- jsonwebtoken 11.1.0 (aws-lc-rs) → struct, every key source, ES512: jsonwebtoken has no ES512 (P-521).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct, JWKS URL, sync client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct, JWKS URL, async client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value, every key source, ES512: jsonwebtoken has no ES512 (P-521).
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value, JWKS URL, sync client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value, JWKS URL, async client: jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache).
- fast-jwt 6.3.3, JWKS URL, sync client: fast-jwt's JWKS support (get-jwks) is async only.
- fast-jwt 6.3.3, JWKS URL, async client, EdDSA: get-jwks converts JWKs with jwk-to-pem, which doesn't support OKP (Ed25519) keys.
- joserfc 1.7.5, JWKS URL, sync client: joserfc has no JWKS URL client.
- joserfc 1.7.5, JWKS URL, async client: joserfc has no JWKS URL client.
- jose 6.2.12, JWKS URL, sync client: jose's API is async only.
- pyjwt 2.15.1, JWKS URL, async client: PyJWT has no async JWKS client.

## Notes

- ryjwt 0.1.1 → Struct: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.1 → dict (msgspec): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → dict (msgspec): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.1 → dict (jiter): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → dict (jiter): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: claims decoded into typed structs with the fields ryjwt's msgspec lane decodes; other claims ignored.
- ryjwt 0.1.1 → BaseModel: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → BaseModel: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- jsonwebtoken 11.1.0 (aws-lc-rs) → Value: JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- fast-jwt 6.3.3: JWKS document: a verifier per key, made once, picked by the token's `kid` (read with `createDecoder`).
- fast-jwt 6.3.3: JWKS URL rows are fast-jwt + get-jwks 11.0.3 (fast-jwt's documented integration), so they time both: on every verify get-jwks converts the cached JWK to a PEM (with jwk-to-pem) and fast-jwt imports that PEM (`createPublicKey`), which is why they're slow.
- joserfc 1.7.5: `jwt.decode(token, key, algorithms=[...])`, then `JWTClaimsRegistry(exp=..., aud=...).validate(token.claims)`, both essential.
- joserfc 1.7.5: keys imported once (`OctKey`, `RSAKey`, `ECKey`, `OKPKey`); JWKS document: a `KeySet`, which picks the key by `kid`.
- joserfc 1.7.5: EdDSA: joserfc warns on every decode (`SecurityWarning`: RFC 9864 deprecates `EdDSA`), as it does by default.
- jose 6.2.12: HMAC secret imported once (`crypto.subtle.importKey`); `importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`.
- pyjwt 2.15.1: PEM: the key loaded once, with `load_pem_public_key`.
- pyjwt 2.15.1: JWKS document: `PyJWKSet`, picking the key by `get_unverified_header`'s `kid`.
- pyjwt 2.15.1: JWKS URL: `PyJWKClient(cache_keys=True)`, its `ssl_context` trusting the test CA.
