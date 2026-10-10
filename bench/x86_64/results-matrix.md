# JWT decode benchmarks: the full matrix

Generated 2026-10-10 from `bench/results-matrix/` by `bench/compare.py`, on
AMD EPYC 9V74 80-Core Processor (x86_64), Linux.
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

| key source | alg | key | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (jiter) | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | 2.03 (24.4x) | **1.99 (25.0x)** | 2.48 (20.0x) | 4.06 (12.3x) | 3.84 (13.0x) | 4.58 (10.9x) | 6.77 (7.4x) | 27.74 (1.8x) | 25.39 (2.0x) | 49.74 (1.0x) |
| PEM public key | RS256 | RSA 3072 | **35.19 (2.8x)** | 35.80 (2.8x) | 35.43 (2.8x) | 37.46 (2.7x) | 40.97 (2.4x) | 41.80 (2.4x) | 43.01 (2.3x) | 64.41 (1.5x) | 65.06 (1.5x) | 99.63 (1.0x) |
| PEM public key | ES384 | P-384 | 196.41 (2.7x) | **195.50 (2.7x)** | 196.24 (2.7x) | 199.13 (2.6x) | 200.19 (2.6x) | 199.02 (2.6x) | 510.35 (1.0x) | 551.77 (1.0x) | 505.23 (1.0x) | 527.19 (1.0x) |
| PEM public key | EdDSA | Ed25519 | **39.00 (3.8x)** | 39.16 (3.8x) | 39.47 (3.7x) | 41.55 (3.6x) | 40.55 (3.6x) | 41.02 (3.6x) | 57.98 (2.5x) | 82.94 (1.8x) | 130.01 (1.1x) | 147.53 (1.0x) |
| JWKS document | RS256 | RSA 3072 | **35.14 (4.3x)** | 35.15 (4.3x) | 35.40 (4.2x) | 37.32 (4.0x) | 41.61 (3.6x) | 42.26 (3.6x) | 47.40 (3.2x) | 66.79 (2.3x) | 68.36 (2.2x) | 150.36 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | **35.53 (4.4x)** | 35.76 (4.4x) | 36.64 (4.3x) | 38.08 (4.1x) | n/a | n/a | n/a | n/a | n/a | 156.61 (1.0x) |
| JWKS URL, async client | RS256 | RSA 3072 | **35.62 (4.4x)** | 35.69 (4.4x) | 36.18 (4.3x) | 37.63 (4.2x) | n/a | n/a | 95.40 (1.6x) | 68.26 (2.3x) | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (jiter) | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | **1.03 (30.8x)** | 1.11 (28.6x) | 1.18 (27.0x) | 2.25 (14.1x) | 1.98 (16.0x) | 2.32 (13.7x) | 9.43 (3.4x) | 34.18 (0.9x) | 22.55 (1.4x) | 31.84 (1.0x) |
| HS256 | 32 B | typical | 661 | 2.08 (24.2x) | **2.02 (24.9x)** | 2.48 (20.3x) | 4.05 (12.4x) | 3.77 (13.4x) | 4.45 (11.3x) | 10.06 (5.0x) | 34.40 (1.5x) | 25.40 (2.0x) | 50.37 (1.0x) |
| HS256 | 32 B | medium | 2244 | 5.18 (21.7x) | **3.28 (34.2x)** | 6.36 (17.6x) | 6.17 (18.2x) | 7.51 (14.9x) | 11.93 (9.4x) | 13.56 (8.3x) | 36.62 (3.1x) | 38.17 (2.9x) | 112.16 (1.0x) |
| HS256 | 32 B | large | 20884 | 44.52 (20.6x) | **21.84 (42.1x)** | 51.57 (17.8x) | 40.09 (22.9x) | 52.72 (17.4x) | 110.53 (8.3x) | 104.11 (8.8x) | 132.57 (6.9x) | 204.33 (4.5x) | 918.50 (1.0x) |
| HS256 | 64 B | small | 231 | **1.04 (30.6x)** | 1.11 (28.9x) | 1.19 (27.0x) | 2.24 (14.2x) | 1.96 (16.3x) | 2.32 (13.8x) | 4.14 (7.7x) | 24.47 (1.3x) | 20.26 (1.6x) | 31.96 (1.0x) |
| HS256 | 64 B | typical | 661 | 2.03 (24.4x) | **1.99 (25.0x)** | 2.48 (20.0x) | 4.06 (12.3x) | 3.84 (13.0x) | 4.58 (10.9x) | 6.77 (7.4x) | 27.74 (1.8x) | 25.39 (2.0x) | 49.74 (1.0x) |
| HS256 | 64 B | medium | 2244 | 6.21 (18.0x) | **3.29 (33.9x)** | 6.34 (17.6x) | 6.17 (18.1x) | 7.03 (15.9x) | 11.98 (9.3x) | 12.80 (8.7x) | 36.21 (3.1x) | 38.51 (2.9x) | 111.65 (1.0x) |
| HS256 | 64 B | large | 20884 | 44.76 (19.8x) | **21.81 (40.7x)** | 51.94 (17.1x) | 40.14 (22.1x) | 52.75 (16.8x) | 109.85 (8.1x) | 98.58 (9.0x) | 123.99 (7.2x) | 204.59 (4.3x) | 887.21 (1.0x) |
| HS256 | 256 B | small | 231 | **1.03 (32.7x)** | 1.12 (30.0x) | 1.17 (28.6x) | 2.25 (14.9x) | 2.27 (14.7x) | 2.48 (13.5x) | 4.38 (7.7x) | 25.84 (1.3x) | 20.38 (1.6x) | 33.50 (1.0x) |
| HS256 | 256 B | typical | 661 | 2.01 (26.0x) | **1.98 (26.5x)** | 2.48 (21.1x) | 4.05 (12.9x) | 4.07 (12.9x) | 4.72 (11.1x) | 6.84 (7.7x) | 33.57 (1.6x) | 25.50 (2.1x) | 52.34 (1.0x) |
| HS256 | 256 B | medium | 2244 | 5.21 (22.1x) | **3.28 (35.0x)** | 6.36 (18.1x) | 6.18 (18.6x) | 7.33 (15.7x) | 12.19 (9.4x) | 11.92 (9.7x) | 35.59 (3.2x) | 38.58 (3.0x) | 115.00 (1.0x) |
| HS256 | 256 B | large | 20884 | 44.81 (19.9x) | **21.86 (40.8x)** | 51.64 (17.3x) | 40.20 (22.2x) | 52.99 (16.8x) | 109.83 (8.1x) | 97.64 (9.1x) | 126.62 (7.0x) | 205.46 (4.3x) | 891.79 (1.0x) |
| HS256 | 4096 B | small | 231 | **1.04 (63.4x)** | 1.13 (58.3x) | 1.17 (56.4x) | 2.24 (29.3x) | 4.35 (15.1x) | 4.63 (14.2x) | 6.50 (10.1x) | 30.77 (2.1x) | 22.77 (2.9x) | 65.70 (1.0x) |
| HS256 | 4096 B | typical | 661 | 2.05 (41.8x) | **1.99 (43.2x)** | 2.47 (34.7x) | 4.09 (21.0x) | 6.21 (13.8x) | 6.90 (12.4x) | 8.60 (10.0x) | 32.97 (2.6x) | 27.56 (3.1x) | 85.78 (1.0x) |
| HS256 | 4096 B | medium | 2244 | 5.30 (28.2x) | **3.20 (46.7x)** | 6.31 (23.7x) | 6.16 (24.2x) | 9.39 (15.9x) | 14.28 (10.4x) | 14.21 (10.5x) | 39.29 (3.8x) | 40.58 (3.7x) | 149.22 (1.0x) |
| HS256 | 4096 B | large | 20884 | 44.98 (20.5x) | **21.85 (42.2x)** | 51.72 (17.8x) | 40.16 (23.0x) | 55.03 (16.8x) | 112.15 (8.2x) | 98.93 (9.3x) | 127.30 (7.2x) | 207.43 (4.4x) | 922.54 (1.0x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (jiter) | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **16.52 (3.4x)** | 16.61 (3.4x) | 16.74 (3.4x) | 17.73 (3.2x) | 20.17 (2.8x) | 20.19 (2.8x) | 22.45 (2.5x) | 44.90 (1.3x) | 40.48 (1.4x) | 56.24 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 17.56 (4.2x) | **17.47 (4.2x)** | 17.99 (4.1x) | 19.48 (3.8x) | 21.70 (3.4x) | 22.09 (3.4x) | 25.53 (2.9x) | 47.77 (1.6x) | 45.02 (1.6x) | 74.14 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | 20.85 (7.3x) | **18.73 (8.2x)** | 21.93 (7.0x) | 21.65 (7.1x) | 25.30 (6.0x) | 30.08 (5.1x) | 31.06 (4.9x) | 61.38 (2.5x) | 58.54 (2.6x) | 152.79 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | 60.40 (14.9x) | **37.46 (24.0x)** | 67.26 (13.3x) | 55.58 (16.2x) | 71.25 (12.6x) | 142.68 (6.3x) | 120.63 (7.4x) | 139.11 (6.5x) | 228.48 (3.9x) | 897.87 (1.0x) |
| RS256 | RSA 3072 | small | 731 | **34.09 (2.4x)** | 34.16 (2.4x) | 34.28 (2.4x) | 36.20 (2.2x) | 39.40 (2.1x) | 39.76 (2.0x) | 40.48 (2.0x) | 63.67 (1.3x) | 59.88 (1.4x) | 81.38 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **35.19 (2.8x)** | 35.80 (2.8x) | 35.43 (2.8x) | 37.46 (2.7x) | 40.97 (2.4x) | 41.80 (2.4x) | 43.01 (2.3x) | 64.41 (1.5x) | 65.06 (1.5x) | 99.63 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 39.22 (4.1x) | **36.45 (4.4x)** | 39.55 (4.0x) | 39.41 (4.1x) | 44.53 (3.6x) | 49.61 (3.2x) | 49.09 (3.3x) | 71.39 (2.2x) | 79.42 (2.0x) | 159.79 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | 78.70 (11.7x) | **54.93 (16.8x)** | 85.74 (10.8x) | 73.20 (12.6x) | 93.09 (9.9x) | 154.64 (6.0x) | 140.20 (6.6x) | 160.37 (5.8x) | 248.76 (3.7x) | 922.24 (1.0x) |
| RS256 | RSA 4096 | small | 902 | **57.60 (2.0x)** | 57.88 (2.0x) | 57.88 (2.0x) | 58.81 (2.0x) | 65.71 (1.8x) | 67.30 (1.7x) | 65.03 (1.8x) | 88.41 (1.3x) | 86.16 (1.4x) | 116.37 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **58.72 (2.3x)** | 58.89 (2.2x) | 59.14 (2.2x) | 60.99 (2.2x) | 67.45 (2.0x) | 68.25 (1.9x) | 66.71 (2.0x) | 89.90 (1.5x) | 91.26 (1.4x) | 132.25 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 61.93 (3.1x) | **60.05 (3.2x)** | 63.16 (3.1x) | 63.21 (3.1x) | 70.98 (2.7x) | 75.86 (2.6x) | 72.46 (2.7x) | 94.91 (2.1x) | 104.49 (1.9x) | 194.90 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | 103.41 (9.3x) | **78.63 (12.2x)** | 108.90 (8.8x) | 96.98 (9.9x) | 117.68 (8.2x) | 180.57 (5.3x) | 161.75 (5.9x) | 181.32 (5.3x) | 278.74 (3.4x) | 960.13 (1.0x) |
| ES256 | P-256 | small | 304 | **50.59 (1.8x)** | 50.79 (1.8x) | 50.75 (1.8x) | 52.10 (1.8x) | 52.58 (1.8x) | 52.84 (1.7x) | 56.73 (1.6x) | 78.98 (1.2x) | 86.11 (1.1x) | 92.40 (1.0x) |
| ES256 | P-256 | typical | 704 | **51.94 (2.1x)** | 52.01 (2.1x) | 52.50 (2.1x) | 54.15 (2.0x) | 54.61 (2.0x) | 55.05 (2.0x) | 57.60 (1.9x) | 81.19 (1.4x) | 91.37 (1.2x) | 110.80 (1.0x) |
| ES256 | P-256 | medium | 2317 | 55.23 (3.2x) | **53.13 (3.3x)** | 56.20 (3.1x) | 56.06 (3.1x) | 57.86 (3.0x) | 62.83 (2.8x) | 62.84 (2.8x) | 87.30 (2.0x) | 105.59 (1.7x) | 174.67 (1.0x) |
| ES256 | P-256 | large | 20957 | 96.97 (9.8x) | **71.72 (13.2x)** | 101.79 (9.3x) | 90.06 (10.5x) | 103.79 (9.1x) | 168.47 (5.6x) | 153.86 (6.1x) | 170.80 (5.5x) | 275.82 (3.4x) | 945.64 (1.0x) |
| ES384 | P-384 | small | 346 | 193.73 (2.6x) | **193.69 (2.6x)** | 193.82 (2.6x) | 195.32 (2.6x) | 195.77 (2.6x) | 196.61 (2.6x) | 505.22 (1.0x) | 541.41 (0.9x) | 499.77 (1.0x) | 506.28 (1.0x) |
| ES384 | P-384 | typical | 746 | 196.41 (2.7x) | **195.50 (2.7x)** | 196.24 (2.7x) | 199.13 (2.6x) | 200.19 (2.6x) | 199.02 (2.6x) | 510.35 (1.0x) | 551.77 (1.0x) | 505.23 (1.0x) | 527.19 (1.0x) |
| ES384 | P-384 | medium | 2359 | 200.68 (2.9x) | **197.16 (3.0x)** | 200.51 (2.9x) | 200.60 (2.9x) | 202.17 (2.9x) | 207.35 (2.8x) | 517.45 (1.1x) | 559.57 (1.1x) | 523.48 (1.1x) | 590.18 (1.0x) |
| ES384 | P-384 | large | 20999 | 265.48 (5.2x) | **237.23 (5.8x)** | 268.50 (5.1x) | 255.42 (5.4x) | 269.78 (5.1x) | 338.05 (4.1x) | 631.71 (2.2x) | 681.84 (2.0x) | 715.59 (1.9x) | 1380.73 (1.0x) |
| ES512 | P-521 | small | 394 | 337.35 (1.5x) | **337.23 (1.5x)** | 337.31 (1.5x) | 338.07 (1.5x) | n/a | n/a | 1198.20 (0.4x) | 1253.71 (0.4x) | 490.86 (1.0x) | 500.29 (1.0x) |
| ES512 | P-521 | typical | 794 | 335.75 (1.5x) | **335.22 (1.6x)** | 335.93 (1.5x) | 338.14 (1.5x) | n/a | n/a | 1182.22 (0.4x) | 1238.99 (0.4x) | 497.98 (1.0x) | 520.12 (1.0x) |
| ES512 | P-521 | medium | 2407 | 341.85 (1.7x) | **339.51 (1.7x)** | 345.91 (1.7x) | 343.09 (1.7x) | n/a | n/a | 1179.39 (0.5x) | 1242.33 (0.5x) | 512.81 (1.1x) | 585.18 (1.0x) |
| ES512 | P-521 | large | 21047 | 407.65 (3.4x) | **378.44 (3.6x)** | 410.50 (3.3x) | 396.67 (3.4x) | n/a | n/a | 1322.53 (1.0x) | 1388.90 (1.0x) | 708.92 (1.9x) | 1366.49 (1.0x) |
| EdDSA | Ed25519 | small | 306 | **37.50 (3.5x)** | 37.74 (3.5x) | 38.10 (3.4x) | 39.09 (3.4x) | 38.45 (3.4x) | 38.70 (3.4x) | 55.34 (2.4x) | 81.05 (1.6x) | 125.90 (1.0x) | 131.01 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **39.00 (3.8x)** | 39.16 (3.8x) | 39.47 (3.7x) | 41.55 (3.6x) | 40.55 (3.6x) | 41.02 (3.6x) | 57.98 (2.5x) | 82.94 (1.8x) | 130.01 (1.1x) | 147.53 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | 45.24 (4.6x) | **42.25 (5.0x)** | 45.38 (4.6x) | 45.33 (4.6x) | 45.87 (4.6x) | 50.78 (4.1x) | 65.93 (3.2x) | 91.65 (2.3x) | 147.23 (1.4x) | 210.19 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | 104.77 (9.4x) | **80.82 (12.2x)** | 110.70 (8.9x) | 98.99 (10.0x) | 111.64 (8.8x) | 172.43 (5.7x) | 176.57 (5.6x) | 200.66 (4.9x) | 329.91 (3.0x) | 985.43 (1.0x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (jiter) | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **16.57 (5.1x)** | 17.41 (4.9x) | 16.63 (5.1x) | 17.70 (4.8x) | 20.69 (4.1x) | 20.73 (4.1x) | 24.74 (3.4x) | 48.98 (1.7x) | 43.54 (2.0x) | 85.09 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 17.59 (6.6x) | **17.55 (6.7x)** | 18.02 (6.5x) | 19.54 (6.0x) | 22.27 (5.2x) | 22.91 (5.1x) | 27.28 (4.3x) | 50.58 (2.3x) | 48.33 (2.4x) | 116.82 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | 20.87 (11.3x) | **18.75 (12.6x)** | 21.84 (10.8x) | 21.57 (10.9x) | 26.38 (8.9x) | 32.12 (7.3x) | 37.29 (6.3x) | 56.88 (4.1x) | 62.17 (3.8x) | 235.66 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | 61.56 (27.5x) | **37.48 (45.2x)** | 67.96 (24.9x) | 55.80 (30.4x) | 80.36 (21.1x) | 148.06 (11.4x) | 201.54 (8.4x) | 139.75 (12.1x) | 234.79 (7.2x) | 1694.01 (1.0x) |
| RS256 | RSA 3072 | small | 731 | **34.04 (3.4x)** | 34.27 (3.4x) | 34.32 (3.4x) | 34.90 (3.3x) | 40.00 (2.9x) | 40.13 (2.9x) | 42.69 (2.7x) | 65.24 (1.8x) | 62.93 (1.8x) | 115.81 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **35.14 (4.3x)** | 35.15 (4.3x) | 35.40 (4.2x) | 37.32 (4.0x) | 41.61 (3.6x) | 42.26 (3.6x) | 47.40 (3.2x) | 66.79 (2.3x) | 68.36 (2.2x) | 150.36 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 38.34 (6.9x) | **36.33 (7.3x)** | 39.34 (6.8x) | 39.44 (6.7x) | 45.82 (5.8x) | 51.56 (5.2x) | 56.03 (4.7x) | 73.88 (3.6x) | 81.73 (3.3x) | 265.83 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | 79.89 (21.5x) | **54.97 (31.3x)** | 85.97 (20.0x) | 73.30 (23.4x) | 96.72 (17.8x) | 169.60 (10.1x) | 223.37 (7.7x) | 161.63 (10.6x) | 257.83 (6.7x) | 1718.64 (1.0x) |
| RS256 | RSA 4096 | small | 902 | **57.71 (2.7x)** | 57.91 (2.6x) | 57.80 (2.6x) | 58.73 (2.6x) | 67.03 (2.3x) | 66.53 (2.3x) | 67.85 (2.3x) | 90.23 (1.7x) | 92.25 (1.7x) | 153.08 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | **58.86 (3.2x)** | 58.87 (3.2x) | 59.29 (3.2x) | 61.53 (3.0x) | 68.10 (2.7x) | 68.98 (2.7x) | 71.34 (2.6x) | 91.33 (2.0x) | 94.47 (2.0x) | 187.02 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 62.03 (5.0x) | **60.60 (5.1x)** | 63.60 (4.8x) | 63.05 (4.9x) | 72.24 (4.3x) | 77.86 (3.9x) | 81.94 (3.8x) | 99.07 (3.1x) | 109.14 (2.8x) | 307.40 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | 103.94 (16.9x) | **79.01 (22.3x)** | 108.56 (16.2x) | 96.85 (18.2x) | 123.33 (14.3x) | 192.60 (9.1x) | 246.73 (7.1x) | 187.13 (9.4x) | 285.72 (6.2x) | 1761.37 (1.0x) |
| ES256 | P-256 | small | 304 | 53.42 (2.1x) | 50.90 (2.2x) | **50.76 (2.2x)** | 52.12 (2.1x) | 53.14 (2.1x) | 53.34 (2.1x) | 57.34 (1.9x) | 83.16 (1.3x) | 89.87 (1.2x) | 110.77 (1.0x) |
| ES256 | P-256 | typical | 704 | **51.97 (2.9x)** | 52.16 (2.9x) | 52.48 (2.8x) | 54.20 (2.8x) | 55.27 (2.7x) | 55.68 (2.7x) | 61.59 (2.4x) | 85.50 (1.7x) | 95.77 (1.6x) | 149.10 (1.0x) |
| ES256 | P-256 | medium | 2317 | 55.04 (4.8x) | **53.44 (5.0x)** | 56.24 (4.7x) | 56.15 (4.7x) | 61.47 (4.3x) | 64.34 (4.1x) | 71.60 (3.7x) | 90.15 (3.0x) | 109.33 (2.4x) | 266.63 (1.0x) |
| ES256 | P-256 | large | 20957 | 97.37 (17.8x) | **71.84 (24.1x)** | 101.88 (17.0x) | 90.14 (19.2x) | 110.41 (15.7x) | 180.25 (9.6x) | 237.21 (7.3x) | 176.72 (9.8x) | 289.64 (6.0x) | 1734.80 (1.0x) |
| ES384 | P-384 | small | 346 | 194.15 (2.7x) | **193.54 (2.7x)** | 193.89 (2.7x) | 195.20 (2.7x) | 198.00 (2.7x) | 198.63 (2.6x) | 509.99 (1.0x) | 543.65 (1.0x) | 502.73 (1.0x) | 526.03 (1.0x) |
| ES384 | P-384 | typical | 746 | **195.81 (2.9x)** | 196.16 (2.9x) | 196.30 (2.9x) | 198.93 (2.8x) | 200.35 (2.8x) | 200.86 (2.8x) | 518.05 (1.1x) | 546.04 (1.0x) | 508.27 (1.1x) | 561.51 (1.0x) |
| ES384 | P-384 | medium | 2359 | 200.54 (3.4x) | **197.04 (3.5x)** | 200.74 (3.4x) | 200.52 (3.4x) | 203.36 (3.4x) | 209.62 (3.3x) | 527.12 (1.3x) | 557.84 (1.2x) | 524.00 (1.3x) | 683.65 (1.0x) |
| ES384 | P-384 | large | 20999 | 265.64 (8.1x) | **240.43 (9.0x)** | 268.81 (8.0x) | 255.78 (8.4x) | 275.94 (7.8x) | 348.50 (6.2x) | 723.00 (3.0x) | 663.95 (3.2x) | 719.39 (3.0x) | 2154.10 (1.0x) |
| ES512 | P-521 | small | 394 | **336.78 (1.5x)** | 337.50 (1.5x) | 337.60 (1.5x) | 338.81 (1.5x) | n/a | n/a | 1200.98 (0.4x) | 1246.75 (0.4x) | 495.37 (1.1x) | 521.57 (1.0x) |
| ES512 | P-521 | typical | 794 | **335.56 (1.7x)** | 335.90 (1.7x) | 336.04 (1.7x) | 337.55 (1.6x) | n/a | n/a | 1190.93 (0.5x) | 1231.73 (0.5x) | 501.73 (1.1x) | 556.14 (1.0x) |
| ES512 | P-521 | medium | 2407 | 341.38 (2.0x) | **339.54 (2.0x)** | 343.58 (2.0x) | 342.54 (2.0x) | n/a | n/a | 1189.20 (0.6x) | 1228.58 (0.6x) | 524.52 (1.3x) | 676.84 (1.0x) |
| ES512 | P-521 | large | 21047 | 406.28 (5.3x) | **378.86 (5.7x)** | 410.73 (5.2x) | 397.12 (5.4x) | n/a | n/a | 1417.38 (1.5x) | 1385.60 (1.6x) | 716.65 (3.0x) | 2150.67 (1.0x) |
| EdDSA | Ed25519 | small | 306 | **37.47 (4.0x)** | 37.73 (4.0x) | 37.59 (4.0x) | 39.22 (3.8x) | 38.96 (3.8x) | 41.56 (3.6x) | 58.15 (2.6x) | 82.91 (1.8x) | 129.93 (1.1x) | 149.14 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **38.95 (4.7x)** | 39.13 (4.6x) | 39.39 (4.6x) | 41.54 (4.4x) | 41.68 (4.4x) | 41.72 (4.4x) | 61.91 (2.9x) | 83.94 (2.2x) | 132.72 (1.4x) | 181.70 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | 45.03 (6.7x) | **42.13 (7.1x)** | 45.11 (6.7x) | 45.39 (6.6x) | 46.87 (6.4x) | 52.64 (5.7x) | 74.54 (4.0x) | 93.14 (3.2x) | 148.55 (2.0x) | 300.97 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | 105.89 (16.5x) | **80.90 (21.6x)** | 110.64 (15.8x) | 99.11 (17.6x) | 117.77 (14.8x) | 185.35 (9.4x) | 259.63 (6.7x) | 199.43 (8.8x) | 339.07 (5.2x) | 1748.45 (1.0x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (jiter) | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **16.86 (5.4x)** | 16.99 (5.4x) | 17.17 (5.3x) | 18.02 (5.1x) | n/a | n/a | n/a | n/a | n/a | 91.42 (1.0x) |
| RS256 | RSA 2048 | typical | 961 | 17.94 (7.0x) | **17.80 (7.0x)** | 18.57 (6.7x) | 19.85 (6.3x) | n/a | n/a | n/a | n/a | n/a | 124.83 (1.0x) |
| RS256 | RSA 2048 | medium | 2574 | 21.26 (11.4x) | **19.11 (12.7x)** | 22.59 (10.8x) | 21.94 (11.1x) | n/a | n/a | n/a | n/a | n/a | 243.31 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | 61.21 (28.4x) | **37.86 (45.9x)** | 67.97 (25.5x) | 55.87 (31.1x) | n/a | n/a | n/a | n/a | n/a | 1736.22 (1.0x) |
| RS256 | RSA 3072 | small | 731 | **34.41 (3.5x)** | 34.59 (3.5x) | 34.61 (3.5x) | 35.67 (3.4x) | n/a | n/a | n/a | n/a | n/a | 120.98 (1.0x) |
| RS256 | RSA 3072 | typical | 1131 | **35.53 (4.4x)** | 35.76 (4.4x) | 36.64 (4.3x) | 38.08 (4.1x) | n/a | n/a | n/a | n/a | n/a | 156.61 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | 39.31 (7.0x) | **36.81 (7.5x)** | 40.20 (6.8x) | 39.72 (6.9x) | n/a | n/a | n/a | n/a | n/a | 274.96 (1.0x) |
| RS256 | RSA 3072 | large | 21384 | 80.03 (22.4x) | **55.43 (32.3x)** | 86.15 (20.8x) | 73.17 (24.5x) | n/a | n/a | n/a | n/a | n/a | 1789.65 (1.0x) |
| RS256 | RSA 4096 | small | 902 | **58.23 (2.8x)** | 58.46 (2.8x) | 58.39 (2.8x) | 59.24 (2.7x) | n/a | n/a | n/a | n/a | n/a | 161.77 (1.0x) |
| RS256 | RSA 4096 | typical | 1302 | 59.36 (3.3x) | **59.32 (3.3x)** | 59.93 (3.3x) | 62.17 (3.2x) | n/a | n/a | n/a | n/a | n/a | 197.62 (1.0x) |
| RS256 | RSA 4096 | medium | 2915 | 62.56 (5.1x) | **60.51 (5.3x)** | 63.77 (5.0x) | 63.40 (5.0x) | n/a | n/a | n/a | n/a | n/a | 320.00 (1.0x) |
| RS256 | RSA 4096 | large | 21555 | 104.19 (17.4x) | **79.11 (23.0x)** | 110.10 (16.5x) | 96.86 (18.7x) | n/a | n/a | n/a | n/a | n/a | 1815.98 (1.0x) |
| ES256 | P-256 | small | 304 | **51.05 (2.3x)** | 51.41 (2.3x) | 51.54 (2.3x) | 52.50 (2.3x) | n/a | n/a | n/a | n/a | n/a | 118.19 (1.0x) |
| ES256 | P-256 | typical | 704 | **52.49 (3.0x)** | 52.53 (3.0x) | 53.05 (2.9x) | 54.63 (2.8x) | n/a | n/a | n/a | n/a | n/a | 155.14 (1.0x) |
| ES256 | P-256 | medium | 2317 | 55.60 (5.0x) | **53.66 (5.2x)** | 56.99 (4.9x) | 56.46 (4.9x) | n/a | n/a | n/a | n/a | n/a | 278.39 (1.0x) |
| ES256 | P-256 | large | 20957 | 97.85 (18.3x) | **72.23 (24.8x)** | 103.87 (17.2x) | 89.85 (19.9x) | n/a | n/a | n/a | n/a | n/a | 1788.19 (1.0x) |
| ES384 | P-384 | small | 346 | 194.36 (2.7x) | 194.44 (2.7x) | **194.07 (2.7x)** | 195.72 (2.7x) | n/a | n/a | n/a | n/a | n/a | 531.99 (1.0x) |
| ES384 | P-384 | typical | 746 | 196.33 (2.9x) | **196.28 (2.9x)** | 196.87 (2.9x) | 199.18 (2.9x) | n/a | n/a | n/a | n/a | n/a | 568.56 (1.0x) |
| ES384 | P-384 | medium | 2359 | 200.20 (3.5x) | **197.87 (3.5x)** | 201.18 (3.5x) | 200.96 (3.5x) | n/a | n/a | n/a | n/a | n/a | 695.07 (1.0x) |
| ES384 | P-384 | large | 20999 | 266.23 (8.4x) | **237.63 (9.4x)** | 269.54 (8.3x) | 255.46 (8.7x) | n/a | n/a | n/a | n/a | n/a | 2227.97 (1.0x) |
| ES512 | P-521 | small | 394 | **337.78 (1.6x)** | 338.28 (1.6x) | 338.03 (1.6x) | 346.28 (1.5x) | n/a | n/a | n/a | n/a | n/a | 527.82 (1.0x) |
| ES512 | P-521 | typical | 794 | 336.56 (1.7x) | **336.19 (1.7x)** | 337.40 (1.7x) | 345.63 (1.6x) | n/a | n/a | n/a | n/a | n/a | 564.71 (1.0x) |
| ES512 | P-521 | medium | 2407 | 341.93 (2.0x) | **340.58 (2.0x)** | 344.59 (2.0x) | 350.88 (2.0x) | n/a | n/a | n/a | n/a | n/a | 694.46 (1.0x) |
| ES512 | P-521 | large | 21047 | 406.96 (5.5x) | **379.87 (5.9x)** | 412.32 (5.4x) | 407.41 (5.5x) | n/a | n/a | n/a | n/a | n/a | 2232.93 (1.0x) |
| EdDSA | Ed25519 | small | 306 | **37.86 (4.1x)** | 38.27 (4.0x) | 38.03 (4.0x) | 39.59 (3.9x) | n/a | n/a | n/a | n/a | n/a | 153.45 (1.0x) |
| EdDSA | Ed25519 | typical | 706 | **39.49 (4.8x)** | 40.29 (4.7x) | 39.87 (4.7x) | 41.86 (4.5x) | n/a | n/a | n/a | n/a | n/a | 188.00 (1.0x) |
| EdDSA | Ed25519 | medium | 2319 | 45.29 (6.9x) | **42.69 (7.3x)** | 45.70 (6.8x) | 45.76 (6.8x) | n/a | n/a | n/a | n/a | n/a | 311.37 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | 105.76 (17.2x) | **81.36 (22.4x)** | 111.68 (16.3x) | 99.13 (18.4x) | n/a | n/a | n/a | n/a | n/a | 1819.34 (1.0x) |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (jiter) | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **16.95 (5.4x)** | 17.12 (5.3x) | 17.18 (5.3x) | 18.06 (5.1x) | n/a | n/a | 70.86 (1.3x) | 48.98 (1.9x) | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | 18.11 (6.9x) | **17.93 (7.0x)** | 18.51 (6.7x) | 19.88 (6.3x) | n/a | n/a | 60.90 (2.0x) | 48.31 (2.6x) | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | 21.26 (11.4x) | **19.24 (12.6x)** | 22.30 (10.9x) | 22.11 (11.0x) | n/a | n/a | 63.20 (3.8x) | 55.39 (4.4x) | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | 61.29 (28.3x) | **38.03 (45.7x)** | 67.75 (25.6x) | 55.64 (31.2x) | n/a | n/a | 160.21 (10.8x) | 141.35 (12.3x) | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | **34.48 (3.5x)** | 34.75 (3.5x) | 34.81 (3.5x) | 35.80 (3.4x) | n/a | n/a | 91.17 (1.3x) | 66.17 (1.8x) | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | **35.62 (4.4x)** | 35.69 (4.4x) | 36.18 (4.3x) | 37.63 (4.2x) | n/a | n/a | 95.40 (1.6x) | 68.26 (2.3x) | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | 39.26 (7.0x) | **37.02 (7.4x)** | 40.09 (6.9x) | 39.76 (6.9x) | n/a | n/a | 99.77 (2.8x) | 74.57 (3.7x) | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | 81.61 (21.9x) | **55.61 (32.2x)** | 86.31 (20.7x) | 73.92 (24.2x) | n/a | n/a | 202.78 (8.8x) | 164.62 (10.9x) | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | 58.44 (2.8x) | 58.42 (2.8x) | **58.29 (2.8x)** | 59.57 (2.7x) | n/a | n/a | 140.66 (1.2x) | 89.63 (1.8x) | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | **59.33 (3.3x)** | 59.41 (3.3x) | 59.88 (3.3x) | 61.95 (3.2x) | n/a | n/a | 141.36 (1.4x) | 92.77 (2.1x) | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | 62.78 (5.1x) | **60.60 (5.3x)** | 63.82 (5.0x) | 63.58 (5.0x) | n/a | n/a | 149.25 (2.1x) | 98.50 (3.2x) | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | 107.06 (17.0x) | **79.79 (22.8x)** | 110.06 (16.5x) | 96.91 (18.7x) | n/a | n/a | 247.05 (7.4x) | 202.14 (9.0x) | n/a | n/a |
| ES256 | P-256 | small | 304 | **51.21 (2.3x)** | 51.51 (2.3x) | 51.31 (2.3x) | 52.58 (2.2x) | n/a | n/a | 4041.29 (0.03x) | 81.56 (1.4x) | n/a | n/a |
| ES256 | P-256 | typical | 704 | **52.58 (3.0x)** | 52.60 (2.9x) | 53.07 (2.9x) | 54.63 (2.8x) | n/a | n/a | 4007.20 (0.04x) | 84.20 (1.8x) | n/a | n/a |
| ES256 | P-256 | medium | 2317 | 55.77 (5.0x) | **53.76 (5.2x)** | 56.74 (4.9x) | 56.52 (4.9x) | n/a | n/a | 4032.55 (0.07x) | 91.38 (3.0x) | n/a | n/a |
| ES256 | P-256 | large | 20957 | 98.80 (18.1x) | **72.30 (24.7x)** | 103.19 (17.3x) | 90.74 (19.7x) | n/a | n/a | 4051.14 (0.4x) | 187.01 (9.6x) | n/a | n/a |
| ES384 | P-384 | small | 346 | 194.41 (2.7x) | **194.31 (2.7x)** | 194.37 (2.7x) | 195.68 (2.7x) | n/a | n/a | 20481.30 (0.03x) | 545.03 (1.0x) | n/a | n/a |
| ES384 | P-384 | typical | 746 | 197.08 (2.9x) | **197.02 (2.9x)** | 197.28 (2.9x) | 199.26 (2.9x) | n/a | n/a | 20569.97 (0.03x) | 550.49 (1.0x) | n/a | n/a |
| ES384 | P-384 | medium | 2359 | 200.26 (3.5x) | **197.84 (3.5x)** | 201.24 (3.5x) | 201.03 (3.5x) | n/a | n/a | 20535.86 (0.03x) | 561.07 (1.2x) | n/a | n/a |
| ES384 | P-384 | large | 20999 | 267.11 (8.3x) | **238.59 (9.3x)** | 270.24 (8.2x) | 256.13 (8.7x) | n/a | n/a | 20596.10 (0.1x) | 679.30 (3.3x) | n/a | n/a |
| ES512 | P-521 | small | 394 | **337.71 (1.6x)** | 338.00 (1.6x) | 337.93 (1.6x) | 340.14 (1.6x) | n/a | n/a | 48832.45 (0.01x) | 1245.81 (0.4x) | n/a | n/a |
| ES512 | P-521 | typical | 794 | 336.56 (1.7x) | **336.09 (1.7x)** | 337.14 (1.7x) | 339.22 (1.7x) | n/a | n/a | 48909.48 (0.01x) | 1245.70 (0.5x) | n/a | n/a |
| ES512 | P-521 | medium | 2407 | 343.01 (2.0x) | **340.97 (2.0x)** | 343.98 (2.0x) | 343.60 (2.0x) | n/a | n/a | 48605.80 (0.01x) | 1242.19 (0.6x) | n/a | n/a |
| ES512 | P-521 | large | 21047 | 407.93 (5.5x) | **379.90 (5.9x)** | 412.62 (5.4x) | 398.17 (5.6x) | n/a | n/a | 48263.48 (0.05x) | 1395.13 (1.6x) | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | **38.05 (4.0x)** | 38.33 (4.0x) | 38.07 (4.0x) | 39.69 (3.9x) | n/a | n/a | n/a | 81.98 (1.9x) | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | 39.95 (4.7x) | **39.76 (4.7x)** | 39.92 (4.7x) | 42.01 (4.5x) | n/a | n/a | n/a | 87.17 (2.2x) | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | 44.80 (6.9x) | **42.80 (7.3x)** | 45.70 (6.8x) | 45.86 (6.8x) | n/a | n/a | n/a | 93.66 (3.3x) | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | 106.31 (17.1x) | **81.48 (22.3x)** | 111.66 (16.3x) | 99.25 (18.3x) | n/a | n/a | n/a | 208.51 (8.7x) | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.1.1 → dict (msgspec) | ryjwt 0.1.1 → Struct | ryjwt 0.1.1 → dict (jiter) | ryjwt 0.1.1 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) → struct | jsonwebtoken 11.1.0 (aws-lc-rs) → Value | fast-jwt 6.3.3 | jose 6.2.12 | joserfc 1.7.5 | pyjwt 2.15.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 2.0 | 2.5 | 2.3 | 2.4 | n/a | n/a | n/a | n/a | n/a | 2.0 |
| JWKS URL, async client | 2.0 | 2.6 | 2.3 | 2.4 | n/a | n/a | 2.0 | 1.2 | n/a | n/a |

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

- ryjwt 0.1.1 → dict (msgspec): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → dict (msgspec): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.1 → Struct: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.1 → dict (jiter): `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → dict (jiter): JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.1 → BaseModel: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.1 → BaseModel: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`).
- jsonwebtoken 11.1.0 (aws-lc-rs) → struct: struct: claims decoded into typed structs with the fields ryjwt's msgspec lane decodes; other claims ignored.
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
