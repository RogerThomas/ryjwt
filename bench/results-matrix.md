# JWT decode benchmarks: the full matrix

Generated 2026-10-09 from `bench/results-matrix/` by `bench/compare.py`, on
INTEL(R) XEON(R) PLATINUM 8573C (x86_64), Linux.
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

| key source | alg | key | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HMAC secret | HS256 | 64 B | **2.21 (28.6x)** | 2.35 (26.8x) | 4.65 (13.5x) | 5.20 (12.1x) | 6.29 (10.0x) | 19.43 (3.2x) | 29.38 (2.1x) | 34.28 (1.8x) | 62.98 (1.0x) | 106.37 (0.6x) |
| PEM public key | RS256 | RSA 3072 | **40.83 (2.8x)** | 41.01 (2.8x) | 43.34 (2.6x) | 47.77 (2.4x) | 46.82 (2.4x) | 59.51 (1.9x) | 77.01 (1.5x) | 81.49 (1.4x) | 113.53 (1.0x) | 150.87 (0.8x) |
| PEM public key | ES384 | P-384 | 222.35 (2.0x) | **222.03 (2.0x)** | 222.88 (2.0x) | 223.90 (2.0x) | 451.05 (1.0x) | 472.08 (0.9x) | 416.45 (1.1x) | 428.21 (1.0x) | 445.67 (1.0x) | 493.59 (0.9x) |
| PEM public key | EdDSA | Ed25519 | **42.60 (3.8x)** | 42.82 (3.7x) | 45.37 (3.5x) | 44.33 (3.6x) | 53.99 (3.0x) | 69.34 (2.3x) | n/a | 147.68 (1.1x) | 160.01 (1.0x) | 212.41 (0.8x) |
| JWKS document | RS256 | RSA 3072 | **40.71 (4.1x)** | 40.87 (4.1x) | 43.09 (3.8x) | 48.33 (3.4x) | 51.83 (3.2x) | 60.15 (2.8x) | 84.49 (2.0x) | 87.71 (1.9x) | 165.56 (1.0x) | 167.33 (1.0x) |
| JWKS URL, sync client | RS256 | RSA 3072 | **41.14 (4.3x)** | 41.63 (4.2x) | 43.83 (4.0x) | n/a | n/a | n/a | n/a | n/a | 176.56 (1.0x) | n/a |
| JWKS URL, async client | RS256 | RSA 3072 | **40.70 (4.3x)** | 41.73 (4.2x) | 43.90 (4.0x) | n/a | 113.90 (1.6x) | 60.19 (2.9x) | n/a | n/a | n/a | n/a |

## HMAC secret

| alg | key | payload | token B | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| HS256 | 32 B | small | 231 | 1.18 (35.5x) | **1.16 (36.2x)** | 2.40 (17.5x) | 2.48 (16.9x) | 3.88 (10.8x) | 17.19 (2.4x) | 21.84 (1.9x) | 25.51 (1.6x) | 41.93 (1.0x) | 95.90 (0.4x) |
| HS256 | 32 B | typical | 661 | **2.23 (28.1x)** | 2.35 (26.8x) | 4.65 (13.5x) | 5.12 (12.3x) | 6.27 (10.0x) | 19.93 (3.2x) | 29.11 (2.2x) | 33.81 (1.9x) | 62.88 (1.0x) | 105.06 (0.6x) |
| HS256 | 32 B | medium | 2244 | **3.87 (33.6x)** | 5.89 (22.1x) | 7.11 (18.3x) | 13.41 (9.7x) | 12.74 (10.2x) | 27.92 (4.7x) | 40.82 (3.2x) | 53.27 (2.4x) | 130.23 (1.0x) | 125.47 (1.0x) |
| HS256 | 32 B | large | 20884 | **28.09 (31.4x)** | 53.47 (16.5x) | 48.65 (18.1x) | 137.12 (6.4x) | 133.47 (6.6x) | 137.66 (6.4x) | 194.93 (4.5x) | 279.21 (3.2x) | 882.86 (1.0x) | 358.60 (2.5x) |
| HS256 | 64 B | small | 231 | 1.19 (36.0x) | **1.17 (36.5x)** | 2.43 (17.6x) | 2.53 (16.9x) | 3.84 (11.1x) | 15.78 (2.7x) | 21.83 (2.0x) | 26.04 (1.6x) | 42.76 (1.0x) | 95.94 (0.4x) |
| HS256 | 64 B | typical | 661 | **2.21 (28.6x)** | 2.35 (26.8x) | 4.65 (13.5x) | 5.20 (12.1x) | 6.29 (10.0x) | 19.43 (3.2x) | 29.38 (2.1x) | 34.28 (1.8x) | 62.98 (1.0x) | 106.37 (0.6x) |
| HS256 | 64 B | medium | 2244 | **3.88 (33.5x)** | 5.86 (22.2x) | 7.12 (18.2x) | 13.45 (9.7x) | 12.56 (10.3x) | 27.25 (4.8x) | 40.74 (3.2x) | 52.44 (2.5x) | 129.84 (1.0x) | 124.51 (1.0x) |
| HS256 | 64 B | large | 20884 | **28.11 (31.5x)** | 54.82 (16.2x) | 48.87 (18.1x) | 136.70 (6.5x) | 134.31 (6.6x) | 137.83 (6.4x) | 194.45 (4.6x) | 273.61 (3.2x) | 886.82 (1.0x) | 361.67 (2.5x) |
| HS256 | 256 B | small | 231 | 1.17 (38.1x) | **1.15 (38.8x)** | 2.43 (18.4x) | 2.70 (16.5x) | 4.02 (11.1x) | 16.83 (2.7x) | 22.15 (2.0x) | 26.17 (1.7x) | 44.63 (1.0x) | 96.38 (0.5x) |
| HS256 | 256 B | typical | 661 | **2.24 (29.6x)** | 2.35 (28.3x) | 4.69 (14.2x) | 5.41 (12.3x) | 6.56 (10.1x) | 18.69 (3.6x) | 29.89 (2.2x) | 34.77 (1.9x) | 66.44 (1.0x) | 106.71 (0.6x) |
| HS256 | 256 B | medium | 2244 | **3.86 (34.3x)** | 5.97 (22.2x) | 7.16 (18.5x) | 13.63 (9.7x) | 12.93 (10.2x) | 28.03 (4.7x) | 40.78 (3.2x) | 53.56 (2.5x) | 132.37 (1.0x) | 125.66 (1.1x) |
| HS256 | 256 B | large | 20884 | **28.14 (31.6x)** | 53.92 (16.5x) | 48.67 (18.3x) | 136.10 (6.5x) | 133.89 (6.6x) | 136.80 (6.5x) | 194.17 (4.6x) | 279.47 (3.2x) | 888.20 (1.0x) | 363.35 (2.4x) |
| HS256 | 4096 B | small | 231 | 1.19 (75.8x) | **1.17 (77.1x)** | 2.40 (37.5x) | 5.32 (17.0x) | 6.81 (13.2x) | 20.32 (4.4x) | 24.75 (3.6x) | 28.77 (3.1x) | 90.20 (1.0x) | 108.54 (0.8x) |
| HS256 | 4096 B | typical | 661 | **2.22 (50.1x)** | 2.35 (47.3x) | 4.67 (23.8x) | 8.03 (13.8x) | 9.31 (11.9x) | 23.10 (4.8x) | 32.33 (3.4x) | 37.07 (3.0x) | 111.11 (1.0x) | 118.67 (0.9x) |
| HS256 | 4096 B | medium | 2244 | **3.88 (45.9x)** | 5.95 (29.9x) | 7.22 (24.6x) | 16.13 (11.0x) | 15.46 (11.5x) | 30.84 (5.8x) | 43.58 (4.1x) | 55.57 (3.2x) | 177.84 (1.0x) | 136.98 (1.3x) |
| HS256 | 4096 B | large | 20884 | **28.16 (33.0x)** | 53.69 (17.3x) | 48.55 (19.1x) | 140.12 (6.6x) | 138.15 (6.7x) | 136.57 (6.8x) | 196.79 (4.7x) | 281.24 (3.3x) | 928.65 (1.0x) | 373.37 (2.5x) |

## PEM public key

| alg | key | payload | token B | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 19.12 (3.4x) | **19.02 (3.5x)** | 20.52 (3.2x) | 23.28 (2.8x) | 25.30 (2.6x) | 36.39 (1.8x) | 46.95 (1.4x) | 50.87 (1.3x) | 65.66 (1.0x) | 120.58 (0.5x) |
| RS256 | RSA 2048 | typical | 961 | **20.23 (4.1x)** | 20.52 (4.1x) | 22.97 (3.6x) | 25.46 (3.3x) | 25.75 (3.2x) | 39.17 (2.1x) | 53.60 (1.6x) | 58.52 (1.4x) | 83.62 (1.0x) | 130.25 (0.6x) |
| RS256 | RSA 2048 | medium | 2574 | **22.06 (6.9x)** | 24.14 (6.3x) | 25.50 (5.9x) | 34.47 (4.4x) | 32.10 (4.7x) | 46.15 (3.3x) | 65.57 (2.3x) | 77.52 (2.0x) | 151.33 (1.0x) | 149.00 (1.0x) |
| RS256 | RSA 2048 | large | 21214 | **46.48 (19.5x)** | 71.68 (12.6x) | 67.08 (13.5x) | 159.43 (5.7x) | 152.60 (5.9x) | 158.09 (5.7x) | 219.04 (4.1x) | 306.98 (3.0x) | 905.60 (1.0x) | 385.86 (2.3x) |
| RS256 | RSA 3072 | small | 731 | 39.66 (2.4x) | **39.53 (2.4x)** | 40.88 (2.3x) | 45.60 (2.1x) | 43.95 (2.2x) | 57.07 (1.7x) | 69.70 (1.4x) | 73.78 (1.3x) | 94.65 (1.0x) | 142.52 (0.7x) |
| RS256 | RSA 3072 | typical | 1131 | **40.83 (2.8x)** | 41.01 (2.8x) | 43.34 (2.6x) | 47.77 (2.4x) | 46.82 (2.4x) | 59.51 (1.9x) | 77.01 (1.5x) | 81.49 (1.4x) | 113.53 (1.0x) | 150.87 (0.8x) |
| RS256 | RSA 3072 | medium | 2744 | **42.56 (4.3x)** | 44.49 (4.1x) | 45.86 (4.0x) | 56.65 (3.2x) | 53.56 (3.4x) | 67.96 (2.7x) | 88.08 (2.1x) | 100.19 (1.8x) | 182.28 (1.0x) | 170.05 (1.1x) |
| RS256 | RSA 3072 | large | 21384 | **66.63 (14.1x)** | 91.91 (10.2x) | 86.88 (10.8x) | 180.76 (5.2x) | 176.32 (5.3x) | 180.24 (5.2x) | 241.70 (3.9x) | 328.90 (2.9x) | 938.27 (1.0x) | 407.37 (2.3x) |
| RS256 | RSA 4096 | small | 902 | 67.86 (2.0x) | **67.33 (2.0x)** | 69.20 (1.9x) | 76.60 (1.7x) | 73.39 (1.8x) | 86.67 (1.5x) | 101.70 (1.3x) | 105.28 (1.3x) | 133.67 (1.0x) | 173.42 (0.8x) |
| RS256 | RSA 4096 | typical | 1302 | **69.23 (2.2x)** | 69.32 (2.2x) | 71.62 (2.1x) | 78.97 (1.9x) | 76.33 (2.0x) | 89.33 (1.7x) | 108.64 (1.4x) | 113.66 (1.3x) | 151.05 (1.0x) | 182.40 (0.8x) |
| RS256 | RSA 4096 | medium | 2915 | **70.95 (3.1x)** | 72.61 (3.0x) | 74.45 (2.9x) | 87.31 (2.5x) | 81.88 (2.7x) | 97.99 (2.2x) | 120.58 (1.8x) | 131.41 (1.7x) | 219.09 (1.0x) | 204.08 (1.1x) |
| RS256 | RSA 4096 | large | 21555 | **95.26 (10.2x)** | 120.75 (8.0x) | 115.64 (8.4x) | 213.70 (4.5x) | 204.16 (4.7x) | 208.40 (4.6x) | 274.65 (3.5x) | 358.97 (2.7x) | 967.11 (1.0x) | 441.01 (2.2x) |
| ES256 | P-256 | small | 304 | 65.18 (1.8x) | **64.52 (1.8x)** | 66.24 (1.8x) | 66.98 (1.7x) | 69.26 (1.7x) | 82.85 (1.4x) | 104.61 (1.1x) | 112.33 (1.0x) | 116.13 (1.0x) | 179.56 (0.6x) |
| ES256 | P-256 | typical | 704 | 66.38 (2.0x) | **66.23 (2.0x)** | 68.89 (2.0x) | 69.39 (1.9x) | 70.71 (1.9x) | 86.01 (1.6x) | 111.59 (1.2x) | 119.67 (1.1x) | 135.23 (1.0x) | 187.61 (0.7x) |
| ES256 | P-256 | medium | 2317 | **67.79 (3.0x)** | 69.91 (2.9x) | 70.68 (2.9x) | 78.00 (2.6x) | 77.22 (2.6x) | 92.69 (2.2x) | 123.85 (1.6x) | 138.94 (1.5x) | 203.44 (1.0x) | 208.46 (1.0x) |
| ES256 | P-256 | large | 20957 | **92.49 (10.4x)** | 118.00 (8.2x) | 113.11 (8.5x) | 204.60 (4.7x) | 199.11 (4.8x) | 197.90 (4.9x) | 278.86 (3.4x) | 369.32 (2.6x) | 962.02 (1.0x) | 444.84 (2.2x) |
| ES384 | P-384 | small | 346 | 219.89 (1.9x) | **218.40 (2.0x)** | 219.26 (1.9x) | 220.80 (1.9x) | 450.11 (0.9x) | 468.29 (0.9x) | 408.95 (1.0x) | 421.31 (1.0x) | 426.66 (1.0x) | 481.83 (0.9x) |
| ES384 | P-384 | typical | 746 | 222.35 (2.0x) | **222.03 (2.0x)** | 222.88 (2.0x) | 223.90 (2.0x) | 451.05 (1.0x) | 472.08 (0.9x) | 416.45 (1.1x) | 428.21 (1.0x) | 445.67 (1.0x) | 493.59 (0.9x) |
| ES384 | P-384 | medium | 2359 | **223.19 (2.3x)** | 225.72 (2.3x) | 225.48 (2.3x) | 231.50 (2.2x) | 460.88 (1.1x) | 483.39 (1.1x) | 429.88 (1.2x) | 445.08 (1.2x) | 514.73 (1.0x) | 518.08 (1.0x) |
| ES384 | P-384 | large | 20999 | **268.40 (4.8x)** | 294.85 (4.4x) | 288.05 (4.5x) | 381.56 (3.4x) | 595.25 (2.2x) | 609.20 (2.1x) | 603.94 (2.1x) | 686.26 (1.9x) | 1287.41 (1.0x) | 771.43 (1.7x) |
| ES512 | P-521 | small | 394 | 352.11 (1.5x) | 347.09 (1.5x) | **346.15 (1.5x)** | n/a | 1096.24 (0.5x) | 1137.99 (0.5x) | 495.41 (1.0x) | 507.32 (1.0x) | 514.21 (1.0x) | 571.56 (0.9x) |
| ES512 | P-521 | typical | 794 | 349.57 (1.5x) | **345.59 (1.5x)** | 347.26 (1.5x) | n/a | 1080.77 (0.5x) | 1131.62 (0.5x) | 505.59 (1.1x) | 514.28 (1.0x) | 533.26 (1.0x) | 577.38 (0.9x) |
| ES512 | P-521 | medium | 2407 | 353.23 (1.7x) | 351.32 (1.7x) | **351.05 (1.7x)** | n/a | 1079.20 (0.6x) | 1126.00 (0.5x) | 518.90 (1.2x) | 534.79 (1.1x) | 602.70 (1.0x) | 602.43 (1.0x) |
| ES512 | P-521 | large | 21047 | **395.61 (3.5x)** | 419.13 (3.3x) | 411.72 (3.3x) | n/a | 1255.72 (1.1x) | 1284.72 (1.1x) | 690.07 (2.0x) | 780.33 (1.8x) | 1378.86 (1.0x) | 857.31 (1.6x) |
| EdDSA | Ed25519 | small | 306 | 41.19 (3.5x) | **41.08 (3.5x)** | 42.38 (3.4x) | 41.53 (3.4x) | 51.88 (2.8x) | 66.90 (2.1x) | n/a | 140.38 (1.0x) | 143.08 (1.0x) | 205.81 (0.7x) |
| EdDSA | Ed25519 | typical | 706 | **42.60 (3.8x)** | 42.82 (3.7x) | 45.37 (3.5x) | 44.33 (3.6x) | 53.99 (3.0x) | 69.34 (2.3x) | n/a | 147.68 (1.1x) | 160.01 (1.0x) | 212.41 (0.8x) |
| EdDSA | Ed25519 | medium | 2319 | **46.43 (5.0x)** | 48.40 (4.8x) | 49.19 (4.7x) | 54.95 (4.2x) | 64.21 (3.6x) | 79.55 (2.9x) | n/a | 167.31 (1.4x) | 231.15 (1.0x) | 235.56 (1.0x) |
| EdDSA | Ed25519 | large | 20959 | **89.50 (11.2x)** | 115.63 (8.7x) | 110.26 (9.1x) | 198.11 (5.1x) | 204.21 (4.9x) | 206.26 (4.9x) | n/a | 411.58 (2.4x) | 1001.72 (1.0x) | 488.91 (2.0x) |

## JWKS document

| alg | key | payload | token B | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **19.14 (5.0x)** | 19.25 (5.0x) | 20.63 (4.7x) | 23.74 (4.1x) | 26.37 (3.7x) | 37.50 (2.6x) | 53.87 (1.8x) | 57.28 (1.7x) | 96.57 (1.0x) | 135.87 (0.7x) |
| RS256 | RSA 2048 | typical | 961 | **20.45 (6.4x)** | 20.64 (6.3x) | 23.05 (5.6x) | 26.05 (5.0x) | 30.06 (4.3x) | 39.42 (3.3x) | 61.97 (2.1x) | 64.67 (2.0x) | 129.88 (1.0x) | 144.62 (0.9x) |
| RS256 | RSA 2048 | medium | 2574 | **22.18 (11.6x)** | 24.13 (10.7x) | 25.43 (10.2x) | 35.93 (7.2x) | 41.99 (6.2x) | 47.39 (5.5x) | 76.85 (3.4x) | 83.34 (3.1x) | 258.40 (1.0x) | 166.13 (1.6x) |
| RS256 | RSA 2048 | large | 21214 | **46.41 (36.0x)** | 72.01 (23.2x) | 66.82 (25.0x) | 171.45 (9.7x) | 265.00 (6.3x) | 149.85 (11.1x) | 264.76 (6.3x) | 311.00 (5.4x) | 1669.21 (1.0x) | 400.92 (4.2x) |
| RS256 | RSA 3072 | small | 731 | **39.66 (3.3x)** | 39.72 (3.3x) | 40.86 (3.2x) | 46.06 (2.9x) | 47.11 (2.8x) | 58.45 (2.3x) | 76.76 (1.7x) | 79.70 (1.7x) | 132.37 (1.0x) | 158.31 (0.8x) |
| RS256 | RSA 3072 | typical | 1131 | **40.71 (4.1x)** | 40.87 (4.1x) | 43.09 (3.8x) | 48.33 (3.4x) | 51.83 (3.2x) | 60.15 (2.8x) | 84.49 (2.0x) | 87.71 (1.9x) | 165.56 (1.0x) | 167.33 (1.0x) |
| RS256 | RSA 3072 | medium | 2744 | **42.46 (6.9x)** | 44.56 (6.6x) | 45.65 (6.4x) | 58.16 (5.1x) | 63.31 (4.6x) | 68.11 (4.3x) | 99.67 (2.9x) | 107.13 (2.7x) | 293.73 (1.0x) | 188.13 (1.6x) |
| RS256 | RSA 3072 | large | 21384 | **66.47 (25.7x)** | 92.74 (18.5x) | 87.48 (19.6x) | 195.06 (8.8x) | 289.03 (5.9x) | 175.55 (9.7x) | 287.04 (6.0x) | 331.92 (5.2x) | 1711.32 (1.0x) | 425.59 (4.0x) |
| RS256 | RSA 4096 | small | 902 | 68.03 (2.6x) | **67.98 (2.6x)** | 69.42 (2.6x) | 76.78 (2.3x) | 75.65 (2.4x) | 87.64 (2.0x) | 109.49 (1.6x) | 111.01 (1.6x) | 178.16 (1.0x) | 190.25 (0.9x) |
| RS256 | RSA 4096 | typical | 1302 | **69.13 (3.0x)** | 69.17 (3.0x) | 71.32 (2.9x) | 79.56 (2.6x) | 79.91 (2.6x) | 89.49 (2.3x) | 117.26 (1.8x) | 118.21 (1.8x) | 210.00 (1.0x) | 199.56 (1.1x) |
| RS256 | RSA 4096 | medium | 2915 | **70.97 (4.8x)** | 72.93 (4.6x) | 74.38 (4.5x) | 89.34 (3.8x) | 92.06 (3.7x) | 98.37 (3.4x) | 131.70 (2.6x) | 137.07 (2.5x) | 337.69 (1.0x) | 221.28 (1.5x) |
| RS256 | RSA 4096 | large | 21555 | **95.27 (18.4x)** | 121.22 (14.5x) | 115.81 (15.1x) | 224.82 (7.8x) | 318.10 (5.5x) | 199.80 (8.8x) | 318.81 (5.5x) | 361.87 (4.8x) | 1752.28 (1.0x) | 461.39 (3.8x) |
| ES256 | P-256 | small | 304 | 65.23 (2.1x) | **64.68 (2.1x)** | 65.84 (2.1x) | 67.03 (2.0x) | 70.36 (1.9x) | 83.40 (1.6x) | 111.06 (1.2x) | 117.35 (1.2x) | 136.67 (1.0x) | 193.17 (0.7x) |
| ES256 | P-256 | typical | 704 | **66.56 (2.6x)** | 66.75 (2.6x) | 68.53 (2.5x) | 70.02 (2.4x) | 74.47 (2.3x) | 86.43 (2.0x) | 118.79 (1.4x) | 124.84 (1.4x) | 170.89 (1.0x) | 204.10 (0.8x) |
| ES256 | P-256 | medium | 2317 | **67.95 (4.4x)** | 69.70 (4.3x) | 70.99 (4.2x) | 79.28 (3.8x) | 86.27 (3.5x) | 92.53 (3.2x) | 134.52 (2.2x) | 143.77 (2.1x) | 299.85 (1.0x) | 226.55 (1.3x) |
| ES256 | P-256 | large | 20957 | **92.76 (18.5x)** | 117.72 (14.6x) | 112.26 (15.3x) | 215.91 (7.9x) | 309.73 (5.5x) | 198.70 (8.6x) | 323.19 (5.3x) | 370.23 (4.6x) | 1715.29 (1.0x) | 459.50 (3.7x) |
| ES384 | P-384 | small | 346 | 220.26 (2.0x) | 219.43 (2.0x) | **218.41 (2.0x)** | 220.75 (2.0x) | 450.36 (1.0x) | 472.57 (0.9x) | 416.74 (1.1x) | 420.72 (1.1x) | 444.72 (1.0x) | 499.54 (0.9x) |
| ES384 | P-384 | typical | 746 | **221.32 (2.2x)** | 221.40 (2.2x) | 221.75 (2.2x) | 224.06 (2.2x) | 453.72 (1.1x) | 471.19 (1.0x) | 425.78 (1.1x) | 427.28 (1.1x) | 481.96 (1.0x) | 507.95 (0.9x) |
| ES384 | P-384 | medium | 2359 | **224.12 (2.7x)** | 224.71 (2.7x) | 224.55 (2.7x) | 233.03 (2.6x) | 464.55 (1.3x) | 481.83 (1.3x) | 439.76 (1.4x) | 450.51 (1.4x) | 609.33 (1.0x) | 532.20 (1.1x) |
| ES384 | P-384 | large | 20999 | **268.50 (7.6x)** | 295.08 (6.9x) | 286.37 (7.1x) | 392.38 (5.2x) | 706.56 (2.9x) | 605.85 (3.4x) | 647.23 (3.1x) | 687.52 (3.0x) | 2038.03 (1.0x) | 791.68 (2.6x) |
| ES512 | P-521 | small | 394 | 352.28 (1.5x) | 346.04 (1.5x) | **345.86 (1.5x)** | n/a | 1099.87 (0.5x) | 1145.88 (0.5x) | 504.62 (1.1x) | 506.12 (1.1x) | 534.65 (1.0x) | 586.67 (0.9x) |
| ES512 | P-521 | typical | 794 | 349.39 (1.6x) | **344.59 (1.7x)** | 346.74 (1.7x) | n/a | 1086.23 (0.5x) | 1123.32 (0.5x) | 513.52 (1.1x) | 514.69 (1.1x) | 573.21 (1.0x) | 596.22 (1.0x) |
| ES512 | P-521 | medium | 2407 | 354.10 (2.0x) | **351.00 (2.0x)** | 351.94 (2.0x) | n/a | 1088.35 (0.6x) | 1127.25 (0.6x) | 526.35 (1.3x) | 534.76 (1.3x) | 700.92 (1.0x) | 620.58 (1.1x) |
| ES512 | P-521 | large | 21047 | **394.82 (5.4x)** | 420.71 (5.1x) | 411.90 (5.2x) | n/a | 1363.01 (1.6x) | 1292.92 (1.6x) | 734.52 (2.9x) | 778.23 (2.7x) | 2129.61 (1.0x) | 880.43 (2.4x) |
| EdDSA | Ed25519 | small | 306 | 41.18 (4.0x) | **41.01 (4.0x)** | 42.35 (3.9x) | 42.15 (3.9x) | 53.84 (3.0x) | 68.21 (2.4x) | n/a | 143.92 (1.1x) | 164.18 (1.0x) | 220.42 (0.7x) |
| EdDSA | Ed25519 | typical | 706 | **42.84 (4.6x)** | 43.05 (4.5x) | 45.10 (4.3x) | 45.19 (4.3x) | 57.52 (3.4x) | 69.56 (2.8x) | n/a | 150.80 (1.3x) | 195.22 (1.0x) | 229.12 (0.9x) |
| EdDSA | Ed25519 | medium | 2319 | **46.08 (7.1x)** | 48.47 (6.7x) | 49.69 (6.6x) | 56.44 (5.8x) | 73.08 (4.5x) | 79.85 (4.1x) | n/a | 171.13 (1.9x) | 326.15 (1.0x) | 250.31 (1.3x) |
| EdDSA | Ed25519 | large | 20959 | **89.79 (19.6x)** | 116.17 (15.1x) | 110.13 (16.0x) | 207.91 (8.5x) | 317.05 (5.5x) | 206.27 (8.5x) | n/a | 411.43 (4.3x) | 1757.71 (1.0x) | 505.02 (3.5x) |

## JWKS URL, sync client

| alg | key | payload | token B | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | **19.58 (5.4x)** | 19.65 (5.4x) | 20.98 (5.0x) | n/a | n/a | n/a | n/a | n/a | 105.12 (1.0x) | n/a |
| RS256 | RSA 2048 | typical | 961 | **20.67 (6.8x)** | 20.99 (6.7x) | 23.48 (6.0x) | n/a | n/a | n/a | n/a | n/a | 140.96 (1.0x) | n/a |
| RS256 | RSA 2048 | medium | 2574 | **22.32 (12.3x)** | 24.47 (11.2x) | 25.81 (10.6x) | n/a | n/a | n/a | n/a | n/a | 274.45 (1.0x) | n/a |
| RS256 | RSA 2048 | large | 21214 | **46.58 (38.0x)** | 72.03 (24.5x) | 66.79 (26.5x) | n/a | n/a | n/a | n/a | n/a | 1768.17 (1.0x) | n/a |
| RS256 | RSA 3072 | small | 731 | 39.91 (3.5x) | **39.79 (3.5x)** | 41.20 (3.4x) | n/a | n/a | n/a | n/a | n/a | 140.42 (1.0x) | n/a |
| RS256 | RSA 3072 | typical | 1131 | **41.14 (4.3x)** | 41.63 (4.2x) | 43.83 (4.0x) | n/a | n/a | n/a | n/a | n/a | 176.56 (1.0x) | n/a |
| RS256 | RSA 3072 | medium | 2744 | **42.64 (7.3x)** | 45.07 (6.9x) | 46.22 (6.7x) | n/a | n/a | n/a | n/a | n/a | 311.58 (1.0x) | n/a |
| RS256 | RSA 3072 | large | 21384 | **66.99 (26.9x)** | 92.53 (19.5x) | 86.78 (20.8x) | n/a | n/a | n/a | n/a | n/a | 1804.20 (1.0x) | n/a |
| RS256 | RSA 4096 | small | 902 | **68.18 (2.7x)** | 68.38 (2.7x) | 69.38 (2.7x) | n/a | n/a | n/a | n/a | n/a | 186.75 (1.0x) | n/a |
| RS256 | RSA 4096 | typical | 1302 | **69.40 (3.2x)** | 69.45 (3.2x) | 72.04 (3.1x) | n/a | n/a | n/a | n/a | n/a | 222.92 (1.0x) | n/a |
| RS256 | RSA 4096 | medium | 2915 | **71.41 (5.0x)** | 73.54 (4.8x) | 74.48 (4.8x) | n/a | n/a | n/a | n/a | n/a | 356.15 (1.0x) | n/a |
| RS256 | RSA 4096 | large | 21555 | **95.14 (19.5x)** | 122.25 (15.2x) | 115.64 (16.0x) | n/a | n/a | n/a | n/a | n/a | 1854.86 (1.0x) | n/a |
| ES256 | P-256 | small | 304 | **65.04 (2.2x)** | 65.41 (2.2x) | 66.73 (2.2x) | n/a | n/a | n/a | n/a | n/a | 144.91 (1.0x) | n/a |
| ES256 | P-256 | typical | 704 | **66.73 (2.7x)** | 66.95 (2.7x) | 68.98 (2.6x) | n/a | n/a | n/a | n/a | n/a | 180.62 (1.0x) | n/a |
| ES256 | P-256 | medium | 2317 | **68.21 (4.7x)** | 70.13 (4.6x) | 71.30 (4.5x) | n/a | n/a | n/a | n/a | n/a | 319.22 (1.0x) | n/a |
| ES256 | P-256 | large | 20957 | **92.61 (19.6x)** | 119.04 (15.2x) | 112.19 (16.2x) | n/a | n/a | n/a | n/a | n/a | 1814.73 (1.0x) | n/a |
| ES384 | P-384 | small | 346 | **218.54 (2.1x)** | 219.49 (2.1x) | 219.76 (2.1x) | n/a | n/a | n/a | n/a | n/a | 457.39 (1.0x) | n/a |
| ES384 | P-384 | typical | 746 | **221.87 (2.2x)** | 222.53 (2.2x) | 223.97 (2.2x) | n/a | n/a | n/a | n/a | n/a | 492.66 (1.0x) | n/a |
| ES384 | P-384 | medium | 2359 | **222.27 (2.8x)** | 226.41 (2.8x) | 227.15 (2.8x) | n/a | n/a | n/a | n/a | n/a | 630.89 (1.0x) | n/a |
| ES384 | P-384 | large | 20999 | **267.24 (8.0x)** | 296.87 (7.2x) | 288.00 (7.4x) | n/a | n/a | n/a | n/a | n/a | 2142.85 (1.0x) | n/a |
| ES512 | P-521 | small | 394 | 348.50 (1.6x) | **346.90 (1.6x)** | 349.82 (1.6x) | n/a | n/a | n/a | n/a | n/a | 543.18 (1.0x) | n/a |
| ES512 | P-521 | typical | 794 | 345.08 (1.7x) | **344.72 (1.7x)** | 351.08 (1.7x) | n/a | n/a | n/a | n/a | n/a | 581.12 (1.0x) | n/a |
| ES512 | P-521 | medium | 2407 | **348.87 (2.1x)** | 350.51 (2.0x) | 356.96 (2.0x) | n/a | n/a | n/a | n/a | n/a | 716.65 (1.0x) | n/a |
| ES512 | P-521 | large | 21047 | **391.86 (5.7x)** | 420.78 (5.3x) | 415.58 (5.4x) | n/a | n/a | n/a | n/a | n/a | 2227.68 (1.0x) | n/a |
| EdDSA | Ed25519 | small | 306 | 41.58 (4.1x) | **41.34 (4.1x)** | 42.93 (4.0x) | n/a | n/a | n/a | n/a | n/a | 170.07 (1.0x) | n/a |
| EdDSA | Ed25519 | typical | 706 | **43.01 (4.8x)** | 43.36 (4.8x) | 45.81 (4.5x) | n/a | n/a | n/a | n/a | n/a | 206.10 (1.0x) | n/a |
| EdDSA | Ed25519 | medium | 2319 | **46.59 (7.4x)** | 48.95 (7.0x) | 50.05 (6.8x) | n/a | n/a | n/a | n/a | n/a | 342.74 (1.0x) | n/a |
| EdDSA | Ed25519 | large | 20959 | **89.98 (20.6x)** | 115.51 (16.0x) | 109.93 (16.8x) | n/a | n/a | n/a | n/a | n/a | 1849.31 (1.0x) | n/a |

## JWKS URL, async client

pyjwt 2.15.1 has no async JWKS client: speed-ups are vs its sync one.

| alg | key | payload | token B | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | :-- | :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| RS256 | RSA 2048 | small | 561 | 19.69 (5.3x) | **19.66 (5.3x)** | 20.83 (5.0x) | n/a | 72.56 (1.4x) | 37.20 (2.8x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | typical | 961 | **20.69 (6.8x)** | 21.02 (6.7x) | 23.39 (6.0x) | n/a | 65.45 (2.2x) | 40.06 (3.5x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | medium | 2574 | **22.40 (12.3x)** | 24.62 (11.1x) | 25.98 (10.6x) | n/a | 72.36 (3.8x) | 47.24 (5.8x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 2048 | large | 21214 | **46.86 (37.7x)** | 72.79 (24.3x) | 66.95 (26.4x) | n/a | 201.03 (8.8x) | 153.16 (11.5x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | small | 731 | **39.76 (3.5x)** | 40.21 (3.5x) | 41.24 (3.4x) | n/a | 107.17 (1.3x) | 58.70 (2.4x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | typical | 1131 | **40.70 (4.3x)** | 41.73 (4.2x) | 43.90 (4.0x) | n/a | 113.90 (1.6x) | 60.19 (2.9x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | medium | 2744 | **42.97 (7.3x)** | 45.23 (6.9x) | 46.44 (6.7x) | n/a | 119.77 (2.6x) | 68.22 (4.6x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 3072 | large | 21384 | **67.26 (26.8x)** | 93.18 (19.4x) | 87.30 (20.7x) | n/a | 246.20 (7.3x) | 174.99 (10.3x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | small | 902 | 68.18 (2.7x) | **68.01 (2.7x)** | 70.16 (2.7x) | n/a | 171.49 (1.1x) | 87.72 (2.1x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | typical | 1302 | 70.04 (3.2x) | **69.77 (3.2x)** | 72.19 (3.1x) | n/a | 175.22 (1.3x) | 90.00 (2.5x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | medium | 2915 | **71.55 (5.0x)** | 73.64 (4.8x) | 74.52 (4.8x) | n/a | 183.42 (1.9x) | 96.71 (3.7x) | n/a | n/a | n/a | n/a |
| RS256 | RSA 4096 | large | 21555 | **95.71 (19.4x)** | 121.86 (15.2x) | 115.69 (16.0x) | n/a | 309.79 (6.0x) | 206.52 (9.0x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | small | 304 | 65.77 (2.2x) | **65.42 (2.2x)** | 66.74 (2.2x) | n/a | 4062.17 (0.04x) | 84.11 (1.7x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | typical | 704 | **66.75 (2.7x)** | 67.16 (2.7x) | 69.51 (2.6x) | n/a | 4126.67 (0.04x) | 86.79 (2.1x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | medium | 2317 | **68.46 (4.7x)** | 70.48 (4.5x) | 71.65 (4.5x) | n/a | 3905.78 (0.08x) | 93.74 (3.4x) | n/a | n/a | n/a | n/a |
| ES256 | P-256 | large | 20957 | **92.61 (19.6x)** | 119.11 (15.2x) | 111.81 (16.2x) | n/a | 4065.97 (0.4x) | 198.78 (9.1x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | small | 346 | 218.79 (2.1x) | 221.06 (2.1x) | **218.74 (2.1x)** | n/a | 26684.12 (0.02x) | 472.50 (1.0x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | typical | 746 | **221.12 (2.2x)** | 223.44 (2.2x) | 224.07 (2.2x) | n/a | 26777.52 (0.02x) | 473.71 (1.0x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | medium | 2359 | **223.60 (2.8x)** | 226.60 (2.8x) | 227.36 (2.8x) | n/a | 26761.19 (0.02x) | 484.83 (1.3x) | n/a | n/a | n/a | n/a |
| ES384 | P-384 | large | 20999 | **268.19 (8.0x)** | 296.09 (7.2x) | 286.13 (7.5x) | n/a | 27233.30 (0.08x) | 612.12 (3.5x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | small | 394 | **345.03 (1.6x)** | 346.65 (1.6x) | 349.70 (1.6x) | n/a | 65771.33 (0.01x) | 1140.94 (0.5x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | typical | 794 | **342.12 (1.7x)** | 345.17 (1.7x) | 348.59 (1.7x) | n/a | 65524.96 (0.01x) | 1125.70 (0.5x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | medium | 2407 | **349.40 (2.1x)** | 351.28 (2.0x) | 353.44 (2.0x) | n/a | 65424.15 (0.01x) | 1119.32 (0.6x) | n/a | n/a | n/a | n/a |
| ES512 | P-521 | large | 21047 | **391.68 (5.7x)** | 417.72 (5.3x) | 414.31 (5.4x) | n/a | 65640.90 (0.03x) | 1285.75 (1.7x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | small | 306 | 41.53 (4.1x) | **41.42 (4.1x)** | 42.82 (4.0x) | n/a | n/a | 67.30 (2.5x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | typical | 706 | **43.15 (4.8x)** | 43.46 (4.7x) | 45.73 (4.5x) | n/a | n/a | 70.14 (2.9x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | medium | 2319 | **46.89 (7.3x)** | 48.73 (7.0x) | 50.04 (6.8x) | n/a | n/a | 80.56 (4.3x) | n/a | n/a | n/a | n/a |
| EdDSA | Ed25519 | large | 20959 | **90.31 (20.5x)** | 115.65 (16.0x) | 109.35 (16.9x) | n/a | n/a | 205.89 (9.0x) | n/a | n/a | n/a | n/a |

## First fetch from a JWKS URL

Milliseconds from a fresh client to its first decode: connect, TLS handshake,
GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh
clients, each on a new connection.

| key source | ryjwt 0.1.0 → Struct | ryjwt 0.1.0 → dict | ryjwt 0.1.0 → BaseModel | jsonwebtoken 11.1.0 (aws-lc-rs) | fast-jwt 6.3.3 | jose 6.2.12 | python-jose 3.5.0 | joserfc 1.7.5 | pyjwt 2.15.1 | jwcrypto 1.6.1 |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| JWKS URL, sync client | 3.0 | 2.6 | 2.5 | n/a | n/a | n/a | n/a | n/a | 2.4 | n/a |
| JWKS URL, async client | 3.0 | 2.5 | 2.7 | n/a | 1.4 | 1.7 | n/a | n/a | n/a | n/a |

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

- ryjwt 0.1.0 → Struct: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.0 → Struct: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
- ryjwt 0.1.0 → dict: `SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`.
- ryjwt 0.1.0 → dict: JWKS URL: trusting the test CA through `SSL_CERT_FILE`.
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
