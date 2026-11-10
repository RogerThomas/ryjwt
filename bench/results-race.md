# The races' numbers

Generated 2026-11-10 from `bench/results-race/` by `bench/race_svg.py`, on
AWS m9g.2xlarge, Graviton5 (aarch64), Linux. Each library decodes the same token for 3 rounds of 10 s each, after 1 s of untimed decodes, so each is timed for as long, however fast. The time per decode is the mean over every timed decode; the time for 100,000 decodes is 100,000 times that.

## HS256, a 64-byte secret

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → Struct (Python) | 0.14 s | 1.40 | 1.39 to 1.40 | 27.9x |
| ryjwt → dict (msgspec) (Python) | 0.15 s | 1.46 | 1.46 to 1.46 | 26.7x |
| ryjwt → dict (jiter) (Python) | 0.18 s | 1.77 | 1.76 to 1.77 | 22.0x |
| ryjwt → BaseModel (Python) | 0.27 s | 2.73 | 2.72 to 2.73 | 14.3x |
| jsonwebtoken → struct (Rust) | 0.31 s | 3.14 | 3.14 to 3.14 | 12.4x |
| jsonwebtoken → Value (Rust) | 0.37 s | 3.68 | 3.68 to 3.68 | 10.6x |
| fast-jwt (Bun) | 0.45 s | 4.48 | 4.48 to 4.48 | 8.7x |
| jose (Bun) | 1.26 s | 12.60 | 12.60 to 12.60 | 3.1x |
| joserfc (Python) | 1.91 s | 19.08 | 19.04 to 19.10 | 2.0x |
| PyJWT (Python) | 3.89 s | 38.92 | 38.79 to 38.98 | 1.0x |

## RS256, a 3072-bit RSA PEM public key

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → Struct (Python) | 2.90 s | 28.98 | 28.97 to 28.98 | 2.7x |
| ryjwt → dict (msgspec) (Python) | 2.94 s | 29.41 | 29.41 to 29.42 | 2.7x |
| ryjwt → dict (jiter) (Python) | 2.97 s | 29.68 | 29.68 to 29.69 | 2.6x |
| ryjwt → BaseModel (Python) | 3.07 s | 30.72 | 30.70 to 30.74 | 2.6x |
| fast-jwt (Bun) | 3.39 s | 33.88 | 33.83 to 33.99 | 2.3x |
| jsonwebtoken → struct (Rust) | 3.52 s | 35.23 | 35.23 to 35.23 | 2.2x |
| jsonwebtoken → Value (Rust) | 3.56 s | 35.60 | 35.60 to 35.60 | 2.2x |
| jose (Bun) | 4.17 s | 41.72 | 41.63 to 41.88 | 1.9x |
| joserfc (Python) | 5.27 s | 52.72 | 52.68 to 52.74 | 1.5x |
| PyJWT (Python) | 7.87 s | 78.65 | 78.60 to 78.69 | 1.0x |
