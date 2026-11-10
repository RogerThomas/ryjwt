# The races' numbers

Generated 2026-11-10 from `bench/results-race/` by `bench/race_svg.py`, on
AWS m9g.2xlarge, Graviton5 (aarch64), Linux. Each library decodes the same token 100,000 times, in 3 rounds,
after 1,000 untimed decodes; the time is the mean over all three.

## HS256, a 64-byte secret

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → Struct (Python) | 0.14 s | 1.42 | 1.41 to 1.44 | 27.3x |
| ryjwt → dict (msgspec) (Python) | 0.15 s | 1.46 | 1.45 to 1.46 | 26.6x |
| ryjwt → dict (jiter) (Python) | 0.17 s | 1.74 | 1.73 to 1.74 | 22.3x |
| ryjwt → BaseModel (Python) | 0.28 s | 2.78 | 2.76 to 2.80 | 13.9x |
| jsonwebtoken → struct (Rust) | 0.32 s | 3.18 | 3.18 to 3.18 | 12.2x |
| jsonwebtoken → Value (Rust) | 0.37 s | 3.75 | 3.74 to 3.75 | 10.3x |
| fast-jwt (Bun) | 0.48 s | 4.80 | 4.42 to 5.51 | 8.1x |
| jose (Bun) | 1.28 s | 12.78 | 12.42 to 13.39 | 3.0x |
| joserfc (Python) | 1.92 s | 19.21 | 19.20 to 19.24 | 2.0x |
| PyJWT (Python) | 3.88 s | 38.75 | 38.68 to 38.83 | 1.0x |

## RS256, a 3072-bit RSA PEM public key

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → dict (msgspec) (Python) | 2.91 s | 29.13 | 29.12 to 29.14 | 2.7x |
| ryjwt → Struct (Python) | 2.91 s | 29.13 | 29.12 to 29.17 | 2.7x |
| ryjwt → dict (jiter) (Python) | 2.96 s | 29.57 | 29.51 to 29.61 | 2.7x |
| ryjwt → BaseModel (Python) | 3.08 s | 30.80 | 30.69 to 30.88 | 2.6x |
| fast-jwt (Bun) | 3.41 s | 34.15 | 33.79 to 34.81 | 2.3x |
| jsonwebtoken → struct (Rust) | 3.54 s | 35.44 | 35.43 to 35.45 | 2.2x |
| jsonwebtoken → Value (Rust) | 3.59 s | 35.92 | 35.91 to 35.92 | 2.2x |
| jose (Bun) | 4.20 s | 41.96 | 41.57 to 42.72 | 1.9x |
| joserfc (Python) | 5.29 s | 52.91 | 52.90 to 52.93 | 1.5x |
| PyJWT (Python) | 7.88 s | 78.80 | 78.78 to 78.83 | 1.0x |
