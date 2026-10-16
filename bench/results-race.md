# The races' numbers

Generated 2026-10-16 from `bench/results-race/` by `bench/race_svg.py`, on
AWS c9g.2xlarge, Graviton5 (aarch64), Linux. Each library decodes the same token 100,000 times, in 3 rounds,
after 1,000 untimed decodes; the time is the mean over all three.

## HS256, a 64-byte secret

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → Struct (Python) | 0.15 s | 1.47 | 1.46 to 1.47 | 26.4x |
| ryjwt → dict (msgspec) (Python) | 0.15 s | 1.55 | 1.55 to 1.55 | 25.0x |
| ryjwt → dict (jiter) (Python) | 0.19 s | 1.87 | 1.87 to 1.88 | 20.7x |
| ryjwt → BaseModel (Python) | 0.31 s | 3.06 | 3.06 to 3.07 | 12.7x |
| jsonwebtoken → struct (Rust) | 0.32 s | 3.16 | 3.16 to 3.16 | 12.3x |
| jsonwebtoken → Value (Rust) | 0.38 s | 3.77 | 3.77 to 3.77 | 10.3x |
| fast-jwt (Bun) | 0.48 s | 4.77 | 4.41 to 5.45 | 8.1x |
| jose (Bun) | 1.29 s | 12.87 | 12.60 to 13.29 | 3.0x |
| joserfc (Python) | 1.89 s | 18.94 | 18.93 to 18.95 | 2.0x |
| PyJWT (Python) | 3.88 s | 38.75 | 38.72 to 38.80 | 1.0x |

## RS256, a 3072-bit RSA PEM public key

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → Struct (Python) | 2.94 s | 29.40 | 29.33 to 29.48 | 2.7x |
| ryjwt → dict (msgspec) (Python) | 2.95 s | 29.47 | 29.43 to 29.51 | 2.7x |
| ryjwt → dict (jiter) (Python) | 2.97 s | 29.74 | 29.69 to 29.78 | 2.6x |
| ryjwt → BaseModel (Python) | 3.09 s | 30.87 | 30.80 to 30.94 | 2.5x |
| fast-jwt (Bun) | 3.44 s | 34.37 | 33.79 to 34.91 | 2.3x |
| jsonwebtoken → struct (Rust) | 3.54 s | 35.44 | 35.43 to 35.44 | 2.2x |
| jsonwebtoken → Value (Rust) | 3.60 s | 35.97 | 35.97 to 35.98 | 2.2x |
| jose (Bun) | 4.20 s | 42.01 | 41.63 to 42.72 | 1.9x |
| joserfc (Python) | 5.26 s | 52.61 | 52.59 to 52.63 | 1.5x |
| PyJWT (Python) | 7.86 s | 78.56 | 78.53 to 78.59 | 1.0x |
