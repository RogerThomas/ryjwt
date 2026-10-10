# The races' numbers

Generated 2026-10-10 from `bench/results-race/` by `bench/race_svg.py`, on
AMD EPYC 9V74 80-Core Processor (x86_64), Linux. Each library decodes the same token 100,000 times, in 3 rounds,
after 1,000 untimed decodes; the time is the mean over all three.

## HS256, a 64-byte secret

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → Struct (Python) | 0.19 s | 1.91 | 1.90 to 1.92 | 26.8x |
| ryjwt → dict (msgspec) (Python) | 0.21 s | 2.05 | 2.05 to 2.06 | 24.9x |
| ryjwt → dict (jiter) (Python) | 0.26 s | 2.57 | 2.57 to 2.58 | 19.9x |
| jsonwebtoken → struct (Rust) | 0.38 s | 3.81 | 3.81 to 3.82 | 13.4x |
| ryjwt → BaseModel (Python) | 0.41 s | 4.10 | 4.10 to 4.10 | 12.5x |
| jsonwebtoken → Value (Rust) | 0.45 s | 4.48 | 4.47 to 4.48 | 11.4x |
| fast-jwt (Bun) | 0.60 s | 5.98 | 5.50 to 6.81 | 8.6x |
| joserfc (Python) | 2.52 s | 25.16 | 25.13 to 25.22 | 2.0x |
| jose (Bun) | 2.74 s | 27.36 | 26.88 to 28.12 | 1.9x |
| PyJWT (Python) | 5.12 s | 51.16 | 50.64 to 51.97 | 1.0x |

## RS256, a 3072-bit RSA PEM public key

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → dict (msgspec) (Python) | 3.51 s | 35.06 | 35.04 to 35.10 | 2.9x |
| ryjwt → Struct (Python) | 3.52 s | 35.22 | 35.21 to 35.24 | 2.9x |
| ryjwt → dict (jiter) (Python) | 3.55 s | 35.46 | 35.45 to 35.47 | 2.8x |
| ryjwt → BaseModel (Python) | 3.75 s | 37.48 | 37.41 to 37.59 | 2.7x |
| jsonwebtoken → struct (Rust) | 4.11 s | 41.09 | 41.08 to 41.12 | 2.5x |
| jsonwebtoken → Value (Rust) | 4.15 s | 41.52 | 41.51 to 41.53 | 2.4x |
| fast-jwt (Bun) | 4.19 s | 41.89 | 41.45 to 42.76 | 2.4x |
| jose (Bun) | 6.37 s | 63.66 | 63.23 to 64.51 | 1.6x |
| joserfc (Python) | 6.47 s | 64.66 | 64.57 to 64.75 | 1.6x |
| PyJWT (Python) | 10.08 s | 100.84 | 100.58 to 101.03 | 1.0x |
