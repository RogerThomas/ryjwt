# The races' numbers

Generated 2026-10-10 from `bench/results-race/` by `bench/race_svg.py`, on
Neoverse-N2 (aarch64), Linux. Each library decodes the same token 100,000 times, in 3 rounds,
after 1,000 untimed decodes; the time is the mean over all three.

## HS256, a 64-byte secret

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| ryjwt → Struct (Python) | 0.21 s | 2.08 | 2.06 to 2.08 | 28.6x |
| ryjwt → dict (msgspec) (Python) | 0.22 s | 2.18 | 2.18 to 2.19 | 27.2x |
| ryjwt → dict (jiter) (Python) | 0.26 s | 2.60 | 2.59 to 2.60 | 22.8x |
| jsonwebtoken → struct (Rust) | 0.38 s | 3.83 | 3.83 to 3.83 | 15.5x |
| ryjwt → BaseModel (Python) | 0.44 s | 4.38 | 4.37 to 4.39 | 13.5x |
| jsonwebtoken → Value (Rust) | 0.47 s | 4.71 | 4.70 to 4.72 | 12.6x |
| fast-jwt (Bun) | 0.69 s | 6.85 | 6.35 to 7.83 | 8.7x |
| joserfc (Python) | 2.81 s | 28.14 | 28.12 to 28.18 | 2.1x |
| jose (Bun) | 3.94 s | 39.44 | 38.76 to 40.10 | 1.5x |
| PyJWT (Python) | 5.93 s | 59.31 | 59.27 to 59.36 | 1.0x |

## RS256, a 3072-bit RSA PEM public key

| library | 100,000 decodes | µs per decode | range over 3 rounds | vs PyJWT |
| :-- | --: | --: | --: | --: |
| fast-jwt (Bun) | 4.85 s | 48.46 | 47.97 to 49.41 | 2.4x |
| ryjwt → Struct (Python) | 7.04 s | 70.39 | 70.33 to 70.45 | 1.7x |
| ryjwt → dict (msgspec) (Python) | 7.04 s | 70.43 | 70.37 to 70.49 | 1.7x |
| ryjwt → dict (jiter) (Python) | 7.09 s | 70.89 | 70.88 to 70.93 | 1.6x |
| ryjwt → BaseModel (Python) | 7.30 s | 73.03 | 73.03 to 73.04 | 1.6x |
| joserfc (Python) | 7.60 s | 76.04 | 75.89 to 76.20 | 1.5x |
| jsonwebtoken → struct (Rust) | 7.72 s | 77.18 | 77.11 to 77.21 | 1.5x |
| jsonwebtoken → Value (Rust) | 7.79 s | 77.92 | 77.85 to 77.99 | 1.5x |
| jose (Bun) | 8.03 s | 80.34 | 79.76 to 81.36 | 1.4x |
| PyJWT (Python) | 11.64 s | 116.41 | 116.38 to 116.45 | 1.0x |
