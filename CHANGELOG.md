# Changelog

## [0.2.1](https://github.com/RogerThomas/ryjwt/compare/v0.2.0...v0.2.1) (2026-10-12)


### Performance Improvements

* decode and encode datetime claims in Rust; build tokens in place ([#25](https://github.com/RogerThomas/ryjwt/issues/25)) ([2318c0d](https://github.com/RogerThomas/ryjwt/commit/2318c0d641fb1d75a5a17209c1c13350628b17fc))

## [0.2.0](https://github.com/RogerThomas/ryjwt/compare/v0.1.2...v0.2.0) (2026-10-11)


### ⚠ BREAKING CHANGES

* the decode methods' type= argument is now into=; type= is no longer accepted.

### Features

* decode(token, into=Claims), replacing type= ([#23](https://github.com/RogerThomas/ryjwt/issues/23)) ([eb87b82](https://github.com/RogerThomas/ryjwt/commit/eb87b82c2aeaa3e5732176867e68abc2be2af5fb))

## [0.1.2](https://github.com/RogerThomas/ryjwt/compare/v0.1.1...v0.1.2) (2026-10-11)


### Features

* publish your public keys as a JWKS, with a kid on the key ([#18](https://github.com/RogerThomas/ryjwt/issues/18)) ([5a47a65](https://github.com/RogerThomas/ryjwt/commit/5a47a650ef52e8e992946480e87fb56fe47837f6))

## [0.1.1](https://github.com/RogerThomas/ryjwt/compare/v0.1.0...v0.1.1) (2026-10-10)


### Bug Fixes

* don't read a JWKS response over 1 MiB; benchmarks from Linux, an RS256 race, shorter docs ([#15](https://github.com/RogerThomas/ryjwt/issues/15)) ([6aef8ab](https://github.com/RogerThomas/ryjwt/commit/6aef8ab1d8323696c22ae6d167392b5de6c27ce4))

## [0.1.0](https://github.com/RogerThomas/ryjwt/compare/v0.0.0-alpha.1...v0.1.0) (2026-10-09)


### Miscellaneous Chores

* release 0.1.0, the first non-pre-release version ([#11](https://github.com/RogerThomas/ryjwt/issues/11)) ([9d5cb2c](https://github.com/RogerThomas/ryjwt/commit/9d5cb2c0f04ea32fa6859dd842e27292e8c07fe6))

## [0.0.0-alpha.1](https://github.com/RogerThomas/ryjwt/compare/v0.0.0-alpha.0...v0.0.0-alpha.1) (2026-10-09)


### Features

* stricter secret and header checks, and a ryjwt User-Agent ([#8](https://github.com/RogerThomas/ryjwt/issues/8)) ([42c81c6](https://github.com/RogerThomas/ryjwt/commit/42c81c6301128c86d0cd0326b944dd39316ae35d))

## 0.0.0-alpha.0 (2026-10-09)


### Features

* initial alpha of ryjwt ([#1](https://github.com/RogerThomas/ryjwt/issues/1)) ([f8774f5](https://github.com/RogerThomas/ryjwt/commit/f8774f5a6318e2677c8607b6c294376a3ae93f8c))
