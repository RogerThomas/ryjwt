"""Encoding and decoding with a `PrivateKey` / `PublicKey` (RSA, RSA-PSS, ECDSA, EdDSA), and the
key and JWKS operations around them."""

import pytest
import ryjwt
from _bench_support import AUDIENCE, ISSUER, make_claims
from pytest_codspeed import BenchmarkFixture

ALGORITHMS: list[ryjwt.AsymmetricAlgorithm] = ["RS256", "PS256", "ES256", "ES384", "EdDSA"]


def _private_key(pems: dict[str, bytes], algorithm: ryjwt.AsymmetricAlgorithm) -> ryjwt.PrivateKey:
    return ryjwt.PrivateKey(
        pems[algorithm],
        algorithms=[algorithm],
        audience=AUDIENCE,
        issuer=ISSUER,
        kid=f"key-{algorithm}",
    )


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_encode(
    benchmark: BenchmarkFixture,
    private_pems: dict[str, bytes],
    algorithm: ryjwt.AsymmetricAlgorithm,
) -> None:
    key = _private_key(private_pems, algorithm)
    claims = make_claims()
    token = benchmark(key.encode, claims)
    assert token.count(".") == 2


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_decode_public_key(
    benchmark: BenchmarkFixture,
    private_pems: dict[str, bytes],
    algorithm: ryjwt.AsymmetricAlgorithm,
) -> None:
    private_key = _private_key(private_pems, algorithm)
    public_key = ryjwt.PublicKey.from_jwks(
        ryjwt.jwks([private_key]), algorithms=[algorithm], audience=AUDIENCE, issuer=ISSUER
    )
    token = private_key.encode(make_claims())
    claims = benchmark(public_key.decode, token)
    assert claims["sub"] == "user-1234567890"


@pytest.mark.parametrize("algorithm", ["RS256", "ES256", "EdDSA"])
def test_private_key_from_pem(
    benchmark: BenchmarkFixture,
    private_pems: dict[str, bytes],
    algorithm: ryjwt.AsymmetricAlgorithm,
) -> None:
    pem = private_pems[algorithm]
    key = benchmark(ryjwt.PrivateKey, pem, algorithms=[algorithm])
    assert key.algorithms == [algorithm]


def test_jwks(benchmark: BenchmarkFixture, private_pems: dict[str, bytes]) -> None:
    keys = [_private_key(private_pems, algorithm) for algorithm in ALGORITHMS]
    published = benchmark(ryjwt.jwks, keys)
    assert len(published["keys"]) == len(ALGORITHMS)


def test_public_key_from_jwks(benchmark: BenchmarkFixture, private_pems: dict[str, bytes]) -> None:
    keys = [_private_key(private_pems, algorithm) for algorithm in ALGORITHMS]
    published = ryjwt.jwks(keys)
    public_key = benchmark(ryjwt.PublicKey.from_jwks, published, algorithms=ALGORITHMS)
    assert public_key.algorithms == ALGORITHMS


def test_decode_multi_key_jwks(benchmark: BenchmarkFixture, private_pems: dict[str, bytes]) -> None:
    """Decoding with a `PublicKey` of several keys, where the token's `kid` picks the key."""
    keys = [_private_key(private_pems, algorithm) for algorithm in ALGORITHMS]
    public_key = ryjwt.PublicKey.from_jwks(
        ryjwt.jwks(keys), algorithms=ALGORITHMS, audience=AUDIENCE, issuer=ISSUER
    )
    token = keys[2].encode(make_claims())  # ES256
    claims = benchmark(public_key.decode, token)
    assert claims["sub"] == "user-1234567890"
