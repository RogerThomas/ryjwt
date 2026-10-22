"""Reading a token's header and claims without verifying it."""

import ryjwt
from _bench_support import make_claims
from pytest_codspeed import BenchmarkFixture


def test_unverified_header(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_claims(), algorithm="HS256", header={"kid": "key-1"})
    header = benchmark(ryjwt.unverified_header, token)
    assert header["kid"] == "key-1"


def test_unverified_claims(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_claims(), algorithm="HS256")
    claims = benchmark(ryjwt.unverified_claims, token)
    assert claims["sub"] == "user-1234567890"


def test_unverified_token(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_claims(), algorithm="HS256")
    header, claims = benchmark(ryjwt.unverified_token, token)
    assert header["alg"] == "HS256"
    assert claims["sub"] == "user-1234567890"
