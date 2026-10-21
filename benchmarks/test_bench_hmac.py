"""Encoding and decoding with a `SecretKey` (HS256, HS384, HS512)."""

import msgspec
import pytest
import ryjwt
from _bench_support import ClaimsModel, ClaimsStruct, make_claims, make_large_claims
from pytest_codspeed import BenchmarkFixture

HMAC_ALGORITHMS: list[ryjwt.HMACAlgorithm] = ["HS256", "HS384", "HS512"]


@pytest.mark.parametrize("algorithm", HMAC_ALGORITHMS)
def test_encode(
    benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey, algorithm: ryjwt.HMACAlgorithm
) -> None:
    claims = make_claims()
    token = benchmark(secret_key.encode, claims, algorithm=algorithm)
    assert token.count(".") == 2


@pytest.mark.parametrize("algorithm", HMAC_ALGORITHMS)
def test_decode(
    benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey, algorithm: ryjwt.HMACAlgorithm
) -> None:
    token = secret_key.encode(make_claims(), algorithm=algorithm)
    claims = benchmark(secret_key.decode, token)
    assert claims["sub"] == "user-1234567890"


def test_decode_bytes_token(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_claims(), algorithm="HS256").encode()
    claims = benchmark(secret_key.decode, token)
    assert claims["sub"] == "user-1234567890"


def test_decode_into_struct(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_claims(), algorithm="HS256")
    claims = benchmark(secret_key.decode, token, into=ClaimsStruct)
    assert claims.sub == "user-1234567890"


def test_decode_into_model(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_claims(), algorithm="HS256")
    claims = benchmark(secret_key.decode, token, into=ClaimsModel)
    assert claims.sub == "user-1234567890"


def test_encode_struct(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    claims = msgspec.convert(make_claims(), ClaimsStruct)
    token = benchmark(secret_key.encode, claims, algorithm="HS256")
    assert token.count(".") == 2


def test_encode_model(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    claims = ClaimsModel.model_validate(make_claims())
    token = benchmark(secret_key.encode, claims, algorithm="HS256")
    assert token.count(".") == 2


def test_encode_large_payload(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    claims = make_large_claims()
    token = benchmark(secret_key.encode, claims, algorithm="HS256")
    assert token.count(".") == 2


def test_decode_large_payload(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_large_claims(), algorithm="HS256")
    claims = benchmark(secret_key.decode, token)
    assert len(claims["roles"]) == 100


def test_decode_invalid_signature(benchmark: BenchmarkFixture, secret_key: ryjwt.SecretKey) -> None:
    token = secret_key.encode(make_claims(), algorithm="HS256")
    head, payload, _ = token.split(".")
    forged = f"{head}.{payload}.{'A' * 43}"

    def decode_forged() -> None:
        try:
            secret_key.decode(forged)
        except ryjwt.InvalidSignatureError:
            return
        msg = "the forged token was accepted"
        raise AssertionError(msg)

    benchmark(decode_forged)


def test_secret_key_construction(benchmark: BenchmarkFixture) -> None:
    secret = b"benchmark-secret-" * 4
    key = benchmark(ryjwt.SecretKey, secret, algorithms=["HS256"], audience="my-api")
    assert key.algorithms == ["HS256"]
