"""What a user's type checker infers from ryjwt's public API.

`assert_type` is a no-op at runtime; the gate is the type checkers (mypy, ty, pyright, zuban,
pyrefly), which all run over tests/ and fail if any of these inferences drift.
"""

import base64
import inspect
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, assert_type

import msgspec
import ryjwt
from _support import ClaimsModel, ClaimsStruct, DatetimeClaimsStruct


class GenericClaims[T](msgspec.Struct):
    sub: T


def test_decode_return_types(
    hmac_jwt: ryjwt.HMAC,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    token = hmac_jwt.encode({"sub": "sub"})
    private_key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])
    public_key = ryjwt.PublicKey(public_pems["ES256"], algorithms=["ES256"])
    es256_token = private_key.encode({"sub": "sub"})

    assert_type(hmac_jwt.decode(token), dict[str, Any])
    assert_type(hmac_jwt.decode(token.encode()), dict[str, Any])
    assert_type(hmac_jwt.decode(token, type=None), dict[str, Any])
    assert_type(hmac_jwt.decode(token, type=ClaimsStruct), ClaimsStruct)
    assert_type(hmac_jwt.decode(token, type=ClaimsModel), ClaimsModel)
    assert_type(hmac_jwt.decode(token, type=GenericClaims[str]), GenericClaims[str])
    for key in (private_key, public_key):
        assert_type(key.decode(es256_token), dict[str, Any])
        assert_type(key.decode(es256_token.encode()), dict[str, Any])
        assert_type(key.decode(es256_token, type=None), dict[str, Any])
        assert_type(key.decode(es256_token, type=ClaimsStruct), ClaimsStruct)
        assert_type(key.decode(es256_token, type=ClaimsModel), ClaimsModel)
        assert_type(key.decode(es256_token, type=GenericClaims[str]), GenericClaims[str])


def test_decode_datetime_claims_types(hmac_jwt: ryjwt.HMAC) -> None:
    token = hmac_jwt.encode({"sub": "sub", "exp": 4_102_444_800, "iat": 946_684_800})

    claims = hmac_jwt.decode(token, type=DatetimeClaimsStruct)

    assert_type(claims, DatetimeClaimsStruct)
    assert_type(claims.exp, datetime)
    assert_type(claims.nbf, datetime | None)


def test_encode_and_algorithms_types(
    hmac_jwt: ryjwt.HMAC,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    private_key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])
    public_key = ryjwt.PublicKey(public_pems["ES256"], algorithms=["ES256"])

    assert_type(hmac_jwt.encode({"sub": "sub"}), str)
    assert_type(hmac_jwt.encode(ClaimsStruct(sub="sub")), str)
    assert_type(hmac_jwt.encode(ClaimsModel(sub="sub")), str)
    assert_type(hmac_jwt.encode({"sub": "sub"}, algorithm="HS256"), str)
    assert_type(private_key.encode({"sub": "sub"}), str)
    assert_type(private_key.encode(ClaimsStruct(sub="sub")), str)
    assert_type(private_key.encode(ClaimsModel(sub="sub"), algorithm="ES256"), str)
    assert_type(hmac_jwt.algorithms, list[ryjwt.HMACAlgorithm])
    assert_type(private_key.algorithms, list[ryjwt.AsymmetricAlgorithm])
    assert_type(public_key.algorithms, list[ryjwt.AsymmetricAlgorithm])


def test_hmac_constructor_types(hmac_key: str) -> None:
    assert_type(ryjwt.HMAC(hmac_key, algorithms=["HS256"]), ryjwt.HMAC)
    assert_type(ryjwt.HMAC(b"secret", algorithms=["HS256"], allow_short_secret=True), ryjwt.HMAC)


def test_from_path_types(
    tmp_path: Path,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    (tmp_path / "private.pem").write_bytes(private_pems["ES256"])
    (tmp_path / "public.pem").write_bytes(public_pems["ES256"])

    assert_type(
        ryjwt.PrivateKey.from_path(tmp_path / "private.pem", algorithms=["ES256"]),
        ryjwt.PrivateKey,
    )
    assert_type(
        ryjwt.PublicKey.from_path(str(tmp_path / "public.pem"), algorithms=["ES256"]),
        ryjwt.PublicKey,
    )


def test_from_jwks_types(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    pem = public_pems["EdDSA"].decode()
    x = base64.urlsafe_b64encode(base64.b64decode("".join(pem.splitlines()[1:-1]))[-32:])
    jwks: dict[str, Any] = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x.decode().rstrip("=")}]}
    from_mapping = ryjwt.PublicKey.from_jwks(jwks, algorithms=["EdDSA"])
    token = ryjwt.PrivateKey(private_pems["EdDSA"], algorithms=["EdDSA"]).encode({"sub": "sub"})

    assert_type(from_mapping, ryjwt.PublicKey)
    assert_type(ryjwt.PublicKey.from_jwks(json.dumps(jwks), algorithms=["EdDSA"]), ryjwt.PublicKey)
    assert_type(
        ryjwt.PublicKey.from_jwks(json.dumps(jwks).encode(), algorithms=["EdDSA"]),
        ryjwt.PublicKey,
    )
    assert_type(from_mapping.algorithms, list[ryjwt.AsymmetricAlgorithm])
    assert_type(from_mapping.decode(token), dict[str, Any])
    assert_type(from_mapping.decode(token, type=ClaimsStruct), ClaimsStruct)


def test_unknown_key_error_type() -> None:
    error: ryjwt.InvalidTokenError = ryjwt.UnknownKeyError("kid")

    assert_type(ryjwt.UnknownKeyError("kid"), ryjwt.UnknownKeyError)
    assert isinstance(error, ryjwt.UnknownKeyError)


async def _jwks_client_calls(client: ryjwt.JWKSClient) -> None:
    """Type-checked, never run: these would fetch."""
    assert_type(client.decode("token"), dict[str, Any])
    assert_type(client.decode("token", type=None, leeway=1), dict[str, Any])
    assert_type(client.decode("token", type=ClaimsStruct), ClaimsStruct)
    assert_type(client.decode("token", type=ClaimsModel, issuer="iss"), ClaimsModel)
    assert_type(client.decode("token", type=GenericClaims[int]), GenericClaims[int])
    assert_type(await client.adecode("token"), dict[str, Any])
    assert_type(await client.adecode(b"token", type=None), dict[str, Any])
    assert_type(await client.adecode("token", type=ClaimsStruct), ClaimsStruct)
    assert_type(await client.adecode("token", type=ClaimsModel, audience="aud"), ClaimsModel)
    assert_type(client.decode_nowait("token"), dict[str, Any])
    assert_type(client.decode_nowait(b"token", type=None, leeway=timedelta(1)), dict[str, Any])
    assert_type(client.decode_nowait("token", type=ClaimsStruct), ClaimsStruct)
    assert_type(client.decode_nowait("token", type=ClaimsModel, audience="aud"), ClaimsModel)
    assert_type(client.refresh(), None)
    assert_type(await client.arefresh(), None)


def test_jwks_client_types() -> None:
    client = ryjwt.JWKSClient("https://issuer/jwks", algorithms=["ES256"])
    configured = ryjwt.JWKSClient(
        "https://issuer/jwks",
        algorithms=["RS256", "ES256"],
        max_stale=timedelta(hours=1),
        cooldown=timedelta(seconds=1),
    )

    assert_type(client, ryjwt.JWKSClient)
    assert_type(configured, ryjwt.JWKSClient)
    assert_type(client.needs_refresh, bool)
    assert inspect.iscoroutinefunction(_jwks_client_calls)


def test_jwks_fetch_error_type() -> None:
    error: ryjwt.RYJWTError = ryjwt.JWKSFetchError("jwks")

    assert_type(ryjwt.JWKSFetchError("jwks"), ryjwt.JWKSFetchError)
    assert isinstance(error, ryjwt.JWKSFetchError)
    assert not isinstance(error, ryjwt.InvalidTokenError)
