"""Tokens ryjwt signs must verify with PyJWT, and vice versa, for every algorithm and key form."""

from typing import TYPE_CHECKING, Any

import jwt
import pytest
import ryjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

_ALGORITHMS = [
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "ES521",
    "EdDSA",
]


def _private_forms(private_key: PrivateKeyTypes) -> dict[str, Any]:
    forms: dict[str, Any] = {
        "object": private_key,
        "pkcs8-pem": private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }
    if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        forms["traditional-pem"] = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
    return forms


def _public_forms(private_key: PrivateKeyTypes) -> dict[str, Any]:
    public_key = private_key.public_key()
    forms: dict[str, Any] = {
        "object": public_key,
        "spki-pem": public_key.public_bytes(  # pyright: ignore[reportUnknownMemberType]
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    }
    if isinstance(public_key, rsa.RSAPublicKey):
        forms["pkcs1-pem"] = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1,
        ).decode()
    return forms


@pytest.mark.parametrize("alg", _ALGORITHMS)
def test_ryjwt_tokens_verify_with_pyjwt(
    alg: str,
    private_keys: dict[str, PrivateKeyTypes],
    future: int,
) -> None:
    private_key = private_keys[alg]
    claims = {"sub": "sub", "exp": future}

    for form, key in _private_forms(private_key).items():
        token = ryjwt.RYJWT(key, algorithms=[alg]).encode(claims)
        assert jwt.decode(token, private_key.public_key(), algorithms=[alg]) == claims, form  # pyright: ignore[reportArgumentType]
        assert jwt.get_unverified_header(token) == {"alg": alg, "typ": "JWT"}, form


@pytest.mark.parametrize("alg", _ALGORITHMS)
def test_pyjwt_tokens_verify_with_ryjwt(
    alg: str,
    private_keys: dict[str, PrivateKeyTypes],
    future: int,
) -> None:
    private_key = private_keys[alg]
    claims = {"sub": "sub", "exp": future}
    token = jwt.encode(claims, private_key, algorithm=alg)  # pyright: ignore[reportArgumentType]

    forms = _public_forms(private_key) | {
        f"private-{k}": v for k, v in _private_forms(private_key).items()
    }
    for form, key in forms.items():
        assert ryjwt.RYJWT(key, algorithms=[alg]).decode(token) == claims, form


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_hmac_interop(alg: str, hmac_key: str, future: int) -> None:
    claims = {"sub": "sub", "exp": future}
    ours = ryjwt.RYJWT(hmac_key, algorithms=[alg])

    assert jwt.decode(ours.encode(claims), hmac_key, algorithms=[alg]) == claims
    assert ours.decode(jwt.encode(claims, hmac_key, algorithm=alg)) == claims
    assert ryjwt.RYJWT(hmac_key.encode(), algorithms=[alg]).decode(ours.encode(claims)) == claims


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
@pytest.mark.parametrize("key_len", [1, 63, 64, 65, 127, 128, 129, 300])
@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_hmac_key_lengths_interop(alg: str, key_len: int) -> None:
    """Keys shorter than, equal to and longer than the hash block (longer ones get hashed)."""
    key = bytes(range(256)) * 2
    key = key[:key_len].replace(b"-", b"+")  # never looks like a PEM
    ours = ryjwt.RYJWT(key, algorithms=[alg])
    for size in [0, 10, 50, 100, 200, 1000]:
        claims = {"sub": "x" * size}
        assert jwt.decode(ours.encode(claims), key, algorithms=[alg]) == claims
        assert ours.decode(jwt.encode(claims, key, algorithm=alg)) == claims


def test_one_rsa_key_serves_several_algorithms(
    private_keys: dict[str, PrivateKeyTypes],
    future: int,
) -> None:
    rsa_jwt = ryjwt.RYJWT(private_keys["RS256"], algorithms=["RS256", "PS512"])

    for alg in ["RS256", "PS512"]:
        token = rsa_jwt.encode({"exp": future}, algorithm=alg)
        assert jwt.get_unverified_header(token)["alg"] == alg
        assert rsa_jwt.decode(token) == {"exp": future}
