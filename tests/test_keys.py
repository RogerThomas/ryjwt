from typing import TYPE_CHECKING, Any

import pytest
import ryjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, rsa

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


def _pem(private_key: PrivateKeyTypes) -> bytes:
    return private_key.public_key().public_bytes(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.mark.parametrize(
    ("algorithms", "match"),
    [
        pytest.param([], "must not be empty", id="empty"),
        pytest.param(["HS999"], "Unsupported algorithm", id="unknown"),
        pytest.param(["none"], "Unsupported algorithm", id="none"),
        pytest.param(["HS256", "RS256"], "same kind of key", id="hmac-and-rsa"),
        pytest.param(["ES256", "ES384"], "same kind of key", id="two-curves"),
    ],
)
def test_invalid_algorithms(algorithms: list[str], match: str, hmac_key: str) -> None:
    with pytest.raises(ValueError, match=match):
        ryjwt.RYJWT(hmac_key, algorithms=algorithms)


def test_algorithms_must_be_a_sequence(hmac_key: str) -> None:
    with pytest.raises(TypeError):
        ryjwt.RYJWT(hmac_key, algorithms="HS256")  # pyright: ignore[reportArgumentType]


def test_algorithms_property(hmac_key: str) -> None:
    assert ryjwt.RYJWT(hmac_key, algorithms=["HS512", "HS256", "HS512"]).algorithms == [
        "HS512",
        "HS256",
    ]


@pytest.mark.parametrize(
    ("key", "match"),
    [
        pytest.param("", "must not be empty", id="empty"),
        pytest.param(1, "str or bytes", id="int"),
        pytest.param(
            "-----BEGIN PUBLIC KEY-----\nMII=\n-----END PUBLIC KEY-----",
            "asymmetric",
            id="pem",
        ),
        pytest.param("ssh-rsa AAAA", "asymmetric", id="ssh"),
    ],
)
def test_invalid_hmac_keys(key: Any, match: str) -> None:  # noqa: ANN401
    with pytest.raises(ryjwt.InvalidKeyError, match=match):
        ryjwt.RYJWT(key, algorithms=["HS256"])


def test_invalid_asymmetric_keys(private_keys: dict[str, PrivateKeyTypes]) -> None:
    encrypted = private_keys["ES256"].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"password"),
    )
    small_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - testing rejection
    cases: list[tuple[Any, str]] = [
        ("not-a-pem", "RS256"),
        (b"-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----", "RS256"),
        (encrypted, "ES256"),
        (_pem(private_keys["ES256"]), "RS256"),
        (_pem(private_keys["ES384"]), "ES256"),
        (private_keys["ES384"], "ES256"),
        (_pem(private_keys["RS256"]), "EdDSA"),
        (small_rsa, "RS256"),
        (ed448.Ed448PrivateKey.generate(), "EdDSA"),
        (object(), "RS256"),
    ]
    for key, alg in cases:
        with pytest.raises(ryjwt.InvalidKeyError):
            ryjwt.RYJWT(key, algorithms=[alg])


def test_public_keys_can_only_decode(private_keys: dict[str, PrivateKeyTypes]) -> None:
    token = ryjwt.RYJWT(private_keys["ES256"], algorithms=["ES256"]).encode({"sub": "sub"})
    verifier = ryjwt.RYJWT(_pem(private_keys["ES256"]), algorithms=["ES256"])

    assert verifier.decode(token) == {"sub": "sub"}
    with pytest.raises(ryjwt.InvalidKeyError, match="public key"):
        verifier.encode({"sub": "sub"})
