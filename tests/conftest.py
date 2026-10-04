import base64
import hashlib
import hmac
import time
from typing import TYPE_CHECKING

import pytest
import ryjwt
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

if TYPE_CHECKING:
    from collections.abc import Callable

    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(name="private_keys", scope="session")
def _private_keys() -> dict[str, PrivateKeyTypes]:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p521_key = ec.generate_private_key(ec.SECP521R1())
    return {
        "RS256": rsa_key,
        "RS384": rsa_key,
        "RS512": rsa_key,
        "PS256": rsa_key,
        "PS384": rsa_key,
        "PS512": rsa_key,
        "ES256": ec.generate_private_key(ec.SECP256R1()),
        "ES256K": ec.generate_private_key(ec.SECP256K1()),
        "ES384": ec.generate_private_key(ec.SECP384R1()),
        "ES512": p521_key,
        "ES521": p521_key,
        "EdDSA": ed25519.Ed25519PrivateKey.generate(),
    }


@pytest.fixture(name="hmac_key")
def _hmac_key() -> str:
    return "hmac-key" * 8


@pytest.fixture(name="hmac_jwt")
def _hmac_jwt(hmac_key: str) -> ryjwt.RYJWT:
    return ryjwt.RYJWT(hmac_key, algorithms=["HS256"])


@pytest.fixture(name="future")
def _future() -> int:
    return int(time.time()) + 3600


@pytest.fixture(name="past")
def _past() -> int:
    return int(time.time()) - 3600


@pytest.fixture(name="raw_hs256_token")
def _raw_hs256_token(hmac_key: str) -> Callable[[bytes, bytes], str]:
    """Builds an HS256 token from raw header/payload JSON bytes (which may be malformed)."""

    def make(header: bytes, payload: bytes) -> str:
        signing_input = f"{_b64(header)}.{_b64(payload)}"
        signature = hmac.new(hmac_key.encode(), signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{_b64(signature)}"

    return make
