import sys
import time
from collections.abc import Iterator

import pytest
import ryjwt
from _support import JWKSServer, RawHS256Token, SigningKey, private_pem, public_pem, serve_jwks
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

collect_ignore = ["typing_errors"]  # code that must not type-check, see test_typing_errors.py


@pytest.fixture(name="private_keys", scope="session")
def _private_keys() -> dict[ryjwt.AsymmetricAlgorithm, SigningKey]:
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


@pytest.fixture(name="private_pems", scope="session")
def _private_pems(
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> dict[ryjwt.AsymmetricAlgorithm, bytes]:
    """`private_keys` as PKCS#8 PEMs."""
    return {alg: private_pem(key) for alg, key in private_keys.items()}


@pytest.fixture(name="public_pems", scope="session")
def _public_pems(
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> dict[ryjwt.AsymmetricAlgorithm, bytes]:
    """The public halves of `private_keys`, as SubjectPublicKeyInfo PEMs."""
    return {alg: public_pem(key) for alg, key in private_keys.items()}


@pytest.fixture(name="small_rsa_key", scope="session")
def _small_rsa_key() -> rsa.RSAPrivateKey:
    """An RSA key under the 2048 bits ryjwt requires."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - testing rejection


@pytest.fixture(name="hmac_key")
def _hmac_key() -> str:
    return "hmac-key" * 8


@pytest.fixture(name="hmac_jwt", params=["msgspec", "jiter"])
def _hmac_jwt(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    hmac_key: str,
) -> ryjwt.SecretKey:
    """An HS256 `SecretKey` decoding dicts with msgspec, or with jiter as when msgspec isn't
    installed."""
    with monkeypatch.context() as m:
        if request.param == "jiter":
            m.setitem(sys.modules, "msgspec.json", None)
        return ryjwt.SecretKey(hmac_key, algorithms=["HS256"])


@pytest.fixture(name="future")
def _future() -> int:
    return int(time.time()) + 3600


@pytest.fixture(name="past")
def _past() -> int:
    return int(time.time()) - 3600


@pytest.fixture(name="raw_hs256_token")
def _raw_hs256_token(hmac_key: str) -> RawHS256Token:
    """Builds an HS256 token from raw header/payload JSON bytes (which may be malformed)."""
    return RawHS256Token(hmac_key)


@pytest.fixture(name="server")
def _server() -> Iterator[JWKSServer]:
    """A real HTTP server on 127.0.0.1, in a daemon thread."""
    yield from serve_jwks()
