"""Signatures that mustn't verify, for every algorithm."""

import base64
import json

import pytest
import ryjwt
from _support import ASYMMETRIC_ALGORITHMS, SigningKey, b64, private_pem, public_pem
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils


def _b64decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _with_signature(token: str, signature: bytes) -> str:
    signing_input = token.rsplit(".", 1)[0]
    return f"{signing_input}.{b64(signature)}"


def _signing_input(alg: str) -> bytes:
    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    return f"{header}.{b64(b'{"sub":"sub"}')}".encode()


@pytest.fixture(name="other_private_keys", scope="module")
def _other_private_keys() -> dict[ryjwt.AsymmetricAlgorithm, SigningKey]:
    """Another key for each algorithm, of the kind `private_keys` has for it."""
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


@pytest.mark.parametrize("tamper", ["bit-flipped", "truncated", "extended", "zeros", "empty"])
@pytest.mark.parametrize("alg", ASYMMETRIC_ALGORITHMS)
def test_tampered_signatures(
    alg: ryjwt.AsymmetricAlgorithm,
    tamper: str,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    token = ryjwt.PrivateKey(private_pems[alg], algorithms=[alg]).encode({"sub": "sub"})
    signature = _b64decode(token.rsplit(".", 1)[1])
    tampered = {
        "bit-flipped": bytes([signature[0] ^ 1]) + signature[1:],
        "truncated": signature[:-1],
        "extended": signature + b"\0",
        "zeros": bytes(len(signature)),
        "empty": b"",
    }
    verifier = ryjwt.PublicKey(public_pems[alg], algorithms=[alg])

    assert verifier.decode(token) == {"sub": "sub"}
    with pytest.raises(ryjwt.InvalidSignatureError):
        verifier.decode(_with_signature(token, tampered[tamper]))


@pytest.mark.parametrize("alg", ASYMMETRIC_ALGORITHMS)
def test_signed_by_another_key(
    alg: ryjwt.AsymmetricAlgorithm,
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    other_private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    other = private_pem(other_private_keys[alg])
    token = ryjwt.PrivateKey(other, algorithms=[alg]).encode({"sub": "sub"})

    with pytest.raises(ryjwt.InvalidSignatureError):
        ryjwt.PublicKey(public_pems[alg], algorithms=[alg]).decode(token)


@pytest.mark.parametrize("alg", ["ES256", "ES256K", "ES384", "ES512", "ES521"])
def test_ecdsa_signature_in_der_form(
    alg: ryjwt.AsymmetricAlgorithm,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    """JWS signatures are r and s side by side; the DER form other protocols use must fail."""
    token = ryjwt.PrivateKey(private_pems[alg], algorithms=[alg]).encode({"sub": "sub"})
    signature = _b64decode(token.rsplit(".", 1)[1])
    half = len(signature) // 2
    der = utils.encode_dss_signature(
        int.from_bytes(signature[:half]), int.from_bytes(signature[half:])
    )

    with pytest.raises(ryjwt.InvalidSignatureError):
        ryjwt.PublicKey(public_pems[alg], algorithms=[alg]).decode(_with_signature(token, der))


@pytest.mark.parametrize(
    ("alg", "signed_as"),
    [
        pytest.param("PS256", padding.PKCS1v15(), id="RS256-labelled-PS256"),
        pytest.param(
            "RS256",
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            id="PS256-labelled-RS256",
        ),
    ],
)
def test_rsa_signature_under_the_other_padding(
    alg: ryjwt.AsymmetricAlgorithm,
    signed_as: padding.AsymmetricPadding,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    """A key allowed both paddings checks each token with the one its header names."""
    private_key = private_keys["RS256"]
    assert isinstance(private_key, rsa.RSAPrivateKey)
    signing_input = _signing_input(alg)
    signature = private_key.sign(signing_input, signed_as, hashes.SHA256())
    verifier = ryjwt.PublicKey(public_pem(private_key), algorithms=["RS256", "PS256"])

    with pytest.raises(ryjwt.InvalidSignatureError):
        verifier.decode(f"{signing_input.decode()}.{b64(signature)}")
