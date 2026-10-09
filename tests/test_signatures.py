"""Signatures that mustn't verify, for every algorithm; and the published examples that must."""

import base64
import json
from datetime import timedelta

import pytest
import ryjwt
from _support import ASYMMETRIC_ALGORITHMS, SigningKey, b64, private_pem, public_pem
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

RFC_7515_CLAIMS = {"iss": "joe", "exp": 1_300_819_380, "http://example.com/is_root": True}
"""The claims of RFC 7515's examples, which expired in 2011."""

RFC_7515_HS256_JWK = {
    "kty": "oct",
    "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
}
RFC_7515_HS256_JWS = (
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsD"
    "QogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gF"
    "WFOEjXk"
)
"""RFC 7515's HS256 example (appendix A.1): the secret, as a JWK, and the token."""

RFC_7515_EXAMPLES = [
    pytest.param(
        "RS256",
        {
            "kty": "RSA",
            "n": (
                "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPM"
                "EzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-"
                "bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3"
                "qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9g"
                "b54h4FRWyuXpoQ"
            ),
            "e": "AQAB",
        },
        (
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtc"
            "GxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOi"
            "Zj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_"
            "nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwu"
            "sC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywl"
            "VmtVrBp0igcN_IoypGlUPQGe77Rw"
        ),
        id="A.2-RS256",
    ),
    pytest.param(
        "ES256",
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        },
        (
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtc"
            "GxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djx"
            "La8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        ),
        id="A.3-ES256",
    ),
]
"""RFC 7515's public-key examples (appendix A.2 and A.3): the algorithm, the public JWK and the
token."""

RFC_8037_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
RFC_8037_JWS = (
    "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)
"""RFC 8037's Ed25519 example (appendix A.2 and A.4), whose payload is text, not claims."""


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


def _check_rfc_7515_example(key: ryjwt.SecretKey | ryjwt.PublicKey, token: str) -> None:
    """It verifies (the claims are checked after the signature, and expired in 2011), and doesn't
    once its signature is changed."""
    with pytest.raises(ryjwt.ExpiredSignatureError):
        key.decode(token)
    assert key.decode(token, leeway=timedelta(days=365 * 100)) == RFC_7515_CLAIMS
    with pytest.raises(ryjwt.InvalidSignatureError):
        key.decode(_with_signature(token, _b64decode(token.rsplit(".", 1)[1])[::-1]))


def test_rfc_7515_hs256_example() -> None:
    key = ryjwt.SecretKey(_b64decode(RFC_7515_HS256_JWK["k"]), algorithms=["HS256"])

    _check_rfc_7515_example(key, RFC_7515_HS256_JWS)


@pytest.mark.parametrize(("alg", "jwk", "token"), RFC_7515_EXAMPLES)
def test_rfc_7515_public_key_examples(
    alg: ryjwt.AsymmetricAlgorithm, jwk: dict[str, str], token: str
) -> None:
    key = ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=[alg])

    _check_rfc_7515_example(key, token)


def test_rfc_8037_ed25519_example() -> None:
    """It verifies: the payload is then rejected, as it's text, not claims."""
    key = ryjwt.PublicKey.from_jwks({"keys": [RFC_8037_JWK]}, algorithms=["EdDSA"])

    with pytest.raises(ryjwt.DecodeError, match="Invalid payload JSON"):
        key.decode(RFC_8037_JWS)
    with pytest.raises(ryjwt.InvalidSignatureError):
        key.decode(_with_signature(RFC_8037_JWS, bytes(64)))
