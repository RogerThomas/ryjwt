"""Tokens ryjwt signs must verify with PyJWT, and vice versa, for every algorithm and PEM form."""

from typing import get_args

import jwt
import pytest
import ryjwt
from _support import ASYMMETRIC_ALGORITHMS, SigningKey, private_pem, public_pem
from cryptography.hazmat.primitives import serialization


def _forms(*forms: str) -> list[tuple[ryjwt.AsymmetricAlgorithm, str]]:
    """Each algorithm, with each of `forms` its keys come in: only RSA keys have a PKCS#1 public
    form, and Ed25519 keys have no traditional private one."""
    return [
        (alg, form)
        for alg in ASYMMETRIC_ALGORITHMS
        for form in forms
        if (form != "pkcs1" or alg.startswith(("RS", "PS")))
        and (form != "traditional" or alg != "EdDSA")
    ]


def _pem(private_key: SigningKey, form: str) -> str | bytes:
    """The PEM of `private_key` (pkcs8, traditional) or its public key (spki, pkcs1): PKCS#8 and
    SubjectPublicKeyInfo as bytes, the traditional and PKCS#1 forms as str."""
    match form:
        case "pkcs8":
            return private_pem(private_key)
        case "traditional":
            return private_pem(private_key, serialization.PrivateFormat.TraditionalOpenSSL).decode()
        case "spki":
            return public_pem(private_key)
        case _:
            return public_pem(private_key, serialization.PublicFormat.PKCS1).decode()


def test_algorithm_aliases_list_every_algorithm() -> None:
    assert list(get_args(ryjwt.AsymmetricAlgorithm.__value__)) == ASYMMETRIC_ALGORITHMS
    assert list(get_args(ryjwt.HMACAlgorithm.__value__)) == ["HS256", "HS384", "HS512"]


@pytest.mark.parametrize(("alg", "form"), _forms("pkcs8", "traditional"))
def test_ryjwt_tokens_verify_with_pyjwt(
    alg: ryjwt.AsymmetricAlgorithm,
    form: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    future: int,
) -> None:
    private_key = private_keys[alg]
    claims = {"sub": "sub", "exp": future}

    token = ryjwt.PrivateKey(_pem(private_key, form), algorithms=[alg]).encode(claims)

    assert jwt.decode(token, private_key.public_key(), algorithms=[alg]) == claims
    assert jwt.get_unverified_header(token) == {"alg": alg, "typ": "JWT"}


@pytest.mark.parametrize(("alg", "form"), _forms("pkcs8", "traditional", "spki", "pkcs1"))
def test_pyjwt_tokens_verify_with_ryjwt(
    alg: ryjwt.AsymmetricAlgorithm,
    form: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    future: int,
) -> None:
    private_key = private_keys[alg]
    claims = {"sub": "sub", "exp": future}
    token = jwt.encode(claims, private_key, algorithm=alg)
    key_class = ryjwt.PublicKey if form in {"spki", "pkcs1"} else ryjwt.PrivateKey

    assert key_class(_pem(private_key, form), algorithms=[alg]).decode(token) == claims


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_hmac_interop(alg: ryjwt.HMACAlgorithm, hmac_key: str, future: int) -> None:
    claims = {"sub": "sub", "exp": future}
    ours = ryjwt.SecretKey(hmac_key, algorithms=[alg])

    assert jwt.decode(ours.encode(claims), hmac_key, algorithms=[alg]) == claims
    assert ours.decode(jwt.encode(claims, hmac_key, algorithm=alg)) == claims
    assert (
        ryjwt.SecretKey(hmac_key.encode(), algorithms=[alg]).decode(ours.encode(claims)) == claims
    )


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
@pytest.mark.parametrize("key_len", [1, 63, 64, 65, 127, 128, 129, 300])
@pytest.mark.parametrize("size", [0, 10, 50, 100, 200, 1000])
@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_hmac_key_lengths_interop(alg: ryjwt.HMACAlgorithm, key_len: int, size: int) -> None:
    """Keys shorter than, equal to and longer than the hash block (longer ones get hashed)."""
    key = bytes(range(256)) * 2
    key = key[:key_len].replace(b"-", b"+")  # never looks like a PEM
    ours = ryjwt.SecretKey(key, algorithms=[alg], allow_short_secret=True)
    claims = {"sub": "x" * size}

    assert jwt.decode(ours.encode(claims), key, algorithms=[alg]) == claims
    assert ours.decode(jwt.encode(claims, key, algorithm=alg)) == claims


def test_one_rsa_key_serves_several_algorithms(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    future: int,
) -> None:
    algorithms: list[ryjwt.AsymmetricAlgorithm] = ["RS256", "PS512"]
    rsa_jwt = ryjwt.PrivateKey(private_pems["RS256"], algorithms=algorithms)
    verifier = ryjwt.PublicKey(public_pems["RS256"], algorithms=algorithms)

    for alg in algorithms:
        token = rsa_jwt.encode({"exp": future}, algorithm=alg)
        assert jwt.get_unverified_header(token)["alg"] == alg
        assert rsa_jwt.decode(token) == {"exp": future}
        assert verifier.decode(token) == {"exp": future}
