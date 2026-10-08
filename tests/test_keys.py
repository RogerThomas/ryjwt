import base64
import hashlib
from pathlib import Path
from typing import Any

import pytest
import ryjwt
from _support import ASYMMETRIC_ALGORITHMS, SigningKey, private_pem, public_pem
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, rsa

type KeyClass = type[ryjwt.PrivateKey] | type[ryjwt.PublicKey]


@pytest.mark.parametrize(
    ("algorithms", "match"),
    [
        pytest.param([], "must not be empty", id="empty"),
        pytest.param(["HS999"], "Unsupported algorithm", id="unknown"),
        pytest.param(["HS265"], "Unsupported algorithm", id="typo"),
        pytest.param(["none"], "Unsupported algorithm", id="none"),
        pytest.param(["HS256", "RS256"], "needs a PrivateKey or PublicKey", id="hmac-and-rsa"),
        pytest.param(["EdDSA"], "needs a PrivateKey or PublicKey", id="eddsa"),
    ],
)
def test_invalid_hmac_algorithms(algorithms: list[str], match: str, hmac_key: str) -> None:
    untyped_caller: Any = algorithms  # what an untyped caller could pass

    with pytest.raises(ValueError, match=match):
        ryjwt.SecretKey(hmac_key, algorithms=untyped_caller)


@pytest.mark.parametrize("key_class", [ryjwt.PrivateKey, ryjwt.PublicKey])
@pytest.mark.parametrize(
    ("algorithms", "match"),
    [
        pytest.param([], "must not be empty", id="empty"),
        pytest.param(["ES999"], "Unsupported algorithm", id="unknown"),
        pytest.param(["none"], "Unsupported algorithm", id="none"),
        pytest.param(["HS256"], "needs a SecretKey", id="hmac"),
        pytest.param(["ES256", "HS256"], "needs a SecretKey", id="ec-and-hmac"),
        pytest.param(["ES256", "ES384"], "same kind of key", id="two-curves"),
        pytest.param(["ES256", "EdDSA"], "same kind of key", id="ec-and-eddsa"),
    ],
)
def test_invalid_asymmetric_algorithms(
    key_class: KeyClass,
    algorithms: list[str],
    match: str,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    pem = private_pems["ES256"] if key_class is ryjwt.PrivateKey else public_pems["ES256"]
    untyped_caller: Any = algorithms  # what an untyped caller could pass

    with pytest.raises(ValueError, match=match):
        key_class(pem, algorithms=untyped_caller)


def test_algorithms_must_be_a_sequence(hmac_key: str) -> None:
    untyped_caller: Any = "HS256"  # what an untyped caller could pass

    with pytest.raises(TypeError):
        ryjwt.SecretKey(hmac_key, algorithms=untyped_caller)


def test_algorithms_property(
    hmac_key: str,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    assert ryjwt.SecretKey(hmac_key, algorithms=["HS512", "HS256", "HS512"]).algorithms == [
        "HS512",
        "HS256",
    ]
    assert ryjwt.PrivateKey(private_pems["RS256"], algorithms=["PS256", "RS256"]).algorithms == [
        "PS256",
        "RS256",
    ]
    assert ryjwt.PublicKey(public_pems["ES521"], algorithms=["ES521", "ES512"]).algorithms == [
        "ES521",
        "ES512",
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
        pytest.param("ssh-ed25519 AAAA", "asymmetric", id="ssh-ed25519"),
        pytest.param("ecdsa-sha2-nistp256 AAAA", "asymmetric", id="ssh-ecdsa"),
        pytest.param(
            "---- BEGIN SSH2 PUBLIC KEY ----\nAAAA\n---- END SSH2 PUBLIC KEY ----",
            "asymmetric",
            id="ssh2",
        ),
        pytest.param('{"kty": "OKP", "crv": "Ed25519", "x": "x"}', "asymmetric", id="jwk"),
        pytest.param(b'{"keys": [{"kty": "OKP"}]}', "asymmetric", id="jwks"),
        pytest.param("sk-ssh-ed25519@openssh.com AAAA", "asymmetric", id="ssh-fido"),
        pytest.param("sk-ecdsa-sha2-nistp256@openssh.com AAAA", "asymmetric", id="ssh-fido-ecdsa"),
        pytest.param("\n  ssh-rsa AAAA", "asymmetric", id="leading-whitespace"),
        pytest.param("\ud800" * 40, "lone surrogate", id="lone-surrogate"),
    ],
)
@pytest.mark.parametrize("length_check", ["checked", "skipped"])
def test_invalid_hmac_secrets(key: object, match: str, length_check: str) -> None:
    untyped_caller: Any = key  # what an untyped caller could pass

    with pytest.raises(ryjwt.InvalidKeyError, match=match):
        ryjwt.SecretKey(
            untyped_caller, algorithms=["HS256"], allow_short_secret=length_check == "skipped"
        )


def _encoded(der: bytes, encoding: str) -> str | bytes:
    match encoding:
        case "base64":
            return base64.b64encode(der).decode()
        case "base64url":
            return base64.urlsafe_b64encode(der).rstrip(b"=")
        case "base64-lines":
            return base64.encodebytes(der)
        case _:
            return der


@pytest.mark.parametrize(
    ("alg", "form", "encoding"),
    [
        pytest.param("RS256", serialization.PublicFormat.SubjectPublicKeyInfo, "base64", id="rsa"),
        pytest.param("ES256", serialization.PublicFormat.SubjectPublicKeyInfo, "base64", id="p256"),
        pytest.param(
            "EdDSA", serialization.PublicFormat.SubjectPublicKeyInfo, "base64", id="ed25519"
        ),
        pytest.param("RS256", serialization.PublicFormat.PKCS1, "base64", id="rsa-pkcs1"),
        pytest.param(
            "RS256", serialization.PublicFormat.SubjectPublicKeyInfo, "base64url", id="rsa-url"
        ),
        pytest.param(
            "ES256", serialization.PublicFormat.SubjectPublicKeyInfo, "base64url", id="p256-url"
        ),
        pytest.param(
            "RS256", serialization.PublicFormat.SubjectPublicKeyInfo, "base64-lines", id="lines"
        ),
        pytest.param("RS256", serialization.PublicFormat.SubjectPublicKeyInfo, "der", id="rsa-der"),
        pytest.param("RS256", serialization.PublicFormat.PKCS1, "der", id="rsa-pkcs1-der"),
        pytest.param(
            "ES256", serialization.PublicFormat.SubjectPublicKeyInfo, "der", id="p256-der"
        ),
        pytest.param(
            "EdDSA", serialization.PublicFormat.SubjectPublicKeyInfo, "der", id="ed25519-der"
        ),
    ],
)
@pytest.mark.parametrize("length_check", ["checked", "skipped"])
def test_hmac_rejects_public_key_der(
    alg: ryjwt.AsymmetricAlgorithm,
    form: serialization.PublicFormat,
    encoding: str,
    length_check: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    """A public key as DER, raw or in base64 (as Keycloak shows a realm's public key)."""
    der = private_keys[alg].public_key().public_bytes(serialization.Encoding.DER, form)

    with pytest.raises(ryjwt.InvalidKeyError, match="looks like an asymmetric key"):
        ryjwt.SecretKey(
            _encoded(der, encoding),
            algorithms=["HS256"],
            allow_short_secret=length_check == "skipped",
        )


def test_hmac_accepts_random_secrets() -> None:
    """Random secrets, raw and in base64, are never taken for public keys, even those starting as
    DER does (0x30), which the check parses."""
    for seed in range(1000):
        digest = hashlib.sha512(b"seed-%d" % seed).digest()
        for secret in (digest[:32], digest, b"\x30" + digest[1:32], b"\x30" + digest[1:]):
            for encoded in (secret, base64.b64encode(secret), base64.urlsafe_b64encode(secret)):
                ryjwt.SecretKey(encoded, algorithms=["HS256"])


@pytest.mark.parametrize(("alg", "min_len"), [("HS256", 32), ("HS384", 48), ("HS512", 64)])
def test_hmac_secret_minimum_length(alg: ryjwt.HMACAlgorithm, min_len: int) -> None:
    with pytest.raises(
        ryjwt.InvalidKeyError,
        match=rf'"{alg}" needs a secret of at least {min_len} bytes, got {min_len - 1} \(pass '
        r"allow_short_secret=True to accept it\)",
    ):
        ryjwt.SecretKey(b"s" * (min_len - 1), algorithms=[alg])

    assert ryjwt.SecretKey(b"s" * min_len, algorithms=[alg]).algorithms == [alg]


def test_hmac_secret_minimum_length_with_several_algorithms() -> None:
    with pytest.raises(ryjwt.InvalidKeyError, match='"HS512" needs a secret of at least 64 bytes'):
        ryjwt.SecretKey(b"s" * 63, algorithms=["HS256", "HS512", "HS384"])

    assert ryjwt.SecretKey(b"s" * 64, algorithms=["HS256", "HS512"]).algorithms == [
        "HS256",
        "HS512",
    ]


def test_hmac_str_secret_length_is_in_utf8_bytes() -> None:
    with pytest.raises(ryjwt.InvalidKeyError, match="got 31"):
        ryjwt.SecretKey("é" * 15 + "s", algorithms=["HS256"])

    assert ryjwt.SecretKey("é" * 16, algorithms=["HS256"]).algorithms == ["HS256"]


def test_hmac_allow_short_secret() -> None:
    hmac = ryjwt.SecretKey("secret", algorithms=["HS256"], allow_short_secret=True)
    token = hmac.encode({"sub": "sub"})

    assert hmac.decode(token) == {"sub": "sub"}
    with pytest.raises(ryjwt.InvalidSignatureError):
        ryjwt.SecretKey("other", algorithms=["HS256"], allow_short_secret=True).decode(token)


@pytest.fixture(name="ed448_key", scope="module")
def _ed448_key() -> ed448.Ed448PrivateKey:
    """A key of a type ryjwt doesn't support."""
    return ed448.Ed448PrivateKey.generate()


@pytest.fixture(name="encrypted_pem", scope="module")
def _encrypted_pem(private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey]) -> bytes:
    return private_keys["ES256"].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"password"),
    )


@pytest.mark.parametrize(
    ("key", "alg", "match"),
    [
        pytest.param("not-a-pem", "RS256", "Expected a PEM", id="not-a-pem"),
        pytest.param("certificate", "RS256", "PEM type", id="certificate"),
        pytest.param("encrypted", "ES256", "Encrypted", id="encrypted"),
        pytest.param("es256", "RS256", 'can\'t be used for "RS256"', id="ec-key-for-rsa"),
        pytest.param("es384", "ES256", 'can\'t be used for "ES256"', id="other-curve"),
        pytest.param("rs256", "EdDSA", 'can\'t be used for "EdDSA"', id="rsa-key-for-eddsa"),
        pytest.param("small-rsa", "RS256", 'can\'t be used for "RS256"', id="small-rsa"),
        pytest.param("ed448", "EdDSA", 'can\'t be used for "EdDSA"', id="ed448"),
        pytest.param("key-object", "ES256", "str or bytes", id="key-object"),
        pytest.param("object", "RS256", "str or bytes", id="object"),
        pytest.param("lone-surrogate", "ES256", "lone surrogate", id="lone-surrogate"),
    ],
)
def test_invalid_private_keys(
    key: str,
    alg: ryjwt.AsymmetricAlgorithm,
    match: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    small_rsa_key: rsa.RSAPrivateKey,
    ed448_key: ed448.Ed448PrivateKey,
    encrypted_pem: bytes,
) -> None:
    keys: dict[str, object] = {
        "not-a-pem": "not-a-pem",
        "certificate": b"-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----",
        "encrypted": encrypted_pem,
        "es256": private_pems["ES256"],
        "es384": private_pems["ES384"],
        "rs256": private_pems["RS256"],
        "small-rsa": private_pem(small_rsa_key),
        "ed448": private_pem(ed448_key),
        "key-object": private_keys["ES256"],
        "object": object(),
        "lone-surrogate": "\ud800",
    }
    untyped_caller: Any = keys[key]  # what an untyped caller could pass

    with pytest.raises(ryjwt.InvalidKeyError, match=match):
        ryjwt.PrivateKey(untyped_caller, algorithms=[alg])


@pytest.mark.parametrize(
    ("key", "alg", "match"),
    [
        pytest.param(
            "small-rsa",
            "RS256",
            "RSA keys must be 2048 to 8192 bits, this one has 1024",
            id="small-rsa",
        ),
        pytest.param(
            "small-rsa-pkcs1",
            "PS256",
            "RSA keys must be 2048 to 8192 bits, this one has 1024",
            id="small-rsa-pkcs1",
        ),
        pytest.param("not-a-pem", "RS256", "Expected a PEM", id="not-a-pem"),
        pytest.param("certificate", "RS256", "PEM type", id="certificate"),
        pytest.param("es256", "RS256", 'can\'t be used for "RS256"', id="ec-key-for-rsa"),
        pytest.param("es384", "ES256", 'can\'t be used for "ES256"', id="other-curve"),
        pytest.param("rs256", "EdDSA", 'can\'t be used for "EdDSA"', id="rsa-key-for-eddsa"),
        pytest.param("ed448", "EdDSA", 'can\'t be used for "EdDSA"', id="ed448"),
        pytest.param("key-object", "ES256", "str or bytes", id="key-object"),
        pytest.param("lone-surrogate", "ES256", "lone surrogate", id="lone-surrogate"),
    ],
)
def test_invalid_public_keys(
    key: str,
    alg: ryjwt.AsymmetricAlgorithm,
    match: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    small_rsa_key: rsa.RSAPrivateKey,
    ed448_key: ed448.Ed448PrivateKey,
) -> None:
    keys: dict[str, object] = {
        "small-rsa": public_pem(small_rsa_key),
        "small-rsa-pkcs1": public_pem(small_rsa_key, serialization.PublicFormat.PKCS1),
        "not-a-pem": "not-a-pem",
        "certificate": b"-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----",
        "es256": public_pems["ES256"],
        "es384": public_pems["ES384"],
        "rs256": public_pems["RS256"],
        "ed448": public_pem(ed448_key),
        "key-object": private_keys["ES256"].public_key(),
        "lone-surrogate": "\ud800",
    }
    untyped_caller: Any = keys[key]  # what an untyped caller could pass

    with pytest.raises(ryjwt.InvalidKeyError, match=match):
        ryjwt.PublicKey(untyped_caller, algorithms=[alg])


@pytest.mark.parametrize(
    ("alg", "form"),
    [*((alg, "spki") for alg in ASYMMETRIC_ALGORITHMS), ("RS256", "pkcs1")],
)
def test_private_key_rejects_public_pems(
    alg: ryjwt.AsymmetricAlgorithm,
    form: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    forms = {
        "spki": serialization.PublicFormat.SubjectPublicKeyInfo,
        "pkcs1": serialization.PublicFormat.PKCS1,
    }
    pem = public_pem(private_keys[alg], forms[form])

    with pytest.raises(ryjwt.InvalidKeyError, match="PrivateKey needs a private key"):
        ryjwt.PrivateKey(pem, algorithms=[alg])


@pytest.mark.parametrize(
    ("alg", "form"),
    [
        *((alg, "pkcs8") for alg in ASYMMETRIC_ALGORITHMS),
        ("RS256", "traditional"),
        ("ES256", "traditional"),
    ],
)
def test_public_key_rejects_private_pems(
    alg: ryjwt.AsymmetricAlgorithm,
    form: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    forms = {
        "pkcs8": serialization.PrivateFormat.PKCS8,
        "traditional": serialization.PrivateFormat.TraditionalOpenSSL,
    }
    pem = private_pem(private_keys[alg], forms[form])

    with pytest.raises(ryjwt.InvalidKeyError, match="PublicKey needs a public key"):
        ryjwt.PublicKey(pem, algorithms=[alg])


def test_public_keys_can_only_decode(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    token = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"]).encode({"sub": "sub"})
    verifier = ryjwt.PublicKey(public_pems["ES256"], algorithms=["ES256"])

    assert verifier.decode(token) == {"sub": "sub"}
    assert not hasattr(verifier, "encode")


@pytest.mark.parametrize("path_type", [str, Path])
def test_from_path(
    path_type: type[str] | type[Path],
    tmp_path: Path,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    (tmp_path / "private.pem").write_bytes(private_pems["ES256"])
    (tmp_path / "public.pem").write_bytes(public_pems["ES256"])

    signer = ryjwt.PrivateKey.from_path(path_type(tmp_path / "private.pem"), algorithms=["ES256"])
    verifier = ryjwt.PublicKey.from_path(path_type(tmp_path / "public.pem"), algorithms=["ES256"])

    assert verifier.decode(signer.encode({"sub": "sub"})) == {"sub": "sub"}
    assert signer.algorithms == verifier.algorithms == ["ES256"]


@pytest.mark.parametrize("key_class", [ryjwt.PrivateKey, ryjwt.PublicKey])
def test_from_path_os_errors_propagate(key_class: KeyClass, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError) as missing:
        key_class.from_path(tmp_path / "missing.pem", algorithms=["ES256"])
    # Reading a directory: IsADirectoryError, or PermissionError on Windows.
    with pytest.raises((IsADirectoryError, PermissionError)):
        key_class.from_path(str(tmp_path), algorithms=["ES256"])

    assert missing.value.filename == str(tmp_path / "missing.pem")


def test_from_path_rejects_unusable_contents(
    tmp_path: Path,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    (tmp_path / "empty.pem").write_bytes(b"")
    (tmp_path / "private.pem").write_bytes(private_pems["ES256"])
    (tmp_path / "public.pem").write_bytes(public_pems["ES256"])

    with pytest.raises(ryjwt.InvalidKeyError, match="Expected a PEM"):
        ryjwt.PrivateKey.from_path(tmp_path / "empty.pem", algorithms=["ES256"])
    with pytest.raises(ryjwt.InvalidKeyError, match="Expected a PEM"):
        ryjwt.PublicKey.from_path(tmp_path / "empty.pem", algorithms=["ES256"])
    with pytest.raises(ryjwt.InvalidKeyError, match="PrivateKey needs a private key"):
        ryjwt.PrivateKey.from_path(tmp_path / "public.pem", algorithms=["ES256"])
    with pytest.raises(ryjwt.InvalidKeyError, match="PublicKey needs a public key"):
        ryjwt.PublicKey.from_path(tmp_path / "private.pem", algorithms=["ES256"])
    with pytest.raises(ryjwt.InvalidKeyError, match='can\'t be used for "ES384"'):
        ryjwt.PrivateKey.from_path(tmp_path / "private.pem", algorithms=["ES384"])


def test_hmac_has_no_from_path() -> None:
    assert not hasattr(ryjwt.SecretKey, "from_path")


@pytest.fixture(name="ec_parameters_pem")
def _ec_parameters_pem() -> bytes:
    """The `EC PARAMETERS` block `openssl ecparam -genkey -name prime256v1` writes first."""
    return b"-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"


def test_pem_ec_parameters_are_skipped(
    ec_parameters_pem: bytes,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    sec1 = private_pem(private_keys["ES256"], serialization.PrivateFormat.TraditionalOpenSSL)
    signer = ryjwt.PrivateKey(ec_parameters_pem + sec1, algorithms=["ES256"])
    verifier = ryjwt.PublicKey(ec_parameters_pem + public_pems["ES256"], algorithms=["ES256"])

    assert verifier.decode(signer.encode({"sub": "sub"})) == {"sub": "sub"}


def test_pem_with_several_keys_is_rejected(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    with pytest.raises(ryjwt.InvalidKeyError, match="found 2 blocks: PRIVATE KEY, PRIVATE KEY"):
        ryjwt.PrivateKey(private_pems["ES256"] + private_pems["ES256"], algorithms=["ES256"])
    with pytest.raises(ryjwt.InvalidKeyError, match="found 2 blocks: PUBLIC KEY, PUBLIC KEY"):
        ryjwt.PublicKey(public_pems["ES256"] + public_pems["ES384"], algorithms=["ES256"])


def test_pem_without_a_key_block_is_rejected(ec_parameters_pem: bytes) -> None:
    with pytest.raises(ryjwt.InvalidKeyError, match="no key block"):
        ryjwt.PrivateKey(ec_parameters_pem, algorithms=["ES256"])
    with pytest.raises(ryjwt.InvalidKeyError, match="no key block"):
        ryjwt.PublicKey(ec_parameters_pem, algorithms=["ES256"])


def test_small_order_ed25519_public_key_is_rejected() -> None:
    # Ed25519's SubjectPublicKeyInfo prefix, then the key: the identity point, against which a
    # signature (R, S) with R = SB verifies for any message.
    der = bytes.fromhex("302a300506032b6570032100") + b"\x01" + bytes(31)
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END PUBLIC KEY-----\n"

    with pytest.raises(ryjwt.InvalidKeyError, match="small-order Ed25519 point"):
        ryjwt.PublicKey(pem, algorithms=["EdDSA"])
