"""`PublicKey.from_jwks`: JWKS documents shaped like real providers', and every key rule."""

import base64
import json
from types import MappingProxyType
from typing import Any

import jwt
import pytest
import ryjwt
from _support import (
    ASYMMETRIC_ALGORITHMS,
    JWK,
    ClaimsModel,
    ClaimsStruct,
    SigningKey,
    b64,
    make_jwk,
)
from cryptography.hazmat.primitives.asymmetric import ec, rsa


@pytest.fixture(name="old_rsa_key", scope="session")
def _old_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(name="rsa_key")
def _rsa_key(private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey]) -> SigningKey:
    return private_keys["RS256"]


@pytest.fixture(name="ec_key")
def _ec_key(private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey]) -> SigningKey:
    return private_keys["ES256"]


@pytest.fixture(name="mixed_jwks")
def _mixed_jwks(rsa_key: SigningKey, ec_key: SigningKey) -> ryjwt.PublicKey:
    """An RSA key ("rsa") and a P-256 key ("ec"), for RS256 and ES256."""
    jwks = {"keys": [make_jwk(rsa_key, kid="rsa"), make_jwk(ec_key, kid="ec")]}
    return ryjwt.PublicKey.from_jwks(jwks, algorithms=["RS256", "ES256"])


@pytest.mark.parametrize(
    "members",
    [
        pytest.param(
            {"use": "sig", "kid": "kid", "x5t": "x5t", "x5c": ["x5c"], "alg": "RS256"},
            id="auth0",
        ),
        pytest.param({"alg": "RS256", "kid": "kid", "use": "sig"}, id="okta-google"),
        pytest.param(
            {
                "use": "sig",
                "kid": "kid",
                "x5t": "x5t",
                "x5c": ["x5c"],
                "cloud_instance_name": "cloud-instance-name",
                "issuer": "issuer",
            },
            id="entra",
        ),
    ],
)
def test_provider_shaped_rsa_jwks(
    members: dict[str, Any],
    rsa_key: SigningKey,
    old_rsa_key: SigningKey,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    future: int,
) -> None:
    claims = {"sub": "sub", "exp": future}
    jwks = {
        "keys": [
            make_jwk(old_rsa_key, **(members | {"kid": "old-kid"})),
            make_jwk(rsa_key, **members),
        ]
    }
    verifier = ryjwt.PublicKey.from_jwks(json.dumps(jwks), algorithms=["RS256"])
    signer = ryjwt.PrivateKey(private_pems["RS256"], algorithms=["RS256"])

    pyjwt_token = jwt.encode(claims, rsa_key, algorithm="RS256", headers={"kid": "kid"})
    assert verifier.decode(pyjwt_token) == claims
    assert verifier.decode(signer.encode(claims, headers={"kid": "kid"})) == claims
    old_token = jwt.encode(claims, old_rsa_key, algorithm="RS256", headers={"kid": "old-kid"})
    assert verifier.decode(old_token) == claims


@pytest.mark.parametrize("alg", ASYMMETRIC_ALGORITHMS)
def test_every_key_type(
    alg: ryjwt.AsymmetricAlgorithm,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    private_key = private_keys[alg]
    jwks = {"keys": [make_jwk(private_key, kid="kid", use="sig")]}
    verifier = ryjwt.PublicKey.from_jwks(jwks, algorithms=[alg])
    signer = ryjwt.PrivateKey(private_pems[alg], algorithms=[alg])
    token = jwt.encode({"sub": "sub"}, private_key, algorithm=alg, headers={"kid": "kid"})

    assert verifier.decode(token) == {"sub": "sub"}
    assert verifier.decode(signer.encode({"sub": "sub"}, headers={"kid": "kid"})) == {"sub": "sub"}


def test_key_rotation(rsa_key: SigningKey, old_rsa_key: SigningKey) -> None:
    old_token = jwt.encode({"sub": "old"}, old_rsa_key, algorithm="RS256", headers={"kid": "old"})
    new_token = jwt.encode({"sub": "new"}, rsa_key, algorithm="RS256", headers={"kid": "new"})
    both = {"keys": [make_jwk(old_rsa_key, kid="old"), make_jwk(rsa_key, kid="new")]}
    new_only = {"keys": [make_jwk(rsa_key, kid="new")]}

    verifier = ryjwt.PublicKey.from_jwks(both, algorithms=["RS256"])
    assert verifier.decode(old_token) == {"sub": "old"}
    assert verifier.decode(new_token) == {"sub": "new"}
    rotated = ryjwt.PublicKey.from_jwks(new_only, algorithms=["RS256"])
    assert rotated.decode(new_token) == {"sub": "new"}
    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "old"'):
        rotated.decode(old_token)


@pytest.mark.parametrize("kid", [{"kid": "kid"}, {}], ids=["key-with-kid", "key-without-kid"])
def test_token_without_kid_and_one_key(kid: dict[str, str], ec_key: SigningKey) -> None:
    verifier = ryjwt.PublicKey.from_jwks({"keys": [make_jwk(ec_key, **kid)]}, algorithms=["ES256"])

    assert verifier.decode(jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256")) == {"sub": "sub"}


def test_token_without_kid_and_several_keys(
    mixed_jwks: ryjwt.PublicKey, ec_key: SigningKey
) -> None:
    token = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256")

    with pytest.raises(ryjwt.UnknownKeyError, match="no kid, and there are several keys"):
        mixed_jwks.decode(token)


def test_token_with_kid_and_several_keys_without(rsa_key: SigningKey, ec_key: SigningKey) -> None:
    jwks = {"keys": [make_jwk(rsa_key), make_jwk(ec_key)]}
    verifier = ryjwt.PublicKey.from_jwks(jwks, algorithms=["RS256", "ES256"])
    token = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256", headers={"kid": "kid"})

    with pytest.raises(ryjwt.UnknownKeyError, match="None of the 2 keys has a kid"):
        verifier.decode(token)


def test_one_key_with_another_kid(ec_key: SigningKey) -> None:
    verifier = ryjwt.PublicKey.from_jwks(
        {"keys": [make_jwk(ec_key, kid="kid")]}, algorithms=["ES256"]
    )
    token = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256", headers={"kid": "other-kid"})

    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "other-kid"'):
        verifier.decode(token)


def test_one_key_without_kid_takes_any_kid(ec_key: SigningKey) -> None:
    verifier = ryjwt.PublicKey.from_jwks({"keys": [make_jwk(ec_key)]}, algorithms=["ES256"])
    token = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256", headers={"kid": "kid"})

    assert verifier.decode(token) == {"sub": "sub"}


def test_unknown_key_error_is_an_invalid_token_error() -> None:
    assert issubclass(ryjwt.UnknownKeyError, ryjwt.InvalidTokenError)


def test_key_alg_is_enforced(rsa_key: SigningKey) -> None:
    jwks = {"keys": [make_jwk(rsa_key, kid="kid", alg="RS384")]}
    verifier = ryjwt.PublicKey.from_jwks(jwks, algorithms=["RS256", "RS384"])
    rs256 = jwt.encode({"sub": "sub"}, rsa_key, algorithm="RS256", headers={"kid": "kid"})
    rs384 = jwt.encode({"sub": "sub"}, rsa_key, algorithm="RS384", headers={"kid": "kid"})

    assert verifier.decode(rs384) == {"sub": "sub"}
    with pytest.raises(
        ryjwt.InvalidAlgorithmError, match='"RS256" is not allowed for the key "kid"'
    ):
        verifier.decode(rs256)


def test_key_alg_must_be_configured(rsa_key: SigningKey, ec_key: SigningKey) -> None:
    jwks = {"keys": [make_jwk(rsa_key, kid="rsa", alg="RS384"), make_jwk(ec_key, kid="ec")]}
    verifier = ryjwt.PublicKey.from_jwks(jwks, algorithms=["RS256", "ES256"])
    token = jwt.encode({"sub": "sub"}, rsa_key, algorithm="RS256", headers={"kid": "rsa"})

    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "rsa"'):
        verifier.decode(token)
    with pytest.raises(ryjwt.InvalidKeyError, match='no key usable with "RS256"'):
        ryjwt.PublicKey.from_jwks({"keys": jwks["keys"][:1]}, algorithms=["RS256"])


def test_encryption_keys_are_ignored(rsa_key: SigningKey, old_rsa_key: SigningKey) -> None:
    jwks = {
        "keys": [
            make_jwk(old_rsa_key, kid="enc", use="enc"),
            make_jwk(rsa_key, kid="sig", use="sig"),
        ]
    }
    verifier = ryjwt.PublicKey.from_jwks(jwks, algorithms=["RS256"])
    token = jwt.encode({"sub": "sub"}, old_rsa_key, algorithm="RS256", headers={"kid": "enc"})

    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "enc"'):
        verifier.decode(token)
    with pytest.raises(ryjwt.InvalidKeyError, match="no key usable"):
        ryjwt.PublicKey.from_jwks({"keys": jwks["keys"][:1]}, algorithms=["RS256"])


@pytest.mark.parametrize("member", ["d", "p", "q", "dp", "dq", "qi", "oth", "k"])
def test_private_key_material_rejects_the_document(
    member: str,
    rsa_key: SigningKey,
    ec_key: SigningKey,
) -> None:
    # Even on a key that would otherwise be ignored (an encryption key).
    leaked = make_jwk(ec_key, kid="leaked", use="enc", **{member: "AQAB"})
    jwks = {"keys": [make_jwk(rsa_key, kid="kid"), leaked]}

    with pytest.raises(ryjwt.InvalidKeyError, match='kid "leaked"\\): holds private key material'):
        ryjwt.PublicKey.from_jwks(jwks, algorithms=["RS256"])


@pytest.mark.parametrize(
    "unsupported",
    [
        pytest.param({"kty": "OKP", "crv": "X25519", "x": "x"}, id="x25519"),
        pytest.param({"kty": "OKP", "crv": "Ed448", "x": "x"}, id="ed448"),
        pytest.param({"kty": "EC", "crv": "P-192", "x": "x", "y": "y"}, id="p192"),
        pytest.param({"kty": "AKP", "alg": "ML-DSA-44", "pub": "pub"}, id="ml-dsa"),
    ],
)
def test_unsupported_keys_are_ignored(unsupported: JWK, ec_key: SigningKey) -> None:
    jwks = {"keys": [unsupported | {"kid": "unsupported"}, make_jwk(ec_key, kid="kid")]}
    verifier = ryjwt.PublicKey.from_jwks(jwks, algorithms=["ES256"])
    token = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256", headers={"kid": "kid"})

    assert verifier.decode(token) == {"sub": "sub"}
    with pytest.raises(ryjwt.InvalidKeyError, match='no key usable with "ES256"'):
        ryjwt.PublicKey.from_jwks({"keys": [unsupported]}, algorithms=["ES256"])


@pytest.mark.parametrize("keys", [[], [{"kty": "OKP", "crv": "X25519", "x": "x"}]])
def test_no_usable_keys(keys: list[JWK], ec_key: SigningKey) -> None:
    with pytest.raises(ryjwt.InvalidKeyError, match='no key usable with "ES256", "EdDSA"'):
        ryjwt.PublicKey.from_jwks({"keys": keys}, algorithms=["ES256", "EdDSA"])
    # An EC key is no use for RSA algorithms.
    with pytest.raises(ryjwt.InvalidKeyError, match='no key usable with "RS256"'):
        ryjwt.PublicKey.from_jwks({"keys": [make_jwk(ec_key)]}, algorithms=["RS256"])


def test_duplicate_kids(rsa_key: SigningKey, old_rsa_key: SigningKey) -> None:
    jwks = {"keys": [make_jwk(old_rsa_key, kid="kid"), make_jwk(rsa_key, kid="kid")]}

    with pytest.raises(ryjwt.InvalidKeyError, match='Several JWKS keys have kid "kid"'):
        ryjwt.PublicKey.from_jwks(jwks, algorithms=["RS256"])


@pytest.mark.parametrize("alg", ["RS256", "PS256"])
def test_small_rsa_keys(
    alg: ryjwt.AsymmetricAlgorithm,
    small_rsa_key: rsa.RSAPrivateKey,
) -> None:
    jwks = {"keys": [make_jwk(small_rsa_key, kid="kid")]}

    with pytest.raises(ryjwt.InvalidKeyError, match="2048 to 8192 bits, this one has 1024"):
        ryjwt.PublicKey.from_jwks(jwks, algorithms=[alg])


def test_rsa_leading_zeros_are_tolerated(rsa_key: SigningKey) -> None:
    jwk = make_jwk(rsa_key, kid="kid")
    jwk["n"] = b64(b"\0" + base64.urlsafe_b64decode(jwk["n"] + "=="))
    verifier = ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=["RS256"])
    token = jwt.encode({"sub": "sub"}, rsa_key, algorithm="RS256", headers={"kid": "kid"})

    assert verifier.decode(token) == {"sub": "sub"}


def _off_curve(jwk: JWK) -> JWK:
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    return jwk | {"y": b64(y[:-1] + bytes([y[-1] ^ 1]))}


@pytest.mark.parametrize(
    ("alg", "change", "match"),
    [
        pytest.param("RS256", {"n": "AQAB="}, "n is not unpadded base64url", id="rsa-padded"),
        pytest.param("RS256", {"n": "A+/B"}, "n is not unpadded base64url", id="rsa-not-b64url"),
        pytest.param("RS256", {"n": None}, "n must be a string", id="rsa-n-null"),
        pytest.param("RS256", {"e": ""}, "aren't an RSA public key", id="rsa-empty-e"),
        pytest.param("ES256", {"x": "AQAB"}, "x must be 32 bytes, not 3", id="ec-short-x"),
        pytest.param("ES384", {"y": "AQAB"}, "y must be 48 bytes, not 3", id="ec-short-y"),
        pytest.param("ES256", {"kid": 1}, "kid must be a string", id="kid-int"),
        pytest.param("ES256", {"alg": ["ES256"]}, "alg must be a string", id="alg-list"),
        pytest.param("ES256", {"use": 1}, "use must be a string", id="use-int"),
        pytest.param("ES256", {"kty": 1}, "kty must be a string", id="kty-int"),
        pytest.param("EdDSA", {"x": b64(bytes(31))}, "x must be 32 bytes", id="ed25519-short"),
    ],
)
def test_malformed_members(
    alg: ryjwt.AsymmetricAlgorithm,
    change: JWK,
    match: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    jwk = make_jwk(private_keys[alg]) | change

    with pytest.raises(ryjwt.InvalidKeyError, match=match):
        ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=[alg])


@pytest.mark.parametrize(
    "point",
    [
        pytest.param("00" * 32, id="zero"),
        pytest.param("00" * 31 + "80", id="zero-sign-bit"),
        pytest.param("01" + "00" * 31, id="identity"),
        pytest.param("01" + "00" * 30 + "80", id="identity-sign-bit"),
        pytest.param("ec" + "ff" * 30 + "7f", id="minus-one"),
        pytest.param("ed" + "ff" * 30 + "7f", id="zero-non-canonical"),
        pytest.param("ee" + "ff" * 30 + "7f", id="identity-non-canonical"),
        pytest.param(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", id="order-8"
        ),
        pytest.param(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            id="other-order-8-sign-bit",
        ),
    ],
)
def test_small_order_ed25519_keys(point: str) -> None:
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(bytes.fromhex(point))}

    with pytest.raises(ryjwt.InvalidKeyError, match="small-order Ed25519 point"):
        ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=["EdDSA"])


@pytest.mark.parametrize("member", ["kty", "n", "e"])
def test_missing_members(member: str, rsa_key: SigningKey) -> None:
    jwk = make_jwk(rsa_key)
    del jwk[member]

    with pytest.raises(ryjwt.InvalidKeyError, match=f"{member} is missing"):
        ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=["RS256"])


@pytest.mark.parametrize("alg", ["ES256", "ES256K", "ES384", "ES512"])
def test_point_not_on_curve(
    alg: ryjwt.AsymmetricAlgorithm,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    jwk = _off_curve(make_jwk(private_keys[alg]))

    with pytest.raises(ryjwt.InvalidKeyError, match=f'can\'t be used for "{alg}"'):
        ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=[alg])


def test_algorithm_confusion_across_key_types(
    mixed_jwks: ryjwt.PublicKey,
    rsa_key: SigningKey,
    ec_key: SigningKey,
) -> None:
    rs256 = jwt.encode({"sub": "sub"}, rsa_key, algorithm="RS256", headers={"kid": "ec"})
    es256 = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256", headers={"kid": "rsa"})

    with pytest.raises(
        ryjwt.InvalidAlgorithmError, match='"RS256" is not allowed for the key "ec"'
    ):
        mixed_jwks.decode(rs256)
    with pytest.raises(
        ryjwt.InvalidAlgorithmError, match='"ES256" is not allowed for the key "rsa"'
    ):
        mixed_jwks.decode(es256)


def test_token_signed_by_another_key_than_its_kid(
    mixed_jwks: ryjwt.PublicKey,
    ec_key: SigningKey,
) -> None:
    good = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256", headers={"kid": "ec"})
    other_key = ec.generate_private_key(ec.SECP256R1())
    forged = jwt.encode({"sub": "sub"}, other_key, algorithm="ES256", headers={"kid": "ec"})

    assert mixed_jwks.decode(good) == {"sub": "sub"}  # its header is now known
    with pytest.raises(ryjwt.InvalidSignatureError):
        mixed_jwks.decode(forged)


def test_header_cache_with_interleaved_kids(
    rsa_key: SigningKey,
    old_rsa_key: SigningKey,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    # More keys (6) than headers the cache holds, so some tokens always take the slow path.
    signing_keys: dict[str, SigningKey] = {
        "rsa": rsa_key,
        "old-rsa": old_rsa_key,
        "es256": private_keys["ES256"],
        "es384": private_keys["ES384"],
        "es512": private_keys["ES512"],
        "eddsa": private_keys["EdDSA"],
    }
    algorithms: list[ryjwt.AsymmetricAlgorithm] = ["RS256", "ES256", "ES384", "ES512", "EdDSA"]
    jwks = {"keys": [make_jwk(key, kid=kid) for kid, key in signing_keys.items()]}
    verifier = ryjwt.PublicKey.from_jwks(jwks, algorithms=algorithms)
    algs = {"rsa": "RS256", "old-rsa": "RS256", "es256": "ES256"}
    algs |= {"es384": "ES384", "es512": "ES512", "eddsa": "EdDSA"}
    tokens = {
        kid: jwt.encode({"sub": kid}, key, algorithm=algs[kid], headers={"kid": kid})
        for kid, key in signing_keys.items()
    }

    for _ in range(3):
        for kid, token in tokens.items():
            assert verifier.decode(token) == {"sub": kid}
            assert verifier.decode(token) == {"sub": kid}


def test_token_kid_must_be_a_string(
    mixed_jwks: ryjwt.PublicKey,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    signer = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])
    token = signer.encode({"sub": "sub"}, headers={"kid": 1})

    with pytest.raises(ryjwt.DecodeError, match="kid must be a string"):
        mixed_jwks.decode(token)


@pytest.mark.parametrize("form", ["str", "bytes", "dict", "mapping", "nested-mappings"])
def test_document_forms(form: str, ec_key: SigningKey) -> None:
    jwk = make_jwk(ec_key, kid="kid")
    jwks = {"keys": [jwk]}
    documents: dict[str, str | bytes | dict[str, Any] | MappingProxyType[str, Any]] = {
        "str": json.dumps(jwks),
        "bytes": json.dumps(jwks).encode(),
        "dict": jwks,
        "mapping": MappingProxyType(jwks),
        "nested-mappings": MappingProxyType({"keys": (MappingProxyType(jwk),)}),
    }
    verifier = ryjwt.PublicKey.from_jwks(documents[form], algorithms=["ES256"])
    token = jwt.encode({"sub": "sub"}, ec_key, algorithm="ES256", headers={"kid": "kid"})

    assert verifier.decode(token) == {"sub": "sub"}


@pytest.mark.parametrize(
    ("document", "match"),
    [
        pytest.param("{", "Invalid JWKS JSON", id="bad-json"),
        pytest.param(b"", "Invalid JWKS JSON", id="empty"),
        pytest.param("[]", "must be a JSON object", id="array"),
        pytest.param("{}", 'must have a "keys" array', id="no-keys"),
        pytest.param({"keys": {}}, 'must have a "keys" array', id="keys-object"),
        pytest.param({"keys": ["key"]}, "JWKS key 0 must be a JSON object", id="key-str"),
        pytest.param("\ud800", "The JWKS is a str that isn't valid Unicode", id="lone-surrogate"),
        pytest.param(
            {"keys": [{"kty": "\ud800"}]},
            "The jwks Mapping holds a str that isn't valid Unicode",
            id="mapping-lone-surrogate",
        ),
    ],
)
def test_malformed_documents(document: str | bytes | dict[str, Any], match: str) -> None:
    with pytest.raises(ryjwt.InvalidKeyError, match=match):
        ryjwt.PublicKey.from_jwks(document, algorithms=["ES256"])


def test_duplicate_document_member(rsa_key: SigningKey) -> None:
    document = f'{{"keys": [], "keys": [{json.dumps(make_jwk(rsa_key))}]}}'

    with pytest.raises(ryjwt.InvalidKeyError, match='Invalid JWKS: duplicate "keys" member'):
        ryjwt.PublicKey.from_jwks(document, algorithms=["RS256"])


@pytest.mark.parametrize(("member", "value"), [("n", "AQAB"), ("kid", "kid"), ("alg", "RS256")])
def test_duplicate_key_member(
    member: str,
    value: str,
    rsa_key: SigningKey,
) -> None:
    jwk = json.dumps(make_jwk(rsa_key, kid="kid", alg="RS256"))
    document = f'{{"keys": [{jwk[:-1]}, "{member}": "{value}"}}]}}'

    with pytest.raises(
        ryjwt.InvalidKeyError, match=f'JWKS key 0 \\(kid "kid"\\): duplicate "{member}" member'
    ):
        ryjwt.PublicKey.from_jwks(document, algorithms=["RS256"])


def test_mapping_with_a_non_str_key(rsa_key: SigningKey) -> None:
    untyped_caller: Any = {
        "keys": [make_jwk(rsa_key)],
        1: "one",
    }  # what an untyped caller could pass

    with pytest.raises(
        TypeError, match="The jwks Mapping isn't JSON: Object member names must be str, got int"
    ):
        ryjwt.PublicKey.from_jwks(untyped_caller, algorithms=["RS256"])


def test_document_type(ec_key: SigningKey) -> None:
    untyped_caller: Any = [make_jwk(ec_key)]  # what an untyped caller could pass

    with pytest.raises(TypeError, match="jwks must be str, bytes or a Mapping, got list"):
        ryjwt.PublicKey.from_jwks(untyped_caller, algorithms=["ES256"])


@pytest.mark.parametrize(
    ("algorithms", "match"),
    [
        pytest.param([], "must not be empty", id="empty"),
        pytest.param(["HS256"], "needs an HMAC secret", id="hmac"),
        pytest.param(["ES999"], "Unsupported algorithm", id="unknown"),
    ],
)
def test_invalid_algorithms(algorithms: list[str], match: str, ec_key: SigningKey) -> None:
    untyped_caller: Any = algorithms  # what an untyped caller could pass

    with pytest.raises(ValueError, match=match):
        ryjwt.PublicKey.from_jwks({"keys": [make_jwk(ec_key)]}, algorithms=untyped_caller)


def test_algorithms_property(mixed_jwks: ryjwt.PublicKey, ec_key: SigningKey) -> None:
    only_ec = ryjwt.PublicKey.from_jwks({"keys": [make_jwk(ec_key)]}, algorithms=["RS256", "ES256"])

    assert mixed_jwks.algorithms == ["RS256", "ES256"]
    assert only_ec.algorithms == ["RS256", "ES256"]


def test_full_decode_api(mixed_jwks: ryjwt.PublicKey, ec_key: SigningKey, past: int) -> None:
    claims = {"sub": "sub", "aud": "aud", "iss": "iss"}
    token = jwt.encode(claims, ec_key, algorithm="ES256", headers={"kid": "ec"})
    expired = jwt.encode({"exp": past}, ec_key, algorithm="ES256", headers={"kid": "ec"})

    assert mixed_jwks.decode(token, audience="aud", issuer="iss") == claims
    assert mixed_jwks.decode(token, type=ClaimsStruct, audience="aud") == ClaimsStruct(sub="sub")
    assert mixed_jwks.decode(token, type=ClaimsModel, audience="aud") == ClaimsModel(sub="sub")
    with pytest.raises(ryjwt.InvalidAudienceError):
        mixed_jwks.decode(token, audience="other-aud")
    with pytest.raises(ryjwt.InvalidIssuerError):
        mixed_jwks.decode(token, audience="aud", issuer="other-iss")
    with pytest.raises(ryjwt.ExpiredSignatureError):
        mixed_jwks.decode(expired)
    assert mixed_jwks.decode(expired, leeway=7200) == {"exp": past}
    assert not hasattr(mixed_jwks, "encode")
