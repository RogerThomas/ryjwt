"""`kid`, `jwk()` and `jwks()`: exporting public keys as the JWKS a token issuer publishes."""

import base64
import json
from pathlib import Path
from typing import Any

import jwt
import pytest
import ryjwt
from _support import ASYMMETRIC_ALGORITHMS, SigningKey, make_jwk, private_pem
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

type KeyClass = type[ryjwt.PrivateKey] | type[ryjwt.PublicKey]

_PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
"""Members only a private (or symmetric) JWK has."""

_MATERIAL_MEMBERS = ("kty", "crv", "n", "e", "x", "y")
"""The members that identify the key itself."""


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _pyjwt_jwk(private_key: SigningKey) -> dict[str, Any]:
    """The public key's members that identify it, in the JWK PyJWT makes of it."""
    public_key = private_key.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        jwk = ECAlgorithm.to_jwk(public_key, as_dict=True)
    else:
        jwk = OKPAlgorithm.to_jwk(public_key, as_dict=True)
    return {name: value for name, value in jwk.items() if name in _MATERIAL_MEMBERS}


def _has_leading_zero(key: ec.EllipticCurvePrivateKey, size: int) -> bool:
    """Whether the public point's x or y, in `size` bytes, starts with a zero byte."""
    point = key.public_key().public_numbers()
    return point.x.bit_length() <= 8 * (size - 1) or point.y.bit_length() <= 8 * (size - 1)


def _ec_key_with_leading_zero(curve: ec.EllipticCurve, size: int) -> ec.EllipticCurvePrivateKey:
    """A key on `curve` whose x or y has a leading zero byte (about 1 key in 128 on P-256)."""
    for _ in range(10_000):
        key = ec.generate_private_key(curve)
        if _has_leading_zero(key, size):
            return key
    pytest.fail("No key with a leading zero byte in x or y")


@pytest.mark.parametrize("exported_by", ["private-key", "public-key"])
@pytest.mark.parametrize("alg", ASYMMETRIC_ALGORITHMS)
def test_round_trip_through_jwks(
    alg: ryjwt.AsymmetricAlgorithm,
    exported_by: str,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    future: int,
) -> None:
    signer = ryjwt.PrivateKey(private_pems[alg], algorithms=[alg], kid="2026-10")
    exported = (
        signer
        if exported_by == "private-key"
        else ryjwt.PublicKey(public_pems[alg], algorithms=[alg], kid="2026-10")
    )
    claims = {"sub": "sub", "exp": future}

    token = signer.encode(claims)
    verifier = ryjwt.PublicKey.from_jwks(ryjwt.jwks([exported]), algorithms=[alg])

    assert ryjwt.unverified_header(token) == {"alg": alg, "kid": "2026-10", "typ": "JWT"}
    assert verifier.decode(token) == claims


@pytest.mark.parametrize("alg", ASYMMETRIC_ALGORITHMS)
def test_key_material_matches_pyjwts(
    alg: ryjwt.AsymmetricAlgorithm,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    expected = _pyjwt_jwk(private_keys[alg])

    for key in (
        ryjwt.PrivateKey(private_pems[alg], algorithms=[alg]),
        ryjwt.PublicKey(public_pems[alg], algorithms=[alg]),
    ):
        jwk = key.jwk()
        assert {name: jwk[name] for name in expected} == expected


# PyJWT has no ES521 alias (ES512 tests P-521).
@pytest.mark.parametrize("alg", [alg for alg in ASYMMETRIC_ALGORITHMS if alg != "ES521"])
def test_pyjwt_verifies_with_the_jwks(
    alg: ryjwt.AsymmetricAlgorithm,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    future: int,
) -> None:
    key = ryjwt.PrivateKey(private_pems[alg], algorithms=[alg], kid="kid")
    claims = {"sub": "sub", "exp": future}

    jwk_set = jwt.PyJWKSet.from_dict(ryjwt.jwks([key]))

    assert jwt.decode(key.encode(claims), jwk_set["kid"].key, algorithms=[alg]) == claims


@pytest.mark.parametrize(
    ("curve", "size", "alg"),
    [
        pytest.param(ec.SECP256R1(), 32, "ES256", id="P-256"),
        pytest.param(ec.SECP256K1(), 32, "ES256K", id="secp256k1"),
        pytest.param(ec.SECP384R1(), 48, "ES384", id="P-384"),
        pytest.param(ec.SECP521R1(), 66, "ES512", id="P-521"),
    ],
)
def test_ec_coordinates_keep_their_leading_zeros(
    curve: ec.EllipticCurve, size: int, alg: ryjwt.AsymmetricAlgorithm, future: int
) -> None:
    private_key = _ec_key_with_leading_zero(curve, size)
    key = ryjwt.PrivateKey(private_pem(private_key), algorithms=[alg], kid="kid")

    jwk = key.jwk()
    verifier = ryjwt.PublicKey.from_jwks(ryjwt.jwks([key]), algorithms=[alg])

    assert len(_unb64(jwk["x"])) == len(_unb64(jwk["y"])) == size
    assert {name: jwk[name] for name in ("x", "y")} == {
        name: value for name, value in _pyjwt_jwk(private_key).items() if name in {"x", "y"}
    }
    assert verifier.decode(key.encode({"exp": future})) == {"exp": future}


def test_rsa_modulus_and_exponent_have_no_leading_zeros(
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    public_key = private_keys["RS256"].public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    numbers = public_key.public_numbers()

    jwk = ryjwt.PrivateKey(private_pems["RS256"], algorithms=["RS256"]).jwk()

    n, e = _unb64(jwk["n"]), _unb64(jwk["e"])
    assert n[0] != 0
    assert int.from_bytes(n) == numbers.n
    assert jwk["e"] == "AQAB"
    assert int.from_bytes(e) == numbers.e == 65537


@pytest.mark.parametrize(
    ("alg", "kid", "members"),
    [
        pytest.param("RS256", "kid", ["kty", "kid", "use", "alg", "n", "e"], id="rsa"),
        pytest.param("ES256", "kid", ["kty", "kid", "use", "alg", "crv", "x", "y"], id="ec"),
        pytest.param("EdDSA", "kid", ["kty", "kid", "use", "alg", "crv", "x"], id="ed25519"),
        pytest.param("RS256", None, ["kty", "use", "alg", "n", "e"], id="rsa-no-kid"),
        pytest.param("ES384", None, ["kty", "use", "alg", "crv", "x", "y"], id="ec-no-kid"),
    ],
)
def test_jwk_members_and_their_order(
    alg: ryjwt.AsymmetricAlgorithm,
    kid: str | None,
    members: list[str],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    """A fixed order: `kty`, `kid`, `use`, `alg`, `crv`, then the key material."""
    private_jwk = ryjwt.PrivateKey(private_pems[alg], algorithms=[alg], kid=kid).jwk()
    public_jwk = ryjwt.PublicKey(public_pems[alg], algorithms=[alg], kid=kid).jwk()

    assert list(private_jwk) == list(public_jwk) == members
    assert private_jwk == public_jwk
    assert private_jwk["use"] == "sig"
    assert private_jwk["alg"] == alg


@pytest.mark.parametrize("alg", ASYMMETRIC_ALGORITHMS)
def test_private_key_jwk_holds_no_private_members(
    alg: ryjwt.AsymmetricAlgorithm, private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes]
) -> None:
    key = ryjwt.PrivateKey(private_pems[alg], algorithms=[alg], kid="kid")

    assert not _PRIVATE_MEMBERS & key.jwk().keys()
    assert not _PRIVATE_MEMBERS & ryjwt.jwks([key])["keys"][0].keys()


@pytest.mark.parametrize(
    ("algorithms", "alg"),
    [
        pytest.param(["PS256"], "PS256", id="one"),
        pytest.param(["RS256", "PS256"], None, id="two"),
    ],
)
def test_alg_only_with_one_algorithm(
    algorithms: list[ryjwt.AsymmetricAlgorithm],
    alg: str | None,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    from_jwks = ryjwt.PublicKey.from_jwks(
        {"keys": [make_jwk(private_keys["RS256"])]}, algorithms=algorithms
    )

    for key in (
        ryjwt.PrivateKey(private_pems["RS256"], algorithms=algorithms),
        ryjwt.PublicKey(public_pems["RS256"], algorithms=algorithms),
        from_jwks,
    ):
        assert key.jwk().get("alg") == alg


def test_jwks_key_alg_is_the_one_algorithm_it_serves(
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    """A JWKS key with its own `alg` is only used for that one of the configured algorithms."""
    key = ryjwt.PublicKey.from_jwks(
        {"keys": [make_jwk(private_keys["RS256"], alg="PS256")]},
        algorithms=["RS256", "PS256"],
    )

    assert key.jwk()["alg"] == "PS256"


def test_jwk_of_a_single_key_jwks(
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> None:
    published = make_jwk(private_keys["ES256"], kid="kid", use="sig", alg="ES256")
    key = ryjwt.PublicKey.from_jwks({"keys": [published]}, algorithms=["ES256"])

    assert key.jwk() == published


def test_jwks_of_a_several_key_jwks(
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    published = [
        make_jwk(private_keys["RS256"], kid="rsa", use="sig", alg="RS256"),
        make_jwk(private_keys["ES256"], kid="ec", use="sig", alg="ES256"),
    ]
    several = ryjwt.PublicKey.from_jwks({"keys": published}, algorithms=["RS256", "ES256"])
    new_key = ryjwt.PrivateKey(private_pems["EdDSA"], algorithms=["EdDSA"], kid="ed")

    with pytest.raises(ValueError, match=r"holds 2 keys: export them with ryjwt\.jwks"):
        several.jwk()
    assert ryjwt.jwks([new_key, several]) == {"keys": [new_key.jwk(), *published]}


def test_jwks_of_one_key_without_kid(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes], future: int
) -> None:
    key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])
    token = key.encode({"exp": future})

    jwks = ryjwt.jwks([key])

    assert jwks == {"keys": [key.jwk()]}
    assert "kid" not in jwks["keys"][0]
    assert "kid" not in ryjwt.unverified_header(token)
    assert ryjwt.PublicKey.from_jwks(jwks, algorithms=["ES256"]).decode(token) == {"exp": future}


def test_jwks_takes_any_iterable(private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes]) -> None:
    keys = [
        ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"], kid="a"),
        ryjwt.PrivateKey(private_pems["EdDSA"], algorithms=["EdDSA"], kid="b"),
    ]

    assert ryjwt.jwks(iter(keys)) == ryjwt.jwks(tuple(keys)) == {"keys": [k.jwk() for k in keys]}


def test_jwks_is_json(private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes]) -> None:
    jwks = ryjwt.jwks([
        ryjwt.PrivateKey(private_pems["RS256"], algorithms=["RS256", "PS256"], kid="rsa"),
        ryjwt.PrivateKey(private_pems["ES384"], algorithms=["ES384"], kid="ec"),
    ])

    assert json.loads(json.dumps(jwks)) == jwks


def test_jwk_and_jwks_are_new_each_call(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"], kid="kid")

    key.jwk()["kid"] = "changed"
    ryjwt.jwks([key])["keys"].clear()

    assert key.jwk()["kid"] == "kid"
    assert ryjwt.jwks([key])["keys"] == [key.jwk()]


@pytest.mark.parametrize(
    ("kid", "error", "match"),
    [
        pytest.param(1, TypeError, "kid must be str, got int", id="int"),
        pytest.param(b"kid", TypeError, "kid must be str, got bytes", id="bytes"),
        pytest.param("", ValueError, "kid must not be empty", id="empty"),
    ],
)
@pytest.mark.parametrize("key_class", [ryjwt.PrivateKey, ryjwt.PublicKey])
def test_kid_must_be_a_non_empty_str(
    key_class: KeyClass,
    kid: object,
    error: type[Exception],
    match: str,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    tmp_path: Path,
) -> None:
    pem = private_pems["ES256"] if key_class is ryjwt.PrivateKey else public_pems["ES256"]
    (tmp_path / "key.pem").write_bytes(pem)
    untyped_caller: Any = kid  # what an untyped caller could pass

    with pytest.raises(error, match=match):
        key_class(pem, algorithms=["ES256"], kid=untyped_caller)
    with pytest.raises(error, match=match):
        key_class.from_path(tmp_path / "key.pem", algorithms=["ES256"], kid=untyped_caller)


@pytest.mark.parametrize("key_class", [ryjwt.PrivateKey, ryjwt.PublicKey])
def test_from_path_takes_a_kid(
    key_class: KeyClass,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    tmp_path: Path,
) -> None:
    pem = private_pems["ES256"] if key_class is ryjwt.PrivateKey else public_pems["ES256"]
    (tmp_path / "key.pem").write_bytes(pem)

    key = key_class.from_path(tmp_path / "key.pem", algorithms=["ES256"], kid="kid")

    assert key.jwk() == key_class(pem, algorithms=["ES256"], kid="kid").jwk()
    assert key.jwk()["kid"] == "kid"


def test_secret_key_takes_no_kid(hmac_key: str) -> None:
    untyped_caller: Any = {"kid": "kid"}  # what an untyped caller could pass

    with pytest.raises(TypeError, match="kid"):
        ryjwt.SecretKey(hmac_key, algorithms=["HS256"], **untyped_caller)


@pytest.mark.parametrize("header_kid", ["kid", "other", 1])
def test_header_kid_with_a_key_kid(
    header_kid: object, private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes]
) -> None:
    """The key's kid and the header's could disagree, so only one may be set."""
    key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"], kid="kid")

    with pytest.raises(ValueError, match="drop kid from header, or from the key"):
        key.encode({}, header={"kid": header_kid})


def test_key_kid_comes_with_header_fields(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    with_kid = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"], kid="kid")
    without_kid = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])

    assert ryjwt.unverified_header(with_kid.encode({}, header={"typ": "at+jwt"})) == {
        "alg": "ES256",
        "kid": "kid",
        "typ": "at+jwt",
    }
    assert ryjwt.unverified_header(without_kid.encode({}, header={"kid": "header"})) == {
        "alg": "ES256",
        "kid": "header",
        "typ": "JWT",
    }


def test_key_kid_counts_toward_the_header_limit(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    """64 parameters, with `alg`, the key's `kid` and `typ`."""
    key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"], kid="kid")
    largest = {f"x{i}": i for i in range(61)}

    assert len(ryjwt.unverified_header(key.encode({}, header=largest))) == 64
    with pytest.raises(ValueError, match="more parameters"):
        key.encode({}, header={**largest, "x61": 61})


def test_key_kid_doesnt_change_decoding(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    """A PEM key's kid only names it in tokens it encodes and in its JWK."""
    signer = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])
    verifier = ryjwt.PublicKey(public_pems["ES256"], algorithms=["ES256"], kid="kid")

    for header in (None, {"kid": "other"}):
        token = signer.encode({"sub": "sub"}, header=header)
        assert verifier.decode(token) == {"sub": "sub"}


def test_jwks_rejects_duplicate_kids(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    rsa_key = ryjwt.PrivateKey(private_pems["RS256"], algorithms=["RS256"], kid="kid")
    ec_key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"], kid="kid")
    same_key = ryjwt.PublicKey(public_pems["RS256"], algorithms=["RS256"], kid="kid")

    cases: list[list[ryjwt.PrivateKey | ryjwt.PublicKey]] = [
        [rsa_key, ec_key],
        [rsa_key, rsa_key],
        [rsa_key, same_key],
    ]
    for keys in cases:
        with pytest.raises(ValueError, match='Several keys have kid "kid"'):
            ryjwt.jwks(keys)


def test_jwks_of_several_keys_needs_every_kid(
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    named = ryjwt.PrivateKey(private_pems["RS256"], algorithms=["RS256"], kid="kid")
    unnamed = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])

    with pytest.raises(ValueError, match="Key 1 has no kid"):
        ryjwt.jwks([named, unnamed])
    with pytest.raises(ValueError, match="Key 0 has no kid"):
        ryjwt.jwks([unnamed, unnamed])


def test_jwks_of_no_keys() -> None:
    with pytest.raises(ValueError, match="at least one key"):
        ryjwt.jwks([])


def test_jwks_never_takes_a_secret_key(hmac_key: str) -> None:
    secret = ryjwt.SecretKey(hmac_key, algorithms=["HS256"])
    untyped_caller: Any = [secret]  # what an untyped caller could pass

    with pytest.raises(
        TypeError, match=r"got SecretKey \(a shared secret must never be published\)"
    ):
        ryjwt.jwks(untyped_caller)


@pytest.mark.parametrize("key", ["pem", None, {"kty": "RSA"}])
def test_jwks_takes_only_private_and_public_keys(key: object) -> None:
    untyped_caller: Any = [key]  # what an untyped caller could pass

    with pytest.raises(TypeError, match=r"jwks\(\) takes PrivateKey and PublicKey objects, got"):
        ryjwt.jwks(untyped_caller)
