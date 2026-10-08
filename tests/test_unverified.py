"""`unverified_header`, `unverified_claims` and `unverified_token`: reading a token without
verifying it, though it must still be well formed."""

import sys
from collections.abc import Callable
from typing import Any

import pytest
import ryjwt


@pytest.fixture(name="dict_parser", params=["msgspec", "jiter"])
def _dict_parser(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Payloads read with msgspec, or with jiter as when msgspec isn't installed, for the test."""
    if request.param == "jiter":
        monkeypatch.setitem(sys.modules, "msgspec.json", None)
    return request.param


@pytest.mark.usefixtures("dict_parser")
def test_reads_an_hmac_token(hmac_key: str) -> None:
    key = ryjwt.SecretKey(hmac_key, algorithms=["HS256"])
    token = key.encode({"sub": "sub", "n": 1}, header={"kid": "kid"})
    header = {"alg": "HS256", "typ": "JWT", "kid": "kid"}

    assert ryjwt.unverified_header(token) == header
    assert ryjwt.unverified_claims(token) == {"sub": "sub", "n": 1}
    assert ryjwt.unverified_token(token) == (header, {"sub": "sub", "n": 1})


@pytest.mark.usefixtures("dict_parser")
@pytest.mark.parametrize("algorithm", ["RS256", "ES256", "EdDSA"])
def test_reads_a_private_key_token(
    algorithm: ryjwt.AsymmetricAlgorithm,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    key = ryjwt.PrivateKey(private_pems[algorithm], algorithms=[algorithm])
    token = key.encode({"sub": "sub", "n": 1}, header={"kid": "kid"})
    header = {"alg": algorithm, "typ": "JWT", "kid": "kid"}

    assert ryjwt.unverified_header(token) == header
    assert ryjwt.unverified_claims(token) == {"sub": "sub", "n": 1}
    assert ryjwt.unverified_token(token) == (header, {"sub": "sub", "n": 1})


def test_takes_str_or_bytes(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub"})

    assert ryjwt.unverified_header(token.encode()) == ryjwt.unverified_header(token)
    assert ryjwt.unverified_claims(token.encode()) == {"sub": "sub"}
    assert ryjwt.unverified_token(token.encode()) == ryjwt.unverified_token(token)


def test_token_must_be_str_or_bytes() -> None:
    untyped_caller: Any = 1  # what an untyped caller could pass

    with pytest.raises(TypeError):
        ryjwt.unverified_header(untyped_caller)
    with pytest.raises(TypeError):
        ryjwt.unverified_claims(untyped_caller)
    with pytest.raises(TypeError):
        ryjwt.unverified_token(untyped_caller)


@pytest.mark.parametrize("problem", ["expired", "not-yet-valid", "wrong-aud", "wrong-iss"])
def test_claims_are_not_checked(problem: str, hmac_key: str, past: int, future: int) -> None:
    key = ryjwt.SecretKey(hmac_key, algorithms=["HS256"], audience="aud", issuer="iss")
    problems: dict[str, dict[str, Any]] = {
        "expired": {"exp": past, "aud": "aud", "iss": "iss"},
        "not-yet-valid": {"nbf": future, "aud": "aud", "iss": "iss"},
        "wrong-aud": {"aud": "other-aud", "iss": "iss"},
        "wrong-iss": {"aud": "aud", "iss": "other-iss"},
    }
    claims = problems[problem]
    token = key.encode(claims)

    with pytest.raises(ryjwt.InvalidTokenError):
        key.decode(token)
    assert ryjwt.unverified_claims(token) == claims
    assert ryjwt.unverified_token(token)[1] == claims


@pytest.mark.parametrize("tamper", ["other-key", "replaced", "empty"])
def test_signature_is_not_checked(tamper: str, hmac_jwt: ryjwt.SecretKey) -> None:
    other_key = ryjwt.SecretKey("other-key" * 8, algorithms=["HS256"])
    token = hmac_jwt.encode({"sub": "sub"})
    tampered = {
        "other-key": other_key.encode({"sub": "sub"}),
        "replaced": token[:-4] + "AAAA",
        "empty": token.rsplit(".", 1)[0] + ".",
    }[tamper]

    with pytest.raises(ryjwt.InvalidSignatureError):
        hmac_jwt.decode(tampered)
    assert ryjwt.unverified_header(tampered) == {"alg": "HS256", "typ": "JWT"}
    assert ryjwt.unverified_claims(tampered) == {"sub": "sub"}


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        pytest.param(b"{}", {}, id="no-alg"),
        pytest.param(b'{"alg":1}', {"alg": 1}, id="non-str-alg"),
        pytest.param(b'{"alg":"none"}', {"alg": "none"}, id="alg-none"),
        pytest.param(
            b'{"alg":"HS256","crit":["exp"]}', {"alg": "HS256", "crit": ["exp"]}, id="crit"
        ),
    ],
)
def test_header_fields_are_not_checked(
    header: bytes,
    expected: dict[str, Any],
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    """Headers `decode` rejects for what their fields say, not for their form."""
    token = raw_hs256_token(header, b'{"sub":"sub"}')

    with pytest.raises(ryjwt.InvalidTokenError):
        hmac_jwt.decode(token)
    assert ryjwt.unverified_header(token) == expected
    assert ryjwt.unverified_token(token) == (expected, {"sub": "sub"})


@pytest.mark.parametrize("payload", ["{payload}=", "{payload}!"])
def test_payload_must_be_unpadded_base64url(payload: str, hmac_jwt: ryjwt.SecretKey) -> None:
    """`decode` rejects these tokens too, but for their signature, which it checks first."""
    header, original, signature = hmac_jwt.encode({"sub": "sub"}).split(".")
    token = f"{header}.{payload.format(payload=original)}.{signature}"

    with pytest.raises(ryjwt.DecodeError, match="Invalid payload encoding"):
        ryjwt.unverified_header(token)
    with pytest.raises(ryjwt.DecodeError, match="Invalid payload encoding"):
        ryjwt.unverified_claims(token)
    with pytest.raises(ryjwt.DecodeError, match="Invalid payload encoding"):
        ryjwt.unverified_token(token)


def _assert_rejected_as_decode_rejects(key: ryjwt.SecretKey, token: str) -> None:
    """Each of the three functions raises the `DecodeError` `key.decode` raises for `token`."""
    with pytest.raises(ryjwt.DecodeError) as decoded:
        key.decode(token)
    with pytest.raises(ryjwt.DecodeError) as header:
        ryjwt.unverified_header(token)
    with pytest.raises(ryjwt.DecodeError) as claims:
        ryjwt.unverified_claims(token)
    with pytest.raises(ryjwt.DecodeError) as both:
        ryjwt.unverified_token(token)

    assert str(header.value) == str(claims.value) == str(both.value) == str(decoded.value)
    assert type(header.value) is type(claims.value) is type(both.value) is ryjwt.DecodeError


@pytest.mark.parametrize(
    "malformation",
    [
        "two-segments",
        "four-segments",
        "empty",
        "padded-header",
        "padded-signature",
        "truncated-signature",
        "non-ascii",
        "lone-surrogate",
    ],
)
def test_malformed_tokens_are_rejected_as_decode_rejects_them(
    malformation: str, hmac_key: str
) -> None:
    key = ryjwt.SecretKey(hmac_key, algorithms=["HS256"])
    token = key.encode({"sub": "sub"})
    header, payload, signature = token.split(".")
    malformed = {
        "two-segments": f"{header}.{payload}",
        "four-segments": f"{token}.x",
        "empty": "",
        "padded-header": f"{header}==.{payload}.{signature}",
        "padded-signature": f"{token}=",
        "truncated-signature": token[:-2],
        "non-ascii": token + "é",
        "lone-surrogate": token + "\ud800",
    }

    _assert_rejected_as_decode_rejects(key, malformed[malformation])


@pytest.mark.usefixtures("dict_parser")
@pytest.mark.parametrize(
    ("header", "payload"),
    [
        pytest.param(b'["alg","HS256"]', b'{"sub":"sub"}', id="header-not-an-object"),
        pytest.param(b'{"alg":"HS256"', b'{"sub":"sub"}', id="header-not-json"),
        pytest.param(
            b'{"alg":"HS256"' + b"".join(b',"p%d":0' % i for i in range(64)) + b"}",
            b'{"sub":"sub"}',
            id="header-too-many-parameters",
        ),
        pytest.param(
            b'{"alg":"HS256","kid":"a","kid":"b"}', b'{"sub":"sub"}', id="header-repeated-parameter"
        ),
        pytest.param(
            b'{"alg":"HS256","x":' + b"[" * 100_000 + b"]" * 100_000 + b"}",
            b'{"sub":"sub"}',
            id="header-too-deep",
        ),
        pytest.param(b'{"alg":"HS256"}', b'["sub"]', id="payload-not-an-object"),
        pytest.param(b'{"alg":"HS256"}', b'{"sub":', id="payload-not-json"),
        pytest.param(
            b'{"alg":"HS256"}',
            b'{"x":' + b"[" * 100_000 + b"]" * 100_000 + b"}",
            id="payload-too-deep",
        ),
    ],
)
def test_malformed_json_is_rejected_as_decode_rejects_it(
    header: bytes,
    payload: bytes,
    hmac_key: str,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    key = ryjwt.SecretKey(hmac_key, algorithms=["HS256"])

    _assert_rejected_as_decode_rejects(key, raw_hs256_token(header, payload))
