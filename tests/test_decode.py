import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import msgspec
import pydantic
import pytest
import ryjwt

if TYPE_CHECKING:
    from collections.abc import Callable


class ClaimsStruct(msgspec.Struct):
    sub: str


class ClaimsModel(pydantic.BaseModel):
    sub: str


class NoClaims(msgspec.Struct):
    pass


def _decode_both_ways(hmac_jwt: ryjwt.RYJWT, token: str, **kwargs: Any) -> list[object]:  # noqa: ANN401
    """Decodes as a dict and as a Struct: claim validation must behave the same either way."""
    outcomes: list[object] = []
    for type_ in (dict, NoClaims):
        try:
            outcomes.append(hmac_jwt.decode(token, type=type_, **kwargs))
        except ryjwt.RYJWTError as e:
            outcomes.append(type(e))
    return outcomes


def test_decodes_to_dict_by_default(hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode({"sub": "sub", "n": [1, 2.5, None, True]})

    assert hmac_jwt.decode(token) == {"sub": "sub", "n": [1, 2.5, None, True]}
    assert hmac_jwt.decode(token, type=dict) == {"sub": "sub", "n": [1, 2.5, None, True]}
    assert hmac_jwt.decode(token.encode()) == {"sub": "sub", "n": [1, 2.5, None, True]}


def test_decodes_to_struct_and_model(hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode({"sub": "sub", "other": "other"})

    assert hmac_jwt.decode(token, type=ClaimsStruct) == ClaimsStruct(sub="sub")
    assert hmac_jwt.decode(token, type=ClaimsModel) == ClaimsModel(sub="sub")


def test_type_mismatch_raises_the_library_error(hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode({"other": "other"})

    with pytest.raises(msgspec.ValidationError):
        hmac_jwt.decode(token, type=ClaimsStruct)
    with pytest.raises(pydantic.ValidationError):
        hmac_jwt.decode(token, type=ClaimsModel)


@pytest.mark.parametrize("type_", [list, int, str, ClaimsStruct(sub="sub")])
def test_unsupported_type_raises_type_error(type_: Any, hmac_jwt: ryjwt.RYJWT) -> None:  # noqa: ANN401
    with pytest.raises(TypeError):
        hmac_jwt.decode(hmac_jwt.encode({"sub": "sub"}), type=type_)


def test_claims_are_validated_even_when_the_type_omits_them(
    hmac_jwt: ryjwt.RYJWT,
    past: int,
) -> None:
    token = hmac_jwt.encode({"sub": "sub", "exp": past})

    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(token, type=ClaimsStruct)


@pytest.mark.parametrize(
    ("claims", "kwargs", "expected"),
    [
        pytest.param({"exp": "future"}, {}, None, id="exp-valid"),
        pytest.param({"exp": "past"}, {}, ryjwt.ExpiredSignatureError, id="exp-expired"),
        pytest.param({"exp": "recent"}, {"leeway": 120}, None, id="exp-within-leeway"),
        pytest.param(
            {"exp": "recent"},
            {"leeway": timedelta(minutes=2)},
            None,
            id="exp-within-timedelta-leeway",
        ),
        pytest.param({"exp": 4_102_444_800.5}, {}, None, id="exp-float"),
        pytest.param({"exp": 2**80}, {}, None, id="exp-huge"),
        pytest.param({"exp": -(2**80)}, {}, ryjwt.ExpiredSignatureError, id="exp-huge-negative"),
        pytest.param({"exp": "exp"}, {}, ryjwt.DecodeError, id="exp-string"),
        pytest.param({"exp": True}, {}, ryjwt.DecodeError, id="exp-bool"),
        pytest.param({"nbf": "past"}, {}, None, id="nbf-valid"),
        pytest.param({"nbf": "future"}, {}, ryjwt.ImmatureSignatureError, id="nbf-future"),
        pytest.param({"nbf": None}, {}, ryjwt.DecodeError, id="nbf-null"),
        pytest.param({"iat": "future"}, {}, None, id="iat-future-is-not-checked"),
        pytest.param({"aud": "aud"}, {"audience": "aud"}, None, id="aud-match"),
        pytest.param({"aud": ["x", "aud"]}, {"audience": "aud"}, None, id="aud-list-match"),
        pytest.param({"aud": "aud"}, {"audience": ["x", "aud"]}, None, id="audience-list-match"),
        pytest.param(
            {"aud": "aud"},
            {"audience": "other"},
            ryjwt.InvalidAudienceError,
            id="aud-mismatch",
        ),
        pytest.param({"aud": "aud"}, {}, ryjwt.InvalidAudienceError, id="aud-without-audience"),
        pytest.param({}, {"audience": "aud"}, ryjwt.InvalidAudienceError, id="aud-missing"),
        pytest.param({"aud": 1}, {"audience": "aud"}, ryjwt.InvalidAudienceError, id="aud-int"),
        pytest.param(
            {"aud": ["aud", 1]},
            {"audience": "aud"},
            ryjwt.InvalidAudienceError,
            id="aud-list-non-str",
        ),
        pytest.param({"iss": "iss"}, {"issuer": "iss"}, None, id="iss-match"),
        pytest.param({"iss": "iss"}, {"issuer": {"x", "iss"}}, None, id="issuer-set-match"),
        pytest.param(
            {"iss": "iss"},
            {"issuer": "other"},
            ryjwt.InvalidIssuerError,
            id="iss-mismatch",
        ),
        pytest.param({}, {"issuer": "iss"}, ryjwt.InvalidIssuerError, id="iss-missing"),
        pytest.param({"iss": 1}, {"issuer": "iss"}, ryjwt.InvalidIssuerError, id="iss-int"),
        pytest.param({"iss": 1}, {}, None, id="iss-unchecked-without-issuer"),
    ],
)
def test_registered_claims(
    claims: dict[str, Any],
    kwargs: dict[str, Any],
    expected: type[Exception] | None,
    hmac_jwt: ryjwt.RYJWT,
) -> None:
    now = int(time.time())
    times = {"future": now + 3600, "past": now - 3600, "recent": now - 60}
    payload = {"sub": "sub"} | {
        k: times.get(v, v) if isinstance(v, str) else v for k, v in claims.items()
    }
    token = hmac_jwt.encode(payload)

    for outcome in _decode_both_ways(hmac_jwt, token, **kwargs):
        if expected is None:
            assert not isinstance(outcome, type), outcome
        else:
            assert outcome is expected


def test_audience_accepts_any_iterable(hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode({"aud": "aud"})

    assert hmac_jwt.decode(token, audience=(a for a in ["x", "aud"])) == {"aud": "aud"}


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        pytest.param({"audience": 1}, TypeError, id="audience-int"),
        pytest.param({"audience": ["aud", 1]}, TypeError, id="audience-non-str-item"),
        pytest.param({"issuer": 1}, TypeError, id="issuer-int"),
        pytest.param({"leeway": "1"}, TypeError, id="leeway-str"),
        pytest.param({"leeway": True}, TypeError, id="leeway-bool"),
    ],
)
def test_invalid_arguments(
    kwargs: dict[str, Any],
    error: type[Exception],
    hmac_jwt: ryjwt.RYJWT,
) -> None:
    with pytest.raises(error):
        hmac_jwt.decode(hmac_jwt.encode({"sub": "sub"}), **kwargs)


@pytest.mark.parametrize(
    ("header", "payload", "expected"),
    [
        pytest.param(b'{"alg":"HS256"}', b'{"a":1}', None, id="minimal"),
        pytest.param(b'{"alg":"HS256","kid":1}', b'{"a":1}', None, id="kid-any-type"),
        pytest.param(
            b'{"alg":"HS512"}',
            b'{"a":1}',
            ryjwt.InvalidAlgorithmError,
            id="alg-not-configured",
        ),
        pytest.param(b'{"alg":"none"}', b'{"a":1}', ryjwt.InvalidAlgorithmError, id="alg-none"),
        pytest.param(b'{"typ":"JWT"}', b'{"a":1}', ryjwt.InvalidAlgorithmError, id="alg-missing"),
        pytest.param(b'{"alg":1}', b'{"a":1}', ryjwt.InvalidAlgorithmError, id="alg-int"),
        pytest.param(
            b'{"alg":"HS256","crit":["exp"]}',
            b'{"a":1}',
            ryjwt.InvalidTokenError,
            id="crit",
        ),
        pytest.param(
            b'{"alg":"none","alg":"HS256"}',
            b'{"a":1}',
            ryjwt.DecodeError,
            id="header-duplicate",
        ),
        pytest.param(b'["HS256"]', b'{"a":1}', ryjwt.DecodeError, id="header-array"),
        pytest.param(b'{"alg":"HS256"', b'{"a":1}', ryjwt.DecodeError, id="header-bad-json"),
        pytest.param(b'{"alg":"HS256"}', b"[1]", ryjwt.DecodeError, id="payload-array"),
        pytest.param(b'{"alg":"HS256"}', b"", ryjwt.DecodeError, id="payload-empty"),
        pytest.param(b'{"alg":"HS256"}', b'{"a":NaN}', ryjwt.DecodeError, id="payload-nan"),
        pytest.param(
            b'{"alg":"HS256"}',
            b'{"a":"\\ud800"}',
            ryjwt.DecodeError,
            id="payload-lone-surrogate",
        ),
        pytest.param(
            b'{"alg":"HS256"}',
            b'{"a":"\x01"}',
            ryjwt.DecodeError,
            id="payload-control-char",
        ),
        pytest.param(
            b'{"alg":"HS256"}',
            b'{"a":"\xff"}',
            ryjwt.DecodeError,
            id="payload-invalid-utf8",
        ),
        pytest.param(
            b'{"alg":"HS256"}',
            b'{"a":1} x',
            ryjwt.DecodeError,
            id="payload-trailing-garbage",
        ),
        pytest.param(b'{"alg":"HS256"}', b'{"a":1,"a":2}', None, id="payload-duplicate-key"),
    ],
)
def test_raw_tokens(
    header: bytes,
    payload: bytes,
    expected: type[Exception] | None,
    hmac_jwt: ryjwt.RYJWT,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    for outcome in _decode_both_ways(hmac_jwt, raw_hs256_token(header, payload)):
        if expected is None:
            assert not isinstance(outcome, type), outcome
        else:
            assert isinstance(outcome, type), outcome
            assert issubclass(outcome, expected)


def test_malformed_tokens(hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode({"sub": "sub"})
    header, payload, signature = token.split(".")
    malformed = [
        f"{header}.{payload}",
        f"{token}.x",
        "",
        f"{token}=",
        f"{header}==.{payload}.{signature}",
        f"{header}.{payload}!.{signature}",
        token + "é",
        token[:-2],
    ]
    for bad in malformed:
        with pytest.raises(ryjwt.DecodeError):
            hmac_jwt.decode(bad)


@pytest.mark.parametrize("tamper", ["replaced", "truncated", "empty"])
def test_bad_signature(tamper: str, hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode({"sub": "sub"})
    signing_input = token.rsplit(".", 1)[0]
    tampered = {
        "replaced": token[:-4] + "AAAA",
        "truncated": token[:-3],
        "empty": f"{signing_input}.",
    }

    with pytest.raises(ryjwt.InvalidSignatureError):
        hmac_jwt.decode(tampered[tamper])


def test_wrong_key(hmac_jwt: ryjwt.RYJWT) -> None:
    other = ryjwt.RYJWT("other-key" * 8, algorithms=["HS256"])

    with pytest.raises(ryjwt.InvalidSignatureError):
        hmac_jwt.decode(other.encode({"sub": "sub"}))


def test_token_must_be_str_or_bytes(hmac_jwt: ryjwt.RYJWT) -> None:
    with pytest.raises(TypeError):
        hmac_jwt.decode(1)  # pyright: ignore[reportArgumentType, reportCallIssue]


def test_exception_hierarchy() -> None:
    assert issubclass(ryjwt.InvalidSignatureError, ryjwt.DecodeError)
    for error in [
        ryjwt.DecodeError,
        ryjwt.InvalidAlgorithmError,
        ryjwt.ExpiredSignatureError,
        ryjwt.ImmatureSignatureError,
        ryjwt.InvalidAudienceError,
        ryjwt.InvalidIssuerError,
    ]:
        assert issubclass(error, ryjwt.InvalidTokenError)
    assert issubclass(ryjwt.InvalidTokenError, ryjwt.RYJWTError)
    assert issubclass(ryjwt.InvalidKeyError, ryjwt.RYJWTError)
