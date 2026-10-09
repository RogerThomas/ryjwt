import math
import random
import sys
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, ClassVar, Protocol, TypedDict, Unpack

import msgspec
import pydantic
import pytest
import ryjwt
from _support import (
    ClaimsModel,
    ClaimsStruct,
    DatetimeClaimsModel,
    DatetimeClaimsStruct,
    SigningKey,
    make_jwk,
)

type AnyKey = ryjwt.SecretKey | ryjwt.PrivateKey | ryjwt.PublicKey

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
Y2K = datetime(2000, 1, 1, tzinfo=UTC)


class NoClaims(msgspec.Struct):
    pass


class GenericClaims[T](msgspec.Struct):
    sub: T


class GenericDeclaredClaims[T](msgspec.Struct):
    """Generic, and declares `exp`: `decode` reads it from the instance."""

    exp: int
    value: T


class DeclaredClaims(msgspec.Struct):
    """Declares registered claims, so `decode` reads them from the instance when it can."""

    exp: int
    aud: str | list[str]


class ScannedClaims(DeclaredClaims):
    """`DeclaredClaims`, but having a `__post_init__` makes `decode` scan the payload for claims."""

    def __post_init__(self) -> None:
        pass


class DatedMembers(msgspec.Struct):
    """A datetime `exp`, and members whose decoded value depends on the very JSON they are."""

    exp: datetime
    raw: msgspec.Raw
    keys: dict[int, str]
    amount: Decimal


class NumberedMembers(msgspec.Struct):
    """`DatedMembers`, with an int `exp`."""

    exp: int
    raw: msgspec.Raw
    keys: dict[int, str]
    amount: Decimal


class DefaultExp(msgspec.Struct):
    exp: int = 0


class DecimalExp(msgspec.Struct):
    exp: Decimal


class RenamedExp(msgspec.Struct):
    expires: int = msgspec.field(name="exp")


class ShadowedExp(msgspec.Struct, rename={"exp": "expires_at"}):
    exp: int


class Recorded(msgspec.Struct):
    """Records every instance msgspec builds."""

    built: ClassVar[list["Recorded"]] = []  # quoted: Python < 3.14 evaluates it at once
    exp: int

    def __post_init__(self) -> None:
        Recorded.built.append(self)


class ArrayLike(msgspec.Struct, array_like=True):
    exp: int


class DeclaredClaimsWithDatetime(DeclaredClaims):
    """`DeclaredClaims` (read from the instance), plus a datetime `iat`, renamed."""

    issued: datetime = msgspec.field(name="iat")


class Issued(msgspec.Struct):
    """A datetime `iat` (which `decode` doesn't validate, so any NumericDate decodes)."""

    iat: datetime
    sub: str = ""


class DatedSession(msgspec.Struct, frozen=True, forbid_unknown_fields=True, kw_only=True):
    """Frozen, forbidding unknown members: a renamed datetime `exp`, an optional datetime `nbf`, and
    a default for a member that isn't a claim."""

    expires: datetime = msgspec.field(name="exp")
    nbf: datetime | None = None
    sub: str = "anonymous"


class GenericDated[T](msgspec.Struct):
    exp: datetime
    value: T


class RecordedDated(msgspec.Struct):
    """Records every instance msgspec builds."""

    built: ClassVar[list["RecordedDated"]] = []  # quoted: Python < 3.14 evaluates it at once
    exp: datetime

    def __post_init__(self) -> None:
        RecordedDated.built.append(self)


class DictClaims(dict[str, Any]):
    pass


class FarDatetimeModel(pydantic.BaseModel):
    """NumericDate claims in fields of each annotation that can hold a datetime."""

    exp: pydantic.AwareDatetime
    nbf: Annotated[datetime, "metadata"] | None = None
    issued: pydantic.FutureDatetime | None = pydantic.Field(default=None, alias="iat")


class AliasedDatetimeModel(pydantic.BaseModel):
    """A datetime `exp` by an alias among choices, and a datetime field named `iat` that doesn't
    validate from the `iat` claim (aliased away from it)."""

    expires: datetime = pydantic.Field(validation_alias=pydantic.AliasChoices("expires", "exp"))
    iat: datetime | None = pydantic.Field(default=None, alias="issued")


class NumberModel(pydantic.BaseModel):
    """NumericDate claims as numbers, kept as they are."""

    model_config = pydantic.ConfigDict(extra="allow")

    exp: int
    nbf: float


class DatedMembersModel(pydantic.BaseModel):
    """A datetime `exp`, and members whose decoded value depends on the very JSON they are."""

    exp: datetime
    amount: Decimal
    nested: dict[str, list[float | int]]


class NumberedMembersModel(pydantic.BaseModel):
    """`DatedMembersModel`, with an int `exp`."""

    exp: int
    amount: Decimal
    nested: dict[str, list[float | int]]


class Expectations(TypedDict, total=False):
    """The `audience` and `issuer` a key, or a `decode` call, checks tokens against."""

    audience: str | Iterable[str] | None
    issuer: str | Iterable[str] | None


class DecodeOptions(Expectations, total=False):
    leeway: float | timedelta


class Decode(Protocol):
    def __call__(self, token: str, **kwargs: Unpack[DecodeOptions]) -> object: ...


@dataclass(frozen=True, slots=True)
class _DecodeTo:
    """`Decode`: `key.decode`, to a dict or (`to` "struct") to a `NoClaims` Struct."""

    key: ryjwt.SecretKey
    to: str

    def __call__(self, token: str, **kwargs: Unpack[DecodeOptions]) -> object:
        if self.to == "dict":
            return self.key.decode(token, **kwargs)
        return self.key.decode(token, type=NoClaims, **kwargs)


@pytest.fixture(name="decode", params=["dict", "struct"])
def _decode(request: pytest.FixtureRequest, hmac_jwt: ryjwt.SecretKey) -> Decode:
    """`hmac_jwt.decode`, to a dict or to a Struct: claim validation must behave the same either
    way."""
    return _DecodeTo(hmac_jwt, request.param)


@dataclass(frozen=True, slots=True)
class KeyMaker:
    """Builds keys from one `source` (a class, or one of its other constructors), set up with an
    audience and issuer, and signs tokens they verify."""

    source: str
    hmac_key: str
    private_pem: bytes
    public_pem: bytes
    jwk: dict[str, Any]
    directory: Path

    def __call__(self, **expected: Unpack[Expectations]) -> AnyKey:
        private_path, public_path = self.directory / "private.pem", self.directory / "public.pem"
        private_path.write_bytes(self.private_pem)
        public_path.write_bytes(self.public_pem)
        match self.source:
            case "hmac":
                return ryjwt.SecretKey(self.hmac_key, algorithms=["HS256"], **expected)
            case "private-key":
                return ryjwt.PrivateKey(self.private_pem, algorithms=["ES256"], **expected)
            case "private-key-from-path":
                return ryjwt.PrivateKey.from_path(private_path, algorithms=["ES256"], **expected)
            case "public-key":
                return ryjwt.PublicKey(self.public_pem, algorithms=["ES256"], **expected)
            case "public-key-from-path":
                return ryjwt.PublicKey.from_path(public_path, algorithms=["ES256"], **expected)
            case _:
                jwks = {"keys": [self.jwk]}
                return ryjwt.PublicKey.from_jwks(jwks, algorithms=["ES256"], **expected)

    def encode(self, claims: dict[str, Any]) -> str:
        if self.source == "hmac":
            return ryjwt.SecretKey(self.hmac_key, algorithms=["HS256"]).encode(claims)
        return ryjwt.PrivateKey(self.private_pem, algorithms=["ES256"]).encode(claims)


@pytest.fixture(
    name="make_key",
    params=[
        "hmac",
        "private-key",
        "private-key-from-path",
        "public-key",
        "public-key-from-path",
        "public-key-from-jwks",
    ],
)
def _make_key(
    request: pytest.FixtureRequest,
    hmac_key: str,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    tmp_path: Path,
) -> KeyMaker:
    return KeyMaker(
        request.param,
        hmac_key,
        private_pems["ES256"],
        public_pems["ES256"],
        make_jwk(private_keys["ES256"]),
        tmp_path,
    )


def _rejection(
    key: AnyKey,
    token: str,
    **kwargs: Unpack[Expectations],
) -> tuple[type[Exception], str] | None:
    """Why `key.decode(token, **kwargs)` rejects the token (its error's type and message), or None
    if it doesn't."""
    try:
        key.decode(token, **kwargs)
    except ryjwt.InvalidTokenError as e:
        return type(e), str(e)
    return None


def test_decodes_to_dict_by_default(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub", "n": [1, 2.5, None, True]})

    assert hmac_jwt.decode(token) == {"sub": "sub", "n": [1, 2.5, None, True]}
    assert hmac_jwt.decode(token.encode()) == {"sub": "sub", "n": [1, 2.5, None, True]}


def test_decodes_to_struct_and_model(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub", "other": "other"})

    assert hmac_jwt.decode(token, type=ClaimsStruct) == ClaimsStruct(sub="sub")
    assert hmac_jwt.decode(token, type=ClaimsModel) == ClaimsModel(sub="sub")


def test_decodes_to_a_generic_struct(hmac_jwt: ryjwt.SecretKey, future: int, past: int) -> None:
    token = hmac_jwt.encode({"sub": 1, "exp": future, "value": "value"})

    assert hmac_jwt.decode(token, type=GenericClaims[int]) == GenericClaims(1)
    assert hmac_jwt.decode(token, type=GenericDeclaredClaims[str]) == GenericDeclaredClaims(
        future, "value"
    )
    with pytest.raises(ryjwt.ClaimsValidationError, match="GenericClaims: Expected `str`"):
        hmac_jwt.decode(token, type=GenericClaims[str])
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(hmac_jwt.encode({"exp": past, "value": 1}), type=GenericDeclaredClaims[int])


@pytest.mark.parametrize(
    ("type_", "cause"),
    [
        pytest.param(DatetimeClaimsStruct, msgspec.ValidationError, id="struct"),
        pytest.param(DatetimeClaimsModel, pydantic.ValidationError, id="model"),
    ],
)
@pytest.mark.parametrize(
    ("claims", "match"),
    [
        pytest.param({"exp": 4_102_444_800, "iat": 946_684_800}, "sub", id="missing"),
        pytest.param({"sub": 1, "exp": 4_102_444_800, "iat": 946_684_800}, "sub", id="wrong-type"),
        pytest.param({"sub": "sub", "exp": 4_102_444_800, "iat": 10**20}, "iat", id="out-of-range"),
    ],
)
def test_claims_that_dont_fit_the_type(
    claims: dict[str, object],
    match: str,
    type_: type[DatetimeClaimsStruct | DatetimeClaimsModel],
    cause: type[Exception],
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    with pytest.raises(ryjwt.ClaimsValidationError, match=match) as error:
        hmac_jwt.decode(hmac_jwt.encode(claims), type=type_)

    assert isinstance(error.value, ryjwt.InvalidTokenError)
    assert isinstance(error.value.__cause__, cause)


@pytest.mark.parametrize(
    ("type_", "cause"),
    [
        pytest.param(ClaimsStruct, msgspec.ValidationError, id="struct"),
        pytest.param(ClaimsModel, pydantic.ValidationError, id="model"),
    ],
)
def test_claims_that_dont_fit_a_plain_type(
    type_: type[ClaimsStruct | ClaimsModel],
    cause: type[Exception],
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    with pytest.raises(ryjwt.ClaimsValidationError, match="sub") as error:
        hmac_jwt.decode(hmac_jwt.encode({"other": "other"}), type=type_)

    assert isinstance(error.value.__cause__, cause)


def test_payload_only_pydantic_rejects_is_a_decode_error(
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    """Nesting just past pydantic's limit, which it reports as a ValidationError (json_invalid)."""
    payload = b'{"sub":"sub","x":' + b"[" * 201 + b"]" * 201 + b"}"
    token = raw_hs256_token(b'{"alg":"HS256"}', payload)

    with pytest.raises(ryjwt.DecodeError, match="Invalid payload JSON"):
        hmac_jwt.decode(token, type=ClaimsModel)


@pytest.mark.parametrize(
    "type_",
    [
        dict,
        dict[str, Any],
        OrderedDict,
        DictClaims,
        list,
        int,
        str,
        ClaimsStruct(sub="sub"),
        list[int],
    ],
)
def test_unsupported_type_raises_type_error(type_: object, hmac_jwt: ryjwt.SecretKey) -> None:
    untyped_caller: Any = type_  # what an untyped caller could pass

    with pytest.raises(TypeError, match="type must be None, a msgspec Struct or a pydantic"):
        hmac_jwt.decode(hmac_jwt.encode({"sub": "sub"}), type=untyped_caller)


def test_claims_are_validated_even_when_the_type_omits_them(
    hmac_jwt: ryjwt.SecretKey,
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
    claims: dict[str, object],
    kwargs: DecodeOptions,
    expected: type[Exception] | None,
    hmac_jwt: ryjwt.SecretKey,
    decode: Decode,
) -> None:
    now = int(time.time())
    times = {"future": now + 3600, "past": now - 3600, "recent": now - 60}
    payload = {"sub": "sub"} | {
        k: times.get(v, v) if isinstance(v, str) else v for k, v in claims.items()
    }
    token = hmac_jwt.encode(payload)

    if expected is None:
        decode(token, **kwargs)
    else:
        with pytest.raises(expected) as error:
            decode(token, **kwargs)
        assert type(error.value) is expected


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        pytest.param('{{"exp":{future},"aud":"a"}}', None, id="valid"),
        pytest.param('{{"exp":{past},"aud":"a"}}', ryjwt.ExpiredSignatureError, id="expired"),
        pytest.param(
            '{{"exp":{future},"aud":"a","exp":{past}}}',
            ryjwt.ExpiredSignatureError,
            id="duplicate-takes-last",
        ),
        pytest.param('{{"exp":{past},"aud":"a","exp":{future}}}', None, id="duplicate-valid-last"),
        pytest.param(
            '{{"exp":{future},"aud":"a","e\\u0078p":{past}}}',
            ryjwt.ExpiredSignatureError,
            id="escaped-key",
        ),
        pytest.param(
            '{{"exp":{past},"aud":1}}',
            ryjwt.ExpiredSignatureError,
            id="expired-before-type-mismatch",
        ),
        pytest.param('{{"exp":{future},"aud":"b"}}', ryjwt.InvalidAudienceError, id="aud-mismatch"),
        pytest.param(
            '{{"exp":{future},"aud":"a","nbf":{future}}}',
            ryjwt.ImmatureSignatureError,
            id="undeclared-claim",
        ),
        pytest.param(
            '{{"exp":{future},"aud":"a","n\\u0062f":{future}}}',
            ryjwt.ImmatureSignatureError,
            id="undeclared-claim-escaped",
        ),
        pytest.param('{{"exp":{future},"aud":"a","o":{{"exp":{past}}}}}', None, id="nested-exp"),
        pytest.param(
            '{{"exp":{future},"aud":"a","x":' + "[" * 250 + "]" * 250 + "}}",
            ryjwt.DecodeError,
            id="too-deep",
        ),
        pytest.param('{{"exp":{future},"aud":"a","x":"\udcff"}}', ryjwt.DecodeError, id="bad-utf8"),
        pytest.param(
            '{{"exp":{future},"aud":"a","x":"\\ud800"}}',
            ryjwt.DecodeError,
            id="lone-surrogate",
        ),
        pytest.param('{{"exp":{future},"aud":"a",}}', ryjwt.DecodeError, id="bad-json"),
    ],
)
@pytest.mark.parametrize("type_", [DeclaredClaims, ScannedClaims], ids=["declared", "scanned"])
def test_declared_claims(
    payload: str,
    expected: type[Exception] | None,
    type_: type[DeclaredClaims],
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
    future: int,
    past: int,
) -> None:
    raw = payload.format(future=future, past=past).encode(errors="surrogateescape")
    token = raw_hs256_token(b'{"alg":"HS256"}', raw)

    if expected is None:
        hmac_jwt.decode(token, type=type_, audience="a")
    else:
        with pytest.raises(expected):
            hmac_jwt.decode(token, type=type_, audience="a")


def test_claim_with_default_is_absent_when_missing(hmac_jwt: ryjwt.SecretKey, past: int) -> None:
    assert hmac_jwt.decode(hmac_jwt.encode({"sub": "sub"}), type=DefaultExp) == DefaultExp()
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(hmac_jwt.encode({"exp": past}), type=DefaultExp)


def test_claim_of_another_type_is_validated_from_the_payload(
    hmac_jwt: ryjwt.SecretKey,
    future: int,
) -> None:
    token = hmac_jwt.encode({"exp": future})

    assert hmac_jwt.decode(token, type=DecimalExp) == DecimalExp(Decimal(future))


def test_claims_follow_field_renames(hmac_jwt: ryjwt.SecretKey, future: int, past: int) -> None:
    assert hmac_jwt.decode(hmac_jwt.encode({"exp": future}), type=RenamedExp) == RenamedExp(future)
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(hmac_jwt.encode({"exp": past}), type=RenamedExp)
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(hmac_jwt.encode({"exp": past, "expires_at": future}), type=ShadowedExp)


def test_type_never_sees_invalid_claims(hmac_jwt: ryjwt.SecretKey, past: int) -> None:
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(hmac_jwt.encode({"exp": past}), type=Recorded)

    assert Recorded.built == []


def test_array_like_struct_needs_an_object_payload(
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    with pytest.raises(ryjwt.DecodeError):
        hmac_jwt.decode(raw_hs256_token(b'{"alg":"HS256"}', b"[4102444800]"), type=ArrayLike)


@pytest.mark.parametrize("type_", [DatetimeClaimsStruct, DatetimeClaimsModel])
def test_datetime_claims_round_trip(
    type_: type[DatetimeClaimsStruct | DatetimeClaimsModel],
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    token = hmac_jwt.encode(
        type_(
            sub="sub",
            exp=datetime(2100, 1, 1, tzinfo=UTC),
            iat=datetime(2000, 1, 1, tzinfo=UTC),
            nbf=datetime(2000, 1, 1, tzinfo=UTC),
        )
    )

    claims = hmac_jwt.decode(token, type=type_)

    assert claims == type_(
        sub="sub",
        exp=datetime(2100, 1, 1, tzinfo=UTC),
        iat=datetime(2000, 1, 1, tzinfo=UTC),
        nbf=datetime(2000, 1, 1, tzinfo=UTC),
    )
    assert claims.exp.utcoffset() == timedelta(0)
    assert hmac_jwt.decode(token) == {
        "sub": "sub",
        "exp": 4_102_444_800,
        "iat": 946_684_800,
        "nbf": 946_684_800,
    }


@pytest.mark.parametrize("type_", [DatetimeClaimsStruct, DatetimeClaimsModel])
def test_datetime_claims_from_numbers(
    type_: type[DatetimeClaimsStruct | DatetimeClaimsModel],
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    token = hmac_jwt.encode({"sub": "sub", "exp": 4_102_444_800.5, "iat": 946_684_800})

    assert hmac_jwt.decode(token, type=type_) == type_(
        sub="sub",
        exp=datetime(2100, 1, 1, 0, 0, 0, 500_000, tzinfo=UTC),
        iat=datetime(2000, 1, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize("type_", [DatetimeClaimsStruct, DatetimeClaimsModel])
@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        pytest.param({"exp": "past"}, ryjwt.ExpiredSignatureError, id="exp-expired"),
        pytest.param({"exp": "future", "nbf": "future"}, ryjwt.ImmatureSignatureError, id="nbf"),
        pytest.param({"exp": "2100-01-01T00:00:00Z"}, ryjwt.DecodeError, id="exp-string"),
        pytest.param({"exp": True}, ryjwt.DecodeError, id="exp-bool"),
        pytest.param({"exp": "future", "nbf": None}, ryjwt.DecodeError, id="nbf-null"),
    ],
)
def test_datetime_claims_are_validated(
    claims: dict[str, object],
    expected: type[Exception],
    type_: type[DatetimeClaimsStruct | DatetimeClaimsModel],
    hmac_jwt: ryjwt.SecretKey,
    future: int,
    past: int,
) -> None:
    times = {"future": future, "past": past}
    payload = {"sub": "sub", "iat": past} | {
        k: times.get(v, v) if isinstance(v, str) else v for k, v in claims.items()
    }

    with pytest.raises(expected) as error:
        hmac_jwt.decode(hmac_jwt.encode(payload), type=type_)
    assert type(error.value) is expected


def test_datetime_claim_leaves_the_other_members_alone(
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    """A datetime claim decoded from a NumericDate changes how nothing else decodes."""
    token = raw_hs256_token(
        b'{"alg":"HS256"}',
        b'{"exp": 4102444800, "raw": {"a": [1, 2.50]}, "keys": {"1": "one"}, '
        b'"amount": 0.1000000000000000055511151231257827}',
    )

    dated = hmac_jwt.decode(token, type=DatedMembers)
    numbered = hmac_jwt.decode(token, type=NumberedMembers)

    assert dated.exp == datetime(2100, 1, 1, tzinfo=UTC)
    assert numbered.exp == 4_102_444_800
    assert bytes(dated.raw) == bytes(numbered.raw) == b'{"a": [1, 2.50]}'
    assert dated.keys == numbered.keys == {1: "one"}
    assert dated.amount == numbered.amount == Decimal("0.1000000000000000055511151231257827")


def test_far_datetime_claims_in_models(hmac_jwt: ryjwt.SecretKey) -> None:
    """NumericDates from 2e10 on, which pydantic would take as milliseconds, are seconds, as
    `decode` validated them: whatever the annotation, by alias, `Optional` or `Annotated`."""
    token = hmac_jwt.encode({"exp": 30_000_000_000.5, "nbf": 0, "iat": 20_000_000_001})

    claims = hmac_jwt.decode(token, type=FarDatetimeModel)
    aliased = hmac_jwt.decode(token, type=AliasedDatetimeModel)

    assert claims == FarDatetimeModel(
        exp=datetime(2920, 8, 30, 5, 20, 0, 500_000, tzinfo=UTC),
        nbf=datetime(1970, 1, 1, tzinfo=UTC),
        iat=datetime(2603, 10, 11, 11, 33, 21, tzinfo=UTC),
    )
    assert aliased == AliasedDatetimeModel(
        expires=datetime(2920, 8, 30, 5, 20, 0, 500_000, tzinfo=UTC)
    )


def test_numeric_date_claims_in_number_fields_are_unchanged(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"exp": 30_000_000_000, "nbf": 0.5, "iat": 20_000_000_001})

    claims = hmac_jwt.decode(token, type=NumberModel)

    assert claims.model_dump() == {"exp": 30_000_000_000, "nbf": 0.5, "iat": 20_000_000_001}


def test_model_datetime_claim_leaves_the_other_members_alone(
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    """A datetime claim decoded from a NumericDate changes how nothing else decodes."""
    token = raw_hs256_token(
        b'{"alg":"HS256"}',
        b' { "amount" : 0.1000000000000000055511151231257827,"exp":\n30000000000 , '
        b'"nested": {"\\u0065xp": [1, 2.50]}} ',
    )

    dated = hmac_jwt.decode(token, type=DatedMembersModel)
    numbered = hmac_jwt.decode(token, type=NumberedMembersModel)

    assert dated.exp == datetime(2920, 8, 30, 5, 20, tzinfo=UTC)
    assert numbered.exp == 30_000_000_000
    assert dated.amount == numbered.amount
    assert dated.nested == numbered.nested == {"exp": [1, 2.5]}
    assert type(dated.nested["exp"][0]) is type(numbered.nested["exp"][0]) is int


def test_out_of_range_datetime_claim_in_a_model(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub", "exp": 2**40, "iat": 946_684_800})

    with pytest.raises(ryjwt.ClaimsValidationError, match=r"out of range - at `exp`") as error:
        hmac_jwt.decode(token, type=DatetimeClaimsModel)
    assert isinstance(error.value.__cause__, pydantic.ValidationError)


def test_expired_datetime_claim_is_rejected(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode(
        DatetimeClaimsStruct(
            sub="sub",
            exp=datetime(2000, 1, 1, tzinfo=UTC),
            iat=datetime(2000, 1, 1, tzinfo=UTC),
        )
    )

    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(token, type=DatetimeClaimsStruct)
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(token, type=DatetimeClaimsModel)


def test_out_of_range_datetime_claim(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub", "exp": 2**40, "iat": 946_684_800})

    with pytest.raises(ryjwt.ClaimsValidationError, match=r"out of range.*at `\$\.exp`"):
        hmac_jwt.decode(token, type=DatetimeClaimsStruct)


def test_datetime_claim_among_claims_read_from_the_instance(
    hmac_jwt: ryjwt.SecretKey,
    future: int,
    past: int,
) -> None:
    token = hmac_jwt.encode({"exp": future, "aud": "aud", "iat": 946_684_800})

    assert hmac_jwt.decode(
        token, type=DeclaredClaimsWithDatetime, audience="aud"
    ) == DeclaredClaimsWithDatetime(future, "aud", datetime(2000, 1, 1, tzinfo=UTC))
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(
            hmac_jwt.encode({"exp": past, "aud": "aud", "iat": 946_684_800}),
            type=DeclaredClaimsWithDatetime,
            audience="aud",
        )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        pytest.param(b'{"iat":0}', Issued(EPOCH), id="epoch"),
        pytest.param(
            b'{"iat":253402300799}',
            Issued(datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)),
            id="latest",
        ),
        pytest.param(b'{"iat":-1}', Issued(EPOCH - timedelta(seconds=1)), id="negative"),
        pytest.param(b'{"iat":-0}', Issued(EPOCH), id="negative-zero"),
        pytest.param(b'{"iat":1.5}', Issued(EPOCH + timedelta(seconds=1.5)), id="fraction"),
        pytest.param(b'{"iat":1e3}', Issued(EPOCH + timedelta(seconds=1000)), id="exponent"),
        pytest.param(b' { "iat" :\n 946684800 } ', Issued(Y2K), id="whitespace"),
        pytest.param(b'{"\\u0069at":946684800}', Issued(Y2K), id="escaped-name"),
        pytest.param(b'{"iat":"x","iat":946684800}', Issued(Y2K), id="repeated-claim"),
        pytest.param(
            b'{"iat":946684800,"sub":1,"sub":"s"}', Issued(Y2K, "s"), id="repeated-member"
        ),
        pytest.param(b'{"iat":"2000-01-01T00:00:00Z"}', Issued(Y2K), id="rfc3339"),
        pytest.param(
            b'{"iat":946684800,' + b",".join(b'"m%d":%d' % (i, i) for i in range(40)) + b"}",
            Issued(Y2K),
            id="many-members",
        ),
    ],
)
def test_datetime_claim_however_the_payload_spells_it(
    payload: bytes,
    expected: Issued,
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    claims = hmac_jwt.decode(raw_hs256_token(b'{"alg":"HS256"}', payload), type=Issued)

    assert claims == expected
    assert claims.iat.tzinfo is UTC


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        pytest.param(b'{"iat":-62135596801}', r"out of range.*at `\$\.iat`", id="before-year-1"),
        pytest.param(b'{"iat":253402300800}', r"out of range.*at `\$\.iat`", id="after-year-9999"),
        pytest.param(b'{"iat":1e300}', r"out of range.*at `\$\.iat`", id="huge-float"),
        pytest.param(b'{"iat":true}', r"Expected `datetime`, got `bool` - at `\$\.iat`", id="bool"),
        pytest.param(b'{"iat":null}', r"Expected `datetime`, got `null` - at `\$\.iat`", id="null"),
        pytest.param(
            b'{"iat":946684800,"sub":1}', r"Expected `str`, got `int` - at `\$\.sub`", id="sub"
        ),
    ],
)
def test_invalid_datetime_claim(
    payload: bytes,
    match: str,
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    with pytest.raises(ryjwt.ClaimsValidationError, match=match):
        hmac_jwt.decode(raw_hs256_token(b'{"alg":"HS256"}', payload), type=Issued)


def test_datetime_claims_from_whole_seconds(hmac_jwt: ryjwt.SecretKey) -> None:
    rng = random.Random(0)
    seconds = [rng.randrange(253_402_300_800) for _ in range(2000)]

    for n in seconds:
        claims = hmac_jwt.decode(hmac_jwt.encode({"iat": n}), type=Issued)
        assert claims == Issued(EPOCH + timedelta(seconds=n)), n


def test_datetime_claims_in_a_frozen_struct(hmac_jwt: ryjwt.SecretKey, future: int) -> None:
    expires = EPOCH + timedelta(seconds=future)

    assert hmac_jwt.decode(hmac_jwt.encode({"exp": future}), type=DatedSession) == DatedSession(
        expires=expires
    )
    assert hmac_jwt.decode(
        hmac_jwt.encode({"exp": future, "nbf": 946_684_800, "sub": "s"}), type=DatedSession
    ) == DatedSession(expires=expires, nbf=Y2K, sub="s")
    with pytest.raises(ryjwt.ClaimsValidationError, match="unknown field `iat`"):
        hmac_jwt.decode(hmac_jwt.encode({"exp": future, "iat": 0}), type=DatedSession)


def test_datetime_claim_in_a_generic_struct(hmac_jwt: ryjwt.SecretKey, future: int) -> None:
    token = hmac_jwt.encode({"exp": future, "value": 1})

    assert hmac_jwt.decode(token, type=GenericDated[int]) == GenericDated(
        EPOCH + timedelta(seconds=future), 1
    )
    with pytest.raises(ryjwt.ClaimsValidationError, match="Expected `str`, got `int`"):
        hmac_jwt.decode(token, type=GenericDated[str])


def test_datetime_claims_are_checked_before_post_init(
    hmac_jwt: ryjwt.SecretKey,
    future: int,
    past: int,
) -> None:
    RecordedDated.built.clear()
    with pytest.raises(ryjwt.ExpiredSignatureError):
        hmac_jwt.decode(hmac_jwt.encode({"exp": past}), type=RecordedDated)
    assert RecordedDated.built == []

    claims = hmac_jwt.decode(hmac_jwt.encode({"exp": future}), type=RecordedDated)

    assert RecordedDated.built == [claims]
    assert claims.exp == EPOCH + timedelta(seconds=future)


def test_audience_accepts_any_iterable(hmac_jwt: ryjwt.SecretKey) -> None:
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
        pytest.param({"leeway": math.nan}, ValueError, id="leeway-nan"),
        pytest.param({"leeway": math.inf}, ValueError, id="leeway-inf"),
        pytest.param({"leeway": -math.inf}, ValueError, id="leeway-negative-inf"),
        pytest.param({"leeway": -1}, ValueError, id="leeway-negative"),
        pytest.param({"leeway": timedelta(seconds=-1)}, ValueError, id="leeway-negative-timedelta"),
    ],
)
def test_invalid_arguments(
    kwargs: dict[str, object],
    error: type[Exception],
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    untyped_caller: dict[str, Any] = kwargs  # what an untyped caller could pass

    with pytest.raises(error):
        hmac_jwt.decode(hmac_jwt.encode({"sub": "sub"}), **untyped_caller)


@pytest.mark.parametrize(
    ("expected", "claims", "error"),
    [
        pytest.param({"audience": "aud"}, {"aud": "aud"}, None, id="aud-match"),
        pytest.param({"audience": "aud"}, {"aud": ["x", "aud"]}, None, id="aud-list-match"),
        pytest.param({"audience": ["x", "aud"]}, {"aud": "aud"}, None, id="audience-list-match"),
        pytest.param(
            {"audience": "aud"},
            {"aud": "other"},
            ryjwt.InvalidAudienceError,
            id="aud-mismatch",
        ),
        pytest.param({"audience": "aud"}, {}, ryjwt.InvalidAudienceError, id="aud-missing"),
        pytest.param(
            {"audience": []}, {"aud": "aud"}, ryjwt.InvalidAudienceError, id="no-audiences"
        ),
        pytest.param(
            {"issuer": "iss"},
            {"aud": "aud", "iss": "iss"},
            ryjwt.InvalidAudienceError,
            id="aud-without-audience",
        ),
        pytest.param({"issuer": "iss"}, {"iss": "iss"}, None, id="iss-match"),
        pytest.param({"issuer": {"x", "iss"}}, {"iss": "iss"}, None, id="issuer-set-match"),
        pytest.param(
            {"issuer": "iss"},
            {"iss": "other"},
            ryjwt.InvalidIssuerError,
            id="iss-mismatch",
        ),
        pytest.param({"issuer": "iss"}, {}, ryjwt.InvalidIssuerError, id="iss-missing"),
        pytest.param({"issuer": "iss"}, {"iss": 1}, ryjwt.InvalidIssuerError, id="iss-int"),
        pytest.param({"issuer": []}, {"iss": "iss"}, ryjwt.InvalidIssuerError, id="no-issuers"),
        pytest.param({"audience": "aud"}, {"aud": "aud", "iss": 1}, None, id="iss-unchecked"),
        pytest.param(
            {"audience": "aud", "issuer": "iss"},
            {"aud": "aud", "iss": "iss"},
            None,
            id="both-match",
        ),
    ],
)
def test_audience_and_issuer_set_on_the_key(
    expected: Expectations,
    claims: dict[str, Any],
    error: type[Exception] | None,
    make_key: KeyMaker,
) -> None:
    """The key checks them when `decode` isn't given any, as `decode` checks its own: the same
    errors, with the same messages."""
    token = make_key.encode(claims)

    rejection = _rejection(make_key(**expected), token)

    assert rejection == _rejection(make_key(), token, **expected)
    assert (None if rejection is None else rejection[0]) is error


def test_decode_arguments_replace_the_keys_audience_and_issuer(make_key: KeyMaker) -> None:
    key = make_key(audience="aud", issuer="iss")
    token = make_key.encode({"aud": "aud", "iss": "iss"})
    other_token = make_key.encode({"aud": "other-aud", "iss": "other-iss"})

    assert key.decode(token, audience=None, issuer=None) == {"aud": "aud", "iss": "iss"}
    assert key.decode(other_token, audience="other-aud", issuer=["other-iss"]) == {
        "aud": "other-aud",
        "iss": "other-iss",
    }
    with pytest.raises(ryjwt.InvalidAudienceError, match="Audience doesn't match"):
        key.decode(token, audience="other-aud")  # replaces the key's, rather than adding to it
    with pytest.raises(ryjwt.InvalidIssuerError, match="Issuer doesn't match"):
        key.decode(token, issuer="other-iss")
    with pytest.raises(ryjwt.InvalidIssuerError, match="Issuer doesn't match"):
        key.decode(other_token, audience="other-aud")  # the key's issuer still applies
    with pytest.raises(ryjwt.InvalidAudienceError, match="Audience doesn't match"):
        key.decode(other_token, issuer="other-iss")  # and so does its audience


def test_key_audience_and_issuer_accept_any_iterable(make_key: KeyMaker) -> None:
    key = make_key(audience=(a for a in ["x", "aud"]), issuer=iter(["iss"]))
    token = make_key.encode({"aud": "aud", "iss": "iss"})

    assert key.decode(token) == {"aud": "aud", "iss": "iss"}
    assert key.decode(token) == {"aud": "aud", "iss": "iss"}  # read once, and kept


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        pytest.param(
            {"audience": 1}, "audience must be a str or an iterable of str", id="audience"
        ),
        pytest.param(
            {"audience": ["aud", 1]},
            "audience must be a str or an iterable of str",
            id="audience-item",
        ),
        pytest.param({"issuer": 1}, "issuer must be a str or an iterable of str", id="issuer"),
        pytest.param(
            {"issuer": [b"iss"]},
            "issuer must be a str or an iterable of str",
            id="issuer-item",
        ),
    ],
)
def test_invalid_key_audience_and_issuer(
    kwargs: dict[str, object], match: str, make_key: KeyMaker
) -> None:
    """They're checked when the key is created, raising what `decode` raises for them."""
    untyped_caller: Any = kwargs  # what an untyped caller could pass
    token = make_key.encode({"sub": "sub"})

    with pytest.raises(TypeError, match=match):
        make_key(**untyped_caller)
    with pytest.raises(TypeError, match=match):
        make_key().decode(token, **untyped_caller)


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
        pytest.param(b'{"alg":"HS256"}', b'{"a":1' + b"0" * 40 + b"}", None, id="payload-bigint"),
    ],
)
def test_raw_tokens(
    header: bytes,
    payload: bytes,
    expected: type[Exception] | None,
    decode: Decode,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    token = raw_hs256_token(header, payload)

    if expected is None:
        decode(token)
    else:
        with pytest.raises(expected):
            decode(token)


@pytest.mark.parametrize(
    ("parameters", "expected"), [(64, None), (65, ryjwt.DecodeError), (5000, ryjwt.DecodeError)]
)
def test_header_parameter_limit(
    parameters: int,
    expected: type[Exception] | None,
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    others = "".join(f',"p{i}":0' for i in range(parameters - 1))
    token = raw_hs256_token(f'{{"alg":"HS256"{others}}}'.encode(), b'{"sub":"sub"}')

    if expected is None:
        assert hmac_jwt.decode(token) == {"sub": "sub"}
    else:
        with pytest.raises(expected, match="more than 64 parameters"):
            hmac_jwt.decode(token)


def test_deeply_nested_payload(
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    payload = b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    token = raw_hs256_token(b'{"alg":"HS256"}', payload)

    with pytest.raises(ryjwt.DecodeError, match="Invalid payload JSON"):
        hmac_jwt.decode(token)
    with pytest.raises(ryjwt.DecodeError, match="Invalid payload JSON"):
        hmac_jwt.decode(token, type=ClaimsStruct)
    with pytest.raises(ryjwt.DecodeError, match="Invalid payload JSON"):
        hmac_jwt.decode(token, type=ClaimsModel)


@pytest.mark.parametrize(
    "malformation",
    [
        "two-segments",
        "four-segments",
        "empty",
        "padded-signature",
        "padded-header",
        "non-base64url-payload",
        "non-ascii",
        "truncated-signature",
    ],
)
def test_malformed_tokens(malformation: str, hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub"})
    header, payload, signature = token.split(".")
    malformed = {
        "two-segments": f"{header}.{payload}",
        "four-segments": f"{token}.x",
        "empty": "",
        "padded-signature": f"{token}=",
        "padded-header": f"{header}==.{payload}.{signature}",
        "non-base64url-payload": f"{header}.{payload}!.{signature}",
        "non-ascii": token + "é",
        "truncated-signature": token[:-2],
    }

    with pytest.raises(ryjwt.DecodeError):
        hmac_jwt.decode(malformed[malformation])


@pytest.mark.parametrize("tamper", ["replaced", "truncated", "empty"])
def test_bad_signature(tamper: str, hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub"})
    signing_input = token.rsplit(".", 1)[0]
    tampered = {
        "replaced": token[:-4] + "AAAA",
        "truncated": token[:-3],
        "empty": f"{signing_input}.",
    }

    with pytest.raises(ryjwt.InvalidSignatureError):
        hmac_jwt.decode(tampered[tamper])


def test_wrong_key(hmac_jwt: ryjwt.SecretKey) -> None:
    other = ryjwt.SecretKey("other-key" * 8, algorithms=["HS256"])

    with pytest.raises(ryjwt.InvalidSignatureError):
        hmac_jwt.decode(other.encode({"sub": "sub"}))


def test_token_must_be_str_or_bytes(hmac_jwt: ryjwt.SecretKey) -> None:
    untyped_caller: Any = 1  # what an untyped caller could pass

    with pytest.raises(TypeError):
        hmac_jwt.decode(untyped_caller)


@pytest.mark.parametrize(
    ("error", "base"),
    [
        (ryjwt.InvalidSignatureError, ryjwt.DecodeError),
        (ryjwt.ClaimsValidationError, ryjwt.InvalidTokenError),
        (ryjwt.DecodeError, ryjwt.InvalidTokenError),
        (ryjwt.InvalidAlgorithmError, ryjwt.InvalidTokenError),
        (ryjwt.ExpiredSignatureError, ryjwt.InvalidTokenError),
        (ryjwt.ImmatureSignatureError, ryjwt.InvalidTokenError),
        (ryjwt.InvalidAudienceError, ryjwt.InvalidTokenError),
        (ryjwt.InvalidIssuerError, ryjwt.InvalidTokenError),
        (ryjwt.InvalidTokenError, ryjwt.RYJWTError),
        (ryjwt.InvalidKeyError, ryjwt.RYJWTError),
    ],
)
def test_exception_hierarchy(error: type[Exception], base: type[Exception]) -> None:
    assert issubclass(error, base)


def test_dict_decoder_is_msgspec_when_installed(
    monkeypatch: pytest.MonkeyPatch,
    hmac_key: str,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    token = raw_hs256_token(b'{"alg":"HS256"}', b'{"a":}')
    with_msgspec = ryjwt.SecretKey(hmac_key, algorithms=["HS256"])
    monkeypatch.setitem(sys.modules, "msgspec.json", None)
    without_msgspec = ryjwt.SecretKey(hmac_key, algorithms=["HS256"])

    with pytest.raises(ryjwt.DecodeError, match="Invalid payload JSON") as msgspec_error:
        with_msgspec.decode(token)
    with pytest.raises(ryjwt.DecodeError, match="Invalid payload JSON") as jiter_error:
        without_msgspec.decode(token)

    assert isinstance(msgspec_error.value.__cause__, msgspec.DecodeError)
    assert jiter_error.value.__cause__ is None
