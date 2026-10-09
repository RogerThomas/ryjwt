import base64
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Annotated, Any

import jwt
import msgspec
import pydantic
import pytest
import ryjwt
from _support import DatetimeClaimsModel, DatetimeClaimsStruct


class ClaimsStruct(msgspec.Struct):
    sub: str
    exp: int


class RenamedStruct(msgspec.Struct, rename={"subject": "sub"}):
    subject: str


class ArrayStruct(msgspec.Struct, array_like=True):
    sub: str


class AliasedModel(pydantic.BaseModel):
    subject: str = pydantic.Field(alias="sub")


class DatetimeFieldsStruct(msgspec.Struct):
    """A renamed datetime claim, and a datetime field that isn't a claim."""

    exp: datetime
    issued: datetime = msgspec.field(name="iat")
    other: datetime | None = None


class AliasedDatetimeModel(pydantic.BaseModel):
    issued: datetime = pydantic.Field(alias="iat")
    other: datetime


class AnnotatedDatetimeStruct(msgspec.Struct):
    """The NumericDate claims as datetimes, annotated otherwise than as plain `datetime`s."""

    exp: Annotated[datetime, msgspec.Meta(tz=True)]
    nbf: datetime | None
    iat: Annotated[datetime, msgspec.Meta(tz=True)] | None


class AwareDatetimeModel(pydantic.BaseModel):
    """The NumericDate claims as pydantic's own datetime types."""

    exp: pydantic.FutureDatetime
    nbf: pydantic.AwareDatetime | None
    iat: pydantic.PastDatetime


class AnnotatedDatetimeModel(pydantic.BaseModel):
    """The NumericDate claims as datetimes, annotated otherwise than as plain `datetime`s."""

    exp: Annotated[datetime, pydantic.Field(description="description")]
    nbf: Annotated[pydantic.AwareDatetime, pydantic.Field(description="description")] | None
    iat: pydantic.AwareDatetime | None = None


class Big(int):
    """An int that writes itself otherwise than as its digits."""

    def __str__(self) -> str:
        return "not-digits"

    def __repr__(self) -> str:
        return "not-digits"


class GenericStruct[T](msgspec.Struct):
    sub: str
    exp: T


def _payload(token: str) -> object:
    segment = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({}, id="empty"),
        pytest.param({"sub": "sub", "exp": 4_102_444_800}, id="simple"),
        pytest.param(
            {"s": 'quote " backslash \\ newline \n tab \t nul \x00 bell \x07 é 名 🙂'},
            id="escapes",
        ),
        pytest.param(
            {"big": 2**80, "neg": -(2**70), "f": 1.5e300, "tiny": 5e-324, "z": -0.0},
            id="numbers",
        ),
        pytest.param({"l": [1, [2, {"d": None}], (3, 4)], "b": [True, False]}, id="nested"),
    ],
)
def test_dict_claims_round_trip_as_json(claims: dict[str, Any], hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode(claims)

    assert _payload(token) == json.loads(json.dumps(claims))
    assert hmac_jwt.decode(token) == json.loads(json.dumps(claims))


def test_int_subclass_claims_are_written_as_their_digits(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"big": Big(2**70), "small": Big(-1)})

    assert _payload(token) == {"big": 2**70, "small": -1}


def test_typed_claims(hmac_jwt: ryjwt.SecretKey) -> None:
    assert _payload(hmac_jwt.encode(ClaimsStruct(sub="sub", exp=1))) == {"sub": "sub", "exp": 1}
    assert _payload(hmac_jwt.encode(RenamedStruct(subject="sub"))) == {"sub": "sub"}
    assert _payload(hmac_jwt.encode(AliasedModel(sub="sub"))) == {"sub": "sub"}
    assert hmac_jwt.decode(
        hmac_jwt.encode(AliasedModel(sub="sub")),
        type=AliasedModel,
    ) == AliasedModel(sub="sub")


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param(
            DatetimeClaimsStruct(
                sub="sub",
                exp=datetime(2100, 1, 1, tzinfo=UTC),
                iat=datetime(2000, 1, 1, tzinfo=UTC),
                nbf=datetime(2000, 1, 1, tzinfo=UTC),
            ),
            id="struct",
        ),
        pytest.param(
            DatetimeClaimsModel(
                sub="sub",
                exp=datetime(2100, 1, 1, tzinfo=UTC),
                iat=datetime(2000, 1, 1, tzinfo=UTC),
                nbf=datetime(2000, 1, 1, tzinfo=UTC),
            ),
            id="model",
        ),
        pytest.param(
            {
                "sub": "sub",
                "exp": datetime(2100, 1, 1, tzinfo=UTC),
                "iat": datetime(2000, 1, 1, tzinfo=UTC),
                "nbf": datetime(2000, 1, 1, tzinfo=UTC),
            },
            id="dict",
        ),
    ],
)
def test_datetime_claims_are_encoded_as_numeric_dates(
    claims: dict[str, Any] | msgspec.Struct | pydantic.BaseModel,
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    assert _payload(hmac_jwt.encode(claims)) == {
        "sub": "sub",
        "exp": 4_102_444_800,
        "iat": 946_684_800,
        "nbf": 946_684_800,
    }


def test_only_datetime_claims_are_numeric_dates(hmac_jwt: ryjwt.SecretKey) -> None:
    struct = DatetimeFieldsStruct(
        exp=datetime(2100, 1, 1, tzinfo=UTC),
        issued=datetime(2100, 1, 1, tzinfo=UTC),
        other=datetime(2100, 1, 1, tzinfo=UTC),
    )
    model = AliasedDatetimeModel(
        iat=datetime(2100, 1, 1, tzinfo=UTC),
        other=datetime(2100, 1, 1, tzinfo=UTC),
    )

    assert _payload(hmac_jwt.encode(struct)) == {
        "exp": 4_102_444_800,
        "iat": 4_102_444_800,
        "other": "2100-01-01T00:00:00Z",
    }
    assert _payload(hmac_jwt.encode(model)) == {
        "iat": 4_102_444_800,
        "other": "2100-01-01T00:00:00Z",
    }
    with pytest.raises(TypeError):
        hmac_jwt.encode({"other": datetime(2100, 1, 1, tzinfo=UTC)})
    with pytest.raises(TypeError):
        hmac_jwt.encode({"nested": {"exp": datetime(2100, 1, 1, tzinfo=UTC)}})


@pytest.mark.parametrize(
    "type_", [AnnotatedDatetimeStruct, AwareDatetimeModel, AnnotatedDatetimeModel]
)
def test_annotated_datetime_claims_round_trip(
    type_: type[AnnotatedDatetimeStruct | AwareDatetimeModel | AnnotatedDatetimeModel],
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    claims = type_(
        exp=datetime(2100, 1, 1, tzinfo=UTC),
        nbf=datetime(2000, 1, 1, tzinfo=UTC),
        iat=datetime(2000, 1, 1, tzinfo=UTC),
    )

    token = hmac_jwt.encode(claims)

    assert json.dumps(_payload(token)) == '{"exp": 4102444800, "nbf": 946684800, "iat": 946684800}'
    assert hmac_jwt.decode(token, type=type_) == claims


def test_generic_struct_datetime_claims_round_trip(hmac_jwt: ryjwt.SecretKey) -> None:
    """A generic Struct's claim is a datetime only in its parametrisations, which its instances
    don't know of (`type(instance)` is `GenericStruct`): its value says how to encode it."""
    claims = GenericStruct[datetime](sub="sub", exp=datetime(2100, 1, 1, tzinfo=UTC))

    token = hmac_jwt.encode(claims)

    assert json.dumps(_payload(token)) == '{"sub": "sub", "exp": 4102444800}'
    assert hmac_jwt.decode(token, type=GenericStruct[datetime]) == claims
    assert hmac_jwt.decode(token, type=GenericStruct[int]) == GenericStruct[int](
        sub="sub", exp=4_102_444_800
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(datetime(2100, 1, 1, 0, 0, 0, 999_999, tzinfo=UTC), 4_102_444_800, id="utc"),
        pytest.param(
            datetime(2100, 1, 1, 1, 0, 0, 999_999, tzinfo=timezone(timedelta(hours=1))),
            4_102_444_800,
            id="offset",
        ),
        pytest.param(datetime(1969, 12, 31, 23, 59, 59, 1, tzinfo=UTC), -1, id="before-epoch"),
    ],
)
def test_numeric_dates_drop_sub_second_precision(
    value: datetime,
    expected: int,
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    struct = DatetimeClaimsStruct(sub="sub", exp=value, iat=value)

    assert _payload(hmac_jwt.encode(struct)) == {"sub": "sub", "exp": expected, "iat": expected}
    assert _payload(hmac_jwt.encode({"exp": value})) == {"exp": expected}


@pytest.mark.parametrize("kind", ["struct", "model", "dict"])
def test_naive_datetime_claims_are_rejected(kind: str, hmac_jwt: ryjwt.SecretKey) -> None:
    naive = datetime(2100, 1, 1, tzinfo=UTC).replace(tzinfo=None)
    claims: dict[str, DatetimeClaimsStruct | DatetimeClaimsModel | dict[str, Any]] = {
        "struct": DatetimeClaimsStruct(sub="sub", exp=naive, iat=datetime(2000, 1, 1, tzinfo=UTC)),
        "model": DatetimeClaimsModel(sub="sub", exp=naive, iat=datetime(2000, 1, 1, tzinfo=UTC)),
        "dict": {"sub": "sub", "exp": naive},
    }

    with pytest.raises(ValueError, match="exp claim is a naive datetime"):
        hmac_jwt.encode(claims[kind])


@pytest.mark.parametrize(
    ("claims", "error"),
    [
        pytest.param({"f": float("nan")}, ValueError, id="nan"),
        pytest.param({"f": float("inf")}, ValueError, id="inf"),
        pytest.param({"s": {1, 2}}, TypeError, id="set"),
        pytest.param({"b": b"bytes"}, TypeError, id="bytes"),
        pytest.param(ArrayStruct(sub="sub"), TypeError, id="array-like-struct"),
    ],
)
def test_unserialisable_claims(
    claims: dict[str, object] | msgspec.Struct,
    error: type[Exception],
    hmac_jwt: ryjwt.SecretKey,
) -> None:
    with pytest.raises(error):
        hmac_jwt.encode(claims)


@pytest.mark.parametrize("claims", [{1: "one"}, [1]], ids=["non-str-key", "list"])
def test_claims_of_the_wrong_type(claims: object, hmac_jwt: ryjwt.SecretKey) -> None:
    untyped_caller: Any = claims  # what an untyped caller could pass

    with pytest.raises(TypeError):
        hmac_jwt.encode(untyped_caller)


def test_deeply_nested_claims_are_rejected(hmac_jwt: ryjwt.SecretKey) -> None:
    claims: dict[str, Any] = {}
    for _ in range(300):
        claims = {"n": claims}

    with pytest.raises(ValueError, match="nested too deeply"):
        hmac_jwt.encode(claims)


def test_header(hmac_jwt: ryjwt.SecretKey) -> None:
    token = hmac_jwt.encode({"sub": "sub"}, header={"kid": "kid", "cty": "cty"})

    assert jwt.get_unverified_header(token) == {
        "alg": "HS256",
        "typ": "JWT",
        "kid": "kid",
        "cty": "cty",
    }
    assert (
        jwt.get_unverified_header(hmac_jwt.encode({}, header={"typ": "at+jwt"}))["typ"] == "at+jwt"
    )


def test_alg_header_is_not_settable(hmac_jwt: ryjwt.SecretKey) -> None:
    with pytest.raises(ValueError, match="algorithm="):
        hmac_jwt.encode({}, header={"alg": "none"})


@pytest.mark.parametrize(
    ("header", "error", "match"),
    [
        pytest.param({"crit": ["exp"]}, ValueError, r"crit\) aren't supported", id="crit"),
        pytest.param({"b64": False}, ValueError, r"b64\) aren't supported", id="b64"),
        pytest.param({"kid": 1}, TypeError, "kid must be str, got int", id="kid-int"),
        pytest.param({"kid": None}, TypeError, "kid must be str, got NoneType", id="kid-null"),
        pytest.param({f"x{i}": i for i in range(63)}, ValueError, "more parameters", id="65"),
        pytest.param({"x": object()}, TypeError, "object", id="unserialisable"),
        pytest.param({1: "x"}, TypeError, "names must be str", id="non-str-name"),
    ],
)
def test_headers_decode_would_reject(
    header: dict[Any, Any], error: type[Exception], match: str, hmac_jwt: ryjwt.SecretKey
) -> None:
    """`encode` doesn't make tokens that `decode` rejects."""
    with pytest.raises(error, match=match):
        hmac_jwt.encode({}, header=header)


def test_largest_header_decode_takes(hmac_jwt: ryjwt.SecretKey) -> None:
    """64 parameters, with `alg` and `typ`."""
    without_typ = {f"x{i}": i for i in range(62)}
    with_typ = {**without_typ, "typ": "at+jwt"}

    for header in (without_typ, with_typ):
        assert len(ryjwt.unverified_header(hmac_jwt.encode({}, header=header))) == 64
        assert hmac_jwt.decode(hmac_jwt.encode({}, header=header)) == {}


def test_encode_leaves_its_arguments_unchanged(hmac_jwt: ryjwt.SecretKey) -> None:
    claims = {"sub": "sub", "exp": datetime(2100, 1, 1, tzinfo=UTC)}
    header = {"kid": "kid"}

    hmac_jwt.encode(claims, header=header)

    assert claims == {"sub": "sub", "exp": datetime(2100, 1, 1, tzinfo=UTC)}
    assert header == {"kid": "kid"}


def test_headers_is_not_an_argument(hmac_jwt: ryjwt.SecretKey) -> None:
    untyped_caller: Any = {"headers": {"kid": "kid"}}  # what an untyped caller could pass

    with pytest.raises(TypeError, match="headers"):
        hmac_jwt.encode({}, **untyped_caller)


def test_algorithm_choice(hmac_key: str) -> None:
    several = ryjwt.SecretKey(hmac_key, algorithms=["HS256", "HS512"])

    with pytest.raises(ValueError, match="algorithm="):
        several.encode({})
    with pytest.raises(ValueError, match="not one of the configured"):
        several.encode({}, algorithm="HS384")
    assert jwt.get_unverified_header(several.encode({}, algorithm="HS512"))["alg"] == "HS512"
