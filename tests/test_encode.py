import base64
import json
from typing import Any

import jwt
import msgspec
import pydantic
import pytest
import ryjwt


class ClaimsStruct(msgspec.Struct):
    sub: str
    exp: int


class RenamedStruct(msgspec.Struct, rename={"subject": "sub"}):
    subject: str


class ArrayStruct(msgspec.Struct, array_like=True):
    sub: str


class AliasedModel(pydantic.BaseModel):
    subject: str = pydantic.Field(alias="sub")


def _payload(token: str) -> Any:  # noqa: ANN401
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
def test_dict_claims_round_trip_as_json(claims: dict[str, Any], hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode(claims)

    assert _payload(token) == json.loads(json.dumps(claims))
    assert hmac_jwt.decode(token) == json.loads(json.dumps(claims))


def test_typed_claims(hmac_jwt: ryjwt.RYJWT) -> None:
    assert _payload(hmac_jwt.encode(ClaimsStruct(sub="sub", exp=1))) == {"sub": "sub", "exp": 1}
    assert _payload(hmac_jwt.encode(RenamedStruct(subject="sub"))) == {"sub": "sub"}
    assert _payload(hmac_jwt.encode(AliasedModel(sub="sub"))) == {"sub": "sub"}
    assert hmac_jwt.decode(
        hmac_jwt.encode(AliasedModel(sub="sub")),
        type=AliasedModel,
    ) == AliasedModel(sub="sub")


@pytest.mark.parametrize(
    ("claims", "error"),
    [
        pytest.param({"f": float("nan")}, ValueError, id="nan"),
        pytest.param({"f": float("inf")}, ValueError, id="inf"),
        pytest.param({1: "one"}, TypeError, id="non-str-key"),
        pytest.param({"s": {1, 2}}, TypeError, id="set"),
        pytest.param({"b": b"bytes"}, TypeError, id="bytes"),
        pytest.param([1], TypeError, id="list-claims"),
        pytest.param(ArrayStruct(sub="sub"), TypeError, id="array-like-struct"),
    ],
)
def test_unserialisable_claims(claims: Any, error: type[Exception], hmac_jwt: ryjwt.RYJWT) -> None:  # noqa: ANN401
    with pytest.raises(error):
        hmac_jwt.encode(claims)


def test_deeply_nested_claims_are_rejected(hmac_jwt: ryjwt.RYJWT) -> None:
    claims: dict[str, Any] = {}
    for _ in range(300):
        claims = {"n": claims}

    with pytest.raises(ValueError, match="nested too deeply"):
        hmac_jwt.encode(claims)


def test_headers(hmac_jwt: ryjwt.RYJWT) -> None:
    token = hmac_jwt.encode({"sub": "sub"}, headers={"kid": "kid", "cty": "cty"})

    assert jwt.get_unverified_header(token) == {
        "alg": "HS256",
        "typ": "JWT",
        "kid": "kid",
        "cty": "cty",
    }
    assert (
        jwt.get_unverified_header(hmac_jwt.encode({}, headers={"typ": "at+jwt"}))["typ"] == "at+jwt"
    )


def test_alg_header_is_not_settable(hmac_jwt: ryjwt.RYJWT) -> None:
    with pytest.raises(ValueError, match="algorithm="):
        hmac_jwt.encode({}, headers={"alg": "none"})


def test_algorithm_choice(hmac_key: str) -> None:
    several = ryjwt.RYJWT(hmac_key, algorithms=["HS256", "HS512"])

    with pytest.raises(ValueError, match="algorithm="):
        several.encode({})
    with pytest.raises(ValueError, match="not one of the configured"):
        several.encode({}, algorithm="HS384")
    assert jwt.get_unverified_header(several.encode({}, algorithm="HS512"))["alg"] == "HS512"
