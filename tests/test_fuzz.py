"""Randomised inputs: decoding must only ever succeed correctly or raise ryjwt's own errors."""

import contextlib
import json
import random
from collections.abc import Callable
from typing import NoReturn, TypeGuard

import msgspec
import pytest
import ryjwt


class Empty(msgspec.Struct):
    pass


class Claims(msgspec.Struct):
    """Declares every registered claim, so they're read from the decoded instance."""

    exp: int
    nbf: int
    aud: str | list[str]
    iss: str


class ScannedClaims(Claims):
    """`Claims`, but having a `__post_init__` makes `decode` scan the payload for the claims."""

    def __post_init__(self) -> None:
        pass


def _mutate(data: bytes, rng: random.Random) -> bytes:
    alphabet = b'{}[]",:0123456789.eE+-\\u ntrufalsNI\x00\x7f\xff\xc3\xa9'
    out = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        i = rng.randrange(len(out) + 1)
        match rng.randrange(3):
            case 0 if out:
                del out[min(i, len(out) - 1)]
            case 1:
                out.insert(i, rng.choice(alphabet))
            case _ if out:
                out[min(i, len(out) - 1)] = rng.choice(alphabet)
            case _:
                pass
    return bytes(out)


def _is_json_object(value: object) -> TypeGuard[dict[str, object]]:
    """Whether `value`, parsed by `json.loads`, is an object (whose keys are always str)."""
    return isinstance(value, dict)


def _reject_constant(name: str) -> NoReturn:
    """Rejects `NaN`, `Infinity` and `-Infinity`, which `json` accepts but JSON doesn't."""
    raise ValueError(name)


def _reference(payload: bytes) -> object | None:
    """What a strict JSON object parser makes of `payload`, or None if it's invalid."""
    try:
        parsed = json.loads(payload, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return None
    return parsed if _is_json_object(parsed) else None


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            b'{"sub":"s","n":-1.5e3,"l":[true,false,null],"o":{"k":"\\u00e9"},'
            b'"x":"\\ud83d\\ude00"}',
            id="escapes",
        ),
        pytest.param(
            b'{"sub":"s","n":-1.5e3,"l":[true,false,null],"o":{"k":"\xc3\xa9"}}',
            id="plain",
        ),
    ],
)
def test_fuzzed_payloads(
    payload: bytes,
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    rng = random.Random(0)
    outcomes: set[bool] = set()
    for _ in range(5000):
        mutated = _mutate(payload, rng)
        token = raw_hs256_token(b'{"alg":"HS256"}', mutated)
        expected = _reference(mutated)
        try:
            as_dict = hmac_jwt.decode(token)
        except ryjwt.InvalidTokenError:
            as_dict = None
        try:
            as_struct = hmac_jwt.decode(token, type=Empty)
        except ryjwt.InvalidTokenError:
            as_struct = None
        # ryjwt may be stricter than json.loads (e.g. lone surrogates), never looser.
        assert as_dict is None or as_dict == expected, mutated
        assert (as_dict is None) == (as_struct is None), mutated
        outcomes.add(as_dict is None)
    assert outcomes == {True, False}


def _outcome(hmac_jwt: ryjwt.SecretKey, token: str, type_: type[Claims]) -> object:
    """The decoded claims, or the type of the error decoding raised."""
    try:
        return msgspec.structs.asdict(hmac_jwt.decode(token, type=type_, audience="a", issuer="i"))
    except ryjwt.RYJWTError as e:
        return type(e)


def test_fuzzed_claims(
    hmac_jwt: ryjwt.SecretKey,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    """Reading the claims from a decoded Struct must validate them exactly as scanning does."""
    rng = random.Random(2)
    payload = (
        b'{"exp":4102444800,"nbf":1000000000,"aud":["a","b"],"iss":"i",'
        b'"l":[true,false,null,-1.5e3],"o":{"exp":1,"k":"\xc3\xa9"}}'
    )
    outcomes: list[object] = []
    for _ in range(20000):
        mutated = _mutate(payload, rng)
        token = raw_hs256_token(b'{"alg":"HS256"}', mutated)
        outcome = _outcome(hmac_jwt, token, Claims)
        assert outcome == _outcome(hmac_jwt, token, ScannedClaims), mutated
        outcomes.append(outcome)
    decoded = sum(isinstance(o, dict) for o in outcomes)
    assert decoded > 1000
    assert len({o for o in outcomes if isinstance(o, type)}) > 4


def test_fuzzed_tokens(hmac_jwt: ryjwt.SecretKey) -> None:
    rng = random.Random(1)
    token = hmac_jwt.encode({"sub": "sub", "aud": "aud"})
    for _ in range(5000):
        chars = list(token)
        chars[rng.randrange(len(chars))] = rng.choice("ABCabc019-_.=+/ é")
        with contextlib.suppress(ryjwt.InvalidTokenError):
            hmac_jwt.decode("".join(chars), audience="aud")
