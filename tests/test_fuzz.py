"""Randomised inputs: decoding must only ever succeed correctly or raise ryjwt's own errors."""

import contextlib
import json
import random
from typing import TYPE_CHECKING, cast

import msgspec
import ryjwt

if TYPE_CHECKING:
    from collections.abc import Callable


class Empty(msgspec.Struct):
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


def _reference(payload: bytes) -> object | None:
    """What a strict JSON object parser makes of `payload`, or None if it's invalid."""
    try:
        parsed = json.loads(payload, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except ValueError, RecursionError:
        return None
    return cast("dict[str, object]", parsed) if isinstance(parsed, dict) else None


def test_fuzzed_payloads(
    hmac_jwt: ryjwt.RYJWT,
    raw_hs256_token: Callable[[bytes, bytes], str],
) -> None:
    rng = random.Random(0)
    payload = (
        b'{"sub":"s","n":-1.5e3,"l":[true,false,null],"o":{"k":"\\u00e9"},"x":"\\ud83d\\ude00"}'
    )
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


def test_fuzzed_tokens(hmac_jwt: ryjwt.RYJWT) -> None:
    rng = random.Random(1)
    token = hmac_jwt.encode({"sub": "sub", "aud": "aud"})
    for _ in range(5000):
        chars = list(token)
        chars[rng.randrange(len(chars))] = rng.choice("ABCabc019-_.=+/ é")
        with contextlib.suppress(ryjwt.InvalidTokenError):
            hmac_jwt.decode("".join(chars), audience="aud")
