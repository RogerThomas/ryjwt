"""The fuzz targets' checks. Each target (fuzz_targets/<target>.rs) passes every input libFuzzer
makes to `check(target)`, which drives ryjwt's public API with it and raises if ryjwt got it wrong:
by raising anything but its documented errors, by accepting what it must reject, or by disagreeing
with a reference (Python's json and hmac, the cryptography package, and ryjwt's own slower paths).

Here ryjwt runs on the extension module the targets are built with, instrumented for coverage and
AddressSanitizer (see src/lib.rs). The first byte of a `claims`, `jwks` or `keys` input picks its
options (its check says how); the rest is the payload, document or key. A `decode` input is all
token, and an `encode` input is read as a series of choices that build the claims to encode.
"""

import base64
import binascii
import hashlib
import hmac
import json
import math
import struct
import sys
import time
from collections.abc import Callable, Collection, Generator, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from enum import Enum
from functools import partial
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Final, NamedTuple, NoReturn, cast

import msgspec
import pydantic
import ryjwt
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from ryjwt import AsymmetricAlgorithm, HMACAlgorithm, _types
from ryjwt._ryjwt import public_key_from_fetched_jwks

ROOT: Final = Path(__file__).resolve().parent.parent

_spec = sys.modules["ryjwt._ryjwt"].__spec__
if _spec is None or _spec.origin != "built-in":
    raise RuntimeError("ryjwt._ryjwt isn't the fuzz targets' own build: run them with task fuzz")


class MismatchError(AssertionError):
    """ryjwt did something its check says is wrong: a finding."""


def expect(condition: bool, what: str, *details: object) -> None:  # noqa: FBT001 - an assertion
    if not condition:
        raise MismatchError("\n  ".join([what, *(repr(d) for d in details)]))


class Input:
    """An input read as a series of choices, each taking bytes from the front (zeros once they run
    out), so that libFuzzer's mutations steer what a check does."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def byte(self) -> int:
        if self._at >= len(self._data):
            return 0
        self._at += 1
        return self._data[self._at - 1]

    def choose[T](self, options: Sequence[T]) -> T:
        return options[self.byte() % len(options)]

    def take(self, size: int) -> bytes:
        chunk = self._data[self._at : self._at + size]
        self._at += len(chunk)
        return chunk

    def rest(self) -> bytes:
        return self.take(len(self._data))


# ---- References: what ryjwt's answers are checked against ----


class Invalid(Enum):
    """What the JSON reference makes of a document it rejects, or can't judge."""

    JSON = "not JSON"
    DEEP = "nested too deeply for Python's json to judge"


type JSON = bool | int | float | str | list[JSON] | dict[str, JSON] | None
"""A JSON value, as Python's json parses it."""


class DuplicatedObject(dict[str, JSON]):
    """A JSON object with a repeated member name, as a dict (the last value of each)."""


def _object(pairs: list[tuple[str, JSON]]) -> dict[str, JSON]:
    members = dict(pairs)
    return members if len(members) == len(pairs) else DuplicatedObject(members)


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(name)  # NaN and Infinity, which Python's json takes but JSON doesn't


def reference_json(data: bytes) -> JSON | Invalid:
    """`data` as strict JSON (UTF-8, no NaN or Infinity), parsed by Python's json."""
    try:
        parsed = json.loads(
            data.decode(), object_pairs_hook=_object, parse_constant=_reject_constant
        )
        return cast("JSON", parsed)
    except ValueError:
        return Invalid.JSON
    except RecursionError:
        return Invalid.DEEP


def _values(value: object) -> Iterator[object]:
    """`value` and every value in it, member names included."""
    yield value
    if isinstance(value, dict):
        for name, member in cast("dict[object, object]", value).items():
            yield name
            yield from _values(member)
    elif isinstance(value, list | tuple):
        for item in cast("Sequence[object]", value):
            yield from _values(item)


def _depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max(map(_depth, cast("dict[object, object]", value).values()), default=0)
    if isinstance(value, list):
        return 1 + max(map(_depth, cast("list[object]", value)), default=0)
    return 0


def _is_text(value: object) -> bool:
    """Whether `value` is a str that's valid Unicode: without lone surrogates, so it has UTF-8."""
    if not isinstance(value, str):
        return False
    try:
        value.encode()
    except UnicodeEncodeError:
        return False
    return True


def diverges(value: object) -> bool:
    """Whether JSON parsed to `value` holds what ryjwt's parsers (jiter, msgspec) may reject though
    Python's json takes it: a lone surrogate, a number too large for a float (which Python makes
    infinite), or nesting deeper than jiter's limit."""
    return _depth(value) > 190 or any(
        (isinstance(v, str) and not _is_text(v)) or (isinstance(v, float) and not math.isfinite(v))
        for v in _values(value)
    )


def _flatten(pairs: list[tuple[str, JSON]]) -> list[JSON]:
    return [item for pair in pairs for item in pair]


def diverges_json(data: bytes) -> bool:
    """`diverges`, for JSON text: for every value in it, repeated members' included (each of which
    ryjwt's parsers read, though only the last is kept)."""
    try:
        everything = json.loads(data.decode(), object_pairs_hook=_flatten)
    except (ValueError, RecursionError):
        return False
    return diverges(everything)


def same(a: object, b: object) -> bool:
    """Whether `a` and `b` are the same value, types included (unlike ==: 1 == 1.0 == True), for
    JSON values (a dict and a dict subclass alike) and for instances of a Struct or model."""
    if isinstance(a, dict) != isinstance(b, dict) or isinstance(a, list) != isinstance(b, list):
        return False
    if isinstance(a, dict):
        x, y = cast("dict[object, object]", a), cast("dict[object, object]", b)
        return x.keys() == y.keys() and all(same(x[k], y[k]) for k in x)
    if isinstance(a, list):
        x, y = cast("list[object]", a), cast("list[object]", b)
        return len(x) == len(y) and all(map(same, x, y))
    if type(a) is not type(b):
        return False
    if isinstance(a, float) and isinstance(b, float):
        return a == b and math.copysign(1, a) == math.copysign(1, b)
    return a == b


def b64decode(segment: bytes | str) -> bytes | None:
    """`segment` decoded as canonical unpadded base64url (RFC 7515 §2); None if it isn't that."""
    text = segment.encode() if isinstance(segment, str) else segment
    if b"=" in text:
        return None
    standard = text.translate(bytes.maketrans(b"-_", b"+/")) + b"=" * (-len(text) % 4)
    try:
        decoded = binascii.a2b_base64(standard, strict_mode=True)
    except binascii.Error:
        return None
    return decoded if b64encode(decoded) == text else None


def b64encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


# ---- Keys ----

HMAC_HASHES: Final = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
HMAC_ALGORITHMS: Final[tuple[HMACAlgorithm, ...]] = ("HS256", "HS384", "HS512")
ASYMMETRIC_ALGORITHMS: Final[tuple[AsymmetricAlgorithm, ...]] = (
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    "ES256", "ES256K", "ES384", "ES512", "ES521", "EdDSA",
)  # fmt: skip
SHA2: Final = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
CURVES: Final = {
    "P-256": ec.SECP256R1(),
    "secp256k1": ec.SECP256K1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}
# The bench's keys and tokens (bench/gen_fixtures.py), which the seed corpus (seeds.py) holds.
BENCH: Final = ROOT / "bench" / "matrix"
FIXTURES: Final = json.loads((BENCH / "fixtures.json").read_text())
# The 64-byte secret, which the seeds' HS256 tokens of the "k64" cases are signed with.
SECRET: Final = next(c["secret"] for c in FIXTURES["cases"] if c["key"] == "k64").encode()
JWKS: Final = {
    "keys": [
        jwk
        for name in ("rs2048", "rs3072", "es256", "es384", "es512", "ed25519")
        for jwk in json.loads((BENCH / "jwks" / f"{name}.json").read_text())["keys"]
    ]
}
AUDIENCE: Final = "ryjwt-bench"
ISSUER: Final = "https://auth.example.com"


def _private_pem(name: str) -> bytes:
    return (BENCH / "keys" / f"{name}.pem").read_bytes()


@contextmanager
def jiter_payloads() -> Generator[None, None, None]:
    """Hides msgspec from ryjwt, which then parses payloads into dicts with jiter instead."""
    saved = sys.modules["msgspec.json"]
    sys.modules["msgspec.json"] = cast("ModuleType", None)  # None: importing it fails
    try:
        yield
    finally:
        sys.modules["msgspec.json"] = saved


SECRET_KEY: Final = ryjwt.SecretKey(SECRET, algorithms=list(HMAC_ALGORITHMS))
with jiter_payloads():
    JITER_SECRET_KEY: Final = ryjwt.SecretKey(SECRET, algorithms=list(HMAC_ALGORITHMS))
JWKS_KEY: Final = ryjwt.PublicKey.from_jwks(JWKS, algorithms=list(ASYMMETRIC_ALGORITHMS))
ES256_PUBLIC_KEY: Final = ryjwt.PublicKey(FIXTURES["keys"]["es256"]["pem"], algorithms=["ES256"])
ED25519_KEY: Final = ryjwt.PrivateKey(
    _private_pem("ed25519"), algorithms=["EdDSA"], kid="ed25519-signing"
)
REFERENCE_KEYS: Final = {
    name: serialization.load_pem_private_key(_private_pem(name), None).public_key()
    for name in ("es256", "ed25519", "rs2048")
}


class Signer(NamedTuple):
    """How `encode` is checked for an algorithm: `encode`, the key's with that algorithm; the key,
    to decode with; the kid it puts in headers; and its public key by the reference (None for the
    HMAC secret)."""

    encode: Callable[..., str]
    key: ryjwt.SecretKey | ryjwt.PrivateKey
    kid: str | None
    public: PublicKeyTypes | None


def _signers() -> dict[str, Signer]:
    es256 = ryjwt.PrivateKey(_private_pem("es256"), algorithms=["ES256"], kid="es256-signing")
    rs2048 = ryjwt.PrivateKey(
        _private_pem("rs2048"), algorithms=["RS256", "PS256"], kid="rs2048-signing"
    )
    return {
        "HS256": Signer(partial(SECRET_KEY.encode, algorithm="HS256"), SECRET_KEY, None, None),
        "HS384": Signer(partial(SECRET_KEY.encode, algorithm="HS384"), SECRET_KEY, None, None),
        "HS512": Signer(partial(SECRET_KEY.encode, algorithm="HS512"), SECRET_KEY, None, None),
        "ES256": Signer(es256.encode, es256, "es256-signing", REFERENCE_KEYS["es256"]),
        "EdDSA": Signer(
            ED25519_KEY.encode, ED25519_KEY, "ed25519-signing", REFERENCE_KEYS["ed25519"]
        ),
        "RS256": Signer(
            partial(rs2048.encode, algorithm="RS256"),
            rs2048,
            "rs2048-signing",
            REFERENCE_KEYS["rs2048"],
        ),
        "PS256": Signer(
            partial(rs2048.encode, algorithm="PS256"),
            rs2048,
            "rs2048-signing",
            REFERENCE_KEYS["rs2048"],
        ),
    }


SIGNERS: Final = _signers()


def reference_public_key(jwk: Mapping[str, object]) -> PublicKeyTypes | None:
    """The public key of a JWK, by the cryptography package; None if it isn't one."""
    members = {name: b64decode(v) if isinstance(v, str) else None for name, v in jwk.items()}
    try:
        match jwk.get("kty"), jwk.get("crv"), members:
            case "RSA", _, {"n": bytes(n), "e": bytes(e)}:
                numbers = rsa.RSAPublicNumbers(int.from_bytes(e), int.from_bytes(n))
                return numbers.public_key()
            case "EC", str(crv), {"x": bytes(x), "y": bytes(y)} if crv in CURVES:
                point = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(x), int.from_bytes(y), CURVES[crv]
                )
                return point.public_key()
            case "OKP", "Ed25519", {"x": bytes(x)}:
                return ed25519.Ed25519PublicKey.from_public_bytes(x)
            case _:
                return None
    except ValueError:
        return None


def reference_verify(
    algorithm: str, key: PublicKeyTypes, signing_input: bytes, signature: bytes
) -> bool:
    """Whether `signature` is `key`'s for `algorithm`, by the cryptography package."""
    digest = SHA2.get(algorithm[-3:], hashes.SHA512())
    try:
        match algorithm[:2], key:
            case "RS", rsa.RSAPublicKey():
                key.verify(signature, signing_input, padding.PKCS1v15(), digest)
            case "PS", rsa.RSAPublicKey():
                pss = padding.PSS(padding.MGF1(digest), salt_length=digest.digest_size)
                key.verify(signature, signing_input, pss, digest)
            case "ES", ec.EllipticCurvePublicKey():
                size = (key.curve.key_size + 7) // 8
                if len(signature) != 2 * size:
                    return False
                r, s = int.from_bytes(signature[:size]), int.from_bytes(signature[size:])
                key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(digest))
            case "Ed", ed25519.Ed25519PublicKey():
                key.verify(signature, signing_input)
            case _:
                return False
    except InvalidSignature:
        return False
    return True


def reference_mac(algorithm: str, secret: bytes, signing_input: bytes) -> bytes:
    return hmac.new(secret, signing_input, HMAC_HASHES[algorithm]).digest()


# ---- Registered claims, as ryjwt documents it validates them ----


class Checks(NamedTuple):
    """A `decode`'s audience, issuer and leeway."""

    audience: str | tuple[str, ...] | None
    issuer: str | None
    leeway: float


class Clock(Enum):
    """A time claim too close to the clock to say which side of it ryjwt sees it."""

    EDGE = "on the edge"


type ClaimsVerdict = type[ryjwt.InvalidTokenError] | Clock | None

HUGE_LEEWAY: Final = 1e18  # lets every exp and nbf by, except the most extreme
_ABSENT: Final = object()


def _seconds(value: object) -> float | None:
    """A time claim's value as the float ryjwt compares (ints beyond 64 bits saturate); None if it
    isn't a number."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, int) and not -(2**63) <= value < 2**63:
        return sys.float_info.max if value > 0 else -sys.float_info.max
    return float(value)


def _near(a: float, b: float) -> bool:
    return math.isfinite(a) and math.isfinite(b) and abs(a - b) <= 10 + abs(b) * 1e-12


def _time_error(claims: Mapping[str, object], checks: Checks, now: float) -> ClaimsVerdict:
    for name, error in (
        ("exp", ryjwt.ExpiredSignatureError),
        ("nbf", ryjwt.ImmatureSignatureError),
    ):
        value = claims.get(name, _ABSENT)
        if value is _ABSENT:
            continue
        seconds = _seconds(value)
        if seconds is None:
            return ryjwt.DecodeError
        edge = now - checks.leeway if name == "exp" else now + checks.leeway
        if _near(seconds, edge):
            return Clock.EDGE
        if (seconds <= edge) if name == "exp" else (seconds > edge):
            return error
    return None


def _matches(expected: str | tuple[str, ...], value: str) -> bool:
    return value == expected if isinstance(expected, str) else value in expected


def claims_error(claims: Mapping[str, object], checks: Checks, now: float) -> ClaimsVerdict:
    """The error decoding claims parsed to `claims` must raise (exp, then nbf, aud and iss)."""
    error = _time_error(claims, checks, now)
    if error is not None:
        return error
    aud = claims.get("aud", _ABSENT)
    if aud is _ABSENT:
        if checks.audience is not None:
            return ryjwt.InvalidAudienceError
    else:
        items = cast("list[object]", aud) if isinstance(aud, list) else [aud]
        if not all(map(_is_text, items)):
            return ryjwt.InvalidAudienceError  # not a str or list of str
        expected = checks.audience
        if expected is None or not any(_matches(expected, cast("str", i)) for i in items):
            return ryjwt.InvalidAudienceError
    if checks.issuer is not None:
        iss = claims.get("iss", _ABSENT)
        if not (_is_text(iss) and _matches(checks.issuer, cast("str", iss))):
            return ryjwt.InvalidIssuerError
    return None


MAX_HEADER_PARAMETERS: Final = 64


def header_error(
    header: JSON | Invalid, algorithms: Collection[str]
) -> type[ryjwt.InvalidTokenError] | None:
    """The error a token with this header (parsed by `reference_json`) must be rejected with before
    its signature is checked, for a key without `kid`s configured for `algorithms`."""
    if not isinstance(header, dict):
        return ryjwt.DecodeError
    if isinstance(header, DuplicatedObject) or len(header) > MAX_HEADER_PARAMETERS:
        return ryjwt.DecodeError
    for name, value in header.items():
        if name == "crit":
            return ryjwt.InvalidTokenError
        if name == "alg" and not isinstance(value, str):
            return ryjwt.InvalidAlgorithmError
    if header.get("alg") not in algorithms:
        return ryjwt.InvalidAlgorithmError
    return None


# ---- Running ryjwt ----


class Outcome(NamedTuple):
    """What a call to ryjwt did: returned `value`, or raised `error`."""

    value: object
    error: Exception | None


def attempt(call: Callable[[], object], *errors: type[Exception]) -> Outcome:
    """Runs `call`, which may raise only `errors` (ryjwt's documented errors for it): anything else
    propagates, a finding."""
    try:
        return Outcome(call(), None)
    except errors as e:
        return Outcome(None, e)


def expect_error(outcome: Outcome, allowed: Collection[type[Exception]], what: str) -> None:
    expect(
        outcome.error is not None and type(outcome.error) in allowed,
        f"{what}: expected one of {sorted(e.__name__ for e in allowed)}",
        outcome,
    )


# ---- decode: tokens as they arrive, unverified ----

DECODE_CHECKS: Final = Checks(audience=AUDIENCE, issuer=None, leeway=0.0)


def _verified_by_reference(
    key: object, header: Mapping[str, object], segments: list[bytes]
) -> bool:
    """Whether a reference verifies a token `key` accepted: its signature, made with the key the
    header picks (by `kid` in the JWKS) for an algorithm that key may be used with."""
    algorithm = header.get("alg")
    signing_input = segments[0] + b"." + segments[1]
    signature = b64decode(segments[2])
    if not isinstance(algorithm, str) or signature is None:
        return False
    if key is SECRET_KEY or key is JITER_SECRET_KEY:
        return algorithm in HMAC_HASHES and hmac.compare_digest(
            signature, reference_mac(algorithm, SECRET, signing_input)
        )
    if key is JWKS_KEY:
        jwks = [k for k in JWKS["keys"] if k["kid"] == header.get("kid")]
        if len(jwks) != 1 or jwks[0].get("alg", algorithm) != algorithm:
            return False
        public = reference_public_key(jwks[0])
    else:
        public = REFERENCE_KEYS["es256" if key is ES256_PUBLIC_KEY else "ed25519"]
    allowed = cast("ryjwt.PublicKey", key).algorithms
    return (
        public is not None
        and algorithm in allowed
        and reference_verify(algorithm, public, signing_input, signature)
    )


def _check_accepted(key: object, token: bytes, claims: object) -> None:
    """Checks a token `key` decoded to `claims` is one a reference accepts too."""
    segments = token.split(b".")
    expect(len(segments) == 3, "decode accepted a token without three segments", token)
    header = reference_json(b64decode(segments[0]) or b"")
    payload = reference_json(b64decode(segments[1]) or b"")
    allowed = cast("ryjwt.PublicKey", key).algorithms
    expect(header_error(header, allowed) is None, "decode accepted a bad header", header)
    header = cast("dict[str, JSON]", header)
    expect(_verified_by_reference(key, header, segments), "decode accepted a bad signature", token)
    expect(isinstance(payload, dict), "decode accepted a payload that isn't valid", token)
    payload = cast("dict[str, JSON]", payload)
    verdict = claims_error(payload, DECODE_CHECKS, time.time())
    expect(verdict in {None, Clock.EDGE}, "decode accepted invalid claims", verdict, payload)
    expect(same(claims, payload), "decode's claims aren't the payload's", claims, payload)


def _check_unverified(token: bytes, outcome: Outcome) -> None:
    if outcome.error is not None:
        return
    header, claims = cast("tuple[object, object]", outcome.value)
    segments = token.split(b".")
    expect(len(segments) == 3, "unverified_token took a token without three segments", token)
    decoded = [b64decode(s) for s in segments]
    expect(None not in decoded, "unverified_token took a segment that isn't base64url", token)
    for segment, value in zip(decoded[:2], (header, claims), strict=True):
        parsed = reference_json(segment or b"")
        expect(
            parsed is Invalid.DEEP or (isinstance(parsed, dict) and same(value, parsed)),
            "unverified_token's result isn't the token's JSON",
            value,
            parsed,
        )
    expect(not isinstance(reference_json(decoded[0] or b""), DuplicatedObject), "duplicate header")


def check_decode(data: bytes) -> None:
    """A token, decoded by each of the keys (HMAC with msgspec and with jiter payloads, a JWKS, a
    public and a private key), as bytes and as str, and read unverified."""
    as_str = data.decode(errors="surrogateescape")
    for token in (data, as_str):
        outcome = attempt(partial(ryjwt.unverified_token, token), ryjwt.DecodeError)
        _check_unverified(data, outcome)
    with jiter_payloads():
        outcome = attempt(partial(ryjwt.unverified_token, data), ryjwt.DecodeError)
    _check_unverified(data, outcome)
    for key in (SECRET_KEY, JITER_SECRET_KEY, JWKS_KEY, ES256_PUBLIC_KEY, ED25519_KEY):
        for token in (data, as_str) if key is SECRET_KEY else (data,):
            outcome = attempt(
                partial(key.decode, token, audience=AUDIENCE), ryjwt.InvalidTokenError
            )
            if outcome.error is None:
                _check_accepted(key, data, outcome.value)


# ---- claims: payloads (and headers), signed, decoded every way ----


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


class PartialClaims(msgspec.Struct):
    """Declares `exp`, so a payload naming another registered claim is scanned."""

    exp: int
    sub: str = ""


class DatedClaims(msgspec.Struct):
    """Declares datetime claims, which `decode` rewrites as datetime strings for msgspec."""

    exp: datetime
    iat: datetime
    nbf: datetime | None = None
    sub: str = ""


class Model(pydantic.BaseModel):
    sub: str = ""
    aud: str | list[str] | None = None


class DatedModel(pydantic.BaseModel):
    """Declares datetime claims, which `decode` rewrites as isoformat strings for pydantic."""

    exp: datetime
    iat: datetime | None = None
    nbf: datetime | None = None


TYPES: Final = (Empty, Claims, ScannedClaims, PartialClaims, DatedClaims, Model, DatedModel)

CLAIMS_CHECKS: Final = (
    Checks(audience=None, issuer=None, leeway=0.0),
    Checks(audience=None, issuer=None, leeway=HUGE_LEEWAY),
    Checks(audience="a", issuer=None, leeway=HUGE_LEEWAY),
    Checks(audience=("a", "b"), issuer="i", leeway=HUGE_LEEWAY),
    Checks(audience=AUDIENCE, issuer=ISSUER, leeway=0.0),
    Checks(audience=None, issuer="i", leeway=60.0),
    Checks(audience=("",), issuer="", leeway=HUGE_LEEWAY),
    Checks(audience=(), issuer=None, leeway=HUGE_LEEWAY),
)


class Expected(NamedTuple):
    """What a decode must do: return `value` (if `accepts`), or raise one of `errors`, with
    `message` if it's given."""

    accepts: bool
    value: object = None
    errors: frozenset[type[Exception]] = frozenset()
    message: str | None = None


ANYTHING: Final = Expected(accepts=True, errors=frozenset({ryjwt.InvalidTokenError}))


def _expected_type(type_: type, payload: bytes) -> Expected:
    """What decoding a payload whose claims are valid into `type_` makes: what its slow path
    (`ryjwt._types.payload_parser`, which `decode` speeds up) makes of it."""
    try:
        return Expected(accepts=True, value=_types.payload_parser(type_)(payload))
    except (msgspec.ValidationError, pydantic.ValidationError) as e:
        explained = _types.mismatch(type_, e)
        expect(explained is not None, "ryjwt._types.mismatch can't explain", e)
        message, malformed = cast("tuple[str, bool]", explained)
        error = ryjwt.DecodeError if malformed else ryjwt.ClaimsValidationError
        return Expected(accepts=False, errors=frozenset({error}), message=message)
    except msgspec.DecodeError:  # malformed, by msgspec's lights
        return Expected(accepts=False, errors=frozenset({ryjwt.DecodeError}))


def expected_decode(
    header_bytes: bytes, payload: bytes, type_: type | None, checks: Checks, now: float
) -> Expected:
    """What decoding the signed token of `header_bytes` and `payload` must do."""
    header, parsed = reference_json(header_bytes), reference_json(payload)
    if header is Invalid.DEEP or parsed is Invalid.DEEP:
        return ANYTHING
    error = header_error(header, HMAC_ALGORITHMS)
    if error is not None:
        expected = Expected(accepts=False, errors=frozenset({error}))
    elif not isinstance(parsed, dict):
        expected = Expected(accepts=False, errors=frozenset({ryjwt.DecodeError}))
    else:
        claims = parsed
        verdict = claims_error(claims, checks, now)
        if verdict is Clock.EDGE:
            return ANYTHING
        if verdict is not None:
            expected = Expected(accepts=False, errors=frozenset({verdict}))
        elif type_ is None:
            expected = Expected(accepts=True, value=claims)
        else:
            expected = _expected_type(type_, payload)
    if diverges_json(header_bytes) or (error is None and diverges_json(payload)):
        return expected._replace(errors=expected.errors | {ryjwt.DecodeError}, message=None)
    return expected


def check_outcome(outcome: Outcome, expected: Expected, what: str) -> None:
    if outcome.error is None:
        expect(expected.accepts, f"{what} accepted", expected, outcome)
        if expected.value is not None and expected is not ANYTHING:
            match = same(outcome.value, expected.value)
            expect(match, f"{what} decoded differently", outcome.value, expected.value)
        return
    if expected is ANYTHING:
        return
    expect_error(outcome, expected.errors, f"{what} raised")
    if expected.message is not None and type(outcome.error) in expected.errors:
        expect(str(outcome.error) == expected.message, f"{what}'s message", outcome, expected)


def hmac_token(header: bytes, payload: bytes, algorithm: str) -> str:
    signing_input = b64encode(header) + b"." + b64encode(payload)
    signature = reference_mac(algorithm, SECRET, signing_input)
    return (signing_input + b"." + b64encode(signature)).decode()


def _check_claims_unverified(token: str, header_bytes: bytes, payload: bytes) -> None:
    """unverified_* checks only that the header and payload are JSON objects (and the header has
    no repeated or too many parameters)."""
    header, parsed = reference_json(header_bytes), reference_json(payload)
    for jiter in (False, True):
        with jiter_payloads() if jiter else _nothing():
            outcome = attempt(partial(ryjwt.unverified_token, token), ryjwt.DecodeError)
        if header is Invalid.DEEP or parsed is Invalid.DEEP:
            continue
        valid_header = (
            isinstance(header, dict)
            and not isinstance(header, DuplicatedObject)
            and len(header) <= MAX_HEADER_PARAMETERS
        )
        if not valid_header or not isinstance(parsed, dict):
            expect_error(outcome, {ryjwt.DecodeError}, "unverified_token raised")
            continue
        if outcome.error is not None:
            lax = diverges_json(header_bytes) or diverges_json(payload)
            expect(lax, "unverified_token rejected", outcome)
            continue
        got_header, got_claims = cast("tuple[object, object]", outcome.value)
        expect(same(got_header, header), "unverified header", got_header, header)
        expect(same(got_claims, parsed), "unverified claims", got_claims, parsed)


@contextmanager
def _nothing() -> Generator[None, None, None]:
    yield


def _same_outcome(a: Outcome, b: Outcome) -> bool:
    """Whether two decodes into Structs did the same: the same fields, or the same error."""
    if a.error is not None or b.error is not None:
        # Their messages name their own class.
        messages = [str(e).replace(" ScannedClaims:", " Claims:") for e in (a.error, b.error)]
        return type(a.error) is type(b.error) and messages[0] == messages[1]
    return msgspec.structs.asdict(cast("msgspec.Struct", a.value)) == msgspec.structs.asdict(
        cast("msgspec.Struct", b.value)
    )


def check_claims(data: bytes) -> None:
    """A payload (and with option bit 7, a header: the input's bytes up to the first NUL), signed
    with the HMAC algorithm option bits 0-1 pick (unless the header names another), and decoded by
    every path ryjwt has (a dict from msgspec or jiter, a Struct whose claims are read from it or
    scanned for, datetime claims rewritten for msgspec or pydantic) with the audience, issuer and
    leeway bits 2-4 pick; and read unverified."""
    source = Input(data)
    options = source.byte()
    algorithm: str = HMAC_ALGORITHMS[options % 4 % 3]
    checks = CLAIMS_CHECKS[options >> 2 & 7]
    if options & 0x80:
        header_bytes, _, payload = source.rest().partition(b"\0")
    else:
        header_bytes, payload = b'{"alg":"%s","typ":"JWT"}' % algorithm.encode(), source.rest()
    header = reference_json(header_bytes)
    if isinstance(header, dict):
        named = header.get("alg")
        algorithm = named if isinstance(named, str) and named in HMAC_HASHES else algorithm
    token = hmac_token(header_bytes, payload, algorithm)
    now = time.time()
    for key in (SECRET_KEY, JITER_SECRET_KEY):
        outcome = attempt(
            partial(
                key.decode,
                token,
                audience=checks.audience,
                issuer=checks.issuer,
                leeway=checks.leeway,
            ),
            ryjwt.InvalidTokenError,
        )
        expected = expected_decode(header_bytes, payload, None, checks, now)
        check_outcome(
            outcome,
            expected,
            "decode (dict, jiter)" if key is JITER_SECRET_KEY else "decode (dict)",
        )
    outcomes: dict[type, Outcome] = {}
    for type_ in TYPES:
        outcome = attempt(
            partial(
                SECRET_KEY.decode,
                token,
                into=type_,
                audience=checks.audience,
                issuer=checks.issuer,
                leeway=checks.leeway,
            ),
            ryjwt.InvalidTokenError,
        )
        check_outcome(
            outcome,
            expected_decode(header_bytes, payload, type_, checks, now),
            f"decode into {type_.__name__}",
        )
        outcomes[type_] = outcome
    # Reading the claims from the instance must validate them exactly as scanning does.
    read, scanned = outcomes[Claims], outcomes[ScannedClaims]
    expect(_same_outcome(read, scanned), "Claims and ScannedClaims disagree", read, scanned)
    _check_claims_unverified(token, header_bytes, payload)


# ---- encode: claims of every kind, encoded, then decoded back ----


class Text(str):
    """A str subclass: json_write's str-but-not-exactly path."""

    __slots__ = ()


class Number(int):
    """An int subclass whose str and repr aren't its digits, which json_write must write."""

    def __repr__(self) -> str:
        return "Number()"

    def __str__(self) -> str:
        return "Number()"


class Real(float):
    """A float subclass."""


class Opaque:
    """A value that isn't JSON."""


class Zone(tzinfo):
    """A tzinfo that isn't a `datetime.timezone`: the datetime's NumericDate is Python's."""

    def __init__(self, minutes: int) -> None:
        self._offset = timedelta(minutes=minutes)

    def utcoffset(self, dt: datetime | None) -> timedelta:  # noqa: ARG002 - fixed
        return self._offset

    def dst(self, dt: datetime | None) -> timedelta:  # noqa: ARG002 - fixed
        return timedelta(0)


class Moment(datetime):
    """A datetime subclass."""


NAMES: Final = (
    "exp", "nbf", "iat", "aud", "iss", "sub", "jti", "", "é", "\x00", '"', "\\", "\u2028",
    "\U0001f600", "\ud800", "a\udfffb", "\x7f", "\n\t\r\b\f", "\u0001",
)  # fmt: skip
EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
DATETIME_RANGE: Final = int(
    (datetime.max.replace(tzinfo=UTC) - datetime.min.replace(tzinfo=UTC)).total_seconds()
)


def make_text(source: Input) -> str:
    match source.byte() % 4:
        case 0:
            return source.choose(NAMES)
        case 1:
            count = source.byte() % 16
            return "".join(chr(int.from_bytes(source.take(3)) % 0x110000) for _ in range(count))
        case 2:
            return source.take(source.byte() % 32).decode("latin-1")
        case _:
            return source.take(source.byte() % 32).decode(errors="replace")


def make_datetime(source: Input) -> datetime:
    """A datetime anywhere in datetime's range: naive, UTC, at a fixed offset (a `timezone`, or
    another tzinfo), or a datetime subclass's."""
    moment = datetime.min.replace(tzinfo=UTC) + timedelta(
        seconds=int.from_bytes(source.take(6)) % DATETIME_RANGE,
        microseconds=int.from_bytes(source.take(3)) % 10**6,
    )
    minutes = int.from_bytes(source.take(2)) % (24 * 60 - 1) - (12 * 60 - 1)
    match source.byte() % 5:
        case 0:
            return moment.replace(tzinfo=None)
        case 1:
            return moment
        case 2:
            return moment.replace(tzinfo=timezone(timedelta(minutes=minutes)))
        case 3:
            return moment.replace(tzinfo=Zone(minutes))
        case _:
            return Moment.combine(moment.date(), moment.time(), UTC)


def make_value(source: Input, depth: int) -> object:  # noqa: C901 - one case per kind
    if depth > 300:
        return None
    match source.byte() % 20:
        case 0:
            return None
        case 1:
            return source.byte() & 1 == 1
        case 2:
            return int.from_bytes(source.take(1), signed=True)
        case 3:
            return int.from_bytes(source.take(8), signed=True)
        case 4:
            return int.from_bytes(source.take(source.byte() % 40), signed=True)
        case 5:
            return struct.unpack("<d", source.take(8).ljust(8, b"\0"))[0]
        case 6:
            return int.from_bytes(source.take(2), signed=True) / 10 ** (source.byte() % 8)
        case 7 | 8:
            return make_text(source)
        case 9:
            return Text(make_text(source))
        case 10:
            return Number(int.from_bytes(source.take(source.byte() % 12), signed=True))
        case 11:
            return Real(int.from_bytes(source.take(2), signed=True) / 7)
        case 12:
            return [make_value(source, depth + 1) for _ in range(source.byte() % 5)]
        case 13:
            return tuple(make_value(source, depth + 1) for _ in range(source.byte() % 5))
        case 14:
            return {
                make_text(source): make_value(source, depth + 1) for _ in range(source.byte() % 5)
            }
        case 15:
            return {source.choose((1, None, (), 1.5, b"k")): make_value(source, depth + 1)}
        case 16:
            nested: object = make_value(source, depth + 1)
            for _ in range(source.byte() * 2):
                nested = [nested]
            return nested
        case 17:
            return make_datetime(source)
        case 18:
            return source.choose((
                Opaque(),
                b"bytes",
                {1, 2},
                Real("nan"),
                float("inf"),
                MappingProxyType[str, object]({}),
            ))
        case _:
            return source.choose(([], {}, "", 0, -0.0, 2**63, -(2**63) - 1, 2**64, 1e308, 5e-324))


class NotJSONError(Exception):
    """Why the reference can't serialise a value: what ryjwt must raise."""

    def __init__(self, error: type[Exception], why: str) -> None:
        super().__init__(why)
        self.error = error


def to_json(value: object, depth: int, claim: str | None = None) -> object:  # noqa: C901 - one case per rule
    """`value` as the JSON value ryjwt's encoder must write for it (as a top-level claim named
    `claim`), or NotJSONError with the error it must raise: json_write's rules, written plainly."""
    if depth > 255:
        raise NotJSONError(ValueError, "nested too deeply")
    if isinstance(value, str):
        if not _is_text(value):
            raise NotJSONError(ValueError, "lone surrogate")
        return str(value)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise NotJSONError(ValueError, "not finite")
        return float(value)
    if isinstance(value, dict):
        members: dict[str, object] = {}
        for name, member in cast("dict[object, object]", value).items():
            if not isinstance(name, str):
                raise NotJSONError(TypeError, "member name isn't a str")
            if not _is_text(name):
                raise NotJSONError(ValueError, "lone surrogate")
            members[str(name)] = to_json(member, depth + 1)
        return members
    if isinstance(value, list | tuple):
        return [to_json(item, depth + 1) for item in cast("Sequence[object]", value)]
    if claim in {"exp", "nbf", "iat"} and isinstance(value, datetime):
        if value.utcoffset() is None:
            raise NotJSONError(ValueError, "naive datetime")
        return (value - EPOCH) // timedelta(seconds=1)
    raise NotJSONError(TypeError, "not JSON")


def claims_json(claims: dict[str, object]) -> dict[str, object]:
    members: dict[str, object] = {}
    for name, value in claims.items():
        if not _is_text(name):
            raise NotJSONError(ValueError, "lone surrogate")
        members[name] = to_json(value, 1, name)
    return members


def header_json(
    algorithm: str, kid: str | None, extra: Mapping[object, object]
) -> dict[str, object]:
    header: dict[str, object] = {"alg": algorithm}
    if kid is not None:
        header["kid"] = kid
    for name, value in extra.items():
        if not isinstance(name, str):
            raise NotJSONError(TypeError, "header name isn't a str")
        if not _is_text(name):
            raise NotJSONError(ValueError, "lone surrogate")
        if name in {"alg", "crit", "b64"} or (name == "kid" and kid is not None):
            raise NotJSONError(ValueError, f"header {name}")
        if name == "kid" and not isinstance(value, str):
            raise NotJSONError(TypeError, "header kid isn't a str")
        header[name] = to_json(value, 1)
    header.setdefault("typ", "JWT")
    if len(extra) + 1 + (kid is not None) + ("typ" not in extra) > MAX_HEADER_PARAMETERS:
        raise NotJSONError(ValueError, "too many header parameters")
    return header


# HMAC most often (it's quickest), RSA least (its signing is slowest).
ENCODE_ALGORITHMS: Final = (
    *HMAC_ALGORITHMS,
    *HMAC_ALGORITHMS,
    "ES256",
    "ES256",
    "EdDSA",
    "RS256",
    "PS256",
)


def _check_signature(
    signer: Signer, algorithm: str, signing_input: bytes, signature: bytes
) -> None:
    if signer.public is None:
        valid = hmac.compare_digest(signature, reference_mac(algorithm, SECRET, signing_input))
    else:
        valid = reference_verify(algorithm, signer.public, signing_input, signature)
    expect(valid, "encode's signature doesn't verify", algorithm, signing_input, signature)


def _audience(claims: Mapping[str, object]) -> str | None:
    aud = claims.get("aud")
    if isinstance(aud, list) and aud:
        aud = cast("list[object]", aud)[0]
    return aud if isinstance(aud, str) else None


def check_encode(data: bytes) -> None:
    """Claims (and header parameters) built from the input, of every kind json_write handles or
    must refuse, encoded with an algorithm it picks; then checked against a reference serialisation,
    and decoded back."""
    source = Input(data)
    algorithm = source.choose(ENCODE_ALGORITHMS)
    count = source.byte()
    claims = {
        (source.choose(NAMES) if source.byte() & 1 else make_text(source)): make_value(source, 1)
        for _ in range(count % 8)
    }
    count = source.byte()
    extra: dict[object, object] = {
        (make_text(source) if source.byte() % 8 else 1): make_value(source, 1)
        for _ in range(count % 4 if count < 250 else 60)
    }
    signer = SIGNERS[algorithm]
    try:
        expected_claims = claims_json(claims)
        expected_header = header_json(algorithm, signer.kid, extra)
    except NotJSONError as e:
        outcome = attempt(partial(signer.encode, claims, header=extra), TypeError, ValueError)
        expect(
            isinstance(outcome.error, e.error),
            f"encode should raise {e.error.__name__}: {e}",
            outcome,
        )
        return
    header = extra if source.byte() & 1 else MappingProxyType(extra)
    token = signer.encode(claims, header=header if extra else None)
    expect(token.isascii(), "encode made a token that isn't ASCII", token)
    segments = token.encode().split(b".")
    expect(len(segments) == 3, "encode made a token without three segments", token)
    decoded = [b64decode(s) for s in segments]
    expect(None not in decoded, "encode made a segment that isn't base64url", token)
    header_bytes, payload, signature = cast("list[bytes]", decoded)
    expect(
        same(reference_json(header_bytes), expected_header),
        "encode's header",
        header_bytes,
        expected_header,
    )
    expect(
        same(reference_json(payload), expected_claims), "encode's claims", payload, expected_claims
    )
    _check_signature(signer, algorithm, segments[0] + b"." + segments[1], signature)
    _check_decodes(signer.key, token, expected_header, expected_claims)


def _check_decodes(
    key: ryjwt.SecretKey | ryjwt.PrivateKey,
    token: str,
    header: dict[str, object],
    claims: dict[str, object],
) -> None:
    """Checks `key` decodes the token it encoded as `header` and `claims`, unless the claims are
    invalid, and that unverified_claims reads the claims."""
    checks = Checks(audience=_audience(claims), issuer=None, leeway=HUGE_LEEWAY)
    outcome = attempt(
        partial(key.decode, token, audience=checks.audience, leeway=checks.leeway),
        ryjwt.InvalidTokenError,
    )
    verdict = claims_error(claims, checks, time.time())
    if verdict is Clock.EDGE:
        return
    expected = (
        Expected(accepts=True, value=claims)
        if verdict is None
        else Expected(accepts=False, errors=frozenset({verdict}))
    )
    # encode writes values nested up to json_write's MAX_DEPTH (255) deep, but decode parses the
    # header with jiter, which stops at 200: such a token doesn't decode (a known divergence).
    if diverges(header):
        expected = expected._replace(errors=expected.errors | {ryjwt.DecodeError})
    check_outcome(outcome, expected, "decode of what encode made")
    unverified = attempt(partial(ryjwt.unverified_claims, token), ryjwt.DecodeError)
    if not (diverges(header) and unverified.error is not None):
        expect(same(unverified.value, claims), "unverified_claims of encode's token", unverified)


# ---- jwks: JWKS documents ----

PRIVATE_MEMBERS: Final = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
JWKS_ALGORITHMS: Final[tuple[tuple[AsymmetricAlgorithm, ...], ...]] = (
    ASYMMETRIC_ALGORITHMS,
    ("RS256",),
    ("ES256", "ES384"),
    ("EdDSA",),
    ("PS512", "ES512", "ES256K"),
    ("RS384", "PS256", "ES521", "EdDSA"),
    ("ES256K",),
    ("PS384",),
)
# Tokens the bench's private keys signed, which a JWKS holding their public keys verifies.
SIGNED_TOKENS: Final = [
    case["token"]
    for case in FIXTURES["cases"]
    if case["alg"] not in HMAC_HASHES and case["payload_size"] == "small"
]


def _material(jwk: Mapping[str, object]) -> tuple[object, ...]:
    """A JWK's type and key material, decoded (RSA's numbers without leading zeros)."""
    members = {name: b64decode(v) if isinstance(v, str) else None for name, v in jwk.items()}
    if jwk.get("kty") == "RSA":
        n, e = members.get("n"), members.get("e")
        return ("RSA", n and int.from_bytes(n), e and int.from_bytes(e))
    if jwk.get("kty") == "OKP":
        return ("OKP", jwk.get("crv"), members.get("x"))
    return (jwk.get("kty"), jwk.get("crv"), members.get("x"), members.get("y"))


def _given(jwks: Mapping[str, object]) -> list[dict[str, object]]:
    """The keys of a JWKS (parsed): its "keys" items that are objects."""
    keys = jwks.get("keys")
    items = cast("list[object]", keys) if isinstance(keys, list) else []
    return [cast("dict[str, object]", k) for k in items if isinstance(k, dict)]


def exported(key: ryjwt.PublicKey) -> list[dict[str, object]] | None:
    """The JWKs `key` exports; None if it can't (it holds several keys, not all with a kid)."""
    outcome = attempt(partial(ryjwt.jwks, [key]), ValueError)
    if outcome.error is not None:
        expect("kid" in str(outcome.error), "jwks() refused", outcome)
        return None
    return cast("dict[str, list[dict[str, object]]]", outcome.value)["keys"]


def _check_exported(
    jwks: Mapping[str, object], key: ryjwt.PublicKey, algorithms: Sequence[AsymmetricAlgorithm]
) -> None:
    """Checks the keys `key` took from `jwks` are keys in it (same material and kid), valid by the
    cryptography package, and that their export takes back as they were."""
    jwk_set = exported(key)
    if jwk_set is None:
        return
    given = _given(jwks)
    for jwk in jwk_set:
        expect(
            any(_material(k) == _material(jwk) and k.get("kid") == jwk.get("kid") for k in given),
            "from_jwks took a key the JWKS doesn't hold",
            jwk,
        )
        public = reference_public_key(jwk)
        expect(public is not None, "from_jwks took a key the reference rejects", jwk)
        if isinstance(public, rsa.RSAPublicKey):
            expect(2048 <= public.key_size <= 8192, "from_jwks took an RSA key's wrong size", jwk)
    again = ryjwt.PublicKey.from_jwks({"keys": jwk_set}, algorithms=list(algorithms))
    expect(exported(again) == jwk_set, "a JWKS from_jwks exported doesn't take back the same")


def _verifies(jwk: Mapping[str, object], header: Mapping[str, object], token: bytes) -> bool:
    """Whether the reference verifies `token` (with `header`) with `jwk`, for an algorithm it may
    be used with."""
    segments = token.split(b".")
    algorithm, public = header.get("alg"), reference_public_key(jwk)
    return (
        isinstance(algorithm, str)
        and jwk.get("alg", algorithm) == algorithm
        and public is not None
        and reference_verify(
            algorithm, public, segments[0] + b"." + segments[1], b64decode(segments[2]) or b""
        )
    )


def _check_signed_tokens(jwks: Mapping[str, object], key: ryjwt.PublicKey) -> None:
    """Checks `key` verifies the bench's tokens only if a reference does with a key in `jwks` the
    token's kid could pick (one with that kid, or any key if either has no kid)."""
    for token in SIGNED_TOKENS:
        outcome = attempt(partial(key.decode, token, audience=AUDIENCE), ryjwt.InvalidTokenError)
        if outcome.error is not None:
            continue
        header = cast("dict[str, object]", reference_json(b64decode(token.split(".")[0]) or b""))
        kid = header.get("kid")
        candidates = [k for k in _given(jwks) if kid is None or k.get("kid", kid) == kid]
        expect(
            any(_verifies(k, header, token.encode()) for k in candidates),
            "a JWKS key verified a token the reference doesn't",
            token,
        )


def _check_jwks_taken(
    jwks: object, key: ryjwt.PublicKey, algorithms: Sequence[AsymmetricAlgorithm]
) -> None:
    """Checks a JWKS (parsed) from_jwks took holds no private key material, and the keys it took."""
    expect(isinstance(jwks, dict), "from_jwks took a JWKS that isn't an object", jwks)
    members = cast("dict[str, object]", jwks)
    expect(isinstance(members.get("keys"), list), "from_jwks took a JWKS without keys", jwks)
    for jwk in _given(members):
        leaked = [m for m in PRIVATE_MEMBERS if m in jwk]
        expect(not leaked, "from_jwks took a JWKS holding private key material", jwk)
    _check_exported(members, key, algorithms)
    _check_signed_tokens(members, key)


def _jwks_document(form: int, document: bytes) -> tuple[object, JSON | Invalid]:
    """The document as given to from_jwks (bytes, str, a dict or another Mapping), and parsed."""
    parsed = reference_json(document)
    match form:
        case 1:
            return document.decode(errors="surrogateescape"), parsed
        case 2 if isinstance(parsed, dict):
            return parsed, parsed
        case 3 if isinstance(parsed, dict):
            return MappingProxyType(parsed), parsed
        case _:
            return document, parsed


def _same_uses(jwks: object) -> bool:
    """Whether every key of a JWKS (parsed) has a `use` both readings treat alike."""
    keys = _given(cast("dict[str, object]", jwks)) if isinstance(jwks, dict) else []
    return all(k.get("use", "sig") in {"sig", "enc"} for k in keys)


def check_jwks(data: bytes) -> None:
    """A JWKS document taken by PublicKey.from_jwks and by the JWKS client's lenient reading, as
    bytes, str, a dict or another Mapping (option bits 0-1), for the algorithms bits 3-5 pick. A
    document either takes must hold no private key material, hold the keys taken, and export them
    as they were; the bench's tokens must verify with them only as a reference says they do; and
    SecretKey must refuse it as a secret."""
    source = Input(data)
    options = source.byte()
    algorithms = JWKS_ALGORITHMS[options >> 3 & 7]
    document, parsed = _jwks_document(options & 3, source.rest())
    as_text = isinstance(document, bytes | str)
    outcomes = [
        attempt(
            partial(read, document, algorithms=list(algorithms)), ryjwt.InvalidKeyError, ValueError
        )
        for read in (ryjwt.PublicKey.from_jwks, public_key_from_fetched_jwks)
    ]
    for outcome in outcomes:
        if isinstance(outcome.error, ryjwt.InvalidKeyError):
            continue
        if outcome.error is not None:  # a Mapping json_write can't write
            expect(not as_text and diverges(parsed), "from_jwks raised", outcome)
            continue
        expect(
            not (as_text and isinstance(parsed, DuplicatedObject)),
            "from_jwks took a JWKS with a repeated member",
        )
        _check_jwks_taken(parsed, cast("ryjwt.PublicKey", outcome.value), algorithms)
    strict, lenient = outcomes
    if strict.error is None and lenient.error is None:
        strict_keys = exported(cast("ryjwt.PublicKey", strict.value))
        lenient_keys = exported(cast("ryjwt.PublicKey", lenient.value))
        if strict_keys is not None and lenient_keys is not None:
            expect(all(k in strict_keys for k in lenient_keys), "the readings took other keys")
    if strict.error is None and _same_uses(parsed):
        expect(lenient.error is None, "the lenient reading refused what from_jwks took", lenient)
    if as_text and (strict.error is None or lenient.error is None):
        secret = attempt(
            partial(ryjwt.SecretKey, document, algorithms=["HS256"], allow_short_secret=True),
            ryjwt.InvalidKeyError,
        )
        expect(secret.error is not None, "SecretKey took a JWKS as a secret", document)


# ---- keys: PEMs, secrets and whatever else people pass ----

FAMILIES: Final[tuple[tuple[AsymmetricAlgorithm, ...], ...]] = (
    ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"),
    ("ES256",),
    ("ES256K",),
    ("ES384",),
    ("ES512", "ES521"),
    ("EdDSA",),
)


def _reference_jwk_key(jwk: Mapping[str, object]) -> PublicKeyTypes:
    public = reference_public_key(jwk)
    expect(public is not None, "a key's JWK isn't a key by the reference", jwk)
    return cast("PublicKeyTypes", public)


def _check_private(
    key: ryjwt.PrivateKey, algorithm: AsymmetricAlgorithm, material: bytes | str
) -> None:
    """Checks a private key ryjwt took signs tokens it verifies, its JWK verifies, and the
    reference verifies with that JWK; and its public key is the reference's, if it reads it."""
    token = key.encode({"sub": "fuzz"}, algorithm=algorithm)
    expect(key.decode(token) == {"sub": "fuzz"}, "a PrivateKey doesn't verify its own token")
    jwk = key.jwk()
    public = ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=[algorithm])
    expect(public.decode(token) == {"sub": "fuzz"}, "a PrivateKey's JWK doesn't verify its token")
    segments = token.encode().split(b".")
    signature = b64decode(segments[2]) or b""
    reference = _reference_jwk_key(jwk)
    verified = reference_verify(algorithm, reference, segments[0] + b"." + segments[1], signature)
    expect(verified, "the reference doesn't verify a PrivateKey's token with its JWK", token, jwk)
    pem = material.encode(errors="surrogateescape") if isinstance(material, str) else material
    try:
        loaded = serialization.load_pem_private_key(pem, None).public_key()
    except (ValueError, TypeError, UnsupportedAlgorithm):  # the reference can't read it
        return
    expect(_same_key(loaded, reference), "PrivateKey's public key isn't the reference's", jwk)


def _same_key(a: PublicKeyTypes, b: PublicKeyTypes) -> bool:
    der = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    return a.public_bytes(*der) == b.public_bytes(*der)


def _check_public(
    key: ryjwt.PublicKey, family: Sequence[AsymmetricAlgorithm], material: bytes | str
) -> None:
    jwk = key.jwk()
    again = ryjwt.PublicKey.from_jwks({"keys": [jwk]}, algorithms=list(family))
    expect(again.jwk() == jwk, "a PublicKey's JWK doesn't take back the same", jwk)
    reference = _reference_jwk_key(jwk)
    pem = material.encode(errors="surrogateescape") if isinstance(material, str) else material
    try:
        loaded = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError, UnsupportedAlgorithm):  # the reference can't read it
        return
    expect(_same_key(loaded, reference), "PublicKey's key isn't the reference's", jwk)


def _check_secret(key: ryjwt.SecretKey, secret: bytes) -> None:
    for algorithm in key.algorithms:
        token = key.encode({"sub": "fuzz"}, algorithm=algorithm).encode()
        signing_input, _, signature = token.rpartition(b".")
        expected = reference_mac(algorithm, secret, signing_input)
        expect(b64decode(signature) == expected, "SecretKey's MAC isn't the reference's", algorithm)
        expect(key.decode(token) == {"sub": "fuzz"}, "SecretKey doesn't verify its own token")


def check_keys(data: bytes) -> None:
    """Key material given to SecretKey, PrivateKey and PublicKey (for each family of algorithms),
    as bytes or (with option bit 0) str, with a kid (bit 1), for HMAC with a short secret allowed
    (bit 2). A key taken must work, and match the reference's reading of it; a public or private
    key taken must not be taken as an HMAC secret."""
    source = Input(data)
    options = source.byte()
    raw = source.rest()
    material: bytes | str = raw.decode(errors="surrogateescape") if options & 1 else raw
    kid = "fuzz-kid" if options & 2 else None
    secret = attempt(
        partial(
            ryjwt.SecretKey,
            material,
            algorithms=list(HMAC_ALGORITHMS),
            allow_short_secret=bool(options & 4),
        ),
        ryjwt.InvalidKeyError,
    )
    if secret.error is None:
        _check_secret(
            cast("ryjwt.SecretKey", secret.value),
            material.encode() if isinstance(material, str) else material,
        )
    for family in FAMILIES:
        private = attempt(
            partial(ryjwt.PrivateKey, material, algorithms=list(family), kid=kid),
            ryjwt.InvalidKeyError,
        )
        public = attempt(
            partial(ryjwt.PublicKey, material, algorithms=list(family), kid=kid),
            ryjwt.InvalidKeyError,
        )
        if private.error is None:
            algorithm = family[len(raw) % len(family)]
            _check_private(cast("ryjwt.PrivateKey", private.value), algorithm, material)
        if public.error is None:
            _check_public(cast("ryjwt.PublicKey", public.value), family, material)
        if private.error is None or public.error is None:
            expect(secret.error is not None, "SecretKey took an asymmetric key as a secret", family)


TARGETS: Final[Mapping[str, Callable[[bytes], None]]] = {
    "decode": check_decode,
    "claims": check_claims,
    "encode": check_encode,
    "jwks": check_jwks,
    "keys": check_keys,
}


def check(target: str) -> Callable[[bytes], None]:
    """The check `target` runs on each input."""
    return TARGETS[target]
