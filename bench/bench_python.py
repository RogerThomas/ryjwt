#!yeet
"""Benchmark Python JWT decoding (PyJWT, joserfc, or ryjwt into a dict, read with msgspec or
jiter, or a msgspec Struct / pydantic model) over the fixture matrix.

Each call verifies the signature and validates exp/aud, as a real caller would. Each case gets
1,000 untimed warm-up decodes, then `rounds` rounds of `iterations` decodes, each round timed as
one loop.

Usage: `yeet ./bench_python.py [impl] [iterations] [rounds]`
"""

import base64
import hashlib
import hmac
import json
import math
import platform
import secrets
import sys
import time
from dataclasses import asdict, dataclass
from importlib.abc import MetaPathFinder
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import jwt
import msgspec
import pydantic
import ryjwt
from joserfc import jwt as joserfc_jwt
from joserfc.errors import ExpiredTokenError, InvalidClaimError
from joserfc.jwk import ECKey, KeySet, OctKey, OKPKey, RSAKey
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from importlib.machinery import ModuleSpec
    from types import ModuleType

type Impl = Literal["pyjwt", "joserfc", "ryjwt", "ryjwt-jiter", "ryjwt-msgspec", "ryjwt-pydantic"]

WARMUP = 1_000
"""Untimed decodes before each case's timed rounds."""


REJECTIONS: dict[Impl, tuple[type[Exception], type[Exception]]] = {
    "pyjwt": (jwt.ExpiredSignatureError, jwt.InvalidAudienceError),
    "joserfc": (ExpiredTokenError, InvalidClaimError),
    "ryjwt": (ryjwt.ExpiredSignatureError, ryjwt.InvalidAudienceError),
    "ryjwt-jiter": (ryjwt.ExpiredSignatureError, ryjwt.InvalidAudienceError),
    "ryjwt-msgspec": (ryjwt.ExpiredSignatureError, ryjwt.InvalidAudienceError),
    "ryjwt-pydantic": (ryjwt.ExpiredSignatureError, ryjwt.InvalidAudienceError),
}
"""What each implementation raises for an expired token, and for another audience's."""


class BaseClaimsStruct(msgspec.Struct):
    sub: str
    iss: str
    aud: str
    iat: int
    exp: int


class TypicalClaimsStruct(BaseClaimsStruct):
    nbf: int
    jti: str
    sid: str
    email: str
    name: str
    scope: str
    roles: list[str]
    amr: list[str]


class BaseClaimsModel(pydantic.BaseModel):
    sub: str
    iss: str
    aud: str
    iat: int
    exp: int


class TypicalClaimsModel(BaseClaimsModel):
    nbf: int
    jti: str
    sid: str
    email: str
    name: str
    scope: str
    roles: list[str]
    amr: list[str]


def joserfc_decode(
    token: str,
    *,
    key: OctKey | RSAKey | ECKey | OKPKey | KeySet,
    algorithms: list[str],
    claims_registry: joserfc_jwt.JWTClaimsRegistry,
) -> dict[str, Any]:
    """joserfc, as its docs show: `decode` verifies the signature (a `KeySet` picks the key by the
    token's `kid`), then the claims registry checks `exp` and `aud`."""
    decoded = joserfc_jwt.decode(token, key, algorithms=algorithms)
    claims_registry.validate(decoded.claims)
    return decoded.claims


def joserfc_claims(audience: str) -> joserfc_jwt.JWTClaimsRegistry:
    """A claims registry that requires `exp` (and checks it) and `aud`, matching `audience`."""
    return joserfc_jwt.JWTClaimsRegistry(
        exp={"essential": True}, aud={"essential": True, "value": audience}
    )


class _NoMsgspecJson(MetaPathFinder):
    """Makes `import msgspec.json` raise ImportError, as if msgspec weren't installed."""

    def find_spec(
        self,
        fullname: str,
        _path: Sequence[str] | None,
        _target: ModuleType | None = None,
        /,
    ) -> ModuleSpec | None:
        if fullname == "msgspec.json":
            raise ModuleNotFoundError("msgspec.json is blocked for ryjwt-jiter", name=fullname)
        return None


def use_jiter_for_dicts() -> None:
    """Makes ryjwt read dicts with jiter, as on a default install, though these scripts import
    msgspec. Each ryjwt key picks when created: msgspec if `import msgspec.json` succeeds, else
    jiter. msgspec imports `msgspec.json` itself, so it's dropped from `sys.modules` (else the
    import would just return it) and blocked from being imported again. Call before creating any
    ryjwt key."""
    sys.modules.pop("msgspec.json", None)
    sys.meta_path.insert(0, _NoMsgspecJson())


def _b64(data: bytes) -> str:
    """Unpadded base64url, as in JWTs."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _huge_number_token(secret: str) -> str:
    """An HS256 token, signed with `secret`, whose payload holds `1e400`: a number too big for a
    float, which jiter reads as `inf` and msgspec rejects. Built by hand, as encoders won't write
    it."""
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64(b'{"huge":1e400,"exp":4102444800}')
    signing_input = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def _decode_huge_number() -> object:
    """`_huge_number_token`'s `huge`, decoded to a dict by a fresh ryjwt key."""
    secret = secrets.token_urlsafe(32)
    key = ryjwt.SecretKey(secret, algorithms=["HS256"])
    return key.decode(_huge_number_token(secret))["huge"]


def prove_dict_parser(impl: str) -> None:
    """Fails unless ryjwt decodes dicts with jiter for `ryjwt-jiter`, and with msgspec for
    `ryjwt`, telling them apart by a number too big for a float (jiter: `inf`, msgspec: an
    error). Other implementations aren't checked."""
    if impl == "ryjwt-jiter":
        not_jiter = "ryjwt-jiter: ryjwt isn't decoding with jiter"
        try:
            huge = _decode_huge_number()
        except ryjwt.DecodeError as e:
            raise AssertionError(not_jiter) from e
        if huge != math.inf:
            raise AssertionError(not_jiter)
    elif impl == "ryjwt":
        try:
            _decode_huge_number()
        except ryjwt.DecodeError:
            return
        raise AssertionError("ryjwt: ryjwt isn't decoding with msgspec")


@dataclass(frozen=True, slots=True)
class Result:
    impl: str
    name: str
    token_len: int
    key_len: int
    iterations: int
    rounds: int
    ops_per_sec: float
    mean_us: float
    round_means_us: list[float]


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    token: str
    key: str
    alg: ryjwt.HMACAlgorithm
    audience: str
    payload: dict[str, Any]
    token_len: int
    expired_token: str
    wrong_audience_token: str


@dataclass(frozen=True, slots=True)
class Prepared:
    """A decode callable, the keyword arguments every call passes, and the expected result."""

    decode: Callable[..., Any]
    kwargs: dict[str, Any]
    expected: object


@dataclass(slots=True)
class PythonBenchmark:
    _impl: Impl
    _label: str
    _iterations: int
    _rounds: int

    def _prepare(self, case: Case) -> Prepared:
        if self._impl == "pyjwt":
            kwargs = {"key": case.key, "algorithms": [case.alg], "audience": case.audience}
            return Prepared(jwt.decode, kwargs, case.payload)
        if self._impl == "joserfc":
            kwargs = {
                "key": OctKey.import_key(case.key),
                "algorithms": [case.alg],
                "claims_registry": joserfc_claims(case.audience),
            }
            return Prepared(joserfc_decode, kwargs, case.payload)
        decode = ryjwt.SecretKey(case.key, algorithms=[case.alg]).decode
        kwargs: dict[str, Any] = {"audience": case.audience}
        typical = case.name.startswith("typical")
        if self._impl == "ryjwt-msgspec":
            struct = TypicalClaimsStruct if typical else BaseClaimsStruct
            return Prepared(
                decode,
                kwargs | {"type": struct},
                msgspec.convert(case.payload, struct),
            )
        if self._impl == "ryjwt-pydantic":
            model = TypicalClaimsModel if typical else BaseClaimsModel
            return Prepared(decode, kwargs | {"type": model}, model.model_validate(case.payload))
        return Prepared(decode, kwargs, case.payload)

    def _loop_ns(self, prepared: Prepared, token: str, iterations: int) -> int:
        """`iterations` decodes of `token`, timed as one loop."""
        decode, kwargs = prepared.decode, prepared.kwargs
        start = time.perf_counter_ns()
        for _ in range(iterations):
            decode(token, **kwargs)
        return time.perf_counter_ns() - start

    def _rejects(self, prepared: Prepared, token: str, error: type[Exception]) -> bool:
        try:
            prepared.decode(token, **prepared.kwargs)
        except error:
            return True
        return False

    def _prove_checks(self, prepared: Prepared, case: Case) -> None:
        """Fails unless the decode rejects an expired token and one for another audience."""
        expired_error, audience_error = REJECTIONS[self._impl]
        if not self._rejects(prepared, case.expired_token, expired_error):
            raise AssertionError(f"{self._impl}, {case.name}: accepted an expired token")
        if not self._rejects(prepared, case.wrong_audience_token, audience_error):
            raise AssertionError(f"{self._impl}, {case.name}: accepted another audience's token")

    def run(self, case: Case) -> Result:
        prepared = self._prepare(case)
        if prepared.decode(case.token, **prepared.kwargs) != prepared.expected:
            msg = f"{case.name}: decoded payload does not match fixture"
            raise AssertionError(msg)
        self._prove_checks(prepared, case)

        self._loop_ns(prepared, case.token, WARMUP)
        rounds_ns = [
            self._loop_ns(prepared, case.token, self._iterations) for _ in range(self._rounds)
        ]
        mean_us = sum(rounds_ns) / (self._iterations * self._rounds) / 1e3
        return Result(
            impl=self._label,
            name=case.name,
            token_len=case.token_len,
            key_len=len(case.key),
            iterations=self._iterations,
            rounds=self._rounds,
            ops_per_sec=1e6 / mean_us,
            mean_us=mean_us,
            round_means_us=[ns / self._iterations / 1e3 for ns in rounds_ns],
        )


def _load_cases(path: Path) -> list[Case]:
    return [
        Case(
            name=c["name"],
            token=c["token"],
            key=c["key"],
            alg=c["alg"],
            audience=c["audience"],
            payload=c["payload"],
            token_len=c["token_len"],
            expired_token=c["expired_token"],
            wrong_audience_token=c["wrong_audience_token"],
        )
        for c in json.loads(path.read_text())
    ]


def _label(impl: Impl) -> str:
    if not impl.startswith("ryjwt"):
        return f"{impl} {version(impl)}"
    target = {
        "ryjwt": "dict (msgspec)",
        "ryjwt-jiter": "dict (jiter)",
        "ryjwt-msgspec": "Struct",
        "ryjwt-pydantic": "BaseModel",
    }[impl]
    return f"ryjwt {version('ryjwt')} → {target}"


def round_means_range(round_means_us: list[float]) -> str:
    """The lowest and highest round mean, in µs."""
    return f"{min(round_means_us):.2f}-{max(round_means_us):.2f}"


def _print_table(console: Console, label: str, rounds: int, results: list[Result]) -> None:
    table = Table(title=f"decode — {label}")
    table.add_column("case")
    columns = ["token_len", "iterations", "rounds", "mean µs"]
    if rounds > 1:
        columns.append("round means µs")
    for col in columns:
        table.add_column(col, justify="right")
    for r in results:
        cells = [r.name, f"{r.token_len:,}", f"{r.iterations:,}", f"{r.rounds}", f"{r.mean_us:.2f}"]
        if rounds > 1:
            cells.append(round_means_range(r.round_means_us))
        table.add_row(*cells)
    console.print(table)


def main(impl: Impl = "pyjwt", iterations: int = 10_000, rounds: int = 1) -> None:
    """`iterations` decodes per round, `rounds` rounds per case."""
    if impl == "ryjwt-jiter":
        # This script imports msgspec, so ryjwt would read dicts with it; block it, before any
        # ryjwt key is created, to time a default install's jiter.
        use_jiter_for_dicts()
    prove_dict_parser(impl)
    bench_dir = Path(__file__).parent
    label = _label(impl)
    benchmark = PythonBenchmark(impl, label, iterations, rounds)

    console = Console()
    console.print(
        f"[bold]{label}[/] on {platform.python_implementation()} {platform.python_version()}"
        f" — {WARMUP:,} warm-up decodes, then {rounds} x {iterations:,} timed",
    )
    results: list[Result] = []
    for case in _load_cases(bench_dir / "fixtures.json"):
        with console.status(f"benchmarking {case.name}..."):
            results.append(benchmark.run(case))

    results_path = bench_dir / "results" / f"{impl}.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps([asdict(r) for r in results], indent=2) + "\n")
    _print_table(console, label, rounds, results)
    console.print(f"wrote {results_path}")
