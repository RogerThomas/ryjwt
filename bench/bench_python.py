#!yeet
"""Benchmark Python JWT decoding (PyJWT, python-jose, joserfc, jwcrypto, or ryjwt into a dict /
msgspec Struct / pydantic model) over the fixture matrix.

Each call verifies the signature and validates exp/aud, as a real caller would.
"""

import json
import platform
import statistics
import time
from dataclasses import asdict, dataclass
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import jwt
import msgspec
import pydantic
import ryjwt
from jose import jwk as jose_jwk
from jose import jwt as jose_jwt
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import ECKey, KeySet, OctKey, OKPKey, RSAKey
from jwcrypto import jwk as jwcrypto_jwk
from jwcrypto import jwt as jwcrypto_jwt
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable

type Impl = Literal[
    "pyjwt", "python-jose", "joserfc", "jwcrypto", "ryjwt", "ryjwt-msgspec", "ryjwt-pydantic"
]


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


def jwcrypto_decode(
    token: str,
    *,
    key: jwcrypto_jwk.JWK | jwcrypto_jwk.JWKSet,
    algs: list[str],
    check_claims: dict[str, str | None],
) -> dict[str, Any]:
    """jwcrypto: `JWT(jwt=..., key=...)` verifies the signature (a `JWKSet` picks the key by the
    token's `kid`) and checks the claims (`exp` always, when present; `"exp": None` requires it);
    its claims are the payload's JSON."""
    verified = jwcrypto_jwt.JWT(jwt=token, key=key, algs=algs, check_claims=check_claims)
    return json.loads(verified.claims)


@dataclass(frozen=True, slots=True)
class Result:
    impl: str
    name: str
    token_len: int
    key_len: int
    ops_per_sec: float
    mean_us: float
    p50_us: float
    p99_us: float


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    token: str
    key: str
    alg: ryjwt.HMACAlgorithm
    audience: str
    payload: dict[str, Any]
    token_len: int


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
    _warmup: int
    _repeats: int
    _samples: int

    def _prepare(self, case: Case) -> Prepared:
        if self._impl == "pyjwt":
            kwargs = {"key": case.key, "algorithms": [case.alg], "audience": case.audience}
            return Prepared(jwt.decode, kwargs, case.payload)
        if self._impl == "python-jose":
            key = jose_jwk.construct(case.key, case.alg)
            kwargs = {"key": key, "algorithms": [case.alg], "audience": case.audience}
            return Prepared(jose_jwt.decode, kwargs, case.payload)
        if self._impl == "joserfc":
            kwargs = {
                "key": OctKey.import_key(case.key),
                "algorithms": [case.alg],
                "claims_registry": joserfc_claims(case.audience),
            }
            return Prepared(joserfc_decode, kwargs, case.payload)
        if self._impl == "jwcrypto":
            kwargs = {
                "key": jwcrypto_jwk.JWK.from_password(case.key),
                "algs": [case.alg],
                "check_claims": {"exp": None, "aud": case.audience},
            }
            return Prepared(jwcrypto_decode, kwargs, case.payload)
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

    def _batch_ns(self, prepared: Prepared, token: str, iterations: int) -> int:
        decode, kwargs = prepared.decode, prepared.kwargs
        start = time.perf_counter_ns()
        for _ in range(iterations):
            decode(token, **kwargs)
        return time.perf_counter_ns() - start

    def _samples_ns(self, prepared: Prepared, token: str) -> list[int]:
        decode, kwargs, clock = prepared.decode, prepared.kwargs, time.perf_counter_ns
        samples: list[int] = []
        for _ in range(self._samples):
            t0 = clock()
            decode(token, **kwargs)
            samples.append(clock() - t0)
        return samples

    def run(self, case: Case) -> Result:
        prepared = self._prepare(case)
        if prepared.decode(case.token, **prepared.kwargs) != prepared.expected:
            msg = f"{case.name}: decoded payload does not match fixture"
            raise AssertionError(msg)

        self._batch_ns(prepared, case.token, self._warmup)
        best_ns = min(
            self._batch_ns(prepared, case.token, self._iterations) for _ in range(self._repeats)
        )
        per_call = sorted(self._samples_ns(prepared, case.token))
        mean_ns = best_ns / self._iterations
        return Result(
            impl=self._label,
            name=case.name,
            token_len=case.token_len,
            key_len=len(case.key),
            ops_per_sec=1e9 / mean_ns,
            mean_us=mean_ns / 1e3,
            p50_us=statistics.median(per_call) / 1e3,
            p99_us=statistics.quantiles(per_call, n=100, method="inclusive")[98] / 1e3,
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
        )
        for c in json.loads(path.read_text())
    ]


def _label(impl: Impl) -> str:
    if not impl.startswith("ryjwt"):
        return f"{impl} {version(impl)}"
    target = {"ryjwt": "dict", "ryjwt-msgspec": "Struct", "ryjwt-pydantic": "BaseModel"}[impl]
    return f"ryjwt {version('ryjwt')} → {target}"


def _print_table(console: Console, label: str, results: list[Result]) -> None:
    table = Table(title=f"decode — {label}")
    table.add_column("case")
    for col in ("token_len", "key_len", "ops/s", "mean µs", "p50 µs", "p99 µs"):
        table.add_column(col, justify="right")
    for r in results:
        table.add_row(
            r.name,
            f"{r.token_len:,}",
            f"{r.key_len:,}",
            f"{r.ops_per_sec:,.0f}",
            f"{r.mean_us:.2f}",
            f"{r.p50_us:.2f}",
            f"{r.p99_us:.2f}",
        )
    console.print(table)


def main(
    impl: Impl = "pyjwt",
    iterations: int = 20_000,
    warmup: int = 1_000,
    repeats: int = 5,
    samples: int = 5_000,
) -> None:
    bench_dir = Path(__file__).parent
    label = _label(impl)
    benchmark = PythonBenchmark(impl, label, iterations, warmup, repeats, samples)

    console = Console()
    console.print(
        f"[bold]{label}[/] on {platform.python_implementation()} {platform.python_version()}"
        f" — {iterations:,} iters x {repeats} repeats (best), {samples:,} timed samples",
    )
    results: list[Result] = []
    for case in _load_cases(bench_dir / "fixtures.json"):
        with console.status(f"benchmarking {case.name}..."):
            results.append(benchmark.run(case))

    results_path = bench_dir / "results" / f"{impl}.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps([asdict(r) for r in results], indent=2) + "\n")
    _print_table(console, label, results)
    console.print(f"wrote {results_path}")
