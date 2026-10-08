#!yeet
"""Benchmark Python JWT decoding (PyJWT, or ryjwt into a dict / msgspec Struct / pydantic model)
over the fixture matrix.

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
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable

type Impl = Literal["pyjwt", "ryjwt", "ryjwt-msgspec", "ryjwt-pydantic"]


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
        decode = ryjwt.HMAC(case.key, algorithms=[case.alg]).decode
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
    if impl == "pyjwt":
        return f"pyjwt {version('pyjwt')}"
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
