#!yeet
"""Benchmark Python JWT decoding (PyJWT, or ryjwt into a dict / msgspec Struct) over the full
matrix in `matrix/fixtures.json`: every algorithm and key size, payload size and key source.

Key sources:

- `hmac`: the HS256 secret.
- `pem`: the public key's PEM, parsed once.
- `jwks`: a JWKS document of 3 keys, the signing key in the middle; the token's `kid` picks it.
- `jwks-url-sync` / `jwks-url-async`: that document, fetched over HTTPS from the bench JWKS server.
  Decodes are timed in the steady state, after a warm-up, with the keys cached; the first fetch
  (a fresh client: connect, TLS, GET, parse the keys, verify) is timed on its own.

Each decode verifies the signature and checks `exp` and `aud`, and is checked once against the
fixture's payload before timing. A case's iteration counts follow from its cost, measured in the
warm-up, so slow cases (RSA 4096, P-521) run fewer iterations in about the same time.
"""

import json
import platform
import ssl
import statistics
import time
from dataclasses import asdict, dataclass
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal

import jwt
import msgspec
import ryjwt
from bench_python import BaseClaimsStruct, TypicalClaimsStruct
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable

type Impl = Literal["pyjwt", "ryjwt", "ryjwt-msgspec"]
type Source = Literal["hmac", "pem", "jwks", "jwks-url-sync", "jwks-url-async"]


@dataclass(frozen=True, slots=True)
class Key:
    id: str
    alg: str
    size: str
    label: str
    kid: str | None
    pem: str | None
    jwks: str | None


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    key: Key
    payload_size: str
    secret: str | None
    token: str
    token_len: int
    audience: str
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Prepared:
    """A decode callable, the keyword arguments every call passes, and the expected result.
    `is_async` decodes return an awaitable."""

    decode: Callable[..., Any]
    kwargs: dict[str, Any]
    expected: object
    is_async: bool = False


@dataclass(frozen=True, slots=True)
class Row:
    impl: str
    source: str
    name: str
    key: str
    alg: str
    payload_size: str
    token_len: int
    iterations: int
    ops_per_sec: float
    mean_us: float
    p50_us: float
    p99_us: float


@dataclass(frozen=True, slots=True)
class FirstFetch:
    source: str
    name: str
    ms: float
    trials_ms: list[float]


@dataclass(frozen=True, slots=True)
class NotApplicable:
    source: Source
    alg: str  # "*" for every algorithm
    reason: str


@dataclass(frozen=True, slots=True)
class Timing:
    """Each phase's time budget per case. The warm-up estimates one call's cost; the batch and
    sample counts follow from it (capped as in `bench_python.py`). The mean is the best batch's."""

    warmup_s: float
    batch_s: float
    samples_s: float
    repeats: int = 5
    max_iterations: int = 20_000
    max_samples: int = 5_000
    min_count: int = 10

    def counts(self, per_call_ns: float) -> tuple[int, int]:
        """The iterations per batch and the number of timed samples."""
        iterations = int(self.batch_s * 1e9 / per_call_ns)
        samples = int(self.samples_s * 1e9 / per_call_ns)
        return (
            max(self.min_count, min(self.max_iterations, iterations)),
            max(self.min_count, min(self.max_samples, samples)),
        )


@dataclass(frozen=True, slots=True)
class Stats:
    iterations: int
    mean_ns: float
    samples_ns: list[int]


@dataclass(frozen=True, slots=True)
class Measure:
    """Times a prepared decode: sync and async variants of the same methodology."""

    _timing: Timing

    def _check(self, case: Case, decoded: object, expected: object) -> None:
        if decoded != expected:
            raise AssertionError(f"{case.name}: decoded payload does not match the fixture")

    def _stats(self, iterations: int, batches_ns: list[int], samples: list[int]) -> Stats:
        return Stats(iterations, min(batches_ns) / iterations, sorted(samples))

    def sync(self, prepared: Prepared, case: Case) -> Stats:
        decode, kwargs, token, clock = (
            prepared.decode,
            prepared.kwargs,
            case.token,
            time.perf_counter_ns,
        )
        self._check(case, decode(token, **kwargs), prepared.expected)
        start, calls, deadline = clock(), 0, clock() + int(self._timing.warmup_s * 1e9)
        while calls < self._timing.min_count or clock() < deadline:
            decode(token, **kwargs)
            calls += 1
        iterations, n_samples = self._timing.counts((clock() - start) / calls)
        batches: list[int] = []
        for _ in range(self._timing.repeats):
            t0 = clock()
            for _ in range(iterations):
                decode(token, **kwargs)
            batches.append(clock() - t0)
        samples: list[int] = []
        for _ in range(n_samples):
            t0 = clock()
            decode(token, **kwargs)
            samples.append(clock() - t0)
        return self._stats(iterations, batches, samples)

    async def async_(self, prepared: Prepared, case: Case) -> Stats:
        decode, kwargs, token, clock = (
            prepared.decode,
            prepared.kwargs,
            case.token,
            time.perf_counter_ns,
        )
        self._check(case, await decode(token, **kwargs), prepared.expected)
        start, calls, deadline = clock(), 0, clock() + int(self._timing.warmup_s * 1e9)
        while calls < self._timing.min_count or clock() < deadline:
            await decode(token, **kwargs)
            calls += 1
        iterations, n_samples = self._timing.counts((clock() - start) / calls)
        batches: list[int] = []
        for _ in range(self._timing.repeats):
            t0 = clock()
            for _ in range(iterations):
                await decode(token, **kwargs)
            batches.append(clock() - t0)
        samples: list[int] = []
        for _ in range(n_samples):
            t0 = clock()
            await decode(token, **kwargs)
            samples.append(clock() - t0)
        return self._stats(iterations, batches, samples)


def _asymmetric(alg: str) -> ryjwt.AsymmetricAlgorithm:
    match alg:
        case "RS256" | "ES256" | "ES384" | "ES512" | "EdDSA":
            return alg
        case _:
            raise ValueError(f"not an asymmetric algorithm in the matrix: {alg}")


def _pyjwt_jwks_decode(
    token: str, *, jwk_set: jwt.PyJWKSet, algorithms: list[str], audience: str
) -> dict[str, Any]:
    """PyJWT with a JWKS document: pick the key by the token's `kid`, then verify with it."""
    key = jwk_set[jwt.get_unverified_header(token)["kid"]]
    return jwt.decode(token, key, algorithms=algorithms, audience=audience)


def _pyjwt_client_decode(
    token: str, *, client: jwt.PyJWKClient, algorithms: list[str], audience: str
) -> dict[str, Any]:
    """PyJWT with a JWKS URL, as its docs show: the client picks the key, then verify with it."""
    key = client.get_signing_key_from_jwt(token)
    return jwt.decode(token, key, algorithms=algorithms, audience=audience)


@dataclass(frozen=True, slots=True)
class Sources:
    """Builds each implementation's decode for a case and key source. Every case gets its own URL
    client, whose first decode (the correctness check) fetches the keys."""

    _impl: Impl
    _jwks_url: str
    _ca_pem: bytes
    first_fetch_case: ClassVar[str] = "typical-rs3072"
    first_fetch_trials: ClassVar[int] = 5

    def _url(self, key: Key) -> str:
        return f"{self._jwks_url}/{key.id}.json"

    def _pyjwt_client(self, key: Key) -> jwt.PyJWKClient:
        context = ssl.create_default_context(cadata=self._ca_pem.decode())
        return jwt.PyJWKClient(self._url(key), cache_keys=True, ssl_context=context)

    def _client(self, key: Key) -> ryjwt.JWKSClient:
        """A JWKS client for `key`'s URL. It trusts the test CA through `SSL_CERT_FILE` (set by
        compose.yaml), as ryjwt's fetches use Python's default SSL context."""
        return ryjwt.JWKSClient(self._url(key), algorithms=[_asymmetric(key.alg)])

    def _pyjwt(self, source: Source, case: Case) -> Prepared:
        kwargs: dict[str, Any] = {"algorithms": [case.key.alg], "audience": case.audience}
        if source == "hmac":
            return Prepared(jwt.decode, kwargs | {"key": case.secret}, case.payload)
        if source == "pem":
            key = load_pem_public_key(str(case.key.pem).encode())
            return Prepared(jwt.decode, kwargs | {"key": key}, case.payload)
        if source == "jwks":
            jwk_set = jwt.PyJWKSet.from_json(str(case.key.jwks))
            return Prepared(_pyjwt_jwks_decode, kwargs | {"jwk_set": jwk_set}, case.payload)
        client = self._pyjwt_client(case.key)
        return Prepared(_pyjwt_client_decode, kwargs | {"client": client}, case.payload)

    def _ryjwt(self, source: Source, case: Case) -> Prepared:
        kwargs: dict[str, Any] = {"audience": case.audience}
        expected: object = case.payload
        if self._impl == "ryjwt-msgspec":
            struct = TypicalClaimsStruct if case.payload_size == "typical" else BaseClaimsStruct
            kwargs["type"] = struct
            expected = msgspec.convert(case.payload, struct)
        if source == "hmac":
            decode = ryjwt.SecretKey(str(case.secret), algorithms=["HS256"]).decode
            return Prepared(decode, kwargs, expected)
        alg = _asymmetric(case.key.alg)
        if source == "pem":
            decode = ryjwt.PublicKey(str(case.key.pem), algorithms=[alg]).decode
            return Prepared(decode, kwargs, expected)
        if source == "jwks":
            decode = ryjwt.PublicKey.from_jwks(str(case.key.jwks), algorithms=[alg]).decode
            return Prepared(decode, kwargs, expected)
        if source == "jwks-url-sync":
            return Prepared(self._client(case.key).decode, kwargs, expected)
        return Prepared(self._client(case.key).adecode, kwargs, expected, is_async=True)

    def _prepare(self, source: Source, case: Case) -> Prepared:
        if self._impl == "pyjwt":
            return self._pyjwt(source, case)
        return self._ryjwt(source, case)

    def not_applicable(self) -> list[NotApplicable]:
        if self._impl == "pyjwt":
            return [NotApplicable("jwks-url-async", "*", "PyJWT has no async JWKS client")]
        return []

    def notes(self) -> list[str]:
        if self._impl == "pyjwt":
            return [
                "PEM: the key loaded once, with `load_pem_public_key`",
                "JWKS document: `PyJWKSet`, picking the key by `get_unverified_header`'s `kid`",
                "JWKS URL: `PyJWKClient(cache_keys=True)`, its `ssl_context` trusting the test CA",
            ]
        return [
            "`SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and `.adecode`",
            "JWKS URL: trusting the test CA through `SSL_CERT_FILE`",
        ]

    def prepare(self, source: Source, case: Case) -> Prepared:
        return self._prepare(source, case)

    async def first_fetch(self, source: Source, case: Case) -> list[float]:
        """Milliseconds to the first decode of a fresh client (HTTP client included), per trial."""
        trials: list[float] = []
        for _ in range(self.first_fetch_trials):
            prepared = self._prepare(source, case)
            t0 = time.perf_counter_ns()
            decoded = prepared.decode(case.token, **prepared.kwargs)
            if prepared.is_async:
                decoded = await decoded
            trials.append((time.perf_counter_ns() - t0) / 1e6)
            if decoded != prepared.expected:
                raise AssertionError(f"{case.name}: decoded payload does not match the fixture")
        return trials


def _load(path: Path) -> list[Case]:
    raw = json.loads(path.read_text())
    keys = {
        key_id: Key(
            id=key_id,
            alg=k["alg"],
            size=k["size"],
            label=k["label"],
            kid=k.get("kid"),
            pem=k.get("pem"),
            jwks=k.get("jwks"),
        )
        for key_id, k in raw["keys"].items()
    }
    return [
        Case(
            name=c["name"],
            key=keys[c["key"]],
            payload_size=c["payload_size"],
            secret=c.get("secret"),
            token=c["token"],
            token_len=c["token_len"],
            audience=c["audience"],
            payload=c["payload"],
        )
        for c in raw["cases"]
    ]


def _label(impl: Impl) -> str:
    if impl == "pyjwt":
        return f"pyjwt {version('pyjwt')}"
    return f"ryjwt {version('ryjwt')} → {'Struct' if impl == 'ryjwt-msgspec' else 'dict'}"


def _print_table(console: Console, label: str, source: str, rows: list[Row]) -> None:
    table = Table(title=f"decode — {label} — {source}")
    table.add_column("case")
    for col in ("token_len", "iterations", "ops/s", "mean µs", "p50 µs", "p99 µs"):
        table.add_column(col, justify="right")
    for r in rows:
        table.add_row(
            r.name,
            f"{r.token_len:,}",
            f"{r.iterations:,}",
            f"{r.ops_per_sec:,.0f}",
            f"{r.mean_us:.2f}",
            f"{r.p50_us:.2f}",
            f"{r.p99_us:.2f}",
        )
    console.print(table)


async def main(
    impl: Impl = "ryjwt",
    jwks_url: str = "https://jwks:8443",
    only_sources: str = "",
    only_cases: str = "",
    budget: float = 1.0,
) -> None:
    """`only_sources` / `only_cases` are comma-separated filters; `budget` scales each case's time
    (1.0: 0.1 s warm-up, 5 batches of 0.2 s, 0.3 s of samples)."""
    bench_dir = Path(__file__).parent
    label = _label(impl)
    sources = Sources(
        impl, jwks_url.rstrip("/"), (bench_dir / "matrix" / "tls" / "ca.pem").read_bytes()
    )
    measure = Measure(Timing(0.1 * budget, 0.2 * budget, 0.3 * budget))
    not_applicable = sources.not_applicable()
    skipped: set[Source] = {n.source for n in not_applicable}
    all_sources: list[Source] = ["hmac", "pem", "jwks", "jwks-url-sync", "jwks-url-async"]
    by_name: dict[str, Source] = {s: s for s in all_sources}
    requested: list[Source] = (
        [by_name[s] for s in only_sources.split(",")] if only_sources else all_sources
    )
    selected: list[Source] = [s for s in requested if s not in skipped]
    cases = [
        c
        for c in _load(bench_dir / "matrix" / "fixtures.json")
        if not only_cases or c.name in only_cases.split(",")
    ]

    console = Console()
    console.print(
        f"[bold]{label}[/] on {platform.python_implementation()} {platform.python_version()}"
        f" — {len(cases)} cases x {', '.join(selected)}",
    )
    rows: list[Row] = []
    first_fetch: list[FirstFetch] = []
    for source in selected:
        source_rows: list[Row] = []
        url = source.startswith("jwks-url")
        for case in cases:
            if (case.key.alg == "HS256") != (source == "hmac"):
                continue
            if url and case.name == sources.first_fetch_case:
                trials = await sources.first_fetch(source, case)
                first_fetch.append(FirstFetch(source, case.name, statistics.median(trials), trials))
            with console.status(f"{source}: {case.name}..."):
                prepared = sources.prepare(source, case)
                if prepared.is_async:
                    stats = await measure.async_(prepared, case)
                else:
                    stats = measure.sync(prepared, case)
            source_rows.append(
                Row(
                    impl=label,
                    source=source,
                    name=case.name,
                    key=case.key.id,
                    alg=case.key.alg,
                    payload_size=case.payload_size,
                    token_len=case.token_len,
                    iterations=stats.iterations,
                    ops_per_sec=1e9 / stats.mean_ns,
                    mean_us=stats.mean_ns / 1e3,
                    p50_us=statistics.median(stats.samples_ns) / 1e3,
                    p99_us=statistics.quantiles(stats.samples_ns, n=100, method="inclusive")[98]
                    / 1e3,
                )
            )
        _print_table(console, label, source, source_rows)
        rows += source_rows
    for f in first_fetch:
        trials = ", ".join(f"{t:.1f}" for t in f.trials_ms)
        console.print(f"first fetch, {f.source} ({f.name}): median {f.ms:.2f} ms [{trials}]")

    results_path = bench_dir / "results" / "matrix" / f"{impl}.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results = {
        "impl": label,
        "runtime": f"{platform.python_implementation()} {platform.python_version()}",
        "rows": [asdict(r) for r in rows],
        "first_fetch": [asdict(f) for f in first_fetch],
        "not_applicable": [asdict(n) for n in not_applicable],
        "notes": sources.notes(),
    }
    results_path.write_text(json.dumps(results, indent=2) + "\n")
    console.print(f"wrote {results_path}")
