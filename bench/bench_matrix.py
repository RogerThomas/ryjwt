#!yeet
"""Benchmark Python JWT decoding (PyJWT, joserfc, or ryjwt into a dict, read with msgspec or
jiter, or a msgspec Struct or pydantic BaseModel) over the full matrix in
`matrix/fixtures.json`: every algorithm and key size, payload size and key source.

Key sources:

- `hmac`: the HS256 secret.
- `pem`: the public key's PEM, parsed once.
- `jwks`: a JWKS document of 3 keys, the signing key in the middle; the token's `kid` picks it.
- `jwks-url-sync` / `jwks-url-async`: that document, fetched over HTTPS from the bench JWKS server.
  Decodes are timed in the steady state, after a warm-up, with the keys cached; the first fetch
  (a fresh client: connect, TLS, GET, parse the keys, verify) is timed on its own.

Each decode verifies the signature and checks `exp` and `aud`, and is checked once against the
fixture's payload before timing. Before that, each library must reject two tokens signed with the
case's key (from `matrix/keys/`, or the HMAC secret): an expired one and one for another audience.
Then each case gets 1,000 untimed warm-up decodes, then `rounds` rounds of `iterations` decodes,
each round timed as one loop.

Usage: `yeet ./bench_matrix.py [impl] [jwks_url] [only_sources] [only_cases] [iterations] [rounds]`
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
from bench_python import (
    REJECTIONS,
    WARMUP,
    BaseClaimsModel,
    BaseClaimsStruct,
    TypicalClaimsModel,
    TypicalClaimsStruct,
    joserfc_claims,
    joserfc_decode,
    prove_dict_parser,
    round_means_range,
    use_jiter_for_dicts,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from joserfc.jwk import ECKey, KeySet, OctKey, OKPKey, RSAKey
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable

type Impl = Literal["pyjwt", "joserfc", "ryjwt", "ryjwt-jiter", "ryjwt-msgspec", "ryjwt-pydantic"]
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
    rounds: int
    ops_per_sec: float
    mean_us: float
    round_means_us: list[float]


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
class Measure:
    """Times a prepared decode: `WARMUP` untimed decodes, then `rounds` rounds of `iterations`
    decodes, each round timed as one loop. Sync and async variants of the same methodology; each
    returns every round's nanoseconds."""

    _iterations: int
    _rounds: int

    def _check(self, case: Case, decoded: object, expected: object) -> None:
        if decoded != expected:
            raise AssertionError(f"{case.name}: decoded payload does not match the fixture")

    def sync(self, prepared: Prepared, case: Case) -> list[int]:
        decode, kwargs, token, clock = (
            prepared.decode,
            prepared.kwargs,
            case.token,
            time.perf_counter_ns,
        )
        self._check(case, decode(token, **kwargs), prepared.expected)
        for _ in range(WARMUP):
            decode(token, **kwargs)
        rounds_ns: list[int] = []
        for _ in range(self._rounds):
            t0 = clock()
            for _ in range(self._iterations):
                decode(token, **kwargs)
            rounds_ns.append(clock() - t0)
        return rounds_ns

    async def async_(self, prepared: Prepared, case: Case) -> list[int]:
        decode, kwargs, token, clock = (
            prepared.decode,
            prepared.kwargs,
            case.token,
            time.perf_counter_ns,
        )
        self._check(case, await decode(token, **kwargs), prepared.expected)
        for _ in range(WARMUP):
            await decode(token, **kwargs)
        rounds_ns: list[int] = []
        for _ in range(self._rounds):
            t0 = clock()
            for _ in range(self._iterations):
                await decode(token, **kwargs)
            rounds_ns.append(clock() - t0)
        return rounds_ns


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


def _joserfc_key(alg: str, pem: str) -> RSAKey | ECKey | OKPKey:
    match alg:
        case "RS256":
            return RSAKey.import_key(pem)
        case "ES256" | "ES384" | "ES512":
            return ECKey.import_key(pem)
        case "EdDSA":
            return OKPKey.import_key(pem)
        case _:
            raise ValueError(f"not an asymmetric algorithm in the matrix: {alg}")


@dataclass(frozen=True, slots=True)
class Sources:
    """Builds each implementation's decode for a case and key source. Every case gets its own URL
    client, whose first decode (the correctness check) fetches the keys."""

    _impl: Impl
    _jwks_url: str
    _ca_pem: bytes
    _private_keys: Path
    """`matrix/keys/`, for signing the tokens each library must reject."""
    first_fetch_case: ClassVar[str] = "typical-rs3072"
    first_fetch_trials: ClassVar[int] = 5
    notes_by_impl: ClassVar[dict[Impl, tuple[str, ...]]] = {
        "pyjwt": (
            "PEM: the key loaded once, with `load_pem_public_key`",
            "JWKS document: `PyJWKSet`, picking the key by `get_unverified_header`'s `kid`",
            "JWKS URL: `PyJWKClient(cache_keys=True)`, its `ssl_context` trusting the test CA",
        ),
        "joserfc": (
            (
                "`jwt.decode(token, key, algorithms=[...])`, then"
                " `JWTClaimsRegistry(exp=..., aud=...).validate(token.claims)`, both essential"
            ),
            (
                "keys imported once (`OctKey`, `RSAKey`, `ECKey`, `OKPKey`); JWKS document: a"
                " `KeySet`, which picks the key by `kid`"
            ),
            (
                "EdDSA: joserfc warns on every decode (`SecurityWarning`: RFC 9864 deprecates"
                " `EdDSA`), as it does by default"
            ),
        ),
        **dict.fromkeys(
            ("ryjwt", "ryjwt-jiter", "ryjwt-msgspec", "ryjwt-pydantic"),
            (
                (
                    "`SecretKey`, `PublicKey`, `PublicKey.from_jwks`, `JWKSClient.decode` and"
                    " `.adecode`"
                ),
                "JWKS URL: trusting the test CA through `SSL_CERT_FILE`",
            ),
        ),
    }
    no_url_client: ClassVar[dict[Impl, str]] = {
        "joserfc": "joserfc has no JWKS URL client",
    }

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

    def _joserfc(self, source: Source, case: Case) -> Prepared:
        kwargs: dict[str, Any] = {
            "algorithms": [case.key.alg],
            "claims_registry": joserfc_claims(case.audience),
        }
        key: OctKey | RSAKey | ECKey | OKPKey | KeySet
        if source == "hmac":
            key = OctKey.import_key(str(case.secret))
        elif source == "pem":
            key = _joserfc_key(case.key.alg, str(case.key.pem))
        else:
            key = KeySet.import_key_set(json.loads(str(case.key.jwks)))
        return Prepared(joserfc_decode, kwargs | {"key": key}, case.payload)

    def _ryjwt(self, source: Source, case: Case) -> Prepared:
        kwargs: dict[str, Any] = {"audience": case.audience}
        expected: object = case.payload
        if self._impl == "ryjwt-msgspec":
            struct = TypicalClaimsStruct if case.payload_size == "typical" else BaseClaimsStruct
            kwargs["type"] = struct
            expected = msgspec.convert(case.payload, struct)
        if self._impl == "ryjwt-pydantic":
            model = TypicalClaimsModel if case.payload_size == "typical" else BaseClaimsModel
            kwargs["type"] = model
            expected = model.model_validate(case.payload)
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
        match self._impl:
            case "pyjwt":
                return self._pyjwt(source, case)
            case "joserfc":
                return self._joserfc(source, case)
            case _:
                return self._ryjwt(source, case)

    def _signed(self, case: Case, claims: dict[str, Any]) -> str:
        """A token of `case`'s payload with `claims` changed, signed with its key (and `kid`)."""
        key = case.secret or (self._private_keys / f"{case.key.id}.pem").read_text()
        headers = {"kid": case.key.kid} if case.key.kid else None
        return jwt.encode(case.payload | claims, key, algorithm=case.key.alg, headers=headers)

    async def _decode(self, prepared: Prepared, token: str) -> object:
        decoded = prepared.decode(token, **prepared.kwargs)
        return await decoded if prepared.is_async else decoded

    async def _rejects(self, prepared: Prepared, token: str, error: type[Exception]) -> bool:
        try:
            await self._decode(prepared, token)
        except error:
            return True
        return False

    async def _prove_checks(self, prepared: Prepared, case: Case) -> None:
        """Fails unless the decode rejects an expired token and one for another audience."""
        expired_error, audience_error = REJECTIONS[self._impl]
        expired = self._signed(case, {"exp": case.payload["iat"] + 60})
        if not await self._rejects(prepared, expired, expired_error):
            raise AssertionError(f"{self._impl}, {case.name}: accepted an expired token")
        wrong_audience = self._signed(case, {"aud": "another-audience"})
        if not await self._rejects(prepared, wrong_audience, audience_error):
            raise AssertionError(f"{self._impl}, {case.name}: accepted another audience's token")

    def not_applicable(self) -> list[NotApplicable]:
        if self._impl == "pyjwt":
            return [NotApplicable("jwks-url-async", "*", "PyJWT has no async JWKS client")]
        return [
            NotApplicable(source, "*", self.no_url_client[self._impl])
            for source in ("jwks-url-sync", "jwks-url-async")
            if self._impl in self.no_url_client
        ]

    def notes(self) -> list[str]:
        return list(self.notes_by_impl[self._impl])

    async def prepare(self, source: Source, case: Case) -> Prepared:
        """`case`'s decode for `source`, once it has rejected an expired token and one for another
        audience."""
        prepared = self._prepare(source, case)
        await self._prove_checks(prepared, case)
        return prepared

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
    if not impl.startswith("ryjwt"):
        return f"{impl} {version(impl)}"
    target = {
        "ryjwt": "dict (msgspec)",
        "ryjwt-jiter": "dict (jiter)",
        "ryjwt-msgspec": "Struct",
        "ryjwt-pydantic": "BaseModel",
    }[impl]
    return f"ryjwt {version('ryjwt')} → {target}"


def _print_table(console: Console, label: str, source: str, rounds: int, rows: list[Row]) -> None:
    table = Table(title=f"decode — {label} — {source}")
    table.add_column("case")
    columns = ["token_len", "iterations", "rounds", "mean µs"]
    if rounds > 1:
        columns.append("round means µs")
    for col in columns:
        table.add_column(col, justify="right")
    for r in rows:
        cells = [r.name, f"{r.token_len:,}", f"{r.iterations:,}", f"{r.rounds}", f"{r.mean_us:.2f}"]
        if rounds > 1:
            cells.append(round_means_range(r.round_means_us))
        table.add_row(*cells)
    console.print(table)


async def main(
    impl: Impl = "ryjwt",
    jwks_url: str = "https://jwks:8443",
    only_sources: str = "",
    only_cases: str = "",
    iterations: int = 10_000,
    rounds: int = 1,
) -> None:
    """`only_sources` / `only_cases` are comma-separated filters; `iterations` decodes per round,
    `rounds` rounds per case."""
    if impl == "ryjwt-jiter":
        # This script imports msgspec, so ryjwt would read dicts with it; block it, before any
        # ryjwt key is created, to time a default install's jiter.
        use_jiter_for_dicts()
    prove_dict_parser(impl)
    bench_dir = Path(__file__).parent
    label = _label(impl)
    sources = Sources(
        impl,
        jwks_url.rstrip("/"),
        (bench_dir / "matrix" / "tls" / "ca.pem").read_bytes(),
        bench_dir / "matrix" / "keys",
    )
    measure = Measure(iterations, rounds)
    not_applicable = sources.not_applicable()
    skipped: set[Source] = {n.source for n in not_applicable if n.alg == "*"}
    skipped_algs: set[tuple[Source, str]] = {(n.source, n.alg) for n in not_applicable}
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
        f" — {len(cases)} cases x {', '.join(selected)}; {WARMUP:,} warm-up decodes, then"
        f" {rounds} x {iterations:,} timed",
    )
    rows: list[Row] = []
    first_fetch: list[FirstFetch] = []
    for source in selected:
        source_rows: list[Row] = []
        url = source.startswith("jwks-url")
        for case in cases:
            if (case.key.alg == "HS256") != (source == "hmac"):
                continue
            if (source, case.key.alg) in skipped_algs:
                continue
            if url and case.name == sources.first_fetch_case:
                trials = await sources.first_fetch(source, case)
                first_fetch.append(FirstFetch(source, case.name, statistics.median(trials), trials))
            with console.status(f"{source}: {case.name}..."):
                prepared = await sources.prepare(source, case)
                if prepared.is_async:
                    rounds_ns = await measure.async_(prepared, case)
                else:
                    rounds_ns = measure.sync(prepared, case)
            mean_us = sum(rounds_ns) / (iterations * rounds) / 1e3
            source_rows.append(
                Row(
                    impl=label,
                    source=source,
                    name=case.name,
                    key=case.key.id,
                    alg=case.key.alg,
                    payload_size=case.payload_size,
                    token_len=case.token_len,
                    iterations=iterations,
                    rounds=rounds,
                    ops_per_sec=1e6 / mean_us,
                    mean_us=mean_us,
                    round_means_us=[ns / iterations / 1e3 for ns in rounds_ns],
                )
            )
        _print_table(console, label, source, rounds, source_rows)
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
