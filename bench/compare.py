#!yeet
"""Merge bench/<results>/*.json into one side-by-side table: a rich table in the terminal, or a
Markdown page written to bench/<results>.md.

`yeet ./compare.py:matrix` does the same for the full matrix (`bench_matrix.py`, `bun/matrix.ts`,
`rust/src/bin/jwt_matrix.rs`): a Markdown page with a section per key source.
"""

import json
import math
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, ClassVar, Literal

from rich.console import Console
from rich.table import Table

type Output = Literal["terminal", "markdown"]
type Rows = dict[str, dict[str, Any]]

HEADLINE_CASE = "typical-k64"


def _load(results_dir: Path) -> dict[str, Rows]:
    by_impl: dict[str, Rows] = {}
    for path in sorted(results_dir.glob("*.json")):
        rows: list[dict[str, Any]] = json.loads(path.read_text())
        by_impl[str(rows[0]["impl"])] = {str(r["name"]): r for r in rows}
    return by_impl


def _terminal(by_impl: dict[str, Rows], impls: list[str]) -> None:
    base = by_impl[impls[0]]
    table = Table(title="JWT decode/verify (HS256) — ops/sec, speedup vs " + impls[0])
    table.add_column("case")
    table.add_column("token B", justify="right")
    table.add_column("key B", justify="right")
    for impl in impls:
        table.add_column(impl, justify="right")
    for name, ref in base.items():
        cells = [name, str(ref["token_len"]), str(ref["key_len"])]
        for impl in impls:
            row = by_impl[impl].get(name)
            if row is None:
                cells.append("-")
                continue
            speedup = row["ops_per_sec"] / ref["ops_per_sec"]
            cells.append(f"{row['ops_per_sec']:,.0f} ({speedup:.2f}x)")
        table.add_row(*cells)
    Console().print(table)


def _headline_mean(by_impl: dict[str, Rows], impl: str) -> float:
    """`impl`'s mean µs on the realistic headline case (very slow if it has none)."""
    return by_impl[impl].get(HEADLINE_CASE, {}).get("mean_us", 1e9)


def _markdown(by_impl: dict[str, Rows], baseline: str, results: str, note: str) -> str:
    base = by_impl[baseline]
    # Fastest first, by the realistic headline case.
    impls = sorted(by_impl, key=partial(_headline_mean, by_impl))
    generated = datetime.now(UTC).strftime("%Y-%m-%d")
    lines = [
        "# JWT decode benchmarks",
        "",
        f"Generated {generated} from `bench/{results}/` by `bench/compare.py`.",
        *([note] if note else []),
        "",
        "Each decode verifies an HS256 signature and checks `exp` and `aud`, as a real caller",
        "would. Times are the mean µs per decode (lower is better); `(Nx)` is the speed-up vs",
        f"{baseline}.",
        "",
        f"## Typical token ({base[HEADLINE_CASE]['token_len']} B, 64-byte key)",
        "",
        "| library | µs per decode | vs " + baseline + " |",
        "| :-- | --: | --: |",
    ]
    for impl in impls:
        row = by_impl[impl][HEADLINE_CASE]
        speedup = base[HEADLINE_CASE]["mean_us"] / row["mean_us"]
        lines.append(f"| {impl} | {row['mean_us']:.2f} | {speedup:.1f}x |")
    lines += [
        "",
        "## Every token and key size",
        "",
        "Fastest per row in bold.",
        "",
        "| case | token B | key B | " + " | ".join(impls) + " |",
        "| :-- | --: | --: |" + " --: |" * len(impls),
    ]
    for name, ref in base.items():
        means = {impl: by_impl[impl][name]["mean_us"] for impl in impls if name in by_impl[impl]}
        fastest = min(means, key=means.__getitem__)
        cells = [name, str(ref["token_len"]), str(ref["key_len"])]
        for impl in impls:
            if impl not in means:
                cells.append("-")
                continue
            cell = f"{means[impl]:.2f} ({ref['mean_us'] / means[impl]:.1f}x)"
            cells.append(f"**{cell}**" if impl == fastest else cell)
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class MatrixResults:
    """One implementation's results file from the full matrix."""

    impl: str
    runtime: str
    rows: dict[tuple[str, str], dict[str, Any]]  # by (source, case name)
    first_fetch: dict[str, dict[str, Any]]  # by source
    not_applicable: list[dict[str, str]]
    notes: list[str]

    @classmethod
    def load(cls, path: Path) -> MatrixResults:
        raw: dict[str, Any] = json.loads(path.read_text())
        return cls(
            impl=raw["impl"],
            runtime=raw["runtime"],
            rows={(r["source"], r["name"]): r for r in raw["rows"]},
            first_fetch={f["source"]: f for f in raw["first_fetch"]},
            not_applicable=raw["not_applicable"],
            notes=raw.get("notes", []),
        )

    def why_not(self, source: str, alg: str) -> str | None:
        """The reason this implementation has no result for `source` and `alg`, if it can't."""
        for n in self.not_applicable:
            if n["source"] in {source, "*"} and n["alg"] in {alg, "*"}:
                return n["reason"]
        return None


@dataclass(frozen=True, slots=True)
class MatrixPage:
    """The full matrix's Markdown page: a headline table, a table per key source, first-fetch
    latencies, and what isn't applicable to which library."""

    _results: dict[str, MatrixResults]  # by implementation label, fastest first
    _baseline: str
    _keys: dict[str, dict[str, Any]]
    _cases: list[dict[str, Any]]
    sources: ClassVar[dict[str, str]] = {
        "hmac": "HMAC secret",
        "pem": "PEM public key",
        "jwks": "JWKS document",
        "jwks-url-sync": "JWKS URL, sync client",
        "jwks-url-async": "JWKS URL, async client",
    }
    # (source, case): the typical payload with each algorithm's medium key, then RS256 per source
    headline: ClassVar[list[tuple[str, str]]] = [
        ("hmac", "typical-k64"),
        ("pem", "typical-rs3072"),
        ("pem", "typical-es384"),
        ("pem", "typical-ed25519"),
        ("jwks", "typical-rs3072"),
        ("jwks-url-sync", "typical-rs3072"),
        ("jwks-url-async", "typical-rs3072"),
    ]
    payload_sizes: ClassVar[list[str]] = ["small", "typical", "medium", "large"]
    # PyJWT has no async JWKS client: compare the async clients with its sync one
    baseline_source: ClassVar[dict[str, str]] = {"jwks-url-async": "jwks-url-sync"}

    def _baseline_mean(self, source: str, name: str) -> float | None:
        row = self._results[self._baseline].rows.get((
            self.baseline_source.get(source, source),
            name,
        ))
        return row["mean_us"] if row else None

    def _score(self, impl: str) -> float:
        """Minus `impl`'s geometric mean speed-up over its headline rows (fastest lowest)."""
        ratios = [
            base / row["mean_us"]
            for source, name in self.headline
            if (row := self._results[impl].rows.get((source, name)))
            and (base := self._baseline_mean(source, name))
        ]
        return -math.exp(sum(map(math.log, ratios)) / len(ratios)) if ratios else 0.0

    def _fastest_first(self) -> dict[str, MatrixResults]:
        """Orders implementations by their geometric mean speed-up over their headline rows."""
        return {impl: self._results[impl] for impl in sorted(self._results, key=self._score)}

    def _case_key(self, keys: list[str], case: dict[str, Any]) -> tuple[int, int]:
        """Where `case` sorts: by key (in `keys`' order), then by payload size."""
        return keys.index(case["key"]), self.payload_sizes.index(case["payload_size"])

    def _case_order(self) -> list[dict[str, Any]]:
        return sorted(self._cases, key=partial(self._case_key, list(self._keys)))

    def _cells(self, source: str, case: dict[str, Any]) -> list[str]:
        """One cell per implementation: mean µs and speed-up, the fastest in bold; n/a where the
        library can't; "missing" where it should have a result and hasn't (a failed run)."""
        name, alg = case["name"], case["alg"]
        means = {
            impl: r.rows[source, name]["mean_us"]
            for impl, r in self._results.items()
            if (source, name) in r.rows
        }
        fastest = min(means, key=means.__getitem__) if means else None
        cells: list[str] = []
        for impl, r in self._results.items():
            if impl not in means:
                cells.append("n/a" if r.why_not(source, alg) else "missing")
                continue
            base = self._baseline_mean(source, name)
            speedup = base / means[impl] if base else None
            # two decimals for big slow-downs, which would round to 0.0x
            ratio = f" ({speedup:.{1 if speedup >= 0.1 else 2}f}x)" if speedup else ""
            cell = f"{means[impl]:.2f}{ratio}"
            cells.append(f"**{cell}**" if impl == fastest else cell)
        return cells

    def _header(self, *columns: str) -> list[str]:
        names = [*columns, *self._results]
        return [
            "| " + " | ".join(names) + " |",
            "| "
            + " | ".join(["--:" if c == "token B" else ":--" for c in columns])
            + " |"
            + " --: |" * len(self._results),
        ]

    def _key_cells(self, case: dict[str, Any]) -> list[str]:
        key = self._keys[case["key"]]
        return [key["alg"], key["label"]]

    def _headline(self) -> list[str]:
        cases = {c["name"]: c for c in self._cases}
        lines = self._header("key source", "alg", "key")
        for source, name in self.headline:
            cells = [
                self.sources[source],
                *self._key_cells(cases[name]),
                *self._cells(source, cases[name]),
            ]
            lines.append("| " + " | ".join(cells) + " |")
        return lines

    def _section(self, source: str) -> list[str]:
        lines = [f"## {self.sources[source]}", ""]
        if source in self.baseline_source:
            lines += [
                f"{self._baseline} has no async JWKS client: speed-ups are vs its sync one.",
                "",
            ]
        lines += self._header("alg", "key", "payload", "token B")
        for case in self._case_order():
            if (case["alg"] == "HS256") != (source == "hmac"):
                continue
            cells = [*self._key_cells(case), case["payload_size"], str(case["token_len"])]
            lines.append("| " + " | ".join(cells + self._cells(source, case)) + " |")
        return [*lines, ""]

    def _first_fetches(self) -> list[str]:
        lines = self._header("key source")
        for source in ("jwks-url-sync", "jwks-url-async"):
            cells = [self.sources[source]]
            for r in self._results.values():
                fetch = r.first_fetch.get(source)
                cells.append(f"{fetch['ms']:.1f}" if fetch else "n/a")
            lines.append("| " + " | ".join(cells) + " |")
        return lines

    @staticmethod
    def _apple_silicon_caveat() -> list[str]:
        """A caveat for pages generated on macOS on Apple Silicon, where Docker runs the
        benchmarks in a Linux VM on the same CPU."""
        if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
            return []
        return [
            "## Apple Silicon caveat",
            "",
            "These numbers come from Docker on a Mac: Linux in a VM on Apple Silicon. There,",
            "aws-lc (the crypto library under ryjwt and jsonwebtoken) doesn't recognise the",
            "CPU: its Linux CPU detection knows only Arm's own cores. So it uses a big-number",
            "multiply meant for CPUs with slow multipliers, which makes RSA, Ed25519, P-384",
            "and P-521 verification about 1.6-1.8x slower than the same machine runs them",
            "natively. ES256 and HMAC are unaffected, and so is Linux on x86_64 and on",
            "Graviton 3/4, which aws-lc detects. BoringSSL (Bun's fast-jwt and jose) always",
            "uses the fast multiply.",
            "",
            "The same machine natively (macOS, M3 Max), RS256 decode in µs:",
            "",
            "| key | ryjwt | fast-jwt |",
            "| :-- | --: | --: |",
            "| RSA 2048 | 10.5 | 15.1 |",
            "| RSA 3072 | 21.8 | 27.1 |",
            "| RSA 4096 | 37.4 | 43.5 |",
            "",
        ]

    def _not_applicable(self) -> list[str]:
        lines: list[str] = []
        for impl, r in self._results.items():
            for n in r.not_applicable:
                source = "every key source" if n["source"] == "*" else self.sources[n["source"]]
                alg = "" if n["alg"] == "*" else f", {n['alg']}"
                lines.append(f"- {impl}, {source}{alg}: {n['reason']}.")
        return lines

    def _notes(self) -> list[str]:
        return [f"- {impl}: {note}." for impl, r in self._results.items() for note in r.notes]

    @classmethod
    def build(cls, results_dir: Path, fixtures: Path, baseline: str) -> MatrixPage:
        loaded = [MatrixResults.load(p) for p in sorted(results_dir.glob("*.json"))]
        by_impl = {r.impl: r for r in loaded}
        baseline_impl = next(i for i in sorted(by_impl) if i.startswith(baseline))
        raw = json.loads(fixtures.read_text())
        unordered = cls(by_impl, baseline_impl, raw["keys"], raw["cases"])
        return cls(unordered._fastest_first(), baseline_impl, raw["keys"], raw["cases"])

    def render(self, results: str, note: str) -> str:
        generated = datetime.now(UTC).strftime("%Y-%m-%d")
        runtimes = ", ".join(sorted({r.runtime for r in self._results.values()}))
        return (
            "\n".join([
                "# JWT decode benchmarks: the full matrix",
                "",
                f"Generated {generated} from `bench/{results}/` by `bench/compare.py`.",
                *([note] if note else []),
                f"Runtimes: {runtimes}.",
                "",
                "Each decode verifies the signature and checks `exp` and `aud`, as a real",
                "caller would, and each library's result is checked against the token's claims",
                "before timing. Times are the mean µs per decode (lower is better); `(Nx)` is the",
                f"speed-up vs {self._baseline}. Each case runs about a second (a warm-up, then",
                "the best of 5 batches), so slow ones (RSA 4096, P-521) run fewer iterations.",
                "Fastest per row in bold; n/a where the library can't (see the end).",
                "",
                "Key sources: an HMAC secret (HS256 only); a PEM public key, parsed once; a",
                "JWKS document of 3 keys, the signing key in the middle, picked by the token's",
                "`kid`; and that document fetched over HTTPS from a JWKS server",
                "(static-web-server, in its own container), timed in the steady state with the",
                "keys cached.",
                "",
                *self._apple_silicon_caveat(),
                "## Headline: typical token, medium key",
                "",
                *self._headline(),
                "",
                *[line for source in self.sources for line in self._section(source)],
                "## First fetch from a JWKS URL",
                "",
                "Milliseconds from a fresh client to its first decode: connect, TLS handshake,",
                "GET the JWKS, parse it, verify (typical token, RSA 3072). The median of 5 fresh",
                "clients, each on a new connection.",
                "",
                *self._first_fetches(),
                "",
                "## Not applicable",
                "",
                *self._not_applicable(),
                "",
                "## Notes",
                "",
                *self._notes(),
            ])
            + "\n"
        )


def _baseline_first(baseline: str, impl: str) -> tuple[bool, str]:
    """Where `impl` sorts: `baseline` first, then by name."""
    return impl != baseline, impl


def main(
    results: str = "results",
    output: Output = "terminal",
    note: str = "",
    baseline: str = "pyjwt",
) -> None:
    bench_dir = Path(__file__).parent
    by_impl = _load(bench_dir / results)
    baseline_impl = next(i for i in sorted(by_impl) if i.startswith(baseline))
    if output == "terminal":
        _terminal(by_impl, sorted(by_impl, key=partial(_baseline_first, baseline_impl)))
        return
    path = bench_dir / f"{results}.md"
    path.write_text(_markdown(by_impl, baseline_impl, results, note))
    Console().print(f"wrote {path}")


def matrix(results: str = "results-matrix", note: str = "", baseline: str = "pyjwt") -> None:
    """Writes the full matrix's results, bench/<results>/*.json, as a Markdown page."""
    bench_dir = Path(__file__).parent
    page = MatrixPage.build(bench_dir / results, bench_dir / "matrix" / "fixtures.json", baseline)
    path = bench_dir / f"{results}.md"
    path.write_text(page.render(results, note))
    Console().print(f"wrote {path}")
