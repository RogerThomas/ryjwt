#!yeet
"""Merge bench/results/*.json into one side-by-side ops/sec table."""

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table


def main(baseline: str = "pyjwt") -> None:
    by_impl: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted((Path(__file__).parent / "results").glob("*.json")):
        rows: list[dict[str, Any]] = json.loads(path.read_text())
        by_impl[str(rows[0]["impl"])] = {str(r["name"]): r for r in rows}

    impls = sorted(by_impl, key=lambda i: (not i.startswith(baseline), i))
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
