"""Shared fixtures for the CodSpeed benchmarks: keys, PEMs and tokens, built once per session so
that only the call under test is measured.

Run with `task bench-codspeed` (or `uv run --group codspeed pytest benchmarks --codspeed`). Without
pytest-codspeed installed (as in `task test`), the benchmarks are ignored.
"""

import importlib.util
from pathlib import Path

import pytest
import ryjwt
from _bench_support import AUDIENCE, HMAC_SECRET, ISSUER

if importlib.util.find_spec("pytest_codspeed") is None:
    collect_ignore_glob = ["test_*.py"]

KEYS_DIR = Path(__file__).parent.parent / "bench" / "matrix" / "keys"


@pytest.fixture(name="private_pems", scope="session")
def _private_pems() -> dict[str, bytes]:
    """The bench's stored keys (bench/matrix/keys), so every run signs with the same keys."""

    def read(name: str) -> bytes:
        return (KEYS_DIR / f"{name}.pem").read_bytes()

    return {
        "RS256": read("rs2048"),
        "PS256": read("rs2048"),
        "ES256": read("es256"),
        "ES384": read("es384"),
        "EdDSA": read("ed25519"),
    }


@pytest.fixture(name="secret_key", scope="session")
def _secret_key() -> ryjwt.SecretKey:
    return ryjwt.SecretKey(
        HMAC_SECRET, algorithms=["HS256", "HS384", "HS512"], audience=AUDIENCE, issuer=ISSUER
    )
