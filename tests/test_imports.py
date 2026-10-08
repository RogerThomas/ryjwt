"""What importing and using ryjwt imports: nothing a caller doesn't use. pydantic only matters to
callers with pydantic models (who have imported it already), asyncio only to a JWKS client's async
methods, ssl and urllib.request (~25 ms to import) only to a JWKS client's fetches, and ipaddress
only to a JWKS client for an IPv6 address, so none is imported for anyone else. Each case runs in
a fresh interpreter, since this one has imported them all already.
"""

import json
import subprocess
import sys

import pytest

_IMPORT = "import ryjwt"

_STRUCT_ROUND_TRIP = """
from datetime import UTC, datetime

import msgspec
import ryjwt


class Claims(msgspec.Struct):
    sub: str
    exp: datetime


key = ryjwt.SecretKey("s" * 32, algorithms=["HS256"])
token = key.encode(Claims(sub="sub", exp=datetime(2100, 1, 1, tzinfo=UTC)))
assert key.decode(token, type=Claims).sub == "sub"
"""

_DICT_ROUND_TRIP = """
import ryjwt

key = ryjwt.SecretKey("s" * 32, algorithms=["HS256"])
assert key.decode(key.encode({"sub": "sub"})) == {"sub": "sub"}
"""

_JWKS_CLIENT = """
import ryjwt

client = ryjwt.JWKSClient("https://issuer/jwks", algorithms=["ES256"])
assert client.needs_refresh
"""

_REPORT = """
import json
import sys

modules = {"asyncio", "ipaddress", "pydantic", "ssl", "urllib.request"}
print(json.dumps(sorted(modules & sys.modules.keys())))
"""


def _imported(code: str) -> list[str]:
    """Which of asyncio, ipaddress, pydantic, ssl and urllib.request are imported after running
    `code` in a fresh interpreter."""
    result = subprocess.run(
        [sys.executable, "-c", code + _REPORT],
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(_IMPORT, id="import"),
        pytest.param(_DICT_ROUND_TRIP, id="dict"),
        pytest.param(_STRUCT_ROUND_TRIP, id="struct"),
        pytest.param(_JWKS_CLIENT, id="jwks-client"),
    ],
)
def test_nothing_unused_is_imported(code: str) -> None:
    assert _imported(code) == []
