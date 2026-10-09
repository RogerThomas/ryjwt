"""`JWKSClient` against a real local HTTP server: fetching, caching, key rotation, cooldown,
outages, background refreshes, single-flight fetches, and the manual API (`refresh`,
`needs_refresh`, `decode_nowait`).

Tests parametrised by `kind` use the client from sync code (`decode`, `refresh`) and from async code
(`adecode`, `arefresh`). They wait for what happens in the background (a refresh, a response) with
`eventually`, and only sleep to let time pass (for keys to expire, or a cooldown to end), with a
margin.
"""

import asyncio
import base64
import datetime
import http.client
import importlib.metadata
import inspect
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
import time
import typing
from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, NoReturn, Protocol, TypedDict, Unpack
from urllib.error import URLError

import jwt
import pytest
import ryjwt
from _support import (
    ClaimsModel,
    ClaimsStruct,
    JWKSHandler,
    JWKSServer,
    LocalHTTPServer,
    SigningKey,
    make_jwk,
    serve_jwks,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


class Policy(TypedDict, total=False):
    """The refresh policy a test sets; the client's defaults apply to the rest."""

    cache_lifetime: float | timedelta
    min_cache_lifetime: float | timedelta
    max_cache_lifetime: float | timedelta
    max_stale: float | timedelta
    cooldown: float | timedelta


class ClaimChecks(TypedDict, total=False):
    """The `audience` and `issuer` a client, or a decode, checks tokens against."""

    audience: str | Iterable[str] | None
    issuer: str | Iterable[str] | None


@dataclass
class Caller:
    """A `JWKSClient`, called from sync code (`decode`, `refresh`) or from async code (`adecode`,
    `arefresh`, on the test's event loop), as the test's `kind` says."""

    client: ryjwt.JWKSClient
    kind: str
    runner: asyncio.Runner

    def _refresh(self) -> None:
        if self.kind == "sync":
            self.client.refresh()
        else:
            self.runner.run(self.client.arefresh())

    def decode(self, token: str) -> dict[str, Any]:
        if self.kind == "sync":
            return self.client.decode(token)
        return self.runner.run(self.client.adecode(token))

    def refresh(self) -> None:
        self._refresh()

    def decode_manually(self, token: str) -> dict[str, Any]:
        """The manual pattern: refresh only if needed, then decode without waiting."""
        if self.client.needs_refresh:
            self._refresh()
        return self.client.decode_nowait(token)


class MakeClient(Protocol):
    """Builds a `JWKSClient`, for ES256 unless given `algorithms`, with the given `policy`, called
    as the test's `kind` says."""

    def __call__(
        self,
        url: str,
        *,
        algorithms: Sequence[ryjwt.AsymmetricAlgorithm] | None = None,
        **policy: Unpack[Policy],
    ) -> Caller: ...


class _IPv6HTTPServer(LocalHTTPServer):
    address_family = socket.AF_INET6


@dataclass
class _ClientMaker:
    """`MakeClient`, with the test's client `kind` and event loop."""

    kind: str
    runner: asyncio.Runner

    def __call__(
        self,
        url: str,
        *,
        algorithms: Sequence[ryjwt.AsymmetricAlgorithm] | None = None,
        **policy: Unpack[Policy],
    ) -> Caller:
        client = ryjwt.JWKSClient(url, algorithms=algorithms or ["ES256"], **policy)
        return Caller(client, self.kind, self.runner)


@dataclass
class ClientDecode:
    """A `JWKSClient`'s `decode`, `adecode` (run on `runner`) or `decode_nowait`, as `method`
    says."""

    client: ryjwt.JWKSClient
    method: str
    runner: asyncio.Runner

    def __call__(self, token: str, **checks: Unpack[ClaimChecks]) -> dict[str, Any]:
        match self.method:
            case "decode":
                return self.client.decode(token, **checks)
            case "adecode":
                return self.runner.run(self.client.adecode(token, **checks))
            case _:
                return self.client.decode_nowait(token, **checks)


@dataclass
class HungDNS:
    """Stands in for `socket.getaddrinfo`: hangs (well past a fetch's deadline) until released,
    then fails."""

    hosts: list[str] = field(default_factory=list[str])
    """The hosts looked up."""
    released: threading.Event = field(default_factory=threading.Event)

    def __call__(self, host: str, *_args: object, **_kwargs: object) -> NoReturn:
        self.hosts.append(host)
        self.released.wait(30)
        raise socket.gaierror("released")


@dataclass
class HeldHeaders:
    """Stands in for `http.client.HTTPResponse.getheader`, which a fetch calls once it has read the
    whole response: the first call waits until released; every call finds no such header."""

    held: threading.Event = field(default_factory=threading.Event)
    """Set once the first call is waiting."""
    released: threading.Event = field(default_factory=threading.Event)

    def __call__(self, _name: str, default: str | None = None) -> str | None:
        if not self.held.is_set():
            self.held.set()
            self.released.wait(30)
        return default


@dataclass
class RefreshOnClockRead:
    """Stands in for `time.monotonic`: once armed with a client, the next read (on the thread that
    armed it) first refreshes that client, as another thread could at that very moment."""

    clock: Callable[[], float]
    """The real `time.monotonic`."""
    client: ryjwt.JWKSClient | None = None
    thread: int = 0

    def arm(self, client: ryjwt.JWKSClient) -> None:
        self.client, self.thread = client, threading.get_ident()

    def __call__(self) -> float:
        if self.client is not None and threading.get_ident() == self.thread:
            client, self.client = self.client, None
            client.refresh()
        return self.clock()


def eventually(condition: Callable[[], bool], timeout: float = 3) -> None:
    """Waits until `condition` holds, checking it every 10 ms, for up to `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, f"not within {timeout} s"
        time.sleep(0.01)


def _raises(error: type[Exception], decode: Callable[[str], object], token: str) -> bool:
    """Whether `decode(token)` raises `error`, rather than returning."""
    try:
        decode(token)
    except error:
        return True
    return False


def _refreshed(client: ryjwt.JWKSClient) -> bool:
    return not client.needs_refresh


def _client_decode(
    url: str,
    method: str,
    runner: asyncio.Runner,
    **checks: Unpack[ClaimChecks],
) -> ClientDecode:
    """`method` of a new client for `url` (RS256 and ES256, with `checks`), which has fetched the
    keys already for `decode_nowait`."""
    client = ryjwt.JWKSClient(url, algorithms=["RS256", "ES256"], **checks)
    if method == "decode_nowait":
        client.refresh()
    return ClientDecode(client, method, runner)


def _decodes(decode: Callable[[str], object], token: str) -> bool:
    """Whether `decode(token)` returns, rather than raising `JWKSFetchError`."""
    try:
        decode(token)
    except ryjwt.JWKSFetchError:
        return False
    return True


async def _adecode_all(client: ryjwt.JWKSClient, token: str, count: int) -> list[dict[str, Any]]:
    """`count` concurrent `adecode`s of `token`."""
    return await asyncio.gather(*(client.adecode(token) for _ in range(count)))


def _adecode_all_on_own_loop(
    client: ryjwt.JWKSClient,
    token: str,
    start: threading.Barrier,
) -> list[dict[str, Any]]:
    """`_adecode_all` of 20, on an event loop of its own, once `start` lets it go."""
    start.wait()
    return asyncio.run(_adecode_all(client, token, 20))


def _decode_after(client: ryjwt.JWKSClient, token: str, start: threading.Barrier) -> dict[str, Any]:
    start.wait()
    return client.decode(token)


async def _arefresh_all(client: ryjwt.JWKSClient, count: int) -> None:
    """`count` concurrent `arefresh`es."""
    await asyncio.gather(*(client.arefresh() for _ in range(count)))


async def _cancel_one(client: ryjwt.JWKSClient, server: JWKSServer, token: str) -> dict[str, Any]:
    """Two `adecode`s wait for the same fetch; the first is cancelled, the other's result is
    returned."""
    cancelled = asyncio.create_task(client.adecode(token))
    other = asyncio.create_task(client.adecode(token))
    await asyncio.to_thread(eventually, partial(server.received, 1))  # both wait for the fetch now
    cancelled.cancel()
    return await other


async def _check_adecode_api(
    client: ryjwt.JWKSClient,
    tokens: dict[str, str],
    past: int,
) -> None:
    claims = {"sub": "sub", "aud": "aud", "iss": "iss"}
    assert await client.adecode(tokens["rs256"], audience="aud", issuer="iss") == claims
    assert await client.adecode(tokens["es256"].encode(), audience=["aud"]) == claims
    struct = await client.adecode(tokens["es256"], type=ClaimsStruct, audience="aud")
    assert struct == ClaimsStruct("sub")
    model = await client.adecode(tokens["rs256"], type=ClaimsModel, audience="aud")
    assert model == ClaimsModel(sub="sub")
    with pytest.raises(ryjwt.InvalidAudienceError):
        await client.adecode(tokens["es256"], audience="other-aud")
    with pytest.raises(ryjwt.InvalidIssuerError):
        await client.adecode(tokens["es256"], audience="aud", issuer="other-iss")
    with pytest.raises(ryjwt.ExpiredSignatureError):
        await client.adecode(tokens["expired"])
    assert await client.adecode(tokens["expired"], leeway=7200) == {"exp": past}
    with pytest.raises(ryjwt.ClaimsValidationError):
        await client.adecode(tokens["expired"], type=ClaimsModel, leeway=7200)
    with pytest.raises(ryjwt.DecodeError):
        await client.adecode("not-a-token")


@pytest.fixture(name="second_server")
def _second_server() -> Iterator[JWKSServer]:
    """Another `server`."""
    yield from serve_jwks()


@pytest.fixture(name="ipv6_server")
def _ipv6_server() -> Iterator[JWKSServer]:
    """`server`, on [::1] instead; the test is skipped if this machine can't listen there."""
    state = JWKSServer()
    try:
        httpd = _IPv6HTTPServer(("::1", 0), partial(JWKSHandler, state=state))
    except OSError as e:
        pytest.skip(f"Can't listen on [::1]: {e}")
    state.origin = f"http://[::1]:{httpd.server_port}"
    state.url = f"{state.origin}/jwks"
    threading.Thread(target=httpd.serve_forever, args=(0.01,), daemon=True).start()
    yield state
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(name="proxy")
def _proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[JWKSServer]:
    """A local stand-in for an HTTP proxy, which the environment (`HTTP_PROXY`, `HTTPS_PROXY`, in
    either case, and no `NO_PROXY`) says to use for every URL. It counts requests, and serves no
    usable keys."""
    state = JWKSServer()
    httpd = LocalHTTPServer(("127.0.0.1", 0), partial(JWKSHandler, state=state))
    state.origin = f"http://127.0.0.1:{httpd.server_port}"
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(name, state.origin)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    threading.Thread(target=httpd.serve_forever, args=(0.01,), daemon=True).start()
    yield state
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(name="tls_cert", scope="session")
def _tls_cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A self-signed certificate for 127.0.0.1, and its private key, as PEM files."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "common-name")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509
        .CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("tls")
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture(name="tls_server")
def _tls_server(tls_cert: tuple[Path, Path]) -> Iterator[JWKSServer]:
    """`server`, over TLS with `tls_cert`."""
    state = JWKSServer()
    httpd = LocalHTTPServer(("127.0.0.1", 0), partial(JWKSHandler, state=state))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*tls_cert)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    state.origin = f"https://127.0.0.1:{httpd.server_port}"
    state.url = f"{state.origin}/jwks"
    threading.Thread(target=httpd.serve_forever, args=(0.01,), daemon=True).start()
    yield state
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(name="hung_dns")
def _hung_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[HungDNS]:
    """DNS lookups hang (until the test is over)."""
    hung_dns = HungDNS()
    monkeypatch.setattr(socket, "getaddrinfo", hung_dns)
    yield hung_dns
    hung_dns.released.set()


@pytest.fixture(name="held_headers")
def _held_headers(monkeypatch: pytest.MonkeyPatch) -> Iterator[HeldHeaders]:
    """A fetch's first response holds its thread once read (until the test is over)."""
    held_headers = HeldHeaders()
    monkeypatch.setattr(http.client.HTTPResponse, "getheader", held_headers)
    yield held_headers
    held_headers.released.set()


@pytest.fixture(name="old_key", scope="session")
def _old_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(name="new_key", scope="session")
def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(name="old_token")
def _old_token(old_key: ec.EllipticCurvePrivateKey) -> str:
    return jwt.encode({"sub": "old"}, old_key, algorithm="ES256", headers={"kid": "old"})


@pytest.fixture(name="new_token")
def _new_token(new_key: ec.EllipticCurvePrivateKey) -> str:
    return jwt.encode({"sub": "new"}, new_key, algorithm="ES256", headers={"kid": "new"})


@pytest.fixture(name="runner")
def _runner() -> Iterator[asyncio.Runner]:
    with asyncio.Runner() as runner:
        yield runner


@pytest.fixture(name="kind", params=["sync", "async"])
def _kind(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(name="make_client")
def _make_client(kind: str, runner: asyncio.Runner) -> MakeClient:
    return _ClientMaker(kind, runner)


def test_fetches_once_on_first_decode(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url).decode
    assert server.requests == 0

    assert decode(old_token) == {"sub": "old"}
    assert decode(old_token) == {"sub": "old"}
    assert decode(old_token) == {"sub": "old"}
    assert server.requests == 1


def test_fetches_say_they_are_from_ryjwt(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    """Not urllib's default `Python-urllib/3.x`, which some firewalls (e.g. Cloudflare's) refuse."""
    server.serve(make_jwk(old_key, kid="old"))
    make_client(server.url).decode(old_token)

    [headers] = server.request_headers
    assert headers["user-agent"] == f"ryjwt/{importlib.metadata.version('ryjwt')}"


@pytest.mark.parametrize(
    ("cache_control", "age", "lifetime", "policy"),
    # Without a cooldown, which fetched keys would otherwise stay fresh for at least.
    [
        pytest.param("max-age=1", None, 1, {"cooldown": 0, "min_cache_lifetime": 0}, id="max-age"),
        pytest.param(
            "public, max-age=0, must-revalidate",
            None,
            0.5,
            {"cooldown": 0, "min_cache_lifetime": 0.5},
            id="clamped-to-min",
        ),
        pytest.param(
            "max-age=3600",
            None,
            0.5,
            {"cooldown": 0, "min_cache_lifetime": 0, "max_cache_lifetime": 0.5},
            id="clamped-to-max",
        ),
        pytest.param(
            "max-age=3601",
            "3600",
            1,
            {"cooldown": 0, "min_cache_lifetime": 0},
            id="max-age-less-age",
        ),
        pytest.param(
            "max-age=3600",
            "7200",
            0.5,
            {"cooldown": 0, "min_cache_lifetime": 0.5},
            id="age-over-max-age",
        ),
        pytest.param(
            "max-age=1", "x", 1, {"cooldown": 0, "min_cache_lifetime": 0}, id="invalid-age"
        ),
        pytest.param(None, None, 0.5, {"cooldown": 0, "cache_lifetime": 0.5}, id="no-header"),
        pytest.param(
            None, "3600", 0.5, {"cooldown": 0, "cache_lifetime": 0.5}, id="age-without-max-age"
        ),
        pytest.param(
            "no-cache", None, 0.5, {"cooldown": 0, "cache_lifetime": 0.5}, id="no-max-age"
        ),
        pytest.param(
            "max-age=x", None, 0.5, {"cooldown": 0, "cache_lifetime": 0.5}, id="invalid-max-age"
        ),
        # The same lifetimes as timedeltas.
        pytest.param(
            None,
            None,
            0.5,
            {"cooldown": 0, "cache_lifetime": timedelta(seconds=0.5)},
            id="no-header-timedelta",
        ),
        pytest.param(
            "max-age=0",
            None,
            0.5,
            {"cooldown": 0, "min_cache_lifetime": timedelta(seconds=0.5)},
            id="clamped-to-min-timedelta",
        ),
        pytest.param(
            "max-age=3600",
            None,
            0.5,
            {
                "cooldown": 0,
                "min_cache_lifetime": timedelta(0),
                "max_cache_lifetime": timedelta(seconds=0.5),
            },
            id="clamped-to-max-timedelta",
        ),
    ],
)
def test_cache_lifetime(
    cache_control: str | None,
    age: str | None,
    lifetime: float,
    policy: Policy,
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.cache_control = cache_control
    server.age = age
    decode = make_client(server.url, **policy).decode

    decode(old_token)
    time.sleep(lifetime / 2)
    decode(old_token)
    assert server.requests == 1
    time.sleep(lifetime / 2 + 0.05)
    assert decode(old_token) == {"sub": "old"}  # expired: refreshes in the background
    assert decode(old_token) == {"sub": "old"}
    eventually(partial(server.answered, 2))
    assert server.requests == 2


def test_zero_cache_lifetime(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url, cache_lifetime=timedelta(0), cooldown=timedelta(0)).decode

    decode(old_token)
    decode(old_token)  # expired at once (without a cooldown): refreshes in the background
    eventually(partial(server.answered, 2))
    assert server.requests == 2


def test_zero_cache_lifetime_fetches_once_per_cooldown(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    """Fetched keys stay fresh for at least `cooldown`: a zero lifetime can't make every decode
    refetch."""
    server.serve(make_jwk(old_key, kid="old"))
    server.cache_control = "max-age=0"
    decode = make_client(server.url, min_cache_lifetime=0, cooldown=0.3).decode

    # Decoding all along: the refresh comes no sooner than a cooldown after the first fetch...
    start = time.monotonic()
    while server.requests < 2:
        assert time.monotonic() - start < 5, "no refresh within 5 s"
        assert decode(old_token) == {"sub": "old"}
        time.sleep(0.002)
    assert time.monotonic() - start >= 0.3
    # ...and the refreshed keys stay fresh for a cooldown too, however many decodes.
    refreshed = time.monotonic()
    while time.monotonic() - refreshed < 0.2:
        assert decode(old_token) == {"sub": "old"}
        time.sleep(0.002)
    assert server.requests == 2


@pytest.mark.parametrize(
    "max_age",
    [pytest.param("9" * 5000, id="5000-digits"), pytest.param("9" * 11, id="11-digits")],
)
def test_huge_max_age(
    max_age: str,
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    """A max-age past 2**31 counts as 2**31 (RFC 9111 §1.2.2), however many digits it has (`int()`
    raises past 4300): clamped to `max_cache_lifetime`."""
    server.serve(make_jwk(old_key, kid="old"))
    server.cache_control = f"max-age={max_age}"
    caller = make_client(server.url, min_cache_lifetime=0, max_cache_lifetime=0.5, cooldown=0)

    assert caller.decode(old_token) == {"sub": "old"}
    assert _refreshed(caller.client)
    time.sleep(0.55)
    assert not _refreshed(caller.client)
    assert caller.decode(old_token) == {"sub": "old"}  # expired: refreshes in the background
    eventually(partial(_refreshed, caller.client))
    caller.refresh()  # fetches again: no fetch is stuck in flight
    assert server.requests == 3


def test_huge_age_in_a_background_refresh(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    """An `Age` too long for `int()` makes the keys a background refresh fetched expire at once
    (clamped to `min_cache_lifetime`), and the client goes on refreshing."""
    server.serve(make_jwk(old_key, kid="old"))
    caller = make_client(server.url, cache_lifetime=0.5, min_cache_lifetime=0.5, cooldown=0)
    caller.decode(old_token)
    server.cache_control, server.age = "max-age=60", "1" * 5000
    time.sleep(0.55)

    assert caller.decode(old_token) == {"sub": "old"}  # expired: refreshes in the background
    eventually(partial(_refreshed, caller.client))
    assert server.requests == 2
    server.cache_control = server.age = None
    time.sleep(0.55)
    assert caller.decode(old_token) == {"sub": "old"}  # expired again: refreshes again
    eventually(partial(server.answered, 3))
    eventually(partial(_refreshed, caller.client))


def test_key_rotation(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    new_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url, cache_lifetime=0.1, cooldown=0).decode
    assert decode(old_token) == {"sub": "old"}

    # The provider publishes the new key next to the old one: a new-kid token refetches.
    server.serve(make_jwk(old_key, kid="old"), make_jwk(new_key, kid="new"))
    assert decode(new_token) == {"sub": "new"}
    assert decode(old_token) == {"sub": "old"}
    assert decode(new_token) == {"sub": "new"}
    assert server.requests == 2

    # Then retires the old key: once the cache expires and is refreshed, old-kid tokens are unknown.
    server.serve(make_jwk(new_key, kid="new"))
    server.cache_control = "max-age=3600"  # the refreshed keys stay fresh for the rest of the test
    assert decode(old_token) == {"sub": "old"}
    time.sleep(0.15)
    assert decode(new_token) == {"sub": "new"}  # expired: refreshes in the background
    eventually(partial(server.answered, 3))
    assert server.requests == 3

    # Once the client has taken the refreshed keys.
    eventually(partial(_raises, ryjwt.UnknownKeyError, decode, old_token))
    assert server.requests == 4  # the unknown kid refetched (no cooldown), to no avail
    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "old"'):
        decode(old_token)


@pytest.mark.parametrize("cooldown", [0.2, timedelta(seconds=0.2)], ids=["seconds", "timedelta"])
def test_unknown_kid_cooldown(
    cooldown: float | timedelta,
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    new_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url, cooldown=cooldown).decode
    decode(old_token)
    server.serve(make_jwk(old_key, kid="old"), make_jwk(new_key, kid="new"))

    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "new"'):
        decode(new_token)
    assert server.requests == 1
    time.sleep(0.25)
    assert decode(new_token) == {"sub": "new"}
    assert server.requests == 2
    other_token = jwt.encode({}, new_key, algorithm="ES256", headers={"kid": "other-kid"})
    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "other-kid"'):
        decode(other_token)
    assert server.requests == 2


@pytest.mark.parametrize("outage", ["status-500", "invalid-json", "private-key"])
def test_outage_keeps_the_cached_keys(
    outage: str,
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_token: str,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url, cache_lifetime=0.2, cooldown=0.2).decode
    decode(old_token)
    match outage:
        case "status-500":
            server.status = 500
        case "invalid-json":
            server.body = b"{"
        case _:
            server.serve(make_jwk(old_key, kid="old", d="AQAB"))

    time.sleep(0.25)
    assert decode(old_token) == {"sub": "old"}  # expired: refreshes in the background
    eventually(partial(server.received, 2))
    assert server.requests == 2
    assert decode(old_token) == {"sub": "old"}  # the refresh fails: stale keys
    with pytest.raises(ryjwt.UnknownKeyError):
        decode(new_token)
    assert server.requests == 2  # no retry within the cooldown, expiry or unknown kid alike
    time.sleep(0.3)
    assert decode(old_token) == {"sub": "old"}
    eventually(partial(server.received, 3))
    assert server.requests == 3


def test_stale_keys_are_dropped_after_max_stale(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url, cache_lifetime=0.05, max_stale=0.5, cooldown=0.05).decode
    decode(old_token)
    server.status = 500
    time.sleep(0.1)
    assert decode(old_token) == {"sub": "old"}  # expired under max_stale ago: still used

    eventually(partial(_raises, ryjwt.JWKSFetchError, decode, old_token))
    # No more stale keys, even within the cooldown.
    with pytest.raises(
        ryjwt.JWKSFetchError,
        match=r"HTTP status 500 \(and the cached keys expired over max_stale ago\)",
    ):
        decode(old_token)

    server.status = 200
    eventually(partial(_decodes, decode, old_token))


def test_recovers_after_an_outage(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    new_token: str,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url, cache_lifetime=0.05, cooldown=0.05).decode
    decode(old_token)
    server.status = 503
    time.sleep(0.1)
    decode(old_token)  # expired: refreshes in the background, and that fails
    eventually(partial(server.answered, 2))

    server.status = 200
    server.serve(make_jwk(new_key, kid="new"))
    time.sleep(0.15)
    # The unknown kid waits for the refresh (joining the one just started in the background).
    assert decode(new_token) == {"sub": "new"}
    assert server.requests == 3


@pytest.mark.parametrize(
    ("outage", "cause", "match"),
    [
        pytest.param("status-500", None, "HTTP status 500", id="status-500"),
        pytest.param("invalid-json", ryjwt.InvalidKeyError, "Invalid JWKS JSON", id="invalid-json"),
        pytest.param(
            "private-key", ryjwt.InvalidKeyError, "holds private key material", id="private-key"
        ),
        pytest.param("no-usable-key", ryjwt.InvalidKeyError, "no key usable", id="no-usable-key"),
        pytest.param("only-unusable-keys", ryjwt.InvalidKeyError, "no key usable", id="unusable"),
        pytest.param(
            "duplicate-kid", ryjwt.InvalidKeyError, 'Several JWKS keys have kid "old"', id="dup-kid"
        ),
        pytest.param(
            "bad-status-line", http.client.BadStatusLine, "BadStatusLine", id="bad-status-line"
        ),
    ],
)
def test_first_fetch_fails(
    outage: str,
    cause: type[Exception] | None,
    match: str,
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    match outage:
        case "status-500":
            server.status = 500
        case "invalid-json":
            server.body = b"{"
        case "private-key":
            server.serve(make_jwk(old_key, kid="old", d="AQAB"))
        case "no-usable-key":
            server.serve()
        case "only-unusable-keys":
            malformed = {"kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
            server.serve(make_jwk(old_key, kid="old", use="enc"), malformed)
        case "duplicate-kid":
            server.serve(make_jwk(old_key, kid="old"), make_jwk(old_key, kid="old", use="sig"))
        case _:
            server.raw = b"not-http\r\n"
    decode = make_client(server.url, cooldown=0.2).decode

    with pytest.raises(ryjwt.JWKSFetchError, match=f"from {server.origin}: .*{match}") as error:
        decode(old_token)
    if cause is None:
        assert error.value.__cause__ is None
    else:
        assert isinstance(error.value.__cause__, cause)
    # Within the cooldown, the same error again, without a request.
    with pytest.raises(ryjwt.JWKSFetchError, match=match):
        decode(old_token)
    assert server.requests == 1

    server.status, server.raw = 200, None
    server.serve(make_jwk(old_key, kid="old"))
    time.sleep(0.25)
    assert decode(old_token) == {"sub": "old"}
    assert server.requests == 2


def test_connection_refused(make_client: MakeClient, old_token: str) -> None:
    with LocalHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler) as closed:
        port = closed.server_port
    decode = make_client(f"http://127.0.0.1:{port}/jwks").decode

    with pytest.raises(ryjwt.JWKSFetchError, match="ConnectionRefusedError") as error:
        decode(old_token)
    assert isinstance(error.value.__cause__, URLError)
    assert isinstance(error.value.__cause__.reason, ConnectionRefusedError)


def _dribbled_fetch_times_out(server: JWKSServer, token: str) -> None:
    """`test_fetch_deadline`, for one server."""
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    start = time.monotonic()
    with pytest.raises(ryjwt.JWKSFetchError) as error:
        client.decode(token)
    assert 2.45 <= time.monotonic() - start < 3  # 50 ms slack for Windows' coarse clock
    message = f"Couldn't fetch the JWKS from {server.origin}: TimeoutError: timed out"
    assert str(error.value) == message
    assert isinstance(error.value.__cause__, TimeoutError)
    with pytest.raises(ryjwt.JWKSFetchError, match="TimeoutError"):
        client.decode(token)  # within the cooldown, without a request
    assert server.requests == 1
    # The fetch's thread gives up at its deadline too: the server sees it hang up well before it
    # has sent everything (4 s).
    eventually(partial(server.answered, 1), timeout=1)


def test_fetch_deadline(server: JWKSServer, second_server: JWKSServer, old_token: str) -> None:
    """A fetch has 2.5 s in all: a server sending a byte every 0.2 s can't hold it open longer,
    whether it's sending the headers or the body (both at once, to share the wait)."""
    server.raw, server.dribbled = b"HTTP/1.0 200 OK\r\n", b"Age: 1\r\n" * 20
    second_server.raw = b"HTTP/1.0 200 OK\r\nContent-Length: 20\r\n\r\n"
    second_server.dribbled = b"x" * 20

    with ThreadPoolExecutor(max_workers=2) as pool:
        for done in [
            pool.submit(_dribbled_fetch_times_out, s, old_token) for s in (server, second_server)
        ]:
            done.result()


def _fetch_hung_in_dns_times_out(caller: Caller, token: str) -> None:
    """`test_fetch_deadline_covers_dns`, for one caller."""
    start = time.monotonic()
    with pytest.raises(ryjwt.JWKSFetchError) as error:
        caller.decode(token)
    assert 2.45 <= time.monotonic() - start < 3  # 50 ms slack for Windows' coarse clock
    message = "Couldn't fetch the JWKS from https://issuer: TimeoutError: timed out"
    assert str(error.value) == message
    assert isinstance(error.value.__cause__, TimeoutError)
    start = time.monotonic()
    with pytest.raises(ryjwt.JWKSFetchError, match="TimeoutError"):
        caller.decode(token)  # within the cooldown: at once, without another fetch
    assert time.monotonic() - start < 0.1


def test_fetch_deadline_covers_dns(
    hung_dns: HungDNS,
    runner: asyncio.Runner,
    old_token: str,
) -> None:
    """Callers stop waiting 2.5 s after the fetch started, though its thread is stuck in a DNS
    lookup; the fetch then counts as failed, so the cooldown applies. A sync and an async caller,
    each with a client of its own, at once (to share the wait)."""
    callers = [_ClientMaker(kind, runner)("https://issuer/jwks") for kind in ("sync", "async")]

    with ThreadPoolExecutor(max_workers=2) as pool:
        for done in [pool.submit(_fetch_hung_in_dns_times_out, c, old_token) for c in callers]:
            done.result()
    assert hung_dns.hosts == ["issuer", "issuer"]


def _outlives_a_hung_refresh(caller: Caller, old_token: str, new_token: str) -> None:
    """`test_background_refresh_past_its_deadline`, for one caller, once its keys expired."""
    start = time.monotonic()
    assert caller.decode(old_token) == {
        "sub": "old"
    }  # expired: refreshes in the background, and hangs
    with pytest.raises(ryjwt.UnknownKeyError):
        caller.decode(new_token)  # waits for the refresh, until its deadline
    assert 2.45 <= time.monotonic() - start < 3  # 50 ms slack for Windows' coarse clock
    # The keys are now over max_stale out of date, and within the cooldown: no fetch, at once.
    start = time.monotonic()
    with pytest.raises(ryjwt.JWKSFetchError, match="TimeoutError: timed out") as error:
        caller.decode(old_token)
    assert time.monotonic() - start < 0.5
    assert isinstance(error.value.__cause__, TimeoutError)


def test_background_refresh_past_its_deadline(
    server: JWKSServer,
    runner: asyncio.Runner,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    new_token: str,
    request: pytest.FixtureRequest,
) -> None:
    """A background refresh stuck in a DNS lookup: an unknown `kid` joins it, and stops waiting
    2.5 s after it started. It then counts as failed (timed out), so the cooldown applies. A sync
    and an async caller, each with a client of its own, at once (to share the wait)."""
    server.serve(make_jwk(old_key, kid="old"))
    callers = [
        _ClientMaker(kind, runner)(server.url, cache_lifetime=1, max_stale=0.5, cooldown=1)
        for kind in ("sync", "async")
    ]
    for caller in callers:
        caller.decode(old_token)
    hung_dns: HungDNS = request.getfixturevalue("hung_dns")
    time.sleep(1.05)

    with ThreadPoolExecutor(max_workers=2) as pool:
        for done in [
            pool.submit(_outlives_a_hung_refresh, c, old_token, new_token) for c in callers
        ]:
            done.result()
    assert hung_dns.hosts == ["127.0.0.1", "127.0.0.1"]
    assert server.requests == 2


def test_keys_read_after_the_deadline_are_used(
    server: JWKSServer,
    held_headers: HeldHeaders,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    """A fetch that read its response in time, but got the keys only once its deadline had passed
    and its caller had given up on it: they're used all the same, rather than dropped (leaving
    the client without keys until the cooldown is over)."""
    server.serve(make_jwk(old_key, kid="old"))
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    with pytest.raises(ryjwt.JWKSFetchError, match="TimeoutError: timed out"):
        client.decode(old_token)  # the fetch's thread is held, once it has read the response
    assert held_headers.held.is_set()
    held_headers.released.set()

    eventually(partial(_decodes, client.decode, old_token))
    assert not client.needs_refresh
    assert server.requests == 1


def test_decode_reads_keys_and_their_expiry_from_one_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keys over `max_stale` out of date are never used, even when a refresh lands just as a decode
    looks at them: the decode doesn't take the stale keys with the refreshed keys' expiry."""
    server.serve(make_jwk(old_key, kid="old"))
    client = ryjwt.JWKSClient(
        server.url, algorithms=["ES256"], cache_lifetime=0.05, max_stale=0, cooldown=0
    )
    client.refresh()
    server.serve(make_jwk(new_key, kid="new"))  # the provider drops the old key
    time.sleep(0.1)  # the old key is over max_stale out of date
    clock = RefreshOnClockRead(time.monotonic)
    monkeypatch.setattr(time, "monotonic", clock)

    clock.arm(client)  # the decode's first look at the clock refreshes, to the new key only
    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "old"'):
        client.decode(old_token)


@pytest.mark.parametrize("jwks_server", ["server", "ipv6_server"])
def test_http_urls_never_go_through_a_proxy(
    jwks_server: str,
    proxy: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    request: pytest.FixtureRequest,
) -> None:
    """An http:// URL is to this machine: a proxy mustn't stand in for it."""
    local: JWKSServer = request.getfixturevalue(jwks_server)
    local.serve(make_jwk(old_key, kid="old"))

    assert make_client(local.url).decode(old_token) == {"sub": "old"}
    assert local.requests == 1
    assert proxy.requests == 0


def test_https_urls_go_through_the_proxy(
    proxy: JWKSServer,
    make_client: MakeClient,
    old_token: str,
) -> None:
    with pytest.raises(ryjwt.JWKSFetchError, match="Tunnel connection failed: 403"):
        make_client("https://issuer/jwks").decode(old_token)
    assert proxy.requests == 1


def test_tls_certificates_are_verified(
    tls_server: JWKSServer,
    tls_cert: tuple[Path, Path],
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tls_server.serve(make_jwk(old_key, kid="old"))

    with pytest.raises(ryjwt.JWKSFetchError, match="SSLCertVerificationError") as error:
        make_client(tls_server.url).decode(old_token)
    assert isinstance(error.value.__cause__, URLError)
    assert isinstance(error.value.__cause__.reason, ssl.SSLCertVerificationError)
    # Once the certificate is trusted, as the default SSL context's SSL_CERT_FILE can make it.
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_cert[0]))
    assert make_client(tls_server.url).decode(old_token) == {"sub": "old"}


def test_fetched_keys_that_cant_be_used_are_skipped(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    small_rsa_key: rsa.RSAPrivateKey,
    old_token: str,
) -> None:
    identity = base64.urlsafe_b64encode(b"\x01" + bytes(31)).rstrip(b"=").decode()
    jwks = {
        "keys": [
            make_jwk(new_key, kid="old", use="enc"),  # shares its kid with the signing key below
            make_jwk(new_key, kid="other-use", use="other-use"),
            make_jwk(new_key, kid="other-alg", alg="ES384"),
            make_jwk(small_rsa_key, kid="small-rsa"),
            {"kty": "EC", "crv": "P-256", "kid": "malformed", "x": "AQAB", "y": "AQAB"},
            {"kty": "OKP", "crv": "Ed25519", "kid": "small-order", "x": identity},
            {"kty": "EC", "kid": 1},
            "not-an-object",
            make_jwk(old_key, kid="old", use="sig"),
        ]
    }
    server.body = json.dumps(jwks).encode()
    decode = make_client(server.url, algorithms=["ES256", "RS256", "EdDSA"]).decode

    assert decode(old_token) == {"sub": "old"}
    # `PublicKey.from_jwks` is strict: the same document is rejected.
    with pytest.raises(ryjwt.InvalidKeyError, match="2048 to 8192 bits"):
        ryjwt.PublicKey.from_jwks(server.body, algorithms=["ES256", "RS256", "EdDSA"])


def test_redirects_are_not_followed(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.redirect = "/moved"
    decode = make_client(server.url).decode

    with pytest.raises(ryjwt.JWKSFetchError, match="HTTP status 302"):
        decode(old_token)
    assert server.requests == 1


def test_fetch_errors_leave_the_url_secrets_out(
    server: JWKSServer,
    make_client: MakeClient,
    old_token: str,
) -> None:
    server.status = 500
    url = server.url + "?token=s3cret#fragment"
    decode = make_client(url).decode

    with pytest.raises(ryjwt.JWKSFetchError) as error:
        decode(old_token)
    assert str(error.value) == f"Couldn't fetch the JWKS from {server.origin}: HTTP status 500"


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        pytest.param(
            "http://user:password@issuer/jwks?token=s3cret", "http://issuer", id="userinfo"
        ),
        # A password holding /, ? or # ends the authority early: nothing of it is shown.
        pytest.param("https://user:pass/word@issuer/jwks", "an invalid URL", id="slash"),
        pytest.param("https://user:pass?word@issuer/jwks", "an invalid URL", id="question-mark"),
        pytest.param("https://user:pass#word@issuer/jwks", "an invalid URL", id="hash"),
        pytest.param("https://issuer:port/jwks", "an invalid URL", id="invalid-port"),
    ],
)
def test_invalid_url_errors_leave_the_url_secrets_out(url: str, shown: str) -> None:
    with pytest.raises(ValueError, match="url must be https://") as error:
        ryjwt.JWKSClient(url, algorithms=["ES256"])
    assert str(error.value).endswith(f", got {shown}")


def test_fetch_error_is_not_an_invalid_token_error() -> None:
    assert issubclass(ryjwt.JWKSFetchError, ryjwt.RYJWTError)
    assert not issubclass(ryjwt.JWKSFetchError, ryjwt.InvalidTokenError)


def test_concurrent_decodes_share_one_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.delay = 0.1
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(client.decode, [old_token] * 16))

    assert results == [{"sub": "old"}] * 16
    assert server.requests == 1


def test_concurrent_adecodes_share_one_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.delay = 0.1
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    assert asyncio.run(_adecode_all(client, old_token, 16)) == [{"sub": "old"}] * 16
    assert server.requests == 1


def test_cancelled_adecode_does_not_cancel_the_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.delay = 0.1
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    assert asyncio.run(_cancel_one(client, server, old_token)) == {"sub": "old"}
    assert server.requests == 1


def test_cached_adecode_never_suspends(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    runner: asyncio.Runner,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])
    runner.run(client.adecode(old_token))

    # Outside any event loop: the coroutine finishes on its first step.
    with pytest.raises(StopIteration) as done:
        client.adecode(old_token).send(None)
    assert done.value.value == {"sub": "old"}


def test_one_fetch_across_event_loops(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.delay = 0.1
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])
    start = threading.Barrier(2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_adecode_all_on_own_loop, client, old_token, start) for _ in range(2)
        ]
        results = [future.result() for future in futures]

    assert results == [[{"sub": "old"}] * 20] * 2
    assert server.requests == 1


def test_sync_and_async_callers_share_one_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    """One client, used from sync code in threads and from async code on an event loop at once."""
    server.serve(make_jwk(old_key, kid="old"))
    server.delay = 0.2
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])
    start = threading.Barrier(3)

    with ThreadPoolExecutor(max_workers=3) as pool:
        decoded = [pool.submit(_decode_after, client, old_token, start) for _ in range(2)]
        adecoded = pool.submit(_adecode_all_on_own_loop, client, old_token, start)
        results = [future.result() for future in decoded]

    assert results == [{"sub": "old"}] * 2
    assert adecoded.result() == [{"sub": "old"}] * 20
    assert server.requests == 1


def test_refreshes_with_an_event_loop_per_request(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    new_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"], cache_lifetime=0.2, cooldown=0.2)
    assert asyncio.run(client.adecode(old_token)) == {"sub": "old"}
    server.serve(make_jwk(new_key, kid="new"))
    time.sleep(0.25)

    # Each `asyncio.run` ends its event loop as soon as the decode returns; the refresh it started
    # in the background runs on a thread of its own, so it lands all the same.
    assert asyncio.run(client.adecode(old_token)) == {"sub": "old"}  # expired: refreshes
    eventually(partial(server.answered, 2))
    assert asyncio.run(client.adecode(new_token)) == {"sub": "new"}
    with pytest.raises(ryjwt.UnknownKeyError):
        asyncio.run(client.adecode(old_token))  # the old key is gone (no refetch: cooldown)
    assert server.requests == 2


def test_expired_keys_refresh_without_blocking(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    new_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    decode = make_client(server.url, cache_lifetime=0.05, cooldown=0).decode
    decode(old_token)
    server.serve(make_jwk(old_key, kid="old"), make_jwk(new_key, kid="new"))
    server.cache_control = "max-age=3600"  # the refreshed keys stay fresh for the rest of the test
    server.delay = 0.5
    time.sleep(0.1)

    # Expired keys: decodes don't wait for the slow refresh, and share it.
    start = time.monotonic()
    for _ in range(20):
        assert decode(old_token) == {"sub": "old"}
    assert time.monotonic() - start < 0.25
    eventually(partial(server.answered, 2))
    assert server.requests == 2

    # The refreshed keys are in use: the new kid verifies without another request.
    server.delay = 0
    assert decode(new_token) == {"sub": "new"}
    assert server.requests == 2


def test_needs_refresh(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    caller = make_client(server.url, cache_lifetime=0.1, cooldown=0)
    needs_refresh = [caller.client.needs_refresh]  # before the first fetch

    caller.refresh()
    needs_refresh.append(caller.client.needs_refresh)
    time.sleep(0.15)
    needs_refresh.append(caller.client.needs_refresh)  # expired
    assert needs_refresh == [True, False, True]
    assert caller.decode(old_token) == {"sub": "old"}  # refreshes in the background
    eventually(partial(_refreshed, caller.client))
    assert server.requests == 2


def test_refresh_fetches(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    caller = make_client(server.url)

    caller.refresh()
    assert server.requests == 1
    assert caller.client.decode_nowait(old_token) == {"sub": "old"}
    caller.refresh()  # fetches again, fresh keys or not
    assert server.requests == 2


def test_concurrent_refreshes_share_one_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.delay = 0.1
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    with ThreadPoolExecutor(max_workers=16) as pool:
        for future in [pool.submit(client.refresh) for _ in range(16)]:
            future.result()

    assert server.requests == 1
    assert client.decode_nowait(old_token) == {"sub": "old"}


def test_concurrent_arefreshes_share_one_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    server.delay = 0.1
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    asyncio.run(_arefresh_all(client, 16))

    assert server.requests == 1
    assert client.decode_nowait(old_token) == {"sub": "old"}


def test_refresh_without_usable_keys_raises_and_respects_the_cooldown(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.body = b"{"
    caller = make_client(server.url, cooldown=0.2)

    with pytest.raises(ryjwt.JWKSFetchError, match="Invalid JWKS JSON") as error:
        caller.refresh()
    assert isinstance(error.value.__cause__, ryjwt.InvalidKeyError)
    with pytest.raises(ryjwt.JWKSFetchError, match="Invalid JWKS JSON"):
        caller.refresh()  # within the cooldown: the same error, without a request
    with pytest.raises(ryjwt.JWKSFetchError, match="Invalid JWKS JSON"):
        caller.client.decode_nowait(old_token)
    assert server.requests == 1
    assert caller.client.needs_refresh

    server.serve(make_jwk(old_key, kid="old"))
    time.sleep(0.25)
    caller.refresh()
    assert server.requests == 2
    assert caller.client.decode_nowait(old_token) == {"sub": "old"}


def test_refresh_keeps_stale_keys_during_an_outage(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    caller = make_client(server.url, cache_lifetime=0.2, cooldown=0.2)
    caller.refresh()
    server.status = 500
    time.sleep(0.25)

    caller.refresh()  # fails, but the expired keys are still usable: no error
    assert server.requests == 2
    assert caller.client.needs_refresh
    assert caller.client.decode_nowait(old_token) == {"sub": "old"}
    caller.refresh()  # within the cooldown: no request, no error
    assert server.requests == 2


def test_refresh_raises_once_the_keys_are_over_max_stale(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    caller = make_client(server.url, cache_lifetime=0.05, max_stale=0.1, cooldown=0)
    caller.refresh()
    server.status = 500
    time.sleep(0.2)

    with pytest.raises(
        ryjwt.JWKSFetchError,
        match=r"HTTP status 500 \(and the cached keys expired over max_stale ago\)",
    ):
        caller.refresh()
    with pytest.raises(ryjwt.JWKSFetchError, match="HTTP status 500"):
        caller.client.decode_nowait(old_token)
    assert server.requests == 2


def test_decode_nowait_before_the_first_fetch(
    server: JWKSServer,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256"])

    message = f"No keys fetched from {server.origin} yet: call refresh() first"
    with pytest.raises(ryjwt.JWKSFetchError, match=re.escape(message)) as error:
        client.decode_nowait(old_token)
    assert error.value.__cause__ is None
    assert server.requests == 0


def test_decode_nowait_does_not_refetch_for_an_unknown_kid(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    new_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    caller = make_client(server.url, cooldown=0)
    caller.refresh()
    server.serve(make_jwk(old_key, kid="old"), make_jwk(new_key, kid="new"))

    with pytest.raises(ryjwt.UnknownKeyError, match='No key has kid "new"'):
        caller.client.decode_nowait(new_token)
    assert caller.client.decode_nowait(old_token) == {"sub": "old"}
    assert server.requests == 1


def test_decode_nowait_uses_expired_keys_until_max_stale(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    old_token: str,
) -> None:
    server.serve(make_jwk(old_key, kid="old"))
    # Wide enough that a slow CI runner's sleep(0.1) doesn't overshoot max_stale.
    caller = make_client(server.url, cache_lifetime=0.05, max_stale=0.5, cooldown=0)
    caller.refresh()
    time.sleep(0.1)

    assert caller.client.needs_refresh
    assert caller.client.decode_nowait(old_token) == {"sub": "old"}  # expired, not over max_stale
    time.sleep(0.5)
    message = f"The keys from {server.origin} expired over max_stale ago: call refresh()"
    with pytest.raises(ryjwt.JWKSFetchError, match=re.escape(message)):
        caller.client.decode_nowait(old_token)
    assert server.requests == 1  # never fetched

    caller.refresh()
    assert caller.client.decode_nowait(old_token) == {"sub": "old"}
    assert server.requests == 2


def test_manual_refresh_through_rotation_and_outage(
    server: JWKSServer,
    make_client: MakeClient,
    old_key: ec.EllipticCurvePrivateKey,
    new_key: ec.EllipticCurvePrivateKey,
    old_token: str,
    new_token: str,
) -> None:
    """The manual pattern: `if client.needs_refresh: client.refresh()`, then `decode_nowait`."""
    server.serve(make_jwk(old_key, kid="old"))
    caller = make_client(server.url, cache_lifetime=0.1, cooldown=0.1)
    assert caller.decode_manually(old_token) == {"sub": "old"}
    assert caller.decode_manually(old_token) == {"sub": "old"}
    assert server.requests == 1

    # The provider rotates its key: the new kid is unknown until the keys expire and are refreshed.
    server.serve(make_jwk(new_key, kid="new"))
    with pytest.raises(ryjwt.UnknownKeyError):
        caller.decode_manually(new_token)
    time.sleep(0.15)
    assert caller.decode_manually(new_token) == {"sub": "new"}
    with pytest.raises(ryjwt.UnknownKeyError):
        caller.decode_manually(old_token)
    assert server.requests == 2

    # An outage: refreshing fails, the expired keys stay in use, and the cooldown applies.
    server.status = 500
    time.sleep(0.15)
    assert caller.decode_manually(new_token) == {"sub": "new"}
    assert caller.decode_manually(new_token) == {"sub": "new"}
    assert server.requests == 3

    # Recovered: the first round after the cooldown refreshes.
    server.status = 200
    time.sleep(0.25)
    assert caller.decode_manually(new_token) == {"sub": "new"}
    assert server.requests == 4
    assert not caller.client.needs_refresh


@pytest.mark.parametrize(
    "url",
    [
        "https://issuer/jwks",
        "HTTPS://issuer/jwks",
        "http://localhost/jwks",
        "http://localhost:8080/jwks",
        "http://127.0.0.1:8080/jwks",
        "http://[::1]:8080/jwks",
        "http://[::1]/jwks",
        "http://LOCALHOST/jwks",
        "https://issuer/jwks?query=query#fragment",
        "https://issuer:8443/jwks",
        "https://[2001:db8::1]:8443/jwks",
    ],
)
def test_valid_urls(url: str) -> None:
    ryjwt.JWKSClient(url, algorithms=["ES256"])


@pytest.mark.parametrize(
    "url",
    [
        "http://issuer/jwks",
        "http://localhost.issuer/jwks",
        "ftp://issuer/jwks",
        "https://",
        "issuer/jwks",
        "",
        "https://user:password@issuer/jwks",
        "https://user@issuer/jwks",
        # urlsplit sees host localhost; urllib.request, which fetches it, evil.example\@localhost.
        "http://evil.example\\@localhost/jwks",
        "http://local%68ost/jwks",
        "http://localhost:8_0/jwks",
        "http://localhost:65536/jwks",
        "https://issuer/jw ks",
        "https://issuer/jwks\n",
        "https://issuer/jwks\x7f",
        "https://issuer/jwéks",
        "<https://issuer/jwks>",
        # Brackets around anything but an IPv6 address: http.client could never connect.
        "https://[::1/jwks",
        "https://[issuer]/jwks",
        "https://[::1]x/jwks",
        "https://issuer]/jwks",
        "https://localhost:99999999999999999999/jwks",
    ],
)
def test_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError, match="url must be https://"):
        ryjwt.JWKSClient(url, algorithms=["ES256"])


@pytest.mark.parametrize(
    ("policy", "error", "match"),
    [
        pytest.param({"cooldown": -1}, ValueError, "cooldown must not be negative", id="negative"),
        pytest.param(
            {"max_stale": -1}, ValueError, "max_stale must not be negative", id="negative-max-stale"
        ),
        pytest.param(
            {"cache_lifetime": timedelta(seconds=-1)},
            ValueError,
            "cache_lifetime must not be negative",
            id="negative-timedelta",
        ),
        pytest.param(
            {"min_cache_lifetime": math.nan}, ValueError, "must not be negative", id="nan"
        ),
        pytest.param(
            {"min_cache_lifetime": 10, "max_cache_lifetime": 5},
            ValueError,
            "min_cache_lifetime must not exceed max_cache_lifetime",
            id="min-over-max",
        ),
        pytest.param(
            {"cooldown": "30"},
            TypeError,
            "cooldown must be a number of seconds or a timedelta",
            id="str",
        ),
        pytest.param(
            {"max_stale": True},
            TypeError,
            "max_stale must be a number of seconds or a timedelta",
            id="bool",
        ),
        pytest.param(
            {"cache_lifetime": None},
            TypeError,
            "cache_lifetime must be a number of seconds or a timedelta",
            id="none",
        ),
        pytest.param(
            {"algorithms": ["HS256"]}, ValueError, "needs a SecretKey", id="hmac-algorithm"
        ),
        pytest.param({"algorithms": []}, ValueError, "must not be empty", id="no-algorithms"),
        pytest.param(
            {"audience": 1},
            TypeError,
            "audience must be a str or an iterable of str",
            id="audience",
        ),
        pytest.param(
            {"issuer": ["iss", 1]},
            TypeError,
            "issuer must be a str or an iterable of str",
            id="issuer-item",
        ),
    ],
)
def test_invalid_arguments(policy: dict[str, Any], error: type[Exception], match: str) -> None:
    untyped_caller: dict[str, Any] = {"algorithms": ["ES256"]} | policy  # as untyped callers could

    with pytest.raises(error, match=match):
        ryjwt.JWKSClient("https://issuer/jwks", **untyped_caller)


@pytest.mark.parametrize(
    "method", ["__init__", "refresh", "arefresh", "decode", "adecode", "decode_nowait"]
)
def test_signatures_resolve_at_runtime(method: str) -> None:
    """The names in the public signatures exist at runtime, for introspection."""
    function = getattr(ryjwt.JWKSClient, method)

    for signed in [function, *typing.get_overloads(function)]:
        assert inspect.signature(signed).parameters
        assert typing.get_type_hints(signed)
    assert "url" in inspect.signature(ryjwt.JWKSClient).parameters


@pytest.fixture(name="mixed_server")
def _mixed_server(
    server: JWKSServer,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
) -> JWKSServer:
    """Serves an RSA key ("rsa") and a P-256 key ("ec")."""
    server.serve(
        make_jwk(private_keys["RS256"], kid="rsa"),
        make_jwk(private_keys["ES256"], kid="ec"),
    )
    return server


@pytest.fixture(name="tokens")
def _tokens(
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    past: int,
) -> dict[str, str]:
    claims = {"sub": "sub", "aud": "aud", "iss": "iss"}
    rs256 = jwt.encode(claims, private_keys["RS256"], algorithm="RS256", headers={"kid": "rsa"})
    es256 = jwt.encode(claims, private_keys["ES256"], algorithm="ES256", headers={"kid": "ec"})
    expired = jwt.encode(
        {"exp": past}, private_keys["ES256"], algorithm="ES256", headers={"kid": "ec"}
    )
    return {"rs256": rs256, "es256": es256, "expired": expired}


def test_full_decode_api(mixed_server: JWKSServer, tokens: dict[str, str], past: int) -> None:
    claims = {"sub": "sub", "aud": "aud", "iss": "iss"}
    client = ryjwt.JWKSClient(mixed_server.url, algorithms=["RS256", "ES256"], cooldown=0)

    assert client.decode(tokens["rs256"], audience="aud", issuer="iss") == claims
    assert client.decode(tokens["es256"].encode(), audience=["aud"]) == claims
    assert client.decode(tokens["es256"], type=ClaimsStruct, audience="aud") == ClaimsStruct("sub")
    assert client.decode(tokens["rs256"], type=ClaimsModel, audience="aud") == ClaimsModel(
        sub="sub"
    )
    with pytest.raises(ryjwt.InvalidAudienceError):
        client.decode(tokens["es256"], audience="other-aud")
    with pytest.raises(ryjwt.InvalidIssuerError):
        client.decode(tokens["es256"], audience="aud", issuer="other-iss")
    with pytest.raises(ryjwt.ExpiredSignatureError):
        client.decode(tokens["expired"])
    assert client.decode(tokens["expired"], leeway=timedelta(hours=2)) == {"exp": past}
    with pytest.raises(ryjwt.ClaimsValidationError):
        client.decode(tokens["expired"], type=ClaimsStruct, leeway=timedelta(hours=2))
    with pytest.raises(ryjwt.DecodeError):
        client.decode("not-a-token")
    assert mixed_server.requests == 1  # invalid tokens never refetch, even without a cooldown


def test_full_adecode_api(mixed_server: JWKSServer, tokens: dict[str, str], past: int) -> None:
    client = ryjwt.JWKSClient(mixed_server.url, algorithms=["RS256", "ES256"], cooldown=0)

    asyncio.run(_check_adecode_api(client, tokens, past))
    assert mixed_server.requests == 1


def test_full_decode_nowait_api(
    mixed_server: JWKSServer,
    tokens: dict[str, str],
    past: int,
) -> None:
    claims = {"sub": "sub", "aud": "aud", "iss": "iss"}
    client = ryjwt.JWKSClient(mixed_server.url, algorithms=["RS256", "ES256"])
    client.refresh()

    assert client.decode_nowait(tokens["rs256"], audience="aud", issuer="iss") == claims
    assert client.decode_nowait(tokens["es256"].encode(), audience=["aud"]) == claims
    struct = client.decode_nowait(tokens["es256"], type=ClaimsStruct, audience="aud")
    assert struct == ClaimsStruct("sub")
    model = client.decode_nowait(tokens["rs256"], type=ClaimsModel, audience="aud")
    assert model == ClaimsModel(sub="sub")
    with pytest.raises(ryjwt.InvalidAudienceError):
        client.decode_nowait(tokens["es256"], audience="other-aud")
    with pytest.raises(ryjwt.InvalidIssuerError):
        client.decode_nowait(tokens["es256"], audience="aud", issuer="other-iss")
    with pytest.raises(ryjwt.ExpiredSignatureError):
        client.decode_nowait(tokens["expired"])
    assert client.decode_nowait(tokens["expired"], leeway=timedelta(hours=2)) == {"exp": past}
    with pytest.raises(ryjwt.DecodeError):
        client.decode_nowait("not-a-token")
    assert mixed_server.requests == 1


@pytest.mark.parametrize("method", ["decode", "adecode", "decode_nowait"])
def test_audience_and_issuer_set_on_the_client(
    method: str,
    mixed_server: JWKSServer,
    tokens: dict[str, str],
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    runner: asyncio.Runner,
) -> None:
    claims = {"sub": "sub", "aud": "aud", "iss": "iss"}
    without_iss = jwt.encode(
        {"aud": "aud"}, private_keys["ES256"], algorithm="ES256", headers={"kid": "ec"}
    )
    decode = _client_decode(mixed_server.url, method, runner, audience="aud", issuer=["x", "iss"])
    other = _client_decode(mixed_server.url, method, runner, audience="other", issuer="other")
    no_audience = _client_decode(mixed_server.url, method, runner, issuer="iss")

    assert decode(tokens["rs256"]) == claims
    assert decode(tokens["es256"]) == claims
    with pytest.raises(ryjwt.InvalidIssuerError, match="missing the iss claim"):
        decode(without_iss)
    with pytest.raises(ryjwt.InvalidAudienceError, match="Audience doesn't match"):
        other(tokens["es256"])
    with pytest.raises(ryjwt.InvalidIssuerError, match="Issuer doesn't match"):
        other(tokens["es256"], audience="aud")
    assert other(tokens["es256"], audience="aud", issuer="iss") == claims
    with pytest.raises(ryjwt.InvalidAudienceError, match="Audience doesn't match"):
        decode(tokens["es256"], audience="other")  # replaces the client's, rather than adding
    with pytest.raises(ryjwt.InvalidIssuerError, match="Issuer doesn't match"):
        decode(tokens["es256"], issuer="other")
    with pytest.raises(ryjwt.InvalidAudienceError, match="no audience was given"):
        no_audience(tokens["es256"])
    assert no_audience(tokens["es256"], audience="aud") == claims


def test_client_audience_and_issuer_accept_any_iterable(
    mixed_server: JWKSServer,
    tokens: dict[str, str],
) -> None:
    claims = {"sub": "sub", "aud": "aud", "iss": "iss"}
    client = ryjwt.JWKSClient(
        mixed_server.url,
        algorithms=["RS256", "ES256"],
        audience=(a for a in ["x", "aud"]),
        issuer=iter(["iss"]),
    )

    client.refresh()
    assert client.decode_nowait(tokens["es256"]) == claims
    client.refresh()  # the keys fetched again get the same audience and issuer
    assert client.decode_nowait(tokens["es256"]) == claims
    assert mixed_server.requests == 2
