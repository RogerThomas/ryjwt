"""What several test modules share: key and claim types, key encodings, and a local JWKS server.

Shared values that are costly to build (keys, PEMs) are fixtures, in conftest.py.
"""

import base64
import hashlib
import hmac
import json
import socket
import socketserver
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import msgspec
import pydantic
import ryjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

type SigningKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
type JWK = dict[str, Any]

ASYMMETRIC_ALGORITHMS: list[ryjwt.AsymmetricAlgorithm] = [
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "ES521",
    "EdDSA",
]
"""Every algorithm `PrivateKey` and `PublicKey` take."""


class ClaimsStruct(msgspec.Struct):
    sub: str


class ClaimsModel(pydantic.BaseModel):
    sub: str


class DatetimeClaimsStruct(msgspec.Struct, omit_defaults=True):
    """Declares the NumericDate claims as datetimes; omits a None `nbf` (null would be invalid)."""

    sub: str
    exp: datetime
    iat: datetime
    nbf: datetime | None = None


class DatetimeClaimsModel(pydantic.BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    nbf: datetime | None = None


def b64(data: bytes) -> str:
    """Unpadded base64url, as in JWTs and JWKs."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def private_pem(
    private_key: PrivateKeyTypes,
    form: serialization.PrivateFormat = serialization.PrivateFormat.PKCS8,
) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        form,
        serialization.NoEncryption(),
    )


def public_pem(
    private_key: PrivateKeyTypes,
    form: serialization.PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo,
) -> bytes:
    """The PEM of `private_key`'s public key."""
    return private_key.public_key().public_bytes(serialization.Encoding.PEM, form)


def _b64_int(value: int, size: int = 0) -> str:
    return b64(value.to_bytes(max(size, (value.bit_length() + 7) // 8)))


def make_jwk(private_key: SigningKey, **members: object) -> JWK:
    """The public JWK of `private_key`, plus `members`: `make_jwk(key, kid="kid")`."""
    public_key = private_key.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        jwk: JWK = {"kty": "RSA", "n": _b64_int(numbers.n), "e": _b64_int(numbers.e)}
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        size = (public_key.curve.key_size + 7) // 8
        point = public_key.public_numbers()
        curves = {"secp256r1": "P-256", "secp256k1": "secp256k1"}
        curves |= {"secp384r1": "P-384", "secp521r1": "P-521"}
        jwk = {
            "kty": "EC",
            "crv": curves[public_key.curve.name],
            "x": _b64_int(point.x, size),
            "y": _b64_int(point.y, size),
        }
    else:
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(public_key.public_bytes_raw())}
    merged: JWK = {**jwk, **members}
    return merged


@dataclass(frozen=True, slots=True)
class RawHS256Token:
    """Builds an HS256 token signed with `key` from raw header/payload JSON bytes (which may be
    malformed)."""

    key: str

    def __call__(self, header: bytes, payload: bytes) -> str:
        signing_input = f"{b64(header)}.{b64(payload)}"
        signature = hmac.new(self.key.encode(), signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{b64(signature)}"


@dataclass
class JWKSServer:
    """What the local JWKS endpoint serves (tests change it as they go), and what it was sent."""

    url: str = ""
    origin: str = ""
    """`url` as error messages show it: scheme, host and port."""
    body: bytes = b'{"keys": []}'
    status: int = 200
    cache_control: str | None = None
    age: str | None = None
    redirect: str | None = None
    """Where requests for /jwks are redirected (302) to, if anywhere; any other path is served."""
    delay: float = 0
    raw: bytes | None = None
    """Sent as the whole response, if set, instead of one made of the fields above."""
    dribbled: bytes = b""
    """Sent after `raw`, a byte every 0.2 s, until the client hangs up."""
    requests: int = 0
    responses: int = 0
    """Requests answered in full (so a change to what's served no longer affects them)."""
    request_headers: list[dict[str, str]] = field(default_factory=list[dict[str, str]])
    lock: threading.Lock = field(default_factory=threading.Lock)

    def serve(self, *jwks: JWK) -> None:
        self.body = json.dumps({"keys": list(jwks)}).encode()

    def received(self, requests: int) -> bool:
        """Whether `requests` requests have come in so far."""
        return self.requests >= requests

    def answered(self, responses: int) -> bool:
        """Whether `responses` requests have been answered in full so far."""
        return self.responses >= responses


class LocalHTTPServer(ThreadingHTTPServer):
    """A `ThreadingHTTPServer` for tests, which skips the reverse DNS lookup of its own address
    that `HTTPServer` does on start (`socket.getfqdn`): on some CI runners that lookup hangs for
    over 30 s, and the tests never need the name."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = port


class JWKSHandler(BaseHTTPRequestHandler):
    """Serves what a `JWKSServer` (its `state`) says."""

    def __init__(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
        server: socketserver.BaseServer,
        *,
        state: JWKSServer,
    ) -> None:
        self.state = state  # before handling the request, which the base class does at once
        super().__init__(request, client_address, server)

    def _send_raw(self, raw: bytes) -> None:
        self.wfile.write(raw)
        for byte in self.state.dribbled:
            time.sleep(0.2)
            try:
                self.wfile.write(bytes([byte]))
            except OSError:  # the client hung up
                return

    def _respond(self) -> None:
        state = self.state
        if state.raw is not None:
            self._send_raw(state.raw)
            return
        if state.redirect is not None and self.path == "/jwks":
            self.send_response(302)
            self.send_header("Location", state.redirect)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(state.status)
        if state.cache_control is not None:
            self.send_header("Cache-Control", state.cache_control)
        if state.age is not None:
            self.send_header("Age", state.age)
        self.send_header("Content-Length", str(len(state.body)))
        self.end_headers()
        self.wfile.write(state.body)

    def do_GET(self) -> None:
        state = self.state
        with state.lock:
            state.requests += 1
            state.request_headers.append({k.lower(): v for k, v in self.headers.items()})
        time.sleep(state.delay)
        self._respond()
        with state.lock:
            state.responses += 1

    def do_CONNECT(self) -> None:
        """A tunnel request, as a proxy gets for an https URL: counted, and refused."""
        with self.state.lock:
            self.state.requests += 1
        self.send_error(403)


def serve_jwks() -> Iterator[JWKSServer]:
    """A real HTTP server on 127.0.0.1, in a daemon thread, until resumed."""
    state = JWKSServer()
    httpd = LocalHTTPServer(("127.0.0.1", 0), partial(JWKSHandler, state=state))
    state.origin = f"http://127.0.0.1:{httpd.server_port}"
    state.url = f"{state.origin}/jwks"
    threading.Thread(target=httpd.serve_forever, args=(0.01,), daemon=True).start()
    yield state
    httpd.shutdown()
    httpd.server_close()
