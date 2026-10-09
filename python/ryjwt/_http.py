"""`JWKSClient`'s HTTP GET, with the standard library (`urllib.request`): one deadline for the
whole fetch, and redirects aren't followed. https:// URLs go through the proxy urllib finds
(`HTTPS_PROXY`/`NO_PROXY`, or the system settings on macOS and Windows); http:// ones, which are
always to this machine, never go through a proxy. Requests say they're from ryjwt (`User-Agent:
ryjwt/<version>`): some firewalls refuse urllib's default, `Python-urllib/<version>`.

Imported on a client's first fetch only: `ssl` and `urllib.request` take ~25 ms to import.
"""

import http.client
import importlib.metadata
import io
import socket
import ssl
import time
import urllib.request
from collections.abc import Buffer
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import ClassVar

type Response = tuple[int, str | None, str | None, bytes]
"""What a fetch got: the status, the `Cache-Control` and `Age` headers, and the body."""

USER_AGENT = f"ryjwt/{importlib.metadata.version('ryjwt')}"


class _DeadlineReader(io.RawIOBase):
    """Reads a response from its socket, each read with the time left until `deadline` as its
    timeout: a server sending a byte now and then can't hold a fetch open past the deadline."""

    def __init__(self, reader: io.BufferedReader, sock: socket.socket, deadline: float) -> None:
        super().__init__()
        self._reader = reader  # the socket's own reader, which this replaces: closed with it
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Buffer, /) -> int:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out")
        self._sock.settimeout(remaining)
        return self._sock.recv_into(buffer)

    def close(self) -> None:
        self._reader.close()
        super().close()


class _HTTPResponse(http.client.HTTPResponse):
    """An `HTTPResponse` (status line, headers and body) read within the deadline of its fetch."""

    deadline: ClassVar[ContextVar[float]] = ContextVar("deadline")
    """The `time.monotonic()` deadline of the fetch running in this context (set by `get`)."""

    def __init__(
        self,
        sock: socket.socket,
        debuglevel: int = 0,
        method: str | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(sock, debuglevel, method, url)
        self.fp = io.BufferedReader(_DeadlineReader(self.fp, sock, self.deadline.get()))


class _HTTPConnection(http.client.HTTPConnection):
    response_class = _HTTPResponse


class _HTTPSConnection(http.client.HTTPSConnection):
    response_class = _HTTPResponse


class _HTTPHandler(urllib.request.AbstractHTTPHandler):
    """Opens http and https URLs with the connections above. https ones verify the server's
    certificate with the default SSL context, made on the first https fetch (it takes ~3 ms) and
    reused for later ones."""

    http_request = urllib.request.AbstractHTTPHandler.do_request_
    https_request = urllib.request.AbstractHTTPHandler.do_request_

    def __init__(self) -> None:
        super().__init__()
        self._ssl_context: ssl.SSLContext | None = None

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_HTTPConnection, req)

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        if self._ssl_context is None:
            self._ssl_context = ssl.create_default_context()
        return self.do_open(_HTTPSConnection, req, context=self._ssl_context)


@dataclass
class HTTPGetter:
    """GETs one URL, the one a JWKS client checked: its scheme and `host[:port]` as
    `urllib.request.Request` parses them (its `type` and `host`) are `scheme` and `host`.

    The opener has no redirect or HTTP error handlers: every response, 3xx included, is returned
    with its status, and none is followed. Only https URLs may use a proxy: an http one is to this
    machine, which a proxy (from `HTTP_PROXY`, or the system's) mustn't stand in for.
    """

    _url: str
    _scheme: str
    _host: str
    _opener: urllib.request.OpenerDirector = field(init=False)

    def __post_init__(self) -> None:
        self._opener = urllib.request.OpenerDirector()
        self._opener.addheaders = [("User-Agent", USER_AGENT)]
        proxies: dict[str, str] | None = {} if self._scheme == "http" else None  # None: urllib's
        self._opener.add_handler(urllib.request.ProxyHandler(proxies))
        self._opener.add_handler(_HTTPHandler())

    def get(self, timeout: float) -> Response:
        """The response, read in full within `timeout` seconds of the call; `TimeoutError` (or
        `URLError` wrapping one, while connecting) past that."""
        deadline = time.monotonic() + timeout
        request = urllib.request.Request(self._url)
        if (request.type, request.host) != (self._scheme, self._host):
            raise ValueError("urllib.request parses the URL otherwise than it was checked")
        token = _HTTPResponse.deadline.set(deadline)
        try:
            response: http.client.HTTPResponse = self._opener.open(request, timeout=timeout)
            with response:
                body = response.read()
        finally:
            _HTTPResponse.deadline.reset(token)
        cache_control, age = response.getheader("Cache-Control"), response.getheader("Age")
        return response.status, cache_control, age, body
