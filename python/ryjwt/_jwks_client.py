"""`JWKSClient`: a `PublicKey.from_jwks` kept up to date from a JWKS URL.

It holds the current keys as a `PublicKey` and delegates decoding to it, stepping in only when the
keys must be (re)fetched: none yet, expired, or a token's `kid` is unknown (the provider likely
rotated its keys). Fetches use the standard library's `urllib.request` (see `_http`), imported on
the first fetch.

Every fetch runs on a daemon thread of its own. The one in flight is a `concurrent.futures.Future`,
which sync callers wait on directly and async ones through `asyncio.wrap_future`: callers on any
thread or event loop, sync or async, share it, and a background refresh needs no event loop.
"""

import math
import threading
import time
from collections.abc import Callable, Iterable, Sequence  # at runtime: in public signatures
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, ClassVar, final, overload

from ryjwt._algorithms import AsymmetricAlgorithm  # at runtime: in public signatures
from ryjwt._ryjwt import (
    InvalidKeyError,
    JWKSFetchError,
    PublicKey,
    UnknownKeyError,
    public_key_from_fetched_jwks,
    validate_audience_and_issuer,
    validate_jwks_algorithms,
)

if TYPE_CHECKING:
    from concurrent.futures import Future

    # Only in type parameters' bounds, evaluated lazily (importing _compat imports msgspec).
    from ryjwt._compat import BaseModelTyping, StructTyping
    from ryjwt._http import HTTPGetter, Response


def _seconds(name: str, value: object) -> float:
    """`value` (typed `float | timedelta`, but untyped callers may pass anything) in seconds."""
    if isinstance(value, timedelta):
        seconds = value.total_seconds()
    elif isinstance(value, int | float) and not isinstance(value, bool):
        seconds = float(value)
    else:
        raise TypeError(f"{name} must be a number of seconds or a timedelta")
    if not seconds >= 0:
        raise ValueError(f"{name} must not be negative, got {value!r}")
    return seconds


def _delta_seconds(value: str) -> int | None:
    """An HTTP delta-seconds value (as in `max-age=60`, or `Age`), or None if it isn't one. Values
    over 2**31 count as 2**31, as RFC 9111 §1.2.2 says (and `int()` raises past 4300 digits)."""
    value = value.strip().strip('"')
    if not (value.isascii() and value.isdigit()):
        return None
    digits = value.lstrip("0")
    return 2**31 if len(digits) > 10 else min(int(digits or "0"), 2**31)


def _parse_url(url: str) -> tuple[str, str] | None:
    """`url`'s scheme and `host[:port]`, as `urllib.request.Request` parses them (its `type` and
    `host`), without importing it (that takes ~25 ms, with ssl), so the check is of what's fetched:
    another parser may see another host (e.g. `evil.example` in `http://evil.example\\@localhost/`).
    None if it has no host, or anything that may be read in more than one way: whitespace, control
    or non-ASCII characters, backslashes, or %-escapes in the host."""
    if not (url.isascii() and url.isprintable()) or " " in url or "\\" in url:
        return None
    if "#" in url:
        url = url.rpartition("#")[0]  # Request drops the fragment, from the last #
    scheme, colon, rest = url.partition(":")
    if not colon or not scheme or "/" in scheme or not rest.startswith("//"):
        return None
    authority = rest[2:]
    end = min((i for i in map(authority.find, "/?#") if i >= 0), default=len(authority))
    host = authority[:end]
    return None if not host or "%" in host else (scheme.lower(), host)


def _is_ipv6(address: str) -> bool:
    import ipaddress  # only here: few URLs have an IPv6 host (a no-op if already imported)

    try:
        ipaddress.IPv6Address(address)
    except ValueError:
        return False
    return True


def _hostname(host: str) -> str | None:
    """The host name of `host[:port]` (an IPv6 address without its brackets), as `http.client`
    splits it to connect; None unless it's a valid one, with a valid port (up to 65535) if any."""
    colon, bracket = host.rfind(":"), host.rfind("]")
    name, port = (host[:colon], host[colon + 1 :]) if colon > bracket else (host, "")
    if port and not (len(port) <= 5 and port.isdigit() and int(port) <= 65535):
        return None
    if name.startswith("[") and name.endswith("]"):
        return name[1:-1] if _is_ipv6(name[1:-1]) else None
    return None if "[" in name or "]" in name else name


def _redacted(scheme: str, host: str) -> str:
    """The URL of `scheme` and `host` without the parts that may hold secrets (credentials, path,
    query, fragment); "an invalid URL" if `host` is no valid `host[:port]` once any credentials
    are left out, as then it may be part of them (a password holding `/`, `?` or `#` ends the
    host early, e.g. `alice:s3cr` in `https://alice:s3cr/et@idp.example/`)."""
    host = host.rpartition("@")[2]
    return "an invalid URL" if _hostname(host) is None else f"{scheme}://{host.lower()}"


class _Fetch:
    """A fetch running on its own thread. (A plain class: a dataclass or NamedTuple would add
    `dataclasses` or `annotationlib` to `import ryjwt`'s time.)"""

    __slots__ = ("deadline", "future", "number")

    def __init__(self, future: "Future[None]", deadline: float, number: int) -> None:
        self.future = future
        """Done once the fetch's outcome is recorded (or it was abandoned)."""
        self.deadline = deadline
        """When callers stop waiting for it (`time.monotonic()`): `JWKSClient._timeout` after it
        started, however late they joined."""
        self.number = number
        """The fetch's number: fetches are numbered in the order they start."""


type _Held = tuple[PublicKey | None, float, float, float]
"""The keys held (None before the first successful fetch), and their deadlines, in
`time.monotonic()` seconds, replaced as one, so a decode reads them all from one fetch:

- `refresh_at`: until then, decodes just use the keys: their expiry, or the end of the cooldown
  after a failed fetch if later, but not past `stale_at`;
- `stale_at`: when the keys stop being usable, while fetches fail: `max_stale` after they expired;
- `expiry`: when the keys expire (`needs_refresh`).

(A plain tuple: decodes unpack it, which is quicker than reading attributes.)"""


class _Outcome:
    """How a fetch ended: what to record (with the lock held), and whether it got keys."""

    __slots__ = ("record", "succeeded")

    def __init__(self, record: Callable[[], None], *, succeeded: bool) -> None:
        self.record = record
        self.succeeded = succeeded


@final
class JWKSClient:
    """Decodes JWTs with the keys published at a JWKS URL, which it fetches and keeps up to date.

    Creating it doesn't fetch anything. Use it in one of two ways:

    - Automatic: `decode` (in sync code) or `await adecode` (in async code). They fetch the keys
      when needed: the first time, and when a token's `kid` is unknown. Once the keys expire,
      they keep using them while new ones are fetched in the background.
    - Manual: `refresh()` or `await arefresh()` fetch the keys when you decide (at startup, or
      when `needs_refresh`), and `decode_nowait` decodes with the keys held, never fetching or
      waiting.

    If a fetch fails, the client keeps using the keys it has, for up to `max_stale` after they
    expired, and tries again after `cooldown`. With no usable keys, decodes raise
    `JWKSFetchError`. Keys in a fetched JWKS that can't be used are skipped.

    Fetches use the standard library's `urllib.request`. They check TLS certificates, don't
    follow redirects, and give up after 2.5 seconds. One fetch runs at a time, on a thread of its
    own, and every caller that needs it shares it, sync or async, on any thread or event loop.

    `decode` blocks while it waits for a fetch: in async code, use `adecode`.
    """

    # Times are `time.monotonic()` seconds. The keys and their deadlines are `_held` (a `_Held`):
    # decodes read them once, without the lock. A failed fetch isn't retried before `_retry_at`,
    # `cooldown` later.
    #
    # A fetch whose deadline passes while someone waits for it is abandoned: recorded as failed
    # (`TimeoutError`) and no longer in flight, so the cooldown and stale keys apply. Its thread
    # may live on (a DNS lookup can't be interrupted). If it then fails, that's dropped; if it gets
    # keys (`_http` read the response by the deadline, but reading the JWKS ended after it), they
    # are recorded after all, unless a later fetch has recorded how it ended meanwhile
    # (`_recorded`).
    # A background refresh nobody waits for stays in flight until its thread ends (and records
    # how), or until a caller joins it past its deadline, and so abandons it at once.

    _local_hosts: ClassVar[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})
    _timeout: ClassVar[float] = 2.5
    """How long callers wait for a fetch, from its start, in seconds; also `_http`'s deadline."""

    def __init__(
        self,
        url: str,
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        cache_lifetime: float | timedelta = 900,
        min_cache_lifetime: float | timedelta = 60,
        max_cache_lifetime: float | timedelta = 86400,
        max_stale: float | timedelta = 86400,
        cooldown: float | timedelta = 30,
    ) -> None:
        """`url` must be `https://`, or `http://` to this machine (`localhost`, `127.0.0.1` or
        `[::1]`). URLs with credentials, whitespace, control or non-ASCII characters, or
        backslashes are rejected too. A URL that isn't allowed is a `ValueError`. `algorithms` are
        checked as `PublicKey.from_jwks` checks them.

        `audience` and `issuer` are what `decode`, `adecode` and `decode_nowait` check tokens'
        `aud` and `iss` against, as for `PublicKey`. Each call may pass its own instead.

        The times are seconds or `timedelta`s, and mustn't be negative:

        - `cache_lifetime`: how long keys stay fresh if the response doesn't say (it has no
          `Cache-Control: max-age`).
        - `min_cache_lifetime`, `max_cache_lifetime`: the shortest and longest time keys stay
          fresh, whatever the response says.
        - `max_stale`: how long expired keys stay in use while fetching new ones keeps failing.
        - `cooldown`: the least time between fetches, after a failed fetch or for an unknown
          `kid`. Keys also stay fresh for at least this long.
        """
        parsed = _parse_url(url)
        if parsed is None or not self._allowed(*parsed):
            got = "an invalid URL" if parsed is None else _redacted(*parsed)
            raise ValueError(
                "url must be https:// (or http:// to localhost, 127.0.0.1 or [::1]), without"
                f" credentials, got {got}"
            )
        validate_jwks_algorithms(algorithms)  # now, rather than on the first fetch
        self._audience, self._issuer = validate_audience_and_issuer(
            audience=audience, issuer=issuer
        )
        self._url = url
        self._scheme, self._host = parsed
        self._origin = _redacted(*parsed)  # what messages show of the URL
        self._http: HTTPGetter | None = None
        self._algorithms = list(algorithms)
        self._cache_lifetime = _seconds("cache_lifetime", cache_lifetime)
        self._min_cache_lifetime = _seconds("min_cache_lifetime", min_cache_lifetime)
        self._max_cache_lifetime = _seconds("max_cache_lifetime", max_cache_lifetime)
        if self._min_cache_lifetime > self._max_cache_lifetime:
            raise ValueError("min_cache_lifetime must not exceed max_cache_lifetime")
        self._max_stale = _seconds("max_stale", max_stale)
        self._cooldown = _seconds("cooldown", cooldown)
        self._lock = threading.Lock()
        """Guards the fetch in flight and the outcome of fetches (decodes read `_held` without
        it)."""
        self._in_flight: _Fetch | None = None
        self._started = 0
        """How many fetches have started (the last one's number)."""
        self._recorded = 0
        """The number of the last fetch whose outcome (or abandonment) was recorded."""
        self._held: _Held = (None, -math.inf, -math.inf, -math.inf)
        self._retry_at = -math.inf
        self._fetched_at = -math.inf
        """When the last fetch ended (an unknown `kid` refetches only `cooldown` after it)."""
        self._failure: tuple[str, BaseException | None] = ("", None)
        """Why the last fetch failed (empty if it didn't), and the exception it raised, if any:
        replaced as one, as `_held` is, so a reader without the lock can't mix two fetches'."""

    @classmethod
    def _allowed(cls, scheme: str, host: str) -> bool:
        """Whether a JWKS may be fetched from `scheme://host`: https, or http to this machine; no
        credentials, a valid IPv6 address if in brackets, and a valid port if any."""
        hostname = _hostname(host)
        if "@" in host or hostname is None:
            return False
        return scheme == "https" or (scheme == "http" and hostname.lower() in cls._local_hosts)

    def _get(self, deadline: float) -> "Response":
        """GETs the JWKS, on the calling thread, by `deadline`."""
        if self._http is None:
            from ryjwt._http import HTTPGetter  # only now: it imports ssl and urllib.request

            self._http = HTTPGetter(self._url, self._scheme, self._host)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out")
        return self._http.get(remaining)

    def _describe(self, error: Exception) -> str:
        """What went wrong in a fetch: the exception (a `URLError`'s reason, if an exception) and
        its message, less the URL's path and query, which may hold secrets (no urllib error is
        known to include them; this makes sure)."""
        from urllib.error import URLError  # imported already, by the fetch

        if isinstance(error, URLError) and isinstance(error.reason, Exception):
            error = error.reason
        message = str(error)
        path_and_query = self._url[len(self._scheme) + 3 + len(self._host) :]
        if "#" in path_and_query:
            path_and_query = path_and_query.rpartition("#")[0]
        for secret in (self._url, path_and_query):
            if len(secret) > 1:
                message = message.replace(secret, "...")
        return f"{type(error).__name__}: {message}"

    def _lifetime(self, cache_control: str | None, age: str | None) -> float:
        """How long fetched keys stay fresh: `Cache-Control: max-age` less the response's `Age`,
        clamped, if given."""
        for directive in (cache_control or "").split(","):
            name, _, value = directive.partition("=")
            max_age = _delta_seconds(value)
            if name.strip().lower() == "max-age" and max_age is not None:
                remaining = max_age - (_delta_seconds(age or "") or 0)
                return min(max(remaining, self._min_cache_lifetime), self._max_cache_lifetime)
        return self._cache_lifetime

    def _failed(self, failure: str, cause: BaseException | None) -> None:
        """Records a failed fetch (with the lock held): the keys held (if any) stay in use, as long
        as they're under `max_stale` out of date, and no fetch starts until the cooldown is over."""
        self._fetched_at = time.monotonic()
        self._retry_at = self._fetched_at + self._cooldown
        keys, _, stale_at, expiry = self._held
        refresh_at = min(max(expiry, self._retry_at), stale_at)
        self._held = (keys, refresh_at, stale_at, expiry)
        self._failure = (failure, cause)

    def _received(self, keys: PublicKey, lifetime: float) -> None:
        """Records fetched keys, fresh for `lifetime` seconds, or `cooldown` if longer (so a zero
        lifetime can't make every decode refetch) (with the lock held)."""
        self._fetched_at = time.monotonic()
        expiry = self._fetched_at + max(lifetime, self._cooldown)
        self._held = (keys, expiry, expiry + self._max_stale, expiry)
        self._retry_at = -math.inf
        self._failure = ("", None)

    def _fetched(self, deadline: float) -> _Outcome:
        """GETs the JWKS and reads it: returns what to record, the keys or why the fetch failed
        (or raises, e.g. if the GET does)."""
        status, cache_control, age, body = self._get(deadline)
        if not 200 <= status < 300:
            return _Outcome(partial(self._failed, f"HTTP status {status}", None), succeeded=False)
        try:
            keys = public_key_from_fetched_jwks(
                body, algorithms=self._algorithms, audience=self._audience, issuer=self._issuer
            )
        except InvalidKeyError as e:
            return _Outcome(partial(self._failed, str(e), e), succeeded=False)
        lifetime = self._lifetime(cache_control, age)
        return _Outcome(partial(self._received, keys, lifetime), succeeded=True)

    def _outcome(self, deadline: float) -> _Outcome:
        """`_fetched`, or if anything raises, the failure to record: a fetch's outcome is always
        recorded, so it can't stay in flight."""
        try:
            return self._fetched(deadline)
        except Exception as e:  # noqa: BLE001 - every failure is recorded, raised as JWKSFetchError's cause
            return _Outcome(partial(self._failed, self._describe(e), e), succeeded=False)

    def _run(self, fetch: _Fetch) -> None:
        """A fetch's thread: records its outcome, then lets its waiters go. Whatever happens, the
        fetch is then no longer in flight. If it was abandoned meanwhile, only keys it got are
        recorded, and only if no later fetch has recorded its outcome since."""
        failed = partial(self._failed, "The fetch failed unexpectedly", None)
        outcome = _Outcome(failed, succeeded=False)
        try:
            outcome = self._outcome(fetch.deadline)
        finally:
            with self._lock:
                if self._in_flight is fetch:
                    self._in_flight = None
                    self._recorded = fetch.number
                    outcome.record()
                elif outcome.succeeded and self._recorded == fetch.number:
                    outcome.record()  # abandoned, yet got keys: better late than never
            fetch.future.set_result(None)

    def _start(self) -> _Fetch:
        """Starts a fetch on a daemon thread of its own, as the one in flight (with the lock held,
        so the thread can't record its outcome before then)."""
        from concurrent.futures import Future  # only now: it imports logging (~10 ms)

        future: Future[None] = Future()
        future.set_running_or_notify_cancel()  # so a waiter can't cancel it for the others
        self._started += 1
        fetch = _Fetch(future, time.monotonic() + self._timeout, self._started)
        thread = threading.Thread(target=self._run, args=(fetch,), name="ryjwt-jwks", daemon=True)
        thread.start()
        self._in_flight = fetch
        return fetch

    def _join_or_start(self, start_if: Callable[[], bool]) -> _Fetch | None:
        """The fetch in flight; else a new one if `start_if()`, checked with the lock held (another
        fetch may have ended since the caller looked); else None."""
        with self._lock:
            if self._in_flight is not None:
                return self._in_flight
            return self._start() if start_if() else None

    def _timed_out(self, fetch: _Fetch) -> None:
        """`fetch`'s deadline passed while waiting for it: it's abandoned, recorded as timed out
        (unless it ended meanwhile, or another waiter got here first)."""
        with self._lock:
            if self._in_flight is fetch:
                self._in_flight = None
                self._recorded = fetch.number
                self._failed("TimeoutError: timed out", TimeoutError("timed out"))

    def _wait(self, fetch: _Fetch | None) -> None:
        """Waits for `fetch` (if any), until its deadline."""
        if fetch is None:
            return
        try:
            fetch.future.result(timeout=max(fetch.deadline - time.monotonic(), 0))
        except TimeoutError:
            self._timed_out(fetch)

    async def _await(self, fetch: _Fetch | None) -> None:
        """`_wait`, letting the event loop run meanwhile. Cancelling it doesn't cancel the fetch,
        which others may be waiting for (its future is already running, so can't be cancelled)."""
        import asyncio  # only here: sync-only users needn't pay for importing it

        if fetch is None:
            return
        timeout = max(fetch.deadline - time.monotonic(), 0)
        try:
            await asyncio.wait_for(asyncio.wrap_future(fetch.future), timeout)
        except TimeoutError:
            self._timed_out(fetch)

    def _may_fetch(self) -> bool:
        """Whether a fetch may start: the last one didn't fail under `cooldown` ago."""
        return time.monotonic() >= self._retry_at

    def _must_fetch(self) -> bool:
        """Whether a decode needs a fetch: there are no usable keys, and a fetch may start."""
        keys, _, stale_at, _ = self._held
        return (keys is None or time.monotonic() >= stale_at) and self._may_fetch()

    def _expired(self) -> bool:
        """Whether a refresh may start in the background: the keys expired, the cooldown is over."""
        _, refresh_at, _, _ = self._held
        return time.monotonic() >= refresh_at

    def _can_refetch(self, stale: PublicKey) -> bool:
        """Whether a token's unknown `kid` may refetch: `stale` are still the current keys (no one
        else refetched meanwhile), and the last fetch ended at least `cooldown` ago."""
        keys, _, _, _ = self._held
        return keys is stale and time.monotonic() - self._fetched_at >= self._cooldown

    def _no_usable_keys(self, keys: PublicKey | None) -> JWKSFetchError:
        """Why there are no usable keys, `keys` being the ones held (if any)."""
        failure, cause = self._failure
        if failure:
            stale = "" if keys is None else " (and the cached keys expired over max_stale ago)"
            message = f"Couldn't fetch the JWKS from {self._origin}: {failure}{stale}"
        elif keys is None:
            message = f"No keys fetched from {self._origin} yet: call refresh() first"
        else:
            message = f"The keys from {self._origin} expired over max_stale ago: call refresh()"
        error = JWKSFetchError(message)
        error.__cause__ = cause
        return error

    def _usable_keys(self) -> PublicKey:
        """The keys held; `JWKSFetchError` if there are none, or they've been expired for over
        `max_stale`."""
        keys, _, stale_at, _ = self._held
        if keys is None or time.monotonic() >= stale_at:
            raise self._no_usable_keys(keys)
        return keys

    def _current_keys(self, start_if: Callable[[], bool]) -> PublicKey:
        """The usable keys, once the fetch in flight (or a new one, if `start_if()`) is over."""
        self._wait(self._join_or_start(start_if))
        return self._usable_keys()

    async def _acurrent_keys(self, start_if: Callable[[], bool]) -> PublicKey:
        await self._await(self._join_or_start(start_if))
        return self._usable_keys()

    def _expired_keys(self, keys: PublicKey, stale_at: float) -> PublicKey:
        """The keys to decode with once `keys` (usable until `stale_at`) have expired: still
        `keys`, refreshed in the background meanwhile, unless they're over `max_stale` out of
        date: then fetched first."""
        if time.monotonic() < stale_at:
            self._join_or_start(self._expired)  # not waited for
            return keys
        return self._current_keys(self._must_fetch)

    async def _aexpired_keys(self, keys: PublicKey, stale_at: float) -> PublicKey:
        if time.monotonic() < stale_at:
            self._join_or_start(self._expired)  # not waited for
            return keys
        return await self._acurrent_keys(self._must_fetch)

    def _refetched(self, stale: PublicKey) -> PublicKey:
        """The keys after refetching for an unknown `kid`, if `_can_refetch`."""
        self._wait(self._join_or_start(partial(self._can_refetch, stale)))
        keys, _, _, _ = self._held
        return keys or stale

    async def _arefetched(self, stale: PublicKey) -> PublicKey:
        await self._await(self._join_or_start(partial(self._can_refetch, stale)))
        keys, _, _, _ = self._held
        return keys or stale

    @property
    def needs_refresh(self) -> bool:
        """Whether there are no keys yet, or they've expired: time to call `refresh()`. Still True
        during the cooldown after a failed fetch (`refresh()` then returns at once)."""
        _, _, _, expiry = self._held
        return time.monotonic() >= expiry

    def refresh(self) -> None:
        """Fetches the keys now, so the client has usable keys, or raises `JWKSFetchError`.

        Joins the fetch in flight, if any. Within `cooldown` of a failed fetch, doesn't fetch. A
        failed fetch only raises if the client is left without usable keys: none, or expired over
        `max_stale` ago; otherwise the keys held stay in use (and `needs_refresh` stays True).
        Waits at most 2.5 seconds.
        """
        self._current_keys(self._may_fetch)

    async def arefresh(self) -> None:
        """`refresh`, for async code."""
        await self._acurrent_keys(self._may_fetch)

    @overload
    def decode(
        self,
        token: str | bytes,
        *,
        type: None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> dict[str, Any]: ...
    @overload
    def decode[T: StructTyping | BaseModelTyping](
        self,
        token: str | bytes,
        *,
        type: type[T],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> T: ...
    def decode(
        self,
        token: str | bytes,
        *,
        type: type[Any] | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> object:
        """Verifies `token` with the JWKS' keys, as `PublicKey.decode` does, fetching them first if
        needed (blocking: in async code, use `adecode`). `audience` and `issuer`, if given, replace
        the client's own for this call.

        Raises `JWKSFetchError` if there are no keys (the fetch failed) or they've been out of date
        for over `max_stale`, and `UnknownKeyError` if the token's `kid` is in neither the keys
        held nor (cooldown permitting) refetched ones.
        """
        keys, refresh_at, stale_at, _ = self._held
        if keys is None:
            keys = self._current_keys(self._must_fetch)
        elif time.monotonic() >= refresh_at:
            keys = self._expired_keys(keys, stale_at)
        try:
            return keys.decode(token, type=type, audience=audience, issuer=issuer, leeway=leeway)
        except UnknownKeyError:
            refetched = self._refetched(keys)
            if refetched is keys:
                raise
        return refetched.decode(token, type=type, audience=audience, issuer=issuer, leeway=leeway)

    @overload
    async def adecode(
        self,
        token: str | bytes,
        *,
        type: None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> dict[str, Any]: ...
    @overload
    async def adecode[T: StructTyping | BaseModelTyping](
        self,
        token: str | bytes,
        *,
        type: type[T],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> T: ...
    async def adecode(
        self,
        token: str | bytes,
        *,
        type: type[Any] | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> object:
        """`decode`, for async code: waiting for a fetch lets the event loop run. With fresh keys
        held, it only suspends to wait for a refetch, for a token whose `kid` is unknown."""
        keys, refresh_at, stale_at, _ = self._held
        if keys is None:
            keys = await self._acurrent_keys(self._must_fetch)
        elif time.monotonic() >= refresh_at:
            keys = await self._aexpired_keys(keys, stale_at)
        try:
            return keys.decode(token, type=type, audience=audience, issuer=issuer, leeway=leeway)
        except UnknownKeyError:
            refetched = await self._arefetched(keys)
            if refetched is keys:
                raise
        return refetched.decode(token, type=type, audience=audience, issuer=issuer, leeway=leeway)

    @overload
    def decode_nowait(
        self,
        token: str | bytes,
        *,
        type: None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> dict[str, Any]: ...
    @overload
    def decode_nowait[T: StructTyping | BaseModelTyping](
        self,
        token: str | bytes,
        *,
        type: type[T],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> T: ...
    def decode_nowait(
        self,
        token: str | bytes,
        *,
        type: type[Any] | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> object:
        """Verifies `token` with the keys held, as `PublicKey.decode` does; never fetches or waits
        (call `refresh()` for that).

        Raises `JWKSFetchError` if there are no keys yet, or they've been expired for over
        `max_stale` (expired keys are used until then), and `UnknownKeyError` if the token's `kid`
        isn't in the keys held.
        """
        keys = self._usable_keys()
        return keys.decode(token, type=type, audience=audience, issuer=issuer, leeway=leeway)


__all__ = ["JWKSClient"]
