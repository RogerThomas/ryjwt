from collections.abc import Iterable, Mapping, Sequence
from datetime import timedelta
from os import PathLike
from typing import Any, final, overload

from ryjwt._algorithms import AsymmetricAlgorithm, HMACAlgorithm
from ryjwt._compat import BaseModelTyping, StructTyping

type Claims = dict[str, Any] | StructTyping | BaseModelTyping

@final
class SecretKey:
    """Encodes and decodes JWTs with a shared secret, `str` or `bytes`, for the HMAC algorithms
    (HS256, HS384, HS512).

    `secret` must not be empty, nor look like a public key: a PEM, an SSH key or a JWK (use
    `PrivateKey`/`PublicKey`).
    """

    def __init__(
        self,
        secret: str | bytes,
        *,
        algorithms: Sequence[HMACAlgorithm],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        allow_short_secret: bool = False,
    ) -> None:
        """`audience` and `issuer` are what `decode` checks tokens' `aud` and `iss` claims against,
        unless a call passes its own. Each is a str, or an iterable of them, any one of which may
        match. Without `audience`, a token that has an `aud` is rejected. Without `issuer`, `iss`
        isn't checked: set it too, above all if one key signs for several issuers.

        `secret` must be at least as long as the hash's output (RFC 7518 §3.2): 32 bytes for
        HS256, 48 for HS384, 64 for HS512, the longest of them if several are allowed. A `str` is
        measured in UTF-8 bytes. Anyone holding a single token can brute-force a shorter secret
        offline, then forge tokens; generate one with `secrets.token_bytes(32)`.

        `allow_short_secret=True` skips (only) that length check, e.g. for a secret you don't
        control.
        """
    @property
    def algorithms(self) -> list[HMACAlgorithm]:
        """The configured algorithm names."""
    def encode(
        self,
        claims: Claims,
        *,
        algorithm: HMACAlgorithm | None = None,
        header: Mapping[str, Any] | None = None,
    ) -> str:
        """Signs `claims` (a dict, a msgspec Struct or a pydantic BaseModel) and returns the token.

        `algorithm` must be one of `algorithms`, and may be left out when only one is configured.
        `header`'s fields are added to the token's header, which always has `alg`, and
        `"typ": "JWT"` unless `header` sets `typ`. Setting `alg`, `crit` or `b64` in `header`, or
        more fields than `decode` takes (64, with `alg` and `typ`), is a `ValueError`; a `kid` that
        isn't a str is a `TypeError`. A `datetime` under `exp`, `nbf` or `iat` is written as whole
        seconds since the epoch; a naive one is a `ValueError`.
        """
    @overload
    def decode(
        self,
        token: str | bytes,
        *,
        type: None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> dict[str, Any]:
        """Verifies `token` and returns its claims as a dict, or (given `type`, a msgspec Struct or
        pydantic BaseModel class) as an instance of `type`.

        Checks the signature, with the algorithm the token's header names: it must be one of
        `algorithms`. Then checks the claims:

        - `exp` and `nbf`, if the token has them, allowing `leeway` seconds for clock differences;
        - `aud` against `audience`. A token with an `aud` is rejected if there's no `audience`;
        - `iss` against `issuer`, if there is one.

        `audience` and `issuer` default to the ones this key was created with. Passing one here
        replaces the key's for this call. To skip a check the key makes, use another key object.

        Every rejection is an `InvalidTokenError`.

        The payload is parsed with msgspec if it was installed when this object was created, else
        with jiter. They agree on all valid JSON, but may differ on exotic payloads (e.g. `1e400`,
        or nesting over ~200 levels deep); see the documentation's "Encoding and decoding" page.
        """
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

@final
class PrivateKey:
    """Encodes and decodes JWTs with a private key (`RS*`, `PS*`, `ES*`, `EdDSA`).

    `pem` is a PEM-encoded, unencrypted private key: PKCS#8 (`BEGIN PRIVATE KEY`), or PKCS#1 /
    SEC 1 (`BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY`). A public key is rejected.
    """

    def __init__(
        self,
        pem: str | bytes,
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
    ) -> None:
        """`audience` and `issuer` are what `decode` checks tokens' `aud` and `iss` claims against,
        unless a call passes its own. Each is a str, or an iterable of them, any one of which may
        match. Without `audience`, a token that has an `aud` is rejected. Without `issuer`, `iss`
        isn't checked: set it too, above all if one key signs for several issuers.
        """
    @staticmethod
    def from_path(
        path: str | PathLike[str],
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
    ) -> PrivateKey:
        """Reads the PEM from the file at `path`.

        OS errors (`FileNotFoundError`, ...) propagate; unusable contents raise `InvalidKeyError`.
        """
    @property
    def algorithms(self) -> list[AsymmetricAlgorithm]:
        """The configured algorithm names."""
    def encode(
        self,
        claims: Claims,
        *,
        algorithm: AsymmetricAlgorithm | None = None,
        header: Mapping[str, Any] | None = None,
    ) -> str:
        """Signs `claims` (a dict, a msgspec Struct or a pydantic BaseModel) and returns the token.

        `algorithm` must be one of `algorithms`, and may be left out when only one is configured.
        `header`'s fields are added to the token's header, which always has `alg`, and
        `"typ": "JWT"` unless `header` sets `typ`. Setting `alg`, `crit` or `b64` in `header`, or
        more fields than `decode` takes (64, with `alg` and `typ`), is a `ValueError`; a `kid` that
        isn't a str is a `TypeError`. A `datetime` under `exp`, `nbf` or `iat` is written as whole
        seconds since the epoch; a naive one is a `ValueError`.
        """
    @overload
    def decode(
        self,
        token: str | bytes,
        *,
        type: None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> dict[str, Any]:
        """Verifies `token` and returns its claims as a dict, or (given `type`, a msgspec Struct or
        pydantic BaseModel class) as an instance of `type`.

        Checks the signature, with the algorithm the token's header names: it must be one of
        `algorithms`. Then checks the claims:

        - `exp` and `nbf`, if the token has them, allowing `leeway` seconds for clock differences;
        - `aud` against `audience`. A token with an `aud` is rejected if there's no `audience`;
        - `iss` against `issuer`, if there is one.

        `audience` and `issuer` default to the ones this key was created with. Passing one here
        replaces the key's for this call. To skip a check the key makes, use another key object.

        Every rejection is an `InvalidTokenError`.

        The payload is parsed with msgspec if it was installed when this object was created, else
        with jiter. They agree on all valid JSON, but may differ on exotic payloads (e.g. `1e400`,
        or nesting over ~200 levels deep); see the documentation's "Encoding and decoding" page.
        """
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

@final
class PublicKey:
    """Decodes JWTs with a public key or a JWKS' keys (`RS*`, `PS*`, `ES*`, `EdDSA`). It can't
    encode.

    `pem` is a PEM-encoded public key: SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`), or PKCS#1
    (`BEGIN RSA PUBLIC KEY`). A private key is rejected: pass its public key instead.

    Built with `from_jwks`, it may hold several keys, and each token picks one by its `kid`.
    """

    def __init__(
        self,
        pem: str | bytes,
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
    ) -> None:
        """`audience` and `issuer` are what `decode` checks tokens' `aud` and `iss` claims against,
        unless a call passes its own. Each is a str, or an iterable of them, any one of which may
        match. Without `audience`, a token that has an `aud` is rejected. Without `issuer`, `iss`
        isn't checked: set it too, above all if one key signs for several issuers.
        """
    @staticmethod
    def from_path(
        path: str | PathLike[str],
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
    ) -> PublicKey:
        """Reads the PEM from the file at `path`.

        OS errors (`FileNotFoundError`, ...) propagate; unusable contents raise `InvalidKeyError`.
        """
    @staticmethod
    def from_jwks(
        jwks: str | bytes | Mapping[str, Any],
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
    ) -> PublicKey:
        """Takes the keys of a JWKS document (JSON, or the already-parsed Mapping).

        Keys of an unsupported type, and `"use": "enc"` keys, are ignored; a key with its own
        `alg` is only used for that algorithm. Tokens pick their key by `kid` (which may only be
        left out if there's a single usable key): an unknown `kid` raises `UnknownKeyError`.
        A document holding private key material, or no usable key, raises `InvalidKeyError`.
        """
    @property
    def algorithms(self) -> list[AsymmetricAlgorithm]:
        """The configured algorithm names."""
    @overload
    def decode(
        self,
        token: str | bytes,
        *,
        type: None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> dict[str, Any]:
        """Verifies `token` and returns its claims as a dict, or (given `type`, a msgspec Struct or
        pydantic BaseModel class) as an instance of `type`.

        Checks the signature, with the algorithm the token's header names: it must be one of
        `algorithms`. Then checks the claims:

        - `exp` and `nbf`, if the token has them, allowing `leeway` seconds for clock differences;
        - `aud` against `audience`. A token with an `aud` is rejected if there's no `audience`;
        - `iss` against `issuer`, if there is one.

        `audience` and `issuer` default to the ones this key was created with. Passing one here
        replaces the key's for this call. To skip a check the key makes, use another key object.

        Every rejection is an `InvalidTokenError`.

        The payload is parsed with msgspec if it was installed when this object was created, else
        with jiter. They agree on all valid JSON, but may differ on exotic payloads (e.g. `1e400`,
        or nesting over ~200 levels deep); see the documentation's "Encoding and decoding" page.
        """
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

def unverified_header(token: str | bytes) -> dict[str, Any]:
    """Return a token's header without verifying its signature; use it for routing or logging,
    never for trust decisions.

    Nothing is checked, but the token must be well formed, as `decode` requires: three parts of
    unpadded base64url, with a JSON object in the header and in the payload. If not, it raises
    `DecodeError`.
    """

def unverified_claims(token: str | bytes) -> dict[str, Any]:
    """Return a token's claims without verifying its signature or checking exp/nbf/aud/iss; don't
    trust any value in the result.

    The token must still be well formed, as `decode` requires, or it raises `DecodeError`.
    """

def unverified_token(token: str | bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a token's `(header, claims)` without verifying anything; verify with a key's
    `decode()` before trusting either.

    The token must still be well formed, as `decode` requires, or it raises `DecodeError`.
    """

def public_key_from_fetched_jwks(
    jwks: bytes,
    *,
    algorithms: Sequence[AsymmetricAlgorithm],
    audience: str | Iterable[str] | None = None,
    issuer: str | Iterable[str] | None = None,
) -> PublicKey:
    """`PublicKey.from_jwks` for a document a JWKS client fetched: keys that can't be used (other
    types or curves, a `use` other than `"sig"`, malformed or unsafe key material, an `alg` not in
    `algorithms`) are skipped instead of rejecting the document. Private key material, invalid
    JSON, or no usable key still raise `InvalidKeyError`.
    """

def validate_jwks_algorithms(algorithms: Sequence[AsymmetricAlgorithm]) -> None:
    """Validates `algorithms` as `PublicKey.from_jwks` does, raising the same errors: a JWKS client
    checks its algorithms when it's built, before it fetches any keys."""

def validate_audience_and_issuer(
    *,
    audience: str | Iterable[str] | None,
    issuer: str | Iterable[str] | None,
) -> tuple[str | tuple[str, ...] | None, str | tuple[str, ...] | None]:
    """Validates `audience` and `issuer` as the key classes do, raising the same errors: a JWKS
    client checks them when it's built, and keeps what this returns (an iterable as a tuple, as it
    may only be read once) to pass to each `PublicKey` it builds."""

class RYJWTError(Exception):
    """Base class for all ryjwt errors."""

class InvalidKeyError(RYJWTError):
    """A key can't be used: it doesn't parse, isn't supported, is too weak, or doesn't suit the
    configured algorithms."""

class JWKSFetchError(RYJWTError):
    """A JWKS client has no usable keys. Fetching them failed, and it has none cached, or they've
    been expired for over `max_stale`; or `decode_nowait` was called before the first fetch. It's
    not the token's fault: respond 503."""

class InvalidTokenError(RYJWTError):
    """The token was rejected: respond 401. Each reason has a subclass. This class itself is
    raised for a header with a `crit` field, which ryjwt must reject."""

class DecodeError(InvalidTokenError):
    """The token is malformed: e.g. not three parts, not valid base64url, or not valid JSON. Also
    raised when its `exp` or `nbf` claim isn't a number."""

class InvalidSignatureError(DecodeError):
    """The signature doesn't match."""

class ClaimsValidationError(InvalidTokenError):
    """The claims don't fit the `type` given to `decode`: a required claim is missing, or one has
    the wrong type or is out of range. Its `__cause__` is msgspec's or pydantic's
    `ValidationError`."""

class InvalidAlgorithmError(InvalidTokenError):
    """The token's algorithm (its header's `alg`) is missing, or isn't one the key may be used
    with."""

class UnknownKeyError(InvalidTokenError):
    """No key in the JWKS has the token's `kid`. Also raised when the JWKS has several keys, and
    the token has no `kid` (or the keys have none) to pick one with."""

class ExpiredSignatureError(InvalidTokenError):
    """The `exp` claim is in the past (allowing for `leeway`)."""

class ImmatureSignatureError(InvalidTokenError):
    """The `nbf` claim is in the future (allowing for `leeway`)."""

class InvalidAudienceError(InvalidTokenError):
    """The token's audience (`aud`) doesn't match `audience`, or is missing or malformed. Also
    raised when the token has an `aud` but no `audience` was set, on the key or the call."""

class InvalidIssuerError(InvalidTokenError):
    """The token's issuer (`iss`) doesn't match `issuer`, or is missing or malformed."""
