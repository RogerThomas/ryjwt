from collections.abc import Iterable, Mapping, Sequence
from datetime import timedelta
from os import PathLike
from typing import Any, final, overload

from ryjwt._algorithms import AsymmetricAlgorithm, HMACAlgorithm
from ryjwt._compat import BaseModelTyping, StructTyping

type Claims = dict[str, Any] | StructTyping | BaseModelTyping

@final
class HMAC:
    """Encodes and decodes JWTs with a shared secret (HS256, HS384, HS512).

    `secret` must not be empty, nor look like a public key: a PEM, an SSH key or a JWK (use
    `PrivateKey`/`PublicKey`).
    """

    def __init__(
        self,
        secret: str | bytes,
        *,
        algorithms: Sequence[HMACAlgorithm],
        allow_short_secret: bool = False,
    ) -> None:
        """`secret` must be at least as long as the hash's output (RFC 7518 §3.2): 32 bytes for
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
        headers: Mapping[str, Any] | None = None,
    ) -> str: ...
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

        The payload is parsed with msgspec if it was installed when this object was created, else
        with jiter. They agree on all valid JSON, but may differ on exotic payloads (e.g. `1e400`,
        or nesting over ~200 levels deep); see the README.
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
    """Encodes and decodes JWTs with a private key (RS*, PS*, ES*, EdDSA).

    `pem` is a PEM-encoded, unencrypted private key: PKCS#8 (`BEGIN PRIVATE KEY`), or PKCS#1 /
    SEC 1 (`BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY`). A public key is rejected.
    """

    def __init__(self, pem: str | bytes, *, algorithms: Sequence[AsymmetricAlgorithm]) -> None: ...
    @staticmethod
    def from_path(
        path: str | PathLike[str],
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
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
        headers: Mapping[str, Any] | None = None,
    ) -> str: ...
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

        The payload is parsed with msgspec if it was installed when this object was created, else
        with jiter. They agree on all valid JSON, but may differ on exotic payloads (e.g. `1e400`,
        or nesting over ~200 levels deep); see the README.
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
    """Decodes JWTs with a public key or a JWKS' keys (RS*, PS*, ES*, EdDSA). It can't encode.

    `pem` is a PEM-encoded public key: SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`), or PKCS#1
    (`BEGIN RSA PUBLIC KEY`). A private key is rejected: pass its public key instead.
    """

    def __init__(self, pem: str | bytes, *, algorithms: Sequence[AsymmetricAlgorithm]) -> None: ...
    @staticmethod
    def from_path(
        path: str | PathLike[str],
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
    ) -> PublicKey:
        """Reads the PEM from the file at `path`.

        OS errors (`FileNotFoundError`, ...) propagate; unusable contents raise `InvalidKeyError`.
        """
    @staticmethod
    def from_jwks(
        jwks: str | bytes | Mapping[str, Any],
        *,
        algorithms: Sequence[AsymmetricAlgorithm],
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

        The payload is parsed with msgspec if it was installed when this object was created, else
        with jiter. They agree on all valid JSON, but may differ on exotic payloads (e.g. `1e400`,
        or nesting over ~200 levels deep); see the README.
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

def public_key_from_fetched_jwks(
    jwks: bytes,
    *,
    algorithms: Sequence[AsymmetricAlgorithm],
) -> PublicKey:
    """`PublicKey.from_jwks` for a document a JWKS client fetched: keys that can't be used (other
    types or curves, a `use` other than `"sig"`, malformed or unsafe key material, an `alg` not in
    `algorithms`) are skipped instead of rejecting the document. Private key material, invalid
    JSON, or no usable key still raise `InvalidKeyError`.
    """

def validate_jwks_algorithms(algorithms: Sequence[AsymmetricAlgorithm]) -> None:
    """Validates `algorithms` as `PublicKey.from_jwks` does, raising the same errors: a JWKS client
    checks its algorithms when it's built, before it fetches any keys."""

class RYJWTError(Exception): ...
class InvalidKeyError(RYJWTError): ...

class JWKSFetchError(RYJWTError):
    """A JWKS client has no usable keys: none fetched yet (or none under `max_stale` out of date),
    because fetching them failed, or `decode_nowait` was called before `refresh()`. Not the token's
    fault (-> 503)."""

class InvalidTokenError(RYJWTError): ...
class DecodeError(InvalidTokenError): ...
class InvalidSignatureError(DecodeError): ...

class ClaimsValidationError(InvalidTokenError):
    """The claims don't fit the `type` given to `decode`: a required claim is missing, or one has
    the wrong type or is out of range. Its `__cause__` is msgspec's or pydantic's
    `ValidationError`."""

class InvalidAlgorithmError(InvalidTokenError): ...
class UnknownKeyError(InvalidTokenError): ...
class ExpiredSignatureError(InvalidTokenError): ...
class ImmatureSignatureError(InvalidTokenError): ...
class InvalidAudienceError(InvalidTokenError): ...
class InvalidIssuerError(InvalidTokenError): ...
