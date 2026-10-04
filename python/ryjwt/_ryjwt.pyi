from collections.abc import Iterable, Mapping, Sequence
from datetime import timedelta
from typing import Any, overload

from ryjwt._compat import BaseModelTyping, StructTyping

type Claims = dict[str, Any] | StructTyping | BaseModelTyping

class RYJWT:
    """Encodes and decodes JWTs with one key, for the configured algorithms.

    `key` is an HMAC secret (str/bytes) for HS*, or for RS*/PS*/ES*/EdDSA a PEM (str/bytes) or a
    cryptography key object. Private keys can encode and decode; public keys can only decode.
    """

    def __init__(self, key: str | bytes | object, *, algorithms: Sequence[str]) -> None: ...
    @property
    def algorithms(self) -> list[str]: ...
    def encode(
        self,
        claims: Claims,
        *,
        algorithm: str | None = None,
        headers: Mapping[str, Any] | None = None,
    ) -> str: ...
    @overload
    def decode(
        self,
        token: str | bytes,
        *,
        type: type[dict[str, Any]] | None = None,
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

class RYJWTError(Exception): ...
class InvalidKeyError(RYJWTError): ...
class InvalidTokenError(RYJWTError): ...
class DecodeError(InvalidTokenError): ...
class InvalidSignatureError(DecodeError): ...
class InvalidAlgorithmError(InvalidTokenError): ...
class ExpiredSignatureError(InvalidTokenError): ...
class ImmatureSignatureError(InvalidTokenError): ...
class InvalidAudienceError(InvalidTokenError): ...
class InvalidIssuerError(InvalidTokenError): ...
