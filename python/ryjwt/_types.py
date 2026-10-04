"""Glue between ryjwt's Rust core and msgspec/pydantic, for `decode(type=...)` and `encode`."""

from typing import TYPE_CHECKING, Any

from ryjwt._compat import BaseModel, Struct, msgspec

if TYPE_CHECKING:
    from collections.abc import Callable


def payload_parser(type_: type) -> Callable[[bytes], Any]:
    """A callable turning payload JSON bytes into an instance of `type_`."""
    if issubclass(type_, Struct):
        return msgspec.json.Decoder(type_).decode
    if issubclass(type_, BaseModel):
        return type_.model_validate_json
    msg = f"type must be dict, a msgspec Struct or a pydantic BaseModel, got {type_!r}"
    raise TypeError(msg)


def encode_claims(claims: object) -> bytes:
    """JSON bytes for a Struct or BaseModel instance."""
    if isinstance(claims, Struct):
        return msgspec.json.encode(claims)
    if isinstance(claims, BaseModel):
        # Encode by alias (matching how the model decodes) unless the model opts out.
        by_alias: bool = claims.model_config.get("serialize_by_alias", True)
        return claims.model_dump_json(by_alias=by_alias).encode()
    msg = (
        f"claims must be a dict, msgspec Struct or pydantic BaseModel, got {type(claims).__name__}"
    )
    raise TypeError(msg)
