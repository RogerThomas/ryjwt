"""Optional msgspec/pydantic imports, and structural stand-ins for typing (as in lothc).

The real `Struct`/`BaseModel` are for runtime `issubclass`/`isinstance` checks; when a library isn't
installed they're placeholder classes nothing subclasses. The `*Typing` Protocols are for public
annotations only, so those stay fully typed even when a library isn't resolvable to the checker.
"""

from typing import TYPE_CHECKING, Any, ClassVar, Protocol

if TYPE_CHECKING:
    import msgspec
    from msgspec import Struct
    from pydantic import BaseModel
else:
    try:
        import msgspec
        from msgspec import Struct
    except ImportError:
        msgspec = None

        class Struct:
            pass

    try:
        from pydantic import BaseModel
    except ImportError:

        class BaseModel:
            pass


class StructTyping(Protocol):
    """Structural stand-in for `msgspec.Struct` (which declares `__struct_fields__`)."""

    __struct_fields__: ClassVar[tuple[str, ...]]


class BaseModelTyping(Protocol):
    """Structural stand-in for `pydantic.BaseModel`, matched on `model_validate_json`."""

    @classmethod
    def model_validate_json(cls, json_data: str | bytes, /) -> Any: ...  # noqa: ANN401


__all__ = ["BaseModel", "BaseModelTyping", "Struct", "StructTyping", "msgspec"]
