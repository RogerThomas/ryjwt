"""Optional msgspec/pydantic support, and structural stand-ins for typing.

The real `Struct` is for runtime `issubclass`/`isinstance` checks; when msgspec isn't installed it's
a placeholder class nothing subclasses. pydantic is never imported here: a model class can only
exist once pydantic has been imported, so `is_model_class` looks for it in `sys.modules` instead,
which keeps pydantic's import time off everyone who doesn't use it. The `*Typing` Protocols are for
public annotations only, so those stay fully typed even when a library isn't resolvable to the
checker.
"""

import sys
from typing import TYPE_CHECKING, ClassVar, Protocol, Self, TypeGuard

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


def is_model_class(cls: type[object]) -> "TypeGuard[type[BaseModel]]":
    """Whether `cls` is a pydantic `BaseModel` subclass, without importing pydantic."""
    pydantic_main = sys.modules.get("pydantic.main")
    return pydantic_main is not None and issubclass(cls, pydantic_main.BaseModel)


class StructTyping(Protocol):
    """Structural stand-in for `msgspec.Struct` (which declares `__struct_fields__`)."""

    __struct_fields__: ClassVar[tuple[str, ...]]


class BaseModelTyping(Protocol):
    """Structural stand-in for `pydantic.BaseModel`, matched on `model_validate_json`."""

    @classmethod
    def model_validate_json(cls, json_data: str | bytes, /) -> Self: ...


__all__ = [
    "BaseModelTyping",
    "Struct",
    "StructTyping",
    "is_model_class",
    "msgspec",
]
