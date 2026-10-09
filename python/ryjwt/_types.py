"""Glue between ryjwt's Rust core and msgspec/pydantic, for `decode(type=...)` and `encode`."""

import inspect
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from types import MemberDescriptorType, NoneType, UnionType
from typing import TYPE_CHECKING, Annotated, Any, TypeAliasType, Union, get_args, get_origin

from ryjwt._compat import Struct, is_model_class, msgspec

if TYPE_CHECKING:
    import msgspec.inspect as msgspec_inspect
    from pydantic import BaseModel
    from pydantic.fields import FieldInfo
    from pydantic_core import InitErrorDetails

REGISTERED_CLAIMS = ("exp", "nbf", "aud", "iss")
NUMERIC_DATE_CLAIMS = ("exp", "nbf", "iat")

type ClaimAttributes = tuple[str | None, str | None, str | None, str | None]
type DateClaims = tuple[tuple[str, str], ...]
"""Per NumericDate claim (`exp`, `nbf`, `iat`) a class has a field for: its JSON name, and the
field's attribute."""
type PayloadEncoder = tuple[Callable[[Any], bytes], tuple[str, ...], Callable[[Any], bytes]]
"""How instances of a claims class encode: plainly, unless any of the attributes holding their
NumericDate claims holds a datetime (as the encoder checks), then with the other callable."""


def _members(value: object) -> Iterator[object]:
    """`value`'s items if it's a tuple, else `value` itself."""
    if isinstance(value, tuple):
        yield from value
    else:
        yield value


def _nested_types(node: "msgspec_inspect.Type") -> Iterator["msgspec_inspect.Type"]:
    """The types directly inside `node` (item, key/value, union member and field types)."""
    for value in msgspec.structs.astuple(node):
        for item in _members(value):
            if isinstance(item, msgspec.inspect.Field):
                yield item.type
            elif isinstance(item, msgspec.inspect.Type):
                yield item


def _decodes_without_user_code(root: "msgspec_inspect.Type") -> bool:
    """Whether msgspec decodes `root` without calling any user code (`__post_init__`, a
    dataclass's or NamedTuple's constructor, an Enum's `_missing_`, a custom type's hook)."""
    unsafe = (
        msgspec.inspect.CustomType,
        msgspec.inspect.DataclassType,
        msgspec.inspect.EnumType,
        msgspec.inspect.NamedTupleType,
    )
    seen: set[int] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, unsafe):
            return False
        if isinstance(node, msgspec.inspect.StructType) and hasattr(node.cls, "__post_init__"):
            return False
        pending.extend(_nested_types(node))
    return True


def _is_claim_type(claim: str, type_: "msgspec_inspect.Type") -> bool:
    """Whether a field of this type decodes the claim to the very value `decode` validates."""
    str_type, list_type = msgspec.inspect.StrType, msgspec.inspect.ListType
    match claim:
        case "exp" | "nbf":
            # Not float: msgspec makes an int beyond i64 a float, which `decode` saturates instead.
            return isinstance(type_, msgspec.inspect.IntType)
        case "iss":
            return isinstance(type_, str_type)
        case _:
            members = type_.types if isinstance(type_, msgspec.inspect.UnionType) else (type_,)
            return all(
                isinstance(t, str_type)
                or (isinstance(t, list_type) and isinstance(t.item_type, str_type))
                for t in members
            )


def _is_plain_slot(cls: type, name: str) -> bool:
    """Whether `getattr(instance, name)` just reads the field's slot."""
    return cls.__getattribute__ is object.__getattribute__ and isinstance(
        inspect.getattr_static(cls, name),
        MemberDescriptorType,
    )


def _origin(type_: object) -> type[object] | None:
    """The class `type_` is, or (for a parametrised generic such as `G[int]`) is an alias of."""
    origin = get_origin(type_) or type_
    return origin if isinstance(origin, type) else None


def _is_struct_datetime(type_: "msgspec_inspect.Type") -> bool:
    """Whether a Struct field of this type is a datetime: `datetime`, or `datetime | None`."""
    members = type_.types if isinstance(type_, msgspec.inspect.UnionType) else (type_,)
    datetime_type, none_type = msgspec.inspect.DateTimeType, msgspec.inspect.NoneType
    return any(isinstance(t, datetime_type) for t in members) and all(
        isinstance(t, datetime_type | none_type) for t in members
    )


def _struct_datetime_claims(type_: object) -> tuple[str, ...]:
    """The NumericDate claims (`exp`, `nbf`, `iat`) Struct `type_` declares as datetimes."""
    info = msgspec.inspect.type_info(type_)
    if not isinstance(info, msgspec.inspect.StructType) or info.array_like:
        return ()
    return tuple(
        field.encode_name
        for field in info.fields
        if field.encode_name in NUMERIC_DATE_CLAIMS and _is_struct_datetime(field.type)
    )


def _struct_date_claims(cls: type[Struct]) -> DateClaims:
    """The NumericDate claims (`exp`, `nbf`, `iat`) Struct class `cls` has fields for, whatever
    their annotations (a generic `G[T]` encodes as `G`)."""
    if cls.__struct_config__.array_like:
        return ()
    names = zip(cls.__struct_encode_fields__, cls.__struct_fields__, strict=True)
    return tuple((key, name) for key, name in names if key in NUMERIC_DATE_CLAIMS)


def _model_date_claims(cls: "type[BaseModel]", *, by_alias: bool) -> DateClaims:
    """The NumericDate claims (`exp`, `nbf`, `iat`) BaseModel `cls` has fields for, whatever their
    annotations, named as `cls` encodes them."""
    claims: list[tuple[str, str]] = []
    for name, field in cls.model_fields.items():
        key = (field.serialization_alias or field.alias or name) if by_alias else name
        if key in NUMERIC_DATE_CLAIMS:
            claims.append((key, name))
    return tuple(claims)


def numeric_date(claim: str, value: datetime) -> int:
    """`value` as a NumericDate: whole seconds since the epoch, sub-second precision dropped."""
    if value.utcoffset() is None:
        raise ValueError(
            f"The {claim} claim is a naive datetime (it has no timezone): use an aware one, "
            "e.g. datetime.now(UTC)"
        )
    return (value - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(seconds=1)


def _from_numeric_date(claim: str, value: float) -> datetime:
    """The UTC datetime of a NumericDate, as msgspec converts a Unix timestamp."""
    try:
        return msgspec.convert(value, datetime, strict=False)
    except msgspec.ValidationError as e:
        raise msgspec.ValidationError(f"{e} - at `$.{claim}`") from e
    except (ValueError, OverflowError) as e:  # past year 9999: msgspec's own range check lets it by
        raise msgspec.ValidationError(f"Timestamp is out of range - at `$.{claim}`") from e


def _parse_with_dates(
    decode_members: Callable[[bytes], dict[str, msgspec.Raw]],
    decode: Callable[[bytes], object],
    claims: tuple[str, ...],
    payload: bytes,
) -> object:
    """`decode(payload)` (a Decoder of a Struct), but with each of `claims` that's a NumericDate (a
    JSON number) as its UTC datetime's RFC 3339 string, the only form a (strict) Decoder takes for
    a datetime field. Every other member reaches `decode` as the very JSON it was.

    `decode` does the same in one pass itself (src/dates.rs) for whole seconds from 1970 on in a
    plain payload, the common case, so this decodes the rest."""
    members = decode_members(payload)
    dated = False
    for claim in claims:
        raw = members.get(claim)
        if raw is None:
            continue
        value = msgspec.json.decode(raw)
        if isinstance(value, int | float) and not isinstance(value, bool):
            members[claim] = msgspec.Raw(msgspec.json.encode(_from_numeric_date(claim, value)))
            dated = True
    return decode(msgspec.json.encode(members) if dated else payload)


def _union_members(annotation: object) -> Iterator[object]:
    """The types a field annotated `annotation` may hold: the members of a union (`X | None`),
    without `Annotated` metadata, type aliases resolved."""
    if isinstance(annotation, TypeAliasType):
        yield from _union_members(annotation.__value__)
    elif get_origin(annotation) is Annotated:
        yield from _union_members(get_args(annotation)[0])
    elif get_origin(annotation) in {Union, UnionType}:
        for member in get_args(annotation):
            yield from _union_members(member)
    else:
        yield annotation


def _is_model_datetime(annotation: object) -> bool:
    """Whether a BaseModel field of this annotation is a datetime: `datetime` or one of pydantic's
    datetime types (`AwareDatetime`, `FutureDatetime`, ...), or such a type or None; `Annotated`
    or not."""
    import pydantic  # imported already: the model's class was made with it

    datetime_types = {
        pydantic.AwareDatetime,
        pydantic.FutureDatetime,
        pydantic.NaiveDatetime,
        pydantic.PastDatetime,
    }
    members = list(_union_members(annotation))
    is_datetime = [
        member in datetime_types or (isinstance(member, type) and issubclass(member, datetime))
        for member in members
    ]
    return any(is_datetime) and all(
        dated or member in {None, NoneType}
        for dated, member in zip(is_datetime, members, strict=True)
    )


def _validation_keys(name: str, field: "FieldInfo", *, by_alias: bool, by_name: bool) -> set[str]:
    """The payload members a BaseModel field named `name` is validated from: its alias(es) (single
    keys; not paths into nested values), and its name, if the model validates by it."""
    import pydantic  # imported already: the model's class was made with it

    alias = field.validation_alias if field.validation_alias is not None else field.alias
    if alias is None:
        return {name}
    keys: set[str] = {name} if by_name else set()
    if by_alias:
        choices = alias.choices if isinstance(alias, pydantic.AliasChoices) else [alias]
        for choice in choices:
            path = choice.path if isinstance(choice, pydantic.AliasPath) else [choice]
            if len(path) == 1 and isinstance(path[0], str):
                keys.add(path[0])
    return keys


def _model_datetime_claims(cls: "type[BaseModel]") -> tuple[str, ...]:
    """The NumericDate claims (`exp`, `nbf`, `iat`) BaseModel `cls` validates into datetime
    fields."""
    by_alias: bool = cls.model_config.get("validate_by_alias", True)
    by_name: bool = cls.model_config.get("validate_by_name", False) or cls.model_config.get(
        "populate_by_name", False
    )
    claims: set[str] = set()
    for name, field in cls.model_fields.items():
        if _is_model_datetime(field.annotation):
            keys = _validation_keys(name, field, by_alias=by_alias, by_name=by_name)
            claims |= keys.intersection(NUMERIC_DATE_CLAIMS)
    return tuple(claim for claim in NUMERIC_DATE_CLAIMS if claim in claims)


def _skip_whitespace(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\n\r":
        index += 1
    return index


def _members_at(text: str) -> list[tuple[str, object, int, int]] | None:
    """The members of JSON object `text`: each one's name and value, and where the value starts
    and ends in `text`; None unless `text` is a JSON object."""
    import json  # only here: only models with datetime claims need it

    decoder = json.JSONDecoder()
    index = _skip_whitespace(text, 0)
    if not text.startswith("{", index):
        return None
    index = _skip_whitespace(text, index + 1)
    members: list[tuple[str, object, int, int]] = []
    while not text.startswith("}", index):
        if members:
            if not text.startswith(",", index):
                return None
            index = _skip_whitespace(text, index + 1)
        name, index = decoder.raw_decode(text, index)
        index = _skip_whitespace(text, index)
        if not (isinstance(name, str) and text.startswith(":", index)):
            return None
        start = _skip_whitespace(text, index + 1)
        value, end = decoder.raw_decode(text, start)
        members.append((name, value, start, end))
        index = _skip_whitespace(text, end)
    return members if _skip_whitespace(text, index + 1) == len(text) else None


def _rfc3339(title: str, claim: str, value: float) -> str:
    """The NumericDate `value` as a JSON string of its UTC datetime in RFC 3339 form; pydantic's
    `ValidationError` (for a model titled `title`) if no datetime is that far out."""
    from pydantic_core import ValidationError  # only here: pydantic is optional

    try:
        moment = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=value)
    except (OverflowError, ValueError):
        error: InitErrorDetails = {
            "type": "datetime_parsing",
            "loc": (claim,),
            "input": value,
            "ctx": {"error": "the NumericDate is out of range"},
        }
        raise ValidationError.from_exception_data(title, [error], input_type="json") from None
    return f'"{moment.isoformat()}"'


def _validate_with_dates(
    validate: Callable[[str | bytes], object],
    title: str,
    claims: tuple[str, ...],
    payload: bytes,
) -> object:
    """`validate(payload)` (a BaseModel's `model_validate_json`), but with each of `claims` that's a
    NumericDate (a JSON number) as its UTC datetime's RFC 3339 string: pydantic would take a number
    from 2e10 on as milliseconds (or, as `val_temporal_unit` says, always), not the seconds `decode`
    validated. Every other member reaches `validate` as the very JSON it was."""
    try:
        text = payload.decode()
        members = _members_at(text)
    except ValueError:  # not UTF-8, or not JSON: as pydantic will report
        return validate(payload)
    if members is None:
        return validate(payload)
    pieces: list[str] = []
    copied = 0
    for name, value, start, end in members:
        if name in claims and isinstance(value, int | float) and not isinstance(value, bool):
            pieces += (text[copied:start], _rfc3339(title, name, value))
            copied = end
    if not pieces:
        return validate(payload)
    pieces.append(text[copied:])
    return validate("".join(pieces))


def _encode_with_dates(
    to_dict: Callable[[Any], dict[str, Any]],
    to_json: Callable[[Any], bytes],
    claims: DateClaims,
    instance: object,
) -> bytes:
    """`to_json(to_dict(instance))`, with each of the instance's `claims` that holds a datetime as a
    NumericDate."""
    data = to_dict(instance)
    for key, attribute in claims:
        value = getattr(instance, attribute)
        if key in data and isinstance(value, datetime):
            data[key] = numeric_date(key, value)
    return to_json(data)


def claim_attributes(type_: object) -> ClaimAttributes | None:
    """Where the registered claims (`exp`, `nbf`, `aud`, `iss`) of a decoded `type_` instance are,
    so the payload needn't be scanned for them as well: per claim, the attribute holding it, or
    None if `type_` doesn't declare it (then it's absent unless its name is in the payload).

    None overall unless that is exactly equivalent to scanning the payload: a msgspec Struct that
    decodes from a JSON object without running user code (which mustn't see a token whose claims
    are invalid), where each declared claim is a required field (a default would hide its absence)
    of a type whose decoded value is the JSON value, read straight from its slot.
    """
    origin = _origin(type_)
    if origin is None or not issubclass(origin, Struct):
        return None
    info = msgspec.inspect.type_info(type_)
    if (
        not isinstance(info, msgspec.inspect.StructType)
        or info.array_like
        or info.tag_field in REGISTERED_CLAIMS
        or not _decodes_without_user_code(info)
    ):
        return None
    fields = {f.encode_name: f for f in info.fields}
    attributes: list[str | None] = []
    for claim in REGISTERED_CLAIMS:
        if claim not in fields:
            attributes.append(None)
            continue
        field = fields[claim]
        if not (
            field.required
            and _is_claim_type(claim, field.type)
            and _is_plain_slot(origin, field.name)
        ):
            return None
        attributes.append(field.name)
    exp, nbf, aud, iss = attributes
    return exp, nbf, aud, iss


def payload_parser(type_: object) -> Callable[[bytes], Any]:
    """A callable turning payload JSON bytes into an instance of `type_` (a class, or a
    parametrised generic Struct such as `G[int]`)."""
    origin = _origin(type_)
    if origin is not None and issubclass(origin, Struct):
        decode = msgspec.json.Decoder(type_).decode
        date_claims = _struct_datetime_claims(type_)
        if date_claims:
            decode_members = msgspec.json.Decoder(dict[str, msgspec.Raw]).decode
            return partial(_parse_with_dates, decode_members, decode, date_claims)
        return decode
    if origin is not None and is_model_class(origin):
        date_claims = _model_datetime_claims(origin)
        if date_claims:
            return partial(
                _validate_with_dates, origin.model_validate_json, origin.__name__, date_claims
            )
        return origin.model_validate_json
    raise TypeError(f"type must be None, a msgspec Struct or a pydantic BaseModel, got {type_!r}")


def struct_date_decoder(
    type_: object,
) -> tuple[tuple[str, ...], Callable[[bytes], Any], type[Exception]] | None:
    """For a Struct that declares NumericDate claims (`exp`, `nbf`, `iat`) as datetimes, which its
    `payload_parser` converts: those claims (by JSON name), the Struct's plain decoder, and the
    error that raises for a payload that doesn't fit. Given the payload with those claims (each a
    whole number of seconds) as RFC 3339 strings, as `_parse_with_dates` makes it, the decoder
    decodes as `payload_parser` would; `decode` makes that payload itself when it can. None for any
    other type."""
    origin = _origin(type_)
    if origin is None or not issubclass(origin, Struct):
        return None
    date_claims = _struct_datetime_claims(type_)
    if not date_claims:
        return None
    return date_claims, msgspec.json.Decoder(type_).decode, msgspec.ValidationError


def mismatch(type_: object, error: BaseException) -> tuple[str, bool] | None:
    """Why the payload doesn't fit `type_`, if that's what `error` (raised by its
    `payload_parser`) says: a message, and whether it's that the payload isn't valid JSON (which
    pydantic reports as a validation error). None for any other error."""
    origin = _origin(type_)
    if origin is None:
        return None
    if is_model_class(origin):
        from pydantic_core import ValidationError  # only here: pydantic is optional

        if not isinstance(error, ValidationError):
            return None
        first = error.errors(include_url=False)[0]
        if first["type"] == "json_invalid":
            return f"Invalid payload JSON: {first['msg'].removeprefix('Invalid JSON: ')}", True
        location = ".".join(str(part) for part in first["loc"])
        detail = f"{first['msg']} - at `{location}`" if location else first["msg"]
        return f"Claims don't match {origin.__name__}: {detail}", False
    if isinstance(error, msgspec.ValidationError):
        return f"Claims don't match {origin.__name__}: {error}", False
    return None


def _model_dump(claims: "BaseModel", *, by_alias: bool) -> dict[str, Any]:
    return claims.model_dump(mode="json", by_alias=by_alias)


def _model_dump_json(claims: "BaseModel", *, by_alias: bool) -> bytes:
    return claims.model_dump_json(by_alias=by_alias).encode()


def _payload_encoder(
    encode: Callable[[Any], bytes],
    to_dict: Callable[[Any], dict[str, Any]],
    to_json: Callable[[Any], bytes],
    date_claims: DateClaims,
) -> PayloadEncoder:
    if not date_claims:
        return encode, (), encode
    attributes = tuple(attribute for _, attribute in date_claims)
    return encode, attributes, partial(_encode_with_dates, to_dict, to_json, date_claims)


def payload_encoder(cls: type[object]) -> PayloadEncoder:
    """How to turn an instance of `cls` (a Struct or BaseModel class) into JSON bytes: a callable;
    the attributes of the NumericDate claims (`exp`, `nbf`, `iat`) `cls` has fields for, whatever
    their annotations; and the callable to use instead if any of those holds a datetime (as only
    the value can tell, e.g. for a generic Struct), which encodes those as NumericDates."""
    if issubclass(cls, Struct):
        date_claims = _struct_date_claims(cls)
        return _payload_encoder(
            msgspec.json.encode, msgspec.to_builtins, msgspec.json.encode, date_claims
        )
    if is_model_class(cls):
        from pydantic_core import to_json  # only here: pydantic is optional

        # Encode by alias (matching how the model decodes) unless the model opts out.
        by_alias: bool = cls.model_config.get("serialize_by_alias", True)
        date_claims = _model_date_claims(cls, by_alias=by_alias)
        return _payload_encoder(
            partial(_model_dump_json, by_alias=by_alias),
            partial(_model_dump, by_alias=by_alias),
            to_json,
            date_claims,
        )
    raise TypeError(
        f"claims must be a dict, a msgspec Struct or a pydantic BaseModel, got {cls.__name__}"
    )
