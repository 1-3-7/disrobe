from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final


class ReportError(ValueError):
    pass


class Schema(str, Enum):
    SYMBOL_MAP = "disrobe.native.symbol-map/v1"
    SYMBOLS = "disrobe.native.symbols/v0"
    CAPABILITIES = "disrobe.capabilities/v0"
    STRINGS = "disrobe.strings/v0"


_TEXT_KINDS: Final[frozenset[str]] = frozenset({"text", "function"})
_FUNCTION_CLASSES: Final[frozenset[str]] = frozenset({"function", "entry-point"})


@dataclass(frozen=True, slots=True)
class FunctionName:
    address: int
    name: str
    is_func: bool
    demangled: str | None = None
    rebase_relative: bool = False


@dataclass(frozen=True, slots=True)
class Comment:
    address: int
    text: str
    repeatable: bool = False


@dataclass(frozen=True, slots=True)
class RecoveredString:
    offset: int
    value: str
    tag: str


@dataclass(frozen=True, slots=True)
class StructField:
    name: str
    size: int


@dataclass(frozen=True, slots=True)
class RecoveredStruct:
    name: str
    fields: tuple[StructField, ...]


@dataclass(frozen=True, slots=True)
class Annotations:
    schema: str
    source: str | None
    image_base: int | None
    function_names: tuple[FunctionName, ...] = field(default_factory=tuple)
    comments: tuple[Comment, ...] = field(default_factory=tuple)
    strings: tuple[RecoveredString, ...] = field(default_factory=tuple)
    structs: tuple[RecoveredStruct, ...] = field(default_factory=tuple)


def _require(obj: dict[str, Any], key: str, schema: str) -> Any:
    if key not in obj:
        raise ReportError(f"{schema}: missing required field `{key}`")
    return obj[key]


def _as_int(value: Any, ctx: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportError(f"{ctx}: expected integer, got {type(value).__name__}")
    return value


def _as_str(value: Any, ctx: str) -> str:
    if not isinstance(value, str):
        raise ReportError(f"{ctx}: expected string, got {type(value).__name__}")
    return value


def parse_report(raw: str | bytes) -> Annotations:
    try:
        doc: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportError(f"report is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ReportError("report root must be a JSON object")
    schema: str = _as_str(_require(doc, "schema", "report"), "report.schema")
    match schema:
        case Schema.SYMBOL_MAP:
            return _parse_symbol_map(doc, schema)
        case Schema.SYMBOLS:
            return _parse_symbols(doc, schema)
        case Schema.CAPABILITIES:
            return _parse_capabilities(doc, schema)
        case Schema.STRINGS:
            return _parse_strings(doc, schema)
        case _:
            raise ReportError(
                f"unsupported report schema `{schema}`; expected one of "
                f"{', '.join(s.value for s in Schema)}"
            )


def _parse_symbol_map(doc: dict[str, Any], schema: str) -> Annotations:
    image_base: int = _as_int(_require(doc, "image_base", schema), f"{schema}.image_base")
    source: str | None = doc.get("source") if isinstance(doc.get("source"), str) else None
    raw_symbols: Any = _require(doc, "symbols", schema)
    if not isinstance(raw_symbols, list):
        raise ReportError(f"{schema}.symbols must be a list")
    names: list[FunctionName] = []
    comments: list[Comment] = []
    for index, entry in enumerate(raw_symbols):
        if not isinstance(entry, dict):
            raise ReportError(f"{schema}.symbols[{index}] must be an object")
        ctx: str = f"{schema}.symbols[{index}]"
        address: int = _as_int(_require(entry, "address", ctx), f"{ctx}.address")
        name: str = _as_str(_require(entry, "name", ctx), f"{ctx}.name")
        klass: str = _as_str(_require(entry, "class", ctx), f"{ctx}.class")
        demangled_raw: Any = entry.get("demangled")
        demangled: str | None = demangled_raw if isinstance(demangled_raw, str) else None
        label: str = demangled if demangled is not None else name
        is_func: bool = klass in _FUNCTION_CLASSES
        names.append(
            FunctionName(
                address=address,
                name=label,
                is_func=is_func,
                demangled=demangled,
                rebase_relative=True,
            )
        )
        note_raw: Any = entry.get("note")
        if isinstance(note_raw, str) and note_raw:
            comments.append(Comment(address=address, text=f"disrobe: {note_raw}", repeatable=True))
    return Annotations(
        schema=schema,
        source=source,
        image_base=image_base,
        function_names=tuple(names),
        comments=tuple(comments),
        structs=_parse_structs(doc.get("structs"), schema),
    )


def _parse_structs(raw: Any, schema: str) -> tuple[RecoveredStruct, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ReportError(f"{schema}.structs must be a list")
    out: list[RecoveredStruct] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ReportError(f"{schema}.structs[{index}] must be an object")
        ctx: str = f"{schema}.structs[{index}]"
        name: str = _as_str(_require(entry, "name", ctx), f"{ctx}.name")
        raw_fields: Any = _require(entry, "fields", ctx)
        if not isinstance(raw_fields, list):
            raise ReportError(f"{ctx}.fields must be a list")
        fields: list[StructField] = []
        for field_index, raw_field in enumerate(raw_fields):
            if not isinstance(raw_field, dict):
                raise ReportError(f"{ctx}.fields[{field_index}] must be an object")
            field_ctx: str = f"{ctx}.fields[{field_index}]"
            field_name: str = _as_str(_require(raw_field, "name", field_ctx), f"{field_ctx}.name")
            field_size: int = _as_int(_require(raw_field, "size", field_ctx), f"{field_ctx}.size")
            fields.append(StructField(name=field_name, size=field_size))
        out.append(RecoveredStruct(name=name, fields=tuple(fields)))
    return tuple(out)


def _parse_symbols(doc: dict[str, Any], schema: str) -> Annotations:
    source: str | None = doc.get("input") if isinstance(doc.get("input"), str) else None
    raw_exports: Any = _require(doc, "exports", schema)
    if not isinstance(raw_exports, list):
        raise ReportError(f"{schema}.exports must be a list")
    names: list[FunctionName] = []
    for index, entry in enumerate(raw_exports):
        if not isinstance(entry, dict):
            raise ReportError(f"{schema}.exports[{index}] must be an object")
        ctx: str = f"{schema}.exports[{index}]"
        address: int = _as_int(_require(entry, "address", ctx), f"{ctx}.address")
        name: str = _as_str(_require(entry, "name", ctx), f"{ctx}.name")
        kind: str = _as_str(_require(entry, "kind", ctx), f"{ctx}.kind")
        if address == 0 or not name:
            continue
        names.append(
            FunctionName(
                address=address,
                name=name,
                is_func=kind in _TEXT_KINDS,
                rebase_relative=False,
            )
        )
    return Annotations(
        schema=schema,
        source=source,
        image_base=None,
        function_names=tuple(names),
    )


def _join_tags(attack: Any, mbc: Any) -> str:
    parts: list[str] = []
    if isinstance(attack, list) and attack:
        parts.append("ATT&CK " + "/".join(str(a) for a in attack))
    if isinstance(mbc, list) and mbc:
        parts.append("MBC " + "/".join(str(m) for m in mbc))
    return f"  [{', '.join(parts)}]" if parts else ""


def _parse_capabilities(doc: dict[str, Any], schema: str) -> Annotations:
    source: str | None = doc.get("uri") if isinstance(doc.get("uri"), str) else None
    raw_caps: Any = _require(doc, "capabilities", schema)
    if not isinstance(raw_caps, list):
        raise ReportError(f"{schema}.capabilities must be a list")
    comments: list[Comment] = []
    for index, entry in enumerate(raw_caps):
        if not isinstance(entry, dict):
            raise ReportError(f"{schema}.capabilities[{index}] must be an object")
        ctx: str = f"{schema}.capabilities[{index}]"
        address: int = _as_int(_require(entry, "address", ctx), f"{ctx}.address")
        rule: str = _as_str(_require(entry, "rule", ctx), f"{ctx}.rule")
        namespace: str = _as_str(_require(entry, "namespace", ctx), f"{ctx}.namespace")
        description: str = _as_str(_require(entry, "description", ctx), f"{ctx}.description")
        tags: str = _join_tags(entry.get("attack"), entry.get("mbc"))
        comments.append(
            Comment(
                address=address,
                text=f"disrobe capability: {rule} [{namespace}]: {description}{tags}",
            )
        )
        evidence: Any = entry.get("evidence")
        if isinstance(evidence, list):
            for ev_index, ev in enumerate(evidence):
                if not isinstance(ev, dict):
                    raise ReportError(f"{ctx}.evidence[{ev_index}] must be an object")
                ev_ctx: str = f"{ctx}.evidence[{ev_index}]"
                ev_addr: int = _as_int(_require(ev, "address", ev_ctx), f"{ev_ctx}.address")
                feature: str = _as_str(_require(ev, "feature", ev_ctx), f"{ev_ctx}.feature")
                comments.append(
                    Comment(address=ev_addr, text=f"disrobe evidence: {feature}", repeatable=True)
                )
    return Annotations(
        schema=schema,
        source=source,
        image_base=None,
        comments=tuple(comments),
    )


def _string_tag(entry: dict[str, Any]) -> str:
    tag: str = str(entry.get("tag", "plain"))
    match tag:
        case "plain":
            return "plain:wide" if entry.get("wide") is True else "plain"
        case "xor":
            key: Any = entry.get("key")
            return f"xor:{key:#04x}" if isinstance(key, int) else "xor"
        case "rot":
            n: Any = entry.get("n")
            return f"rot:{n}" if isinstance(n, int) else "rot"
        case "codec":
            scheme: Any = entry.get("scheme")
            return f"codec:{scheme}" if isinstance(scheme, str) else "codec"
        case "stack_string":
            return "stack-string"
        case other:
            return other


def _parse_strings(doc: dict[str, Any], schema: str) -> Annotations:
    source: str | None = doc.get("uri") if isinstance(doc.get("uri"), str) else None
    raw_strings: Any = _require(doc, "strings", schema)
    if not isinstance(raw_strings, list):
        raise ReportError(f"{schema}.strings must be a list")
    strings: list[RecoveredString] = []
    for index, entry in enumerate(raw_strings):
        if not isinstance(entry, dict):
            raise ReportError(f"{schema}.strings[{index}] must be an object")
        ctx: str = f"{schema}.strings[{index}]"
        offset: int = _as_int(_require(entry, "offset", ctx), f"{ctx}.offset")
        value: str = _as_str(_require(entry, "value", ctx), f"{ctx}.value")
        strings.append(RecoveredString(offset=offset, value=value, tag=_string_tag(entry)))
    return Annotations(
        schema=schema,
        source=source,
        image_base=None,
        strings=tuple(strings),
    )


def rebase(address: int, report_base: int | None, ida_base: int) -> int:
    if report_base is None:
        return address
    return ida_base + (address - report_base)
