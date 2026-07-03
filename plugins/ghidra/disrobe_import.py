"""DisrobeImport: apply a disrobe recovery report inside Ghidra.

Run this as a Ghidra script (Window > Script Manager). It runs the disrobe CLI
on the open program (or ingests a saved `disrobe ... --json` report) and applies
the recovered functions, labels, comments, strings, and indicators to the
listing through the FlatProgramAPI and ghidra.program.model.symbol.SymbolTable.

Two invocation styles, both Ghidra-idiomatic:

    # 1. shell out to the disrobe CLI on the program's own backing file
    DisrobeImport.py            (prompts for the subcommand: symbols / disasm /
                                 export / ioc) and applies the parsed report.

    # 2. ingest a report you already saved
    analyzeHeadless ... -postScript DisrobeImport.py <path-to-report.json>

The parse and map layers (parse_report, build_annotations) are pure: they take
JSON text and return a Ghidra-independent AnnotationSet, and are covered by the
unit suite in tests/. The Ghidra calls live behind the GhidraApplier adapter so
the core is testable without a Ghidra runtime. The in-tool application path is
manually verifiable when Ghidra is installed; it is not exercised by the suite.

Supported report schemas (the disrobe --json ingestion contract):

    disrobe.native.symbol-map/v1   recovered names at addresses (native export)
    disrobe.native.symbols/v0      exports / imports / sections (native symbols)
    disrobe.native.disasm/v2       discovered functions          (native disasm)
    disrobe.ioc/v0                 indicators of compromise       (ioc)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Protocol, Sequence


DISROBE_BINARY: str = "disrobe"
CLI_TIMEOUT_SECONDS: int = 300

SCHEMA_SYMBOL_MAP: str = "disrobe.native.symbol-map/v1"
SCHEMA_SYMBOLS: str = "disrobe.native.symbols/v0"
SCHEMA_DISASM: str = "disrobe.native.disasm/v2"
SCHEMA_IOC: str = "disrobe.ioc/v0"

PLATE_PREFIX: str = "disrobe"


class ReportError(ValueError):
    """Raised when a disrobe report is missing, malformed, or unsupported."""


class CommentKind(Enum):
    PLATE = "plate"
    EOL = "eol"


class AnnotationKind(Enum):
    FUNCTION = "function"
    LABEL = "label"
    DATA = "data"


@dataclass(frozen=True)
class FunctionAnnotation:
    address: int
    name: str
    is_entry: bool = False
    plate_comment: str | None = None


@dataclass(frozen=True)
class LabelAnnotation:
    address: int
    name: str
    kind: AnnotationKind = AnnotationKind.LABEL


@dataclass(frozen=True)
class CommentAnnotation:
    address: int
    kind: CommentKind
    text: str


@dataclass(frozen=True)
class StringAnnotation:
    address: int
    value: str


@dataclass(frozen=True)
class AnnotationSet:
    schema: str
    source: str | None
    image_base: int | None = None
    functions: list[FunctionAnnotation] = field(default_factory=list)
    labels: list[LabelAnnotation] = field(default_factory=list)
    comments: list[CommentAnnotation] = field(default_factory=list)
    strings: list[StringAnnotation] = field(default_factory=list)

    def total(self: AnnotationSet, /) -> int:
        return (
            len(self.functions)
            + len(self.labels)
            + len(self.comments)
            + len(self.strings)
        )


def _require(obj: dict[str, Any], key: str, schema: str) -> Any:
    if key not in obj:
        raise ReportError(f"{schema}: missing required field {key!r}")
    return obj[key]


def _as_int(value: Any, schema: str, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportError(f"{schema}: {what} must be an integer, got {value!r}")
    return value


def _as_str(value: Any, schema: str, what: str) -> str:
    if not isinstance(value, str):
        raise ReportError(f"{schema}: {what} must be a string, got {value!r}")
    return value


def _as_list(value: Any, schema: str, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReportError(f"{schema}: {what} must be a list, got {type(value).__name__}")
    return value


def parse_report(text: str) -> dict[str, Any]:
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"report is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ReportError("report root must be a JSON object")
    if "schema" not in parsed:
        raise ReportError("report has no 'schema' field; not a disrobe report")
    if not isinstance(parsed["schema"], str):
        raise ReportError("report 'schema' must be a string")
    return parsed


def _map_symbol_map(report: dict[str, Any]) -> AnnotationSet:
    schema: str = SCHEMA_SYMBOL_MAP
    image_base: int = _as_int(_require(report, "image_base", schema), schema, "image_base")
    source: str | None = report.get("source")
    oep: Any = report.get("original_entry_point")
    functions: list[FunctionAnnotation] = []
    labels: list[LabelAnnotation] = []
    comments: list[CommentAnnotation] = []
    for raw in _as_list(_require(report, "symbols", schema), schema, "symbols"):
        if not isinstance(raw, dict):
            raise ReportError(f"{schema}: each symbol must be an object")
        address: int = _as_int(_require(raw, "address", schema), schema, "symbol address")
        name: str = _as_str(_require(raw, "name", schema), schema, "symbol name")
        cls: str = _as_str(_require(raw, "class", schema), schema, "symbol class")
        origin: str = _as_str(raw.get("origin", "symbol-table"), schema, "symbol origin")
        note: Any = raw.get("note")
        demangled: Any = raw.get("demangled")
        if cls in ("function", "entry-point"):
            plate: str = f"{PLATE_PREFIX}: recovered {cls} ({origin})"
            if isinstance(demangled, str) and demangled:
                plate += f"\n{demangled}"
            functions.append(
                FunctionAnnotation(
                    address=address,
                    name=name,
                    is_entry=cls == "entry-point" or (isinstance(oep, int) and oep == address),
                    plate_comment=plate,
                )
            )
        else:
            labels.append(
                LabelAnnotation(address=address, name=name, kind=AnnotationKind.LABEL)
            )
        if isinstance(note, str) and note:
            comments.append(
                CommentAnnotation(
                    address=address,
                    kind=CommentKind.EOL,
                    text=f"{PLATE_PREFIX}: {note}",
                )
            )
    return AnnotationSet(
        schema=schema,
        source=source if isinstance(source, str) else None,
        image_base=image_base,
        functions=functions,
        labels=labels,
        comments=comments,
    )


def _map_symbols(report: dict[str, Any]) -> AnnotationSet:
    schema: str = SCHEMA_SYMBOLS
    source: str | None = report.get("input")
    entry: Any = report.get("entry")
    functions: list[FunctionAnnotation] = []
    labels: list[LabelAnnotation] = []
    comments: list[CommentAnnotation] = []
    for raw in _as_list(report.get("exports", []), schema, "exports"):
        if not isinstance(raw, dict):
            raise ReportError(f"{schema}: each export must be an object")
        address: int = _as_int(_require(raw, "address", schema), schema, "export address")
        name: str = _as_str(_require(raw, "name", schema), schema, "export name")
        kind: str = _as_str(raw.get("kind", ""), schema, "export kind")
        section: Any = raw.get("section")
        if address == 0:
            continue
        is_text: bool = kind in ("text", "func", "function")
        if is_text:
            is_entry: bool = isinstance(entry, int) and entry == address
            functions.append(
                FunctionAnnotation(
                    address=address,
                    name=name,
                    is_entry=is_entry,
                    plate_comment=f"{PLATE_PREFIX}: symbol-table function {name}",
                )
            )
        else:
            labels.append(
                LabelAnnotation(address=address, name=name, kind=AnnotationKind.LABEL)
            )
        if isinstance(section, str) and section:
            comments.append(
                CommentAnnotation(
                    address=address,
                    kind=CommentKind.EOL,
                    text=f"{PLATE_PREFIX}: {kind} in {section}",
                )
            )
    return AnnotationSet(
        schema=schema,
        source=source if isinstance(source, str) else None,
        functions=functions,
        labels=labels,
        comments=comments,
    )


def _map_disasm(report: dict[str, Any]) -> AnnotationSet:
    schema: str = SCHEMA_DISASM
    functions: list[FunctionAnnotation] = []
    comments: list[CommentAnnotation] = []
    for raw in _as_list(_require(report, "functions", schema), schema, "functions"):
        if not isinstance(raw, dict):
            raise ReportError(f"{schema}: each function must be an object")
        address: int = _as_int(_require(raw, "address", schema), schema, "function address")
        name: str = _as_str(_require(raw, "name", schema), schema, "function name")
        is_export: bool = bool(raw.get("is_export", False))
        complexity: Any = raw.get("complexity")
        insn: Any = raw.get("instruction_count")
        parts: list[str] = [f"{PLATE_PREFIX}: discovered function {name}"]
        if isinstance(insn, int):
            parts.append(f"instructions={insn}")
        if isinstance(complexity, int):
            parts.append(f"cyclomatic={complexity}")
        functions.append(
            FunctionAnnotation(
                address=address,
                name=name,
                is_entry=is_export and name in ("_start", "main", "start"),
                plate_comment="  ".join(parts),
            )
        )
    return AnnotationSet(
        schema=schema,
        source=None,
        functions=functions,
        comments=comments,
    )


def _map_ioc(report: dict[str, Any]) -> AnnotationSet:
    schema: str = SCHEMA_IOC
    source: str | None = report.get("uri")
    comments: list[CommentAnnotation] = []
    strings: list[StringAnnotation] = []
    for raw in _as_list(_require(report, "indicators", schema), schema, "indicators"):
        if not isinstance(raw, dict):
            raise ReportError(f"{schema}: each indicator must be an object")
        offset: int = _as_int(_require(raw, "offset", schema), schema, "indicator offset")
        kind: str = _as_str(_require(raw, "kind", schema), schema, "indicator kind")
        value: str = _as_str(_require(raw, "value", schema), schema, "indicator value")
        encoding: str = _as_str(raw.get("encoding", "plain"), schema, "indicator encoding")
        comments.append(
            CommentAnnotation(
                address=offset,
                kind=CommentKind.EOL,
                text=f"{PLATE_PREFIX} IOC [{kind}/{encoding}]: {value}",
            )
        )
        strings.append(StringAnnotation(address=offset, value=value))
    return AnnotationSet(
        schema=schema,
        source=source if isinstance(source, str) else None,
        comments=comments,
        strings=strings,
    )


_MAPPERS: dict[str, Callable[[dict[str, Any]], AnnotationSet]] = {
    SCHEMA_SYMBOL_MAP: _map_symbol_map,
    SCHEMA_SYMBOLS: _map_symbols,
    SCHEMA_DISASM: _map_disasm,
    SCHEMA_IOC: _map_ioc,
}


def build_annotations(report: dict[str, Any]) -> AnnotationSet:
    schema: str = report["schema"]
    mapper: Callable[[dict[str, Any]], AnnotationSet] | None = _MAPPERS.get(schema)
    if mapper is None:
        supported: str = ", ".join(sorted(_MAPPERS))
        raise ReportError(f"unsupported report schema {schema!r}; supported: {supported}")
    return mapper(report)


def annotations_from_text(text: str) -> AnnotationSet:
    return build_annotations(parse_report(text))


class GhidraApplier(Protocol):
    def address(self: GhidraApplier, value: int, /) -> Any: ...
    def create_function(self: GhidraApplier, ann: FunctionAnnotation, /) -> bool: ...
    def create_label(self: GhidraApplier, ann: LabelAnnotation, /) -> bool: ...
    def set_comment(self: GhidraApplier, ann: CommentAnnotation, /) -> bool: ...
    def create_string(self: GhidraApplier, ann: StringAnnotation, /) -> bool: ...
    def log(self: GhidraApplier, message: str, /) -> None: ...


@dataclass
class ApplyResult:
    functions: int = 0
    labels: int = 0
    comments: int = 0
    strings: int = 0
    skipped: int = 0

    def summary(self: ApplyResult, /) -> str:
        return (
            f"{self.functions} function(s), {self.labels} label(s), "
            f"{self.comments} comment(s), {self.strings} string(s), "
            f"{self.skipped} skipped"
        )


def apply_annotations(annotations: AnnotationSet, applier: GhidraApplier) -> ApplyResult:
    result: ApplyResult = ApplyResult()
    for fn in annotations.functions:
        if applier.create_function(fn):
            result.functions += 1
            if fn.plate_comment is not None:
                applier.set_comment(
                    CommentAnnotation(
                        address=fn.address,
                        kind=CommentKind.PLATE,
                        text=fn.plate_comment,
                    )
                )
                result.comments += 1
        else:
            result.skipped += 1
    for label in annotations.labels:
        if applier.create_label(label):
            result.labels += 1
        else:
            result.skipped += 1
    for comment in annotations.comments:
        if applier.set_comment(comment):
            result.comments += 1
        else:
            result.skipped += 1
    for string in annotations.strings:
        if applier.create_string(string):
            result.strings += 1
        else:
            result.skipped += 1
    applier.log(f"{PLATE_PREFIX}: applied {result.summary()}")
    return result


def resolve_binary() -> str:
    found: str | None = shutil.which(DISROBE_BINARY)
    return found if found is not None else DISROBE_BINARY


def run_disrobe_json(subcommand: Sequence[str], target: str) -> str:
    exe: str = resolve_binary()
    args: list[str] = [exe, *subcommand, target]
    proc: subprocess.CompletedProcess[str] = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=CLI_TIMEOUT_SECONDS,
        check=False,
    )
    if proc.returncode != 0:
        raise ReportError(
            f"disrobe {' '.join(subcommand)} exited {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout


CLI_ACTIONS: dict[str, list[str]] = {
    "native symbols": ["native", "symbols"],
    "native disasm (json)": ["native", "disasm", "--emit", "json"],
    "ioc": ["--json", "ioc"],
}


class _FlatApiApplier:
    def __init__(self: _FlatApiApplier, script: Any, /) -> None:
        self._script: Any = script
        self._program: Any = script.getCurrentProgram()
        self._space: Any = self._program.getAddressFactory().getDefaultAddressSpace()
        self._symbols: Any = self._program.getSymbolTable()
        self._listing: Any = self._program.getListing()

    def address(self: _FlatApiApplier, value: int, /) -> Any:
        return self._space.getAddress(value)

    def create_function(self: _FlatApiApplier, ann: FunctionAnnotation, /) -> bool:
        addr: Any = self.address(ann.address)
        existing: Any = self._listing.getFunctionAt(addr)
        if existing is not None:
            existing.setName(ann.name, _user_defined_source())
            return True
        created: Any = self._script.createFunction(addr, ann.name)
        return created is not None

    def create_label(self: _FlatApiApplier, ann: LabelAnnotation, /) -> bool:
        addr: Any = self.address(ann.address)
        self._symbols.createLabel(addr, ann.name, _user_defined_source())
        return True

    def set_comment(self: _FlatApiApplier, ann: CommentAnnotation, /) -> bool:
        addr: Any = self.address(ann.address)
        from ghidra.program.model.listing import CodeUnit  # type: ignore[import-not-found]

        comment_type: int = (
            CodeUnit.PLATE_COMMENT
            if ann.kind is CommentKind.PLATE
            else CodeUnit.EOL_COMMENT
        )
        self._listing.setComment(addr, comment_type, ann.text)
        return True

    def create_string(self: _FlatApiApplier, ann: StringAnnotation, /) -> bool:
        addr: Any = self.address(ann.address)
        try:
            self._script.createAsciiString(addr, len(ann.value))
            return True
        except Exception:  # noqa: BLE001 - Ghidra throws checked exceptions on overlap
            return False

    def log(self: _FlatApiApplier, message: str, /) -> None:
        self._script.println(message)


def _user_defined_source() -> Any:
    from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

    return SourceType.USER_DEFINED


def _resolve_target(script: Any) -> tuple[str, bool]:
    args: Iterable[str] = script.getScriptArgs()
    arg_list: list[str] = list(args)
    if arg_list:
        return arg_list[0], True
    program: Any = script.getCurrentProgram()
    path: str | None = program.getExecutablePath()
    if not path:
        raise ReportError("no executable path on currentProgram and no report argument given")
    return path, False


def run() -> None:
    script: Any = globals().get("__ghidra_script__")
    if script is None:
        import __main__  # type: ignore[import-not-found]

        script = __main__
    target, is_report = _resolve_target(script)
    if is_report:
        with open(target, "r", encoding="utf-8") as handle:
            text: str = handle.read()
    else:
        action: str = script.askChoice(
            "disrobe",
            "Select the disrobe report to import:",
            list(CLI_ACTIONS.keys()),
            "native symbols",
        )
        text = run_disrobe_json(CLI_ACTIONS[action], target)
    annotations: AnnotationSet = annotations_from_text(text)
    applier: _FlatApiApplier = _FlatApiApplier(script)
    result: ApplyResult = apply_annotations(annotations, applier)
    script.println(f"disrobe: {annotations.schema} -> {result.summary()}")


if __name__ == "__main__":
    run()
