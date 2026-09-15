# @runtime PyGhidra
"""DisrobeImport: apply a disrobe recovery report inside Ghidra.

Run this through PyGhidra (Window > Script Manager). It runs the disrobe CLI
on the open program (or ingests a saved JSON report) and applies
the recovered functions, labels, comments, strings, and indicators to the
listing through the FlatProgramAPI and ghidra.program.model.symbol.SymbolTable.

Two invocation styles:

    # 1. shell out to the disrobe CLI on the program's own backing file
    disrobe_import.py          (prompts for symbols / disasm / ioc)

    # 2. ingest a report you already saved
    python -m pyghidra <binary> disrobe_import.py <path-to-report.json>

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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Protocol, TypeGuard

DISROBE_BINARY: str = "disrobe"
CLI_TIMEOUT_SECONDS: int = 300
MAX_REPORT_BYTES: int = 32 * 1024 * 1024

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
    functions: list[FunctionAnnotation] = field(
        default_factory=list[FunctionAnnotation]
    )
    labels: list[LabelAnnotation] = field(default_factory=list[LabelAnnotation])
    comments: list[CommentAnnotation] = field(default_factory=list[CommentAnnotation])
    strings: list[StringAnnotation] = field(default_factory=list[StringAnnotation])

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


def _is_list(value: object) -> TypeGuard[list[Any]]:
    return isinstance(value, list)


def _is_object(value: object) -> TypeGuard[dict[Any, Any]]:
    return isinstance(value, dict)


def _as_list(value: Any, schema: str, what: str) -> list[Any]:
    if not _is_list(value):
        raise ReportError(
            f"{schema}: {what} must be a list, got {type(value).__name__}"
        )
    return value


def parse_report(text: str) -> dict[str, Any]:
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"report is not valid JSON: {exc}") from exc
    if not _is_object(parsed):
        raise ReportError("report root must be a JSON object")
    if "schema" not in parsed:
        raise ReportError("report has no 'schema' field; not a disrobe report")
    if not isinstance(parsed["schema"], str):
        raise ReportError("report 'schema' must be a string")
    return parsed


def _map_symbol_map(report: dict[str, Any]) -> AnnotationSet:
    schema: str = SCHEMA_SYMBOL_MAP
    image_base: int = _as_int(
        _require(report, "image_base", schema), schema, "image_base"
    )
    source: str | None = report.get("source")
    oep: Any = report.get("original_entry_point")
    functions: list[FunctionAnnotation] = []
    labels: list[LabelAnnotation] = []
    comments: list[CommentAnnotation] = []
    for raw in _as_list(_require(report, "symbols", schema), schema, "symbols"):
        if not _is_object(raw):
            raise ReportError(f"{schema}: each symbol must be an object")
        address: int = _as_int(
            _require(raw, "address", schema), schema, "symbol address"
        )
        name: str = _as_str(_require(raw, "name", schema), schema, "symbol name")
        cls: str = _as_str(_require(raw, "class", schema), schema, "symbol class")
        origin: str = _as_str(
            raw.get("origin", "symbol-table"), schema, "symbol origin"
        )
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
                    is_entry=cls == "entry-point"
                    or (isinstance(oep, int) and oep == address),
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
        if not _is_object(raw):
            raise ReportError(f"{schema}: each export must be an object")
        address: int = _as_int(
            _require(raw, "address", schema), schema, "export address"
        )
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
        if not _is_object(raw):
            raise ReportError(f"{schema}: each function must be an object")
        address: int = _as_int(
            _require(raw, "address", schema), schema, "function address"
        )
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
        if not _is_object(raw):
            raise ReportError(f"{schema}: each indicator must be an object")
        offset: int = _as_int(
            _require(raw, "offset", schema), schema, "indicator offset"
        )
        kind: str = _as_str(_require(raw, "kind", schema), schema, "indicator kind")
        value: str = _as_str(_require(raw, "value", schema), schema, "indicator value")
        encoding: str = _as_str(
            raw.get("encoding", "plain"), schema, "indicator encoding"
        )
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
        raise ReportError(
            f"unsupported report schema {schema!r}; supported: {supported}"
        )
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


def apply_annotations(
    annotations: AnnotationSet, applier: GhidraApplier
) -> ApplyResult:
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


def read_report(path: Path) -> str:
    with path.open("rb") as handle:
        data: bytes = handle.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ReportError(f"report exceeds {MAX_REPORT_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReportError("report is not valid UTF-8") from error


def run_disrobe_json(subcommand: Sequence[str], target: str) -> str:
    exe: str = resolve_binary()
    writes_report: bool = tuple(subcommand[:2]) in (
        ("native", "symbols"),
        ("native", "disasm"),
    )
    with TemporaryDirectory(prefix="disrobe-ghidra-") as directory:
        report: Path = Path(directory) / "report.json"
        stdout_path: Path = Path(directory) / "stdout.log"
        stderr_path: Path = Path(directory) / "stderr.log"
        args: list[str] = [exe, *subcommand, target]
        if writes_report:
            args.extend(["--out", str(report)])
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                proc: subprocess.CompletedProcess[bytes] = subprocess.run(
                    args,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=CLI_TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise ReportError(
                    f"disrobe {' '.join(subcommand)} exceeded {CLI_TIMEOUT_SECONDS} seconds"
                ) from error
        if proc.returncode != 0:
            with stderr_path.open("rb") as diagnostics:
                detail: str = (
                    diagnostics.read(4096).decode("utf-8", errors="replace").strip()
                )
            raise ReportError(
                f"disrobe {' '.join(subcommand)} exited {proc.returncode}: {detail}"
            )
        return read_report(report if writes_report else stdout_path)


CLI_ACTIONS: dict[str, list[str]] = {
    "native symbols": ["native", "symbols"],
    "native disasm (json)": ["native", "disasm", "--emit", "json"],
    "ioc": ["--json", "ioc"],
}


class _FlatApiApplier:
    def __init__(
        self: _FlatApiApplier, script: Any, /, *, file_offsets: bool = False
    ) -> None:
        self._script: Any = script
        self._program: Any = script.getCurrentProgram()
        self._space: Any = self._program.getAddressFactory().getDefaultAddressSpace()
        self._symbols: Any = self._program.getSymbolTable()
        self._listing: Any = self._program.getListing()
        self._file_offsets: bool = file_offsets

    def address(self: _FlatApiApplier, value: int, /) -> Any:
        if self._file_offsets:
            addresses: Any = self._program.getMemory().locateAddressesForFileOffset(
                value
            )
            if len(addresses) != 1:
                raise ReportError(
                    f"file offset {value} maps to {len(addresses)} addresses; expected one"
                )
            return addresses[0]
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
        code_unit: Any = import_module("ghidra.program.model.listing").CodeUnit
        comment_type: int = (
            code_unit.PLATE_COMMENT
            if ann.kind is CommentKind.PLATE
            else code_unit.EOL_COMMENT
        )
        self._listing.setComment(addr, comment_type, ann.text)
        return True

    def create_string(self: _FlatApiApplier, ann: StringAnnotation, /) -> bool:
        addr: Any = self.address(ann.address)
        try:
            if ann.value.isascii():
                self._script.createAsciiString(addr, len(ann.value))
            else:
                string_type: Any = import_module(
                    "ghidra.program.model.data"
                ).StringUTF8DataType.dataType
                self._listing.createData(
                    addr, string_type, len(ann.value.encode("utf-8"))
                )
            return True
        except Exception:  # noqa: BLE001 - Ghidra throws checked exceptions on overlap
            return False

    def log(self: _FlatApiApplier, message: str, /) -> None:
        self._script.println(message)


def _user_defined_source() -> Any:
    source_type: Any = import_module("ghidra.program.model.symbol").SourceType
    return source_type.USER_DEFINED


def _resolve_target(script: Any) -> tuple[str, bool]:
    args: Iterable[str] = script.getScriptArgs()
    arg_list: list[str] = list(args)
    if arg_list:
        return arg_list[0], True
    program: Any = script.getCurrentProgram()
    path: str | None = program.getExecutablePath()
    if not path:
        raise ReportError(
            "no executable path on currentProgram and no report argument given"
        )
    return path, False


def run() -> None:
    script: Any = globals().get("__this__")
    if script is None:
        raise ReportError("run disrobe_import.py through PyGhidra with a program open")
    target, is_report = _resolve_target(script)
    if is_report:
        text: str = read_report(Path(target))
    else:
        action: str = script.askChoice(
            "disrobe",
            "Select the disrobe report to import:",
            list(CLI_ACTIONS.keys()),
            "native symbols",
        )
        text = run_disrobe_json(CLI_ACTIONS[action], target)
    annotations: AnnotationSet = annotations_from_text(text)
    applier: _FlatApiApplier = _FlatApiApplier(
        script, file_offsets=annotations.schema == SCHEMA_IOC
    )
    result: ApplyResult = apply_annotations(annotations, applier)
    script.println(f"disrobe: {annotations.schema} -> {result.summary()}")


if __name__ == "__main__":
    run()
