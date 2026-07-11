# Python bindings

**disrobe** ships a typed Python library that mirrors the full CLI surface. The
importable `disrobe` module is built from `crates/disrobe-python` with pyo3
(abi3, Python 3.9+) and wraps the same Rust library the CLI uses. Bytes go in;
a concrete typed report object comes out. Output is deterministic: the same
input produces the same report bytes.

The library does not read or write the filesystem; the caller owns all I/O.
Wheels are not published to PyPI; build from source.

## Install

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe/bindings/python
pip install maturin
maturin develop --release
```

For a redistributable wheel:

```sh
maturin build --release
pip install target/wheels/disrobe-*.whl
```

The `pyproject.toml` pins `maturin>=1.5,<2.0`, sets `module-name =
"disrobe.disrobe"`, and points at `crates/disrobe-python/Cargo.toml`. On
Windows the crate's `build.rs` searches `PYO3_PYTHON`, an active
`VIRTUAL_ENV`, and standard install locations; set `PYO3_PYTHON=<path-to-python.exe>`
if none is found. A `py.typed` marker is shipped so pyright and mypy resolve
every attribute from the `.pyi` stub.

```python
import disrobe

version: str = disrobe.__version__
```

## Report model

Every analysis function returns a concrete subclass of `_Report`. The base
carries the full serialization surface every report shares.

### `_Report`

| Member | Signature | Notes |
|---|---|---|
| `raw` | `@property -> dict[str, Any]` | Full underlying record; no detail dropped |
| `to_json` | `() -> str` | Compact JSON string |
| `from_json_str` | `classmethod(text: str) -> Self` | Rebuild from a `to_json` string |
| `from_obj` | `classmethod(obj: dict[str, Any]) -> Self` | Wrap an already-decoded dict |

Reports compare equal when their underlying records are equal (`==` / `!=`).

### `_LlmReport`

Subclasses `_Report`. Adds one property:

| Member | Signature | Notes |
|---|---|---|
| `llm` | `@property -> LlmBundle \| None` | Populated when metadata output was requested; `None` otherwise |

Metadata-wired passes: `py_decompile`, `py_disasm`, `py_deob`, `pyarmor_detect`,
`pyarmor_unpack`. Functions that build a metadata bundle accept
`pack: Pack | None` where `Pack = Literal["pack-1", "pack-2", "pack-3", "pack-4"]`.

### `LlmBundle`

A `TypedDict(total=False)` mirroring the `disrobe.metadata.llm.v1` on-disk schema. The type name and schema id are stable API names; the payload is deterministic metadata, not model output.
Keys present depend on which `pack` was requested.

```python
from disrobe import LlmBundle
from typing import Any

bundle: LlmBundle = {
    "schema": "disrobe.metadata.llm.v1",
    "schema_version": "1",
    "generated_at": "2026-06-16T00:00:00Z",
    "tool": {},
    "selection": {},
    "input": {},
    "pipeline": [],
    "categories": {},
}
```

### Literal type aliases

| Alias | Values |
|---|---|
| `Pack` | `"pack-1"`, `"pack-2"`, `"pack-3"`, `"pack-4"` |
| `RoundtripStatus` | `"perfect"`, `"semantic"`, `"code-diff"`, `"no-interpreter"`, `"recompile-failed"`, `"skipped"` |
| `PyarmorUnpackStatus` | `"functional"`, `"bcc-partial"`, `"detect-only"`, `"skeleton"` |
| `ContainerListing` | `"enumerated"`, `"requires-extraction"`, `"unreadable"` |
| `SymbolKind` | `"function"`, `"data"`, `"label"`, `"export"`, `"import"` |
| `InstructionFlow` | `"sequential"`, `"call"`, `"indirect-call"`, `"conditional-branch"`, `"unconditional-branch"`, `"indirect-branch"`, `"return"`, `"interrupt"` |
| `SourceLanguage` | `"python"`, `"py"`, `"python3"` |
| `JsLanguage` | `"javascript"`, `"js"`, `"typescript"`, `"ts"` |
| `ByteLanguage` | `"python-bytecode"`, `"pyc"`, `"jvm-class"`, `"class"`, `"dex"`, `"beam"`, `"hermes"`, `"hermes-bundle"`, `"hbc"`, `"wasm"` |
| `ParseByteLanguage` | `"go"`, `"swift"`, `"objc"`, `"objective-c"`, `"kotlin"`, `"ruby"`, `"lua"`, `"php"` |
| `DisasmByteLanguage` | `"ruby"`, `"ruby-bytecode"`, `"yarv"`, `"mruby"`, `"php"`, `"php-bytecode"` |
| `DecompileLanguage` | `"python-bytecode"`, `"pyc"`, `"jvm-class"`, `"class"`, `"java"`, `"kotlin"`, `"lua"`, `"ruby"`, `"php"`, `"php-bytecode"`, `"javascript"`, `"js"`, `"typescript"`, `"ts"` |

### Exception hierarchy

| Class | Base | Raised when |
|---|---|---|
| `DisrobeError` | `Exception` | Any binding fails |
| `UnsupportedLanguage` | `DisrobeError` | `disasm`/`parse`/`compile`/`decompile` for a language with no backing implementation; message includes a hint |

## Module-level functions: full surface

| Category | Function | Returns |
|---|---|---|
| Auto chain | `auto(input, *, max_depth=8, path_hint=None)` | `ChainReport` |
| Generic dispatch | `decompile(language, source)` | `CanonicalSource` |
| | `disasm(language, source)` | `str` |
| | `parse(language, source)` | typed report or `dict[str, Any]` |
| | `compile(language, source, *, version=None)` | `bytes` |
| Custom pass | `register_pass(name, callable)` | `None` |
| | `register_consumer(name, callable)` | `None` |
| | `registered_passes()` | `list[str]` |
| | `registered_consumers()` | `list[str]` |
| | `unregister(name)` | `bool` |
| | `run_pass(name, data)` | `Any` |
| | `run_chain(names, data)` | `Any` |
| | `emit(name, result, **context)` | `Any` |
| Analysis | `strings_extract(data, *, min_len=4, decode=True)` | `StringsReport` |
| | `ioc_extract(data)` | `IocReport` |
| | `behavior_analyze(data)` | `BehaviorReport` |
| | `identify(data)` | `IdentifyReport` |
| | `secret_scan(data)` | `SecretScanReport` |
| | `capabilities(binary_bytes)` | `Capabilities` |
| | `extract(data, out_dir)` | `ExtractionResult` |
| | `extract_recursive(data, *, source_label='inline', max_depth=8)` | `OverlayReport` |
| | `yara_parse(ruleset_source)` | `YaraReport` |
| | `yara_generate(data, *, name=None)` | `YaraReport` |
| Native | `native_symbols(data)` | `SymbolsReport` |
| | `native_disasm(data)` | `DisasmPayload` |
| | `native_callgraph(data)` | `CallGraph` |
| | `native_imports_dot(data)` | `str` |
| | `native_entropy(data)` | `EntropyReport` |
| | `native_sbom(data)` | `SbomReport` |
| | `native_fingerprint(data, *, flirt=None)` | `FingerprintReport` |
| | `native_signatures(data, *, flirt=None)` | `SignatureReport` |
| | `native_sigmaker(data, at)` | `SigmakerReport` |
| | `native_diff(a, b)` | `DiffReport` |
| | `native_patch(data, *, at, replacement=None, nop_start=None, nop_end=None)` | `tuple[bytes, PatchReport]` |
| | `native_format(binary_bytes)` | `NativeFormat` |
| | `native_detect(binary_bytes)` | `DetectionList` |
| | `native_probe_backends()` | `BackendList` |
| | `native_deobfuscate(code, *, bits=64, base=0, entry=0)` | `NativeDeobfuscation` |
| Query IR | `query_functions(dr_bytes)` | `FunctionList` |
| | `query_calls_to(dr_bytes, target)` | `QueryReport` |
| | `query_xrefs_to(dr_bytes, symbol)` | `QueryReport` |
| | `query_string_decoders(dr_bytes)` | `QueryReport` |
| | `query_complexity_over(dr_bytes, threshold)` | `QueryReport` |
| | `query_capability_sites(dr_bytes, capability)` | `QueryReport` |
| | `query_call_graph(dr_bytes)` | `CallGraph` |
| Envelope | `envelope_create(payload, *, source_label='inline', produced_by=None, detected_format=None)` | `bytes` |
| | `envelope_verify(envelope_bytes)` | `EnvelopeReport` |
| LLM renders | `agents_md(result)` | `str` |
| | `skill_md(result)` | `str` |
| | `provenance(result)` | `Provenance` |
| Python decompile | `py_decompile(pyc_bytes, *, roundtrip=False, pack=None)` | `PyDecompileReport` |
| | `py_disasm(pyc_bytes, *, pack=None)` | `PyDisasmReport` |
| Python deobfuscate | `py_deob(source, *, cleanup=True, pack=None)` | `PyDeobReport` |
| | `py_deob_detect(source)` | `PyDeobDetection` |
| | `py_deob_list_passes()` | `list[ObfuscatorPass]` |
| | `py_deob_detect_pass(source, pass_id)` | `PyDeobDetection` |
| PyArmor | `pyarmor_detect(source, *, pack=None)` | `PyarmorDetection` |
| | `pyarmor_unpack(wrapper_bytes, *, pack=None)` | `PyarmorUnpack` |
| | `pyarmor_classify(source, payload)` | `PyarmorClassification` |
| PyInstaller | `pyinstaller_extract(image_bytes)` | `PyInstallerArchive` |
| | `pyinstaller_entry_bytes(image_bytes, entry_name)` | `bytes` |
| Nuitka | `nuitka_detect(image_bytes)` | `NuitkaDetection` |
| | `nuitka_extract(image_bytes)` | `NuitkaExtraction` |
| Hermes | `hermes_disasm(bundle_bytes)` | `HermesDisassembly` |
| | `hermes_lift(bundle_bytes)` | `HermesLift` |
| | `hermes_info(bundle_bytes)` | `HermesInfo` |
| Mach-O | `macho_dump(macho_bytes)` | `MachoReport` |
| | `swift_analyze(macho_bytes)` | `SwiftReport` |
| JVM / Android | `jvm_parse_class(class_bytes)` | `JvmClass` |
| | `jvm_parse_dex(dex_bytes)` | `DexFileReport` |
| | `jvm_decompile_class(class_bytes)` | `JvmDecompiledClass` |
| | `jvm_detect(class_bytes)` | `DetectionList` |
| | `jvm_backends()` | `JvmBackends` |
| | `apk_resources(apk_bytes)` | `ApkResources` |
| .NET | `dotnet_parse_pe(pe_bytes)` | `DotnetPe` |
| | `dotnet_parse_metadata(pe_bytes)` | `DotnetMetadata` |
| | `dotnet_detect(pe_bytes)` | `DotnetDetection` |
| | `dotnet_analyze(pe_bytes)` | `DotnetAnalysis` |
| | `dotnet_decompile(pe_bytes)` | `DotnetDecompilation` |
| | `dotnet_recover_decoders(pe_bytes)` | `DotnetDecoders` |
| | `dotnet_backends()` | `BackendList` |
| WebAssembly | `wasm_analyze(wasm_bytes)` | `WasmAnalysis` |
| | `wasm_detect(wasm_bytes)` | `WasmDetection` |
| JavaScript | `js_detect(js_source)` | `JsDetection` |
| | `js_unminify(js_source)` | `JsUnminify` |
| | `js_unbundle(js_source, *, bundler=None)` | `JsUnbundle` |
| Lua | `lua_detect(bytecode)` | `LuaDetection` |
| | `lua_decompile(bytecode)` | `LuaDecompilation` |
| | `lua_deobfuscate(source, *, authorize=False, strict=False)` | `LuaDeobfuscation` |
| Go | `go_analyze(binary_bytes)` | `GoAnalysis` |
| | `go_symbols(binary_bytes)` | `GoSymbols` |
| | `go_pclntab(binary_bytes)` | `GoPclntab` |
| | `go_garble(binary_bytes)` | `GarbleReport` |
| Ruby | `ruby_detect(ruby_bytes, *, source_path=None)` | `RubyDetection` |
| | `ruby_decompile(ruby_bytes, *, source_path=None)` | `RubyAnalysis` |
| PHP | `php_detect(php_bytes)` | `PhpDetection` |
| | `php_scan(php_bytes)` | `PhpScan` |
| | `php_decode(php_bytes, *, max_depth=None)` | `PhpDecode` |
| Shell | `batch_deobfuscate(script, *, args=None)` | `BatchDeobReport` |
| | `powershell_detect(script)` | `PowershellDetection` |
| | `powershell_deobfuscate(script)` | `PowershellDeobfuscation` |
| Containers | `container_detect(container_bytes)` | `ContainerDetection` |
| | `container_members(container_bytes)` | `ContainerMembers` |
| Pickle | `pickle_disasm(pickle_bytes)` | `str` |
| | `pickle_decompile(pickle_bytes)` | `PickleDecompilation` |
| | `pickle_safety(pickle_bytes)` | `PickleSafety` |
| | `pickle_trace(pickle_bytes)` | `PickleTrace` |
| | `pickle_polyglot(file_bytes)` | `PicklePolyglot` |
| | `pickle_ml_detect(file_bytes)` | `PickleMlReport` |

## Auto chain

```python
import disrobe
from disrobe import ChainReport

with open("sample.bin", "rb") as fh:
    chain: ChainReport = disrobe.auto(fh.read(), max_depth=8)

spec: str | None = chain.spec
pass_count: int = chain.pass_count
terminated: bool = chain.terminated
full_plan: dict[str, object] = chain.raw
```

`auto` runs the chain detector against raw bytes and returns a `ChainReport`
carrying the full `chain.json` plan the CLI produces; it does not write stage
outputs to disk. `max_depth` must be 1-16; out-of-range values raise
`DisrobeError`. The registered pass tree covers pyarmor, pyinstaller, nuitka,
py-decompile, py-deob, container, js, jvm, dotnet, wasm, mobile, swift-objc,
and the native packer detector.

### `ChainReport` accessors

| Property | Type |
|---|---|
| `spec` | `str \| None` |
| `pass_count` | `int` |
| `terminated` | `bool` |

## Generic dispatch

Language-keyed entry points that fan out to the per-language passes.

### `decompile`

```python
def decompile(language: str, source: str | bytes) -> CanonicalSource: ...
```

Wired families: `python`/`pyc` (py-decompile), `jvm-class`/`class`/`java`/`kotlin`
(JVM lifter), `lua` (register lifter), `ruby` (YARV/mruby recovery),
`php`/`php-bytecode` (eval-chain peel/op-array skeleton),
`javascript`/`js`/`typescript`/`ts` (unminify). Binary-only targets (`go`,
`swift`, `wasm`) have no single source body; call their structural binding or
`parse` instead.

```python
import disrobe
from disrobe import CanonicalSource

with open("module.pyc", "rb") as fh:
    recovered: CanonicalSource = disrobe.decompile("python-bytecode", fh.read())

source: str | None = recovered.source
language: str | None = recovered.language
produced_by: str | None = recovered.produced_by
confidence: float | None = recovered.confidence
```

### `CanonicalSource` accessors

| Property | Type |
|---|---|
| `source` | `str \| None` |
| `language` | `str \| None` |
| `produced_by` | `str \| None` |
| `confidence` | `float \| None` |

### `disasm`

```python
def disasm(language: str, source: str | bytes) -> str: ...
```

Returns a rendered instruction listing as text. Wired: `python`/`pyc`,
`jvm-class`/`class`, `dex`, `beam`, `hermes`, `wasm`,
`ruby`/`yarv`/`mruby`, and `php`/`php-bytecode`. For Lua use
`decompile('lua', ...)` or `parse('lua', ...)` instead.

### `parse`

```python
def parse(language: str, source: str | bytes) -> (
    dict[str, Any]
    | GoAnalysis
    | SwiftReport
    | JvmClass
    | RubyAnalysis
    | LuaDecompilation
    | PhpDecode
    | JsUnminify
): ...
```

Returns a typed report for structural-recovery languages: `go` -> `GoAnalysis`,
`swift`/`objc`/`objective-c` -> `SwiftReport`, `kotlin` -> `JvmClass`,
`ruby` -> `RubyAnalysis`, `lua` -> `LuaDecompilation`, `php` -> `PhpDecode`,
`javascript`/`js`/`typescript`/`ts` -> `JsUnminify`. Container and bytecode
formats (`pyc`, `jvm-class`, `dex`, `wasm`, `hermes`, `beam`) return a nested
`dict[str, Any]` because their full parse records have no single typed shape.

```python
import disrobe
from typing import Any

with open("Hello.class", "rb") as fh:
    parsed: dict[str, Any] = disrobe.parse("jvm-class", fh.read())
method_count: int = len(parsed["methods"])
```

### `compile`

```python
def compile(language: str, source: str, *, version: str | None = None) -> bytes: ...
```

Implemented for Python only; returns raw `marshal.dumps` bytes (no `.pyc`
header) via the host interpreter. `lua`, `ruby`, and `php` raise
`UnsupportedLanguage` with a hint pointing at the CLI subcommand or toolchain.

```python
import disrobe

blob: bytes = disrobe.compile("python", "x: int = 1 + 2\n")
listing: str = disrobe.disasm("python", "x: int = 1 + 2\n")
```

## Custom pass plugin protocol

Register and compose named passes and output consumers in the host process.

```python
from typing import Any
import disrobe
from disrobe import Pass, OutputConsumer

def my_pass(data: Any) -> Any:
    return data[::-1]

def my_consumer(result: Any, **context: Any) -> Any:
    print(result, context)

disrobe.register_pass("reverse", my_pass)
disrobe.register_consumer("print", my_consumer)

names: list[str] = disrobe.registered_passes()
consumer_names: list[str] = disrobe.registered_consumers()

output: Any = disrobe.run_pass("reverse", b"hello")
chained: Any = disrobe.run_chain(["reverse", "reverse"], b"hello")
disrobe.emit("print", chained, source="example")

removed: bool = disrobe.unregister("reverse")
```

### `Pass` and `OutputConsumer` protocols

Both are `@runtime_checkable` protocols.

| Protocol | Signature |
|---|---|
| `Pass` | `__call__(self, data: Any) -> Any` |
| `OutputConsumer` | `__call__(self, result: Any, **context: Any) -> Any` |

## Analysis

### `strings_extract`

```python
def strings_extract(data: bytes, *, min_len: int = 4, decode: bool = True) -> StringsReport: ...
```

Extracts ASCII and UTF-16 strings from a binary blob.

### `ioc_extract`

```python
def ioc_extract(data: bytes) -> IocReport: ...
```

Harvests indicators of compromise from bytes and recovered strings.

### `behavior_analyze`

```python
def behavior_analyze(data: bytes) -> BehaviorReport: ...
```

Behavioral summary by category with MITRE ATT&CK IDs.

### `identify`

```python
def identify(data: bytes) -> IdentifyReport: ...
```

Compiler/linker/packer/protector/installer fingerprint.

### `secret_scan`

```python
def secret_scan(data: bytes) -> SecretScanReport: ...
```

Leaked-credential scan over raw bytes.

### `capabilities`

```python
def capabilities(binary_bytes: bytes) -> Capabilities: ...
```

Capability rule-set matches for a native binary.

### `extract`

```python
def extract(data: bytes, out_dir: str) -> ExtractionResult: ...
```

Carves container/firmware members to `out_dir`.

### `extract_recursive`

```python
def extract_recursive(
    data: bytes, *, source_label: str = "inline", max_depth: int = 8
) -> OverlayReport: ...
```

Recursive multi-magic carve; classifies every chunk by entropy and nesting.

### `yara_parse` / `yara_generate`

```python
def yara_parse(ruleset_source: str) -> YaraReport: ...
def yara_generate(data: bytes, *, name: str | None = None) -> YaraReport: ...
```

Parse a YARA ruleset AST or generate a candidate rule from a binary blob.

```python
import disrobe
from disrobe import (
    StringsReport, IocReport, BehaviorReport, IdentifyReport,
    SecretScanReport, Capabilities, OverlayReport, YaraReport,
)

with open("suspect.bin", "rb") as fh:
    data: bytes = fh.read()

strings: StringsReport = disrobe.strings_extract(data, min_len=6)
string_count: int = strings.string_count

iocs: IocReport = disrobe.ioc_extract(data)
indicator_count: int = iocs.indicator_count

behavior: BehaviorReport = disrobe.behavior_analyze(data)
category_count: int = behavior.category_count

ident: IdentifyReport = disrobe.identify(data)
fmt: str | None = ident.format
finding_count: int = ident.finding_count

caps: Capabilities = disrobe.capabilities(data)
match_count: int = caps.match_count

overlay: OverlayReport = disrobe.extract_recursive(data, max_depth=4)
chunks_total: int | None = overlay.chunks_total
bytes_carved: int | None = overlay.bytes_carved

rule: YaraReport = disrobe.yara_generate(data, name="suspect")
rule_count: int = rule.rule_count
```

### Analysis report classes

| Class | Notable typed accessors |
|---|---|
| `StringsReport` | `string_count: int` |
| `IocReport` | `indicator_count: int` |
| `BehaviorReport` | `category_count: int` |
| `IdentifyReport` | `format: str \| None`, `finding_count: int` |
| `SecretScanReport` | `finding_count: int` |
| `Capabilities` | `match_count: int`, `format: str \| None` |
| `ExtractionResult` | `kind: str \| None`, `entry_count: int`, `integrity_violation_count: int` |
| `OverlayReport` | `max_depth: int \| None`, `nodes_visited: int \| None`, `chunks_total: int \| None`, `bytes_carved: int \| None` |
| `YaraReport` | `rule_count: int` |

## Native binary

### Functions

| Function | Returns | Notes |
|---|---|---|
| `native_symbols(data)` | `SymbolsReport` | Symbols, sections, imports, debug info |
| `native_disasm(data)` | `DisasmPayload` | Full disassembly: functions, stream, symbols |
| `native_callgraph(data)` | `CallGraph` | Whole-program call graph |
| `native_imports_dot(data)` | `str` | GraphViz DOT of the import graph |
| `native_entropy(data)` | `EntropyReport` | Sliding-window Shannon entropy map |
| `native_sbom(data)` | `SbomReport` | CycloneDX 1.5 SBOM from cargo-auditable section |
| `native_fingerprint(data, *, flirt=None)` | `FingerprintReport` | Crypto-constant + FLIRT + string-xref sidecar |
| `native_signatures(data, *, flirt=None)` | `SignatureReport` | Crypto-primitive signatures and FLIRT matches |
| `native_sigmaker(data, at)` | `SigmakerReport` | Wildcarded byte signature for a VA |
| `native_diff(a, b)` | `DiffReport` | Function-level diff of two binaries |
| `native_patch(data, *, at, ...)` | `tuple[bytes, PatchReport]` | Rewrite bytes and revalidate |
| `native_format(binary_bytes)` | `NativeFormat` | Format: kind, bitness, subsystem |
| `native_detect(binary_bytes)` | `DetectionList` | Packer/protector detection hits |
| `native_probe_backends()` | `BackendList` | Probe for installed external tools |
| `native_deobfuscate(code, *, bits=64, base=0, entry=0)` | `NativeDeobfuscation` | x86 OLLVM/Tigress deflattening |

```python
import disrobe
from disrobe import (
    SymbolsReport, DisasmPayload, CallGraph, EntropyReport,
    SbomReport, FingerprintReport, SignatureReport, SigmakerReport,
    DiffReport, PatchReport, NativeFormat, DetectionList,
    BackendList, NativeDeobfuscation,
)

with open("binary.elf", "rb") as fh:
    data: bytes = fh.read()

syms: SymbolsReport = disrobe.native_symbols(data)
symbol_count: int = syms.symbol_count
section_count: int = syms.section_count
import_count: int = syms.import_count

disasm_payload: DisasmPayload = disrobe.native_disasm(data)
instruction_count: int = disasm_payload.instruction_count
source_hash: str | None = disasm_payload.source_hash

entropy: EntropyReport = disrobe.native_entropy(data)
mean: float | None = entropy.mean

sig: SigmakerReport = disrobe.native_sigmaker(data, at=0x1000)
ida_pattern: str | None = sig.ida_pattern

patched_bytes: bytes
patch_report: PatchReport
patched_bytes, patch_report = disrobe.native_patch(data, at=0x1234, nop_start=0x1234, nop_end=0x1240)
revalidated: bool = patch_report.revalidated

deob: NativeDeobfuscation = disrobe.native_deobfuscate(data, bits=64, base=0x400000)
recovered_blocks: int | None = deob.recovered_blocks
fully_recovered: bool = deob.fully_recovered
```

### Native report classes

| Class | Notable typed accessors |
|---|---|
| `SymbolsReport` | `symbol_count: int`, `section_count: int`, `import_count: int` |
| `DisasmPayload` | `instruction_count: int`, `symbol_count: int`, `source_hash: str \| None` |
| `CallGraph` | `node_count: int`, `edge_count: int` |
| `EntropyReport` | `window_count: int`, `mean: float \| None`, `min: float \| None`, `max: float \| None` |
| `SbomReport` | `component_count: int`, `bom_format: str \| None`, `spec_version: str \| None` |
| `FingerprintReport` | `crypto_hit_count: int` |
| `SignatureReport` | `signature_count: int` |
| `SigmakerReport` | `ida_pattern: str \| None`, `byte_count: int` |
| `DiffReport` | `added: int`, `removed: int`, `changed: int` |
| `PatchReport` | `at: int \| None`, `bytes_written: int \| None`, `revalidated: bool` |
| `NativeFormat` | `kind: str \| None`, `bits: int \| None`, `subsystem: str \| None` |
| `DetectionList` | `count: int` |
| `BackendList` | `count: int`, `available_count: int` |
| `NativeDeobfuscation` | `bits: int \| None`, `recovered_blocks: int \| None`, `original_blocks: int \| None`, `fully_recovered: bool` |

## Query IR

The query functions operate on a Disasm- or Mir-rung `.dr` envelope (raw bytes). See
[Editable IR objects](#editable-ir-objects) for how to produce and consume `.dr`
envelopes programmatically.

| Function | Returns | Notes |
|---|---|---|
| `query_functions(dr_bytes)` | `FunctionList` | All recovered functions |
| `query_calls_to(dr_bytes, target)` | `QueryReport` | Call sites targeting a symbol name |
| `query_xrefs_to(dr_bytes, symbol)` | `QueryReport` | Data/code cross-references to a symbol |
| `query_string_decoders(dr_bytes)` | `QueryReport` | Functions with string-decode patterns |
| `query_complexity_over(dr_bytes, threshold)` | `QueryReport` | Functions with cyclomatic complexity above threshold |
| `query_capability_sites(dr_bytes, capability)` | `QueryReport` | Sites exercising a named capability |
| `query_call_graph(dr_bytes)` | `CallGraph` | Whole-program call graph from IR |

```python
import disrobe
from disrobe import FunctionList, QueryReport, CallGraph

with open("module.dr", "rb") as fh:
    dr: bytes = fh.read()

functions: FunctionList = disrobe.query_functions(dr)
fn_count: int = functions.count

callers: QueryReport = disrobe.query_calls_to(dr, "malloc")
match_count: int = callers.match_count

complex_fns: QueryReport = disrobe.query_complexity_over(dr, threshold=20)
graph: CallGraph = disrobe.query_call_graph(dr)
edge_count: int = graph.edge_count
```

### Query report classes

| Class | Notable typed accessors |
|---|---|
| `FunctionList` | `kind: str \| None`, `count: int` |
| `QueryReport` | `kind: str \| None`, `match_count: int` |
| `CallGraph` | `node_count: int`, `edge_count: int` |

## Envelope

`envelope_create` wraps a payload as a Raw-rung `.dr` envelope and returns the
encoded `bytes`. `envelope_verify` decodes and verifies, returning an
`EnvelopeReport`.

```python
import disrobe
from disrobe import EnvelopeReport

envelope: bytes = disrobe.envelope_create(
    b"payload",
    source_label="inline",
    produced_by="my-tool",
    detected_format="elf64",
)
report: EnvelopeReport = disrobe.envelope_verify(envelope)
ok: bool = report.verified
root_hash: str | None = report.root_hash
rung: str | None = report.rung
hot_bytes: int | None = report.hot_bytes
cold_bytes: int | None = report.cold_bytes
version: int | None = report.version
```

### `EnvelopeReport` accessors

| Property | Type |
|---|---|
| `verified` | `bool` |
| `rung` | `str \| None` |
| `version` | `int \| None` |
| `hot_bytes` | `int \| None` |
| `cold_bytes` | `int \| None` |
| `root_hash` | `str \| None` |

The sidecar `DrEnvelope` TypedDict (`bindings/python/dr-envelope.pyi`) mirrors
the raw on-disk header shape: `magic`, `version`, `rung`, `flags`, `hot_len`,
`cold_len`, `root_hash`.

## Metadata renders

`agents_md` and `skill_md` render the AGENTS.md and SKILL.md reconstruction
briefs for a report with metadata attached (or a bare bundle dict), returning
a `str`. `provenance` extracts tool/selection/input metadata as a typed
`Provenance`. Passing a report whose `llm` slot is `None` raises `DisrobeError`.

```python
import disrobe
from disrobe import PyDecompileReport, Provenance

with open("module.pyc", "rb") as fh:
    report: PyDecompileReport = disrobe.py_decompile(fh.read(), pack="pack-2")

agents_brief: str = disrobe.agents_md(report)
skill_brief: str = disrobe.skill_md(report)

prov: Provenance = disrobe.provenance(report)
generated_at: str | None = prov.generated_at
schema: str | None = prov.schema
schema_version: str | None = prov.schema_version
```

### `Provenance` accessors

| Property | Type |
|---|---|
| `schema` | `str \| None` |
| `schema_version` | `str \| None` |
| `generated_at` | `str \| None` |

## Python passes

See also [Python decompiler](./languages/python.md) for the full decompiler design.

### `py_decompile`

Decompiles a `.pyc` (with header) to source. Full CPython 3.14 stdlib coverage is
<!-- m:py_stdlib_full_pct -->92.43%<!-- /m --> per-code-object recompile equivalence (16880 of 18262); the pinned
200-module corpus is <!-- m:py_stdlib_pinned_pct -->95.64%<!-- /m --> (5920 of 6286, CI floor 90%). Legacy CPython
1.0-3.7: <!-- m:py_legacy_pct -->78.5%<!-- /m --> proven-correct (CI floor 150 of 191; 166 of 191 with the full
interpreter zoo present).

```python
import disrobe
from disrobe import PyDecompileReport, RoundtripStatus

with open("module.pyc", "rb") as fh:
    report: PyDecompileReport = disrobe.py_decompile(fh.read(), roundtrip=True)

source: str | None = report.source
marshal_version: str | None = report.marshal_version
decompile_version: str | None = report.decompile_version
recovered_directly: bool = report.recovered_directly
fallback_reason: str | None = report.fallback_reason
status: RoundtripStatus | None = report.roundtrip_status
roundtrip_detail: str | None = report.roundtrip_detail
interpreter_path: str | None = report.interpreter_path
interpreter_version: str | None = report.interpreter_version

if status == "perfect":
    print("recompiled bytecode matched")
```

Round-tripping (when `roundtrip=True`) shells out to a matching host
interpreter; it is the one binding that may run an external `python`.

### `py_disasm`

```python
import disrobe
from disrobe import PyDisasmReport

with open("module.pyc", "rb") as fh:
    result: PyDisasmReport = disrobe.py_disasm(fh.read())

marshal_version: str | None = result.marshal_version
instruction_count: int = result.instruction_count
text: str | None = result.text
```

### `py_deob`, `py_deob_detect`, `py_deob_list_passes`, `py_deob_detect_pass`

```python
import disrobe
from disrobe import ObfuscatorPass, PyDeobDetection, PyDeobReport

obfuscated: str = "exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n"

deob: PyDeobReport = disrobe.py_deob(obfuscated, cleanup=True)
peeled_source: str | None = deob.peeled_source
cleanup_source: str | None = deob.cleanup_source
layer_count: int = deob.layer_count

detection: PyDeobDetection = disrobe.py_deob_detect(obfuscated)
match_count: int = detection.match_count

passes: list[ObfuscatorPass] = disrobe.py_deob_list_passes()
first_id: str | None = passes[0].id if passes else None

per_pass: PyDeobDetection = disrobe.py_deob_detect_pass(obfuscated, "base64-exec")
```

`py_deob_detect_pass` raises `DisrobeError` for an unknown `pass_id`.

### Python pass report classes

| Class | Notable typed accessors |
|---|---|
| `PyDecompileReport` | `source`, `marshal_version`, `decompile_version`, `recovered_directly`, `fallback_reason`, `roundtrip_status`, `roundtrip_detail`, `interpreter_path`, `interpreter_version`, `llm` |
| `PyDisasmReport` | `marshal_version: str \| None`, `instruction_count: int`, `text: str \| None`, `llm` |
| `PyDeobReport` | `peeled_source: str \| None`, `cleanup_source: str \| None`, `layer_count: int`, `llm` |
| `PyDeobDetection` | `match_count: int`, `llm` |
| `ObfuscatorPass` | `id: str \| None` |

## PyArmor

### `pyarmor_detect`

Parses a PyArmor wrapper from source text.

```python
import disrobe
from disrobe import PyarmorDetection

detection: PyarmorDetection = disrobe.pyarmor_detect(open("wrapped.py").read())
version: str | None = detection.version
protection: str | None = detection.protection
confidence: str | None = detection.confidence
serial: str | None = detection.serial
python_major: int | None = detection.python_major
python_minor: int | None = detection.python_minor
payload_offset: int | None = detection.payload_offset
payload_size: int | None = detection.payload_size
```

### `pyarmor_unpack`

Statically unpacks a PyArmor wrapper image. <!-- m:pyarmor_samples -->72<!-- /m --> of 72 PyArmor samples (v6-v9)
recover. The bindings expose only the static path; there is no
`--allow-dynamic` equivalent.

```python
import disrobe
from disrobe import PyarmorUnpack, PyarmorUnpackStatus

with open("wrapper.pyc", "rb") as fh:
    unpacked: PyarmorUnpack = disrobe.pyarmor_unpack(fh.read())

status: PyarmorUnpackStatus | None = unpacked.status
pyarmor_version: str | None = unpacked.pyarmor_version
protection_kind: str | None = unpacked.protection_kind
plaintext_len: int | None = unpacked.plaintext_len
digest: str | None = unpacked.plaintext_blake3_hex
bcc_blob_count: int | None = unpacked.bcc_blob_count
inner_cipher_recovered_co: int | None = unpacked.inner_cipher_recovered_co
```

### `pyarmor_classify`

```python
import disrobe
from disrobe import PyarmorClassification

with open("payload.bin", "rb") as fh:
    payload: bytes = fh.read()

classification: PyarmorClassification = disrobe.pyarmor_classify(open("wrapped.py").read(), payload)
script_type: str | None = classification.script_type
bootstrap_import: str | None = classification.bootstrap_import
disposition: str | None = classification.disposition
rft_enabled: bool = classification.rft_enabled
ecc_enabled: bool = classification.ecc_enabled
```

The sidecar `PyarmorDetection` TypedDict (`bindings/python/pyarmor-detection.pyi`)
names the confidence and protection Literal values used in the raw dict.

### PyArmor report classes

| Class | Notable typed accessors |
|---|---|
| `PyarmorDetection` | `version`, `protection`, `confidence`, `serial`, `python_major`, `python_minor`, `payload_offset`, `payload_size`, `llm` |
| `PyarmorUnpack` | `status`, `pyarmor_version`, `protection_kind`, `plaintext_len`, `plaintext_blake3_hex`, `bcc_blob_count`, `inner_cipher_recovered_co`, `llm` |
| `PyarmorClassification` | `script_type`, `bootstrap_import`, `disposition`, `rft_enabled`, `ecc_enabled` |

## PyInstaller and Nuitka

### `pyinstaller_extract` / `pyinstaller_entry_bytes`

```python
import disrobe
from disrobe import PyInstallerArchive

with open("app.exe", "rb") as fh:
    image: bytes = fh.read()

archive: PyInstallerArchive = disrobe.pyinstaller_extract(image)
entry_count: int = archive.entry_count
encrypted: bool = archive.encrypted
encryption_key_present: bool = archive.encryption_key_present
python_major: int | None = archive.python_major
python_minor: int | None = archive.python_minor

entries: list[dict[str, object]] = archive.raw["entries"]
main_payload: bytes = disrobe.pyinstaller_entry_bytes(image, str(entries[0]["name"]))
```

### `nuitka_detect` / `nuitka_extract`

```python
import disrobe
from disrobe import NuitkaDetection, NuitkaExtraction

with open("app.exe", "rb") as fh:
    image: bytes = fh.read()

det: NuitkaDetection = disrobe.nuitka_detect(image)
flavor: str | None = det.flavor
version: str | None = det.version
wheel_marker: str | None = det.wheel_marker
onefile_payload_offset: int | None = det.onefile_payload_offset
onefile_payload_compressed: bool = det.onefile_payload_compressed

extraction: NuitkaExtraction = disrobe.nuitka_extract(image)
variant: str | None = extraction.variant
```

The sidecar `FreezerManifest` TypedDict (`bindings/python/freezer-manifest.pyi`)
describes the manifest schema for cx-freeze/py2exe/shiv/pex/py-oxidizer/briefcase
freezer families; reach it via `report.raw`.

### PyInstaller/Nuitka report classes

| Class | Notable typed accessors |
|---|---|
| `PyInstallerArchive` | `entry_count: int`, `encrypted: bool`, `encryption_key_present: bool`, `python_major: int \| None`, `python_minor: int \| None`, `llm` |
| `NuitkaDetection` | `flavor: str \| None`, `version: str \| None`, `wheel_marker: str \| None`, `onefile_payload_offset: int \| None`, `onefile_payload_compressed: bool`, `llm` |
| `NuitkaExtraction` | `variant: str \| None`, `llm` |

## Hermes (React Native)

All 8 functions in the committed hermesc-built HBC v96 sample lift at 100%
op-coverage with 0 fallback ops. A <!-- m:hermes_functions -->122,633<!-- /m -->-function production React Native
bundle parses with no module-parse failure in the local scale harness.

```python
import disrobe
from disrobe import HermesDisassembly, HermesLift, HermesInfo

with open("index.android.bundle", "rb") as fh:
    bundle: bytes = fh.read()

disasm_result: HermesDisassembly = disrobe.hermes_disasm(bundle)
function_count: int = disasm_result.function_count
identifier_count: int = disasm_result.identifier_count
string_count: int = disasm_result.string_count

lift: HermesLift = disrobe.hermes_lift(bundle)
function_surface_count: int = lift.function_surface_count

info: HermesInfo = disrobe.hermes_info(bundle)
version: int | None = info.version
header_size: int | None = info.header_size
```

### Hermes report classes

| Class | Notable typed accessors |
|---|---|
| `HermesDisassembly` | `function_count: int`, `identifier_count: int`, `string_count: int`, `llm` |
| `HermesLift` | `function_surface_count: int`, `string_count: int`, `identifier_count: int`, `llm` |
| `HermesInfo` | `version: int \| None`, `function_count: int \| None`, `string_count: int \| None`, `header_size: int \| None`, `llm` |

## Mach-O and Swift

```python
import disrobe
from disrobe import MachoReport, SwiftReport

with open("universal.dylib", "rb") as fh:
    data: bytes = fh.read()

macho: MachoReport = disrobe.macho_dump(data)
kind: str | None = macho.kind
fat_entry_count: int = macho.fat_entry_count
slice_count: int = macho.slice_count

swift: SwiftReport = disrobe.swift_analyze(data)
container: str | None = swift.container
swift_fat_entry_count: int = swift.fat_entry_count
swift_slice_count: int = swift.slice_count
```

### Mach-O report classes

| Class | Notable typed accessors |
|---|---|
| `MachoReport` | `kind: str \| None`, `fat_entry_count: int`, `slice_count: int`, `llm` |
| `SwiftReport` | `container: str \| None`, `fat_entry_count: int`, `slice_count: int`, `llm` |

## JVM and Android

131 of 131 JVM methods recompile error-free under javac (CI floor 131 of 131,
JDK 25). <!-- m:dalvik_verifier_pct -->99%<!-- /m --> of committed DEX classes pass `-Xverify:all`.

```python
import disrobe
from disrobe import (
    JvmClass, DexFileReport, JvmDecompiledClass,
    DetectionList, JvmBackends, ApkResources,
)

with open("Hello.class", "rb") as fh:
    cls: JvmClass = disrobe.jvm_parse_class(fh.read())
major_version: int | None = cls.major_version
minor_version: int | None = cls.minor_version
method_count: int = cls.method_count
field_count: int = cls.field_count
constant_pool_count: int = cls.constant_pool_count

with open("classes.dex", "rb") as fh:
    dex: DexFileReport = disrobe.jvm_parse_dex(fh.read())
class_count: int = dex.class_count
dex_method_count: int = dex.method_count

with open("Hello.class", "rb") as fh:
    decompiled: JvmDecompiledClass = disrobe.jvm_decompile_class(fh.read())
source: str | None = decompiled.source
fully_lifted_methods: int = decompiled.fully_lifted_methods
fallback_methods: int = decompiled.fallback_methods

detections: DetectionList = disrobe.jvm_detect(open("obf.class", "rb").read())
detection_count: int = detections.count

backends: JvmBackends = disrobe.jvm_backends()
jvm_count: int = backends.jvm_count
android_count: int = backends.android_count

with open("app.apk", "rb") as fh:
    apk: ApkResources = disrobe.apk_resources(fh.read())
package: str | None = apk.package
manifest_xml: str | None = apk.manifest_xml
resource_entry_count: int = apk.resource_entry_count
certificate_count: int = apk.certificate_count
dex_count: int = apk.dex_count
```

`jvm_backends` and `dotnet_backends` probe the host for installed external
tools but never shell out to them. Counts are informational only.

### JVM/Android report classes

| Class | Notable typed accessors |
|---|---|
| `JvmClass` | `major_version: int \| None`, `minor_version: int \| None`, `method_count: int`, `field_count: int`, `constant_pool_count: int`, `llm` |
| `DexFileReport` | `string_count: int`, `type_count: int`, `class_count: int`, `method_count: int`, `llm` |
| `JvmDecompiledClass` | `source: str \| None`, `method_count: int`, `field_count: int`, `fully_lifted_methods: int`, `fallback_methods: int` |
| `DetectionList` | `count: int` |
| `JvmBackends` | `jvm_count: int`, `android_count: int`, `llm` |
| `ApkResources` | `package: str \| None`, `manifest_xml: str \| None`, `resource_entry_count: int`, `certificate_count: int`, `dex_count: int`, `llm` |

## .NET

```python
import disrobe
from disrobe import (
    DotnetPe, DotnetMetadata, DotnetDetection,
    DotnetAnalysis, DotnetDecompilation, DotnetDecoders, BackendList,
)

with open("Sample.dll", "rb") as fh:
    pe_bytes: bytes = fh.read()

pe: DotnetPe = disrobe.dotnet_parse_pe(pe_bytes)
bitness: str | None = pe.bitness
machine: int | None = pe.machine
section_count: int = pe.section_count
entry_point_rva: int | None = pe.entry_point_rva

metadata: DotnetMetadata = disrobe.dotnet_parse_metadata(pe_bytes)
version: str | None = metadata.version
major_runtime_version: int | None = metadata.major_runtime_version
stream_count: int = metadata.stream_count

detection: DotnetDetection = disrobe.dotnet_detect(pe_bytes)
primary: str | None = detection.primary
match_count: int = detection.match_count

analysis: DotnetAnalysis = disrobe.dotnet_analyze(pe_bytes)
pe_bitness: str | None = analysis.pe_bitness
native_aot: bool = analysis.native_aot
primary_protector: str | None = analysis.primary_protector
opcode_spec_coverage_pct: int | None = analysis.opcode_spec_coverage_pct

decompilation: DotnetDecompilation = disrobe.dotnet_decompile(pe_bytes)
module_name: str | None = decompilation.module_name
methods_decompiled: int | None = decompilation.methods_decompiled
methods_bodyless: int | None = decompilation.methods_bodyless
methods_failed: int | None = decompilation.methods_failed

decoders: DotnetDecoders = disrobe.dotnet_recover_decoders(pe_bytes)
pure_decoders_found: int | None = decoders.pure_decoders_found
constants_recovered: int = decoders.constants_recovered

backend_list: BackendList = disrobe.dotnet_backends()
available_count: int = backend_list.available_count
```

### .NET report classes

| Class | Notable typed accessors |
|---|---|
| `DotnetPe` | `bitness: str \| None`, `machine: int \| None`, `section_count: int`, `entry_point_rva: int \| None`, `llm` |
| `DotnetMetadata` | `version: str \| None`, `major_runtime_version: int \| None`, `stream_count: int`, `llm` |
| `DotnetDetection` | `primary: str \| None`, `match_count: int`, `llm` |
| `DotnetAnalysis` | `pe_bitness: str \| None`, `clr_runtime_version: str \| None`, `native_aot: bool`, `primary_protector: str \| None`, `opcode_spec_coverage_pct: int \| None`, `llm` |
| `DotnetDecompilation` | `module_name: str \| None`, `methods_decompiled: int \| None`, `methods_bodyless: int \| None`, `methods_failed: int \| None`, `llm` |
| `DotnetDecoders` | `pure_decoders_found: int \| None`, `constants_recovered: int`, `llm` |

## WebAssembly

98.4% op-coverage on 126 functions across 36 parseable corpus modules (124 of
126). 50 of 50 execution-eligible functions are execution-equivalent under wasmtime.

```python
import disrobe
from disrobe import WasmAnalysis, WasmDetection

with open("module.wasm", "rb") as fh:
    wasm_bytes: bytes = fh.read()

analysis: WasmAnalysis = disrobe.wasm_analyze(wasm_bytes)
import_count: int = analysis.import_count
export_count: int = analysis.export_count
func_count: int | None = analysis.func_count
code_size_bytes: int | None = analysis.code_size_bytes
has_dwarf: bool = analysis.has_dwarf

detection: WasmDetection = disrobe.wasm_detect(wasm_bytes)
obfuscator: str | None = detection.obfuscator
confidence: float | None = detection.confidence
has_name_section: bool = detection.has_name_section
function_count: int | None = detection.function_count
```

### WebAssembly report classes

| Class | Notable typed accessors |
|---|---|
| `WasmAnalysis` | `import_count: int`, `export_count: int`, `func_count: int \| None`, `code_size_bytes: int \| None`, `has_dwarf: bool`, `llm` |
| `WasmDetection` | `obfuscator: str \| None`, `confidence: float \| None`, `has_name_section: bool`, `function_count: int \| None`, `llm` |

## JavaScript

Detects <!-- m:js_bundlers -->11<!-- /m --> bundlers. The explicit target hint accepts `auto`, `webpack4`,
`webpack5`/`webpack`, `vite`, `rollup`, `esbuild`, `turbopack`, and `bun`.
An unrecognised hint string raises `DisrobeError`.

```python
import disrobe
from disrobe import JsDetection, JsUnminify, JsUnbundle

source: str = open("main.js").read()

detection: JsDetection = disrobe.js_detect(source)
family: str | None = detection.family
confidence: float | None = detection.confidence
marker_count: int = detection.marker_count

unminified: JsUnminify = disrobe.js_unminify(source)
recovered_source: str | None = unminified.source

bundle_source: str = open("bundle.js").read()
unbundled: JsUnbundle = disrobe.js_unbundle(bundle_source)
module_count: int = unbundled.module_count
bundler: str | None = unbundled.bundler

unbundled_hinted: JsUnbundle = disrobe.js_unbundle(bundle_source, bundler="webpack5")
```

### JavaScript report classes

| Class | Notable typed accessors |
|---|---|
| `JsDetection` | `family: str \| None`, `confidence: float \| None`, `marker_count: int`, `llm` |
| `JsUnminify` | `source: str \| None`, `llm` |
| `JsUnbundle` | `module_count: int`, `bundler: str \| None`, `llm` |

## Lua

Detects, decompiles, and deobfuscates 14 Lua obfuscator families, with 16
catalog entries once Luau and GLua dialect detectors are included. IronBrew2
2.7.0 is reversed against real committed output with a Lua execution
differential.

```python
import disrobe
from disrobe import LuaDetection, LuaDecompilation, LuaDeobfuscation

with open("chunk.luac", "rb") as fh:
    bytecode: bytes = fh.read()

det: LuaDetection = disrobe.lua_detect(bytecode)
lua_format: str | None = det.format

decompiled: LuaDecompilation = disrobe.lua_decompile(bytecode)
decompiled_source: str | None = decompiled.source
fidelity: str | None = decompiled.fidelity
warning_count: int = decompiled.warning_count

deob: LuaDeobfuscation = disrobe.lua_deobfuscate(open("obf.lua").read(), authorize=True)
obfuscator: str | None = deob.obfuscator
deobfuscated: str | None = deob.deobfuscated
fully_recovered: bool = deob.fully_recovered
passes_run_count: int = deob.passes_run_count
recovered_string_count: int = deob.recovered_string_count
```

### Lua report classes

| Class | Notable typed accessors |
|---|---|
| `LuaDetection` | `format: str \| None`, `llm` |
| `LuaDecompilation` | `source: str \| None`, `fidelity: str \| None`, `warning_count: int`, `llm` |
| `LuaDeobfuscation` | `obfuscator: str \| None`, `deobfuscated: str \| None`, `fully_recovered: bool`, `passes_run_count: int`, `recovered_string_count: int`, `llm` |

## Go

<!-- m:go_typename_pct -->85%<!-- /m -->+ type-name recovery on stripped go1.26 fixtures; 528 of 528 measured.

```python
import disrobe
from disrobe import GoAnalysis, GoSymbols, GoPclntab, GarbleReport

with open("binary", "rb") as fh:
    go_bytes: bytes = fh.read()

analysis: GoAnalysis = disrobe.go_analyze(go_bytes)
image_kind: str | None = analysis.image_kind
pclntab_version: str | None = analysis.pclntab_version
buildversion: str | None = analysis.buildversion
ptr_size: int | None = analysis.ptr_size

symbols: GoSymbols = disrobe.go_symbols(go_bytes)
version_label: str | None = symbols.version_label
function_count: int = symbols.function_count
source_file_count: int = symbols.source_file_count
package_count: int = symbols.package_count

pclntab: GoPclntab = disrobe.go_pclntab(go_bytes)
version: str | None = pclntab.version
func_count: int | None = pclntab.func_count

garble: GarbleReport = disrobe.go_garble(go_bytes)
quality: str | None = garble.quality
detection_score: int | None = garble.detection_score
seed_recoverable: bool = garble.seed_recoverable
seed_hash: str | None = garble.seed_hash
recovered_string_count: int = garble.recovered_string_count
```

### Go report classes

| Class | Notable typed accessors |
|---|---|
| `GoAnalysis` | `image_kind: str \| None`, `pclntab_version: str \| None`, `buildversion: str \| None`, `ptr_size: int \| None`, `llm` |
| `GoSymbols` | `version_label: str \| None`, `function_count: int`, `source_file_count: int`, `package_count: int`, `llm` |
| `GoPclntab` | `version: str \| None`, `ptr_size: int \| None`, `func_count: int \| None`, `image_kind: str \| None`, `llm` |
| `GarbleReport` | `quality: str \| None`, `detection_score: int \| None`, `seed_recoverable: bool`, `seed_hash: str \| None`, `recovered_string_count: int`, `llm` |

## Ruby

```python
import disrobe
from disrobe import RubyDetection, RubyAnalysis

with open("hello.rb.enc", "rb") as fh:
    ruby_bytes: bytes = fh.read()

det: RubyDetection = disrobe.ruby_detect(ruby_bytes, source_path="hello.rb.enc")
flavor: str | None = det.flavor

analysis: RubyAnalysis = disrobe.ruby_decompile(ruby_bytes, source_path="hello.rb.enc")
ruby_flavor: str | None = analysis.flavor
source_path: str | None = analysis.source_path
input_len: int | None = analysis.input_len
```

### Ruby report classes

| Class | Notable typed accessors |
|---|---|
| `RubyDetection` | `flavor: str \| None`, `llm` |
| `RubyAnalysis` | `flavor: str \| None`, `source_path: str \| None`, `input_len: int \| None`, `llm` |

## PHP

```python
import disrobe
from disrobe import PhpDetection, PhpScan, PhpDecode

with open("obfuscated.php", "rb") as fh:
    php_bytes: bytes = fh.read()

det: PhpDetection = disrobe.php_detect(php_bytes)
kind: str | None = det.kind
confidence: str | None = det.confidence
open_tag_offset: int | None = det.open_tag_offset
has_halt_compiler: bool = det.has_halt_compiler

scan: PhpScan = disrobe.php_scan(php_bytes)
hit_count: int = scan.hit_count
family_count: int = scan.family_count

decoded: PhpDecode = disrobe.php_decode(php_bytes, max_depth=10)
php_source: str | None = decoded.source
layer_count: int = decoded.layer_count
residual_eval: bool = decoded.residual_eval
```

### PHP report classes

| Class | Notable typed accessors |
|---|---|
| `PhpDetection` | `kind: str \| None`, `confidence: str \| None`, `open_tag_offset: int \| None`, `has_halt_compiler: bool`, `llm` |
| `PhpScan` | `hit_count: int`, `family_count: int`, `llm` |
| `PhpDecode` | `source: str \| None`, `layer_count: int`, `residual_eval: bool`, `llm` |

## Shell

```python
import disrobe
from disrobe import BatchDeobReport, PowershellDetection, PowershellDeobfuscation

batch_script: str = open("dropper.bat").read()
batch_result: BatchDeobReport = disrobe.batch_deobfuscate(batch_script, args=["/run"])
output: str | None = batch_result.output
embedded_payload_count: int = batch_result.embedded_payload_count
decrypted_stage_count: int = batch_result.decrypted_stage_count
commands_emulated: int | None = batch_result.commands_emulated

ps_script: str = open("obf.ps1").read()
ps_det: PowershellDetection = disrobe.powershell_detect(ps_script)
obfuscator: str | None = ps_det.obfuscator
ps_confidence: float | None = ps_det.confidence
marker_count: int = ps_det.marker_count

ps_deob: PowershellDeobfuscation = disrobe.powershell_deobfuscate(ps_script)
ps_output: str | None = ps_deob.output
level: str | None = ps_deob.level
transformation_count: int = ps_deob.transformation_count
```

### Shell report classes

| Class | Notable typed accessors |
|---|---|
| `BatchDeobReport` | `output: str \| None`, `embedded_payload_count: int`, `decrypted_stage_count: int`, `commands_emulated: int \| None`, `llm` |
| `PowershellDetection` | `obfuscator: str \| None`, `confidence: float \| None`, `marker_count: int`, `llm` |
| `PowershellDeobfuscation` | `output: str \| None`, `level: str \| None`, `transformation_count: int`, `llm` |

## Containers

98 container families detected and extracted in-tree. See [container docs](./languages/containers.md)
for the full family list.

```python
import disrobe
from disrobe import ContainerDetection, ContainerMembers, ContainerListing

with open("archive.zip", "rb") as fh:
    container_bytes: bytes = fh.read()

det: ContainerDetection = disrobe.container_detect(container_bytes)
detected: bool = det.detected
kind: str | None = det.kind
is_zip_family: bool = det.is_zip_family

members: ContainerMembers = disrobe.container_members(container_bytes)
fmt: str | None = members.format
size: int | None = members.size
listing: ContainerListing | None = members.listing
entry_count: int = members.entry_count
```

### Container report classes

| Class | Notable typed accessors |
|---|---|
| `ContainerDetection` | `detected: bool`, `kind: str \| None`, `is_zip_family: bool`, `llm` |
| `ContainerMembers` | `format: str \| None`, `size: int \| None`, `listing: ContainerListing \| None`, `entry_count: int`, `llm` |

## Pickle

Nothing is ever unpickled; the VM is symbolic.

```python
import disrobe
from disrobe import (
    PickleDecompilation, PickleSafety, PickleTrace,
    PicklePolyglot, PickleMlReport,
)

with open("model.pkl", "rb") as fh:
    pkl: bytes = fh.read()

listing: str = disrobe.pickle_disasm(pkl)

decompilation: PickleDecompilation = disrobe.pickle_decompile(pkl)
pkl_source: str | None = decompilation.source

safety: PickleSafety = disrobe.pickle_safety(pkl)
severity: str | None = safety.severity
finding_count: int = safety.finding_count
import_count: int = safety.import_count
reduce_count: int | None = safety.reduce_count

trace: PickleTrace = disrobe.pickle_trace(pkl)
protocol: int | None = trace.protocol
memo_count: int | None = trace.memo_count
max_stack_depth: int | None = trace.max_stack_depth
global_ref_count: int = trace.global_ref_count
trace_reduce_count: int | None = trace.reduce_count

polyglot: PicklePolyglot = disrobe.pickle_polyglot(pkl)
is_pickle: bool = polyglot.is_pickle
is_polyglot: bool = polyglot.is_polyglot
kind_count: int = polyglot.kind_count

with open("model.pt", "rb") as fh:
    ml_report: PickleMlReport = disrobe.pickle_ml_detect(fh.read())
fmt: str | None = ml_report.format
framing: str | None = ml_report.framing
embedded_count: int = ml_report.embedded_count
```

### Pickle report classes

| Class | Notable typed accessors |
|---|---|
| `PickleDecompilation` | `source: str \| None`, `llm` |
| `PickleSafety` | `severity: str \| None`, `finding_count: int`, `import_count: int`, `reduce_count: int \| None`, `llm` |
| `PickleTrace` | `protocol: int \| None`, `memo_count: int \| None`, `max_stack_depth: int \| None`, `global_ref_count: int`, `reduce_count: int \| None`, `llm` |
| `PicklePolyglot` | `is_pickle: bool`, `is_polyglot: bool`, `kind_count: int`, `llm` |
| `PickleMlReport` | `format: str \| None`, `framing: str \| None`, `embedded_count: int`, `llm` |

## Editable IR objects

`CodeObject`, `Instruction`, and `Symbol` let you load a Disasm- or Raw-rung
`.dr` envelope, modify it in Python, and write a fresh integrity-hashed `.dr`.

### `Instruction`

```python
from disrobe import Instruction, InstructionFlow

instr: Instruction = Instruction(
    offset=0,
    mnemonic="mov",
    operands=["rax", "rbx"],
    bytes=b"\x48\x89\xd8",
)
instr.branch_target = None
flow: InstructionFlow = instr.flow
text: str = instr.text()
```

| Member | Type | Notes |
|---|---|---|
| `offset` | `int` | Mutable |
| `mnemonic` | `str` | Mutable |
| `operands` | `list[str]` | Mutable |
| `bytes` | `bytes` | Mutable |
| `branch_target` | `int \| None` | Mutable |
| `flow` | `@property InstructionFlow` | Read-only |
| `text()` | `-> str` | Rendered disassembly line |

### `Symbol`

```python
from disrobe import Symbol, SymbolKind

sym: Symbol = Symbol(address=0x1000, name="entry", kind="function")
sym.name = "main"
sym.kind = "export"
```

| Member | Type | Notes |
|---|---|---|
| `address` | `int` | Mutable |
| `name` | `str` | Mutable |
| `kind` | `SymbolKind` | Mutable |

### `CodeObject`

```python
import disrobe
from disrobe import CodeObject, Instruction, Symbol

with open("module.dr", "rb") as fh:
    co: CodeObject = CodeObject.from_dr(fh.read())

instruction_count: int = co.instruction_count
symbol_count: int = co.symbol_count
source_hash: str = co.source_hash
produced_by: str = co.produced_by

instrs: list[Instruction] = co.instructions
syms: list[Symbol] = co.symbols
metadata: dict[str, str] = co.metadata
capabilities: list[str] = co.capabilities
llm_bundle: dict[str, object] | None = co.llm

new_sym: Symbol = Symbol(address=0x2000, name="renamed_fn", kind="function")
co.add_symbol(new_sym)
co.set_metadata("analysis", "patched")
co.add_capability("NETWORK_CONNECT", 1)

fresh_dr: bytes = co.to_dr()
with open("module_patched.dr", "wb") as fh:
    fh.write(fresh_dr)
```

`CodeObject.from_dr` parses a Disasm- or Raw-rung `.dr` envelope. `to_dr` produces a
fresh envelope with a recomputed integrity hash. The `set_instructions` and
`set_symbols` methods replace the full list; `add_instruction` / `add_symbol`
append. `set_metadata(key, value)` sets a single string key; `clear_metadata`
resets all. `set_llm(sidecar)` attaches or removes the metadata sidecar dict.

| Member | Signature | Notes |
|---|---|---|
| `from_dr` | `staticmethod(dr_bytes: bytes) -> CodeObject` | Parse existing envelope |
| `instructions` | `@property -> list[Instruction]` | |
| `set_instructions` | `(instructions: list[Instruction]) -> None` | Replace |
| `add_instruction` | `(instruction: Instruction) -> None` | Append |
| `symbols` | `@property -> list[Symbol]` | |
| `set_symbols` | `(symbols: list[Symbol]) -> None` | Replace |
| `add_symbol` | `(symbol: Symbol) -> None` | Append |
| `instruction_count` | `@property -> int` | |
| `symbol_count` | `@property -> int` | |
| `source_hash` | `str` | Mutable attribute |
| `produced_by` | `str` | Mutable attribute |
| `metadata` | `@property -> dict[str, str]` | |
| `set_metadata` | `(key: str, value: str) -> None` | |
| `clear_metadata` | `() -> None` | |
| `capabilities` | `@property -> list[str]` | |
| `add_capability` | `(name: str, major: int) -> None` | |
| `llm` | `@property -> dict[str, Any] \| None` | |
| `set_llm` | `(sidecar: dict[str, Any] \| None) -> None` | |
| `to_dr` | `() -> bytes` | Produce fresh integrity-hashed envelope |

## Scope

- No file or directory handling: no `--out` trees, no `--capture-stages`, no
  container extraction to disk. `auto` returns the plan document only.
- External backend tools (`jvm_backends`, `dotnet_backends`, `native_probe_backends`)
  are probed for availability but never executed.
- AS3, Flutter, BEAM (beyond `disasm`/`parse`), and the freezer family beyond
  PyInstaller/Nuitka have no dedicated bindings in this release.
- No SARIF/NDJSON emitters and no `serve` daemon; drive the CLI or daemon directly.
