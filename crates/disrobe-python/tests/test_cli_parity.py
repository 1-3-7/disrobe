"""Binding-vs-CLI parity: assert every disrobe CLI capability has a typed
library method on the importable ``disrobe`` module.

The mapping below is the authoritative cross-walk between a CLI verb (or
``native`` sub-verb) and the Python binding that performs the same work. Pure
presentation/maintenance verbs that have no analysis payload (completions, man,
init, doctor, install, config, status, bug-report, self-update, serve, explain,
passes, rename, annot, context) are listed as intentionally CLI-only so the
coverage assertion stays honest rather than silently shrinking.
"""

from __future__ import annotations

import disrobe

CLI_VERB_TO_BINDING: dict[str, str] = {
    "pyarmor unpack": "pyarmor_unpack",
    "pyarmor detect": "pyarmor_detect",
    "pyinstaller extract": "pyinstaller_extract",
    "pyfreeze": "pyinstaller_extract",
    "nuitka detect": "nuitka_detect",
    "nuitka extract": "nuitka_extract",
    "py decompile": "py_decompile",
    "py disasm": "py_disasm",
    "py deob": "py_deob",
    "decompile": "decompile",
    "scan": "secret_scan",
    "ioc": "ioc_extract",
    "strings": "strings_extract",
    "behavior": "behavior_analyze",
    "identify": "identify",
    "extract": "extract",
    "extract --recursive": "extract_recursive",
    "yara parse": "yara_parse",
    "yara gen": "yara_generate",
    "js": "js_unminify",
    "wasm": "wasm_analyze",
    "native decompile": "native_disasm",
    "native symbols": "native_symbols",
    "native identify": "identify",
    "native unpack": "native_deobfuscate",
    "native entropy": "native_entropy",
    "native signatures": "native_signatures",
    "native fingerprint": "native_fingerprint",
    "native sbom": "native_sbom",
    "native graph": "native_imports_dot",
    "native disasm": "native_disasm",
    "native callgraph": "native_callgraph",
    "native patch": "native_patch",
    "native sigmaker": "native_sigmaker",
    "native diff": "native_diff",
    "native match": "native_match",
    "jvm": "jvm_decompile_class",
    "apk": "apk_resources",
    "dotnet": "dotnet_decompile",
    "hermes": "hermes_lift",
    "macho": "macho_dump",
    "lua": "lua_decompile",
    "php": "php_decode",
    "ruby": "ruby_decompile",
    "pickle": "pickle_decompile",
    "go": "go_analyze",
    "swift": "swift_analyze",
    "envelope": "envelope_create",
    "verify": "envelope_verify",
    "query": "query_functions",
    "query calls-to": "query_calls_to",
    "query xrefs-to": "query_xrefs_to",
    "query string-decoders": "query_string_decoders",
    "query complexity-over": "query_complexity_over",
    "query capability": "query_capability_sites",
    "query call-graph": "query_call_graph",
    "capabilities": "capabilities",
    "auto": "auto",
}

CLI_ONLY_VERBS: frozenset[str] = frozenset(
    {
        "chain",
        "diff",
        "guard",
        "serve",
        "install-deps",
        "status",
        "explain",
        "passes",
        "doctor",
        "install",
        "init",
        "bug-report",
        "self-update",
        "completions",
        "man",
        "context",
        "config",
        "annot",
        "rename",
        "report",
        "as3",
        "beam",
        "flutter",
        "mobile",
    }
)


def test_every_mapped_verb_has_a_binding() -> None:
    missing: list[str] = []
    for verb, symbol in CLI_VERB_TO_BINDING.items():
        if not hasattr(disrobe, symbol):
            missing.append(f"{verb} -> disrobe.{symbol}")
    assert not missing, "CLI verbs without a library binding: " + ", ".join(missing)


def test_mapped_bindings_are_callable() -> None:
    for symbol in set(CLI_VERB_TO_BINDING.values()):
        attr = getattr(disrobe, symbol)
        assert callable(attr), f"disrobe.{symbol} is not callable"


def test_typed_return_classes_exported() -> None:
    expected = [
        "CanonicalSource",
        "DisasmPayload",
        "FunctionList",
        "QueryReport",
        "CallGraph",
        "Capabilities",
        "ExtractionResult",
        "OverlayReport",
        "EntropyReport",
        "StringsReport",
        "IocReport",
        "BehaviorReport",
        "IdentifyReport",
        "SecretScanReport",
        "SymbolsReport",
        "FlutterEngineSymbols",
        "SbomReport",
        "FingerprintReport",
        "SignatureReport",
        "SigmakerReport",
        "DiffReport",
        "PatchReport",
        "YaraReport",
        "ChainReport",
        "EnvelopeReport",
        "Provenance",
        "CodeObject",
        "Instruction",
        "Symbol",
    ]
    missing = [name for name in expected if not hasattr(disrobe, name)]
    assert not missing, "typed return classes not exported: " + ", ".join(missing)


def test_extensibility_surface_exported() -> None:
    for name in (
        "register_pass",
        "register_consumer",
        "registered_passes",
        "registered_consumers",
        "unregister",
        "run_pass",
        "run_chain",
        "emit",
    ):
        assert hasattr(disrobe, name), f"missing extensibility hook disrobe.{name}"


def test_no_verb_is_both_mapped_and_cli_only() -> None:
    mapped_roots = {verb.split(" ", 1)[0] for verb in CLI_VERB_TO_BINDING}
    overlap = mapped_roots & CLI_ONLY_VERBS
    assert not overlap, f"verbs marked both mapped and CLI-only: {sorted(overlap)}"
