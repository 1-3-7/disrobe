use pyo3::prelude::*;
use pyo3::types::{PyModule, PyType};
use serde::Serialize;
use serde_json::Value as Json;

use crate::convert::{from_py, value_to_py};
use crate::err::DisrobeError;

#[inline]
pub(crate) fn to_json<T: Serialize>(value: &T) -> PyResult<Json> {
    serde_json::to_value(value)
        .map_err(|e: serde_json::Error| DisrobeError::new_err(format!("serialize: {e}")))
}

#[inline]
fn field<'a>(data: &'a Json, key: &str) -> Option<&'a Json> {
    data.as_object().and_then(|m| m.get(key))
}

#[inline]
fn field_str(data: &Json, key: &str) -> Option<String> {
    field(data, key).and_then(Json::as_str).map(str::to_owned)
}

#[inline]
fn field_u64(data: &Json, key: &str) -> Option<u64> {
    field(data, key).and_then(Json::as_u64)
}

#[inline]
fn field_i64(data: &Json, key: &str) -> Option<i64> {
    field(data, key).and_then(Json::as_i64)
}

#[inline]
fn field_f64(data: &Json, key: &str) -> Option<f64> {
    field(data, key).and_then(Json::as_f64)
}

#[inline]
fn field_bool(data: &Json, key: &str) -> bool {
    field(data, key)
        .and_then(Json::as_bool)
        .is_some_and(|value: bool| value)
}

#[inline]
fn array_len(data: &Json, key: &str) -> usize {
    field(data, key)
        .and_then(Json::as_array)
        .map_or(0, Vec::len)
}

#[inline]
fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).map_or(usize::MAX, |converted: usize| converted)
}

#[inline]
fn object_len(data: &Json, key: &str) -> usize {
    field(data, key)
        .and_then(Json::as_object)
        .map_or(0, serde_json::Map::len)
}

#[inline]
fn nested_str(data: &Json, outer: &str, inner: &str) -> Option<String> {
    field(data, outer).and_then(|v: &Json| field_str(v, inner))
}

#[inline]
fn nested_array_len(data: &Json, outer: &str, inner: &str) -> usize {
    field(data, outer).map_or(0, |v: &Json| array_len(v, inner))
}

#[inline]
fn nested_u64(data: &Json, outer: &str, inner: &str) -> Option<u64> {
    field(data, outer).and_then(|v: &Json| field_u64(v, inner))
}

#[inline]
fn top_array_len(data: &Json) -> usize {
    data.as_array().map_or(0, Vec::len)
}

#[inline]
fn first_non_llm_key(data: &Json) -> Option<String> {
    data.as_object()
        .and_then(|m: &serde_json::Map<String, Json>| {
            m.keys().find(|k: &&String| k.as_str() != "llm").cloned()
        })
}

#[inline]
fn available_backend_count(data: &Json) -> usize {
    data.as_array().map_or(0, |items: &Vec<Json>| {
        items
            .iter()
            .filter(|e: &&Json| field_bool(e, "available") || field_bool(e, "found"))
            .count()
    })
}

macro_rules! typed_report {
    (
        $name:ident, $pyname:literal, $doc:literal,
        accessors { $( $method:ident -> $ret:ty : $body:expr ),* $(,)? }
    ) => {
        typed_report!(@emit $name, $pyname, $doc,
            accessors { $( $method -> $ret : $body ),* }
            extra {});
    };
    (
        $name:ident, $pyname:literal, $doc:literal, llm,
        accessors { $( $method:ident -> $ret:ty : $body:expr ),* $(,)? }
    ) => {
        typed_report!(@emit $name, $pyname, $doc,
            accessors { $( $method -> $ret : $body ),* }
            extra {
                #[getter]
                fn llm<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
                    value_to_py(py, match self.data.get("llm") {
                        Some(value) => value,
                        None => &Json::Null,
                    })
                }
            });
    };
    (
        @emit $name:ident, $pyname:literal, $doc:literal,
        accessors { $( $method:ident -> $ret:ty : $body:expr ),* }
        extra { $( $extra:tt )* }
    ) => {
        #[pyclass(module = "disrobe", name = $pyname, frozen, skip_from_py_object)]
        #[derive(Debug, Clone)]
        pub(crate) struct $name {
            data: Json,
        }

        impl $name {
            #[allow(dead_code)]
            pub(crate) fn from_serialize<T: Serialize>(value: &T) -> PyResult<Self> {
                Ok(Self { data: to_json(value)? })
            }

            #[allow(dead_code)]
            pub(crate) fn from_value(data: Json) -> Self {
                Self { data }
            }
        }

        #[pymethods]
        impl $name {
            $(
                #[getter]
                fn $method(&self) -> $ret {
                    let data: &Json = &self.data;
                    ($body)(data)
                }
            )*

            $( $extra )*

            #[getter]
            fn raw<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
                value_to_py(py, &self.data)
            }

            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.data)
                    .map_err(|e: serde_json::Error| DisrobeError::new_err(format!("serialize: {e}")))
            }

            #[staticmethod]
            fn from_json_str(text: &str) -> PyResult<Self> {
                let data: Json = serde_json::from_str(text).map_err(|e: serde_json::Error| {
                    DisrobeError::new_err(format!("parse: {e}"))
                })?;
                Ok(Self { data })
            }

            #[classmethod]
            #[pyo3(name = "from_obj")]
            fn from_obj(_cls: &Bound<'_, PyType>, obj: &Bound<'_, PyAny>) -> PyResult<Self> {
                Ok(Self { data: from_py(obj)? })
            }

            fn __repr__(&self) -> String {
                format!("{}({})", $pyname, compact_summary(&self.data))
            }

            fn __richcmp__(&self, other: &Self, op: pyo3::pyclass::CompareOp) -> PyResult<bool> {
                match op {
                    pyo3::pyclass::CompareOp::Eq => Ok(self.data == other.data),
                    pyo3::pyclass::CompareOp::Ne => Ok(self.data != other.data),
                    _ => Err(pyo3::exceptions::PyTypeError::new_err(
                        "only == and != are defined for disrobe report types",
                    )),
                }
            }
        }
    };
}

fn compact_summary(data: &Json) -> String {
    let Some(map) = data.as_object() else {
        return String::from("...");
    };
    let mut parts: Vec<String> = Vec::new();
    for (key, value) in map.iter().take(4) {
        let rendered: String = match value {
            Json::Array(items) => format!("[{} items]", items.len()),
            Json::Object(_) => String::from("{...}"),
            Json::String(s) if s.chars().nth(32).is_some() => {
                format!("'{}...'", s.chars().take(32).collect::<String>())
            }
            other => other.to_string(),
        };
        parts.push(format!("{key}={rendered}"));
    }
    parts.join(", ")
}

typed_report!(
    CanonicalSource,
    "CanonicalSource",
    "Recovered source text for a single language target, with the producing pass and confidence.",
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
        language -> Option<String> : |d| field_str(d, "language"),
        produced_by -> Option<String> : |d| field_str(d, "produced_by"),
        confidence -> Option<f64> : |d| field_f64(d, "confidence"),
    }
);

typed_report!(
    ByteCoverage,
    "ByteCoverage",
    "Byte accounting for a native image: how many bytes the declared structures claim, how many are alignment slack, how many nothing claims, and how many a structure declares past the end of the file.",
    accessors {
        format -> Option<String> : |d| field_str(d, "format"),
        file_len -> Option<u64> : |d| field_u64(d, "file_len"),
        claimed_bytes -> Option<u64> : |d| field_u64(d, "claimed_bytes"),
        slack_bytes -> Option<u64> : |d| field_u64(d, "slack_bytes"),
        unclaimed_bytes -> Option<u64> : |d| field_u64(d, "unclaimed_bytes"),
        truncated_bytes -> Option<u64> : |d| field_u64(d, "truncated_bytes"),
        coverage_ratio -> Option<f64> : |d| field_f64(d, "coverage_ratio"),
        complete -> bool : |d| field_bool(d, "complete"),
        overlap_detected -> bool : |d| field_bool(d, "overlap_detected"),
        region_count -> usize : |d| array_len(d, "regions"),
    }
);

typed_report!(
    DisasmPayload,
    "DisasmPayload",
    "Recovered disassembly: instruction stream plus symbol table for a Disasm-rung envelope.",
    accessors {
        instruction_count -> usize : |d| array_len(d, "instructions"),
        symbol_count -> usize : |d| array_len(d, "symbol_table"),
        source_hash -> Option<String> : |d| field_str(d, "source_hash_hex").or_else(|| field_str(d, "source_hash")),
    }
);

typed_report!(
    FunctionList,
    "FunctionList",
    "Query result over a module's recovered functions.",
    accessors {
        kind -> Option<String> : |d| field_str(d, "kind"),
        count -> usize : |d| array_len(d, "functions").max(array_len(d, "matches")),
    }
);

typed_report!(
    QueryReport,
    "QueryReport",
    "Result of a single IR query (calls-to, xrefs-to, string-decoders, complexity-over, capability-sites).",
    accessors {
        kind -> Option<String> : |d| field_str(d, "kind"),
        match_count -> usize : |d| array_len(d, "matches").max(array_len(d, "functions")).max(array_len(d, "decoders")).max(array_len(d, "sites")),
    }
);

typed_report!(
    CallGraph,
    "CallGraph",
    "Whole-program call graph: nodes (functions) and edges (call instructions).",
    accessors {
        node_count -> usize : |d| array_len(d, "nodes"),
        edge_count -> usize : |d| array_len(d, "edges"),
    }
);

typed_report!(
    Capabilities,
    "Capabilities",
    "Capability rule-set match report for a native binary: each matched capability with evidence and ATT&CK/MBC tags.",
    accessors {
        match_count -> usize : |d| array_len(d, "matches"),
        format -> Option<String> : |d| field_str(d, "format"),
    }
);

typed_report!(
    ExtractionResult,
    "ExtractionResult",
    "Container/firmware extraction result: carved member entries and a quota summary.",
    accessors {
        kind -> Option<String> : |d| field_str(d, "kind"),
        entry_count -> usize : |d| array_len(d, "entries"),
        integrity_violation_count -> usize : |d| array_len(d, "integrity_violations"),
    }
);

typed_report!(
    OverlayReport,
    "OverlayReport",
    "Recursive carve report over an arbitrary blob: per-chunk classification, entropy, and nesting.",
    accessors {
        max_depth -> Option<u64> : |d| field_u64(d, "max_depth"),
        nodes_visited -> Option<u64> : |d| field_u64(d, "nodes_visited"),
        chunks_total -> Option<u64> : |d| field_u64(d, "chunks_total"),
        bytes_carved -> Option<u64> : |d| field_u64(d, "bytes_carved"),
    }
);

typed_report!(
    EntropyReport,
    "EntropyReport",
    "Sliding-window Shannon entropy map of a binary, with per-window bits/byte and a byte histogram.",
    accessors {
        window_count -> usize : |d| array_len(d, "windows").max(array_len(d, "samples")),
        mean -> Option<f64> : |d| field_f64(d, "mean").or_else(|| field_f64(d, "mean_entropy")),
        min -> Option<f64> : |d| field_f64(d, "min").or_else(|| field_f64(d, "min_entropy")),
        max -> Option<f64> : |d| field_f64(d, "max").or_else(|| field_f64(d, "max_entropy")),
    }
);

typed_report!(
    StringsReport,
    "StringsReport",
    "Extracted ASCII/UTF-16 strings with optional single-layer deobfuscation (XOR brute, base64, ROT-n, stack strings).",
    accessors {
        string_count -> usize : |d| array_len(d, "strings"),
    }
);

typed_report!(
    IocReport,
    "IocReport",
    "Indicators of compromise harvested from raw bytes and recovered strings, one base64/hex layer decoded.",
    accessors {
        indicator_count -> usize : |d| array_len(d, "indicators"),
    }
);

typed_report!(
    BehaviorReport,
    "BehaviorReport",
    "Behavioral summary of a binary by category (network, filesystem, process, registry, crypto, anti-analysis, dynamic-code) with MITRE ATT&CK ids.",
    accessors {
        category_count -> usize : |d| array_len(d, "categories"),
    }
);

typed_report!(
    IdentifyReport,
    "IdentifyReport",
    "Compiler/linker/packer/protector/installer fingerprint of a PE/ELF/Mach-O with structural evidence and the routing disrobe pass.",
    accessors {
        format -> Option<String> : |d| field_str(d, "format"),
        finding_count -> usize : |d| array_len(d, "findings"),
    }
);

typed_report!(
    SecretScanReport,
    "SecretScanReport",
    "Leaked-credential scan result (cloud keys, VCS tokens, JWTs, PEM/SSH keys) over raw bytes.",
    accessors {
        finding_count -> usize : |d| array_len(d, "findings").max(array_len(d, "secrets")),
    }
);

typed_report!(
    SymbolsReport,
    "SymbolsReport",
    "Symbols, sections, segments, imports, and debug info dumped from a native binary.",
    accessors {
        symbol_count -> usize : |d| array_len(d, "symbols"),
        section_count -> usize : |d| array_len(d, "sections"),
        import_count -> usize : |d| array_len(d, "imports"),
    }
);

typed_report!(
    SbomReport,
    "SbomReport",
    "CycloneDX 1.5 SBOM derived from an embedded cargo-auditable dependency section.",
    accessors {
        component_count -> usize : |d| array_len(d, "components"),
        bom_format -> Option<String> : |d| field_str(d, "bomFormat"),
        spec_version -> Option<String> : |d| field_str(d, "specVersion"),
    }
);

typed_report!(
    FingerprintReport,
    "FingerprintReport",
    "Aggregated crypto-constant + FLIRT + string-xref fingerprint sidecar for a native binary.",
    accessors {
        crypto_hit_count -> usize : |d| array_len(d, "crypto").max(array_len(d, "crypto_constants")),
    }
);

typed_report!(
    SignatureReport,
    "SignatureReport",
    "Crypto-primitive signatures (AES T-tables, SHA/MD5 IV+K, ChaCha20 sigma) and optional FLIRT matches.",
    accessors {
        signature_count -> usize : |d| array_len(d, "signatures").max(array_len(d, "matches")),
    }
);

typed_report!(
    SigmakerReport,
    "SigmakerReport",
    "Wildcarded byte signature generated from a function at a virtual address.",
    accessors {
        ida_pattern -> Option<String> : |d| field_str(d, "ida").or_else(|| field_str(d, "pattern")),
        byte_count -> usize : |d| array_len(d, "bytes"),
    }
);

typed_report!(
    DiffReport,
    "DiffReport",
    "Function-level diff of two binaries: added/removed/changed functions with the kind of change.",
    accessors {
        added -> usize : |d| array_len(d, "added"),
        removed -> usize : |d| array_len(d, "removed"),
        changed -> usize : |d| array_len(d, "changed"),
    }
);

typed_report!(
    PatchReport,
    "PatchReport",
    "Result of rewriting native bytes at a virtual address and revalidating the patched image.",
    accessors {
        at -> Option<u64> : |d| field_u64(d, "at"),
        bytes_written -> Option<u64> : |d| field_u64(d, "bytes_written").or_else(|| field_u64(d, "written")),
        revalidated -> bool : |d| field_bool(d, "revalidated"),
    }
);

typed_report!(
    YaraReport,
    "YaraReport",
    "Parsed YARA ruleset AST, or a generated candidate rule from an artifact.",
    accessors {
        rule_count -> usize : |d| array_len(d, "rules"),
    }
);

typed_report!(
    ChainReport,
    "ChainReport",
    "End-to-end chain/auto recovery document: per-pass status, stage hashes, verdict, provenance.",
    accessors {
        spec -> Option<String> : |d| field_str(d, "spec"),
        pass_count -> usize : |d| array_len(d, "passes").max(array_len(d, "stages")),
        terminated -> bool : |d| field_bool(d, "terminated"),
    }
);

typed_report!(
    EnvelopeReport,
    "EnvelopeReport",
    "Verification report for a .dr envelope: rung, hot/cold sizes, BLAKE3 root hash.",
    accessors {
        verified -> bool : |d| field_bool(d, "verified"),
        rung -> Option<String> : |d| field_str(d, "rung"),
        version -> Option<i64> : |d| field_i64(d, "version"),
        hot_bytes -> Option<u64> : |d| field_u64(d, "hot_bytes"),
        cold_bytes -> Option<u64> : |d| field_u64(d, "cold_bytes"),
        root_hash -> Option<String> : |d| field_str(d, "root_hash_blake3_hex"),
    }
);

typed_report!(
    Provenance,
    "Provenance",
    "Tool/selection/input provenance metadata extracted from an LLM sidecar bundle.",
    accessors {
        schema -> Option<String> : |d| field_str(d, "schema"),
        schema_version -> Option<String> : |d| field_str(d, "schema_version"),
        generated_at -> Option<String> : |d| field_str(d, "generated_at"),
    }
);

typed_report!(
    PyDecompileReport,
    "PyDecompileReport",
    "Decompiled .pyc: recovered source, marshal/decompile versions, and an optional recompile round-trip outcome.",
    llm,
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
        marshal_version -> Option<String> : |d| field(d, "marshal_version").map(version_label),
        decompile_version -> Option<String> : |d| field(d, "decompile_version").map(version_label),
        recovered_directly -> bool : |d| field_bool(d, "recovered_directly"),
        fallback_reason -> Option<String> : |d| field_str(d, "fallback_reason"),
        roundtrip_status -> Option<String> : |d| nested_str(d, "roundtrip", "status"),
        roundtrip_detail -> Option<String> : |d| nested_str(d, "roundtrip", "detail"),
        interpreter_path -> Option<String> : |d| nested_str(d, "roundtrip", "interpreter_path"),
        interpreter_version -> Option<String> : |d| nested_str(d, "roundtrip", "interpreter_version"),
    }
);

typed_report!(
    PyDisasmReport,
    "PyDisasmReport",
    "Python bytecode disassembly: marshal version, instruction count, and the rendered listing.",
    llm,
    accessors {
        marshal_version -> Option<String> : |d| field_str(d, "marshal_version"),
        instruction_count -> usize : |d| field_u64(d, "instruction_count").map_or(0, u64_to_usize),
        text -> Option<String> : |d| field_str(d, "text"),
    }
);

typed_report!(
    PyDeobReport,
    "PyDeobReport",
    "Python deobfuscation: detection verdict, peel trace, and an optional constant-folded cleanup source.",
    llm,
    accessors {
        peeled_source -> Option<String> : |d| nested_str(d, "cleanup", "source").or_else(|| nested_str(d, "peel", "final_source")),
        cleanup_source -> Option<String> : |d| nested_str(d, "cleanup", "source"),
        layer_count -> usize : |d| nested_array_len(d, "peel", "layers").max(nested_array_len(d, "peel", "stages")),
    }
);

typed_report!(
    PyDeobDetection,
    "PyDeobDetection",
    "Family-detection verdict for an obfuscated Python source string.",
    llm,
    accessors {
        match_count -> usize : |d| array_len(d, "matches").max(array_len(d, "families")),
    }
);

typed_report!(
    ObfuscatorPass,
    "ObfuscatorPass",
    "One registered Python obfuscator pass, identified by its stable id.",
    accessors {
        id -> Option<String> : |d| field_str(d, "id"),
    }
);

typed_report!(
    PyarmorDetection,
    "PyarmorDetection",
    "PyArmor wrapper fingerprint: version, protection kind, confidence, serial, Python version, payload geometry.",
    llm,
    accessors {
        version -> Option<String> : |d| field_str(d, "version"),
        protection -> Option<String> : |d| field_str(d, "protection"),
        confidence -> Option<String> : |d| field_str(d, "confidence"),
        serial -> Option<String> : |d| field_str(d, "serial"),
        python_major -> Option<u64> : |d| field_u64(d, "python_major"),
        python_minor -> Option<u64> : |d| field_u64(d, "python_minor"),
        payload_offset -> Option<u64> : |d| field_u64(d, "payload_offset"),
        payload_size -> Option<u64> : |d| field_u64(d, "payload_size"),
    }
);

typed_report!(
    PyarmorUnpack,
    "PyarmorUnpack",
    "Static PyArmor unpack result: status, recovered plaintext geometry, BCC and inner-cipher recovery counts.",
    llm,
    accessors {
        status -> Option<String> : |d| field_str(d, "status"),
        pyarmor_version -> Option<String> : |d| field_str(d, "pyarmor_version"),
        protection_kind -> Option<String> : |d| field_str(d, "protection_kind"),
        plaintext_len -> Option<u64> : |d| field_u64(d, "plaintext_len"),
        plaintext_blake3_hex -> Option<String> : |d| field_str(d, "plaintext_blake3_hex"),
        bcc_blob_count -> Option<u64> : |d| field_u64(d, "bcc_blob_count"),
        inner_cipher_recovered_co -> Option<u64> : |d| field_u64(d, "inner_cipher_recovered_co"),
    }
);

typed_report!(
    PyarmorClassification,
    "PyarmorClassification",
    "PyArmor wrapper-mode classification: script type, bootstrap import, and the RFT/ECC/mix-str feature flags.",
    accessors {
        script_type -> Option<String> : |d| field_str(d, "script_type"),
        bootstrap_import -> Option<String> : |d| field_str(d, "bootstrap_import"),
        disposition -> Option<String> : |d| field_str(d, "disposition"),
        rft_enabled -> bool : |d| field_bool(d, "rft_enabled"),
        ecc_enabled -> bool : |d| field_bool(d, "ecc_enabled"),
    }
);

typed_report!(
    PyInstallerArchive,
    "PyInstallerArchive",
    "PyInstaller image: cookie geometry plus per-entry metadata for each carved member.",
    llm,
    accessors {
        entry_count -> usize : |d| field_u64(d, "entry_count").map_or_else(|| array_len(d, "entries"), u64_to_usize),
        encrypted -> bool : |d| field_bool(d, "encrypted"),
        encryption_key_present -> bool : |d| field_bool(d, "encryption_key_present"),
        python_major -> Option<u64> : |d| field(d, "cookie").and_then(|c: &Json| field_u64(c, "python_major")),
        python_minor -> Option<u64> : |d| field(d, "cookie").and_then(|c: &Json| field_u64(c, "python_minor")),
    }
);

typed_report!(
    NuitkaDetection,
    "NuitkaDetection",
    "Nuitka fingerprint: flavor, version, wheel marker, and onefile payload geometry.",
    llm,
    accessors {
        flavor -> Option<String> : |d| field_str(d, "flavor"),
        version -> Option<String> : |d| field_str(d, "version"),
        wheel_marker -> Option<String> : |d| field_str(d, "wheel_marker"),
        onefile_payload_offset -> Option<u64> : |d| field_u64(d, "onefile_payload_offset"),
        onefile_payload_compressed -> bool : |d| field_bool(d, "onefile_payload_compressed"),
    }
);

typed_report!(
    NuitkaExtraction,
    "NuitkaExtraction",
    "Nuitka variant extraction: the recovered onefile/standalone/module/signed-pe surface.",
    llm,
    accessors {
        variant -> Option<String> : first_non_llm_key,
    }
);

typed_report!(
    HermesDisassembly,
    "HermesDisassembly",
    "Hermes bytecode disassembly: function, identifier, and string counts plus the per-function listing.",
    llm,
    accessors {
        function_count -> usize : |d| field_u64(d, "function_count").map_or(0, u64_to_usize),
        identifier_count -> usize : |d| field_u64(d, "identifier_count").map_or(0, u64_to_usize),
        string_count -> usize : |d| field_u64(d, "string_count").map_or(0, u64_to_usize),
    }
);

typed_report!(
    HermesLift,
    "HermesLift",
    "Hermes JS-surface lift: recovered string/identifier tables and the function surface.",
    llm,
    accessors {
        function_surface_count -> usize : |d| array_len(d, "function_surface"),
        string_count -> usize : |d| object_len(d, "strings_by_index"),
        identifier_count -> usize : |d| object_len(d, "identifiers_by_index"),
    }
);

typed_report!(
    HermesInfo,
    "HermesInfo",
    "Hermes bundle header: format version, geometry counts, and header size.",
    llm,
    accessors {
        version -> Option<u64> : |d| field(d, "header").and_then(|h: &Json| field_u64(h, "version")),
        function_count -> Option<u64> : |d| field(d, "header").and_then(|h: &Json| field_u64(h, "function_count")),
        string_count -> Option<u64> : |d| field(d, "header").and_then(|h: &Json| field_u64(h, "string_count")),
        header_size -> Option<u64> : |d| field_u64(d, "header_size"),
    }
);

typed_report!(
    MachoReport,
    "MachoReport",
    "Mach-O dump: image kind, fat-arch entries, and per-slice parses.",
    llm,
    accessors {
        kind -> Option<String> : |d| field_str(d, "kind"),
        fat_entry_count -> usize : |d| array_len(d, "fat_entries"),
        slice_count -> usize : |d| array_len(d, "slices"),
    }
);

typed_report!(
    SwiftReport,
    "SwiftReport",
    "Swift/Objective-C reflective metadata: container kind, fat entries, and per-slice demangled type surface.",
    llm,
    accessors {
        container -> Option<String> : |d| field_str(d, "container"),
        fat_entry_count -> usize : |d| array_len(d, "fat_entries"),
        slice_count -> usize : |d| array_len(d, "slices"),
    }
);

typed_report!(
    JvmClass,
    "JvmClass",
    "Parsed JVM classfile: version, constant pool, access flags, fields, and methods.",
    llm,
    accessors {
        major_version -> Option<u64> : |d| field_u64(d, "major_version"),
        minor_version -> Option<u64> : |d| field_u64(d, "minor_version"),
        method_count -> usize : |d| array_len(d, "methods"),
        field_count -> usize : |d| array_len(d, "fields"),
        constant_pool_count -> usize : |d| array_len(d, "constant_pool"),
    }
);

typed_report!(
    DexFileReport,
    "DexFileReport",
    "Parsed DEX file: header plus string, type, and class-descriptor pools.",
    llm,
    accessors {
        string_count -> usize : |d| array_len(d, "strings"),
        type_count -> usize : |d| array_len(d, "type_names"),
        class_count -> usize : |d| array_len(d, "class_descriptors"),
        method_count -> usize : |d| array_len(d, "method_ids"),
    }
);

typed_report!(
    JvmDecompiledClass,
    "JvmDecompiledClass",
    "Pseudo-Java decompilation of a classfile: source plus lift-fidelity counts.",
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
        method_count -> usize : |d| field_u64(d, "method_count").map_or(0, u64_to_usize),
        field_count -> usize : |d| field_u64(d, "field_count").map_or(0, u64_to_usize),
        fully_lifted_methods -> usize : |d| field_u64(d, "fully_lifted_methods").map_or(0, u64_to_usize),
        fallback_methods -> usize : |d| field_u64(d, "fallback_methods").map_or(0, u64_to_usize),
    }
);

typed_report!(
    JvmDecompiledDex,
    "JvmDecompiledDex",
    "Pseudo-Java decompilation of a DEX file with per-class source and lift-fidelity counts.",
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
        source_count -> usize : |d| object_len(d, "sources"),
        class_count -> usize : |d| field_u64(d, "class_count").map_or(0, u64_to_usize),
        method_count -> usize : |d| field_u64(d, "method_count").map_or(0, u64_to_usize),
        fully_lifted_methods -> usize : |d| field_u64(d, "fully_lifted_methods").map_or(0, u64_to_usize),
        fallback_methods -> usize : |d| field_u64(d, "fallback_methods").map_or(0, u64_to_usize),
    }
);

typed_report!(
    DetectionList,
    "DetectionList",
    "Ordered list of obfuscator/protector detection hits over an artifact.",
    accessors {
        count -> usize : top_array_len,
    }
);

typed_report!(
    JvmBackends,
    "JvmBackends",
    "Host probe for external JVM and Android decompiler backends.",
    llm,
    accessors {
        jvm_count -> usize : |d| array_len(d, "jvm"),
        android_count -> usize : |d| array_len(d, "android"),
    }
);

typed_report!(
    BackendList,
    "BackendList",
    "Probe result for each external backend: name, binary, and host availability.",
    accessors {
        count -> usize : top_array_len,
        available_count -> usize : available_backend_count,
    }
);

typed_report!(
    ApkResources,
    "ApkResources",
    "Decoded APK resources: package name, resource entries, manifest XML, signing certificates, and JNI surface.",
    llm,
    accessors {
        package -> Option<String> : |d| field_str(d, "package"),
        manifest_xml -> Option<String> : |d| field_str(d, "manifest_xml"),
        resource_entry_count -> usize : |d| field_u64(d, "resource_entry_count").map_or(0, u64_to_usize),
        certificate_count -> usize : |d| array_len(d, "certificates"),
        dex_count -> usize : |d| field_u64(d, "dex_count").map_or(0, u64_to_usize),
        native_lib_count -> usize : |d| field_u64(d, "native_lib_count").map_or(0, u64_to_usize),
        jni_native_method_count -> usize : |d| nested_u64(d, "jni", "native_method_count").map_or(0, u64_to_usize),
        jni_resolved_statically -> usize : |d| nested_u64(d, "jni", "resolved_statically").map_or(0, u64_to_usize),
        jni_dynamic_only -> usize : |d| nested_u64(d, "jni", "dynamic_only").map_or(0, u64_to_usize),
        jni_registered_natives_count -> usize : |d| nested_array_len(d, "jni", "registered_natives"),
    }
);

typed_report!(
    JniLink,
    "JniLink",
    "JNI cross-boundary link table: declared native methods matched against library exports and RegisterNatives triples.",
    accessors {
        native_method_count -> usize : |d| field_u64(d, "native_method_count").map_or(0, u64_to_usize),
        resolved_statically -> usize : |d| field_u64(d, "resolved_statically").map_or(0, u64_to_usize),
        dynamic_only -> usize : |d| field_u64(d, "dynamic_only").map_or(0, u64_to_usize),
        registered_natives_count -> usize : |d| array_len(d, "registered_natives"),
        code_scan_complete -> bool : |d| field_bool(d, "code_scan_complete"),
        decode_error_count -> usize : |d| field_u64(d, "decode_error_count").map_or(0, u64_to_usize),
    }
);

typed_report!(
    DotnetPe,
    "DotnetPe",
    "Parsed .NET PE image: bitness, machine, sections, and data directories.",
    llm,
    accessors {
        bitness -> Option<String> : |d| field_str(d, "bitness"),
        machine -> Option<u64> : |d| field_u64(d, "machine"),
        section_count -> usize : |d| array_len(d, "sections").max(field_u64(d, "number_of_sections").map_or(0, u64_to_usize)),
        entry_point_rva -> Option<u64> : |d| field_u64(d, "entry_point_rva"),
    }
);

typed_report!(
    DotnetMetadata,
    "DotnetMetadata",
    "CLR header plus #~/#Strings/#US metadata root: runtime version, version string, and stream table.",
    llm,
    accessors {
        version -> Option<String> : |d| nested_str(d, "metadata", "version"),
        major_runtime_version -> Option<u64> : |d| field(d, "clr").and_then(|c: &Json| field_u64(c, "major_runtime_version")),
        stream_count -> usize : |d| field(d, "metadata").map_or(0, |m: &Json| object_len(m, "streams")),
    }
);

typed_report!(
    DotnetDetection,
    "DotnetDetection",
    "Protector-detection report for a .NET assembly: matched protectors and the primary verdict.",
    llm,
    accessors {
        primary -> Option<String> : |d| field_str(d, "primary"),
        match_count -> usize : |d| object_len(d, "matches"),
    }
);

typed_report!(
    DotnetAnalysis,
    "DotnetAnalysis",
    ".NET pass summary: bitness, runtime, streams, native-AOT flag, protectors, and opcode-table coverage.",
    llm,
    accessors {
        pe_bitness -> Option<String> : |d| field_str(d, "pe_bitness"),
        clr_runtime_version -> Option<String> : |d| field_str(d, "clr_runtime_version"),
        native_aot -> bool : |d| field_bool(d, "native_aot"),
        primary_protector -> Option<String> : |d| field_str(d, "primary_protector"),
        opcode_spec_coverage_pct -> Option<u64> : |d| field_u64(d, "opcode_spec_coverage_pct"),
    }
);

typed_report!(
    DotnetDecompilation,
    "DotnetDecompilation",
    "Pseudo-C# decompilation of an assembly: module name plus per-method recovery counts.",
    llm,
    accessors {
        module_name -> Option<String> : |d| field_str(d, "module_name"),
        methods_decompiled -> Option<u64> : |d| field_u64(d, "methods_decompiled"),
        methods_bodyless -> Option<u64> : |d| field_u64(d, "methods_bodyless"),
        methods_failed -> Option<u64> : |d| field_u64(d, "methods_failed"),
    }
);

typed_report!(
    DotnetDecoders,
    "DotnetDecoders",
    "Static string-decoder recovery for a .NET assembly: pure decoders found and constants recovered.",
    llm,
    accessors {
        pure_decoders_found -> Option<u64> : |d| field_u64(d, "pure_decoders_found"),
        constants_recovered -> usize : |d| array_len(d, "constants_recovered"),
    }
);

typed_report!(
    WasmAnalysis,
    "WasmAnalysis",
    "WebAssembly module summary: import/export tables, section counts, code size, and DWARF presence.",
    llm,
    accessors {
        import_count -> usize : |d| array_len(d, "imports"),
        export_count -> usize : |d| array_len(d, "exports"),
        func_count -> Option<u64> : |d| field_u64(d, "func_count"),
        code_size_bytes -> Option<u64> : |d| field_u64(d, "code_size_bytes"),
        has_dwarf -> bool : |d| field_bool(d, "has_dwarf"),
    }
);

typed_report!(
    WasmDetection,
    "WasmDetection",
    "WebAssembly obfuscator detection: family, confidence, markers, and module shape signals.",
    llm,
    accessors {
        obfuscator -> Option<String> : |d| field_str(d, "obfuscator"),
        confidence -> Option<f64> : |d| field_f64(d, "confidence"),
        has_name_section -> bool : |d| field_bool(d, "has_name_section"),
        function_count -> Option<u64> : |d| field_u64(d, "function_count"),
    }
);

typed_report!(
    JsDetection,
    "JsDetection",
    "JavaScript obfuscator detection: family, confidence, and matched markers.",
    llm,
    accessors {
        family -> Option<String> : |d| field_str(d, "family"),
        confidence -> Option<f64> : |d| field_f64(d, "confidence"),
        marker_count -> usize : |d| array_len(d, "markers"),
    }
);

typed_report!(
    JsUnminify,
    "JsUnminify",
    "JavaScript unminification: recovered source plus per-transform statistics.",
    llm,
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
    }
);

typed_report!(
    JsUnbundle,
    "JsUnbundle",
    "JavaScript unbundle: per-module recovery from a detected or hinted bundler.",
    llm,
    accessors {
        module_count -> usize : |d| array_len(d, "modules"),
        bundler -> Option<String> : |d| field_str(d, "bundler"),
    }
);

typed_report!(
    NativeFormat,
    "NativeFormat",
    "Native container format: kind, bitness, subsystem, and structural notes.",
    llm,
    accessors {
        kind -> Option<String> : |d| field_str(d, "kind"),
        bits -> Option<u64> : |d| field_u64(d, "bits"),
        subsystem -> Option<String> : |d| field_str(d, "subsystem"),
    }
);

typed_report!(
    NativeDeobfuscation,
    "NativeDeobfuscation",
    "x86 OLLVM/Tigress deobfuscation: control-flow deflatten, bogus-branch, and MBA-substitution results.",
    accessors {
        bits -> Option<u64> : |d| field_u64(d, "bits"),
        recovered_blocks -> Option<u64> : |d| field(d, "cff").and_then(|c: &Json| field_u64(c, "recovered_blocks")),
        original_blocks -> Option<u64> : |d| field(d, "cff").and_then(|c: &Json| field_u64(c, "original_blocks")),
        dispatcher_states -> Option<u64> : |d| field(d, "cff").and_then(|c: &Json| field_u64(c, "dispatcher_states")),
        covered_states -> Option<u64> : |d| field(d, "cff").and_then(|c: &Json| field_u64(c, "covered_states")),
        fully_recovered -> bool : |d| field(d, "cff").is_some_and(|c: &Json| field_bool(c, "fully_recovered")),
    }
);

typed_report!(
    LuaDetection,
    "LuaDetection",
    "Detected Lua bytecode flavor.",
    llm,
    accessors {
        format -> Option<String> : |d| field_str(d, "format"),
    }
);

typed_report!(
    LuaDecompilation,
    "LuaDecompilation",
    "Lua bytecode decompilation: recovered source, fidelity grade, and warnings.",
    llm,
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
        fidelity -> Option<String> : |d| field_str(d, "fidelity"),
        warning_count -> usize : |d| array_len(d, "warnings"),
    }
);

typed_report!(
    LuaDeobfuscation,
    "LuaDeobfuscation",
    "Lua source deobfuscation: detected obfuscator, peeled source, passes run, and recovery completeness.",
    llm,
    accessors {
        obfuscator -> Option<String> : |d| field_str(d, "obfuscator"),
        deobfuscated -> Option<String> : |d| field_str(d, "deobfuscated"),
        fully_recovered -> bool : |d| field_bool(d, "fully_recovered"),
        passes_run_count -> usize : |d| array_len(d, "passes_run"),
        recovered_string_count -> usize : |d| array_len(d, "recovered_strings"),
    }
);

typed_report!(
    GoAnalysis,
    "GoAnalysis",
    "Go binary analysis: image kind, pclntab version, build version, symbols, and garble report.",
    llm,
    accessors {
        image_kind -> Option<String> : |d| field_str(d, "image_kind"),
        pclntab_version -> Option<String> : |d| field_str(d, "pclntab_version"),
        buildversion -> Option<String> : |d| field_str(d, "buildversion"),
        ptr_size -> Option<u64> : |d| field_u64(d, "ptr_size"),
    }
);

typed_report!(
    GoSymbols,
    "GoSymbols",
    "Go pclntab symbols: version label, recovered functions, source files, and package set.",
    llm,
    accessors {
        version_label -> Option<String> : |d| field_str(d, "version_label"),
        function_count -> usize : |d| array_len(d, "funcs"),
        source_file_count -> usize : |d| array_len(d, "source_files"),
        package_count -> usize : |d| array_len(d, "package_set"),
    }
);

typed_report!(
    GoPclntab,
    "GoPclntab",
    "Go pclntab header: format version, pointer size, function count, and image kind.",
    llm,
    accessors {
        version -> Option<String> : |d| field_str(d, "version"),
        ptr_size -> Option<u64> : |d| field_u64(d, "ptr_size"),
        func_count -> Option<u64> : |d| field_u64(d, "func_count"),
        image_kind -> Option<String> : |d| field_str(d, "image_kind"),
    }
);

typed_report!(
    GarbleReport,
    "GarbleReport",
    "garble obfuscation assessment: quality grade, detection score, seed recoverability, and recovered strings.",
    llm,
    accessors {
        quality -> Option<String> : |d| field_str(d, "quality"),
        detection_score -> Option<u64> : |d| field_u64(d, "detection_score"),
        seed_recoverable -> bool : |d| field_bool(d, "seed_recoverable"),
        seed_hash -> Option<String> : |d| field_str(d, "seed_hash"),
        recovered_string_count -> usize : |d| array_len(d, "recovered_strings"),
    }
);

typed_report!(
    RubyDetection,
    "RubyDetection",
    "Detected Ruby artifact flavor (MRI source, YARV, mruby, JRuby, TruffleRuby, or a wrapper).",
    llm,
    accessors {
        flavor -> Option<String> : |d| field_str(d, "flavor"),
    }
);

typed_report!(
    RubyAnalysis,
    "RubyAnalysis",
    "Ruby analysis: flavor plus the MRI/YARV/mruby/JRuby/TruffleRuby/wrapper surface for the detected backend.",
    llm,
    accessors {
        flavor -> Option<String> : |d| field_str(d, "flavor"),
        source_path -> Option<String> : |d| field_str(d, "source_path"),
        input_len -> Option<u64> : |d| field_u64(d, "input_len"),
    }
);

typed_report!(
    PhpDetection,
    "PhpDetection",
    "PHP artifact detection: kind, confidence, open-tag offset, and __halt_compiler presence.",
    llm,
    accessors {
        kind -> Option<String> : |d| field_str(d, "kind"),
        confidence -> Option<String> : |d| field_str(d, "confidence"),
        open_tag_offset -> Option<u64> : |d| field_u64(d, "open_tag_offset"),
        has_halt_compiler -> bool : |d| field_bool(d, "has_halt_compiler"),
    }
);

typed_report!(
    PhpScan,
    "PhpScan",
    "PHP obfuscator signature scan: per-family hit counts.",
    llm,
    accessors {
        hit_count -> usize : |d| array_len(d, "hits"),
        family_count -> usize : |d| object_len(d, "families"),
    }
);

typed_report!(
    PhpDecode,
    "PhpDecode",
    "PHP eval-chain decode: recovered source, per-layer peel trace, and a residual-eval flag.",
    llm,
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
        layer_count -> usize : |d| array_len(d, "layers"),
        residual_eval -> bool : |d| field_bool(d, "residual_eval"),
    }
);

typed_report!(
    BatchDeobReport,
    "BatchDeobReport",
    "Windows batch deobfuscation: per-transform counts, embedded payloads, decrypted stages, IOCs, and recovered output.",
    llm,
    accessors {
        output -> Option<String> : |d| field_str(d, "output"),
        embedded_payload_count -> usize : |d| array_len(d, "embedded_payloads"),
        decrypted_stage_count -> usize : |d| array_len(d, "decrypted_stages"),
        commands_emulated -> Option<u64> : |d| field_u64(d, "commands_emulated"),
    }
);

typed_report!(
    PowershellDetection,
    "PowershellDetection",
    "PowerShell obfuscator detection: family, confidence, markers, and ranked candidates.",
    llm,
    accessors {
        obfuscator -> Option<String> : |d| field_str(d, "obfuscator"),
        confidence -> Option<f64> : |d| field_f64(d, "confidence"),
        marker_count -> usize : |d| array_len(d, "markers"),
    }
);

typed_report!(
    PowershellDeobfuscation,
    "PowershellDeobfuscation",
    "PowerShell deobfuscation: recovered output plus the token/string/AST transforms applied.",
    llm,
    accessors {
        output -> Option<String> : |d| field_str(d, "output"),
        level -> Option<String> : |d| field_str(d, "level"),
        transformation_count -> usize : |d| array_len(d, "transformations"),
    }
);

typed_report!(
    ContainerDetection,
    "ContainerDetection",
    "Container-format detection: whether a container was recognized, its kind, and zip-family membership.",
    llm,
    accessors {
        detected -> bool : |d| field_bool(d, "detected"),
        kind -> Option<String> : |d| field_str(d, "kind"),
        is_zip_family -> bool : |d| field_bool(d, "is_zip_family"),
    }
);

typed_report!(
    ContainerMembers,
    "ContainerMembers",
    "Container member listing: format, total size, listing mode, and per-entry name/size.",
    llm,
    accessors {
        format -> Option<String> : |d| field_str(d, "format"),
        size -> Option<u64> : |d| field_u64(d, "size"),
        listing -> Option<String> : |d| field_str(d, "listing"),
        entry_count -> usize : |d| array_len(d, "entries"),
    }
);

typed_report!(
    PickleDecompilation,
    "PickleDecompilation",
    "Symbolic pickle decompilation: a Python-assignment source rendering plus the reconstructed object graph.",
    llm,
    accessors {
        source -> Option<String> : |d| field_str(d, "source"),
    }
);

typed_report!(
    PickleSafety,
    "PickleSafety",
    "Pickle safety verdict: severity, findings, imported globals, and __reduce__ count.",
    llm,
    accessors {
        severity -> Option<String> : |d| field_str(d, "severity"),
        finding_count -> usize : |d| array_len(d, "findings"),
        import_count -> usize : |d| array_len(d, "imports"),
        reduce_count -> Option<u64> : |d| field_u64(d, "reduce_count"),
    }
);

typed_report!(
    PickleTrace,
    "PickleTrace",
    "Symbolic pickle VM trace: protocol, memo and stack-depth counts, global references, and __reduce__ count.",
    llm,
    accessors {
        protocol -> Option<u64> : |d| field_u64(d, "protocol"),
        memo_count -> Option<u64> : |d| field_u64(d, "memo_count"),
        max_stack_depth -> Option<u64> : |d| field_u64(d, "max_stack_depth"),
        global_ref_count -> usize : |d| array_len(d, "global_refs"),
        reduce_count -> Option<u64> : |d| field_u64(d, "reduce_count"),
    }
);

typed_report!(
    PicklePolyglot,
    "PicklePolyglot",
    "Pickle polyglot detection: pickle membership, co-resident container kinds, and a polyglot verdict.",
    llm,
    accessors {
        is_pickle -> bool : |d| field_bool(d, "is_pickle"),
        is_polyglot -> bool : |d| field_bool(d, "is_polyglot"),
        kind_count -> usize : |d| array_len(d, "kinds"),
    }
);

typed_report!(
    PickleMlReport,
    "PickleMlReport",
    "ML-model pickle scan: model format, framing, and embedded pickle streams.",
    llm,
    accessors {
        format -> Option<String> : |d| field_str(d, "format"),
        framing -> Option<String> : |d| field_str(d, "framing"),
        embedded_count -> usize : |d| array_len(d, "embedded"),
    }
);

fn version_label(value: &Json) -> String {
    let major: u64 = field_u64(value, "major").map_or(0, |value: u64| value);
    let minor: u64 = field_u64(value, "minor").map_or(0, |value: u64| value);
    format!("{major}.{minor}")
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CanonicalSource>()?;
    m.add_class::<DisasmPayload>()?;
    m.add_class::<FunctionList>()?;
    m.add_class::<QueryReport>()?;
    m.add_class::<CallGraph>()?;
    m.add_class::<Capabilities>()?;
    m.add_class::<ExtractionResult>()?;
    m.add_class::<OverlayReport>()?;
    m.add_class::<EntropyReport>()?;
    m.add_class::<StringsReport>()?;
    m.add_class::<IocReport>()?;
    m.add_class::<BehaviorReport>()?;
    m.add_class::<IdentifyReport>()?;
    m.add_class::<SecretScanReport>()?;
    m.add_class::<SymbolsReport>()?;
    m.add_class::<SbomReport>()?;
    m.add_class::<FingerprintReport>()?;
    m.add_class::<SignatureReport>()?;
    m.add_class::<SigmakerReport>()?;
    m.add_class::<DiffReport>()?;
    m.add_class::<PatchReport>()?;
    m.add_class::<YaraReport>()?;
    m.add_class::<ChainReport>()?;
    m.add_class::<EnvelopeReport>()?;
    m.add_class::<Provenance>()?;
    m.add_class::<PyDecompileReport>()?;
    m.add_class::<PyDisasmReport>()?;
    m.add_class::<PyDeobReport>()?;
    m.add_class::<PyDeobDetection>()?;
    m.add_class::<ObfuscatorPass>()?;
    m.add_class::<PyarmorDetection>()?;
    m.add_class::<PyarmorUnpack>()?;
    m.add_class::<PyarmorClassification>()?;
    m.add_class::<PyInstallerArchive>()?;
    m.add_class::<NuitkaDetection>()?;
    m.add_class::<NuitkaExtraction>()?;
    m.add_class::<HermesDisassembly>()?;
    m.add_class::<HermesLift>()?;
    m.add_class::<HermesInfo>()?;
    m.add_class::<MachoReport>()?;
    m.add_class::<SwiftReport>()?;
    m.add_class::<JvmClass>()?;
    m.add_class::<DexFileReport>()?;
    m.add_class::<JvmDecompiledClass>()?;
    m.add_class::<JvmDecompiledDex>()?;
    m.add_class::<DetectionList>()?;
    m.add_class::<JvmBackends>()?;
    m.add_class::<BackendList>()?;
    m.add_class::<ApkResources>()?;
    m.add_class::<JniLink>()?;
    m.add_class::<DotnetPe>()?;
    m.add_class::<DotnetMetadata>()?;
    m.add_class::<DotnetDetection>()?;
    m.add_class::<DotnetAnalysis>()?;
    m.add_class::<DotnetDecompilation>()?;
    m.add_class::<DotnetDecoders>()?;
    m.add_class::<WasmAnalysis>()?;
    m.add_class::<WasmDetection>()?;
    m.add_class::<JsDetection>()?;
    m.add_class::<JsUnminify>()?;
    m.add_class::<JsUnbundle>()?;
    m.add_class::<NativeFormat>()?;
    m.add_class::<NativeDeobfuscation>()?;
    m.add_class::<LuaDetection>()?;
    m.add_class::<LuaDecompilation>()?;
    m.add_class::<LuaDeobfuscation>()?;
    m.add_class::<GoAnalysis>()?;
    m.add_class::<GoSymbols>()?;
    m.add_class::<GoPclntab>()?;
    m.add_class::<GarbleReport>()?;
    m.add_class::<RubyDetection>()?;
    m.add_class::<RubyAnalysis>()?;
    m.add_class::<PhpDetection>()?;
    m.add_class::<PhpScan>()?;
    m.add_class::<PhpDecode>()?;
    m.add_class::<BatchDeobReport>()?;
    m.add_class::<PowershellDetection>()?;
    m.add_class::<PowershellDeobfuscation>()?;
    m.add_class::<ContainerDetection>()?;
    m.add_class::<ContainerMembers>()?;
    m.add_class::<PickleDecompilation>()?;
    m.add_class::<PickleSafety>()?;
    m.add_class::<PickleTrace>()?;
    m.add_class::<PicklePolyglot>()?;
    m.add_class::<PickleMlReport>()?;
    Ok(())
}
