use std::path::Path;

use disrobe_binfmt::{
    CarveConfig, CarveReport, ContainerKind, ExtractionResult as BinExtractionResult, NativeFile,
    carve_recursive, detect_container, extract_to, import_graph_dot, parse_native,
};
use disrobe_capabilities::CapabilitiesReport;
use disrobe_core::behavior::{self, BehaviorReport};
use disrobe_core::ioc::{self, IocReport};
use disrobe_core::secret_scan::{
    SecretScanReport, redact_report as redact_secret_report, scan_report,
};
use disrobe_core::strings::{self, Options, StringsReport};
use disrobe_core::yara::{self, YaraRuleset};
use disrobe_core::yara_gen::{self, GenerateOptions, GeneratedRule};
use disrobe_ir::Envelope;
use disrobe_pass_native::{
    BinDiffReport, CryptoConstHit, EntropyBlock, FileIdReport, FingerprintSidecar, FlirtMatch,
    FlirtSig, PatchEdit, PatchReport as NativePatchReport, SigmakerOptions, Signature, bindiff,
    build_disasm_payload, detect_crypto_constants, identify_file, make_signature, match_flirt,
    parse_flirt, windowed_entropy,
};
use disrobe_query::{CallGraph as QueryCallGraph, Module};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use serde::Serialize;

use crate::err::{DisrobeError, map};
use crate::typed::{
    BehaviorReport as PyBehaviorReport, CallGraph as PyCallGraph, Capabilities as PyCapabilities,
    DiffReport as PyDiffReport, DisasmPayload as PyDisasmPayload, EntropyReport as PyEntropyReport,
    ExtractionResult as PyExtractionResult, FingerprintReport as PyFingerprintReport,
    IdentifyReport as PyIdentifyReport, IocReport as PyIocReport, OverlayReport as PyOverlayReport,
    PatchReport as PyPatchReport, SbomReport as PySbomReport,
    SecretScanReport as PySecretScanReport, SigmakerReport as PySigmakerReport,
    SignatureReport as PySignatureReport, StringsReport as PyStringsReport,
    SymbolsReport as PySymbolsReport, YaraReport as PyYaraReport,
};

const ENTROPY_WINDOW_4K: usize = 4096;

#[pyfunction]
#[pyo3(signature = (data, *, min_len = strings::DEFAULT_MIN_LEN, decode = true))]
#[pyo3(text_signature = "(data, *, min_len=4, decode=True)")]
fn strings_extract(data: &[u8], min_len: usize, decode: bool) -> PyResult<PyStringsReport> {
    let opts: Options = Options { min_len, decode };
    let report: StringsReport = strings::report(data, None, opts);
    PyStringsReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn ioc_extract(data: &[u8]) -> PyResult<PyIocReport> {
    let report: IocReport = ioc::report(data, None);
    PyIocReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn behavior_analyze(data: &[u8]) -> PyResult<PyBehaviorReport> {
    let imports: Vec<String> = native_import_labels(data);
    let report: BehaviorReport = behavior::analyze(data, &imports);
    PyBehaviorReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(name = "identify", text_signature = "(data)")]
fn identify_binary(data: &[u8]) -> PyResult<PyIdentifyReport> {
    let report: FileIdReport = identify_file(data);
    PyIdentifyReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(name = "secret_scan", signature = (data, *, redact = false), text_signature = "(data, *, redact=False)")]
fn secret_scan_fn(data: &[u8], redact: bool) -> PyResult<PySecretScanReport> {
    let mut report: SecretScanReport = scan_report(data, None);
    if redact {
        redact_secret_report(&mut report);
    }
    PySecretScanReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn capabilities(binary_bytes: &[u8]) -> PyResult<PyCapabilities> {
    let report: CapabilitiesReport = if let Ok(env) = Envelope::decode(binary_bytes) {
        let module: Module =
            disrobe_query::module_from_envelope(&env).map_err(map("capabilities load module"))?;
        disrobe_capabilities::analyze_module(&module, binary_bytes, None)
    } else {
        disrobe_capabilities::analyze(binary_bytes).map_err(map("capabilities analyze"))?
    };
    PyCapabilities::from_serialize(&report)
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn native_symbols(data: &[u8]) -> PyResult<PySymbolsReport> {
    let nf: NativeFile = parse_native(data).map_err(map("native symbols"))?;
    PySymbolsReport::from_serialize(&nf)
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn native_disasm(data: &[u8]) -> PyResult<PyDisasmPayload> {
    let module: Module = load_module_for_disasm(data)?;
    PyDisasmPayload::from_serialize(&disasm_view(&module))
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn native_callgraph(data: &[u8]) -> PyResult<PyCallGraph> {
    let module: Module = load_module_for_disasm(data)?;
    let graph: QueryCallGraph = module.call_graph();
    PyCallGraph::from_serialize(&graph)
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn native_imports_dot(data: &[u8]) -> PyResult<String> {
    let nf: NativeFile = parse_native(data).map_err(map("native imports-dot"))?;
    Ok(import_graph_dot(&nf))
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn native_entropy(data: &[u8]) -> PyResult<PyEntropyReport> {
    let blocks: Vec<EntropyBlock> = windowed_entropy(data, ENTROPY_WINDOW_4K);
    let count: usize = blocks.len();
    let high: usize = blocks.iter().filter(|b: &&EntropyBlock| b.high).count();
    let max: f64 = blocks
        .iter()
        .map(|b: &EntropyBlock| b.entropy)
        .fold(0.0_f64, f64::max);
    let min: f64 = blocks
        .iter()
        .map(|b: &EntropyBlock| b.entropy)
        .fold(f64::INFINITY, f64::min);
    let mean: f64 = if count == 0 {
        0.0
    } else {
        blocks.iter().map(|b: &EntropyBlock| b.entropy).sum::<f64>() / count as f64
    };
    let report: EntropyView = EntropyView {
        window: ENTROPY_WINDOW_4K,
        block_count: count,
        high_count: high,
        max,
        min: if count == 0 { 0.0 } else { min },
        mean,
        windows: blocks,
    };
    PyEntropyReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(text_signature = "(data)")]
fn native_sbom(data: &[u8]) -> PyResult<PySbomReport> {
    use disrobe_pass_native::{AuditableSbom, parse_auditable_section};
    let sbom: AuditableSbom =
        parse_auditable_section(data).map_err(map("native sbom parse-auditable"))?;
    let report: SbomView = SbomView {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        components: sbom
            .crates
            .iter()
            .map(|c| SbomComponent {
                name: c.name.clone(),
                version: c.version.clone(),
            })
            .collect(),
    };
    PySbomReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(signature = (data, *, flirt = None))]
#[pyo3(text_signature = "(data, *, flirt=None)")]
fn native_fingerprint(data: &[u8], flirt: Option<&[u8]>) -> PyResult<PyFingerprintReport> {
    let flirt_db: Option<FlirtSig> = match flirt {
        Some(raw) => Some(parse_flirt(raw).map_err(map("native fingerprint flirt"))?),
        None => None,
    };
    let sidecar: FingerprintSidecar = FingerprintSidecar::build("inline", data, flirt_db.as_ref());
    PyFingerprintReport::from_serialize(&sidecar)
}

#[pyfunction]
#[pyo3(signature = (data, *, flirt = None))]
#[pyo3(text_signature = "(data, *, flirt=None)")]
fn native_signatures(data: &[u8], flirt: Option<&[u8]>) -> PyResult<PySignatureReport> {
    let hits: Vec<CryptoConstHit> = detect_crypto_constants(data);
    let flirt_matches: Vec<FlirtMatchView> = match flirt {
        Some(raw) => {
            let db: FlirtSig = parse_flirt(raw).map_err(map("native signatures flirt"))?;
            match_flirt(&db, data)
                .into_iter()
                .map(|m: FlirtMatch| FlirtMatchView {
                    name: m.name,
                    offset: m.image_offset,
                })
                .collect()
        }
        None => Vec::new(),
    };
    let report: SignatureView = SignatureView {
        signatures: hits,
        flirt_matches,
    };
    PySignatureReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(text_signature = "(data, at)")]
fn native_sigmaker(data: &[u8], at: u64) -> PyResult<PySigmakerReport> {
    let sig: Signature =
        make_signature(data, at, SigmakerOptions::default()).map_err(map("native sigmaker"))?;
    PySigmakerReport::from_serialize(&sig)
}

#[pyfunction]
#[pyo3(text_signature = "(a, b)")]
fn native_diff(a: &[u8], b: &[u8]) -> PyResult<PyDiffReport> {
    let report: BinDiffReport = bindiff(a, b).map_err(map("native diff"))?;
    PyDiffReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(signature = (data, *, at, replacement = None, nop_start = None, nop_end = None))]
#[pyo3(text_signature = "(data, *, at, replacement=None, nop_start=None, nop_end=None)")]
fn native_patch<'py>(
    py: Python<'py>,
    data: &[u8],
    at: u64,
    replacement: Option<Vec<u8>>,
    nop_start: Option<u64>,
    nop_end: Option<u64>,
) -> PyResult<(Bound<'py, PyBytes>, PyPatchReport)> {
    let mut edits: Vec<PatchEdit> = Vec::new();
    if let Some(bytes) = replacement
        && !bytes.is_empty()
    {
        edits.push(PatchEdit {
            virtual_address: at,
            bytes,
        });
    }
    if let (Some(start), Some(end)) = (nop_start, nop_end) {
        let edit: PatchEdit = PatchEdit::nop_range(start, end, 0x90).ok_or_else(|| {
            DisrobeError::new_err(format!("invalid nop range {start:#x}:{end:#x}"))
        })?;
        edits.push(edit);
    }
    if edits.is_empty() {
        return Err(DisrobeError::new_err(
            "native_patch needs `replacement` bytes or a nop_start/nop_end span".to_owned(),
        ));
    }
    let (patched, report): (Vec<u8>, NativePatchReport) =
        disrobe_pass_native::apply_patches_reported(data, &edits).map_err(map("native patch"))?;
    let typed: PyPatchReport = PyPatchReport::from_serialize(&report)?;
    Ok((PyBytes::new(py, &patched), typed))
}

#[pyfunction]
#[pyo3(text_signature = "(data, out_dir)")]
fn extract(data: &[u8], out_dir: &str) -> PyResult<PyExtractionResult> {
    let kind: ContainerKind = detect_container(data)
        .ok_or_else(|| DisrobeError::new_err("input is not a recognized container".to_owned()))?;
    let result: BinExtractionResult =
        extract_to(kind, data, Path::new(out_dir)).map_err(map("extract"))?;
    PyExtractionResult::from_serialize(&result)
}

#[pyfunction]
#[pyo3(signature = (data, *, source_label = "inline", max_depth = 8))]
#[pyo3(text_signature = "(data, *, source_label='inline', max_depth=8)")]
fn extract_recursive(data: &[u8], source_label: &str, max_depth: u32) -> PyResult<PyOverlayReport> {
    let config: CarveConfig = CarveConfig::new(max_depth);
    let report: CarveReport = carve_recursive(data, source_label, config, None);
    PyOverlayReport::from_serialize(&report)
}

#[pyfunction]
#[pyo3(text_signature = "(ruleset_source)")]
fn yara_parse(ruleset_source: &str) -> PyResult<PyYaraReport> {
    let ruleset: YaraRuleset = yara::parse_ruleset(ruleset_source).map_err(map("yara parse"))?;
    PyYaraReport::from_serialize(&ruleset)
}

#[pyfunction]
#[pyo3(signature = (data, *, name = None))]
#[pyo3(text_signature = "(data, *, name=None)")]
fn yara_generate(data: &[u8], name: Option<&str>) -> PyResult<PyYaraReport> {
    let mut opts: GenerateOptions = GenerateOptions::default();
    if let Some(n) = name {
        n.clone_into(&mut opts.name);
    }
    let rule: GeneratedRule = yara_gen::generate(data, &opts).map_err(map("yara generate"))?;
    PyYaraReport::from_serialize(&rule)
}

fn native_import_labels(data: &[u8]) -> Vec<String> {
    parse_native(data).map_or_else(
        |_| Vec::new(),
        |nf: NativeFile| {
            nf.imports
                .iter()
                .map(|i: &disrobe_binfmt::ImportInfo| format!("{}!{}", i.library, i.name))
                .collect()
        },
    )
}

fn load_module_for_disasm(data: &[u8]) -> PyResult<Module> {
    if let Ok(env) = Envelope::decode(data) {
        return disrobe_query::module_from_envelope(&env).map_err(map("disasm load module"));
    }
    let payload: disrobe_ir::payload::DisasmPayload =
        build_disasm_payload(data).map_err(map("disasm build payload"))?;
    Ok(Module::from_disasm(&payload))
}

#[derive(Debug, Serialize)]
struct DisasmView {
    kind: &'static str,
    function_count: usize,
    instruction_count: usize,
    functions: Vec<DisasmFunctionView>,
}

#[derive(Debug, Serialize)]
struct DisasmFunctionView {
    name: String,
    address: u64,
    end: u64,
    is_export: bool,
    instruction_count: usize,
    cyclomatic_complexity: u32,
}

fn disasm_view(module: &Module) -> DisasmView {
    let functions: Vec<DisasmFunctionView> = module
        .functions()
        .iter()
        .map(|f| DisasmFunctionView {
            name: f.name.clone(),
            address: f.address,
            end: f.end,
            is_export: f.is_export,
            instruction_count: f.instruction_count(),
            cyclomatic_complexity: f.cyclomatic_complexity(),
        })
        .collect();
    DisasmView {
        kind: "disasm",
        function_count: functions.len(),
        instruction_count: functions.iter().map(|f| f.instruction_count).sum(),
        functions,
    }
}

#[derive(Debug, Serialize)]
struct EntropyView {
    window: usize,
    block_count: usize,
    high_count: usize,
    max: f64,
    min: f64,
    mean: f64,
    windows: Vec<EntropyBlock>,
}

#[derive(Debug, Serialize)]
struct SbomView {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    components: Vec<SbomComponent>,
}

#[derive(Debug, Serialize)]
struct SbomComponent {
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct SignatureView {
    signatures: Vec<CryptoConstHit>,
    flirt_matches: Vec<FlirtMatchView>,
}

#[derive(Debug, Serialize)]
struct FlirtMatchView {
    name: String,
    offset: u64,
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(strings_extract, m)?)?;
    m.add_function(wrap_pyfunction!(ioc_extract, m)?)?;
    m.add_function(wrap_pyfunction!(behavior_analyze, m)?)?;
    m.add_function(wrap_pyfunction!(identify_binary, m)?)?;
    m.add_function(wrap_pyfunction!(secret_scan_fn, m)?)?;
    m.add_function(wrap_pyfunction!(capabilities, m)?)?;
    m.add_function(wrap_pyfunction!(native_symbols, m)?)?;
    m.add_function(wrap_pyfunction!(native_disasm, m)?)?;
    m.add_function(wrap_pyfunction!(native_callgraph, m)?)?;
    m.add_function(wrap_pyfunction!(native_imports_dot, m)?)?;
    m.add_function(wrap_pyfunction!(native_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(native_sbom, m)?)?;
    m.add_function(wrap_pyfunction!(native_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(native_signatures, m)?)?;
    m.add_function(wrap_pyfunction!(native_sigmaker, m)?)?;
    m.add_function(wrap_pyfunction!(native_diff, m)?)?;
    m.add_function(wrap_pyfunction!(native_patch, m)?)?;
    m.add_function(wrap_pyfunction!(extract, m)?)?;
    m.add_function(wrap_pyfunction!(extract_recursive, m)?)?;
    m.add_function(wrap_pyfunction!(yara_parse, m)?)?;
    m.add_function(wrap_pyfunction!(yara_generate, m)?)?;
    Ok(())
}
