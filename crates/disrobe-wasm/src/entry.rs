use disrobe_core::{
    AntiAnalysisReport, BehaviorReport, GeneratedRule, IocReport, SecretScanReport, StringsOptions,
    StringsReport, YaraGenerateOptions, analyze_behavior, generate_yara_rule, ioc_report,
    scan_anti_analysis, scan_report as secret_scan_report, strings_report,
};
use disrobe_pass_as3::abc::parse as parse_abc;
use disrobe_pass_as3::swf::{parse as parse_swf, parse_do_abc, parse_do_abc_legacy};
use disrobe_pass_as3::{
    AbcFile, DoAbc, ObfuscationReport as As3ObfuscationReport, Swf, TagCode,
    analyze as as3_analyze, render_program as as3_render_program,
};
use disrobe_pass_beam::{
    BeamFile, DebugInfo, ElixirRecovery, ErlangSurface, parse_dbgi, recover_elixir, recover_erlang,
};
use disrobe_pass_lua::{
    DecompiledChunk as LuaDecompiledChunk, DetectedFormat as LuaFormat,
    ObfuscatorDetection as LuaObfuscatorDetection, decompile_auto as lua_decompile_auto,
    detect as lua_detect_format,
};
use disrobe_pass_mobile::{
    DetectedKind as MobileKind, detect_kind as mobile_detect_kind, extract_android_bundle_children,
    extract_android_dex_children,
};
use disrobe_pass_php::{
    PhpDetection, RecoveryReport as PhpRecoveryReport, detect_php, recover_php,
};
use disrobe_pass_pickle::{
    Disassembly as PickleDisassembly, PickleValue, PolyglotReport, SafetyReport, Severity, VmTrace,
    analyze_polyglot, disassemble as pickle_dis, execute as pickle_execute, to_python,
    to_python_assignment,
};
use disrobe_pass_py_disasm::Instruction;
use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes as ruby_analyze_bytes};
use disrobe_pass_scriptlang::{
    ScriptArtifact, ScriptLang, analyze as scriptlang_analyze, classify as scriptlang_classify,
};
use disrobe_pass_shell::{
    BatchDeobReport, Detection as ShellDetection, deobfuscate_batch, detect as shell_detect,
};
use disrobe_pass_wasm_deob::{
    CalleeNames, ComponentBindings, ComponentManifest, EhModuleSummary, ExportAlias, FunctionCfg,
    FunctionSig, GcHirModule, GcTypeGraph, LiftResult, LiftTarget, MemoryReport, ModuleSignatures,
    ModuleSummary, RecoveredModule, RecoveryReport, SourceMap, WasmDetection, analyze_module,
    build_function_cfg, c_runtime_prelude, extract_signatures, lift_component_manifest,
    lift_function_body, lift_gc_module, lift_module_faithful_wat, lift_module_to_wat,
    parse_component_manifest, parse_source_map, recover_gc_types, recover_module,
    rust_runtime_prelude, scan_memories, scan_module_eh, typescript_runtime_prelude,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, pyversion_from_magic, read_pyc};
use serde::Serialize;
use wasmparser::{FunctionBody, Parser, Payload};

#[derive(Debug, Serialize)]
pub struct PyDisasmResult {
    ok: bool,
    format: &'static str,
    python_version: String,
    instruction_count: usize,
    instructions: Vec<Instruction>,
    listing: String,
}

#[derive(Debug, Serialize)]
pub struct PyDecompileResult {
    ok: bool,
    format: &'static str,
    python_version: String,
    recovered_directly: bool,
    fallback_reason: Option<String>,
    source: String,
}

#[derive(Debug, Serialize)]
pub struct PickleDisasmResult {
    ok: bool,
    format: &'static str,
    protocol: u8,
    opcode_count: usize,
    disassembly: PickleDisassembly,
    listing: String,
}

#[derive(Debug, Serialize)]
pub struct PickleSafetyResult {
    ok: bool,
    format: &'static str,
    protocol: u8,
    severity: Severity,
    finding_count: usize,
    report: SafetyReport,
}

#[derive(Debug, Serialize)]
pub struct PickleDecompileResult {
    ok: bool,
    format: &'static str,
    protocol: u8,
    reduce_count: usize,
    source: String,
    assignment: String,
}

#[derive(Debug, Serialize)]
pub struct PickleTraceResult {
    ok: bool,
    format: &'static str,
    protocol: u8,
    memo_count: usize,
    max_stack_depth: usize,
    reduce_count: usize,
    result: PickleValue,
    trace: VmTrace,
}

#[derive(Debug, Serialize)]
pub struct PicklePolyglotResult {
    ok: bool,
    format: &'static str,
    report: PolyglotReport,
}

#[derive(Debug, Serialize)]
pub struct WasmAnalyzeResult {
    ok: bool,
    format: &'static str,
    detection: WasmDetection,
    summary: ModuleSummary,
}

#[derive(Debug, Serialize)]
pub struct WasmDetectResult {
    ok: bool,
    format: &'static str,
    detection: WasmDetection,
}

#[derive(Debug, Serialize)]
pub struct LuaDetectResult {
    ok: bool,
    format: &'static str,
    dialect: &'static str,
    obfuscator: Option<LuaObfuscatorDetection>,
}

#[derive(Debug, Serialize)]
pub struct LuaDecompileResult {
    ok: bool,
    format: &'static str,
    dialect: &'static str,
    fidelity: String,
    warning_count: usize,
    chunk: LuaDecompiledChunk,
}

#[derive(Debug, Serialize)]
pub struct RubyDetectResult {
    ok: bool,
    format: &'static str,
    analysis: RubyAnalysis,
}

#[derive(Debug, Serialize)]
pub struct PhpDetectResult {
    ok: bool,
    format: &'static str,
    detection: PhpDetection,
    recovery: PhpRecoveryReport,
}

#[derive(Debug, Serialize)]
pub struct StringsResult {
    ok: bool,
    format: &'static str,
    report: StringsReport,
}

#[derive(Debug, Serialize)]
pub struct IocResult {
    ok: bool,
    format: &'static str,
    report: IocReport,
}

#[derive(Debug, Serialize)]
pub struct BehaviorResult {
    ok: bool,
    format: &'static str,
    report: BehaviorReport,
}

#[derive(Debug, Serialize)]
pub struct SecretsResult {
    ok: bool,
    format: &'static str,
    report: SecretScanReport,
}

#[derive(Debug, Serialize)]
pub struct AntiAnalysisResult {
    ok: bool,
    format: &'static str,
    report: AntiAnalysisReport,
}

#[derive(Debug, Serialize)]
pub struct YaraGenResult {
    ok: bool,
    format: &'static str,
    rule: GeneratedRule,
}

#[derive(Debug, Serialize)]
pub struct EntropyBlock {
    offset: usize,
    len: usize,
    entropy: f64,
    high: bool,
}

#[derive(Debug, Serialize)]
pub struct EntropyResult {
    ok: bool,
    format: &'static str,
    byte_len: usize,
    window: usize,
    overall: f64,
    block_count: usize,
    high_block_count: usize,
    truncated: bool,
    blocks: Vec<EntropyBlock>,
}

#[derive(Debug, Serialize)]
pub struct RouteCandidate {
    ecosystem: &'static str,
    mode: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
pub struct AutoRouteResult {
    ok: bool,
    format: &'static str,
    byte_len: usize,
    primary: Option<RouteCandidate>,
    candidates: Vec<RouteCandidate>,
}

#[derive(Debug, Serialize)]
pub struct DetectResult {
    ok: bool,
    format: &'static str,
    detail: String,
    suggested_command: String,
}

fn version_label(version: PyVersion) -> String {
    format!("{}.{}", version.major, version.minor)
}

fn read_code_object(bytes: &[u8]) -> Result<(CodeObject, PyVersion), String> {
    let pyc: PycFile = read_pyc(bytes).map_err(|e| format!("read pyc: {e}"))?;
    let version: PyVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, version)),
        other => Err(format!(
            "pyc top-level object is not a code object: {other:?}"
        )),
    }
}

pub fn py_disasm(bytes: &[u8]) -> Result<PyDisasmResult, String> {
    let (code, version): (CodeObject, PyVersion) = read_code_object(bytes)?;
    let instructions: Vec<Instruction> = disrobe_pass_py_disasm::disassemble(&code, version);
    let listing: String = disrobe_pass_py_disasm::render_dis(&instructions);
    Ok(PyDisasmResult {
        ok: true,
        format: "pyc",
        python_version: version_label(version),
        instruction_count: instructions.len(),
        instructions,
        listing,
    })
}

pub fn py_decompile(bytes: &[u8]) -> Result<PyDecompileResult, String> {
    let decompiled: disrobe_pass_py_decompile::NativeDecompile =
        disrobe_pass_py_decompile::decompile_pyc(bytes).map_err(|e| format!("decompile: {e}"))?;
    Ok(PyDecompileResult {
        ok: true,
        format: "pyc",
        python_version: format!(
            "{}.{}",
            decompiled.marshal_version.major, decompiled.marshal_version.minor
        ),
        recovered_directly: decompiled.recovered_directly,
        fallback_reason: decompiled.fallback_reason,
        source: decompiled.source,
    })
}

pub fn pickle_disasm(bytes: &[u8]) -> Result<PickleDisasmResult, String> {
    let disassembly: PickleDisassembly =
        pickle_dis(bytes).map_err(|e| format!("pickle disasm: {e}"))?;
    let listing: String = disrobe_pass_pickle::render_disasm(&disassembly);
    Ok(PickleDisasmResult {
        ok: true,
        format: "pickle",
        protocol: disassembly.protocol,
        opcode_count: disassembly.instructions.len(),
        disassembly,
        listing,
    })
}

pub fn pickle_safety(bytes: &[u8]) -> Result<PickleSafetyResult, String> {
    let (disassembly, _trace, report): (PickleDisassembly, VmTrace, SafetyReport) =
        disrobe_pass_pickle::analyze_all(bytes).map_err(|e| format!("pickle safety: {e}"))?;
    Ok(PickleSafetyResult {
        ok: true,
        format: "pickle",
        protocol: disassembly.protocol,
        severity: report.severity,
        finding_count: report.findings.len(),
        report,
    })
}

pub fn pickle_decompile(bytes: &[u8]) -> Result<PickleDecompileResult, String> {
    let disassembly: PickleDisassembly =
        pickle_dis(bytes).map_err(|e| format!("pickle disasm: {e}"))?;
    let trace: VmTrace = pickle_execute(&disassembly).map_err(|e| format!("pickle trace: {e}"))?;
    let source: String = to_python(&trace.result);
    let assignment: String = to_python_assignment(&trace.result);
    Ok(PickleDecompileResult {
        ok: true,
        format: "pickle",
        protocol: disassembly.protocol,
        reduce_count: trace.reduce_count,
        source,
        assignment,
    })
}

pub fn pickle_trace(bytes: &[u8]) -> Result<PickleTraceResult, String> {
    let disassembly: PickleDisassembly =
        pickle_dis(bytes).map_err(|e| format!("pickle disasm: {e}"))?;
    let trace: VmTrace = pickle_execute(&disassembly).map_err(|e| format!("pickle trace: {e}"))?;
    Ok(PickleTraceResult {
        ok: true,
        format: "pickle",
        protocol: trace.protocol,
        memo_count: trace.memo_count,
        max_stack_depth: trace.max_stack_depth,
        reduce_count: trace.reduce_count,
        result: trace.result.clone(),
        trace,
    })
}

pub fn pickle_polyglot(bytes: &[u8]) -> PicklePolyglotResult {
    let report: PolyglotReport = analyze_polyglot(bytes);
    PicklePolyglotResult {
        ok: true,
        format: "pickle",
        report,
    }
}

pub fn wasm_analyze(bytes: &[u8]) -> Result<WasmAnalyzeResult, String> {
    let detection: WasmDetection =
        disrobe_pass_wasm_deob::detect(bytes).map_err(|e| format!("wasm detect: {e}"))?;
    let summary: ModuleSummary =
        disrobe_pass_wasm_deob::analyze_module(bytes).map_err(|e| format!("wasm analyze: {e}"))?;
    Ok(WasmAnalyzeResult {
        ok: true,
        format: "wasm",
        detection,
        summary,
    })
}

pub fn wasm_detect(bytes: &[u8]) -> Result<WasmDetectResult, String> {
    let detection: WasmDetection =
        disrobe_pass_wasm_deob::detect(bytes).map_err(|e| format!("wasm detect: {e}"))?;
    Ok(WasmDetectResult {
        ok: true,
        format: "wasm",
        detection,
    })
}

#[derive(Debug, Serialize)]
pub struct WasmWatResult {
    ok: bool,
    format: &'static str,
    variant: &'static str,
    function_count: usize,
    wat: String,
}

fn collect_code_bodies(bytes: &[u8]) -> Result<Vec<FunctionBody<'_>>, String> {
    let mut bodies: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| format!("wasm parse: {e}"))?;
        if let Payload::CodeSectionEntry(body) = payload {
            bodies.push(body);
        }
    }
    Ok(bodies)
}

pub(crate) fn wasm_index(index: usize, label: &str) -> Result<u32, String> {
    u32::try_from(index).map_err(|_| format!("{label} index exceeds wasm u32 range"))
}

pub fn wasm_decompile_wat(bytes: &[u8]) -> Result<WasmWatResult, String> {
    let sigs: ModuleSignatures =
        extract_signatures(bytes).map_err(|e| format!("wasm signatures: {e}"))?;
    let defined: &[FunctionSig] = sigs.defined();
    let bodies: Vec<FunctionBody<'_>> = collect_code_bodies(bytes)?;
    let mut pairs: Vec<(FunctionBody<'_>, FunctionSig)> = Vec::with_capacity(bodies.len());
    for (idx, body) in bodies.into_iter().enumerate() {
        let sig: FunctionSig = if let Some(sig) = defined.get(idx) {
            sig.clone()
        } else {
            FunctionSig::placeholder(wasm_index(idx, "wasm function")?)
        };
        pairs.push((body, sig));
    }
    let offset: u32 = wasm_index(sigs.imported_function_count(), "imported function")?;
    let wat: String = lift_module_to_wat(&pairs, offset);
    Ok(WasmWatResult {
        ok: true,
        format: "wasm",
        variant: "structured",
        function_count: pairs.len(),
        wat,
    })
}

pub fn wasm_faithful_wat(bytes: &[u8]) -> Result<WasmWatResult, String> {
    let wat: String = lift_module_faithful_wat(bytes)
        .ok_or_else(|| "faithful WAT lift failed (not a parseable core module)".to_string())?;
    let function_count: usize = collect_code_bodies(bytes).map_or(0, |b| b.len());
    Ok(WasmWatResult {
        ok: true,
        format: "wasm",
        variant: "faithful",
        function_count,
        wat,
    })
}

#[derive(Debug, Serialize)]
pub struct WasmCfgFunction {
    function_index: u32,
    block_count: usize,
    edge_count: usize,
    entry: u32,
    cfg: FunctionCfg,
}

#[derive(Debug, Serialize)]
pub struct WasmCfgResult {
    ok: bool,
    format: &'static str,
    function_count: usize,
    functions: Vec<WasmCfgFunction>,
}

pub fn wasm_cfg(bytes: &[u8]) -> Result<WasmCfgResult, String> {
    let bodies: Vec<FunctionBody<'_>> = collect_code_bodies(bytes)?;
    let mut functions: Vec<WasmCfgFunction> = Vec::with_capacity(bodies.len());
    for (idx, body) in bodies.iter().enumerate() {
        let cfg: FunctionCfg =
            build_function_cfg(body).map_err(|e| format!("wasm cfg fn {idx}: {e}"))?;
        functions.push(WasmCfgFunction {
            function_index: wasm_index(idx, "wasm function")?,
            block_count: cfg.blocks.len(),
            edge_count: cfg.edges.len(),
            entry: cfg.entry.0,
            cfg,
        });
    }
    Ok(WasmCfgResult {
        ok: true,
        format: "wasm",
        function_count: functions.len(),
        functions,
    })
}

#[derive(Debug, Serialize)]
pub struct WasmGcTypesResult {
    ok: bool,
    format: &'static str,
    struct_count: usize,
    array_count: usize,
    abstract_ref_count: usize,
    graph: GcTypeGraph,
    hir: GcHirModule,
}

pub fn wasm_gc_types(bytes: &[u8]) -> Result<WasmGcTypesResult, String> {
    let graph: GcTypeGraph = recover_gc_types(bytes).map_err(|e| format!("wasm gc types: {e}"))?;
    let hir: GcHirModule = lift_gc_module(&graph);
    Ok(WasmGcTypesResult {
        ok: true,
        format: "wasm",
        struct_count: hir.structs.len(),
        array_count: hir.arrays.len(),
        abstract_ref_count: hir.abstract_refs.len(),
        graph,
        hir,
    })
}

#[derive(Debug, Serialize)]
pub struct WasmEhResult {
    ok: bool,
    format: &'static str,
    uses_exception_handling: bool,
    uses_legacy_eh: bool,
    uses_modern_eh: bool,
    tag_section_count: u32,
    function_count: usize,
    summary: EhModuleSummary,
}

pub fn wasm_eh(bytes: &[u8]) -> Result<WasmEhResult, String> {
    let summary: EhModuleSummary = scan_module_eh(bytes).map_err(|e| format!("wasm eh: {e}"))?;
    Ok(WasmEhResult {
        ok: true,
        format: "wasm",
        uses_exception_handling: summary.uses_exception_handling(),
        uses_legacy_eh: summary.uses_legacy_eh(),
        uses_modern_eh: summary.uses_modern_eh(),
        tag_section_count: summary.tag_section_count,
        function_count: summary.functions.len(),
        summary,
    })
}

#[derive(Debug, Serialize)]
pub struct WasmComponentResult {
    ok: bool,
    format: &'static str,
    classification: String,
    world_import_count: usize,
    world_export_count: usize,
    embedded_module_count: usize,
    embedded_component_count: usize,
    adapter_func_count: usize,
    manifest: ComponentManifest,
    bindings: ComponentBindings,
}

pub fn wasm_component(bytes: &[u8]) -> Result<WasmComponentResult, String> {
    let manifest: ComponentManifest =
        parse_component_manifest(bytes).map_err(|e| format!("wasm component: {e}"))?;
    let bindings: ComponentBindings = lift_component_manifest(&manifest, "root");
    Ok(WasmComponentResult {
        ok: true,
        format: "wasm",
        classification: format!("{:?}", manifest.classification),
        world_import_count: manifest.world_imports.len(),
        world_export_count: manifest.world_exports.len(),
        embedded_module_count: manifest.embedded_modules.len(),
        embedded_component_count: manifest.embedded_components.len(),
        adapter_func_count: manifest.adapter_funcs.len(),
        manifest,
        bindings,
    })
}

#[derive(Debug, Serialize)]
pub struct WasmMemoriesResult {
    ok: bool,
    format: &'static str,
    memory_count: usize,
    report: MemoryReport,
}

pub fn wasm_memories(bytes: &[u8]) -> Result<WasmMemoriesResult, String> {
    let report: MemoryReport = scan_memories(bytes).map_err(|e| format!("wasm memories: {e}"))?;
    Ok(WasmMemoriesResult {
        ok: true,
        format: "wasm",
        memory_count: report.memory_count(),
        report,
    })
}

#[derive(Debug, Serialize)]
pub struct WasmSignaturesResult {
    ok: bool,
    format: &'static str,
    imported_function_count: usize,
    defined_function_count: usize,
    defined: Vec<FunctionSig>,
    export_aliases: Vec<ExportAlias>,
    summary: ModuleSummary,
    recovery: RecoveryReport,
    recovered_byte_len: usize,
}

pub fn wasm_signatures(bytes: &[u8]) -> Result<WasmSignaturesResult, String> {
    let sigs: ModuleSignatures =
        extract_signatures(bytes).map_err(|e| format!("wasm signatures: {e}"))?;
    let summary: ModuleSummary = analyze_module(bytes).map_err(|e| format!("wasm analyze: {e}"))?;
    let recovered: RecoveredModule =
        recover_module(bytes).map_err(|e| format!("wasm recover: {e}"))?;
    Ok(WasmSignaturesResult {
        ok: true,
        format: "wasm",
        imported_function_count: sigs.imported_function_count(),
        defined_function_count: sigs.defined().len(),
        defined: sigs.defined().to_vec(),
        export_aliases: sigs.export_aliases().to_vec(),
        summary,
        recovery: recovered.report,
        recovered_byte_len: recovered.bytes.len(),
    })
}

#[derive(Debug, Serialize)]
pub struct WasmHighLevelResult {
    ok: bool,
    format: &'static str,
    target: &'static str,
    function_count: usize,
    source: String,
}

fn assemble_high_level(
    bytes: &[u8],
    target: LiftTarget,
    target_label: &'static str,
) -> Result<WasmHighLevelResult, String> {
    let sigs: ModuleSignatures =
        extract_signatures(bytes).map_err(|e| format!("wasm signatures: {e}"))?;
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    );
    let mut source: String = match target {
        LiftTarget::Rust => rust_runtime_prelude().to_owned(),
        LiftTarget::TypeScript => typescript_runtime_prelude().to_owned(),
        LiftTarget::C => c_runtime_prelude().to_owned(),
        LiftTarget::Wat => String::new(),
    };
    let bodies: Vec<FunctionBody<'_>> = collect_code_bodies(bytes)?;
    for (idx, body) in bodies.iter().enumerate() {
        let sig: FunctionSig = if let Some(sig) = defined.get(idx) {
            sig.clone()
        } else {
            FunctionSig::placeholder(wasm_index(idx, "wasm function")?)
        };
        let result: LiftResult = lift_function_body(body, &sig, &callees, target);
        source.push('\n');
        source.push_str(&result.pseudo_source);
        if !result.pseudo_source.ends_with('\n') {
            source.push('\n');
        }
    }
    Ok(WasmHighLevelResult {
        ok: true,
        format: "wasm",
        target: target_label,
        function_count: bodies.len(),
        source,
    })
}

pub fn wasm_lift_rust(bytes: &[u8]) -> Result<WasmHighLevelResult, String> {
    assemble_high_level(bytes, LiftTarget::Rust, "rust")
}

pub fn wasm_lift_ts(bytes: &[u8]) -> Result<WasmHighLevelResult, String> {
    assemble_high_level(bytes, LiftTarget::TypeScript, "typescript")
}

pub fn wasm_lift_c(bytes: &[u8]) -> Result<WasmHighLevelResult, String> {
    assemble_high_level(bytes, LiftTarget::C, "c")
}

#[derive(Debug, Serialize)]
pub struct WasmPreludesResult {
    ok: bool,
    format: &'static str,
    rust: &'static str,
    c: &'static str,
    typescript: &'static str,
}

pub const fn wasm_preludes(_bytes: &[u8]) -> WasmPreludesResult {
    WasmPreludesResult {
        ok: true,
        format: "wasm",
        rust: rust_runtime_prelude(),
        c: c_runtime_prelude(),
        typescript: typescript_runtime_prelude(),
    }
}

#[derive(Debug, Serialize)]
pub struct WasmSourceMapResult {
    ok: bool,
    format: &'static str,
    version: u32,
    source_count: usize,
    name_count: usize,
    segment_count: usize,
    source_map: SourceMap,
}

pub fn wasm_source_map(bytes: &[u8]) -> Result<WasmSourceMapResult, String> {
    let source_map: SourceMap =
        parse_source_map(bytes).map_err(|e| format!("wasm source map: {e}"))?;
    Ok(WasmSourceMapResult {
        ok: true,
        format: "wasm",
        version: u32::from(source_map.version),
        source_count: source_map.sources.len(),
        name_count: source_map.names.len(),
        segment_count: source_map.segments.len(),
        source_map,
    })
}

const fn lua_dialect_label(format: LuaFormat) -> &'static str {
    match format {
        LuaFormat::Lua51 => "lua 5.1",
        LuaFormat::Lua52 => "lua 5.2",
        LuaFormat::Lua53 => "lua 5.3",
        LuaFormat::Lua54 => "lua 5.4",
        LuaFormat::LuaJit => "luajit",
        LuaFormat::Luau => "luau",
        LuaFormat::GLua => "glua",
        LuaFormat::Unknown => "unknown",
    }
}

type LuaObfuscatorProbe = fn(&[u8]) -> Option<LuaObfuscatorDetection>;

fn lua_obfuscator_scan(bytes: &[u8]) -> Option<LuaObfuscatorDetection> {
    let probes: [LuaObfuscatorProbe; 12] = [
        disrobe_pass_lua::prometheus::detect,
        disrobe_pass_lua::moonsec_v1::detect,
        disrobe_pass_lua::moonsec_v2::detect,
        disrobe_pass_lua::moonsec_v3::detect,
        disrobe_pass_lua::ironbrew2::detect,
        disrobe_pass_lua::aztup_brew::detect,
        disrobe_pass_lua::darksec::detect,
        disrobe_pass_lua::boronide::detect,
        disrobe_pass_lua::psu::detect,
        disrobe_pass_lua::wearedevs::detect,
        disrobe_pass_lua::luaobfuscator_com::detect,
        disrobe_pass_lua::slua::detect,
    ];
    let mut best: Option<LuaObfuscatorDetection> = None;
    for probe in probes {
        if let Some(found) = probe(bytes)
            && best
                .as_ref()
                .is_none_or(|b| found.confidence > b.confidence)
        {
            best = Some(found);
        }
    }
    best
}

pub fn lua_detect(bytes: &[u8]) -> LuaDetectResult {
    let format: LuaFormat = lua_detect_format(bytes);
    LuaDetectResult {
        ok: true,
        format: "lua",
        dialect: lua_dialect_label(format),
        obfuscator: lua_obfuscator_scan(bytes),
    }
}

pub fn lua_decompile(bytes: &[u8]) -> Result<LuaDecompileResult, String> {
    let format: LuaFormat = lua_detect_format(bytes);
    let chunk: LuaDecompiledChunk =
        lua_decompile_auto(bytes).map_err(|e| format!("lua decompile: {e}"))?;
    let fidelity: String = format!("{:?}", chunk.fidelity);
    Ok(LuaDecompileResult {
        ok: true,
        format: "lua",
        dialect: lua_dialect_label(format),
        fidelity,
        warning_count: chunk.warnings.len(),
        chunk,
    })
}

pub fn ruby_detect(bytes: &[u8]) -> Result<RubyDetectResult, String> {
    let analysis: RubyAnalysis =
        ruby_analyze_bytes(bytes, "input.rb").map_err(|e| format!("ruby analyze: {e}"))?;
    Ok(RubyDetectResult {
        ok: true,
        format: "ruby",
        analysis,
    })
}

pub fn php_detect(bytes: &[u8]) -> Result<PhpDetectResult, String> {
    let detection: PhpDetection = detect_php(bytes);
    let recovery: PhpRecoveryReport =
        recover_php(bytes, None).map_err(|e| format!("php recover: {e}"))?;
    Ok(PhpDetectResult {
        ok: true,
        format: "php",
        detection,
        recovery,
    })
}

pub fn strings(bytes: &[u8]) -> StringsResult {
    let report: StringsReport = strings_report(bytes, None, StringsOptions::default());
    StringsResult {
        ok: true,
        format: "any",
        report,
    }
}

pub fn ioc(bytes: &[u8]) -> IocResult {
    let report: IocReport = ioc_report(bytes, None);
    IocResult {
        ok: true,
        format: "any",
        report,
    }
}

pub fn behavior(bytes: &[u8]) -> BehaviorResult {
    let report: BehaviorReport = analyze_behavior(bytes, &[]);
    BehaviorResult {
        ok: true,
        format: "any",
        report,
    }
}

pub fn secrets(bytes: &[u8]) -> SecretsResult {
    let report: SecretScanReport = secret_scan_report(bytes, None);
    SecretsResult {
        ok: true,
        format: "any",
        report,
    }
}

pub fn anti_analysis(bytes: &[u8]) -> AntiAnalysisResult {
    let report: AntiAnalysisReport = scan_anti_analysis(bytes, None);
    AntiAnalysisResult {
        ok: true,
        format: "any",
        report,
    }
}

pub fn yara_gen(bytes: &[u8]) -> Result<YaraGenResult, String> {
    let rule: GeneratedRule = generate_yara_rule(bytes, &YaraGenerateOptions::default())
        .map_err(|e| format!("yara gen: {e}"))?;
    Ok(YaraGenResult {
        ok: true,
        format: "any",
        rule,
    })
}

pub(crate) const ENTROPY_WINDOW: usize = 256;
pub(crate) const MAX_ENTROPY_BLOCKS: usize = 4096;
const ENTROPY_HIGH_THRESHOLD: f64 = 7.0;

fn shannon_bits(window: &[u8]) -> f64 {
    if window.is_empty() {
        return 0.0;
    }
    let mut counts: [u32; 256] = [0u32; 256];
    for &b in window {
        counts[b as usize] += 1;
    }
    let len: f64 = window.len() as f64;
    let mut entropy: f64 = 0.0;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p: f64 = f64::from(count) / len;
        entropy = p.mul_add(-p.log2(), entropy);
    }
    entropy
}

pub fn entropy(bytes: &[u8]) -> EntropyResult {
    let overall: f64 = shannon_bits(bytes);
    let mut blocks: Vec<EntropyBlock> = Vec::new();
    let mut offset: usize = 0;
    while offset < bytes.len() && blocks.len() < MAX_ENTROPY_BLOCKS {
        let Some(end): Option<usize> = offset
            .checked_add(ENTROPY_WINDOW)
            .map(|end: usize| end.min(bytes.len()))
        else {
            break;
        };
        let window: &[u8] = &bytes[offset..end];
        let value: f64 = shannon_bits(window);
        blocks.push(EntropyBlock {
            offset,
            len: window.len(),
            entropy: value,
            high: value >= ENTROPY_HIGH_THRESHOLD,
        });
        offset = end;
    }
    let truncated: bool = offset < bytes.len();
    let high_block_count: usize = blocks.iter().filter(|b| b.high).count();
    EntropyResult {
        ok: true,
        format: "any",
        byte_len: bytes.len(),
        window: ENTROPY_WINDOW,
        overall,
        block_count: blocks.len(),
        high_block_count,
        truncated,
        blocks,
    }
}

#[derive(Debug, Serialize)]
pub struct BeamResult {
    ok: bool,
    format: &'static str,
    module: String,
    recovered_from: String,
    erlang_source: String,
    elixir: Option<ElixirRecovery>,
}

pub fn beam_recover(bytes: &[u8]) -> Result<BeamResult, String> {
    let beam: BeamFile = BeamFile::parse(bytes).map_err(|e| format!("beam parse: {e}"))?;
    let surface: ErlangSurface = recover_erlang(&beam).map_err(|e| format!("beam recover: {e}"))?;
    let elixir: Option<ElixirRecovery> = match (&beam.chunks.dbgi, beam.module_name()) {
        (Some(chunk), Some(module)) => match parse_dbgi(&chunk.term) {
            Ok(info @ DebugInfo::ElixirV1 { .. }) => recover_elixir(module, &info).ok(),
            _ => None,
        },
        _ => None,
    };
    Ok(BeamResult {
        ok: true,
        format: "beam",
        module: surface.module,
        recovered_from: format!("{:?}", surface.recovered_from),
        erlang_source: surface.source,
        elixir,
    })
}

#[derive(Debug, Serialize)]
pub struct As3Result {
    ok: bool,
    format: &'static str,
    method_body_count: usize,
    class_count: usize,
    obfuscation: As3ObfuscationReport,
    program: String,
}

fn as3_extract_abc(bytes: &[u8]) -> Result<AbcFile, String> {
    if let Ok(abc) = parse_abc(bytes) {
        return Ok(abc);
    }
    let swf: Swf = parse_swf(bytes).map_err(|e| format!("swf parse: {e}"))?;
    let mut do_abc: Option<DoAbc> = None;
    for tag in &swf.tags {
        if tag.code == TagCode::DO_ABC {
            do_abc = Some(parse_do_abc(tag).map_err(|e| format!("DoABC tag parse: {e}"))?);
            break;
        }
        if tag.code == TagCode::DO_ABC_DEFINE {
            do_abc =
                Some(parse_do_abc_legacy(tag).map_err(|e| format!("DoABCDefine tag parse: {e}"))?);
            break;
        }
    }
    let do_abc: DoAbc = do_abc.ok_or_else(|| "no DoABC tag in SWF container".to_string())?;
    parse_abc(&do_abc.abc_bytes).map_err(|e| format!("abc parse: {e}"))
}

pub fn as3_analyze_entry(bytes: &[u8]) -> Result<As3Result, String> {
    let abc: AbcFile = as3_extract_abc(bytes)?;
    let obfuscation: As3ObfuscationReport = as3_analyze(&abc);
    let program: String = as3_render_program(&abc).map_err(|e| format!("as3 decompile: {e}"))?;
    Ok(As3Result {
        ok: true,
        format: "as3",
        method_body_count: abc.method_bodies.len(),
        class_count: abc.instances.len(),
        obfuscation,
        program,
    })
}

#[derive(Debug, Serialize)]
pub struct ScriptLangResult {
    ok: bool,
    format: &'static str,
    classified: Option<&'static str>,
    artifact: ScriptArtifact,
}

pub fn scriptlang_analyze_entry(bytes: &[u8]) -> Result<ScriptLangResult, String> {
    let classified: Option<&'static str> =
        scriptlang_classify(bytes).map(|lang: ScriptLang| lang.tag());
    let artifact: ScriptArtifact =
        scriptlang_analyze(bytes).map_err(|e| format!("scriptlang analyze: {e}"))?;
    Ok(ScriptLangResult {
        ok: true,
        format: "scriptlang",
        classified,
        artifact,
    })
}

#[derive(Debug, Serialize)]
pub struct ShellResult {
    ok: bool,
    format: &'static str,
    detection: ShellDetection,
    batch: BatchDeobReport,
}

pub fn shell_deob(bytes: &[u8]) -> Result<ShellResult, String> {
    let detection: ShellDetection = shell_detect(bytes);
    let text: &str =
        core::str::from_utf8(bytes).map_err(|_| "shell input is not utf-8 text".to_string())?;
    let batch: BatchDeobReport = deobfuscate_batch(text, &[]);
    Ok(ShellResult {
        ok: true,
        format: "shell",
        detection,
        batch,
    })
}

#[derive(Debug, Serialize)]
pub struct MobileChild {
    name: String,
    byte_len: usize,
}

#[derive(Debug, Serialize)]
pub struct MobileResult {
    ok: bool,
    format: &'static str,
    kind: String,
    child_count: usize,
    children: Vec<MobileChild>,
}

pub fn mobile_detect(bytes: &[u8]) -> Result<MobileResult, String> {
    let kind: MobileKind = mobile_detect_kind(bytes);
    let children: Vec<MobileChild> = mobile_children(kind, bytes)?;
    Ok(MobileResult {
        ok: true,
        format: "mobile",
        kind: format!("{kind:?}"),
        child_count: children.len(),
        children,
    })
}

fn mobile_children(kind: MobileKind, bytes: &[u8]) -> Result<Vec<MobileChild>, String> {
    let entries: Vec<(String, Vec<u8>)> = match kind {
        MobileKind::AndroidDexApk => extract_android_dex_children(bytes)
            .map_err(|e: disrobe_pass_mobile::Error| format!("android dex extract: {e}"))?,
        MobileKind::AndroidBundle => extract_android_bundle_children(bytes)
            .map_err(|e: disrobe_pass_mobile::Error| format!("android bundle extract: {e}"))?,
        _ => Vec::new(),
    };
    Ok(entries
        .into_iter()
        .map(|(name, data): (String, Vec<u8>)| MobileChild {
            name,
            byte_len: data.len(),
        })
        .collect())
}

const WASM_MAGIC: [u8; 4] = *b"\0asm";

fn push_candidate(
    out: &mut Vec<RouteCandidate>,
    ecosystem: &'static str,
    mode: &'static str,
    detail: String,
) {
    out.push(RouteCandidate {
        ecosystem,
        mode,
        detail,
    });
}

pub fn auto_route(bytes: &[u8]) -> AutoRouteResult {
    let mut candidates: Vec<RouteCandidate> = Vec::new();

    if bytes.len() >= 4 && bytes[..4] == WASM_MAGIC {
        push_candidate(
            &mut candidates,
            "wasm",
            "wasm_analyze",
            "WebAssembly binary (\\0asm magic)".to_string(),
        );
    }
    if bytes.len() >= 4 && &bytes[..4] == b"FOR1" {
        push_candidate(
            &mut candidates,
            "beam",
            "beam_recover",
            "Erlang/Elixir BEAM module (FOR1 IFF magic)".to_string(),
        );
    }
    if bytes.len() >= 3 && matches!(&bytes[..3], b"FWS" | b"CWS" | b"ZWS") {
        push_candidate(
            &mut candidates,
            "as3",
            "as3_analyze",
            "Flash SWF container (DoABC ActionScript 3)".to_string(),
        );
    }
    if bytes.len() >= 4 && bytes[..4] == [0x10, 0x00, 0x2e, 0x00] {
        push_candidate(
            &mut candidates,
            "as3",
            "as3_analyze",
            "raw ABC bytecode (ActionScript 3, v46.16)".to_string(),
        );
    }
    if bytes.len() >= 4 {
        let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if let Some(version) = pyversion_from_magic(magic) {
            push_candidate(
                &mut candidates,
                "python",
                "py_decompile",
                format!(
                    "CPython {}.{} bytecode (.pyc)",
                    version.major, version.minor
                ),
            );
        }
    }
    if disrobe_pass_pickle::looks_like_pickle(bytes) {
        push_candidate(
            &mut candidates,
            "pickle",
            "pickle_safety",
            "Python pickle opcode stream".to_string(),
        );
    }
    let lua_format: LuaFormat = lua_detect_format(bytes);
    if lua_format != LuaFormat::Unknown {
        push_candidate(
            &mut candidates,
            "lua",
            "lua_decompile",
            format!("Lua bytecode ({})", lua_dialect_label(lua_format)),
        );
    }
    if let Ok(text) = core::str::from_utf8(bytes) {
        if text.contains("pyarmor") || text.contains("__pyarmor__") {
            push_candidate(
                &mut candidates,
                "python",
                "pyarmor_classify",
                "PyArmor wrapper markers in source".to_string(),
            );
        }
        if text.contains("<?php") || text.contains("__HALT_COMPILER") {
            push_candidate(
                &mut candidates,
                "php",
                "php_detect",
                "PHP source or phar markers".to_string(),
            );
        }
    }
    let php: PhpDetection = detect_php(bytes);
    if php.kind != disrobe_pass_php::PhpKind::Unknown
        && !candidates.iter().any(|c| c.ecosystem == "php")
    {
        push_candidate(
            &mut candidates,
            "php",
            "php_detect",
            format!("PHP container ({:?})", php.kind),
        );
    }
    if let Ok(analysis) = ruby_analyze_bytes(bytes, "input.rb") {
        push_candidate(
            &mut candidates,
            "ruby",
            "ruby_detect",
            format!("Ruby artifact ({:?})", analysis.flavor),
        );
    }
    if let Some(lang) = scriptlang_classify(bytes) {
        push_candidate(
            &mut candidates,
            "scriptlang",
            "scriptlang_analyze",
            format!("scripted-language artifact ({})", lang.tag()),
        );
    }
    let shell_detection: ShellDetection = shell_detect(bytes);
    if shell_detection.family != disrobe_pass_shell::Family::Plain
        || shell_detection.dialect != disrobe_pass_shell::Dialect::Unknown
    {
        push_candidate(
            &mut candidates,
            "shell",
            "shell_deob",
            format!(
                "shell/script artifact ({:?}, {:?})",
                shell_detection.dialect, shell_detection.family
            ),
        );
    }
    let mobile_kind: MobileKind = mobile_detect_kind(bytes);
    if mobile_kind != MobileKind::Unknown {
        push_candidate(
            &mut candidates,
            "mobile",
            "mobile_detect",
            format!("mobile bundle ({mobile_kind:?})"),
        );
    }
    if bytes.len() >= 4 {
        let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if matches!(
            magic,
            0xfeed_face | 0xfeed_facf | 0xcafe_babe | 0xcefa_edfe | 0xcffa_edfe | 0xbeba_feca
        ) {
            push_candidate(
                &mut candidates,
                "swift-objc",
                "swift_objc",
                "Mach-O binary (iOS/macOS Swift + Objective-C)".to_string(),
            );
        }
    }

    let primary: Option<RouteCandidate> =
        candidates.first().map(|c: &RouteCandidate| RouteCandidate {
            ecosystem: c.ecosystem,
            mode: c.mode,
            detail: c.detail.clone(),
        });

    AutoRouteResult {
        ok: true,
        format: "any",
        byte_len: bytes.len(),
        primary,
        candidates,
    }
}

pub fn detect(bytes: &[u8]) -> DetectResult {
    if bytes.len() >= 4 && bytes[..4] == WASM_MAGIC {
        return DetectResult {
            ok: true,
            format: "wasm",
            detail: "WebAssembly binary (\\0asm magic)".to_string(),
            suggested_command: "disrobe wasm <file.wasm>".to_string(),
        };
    }
    if bytes.len() >= 4 {
        let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if let Some(version) = pyversion_from_magic(magic) {
            let version: PyVersion = version;
            return DetectResult {
                ok: true,
                format: "pyc",
                detail: format!(
                    "CPython {}.{} compiled module (.pyc)",
                    version.major, version.minor
                ),
                suggested_command: "disrobe py decompile <file.pyc>".to_string(),
            };
        }
    }
    if disrobe_pass_pickle::looks_like_pickle(bytes) {
        return DetectResult {
            ok: true,
            format: "pickle",
            detail: "Python pickle opcode stream".to_string(),
            suggested_command: "disrobe pickle <file.pkl>".to_string(),
        };
    }
    DetectResult {
        ok: true,
        format: "unknown",
        detail: "no known signature matched the leading bytes".to_string(),
        suggested_command: "disrobe detect <file>".to_string(),
    }
}
