#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use std::io::Write;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_INTERPRETER_BYTECODE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;
use serde::Serialize;

use crate::aot::{
    AotMetadataAttribution, AotMetadataStatus, AotReport, AotType, detect as detect_aot,
};
use crate::decompile::{DecompiledAssembly, decompile_assembly};
use crate::pass::{PassSummary, analyze};
use crate::pe::{DataDirectory, PeImage, parse as parse_pe};
use crate::peel::confuserex_constants::{ConfuserConstantsRecovery, peel_confuserex_constants};
use crate::peel::static_decrypt::{DecodedValue, RecoveredConstant};
use crate::peel::string_emu::RecoveredString as EmulatedString;
use crate::peel::{PeelReport, PeelStrategy, RecoveredMethod, RecoveredResource, peel_by};
use crate::protectors::{DetectionReport, Handling, Protector, detect_all};
use crate::structurize::StructuredMethod;

pub const PASS_ID: PassId = "dotnet.classify";

const TAG_PE_CLR: &str = "dotnet-pe-clr";
const TAG_NATIVE_AOT: &str = "dotnet-native-aot";
const NATIVE_AOT_SYMBOLS_SCHEMA: &str = "disrobe.dotnet.native-aot-symbols/v1";
const MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_NATIVE_AOT_QUALIFIED_NAME_BYTES: usize = MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES;
const MAX_NATIVE_AOT_SYMBOL_WORK_ITEMS: usize = 1_048_576;
const MAX_NATIVE_AOT_TYPE_NESTING_DEPTH: usize = 256;

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[derive(Debug)]
pub struct DotnetDetector;

impl Detector for DotnetDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 64 || &bytes[..2] != b"MZ" {
            return None;
        }
        let pe: PeImage = parse_pe(bytes).ok()?;
        if let Some(dir) = pe.clr_directory()
            && dir.rva != 0
            && dir.size != 0
        {
            return Some(verdict_clr(dir));
        }
        let report: AotReport = detect_aot(bytes);
        report.ready_to_run.as_ref().map(verdict_native_aot)
    }
}

#[derive(Debug)]
pub struct DotnetPass;

impl Pass for DotnetPass {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &DotnetDetector
    }

    #[inline]
    fn output_kind(&self, output: &Artifact) -> OutputKind {
        let is_native_aot_symbols: bool = output.envelope.len()
            <= MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES
            && serde_json::from_slice::<serde_json::Value>(output.envelope.as_slice())
                .ok()
                .is_some_and(|document: serde_json::Value| {
                    document.get("schema").and_then(serde_json::Value::as_str)
                        == Some(NATIVE_AOT_SYMBOLS_SCHEMA)
                });
        if is_native_aot_symbols {
            return OutputKind::Mixed {
                children: Vec::new(),
            };
        }
        OutputKind::Source {
            language: Language::CSharp,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let pe: PeImage = parse_pe(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-DOTNET-0902: PE parse: {e}"))
        })?;
        let clr: Option<DataDirectory> = pe.clr_directory();
        if clr.is_none_or(|directory: DataDirectory| directory.rva == 0 || directory.size == 0) {
            let report: AotReport = detect_aot(bytes);
            if report.ready_to_run.is_none() {
                return Err(CoreError::PassFailure(
                    "DR-DOTNET-0903: dotnet.classify: PE has no CLR data directory or NativeAOT header"
                        .to_string(),
                ));
            }
            let output: Vec<u8> = native_aot_symbols_bytes(&report)?;
            return Ok(Artifact::new(Rung::Surface, output, artifact.root_hash));
        }
        let assembly: DecompiledAssembly =
            decompile_assembly(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-DOTNET-0905: dotnet decompile: {e}"))
            })?;
        let recovered_constants: Vec<String> = peel_confuserex_constants(bytes)
            .ok()
            .flatten()
            .map(|r: ConfuserConstantsRecovery| {
                r.strings_recovered
                    .into_iter()
                    .map(|s: crate::peel::confuserex_constants::RecoveredString| s.text)
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();
        if assembly.methods.is_empty() && recovered_constants.is_empty() {
            return Err(CoreError::PassFailure(format!(
                "DR-DOTNET-0906: dotnet.classify: module {module} carries no recoverable method \
                 bodies (bodyless={bodyless}, failed={failed}) and no decryptable constants; body \
                 code is native-AOT/R2R or stripped, not statically present",
                module = assembly.module_name,
                bodyless = assembly.methods_bodyless,
                failed = assembly.methods_failed,
            )));
        }
        let source: String = render_csharp_source(&assembly, &recovered_constants);
        Ok(Artifact::new(
            Rung::Surface,
            source.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        if parse_pe(bytes).ok().is_some_and(|pe: PeImage| {
            pe.clr_directory()
                .is_none_or(|directory: DataDirectory| directory.rva == 0 || directory.size == 0)
        }) {
            let report: AotReport = detect_aot(bytes);
            if report.ready_to_run.is_some() {
                let output: Vec<u8> = native_aot_symbols_bytes(&report)?;
                let mut children: Vec<ChildArtifact> = Vec::with_capacity(1);
                push_terminal_child(
                    &mut children,
                    format!(
                        "nativeaot-{}-symbols.json",
                        aot_runtime_label(report.runtime_label)
                    ),
                    output,
                );
                return Ok(children);
            }
        }
        let raw_stem: String = decompile_assembly(bytes).ok().map_or_else(
            || "dotnet".to_string(),
            |a: DecompiledAssembly| a.module_name,
        );
        let stem: String = disrobe_binfmt::quota::sanitize_entry_path(&raw_stem)
            .ok()
            .filter(|name: &String| name.len() <= 128)
            .unwrap_or_else(|| "dotnet".to_string());
        let mut children: Vec<ChildArtifact> = Vec::new();

        let summary: Option<PassSummary> = analyze(bytes).ok();
        if let Some(summary) = summary.as_ref()
            && let Ok(json) = serde_json::to_vec_pretty(&analyze_manifest(summary))
        {
            push_terminal_child(&mut children, format!("{stem}.analyze.json"), json);
        }

        let protector: Option<Protector> = summary
            .as_ref()
            .and_then(|summary: &PassSummary| summary.primary_protector)
            .or_else(|| detect_all(bytes).primary);
        if let Some(protector) = protector
            && let Some(Ok(report)) = peel_by(protector, bytes)
        {
            if let Ok(json) = serde_json::to_vec_pretty(&peel_manifest(protector, &report)) {
                push_terminal_child(&mut children, format!("{stem}.peel.json"), json);
            }
            let strings: String = render_recovered_strings(
                &report.recovered_constants,
                &report.recovered_strings,
                bytes,
            );
            if !strings.is_empty() {
                push_terminal_child(
                    &mut children,
                    format!("{stem}.recovered-strings.txt"),
                    strings.into_bytes(),
                );
            }
            if !report.recovered_methods.is_empty() {
                let cil: String = render_recovered_cil(&report.recovered_methods);
                push_terminal_child(
                    &mut children,
                    format!("{stem}.recovered-cil.txt"),
                    cil.into_bytes(),
                );
            }
            for (index, resource) in report.recovered_resources.into_iter().enumerate() {
                let safe_name: String = disrobe_binfmt::quota::sanitize_entry_path(&resource.name)
                    .ok()
                    .filter(|name: &String| name.len() <= 128)
                    .unwrap_or_else(|| format!("resource-{index:05}.bin"));
                push_terminal_child(
                    &mut children,
                    format!("{stem}.recovered-resources/{index:05}-{safe_name}"),
                    resource.bytes,
                );
            }
        }

        Ok(children)
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Dotnet,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static DOTNET_PASS: DotnetPass = DotnetPass;

fn push_terminal_child(children: &mut Vec<ChildArtifact>, relative_path: String, bytes: Vec<u8>) {
    let index: u32 = u32::try_from(children.len()).unwrap_or(u32::MAX);
    children.push(ChildArtifact {
        handle: ChildHandle {
            artifact_index: index,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    });
}

fn analyze_manifest(summary: &PassSummary) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.dotnet.analyze/v1",
        "pe_bitness": summary.pe_bitness,
        "machine": summary.machine,
        "clr_runtime_version": summary.clr_runtime_version,
        "runtime_label": format!("{:?}", summary.runtime_label),
        "r2r_present": summary.r2r_present,
        "native_aot": summary.native_aot,
        "primary_protector": summary.primary_protector.as_ref().map(|p: &Protector| format!("{p:?}")),
        "protectors_detected": summary
            .protectors_detected
            .iter()
            .map(|p: &Protector| format!("{p:?}"))
            .collect::<Vec<String>>(),
        "stream_names": summary.stream_names,
        "opcode_table_size": summary.opcode_table_size,
        "opcode_spec_coverage_pct": summary.opcode_spec_coverage_pct,
        "recovered_constants": summary.recovered_constants,
        "koivm": summary.koivm,
        "eazvm": summary.eazvm,
        "control_flow_flattening": summary.control_flow_flattening,
        "inlined_literals": summary.inlined_literals,
    })
}

fn peel_manifest(protector: Protector, report: &PeelReport) -> serde_json::Value {
    let walled: bool = report.strategy == PeelStrategy::DetectOnlyNativeOrVm;
    let recovered_resources: Vec<serde_json::Value> = report
        .recovered_resources
        .iter()
        .map(|resource: &RecoveredResource| {
            serde_json::json!({
                "name": resource.name,
                "size": resource.bytes.len(),
            })
        })
        .collect();
    serde_json::json!({
        "schema": "disrobe.dotnet.peel/v0",
        "detected": protector.label(),
        "protector": protector,
        "strategy": report.strategy,
        "walled": walled,
        "attributes_stripped": report.attributes_stripped,
        "strings_total": report.strings_total,
        "strings_obfuscated_count": report.strings_obfuscated_count,
        "us_strings_total": report.us_strings_total,
        "renamable_identifiers": report.renamable_identifiers,
        "unobfuscatable_identifiers": report.unobfuscatable_identifiers,
        "recovered_decoders": report.recovered_decoders,
        "recovered_constants": report.recovered_constants,
        "recovered_strings": report.recovered_strings,
        "recovered_methods": report.recovered_methods,
        "recovered_resources": recovered_resources,
        "bytes_in": report.bytes_in,
        "bytes_out": report.bytes_out,
        "notes": report.notes,
    })
}

fn render_recovered_strings(
    constants: &[RecoveredConstant],
    emulated: &[EmulatedString],
    bytes: &[u8],
) -> String {
    let mut text: String = String::new();
    for c in constants {
        if let DecodedValue::Utf16(s) = &c.decoded {
            push_format(
                &mut text,
                format_args!(
                    "static-decoder\t0x{:08X}\t{}\t{s:?}\n",
                    c.method_token, c.method_name
                ),
            );
        }
    }
    for s in emulated {
        push_format(
            &mut text,
            format_args!(
                "emulated-decryptor\t0x{:08X}\t{}\t{:?}\n",
                s.method_token, s.method_name, s.text
            ),
        );
    }
    if let Ok(Some(recovery)) = peel_confuserex_constants(bytes) {
        for rs in &recovery.strings_recovered {
            push_format(
                &mut text,
                format_args!(
                    "confuserex-constants\tcall_site=0x{:08X}\tmut_off={}\t{:?}\n",
                    rs.call_site_id, rs.mutated_offset, rs.text
                ),
            );
        }
    }
    text
}

fn render_recovered_cil(methods: &[RecoveredMethod]) -> String {
    let mut text: String = String::with_capacity(methods.len() * 128);
    for m in methods {
        push_format(
            &mut text,
            format_args!(
                "method {} token=0x{:08X} args={} locals={}\n",
                m.method_name, m.metadata_token, m.arg_count, m.local_count
            ),
        );
        for line in &m.cil {
            push_format(&mut text, format_args!("  {line}\n"));
        }
        text.push_str("end\n");
    }
    text
}

fn render_csharp_source(assembly: &DecompiledAssembly, recovered_constants: &[String]) -> String {
    let mut out: String = String::with_capacity(assembly.methods.len() * 128);
    out.push_str("// disrobe dotnet native CIL->C# decompilation (no runtime, no external tool)\n");
    push_format(
        &mut out,
        format_args!("// module: {}\n", assembly.module_name),
    );
    out.push('\n');
    for m in &assembly.methods {
        let StructuredMethod { body, .. } = m;
        out.push_str(body);
        out.push('\n');
    }
    if !recovered_constants.is_empty() {
        out.push_str("\n// recovered ConfuserEx constant-protected string literals:\n");
        for c in recovered_constants {
            push_format(&mut out, format_args!("//   {c:?}\n"));
        }
    }
    out
}

fn verdict_clr(dir: DataDirectory) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_PE_CLR,
        FAMILY_INTERPRETER_BYTECODE,
        0.95,
        25,
        vec!["PE+CLR-data-directory"],
        format!(
            "PE with CLR header rva={rva:#x} size={sz}",
            rva = dir.rva,
            sz = dir.size,
        ),
    )
}

fn verdict_native_aot(header: &crate::aot::ReadyToRunHeader) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_NATIVE_AOT,
        FAMILY_INTERPRETER_BYTECODE,
        0.99,
        35,
        vec!["PE+NativeAOT-ReadyToRun-header"],
        format!(
            "PE NativeAOT image with ReadyToRun version {major}.{minor} and {sections} sections",
            major = header.major_version,
            minor = header.minor_version,
            sections = header.sections.len(),
        ),
    )
}

const fn aot_runtime_label(runtime: crate::aot::AotRuntime) -> &'static str {
    match runtime {
        crate::aot::AotRuntime::Net7 => "net7",
        crate::aot::AotRuntime::Net8 => "net8",
        crate::aot::AotRuntime::Net9 => "net9",
        crate::aot::AotRuntime::Net10 => "net10",
        crate::aot::AotRuntime::Unknown => "unknown",
    }
}

struct NativeAotSymbolBudget {
    work_items: usize,
    qualified_name_bytes: usize,
}

impl NativeAotSymbolBudget {
    const fn new() -> Self {
        Self {
            work_items: 0,
            qualified_name_bytes: 0,
        }
    }

    fn claim_work(&mut self, count: usize) -> CoreResult<()> {
        self.work_items = self.work_items.checked_add(count).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-DOTNET-0921: NativeAOT symbol work count overflowed".to_string(),
            )
        })?;
        if self.work_items > MAX_NATIVE_AOT_SYMBOL_WORK_ITEMS {
            return Err(CoreError::PassFailure(format!(
                "DR-DOTNET-0921: NativeAOT symbol work exceeds {MAX_NATIVE_AOT_SYMBOL_WORK_ITEMS} items"
            )));
        }
        Ok(())
    }

    fn claim_qualified_name_bytes(&mut self, count: usize) -> CoreResult<()> {
        self.qualified_name_bytes =
            self.qualified_name_bytes
                .checked_add(count)
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0922: NativeAOT qualified name size overflowed".to_string(),
                    )
                })?;
        if self.qualified_name_bytes > MAX_NATIVE_AOT_QUALIFIED_NAME_BYTES {
            return Err(CoreError::PassFailure(format!(
                "DR-DOTNET-0922: NativeAOT qualified names exceed {MAX_NATIVE_AOT_QUALIFIED_NAME_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

fn native_aot_allocation_error(requested: usize) -> CoreError {
    CoreError::PassFailure(format!(
        "DR-DOTNET-0923: NativeAOT symbol allocation of {requested} items or bytes failed"
    ))
}

fn preflight_qualified_aot_type_names(
    types: &[AotType],
    records: &[(u32, &AotType)],
    budget: &mut NativeAotSymbolBudget,
) -> CoreResult<()> {
    for record in types {
        let mut qualified_length: usize = record.name.len();
        if let Some(namespace) = &record.namespace {
            qualified_length = qualified_length
                .checked_add(namespace.len())
                .and_then(|length: usize| length.checked_add(1))
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0922: NativeAOT qualified name size overflowed".to_string(),
                    )
                })?;
        }
        budget.claim_work(1)?;
        let mut enclosing: Option<u32> = record.enclosing_type_record_offset;
        let mut depth: usize = 0;
        while let Some(offset) = enclosing {
            depth = depth.checked_add(1).ok_or_else(|| {
                CoreError::PassFailure(
                    "DR-DOTNET-0920: NativeAOT type nesting depth overflowed".to_string(),
                )
            })?;
            if depth > MAX_NATIVE_AOT_TYPE_NESTING_DEPTH {
                return Err(CoreError::PassFailure(format!(
                    "DR-DOTNET-0920: NativeAOT type nesting exceeds {MAX_NATIVE_AOT_TYPE_NESTING_DEPTH} levels"
                )));
            }
            budget.claim_work(2)?;
            let parent: &AotType = indexed_aot_type(records, offset).ok_or_else(|| {
                CoreError::PassFailure(format!(
                    "DR-DOTNET-0913: NativeAOT enclosing type record 0x{offset:x} is absent"
                ))
            })?;
            qualified_length = qualified_length
                .checked_add(parent.name.len())
                .and_then(|length: usize| length.checked_add(1))
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0922: NativeAOT qualified name size overflowed".to_string(),
                    )
                })?;
            enclosing = parent.enclosing_type_record_offset;
        }
        budget.claim_qualified_name_bytes(qualified_length)?;
    }
    Ok(())
}

fn preflight_native_aot_symbols(
    attribution: &AotMetadataAttribution,
) -> CoreResult<Vec<(u32, &AotType)>> {
    let mut records: Vec<(u32, &AotType)> = Vec::new();
    records
        .try_reserve_exact(attribution.types.len())
        .map_err(|_| native_aot_allocation_error(attribution.types.len()))?;
    for record in &attribution.types {
        records.push((record.record_offset, record));
    }
    records.sort_unstable_by_key(|(offset, _record): &(u32, &AotType)| *offset);
    let mut budget: NativeAotSymbolBudget = NativeAotSymbolBudget::new();
    preflight_qualified_aot_type_names(&attribution.types, &records, &mut budget)?;
    for record in &attribution.types {
        budget.claim_work(
            record
                .method_record_offsets
                .len()
                .checked_mul(2)
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0921: NativeAOT symbol work count overflowed".to_string(),
                    )
                })?,
        )?;
    }
    for method in &attribution.methods {
        let signature_items: usize = method.signature.as_ref().map_or(Ok(0), |signature| {
            signature
                .parameter_types
                .len()
                .checked_add(signature.vararg_parameter_types.len())
                .and_then(|count: usize| count.checked_add(1))
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0921: NativeAOT symbol work count overflowed".to_string(),
                    )
                })
        })?;
        budget.claim_work(signature_items.checked_add(1).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-DOTNET-0921: NativeAOT symbol work count overflowed".to_string(),
            )
        })?)?;
    }
    Ok(records)
}

fn qualified_aot_type_names(
    types: &[AotType],
    records: &[(u32, &AotType)],
) -> CoreResult<Vec<(u32, String)>> {
    let mut names: Vec<(u32, String)> = Vec::new();
    names
        .try_reserve_exact(types.len())
        .map_err(|_| native_aot_allocation_error(types.len()))?;
    for record in types {
        let mut components: Vec<&str> = Vec::new();
        components
            .try_reserve_exact(MAX_NATIVE_AOT_TYPE_NESTING_DEPTH.saturating_add(1))
            .map_err(|_| {
                native_aot_allocation_error(MAX_NATIVE_AOT_TYPE_NESTING_DEPTH.saturating_add(1))
            })?;
        components.push(record.name.as_str());
        let mut enclosing: Option<u32> = record.enclosing_type_record_offset;
        while let Some(offset) = enclosing {
            let parent: &AotType = indexed_aot_type(records, offset).ok_or_else(|| {
                CoreError::PassFailure(format!(
                    "DR-DOTNET-0913: NativeAOT enclosing type record 0x{offset:x} is absent"
                ))
            })?;
            components.push(parent.name.as_str());
            enclosing = parent.enclosing_type_record_offset;
        }
        let component_bytes: usize = components
            .iter()
            .try_fold(
                components.len().saturating_sub(1),
                |length: usize, component: &&str| length.checked_add(component.len()),
            )
            .ok_or_else(|| {
                CoreError::PassFailure(
                    "DR-DOTNET-0922: NativeAOT qualified name size overflowed".to_string(),
                )
            })?;
        let qualified_length: usize =
            record
                .namespace
                .as_ref()
                .map_or(Ok(component_bytes), |namespace: &String| {
                    component_bytes
                        .checked_add(namespace.len())
                        .and_then(|length: usize| length.checked_add(1))
                        .ok_or_else(|| {
                            CoreError::PassFailure(
                                "DR-DOTNET-0922: NativeAOT qualified name size overflowed"
                                    .to_string(),
                            )
                        })
                })?;
        let mut qualified_name: String = String::new();
        qualified_name
            .try_reserve_exact(qualified_length)
            .map_err(|_| native_aot_allocation_error(qualified_length))?;
        if let Some(namespace) = &record.namespace {
            qualified_name.push_str(namespace);
            qualified_name.push('.');
        }
        for (index, component) in components.iter().rev().enumerate() {
            if index != 0 {
                qualified_name.push('+');
            }
            qualified_name.push_str(component);
        }
        names.push((record.record_offset, qualified_name));
    }
    names.sort_unstable_by_key(|(offset, _name): &(u32, String)| *offset);
    Ok(names)
}

fn indexed_aot_type<'a>(records: &'a [(u32, &'a AotType)], offset: u32) -> Option<&'a AotType> {
    records
        .binary_search_by_key(&offset, |(record_offset, _record): &(u32, &AotType)| {
            *record_offset
        })
        .ok()
        .and_then(|index: usize| records.get(index))
        .map(|(_record_offset, record): &(u32, &AotType)| *record)
}

fn indexed_aot_name(names: &[(u32, String)], offset: u32) -> Option<&str> {
    names
        .binary_search_by_key(&offset, |(record_offset, _name): &(u32, String)| {
            *record_offset
        })
        .ok()
        .and_then(|index: usize| names.get(index))
        .map(|(_record_offset, name): &(u32, String)| name.as_str())
}

#[derive(Serialize)]
struct NativeAotOutputType<'a> {
    record_offset: u32,
    qualified_name: &'a str,
    method_record_offsets: &'a [u32],
}

#[derive(Serialize)]
struct NativeAotOutputMethod<'a> {
    record_offset: u32,
    declaring_type: Option<&'a str>,
    declaring_types: Vec<&'a str>,
    name: &'a str,
    signature: Option<&'a crate::aot::AotMethodSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entrypoint_rva: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_range: Option<&'a crate::aot::AotCodeRange>,
}

#[derive(Serialize)]
struct NativeAotSymbolsDocument<'a> {
    schema: &'static str,
    runtime: &'static str,
    metadata_status: &'a AotMetadataStatus,
    types: Vec<NativeAotOutputType<'a>>,
    methods: Vec<NativeAotOutputMethod<'a>>,
}

fn native_aot_symbols_document<'a>(
    report: &'a AotReport,
    type_names: &'a [(u32, String)],
) -> CoreResult<NativeAotSymbolsDocument<'a>> {
    let attribution: &AotMetadataAttribution = &report.metadata_attribution;
    let mut owner_counts: Vec<(u32, usize)> = Vec::new();
    owner_counts
        .try_reserve_exact(attribution.methods.len())
        .map_err(|_| native_aot_allocation_error(attribution.methods.len()))?;
    for method in &attribution.methods {
        owner_counts.push((method.record_offset, 0));
    }
    owner_counts.sort_unstable_by_key(|(offset, _count): &(u32, usize)| *offset);
    for type_record in &attribution.types {
        for method_offset in &type_record.method_record_offsets {
            let count_index: usize = owner_counts
                .binary_search_by_key(method_offset, |(offset, _count): &(u32, usize)| *offset)
                .map_err(|_index: usize| {
                    CoreError::PassFailure(format!(
                        "DR-DOTNET-0924: NativeAOT method owner record 0x{method_offset:x} is absent"
                    ))
                })?;
            let count: &mut usize = &mut owner_counts
                .get_mut(count_index)
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0924: NativeAOT method owner index is absent".to_string(),
                    )
                })?
                .1;
            *count = count.checked_add(1).ok_or_else(|| {
                CoreError::PassFailure(
                    "DR-DOTNET-0921: NativeAOT method owner count overflowed".to_string(),
                )
            })?;
        }
    }
    let mut method_owners: Vec<(u32, Vec<&str>)> = Vec::new();
    method_owners
        .try_reserve_exact(owner_counts.len())
        .map_err(|_| native_aot_allocation_error(owner_counts.len()))?;
    for (method_offset, count) in owner_counts {
        let mut owners: Vec<&str> = Vec::new();
        owners
            .try_reserve_exact(count)
            .map_err(|_| native_aot_allocation_error(count))?;
        method_owners.push((method_offset, owners));
    }
    for type_record in &attribution.types {
        let qualified_name: &str = indexed_aot_name(type_names, type_record.record_offset)
            .ok_or_else(|| {
                CoreError::PassFailure(format!(
                    "DR-DOTNET-0917: NativeAOT type name for record 0x{:x} is absent",
                    type_record.record_offset
                ))
            })?;
        for method_offset in &type_record.method_record_offsets {
            let owner_index: usize = method_owners
                .binary_search_by_key(method_offset, |(offset, _owners): &(u32, Vec<&str>)| *offset)
                .map_err(|_index: usize| {
                    CoreError::PassFailure(format!(
                        "DR-DOTNET-0924: NativeAOT method owner storage for record 0x{method_offset:x} is absent"
                    ))
                })?;
            let owners: &mut Vec<&str> = &mut method_owners
                .get_mut(owner_index)
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0924: NativeAOT method owner index is absent".to_string(),
                    )
                })?
                .1;
            owners.push(qualified_name);
        }
    }
    let mut types: Vec<NativeAotOutputType<'a>> = Vec::new();
    types
        .try_reserve_exact(attribution.types.len())
        .map_err(|_| native_aot_allocation_error(attribution.types.len()))?;
    for record in &attribution.types {
        let qualified_name: &str =
            indexed_aot_name(type_names, record.record_offset).ok_or_else(|| {
                CoreError::PassFailure(format!(
                    "DR-DOTNET-0918: NativeAOT output type name for record 0x{:x} is absent",
                    record.record_offset
                ))
            })?;
        types.push(NativeAotOutputType {
            record_offset: record.record_offset,
            qualified_name,
            method_record_offsets: &record.method_record_offsets,
        });
    }
    let mut methods: Vec<NativeAotOutputMethod<'a>> = Vec::new();
    methods
        .try_reserve_exact(attribution.methods.len())
        .map_err(|_| native_aot_allocation_error(attribution.methods.len()))?;
    for method in &attribution.methods {
        let owner_index: usize = method_owners
            .binary_search_by_key(
                &method.record_offset,
                |(offset, _owners): &(u32, Vec<&str>)| *offset,
            )
            .map_err(|_index: usize| {
                CoreError::PassFailure(format!(
                    "DR-DOTNET-0924: NativeAOT method owner storage for record 0x{:x} is absent",
                    method.record_offset
                ))
            })?;
        let declaring_types: Vec<&str> = std::mem::take(
            &mut method_owners
                .get_mut(owner_index)
                .ok_or_else(|| {
                    CoreError::PassFailure(
                        "DR-DOTNET-0924: NativeAOT method owner index is absent".to_string(),
                    )
                })?
                .1,
        );
        let declaring_type: Option<&str> = declaring_types.first().copied();
        methods.push(NativeAotOutputMethod {
            record_offset: method.record_offset,
            declaring_type,
            declaring_types,
            name: &method.name,
            signature: method.signature.as_ref(),
            entrypoint_rva: method.entrypoint_rva,
            code_range: method.code_range.as_ref(),
        });
    }
    Ok(NativeAotSymbolsDocument {
        schema: NATIVE_AOT_SYMBOLS_SCHEMA,
        runtime: aot_runtime_label(report.runtime_label),
        metadata_status: &attribution.status,
        types,
        methods,
    })
}

struct NativeAotJsonSizer {
    bytes: usize,
    exceeded: Option<usize>,
    limit: usize,
}

impl NativeAotJsonSizer {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: 0,
            exceeded: None,
            limit,
        }
    }
}

impl Write for NativeAotJsonSizer {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let required: usize = self.bytes.saturating_add(buffer.len());
        if required > self.limit {
            self.exceeded = Some(required);
            return Err(std::io::Error::other(
                "NativeAOT symbol artifact limit exceeded",
            ));
        }
        self.bytes = required;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn native_aot_symbols_bytes(report: &AotReport) -> CoreResult<Vec<u8>> {
    let attribution: &AotMetadataAttribution = &report.metadata_attribution;
    match &attribution.status {
        AotMetadataStatus::Recovered | AotMetadataStatus::NotPresent => {}
        AotMetadataStatus::UnsupportedVersion {
            major_version,
            minor_version,
        } => {
            return Err(CoreError::PassFailure(format!(
                "DR-DOTNET-0914: NativeAOT metadata version {major_version}.{minor_version} is unsupported"
            )));
        }
        AotMetadataStatus::Rejected { reason, .. } => {
            return Err(CoreError::PassFailure(format!(
                "DR-DOTNET-0916: NativeAOT metadata was rejected: {reason}"
            )));
        }
    }
    let records: Vec<(u32, &AotType)> = preflight_native_aot_symbols(attribution)?;
    let type_names: Vec<(u32, String)> = qualified_aot_type_names(&attribution.types, &records)?;
    let document: NativeAotSymbolsDocument<'_> = native_aot_symbols_document(report, &type_names)?;
    let mut sizer: NativeAotJsonSizer =
        NativeAotJsonSizer::new(MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES);
    if let Err(error) = serde_json::to_writer_pretty(&mut sizer, &document) {
        return sizer.exceeded.map_or_else(
            || {
                Err(CoreError::PassFailure(format!(
                    "DR-DOTNET-0910: NativeAOT symbol serialization failed: {error}"
                )))
            },
            |actual: usize| {
                Err(CoreError::PassFailure(format!(
                    "DR-DOTNET-0919: NativeAOT symbol artifact would reach {actual} bytes, exceeding {MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES} bytes"
                )))
            },
        );
    }
    let requested: usize = sizer.bytes;
    let mut output: Vec<u8> = Vec::new();
    output
        .try_reserve_exact(requested)
        .map_err(|_| native_aot_allocation_error(requested))?;
    serde_json::to_writer_pretty(&mut output, &document).map_err(|error: serde_json::Error| {
        CoreError::PassFailure(format!(
            "DR-DOTNET-0910: NativeAOT symbol serialization failed: {error}"
        ))
    })?;
    if output.len() != requested {
        return Err(CoreError::PassFailure(
            "DR-DOTNET-0925: NativeAOT symbol serialization size changed after preflight"
                .to_string(),
        ));
    }
    Ok(output)
}

#[derive(Debug)]
pub struct DotnetObfuscatorEntry {
    pub protector: Protector,
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub quality: SupportQuality,
}

impl CatalogEntry for DotnetObfuscatorEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.protector.label()
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const fn quality_for(protector: Protector) -> SupportQuality {
    match protector {
        Protector::ConfuserEx2 | Protector::EazfuscatorNet | Protector::KoiVm => {
            SupportQuality::Full
        }
        Protector::Ilprotector | Protector::MaxToCode | Protector::ThemidaDotnet => {
            SupportQuality::DetectOnly
        }
        Protector::ConfuserEx
        | Protector::Dotfuscator
        | Protector::DotfuscatorCe
        | Protector::SmartAssembly
        | Protector::BabelDotnet
        | Protector::DeepSea
        | Protector::SpicesNet
        | Protector::Goliath
        | Protector::Skater
        | Protector::DotnetReactor
        | Protector::CryptoObfuscator
        | Protector::ArmDot
        | Protector::AgileNet
        | Protector::DotNetPatcher
        | Protector::NetCryptor
        | Protector::Obfuscar
        | Protector::BitMono => SupportQuality::Partial,
    }
}

const CATALOG_COUNT: usize = 22;

static CATALOG: [DotnetObfuscatorEntry; CATALOG_COUNT] = [
    DotnetObfuscatorEntry {
        protector: Protector::ConfuserEx2,
        id: "dotnet-confuserex2",
        aliases: &["confuserex2", "confuserex-2"],
        quality: quality_for(Protector::ConfuserEx2),
    },
    DotnetObfuscatorEntry {
        protector: Protector::ConfuserEx,
        id: "dotnet-confuserex",
        aliases: &["confuserex", "confuser"],
        quality: quality_for(Protector::ConfuserEx),
    },
    DotnetObfuscatorEntry {
        protector: Protector::EazfuscatorNet,
        id: "dotnet-eazfuscator",
        aliases: &["eazfuscator", "eazfuscator.net", "eaz"],
        quality: quality_for(Protector::EazfuscatorNet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::KoiVm,
        id: "dotnet-koivm",
        aliases: &["koivm", "koi"],
        quality: quality_for(Protector::KoiVm),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Ilprotector,
        id: "dotnet-ilprotector",
        aliases: &["ilprotector"],
        quality: quality_for(Protector::Ilprotector),
    },
    DotnetObfuscatorEntry {
        protector: Protector::MaxToCode,
        id: "dotnet-maxtocode",
        aliases: &["maxtocode"],
        quality: quality_for(Protector::MaxToCode),
    },
    DotnetObfuscatorEntry {
        protector: Protector::ThemidaDotnet,
        id: "dotnet-themida",
        aliases: &["themida", "winlicense"],
        quality: quality_for(Protector::ThemidaDotnet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::SmartAssembly,
        id: "dotnet-smartassembly",
        aliases: &["smartassembly"],
        quality: quality_for(Protector::SmartAssembly),
    },
    DotnetObfuscatorEntry {
        protector: Protector::BabelDotnet,
        id: "dotnet-babel",
        aliases: &["babel", "babelfor.net"],
        quality: quality_for(Protector::BabelDotnet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::CryptoObfuscator,
        id: "dotnet-cryptoobfuscator",
        aliases: &["cryptoobfuscator", "crypto-obfuscator"],
        quality: quality_for(Protector::CryptoObfuscator),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DotnetReactor,
        id: "dotnet-reactor",
        aliases: &["dotnetreactor", "reactor", "eziriz"],
        quality: quality_for(Protector::DotnetReactor),
    },
    DotnetObfuscatorEntry {
        protector: Protector::AgileNet,
        id: "dotnet-agile",
        aliases: &["agile.net", "agiledotnet", "clisecure"],
        quality: quality_for(Protector::AgileNet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DotNetPatcher,
        id: "dotnet-patcher",
        aliases: &["dotnetpatcher", "dnpatcher", "dn-patcher"],
        quality: quality_for(Protector::DotNetPatcher),
    },
    DotnetObfuscatorEntry {
        protector: Protector::NetCryptor,
        id: "dotnet-netcryptor",
        aliases: &["netcryptor", "net-cryptor"],
        quality: quality_for(Protector::NetCryptor),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Dotfuscator,
        id: "dotnet-dotfuscator",
        aliases: &["dotfuscator"],
        quality: quality_for(Protector::Dotfuscator),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DotfuscatorCe,
        id: "dotnet-dotfuscator-ce",
        aliases: &["dotfuscator-ce", "dotfuscatorce"],
        quality: quality_for(Protector::DotfuscatorCe),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DeepSea,
        id: "dotnet-deepsea",
        aliases: &["deepsea"],
        quality: quality_for(Protector::DeepSea),
    },
    DotnetObfuscatorEntry {
        protector: Protector::SpicesNet,
        id: "dotnet-spices",
        aliases: &["spices.net", "9rays"],
        quality: quality_for(Protector::SpicesNet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Skater,
        id: "dotnet-skater",
        aliases: &["skater", "rustemsoft"],
        quality: quality_for(Protector::Skater),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Goliath,
        id: "dotnet-goliath",
        aliases: &["goliath", "goliath.net"],
        quality: quality_for(Protector::Goliath),
    },
    DotnetObfuscatorEntry {
        protector: Protector::ArmDot,
        id: "dotnet-armdot",
        aliases: &["armdot"],
        quality: quality_for(Protector::ArmDot),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Obfuscar,
        id: "dotnet-obfuscar",
        aliases: &["obfuscar"],
        quality: quality_for(Protector::Obfuscar),
    },
];

fn catalog_id_for(protector: Protector) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&DotnetObfuscatorEntry| e.protector == protector)
        .map(|e: &DotnetObfuscatorEntry| e.id)
}

fn confidence_for(report: &DetectionReport, protector: Protector) -> f32 {
    let hit_count: usize = report.matches.get(&protector).map_or(0, Vec::len);
    let base: f32 = match protector.handling() {
        Handling::Devirtualize => 0.95,
        Handling::De4dotDelegate => 0.92,
        Handling::GatedDe4dotDelegate => 0.9,
        Handling::NativeStrip => 0.85,
        Handling::DetectOnly => 0.8,
    };
    let bonus: f32 = (hit_count.min(4) as f32) * 0.02;
    (base + bonus).min(0.99)
}

impl ObfuscatorCatalog for DotnetDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static DotnetObfuscatorEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 64 || &bytes[..2] != b"MZ" {
            return None;
        }
        let report: DetectionReport = detect_all(bytes);
        let primary: Protector = report.primary?;
        let entry_id: &'static str = catalog_id_for(primary)?;
        let confidence: f32 = confidence_for(&report, primary);
        let markers: Vec<String> = report
            .matches
            .keys()
            .filter_map(|p: &Protector| catalog_id_for(*p).map(str::to_owned))
            .collect();
        Some(DetectorOutput::new(entry_id, confidence, markers))
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(DotnetDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_misses_non_pe() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(Detector::detect(&DotnetDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_misses_pe_without_clr() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        assert!(Detector::detect(&DotnetDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_csharp_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match DOTNET_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::CSharp);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_non_pe() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = DOTNET_PASS.run(&a).expect_err("must reject");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-DOTNET-0902") || msg.contains("DR-DOTNET-0903"));
    }

    #[test]
    fn native_aot_type_names_reject_excessive_containment_depth() {
        let types: Vec<AotType> = (0..258u32)
            .map(|record_offset: u32| AotType {
                record_offset,
                namespace: None,
                name: format!("Type{record_offset}"),
                enclosing_type_record_offset: record_offset.checked_sub(1),
                method_record_offsets: Vec::new(),
            })
            .collect();
        let attribution: AotMetadataAttribution = AotMetadataAttribution {
            status: AotMetadataStatus::Recovered,
            types,
            methods: Vec::new(),
        };
        let error: CoreError = preflight_native_aot_symbols(&attribution)
            .expect_err("NativeAOT type qualification must have a fixed depth bound");
        assert!(error.to_string().contains("DR-DOTNET-0920"));
    }

    #[test]
    fn native_aot_type_names_reject_cumulative_work() {
        let mut types: Vec<AotType> = (0..256u32)
            .map(|record_offset: u32| AotType {
                record_offset,
                namespace: None,
                name: "T".to_string(),
                enclosing_type_record_offset: record_offset.checked_sub(1),
                method_record_offsets: Vec::new(),
            })
            .collect();
        types.extend((256..4_353u32).map(|record_offset: u32| AotType {
            record_offset,
            namespace: None,
            name: "L".to_string(),
            enclosing_type_record_offset: Some(255),
            method_record_offsets: Vec::new(),
        }));
        let attribution: AotMetadataAttribution = AotMetadataAttribution {
            status: AotMetadataStatus::Recovered,
            types,
            methods: Vec::new(),
        };
        let error: CoreError = preflight_native_aot_symbols(&attribution)
            .expect_err("NativeAOT type qualification must have a cumulative work bound");
        assert!(error.to_string().contains("DR-DOTNET-0921"));
    }

    #[test]
    fn native_aot_type_names_reject_cumulative_output_bytes() {
        let types: Vec<AotType> = (0..100u32)
            .map(|record_offset: u32| AotType {
                record_offset,
                namespace: None,
                name: "N".repeat(4_096),
                enclosing_type_record_offset: record_offset.checked_sub(1),
                method_record_offsets: Vec::new(),
            })
            .collect();
        let attribution: AotMetadataAttribution = AotMetadataAttribution {
            status: AotMetadataStatus::Recovered,
            types,
            methods: Vec::new(),
        };
        let error: CoreError = preflight_native_aot_symbols(&attribution)
            .expect_err("NativeAOT type qualification must have a cumulative byte bound");
        assert!(error.to_string().contains("DR-DOTNET-0922"));
    }

    #[test]
    fn native_aot_json_preflight_rejects_the_first_byte_past_limit() {
        let mut sizer: NativeAotJsonSizer = NativeAotJsonSizer::new(3);
        let result: std::io::Result<()> = sizer.write_all(b"abcd");
        assert!(result.is_err());
        assert_eq!(sizer.bytes, 0);
        assert_eq!(sizer.exceeded, Some(4));
    }

    fn corpus(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel)
    }

    fn fixture(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(rel)
    }

    #[test]
    fn catalog_covers_every_protector_once() {
        let entries: Vec<&'static dyn CatalogEntry> = DotnetDetector.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        let mut ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), CATALOG_COUNT, "catalog ids must be unique");
        for e in &entries {
            assert!(e.id().starts_with("dotnet-"));
            assert!(!e.display_name().is_empty());
        }
    }

    #[test]
    fn quality_map_is_honest() {
        assert_eq!(quality_for(Protector::EazfuscatorNet), SupportQuality::Full);
        assert_eq!(quality_for(Protector::ConfuserEx2), SupportQuality::Full);
        assert_eq!(quality_for(Protector::KoiVm), SupportQuality::Full);
        assert_eq!(
            quality_for(Protector::Ilprotector),
            SupportQuality::DetectOnly
        );
        assert_eq!(
            quality_for(Protector::MaxToCode),
            SupportQuality::DetectOnly
        );
        assert_eq!(
            quality_for(Protector::ThemidaDotnet),
            SupportQuality::DetectOnly
        );
        assert_eq!(
            quality_for(Protector::SmartAssembly),
            SupportQuality::Partial
        );
        assert_eq!(
            quality_for(Protector::DotNetPatcher),
            SupportQuality::Partial
        );
        assert_eq!(quality_for(Protector::NetCryptor), SupportQuality::Partial);
        assert_eq!(quality_for(Protector::Obfuscar), SupportQuality::Partial);
    }

    #[test]
    fn catalog_detects_real_confuserex2_sample() {
        let path: std::path::PathBuf = corpus("dotnet/HelloAppLegacy.confuserex2.dll");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: confuserex2 fixture missing at {}", path.display());
            return;
        };
        let out: DetectorOutput = ObfuscatorCatalog::detect(&DotnetDetector, &ctx(&bytes))
            .expect("real ConfuserEx2 assembly must be catalog-detected");
        assert_eq!(out.entry_id, "dotnet-confuserex2");
        assert!(out.confidence >= 0.9, "confidence={}", out.confidence);
        let entry: &dyn CatalogEntry = DotnetDetector
            .catalog()
            .into_iter()
            .find(|e: &&dyn CatalogEntry| e.id() == out.entry_id)
            .expect("detected id must be in catalog");
        assert_eq!(entry.support_quality(), SupportQuality::Full);
    }

    #[test]
    fn catalog_detect_misses_non_pe() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(ObfuscatorCatalog::detect(&DotnetDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn extract_children_emits_dedicated_sidecars_for_real_confuserex2() {
        let path: std::path::PathBuf = corpus("dotnet/HelloAppLegacy.confuserex2.dll");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: confuserex2 fixture missing at {}", path.display());
            return;
        };
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = DOTNET_PASS
            .extract_children(&artifact)
            .expect("extract_children must not error on a real .NET PE");
        let has_analyze: bool = children
            .iter()
            .any(|c: &ChildArtifact| c.handle.relative_path.ends_with(".analyze.json"));
        let has_peel: bool = children
            .iter()
            .any(|c: &ChildArtifact| c.handle.relative_path.ends_with(".peel.json"));
        assert!(
            has_analyze,
            "auto/chain must emit the dedicated analyze manifest sidecar"
        );
        assert!(
            has_peel,
            "auto/chain must emit the dedicated peel report sidecar for a detected protector"
        );
        for c in &children {
            assert!(
                c.handle.is_terminal(),
                "dotnet sidecars are recovered outputs, must carry the terminal hint"
            );
            assert!(
                !c.bytes.is_empty(),
                "sidecar {} must not be empty",
                c.handle.relative_path
            );
        }
        let analyze_child: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with(".analyze.json"))
            .expect("analyze sidecar present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&analyze_child.bytes).expect("analyze sidecar is valid JSON");
        assert_eq!(parsed["schema"], "disrobe.dotnet.analyze/v1");
    }

    #[test]
    fn extract_children_emits_recovered_confuserex2_resource_bytes() {
        let bytes: Vec<u8> = std::fs::read(fixture(
            "confuser_resources/ConfuserResources.confuserex2.dll",
        ))
        .expect("protected fixture");
        let expected: Vec<u8> =
            std::fs::read(fixture("confuser_resources/ConfuserResourcePayload.bin"))
                .expect("payload fixture");
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = DOTNET_PASS
            .extract_children(&artifact)
            .expect("extract children");
        let resource: &ChildArtifact = children
            .iter()
            .find(|child: &&ChildArtifact| {
                child
                    .handle
                    .relative_path
                    .ends_with(".recovered-resources/00000-ConfuserResources.Payload.bin")
            })
            .expect("recovered resource child");
        assert_eq!(resource.bytes, expected);
        assert!(resource.handle.is_terminal());
        let peel: &ChildArtifact = children
            .iter()
            .find(|child: &&ChildArtifact| child.handle.relative_path.ends_with(".peel.json"))
            .expect("peel manifest");
        let parsed: serde_json::Value =
            serde_json::from_slice(&peel.bytes).expect("peel manifest json");
        assert_eq!(
            parsed["recovered_resources"][0]["name"],
            "ConfuserResources.Payload.bin"
        );
        assert_eq!(parsed["recovered_resources"][0]["size"], 132);
    }

    #[test]
    fn extract_children_analyze_sidecar_surfaces_koivm_devirtualization() {
        let path: std::path::PathBuf = corpus("dotnet/koivm/KoiSample.koivm.exe");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: koivm fixture missing at {}", path.display());
            return;
        };
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = DOTNET_PASS
            .extract_children(&artifact)
            .expect("extract_children must not error on a real KoiVM .NET PE");
        let analyze_child: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with(".analyze.json"))
            .expect("analyze sidecar present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&analyze_child.bytes).expect("analyze sidecar is valid JSON");
        let koivm: &serde_json::Value = &parsed["koivm"];
        assert_eq!(koivm["koi_stream_present"], true);
        assert_eq!(koivm["virtualized_methods"], 6);
        assert_eq!(koivm["devirtualized_methods"], 6);
        let names: Vec<String> = koivm["recovered_method_names"]
            .as_array()
            .expect("recovered_method_names is a json array")
            .iter()
            .map(|v: &serde_json::Value| v.as_str().unwrap_or_default().to_owned())
            .collect();
        assert!(
            names.contains(&"Add".to_owned()),
            "the analyze sidecar must carry the KoiVM devirtualized method names; got {names:?}"
        );
        assert!(parsed["eazvm"].is_null());
    }

    fn analyze_sidecar_for(rel: &str) -> Option<serde_json::Value> {
        let path: std::path::PathBuf = corpus(rel);
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: fixture missing at {}", path.display());
            return None;
        };
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = DOTNET_PASS
            .extract_children(&artifact)
            .expect("extract_children must not error on a real .NET PE");
        let analyze_child: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with(".analyze.json"))
            .expect("analyze sidecar present");
        Some(serde_json::from_slice(&analyze_child.bytes).expect("analyze sidecar is valid JSON"))
    }

    #[test]
    fn extract_children_analyze_sidecar_surfaces_control_flow_flattening() {
        let Some(parsed): Option<serde_json::Value> =
            analyze_sidecar_for("dotnet/cff/CffSample.ctrlflow.exe")
        else {
            return;
        };
        let cff: &serde_json::Value = &parsed["control_flow_flattening"];
        assert!(
            !cff.is_null(),
            "the analyze sidecar must surface the control-flow-flattening summary"
        );
        assert!(
            cff["deflattened_methods"].as_u64().unwrap_or(0) >= 6,
            "expected at least six deflattened methods; got {cff:?}"
        );
        assert_eq!(cff["flattened_methods"], cff["deflattened_methods"]);
    }

    #[test]
    fn extract_children_analyze_sidecar_surfaces_inlined_decryptor_literals() {
        let Some(parsed): Option<serde_json::Value> =
            analyze_sidecar_for("dotnet/cff/DecryptSample.exe")
        else {
            return;
        };
        let inlined: Vec<String> = parsed["inlined_literals"]
            .as_array()
            .expect("inlined_literals is a json array")
            .iter()
            .map(|v: &serde_json::Value| v.as_str().unwrap_or_default().to_owned())
            .collect();
        assert!(
            inlined.contains(&"genuine".to_owned()),
            "the analyze sidecar must carry the recovered decryptor literal; got {inlined:?}"
        );
    }
}
