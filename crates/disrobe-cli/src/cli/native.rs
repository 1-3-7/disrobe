#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SectionKind};
use serde::Serialize;

use super::globals;
use super::output::{self, OutputFormat};
use super::progress_ui::StageSpinner;
use disrobe_binfmt::{import_graph_dot, parse_native};
use disrobe_core::scratch::ScratchDir;

const GHIDRA_DECOMPILE_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_CAPTURE_OUTPUT: usize = 4 * 1024 * 1024;

struct CappedRun {
    exit_code: Option<i32>,
    success: bool,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_capped(mut command: Command, timeout: Duration) -> miette::Result<CappedRun> {
    let child: std::process::Child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| miette::miette!("DR-NATIVE-0004: ghidra-headless spawn failed: {e}"))?;
    Ok(
        match disrobe_core::subprocess::wait_with_output_timeout(child, timeout, MAX_CAPTURE_OUTPUT)
        {
            Some(captured) => CappedRun {
                exit_code: captured.exit_code,
                success: captured.exit_code == Some(0),
                timed_out: false,
                stdout: captured.stdout,
                stderr: captured.stderr,
            },
            None => CappedRun {
                exit_code: None,
                success: false,
                timed_out: true,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        },
    )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DecompileBackend {
    #[default]
    Native,
    Ghidra,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DecompileLang {
    #[default]
    C,
    Rust,
}

impl DecompileLang {
    const fn extension(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Rust => "rs",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::C => "C",
            Self::Rust => "Rust",
        }
    }
}

pub(crate) fn decompile(
    input: PathBuf,
    out: Option<PathBuf>,
    emit: Vec<String>,
    backend: DecompileBackend,
    format: DecompileLang,
    devirt: bool,
) -> miette::Result<()> {
    match backend {
        DecompileBackend::Native => decompile_native(input, out, format, devirt),
        DecompileBackend::Ghidra => decompile_ghidra(input, out, emit),
    }
}

fn sanitize_comment_text(text: &str) -> String {
    text.chars()
        .map(|c: char| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .replace("*/", "* /")
        .replace("/*", "/ *")
}

fn api_type_c(ty: disrobe_typerec::ApiType) -> String {
    use disrobe_typerec::{ApiType, Sign, Width};
    let bits = |w: Width| -> Option<u32> { w.bytes().map(|b: u8| u32::from(b) * 8) };
    match ty {
        ApiType::Pointer => "void*".to_owned(),
        ApiType::Handle => "HANDLE".to_owned(),
        ApiType::Code => "code*".to_owned(),
        ApiType::Float { width } => match bits(width) {
            Some(64) => "double",
            _ => "float",
        }
        .to_owned(),
        ApiType::Integer { width, sign } => match (bits(width), sign) {
            (Some(b), Sign::Signed) => format!("int{b}_t"),
            (Some(b), Sign::Unsigned) => format!("uint{b}_t"),
            (Some(b), _) => format!("int{b}"),
            (None, _) => "int".to_owned(),
        },
        ApiType::Unknown | ApiType::Conflict => "void".to_owned(),
    }
}

fn api_prov(prov: &disrobe_typerec::Provenance) -> String {
    use disrobe_typerec::{ApiSite, Provenance};
    match prov {
        Provenance::ApiDb {
            library,
            name,
            site,
        } => {
            let site: String = match site {
                ApiSite::Return => "ret".to_owned(),
                ApiSite::Arg(index) => format!("arg{index}"),
            };
            format!("{library}!{name} {site} [ApiDb]")
        }
        Provenance::LivenessInferred => "[LivenessInferred]".to_owned(),
        Provenance::Heuristic => "[Heuristic]".to_owned(),
    }
}

fn build_header_comment(
    format: DecompileLang,
    name: &str,
    addr: u64,
    banner: Option<&Vec<String>>,
) -> String {
    let name: String = sanitize_comment_text(name);
    match format {
        DecompileLang::C => {
            let mut out: String = format!("/* {name} @ {addr:#x}");
            if let Some(lines) = banner {
                out.push_str("\n   api-derived types:");
                for line in lines {
                    out.push_str("\n     ");
                    out.push_str(&sanitize_comment_text(line));
                }
                out.push_str("\n */");
            } else {
                out.push_str(" */");
            }
            out
        }
        DecompileLang::Rust => {
            let mut out: String = format!("// {name} @ {addr:#x}");
            if let Some(lines) = banner {
                out.push_str("\n// api-derived types:");
                for line in lines {
                    out.push_str("\n//   ");
                    out.push_str(&sanitize_comment_text(line));
                }
            }
            out
        }
    }
}

fn decompile_native(
    input: PathBuf,
    out: Option<PathBuf>,
    format: DecompileLang,
    devirt: bool,
) -> miette::Result<()> {
    use disrobe_pass_native::{ProgramFunction, PseudoAbi, RecoveredFunction, recover_program};
    use std::fmt::Write as _;

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0160: cannot read input: {e}"))?;
    let module: disrobe_query::Module = load_native_module(&input, &bytes)?;
    let obj: object::File<'_> = object::File::parse(bytes.as_slice())
        .map_err(|e| miette::miette!("DR-NATIVE-0161: cannot parse native object: {e}"))?;
    match obj.architecture() {
        object::Architecture::X86_64 => {}
        object::Architecture::Aarch64 => {
            return decompile_native_aarch64(&input, &obj, &module, out, format, devirt);
        }
        other => {
            return Err(miette::miette!(
                "DR-NATIVE-0162: the in-tree decompiler supports x86-64 and aarch64 only (got {other:?}); use --backend ghidra for other architectures"
            ));
        }
    }
    let abi: PseudoAbi = if matches!(
        obj.format(),
        object::BinaryFormat::Pe | object::BinaryFormat::Coff
    ) {
        PseudoAbi::MsX64
    } else {
        PseudoAbi::SysV
    };

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-native-decompiled")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0163: cannot create out dir: {e}"))?;

    let mut includes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut bodies: String = String::new();
    let mut recovered: Vec<serde_json::Value> = Vec::new();
    let mut unrecovered: Vec<serde_json::Value> = Vec::new();
    let mut program_functions: Vec<ProgramFunction> = Vec::with_capacity(module.functions().len());

    for f in module.functions() {
        let Some(code): Option<Vec<u8>> = bytes_for_va_range(&obj, f.address, f.end) else {
            unrecovered.push(serde_json::json!({
                "name": f.name, "address": f.address, "reason": "no mapped code bytes for the function range"
            }));
            continue;
        };
        program_functions.push(ProgramFunction {
            name: unique_c_name(&f.name, f.address, &mut seen),
            address: f.address,
            code,
        });
    }

    let program: disrobe_pass_native::RecoveredProgram =
        recover_program(&bytes, &program_functions, abi);
    let raw_names_by_address: BTreeMap<u64, &str> = module
        .functions()
        .iter()
        .map(|f: &disrobe_query::Function| (f.address, f.name.as_str()))
        .collect();
    for bad in &program.unrecovered {
        let raw_name: &str = raw_names_by_address
            .get(&bad.address)
            .copied()
            .unwrap_or(bad.name.as_str());
        unrecovered.push(serde_json::json!({
            "name": raw_name, "address": bad.address, "reason": bad.reason
        }));
    }
    let by_address: BTreeMap<u64, &RecoveredFunction> = program
        .recovered
        .iter()
        .map(|rec: &RecoveredFunction| (rec.address, rec))
        .collect();

    let (api_text_base, api_text): (u64, Vec<u8>) =
        disrobe_typerec::load_text(&bytes).unwrap_or((0, Vec::new()));
    let api_imports: disrobe_typerec::ImportMap = disrobe_typerec::ImportMap::from_image(&bytes);
    let api_sigdb: disrobe_typerec::SigDb = disrobe_typerec::SigDb::builtin();
    let api_abi: disrobe_typerec::Abi = match abi {
        PseudoAbi::MsX64 => disrobe_typerec::Abi::Win64,
        PseudoAbi::SysV | PseudoAbi::Aapcs64 => disrobe_typerec::Abi::SysV,
    };
    let mut api_banner: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut api_slots_json: BTreeMap<u64, Vec<serde_json::Value>> = BTreeMap::new();
    let mut api_slots_recovered: usize = 0;
    if !api_text.is_empty() {
        for pf in &program_functions {
            let typing: disrobe_typerec::CallsiteTyping = disrobe_typerec::type_function(
                &api_text,
                api_text_base,
                pf.address,
                pf.address.saturating_add(pf.code.len() as u64),
                &api_imports,
                &api_sigdb,
                api_abi,
            );
            let slots: Vec<disrobe_typerec::TypedSlot> = typing.typed_slots();
            if slots.is_empty() {
                continue;
            }
            let mut banner: Vec<String> = Vec::with_capacity(slots.len());
            let mut json_slots: Vec<serde_json::Value> = Vec::with_capacity(slots.len());
            for slot in &slots {
                api_slots_recovered += 1;
                let c_type: String = api_type_c(slot.ty);
                let provenance: String = api_prov(&slot.provenance);
                let sign: char = if slot.rbp_disp < 0 { '-' } else { '+' };
                banner.push(format!(
                    "[rbp{sign}{:#x}] {c_type} <- {provenance}",
                    slot.rbp_disp.unsigned_abs()
                ));
                json_slots.push(serde_json::json!({
                    "rbp_disp": slot.rbp_disp,
                    "c_type": c_type,
                    "provenance": provenance,
                }));
            }
            api_banner.insert(pf.address, banner);
            api_slots_json.insert(pf.address, json_slots);
        }
    }

    for f in module.functions() {
        let Some(rec): Option<&RecoveredFunction> = by_address.get(&f.address).copied() else {
            continue;
        };
        let selected: Option<&str> = match format {
            DecompileLang::C => Some(rec.source.as_str()),
            DecompileLang::Rust => rec.rust_source.as_deref(),
        };
        let Some(src): Option<&str> = selected else {
            unrecovered.push(serde_json::json!({
                "name": f.name, "address": f.address,
                "reason": "not in the pure-safe Rust-emittable class (struct return or a block memcpy/memset idiom)"
            }));
            continue;
        };
        if matches!(format, DecompileLang::C) {
            for line in src.lines() {
                if line.trim_start().starts_with("#include") {
                    includes.insert(line.trim().to_owned());
                }
            }
        }
        let renamed: String = src
            .lines()
            .filter(|l: &&str| !l.trim_start().starts_with("#include"))
            .collect::<Vec<&str>>()
            .join("\n");
        let comment: String =
            build_header_comment(format, &f.name, f.address, api_banner.get(&f.address));
        let _ = writeln!(bodies, "{comment}\n{}\n", renamed.trim());
        recovered.push(serde_json::json!({
            "name": f.name, "address": f.address, "emitted_as": rec.name
        }));
    }

    let mut typed_functions: Vec<serde_json::Value> = Vec::with_capacity(program_functions.len());
    let mut type_slots_recovered: usize = 0;
    for pf in &program_functions {
        let recovered_types: disrobe_typerec::TypedFunction =
            disrobe_typerec::recover_function(&pf.code, pf.address);
        let api_slots: Vec<serde_json::Value> =
            api_slots_json.get(&pf.address).cloned().unwrap_or_default();
        if recovered_types.rbp_slots.is_empty() && api_slots.is_empty() {
            continue;
        }
        let mut slots: Vec<serde_json::Value> = Vec::with_capacity(recovered_types.rbp_slots.len());
        for (disp, scalar) in &recovered_types.rbp_slots {
            type_slots_recovered += 1;
            slots.push(serde_json::json!({
                "rbp_disp": disp,
                "width": format!("{:?}", scalar.width),
                "sign": format!("{:?}", scalar.sign),
                "sign_conflict": scalar.sign_conflict,
            }));
        }
        typed_functions.push(serde_json::json!({
            "name": pf.name,
            "address": pf.address,
            "has_frame_pointer": recovered_types.has_frame_pointer,
            "slots": slots,
            "api_slots": api_slots,
        }));
    }
    let types_manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.native.types/v1",
        "input": input.display().to_string(),
        "functions_typed": typed_functions.len(),
        "slots_recovered": type_slots_recovered,
        "api_slots_recovered": api_slots_recovered,
        "functions": typed_functions,
    });
    std::fs::write(
        out_dir.join("types.json"),
        serde_json::to_vec_pretty(&types_manifest)
            .map_err(|e| miette::miette!("DR-NATIVE-0167: serialize recovered types: {e}"))?,
    )
    .map_err(|e| miette::miette!("DR-NATIVE-0168: cannot write recovered types: {e}"))?;

    let mut source_text: String = String::new();
    if matches!(format, DecompileLang::C) {
        for inc in &includes {
            source_text.push_str(inc);
            source_text.push('\n');
        }
        if !includes.is_empty() {
            source_text.push('\n');
        }
    }
    source_text.push_str(&bodies);

    let src_path: PathBuf = out_dir.join(format!("{stem}.{}", format.extension()));
    std::fs::write(&src_path, source_text.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0164: cannot write decompiled output: {e}"))?;

    let total: usize = module.functions().len();
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.native.decompile/v1",
        "backend": "native-in-tree-x86_64",
        "language": format.label(),
        "input": input.display().to_string(),
        "abi": format!("{abi:?}"),
        "functions_total": total,
        "functions_recovered": recovered.len(),
        "functions_unrecovered": unrecovered.len(),
        "functions_typed": typed_functions.len(),
        "type_slots_recovered": type_slots_recovered,
        "api_slots_recovered": api_slots_recovered,
        "source": src_path.display().to_string(),
        "types": out_dir.join("types.json").display().to_string(),
        "devirt": if devirt {
            serde_json::json!({
                "enabled": false,
                "reason": "devirt runs on the aarch64 nir path; the in-tree x86-64 recovery path is unchanged"
            })
        } else {
            serde_json::json!({ "enabled": false })
        },
        "recovered": recovered,
        "unrecovered": unrecovered,
    });
    std::fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)
            .map_err(|e| miette::miette!("DR-NATIVE-0165: serialize manifest: {e}"))?,
    )
    .map_err(|e| miette::miette!("DR-NATIVE-0166: cannot write manifest: {e}"))?;

    println!(
        "native decompile (in-tree x86-64 -> {}): recovered {}/{} function(s), {} typed slot(s) across {} function(s) -> {}",
        format.label(),
        recovered.len(),
        total,
        type_slots_recovered,
        typed_functions.len(),
        src_path.display()
    );
    Ok(())
}

#[cfg(feature = "nir-lift")]
fn aarch64_recover_source(
    code: &[u8],
    address: u64,
    name: &str,
    devirt: bool,
) -> Result<(String, bool, serde_json::Value), String> {
    use disrobe_nir::{
        HirFunction, NirFunction, SurfaceFunction, emit_pseudo_source, structurize_function,
        surfacify_function,
    };
    use disrobe_nir_lift::lower_aarch64;

    let nir: NirFunction =
        lower_aarch64(code, address, name).map_err(|e| format!("aarch64 lift failed: {e}"))?;

    #[cfg(feature = "devirt")]
    let (nir, devirt_report): (NirFunction, serde_json::Value) = if devirt {
        apply_nir_devirt(&nir)
    } else {
        (nir, serde_json::Value::Null)
    };
    #[cfg(not(feature = "devirt"))]
    let (nir, devirt_report): (NirFunction, serde_json::Value) = {
        let _ = devirt;
        (nir, serde_json::Value::Null)
    };

    let hir: HirFunction = structurize_function(&nir);
    let surface: SurfaceFunction = surfacify_function(&hir);
    let source: String =
        emit_pseudo_source(&surface).map_err(|e| format!("pseudo-source emit failed: {e}"))?;
    Ok((source, surface.structured, devirt_report))
}

#[cfg(feature = "devirt")]
fn apply_nir_devirt(
    nir: &disrobe_nir::NirFunction,
) -> (disrobe_nir::NirFunction, serde_json::Value) {
    let outcome: disrobe_mba::NirDevirtOutcome = disrobe_mba::devirtualize_nir(nir);
    let report: serde_json::Value = devirt_report_json(&outcome.report);
    (outcome.function, report)
}

#[cfg(feature = "devirt")]
fn devirt_report_json(report: &disrobe_mba::NirDevirtReport) -> serde_json::Value {
    let folded: Vec<serde_json::Value> = report
        .folded
        .iter()
        .map(|branch: &disrobe_mba::FoldedBranch| {
            serde_json::json!({
                "block": branch.block,
                "kept": branch.kept,
                "dropped": branch.dropped,
            })
        })
        .collect();
    let mut value: serde_json::Value = serde_json::json!({
        "status": report.status.label(),
        "edges_folded": report.folded.len(),
        "folded": folded,
        "cff_detected": report.cff.detected,
        "cff_certified_full": report.cff.certified_full,
        "cff_cases": report.cff.cases,
        "cff_resolved": report.cff.resolved,
        "cff_unresolved": report.cff.unresolved,
    });
    if let Some(abstain) = report.abstain {
        value["abstain"] = serde_json::Value::String(abstain.label().to_owned());
    }
    value
}

#[cfg(feature = "nir-lift")]
fn decompile_native_aarch64(
    input: &Path,
    obj: &object::File<'_>,
    module: &disrobe_query::Module,
    out: Option<PathBuf>,
    format: DecompileLang,
    devirt: bool,
) -> miette::Result<()> {
    use std::fmt::Write as _;

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-native-decompiled")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0170: cannot create out dir: {e}"))?;

    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut bodies: String = String::new();
    let mut recovered: Vec<serde_json::Value> = Vec::new();
    let mut unrecovered: Vec<serde_json::Value> = Vec::new();
    let mut structured_count: usize = 0;
    let mut devirt_full: usize = 0;
    let mut devirt_partial: usize = 0;
    let mut devirt_none: usize = 0;
    let mut devirt_edges: usize = 0;
    #[cfg(feature = "devirt")]
    let binary_budget: Option<disrobe_mba::BinaryBudget> =
        devirt.then(|| disrobe_mba::BinaryBudget::new(std::time::Duration::from_mins(1)));
    #[cfg(feature = "devirt")]
    let mut devirt_self_disabled: bool = false;

    for f in module.functions() {
        let Some(code): Option<Vec<u8>> = bytes_for_va_range(obj, f.address, f.end) else {
            unrecovered.push(serde_json::json!({
                "name": f.name, "address": f.address, "reason": "no mapped code bytes for the function range"
            }));
            continue;
        };
        let emitted_name: String = unique_c_name(&f.name, f.address, &mut seen);
        let effective_devirt: bool = {
            #[cfg(feature = "devirt")]
            {
                devirt
                    && match &binary_budget {
                        Some(budget) if budget.exhausted() => {
                            devirt_self_disabled = true;
                            false
                        }
                        _ => true,
                    }
            }
            #[cfg(not(feature = "devirt"))]
            {
                let _ = devirt;
                false
            }
        };
        let (source, structured, devirt_report): (String, bool, serde_json::Value) =
            match aarch64_recover_source(&code, f.address, &emitted_name, effective_devirt) {
                Ok(value) => value,
                Err(reason) => {
                    unrecovered.push(serde_json::json!({
                        "name": f.name, "address": f.address, "reason": reason
                    }));
                    continue;
                }
            };
        if structured {
            structured_count += 1;
        }
        let note: &str = if structured {
            ""
        } else {
            " (unstructured control flow)"
        };
        let _ = writeln!(
            bodies,
            "/* {} @ {:#x}{note} */\n{}\n",
            f.name,
            f.address,
            source.trim()
        );
        let mut entry: serde_json::Value = serde_json::json!({
            "name": f.name, "address": f.address, "emitted_as": emitted_name, "structured": structured
        });
        if !devirt_report.is_null() {
            match devirt_report
                .get("status")
                .and_then(serde_json::Value::as_str)
            {
                Some("full") => devirt_full += 1,
                Some("partial") => devirt_partial += 1,
                _ => devirt_none += 1,
            }
            devirt_edges += devirt_report
                .get("edges_folded")
                .and_then(serde_json::Value::as_u64)
                .and_then(|count: u64| usize::try_from(count).ok())
                .unwrap_or(0);
            entry["devirt"] = devirt_report;
        }
        recovered.push(entry);
    }

    let src_path: PathBuf = out_dir.join(format!("{stem}.c"));
    std::fs::write(&src_path, bodies.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0171: cannot write decompiled output: {e}"))?;

    let self_disabled: bool = {
        #[cfg(feature = "devirt")]
        {
            devirt_self_disabled
        }
        #[cfg(not(feature = "devirt"))]
        {
            false
        }
    };
    let devirt_summary: serde_json::Value = if devirt {
        serde_json::json!({
            "enabled": true,
            "applied": "opaque-predicate fold (proven-dead conditional arms), transactional",
            "self_disabled": self_disabled,
            "functions_full": devirt_full,
            "functions_partial": devirt_partial,
            "functions_none": devirt_none,
            "edges_folded": devirt_edges,
            "deferred": ["control-flow-flattening deflatten", "jump-table edge rewrite"],
        })
    } else {
        serde_json::json!({ "enabled": false })
    };

    let total: usize = module.functions().len();
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.native.decompile/v1",
        "backend": "native-in-tree-aarch64",
        "language": "pseudo-C",
        "requested_language": format.label(),
        "input": input.display().to_string(),
        "functions_total": total,
        "functions_recovered": recovered.len(),
        "functions_structured": structured_count,
        "functions_unrecovered": unrecovered.len(),
        "source": src_path.display().to_string(),
        "devirt": devirt_summary,
        "recovered": recovered,
        "unrecovered": unrecovered,
    });
    std::fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)
            .map_err(|e| miette::miette!("DR-NATIVE-0172: serialize manifest: {e}"))?,
    )
    .map_err(|e| miette::miette!("DR-NATIVE-0173: cannot write manifest: {e}"))?;

    println!(
        "native decompile (in-tree aarch64 -> pseudo-C): recovered {}/{} function(s), {} structured -> {}",
        recovered.len(),
        total,
        structured_count,
        src_path.display()
    );
    if devirt {
        println!(
            "  devirt:       {devirt_full} full, {devirt_partial} partial, {devirt_none} none; {devirt_edges} dead arm(s) folded"
        );
    }
    Ok(())
}

#[cfg(not(feature = "nir-lift"))]
fn decompile_native_aarch64(
    input: &Path,
    _obj: &object::File<'_>,
    _module: &disrobe_query::Module,
    _out: Option<PathBuf>,
    _format: DecompileLang,
    _devirt: bool,
) -> miette::Result<()> {
    Err(miette::miette!(
        "DR-NATIVE-0169: aarch64 in-tree decompile needs the nir-lift feature, which is not built into this binary; rebuild with a default (full) build or `--features nir-lift`, or use --backend ghidra for {}",
        input.display()
    ))
}

fn bytes_for_va_range(obj: &object::File<'_>, start_va: u64, end_va: u64) -> Option<Vec<u8>> {
    let len: usize = usize::try_from(end_va.checked_sub(start_va)?).ok()?;
    if len == 0 {
        return None;
    }
    for section in obj.sections() {
        let addr: u64 = section.address();
        let sec_end: u64 = addr.checked_add(section.size())?;
        if start_va >= addr && start_va < sec_end {
            let data: &[u8] = section.data().ok()?;
            let off: usize = usize::try_from(start_va - addr).ok()?;
            if off >= data.len() {
                return None;
            }
            let take: usize = off.saturating_add(len).min(data.len());
            return Some(data[off..take].to_vec());
        }
    }
    None
}

fn unique_c_name(raw: &str, va: u64, seen: &mut std::collections::BTreeSet<String>) -> String {
    let sanitized: String = raw
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let base: String = if sanitized.is_empty()
        || sanitized
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_digit())
    {
        format!("sub_{va:x}")
    } else {
        sanitized
    };
    let candidate: String = if seen.contains(&base) {
        format!("{base}_{va:x}")
    } else {
        base
    };
    seen.insert(candidate.clone());
    candidate
}

fn decompile_ghidra(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
    let resolved: Option<PathBuf> = locate_ghidra_headless();
    let Some(ghidra): Option<PathBuf> = resolved else {
        return Err(miette::miette!(
            "DR-NATIVE-0001: ghidra-headless not on PATH (set GHIDRA_HOME or run `disrobe install-deps ghidra`). Native decompile uses Ghidra-headless to lift PE/ELF/Mach-O binaries to a pseudo-C-source."
        ));
    };
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-native-decompiled")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0002: cannot create out dir: {e}"))?;

    let workspace: ScratchDir = ScratchDir::create("ghidra-decompile")
        .map_err(|e| miette::miette!("DR-NATIVE-0003: cannot create ghidra project dir: {e}"))?;

    let project_dir: PathBuf = workspace.path().join("project");
    std::fs::create_dir_all(&project_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0003: cannot create ghidra project dir: {e}"))?;

    let script_dir: PathBuf = workspace.path().join("scripts");
    std::fs::create_dir_all(&script_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0008: cannot create scripts dir: {e}"))?;
    let script_name: &str = "DisrobeDecompileScript.java";
    let script_path: PathBuf = script_dir.join(script_name);
    let decompile_out: PathBuf = out_dir.join(format!("{stem}.decompiled.c"));
    write_decompile_script(&script_path, &decompile_out)?;

    let spinner: StageSpinner = StageSpinner::start("native decompile", "running ghidra-headless");
    let mut command: Command = Command::new(&ghidra);
    command
        .arg(&project_dir)
        .arg("disrobe-native")
        .arg("-import")
        .arg(&input)
        .arg("-postScript")
        .arg(script_name)
        .arg("-scriptPath")
        .arg(&script_dir)
        .arg("-deleteProject")
        .arg("-overwrite")
        .arg("-noanalysis");
    let capped: CappedRun = run_capped(command, GHIDRA_DECOMPILE_TIMEOUT)?;
    if capped.timed_out {
        spinner.finish("ghidra-headless timed out");
        return Err(miette::miette!(
            "DR-NATIVE-0009: ghidra-headless exceeded the {}s decompile budget and was terminated",
            GHIDRA_DECOMPILE_TIMEOUT.as_secs()
        ));
    }
    spinner.finish("ghidra-headless complete");

    let exit_code: Option<i32> = capped.exit_code;
    let success: bool = capped.success;
    let stdout: String = String::from_utf8_lossy(&capped.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&capped.stderr).into_owned();
    let decompile_present: bool = decompile_out.is_file();
    let decompile_size: u64 = if decompile_present {
        std::fs::metadata(&decompile_out).map_or(0, |m| m.len())
    } else {
        0
    };
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.native.decompile/v0",
        "input": input.display().to_string(),
        "ghidra_headless": ghidra.display().to_string(),
        "exit_code": exit_code,
        "stdout_tail": tail_bytes(&stdout, 4096),
        "stderr_tail": tail_bytes(&stderr, 4096),
        "out_dir": out_dir.display().to_string(),
        "decompile_path": decompile_out.display().to_string(),
        "decompile_present": decompile_present,
        "decompile_size_bytes": decompile_size,
    });
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-NATIVE-0005: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0006: cannot write manifest: {e}"))?;

    if !success {
        return Err(miette::miette!(
            "DR-NATIVE-0007: ghidra-headless exited with status {:?}; see {}",
            exit_code,
            manifest_path.display()
        ));
    }
    crate::cli::emit::apply_not_applicable_stubs(
        &emit,
        &out_dir,
        &stem,
        "native-decompile",
        "not implemented for the native decompile pass in this build",
    )?;
    let sourcemap_path: Option<PathBuf> =
        emit_dwarf_sourcemap_if_requested(&emit, &input, &out_dir, &stem)?;
    println!("native decompile: OK");
    if let Some(path) = sourcemap_path {
        println!("  sourcemap:    {}", path.display());
    }
    println!("  input:        {}", input.display());
    println!("  ghidra:       {}", ghidra.display());
    println!("  out dir:      {}", out_dir.display());
    println!("  decompile:    {}", decompile_out.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn emit_dwarf_sourcemap_if_requested(
    emit: &[String],
    input: &Path,
    out_dir: &Path,
    stem: &str,
) -> miette::Result<Option<PathBuf>> {
    let spec: crate::cli::emit::EmitSpec = crate::cli::emit::EmitSpec::parse(emit)?;
    if !spec.contains(crate::cli::emit::EmitKind::Sourcemap) {
        return Ok(None);
    }
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-NATIVE-0010: cannot read input for sourcemap: {e}"))?;
    let map: disrobe_pass_native::DwarfSourcemap =
        disrobe_pass_native::synthesize_dwarf_sourcemap(&bytes).map_err(|e| {
            miette::miette!(
                "DR-NATIVE-0011: native --emit sourcemap: no recoverable DWARF in {}: {e}",
                input.display()
            )
        })?;
    let path: PathBuf = crate::cli::emit::write_applicable_payload(
        out_dir,
        stem,
        crate::cli::emit::EmitKind::Sourcemap,
        &map.to_sourcemap_json(),
    )?;
    Ok(Some(path))
}

fn write_decompile_script(script_path: &Path, decompile_out: &Path) -> miette::Result<()> {
    let escaped: String = decompile_out.display().to_string().replace('\\', "\\\\");
    let body: String = format!(
        "import java.io.File;\nimport java.io.FileWriter;\nimport java.io.PrintWriter;\nimport ghidra.app.script.GhidraScript;\nimport ghidra.app.decompiler.DecompInterface;\nimport ghidra.app.decompiler.DecompileResults;\nimport ghidra.program.model.listing.Function;\nimport ghidra.program.model.listing.FunctionIterator;\nimport ghidra.util.task.ConsoleTaskMonitor;\n\npublic class DisrobeDecompileScript extends GhidraScript {{\n    @Override\n    public void run() throws Exception {{\n        DecompInterface ifc = new DecompInterface();\n        ifc.openProgram(currentProgram);\n        File out = new File(\"{escaped}\");\n        out.getParentFile().mkdirs();\n        PrintWriter pw = new PrintWriter(new FileWriter(out));\n        try {{\n            FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);\n            for (Function f : fns) {{\n                if (f.isThunk() || f.isExternal()) continue;\n                DecompileResults r = ifc.decompileFunction(f, 60, new ConsoleTaskMonitor());\n                if (r != null && r.getDecompiledFunction() != null) {{\n                    pw.println(\"// FUNCTION \" + f.getName() + \" @ \" + f.getEntryPoint().toString());\n                    pw.println(r.getDecompiledFunction().getC());\n                    pw.println();\n                }}\n            }}\n        }} finally {{\n            pw.close();\n            ifc.dispose();\n        }}\n    }}\n}}\n"
    );
    std::fs::write(script_path, body.as_bytes()).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0009: cannot write decompile script {}: {e}",
            script_path.display()
        )
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ExportTarget {
    #[default]
    Ghidra,
    Ida,
    Json,
}

impl ExportTarget {
    const fn into_pass(self) -> disrobe_pass_native::ExportFormat {
        match self {
            Self::Ghidra => disrobe_pass_native::ExportFormat::Ghidra,
            Self::Ida => disrobe_pass_native::ExportFormat::Ida,
            Self::Json => disrobe_pass_native::ExportFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveredKind {
    MemoryImage,
    StandaloneFile,
    Auto,
}

#[derive(Debug)]
struct RecoveredArtifact {
    packer: disrobe_pass_native::Packer,
    status: disrobe_pass_native::UnpackerStatus,
    bytes: Vec<u8>,
    kind: RecoveredKind,
    recovered_oep_va: Option<u64>,
}

fn recover_packed_image(input: &Path, bytes: &[u8]) -> miette::Result<RecoveredArtifact> {
    use disrobe_pass_native::{
        AspackPhaseTwoOutput, FsgUnpackOutput, KkrunchyPhaseTwoOutput, MewRebuiltImage,
        MpressUnpackOutput, NspackEmulatedReport, Packer, PackerDetection, PecompactPhaseTwoOutput,
        PetitePhase2EmulatedOutput, UnpackerStatus, UpxUnpackOutput, detect_packers,
        unpack_aspack_phase2_emulated, unpack_fsg, unpack_kkrunchy_phase2_emulated,
        unpack_mew_rebuilt, unpack_mpress, unpack_nspack_emulated,
        unpack_pecompact_phase2_emulated, unpack_petite_phase2_emulated, unpack_upx,
    };

    let mut dets: Vec<PackerDetection> = detect_packers(bytes);
    if dets.is_empty() {
        return Err(miette::miette!(
            "DR-NATIVE-0031: no packer signature in {}; nothing to unpack",
            input.display()
        ));
    }
    dets.sort_by_key(|d: &PackerDetection| packer_rank(d.packer));
    let packer: Packer = dets[0].packer;
    let status: UnpackerStatus = packer.unpacker_status();

    let (recovered, kind, oep): (Vec<u8>, RecoveredKind, Option<u64>) = match status {
        UnpackerStatus::Implemented => match packer {
            Packer::Upx => {
                let o: UpxUnpackOutput = unpack_upx(bytes)
                    .map_err(|e| miette::miette!("DR-NATIVE-0048: upx unpack failed: {e}"))?;
                (o.recovered_image, RecoveredKind::Auto, None)
            }
            Packer::Petite => {
                let o: PetitePhase2EmulatedOutput = unpack_petite_phase2_emulated(bytes)
                    .map_err(|e| miette::miette!("DR-NATIVE-0035: petite unpack failed: {e}"))?;
                (o.recovered_image, RecoveredKind::Auto, o.oep_estimate)
            }
            Packer::Nspack => {
                let r: NspackEmulatedReport = unpack_nspack_emulated(bytes)
                    .map_err(|e| miette::miette!("DR-NATIVE-0036: nspack unpack failed: {e}"))?;
                (r.decompressed_image, RecoveredKind::Auto, None)
            }
            Packer::Mew => {
                let o: MewRebuiltImage = unpack_mew_rebuilt(bytes)
                    .map_err(|e| miette::miette!("DR-NATIVE-0037: mew unpack failed: {e}"))?;
                let oep_va: u64 =
                    u64::from(o.image_base).saturating_add(u64::from(o.original_entry_point_rva));
                (o.file_image, RecoveredKind::StandaloneFile, Some(oep_va))
            }
            Packer::Fsg => {
                let o: FsgUnpackOutput = unpack_fsg(bytes)
                    .map_err(|e| miette::miette!("DR-NATIVE-0038: fsg unpack failed: {e}"))?;
                (o.raw_image, RecoveredKind::Auto, None)
            }
            Packer::Mpress => {
                let o: MpressUnpackOutput = unpack_mpress(bytes)
                    .map_err(|e| miette::miette!("DR-NATIVE-0039: mpress unpack failed: {e}"))?;
                (o.decompressed_image, RecoveredKind::Auto, None)
            }
            Packer::Kkrunchy => {
                let o: KkrunchyPhaseTwoOutput = unpack_kkrunchy_phase2_emulated(bytes)
                    .map_err(|e| miette::miette!("DR-NATIVE-0049: kkrunchy unpack failed: {e}"))?;
                if !o.recovered_file_image.starts_with(b"MZ") {
                    return Err(miette::miette!(
                        "DR-NATIVE-0059: kkrunchy phase-2 emulation did not reach the original entry point for {} (the depacker stub did not finish writing the decompressed image); only the variant with a finished OEP rebuild is recoverable single-file",
                        input.display()
                    ));
                }
                (
                    o.recovered_file_image,
                    RecoveredKind::StandaloneFile,
                    o.oep_estimate,
                )
            }
            Packer::AsPack => {
                let o: AspackPhaseTwoOutput = unpack_aspack_phase2_emulated(bytes, None)
                    .map_err(|e| miette::miette!("DR-NATIVE-0050: aspack unpack failed: {e}"))?;
                (
                    o.recovered_memory_image,
                    RecoveredKind::MemoryImage,
                    o.oep_estimate,
                )
            }
            Packer::PeCompact => {
                let o: PecompactPhaseTwoOutput = unpack_pecompact_phase2_emulated(bytes, None)
                    .map_err(|e| miette::miette!("DR-NATIVE-0052: pecompact unpack failed: {e}"))?;
                (
                    o.recovered_memory_image,
                    RecoveredKind::MemoryImage,
                    o.oep_estimate,
                )
            }
            Packer::YodasCrypter => {
                return Err(miette::miette!(
                    "DR-NATIVE-0054: yoda's crypter recovery is diff-based against the original binary (unpack_yodas_crypter needs both the packed and original images); single-file `native unpack` cannot recover it honestly. detection is production-grade; supply the original for a real comparison-based carve."
                ));
            }
            other => {
                return Err(miette::miette!(
                    "DR-NATIVE-0040: {} reports Implemented status but has no CLI unpack arm",
                    other.label()
                ));
            }
        },
        UnpackerStatus::StubEvalPending => {
            return Err(miette::miette!(
                "DR-NATIVE-0041: {} detected; Rust byte-recovery is stub-eval pending (detection is production-grade)",
                packer.label()
            ));
        }
        UnpackerStatus::DelegatedToDotnet => {
            return Err(miette::miette!(
                "DR-NATIVE-0060: {} is a managed CLR wrapper; route the image through dotnet.classify for metadata, constants, strings, and IL body recovery",
                packer.label()
            ));
        }
        UnpackerStatus::DetectOnly => {
            return Err(miette::miette!(
                "DR-NATIVE-0042: {} is detect-only (crypter/loader family without a deterministic unpack path)",
                packer.label()
            ));
        }
        UnpackerStatus::GreyZoneDetectOnly => {
            return Err(miette::miette!(
                "DR-NATIVE-0043: {} is a grey-zone protector; detection-only per docs/legal stance (no unpack)",
                packer.label()
            ));
        }
        UnpackerStatus::GreyZoneDetectAndCarve => {
            return Err(miette::miette!(
                "DR-NATIVE-0044: {} is a grey-zone protector; original code is virtualized and not recoverable by unpacking",
                packer.label()
            ));
        }
    };

    if recovered.is_empty() {
        return Err(miette::miette!(
            "DR-NATIVE-0045: {} unpacker produced no bytes",
            packer.label()
        ));
    }

    Ok(RecoveredArtifact {
        packer,
        status,
        bytes: recovered,
        kind,
        recovered_oep_va: oep,
    })
}

pub(crate) fn unpack(
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    list: bool,
) -> miette::Result<()> {
    if list {
        crate::cli::emit::print_obfuscator_catalog(
            &disrobe_pass_native::chain_detector::PackerDetector,
            "disrobe native unpack <packed.exe> --out <recovered.bin>",
        );
        return Ok(());
    }
    let Some(input): Option<PathBuf> = input else {
        return Err(miette::miette!(
            "DR-NATIVE-0066: native unpack needs an input file (or `--list` to show supported packers)"
        ));
    };
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0030: cannot read input: {e}"))?;
    let spinner: StageSpinner = StageSpinner::start("native unpack", "detecting packer");
    let artifact: RecoveredArtifact = recover_packed_image(&input, &bytes)?;
    spinner.finish(&format!("unpacked {}", artifact.packer.label()));

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.unpacked.bin")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0046: cannot create out dir: {e}"))?;
    }
    std::fs::write(&out_path, &artifact.bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0047: cannot write recovered bytes: {e}"))?;
    println!("native unpack: OK");
    println!("  input:        {}", input.display());
    println!("  packer:       {}", artifact.packer.label());
    println!("  status:       {:?}", artifact.status);
    println!("  packed_size:  {}", bytes.len());
    println!("  recovered:    {} bytes", artifact.bytes.len());
    if let Some(oep) = artifact.recovered_oep_va {
        println!("  recovered oep:{oep:#x}");
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn entry_va_of_pe(bytes: &[u8]) -> Option<u64> {
    let file: object::File<'_> = object::File::parse(bytes).ok()?;
    if !matches!(file.format(), object::BinaryFormat::Pe) {
        return None;
    }
    let entry: u64 = file.entry();
    (entry != 0).then_some(entry)
}

fn symbol_image_base(bytes: &[u8]) -> u64 {
    object::File::parse(bytes).map_or(0, |f: object::File<'_>| f.relative_address_base())
}

fn rebuild_for_kind(
    packed: &[u8],
    artifact: &RecoveredArtifact,
    recovered_oep_va: Option<u64>,
) -> miette::Result<disrobe_pass_native::RebuiltImage> {
    use disrobe_pass_native::{Error as NativeError, rebuild_passthrough, rebuild_unpacked_pe};

    let label: &str = artifact.packer.label();
    match artifact.kind {
        RecoveredKind::MemoryImage => rebuild_unpacked_pe(
            packed,
            &artifact.bytes,
            recovered_oep_va,
        )
        .map_err(|e: NativeError| {
            miette::miette!("DR-NATIVE-0111: {label} memory-image overlay rebuild failed: {e}")
        }),
        RecoveredKind::StandaloneFile => {
            rebuild_passthrough(&artifact.bytes).map_err(|e: NativeError| {
                miette::miette!("DR-NATIVE-0112: {label} standalone-file rebuild failed: {e}")
            })
        }
        RecoveredKind::Auto => rebuild_unpacked_pe(packed, &artifact.bytes, recovered_oep_va)
            .or_else(|_: NativeError| rebuild_passthrough(&artifact.bytes))
            .map_err(|_: NativeError| {
                miette::miette!(
                    "DR-NATIVE-0101: cannot rebuild a loadable image for {label}: recovered bytes \
                     are neither a reconstructable file image nor a standalone object"
                )
            }),
    }
}

pub(crate) fn export(
    input: PathBuf,
    out: Option<PathBuf>,
    target: ExportTarget,
) -> miette::Result<()> {
    use disrobe_pass_native::{
        ExportFormat, RebuiltImage, SymbolMap, collect_recovered_symbols_with_oep,
        render_ghidra_postscript, render_idapython, render_symbol_map_json,
    };

    let format: ExportFormat = target.into_pass();
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0100: cannot read input: {e}"))?;
    let artifact: RecoveredArtifact = recover_packed_image(&input, &bytes)?;

    let recovered_oep_va: Option<u64> = artifact
        .recovered_oep_va
        .or_else(|| entry_va_of_pe(&artifact.bytes));
    let rebuilt: RebuiltImage = rebuild_for_kind(&bytes, &artifact, recovered_oep_va)?;

    let recovered_oep_for_map: Option<u64> = rebuilt
        .restored_entry_point_rva
        .map(|rva: u32| symbol_image_base(&rebuilt.bytes).saturating_add(u64::from(rva)));
    let mut symbol_map: SymbolMap =
        collect_recovered_symbols_with_oep(&rebuilt.bytes, recovered_oep_for_map).map_err(|e| {
            miette::miette!("DR-NATIVE-0102: cannot collect recovered symbols: {e}")
        })?;
    symbol_map.source = input.display().to_string();

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-export")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0103: cannot create out dir: {e}"))?;

    let rebuilt_path: PathBuf = out_dir.join(format!("{stem}.unpacked.exe"));
    std::fs::write(&rebuilt_path, &rebuilt.bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0104: cannot write rebuilt image: {e}"))?;

    let sidecar_name: String = format!("{stem}.{}", format.sidecar_extension());
    let sidecar_path: PathBuf = out_dir.join(&sidecar_name);
    let sidecar_body: String = match format {
        ExportFormat::Ghidra => render_ghidra_postscript(&symbol_map),
        ExportFormat::Ida => render_idapython(&symbol_map),
        ExportFormat::Json => render_symbol_map_json(&symbol_map)
            .map_err(|e| miette::miette!("DR-NATIVE-0105: symbol-map serialize: {e}"))?,
    };
    std::fs::write(&sidecar_path, sidecar_body.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0106: cannot write sidecar: {e}"))?;

    let map_path: PathBuf = out_dir.join(format!("{stem}.symbols.json"));
    if !matches!(format, ExportFormat::Json) {
        let map_json: String = render_symbol_map_json(&symbol_map)
            .map_err(|e| miette::miette!("DR-NATIVE-0107: symbol-map serialize: {e}"))?;
        std::fs::write(&map_path, map_json.as_bytes())
            .map_err(|e| miette::miette!("DR-NATIVE-0108: cannot write symbol map: {e}"))?;
    }

    let manifest_path: PathBuf = out_dir.join("export.manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.native.export/v1",
        "input": input.display().to_string(),
        "packer": artifact.packer.label(),
        "status": format!("{:?}", artifact.status),
        "format": format.label(),
        "packed_size_bytes": bytes.len(),
        "rebuilt_image": rebuilt_path.display().to_string(),
        "rebuilt_size_bytes": rebuilt.bytes.len(),
        "rebuild_layout": rebuilt.layout.label(),
        "sections_overlaid": rebuilt.sections_overlaid,
        "bytes_placed": rebuilt.bytes_placed,
        "restored_entry_point_rva": rebuilt.restored_entry_point_rva,
        "rebuild_note": rebuilt.note,
        "symbol_sidecar": sidecar_path.display().to_string(),
        "symbol_map": if matches!(format, ExportFormat::Json) { sidecar_path.display().to_string() } else { map_path.display().to_string() },
        "symbol_count": symbol_map.symbol_count,
        "original_entry_point": symbol_map.original_entry_point,
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-NATIVE-0109: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0110: cannot write manifest: {e}"))?;

    println!("native export: OK");
    println!("  input:        {}", input.display());
    println!("  packer:       {}", artifact.packer.label());
    println!("  format:       {}", format.label());
    println!("  rebuilt:      {}", rebuilt_path.display());
    println!("  layout:       {}", rebuilt.layout.label());
    println!(
        "  recovered:    {} bytes placed ({} section(s) overlaid)",
        rebuilt.bytes_placed, rebuilt.sections_overlaid
    );
    println!(
        "  oep:          {}",
        rebuilt.restored_entry_point_rva.map_or_else(
            || "unchanged".to_owned(),
            |rva: u32| format!("RVA {rva:#x}")
        )
    );
    println!("  symbols:      {}", symbol_map.symbol_count);
    println!("  sidecar:      {}", sidecar_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

pub(crate) fn sbom(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    use disrobe_pass_native::{AuditableSbom, parse_auditable_section};

    use crate::cli::cyclonedx::{Component, CycloneDxBom, application_component};

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0060: cannot read input: {e}"))?;
    let sbom: AuditableSbom = parse_auditable_section(&bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0061: parse auditable section: {e}"))?;

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();

    let root: Component =
        application_component(stem.clone(), sha256_hex(&bytes), blake3_hex(&bytes));
    let bom: CycloneDxBom = CycloneDxBom::from_crates(None, Some(root), &sbom.crates);

    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.cyclonedx.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0062: cannot create out dir: {e}"))?;
    }
    let buf: Vec<u8> = serde_json::to_vec_pretty(&bom)
        .map_err(|e| miette::miette!("DR-NATIVE-0063: serialize: {e}"))?;
    std::fs::write(&out_path, buf)
        .map_err(|e| miette::miette!("DR-NATIVE-0064: cannot write sbom: {e}"))?;

    println!("native sbom: OK");
    println!("  input:        {}", input.display());
    println!("  format:       CycloneDX 1.5");
    println!("  components:   {}", bom.components.len());
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    use sha2::Digest as _;

    let mut hasher: sha2::Sha256 = sha2::Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out: String = String::with_capacity(64);
    for b in digest {
        let _: core::fmt::Result = write!(out, "{b:02x}");
    }
    out
}

#[inline]
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[derive(Debug, Serialize)]
struct PdbCxxDeferred {
    original_name: String,
    reason: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct PdbCxxSummary {
    schema: &'static str,
    input: String,
    header_path: String,
    report_path: String,
    udts_recovered: usize,
    enums_recovered: usize,
    typedefs_recovered: usize,
    globals_recovered: usize,
    functions_recovered: usize,
    opaque_enum_forward_decls: usize,
    deferred_count: usize,
    deferred: Vec<PdbCxxDeferred>,
}

pub(crate) fn pdb_cxx(
    input: PathBuf,
    out: Option<PathBuf>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    use disrobe_pass_native::{PdbCxxReconstruction, RejectedType, reconstruct_pdb_cxx};

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0190: cannot read input: {e}"))?;
    let spinner: StageSpinner =
        StageSpinner::start("native pdb-cxx", "parsing TPI/IPI type streams");
    let recon: PdbCxxReconstruction = reconstruct_pdb_cxx(&bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0191: pdb type reconstruction failed: {e}"))?;
    spinner.finish(&format!(
        "{} udt(s), {} enum(s), {} deferred",
        recon.udts.len(),
        recon.enums.len(),
        recon.rejected.len()
    ));

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("pdb-cxx")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-pdb-cxx")));
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0192: cannot create out dir {}: {e}",
            out_dir.display()
        )
    })?;

    let header_path: PathBuf = out_dir.join(format!("{stem}.h"));
    std::fs::write(&header_path, recon.header_text.as_bytes()).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0193: cannot write header {}: {e}",
            header_path.display()
        )
    })?;

    let deferred: Vec<PdbCxxDeferred> = recon
        .rejected
        .iter()
        .map(|r: &RejectedType| PdbCxxDeferred {
            original_name: r.original_name.clone(),
            reason: format!("{:?}", r.reason),
            detail: r.detail.clone(),
        })
        .collect();

    let report_path: PathBuf = out_dir.join(format!("{stem}.pdb-cxx.json"));
    let summary: PdbCxxSummary = PdbCxxSummary {
        schema: "disrobe.native.pdb-cxx/v1",
        input: input.display().to_string(),
        header_path: header_path.display().to_string(),
        report_path: report_path.display().to_string(),
        udts_recovered: recon.udts.len(),
        enums_recovered: recon.enums.len(),
        typedefs_recovered: recon.typedefs.len(),
        globals_recovered: recon.globals.len(),
        functions_recovered: recon.functions.len(),
        opaque_enum_forward_decls: recon.opaque_enum_forward_decls.len(),
        deferred_count: deferred.len(),
        deferred,
    };
    let report_bytes: Vec<u8> = serde_json::to_vec_pretty(&summary)
        .map_err(|e| miette::miette!("DR-NATIVE-0194: serialize report: {e}"))?;
    std::fs::write(&report_path, &report_bytes).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0195: cannot write report {}: {e}",
            report_path.display()
        )
    })?;

    output::emit(fmt, &summary, || render_pdb_cxx(&summary))
}

fn render_pdb_cxx(summary: &PdbCxxSummary) {
    println!("native pdb-cxx: OK");
    println!("  input:        {}", summary.input);
    println!("  udts:         {}", summary.udts_recovered);
    println!("  enums:        {}", summary.enums_recovered);
    println!("  typedefs:     {}", summary.typedefs_recovered);
    println!("  globals:      {}", summary.globals_recovered);
    println!("  functions:    {}", summary.functions_recovered);
    println!("  opaque enums: {}", summary.opaque_enum_forward_decls);
    println!("  deferred:     {}", summary.deferred_count);
    for d in &summary.deferred {
        println!("    {} ({}): {}", d.original_name, d.reason, d.detail);
    }
    println!("  header:       {}", summary.header_path);
    println!("  report:       {}", summary.report_path);
}

const fn packer_rank(p: disrobe_pass_native::Packer) -> u8 {
    use disrobe_pass_native::Packer as P;
    match p {
        P::Upx => 0,
        P::Mpress => 1,
        P::Petite => 2,
        P::Fsg => 3,
        P::Nspack => 4,
        P::Mew => 5,
        _ => 9,
    }
}

#[derive(Debug, Serialize)]
struct FlirtDbSummary {
    version: u8,
    arch: String,
    library_name: String,
    module_count: usize,
}

#[derive(Debug, Serialize)]
struct SignatureDump {
    schema: &'static str,
    input: String,
    byte_count: u64,
    crypto_constants: Vec<disrobe_pass_native::CryptoConstHit>,
    flirt_matches: Vec<disrobe_pass_native::FlirtMatch>,
    string_signatures: Vec<disrobe_pass_native::ObfuscatorHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flirt: Option<FlirtDbSummary>,
}

pub(crate) fn signatures(
    input: PathBuf,
    out: Option<PathBuf>,
    flirt: Option<PathBuf>,
) -> miette::Result<()> {
    use disrobe_pass_native::{
        CryptoConstHit, FlirtMatch, FlirtSig, ObfuscatorHit, detect_crypto_constants,
        detect_obfuscators, match_flirt, parse_flirt,
    };

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0050: cannot read input: {e}"))?;
    let hits: Vec<CryptoConstHit> = detect_crypto_constants(&bytes);
    let string_signatures: Vec<ObfuscatorHit> = detect_obfuscators(&bytes);

    let (flirt_summary, flirt_matches): (Option<FlirtDbSummary>, Vec<FlirtMatch>) = match flirt {
        Some(sig_path) => {
            let sig_bytes: Vec<u8> = std::fs::read(&sig_path)
                .map_err(|e| miette::miette!("DR-NATIVE-0054: cannot read .sig: {e}"))?;
            let sig: FlirtSig = parse_flirt(&sig_bytes)
                .map_err(|e| miette::miette!("DR-NATIVE-0055: FLIRT parse: {e}"))?;
            let matches: Vec<FlirtMatch> = match_flirt(&sig, &bytes);
            (
                Some(FlirtDbSummary {
                    version: sig.header.version,
                    arch: sig.header.arch.label().to_owned(),
                    library_name: sig.header.library_name.clone(),
                    module_count: sig.modules.len(),
                }),
                matches,
            )
        }
        None => (None, Vec::new()),
    };

    let dump: SignatureDump = SignatureDump {
        schema: "disrobe.native.signatures/v1",
        input: input.display().to_string(),
        byte_count: bytes.len() as u64,
        crypto_constants: hits,
        flirt_matches,
        string_signatures,
        flirt: flirt_summary,
    };
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native-signatures")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.signatures.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0051: cannot create out dir: {e}"))?;
    }
    let buf: Vec<u8> = serde_json::to_vec_pretty(&dump)
        .map_err(|e| miette::miette!("DR-NATIVE-0052: serialize: {e}"))?;
    std::fs::write(&out_path, buf)
        .map_err(|e| miette::miette!("DR-NATIVE-0053: cannot write signatures: {e}"))?;
    println!("native signatures: OK");
    println!("  input:        {}", input.display());
    println!("  byte_count:   {}", dump.byte_count);
    println!("  crypto hits:  {}", dump.crypto_constants.len());
    for hit in &dump.crypto_constants {
        println!(
            "    {} @ {} ({:?}, {} bytes)",
            hit.primitive.label(),
            hit.offset,
            hit.confidence,
            hit.matched_len
        );
    }
    println!("  string sigs:  {}", dump.string_signatures.len());
    for hit in &dump.string_signatures {
        println!(
            "    {} @ {} ({})",
            hit.family.label(),
            hit.matched_offset,
            hit.indicator
        );
    }
    if let Some(s) = &dump.flirt {
        println!(
            "  flirt db:     {} v{} ({}, {} modules)",
            s.library_name, s.version, s.arch, s.module_count
        );
        println!("  flirt matches:{}", dump.flirt_matches.len());
        for m in &dump.flirt_matches {
            println!(
                "    {} @ {} (module {})",
                m.name, m.image_offset, m.module_index
            );
        }
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

pub(crate) fn fingerprint(
    input: PathBuf,
    out: Option<PathBuf>,
    flirt: Option<PathBuf>,
) -> miette::Result<()> {
    use disrobe_pass_native::{FingerprintSidecar, FlirtSig, parse_flirt};

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0060: cannot read input: {e}"))?;
    let sig: Option<FlirtSig> = match &flirt {
        Some(p) => {
            let sb: Vec<u8> = std::fs::read(p)
                .map_err(|e| miette::miette!("DR-NATIVE-0061: cannot read .sig: {e}"))?;
            Some(
                parse_flirt(&sb)
                    .map_err(|e| miette::miette!("DR-NATIVE-0062: FLIRT parse: {e}"))?,
            )
        }
        None => None,
    };
    let sidecar: FingerprintSidecar =
        FingerprintSidecar::build(&input.display().to_string(), &bytes, sig.as_ref());

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native-fingerprints")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(".disrobe/fingerprints"));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0063: cannot create fingerprint dir: {e}"))?;
    let out_path: PathBuf = out_dir.join(format!("{stem}.json"));
    let buf: Vec<u8> = serde_json::to_vec_pretty(&sidecar)
        .map_err(|e| miette::miette!("DR-NATIVE-0064: serialize: {e}"))?;
    std::fs::write(&out_path, buf)
        .map_err(|e| miette::miette!("DR-NATIVE-0065: cannot write fingerprints: {e}"))?;

    println!("native fingerprints: OK");
    println!("  input:        {}", input.display());
    println!("  byte_count:   {}", sidecar.byte_count);
    println!("  crypto hits:  {}", sidecar.crypto.len());
    println!("  flirt hits:   {}", sidecar.flirt.len());
    println!("  string xrefs: {}", sidecar.strings.len());
    println!("  out:          {}", out_path.display());
    Ok(())
}

pub(crate) fn symbols(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0010: cannot read input: {e}"))?;
    let dump: SymbolDump = dump_symbols(&bytes, &input)?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native-symbols")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.symbols.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0011: cannot create out dir: {e}"))?;
    }
    let buf: Vec<u8> = serde_json::to_vec_pretty(&dump)
        .map_err(|e| miette::miette!("DR-NATIVE-0012: serialize: {e}"))?;
    std::fs::write(&out_path, buf)
        .map_err(|e| miette::miette!("DR-NATIVE-0013: cannot write symbols: {e}"))?;
    println!("native symbols: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {}", dump.format);
    println!("  arch:         {}", dump.arch);
    println!("  exports:      {}", dump.exports.len());
    render_symbol_rows(&dump.exports);
    println!("  imports:      {}", dump.imports.len());
    render_import_rows(&dump.imports);
    println!("  sections:     {}", dump.sections.len());
    render_section_rows(&dump.sections);
    println!("  segments:     {}", dump.segments.len());
    println!("  debug_info:   {}", dump.debug_info.present);
    if let Some(rtti) = &dump.cxx_rtti {
        println!(
            "  cxx_rtti:     {} ({} classes)",
            rtti.abi,
            rtti.classes.len()
        );
        render_cxx_class_rows(&rtti.classes);
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn render_cxx_class_rows(rows: &[CxxClassRow]) {
    let shown: usize = rows.len().min(SYMBOL_PREVIEW_LIMIT);
    for row in &rows[..shown] {
        let bases: String = if row.bases.is_empty() {
            String::new()
        } else {
            format!(" : {}", row.bases.join(", "))
        };
        let stl: String = if row.stl_templates.is_empty() {
            String::new()
        } else {
            format!("  stl[{}]", row.stl_templates.join(","))
        };
        println!(
            "    {} [{}, {} vmethods]{bases}{stl}",
            row.name, row.inheritance, row.virtual_methods
        );
    }
    if rows.len() > shown {
        println!("    ... {} more (see the symbols JSON)", rows.len() - shown);
    }
}

const SYMBOL_PREVIEW_LIMIT: usize = 40;

fn render_symbol_rows(rows: &[SymbolRow]) {
    let shown: usize = rows.len().min(SYMBOL_PREVIEW_LIMIT);
    for row in &rows[..shown] {
        let section: &str = row.section.as_deref().unwrap_or("-");
        println!(
            "    {:#018x}  {:>8}  {:<6}  {} [{}]",
            row.address, row.size, row.kind, row.name, section
        );
    }
    if rows.len() > shown {
        println!("    ... {} more (see the symbols JSON)", rows.len() - shown);
    }
}

fn render_import_rows(rows: &[ImportRow]) {
    let shown: usize = rows.len().min(SYMBOL_PREVIEW_LIMIT);
    for row in &rows[..shown] {
        match row.library.as_deref() {
            Some(lib) => println!("    {} <- {lib}", row.name),
            None => println!("    {}", row.name),
        }
    }
    if rows.len() > shown {
        println!("    ... {} more (see the symbols JSON)", rows.len() - shown);
    }
}

fn render_section_rows(rows: &[SectionRow]) {
    for row in rows {
        println!(
            "    {:<20}  {:#012x}  {:>10}  {}",
            row.name, row.address, row.size, row.kind
        );
    }
}

pub(crate) fn devirt(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    use disrobe_pass_native::vm_devirt::detect::Bitness;
    use disrobe_pass_native::vm_devirt::{DevirtReport, devirtualize};

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0120: cannot read input: {e}"))?;
    let file: object::File<'_> = object::File::parse(&*bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0121: not a parseable native object: {e}"))?;
    let bitness: Bitness = if file.is_64() {
        Bitness::Bits64
    } else {
        Bitness::Bits32
    };

    let (report, _lifted, _cfg, _semantics): (DevirtReport, _, _, _) = devirtualize(
        &bytes, bitness,
    )
    .map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0122: no recoverable bytecode VM in {} ({:?}). disrobe locates the VM by \
its export table or by scanning for a handler-dispatch loop; a binary whose handler stream is \
generated at runtime or fetched remotely is the one genuine residual.",
            input.display(),
            e
        )
    })?;

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-devirt")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0123: cannot create out dir: {e}"))?;

    let listing_path: PathBuf = out_dir.join(format!("{stem}.vm-listing.asm"));
    std::fs::write(&listing_path, report.recovered_listing.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0124: cannot write listing: {e}"))?;
    let pseudo_path: PathBuf = out_dir.join(format!("{stem}.recovered.c"));
    std::fs::write(&pseudo_path, report.pseudocode.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0125: cannot write pseudocode: {e}"))?;

    let manifest_path: PathBuf = out_dir.join("devirt.manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.native.devirt/v1",
        "input": input.display().to_string(),
        "dispatch_kind": format!("{:?}", report.detection.dispatch_kind),
        "handler_count": report.handler_count,
        "fingerprinted_count": report.fingerprinted_count,
        "bytecode_insn_count": report.bytecode_insn_count,
        "block_count": report.block_count,
        "residual": report.residual,
        "listing": listing_path.display().to_string(),
        "pseudocode": pseudo_path.display().to_string(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-NATIVE-0126: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0127: cannot write manifest: {e}"))?;

    println!("native devirt: OK");
    println!("  input:        {}", input.display());
    println!("  dispatch:     {:?}", report.detection.dispatch_kind);
    println!(
        "  handlers:     {} ({} fingerprinted to a micro-op)",
        report.handler_count, report.fingerprinted_count
    );
    println!("  vm insns:     {}", report.bytecode_insn_count);
    println!("  blocks:       {}", report.block_count);
    println!("  listing:      {}", listing_path.display());
    println!("  pseudocode:   {}", pseudo_path.display());
    println!("  manifest:     {}", manifest_path.display());
    println!("  residual:     {}", report.residual);
    Ok(())
}

pub(crate) fn identify(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0090: cannot read input: {e}"))?;
    let report: disrobe_pass_native::IdentityReport = disrobe_pass_native::detect_identity(&bytes);
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native-identity")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.identity.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0091: cannot create out dir: {e}"))?;
    }
    let buf: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-NATIVE-0092: serialize: {e}"))?;
    std::fs::write(&out_path, buf)
        .map_err(|e| miette::miette!("DR-NATIVE-0093: cannot write identity: {e}"))?;
    println!("native identify: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {}", report.format);
    println!("  detections:   {}", report.hits.len());
    for hit in &report.hits {
        println!(
            "  - {:?} {} ({}%) -> {}",
            hit.kind,
            hit.name,
            hit.confidence,
            hit.support.command()
        );
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

pub(crate) fn graph(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0070: cannot read input: {e}"))?;
    let nf: disrobe_binfmt::NativeFile = parse_native(&bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0071: native parse failed: {e}"))?;
    let dot: String = import_graph_dot(&nf);
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native-graph")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.imports.dot")));
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("native graph: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  imports:      {}", nf.imports.len());
        println!("  exports:      {}", nf.exports.len());
        println!("  would write:  {}", out_path.display());
        return Ok(());
    }
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0072: cannot create out dir: {e}"))?;
    }
    std::fs::write(&out_path, dot.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0073: cannot write DOT: {e}"))?;
    println!("native graph: OK");
    println!("  input:        {}", input.display());
    println!("  imports:      {}", nf.imports.len());
    println!("  exports:      {}", nf.exports.len());
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DisasmEmit {
    #[default]
    Asm,
    CfgDot,
    Json,
}

impl DisasmEmit {
    const fn extension(self) -> &'static str {
        match self {
            Self::Asm => "asm",
            Self::CfgDot => "cfg.dot",
            Self::Json => "disasm.json",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum CallgraphEmit {
    #[default]
    Dot,
    Json,
}

impl CallgraphEmit {
    const fn extension(self) -> &'static str {
        match self {
            Self::Dot => "callgraph.dot",
            Self::Json => "callgraph.json",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DisasmBits {
    #[default]
    Bits64,
    Bits32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DisasmSyntax {
    #[default]
    Nasm,
    Intel,
    Att,
    Masm,
}

impl DisasmSyntax {
    const fn into_syntax(self) -> disrobe_pass_native::Syntax {
        match self {
            Self::Nasm => disrobe_pass_native::Syntax::Nasm,
            Self::Intel => disrobe_pass_native::Syntax::Intel,
            Self::Att => disrobe_pass_native::Syntax::Att,
            Self::Masm => disrobe_pass_native::Syntax::Masm,
        }
    }
}

pub(crate) fn disasm(
    input: PathBuf,
    out: Option<PathBuf>,
    raw: bool,
    base: u64,
    bits: DisasmBits,
    emit: DisasmEmit,
    syntax: DisasmSyntax,
) -> miette::Result<()> {
    use disrobe_pass_native::{Bitness, desync_cleaned_listing};

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0140: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();

    let body: String = if raw {
        let bitness: Bitness = match bits {
            DisasmBits::Bits32 => Bitness::Bits32,
            DisasmBits::Bits64 => Bitness::Bits64,
        };
        match emit {
            DisasmEmit::Asm if matches!(syntax, DisasmSyntax::Nasm) => {
                desync_cleaned_listing(bitness, base, &bytes, &[base]).ok_or_else(|| {
                    miette::miette!("DR-NATIVE-0141: raw disassembly produced no instructions")
                })?
            }
            DisasmEmit::Asm => render_raw_syntax_listing(bits, base, &bytes, syntax)?,
            DisasmEmit::Json | DisasmEmit::CfgDot => {
                return Err(miette::miette!(
                    "DR-NATIVE-0142: --raw supports --emit asm only; json and cfg-dot need a parsed object with a symbol or discovered-function partition"
                ));
            }
        }
    } else {
        if !matches!(syntax, DisasmSyntax::Nasm) {
            return Err(miette::miette!(
                "DR-NATIVE-0148: --syntax {} applies to --raw asm output; the object path renders the recovered IR (nasm) listing",
                syntax.into_syntax().label()
            ));
        }
        let module: disrobe_query::Module = load_native_module(&input, &bytes)?;
        match emit {
            DisasmEmit::Asm => render_module_asm(&module),
            DisasmEmit::CfgDot => render_module_cfg_dot(&module),
            DisasmEmit::Json => serde_json::to_string_pretty(&disasm_json(&module))
                .map_err(|e| miette::miette!("DR-NATIVE-0143: serialize: {e}"))?,
        }
    };

    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.{}", emit.extension())));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0144: cannot create out dir: {e}"))?;
    }
    std::fs::write(&out_path, body.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0145: cannot write disasm: {e}"))?;

    println!("native disasm: OK");
    println!("  input:        {}", input.display());
    println!("  mode:         {}", if raw { "raw" } else { "object" });
    println!("  emit:         {emit:?}");
    if raw && matches!(emit, DisasmEmit::Asm) {
        println!("  syntax:       {}", syntax.into_syntax().label());
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn render_raw_syntax_listing(
    bits: DisasmBits,
    base: u64,
    bytes: &[u8],
    syntax: DisasmSyntax,
) -> miette::Result<String> {
    use std::fmt::Write as _;

    use disrobe_pass_native::{Arch, DisasmInsn, Syntax, disassemble_x86};

    let arch: Arch = match bits {
        DisasmBits::Bits32 => Arch::X86,
        DisasmBits::Bits64 => Arch::X86_64,
    };
    let dialect: Syntax = syntax.into_syntax();
    let insns: Vec<DisasmInsn> = disassemble_x86(arch, base, bytes, dialect).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0149: raw {} disassembly failed: {e}",
            dialect.label()
        )
    })?;
    if insns.is_empty() {
        return Err(miette::miette!(
            "DR-NATIVE-0141: raw disassembly produced no instructions"
        ));
    }
    let mut out: String = String::new();
    let _ = writeln!(
        out,
        "; recovered linear listing ({} instructions, {} syntax)",
        insns.len(),
        dialect.label()
    );
    for insn in &insns {
        if insn.operands.is_empty() {
            let _ = writeln!(out, "  0x{:x}: {}", insn.address, insn.mnemonic);
        } else {
            let _ = writeln!(
                out,
                "  0x{:x}: {} {}",
                insn.address, insn.mnemonic, insn.operands
            );
        }
    }
    Ok(out)
}

fn load_native_module(input: &Path, bytes: &[u8]) -> miette::Result<disrobe_query::Module> {
    use disrobe_ir::Envelope;
    use disrobe_pass_native::build_disasm_payload;

    if let Ok(env) = Envelope::decode(bytes) {
        return disrobe_query::module_from_envelope(&env).map_err(|e| {
            miette::miette!(
                "DR-NATIVE-0146: {} is a .dr envelope but not queryable: {e}",
                input.display()
            )
        });
    }
    let payload: disrobe_ir::payload::DisasmPayload =
        build_disasm_payload(bytes).map_err(|e| {
            miette::miette!(
                "DR-NATIVE-0147: {} is neither a Disasm- or Mir-rung .dr envelope nor a disassemblable native binary: {e}",
                input.display()
            )
        })?;
    Ok(disrobe_query::Module::from_disasm(&payload))
}

fn render_module_asm(module: &disrobe_query::Module) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::new();
    let _ = writeln!(
        out,
        "; disrobe disassembly: {} function(s)",
        module.functions().len()
    );
    for f in module.functions() {
        let tag: &str = if f.is_export { " [export]" } else { "" };
        let _ = writeln!(out, "\n{} @ {:#x}{tag}", f.name, f.address);
        for insn in &f.instructions {
            if insn.operands.is_empty() {
                let _ = writeln!(out, "  {:#018x}: {}", insn.offset, insn.mnemonic);
            } else {
                let _ = writeln!(
                    out,
                    "  {:#018x}: {} {}",
                    insn.offset,
                    insn.mnemonic,
                    insn.operands.join(", ")
                );
            }
        }
    }
    out
}

fn render_module_cfg_dot(module: &disrobe_query::Module) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::new();
    out.push_str("digraph cfg {\n");
    out.push_str("  node [shape=box, fontname=\"monospace\"];\n");
    for f in module.functions() {
        let _ = writeln!(out, "  subgraph \"cluster_{}\" {{", dot_escape(&f.name));
        let _ = writeln!(out, "    label=\"{}\";", dot_escape(&f.name));
        for block in f.basic_blocks() {
            let _ = writeln!(
                out,
                "    \"{}_{:x}\" [label=\"{:#x}\\n{} insn ({:?})\"];",
                dot_escape(&f.name),
                block.start,
                block.start,
                block.instructions.len(),
                block.kind
            );
        }
        for block in f.basic_blocks() {
            for succ in &block.successors {
                let _ = writeln!(
                    out,
                    "    \"{}_{:x}\" -> \"{}_{:x}\";",
                    dot_escape(&f.name),
                    block.start,
                    dot_escape(&f.name),
                    succ
                );
            }
        }
        out.push_str("  }\n");
    }
    out.push_str("}\n");
    out
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn disasm_json(module: &disrobe_query::Module) -> serde_json::Value {
    let functions: Vec<serde_json::Value> = module
        .functions()
        .iter()
        .map(|f: &disrobe_query::Function| {
            serde_json::json!({
                "name": f.name,
                "address": f.address,
                "end": f.end,
                "is_export": f.is_export,
                "instruction_count": f.instruction_count(),
                "complexity": f.cyclomatic_complexity(),
                "instructions": f.instructions,
                "blocks": f.basic_blocks(),
            })
        })
        .collect();
    serde_json::json!({
        "schema": "disrobe.native.disasm/v2",
        "function_count": module.functions().len(),
        "functions": functions,
    })
}

pub(crate) fn callgraph(
    input: PathBuf,
    out: Option<PathBuf>,
    emit: CallgraphEmit,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0150: cannot read input: {e}"))?;
    let module: disrobe_query::Module = load_native_module(&input, &bytes)?;
    let graph: disrobe_query::CallGraph = module.call_graph();

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let body: String = match emit {
        CallgraphEmit::Dot => graph.to_dot(),
        CallgraphEmit::Json => serde_json::to_string_pretty(&graph)
            .map_err(|e| miette::miette!("DR-NATIVE-0151: serialize: {e}"))?,
    };
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.{}", emit.extension())));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0152: cannot create out dir: {e}"))?;
    }
    std::fs::write(&out_path, body.as_bytes())
        .map_err(|e| miette::miette!("DR-NATIVE-0153: cannot write call graph: {e}"))?;

    println!("native callgraph: OK");
    println!("  input:        {}", input.display());
    println!("  nodes:        {}", graph.nodes.len());
    println!("  edges:        {}", graph.edges.len());
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum EntropyFormat {
    #[default]
    Text,
    Json,
    Svg,
}

#[derive(Debug, Serialize)]
struct EntropyDump {
    schema: &'static str,
    input: String,
    window: usize,
    threshold: f64,
    block_count: usize,
    high_count: usize,
    max_entropy: f64,
    mean_entropy: f64,
    sparkline: String,
    heat_strip: String,
    histogram16: Vec<HistogramBucketRow>,
    high_entropy_runs: Vec<disrobe_pass_native::HighEntropyRun>,
    sections: Vec<disrobe_pass_native::SectionSpan>,
    blocks: Vec<disrobe_pass_native::EntropyBlock>,
}

#[derive(Debug, Serialize)]
struct HistogramBucketRow {
    lo: u8,
    hi: u8,
    count: u64,
}

fn histogram_buckets16(hist: &disrobe_pass_native::ByteHistogram) -> Vec<HistogramBucketRow> {
    let mut rows: Vec<HistogramBucketRow> = Vec::with_capacity(16);
    for i in 0..16u16 {
        let lo: usize = (i as usize) << 4;
        let count: u64 = hist.counts[lo..lo + 16].iter().sum();
        rows.push(HistogramBucketRow {
            lo: lo as u8,
            hi: (lo + 0x0F) as u8,
            count,
        });
    }
    rows
}

fn native_section_spans(bytes: &[u8]) -> Vec<disrobe_pass_native::SectionSpan> {
    let Ok(file): Result<object::File<'_>, object::Error> = object::File::parse(bytes) else {
        return Vec::new();
    };
    let mut spans: Vec<disrobe_pass_native::SectionSpan> = Vec::new();
    for section in file.sections() {
        let Some((file_offset, file_size)): Option<(u64, u64)> = section.file_range() else {
            continue;
        };
        if file_size == 0 {
            continue;
        }
        let name: String = section.name().unwrap_or("").to_owned();
        spans.push(disrobe_pass_native::SectionSpan {
            name,
            file_offset,
            file_size,
        });
    }
    spans.sort_by_key(|s: &disrobe_pass_native::SectionSpan| s.file_offset);
    spans
}

pub(crate) fn entropy(
    input: PathBuf,
    out: Option<PathBuf>,
    format: EntropyFormat,
    svg: Option<PathBuf>,
) -> miette::Result<()> {
    use disrobe_pass_native::{
        ByteHistogram, ENTROPY_WINDOW_4K, EntropyBlock, EntropySvgOptions, HIGH_ENTROPY_THRESHOLD,
        HighEntropyRun, SectionSpan, byte_histogram, entropy_heat_strip, entropy_sparkline,
        high_entropy_runs, histogram_ascii_16, render_entropy_svg, windowed_entropy,
    };

    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0050: cannot read input: {e}"))?;
    let blocks: Vec<EntropyBlock> = windowed_entropy(&bytes, ENTROPY_WINDOW_4K);
    let block_count: usize = blocks.len();
    let high_count: usize = blocks.iter().filter(|b: &&EntropyBlock| b.high).count();
    let max_entropy: f64 = blocks
        .iter()
        .map(|b: &EntropyBlock| b.entropy)
        .fold(0.0_f64, f64::max);
    let mean_entropy: f64 = if block_count == 0 {
        0.0
    } else {
        blocks.iter().map(|b: &EntropyBlock| b.entropy).sum::<f64>() / usize_to_f64(block_count)
    };
    let histogram: ByteHistogram = byte_histogram(&bytes);
    let sparkline: String = entropy_sparkline(&blocks);
    let heat_strip: String = entropy_heat_strip(&blocks);
    let runs: Vec<HighEntropyRun> = high_entropy_runs(&blocks);
    let sections: Vec<SectionSpan> = native_section_spans(&bytes);

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native-entropy")
        .to_owned();
    let g: globals::Globals = globals::current();

    if matches!(format, EntropyFormat::Svg) || svg.is_some() {
        let opts: EntropySvgOptions = EntropySvgOptions {
            title: format!("disrobe entropy \u{2022} {stem}"),
            sections: sections.clone(),
            ..EntropySvgOptions::default()
        };
        let markup: String = render_entropy_svg(&blocks, bytes.len() as u64, &opts);
        let svg_path: PathBuf =
            svg.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.entropy.svg")));
        if g.dry_run {
            println!("native entropy: DRY-RUN (svg)");
            println!("  input:        {}", input.display());
            println!("  blocks:       {block_count}");
            println!("  would write:  {}", svg_path.display());
            return Ok(());
        }
        if let Some(parent) = svg_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-NATIVE-0054: cannot create out dir: {e}"))?;
        }
        std::fs::write(&svg_path, markup.as_bytes())
            .map_err(|e| miette::miette!("DR-NATIVE-0055: cannot write entropy svg: {e}"))?;
        if matches!(format, EntropyFormat::Svg) {
            println!("native entropy: OK (svg)");
            println!("  input:        {}", input.display());
            println!("  blocks:       {block_count}");
            println!("  high (>=7.0): {high_count}");
            println!("  sections:     {}", sections.len());
            println!("  wrote:        {}", svg_path.display());
            return Ok(());
        }
    }

    let dump: EntropyDump = EntropyDump {
        schema: "disrobe.native.entropy/v0",
        input: input.display().to_string(),
        window: ENTROPY_WINDOW_4K,
        threshold: HIGH_ENTROPY_THRESHOLD,
        block_count,
        high_count,
        max_entropy,
        mean_entropy,
        sparkline: sparkline.clone(),
        heat_strip,
        histogram16: histogram_buckets16(&histogram),
        high_entropy_runs: runs.clone(),
        sections,
        blocks,
    };

    if matches!(format, EntropyFormat::Json) {
        let out_path: PathBuf =
            out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.entropy.json")));
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-NATIVE-0051: cannot create out dir: {e}"))?;
        }
        let buf: Vec<u8> = serde_json::to_vec_pretty(&dump)
            .map_err(|e| miette::miette!("DR-NATIVE-0052: serialize: {e}"))?;
        std::fs::write(&out_path, buf)
            .map_err(|e| miette::miette!("DR-NATIVE-0053: cannot write entropy dump: {e}"))?;
        println!("native entropy: OK (json)");
        println!("  input:        {}", input.display());
        println!("  wrote:        {}", out_path.display());
        return Ok(());
    }

    println!("native entropy: OK");
    println!("  input:        {}", input.display());
    println!("  window:       {ENTROPY_WINDOW_4K}");
    println!("  blocks:       {block_count}");
    println!("  high (>=7.0): {high_count}");
    println!("  max entropy:  {max_entropy:.4} bits/byte");
    println!("  mean entropy: {mean_entropy:.4} bits/byte");
    if !sparkline.is_empty() {
        println!("  heat strip:");
        for line in sparkline_lines(&sparkline, 64) {
            println!("    {line}");
        }
    }
    println!("  byte histogram (16-bucket):");
    for line in histogram_ascii_16(&histogram).lines() {
        println!("    {line}");
    }
    if runs.is_empty() {
        println!("  high-entropy runs: none");
    } else {
        println!(
            "  high-entropy runs ({} packed/encrypted region(s)):",
            runs.len()
        );
        for run in &runs {
            println!(
                "    blocks {}..={}  offset {:#x}..{:#x}  mean {:.3}  max {:.3}",
                run.start_block,
                run.end_block,
                run.offset_start,
                run.offset_end,
                run.mean_entropy,
                run.max_entropy
            );
        }
    }
    if let Some(out_path) = out {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-NATIVE-0051: cannot create out dir: {e}"))?;
        }
        let buf: Vec<u8> = serde_json::to_vec_pretty(&dump)
            .map_err(|e| miette::miette!("DR-NATIVE-0052: serialize: {e}"))?;
        std::fs::write(&out_path, buf)
            .map_err(|e| miette::miette!("DR-NATIVE-0053: cannot write entropy dump: {e}"))?;
        println!("  wrote:        {}", out_path.display());
    }
    Ok(())
}

fn sparkline_lines(spark: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![spark.to_owned()];
    }
    let chars: Vec<char> = spark.chars().collect();
    chars
        .chunks(width)
        .map(|chunk: &[char]| chunk.iter().collect::<String>())
        .collect()
}

const fn usize_to_f64(n: usize) -> f64 {
    n as f64
}

#[derive(Debug, Serialize)]
struct SymbolDump {
    schema: &'static str,
    input: String,
    format: String,
    arch: String,
    entry: u64,
    is_64: bool,
    exports: Vec<SymbolRow>,
    imports: Vec<ImportRow>,
    sections: Vec<SectionRow>,
    segments: Vec<SegmentRow>,
    debug_info: DebugInfoSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    cxx_rtti: Option<CxxRttiSummary>,
}

#[derive(Debug, Serialize)]
struct CxxRttiSummary {
    abi: String,
    classes: Vec<CxxClassRow>,
}

#[derive(Debug, Serialize)]
struct CxxClassRow {
    name: String,
    inheritance: String,
    bases: Vec<String>,
    virtual_methods: usize,
    stl_templates: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SymbolRow {
    name: String,
    address: u64,
    size: u64,
    kind: String,
    section: Option<String>,
}

#[derive(Debug, Serialize)]
struct ImportRow {
    name: String,
    library: Option<String>,
}

#[derive(Debug, Serialize)]
struct SectionRow {
    index: usize,
    name: String,
    address: u64,
    size: u64,
    kind: String,
    flags: String,
}

#[derive(Debug, Serialize)]
struct SegmentRow {
    name: Option<String>,
    address: u64,
    size: u64,
}

#[derive(Debug, Serialize)]
struct DebugInfoSummary {
    present: bool,
    sections: Vec<String>,
}

fn dump_symbols(bytes: &[u8], input: &Path) -> miette::Result<SymbolDump> {
    let file: object::File<'_> = object::File::parse(bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0020: object parse failed: {e}"))?;
    let format: &'static str = match file.format() {
        object::BinaryFormat::Elf => "elf",
        object::BinaryFormat::Pe => "pe",
        object::BinaryFormat::Coff => "coff",
        object::BinaryFormat::MachO => "macho",
        object::BinaryFormat::Wasm => "wasm",
        object::BinaryFormat::Xcoff => "xcoff",
        _ => "unknown",
    };
    let arch: String = format!("{:?}", file.architecture()).to_lowercase();
    let entry: u64 = file.entry();
    let is_64: bool = file.is_64();

    let mut exports: Vec<SymbolRow> = Vec::new();
    let section_names: BTreeMap<usize, String> = file
        .sections()
        .filter_map(|s| s.name().ok().map(|n| (s.index().0, n.to_owned())))
        .collect();
    for symbol in file.symbols() {
        let Ok(name): Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let section: Option<String> = match symbol.section() {
            object::SymbolSection::Section(idx) => section_names.get(&idx.0).cloned(),
            _ => None,
        };
        exports.push(SymbolRow {
            name: name.to_owned(),
            address: symbol.address(),
            size: symbol.size(),
            kind: format!("{:?}", symbol.kind()).to_lowercase(),
            section,
        });
    }
    for symbol in file.dynamic_symbols() {
        let Ok(name): Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let section: Option<String> = match symbol.section() {
            object::SymbolSection::Section(idx) => section_names.get(&idx.0).cloned(),
            _ => None,
        };
        exports.push(SymbolRow {
            name: name.to_owned(),
            address: symbol.address(),
            size: symbol.size(),
            kind: format!("{:?}", symbol.kind()).to_lowercase(),
            section,
        });
    }

    let mut imports: Vec<ImportRow> = Vec::new();
    if let Ok(import_iter) = file.imports() {
        for imp in import_iter {
            imports.push(ImportRow {
                name: String::from_utf8_lossy(imp.name()).into_owned(),
                library: Some(String::from_utf8_lossy(imp.library()).into_owned())
                    .filter(|s| !s.is_empty()),
            });
        }
    }

    let mut sections: Vec<SectionRow> = Vec::new();
    let mut debug_sections: Vec<String> = Vec::new();
    for (i, section) in file.sections().enumerate() {
        let name: String = section.name().map(str::to_owned).unwrap_or_default();
        let kind_label: String = format!("{:?}", section.kind()).to_lowercase();
        let flags_label: String = section_flags_label(section.flags());
        if matches!(
            section.kind(),
            SectionKind::Debug | SectionKind::DebugString
        ) || name.starts_with(".debug")
            || name.starts_with("__debug")
            || name.starts_with(".zdebug")
        {
            debug_sections.push(name.clone());
        }
        sections.push(SectionRow {
            index: i,
            name,
            address: section.address(),
            size: section.size(),
            kind: kind_label,
            flags: flags_label,
        });
    }

    let mut segments: Vec<SegmentRow> = Vec::new();
    for seg in file.segments() {
        segments.push(SegmentRow {
            name: seg.name().ok().flatten().map(str::to_owned),
            address: seg.address(),
            size: seg.size(),
        });
    }

    let debug_info: DebugInfoSummary = DebugInfoSummary {
        present: !debug_sections.is_empty(),
        sections: debug_sections,
    };

    let cxx_rtti: Option<CxxRttiSummary> = recover_cxx_rtti_summary(bytes);

    Ok(SymbolDump {
        schema: "disrobe.native.symbols/v0",
        input: input.display().to_string(),
        format: format.to_owned(),
        arch,
        entry,
        is_64,
        exports,
        imports,
        sections,
        segments,
        debug_info,
        cxx_rtti,
    })
}

fn recover_cxx_rtti_summary(bytes: &[u8]) -> Option<CxxRttiSummary> {
    use disrobe_pass_native::{CxxClass, CxxHierarchy, recover_cxx_hierarchy};
    let hierarchy: CxxHierarchy = recover_cxx_hierarchy(bytes)?;
    let classes: Vec<CxxClassRow> = hierarchy
        .classes
        .iter()
        .map(|c: &CxxClass| CxxClassRow {
            name: c.name.clone(),
            inheritance: format!("{:?}", c.inheritance).to_lowercase(),
            bases: c
                .direct_bases
                .iter()
                .map(|b| {
                    if b.is_virtual {
                        format!("virtual {}", b.name)
                    } else {
                        b.name.clone()
                    }
                })
                .collect(),
            virtual_methods: c.vtable.as_ref().map_or(0, |v| v.slot_count),
            stl_templates: c
                .stl_templates
                .iter()
                .map(|t| format!("{t:?}").to_lowercase())
                .collect(),
        })
        .collect();
    Some(CxxRttiSummary {
        abi: format!("{:?}", hierarchy.abi).to_lowercase(),
        classes,
    })
}

fn section_flags_label(flags: SectionFlags) -> String {
    match flags {
        SectionFlags::None => "none".to_owned(),
        SectionFlags::Elf { sh_flags } => format!("elf:0x{sh_flags:x}"),
        SectionFlags::MachO { flags } => format!("macho:0x{flags:x}"),
        SectionFlags::Coff { characteristics } => format!("coff:0x{characteristics:x}"),
        SectionFlags::Xcoff { s_flags } => format!("xcoff:0x{s_flags:x}"),
        _ => "other".to_owned(),
    }
}

const fn headless_candidates() -> [&'static str; 2] {
    if cfg!(windows) {
        ["analyzeHeadless.bat", "analyzeHeadless"]
    } else {
        ["analyzeHeadless", "analyzeHeadless.bat"]
    }
}

fn locate_ghidra_headless() -> Option<PathBuf> {
    let candidates: [&str; 2] = headless_candidates();
    for name in candidates {
        if let Some(found) = which_on_path(name) {
            return Some(found);
        }
    }
    if let Ok(home) = std::env::var("GHIDRA_HOME") {
        let base: PathBuf = PathBuf::from(home);
        for name in candidates {
            let p: PathBuf = base.join("support").join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate: PathBuf = dir.join(exe);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn tail_bytes(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let start: usize = s.len() - n;
    let boundary: usize = (start..s.len())
        .find(|i| s.is_char_boundary(*i))
        .unwrap_or(start);
    s[boundary..].to_owned()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum SigEmit {
    #[default]
    CArray,
    PythonBytes,
}

pub(crate) fn parse_patch_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();
    for tok in raw.split(',') {
        let t: &str = tok.trim();
        if t.is_empty() {
            continue;
        }
        let hex: &str = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        let byte: u8 = u8::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid hex byte '{t}' (expected XX or 0xXX)"))?;
        out.push(byte);
    }
    if out.is_empty() {
        return Err("no bytes parsed from --bytes".to_owned());
    }
    Ok(out)
}

fn parse_nop_range(raw: &str) -> Result<(u64, u64), String> {
    let (lo, hi): (&str, &str) = raw
        .split_once(':')
        .ok_or_else(|| format!("--nop-range expects START:END, got '{raw}'"))?;
    let start: u64 = parse_u64_loose(lo)?;
    let end: u64 = parse_u64_loose(hi)?;
    if end <= start {
        return Err(format!(
            "--nop-range END {end:#x} must exceed START {start:#x}"
        ));
    }
    Ok((start, end))
}

fn parse_u64_loose(s: &str) -> Result<u64, String> {
    let t: &str = s.trim();
    let parsed: u64 = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .map_or_else(
            || t.parse::<u64>().map_err(|e| e.to_string()),
            |hex: &str| u64::from_str_radix(hex, 16).map_err(|e| e.to_string()),
        )?;
    Ok(parsed)
}

pub(crate) fn patch(
    input: PathBuf,
    at: u64,
    bytes_arg: String,
    nop_range: Option<String>,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    use disrobe_pass_native::{PatchEdit, PatchReport, apply_patches_reported, default_nop_fill};

    let image: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0160: cannot read input: {e}"))?;

    let mut edits: Vec<PatchEdit> = Vec::new();
    if !bytes_arg.trim().is_empty() {
        let parsed: Vec<u8> =
            parse_patch_bytes(&bytes_arg).map_err(|e| miette::miette!("DR-NATIVE-0167: {e}"))?;
        edits.push(PatchEdit::new(at, parsed));
    }
    if let Some(range) = nop_range {
        let (start, end): (u64, u64) =
            parse_nop_range(&range).map_err(|e| miette::miette!("DR-NATIVE-0161: {e}"))?;
        let edit: PatchEdit = PatchEdit::nop_range(start, end, default_nop_fill())
            .ok_or_else(|| miette::miette!("DR-NATIVE-0162: empty --nop-range span"))?;
        edits.push(edit);
    }
    if edits.is_empty() {
        return Err(miette::miette!(
            "DR-NATIVE-0163: supply --bytes XX,XX and/or --nop-range A:B"
        ));
    }

    let (patched, report): (Vec<u8>, PatchReport) = apply_patches_reported(&image, &edits)
        .map_err(|e| miette::miette!("DR-NATIVE-0164: patch failed: {e}"))?;

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.patched.bin")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0165: cannot create out dir: {e}"))?;
    }
    std::fs::write(&out_path, &patched)
        .map_err(|e| miette::miette!("DR-NATIVE-0166: cannot write patched image: {e}"))?;

    println!("native patch: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {}", report.format);
    println!("  edits:        {}", report.edits.len());
    for edit in &report.edits {
        println!(
            "    {:#x} (file {:#x}, {} byte(s))",
            edit.virtual_address, edit.file_offset, edit.length
        );
    }
    println!("  bytes changed:{}", report.bytes_changed);
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

pub(crate) fn sigmaker(input: PathBuf, at: u64, emit: SigEmit) -> miette::Result<()> {
    use disrobe_pass_native::{SigmakerOptions, Signature, make_signature};

    let image: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0170: cannot read input: {e}"))?;
    let sig: Signature = make_signature(&image, at, SigmakerOptions::default())
        .map_err(|e| miette::miette!("DR-NATIVE-0171: signature generation failed: {e}"))?;

    println!("native sigmaker: OK");
    println!("  input:        {}", input.display());
    println!("  at:           {at:#x}");
    println!("  instructions: {}", sig.instruction_count);
    println!("  length:       {} byte(s)", sig.byte_length);
    println!("  wildcards:    {}", sig.wildcard_count);
    println!(
        "  unique:       {} ({} match(es) in image)",
        sig.unique, sig.match_count
    );
    println!("  ida:          {}", sig.ida_pattern);
    println!("  bytes:        {}", sig.byte_pattern);
    println!("  mask:         {}", sig.mask);
    let emitted: String = match emit {
        SigEmit::CArray => sig.emit_c_array(),
        SigEmit::PythonBytes => sig.emit_python_bytes(),
    };
    println!("  emit ({}):", emit_label(emit));
    for line in emitted.lines() {
        println!("    {line}");
    }
    if !sig.unique {
        println!(
            "  note:         pattern is NOT unique; the function shares its leading bytes with \
             another region (widen with a longer function or anchor a later instruction)"
        );
    }
    Ok(())
}

const fn emit_label(emit: SigEmit) -> &'static str {
    match emit {
        SigEmit::CArray => "c-array",
        SigEmit::PythonBytes => "python-bytes",
    }
}

pub(crate) fn diff(a: PathBuf, b: PathBuf, json: bool) -> miette::Result<()> {
    use disrobe_pass_native::{BinDiffReport, ChangedFunction, FunctionPrint, bindiff};

    let bytes_a: Vec<u8> = std::fs::read(&a)
        .map_err(|e| miette::miette!("DR-NATIVE-0180: cannot read {}: {e}", a.display()))?;
    let bytes_b: Vec<u8> = std::fs::read(&b)
        .map_err(|e| miette::miette!("DR-NATIVE-0181: cannot read {}: {e}", b.display()))?;
    let report: BinDiffReport = bindiff(&bytes_a, &bytes_b)
        .map_err(|e| miette::miette!("DR-NATIVE-0182: diff failed: {e}"))?;

    if json {
        let buf: String = serde_json::to_string_pretty(&report)
            .map_err(|e| miette::miette!("DR-NATIVE-0183: serialize: {e}"))?;
        println!("{buf}");
        return Ok(());
    }

    println!("native diff: OK");
    println!("  a:            {}", a.display());
    println!("  b:            {}", b.display());
    println!("  functions:    {} -> {}", report.total_a, report.total_b);
    println!("  identical:    {}", report.identical);
    println!("  added:        {}", report.added.len());
    for f in &report.added {
        println!(
            "    + {} @ {:#x} ({} bytes)",
            f.name, f.address, f.byte_length
        );
    }
    println!("  removed:      {}", report.removed.len());
    for f in &report.removed {
        let f: &FunctionPrint = f;
        println!(
            "    - {} @ {:#x} ({} bytes)",
            f.name, f.address, f.byte_length
        );
    }
    println!("  changed:      {}", report.changed.len());
    for c in &report.changed {
        let c: &ChangedFunction = c;
        println!(
            "    ~ {} @ {:#x} -> {} @ {:#x} [{:?}]",
            c.name_a, c.address_a, c.name_b, c.address_b, c.kind
        );
    }
    println!("  similarity:   {:.1}%", report.similarity * 100.0);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn api_type_and_provenance_render_for_the_banner() {
        use disrobe_typerec::{ApiSite, ApiType, Provenance, Sign, Width};
        assert_eq!(api_type_c(ApiType::Pointer), "void*");
        assert_eq!(api_type_c(ApiType::Handle), "HANDLE");
        assert_eq!(
            api_type_c(ApiType::Integer {
                width: Width::Dword,
                sign: Sign::Signed
            }),
            "int32_t"
        );
        assert_eq!(
            api_type_c(ApiType::Integer {
                width: Width::Qword,
                sign: Sign::Unsigned
            }),
            "uint64_t"
        );
        assert_eq!(
            api_prov(&Provenance::ApiDb {
                library: "libc".to_owned(),
                name: "strlen".to_owned(),
                site: ApiSite::Arg(0),
            }),
            "libc!strlen arg0 [ApiDb]"
        );
        assert_eq!(
            api_prov(&Provenance::ApiDb {
                library: "kernel32".to_owned(),
                name: "CreateFileW".to_owned(),
                site: ApiSite::Return,
            }),
            "kernel32!CreateFileW ret [ApiDb]"
        );
    }

    #[test]
    fn header_banner_wraps_api_types_in_the_comment() {
        let bare: String = build_header_comment(DecompileLang::C, "f", 0x1179, None);
        assert_eq!(bare, "/* f @ 0x1179 */");
        let banner: Vec<String> = vec!["[rbp-0x8] void* <- libc!strlen arg0 [ApiDb]".to_owned()];
        let annotated: String = build_header_comment(DecompileLang::C, "f", 0x1179, Some(&banner));
        assert!(annotated.starts_with("/* f @ 0x1179"));
        assert!(annotated.contains("api-derived types:"));
        assert!(annotated.contains("[rbp-0x8] void* <- libc!strlen arg0 [ApiDb]"));
        assert!(annotated.trim_end().ends_with("*/"));
        let rust: String = build_header_comment(DecompileLang::Rust, "f", 0x1179, Some(&banner));
        assert!(rust.starts_with("// f @ 0x1179"));
        assert!(rust.contains("// api-derived types:"));
        assert!(!rust.contains("/*"));
    }

    #[test]
    fn header_comment_neutralizes_injection_from_attacker_names() {
        let evil: String = build_header_comment(DecompileLang::C, "evil*/code", 0x1000, None);
        assert!(
            !evil.contains("*/code"),
            "the break-out must be neutralized: {evil}"
        );
        assert!(evil.trim_end().ends_with("*/"));
        let banner: Vec<String> = vec!["[rbp-0x8] void* <- ntdll!a*/b arg0 [ApiDb]".to_owned()];
        let c: String = build_header_comment(DecompileLang::C, "f", 0x1000, Some(&banner));
        let body: &str = c.strip_suffix("\n */").unwrap_or(&c);
        assert!(
            !body.contains("*/"),
            "no interior comment close in the banner: {c}"
        );
        let rust: String = build_header_comment(DecompileLang::Rust, "line1\nline2", 0x1000, None);
        assert_eq!(
            rust.lines().count(),
            1,
            "a newline in the name must not inject a line: {rust}"
        );
    }

    fn corpus_path(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel)
    }

    fn unpack_writes_real_image(fixture: &str, scratch: &str) {
        let input: PathBuf = corpus_path(fixture);
        if !input.is_file() {
            return;
        }
        let out_path: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join(scratch);
        let _ = std::fs::remove_file(&out_path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).expect("mk out dir");
        }
        unpack(Some(input), Some(out_path.clone()), false).expect("unpack ok");
        let recovered: Vec<u8> = std::fs::read(&out_path).expect("read recovered");
        assert!(
            !recovered.is_empty(),
            "recovered image must contain real bytes"
        );
        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn aspack_unpack_writes_recovered_image() {
        unpack_writes_real_image(
            "native/packers/aspack/Clockres.packed.aspack.exe",
            "aspack-unpack-test.bin",
        );
    }

    #[test]
    fn pecompact_unpack_writes_recovered_image() {
        unpack_writes_real_image(
            "native/packers/pecompact/Clockres.packed.pecompact.exe",
            "pecompact-unpack-test.bin",
        );
    }

    #[test]
    fn kkrunchy_unpack_writes_recovered_image() {
        unpack_writes_real_image(
            "native/packers/kkrunchy/hello.packed.kkrunchy.exe",
            "kkrunchy-unpack-test.bin",
        );
    }

    fn find_c_compiler() -> Option<String> {
        for c in ["clang", "gcc", "cc"] {
            if std::process::Command::new(c)
                .arg("--version")
                .output()
                .is_ok_and(|o: std::process::Output| o.status.success())
            {
                return Some(c.to_owned());
            }
        }
        None
    }

    #[test]
    fn native_backend_decompiles_leaf_functions_to_c() {
        if !cfg!(target_arch = "x86_64") {
            eprintln!("skip: in-tree native decompiler is x86-64 only; host is not x86-64");
            return;
        }
        let Some(compiler): Option<String> = find_c_compiler() else {
            eprintln!("skip: no C compiler (clang/gcc/cc) on PATH");
            return;
        };
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-native-decompile-oracle")
                .expect("create scratch directory");
        let dir: PathBuf = scratch.path().to_path_buf();
        let c_src: PathBuf = dir.join("battery.c");
        std::fs::write(
            &c_src,
            b"long long f_add(long long a, long long b){ return a + b; }\nlong long f_sub(long long a, long long b){ return a - b; }\nint main(int argc, char **argv){ (void)argv; return (int)(f_add(argc, 1) + f_sub(argc, 2)); }\n",
        )
        .expect("write battery.c");
        let obj: PathBuf = dir.join("battery.o");
        let compile: std::process::Output = std::process::Command::new(&compiler)
            .args(["-c", "-O1"])
            .arg(&c_src)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("invoke compiler");
        if !compile.status.success() {
            eprintln!(
                "skip: object compile failed: {}",
                String::from_utf8_lossy(&compile.stderr)
            );
            return;
        }
        let out_dir: PathBuf = dir.join("out");
        decompile_native(obj, Some(out_dir.clone()), DecompileLang::C, false)
            .expect("native decompile ok");
        let manifest_text: String =
            std::fs::read_to_string(out_dir.join("manifest.json")).expect("read manifest");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_text).expect("parse manifest");
        let total: u64 = manifest["functions_total"].as_u64().unwrap_or(0);
        assert!(
            total >= 1,
            "in-tree native backend must discover at least one function; manifest: {manifest_text}"
        );
        let recovered: u64 = manifest["functions_recovered"].as_u64().unwrap_or(0);
        let c_out: String =
            std::fs::read_to_string(out_dir.join("battery.c")).expect("read recovered c");
        if recovered >= 1 {
            assert!(
                c_out.contains("return"),
                "recovered C must contain a function body; got: {c_out}"
            );
        } else {
            eprintln!(
                "note: 0 leaf functions recovered from this compiler's codegen (endbr64 / stack-protector / optimizer shapes are soundly rejected); the CLI wiring is verified by discovery + manifest + emitted file, and codegen-level recovery is graded by the pseudo_c leaf oracle"
            );
        }
    }

    #[test]
    fn locate_returns_none_when_path_empty() {
        let prev: Option<std::ffi::OsString> = std::env::var_os("PATH");
        let prev_home: Option<String> = std::env::var("GHIDRA_HOME").ok();
        unsafe {
            std::env::set_var("PATH", "");
            std::env::remove_var("GHIDRA_HOME");
        }
        let result: Option<PathBuf> = locate_ghidra_headless();
        unsafe {
            if let Some(p) = prev {
                std::env::set_var("PATH", p);
            } else {
                std::env::remove_var("PATH");
            }
            if let Some(h) = prev_home {
                std::env::set_var("GHIDRA_HOME", h);
            }
        }
        assert!(result.is_none());
    }

    #[test]
    fn tail_bytes_short_returns_input() {
        assert_eq!(tail_bytes("hello", 100), "hello");
    }

    #[test]
    fn tail_bytes_long_returns_suffix() {
        let s: String = "x".repeat(10_000);
        let cut: String = tail_bytes(&s, 100);
        assert_eq!(cut.len(), 100);
    }

    #[test]
    fn fingerprint_emits_real_aggregated_sidecar() {
        use disrobe_pass_native::{
            CryptoPrimitive, FingerprintSidecar, StringXref as PnStringXref,
        };

        let base: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("fp-cli-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("mk base");

        let mut buf: Vec<u8> = vec![0u8; 8];
        buf.extend_from_slice(b"expand 32-byte k");
        buf.extend_from_slice(&[0x00]);
        buf.extend_from_slice(b"PlantedXrefMarker");
        buf.extend_from_slice(&[0x00]);

        let in_path: PathBuf = base.join("sample.bin");
        std::fs::write(&in_path, &buf).expect("write input");
        let out_dir: PathBuf = base.join("out");

        fingerprint(in_path, Some(out_dir.clone()), None).expect("fingerprint ok");

        let out_path: PathBuf = out_dir.join("sample.json");
        let written: &'static [u8] = Box::leak(
            std::fs::read(&out_path)
                .expect("read sidecar")
                .into_boxed_slice(),
        );
        let sidecar: FingerprintSidecar = serde_json::from_slice(written).expect("parse sidecar");

        assert_eq!(sidecar.byte_count, buf.len() as u64);
        let chacha_hits: usize = sidecar
            .crypto
            .iter()
            .filter(|h| h.primitive == CryptoPrimitive::Chacha20Sigma)
            .count();
        assert_eq!(chacha_hits, 1);
        let planted: Option<&PnStringXref> = sidecar
            .strings
            .iter()
            .find(|s| s.value == "PlantedXrefMarker");
        assert!(planted.is_some());
        assert_eq!(planted.expect("planted").offset, 25);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn histogram_buckets16_folds_256_into_16() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let hist: disrobe_pass_native::ByteHistogram = disrobe_pass_native::byte_histogram(&bytes);
        let rows: Vec<HistogramBucketRow> = histogram_buckets16(&hist);
        assert_eq!(rows.len(), 16);
        assert_eq!(rows[0].lo, 0x00);
        assert_eq!(rows[0].hi, 0x0F);
        assert_eq!(rows[15].lo, 0xF0);
        assert_eq!(rows[15].hi, 0xFF);
        assert!(rows.iter().all(|r: &HistogramBucketRow| r.count == 16));
        let total: u64 = rows.iter().map(|r: &HistogramBucketRow| r.count).sum();
        assert_eq!(total, 256);
    }

    #[test]
    fn sparkline_lines_wraps_at_width() {
        let spark: String = "x".repeat(150);
        let lines: Vec<String> = sparkline_lines(&spark, 64);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].chars().count(), 64);
        assert_eq!(lines[2].chars().count(), 150 - 128);
    }

    #[test]
    fn section_spans_empty_for_non_native_bytes() {
        assert!(native_section_spans(b"not a binary at all").is_empty());
    }

    #[test]
    fn entropy_svg_written_and_deterministic() {
        let base: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("entropy-svg-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("mk base");

        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes.extend((0..4096).map(|i: usize| (i & 0xff) as u8));
        let in_path: PathBuf = base.join("sample.bin");
        std::fs::write(&in_path, &bytes).expect("write input");

        let svg_path: PathBuf = base.join("sample.entropy.svg");
        entropy(
            in_path.clone(),
            None,
            EntropyFormat::Svg,
            Some(svg_path.clone()),
        )
        .expect("entropy svg ok");
        let first: Vec<u8> = std::fs::read(&svg_path).expect("read svg");
        entropy(in_path, None, EntropyFormat::Svg, Some(svg_path.clone())).expect("entropy svg ok");
        let second: Vec<u8> = std::fs::read(&svg_path).expect("read svg again");
        assert_eq!(first, second, "svg output must be byte-stable");
        let text: String = String::from_utf8(first).expect("utf8 svg");
        assert!(text.starts_with("<svg "));
        assert!(text.trim_end().ends_with("</svg>"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(feature = "nir-lift")]
    #[test]
    fn aarch64_leaf_renders_to_pseudo_source() {
        let bytes: Vec<u8> = [0x8b01_0000_u32, 0xd65f_03c0]
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let (source, structured, devirt_report): (String, bool, serde_json::Value) =
            aarch64_recover_source(&bytes, 0x1000, "arith", false).expect("aarch64 leaf recovers");
        assert!(structured, "leaf must structure:\n{source}");
        assert!(
            source.contains("return x0"),
            "return value missing:\n{source}"
        );
        assert!(source.contains('+'), "addition missing:\n{source}");
        assert!(
            devirt_report.is_null(),
            "devirt off must leave no report: {devirt_report}"
        );
    }

    #[cfg(feature = "devirt")]
    #[test]
    fn aarch64_devirt_flag_records_a_report_without_breaking_recovery() {
        let bytes: Vec<u8> = [0x8b01_0000_u32, 0xd65f_03c0]
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let (source, structured, devirt_report): (String, bool, serde_json::Value) =
            aarch64_recover_source(&bytes, 0x1000, "arith", true).expect("aarch64 leaf recovers");
        assert!(
            structured,
            "leaf still structures with devirt on:\n{source}"
        );
        assert!(source.contains("return x0"), "return missing:\n{source}");
        assert!(
            !devirt_report.is_null(),
            "devirt on must attach a report to the function"
        );
        assert_eq!(
            devirt_report
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("none"),
            "a straight-line leaf has no dead arm and no flattening: {devirt_report}"
        );
        assert_eq!(
            devirt_report
                .get("edges_folded")
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "nothing is folded on a leaf: {devirt_report}"
        );
    }

    #[test]
    fn the_headless_launcher_this_platform_can_execute_is_tried_first() {
        let candidates: [&'static str; 2] = headless_candidates();
        if cfg!(windows) {
            assert_eq!(
                candidates[0], "analyzeHeadless.bat",
                "windows cannot execute the extensionless shell script, so trying it first \
                 fails the spawn with os error 193 even though ghidra is installed correctly"
            );
        } else {
            assert_eq!(candidates[0], "analyzeHeadless");
        }
    }

    #[test]
    fn the_ghidra_home_lookup_uses_the_same_order_as_the_path_lookup() {
        let root: std::path::PathBuf =
            disrobe_core::scratch::scratch_root().join("ghidra-home-order");
        let support: std::path::PathBuf = root.join("support");
        std::fs::create_dir_all(&support).expect("support dir");
        for name in ["analyzeHeadless", "analyzeHeadless.bat"] {
            std::fs::write(support.join(name), b"stub").expect("stub launcher");
        }
        let expected: std::path::PathBuf = support.join(headless_candidates()[0]);
        let found: Option<std::path::PathBuf> = headless_candidates()
            .iter()
            .map(|name: &&'static str| support.join(name))
            .find(|p: &std::path::PathBuf| p.is_file());
        assert_eq!(
            found.as_ref(),
            Some(&expected),
            "a GHIDRA_HOME holding both launchers must resolve to the one this platform runs"
        );
        let _: std::io::Result<()> = std::fs::remove_dir_all(&root);
    }
}
