#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_jvm::{
    AndroidBackend, AppliedNames, BackendCapability, BackendInvocation, CLASS_MAGIC, ClassFile,
    DEX_MAGIC_PREFIX, DecompiledClass, DecompiledDex, DexFile, DexStringRecovery,
    FingerprintReport, Instruction, JarExtract, JvmBackend, LibrarySignatureSet, Operands,
    PeelStatus, PeeledClass, ProguardMapping, ProtectorPeelReport, RetracedFrame,
    apply_proguard_mapping, decompile_class, decompile_dex, detect_available,
    detect_protector_family, disassemble, extract_jar, fingerprint_library_symbols, invoke_android,
    invoke_jvm, parse_classfile, parse_code_attribute, parse_dex, parse_proguard_mapping,
    peel_and_decompile_classfile, recover_dex_reflection_strings,
};
use std::fmt::Write as _;

use super::emit::{EmitKind, EmitSpec};
use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum JvmCmd {
    #[command(
        about = "decompile a .class / .jar / .dex / .apk through a JVM/Android backend (CFR, Vineflower, Procyon, JADX, ...)"
    )]
    Decompile {
        #[arg(help = "input .class / .jar / .dex / .apk file")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-jvm)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = JvmBackendKind::Auto,
            help = "decompiler backend; defaults to the first available on PATH"
        )]
        backend: JvmBackendKind,
        #[arg(long, default_value_t = 300, help = "per-backend timeout in seconds")]
        timeout_secs: u64,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
        #[arg(
            long,
            help = "apply a ProGuard/R8 mapping.txt to restore original class/method/field names; writes name-restoration.json"
        )]
        mapping: Option<PathBuf>,
        #[arg(
            long = "library",
            value_name = "JAR",
            help = "known-library jar(s) to fingerprint a mapping-less ProGuard/R8 artifact against; re-identifies renamed library classes/methods and writes library-fingerprint.json"
        )]
        library: Vec<PathBuf>,
        #[arg(
            long,
            help = "force the protector-peel pass (Zelix/Allatori/DashO/DexGuard string-decrypt + control-flow unflattening) even when no protector is auto-detected; peel runs automatically whenever a protector is detected"
        )]
        peel: bool,
    },
    #[command(about = "extract a .jar / .apk container & dump its classfile inventory")]
    Extract {
        #[arg(help = "input .jar / .apk archive")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-jvm-extract)"
        )]
        out: Option<PathBuf>,
    },
    #[command(about = "report available JVM / Android backends discovered on PATH")]
    Backends,
    #[command(
        about = "retrace an obfuscated stack-trace frame back to its original class/method/line through a ProGuard/R8 mapping.txt"
    )]
    Retrace {
        #[arg(
            long,
            help = "ProGuard / R8 mapping.txt produced by the obfuscated build"
        )]
        mapping: PathBuf,
        #[arg(
            long,
            help = "obfuscated (binary or dotted) class name from the stack frame, e.g. a.b.c"
        )]
        class: String,
        #[arg(long, help = "obfuscated method name from the stack frame, e.g. a")]
        method: String,
        #[arg(long, help = "obfuscated source line number from the stack frame")]
        line: u32,
        #[arg(
            long,
            help = "emit the retraced frame(s) as machine-clean JSON to stdout (no human-readable summary)"
        )]
        json: bool,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JvmBackendKind {
    Auto,
    Cfr,
    Vineflower,
    Procyon,
    Jd,
    Krakatau,
    Jadx,
    Dex2Jar,
}

pub(crate) fn run(action: JvmCmd) -> miette::Result<()> {
    match action {
        JvmCmd::Decompile {
            input,
            out,
            backend,
            timeout_secs,
            emit,
            mapping,
            library,
            peel,
        } => decompile(
            input,
            out,
            backend,
            timeout_secs,
            emit,
            mapping,
            library,
            peel,
        ),
        JvmCmd::Extract { input, out } => extract(input, out),
        JvmCmd::Backends => backends(),
        JvmCmd::Retrace {
            mapping,
            class,
            method,
            line,
            json,
        } => retrace(mapping, class, method, line, json),
    }
}

fn retrace(
    mapping_path: PathBuf,
    class: String,
    method: String,
    line: u32,
    json: bool,
) -> miette::Result<()> {
    let mapping: ProguardMapping = load_mapping(&mapping_path)?;
    let frames: Vec<RetracedFrame> = mapping.retrace(&class, &method, line);
    if json {
        let value: serde_json::Value = serde_json::json!({
            "schema": "disrobe.jvm.retrace/v1",
            "mapping": mapping_path.display().to_string(),
            "obfuscated": {
                "class": class,
                "method": method,
                "line": line,
            },
            "frames": frames,
        });
        let text: String = serde_json::to_string_pretty(&value)
            .map_err(|e| miette::miette!("DR-CLI-0425: retrace serialize: {e}"))?;
        println!("{text}");
        return Ok(());
    }
    println!("jvm retrace: OK");
    println!("  mapping:      {}", mapping_path.display());
    println!("  obfuscated:   {class}.{method}:{line}");
    if frames.is_empty() {
        println!("  retraced:     <no mapping entry for this frame>");
        return Ok(());
    }
    for frame in &frames {
        match frame.original_line {
            Some(orig) => println!(
                "  retraced:     {}.{}:{orig}",
                frame.class_name, frame.method_name
            ),
            None => println!("  retraced:     {}.{}", frame.class_name, frame.method_name),
        }
    }
    Ok(())
}

fn load_mapping(mapping_path: &std::path::Path) -> miette::Result<ProguardMapping> {
    let text: String = std::fs::read_to_string(mapping_path)
        .map_err(|e| miette::miette!("DR-CLI-0420: cannot read mapping file: {e}"))?;
    parse_proguard_mapping(&text)
        .map_err(|e| miette::miette!("DR-CLI-0421: proguard mapping parse: {e}"))
}

fn applied_to_json(applied: &AppliedNames) -> serde_json::Value {
    serde_json::json!({
        "class": applied.class_name,
        "super": applied.super_name,
        "interfaces": applied.interfaces,
        "fields": applied.fields,
        "methods": applied.methods,
        "method_descriptors": applied.method_descriptors,
        "restored_count": applied.restored_count,
    })
}

fn write_name_restoration(
    mapping_path: &std::path::Path,
    out_dir: &std::path::Path,
    classes: Vec<serde_json::Value>,
    total_restored: usize,
) -> miette::Result<()> {
    let json: serde_json::Value = serde_json::json!({
        "schema": "disrobe.jvm.name-restoration/v1",
        "mapping": mapping_path.display().to_string(),
        "classes": classes,
        "restored_count": total_restored,
    });
    let path: PathBuf = out_dir.join("name-restoration.json");
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&json)
        .map_err(|e| miette::miette!("DR-CLI-0422: name-restoration serialize: {e}"))?;
    std::fs::write(&path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0423: cannot write name-restoration.json: {e}"))?;
    println!("  mapping:      {total_restored} names restored (see name-restoration.json)");
    Ok(())
}

fn restore_names_with_mapping(
    mapping_path: &std::path::Path,
    cf: &ClassFile,
    out_dir: &std::path::Path,
) -> miette::Result<()> {
    let mapping: ProguardMapping = load_mapping(mapping_path)?;
    let applied: AppliedNames = apply_proguard_mapping(&mapping, cf);
    let restored: usize = applied.restored_count;
    write_name_restoration(
        mapping_path,
        out_dir,
        vec![applied_to_json(&applied)],
        restored,
    )
}

fn restore_names_for_jar(
    mapping_path: &std::path::Path,
    extract: &JarExtract,
    out_dir: &std::path::Path,
) -> miette::Result<()> {
    let mapping: ProguardMapping = load_mapping(mapping_path)?;
    let mut classes: Vec<serde_json::Value> = Vec::new();
    let mut total: usize = 0;
    for (entry_path, class_bytes) in &extract.classes {
        let Ok(cf): Result<ClassFile, _> = parse_classfile(class_bytes) else {
            continue;
        };
        let applied: AppliedNames = apply_proguard_mapping(&mapping, &cf);
        if applied.class_name.is_none() && applied.restored_count == 0 {
            continue;
        }
        total += applied.restored_count;
        let mut obj: serde_json::Value = applied_to_json(&applied);
        if let serde_json::Value::Object(map) = &mut obj {
            map.insert(
                "entry".to_owned(),
                serde_json::Value::String(entry_path.clone()),
            );
        }
        classes.push(obj);
    }
    write_name_restoration(mapping_path, out_dir, classes, total)
}

fn parse_jar_classfiles(extract: &JarExtract) -> Vec<ClassFile> {
    let mut out: Vec<ClassFile> = Vec::with_capacity(extract.classes.len());
    for class_bytes in extract.classes.values() {
        if let Ok(cf) = parse_classfile(class_bytes) {
            out.push(cf);
        }
    }
    out
}

fn load_library_signatures(library: &[PathBuf]) -> miette::Result<LibrarySignatureSet> {
    let mut classes: Vec<ClassFile> = Vec::new();
    for jar_path in library {
        let raw: Vec<u8> = std::fs::read(jar_path)
            .map_err(|e| miette::miette!("DR-CLI-0430: cannot read library jar: {e}"))?;
        if raw.len() >= 4 && u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) == CLASS_MAGIC {
            let cf: ClassFile = parse_classfile(&raw)
                .map_err(|e| miette::miette!("DR-CLI-0431: library classfile parse: {e}"))?;
            classes.push(cf);
            continue;
        }
        let extract: JarExtract = extract_jar(&raw)
            .map_err(|e| miette::miette!("DR-CLI-0432: library jar extract: {e}"))?;
        classes.extend(parse_jar_classfiles(&extract));
    }
    Ok(LibrarySignatureSet::from_classfiles(&classes))
}

fn fingerprint_to_json(report: &FingerprintReport, library: &[PathBuf]) -> serde_json::Value {
    let classes: Vec<serde_json::Value> = report
        .classes
        .iter()
        .map(|c| {
            serde_json::json!({
                "obfuscated": c.obfuscated_name,
                "original": c.original_name,
                "score": c.score,
                "methods": c.methods.iter().map(|m| serde_json::json!({
                    "obfuscated": m.obfuscated_name,
                    "descriptor": m.descriptor,
                    "original": m.original_name,
                    "score": m.score,
                })).collect::<Vec<_>>(),
                "fields": c.fields.iter().map(|f| serde_json::json!({
                    "obfuscated": f.obfuscated_name,
                    "descriptor": f.descriptor,
                    "original": f.original_name,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "schema": "disrobe.jvm.library-fingerprint/v1",
        "note": "user-renamed identifiers without a mapping are unrecoverable; this re-identifies public-library symbols by structural fingerprint",
        "libraries": library.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "classes": classes,
        "class_count": report.class_count(),
        "method_count": report.method_count(),
    })
}

fn fingerprint_against_libraries(
    library: &[PathBuf],
    obfuscated: &[ClassFile],
    out_dir: &std::path::Path,
) -> miette::Result<()> {
    let signatures: LibrarySignatureSet = load_library_signatures(library)?;
    let report: FingerprintReport = fingerprint_library_symbols(obfuscated, &signatures);
    let json: serde_json::Value = fingerprint_to_json(&report, library);
    let path: PathBuf = out_dir.join("library-fingerprint.json");
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&json)
        .map_err(|e| miette::miette!("DR-CLI-0433: library-fingerprint serialize: {e}"))?;
    std::fs::write(&path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0434: cannot write library-fingerprint.json: {e}"))?;
    println!(
        "  library:      {} class(es), {} method(s) re-identified (see library-fingerprint.json)",
        report.class_count(),
        report.method_count()
    );
    Ok(())
}

fn decompile(
    input: PathBuf,
    out: Option<PathBuf>,
    backend_choice: JvmBackendKind,
    timeout_secs: u64,
    emit_kinds: Vec<String>,
    mapping: Option<PathBuf>,
    library: Vec<PathBuf>,
    peel: bool,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0400: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("jvm-decompile")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-jvm")));
    let g: globals::Globals = globals::current();
    let format: ClassformatKind = classify(&bytes, &input);

    if g.dry_run {
        println!("jvm decompile: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  format:       {format:?}");
        println!("  backend:      {backend_choice:?}");
        return Ok(());
    }

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0401: cannot create out dir: {e}"))?;

    let caps: BackendCapability = detect_available();
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let mut class_report: Option<(usize, usize)> = None;
    let mut peel_summaries: Vec<PeelSummary> = Vec::new();

    let (summary, native_emitted): (serde_json::Value, bool) = match format {
        ClassformatKind::Classfile => {
            let cf: ClassFile = parse_classfile(&bytes)
                .map_err(|e| miette::miette!("DR-CLI-0402: classfile parse: {e}"))?;
            if let Some(mapping_path) = mapping.as_ref() {
                restore_names_with_mapping(mapping_path, &cf, &out_dir)?;
            }
            if !library.is_empty() {
                fingerprint_against_libraries(&library, std::slice::from_ref(&cf), &out_dir)?;
            }
            let peeled: Option<PeeledClass> = peel_classfile_if_requested(&cf, peel, &out_dir)?;
            if let Some(p) = &peeled {
                peel_summaries.push(PeelSummary::from_report(&p.report));
            }
            let invocation: Option<BackendInvocation> =
                run_jvm_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            let emitted: bool =
                emit_native_artifacts(&emit_kinds, &out_dir, &stem, &cf, peeled.as_ref())?;
            (classfile_summary(&input, &cf, invocation.as_ref()), emitted)
        }
        ClassformatKind::Dex => {
            let dx: DexFile =
                parse_dex(&bytes).map_err(|e| miette::miette!("DR-CLI-0403: dex parse: {e}"))?;
            let native: DecompiledDex = decompile_dex(&dx, &bytes);
            let string_recovery: Vec<DexStringRecovery> =
                recover_dex_reflection_strings(&dx, &bytes);
            if let Some(s) = dex_peel_summary(&string_recovery) {
                peel_summaries.push(s);
            }
            let emitted: bool = emit_native_dex(&emit_kinds, &out_dir, &stem, &native)?;
            let invocation: Option<BackendInvocation> =
                run_android_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            (
                dex_summary(&input, &dx, &native, &string_recovery, invocation.as_ref()),
                emitted,
            )
        }
        ClassformatKind::Jar => {
            let extract: JarExtract = extract_jar(&bytes)
                .map_err(|e| miette::miette!("DR-CLI-0404: jar extract: {e}"))?;
            if let Some(mapping_path) = mapping.as_ref() {
                restore_names_for_jar(mapping_path, &extract, &out_dir)?;
            }
            if !library.is_empty() {
                let obf_classes: Vec<ClassFile> = parse_jar_classfiles(&extract);
                fingerprint_against_libraries(&library, &obf_classes, &out_dir)?;
            }
            let outcome: JarDecompileOutcome =
                decompile_jar_classes(&emit_kinds, &out_dir, &extract, peel, &mut peel_summaries)?;
            let emitted: bool = outcome.emitted_source;
            class_report = Some((outcome.decompiled, outcome.total));
            let invocation: Option<BackendInvocation> =
                run_jvm_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            (
                jar_summary(&input, &extract, &outcome, invocation.as_ref()),
                emitted,
            )
        }
        ClassformatKind::Apk => {
            let native: DecompiledDex = decompile_apk_dexes(&bytes);
            let emitted: bool = emit_native_dex(&emit_kinds, &out_dir, &stem, &native)?;
            let invocation: Option<BackendInvocation> =
                run_android_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            (apk_summary(&input, &native, invocation.as_ref()), emitted)
        }
        ClassformatKind::Unknown => {
            return Err(miette::miette!(
                "DR-CLI-0405: input does not look like a .class / .jar / .dex / .apk file"
            ));
        }
    };

    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&summary)
        .map_err(|e| miette::miette!("DR-CLI-0406: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0407: cannot write manifest: {e}"))?;

    apply_emit_stubs(
        &emit_kinds,
        &out_dir,
        &stem,
        "jvm-decompile",
        native_emitted,
    )?;

    if !peel_summaries.is_empty() {
        write_peel_report(&out_dir, &peel_summaries)?;
    }

    println!("jvm decompile: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {format:?}");
    if let Some((decompiled, total)) = class_report {
        println!("  classes:      {decompiled} decompiled / {total} total");
        println!("  source dir:   {}", out_dir.display());
    }
    print_peel_summaries(&peel_summaries);
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

#[derive(Debug, Clone)]
struct PeelSummary {
    family: String,
    status: &'static str,
    strings_recovered: usize,
    strings_residual: usize,
    cff_methods_unflattened: u32,
    runtime_key_walled: bool,
}

impl PeelSummary {
    fn from_report(report: &ProtectorPeelReport) -> Self {
        let runtime_key_walled: bool = report.status == PeelStatus::DetectOnly
            && report.notes.iter().any(|n: &String| {
                n.contains("runtime")
                    || n.contains("stack-trace")
                    || n.contains("self-tamper checksum")
                    || n.contains("run time")
            });
        Self {
            family: report.family.name().to_owned(),
            status: peel_status_label(report.status),
            strings_recovered: report.strings_recovered.len(),
            strings_residual: report.strings_residual,
            cff_methods_unflattened: report.cff_methods_unflattened,
            runtime_key_walled,
        }
    }
}

const fn peel_status_label(status: PeelStatus) -> &'static str {
    match status {
        PeelStatus::StubRecovered => "stub-recovered",
        PeelStatus::CipherRecovered => "cipher-recovered",
        PeelStatus::DetectOnly => "detect-only",
    }
}

fn dex_peel_summary(recovery: &[DexStringRecovery]) -> Option<PeelSummary> {
    let strings_recovered: usize = recovery
        .iter()
        .map(|r: &DexStringRecovery| r.recovered.len())
        .sum();
    let runtime_key_walled: bool = recovery
        .iter()
        .any(|r: &DexStringRecovery| r.runtime_key_wall);
    if strings_recovered == 0 && !runtime_key_walled {
        return None;
    }
    Some(PeelSummary {
        family: "DexGuard".to_owned(),
        status: if strings_recovered > 0 {
            "cipher-recovered"
        } else {
            "detect-only"
        },
        strings_recovered,
        strings_residual: 0,
        cff_methods_unflattened: 0,
        runtime_key_walled,
    })
}

fn peel_classfile_if_requested(
    cf: &ClassFile,
    peel: bool,
    out_dir: &std::path::Path,
) -> miette::Result<Option<PeeledClass>> {
    let detected: bool = detect_protector_family(cf).is_some();
    if !detected && !peel {
        return Ok(None);
    }
    let Some(peeled): Option<PeeledClass> = peel_and_decompile_classfile(cf) else {
        if peel {
            println!("  peel:         no protector detected; nothing to peel");
        }
        return Ok(None);
    };
    let report_path: PathBuf = out_dir.join("protector-peel.json");
    let json: serde_json::Value = serde_json::json!({
        "schema": "disrobe.jvm.protector-peel/v1",
        "report": peeled.report,
    });
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&json)
        .map_err(|e| miette::miette!("DR-CLI-0440: protector-peel serialize: {e}"))?;
    std::fs::write(&report_path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0441: cannot write protector-peel.json: {e}"))?;
    Ok(Some(peeled))
}

fn write_peel_report(out_dir: &std::path::Path, summaries: &[PeelSummary]) -> miette::Result<()> {
    let entries: Vec<serde_json::Value> = summaries
        .iter()
        .map(|s: &PeelSummary| {
            serde_json::json!({
                "family": s.family,
                "status": s.status,
                "strings_recovered": s.strings_recovered,
                "strings_residual": s.strings_residual,
                "cff_methods_unflattened": s.cff_methods_unflattened,
                "runtime_key_walled": s.runtime_key_walled,
            })
        })
        .collect();
    let json: serde_json::Value = serde_json::json!({
        "schema": "disrobe.jvm.protector-peel-summary/v1",
        "peeled": entries,
    });
    let path: PathBuf = out_dir.join("protector-peel-summary.json");
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&json)
        .map_err(|e| miette::miette!("DR-CLI-0442: peel-summary serialize: {e}"))?;
    std::fs::write(&path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0443: cannot write peel-summary: {e}"))?;
    Ok(())
}

fn print_peel_summaries(summaries: &[PeelSummary]) {
    let total_strings: usize = summaries
        .iter()
        .map(|s: &PeelSummary| s.strings_recovered)
        .sum();
    let total_cff: u32 = summaries
        .iter()
        .map(|s: &PeelSummary| s.cff_methods_unflattened)
        .sum();
    let mut families: Vec<&str> = summaries
        .iter()
        .filter(|s: &&PeelSummary| s.strings_recovered > 0 || s.cff_methods_unflattened > 0)
        .map(|s: &PeelSummary| s.family.as_str())
        .collect();
    families.sort_unstable();
    families.dedup();
    if !families.is_empty() {
        println!(
            "  peeled:       {} ({total_strings} string(s) recovered, {total_cff} method(s) un-flattened)",
            families.join(", ")
        );
    }
    let walled: Vec<&str> = summaries
        .iter()
        .filter(|s: &&PeelSummary| s.runtime_key_walled)
        .map(|s: &PeelSummary| s.family.as_str())
        .collect();
    if !walled.is_empty() {
        let mut uniq: Vec<&str> = walled;
        uniq.sort_unstable();
        uniq.dedup();
        println!(
            "  honest wall:  {} string decrypt is runtime-keyed; plaintext absent from the static artifact",
            uniq.join(", ")
        );
    }
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0410: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("jvm-extract")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-jvm-extract")));
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("jvm extract: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  out dir:      {}", out_dir.display());
        return Ok(());
    }
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0411: cannot create out dir: {e}"))?;
    let extract: JarExtract =
        extract_jar(&bytes).map_err(|e| miette::miette!("DR-CLI-0412: jar/apk extract: {e}"))?;
    for entry in &extract.entries {
        let safe: PathBuf = sanitize_entry_path(&out_dir, &entry.path);
        if let Some(parent) = safe.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0413: cannot create entry dir: {e}"))?;
        }
        if entry.path.ends_with('/') {
            continue;
        }
        std::fs::write(&safe, &entry.bytes)
            .map_err(|e| miette::miette!("DR-CLI-0414: cannot write entry: {e}"))?;
    }
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.jvm.extract/v0",
        "input": input.display().to_string(),
        "entries": extract.entries.len(),
        "classes": extract.classes.len(),
        "manifest_mf_present": extract.manifest.is_some(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0416: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0415: cannot write manifest: {e}"))?;
    println!("jvm extract: OK");
    println!("  entries:      {}", extract.entries.len());
    println!("  classes:      {}", extract.classes.len());
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn backends() -> miette::Result<()> {
    let caps: BackendCapability = detect_available();
    println!("jvm backends available on PATH:");
    if caps.jvm.is_empty() {
        println!("  (none) - install cfr / vineflower / procyon / jd-cli / krakatau2");
    } else {
        for b in &caps.jvm {
            println!("  - {}", jvm_label(*b));
        }
    }
    println!("android backends available on PATH:");
    if caps.android.is_empty() {
        println!("  (none) - install jadx / d2j-dex2jar");
    } else {
        for b in &caps.android {
            println!("  - {}", android_label(*b));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ClassformatKind {
    Classfile,
    Dex,
    Jar,
    Apk,
    Unknown,
}

fn classify(bytes: &[u8], path: &std::path::Path) -> ClassformatKind {
    if bytes.len() >= 4
        && u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == CLASS_MAGIC
    {
        return ClassformatKind::Classfile;
    }
    if bytes.len() >= 8 && &bytes[..4] == DEX_MAGIC_PREFIX.as_slice() && bytes[7] == 0 {
        return ClassformatKind::Dex;
    }
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        let looks_apk: bool = path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|e| e.eq_ignore_ascii_case("apk"));
        return if looks_apk {
            ClassformatKind::Apk
        } else {
            ClassformatKind::Jar
        };
    }
    ClassformatKind::Unknown
}

fn run_jvm_backend(
    caps: &BackendCapability,
    choice: JvmBackendKind,
    input: &std::path::Path,
    out_dir: &std::path::Path,
    timeout_secs: u64,
) -> miette::Result<Option<BackendInvocation>> {
    let backend: Option<JvmBackend> = pick_jvm_backend(caps, choice);
    let Some(backend): Option<JvmBackend> = backend else {
        return Ok(None);
    };
    let args: Vec<String> = match backend {
        JvmBackend::Cfr => vec![
            input.display().to_string(),
            "--outputdir".to_owned(),
            out_dir.display().to_string(),
        ],
        JvmBackend::Vineflower => vec![input.display().to_string(), out_dir.display().to_string()],
        JvmBackend::Procyon => vec![
            "-o".to_owned(),
            out_dir.display().to_string(),
            input.display().to_string(),
        ],
        JvmBackend::JdGui => vec![
            input.display().to_string(),
            "--outputDir".to_owned(),
            out_dir.display().to_string(),
        ],
        JvmBackend::Krakatau => vec![
            "decompile".to_owned(),
            "-out".to_owned(),
            out_dir.display().to_string(),
            input.display().to_string(),
        ],
    };
    let invocation: BackendInvocation =
        invoke_jvm(backend, &args, Duration::from_secs(timeout_secs))
            .map_err(|e| miette::miette!("DR-CLI-0420: backend {backend:?} failed: {e}"))?;
    Ok(Some(invocation))
}

fn run_android_backend(
    caps: &BackendCapability,
    choice: JvmBackendKind,
    input: &std::path::Path,
    out_dir: &std::path::Path,
    timeout_secs: u64,
) -> miette::Result<Option<BackendInvocation>> {
    let backend: Option<AndroidBackend> = pick_android_backend(caps, choice);
    let Some(backend): Option<AndroidBackend> = backend else {
        return Ok(None);
    };
    let args: Vec<String> = match backend {
        AndroidBackend::Jadx => vec![
            "--output-dir".to_owned(),
            out_dir.display().to_string(),
            input.display().to_string(),
        ],
        AndroidBackend::Dex2Jar => vec![
            "-o".to_owned(),
            out_dir.join("classes.jar").display().to_string(),
            input.display().to_string(),
        ],
    };
    let invocation: BackendInvocation =
        invoke_android(backend, &args, Duration::from_secs(timeout_secs))
            .map_err(|e| miette::miette!("DR-CLI-0421: android backend {backend:?} failed: {e}"))?;
    Ok(Some(invocation))
}

fn pick_jvm_backend(caps: &BackendCapability, choice: JvmBackendKind) -> Option<JvmBackend> {
    let want: Option<JvmBackend> = match choice {
        JvmBackendKind::Cfr => Some(JvmBackend::Cfr),
        JvmBackendKind::Vineflower => Some(JvmBackend::Vineflower),
        JvmBackendKind::Procyon => Some(JvmBackend::Procyon),
        JvmBackendKind::Jd => Some(JvmBackend::JdGui),
        JvmBackendKind::Krakatau => Some(JvmBackend::Krakatau),
        _ => None,
    };
    if let Some(b) = want
        && caps.jvm.contains(&b)
    {
        return Some(b);
    }
    caps.jvm.first().copied()
}

fn pick_android_backend(
    caps: &BackendCapability,
    choice: JvmBackendKind,
) -> Option<AndroidBackend> {
    let want: Option<AndroidBackend> = match choice {
        JvmBackendKind::Jadx => Some(AndroidBackend::Jadx),
        JvmBackendKind::Dex2Jar => Some(AndroidBackend::Dex2Jar),
        _ => None,
    };
    let b: AndroidBackend = want?;
    if caps.android.contains(&b) {
        return Some(b);
    }
    None
}

const fn jvm_label(b: JvmBackend) -> &'static str {
    match b {
        JvmBackend::Cfr => "cfr",
        JvmBackend::Vineflower => "vineflower",
        JvmBackend::Procyon => "procyon",
        JvmBackend::JdGui => "jd-cli",
        JvmBackend::Krakatau => "krakatau2",
    }
}

const fn android_label(b: AndroidBackend) -> &'static str {
    match b {
        AndroidBackend::Jadx => "jadx",
        AndroidBackend::Dex2Jar => "d2j-dex2jar",
    }
}

fn classfile_summary(
    input: &std::path::Path,
    cf: &ClassFile,
    invocation: Option<&BackendInvocation>,
) -> serde_json::Value {
    let this_class: String = cf
        .this_class_name()
        .map_or_else(|_| "?".to_owned(), str::to_owned);
    serde_json::json!({
        "schema": "disrobe.jvm.decompile/v0",
        "input": input.display().to_string(),
        "format": "classfile",
        "this_class": this_class,
        "major_version": cf.major_version,
        "minor_version": cf.minor_version,
        "field_count": cf.fields.len(),
        "method_count": cf.methods.len(),
        "constant_pool_size": cf.constant_pool.len(),
        "backend_invoked": invocation.is_some(),
        "backend_exit_code": invocation.map(|i| i.exit_code),
    })
}

fn dex_summary(
    input: &std::path::Path,
    dx: &DexFile,
    native: &DecompiledDex,
    string_recovery: &[DexStringRecovery],
    invocation: Option<&BackendInvocation>,
) -> serde_json::Value {
    let recovered_total: usize = string_recovery
        .iter()
        .map(|r: &DexStringRecovery| r.recovered.len())
        .sum();
    let reflective_total: usize = string_recovery
        .iter()
        .map(|r: &DexStringRecovery| r.reflective_call_sites.len())
        .sum();
    let recovery_json: Vec<serde_json::Value> = string_recovery
        .iter()
        .map(|r: &DexStringRecovery| {
            serde_json::json!({
                "class": r.class,
                "decrypt_method": r.decrypt_method,
                "table_size": r.table_size,
                "recovered": r.recovered.iter().map(|d| {
                    serde_json::json!({ "index": d.table_index, "plaintext": d.plaintext })
                }).collect::<Vec<serde_json::Value>>(),
                "reflective_call_sites": r.reflective_call_sites.iter().map(|s| {
                    serde_json::json!({
                        "caller_class": s.caller_class,
                        "caller_method": s.caller_method,
                        "resolved_member": s.resolved_member,
                    })
                }).collect::<Vec<serde_json::Value>>(),
                "runtime_key_wall": r.runtime_key_wall,
                "runtime_key_wall_reason": r.runtime_key_wall_reason,
            })
        })
        .collect();
    serde_json::json!({
        "schema": "disrobe.jvm.decompile/v0",
        "input": input.display().to_string(),
        "format": "dex",
        "dex_version": format!("{:?}", dx.header.version),
        "string_count": dx.strings.len(),
        "class_count": dx.class_descriptors.len(),
        "type_name_count": dx.type_names.len(),
        "native_decompiler": "disrobe-dalvik",
        "native_class_count": native.class_count,
        "native_method_count": native.method_count,
        "native_fully_lifted_methods": native.fully_lifted_methods,
        "native_fallback_methods": native.fallback_methods,
        "reflection_strings_recovered": recovered_total,
        "reflection_call_sites_resolved": reflective_total,
        "reflection_string_recovery": recovery_json,
        "backend_invoked": invocation.is_some(),
        "backend_exit_code": invocation.map(|i| i.exit_code),
    })
}

fn jar_summary(
    input: &std::path::Path,
    extract: &JarExtract,
    outcome: &JarDecompileOutcome,
    invocation: Option<&BackendInvocation>,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.jvm.decompile/v0",
        "input": input.display().to_string(),
        "format": "jar",
        "entries": extract.entries.len(),
        "classes": extract.classes.len(),
        "manifest_mf_present": extract.manifest.is_some(),
        "native_decompiler": "disrobe-jvm",
        "native_classes_total": outcome.total,
        "native_classes_decompiled": outcome.decompiled,
        "native_classes_failed": outcome.failed.len(),
        "native_failed_classes": outcome.failed,
        "backend_invoked": invocation.is_some(),
        "backend_exit_code": invocation.map(|i| i.exit_code),
    })
}

fn apk_summary(
    input: &std::path::Path,
    native: &DecompiledDex,
    invocation: Option<&BackendInvocation>,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.jvm.decompile/v0",
        "input": input.display().to_string(),
        "format": "apk",
        "native_decompiler": "disrobe-dalvik",
        "native_class_count": native.class_count,
        "native_method_count": native.method_count,
        "native_fully_lifted_methods": native.fully_lifted_methods,
        "backend_invoked": invocation.is_some(),
        "backend_exit_code": invocation.map(|i| i.exit_code),
    })
}

fn decompile_apk_dexes(apk_bytes: &[u8]) -> DecompiledDex {
    let mut combined: DecompiledDex = DecompiledDex {
        source: String::new(),
        sources: std::collections::BTreeMap::new(),
        class_count: 0,
        method_count: 0,
        fully_lifted_methods: 0,
        fallback_methods: 0,
        code_scan_complete: true,
        decode_error_count: 0,
    };
    let Ok(extract): Result<JarExtract, _> = extract_jar(apk_bytes) else {
        combined.code_scan_complete = false;
        combined.decode_error_count += 1;
        return combined;
    };
    for entry in &extract.entries {
        let leaf: &str = entry.path.rsplit('/').next().unwrap_or(&entry.path);
        let is_classes_dex: bool = leaf.starts_with("classes")
            && std::path::Path::new(leaf)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("dex"));
        if !is_classes_dex {
            continue;
        }
        let Ok(dx): Result<DexFile, _> = parse_dex(&entry.bytes) else {
            combined.code_scan_complete = false;
            combined.decode_error_count += 1;
            continue;
        };
        let part: DecompiledDex = decompile_dex(&dx, &entry.bytes);
        combined.source.push_str(&part.source);
        combined.sources.extend(part.sources);
        combined.class_count += part.class_count;
        combined.method_count += part.method_count;
        combined.fully_lifted_methods += part.fully_lifted_methods;
        combined.fallback_methods += part.fallback_methods;
        combined.code_scan_complete &= part.code_scan_complete;
        combined.decode_error_count += part.decode_error_count;
    }
    combined
}

fn sanitize_entry_path(out_dir: &std::path::Path, raw: &str) -> PathBuf {
    let cleaned: String = raw.replace('\\', "/");
    let mut resolved: PathBuf = out_dir.to_path_buf();
    for segment in cleaned.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            continue;
        }
        resolved.push(segment);
    }
    resolved
}

fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    pass: &'static str,
    native_emitted: bool,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    if spec.is_empty() {
        return Ok(());
    }
    for kind in spec.iter() {
        if native_emitted && matches!(kind, EmitKind::Source | EmitKind::Disasm) {
            continue;
        }
        let _: PathBuf = super::emit::write_not_applicable_stub(
            out_dir,
            stem,
            pass,
            kind,
            "not implemented for the jvm pass in this build",
        )?;
    }
    Ok(())
}

#[must_use]
fn native_decompile_source(cf: &ClassFile) -> String {
    let decompiled: DecompiledClass = decompile_class(cf);
    decompiled.source
}

#[must_use]
fn native_disassembly(cf: &ClassFile) -> String {
    let mut out: String = String::new();
    let this_class: String = cf
        .this_class_name()
        .map_or_else(|_| "?".to_owned(), str::to_owned);
    let _ = writeln!(out, "; disrobe native disassembly: {this_class}");
    for method in &cf.methods {
        let name: &str = cf.utf8_at(method.name_index).unwrap_or("?");
        let desc: &str = cf.utf8_at(method.descriptor_index).unwrap_or("");
        let _ = writeln!(out, "\n.method {name} {desc}");
        for attr in &method.attributes {
            if cf.utf8_at(attr.name_index).is_ok_and(|n| n == "Code")
                && let Ok(code) = parse_code_attribute(&attr.info)
                && let Ok(insns) = disassemble(&code.code)
            {
                let _ = writeln!(
                    out,
                    "  .limit stack {} locals {}",
                    code.max_stack, code.max_locals
                );
                for insn in &insns {
                    let _ = writeln!(
                        out,
                        "  {:>5}: {}{}",
                        insn.pc,
                        insn.mnemonic,
                        operand_text(insn)
                    );
                }
            }
        }
        let _ = writeln!(out, ".end method");
    }
    out
}

fn operand_text(insn: &Instruction) -> String {
    match &insn.operands {
        Operands::None => String::new(),
        Operands::Byte(v) | Operands::Short(v) | Operands::Branch(v) => format!(" {v}"),
        Operands::Local(i) => format!(" #{i}"),
        Operands::ConstPool(i) | Operands::InvokeDynamic(i) => format!(" cp#{i}"),
        Operands::Iinc { index, delta } => format!(" #{index} {delta:+}"),
        Operands::NewArray(t) => format!(" type={t}"),
        Operands::InvokeInterface { index, count } => format!(" cp#{index} args={count}"),
        Operands::MultiANewArray { index, dimensions } => format!(" cp#{index} dims={dimensions}"),
        Operands::TableSwitch { low, high, .. } => format!(" {low}..{high}"),
        Operands::LookupSwitch { pairs, .. } => format!(" npairs={}", pairs.len()),
    }
}

fn emit_native_dex(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    native: &DecompiledDex,
) -> miette::Result<bool> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    let want_source: bool = spec.is_empty() || spec.contains(EmitKind::Source);
    if want_source {
        let path: PathBuf = out_dir.join(format!("{stem}.java"));
        std::fs::write(&path, &native.source)
            .map_err(|e| miette::miette!("DR-CLI-0422: cannot write native dex source: {e}"))?;
    }
    Ok(want_source)
}

fn emit_native_artifacts(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    cf: &ClassFile,
    peeled: Option<&PeeledClass>,
) -> miette::Result<bool> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    let want_source: bool = spec.contains(EmitKind::Source);
    let want_disasm: bool = spec.contains(EmitKind::Disasm);
    if want_source {
        let path: PathBuf = out_dir.join(format!("{stem}.java"));
        let source: String =
            peeled.map_or_else(|| native_decompile_source(cf), |p| p.source.clone());
        std::fs::write(&path, source)
            .map_err(|e| miette::miette!("DR-CLI-0420: cannot write native source: {e}"))?;
    }
    if want_disasm {
        let path: PathBuf = out_dir.join(format!("{stem}.disasm"));
        std::fs::write(&path, native_disassembly(cf))
            .map_err(|e| miette::miette!("DR-CLI-0421: cannot write native disasm: {e}"))?;
    }
    Ok(want_source || want_disasm)
}

#[derive(Debug)]
struct JarDecompileOutcome {
    total: usize,
    decompiled: usize,
    failed: Vec<String>,
    emitted_source: bool,
}

fn decompile_jar_classes(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    extract: &JarExtract,
    peel: bool,
    peel_summaries: &mut Vec<PeelSummary>,
) -> miette::Result<JarDecompileOutcome> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    let want_source: bool = spec.is_empty() || spec.contains(EmitKind::Source);
    let total: usize = extract.classes.len();
    let mut decompiled: usize = 0;
    let mut failed: Vec<String> = Vec::new();
    let mut emitted_source: bool = false;

    if !want_source {
        return Ok(JarDecompileOutcome {
            total,
            decompiled,
            failed,
            emitted_source,
        });
    }

    for (entry_path, class_bytes) in &extract.classes {
        match decompile_one_jar_class(class_bytes, peel) {
            Some(out) => {
                let target: PathBuf = jar_source_path(out_dir, out.rel_name.as_deref(), entry_path);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        miette::miette!("DR-CLI-0423: cannot create class out dir: {e}")
                    })?;
                }
                std::fs::write(&target, out.source.as_bytes()).map_err(|e| {
                    miette::miette!("DR-CLI-0424: cannot write decompiled class: {e}")
                })?;
                if let Some(report) = out.peel {
                    peel_summaries.push(PeelSummary::from_report(&report));
                }
                decompiled += 1;
                emitted_source = true;
            }
            None => failed.push(entry_path.clone()),
        }
    }

    Ok(JarDecompileOutcome {
        total,
        decompiled,
        failed,
        emitted_source,
    })
}

struct JarClassOutput {
    rel_name: Option<String>,
    source: String,
    peel: Option<ProtectorPeelReport>,
}

fn decompile_one_jar_class(class_bytes: &[u8], peel: bool) -> Option<JarClassOutput> {
    let bytes: Vec<u8> = class_bytes.to_vec();
    std::panic::catch_unwind(move || {
        let cf: ClassFile = parse_classfile(&bytes).ok()?;
        let name: Option<String> = cf.this_class_name().ok().map(str::to_owned);
        let detected: bool = detect_protector_family(&cf).is_some();
        if (detected || peel)
            && let Some(peeled) = peel_and_decompile_classfile(&cf)
        {
            return Some(JarClassOutput {
                rel_name: name,
                source: peeled.source,
                peel: Some(peeled.report),
            });
        }
        let decompiled: DecompiledClass = decompile_class(&cf);
        Some(JarClassOutput {
            rel_name: name,
            source: decompiled.source,
            peel: None,
        })
    })
    .ok()
    .flatten()
}

fn jar_source_path(
    out_dir: &std::path::Path,
    internal_name: Option<&str>,
    entry_path: &str,
) -> PathBuf {
    if let Some(name) = internal_name.filter(|n| !n.is_empty()) {
        let mut resolved: PathBuf = out_dir.to_path_buf();
        let mut pushed: bool = false;
        for segment in name.replace('\\', "/").split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                continue;
            }
            resolved.push(segment);
            pushed = true;
        }
        if pushed {
            resolved.set_extension("java");
            return resolved;
        }
    }
    let stripped: &str = entry_path.strip_suffix(".class").unwrap_or(entry_path);
    let mut resolved: PathBuf = sanitize_entry_path(out_dir, stripped);
    resolved.set_extension("java");
    resolved
}
