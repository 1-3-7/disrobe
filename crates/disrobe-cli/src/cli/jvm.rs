#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_jvm::{
    AndroidBackend, BackendCapability, BackendInvocation, CLASS_MAGIC, ClassFile, DEX_MAGIC_PREFIX,
    DecompiledClass, DecompiledDex, DexFile, Instruction, JarExtract, JvmBackend, Operands,
    decompile_class, decompile_dex, detect_available, disassemble, extract_jar, invoke_android,
    invoke_jvm, parse_classfile, parse_code_attribute, parse_dex,
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
        } => decompile(input, out, backend, timeout_secs, emit),
        JvmCmd::Extract { input, out } => extract(input, out),
        JvmCmd::Backends => backends(),
    }
}

fn decompile(
    input: PathBuf,
    out: Option<PathBuf>,
    backend_choice: JvmBackendKind,
    timeout_secs: u64,
    emit_kinds: Vec<String>,
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
    let mut native_emitted: bool = false;

    let summary: serde_json::Value = match format {
        ClassformatKind::Classfile => {
            let cf: ClassFile = parse_classfile(&bytes)
                .map_err(|e| miette::miette!("DR-CLI-0402: classfile parse: {e}"))?;
            let invocation: Option<BackendInvocation> =
                run_jvm_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            native_emitted = emit_native_artifacts(&emit_kinds, &out_dir, &stem, &cf)?;
            classfile_summary(&input, &cf, invocation.as_ref())
        }
        ClassformatKind::Dex => {
            let dx: DexFile =
                parse_dex(&bytes).map_err(|e| miette::miette!("DR-CLI-0403: dex parse: {e}"))?;
            let native: DecompiledDex = decompile_dex(&dx, &bytes);
            native_emitted = emit_native_dex(&emit_kinds, &out_dir, &stem, &native)?;
            let invocation: Option<BackendInvocation> =
                run_android_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            dex_summary(&input, &dx, &native, invocation.as_ref())
        }
        ClassformatKind::Jar => {
            let extract: JarExtract = extract_jar(&bytes)
                .map_err(|e| miette::miette!("DR-CLI-0404: jar extract: {e}"))?;
            let invocation: Option<BackendInvocation> =
                run_jvm_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            jar_summary(&input, &extract, invocation.as_ref())
        }
        ClassformatKind::Apk => {
            let native: DecompiledDex = decompile_apk_dexes(&bytes);
            native_emitted = emit_native_dex(&emit_kinds, &out_dir, &stem, &native)?;
            let invocation: Option<BackendInvocation> =
                run_android_backend(&caps, backend_choice, &input, &out_dir, timeout_secs)?;
            apk_summary(&input, &native, invocation.as_ref())
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

    println!("jvm decompile: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {format:?}");
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
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
    invocation: Option<&BackendInvocation>,
) -> serde_json::Value {
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
        "backend_invoked": invocation.is_some(),
        "backend_exit_code": invocation.map(|i| i.exit_code),
    })
}

fn jar_summary(
    input: &std::path::Path,
    extract: &JarExtract,
    invocation: Option<&BackendInvocation>,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.jvm.decompile/v0",
        "input": input.display().to_string(),
        "format": "jar",
        "entries": extract.entries.len(),
        "classes": extract.classes.len(),
        "manifest_mf_present": extract.manifest.is_some(),
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
        class_count: 0,
        method_count: 0,
        fully_lifted_methods: 0,
        fallback_methods: 0,
    };
    let Ok(extract): Result<JarExtract, _> = extract_jar(apk_bytes) else {
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
            continue;
        };
        let part: DecompiledDex = decompile_dex(&dx, &entry.bytes);
        combined.source.push_str(&part.source);
        combined.class_count += part.class_count;
        combined.method_count += part.method_count;
        combined.fully_lifted_methods += part.fully_lifted_methods;
        combined.fallback_methods += part.fallback_methods;
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
) -> miette::Result<bool> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    let want_source: bool = spec.contains(EmitKind::Source);
    let want_disasm: bool = spec.contains(EmitKind::Disasm);
    if want_source {
        let path: PathBuf = out_dir.join(format!("{stem}.java"));
        std::fs::write(&path, native_decompile_source(cf))
            .map_err(|e| miette::miette!("DR-CLI-0420: cannot write native source: {e}"))?;
    }
    if want_disasm {
        let path: PathBuf = out_dir.join(format!("{stem}.disasm"));
        std::fs::write(&path, native_disassembly(cf))
            .map_err(|e| miette::miette!("DR-CLI-0421: cannot write native disasm: {e}"))?;
    }
    Ok(want_source || want_disasm)
}
