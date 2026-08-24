#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_jvm::{
    AabExtract, AarExtract, AndroidBackend, ApkExtract, ApksExtract, AppliedNames,
    BackendCapability, BackendInvocation, CLASS_MAGIC, ClassFile, DEX_MAGIC_PREFIX,
    DecompiledClass, DecompiledDex, Dex2JarLimits, DexFile, DexStringRecovery, FieldId,
    FingerprintReport, Instruction, JarEntry, JarExtract, JniPrototype, JniSurfaceReport,
    JvmBackend, LibrarySignatureSet, MethodId, NativeMethod, OatEmbeddedDex, Operands, PeelStatus,
    PeeledClass, ProguardMapping, ProtectorPeelReport, ResolvedNative, RetracedFrame,
    analyze_jni_native_methods, apply_proguard_mapping, assemble_jar_with_limit, decompile_class,
    decompile_dex, detect_available, detect_protector_family, disassemble, emit_jni_prototypes,
    extract_aab, extract_aar, extract_apk, extract_apks, extract_jar, extract_native_methods,
    extract_oat_dex, fingerprint_library_symbols, invoke_android, invoke_jvm,
    native_methods_from_class, parse_classfile, parse_code_attribute, parse_dex,
    parse_proguard_mapping, peel_and_decompile_classfile, recover_dex_reflection_strings,
    translate_dex_bytes_with_limits, validate_dex2jar_entries,
};
use disrobe_pass_native::backend_export::{
    DalvikSymbolKey, ExportFormat, ExportSymbol, SYMBOL_EXPORT_SCHEMA, SymbolClass, SymbolExport,
    SymbolKey, SymbolOrigin, render_ghidra_postscript, render_idapython, render_symbol_map_json,
};
use std::fmt::Write as _;

use super::backend_export::{BackendExportTarget, SupplementalOutput, write_supplemental_output};
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
            value_enum,
            help = "emit recovered standalone DEX class, method, and field identifiers as a Ghidra script, IDAPython script, or JSON symbol map"
        )]
        format: Option<BackendExportTarget>,
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
    #[command(
        about = "translate a standalone .dex into deterministic .class files and classes.jar in-house"
    )]
    Dex2Jar {
        #[arg(help = "input standalone .dex file")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-dex2jar)")]
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
    #[command(
        about = "link declared `native` methods across the DEX/classfile <-> .so/.dll/.dylib JNI boundary and emit C prototypes"
    )]
    Jni {
        #[arg(help = "input .class / .jar / .dex / .apk / .aab / .aar / .apks / .oat file")]
        input: PathBuf,
        #[arg(
            long = "native",
            value_name = "LIB",
            help = "native library (.so / .dll / .dylib) or a split .apk/.apks, repeatable; required for a bare .class/.jar/.dex input, additive on top of the native libraries and dex a self-contained .apk/.aab/.aar/.apks already carries"
        )]
        native: Vec<PathBuf>,
        #[arg(long, help = "emit the JNI link table as machine-clean JSON to stdout")]
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

struct DecompileOptions {
    input: PathBuf,
    out: Option<PathBuf>,
    backend: JvmBackendKind,
    timeout_secs: u64,
    emit: Vec<String>,
    format: Option<BackendExportTarget>,
    mapping: Option<PathBuf>,
    library: Vec<PathBuf>,
    peel: bool,
}

pub(crate) fn run(action: JvmCmd) -> miette::Result<()> {
    match action {
        JvmCmd::Decompile {
            input,
            out,
            backend,
            timeout_secs,
            emit,
            format,
            mapping,
            library,
            peel,
        } => decompile(DecompileOptions {
            input,
            out,
            backend,
            timeout_secs,
            emit,
            format,
            mapping,
            library,
            peel,
        }),
        JvmCmd::Extract { input, out } => extract(input, out),
        JvmCmd::Dex2Jar { input, out } => dex2jar(input, out),
        JvmCmd::Backends => backends(),
        JvmCmd::Retrace {
            mapping,
            class,
            method,
            line,
            json,
        } => retrace(mapping, class, method, line, json),
        JvmCmd::Jni {
            input,
            native,
            json,
        } => jni_link(input, native, json),
    }
}

const MAX_IN_HOUSE_DEX_CLASSES: usize = 65_536;
const MAX_IN_HOUSE_DEX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_IN_HOUSE_DEX_OUTPUT_BYTES: usize = 128 * 1024 * 1024;

fn read_in_house_dex_input(path: &Path) -> miette::Result<Vec<u8>> {
    let mut file: std::fs::File = std::fs::File::open(path)
        .map_err(|e| miette::miette!("DR-CLI-0480: cannot read DEX input: {e}"))?;
    let mut bytes: Vec<u8> = Vec::new();
    let mut buffer: Box<[u8]> = vec![0; 64 * 1024].into_boxed_slice();
    loop {
        let read: usize = file
            .read(&mut buffer)
            .map_err(|e| miette::miette!("DR-CLI-0480: cannot read DEX input: {e}"))?;
        if read == 0 {
            return Ok(bytes);
        }
        let next: usize = bytes
            .len()
            .checked_add(read)
            .ok_or_else(|| miette::miette!("DR-CLI-0481: DEX input size overflow"))?;
        if next > MAX_IN_HOUSE_DEX_INPUT_BYTES {
            return Err(miette::miette!(
                "DR-CLI-0482: DEX input exceeds the {}-byte input limit",
                MAX_IN_HOUSE_DEX_INPUT_BYTES
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn dex2jar_staging_dir(out_dir: &Path) -> miette::Result<PathBuf> {
    let parent: &Path = out_dir
        .parent()
        .filter(|path: &&Path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| {
        miette::miette!(
            "DR-CLI-0492: cannot create DEX-to-JAR output parent {} before staging: {error}",
            parent.display()
        )
    })?;
    let stem: &OsStr = out_dir.file_name().unwrap_or_else(|| OsStr::new("dex2jar"));
    for attempt in 0..32_u32 {
        let candidate: PathBuf = parent.join(format!(
            ".{}-dex2jar-{}-{attempt}",
            stem.to_string_lossy(),
            std::process::id()
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(miette::miette!(
                    "DR-CLI-0492: cannot create DEX-to-JAR staging directory: {error}"
                ));
            }
        }
    }
    Err(miette::miette!(
        "DR-CLI-0492: cannot allocate a DEX-to-JAR staging directory"
    ))
}

fn remove_dex2jar_staging(path: &Path) -> miette::Result<()> {
    std::fs::remove_dir_all(path).map_err(|error| {
        miette::miette!(
            "DR-CLI-0497: cannot remove DEX-to-JAR staging directory {}: {error}",
            path.display()
        )
    })
}

fn write_dex2jar_staging_file(path: &Path, bytes: &[u8]) -> miette::Result<()> {
    let mut file: std::fs::File = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            miette::miette!(
                "DR-CLI-0494: cannot exclusively create staged DEX-to-JAR file {}: {error}",
                path.display()
            )
        })?;
    file.write_all(bytes).map_err(|error| {
        miette::miette!(
            "DR-CLI-0494: cannot write staged DEX-to-JAR file {}: {error}",
            path.display()
        )
    })
}

fn finalize_dex2jar_staging(staging: &Path, out_dir: &Path) -> miette::Result<()> {
    let destination_exists: bool = out_dir.try_exists().map_err(|error| {
        miette::miette!(
            "DR-CLI-0496: cannot check DEX-to-JAR destination {} before finalizing staging directory {}: {error}",
            out_dir.display(),
            staging.display()
        )
    })?;
    if destination_exists {
        return Err(miette::miette!(
            "DR-CLI-0484: DEX-to-JAR output directory appeared before finalization: {}; staging directory: {}",
            out_dir.display(),
            staging.display()
        ));
    }
    std::fs::rename(staging, out_dir).map_err(|error| {
        miette::miette!(
            "DR-CLI-0496: cannot finalize DEX-to-JAR staging directory {} as {}: {error}",
            staging.display(),
            out_dir.display()
        )
    })
}

fn dex2jar(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = read_in_house_dex_input(&input)?;
    if !matches!(classify(&bytes, &input), ClassformatKind::Dex) {
        return Err(miette::miette!(
            "DR-CLI-0483: dex2jar requires a standalone DEX input"
        ));
    }
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dex2jar")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dex2jar")));
    if globals::current().dry_run {
        println!("jvm dex2jar: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  out dir:      {}", out_dir.display());
        return Ok(());
    }
    if out_dir.exists() {
        return Err(miette::miette!(
            "DR-CLI-0484: DEX-to-JAR output directory already exists: {}",
            out_dir.display()
        ));
    }
    let limits: Dex2JarLimits = Dex2JarLimits {
        input_bytes: MAX_IN_HOUSE_DEX_INPUT_BYTES,
        classes: MAX_IN_HOUSE_DEX_CLASSES,
        class_bytes: MAX_IN_HOUSE_DEX_OUTPUT_BYTES,
        jar_bytes: MAX_IN_HOUSE_DEX_OUTPUT_BYTES,
    };
    let translated = translate_dex_bytes_with_limits(&bytes, limits)
        .map_err(|e| miette::miette!("DR-CLI-0489: in-house DEX translation: {e}"))?;
    validate_dex2jar_entries(&translated.jar_entries)
        .map_err(|e| miette::miette!("DR-CLI-0486: in-house class path validation: {e}"))?;
    let jar: Vec<u8> = assemble_jar_with_limit(&translated, MAX_IN_HOUSE_DEX_OUTPUT_BYTES)
        .map_err(|e| miette::miette!("DR-CLI-0490: in-house JAR assembly: {e}"))?;
    if jar.len() > MAX_IN_HOUSE_DEX_OUTPUT_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0491: in-house JAR output reached {} bytes, exceeding the {}-byte output limit",
            jar.len(),
            MAX_IN_HOUSE_DEX_OUTPUT_BYTES
        ));
    }
    let staging: PathBuf = dex2jar_staging_dir(&out_dir)?;
    let write_result: miette::Result<()> = (|| {
        for (path, class_bytes) in &translated.jar_entries {
            let target: PathBuf = staging.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    miette::miette!("DR-CLI-0493: cannot create class output directory: {error}")
                })?;
            }
            write_dex2jar_staging_file(&target, class_bytes)?;
        }
        write_dex2jar_staging_file(&staging.join("classes.jar"), &jar)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        if let Err(cleanup) = remove_dex2jar_staging(&staging) {
            return Err(miette::miette!("{error}; {cleanup}"));
        }
        return Err(error);
    }
    if let Err(error) = finalize_dex2jar_staging(&staging, &out_dir) {
        if let Err(cleanup) = remove_dex2jar_staging(&staging) {
            return Err(miette::miette!(
                "DR-CLI-0496: cannot finalize DEX-to-JAR output: {error}; {cleanup}"
            ));
        }
        return Err(miette::miette!(
            "DR-CLI-0496: cannot finalize DEX-to-JAR output: {error}"
        ));
    }
    let jar_path: PathBuf = out_dir.join("classes.jar");
    println!(
        "jvm dex2jar: {}",
        if translated.code_scan_complete && translated.stubbed_body_count == 0 {
            "OK"
        } else {
            "PARTIAL"
        }
    );
    println!("  classes:      {}", translated.jar_entries.len());
    println!(
        "  methods:      {} total, {} recovered, {} stubbed",
        translated.method_total, translated.bodies_recovered, translated.stubbed_body_count
    );
    println!(
        "  code scan:    {} ({} decode error(s))",
        if translated.code_scan_complete {
            "complete"
        } else {
            "partial"
        },
        translated.decode_error_count
    );
    for diagnostic in &translated.diagnostics {
        let identity: String = diagnostic.method.as_ref().map_or_else(
            || diagnostic.class.clone(),
            |method: &String| format!("{}.{}", diagnostic.class, method),
        );
        println!("  partial:      {identity}: {}", diagnostic.reason);
    }
    println!("  jar:          {}", jar_path.display());
    println!("  out dir:      {}", out_dir.display());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod dex2jar_tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use disrobe_pass_jvm::validate_dex2jar_entries;

    use super::{dex2jar_staging_dir, finalize_dex2jar_staging, write_dex2jar_staging_file};

    #[test]
    fn dex2jar_path_validation_rejects_escaping_and_normalized_paths() {
        for path in [
            "../Escape.class",
            "a//B.class",
            "a/../B.class",
            "C:/B.class",
            "CON.class",
            "PRN.class",
            "AUX.class",
            "NUL.class",
            "CLOCK$.class",
            "COM1.class",
            "LPT9.class",
            "name:stream.class",
            "tail .class",
            "tail..class",
        ] {
            let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            entries.insert(path.to_owned(), vec![0xCA, 0xFE, 0xBA, 0xBE]);
            assert!(validate_dex2jar_entries(&entries).is_err(), "{path}");
        }
    }

    #[test]
    fn dex2jar_staging_files_are_created_exclusively() {
        let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary directory");
        let path: PathBuf = directory.path().join("A.class");
        write_dex2jar_staging_file(&path, b"first").expect("first exclusive create");
        let error: miette::Report = write_dex2jar_staging_file(&path, b"second")
            .expect_err("second exclusive create must fail");
        assert!(error.to_string().contains(&path.display().to_string()));
        assert_eq!(
            std::fs::read(path).expect("preserved staged file"),
            b"first"
        );
    }

    #[test]
    fn dex2jar_staging_creates_a_missing_output_parent() {
        let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary directory");
        let output: PathBuf = directory.path().join("missing").join("result");
        let staging: PathBuf = dex2jar_staging_dir(&output).expect("sibling staging directory");
        assert_eq!(staging.parent(), output.parent());
        assert!(output.parent().is_some_and(std::path::Path::is_dir));
        assert!(staging.is_dir());
    }

    #[test]
    fn dex2jar_finalization_rechecks_the_destination() {
        let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary directory");
        let staging: PathBuf = directory.path().join("staging");
        let output: PathBuf = directory.path().join("output");
        std::fs::create_dir(&staging).expect("staging directory");
        std::fs::create_dir(&output).expect("racing output directory");
        let error: miette::Report = finalize_dex2jar_staging(&staging, &output)
            .expect_err("existing destination must be refused");
        assert!(error.to_string().contains("DR-CLI-0484"));
        assert!(error.to_string().contains(&staging.display().to_string()));
        assert!(staging.is_dir());
        assert!(output.is_dir());
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

#[derive(Debug, Clone, Copy)]
enum JniInputKind {
    Class,
    Dex,
    Jar,
    Apk,
    Aab,
    Aar,
    Apks,
    Oat,
    Unknown,
}

fn classify_jni_input(bytes: &[u8], path: &std::path::Path) -> JniInputKind {
    if bytes.len() >= 4
        && u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == CLASS_MAGIC
    {
        return JniInputKind::Class;
    }
    if bytes.len() >= 8 && &bytes[..4] == DEX_MAGIC_PREFIX.as_slice() && bytes[7] == 0 {
        return JniInputKind::Dex;
    }
    let ext: Option<String> = path
        .extension()
        .and_then(OsStr::to_str)
        .map(str::to_ascii_lowercase);
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        return match ext.as_deref() {
            Some("apk") => JniInputKind::Apk,
            Some("aab") => JniInputKind::Aab,
            Some("aar") => JniInputKind::Aar,
            Some("apks") => JniInputKind::Apks,
            _ => JniInputKind::Jar,
        };
    }
    if bytes.len() >= 4 && bytes[..4] == [0x7F, b'E', b'L', b'F'] && ext.as_deref() == Some("oat") {
        return JniInputKind::Oat;
    }
    JniInputKind::Unknown
}

struct JniInputSet {
    native_methods: Vec<NativeMethod>,
    native_libs: Vec<(String, Vec<u8>)>,
    code_scan_complete: bool,
    decode_error_count: usize,
}

struct NativeArgSet {
    native_libs: Vec<(String, Vec<u8>)>,
    dex_files: BTreeMap<String, Vec<u8>>,
}

fn merge_apk_splits(splits: &BTreeMap<String, ApkExtract>) -> NativeArgSet {
    let mut dex_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut native_libs: Vec<(String, Vec<u8>)> = Vec::new();
    for (split_name, split) in splits {
        for (entry_path, bytes) in &split.dex_files {
            dex_files.insert(format!("{split_name}/{entry_path}"), bytes.clone());
        }
        for (entry_path, bytes) in &split.native_libs {
            native_libs.push((format!("{split_name}/{entry_path}"), bytes.clone()));
        }
    }
    NativeArgSet {
        native_libs,
        dex_files,
    }
}

fn read_native_args(paths: &[PathBuf]) -> miette::Result<NativeArgSet> {
    let mut native_libs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut dex_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for path in paths {
        let bytes: Vec<u8> = std::fs::read(path).map_err(|e| {
            miette::miette!(
                "DR-CLI-0459: cannot read native library {}: {e}",
                path.display()
            )
        })?;
        let label: String = path.display().to_string();
        let ext: Option<String> = path
            .extension()
            .and_then(OsStr::to_str)
            .map(str::to_ascii_lowercase);
        let is_zip: bool = bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04";
        match (is_zip, ext.as_deref()) {
            (true, Some("apk")) => {
                let extract: ApkExtract = extract_apk(&bytes).map_err(|e| {
                    miette::miette!("DR-CLI-0472: --native apk extract for {label}: {e}")
                })?;
                for (entry_path, lib_bytes) in extract.native_libs {
                    native_libs.push((format!("{label}/{entry_path}"), lib_bytes));
                }
                for (entry_path, dex_bytes) in extract.dex_files {
                    dex_files.insert(format!("{label}/{entry_path}"), dex_bytes);
                }
            }
            (true, Some("apks")) => {
                let extract: ApksExtract = extract_apks(&bytes).map_err(|e| {
                    miette::miette!("DR-CLI-0473: --native apks extract for {label}: {e}")
                })?;
                let merged: NativeArgSet = merge_apk_splits(&extract.splits);
                for (entry_path, dex_bytes) in merged.dex_files {
                    dex_files.insert(format!("{label}/{entry_path}"), dex_bytes);
                }
                for (entry_path, lib_bytes) in merged.native_libs {
                    native_libs.push((format!("{label}/{entry_path}"), lib_bytes));
                }
            }
            _ => native_libs.push((label, bytes)),
        }
    }
    Ok(NativeArgSet {
        native_libs,
        dex_files,
    })
}

fn native_methods_from_dex_entries(
    dex_files: &BTreeMap<String, Vec<u8>>,
) -> (Vec<NativeMethod>, bool, usize) {
    let mut native_methods: Vec<NativeMethod> = Vec::new();
    let mut code_scan_complete: bool = true;
    let mut decode_error_count: usize = 0;
    for (name, bytes) in dex_files {
        let leaf: &str = name.rsplit('/').next().unwrap_or(name.as_str());
        if !(leaf.starts_with("classes") && leaf.to_ascii_lowercase().ends_with(".dex")) {
            continue;
        }
        let Ok(dex): Result<DexFile, _> = parse_dex(bytes) else {
            code_scan_complete = false;
            decode_error_count += 1;
            continue;
        };
        if let Ok(methods) = extract_native_methods(&dex, bytes) {
            native_methods.extend(methods);
        } else {
            code_scan_complete = false;
            decode_error_count += 1;
        }
    }
    (native_methods, code_scan_complete, decode_error_count)
}

fn is_native_library_path(path: &str) -> bool {
    if !path.contains("/lib/") {
        return false;
    }
    std::path::Path::new(path)
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext: &str| {
            ext.eq_ignore_ascii_case("so")
                || ext.eq_ignore_ascii_case("dll")
                || ext.eq_ignore_ascii_case("dylib")
        })
}

fn aab_native_libs(extract: &AabExtract) -> Vec<(String, Vec<u8>)> {
    extract
        .jar
        .entries
        .iter()
        .filter(|entry: &&JarEntry| is_native_library_path(entry.path.as_str()))
        .map(|entry: &JarEntry| (entry.path.clone(), entry.bytes.clone()))
        .collect()
}

fn aab_dex_files(extract: &AabExtract) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for module in extract.modules.values() {
        for (name, data) in &module.dex_files {
            out.insert(format!("{}/{name}", module.name), data.clone());
        }
    }
    out
}

fn native_methods_from_classes_jar(extract: &JarExtract) -> (Vec<NativeMethod>, bool, usize) {
    let mut native_methods: Vec<NativeMethod> = Vec::new();
    let mut code_scan_complete: bool = true;
    let mut decode_error_count: usize = 0;
    for class_bytes in extract.classes.values() {
        let Ok(cf): Result<ClassFile, _> = parse_classfile(class_bytes) else {
            code_scan_complete = false;
            decode_error_count += 1;
            continue;
        };
        native_methods.extend(native_methods_from_class(&cf));
    }
    (native_methods, code_scan_complete, decode_error_count)
}

fn native_methods_from_oat_dex(embedded: &[OatEmbeddedDex]) -> (Vec<NativeMethod>, bool, usize) {
    let mut native_methods: Vec<NativeMethod> = Vec::new();
    let mut code_scan_complete: bool = true;
    let mut decode_error_count: usize = 0;
    for dex in embedded {
        let Ok(dex_file): Result<DexFile, _> = parse_dex(&dex.bytes) else {
            code_scan_complete = false;
            decode_error_count += 1;
            continue;
        };
        if let Ok(methods) = extract_native_methods(&dex_file, &dex.bytes) {
            native_methods.extend(methods);
        } else {
            code_scan_complete = false;
            decode_error_count += 1;
        }
    }
    (native_methods, code_scan_complete, decode_error_count)
}

fn collect_primary_jni_input(path: &std::path::Path, bytes: &[u8]) -> miette::Result<JniInputSet> {
    match classify_jni_input(bytes, path) {
        JniInputKind::Dex => {
            let dex: DexFile =
                parse_dex(bytes).map_err(|e| miette::miette!("DR-CLI-0460: dex parse: {e}"))?;
            let native_methods: Vec<NativeMethod> = extract_native_methods(&dex, bytes)
                .map_err(|e| miette::miette!("DR-CLI-0461: native method scan: {e}"))?;
            Ok(JniInputSet {
                native_methods,
                native_libs: Vec::new(),
                code_scan_complete: true,
                decode_error_count: 0,
            })
        }
        JniInputKind::Class => {
            let cf: ClassFile = parse_classfile(bytes)
                .map_err(|e| miette::miette!("DR-CLI-0462: classfile parse: {e}"))?;
            Ok(JniInputSet {
                native_methods: native_methods_from_class(&cf),
                native_libs: Vec::new(),
                code_scan_complete: true,
                decode_error_count: 0,
            })
        }
        JniInputKind::Jar => {
            let extract: JarExtract =
                extract_jar(bytes).map_err(|e| miette::miette!("DR-CLI-0463: jar extract: {e}"))?;
            let (native_methods, code_scan_complete, decode_error_count): (
                Vec<NativeMethod>,
                bool,
                usize,
            ) = native_methods_from_classes_jar(&extract);
            Ok(JniInputSet {
                native_methods,
                native_libs: Vec::new(),
                code_scan_complete,
                decode_error_count,
            })
        }
        JniInputKind::Apk => {
            let extract: ApkExtract =
                extract_apk(bytes).map_err(|e| miette::miette!("DR-CLI-0464: apk extract: {e}"))?;
            let (native_methods, code_scan_complete, decode_error_count): (
                Vec<NativeMethod>,
                bool,
                usize,
            ) = native_methods_from_dex_entries(&extract.dex_files);
            let native_libs: Vec<(String, Vec<u8>)> = extract.native_libs.into_iter().collect();
            Ok(JniInputSet {
                native_methods,
                native_libs,
                code_scan_complete,
                decode_error_count,
            })
        }
        JniInputKind::Aab => {
            let extract: AabExtract =
                extract_aab(bytes).map_err(|e| miette::miette!("DR-CLI-0465: aab extract: {e}"))?;
            let dex_files: BTreeMap<String, Vec<u8>> = aab_dex_files(&extract);
            let (native_methods, code_scan_complete, decode_error_count): (
                Vec<NativeMethod>,
                bool,
                usize,
            ) = native_methods_from_dex_entries(&dex_files);
            let native_libs: Vec<(String, Vec<u8>)> = aab_native_libs(&extract);
            Ok(JniInputSet {
                native_methods,
                native_libs,
                code_scan_complete,
                decode_error_count,
            })
        }
        JniInputKind::Aar => {
            let extract: AarExtract =
                extract_aar(bytes).map_err(|e| miette::miette!("DR-CLI-0469: aar extract: {e}"))?;
            let (native_methods, code_scan_complete, decode_error_count): (
                Vec<NativeMethod>,
                bool,
                usize,
            ) = native_methods_from_classes_jar(&extract.classes_jar);
            let native_libs: Vec<(String, Vec<u8>)> = extract.native_libs.into_iter().collect();
            Ok(JniInputSet {
                native_methods,
                native_libs,
                code_scan_complete,
                decode_error_count,
            })
        }
        JniInputKind::Apks => {
            let extract: ApksExtract = extract_apks(bytes)
                .map_err(|e| miette::miette!("DR-CLI-0470: apks extract: {e}"))?;
            let merged: NativeArgSet = merge_apk_splits(&extract.splits);
            let (native_methods, code_scan_complete, decode_error_count): (
                Vec<NativeMethod>,
                bool,
                usize,
            ) = native_methods_from_dex_entries(&merged.dex_files);
            Ok(JniInputSet {
                native_methods,
                native_libs: merged.native_libs,
                code_scan_complete,
                decode_error_count,
            })
        }
        JniInputKind::Oat => {
            let embedded: Vec<OatEmbeddedDex> = extract_oat_dex(bytes)
                .map_err(|e| miette::miette!("DR-CLI-0471: oat dex extract: {e}"))?;
            let (native_methods, code_scan_complete, decode_error_count): (
                Vec<NativeMethod>,
                bool,
                usize,
            ) = native_methods_from_oat_dex(&embedded);
            Ok(JniInputSet {
                native_methods,
                native_libs: Vec::new(),
                code_scan_complete,
                decode_error_count,
            })
        }
        JniInputKind::Unknown => Err(miette::miette!(
            "DR-CLI-0466: input does not look like a .class/.jar/.dex/.apk/.aab/.aar/.apks/.oat \
             file"
        )),
    }
}

fn collect_jni_input(
    path: &std::path::Path,
    bytes: &[u8],
    extra: NativeArgSet,
) -> miette::Result<JniInputSet> {
    let mut input_set: JniInputSet = collect_primary_jni_input(path, bytes)?;
    input_set.native_libs.extend(extra.native_libs);
    if !extra.dex_files.is_empty() {
        let (extra_methods, extra_complete, extra_errors): (Vec<NativeMethod>, bool, usize) =
            native_methods_from_dex_entries(&extra.dex_files);
        input_set.native_methods.extend(extra_methods);
        input_set.code_scan_complete &= extra_complete;
        input_set.decode_error_count += extra_errors;
    }
    Ok(input_set)
}

#[derive(Debug, Clone, serde::Serialize)]
struct JniUnresolvedEntry {
    class: String,
    method: String,
    descriptor: String,
    jni_short_symbol: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct JniAmbiguousEntry {
    symbol: String,
    libraries: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct JniLinkReport {
    schema: &'static str,
    input: String,
    native_libraries: Vec<String>,
    surface: JniSurfaceReport,
    prototypes: Vec<JniPrototype>,
    unresolved: Vec<JniUnresolvedEntry>,
    ambiguous: Vec<JniAmbiguousEntry>,
}

fn derive_unresolved(surface: &JniSurfaceReport) -> Vec<JniUnresolvedEntry> {
    let mut out: Vec<JniUnresolvedEntry> = surface
        .native_methods
        .iter()
        .filter(|m: &&ResolvedNative| m.resolved_in.is_none())
        .map(|m: &ResolvedNative| JniUnresolvedEntry {
            class: m.class.clone(),
            method: m.method.clone(),
            descriptor: m.descriptor.clone(),
            jni_short_symbol: m.jni_short_symbol.clone(),
        })
        .collect();
    out.sort_by(|a: &JniUnresolvedEntry, b: &JniUnresolvedEntry| {
        (a.class.as_str(), a.method.as_str(), a.descriptor.as_str()).cmp(&(
            b.class.as_str(),
            b.method.as_str(),
            b.descriptor.as_str(),
        ))
    });
    out
}

fn derive_ambiguous(surface: &JniSurfaceReport) -> Vec<JniAmbiguousEntry> {
    let mut symbol_to_libs: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for lib in &surface.libraries {
        for sym in &lib.jni_exports {
            symbol_to_libs
                .entry(sym.as_str())
                .or_default()
                .push(lib.path.as_str());
        }
    }
    let mut out: Vec<JniAmbiguousEntry> = symbol_to_libs
        .into_iter()
        .filter(|(_, libs): &(&str, Vec<&str>)| libs.len() > 1)
        .map(|(symbol, libs): (&str, Vec<&str>)| JniAmbiguousEntry {
            symbol: symbol.to_owned(),
            libraries: libs.into_iter().map(str::to_owned).collect(),
        })
        .collect();
    out.sort_by(|a: &JniAmbiguousEntry, b: &JniAmbiguousEntry| a.symbol.cmp(&b.symbol));
    out
}

fn jni_link(input: PathBuf, native: Vec<PathBuf>, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0467: cannot read input: {e}"))?;
    let extra: NativeArgSet = read_native_args(&native)?;
    let input_set: JniInputSet = collect_jni_input(&input, &bytes, extra)?;
    let native_lib_refs: Vec<(&str, &[u8])> = input_set
        .native_libs
        .iter()
        .map(|(p, b): &(String, Vec<u8>)| (p.as_str(), b.as_slice()))
        .collect();
    let mut surface: JniSurfaceReport =
        analyze_jni_native_methods(&input_set.native_methods, &native_lib_refs);
    surface.code_scan_complete = input_set.code_scan_complete;
    surface.decode_error_count = input_set.decode_error_count;
    let prototypes: Vec<JniPrototype> = emit_jni_prototypes(&input_set.native_methods);
    let unresolved: Vec<JniUnresolvedEntry> = derive_unresolved(&surface);
    let ambiguous: Vec<JniAmbiguousEntry> = derive_ambiguous(&surface);
    let native_libraries: Vec<String> = surface.libraries.iter().map(|l| l.path.clone()).collect();
    let report: JniLinkReport = JniLinkReport {
        schema: "disrobe.jvm.jni-link/v1",
        input: input.display().to_string(),
        native_libraries,
        surface,
        prototypes,
        unresolved,
        ambiguous,
    };
    if json {
        let text: String = serde_json::to_string_pretty(&report)
            .map_err(|e| miette::miette!("DR-CLI-0468: jni link serialize: {e}"))?;
        println!("{text}");
        return Ok(());
    }
    print_jni_link_text(&report);
    Ok(())
}

fn print_jni_link_text(report: &JniLinkReport) {
    println!("jvm jni: OK");
    println!("  input:              {}", report.input);
    println!("  native libraries:   {}", report.surface.libraries.len());
    for lib in &report.surface.libraries {
        println!(
            "    - {} (abi={} format={} arch={} exports={})",
            lib.path,
            lib.abi.as_deref().unwrap_or("?"),
            lib.format,
            lib.arch,
            lib.jni_exports.len()
        );
    }
    println!(
        "  native methods:     {}",
        report.surface.native_method_count
    );
    println!(
        "  resolved static:    {}",
        report.surface.resolved_statically
    );
    println!("  dynamic only:       {}", report.surface.dynamic_only);
    println!(
        "  registered natives: {}",
        report.surface.registered_natives.len()
    );
    for reg in &report.surface.registered_natives {
        println!(
            "    - {} {} @ 0x{:x} in {} (fn={})",
            reg.name,
            reg.signature,
            reg.fn_addr,
            reg.library,
            reg.fn_symbol.as_deref().unwrap_or("?")
        );
    }
    println!(
        "  code scan:          {}",
        if report.surface.code_scan_complete {
            "complete".to_owned()
        } else {
            format!(
                "INCOMPLETE ({} decode error(s))",
                report.surface.decode_error_count
            )
        }
    );
    println!("  unresolved:         {}", report.unresolved.len());
    for u in &report.unresolved {
        println!(
            "    - {}.{}{} ({})",
            u.class, u.method, u.descriptor, u.jni_short_symbol
        );
    }
    if !report.ambiguous.is_empty() {
        println!("  ambiguous:          {}", report.ambiguous.len());
        for a in &report.ambiguous {
            println!("    - {} exported by {}", a.symbol, a.libraries.join(", "));
        }
    }
    println!("  prototypes:         {}", report.prototypes.len());
    for p in &report.prototypes {
        println!("    {}", p.declaration);
    }
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

fn decompile(options: DecompileOptions) -> miette::Result<()> {
    let DecompileOptions {
        input,
        out,
        backend: backend_choice,
        timeout_secs,
        emit: emit_kinds,
        format: export_target,
        mapping,
        library,
        peel,
    }: DecompileOptions = options;
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
    if export_target.is_some() && !matches!(format, ClassformatKind::Dex) {
        return Err(miette::miette!(
            "DR-CLI-0435: --format requires a standalone DEX input because class, JAR, and APK identifiers use different source keys"
        ));
    }

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
    let mut symbol_sidecar: Option<PathBuf> = None;

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
            if let Some(target) = export_target {
                let output: SupplementalOutput = render_dalvik_symbol_export(
                    &input,
                    &dx,
                    target,
                    target.standalone_path(&stem),
                )?;
                symbol_sidecar = Some(write_supplemental_output(&out_dir, &output)?);
            }
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
    if let Some(path) = symbol_sidecar {
        println!("  symbols:      {}", path.display());
    }
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

fn dalvik_symbol_export(input: &std::path::Path, dex: &DexFile) -> SymbolExport {
    let capacity: usize = dex
        .class_descriptors
        .len()
        .saturating_add(dex.method_ids.len())
        .saturating_add(dex.field_ids.len());
    let mut symbols: Vec<ExportSymbol> = Vec::with_capacity(capacity);
    for descriptor in &dex.class_descriptors {
        let descriptor: &String = descriptor;
        symbols.push(ExportSymbol {
            key: SymbolKey::Dalvik(DalvikSymbolKey::Class {
                descriptor: descriptor.clone(),
            }),
            name: descriptor.clone(),
            demangled: None,
            class: SymbolClass::Class,
            origin: SymbolOrigin::DalvikIdentifier,
            note: None,
        });
    }
    for method in &dex.method_ids {
        let method: &MethodId = method;
        let parameters: String = method.proto.parameters.concat();
        let signature: String = format!("({parameters}){}", method.proto.return_type);
        symbols.push(ExportSymbol {
            key: SymbolKey::Dalvik(DalvikSymbolKey::Method {
                owner: method.class.clone(),
                original_name: method.name.clone(),
                descriptor: signature,
            }),
            name: method.name.clone(),
            demangled: None,
            class: SymbolClass::Method,
            origin: SymbolOrigin::DalvikIdentifier,
            note: None,
        });
    }
    for field in &dex.field_ids {
        let field: &FieldId = field;
        symbols.push(ExportSymbol {
            key: SymbolKey::Dalvik(DalvikSymbolKey::Field {
                owner: field.class.clone(),
                original_name: field.name.clone(),
                descriptor: field.type_name.clone(),
            }),
            name: field.name.clone(),
            demangled: None,
            class: SymbolClass::Field,
            origin: SymbolOrigin::DalvikIdentifier,
            note: None,
        });
    }
    let symbol_count: usize = symbols.len();
    SymbolExport {
        schema: SYMBOL_EXPORT_SCHEMA,
        source: input.display().to_string(),
        format: "dex-dalvik".to_owned(),
        image_base: None,
        original_entry_point: None,
        symbol_count,
        symbols,
    }
}

pub(crate) fn render_dalvik_symbol_export(
    input: &std::path::Path,
    dex: &DexFile,
    target: BackendExportTarget,
    relative_path: PathBuf,
) -> miette::Result<SupplementalOutput> {
    let format: ExportFormat = target.format();
    let export: SymbolExport = dalvik_symbol_export(input, dex);
    let rendered: String = match format {
        ExportFormat::Ghidra => render_ghidra_postscript(&export)
            .map_err(|error| miette::miette!("DR-CLI-0436: Dalvik symbol export: {error}"))?,
        ExportFormat::Ida => render_idapython(&export)
            .map_err(|error| miette::miette!("DR-CLI-0436: Dalvik symbol export: {error}"))?,
        ExportFormat::Json => render_symbol_map_json(&export)
            .map_err(|error| miette::miette!("DR-CLI-0436: Dalvik symbol export: {error}"))?,
    };
    SupplementalOutput::new(relative_path, rendered.into_bytes())
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
