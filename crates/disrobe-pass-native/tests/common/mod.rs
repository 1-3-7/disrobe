#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_arguments
)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::PseudoAbi;

pub const HOST_ABI: PseudoAbi = if cfg!(windows) {
    PseudoAbi::MsX64
} else {
    PseudoAbi::SysV
};

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
pub const COMPILE_TIMEOUT: Duration = Duration::from_mins(1);
pub const LINK_TIMEOUT: Duration = Duration::from_mins(1);
pub const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerFamily {
    Gcc,
    Clang,
    Msvc,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerId {
    pub bin: &'static str,
    pub family: CompilerFamily,
    pub version: String,
}

const GCC_SUPPRESS_IF_CONVERSION: [&str; 5] = [
    "-fno-stack-protector",
    "-fno-optimize-sibling-calls",
    "-fno-if-conversion",
    "-fno-if-conversion2",
    "-fno-tree-loop-if-convert",
];

const CLANG_SUPPRESS_IF_CONVERSION: [&str; 2] =
    ["-fno-stack-protector", "-fno-optimize-sibling-calls"];

const GENERIC_SUPPRESS_IF_CONVERSION: [&str; 1] = ["-fno-stack-protector"];

#[must_use]
pub const fn codegen_flags(family: CompilerFamily) -> &'static [&'static str] {
    match family {
        CompilerFamily::Gcc => &GCC_SUPPRESS_IF_CONVERSION,
        CompilerFamily::Clang => &CLANG_SUPPRESS_IF_CONVERSION,
        CompilerFamily::Msvc | CompilerFamily::Unknown => &GENERIC_SUPPRESS_IF_CONVERSION,
    }
}

#[must_use]
pub fn probe_version(bin: &str) -> Option<String> {
    let captured: CapturedOutput = run_captured(
        Path::new(bin),
        &["--version"],
        PROBE_TIMEOUT,
        MAX_CAPTURE_BYTES,
    )
    .ok()
    .flatten()?;
    if captured.exit_code != Some(0) {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&captured.stdout);
    let first_line: &str = text.lines().next().unwrap_or("").trim();
    (!first_line.is_empty()).then(|| first_line.to_owned())
}

fn classify_family(version_text: &str) -> CompilerFamily {
    let lower: String = version_text.to_ascii_lowercase();
    if lower.contains("clang") {
        CompilerFamily::Clang
    } else if lower.contains("gcc") || lower.contains("free software foundation") {
        CompilerFamily::Gcc
    } else {
        CompilerFamily::Unknown
    }
}

#[must_use]
pub fn available_compilers() -> Vec<CompilerId> {
    let mut out: Vec<CompilerId> = Vec::with_capacity(3);
    let mut seen_versions: Vec<String> = Vec::with_capacity(3);
    for bin in ["gcc", "clang", "cc"] {
        let Some(version): Option<String> = probe_version(bin) else {
            continue;
        };
        if seen_versions.iter().any(|v: &String| v == &version) {
            continue;
        }
        seen_versions.push(version.clone());
        out.push(CompilerId {
            bin,
            family: classify_family(&version),
            version,
        });
    }
    out
}

#[must_use]
pub fn msvc_probe_reason() -> Option<String> {
    probe_version("cl")
        .is_none()
        .then(|| "cl.exe not on PATH".to_owned())
}

#[must_use]
pub fn cc() -> Option<String> {
    available_compilers()
        .into_iter()
        .find(|c: &CompilerId| c.bin == "gcc" || c.bin == "clang" || c.bin == "cc")
        .map(|c: CompilerId| c.bin.to_owned())
}

#[must_use]
pub fn gcc() -> Option<String> {
    available_compilers()
        .into_iter()
        .find(|c: &CompilerId| c.family == CompilerFamily::Gcc)
        .map(|_| "gcc".to_owned())
}

#[must_use]
pub fn clang() -> Option<String> {
    available_compilers()
        .into_iter()
        .find(|c: &CompilerId| c.family == CompilerFamily::Clang)
        .map(|_| "clang".to_owned())
}

#[must_use]
pub fn scratch_dir(purpose: &str) -> ScratchDir {
    ScratchDir::create(purpose).expect("create scratch directory")
}

#[must_use]
pub fn function_code(object_bytes: &[u8], name: &str) -> Option<(Vec<u8>, u64)> {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let candidates: [String; 2] = [name.to_owned(), format!("_{name}")];
    let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.name()
            .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
    })?;
    let section_index: object::SectionIndex = match sym.section() {
        object::SymbolSection::Section(idx) => idx,
        _ => return None,
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let size: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if size == 0 {
        let next_off: usize = file
            .symbols()
            .filter(|s: &object::Symbol<'_, '_>| {
                matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                    && s.address() > sym_addr
                    && s.kind() == object::SymbolKind::Text
                    && s.name().is_ok_and(|n: &str| !n.is_empty())
            })
            .filter_map(|s: object::Symbol<'_, '_>| {
                usize::try_from(s.address().saturating_sub(section.address())).ok()
            })
            .min()
            .unwrap_or(data.len());
        next_off.min(data.len())
    } else {
        start.saturating_add(size).min(data.len())
    };
    let slice: &[u8] = data.get(start..end)?;
    Some((slice.to_vec(), sym_addr))
}

#[must_use]
pub fn strip_includes(source: &str) -> String {
    source
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

#[derive(Debug)]
pub enum CompileOutcome {
    Object(Vec<u8>),
    Rejected(String),
}

#[must_use]
pub fn link_objects_to_exe(
    compiler: &str,
    opt: &str,
    extra: &[&str],
    objects: &[&Path],
    out_exe: &Path,
) -> CompileOutcome {
    let mut args: Vec<OsString> =
        Vec::with_capacity(objects.len().saturating_add(extra.len()).saturating_add(3));
    args.push(OsStr::new(opt).to_owned());
    for &flag in extra {
        args.push(OsStr::new(flag).to_owned());
    }
    args.push(OsStr::new("-o").to_owned());
    args.push(out_exe.as_os_str().to_owned());
    for obj in objects {
        args.push(obj.as_os_str().to_owned());
    }
    match run_captured(Path::new(compiler), &args, LINK_TIMEOUT, MAX_CAPTURE_BYTES) {
        Ok(Some(captured)) if captured.exit_code == Some(0) => match std::fs::read(out_exe) {
            Ok(bytes) => CompileOutcome::Object(bytes),
            Err(e) => CompileOutcome::Rejected(format!("linked but output missing: {e}")),
        },
        Ok(Some(captured)) => {
            CompileOutcome::Rejected(String::from_utf8_lossy(&captured.stderr).into_owned())
        }
        Ok(None) => CompileOutcome::Rejected(format!(
            "{compiler} link did not complete within {LINK_TIMEOUT:?}"
        )),
        Err(e) => CompileOutcome::Rejected(format!("{compiler} failed to spawn for link: {e}")),
    }
}

fn os_args(opt: &str, extra: &[&str], out: &Path, src: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::with_capacity(extra.len().saturating_add(4));
    args.push(OsStr::new(opt).to_owned());
    for &flag in extra {
        args.push(OsStr::new(flag).to_owned());
    }
    args.push(OsStr::new("-o").to_owned());
    args.push(out.as_os_str().to_owned());
    args.push(src.as_os_str().to_owned());
    args
}

#[must_use]
pub fn compile_object_reasoned(
    compiler: &str,
    opt: &str,
    extra: &[&str],
    source: &str,
    out: &Path,
) -> CompileOutcome {
    let scratch: ScratchDir = scratch_dir("disrobe-native-matrix-cc");
    let dir: PathBuf = scratch.path().to_path_buf();
    let stem: &str = out
        .file_stem()
        .and_then(|s: &OsStr| s.to_str())
        .unwrap_or("unit");
    let src: PathBuf = dir.join(format!("{stem}.c"));
    std::fs::write(&src, source.as_bytes()).expect("write source");
    let args: Vec<OsString> = os_args(opt, extra, out, &src);
    match run_captured(
        Path::new(compiler),
        &args,
        COMPILE_TIMEOUT,
        MAX_CAPTURE_BYTES,
    ) {
        Ok(Some(captured)) if captured.exit_code == Some(0) => match std::fs::read(out) {
            Ok(bytes) => CompileOutcome::Object(bytes),
            Err(e) => CompileOutcome::Rejected(format!("compiled but output missing: {e}")),
        },
        Ok(Some(captured)) => {
            CompileOutcome::Rejected(String::from_utf8_lossy(&captured.stderr).into_owned())
        }
        Ok(None) => CompileOutcome::Rejected(format!(
            "{compiler} did not complete within {COMPILE_TIMEOUT:?}"
        )),
        Err(e) => CompileOutcome::Rejected(format!("{compiler} failed to spawn: {e}")),
    }
}

#[must_use]
pub fn compile_object_opt(
    compiler: &str,
    opt: &str,
    extra: &[&str],
    source: &str,
    out: &Path,
) -> Option<Vec<u8>> {
    match compile_object_reasoned(compiler, opt, extra, source, out) {
        CompileOutcome::Object(bytes) => Some(bytes),
        CompileOutcome::Rejected(reason) => {
            eprintln!("compile with {compiler} failed: {reason}");
            None
        }
    }
}

#[must_use]
pub fn compile_object(compiler: &str, extra: &[&str], source: &str, out: &Path) -> Option<Vec<u8>> {
    compile_object_opt(compiler, "-O1", extra, source, out)
}

#[derive(Debug)]
pub enum RunOutcome {
    Ok(String),
    Failed(String),
}

#[must_use]
pub fn link_and_run_reasoned(
    compiler: &str,
    driver: &str,
    link_object: &[u8],
    tag: &str,
    secs: u64,
) -> RunOutcome {
    let scratch: ScratchDir = scratch_dir("disrobe-native-matrix-link");
    let dir: PathBuf = scratch.path().to_path_buf();
    let obj: PathBuf = dir.join(format!("{tag}_link.o"));
    if let Err(e) = std::fs::write(&obj, link_object) {
        return RunOutcome::Failed(format!("write link object failed: {e}"));
    }
    let driver_c: PathBuf = dir.join(format!("{tag}_driver.c"));
    std::fs::write(&driver_c, driver.as_bytes()).expect("write driver");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        format!("{tag}.exe")
    } else {
        tag.to_owned()
    });
    let link_args: [OsString; 5] = [
        OsStr::new("-O1").to_owned(),
        OsStr::new("-o").to_owned(),
        exe.as_os_str().to_owned(),
        driver_c.as_os_str().to_owned(),
        obj.as_os_str().to_owned(),
    ];
    match run_captured(
        Path::new(compiler),
        &link_args,
        LINK_TIMEOUT,
        MAX_CAPTURE_BYTES,
    ) {
        Ok(Some(captured)) if captured.exit_code == Some(0) => {}
        Ok(Some(captured)) => {
            return RunOutcome::Failed(format!(
                "link failed: {}",
                String::from_utf8_lossy(&captured.stderr)
            ));
        }
        Ok(None) => {
            return RunOutcome::Failed(format!("link did not complete within {LINK_TIMEOUT:?}"));
        }
        Err(e) => return RunOutcome::Failed(format!("linker failed to spawn: {e}")),
    }
    let no_args: [&str; 0] = [];
    match run_captured(&exe, &no_args, Duration::from_secs(secs), MAX_CAPTURE_BYTES) {
        Ok(Some(captured)) => {
            RunOutcome::Ok(String::from_utf8_lossy(&captured.stdout).into_owned())
        }
        Ok(None) => RunOutcome::Failed(format!(
            "harness did not terminate within the {secs}s watchdog; a recovered loop is non-terminating"
        )),
        Err(e) => RunOutcome::Failed(format!("harness failed to spawn: {e}")),
    }
}

#[must_use]
pub fn link_and_run(
    compiler: &str,
    driver: &str,
    link_object: &[u8],
    tag: &str,
    secs: u64,
) -> String {
    match link_and_run_reasoned(compiler, driver, link_object, tag, secs) {
        RunOutcome::Ok(stdout) => stdout,
        RunOutcome::Failed(reason) => {
            panic!("{tag} link/run failed: {reason}\n--- {tag} driver ---\n{driver}")
        }
    }
}
