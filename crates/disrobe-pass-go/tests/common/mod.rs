#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    unreachable_pub
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_go::GoAnalysis;

pub fn fixture_path(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

pub fn fixture(name: &str) -> Vec<u8> {
    let p: PathBuf = fixture_path(name);
    match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) => panic!(
            "missing fixture {}: {e}; regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1",
            p.display()
        ),
    }
}

pub fn fixture_or_skip(name: &str) -> Option<Vec<u8>> {
    let p: PathBuf = fixture_path(name);
    let bytes: Option<Vec<u8>> = std::fs::read(&p).ok();
    if bytes.is_none() {
        eprintln!(
            "\n========================================================================\n\
             SKIPPED: fixture `{name}` absent at {}.\n\
             This assertion did NOT run and is NOT CI-enforced. A green result here is\n\
             a SKIP, not a measured pass. Regenerate the fixtures (Go toolchain required):\n\
             pwsh crates/disrobe-pass-go/tests/fixtures/regen.ps1\n\
             ========================================================================\n",
            p.display()
        );
    }
    bytes
}

pub const HELLO_NORMAL: &str = "hello_normal.exe";
pub const HELLO_STRIPPED: &str = "hello_stripped.exe";
pub const HELLO_GARBLE: &str = "hello_garble.exe";
pub const GARBLE_LITERALS_INDIRECT: &str = "garble_literals_indirect.exe";
pub const HELLO_EMBED: &str = "hello_embed.exe";
pub const HELLO_DEPS: &str = "hello_deps.exe";
pub const HELLO_GENERICS: &str = "hello_generics.exe";
pub const HELLO_GENERICS_STRIPPED: &str = "hello_generics_stripped.exe";
pub const HELLO_386: &str = "hello_386.exe";
pub const BENCH_GENERICS: &str = "bench_generics.exe";
pub const BENCH_GENERICS_STRIPPED: &str = "bench_generics_stripped.exe";
pub const BENCH_GENERICS_NM: &str = "bench_generics.nm.txt";

pub const BENCH_LINUX_AMD64: &str = "bench_generics_linux_amd64";
pub const BENCH_LINUX_AMD64_NM: &str = "bench_generics_linux_amd64.nm.txt";
pub const BENCH_LINUX_AMD64_NM_EQ: &str = "bench_generics_linux_amd64.nm_eq.txt";
pub const BENCH_LINUX_AMD64_NM_ITAB: &str = "bench_generics_linux_amd64.nm_itab.txt";
pub const BENCH_LINUX_ARM64: &str = "bench_generics_linux_arm64";
pub const BENCH_LINUX_ARM64_NM: &str = "bench_generics_linux_arm64.nm.txt";
pub const BENCH_LINUX_ARM64_NM_EQ: &str = "bench_generics_linux_arm64.nm_eq.txt";
pub const BENCH_LINUX_ARM64_NM_ITAB: &str = "bench_generics_linux_arm64.nm_itab.txt";
pub const BENCH_DARWIN_AMD64: &str = "bench_generics_darwin_amd64";
pub const BENCH_DARWIN_AMD64_NM: &str = "bench_generics_darwin_amd64.nm.txt";
pub const BENCH_DARWIN_AMD64_NM_EQ: &str = "bench_generics_darwin_amd64.nm_eq.txt";
pub const BENCH_DARWIN_AMD64_NM_ITAB: &str = "bench_generics_darwin_amd64.nm_itab.txt";
pub const BENCH_DARWIN_ARM64: &str = "bench_generics_darwin_arm64";
pub const BENCH_DARWIN_ARM64_NM: &str = "bench_generics_darwin_arm64.nm.txt";
pub const BENCH_DARWIN_ARM64_NM_EQ: &str = "bench_generics_darwin_arm64.nm_eq.txt";
pub const BENCH_DARWIN_ARM64_NM_ITAB: &str = "bench_generics_darwin_arm64.nm_itab.txt";

pub const GO124_WINDOWS_AMD64: &str = "hello_go124_windows_amd64";
pub const GO124_WINDOWS_AMD64_NM_EQ: &str = "hello_go124_windows_amd64.nm_eq.txt";
pub const GO124_WINDOWS_AMD64_NM_ITAB: &str = "hello_go124_windows_amd64.nm_itab.txt";

const PCLNTAB_MAGICS: [[u8; 4]; 4] = [
    [0xfb, 0xff, 0xff, 0xff],
    [0xfa, 0xff, 0xff, 0xff],
    [0xf0, 0xff, 0xff, 0xff],
    [0xf1, 0xff, 0xff, 0xff],
];

pub fn find_pclntab_offset(bytes: &[u8]) -> Option<usize> {
    let mut i: usize = 0;
    while i + 16 <= bytes.len() {
        for magic in &PCLNTAB_MAGICS {
            if &bytes[i..i + 4] == magic
                && bytes[i + 4] == 0
                && bytes[i + 5] == 0
                && matches!(bytes[i + 6], 1 | 2 | 4)
                && matches!(bytes[i + 7], 4 | 8)
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

pub fn fixture_with_patched_pclntab(name: &str, patch: impl Fn(&mut [u8])) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = fixture(name);
    let off: usize = find_pclntab_offset(&bytes)?;
    let end: usize = (off + 128).min(bytes.len());
    patch(&mut bytes[off..end]);
    Some(bytes)
}

pub fn go_on_path() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o: Output| o.status.success())
}

pub fn garble_on_path() -> bool {
    Command::new("garble")
        .arg("version")
        .output()
        .is_ok_and(|o: Output| o.status.success())
}

fn skip_note(reason: &str) {
    eprintln!(
        "\n========================================================================\n\
         SKIPPED (real-toolchain oracle): {reason}.\n\
         This assertion did NOT run and is NOT a measured pass. Install the toolchain\n\
         (Go 1.26 + `go install mvdan.cc/garble@latest`) and re-run to enforce it.\n\
         ========================================================================\n"
    );
}

pub struct GoBuildScratch {
    scratch: ScratchDir,
}

impl GoBuildScratch {
    pub fn path(&self) -> &Path {
        self.scratch.path()
    }
}

pub fn new_scratch(tag: &str) -> GoBuildScratch {
    let purpose: String = format!("disrobe_go_oracle_{tag}");
    let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
    GoBuildScratch { scratch }
}

pub fn write_module(scratch: &GoBuildScratch, module: &str, main_go: &str) {
    let go_mod: String = format!("module {module}\n\ngo 1.26\n");
    std::fs::write(scratch.path().join("go.mod"), go_mod).expect("write go.mod");
    std::fs::write(scratch.path().join("main.go"), main_go).expect("write main.go");
}

pub fn write_file(scratch: &GoBuildScratch, rel_path: &str, content: &str) {
    let target: PathBuf = scratch.path().join(rel_path);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).expect("create package dir");
    }
    std::fs::write(&target, content).expect("write package source");
}

fn build_env(cmd: &mut Command, dir: &Path) {
    cmd.current_dir(dir)
        .env("GOOS", "windows")
        .env("GOARCH", "amd64")
        .env("CGO_ENABLED", "0")
        .env("GO111MODULE", "on");
}

pub fn go_build(scratch: &GoBuildScratch, out_name: &str, extra: &[&str]) -> Option<PathBuf> {
    let out: PathBuf = scratch.path().join(out_name);
    let mut cmd: Command = Command::new("go");
    build_env(&mut cmd, scratch.path());
    cmd.arg("build").arg("-trimpath");
    for a in extra {
        cmd.arg(a);
    }
    cmd.arg("-o").arg(&out).arg(".");
    let output: Output = cmd.output().ok()?;
    if !output.status.success() {
        eprintln!(
            "go build ({out_name}) failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    Some(out)
}

pub fn go_build_cross(
    scratch: &GoBuildScratch,
    out_name: &str,
    goos: &str,
    goarch: &str,
    extra: &[&str],
) -> Option<PathBuf> {
    match go_build_cross_required(scratch, out_name, goos, goarch, extra) {
        Ok(out) => Some(out),
        Err(error) => {
            eprintln!("{error}");
            None
        }
    }
}

pub fn go_build_cross_required(
    scratch: &GoBuildScratch,
    out_name: &str,
    goos: &str,
    goarch: &str,
    extra: &[&str],
) -> Result<PathBuf, String> {
    let out: PathBuf = scratch.path().join(out_name);
    let mut cmd: Command = Command::new("go");
    cmd.current_dir(scratch.path())
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .env("CGO_ENABLED", "0")
        .env("GO111MODULE", "on");
    cmd.arg("build").arg("-trimpath");
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.arg("-o").arg(&out).arg(".");
    let output: Output = cmd.output().map_err(|error: std::io::Error| {
        format!("go build {goos}/{goarch} ({out_name}) could not start: {error}")
    })?;
    if output.status.success() {
        return Ok(out);
    }
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    Err(format!(
        "go build {goos}/{goarch} ({out_name}) failed with {}: {stderr}",
        output.status
    ))
}

pub fn garble_build(scratch: &GoBuildScratch, out_name: &str, extra: &[&str]) -> Option<PathBuf> {
    let out: PathBuf = scratch.path().join(out_name);
    let mut cmd: Command = Command::new("garble");
    build_env(&mut cmd, scratch.path());
    for a in extra {
        cmd.arg(a);
    }
    cmd.arg("build").arg("-o").arg(&out).arg(".");
    let output: Output = cmd.output().ok()?;
    if !output.status.success() {
        eprintln!(
            "garble build ({out_name}) failed (often a garble<->Go version mismatch):\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    Some(out)
}

pub fn parse_nm_text_symbols(text: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && matches!(cols[cols.len() - 2], "T" | "t") {
            out.insert(cols[cols.len() - 1].to_owned());
        }
    }
    out
}

pub const FUNCTION_NAME_ANCHORS: [&str; 2] = ["runtime.text", "runtime.etext"];

pub struct FunctionRecoveryGrade {
    pub hit: usize,
    pub total: usize,
    pub missing: Vec<String>,
}

impl FunctionRecoveryGrade {
    pub const fn percentage_hundredths(&self) -> u128 {
        if self.total == 0 {
            return 0;
        }
        (self.hit as u128).saturating_mul(10_000) / (self.total as u128)
    }

    pub fn percentage_display(&self) -> String {
        let hundredths: u128 = self.percentage_hundredths();
        format!("{}.{:02}%", hundredths / 100, hundredths % 100)
    }

    pub const fn meets_floor(&self, floor: FunctionRecoveryFloor) -> bool {
        (self.hit as u128).saturating_mul(floor.denominator as u128)
            >= (self.total as u128).saturating_mul(floor.numerator as u128)
    }
}

#[derive(Clone, Copy)]
pub struct FunctionRecoveryFloor {
    pub numerator: usize,
    pub denominator: usize,
}

impl FunctionRecoveryFloor {
    pub const fn new(numerator: usize, denominator: usize) -> Self {
        Self {
            numerator,
            denominator,
        }
    }
}

pub fn recovered_function_names(analysis: &GoAnalysis) -> BTreeSet<String> {
    let mut recovered: BTreeSet<String> = BTreeSet::new();
    for function in &analysis.symbols.funcs {
        recovered.insert(function.name.clone());
        if let Some(linker_symbol) = &function.linker_symbol {
            recovered.insert(linker_symbol.clone());
        }
    }
    recovered
}

pub fn grade_function_name_recovery(
    truth: &BTreeSet<String>,
    recovered: &BTreeSet<String>,
) -> FunctionRecoveryGrade {
    let eligible: BTreeSet<String> = truth
        .iter()
        .filter(|name: &&String| !FUNCTION_NAME_ANCHORS.contains(&name.as_str()))
        .cloned()
        .collect();
    let missing: Vec<String> = eligible
        .iter()
        .filter(|name: &&String| !recovered.contains(*name))
        .cloned()
        .collect();
    let hit: usize = eligible.len().saturating_sub(missing.len());
    FunctionRecoveryGrade {
        hit,
        total: eligible.len(),
        missing,
    }
}

pub fn grade_analyzed_function_names(
    analysis: &GoAnalysis,
    truth: &BTreeSet<String>,
) -> FunctionRecoveryGrade {
    let recovered: BTreeSet<String> = recovered_function_names(analysis);
    grade_function_name_recovery(truth, &recovered)
}

pub fn go_tool_nm_output(binary: &Path) -> Result<String, String> {
    let output: Output = Command::new("go")
        .args(["tool", "nm"])
        .arg(binary)
        .output()
        .map_err(|error: std::io::Error| {
            format!("go tool nm {} could not start: {error}", binary.display())
        })?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    Err(format!(
        "go tool nm {} failed with {}: {stderr}",
        binary.display(),
        output.status
    ))
}

pub fn parse_nm_text_symbol_vas(text: &str) -> std::collections::BTreeMap<String, u64> {
    let mut out: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3
            && matches!(cols[cols.len() - 2], "T" | "t")
            && let Ok(va) = u64::from_str_radix(cols[0], 16)
        {
            out.insert(cols[cols.len() - 1].to_owned(), va);
        }
    }
    out
}

pub fn addr2line_name(binary: &Path, va: u64) -> Option<String> {
    let mut child: std::process::Child = Command::new("go")
        .args(["tool", "addr2line"])
        .arg(binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    {
        use std::io::Write as _;
        let mut stdin: std::process::ChildStdin = child.stdin.take()?;
        writeln!(stdin, "{va:#x}").ok()?;
    }
    let output: Output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    text.lines().next().map(str::to_owned)
}

pub fn nm_text_symbols(binary: &Path) -> Option<BTreeSet<String>> {
    let output: Output = Command::new("go")
        .args(["tool", "nm"])
        .arg(binary)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_nm_text_symbols(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

pub fn parse_eq_type_names(text: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        for tok in line.split_whitespace() {
            if let Some(rest) = tok.strip_prefix("type:.eq.") {
                out.insert(normalize_type_name(rest));
            }
        }
    }
    out
}

pub fn nm_eq_type_names(binary: &Path) -> Option<BTreeSet<String>> {
    let output: Output = Command::new("go")
        .args(["tool", "nm"])
        .arg(binary)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_eq_type_names(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

pub fn parse_itab_pairs(text: &str) -> BTreeSet<(String, String)> {
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    for line in text.lines() {
        for tok in line.split_whitespace() {
            if let Some(rest) = tok.strip_prefix("go:itab.")
                && let Some((concrete, iface)) = rest.split_once(',')
            {
                out.insert((normalize_type_name(concrete), normalize_type_name(iface)));
            }
        }
    }
    out
}

pub fn nm_itab_pairs(binary: &Path) -> Option<BTreeSet<(String, String)>> {
    let output: Output = Command::new("go")
        .args(["tool", "nm"])
        .arg(binary)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_itab_pairs(&String::from_utf8_lossy(&output.stdout)))
}

fn strip_linker_dedup_suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(dot)
            if !name[dot + 1..].is_empty()
                && name[dot + 1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            &name[..dot]
        }
        _ => name,
    }
}

pub fn normalize_type_name(raw: &str) -> String {
    let no_ptr: &str = raw.trim_start_matches('*');
    let base: &str = no_ptr.split(['[', '·']).next().unwrap_or(no_ptr);
    let last: &str = base.rsplit('/').next().unwrap_or(base);
    strip_linker_dedup_suffix(last.trim_start_matches('*')).to_owned()
}

pub struct GoVersionM {
    pub go_version: Option<String>,
    pub path: Option<String>,
    pub settings: std::collections::BTreeMap<String, String>,
}

pub fn go_version_m(binary: &Path) -> Option<GoVersionM> {
    let output: Output = Command::new("go")
        .args(["version", "-m"])
        .arg(binary)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    let mut info: GoVersionM = GoVersionM {
        go_version: None,
        path: None,
        settings: std::collections::BTreeMap::new(),
    };
    for raw in text.lines() {
        if let Some(rest) = raw.strip_prefix('\t') {
            if let Some(v) = rest.strip_prefix("path\t") {
                info.path = Some(v.to_owned());
            } else if let Some(v) = rest.strip_prefix("build\t")
                && let Some((k, val)) = v.split_once('=')
            {
                info.settings.insert(k.to_owned(), val.to_owned());
            }
        } else if let Some(v) = raw.split_once(": go") {
            info.go_version = Some(format!("go{}", v.1.trim()));
        }
    }
    Some(info)
}

pub fn require_go() -> bool {
    if go_on_path() {
        return true;
    }
    skip_note("Go toolchain absent from PATH");
    false
}

const GO_GRADING_VERSION: &str = "go1.26.3";

pub fn require_go_1_26_3_for_grading() -> Result<Option<String>, String> {
    let output: Output = match Command::new("go").arg("version").output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("SKIP live Go grading: go executable not found");
            return Ok(None);
        }
        Err(error) => return Err(format!("go version could not start: {error}")),
    };
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(format!(
            "go version failed with {}: {stderr}",
            output.status
        ));
    }
    let version: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let required_prefix: String = format!("go version {GO_GRADING_VERSION} ");
    if !version.starts_with(&required_prefix) {
        return Err(format!(
            "live Go grading requires {GO_GRADING_VERSION}, found {version}"
        ));
    }
    Ok(Some(version))
}

pub fn require_garble() -> bool {
    if garble_on_path() {
        return true;
    }
    skip_note("garble absent from PATH (go install mvdan.cc/garble@latest)");
    false
}
