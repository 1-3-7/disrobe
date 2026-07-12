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
use std::sync::atomic::{AtomicU64, Ordering};

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

static BUILD_SEQ: AtomicU64 = AtomicU64::new(0);

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
    dir: PathBuf,
}

impl Drop for GoBuildScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl GoBuildScratch {
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

pub fn new_scratch(tag: &str) -> GoBuildScratch {
    let seq: u64 = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut dir: PathBuf = std::env::temp_dir();
    dir.push(format!(
        "disrobe_go_oracle_{tag}_{}_{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    GoBuildScratch { dir }
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
    let out: PathBuf = scratch.path().join(out_name);
    let mut cmd: Command = Command::new("go");
    cmd.current_dir(scratch.path())
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .env("CGO_ENABLED", "0")
        .env("GO111MODULE", "on");
    cmd.arg("build").arg("-trimpath");
    for a in extra {
        cmd.arg(a);
    }
    cmd.arg("-o").arg(&out).arg(".");
    let output: Output = cmd.output().ok()?;
    if !output.status.success() {
        eprintln!(
            "go build ({out_name}, {goos}/{goarch}) failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    Some(out)
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

pub fn require_garble() -> bool {
    if garble_on_path() {
        return true;
    }
    skip_note("garble absent from PATH (go install mvdan.cc/garble@latest)");
    false
}
