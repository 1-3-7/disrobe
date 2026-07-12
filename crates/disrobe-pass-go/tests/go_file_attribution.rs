#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_pass_go::{GoAnalysis, GoFunc, analyze};

const MAIN_SRC: &str = "package main\n\
\n\
import (\n\
\t\"fmt\"\n\
\n\
\t\"filemod/alpha\"\n\
\t\"filemod/beta\"\n\
)\n\
\n\
func main() {\n\
\tfmt.Println(alpha.AlphaOne(), alpha.AlphaTwo(), beta.BetaOne())\n\
}\n";

const ALPHA_SRC: &str = "package alpha\n\
\n\
//go:noinline\n\
func AlphaOne() int { return 11 }\n\
\n\
//go:noinline\n\
func AlphaTwo() int { return AlphaOne() + 1 }\n";

const BETA_SRC: &str = "package beta\n\
\n\
//go:noinline\n\
func BetaOne() int { return 22 }\n";

fn find_func<'a>(analysis: &'a GoAnalysis, name: &str) -> Option<&'a GoFunc> {
    analysis
        .symbols
        .funcs
        .iter()
        .find(|f: &&GoFunc| f.name == name)
}

fn addr2line_files(binary: &Path, addrs: &[u64]) -> Option<Vec<Option<String>>> {
    let mut child: std::process::Child = Command::new("go")
        .args(["tool", "addr2line"])
        .arg(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let stdin: &mut std::process::ChildStdin = child.stdin.as_mut()?;
        let mut buf: String = String::with_capacity(addrs.len() * 12);
        for a in addrs {
            let _ = writeln!(buf, "0x{a:x}");
        }
        stdin.write_all(buf.as_bytes()).ok()?;
    }
    let out: Output = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    let mut files: Vec<Option<String>> = Vec::with_capacity(addrs.len());
    for i in 0..addrs.len() {
        let file_line: Option<&&str> = lines.get(2 * i + 1);
        let parsed: Option<String> = file_line.and_then(|fl: &&str| {
            let (file, _line): (&str, &str) = fl.rsplit_once(':')?;
            if file == "?" || file.is_empty() {
                None
            } else {
                Some(file.replace('\\', "/"))
            }
        });
        files.push(parsed);
    }
    Some(files)
}

struct BuiltPair {
    _scratch: common::GoBuildScratch,
    normal: GoAnalysis,
    stripped: GoAnalysis,
    normal_path: PathBuf,
}

fn build_pair() -> Option<BuiltPair> {
    let scratch: common::GoBuildScratch = common::new_scratch("fileattr");
    common::write_module(&scratch, "filemod", MAIN_SRC);
    common::write_file(&scratch, "alpha/alpha.go", ALPHA_SRC);
    common::write_file(&scratch, "beta/beta.go", BETA_SRC);

    let normal: PathBuf = common::go_build(&scratch, "app_normal.exe", &[])?;
    let stripped: PathBuf = common::go_build(&scratch, "app_stripped.exe", &["-ldflags", "-s -w"])?;

    let normal_bytes: Vec<u8> = std::fs::read(&normal).expect("read normal build");
    let stripped_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped build");
    let normal_analysis: GoAnalysis = analyze(&normal_bytes).expect("analyze normal build");
    let stripped_analysis: GoAnalysis = analyze(&stripped_bytes).expect("analyze stripped build");
    Some(BuiltPair {
        _scratch: scratch,
        normal: normal_analysis,
        stripped: stripped_analysis,
        normal_path: normal,
    })
}

#[test]
fn stripped_binary_attributes_functions_to_source_files() {
    if !common::require_go() {
        return;
    }
    let Some(built): Option<BuiltPair> = build_pair() else {
        panic!("go build failed");
    };
    let normal_analysis: &GoAnalysis = &built.normal;
    let stripped_analysis: &GoAnalysis = &built.stripped;
    let normal_path: &Path = &built.normal_path;

    assert!(
        stripped_analysis.stripped.stripped,
        "the -s -w build must classify as stripped"
    );
    assert_eq!(
        stripped_analysis.pclntab_version, "go1.20+",
        "go1.26 emits the 0xfffffff1 pclntab carrying pcfile/cuOffset"
    );

    let authored: [(&str, &str); 4] = [
        ("filemod/alpha.AlphaOne", "alpha/alpha.go"),
        ("filemod/alpha.AlphaTwo", "alpha/alpha.go"),
        ("filemod/beta.BetaOne", "beta/beta.go"),
        ("main.main", "main.go"),
    ];
    for (name, want_suffix) in authored {
        let func: &GoFunc = find_func(stripped_analysis, name)
            .unwrap_or_else(|| panic!("stripped recovery dropped function {name}"));
        let file: &str = func
            .file
            .as_deref()
            .unwrap_or_else(|| panic!("no file attributed to {name} in stripped build"));
        assert!(
            file.replace('\\', "/").ends_with(want_suffix),
            "{name} must attribute to a file ending in {want_suffix}, got {file}"
        );
    }

    let runtime_main: &GoFunc =
        find_func(stripped_analysis, "runtime.main").expect("runtime.main must be recovered");
    assert_eq!(
        runtime_main
            .file
            .as_deref()
            .map(|f: &str| f.replace('\\', "/")),
        Some("runtime/proc.go".to_owned()),
        "runtime.main lives in runtime/proc.go, got {:?}",
        runtime_main.file
    );

    let total: usize = stripped_analysis.symbols.funcs.len();
    let with_file: usize = stripped_analysis
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.file.is_some())
        .count();
    let ratio: f64 = with_file as f64 / total.max(1) as f64;
    assert!(
        total > 100,
        "the binary exposes hundreds of funcs (got {total})"
    );
    assert!(
        ratio >= 0.95,
        "nearly every recovered func should carry a pcln source file, got {with_file}/{total} = {ratio:.3}"
    );

    for (name, _) in authored {
        let stripped_file: Option<String> = find_func(stripped_analysis, name)
            .and_then(|f: &GoFunc| f.file.clone())
            .map(|f: String| f.replace('\\', "/"));
        let normal_file: Option<String> = find_func(normal_analysis, name)
            .and_then(|f: &GoFunc| f.file.clone())
            .map(|f: String| f.replace('\\', "/"));
        assert_eq!(
            stripped_file, normal_file,
            "stripped and unstripped builds must attribute {name} to the same file"
        );
    }

    cross_check_against_addr2line(normal_analysis, normal_path);
}

fn nm_name_addrs(binary: &Path) -> Option<Vec<(String, u64)>> {
    let out: Output = Command::new("go")
        .args(["tool", "nm"])
        .arg(binary)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    let mut pairs: Vec<(String, u64)> = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || !matches!(cols[1], "T" | "t") {
            continue;
        }
        let Ok(va): Result<u64, _> = u64::from_str_radix(cols[0], 16) else {
            continue;
        };
        pairs.push((cols[2].to_owned(), va));
    }
    Some(pairs)
}

fn cross_check_against_addr2line(normal_analysis: &GoAnalysis, normal_path: &Path) {
    let recovered: BTreeMap<String, String> = normal_analysis
        .symbols
        .funcs
        .iter()
        .filter_map(|f: &GoFunc| {
            f.file
                .as_ref()
                .map(|file: &String| (f.name.clone(), file.replace('\\', "/")))
        })
        .collect();

    let Some(mut name_addrs): Option<Vec<(String, u64)>> = nm_name_addrs(normal_path) else {
        eprintln!(
            "\n=== go tool nm/addr2line unavailable; reference cross-check skipped (authored-layout \
             ground truth already enforced above) ===\n"
        );
        return;
    };
    name_addrs.sort_by_key(|a: &(String, u64)| a.1);
    name_addrs.truncate(600);

    let addrs: Vec<u64> = name_addrs
        .iter()
        .map(|(_, va): &(String, u64)| *va)
        .collect();
    let Some(reference_files): Option<Vec<Option<String>>> = addr2line_files(normal_path, &addrs)
    else {
        eprintln!(
            "\n=== go tool addr2line unavailable; reference cross-check skipped (authored-layout \
             ground truth already enforced above) ===\n"
        );
        return;
    };

    let mut compared: usize = 0;
    let mut agreed: usize = 0;
    let mut mismatches: BTreeMap<String, (String, String)> = BTreeMap::new();
    for ((name, _va), reference_file) in name_addrs.iter().zip(reference_files.iter()) {
        let reference_file: &String = match reference_file.as_ref() {
            Some(rf) => rf,
            None => continue,
        };
        let Some(recovered_file): Option<&String> = recovered.get(name) else {
            continue;
        };
        compared += 1;
        if recovered_file == reference_file {
            agreed += 1;
        } else {
            mismatches
                .entry(name.clone())
                .or_insert_with(|| (recovered_file.clone(), reference_file.clone()));
        }
    }

    assert!(
        compared >= 50,
        "our recovery and go's reference decoder should share many named funcs with a file, got {compared}"
    );
    let agreement: f64 = agreed as f64 / compared.max(1) as f64;
    assert!(
        agreement >= 0.98,
        "our pcfile decode must match go's reference addr2line decoder: {agreed}/{compared} = \
         {agreement:.3}; sample mismatches: {:?}",
        mismatches.iter().take(5).collect::<Vec<_>>()
    );
}
