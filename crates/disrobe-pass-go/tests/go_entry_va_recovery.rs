#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, GoFunc, analyze};

const VA_SRC: &str = "package main\n\
\n\
import \"fmt\"\n\
\n\
//go:noinline\n\
func Alpha() int { return len(\"alpha\") }\n\
\n\
//go:noinline\n\
func Beta(n int) int { return Alpha() + n }\n\
\n\
func main() {\n\
\tfmt.Println(Alpha(), Beta(3))\n\
}\n";

fn unique_recovered_vas(analysis: &GoAnalysis) -> BTreeMap<String, u64> {
    let mut seen_twice: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for f in &analysis.symbols.funcs {
        let Some(va): Option<u64> = f.va else {
            continue;
        };
        if out.insert(f.name.clone(), va).is_some() {
            seen_twice.insert(f.name.clone());
        }
    }
    for dup in &seen_twice {
        out.remove(dup);
    }
    out
}

fn unique_nm_vas(text: &str) -> BTreeMap<String, u64> {
    let counts: BTreeMap<String, usize> =
        text.lines().fold(BTreeMap::new(), |mut acc, line: &str| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 3 && matches!(cols[cols.len() - 2], "T" | "t") {
                *acc.entry(cols[cols.len() - 1].to_owned()).or_insert(0) += 1;
            }
            acc
        });
    common::parse_nm_text_symbol_vas(text)
        .into_iter()
        .filter(|(name, _): &(String, u64)| counts.get(name).copied() == Some(1))
        .collect()
}

#[test]
fn stripped_function_entry_vas_match_go_tool_nm_and_addr2line() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("entryva");
    common::write_module(&scratch, "entryvamod", VA_SRC);

    let Some(normal): Option<PathBuf> = common::go_build(&scratch, "app_normal.exe", &[]) else {
        panic!("normal go build failed");
    };
    let Some(stripped): Option<PathBuf> =
        common::go_build(&scratch, "app_stripped.exe", &["-ldflags", "-s -w"])
    else {
        panic!("stripped go build failed");
    };

    let nm_text: String = {
        let out: std::process::Output = std::process::Command::new("go")
            .args(["tool", "nm"])
            .arg(&normal)
            .output()
            .expect("go tool nm");
        assert!(out.status.success(), "go tool nm must succeed");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let truth: BTreeMap<String, u64> = unique_nm_vas(&nm_text);
    assert!(
        truth.len() > 200,
        "the fixture links hundreds of text symbols with addresses, got {}",
        truth.len()
    );

    let stripped_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped");
    let stripped_analysis: GoAnalysis = analyze(&stripped_bytes).expect("analyze stripped");
    assert!(
        stripped_analysis.stripped.stripped,
        "the -s -w build must classify as stripped"
    );
    assert_eq!(stripped_analysis.pclntab_version, "go1.20+");

    let with_va: usize = stripped_analysis
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.va.is_some())
        .count();
    let total: usize = stripped_analysis.symbols.funcs.len();
    assert_eq!(
        with_va, total,
        "with the text base recovered, every go1.20+ func must carry an absolute va, got {with_va}/{total}"
    );

    let recovered: BTreeMap<String, u64> = unique_recovered_vas(&stripped_analysis);
    let mut matched: usize = 0;
    let mut mismatched: Vec<(String, u64, u64)> = Vec::new();
    for (name, want) in &truth {
        let Some(got): Option<&u64> = recovered.get(name) else {
            continue;
        };
        if got == want {
            matched += 1;
        } else if name != "runtime.text" && name != "runtime.etext" {
            mismatched.push((name.clone(), *want, *got));
        }
    }
    assert!(
        mismatched.is_empty(),
        "recovered absolute vas must equal the go tool nm address exactly: {mismatched:?}"
    );
    assert!(
        matched > 200,
        "the recovered-vs-nm va intersection must be substantial, matched {matched}"
    );

    let normal_bytes: Vec<u8> = std::fs::read(&normal).expect("read normal");
    let normal_analysis: GoAnalysis = analyze(&normal_bytes).expect("analyze normal");
    let normal_recovered: BTreeMap<String, u64> = unique_recovered_vas(&normal_analysis);
    for (name, want) in &truth {
        if let Some(got) = normal_recovered.get(name) {
            assert_eq!(
                got, want,
                "same-file recovery must reproduce the exact nm address for {name}"
            );
        }
    }

    for probe in ["main.Alpha", "main.Beta", "main.main", "runtime.morestack"] {
        let va: u64 = *recovered
            .get(probe)
            .unwrap_or_else(|| panic!("recovered va for {probe}"));
        let Some(resolved): Option<String> = common::addr2line_name(&normal, va) else {
            continue;
        };
        if resolved.is_empty() || resolved == "?" {
            continue;
        }
        assert_eq!(
            resolved, probe,
            "the recovered va {va:#x} must resolve back to {probe} via go tool addr2line, got {resolved}"
        );
    }
}
