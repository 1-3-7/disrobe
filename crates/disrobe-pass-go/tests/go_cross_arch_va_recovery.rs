#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};

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
//go:noinline\n\
func Gamma(a int, b int) int { return Beta(a) * b }\n\
\n\
func main() {\n\
\tfmt.Println(Alpha(), Beta(3), Gamma(2, 4))\n\
}\n";

fn unique_recovered_vas(analysis: &GoAnalysis) -> BTreeMap<String, u64> {
    let mut seen_twice: BTreeSet<String> = BTreeSet::new();
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

fn nm_text(binary: &PathBuf) -> String {
    let out: Output = Command::new("go")
        .args(["tool", "nm"])
        .arg(binary)
        .output()
        .expect("go tool nm");
    assert!(out.status.success(), "go tool nm must succeed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

struct Target {
    goos: &'static str,
    goarch: &'static str,
    kind: &'static str,
    ptr_size: u8,
}

fn assert_target(t: &Target) {
    let scratch: common::GoBuildScratch =
        common::new_scratch(&format!("crossva_{}_{}", t.goos, t.goarch));
    common::write_module(&scratch, "crossvamod", VA_SRC);
    let ext: &str = if t.goos == "windows" { ".exe" } else { "" };

    let Some(normal): Option<PathBuf> =
        common::go_build_cross(&scratch, &format!("n{ext}"), t.goos, t.goarch, &[])
    else {
        panic!("normal cross build failed for {}/{}", t.goos, t.goarch);
    };
    let Some(stripped): Option<PathBuf> = common::go_build_cross(
        &scratch,
        &format!("s{ext}"),
        t.goos,
        t.goarch,
        &["-ldflags", "-s -w"],
    ) else {
        panic!("stripped cross build failed for {}/{}", t.goos, t.goarch);
    };

    let truth: BTreeMap<String, u64> = unique_nm_vas(&nm_text(&normal));
    assert!(
        truth.len() > 800,
        "{}/{}: nm ground truth links hundreds of addressed text symbols, got {}",
        t.goos,
        t.goarch,
        truth.len()
    );

    let stripped_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped");
    let analysis: GoAnalysis = analyze(&stripped_bytes).expect("analyze stripped");

    assert!(
        analysis.stripped.stripped,
        "{}/{}: the -s -w build must classify as stripped",
        t.goos, t.goarch
    );
    assert_eq!(
        analysis.image_kind, t.kind,
        "{}/{} must parse as {}",
        t.goos, t.goarch, t.kind
    );
    assert_eq!(
        analysis.ptr_size, t.ptr_size,
        "{}/{} must report a {}-byte pointer size",
        t.goos, t.goarch, t.ptr_size
    );
    assert_eq!(
        analysis.pclntab_version, "go1.20+",
        "{}/{}: go1.26 emits the 0xfffffff1 pclntab",
        t.goos, t.goarch
    );

    let with_va: usize = analysis
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.va.is_some())
        .count();
    let total: usize = analysis.symbols.funcs.len();
    assert_eq!(
        with_va, total,
        "{}/{}: with the text base recovered, every func must carry an absolute va, got {with_va}/{total}",
        t.goos, t.goarch
    );

    let recovered: BTreeMap<String, u64> = unique_recovered_vas(&analysis);
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
        "{}/{}: recovered absolute vas must equal go tool nm exactly: {mismatched:?}",
        t.goos,
        t.goarch
    );
    assert!(
        matched > 400,
        "{}/{}: the recovered-vs-nm va intersection must be substantial, matched {matched}",
        t.goos,
        t.goarch
    );

    for probe in ["main.Alpha", "main.Beta", "main.Gamma", "main.main"] {
        let want: u64 = *truth
            .get(probe)
            .unwrap_or_else(|| panic!("{}/{}: nm lacks {probe}", t.goos, t.goarch));
        let got: u64 = *recovered
            .get(probe)
            .unwrap_or_else(|| panic!("{}/{}: recovery dropped {probe}", t.goos, t.goarch));
        assert_eq!(
            got, want,
            "{}/{}: {probe} recovered va must equal nm",
            t.goos, t.goarch
        );
    }

    let discriminating: usize = truth
        .iter()
        .filter(|(name, want): &(&String, &u64)| {
            recovered
                .get(*name)
                .is_some_and(|got: &u64| got.wrapping_add(0x1000) != **want)
        })
        .count();
    assert!(
        discriminating > 200,
        "{}/{}: exact-va equality must be a real discriminator: only {discriminating} names \
         would break under a 0x1000 base perturbation",
        t.goos,
        t.goarch
    );
}

#[test]
fn stripped_function_vas_match_nm_across_arch_and_container() {
    if !common::require_go() {
        return;
    }
    let targets: [Target; 4] = [
        Target {
            goos: "windows",
            goarch: "386",
            kind: "pe",
            ptr_size: 4,
        },
        Target {
            goos: "linux",
            goarch: "386",
            kind: "elf",
            ptr_size: 4,
        },
        Target {
            goos: "linux",
            goarch: "arm64",
            kind: "elf",
            ptr_size: 8,
        },
        Target {
            goos: "darwin",
            goarch: "amd64",
            kind: "macho",
            ptr_size: 8,
        },
    ];
    for t in &targets {
        assert_target(t);
    }
}
