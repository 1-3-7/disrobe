#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use disrobe_pass_go::{GoAnalysis, GoMethod, GoTypeRef, analyze};

fn all_methods(a: &GoAnalysis) -> impl Iterator<Item = (&GoTypeRef, &GoMethod)> {
    a.typemeta
        .types
        .iter()
        .flat_map(|t: &GoTypeRef| t.methods.iter().map(move |m: &GoMethod| (t, m)))
}

#[test]
fn method_sets_reconstructed_from_uncommon_type_on_real_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze hello_normal");

    let types_with_methods: usize = analysis
        .typemeta
        .types
        .iter()
        .filter(|t: &&GoTypeRef| !t.methods.is_empty())
        .count();
    assert!(
        types_with_methods >= 120,
        "a real go1.26 binary carries method sets on well over a hundred named types via \
         abi.UncommonType; reconstructed {types_with_methods}"
    );

    let total_methods: usize = all_methods(&analysis).count();
    assert!(
        total_methods >= 800,
        "expected hundreds of reconstructed methods across the type set, got {total_methods}"
    );

    let by_name: BTreeMap<&str, &GoTypeRef> = analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| Some((t.name.as_deref()?, t)))
        .collect();

    let file: &GoTypeRef = by_name
        .get("*os.File")
        .expect("*os.File must be recovered from typelinks");
    let file_methods: BTreeSet<&str> = file
        .methods
        .iter()
        .filter_map(|m: &GoMethod| m.name.as_deref())
        .collect();
    for expected in ["Read", "Write", "Close", "Stat", "Seek", "Name"] {
        assert!(
            file_methods.contains(expected),
            "*os.File method set must contain the exported method '{expected}'; got {file_methods:?}"
        );
    }

    let mutex: &GoTypeRef = by_name
        .get("*sync.Mutex")
        .expect("*sync.Mutex must be recovered");
    let mutex_methods: BTreeSet<&str> = mutex
        .methods
        .iter()
        .filter_map(|m: &GoMethod| m.name.as_deref())
        .collect();
    for expected in ["Lock", "Unlock", "TryLock"] {
        assert!(
            mutex_methods.contains(expected),
            "*sync.Mutex method set must contain '{expected}'; got {mutex_methods:?}"
        );
    }
}

#[test]
fn linked_method_names_match_pclntab_function_names_exactly() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze hello_normal");

    let pclntab_names: BTreeSet<&str> = analysis
        .symbols
        .funcs
        .iter()
        .map(|f: &disrobe_pass_go::GoFunc| f.name.as_str())
        .collect();

    let mut linked: usize = 0;
    let mut mismatches: Vec<(String, String)> = Vec::new();
    let mut missing_from_pclntab: Vec<String> = Vec::new();
    for (_, m) in all_methods(&analysis) {
        let (Some(name), Some(link)) = (m.name.as_deref(), m.linker_name.as_deref()) else {
            continue;
        };
        linked += 1;
        if !link.ends_with(&format!(".{name}")) {
            mismatches.push((name.to_owned(), link.to_owned()));
        }
        if !pclntab_names.contains(link) {
            missing_from_pclntab.push(link.to_owned());
        }
    }

    assert!(
        linked >= 150,
        "a real binary keeps hundreds of method bodies; at least 150 reconstructed methods should \
         cross-reference to a live pclntab function, got {linked}"
    );
    assert!(
        mismatches.is_empty(),
        "every method name decoded from abi.UncommonType must be the exact tail of the pclntab \
         function its Tfn points to; these do not match (non-circular contradiction): {mismatches:?}"
    );
    assert!(
        missing_from_pclntab.is_empty(),
        "a linked method must name a function that is actually in the pclntab table: {missing_from_pclntab:?}"
    );
}

#[test]
fn unlinked_methods_are_honestly_dead_code_not_fabricated() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze hello_normal");

    for (ty, m) in all_methods(&analysis) {
        if m.linker_name.is_none() {
            assert_eq!(
                m.func_va, 0,
                "a method with no live function body must report func_va=0 (Tfn was the -1 \
                 dead-code sentinel); reporting a non-zero address without a resolved function \
                 would be a fabricated recovery: type {:?} method {:?}",
                ty.name, m.name
            );
        } else {
            assert_ne!(
                m.func_va, 0,
                "a linked method must carry the resolved absolute function VA"
            );
        }
    }
}

#[test]
fn method_sets_survive_on_stripped_build() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_STRIPPED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze hello_stripped");
    assert!(
        analysis.stripped.stripped,
        "the -s -w build must be classified as stripped"
    );
    let total_methods: usize = all_methods(&analysis).count();
    assert!(
        total_methods >= 800,
        "the abi type descriptors and pclntab funcname table survive `-s -w`, so method sets are \
         still fully reconstructable on a stripped build; got {total_methods}"
    );
    let linked: usize = all_methods(&analysis)
        .filter(|(_, m): &(&GoTypeRef, &GoMethod)| m.linker_name.is_some())
        .count();
    assert!(
        linked >= 150,
        "stripped builds keep the pclntab, so method->function linking must still land: {linked}"
    );
}

#[test]
fn method_sets_reconstructed_on_32bit_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_386);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze hello_386");
    assert_eq!(analysis.ptr_size, 4, "expected a 32-bit image");

    let total_methods: usize = all_methods(&analysis).count();
    assert!(
        total_methods >= 800,
        "the 32-bit abi.Type base size (32) and per-kind uncommon offsets must be wired: got \
         {total_methods} methods (a 64-bit-only layout reads past the smaller struct and finds none)"
    );
    let mismatches: usize = all_methods(&analysis)
        .filter_map(|(_, m): (&GoTypeRef, &GoMethod)| {
            Some((m.name.as_deref()?, m.linker_name.as_deref()?))
        })
        .filter(|(name, link): &(&str, &str)| !link.ends_with(&format!(".{name}")))
        .count();
    assert_eq!(
        mismatches, 0,
        "32-bit method names must also match their pclntab functions exactly"
    );
}

#[test]
fn recovered_methods_are_subset_of_go_tool_nm_ground_truth() {
    let path: std::path::PathBuf = common::fixture_path(common::HELLO_NORMAL);
    if !path.exists() {
        eprintln!("SKIPPED: hello_normal fixture absent; not CI-enforced");
        return;
    }
    let Ok(out): std::io::Result<std::process::Output> =
        Command::new("go").args(["tool", "nm"]).arg(&path).output()
    else {
        eprintln!(
            "SKIPPED: `go` toolchain not on PATH; the go-tool-nm ground-truth cross-check did not \
             run and is NOT CI-enforced here"
        );
        return;
    };
    if !out.status.success() {
        eprintln!("SKIPPED: `go tool nm` failed; skipping ground-truth cross-check");
        return;
    }
    let nm_text: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let nm_functions: BTreeSet<String> = nm_text
        .lines()
        .filter_map(|line: &str| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            (cols.len() >= 3 && matches!(cols[cols.len() - 2], "T" | "t"))
                .then(|| cols[cols.len() - 1].to_owned())
        })
        .collect();
    assert!(
        !nm_functions.is_empty(),
        "go tool nm produced no text symbols; ground truth is empty"
    );

    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");

    let mut checked: usize = 0;
    let mut absent: Vec<String> = Vec::new();
    for (_, m) in all_methods(&analysis) {
        let Some(link): Option<&str> = m.linker_name.as_deref() else {
            continue;
        };
        checked += 1;
        if !nm_functions.contains(link) && !nm_functions.contains(&format!("{link}.abiinternal")) {
            absent.push(link.to_owned());
        }
    }
    assert!(
        checked >= 150,
        "expected to cross-check >=150 linked methods against go tool nm, got {checked}"
    );
    assert!(
        absent.is_empty(),
        "every method-function we linked must exist in the independent `go tool nm` symbol table; \
         these do not (would be a fabricated method-function): {absent:?}"
    );
}
