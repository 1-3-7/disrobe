#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_go::pclntab::signature_scan_pclntab;
use disrobe_pass_go::{GoAnalysis, GoFunc, GoImage, analyze, locate_pclntab};

const SIGSCAN_SOURCE: &str = r#"package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type Ledger struct {
	Entries map[string]int
	Names   []string
}

func (l *Ledger) Record(name string, delta int) {
	if l.Entries == nil {
		l.Entries = map[string]int{}
	}
	l.Entries[name] += delta
	l.Names = append(l.Names, name)
}

func (l *Ledger) Summary() string {
	sort.Strings(l.Names)
	return strings.Join(l.Names, ",")
}

func total(entries map[string]int) int {
	sum := 0
	for _, v := range entries {
		sum += v
	}
	return sum
}

func main() {
	l := &Ledger{}
	l.Record("north", 3)
	l.Record("south", 7)
	fmt.Fprintln(os.Stdout, l.Summary())
	os.Exit(total(l.Entries) & 0)
}
"#;

fn recovered_func_names(analysis: &GoAnalysis) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &analysis.symbols.funcs {
        out.insert(f.name.clone());
        if let Some(ls) = &f.linker_symbol {
            out.insert(ls.clone());
        }
    }
    out
}

fn stomp_pclntab_magic(bytes: &mut [u8]) -> usize {
    let off: usize =
        common::find_pclntab_offset(bytes).expect("locate pclntab magic in real build");
    bytes[off..off + 4].copy_from_slice(&[0xde, 0xad, 0xbe, 0x5f]);
    off
}

#[test]
fn signature_scan_recovers_funcs_matching_go_tool_nm_oracle() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("sigscan");
    common::write_module(&scratch, "disrobe.example/sigscan", SIGSCAN_SOURCE);
    let Some(clean): Option<PathBuf> = common::go_build(&scratch, "sigscan.exe", &[]) else {
        panic!("go build (sigscan) failed; the real-toolchain oracle cannot run");
    };

    let truth: BTreeSet<String> =
        common::nm_text_symbols(&clean).expect("go tool nm must produce the ground-truth symtab");
    assert!(
        truth.len() > 500,
        "a real go1.26 binary carries hundreds of text symbols in its nm table; got {}",
        truth.len()
    );

    let clean_bytes: Vec<u8> = std::fs::read(&clean).expect("read clean build");
    let baseline: GoAnalysis = analyze(&clean_bytes).expect("analyze clean build");
    let baseline_recovered: BTreeSet<String> = recovered_func_names(&baseline);

    let mut stomped: Vec<u8> = clean_bytes;
    stomp_pclntab_magic(&mut stomped);

    let image: GoImage<'_> = GoImage::parse(&stomped).expect("parse stomped");
    assert!(
        locate_pclntab(&image).is_ok(),
        "locate_pclntab must fall through to the signature scan and succeed after magic-stomp"
    );
    let located = signature_scan_pclntab(&image)
        .expect("signature scan must reconstruct the stomped pclntab");
    assert!(
        located.header.n_funcs as usize >= baseline.symbols.funcs.len().saturating_sub(8),
        "signature-scanned func count must approximate the intact-header count: scan={} intact={}",
        located.header.n_funcs,
        baseline.symbols.funcs.len()
    );

    let recovered: GoAnalysis = analyze(&stomped).expect("analyze stomped");
    let stomped_recovered: BTreeSet<String> = recovered_func_names(&recovered);

    let hit_intact: usize = truth
        .iter()
        .filter(|n| baseline_recovered.contains(*n))
        .count();
    let hit_stomped: usize = truth
        .iter()
        .filter(|n| stomped_recovered.contains(*n))
        .count();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let intact_ratio: f64 = hit_intact as f64 / total.max(1) as f64;
    #[allow(clippy::cast_precision_loss)]
    let stomped_ratio: f64 = hit_stomped as f64 / total.max(1) as f64;

    assert!(
        intact_ratio >= 0.99,
        "intact-header func recovery vs `go tool nm` ground truth must be >= 99%: {hit_intact}/{total} = {intact_ratio:.4}"
    );
    assert!(
        stomped_ratio >= 0.99,
        "after magic-stomp + signature-scan recovery, func recovery vs the SAME independent \
         `go tool nm` ground truth must still be >= 99%: {hit_stomped}/{total} = {stomped_ratio:.4}"
    );

    let missing_after_stomp: Vec<&String> = truth
        .iter()
        .filter(|n| baseline_recovered.contains(*n) && !stomped_recovered.contains(*n))
        .collect();
    assert!(
        missing_after_stomp.is_empty(),
        "no symbol recovered from the intact header may be lost after signature-scan recovery; \
         dropped: {missing_after_stomp:?}"
    );

    assert!(
        stomped_recovered.contains("main.main") && stomped_recovered.contains("runtime.main"),
        "signature-scanned funcname table must contain real user + runtime symbols"
    );
    let user_methods: Vec<&GoFunc> = recovered
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.name.starts_with("main.(*Ledger)."))
        .collect();
    assert!(
        !user_methods.is_empty(),
        "at least one user pointer-receiver method must survive signature-scan recovery \
         (the compiler may inline the smaller ones); got {user_methods:?}"
    );
    let clean_truth_has_summary: bool = truth.contains("main.(*Ledger).Summary");
    assert_eq!(
        clean_truth_has_summary,
        stomped_recovered.contains("main.(*Ledger).Summary"),
        "every non-inlined user method present in the `go tool nm` ground truth must also be \
         recovered from the signature-scanned binary"
    );
}

#[test]
fn signature_scan_recovers_magic_stomped_pclntab() {
    let clean: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let baseline: GoAnalysis = analyze(&clean).expect("baseline analyze");
    let baseline_funcs: usize = baseline.symbols.funcs.len();
    let baseline_named: usize = baseline
        .typemeta
        .types
        .iter()
        .filter(|t| t.name.is_some())
        .count();
    assert!(baseline_funcs > 100, "baseline must have a real pclntab");

    let off: usize = common::find_pclntab_offset(&clean).expect("locate magic in file");
    let mut stomped: Vec<u8> = clean;
    stomped[off..off + 4].copy_from_slice(&[0xde, 0xad, 0xbe, 0x5f]);

    let image: GoImage<'_> = GoImage::parse(&stomped).expect("parse stomped");
    assert!(
        locate_pclntab(&image).is_ok(),
        "locate_pclntab must fall through to the signature scan and succeed"
    );
    let located = signature_scan_pclntab(&image).expect("signature scan must reconstruct pclntab");
    assert!(located.header.n_funcs as usize >= baseline_funcs.saturating_sub(8));

    let recovered: GoAnalysis = analyze(&stomped).expect("analyze stomped");
    assert_eq!(
        recovered.symbols.funcs.len(),
        baseline_funcs,
        "func recovery must match the un-stomped binary"
    );
    let recovered_named: usize = recovered
        .typemeta
        .types
        .iter()
        .filter(|t| t.name.is_some())
        .count();
    assert_eq!(
        recovered_named, baseline_named,
        "type-name recovery must match the un-stomped binary"
    );
    assert!(
        recovered
            .symbols
            .funcs
            .iter()
            .any(|f| f.name == "runtime.main"),
        "recovered funcname table must contain real symbols"
    );
}

#[test]
fn signature_scan_rejects_coincidental_magic() {
    let mut junk: Vec<u8> = vec![0x41u8; 8192];
    junk[0..2].copy_from_slice(b"MZ");
    for i in (64..8000).step_by(64) {
        junk[i..i + 4].copy_from_slice(&[0xf1, 0xff, 0xff, 0xff]);
        junk[i + 6] = 1;
        junk[i + 7] = 8;
    }
    let Ok(image): Result<GoImage<'_>, _> = GoImage::parse(&junk) else {
        return;
    };
    assert!(
        signature_scan_pclntab(&image).is_err(),
        "coincidental magic runs must not validate as a pclntab"
    );
}
