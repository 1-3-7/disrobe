#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, GoItab, GoTypeRef, analyze};

const TYPEMETA_SOURCE: &str = r#"package main

import (
	"fmt"
	"io/fs"
	"os"
	"reflect"
)

type Widget struct {
	Name  string
	Count int
}

type Processor interface {
	Process(w Widget) int
}

type counter struct{ total int }

func (c *counter) Process(w Widget) int { c.total += w.Count; return c.total }

func kinds(v any) reflect.Kind { return reflect.TypeOf(v).Kind() }

func main() {
	c := &counter{}
	widgets := []Widget{{Name: "alpha", Count: 3}, {Name: "beta", Count: 5}}
	sum := 0
	var p Processor = c
	for _, w := range widgets {
		sum += p.Process(w)
	}
	var err error = &fs.PathError{Op: "open", Path: "x", Err: os.ErrNotExist}
	fmt.Fprintln(os.Stdout, sum, kinds(widgets), err)
	os.Exit(sum & 0)
}
"#;

fn recovered_type_names(analysis: &GoAnalysis) -> BTreeSet<String> {
    analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .map(common::normalize_type_name)
        .collect()
}

fn recovered_itab_pairs(analysis: &GoAnalysis) -> BTreeSet<(String, String)> {
    analysis
        .typemeta
        .itabs
        .iter()
        .filter_map(|i: &GoItab| {
            Some((
                common::normalize_type_name(i.concrete_name.as_deref()?),
                common::normalize_type_name(i.interface_name.as_deref()?),
            ))
        })
        .collect()
}

#[test]
fn typemeta_type_names_match_go_tool_nm_eq_oracle() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("typemeta");
    common::write_module(&scratch, "disrobe.example/typemeta", TYPEMETA_SOURCE);
    let Some(binary): Option<PathBuf> = common::go_build(&scratch, "typemeta.exe", &[]) else {
        panic!("go build (typemeta) failed; the real-toolchain oracle cannot run");
    };

    let truth: BTreeSet<String> = common::nm_eq_type_names(&binary)
        .expect("go tool nm must yield the type:.eq.* ground-truth type names");
    assert!(
        truth.len() > 40,
        "a real go1.26 binary emits dozens of type equality routines; got {}",
        truth.len()
    );

    let bytes: Vec<u8> = std::fs::read(&binary).expect("read typemeta build");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze typemeta build");
    let recovered: BTreeSet<String> = recovered_type_names(&analysis);

    let hit: usize = truth.iter().filter(|n| recovered.contains(*n)).count();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    let missing: Vec<&String> = truth.iter().filter(|n| !recovered.contains(*n)).collect();
    eprintln!(
        "windows/amd64 (pe): type-eq recovery {hit}/{total} = {ratio:.4}; missing={missing:?}"
    );
    assert!(
        ratio >= 1.0,
        "type-name recovery vs the independent `go tool nm` type:.eq oracle must be 100% \
         (measured ceiling on go1.26.3/windows-amd64): {hit}/{total} = {ratio:.4}; \
         missing {missing:?}"
    );
    assert!(
        recovered.contains("fs.PathError") && recovered.contains("main.Widget"),
        "the user struct main.Widget and the referenced io/fs.PathError must both be recovered; \
         recovered {} names",
        recovered.len()
    );
}

#[test]
fn typemeta_itab_pairs_match_go_tool_nm_itab_oracle() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("typemeta_itab");
    common::write_module(&scratch, "disrobe.example/typemetaitab", TYPEMETA_SOURCE);
    let Some(binary): Option<PathBuf> = common::go_build(&scratch, "typemetaitab.exe", &[]) else {
        panic!("go build (typemeta itab) failed; the real-toolchain oracle cannot run");
    };

    let truth: BTreeSet<(String, String)> = common::nm_itab_pairs(&binary)
        .expect("go tool nm must yield the go:itab.* concrete,interface ground truth");
    assert!(
        !truth.is_empty(),
        "a real go1.26 binary that stores interface values emits go:itab.* symbols"
    );

    let bytes: Vec<u8> = std::fs::read(&binary).expect("read typemeta itab build");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze typemeta itab build");
    let recovered: BTreeSet<(String, String)> = recovered_itab_pairs(&analysis);

    let hit: usize = truth.iter().filter(|p| recovered.contains(*p)).count();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    let missing: Vec<&(String, String)> =
        truth.iter().filter(|p| !recovered.contains(*p)).collect();
    eprintln!("windows/amd64 (pe): itab recovery {hit}/{total} = {ratio:.4}; missing={missing:?}");
    assert!(
        ratio >= 1.0,
        "itab (concrete,interface) recovery vs the independent `go tool nm` go:itab oracle \
         must be 100% (measured ceiling on go1.26.3/windows-amd64): {hit}/{total} = {ratio:.4}; \
         missing {missing:?}"
    );
    assert!(
        recovered.contains(&("fs.PathError".to_owned(), "error".to_owned())),
        "the *fs.PathError itab bound to error must be recovered; got {recovered:?}"
    );
}

#[test]
fn typemeta_emits_some_types_for_normal_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let total_types: usize = analysis.typemeta.types.len();
    let total_itabs: usize = analysis.typemeta.itabs.len();
    assert!(
        total_types > 0,
        "expected typelinks walk to recover types on go1.26.3 binary"
    );
    assert!(
        total_itabs > 0,
        "expected itablinks walk to recover itabs on go1.26.3 binary"
    );
}

#[test]
fn typemeta_recovers_real_type_names_on_go126() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_STRIPPED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let total: usize = analysis.typemeta.types.len();
    let named: usize = analysis
        .typemeta
        .types
        .iter()
        .filter(|t: &&GoTypeRef| t.name.is_some())
        .count();
    assert!(
        total > 100,
        "stripped go1.26.3 fixture should expose hundreds of types via typelinks (got {total})"
    );
    let ratio: f64 = (named as f64) / (total.max(1) as f64);
    assert!(
        ratio >= 0.85,
        "expected >= 85% type-name recovery on the stripped go1.26.3 fixture \
         (got {named}/{total} = {ratio:.3})"
    );

    let names: Vec<&str> = analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .collect();

    let pkg_categories: &[&str] = &["runtime.", "sync.", "reflect.", "internal/"];
    for pkg in pkg_categories {
        let hits: usize = names.iter().filter(|n: &&&str| n.contains(pkg)).count();
        assert!(
            hits > 0,
            "expected at least one recovered type name containing '{pkg}' (got {hits})"
        );
    }

    let canonical_runtime: &[&str] = &[
        "*runtime.g",
        "*runtime.m",
        "*runtime.p",
        "*runtime.mheap",
        "*runtime._type",
        "*runtime.itab",
    ];
    let canonical_hits: usize = canonical_runtime
        .iter()
        .filter(|needle: &&&str| names.iter().any(|n: &&str| n.contains(*needle)))
        .count();
    assert!(
        canonical_hits >= 3,
        "expected at least 3 canonical runtime types from {:?} (matched {canonical_hits}); recovered {} names",
        canonical_runtime,
        names.len()
    );
}

#[test]
fn typemeta_recovers_itab_concrete_names_on_go126() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let total: usize = analysis.typemeta.itabs.len();
    assert!(total > 0, "expected itabs > 0");

    let fully_resolved: usize = analysis
        .typemeta
        .itabs
        .iter()
        .filter(|i: &&GoItab| i.interface_name.is_some() && i.concrete_name.is_some())
        .count();
    assert!(
        fully_resolved * 2 >= total,
        "expected at least half of itabs to surface BOTH interface+concrete names \
         (got {fully_resolved}/{total})"
    );

    let pairs: Vec<(&str, &str)> = analysis
        .typemeta
        .itabs
        .iter()
        .filter_map(|i: &GoItab| Some((i.interface_name.as_deref()?, i.concrete_name.as_deref()?)))
        .collect();
    let expected_concretes: &[&str] = &["*os.File", "*fs.PathError"];
    for concrete in expected_concretes {
        assert!(
            pairs
                .iter()
                .any(|(_, c): &(&str, &str)| c.contains(concrete)),
            "expected itab concrete name containing '{concrete}'; pairs recovered: {pairs:?}"
        );
    }
}

#[test]
fn typemeta_recovers_embed_types_on_embed_fixture() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_EMBED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze embed");
    let names: Vec<&str> = analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .collect();
    assert!(
        names.iter().any(|n: &&str| n.contains("embed.")),
        "embed fixture must expose embed.* types"
    );
    let pairs: Vec<(&str, &str)> = analysis
        .typemeta
        .itabs
        .iter()
        .filter_map(|i: &GoItab| Some((i.interface_name.as_deref()?, i.concrete_name.as_deref()?)))
        .collect();
    assert!(
        pairs
            .iter()
            .any(|(_, c): &(&str, &str)| c.contains("*embed.FS")),
        "embed fixture must surface an *embed.FS itab; pairs: {pairs:?}"
    );
}

#[test]
fn typemeta_does_not_panic_on_stripped() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_STRIPPED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped");
    let total: usize = analysis.typemeta.types.len();
    let named: usize = analysis
        .typemeta
        .types
        .iter()
        .filter(|t: &&GoTypeRef| t.name.is_some())
        .count();
    assert!(
        total > 0,
        "stripped go1.26.3 binary still preserves typelinks/types"
    );
    assert!(
        named > 0,
        "stripped binary still has typelinks/names section -- expected >0 name recoveries"
    );
}
