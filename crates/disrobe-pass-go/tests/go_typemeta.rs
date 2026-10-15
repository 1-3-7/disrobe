#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use disrobe_pass_go::{GoAnalysis, GoItab, GoTypeRef, analyze};
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};

const STRIPPED_GO126_TYPES: usize = 838;
const STRIPPED_GO126_NAMED: usize = 838;
const DWARF_GO126_TYPES: usize = 699;
const DWARF_GO126_MATCHED: usize = 373;

const PUBLISHED_HEADING: &str = "Go type-name recovery";
const PUBLISHED_BAR: &str = "type names";
const PUBLISHED_RATIO_GUARD: f64 = 0.85;
const DWARF_ORACLE_TIMEOUT: Duration = Duration::from_mins(2);
const DWARF_ORACLE_CAPTURE_BYTES: usize = 1 << 20;

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

const DWARF_TYPE_ORACLE: &str = r#"package main

import (
	"debug/dwarf"
	"debug/pe"
	"fmt"
	"os"
)

const attrGoRuntimeType dwarf.Attr = 0x2904

func main() {
	if len(os.Args) != 2 {
		panic("expected binary path")
	}
	f, err := pe.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	d, err := f.DWARF()
	if err != nil {
		panic(err)
	}
	r := d.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			panic(err)
		}
		if e == nil {
			return
		}
		addr, ok := e.Val(attrGoRuntimeType).(uint64)
		if !ok || addr == 0 {
			continue
		}
		name, ok := e.Val(dwarf.AttrName).(string)
		if !ok || name == "" {
			continue
		}
		fmt.Printf("%x\t%s\n", addr, name)
	}
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

fn dwarf_type_oracle(binary: &std::path::Path) -> BTreeMap<u64, String> {
    let scratch: common::GoBuildScratch = common::new_scratch("dwarf_type_oracle");
    common::write_module(
        &scratch,
        "disrobe.example/dwarf_type_oracle",
        "package main\n",
    );
    common::write_file(&scratch, "dwarf.go", DWARF_TYPE_ORACLE);
    let command: CommandSpec = CommandSpec::new("go", DWARF_ORACLE_TIMEOUT)
        .capture_limits(DWARF_ORACLE_CAPTURE_BYTES, DWARF_ORACLE_CAPTURE_BYTES)
        .args(["run", "dwarf.go"])
        .arg(binary)
        .current_dir(scratch.path().to_path_buf())
        .env("CGO_ENABLED", "0")
        .env("GO111MODULE", "on");
    let output: ToolOutput = tool_output(command)
        .unwrap_or_else(|error: ToolError| panic!("run Go DWARF type oracle: {error}"));
    assert!(
        output.success,
        "Go DWARF type oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Go DWARF type oracle output is UTF-8")
        .lines()
        .map(|line: &str| {
            let (offset, name): (&str, &str) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("invalid Go DWARF type oracle row: {line:?}"));
            let offset: u64 = u64::from_str_radix(offset, 16)
                .unwrap_or_else(|error| panic!("invalid Go DWARF type offset {offset:?}: {error}"));
            (offset, name.to_owned())
        })
        .collect()
}

fn matched_dwarf_types(analysis: &GoAnalysis, oracle: &BTreeMap<u64, String>) -> usize {
    oracle
        .iter()
        .filter(|(address, name): &(&u64, &String)| {
            analysis
                .typemeta
                .types
                .iter()
                .any(|ty: &GoTypeRef| ty.va == **address && ty.name.as_deref() == Some(name))
        })
        .count()
}

#[test]
fn typemeta_type_names_match_go_dwarf_runtime_type_oracle() {
    assert!(
        common::require_go(),
        "the Go toolchain is required for the independent DWARF type-name oracle"
    );
    let binary: PathBuf = common::fixture_path(common::HELLO_NORMAL);
    let offsets: BTreeMap<u64, String> = dwarf_type_oracle(&binary);
    assert!(
        offsets.len() > 600,
        "Go DWARF runtime-type oracle is implausibly small: {} entries",
        offsets.len()
    );
    let bytes: Vec<u8> = std::fs::read(&binary).expect("read unstripped Go fixture");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze unstripped Go fixture");
    assert_ne!(
        analysis.moduledata.types_va, 0,
        "the recovered moduledata must name the runtime.types base"
    );
    let oracle: BTreeMap<u64, String> = offsets
        .into_iter()
        .map(|(offset, name): (u64, String)| {
            let address: u64 = analysis
                .moduledata
                .types_va
                .checked_add(offset)
                .unwrap_or_else(|| panic!("Go DWARF runtime-type offset {offset:#x} overflows"));
            (address, name)
        })
        .collect();
    let hit: usize = matched_dwarf_types(&analysis, &oracle);
    let total: usize = oracle.len();
    let missing: Vec<(u64, String)> = oracle
        .iter()
        .filter(|(address, name): &(&u64, &String)| {
            !analysis
                .typemeta
                .types
                .iter()
                .any(|ty: &GoTypeRef| ty.va == **address && ty.name.as_deref() == Some(name))
        })
        .map(|(address, name): (&u64, &String)| (*address, name.clone()))
        .collect();
    eprintln!("go1.26.3/windows-amd64 DWARF type-name recovery {hit}/{total}");
    assert_eq!(
        total, DWARF_GO126_TYPES,
        "the independent DW_AT_go_runtime_type population changed; missing={missing:?}"
    );
    assert_eq!(
        hit, DWARF_GO126_MATCHED,
        "the independently graded Go type-name numerator changed; missing={missing:?}"
    );
    let mut name_mutation: BTreeMap<u64, String> = oracle.clone();
    let (address, name): (u64, String) = oracle
        .iter()
        .find(|(address, name): &(&u64, &String)| {
            analysis
                .typemeta
                .types
                .iter()
                .any(|ty: &GoTypeRef| ty.va == **address && ty.name.as_deref() == Some(name))
        })
        .map(|(address, name): (&u64, &String)| (*address, name.clone()))
        .expect("the DWARF runtime-type oracle must contain a recovered entry");
    name_mutation.insert(address, format!("{name}.mutation"));
    assert_eq!(
        matched_dwarf_types(&analysis, &name_mutation),
        hit.saturating_sub(1),
        "a mutated independent DWARF type-name oracle must turn the grade red"
    );
    let mutated_address: u64 = address
        .checked_add(1)
        .expect("DWARF runtime-type address has room for mutation");
    assert!(
        !oracle.contains_key(&mutated_address),
        "DWARF runtime-type address mutation must differ from the oracle"
    );
    let mut address_mutation: BTreeMap<u64, String> = oracle;
    address_mutation.remove(&address);
    address_mutation.insert(mutated_address, name);
    assert_eq!(
        matched_dwarf_types(&analysis, &address_mutation),
        hit.saturating_sub(1),
        "a mutated independent DWARF type address oracle must turn the grade red"
    );
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
    let ratio: f64 = (named as f64) / (total.max(1) as f64);
    eprintln!("stripped go1.26.3 (pe): type-name recovery {named}/{total} = {ratio:.4}");
    assert_eq!(
        total, STRIPPED_GO126_TYPES,
        "the typelinks walk over the committed stripped go1.26.3 fixture is fixed at \
         {STRIPPED_GO126_TYPES} types; a different count means the walk changed shape \
         (got {total}) and the published figure needs re-measuring"
    );
    assert!(
        named >= STRIPPED_GO126_NAMED,
        "type-name recovery on the stripped go1.26.3 fixture must not regress below \
         {STRIPPED_GO126_NAMED}/{STRIPPED_GO126_TYPES}; got {named}/{total} = {ratio:.4}"
    );
    assert!(
        ratio >= PUBLISHED_RATIO_GUARD,
        "expected >= 85% type-name recovery on the stripped go1.26.3 fixture \
         (got {named}/{total} = {ratio:.3})"
    );

    let bar: serde_json::Value = common::published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let num: u64 = bar["num"]
        .as_u64()
        .expect("the type names bar must carry a numerator");
    let den: u64 = bar["den"]
        .as_u64()
        .expect("the type names bar must carry a denominator");
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the type names bar must carry a numeric value");
    assert_eq!(
        u64::try_from(total).expect("type total fits u64"),
        den,
        "xtask/data/recovery.json publishes a denominator of {den} types on this fixture and every \
         document renders that number, but the typelinks walk sees {total}"
    );
    assert!(
        u64::try_from(named).expect("named fits u64") >= num,
        "recovery.json publishes {num} of {den} named types; this run recovered {named}"
    );
    let derived: f64 = 100.0 * num as f64 / den as f64;
    assert!(
        (derived - value).abs() < 0.05,
        "the published value {value} plots this measurement and must equal its own {num}/{den} = \
         {derived:.4}; the floor this gate enforces is a separate number and lives in floor_pct"
    );
    let floor_pct: f64 = bar["floor_pct"]
        .as_f64()
        .expect("the type names bar must carry the floor its gate enforces as floor_pct");
    assert!(
        (floor_pct / 100.0 - PUBLISHED_RATIO_GUARD).abs() < f64::EPSILON,
        "recovery.json publishes a floor of {floor_pct}% and four documents render that number, \
         but this gate enforces {PUBLISHED_RATIO_GUARD}"
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
