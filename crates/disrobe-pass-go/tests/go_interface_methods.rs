#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_go::{GoAnalysis, GoFunc, GoInterfaceMethod, GoItab, GoTypeRef, analyze};

const IFACE_SOURCE: &str = r#"package main

import (
	"fmt"
	"os"
	"reflect"
)

type Widget struct {
	Name  string
	Count int
}

type Processor interface {
	Process(w Widget) int
	Reset()
	Label() string
}

type counter struct{ total int }

func (c *counter) Process(w Widget) int { c.total += w.Count; return c.total }
func (c *counter) Reset()               { c.total = 0 }
func (c *counter) Label() string        { return "counter" }

type doubler struct{ n int }

func (d *doubler) Process(w Widget) int { d.n += 2 * w.Count; return d.n }
func (d *doubler) Reset()               { d.n = 0 }
func (d *doubler) Label() string        { return "doubler" }

func pick(sel int) Processor {
	if sel%2 == 0 {
		return &counter{}
	}
	return &doubler{}
}

func main() {
	it := reflect.TypeOf((*Processor)(nil)).Elem()
	for i := 0; i < it.NumMethod(); i++ {
		m := it.Method(i)
		fmt.Fprintf(os.Stdout, "IM\t%s\t%s\t%t\n", m.Name, m.Type.String(), m.IsExported())
	}
	p := pick(len(os.Args))
	sum := p.Process(Widget{Name: "a", Count: 3})
	p.Reset()
	fmt.Fprintln(os.Stdout, sum, p.Label())
	os.Exit(sum & 0)
}
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReflectMethod {
    signature: String,
    exported: bool,
}

fn reflect_interface_truth(dir: &Path) -> BTreeMap<String, ReflectMethod> {
    let output: Output = Command::new("go")
        .args(["run", "."])
        .current_dir(dir)
        .env("CGO_ENABLED", "0")
        .env("GO111MODULE", "on")
        .output()
        .expect("run Go 1.26 reflect interface ground truth");
    assert!(
        output.status.success(),
        "go run interface ground truth failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut truth: BTreeMap<String, ReflectMethod> = BTreeMap::new();
    for line in String::from_utf8(output.stdout)
        .expect("reflect output is UTF-8")
        .lines()
    {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.first() != Some(&"IM") {
            continue;
        }
        assert_eq!(cols.len(), 4, "interface method row: {line:?}");
        truth.insert(
            cols[1].to_owned(),
            ReflectMethod {
                signature: cols[2].to_owned(),
                exported: cols[3].parse().expect("reflect exported flag"),
            },
        );
    }
    truth
}

fn func_abs_entries(analysis: &GoAnalysis) -> BTreeSet<u64> {
    let text_va: u64 = analysis.moduledata.text_va;
    analysis
        .symbols
        .funcs
        .iter()
        .flat_map(|f: &GoFunc| [f.entry, text_va.wrapping_add(f.entry)])
        .collect()
}

fn processor_type(analysis: &GoAnalysis) -> &GoTypeRef {
    analysis
        .typemeta
        .types
        .iter()
        .find(|ty: &&GoTypeRef| ty.name.as_deref() == Some("main.Processor") && ty.kind == Some(20))
        .expect("the declared interface main.Processor must be reachable through typelinks")
}

#[test]
fn interface_method_set_matches_reflect_on_go126() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("iface_methods");
    common::write_module(&scratch, "disrobe.example/ifacemethods", IFACE_SOURCE);
    let truth: BTreeMap<String, ReflectMethod> = reflect_interface_truth(scratch.path());
    assert_eq!(truth.len(), 3, "the interface probe declares three methods");

    let Some(binary): Option<PathBuf> = common::go_build(&scratch, "ifacemethods.exe", &[]) else {
        panic!("go build (interface methods) failed; the real-toolchain oracle cannot run");
    };
    let bytes: Vec<u8> = std::fs::read(&binary).expect("read interface build");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze interface build");

    let processor: &GoTypeRef = processor_type(&analysis);
    assert!(
        !processor.imethods_rejected,
        "valid go1.26 InterfaceType metadata must not carry the rejection marker"
    );

    let recovered: BTreeMap<String, ReflectMethod> = processor
        .imethods
        .iter()
        .filter_map(|m: &GoInterfaceMethod| {
            Some((
                m.name.clone()?,
                ReflectMethod {
                    signature: m.signature.clone()?,
                    exported: m.exported,
                },
            ))
        })
        .collect();

    eprintln!("windows/amd64 (pe): interface method set recovered={recovered:?} truth={truth:?}");
    assert_eq!(
        recovered, truth,
        "recovered interface method set (name, signature, exported) must match live reflect output"
    );
}

fn processor_itab(analysis: &GoAnalysis) -> &GoItab {
    analysis
        .typemeta
        .itabs
        .iter()
        .find(|i: &&GoItab| {
            i.interface_name
                .as_deref()
                .is_some_and(|n: &str| n.contains("Processor"))
                && i.concrete_name
                    .as_deref()
                    .is_some_and(|c: &str| c.contains("counter"))
        })
        .expect("the (*counter -> main.Processor) itab must be recovered from itablinks")
}

#[test]
fn itab_function_slots_resolve_to_concrete_methods_on_go126() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("iface_itab");
    common::write_module(&scratch, "disrobe.example/ifaceitab", IFACE_SOURCE);
    let Some(binary): Option<PathBuf> = common::go_build(&scratch, "ifaceitab.exe", &[]) else {
        panic!("go build (itab slots) failed; the real-toolchain oracle cannot run");
    };
    let bytes: Vec<u8> = std::fs::read(&binary).expect("read itab build");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze itab build");

    let func_entries: BTreeSet<u64> = func_abs_entries(&analysis);

    let itab: &GoItab = processor_itab(&analysis);
    assert!(
        !itab.unimplemented,
        "a committed itab bound to a satisfied interface must not be flagged unimplemented"
    );
    assert_eq!(
        itab.fun.len(),
        3,
        "the itab must carry one function slot per interface method (three): {:?}",
        itab.fun
    );

    let mut method_names: BTreeSet<String> = BTreeSet::new();
    for slot in &itab.fun {
        let name: &str = slot
            .method_name
            .as_deref()
            .expect("each fun slot must pair with an interface method name");
        method_names.insert(name.to_owned());
        let link: &str = slot
            .linker_name
            .as_deref()
            .expect("each fun slot address must resolve to a pclntab function");
        assert!(
            link.ends_with(&format!(".{name}")),
            "fun slot {} concrete implementation {link:?} must be the method '{name}' the \
             interface slot demands",
            slot.index
        );
        assert_ne!(
            slot.func_va, 0,
            "a resolved fun slot carries a real text VA"
        );
        assert!(
            func_entries.contains(&slot.func_va),
            "fun slot VA {:#x} must be a real function entry in the independent pclntab table",
            slot.func_va
        );
    }
    let expected: BTreeSet<String> = ["Process", "Reset", "Label"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    eprintln!("windows/amd64 (pe): itab fun slots={:?}", itab.fun);
    assert_eq!(
        method_names, expected,
        "the itab fun slots must cover exactly the interface's declared methods"
    );
}

#[test]
fn interface_methods_recovered_on_normal_fixture() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze hello_normal");

    let interfaces: Vec<&GoTypeRef> = analysis
        .typemeta
        .types
        .iter()
        .filter(|t: &&GoTypeRef| t.kind == Some(20))
        .collect();
    assert!(
        !interfaces.is_empty(),
        "a real go1.26 binary carries interface type descriptors in typelinks"
    );

    let total_imethods: usize = interfaces
        .iter()
        .map(|t: &&GoTypeRef| t.imethods.len())
        .sum();
    assert!(
        total_imethods >= 20,
        "interface method sets (the imethod array off InterfaceType) must reconstruct across the \
         binary's interfaces; got {total_imethods}"
    );

    let by_name: BTreeMap<&str, &GoTypeRef> = analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| Some((t.name.as_deref()?, t)))
        .collect();

    let error_iface: &GoTypeRef = by_name
        .get("error")
        .expect("the builtin error interface type must be recovered from typelinks");
    let error_methods: BTreeSet<&str> = error_iface
        .imethods
        .iter()
        .filter_map(|m: &GoInterfaceMethod| m.name.as_deref())
        .collect();
    assert!(
        error_methods.contains("Error"),
        "the error interface's method set must contain 'Error'; got {error_methods:?}"
    );
}

#[test]
fn itab_function_slots_link_on_normal_fixture() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze hello_normal");

    let func_entries: BTreeSet<u64> = func_abs_entries(&analysis);

    let with_slots: usize = analysis
        .typemeta
        .itabs
        .iter()
        .filter(|i: &&GoItab| !i.fun.is_empty())
        .count();
    assert!(
        with_slots > 0,
        "itabs must expose their concrete method function slots (fun array)"
    );

    let mut concrete_linked: usize = 0;
    let mut pruned: usize = 0;
    let mut wrong_method: Vec<(String, String)> = Vec::new();
    let mut absent_from_pclntab: Vec<u64> = Vec::new();
    for itab in &analysis.typemeta.itabs {
        for slot in &itab.fun {
            if slot.func_va == 0 {
                continue;
            }
            if !func_entries.contains(&slot.func_va) {
                absent_from_pclntab.push(slot.func_va);
            }
            let (Some(method), Some(link)) =
                (slot.method_name.as_deref(), slot.linker_name.as_deref())
            else {
                continue;
            };
            if link == "runtime.unreachableMethod" {
                pruned += 1;
                continue;
            }
            if link.ends_with(&format!(".{method}")) {
                concrete_linked += 1;
            } else {
                wrong_method.push((method.to_owned(), link.to_owned()));
            }
        }
    }
    eprintln!(
        "hello_normal: itab fun slots concrete_linked={concrete_linked} pruned={pruned} \
         (runtime.unreachableMethod = go linker deadcode-eliminated dynamic dispatch)"
    );
    assert!(
        concrete_linked >= 20,
        "hundreds of itab fun slots exist; at least 20 must resolve to the exact concrete method \
         the interface slot demands, got {concrete_linked}"
    );
    assert!(
        wrong_method.is_empty(),
        "every resolved fun slot must either implement the interface method its position demands \
         or be the linker's runtime.unreachableMethod pruning stub (non-circular pclntab \
         cross-check): {wrong_method:?}"
    );
    assert!(
        absent_from_pclntab.is_empty(),
        "a fun slot VA that is not a live pclntab function entry would be a fabricated slot: {:?}",
        absent_from_pclntab
            .iter()
            .map(|va: &u64| format!("{va:#x}"))
            .collect::<Vec<_>>()
    );
}
