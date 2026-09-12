#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf, StripPrefixError};

use disrobe_pass_pickle::{
    CallKind, CallableRef, DecodedArg, Disassembly, Insn, PickleValue, SafetyReport, Severity,
    VmTrace, analyze_safety, disassemble, execute, to_python,
};

const PUBLISHED_HEADING: &str = "Pickle corpus";
const PUBLISHED_BAR: &str = "pickletools-graded fixtures";
const PUBLISHED_VALUE_TOLERANCE: f64 = 0.05;

const BENIGN_PROTOCOLS: [&str; 6] = ["p0", "p1", "p2", "p3", "p4", "p5"];
const BENIGN_FIXTURES_PER_PROTOCOL: usize = 15;
const STRUCTURAL_FIXTURES: usize = 6;
const MALICIOUS_FIXTURES: [&str; 6] = [
    "malicious/p0/reduce_os_system.pkl",
    "malicious/p1/reduce_os_system.pkl",
    "malicious/p2/reduce_os_system.pkl",
    "malicious/p3/reduce_os_system.pkl",
    "malicious/p4/reduce_os_system.pkl",
    "malicious/p5/reduce_os_system.pkl",
];

fn corpus_root() -> Option<PathBuf> {
    let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("pickle");
    root.is_dir().then_some(root)
}

fn collect_pkl(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_pkl(&path, out);
        } else if path.extension().is_some_and(|e| e == "pkl") {
            out.push(path);
        }
    }
}

#[test]
fn every_fixture_disassembles_and_traces() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let mut files: Vec<PathBuf> = Vec::new();
    collect_pkl(&root, &mut files);
    assert!(!files.is_empty(), "no .pkl fixtures under {root:?}");
    assert!(
        files.iter().any(|f: &PathBuf| f
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new("malicious"))),
        "malicious fixtures missing"
    );

    for file in &files {
        let bytes: Vec<u8> = std::fs::read(file).expect("read fixture");
        let dis: Disassembly =
            disassemble(&bytes).unwrap_or_else(|e| panic!("disasm {file:?}: {e}"));
        assert!(dis.stop_offset.is_some(), "no STOP in {file:?}");
        let trace: VmTrace = execute(&dis).unwrap_or_else(|e| panic!("vm {file:?}: {e}"));
        let _src: String = to_python(&trace.result);
        let report: SafetyReport = analyze_safety(&trace);

        let is_malicious: bool = file
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new("malicious"));
        if is_malicious {
            assert_eq!(
                report.severity,
                Severity::OvertlyMalicious,
                "malicious fixture {file:?} not flagged OvertlyMalicious"
            );
        } else {
            assert_ne!(
                report.severity,
                Severity::OvertlyMalicious,
                "benign fixture {file:?} false-positive OvertlyMalicious"
            );
        }
    }
}

#[test]
fn benign_int_fixtures_decode_to_int() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    for proto in 0u8..=5 {
        let path: PathBuf = root
            .join("benign")
            .join(format!("p{proto}"))
            .join("int.pkl");
        assert!(path.is_file(), "p{proto}/int.pkl missing");
        let bytes: Vec<u8> = std::fs::read(&path).expect("read int fixture");
        let trace: VmTrace = execute(&disassemble(&bytes).expect("disasm")).expect("vm");
        assert_eq!(
            trace.result,
            PickleValue::Int(42),
            "proto {proto} int fixture mismatch"
        );
    }
}

#[test]
fn nested_dict_fixture_structure() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let path: PathBuf = root.join("benign").join("p4").join("nested_dict.pkl");
    assert!(path.is_file(), "p4/nested_dict.pkl missing");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    let trace: VmTrace = execute(&disassemble(&bytes).expect("disasm")).expect("vm");
    assert!(matches!(trace.result, PickleValue::Dict(_)));
}

#[test]
fn disasm_matches_pickletools_reference() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let ref_path: PathBuf = root.join("opcode_ref.json");
    let ref_text: String = std::fs::read_to_string(&ref_path).expect("opcode_ref.json must exist");
    let reference: std::collections::BTreeMap<String, Vec<String>> =
        serde_json::from_str(&ref_text).expect("parse opcode_ref.json");
    assert!(
        !reference.is_empty(),
        "opcode_ref.json carries no fixture sequences"
    );

    let mut checked: usize = 0;
    for (rel, expected) in &reference {
        let path: PathBuf = root.join(rel);
        assert!(path.is_file(), "ref fixture {rel} missing");
        let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
        let dis: Disassembly = disassemble(&bytes).unwrap_or_else(|e| panic!("disasm {rel}: {e}"));
        let actual: Vec<String> = dis.instructions.iter().map(|i| i.name.clone()).collect();
        assert_eq!(
            &actual, expected,
            "opcode stream for {rel} diverges from CPython pickletools reference"
        );
        checked += 1;
    }
    assert!(checked > 0, "no reference fixtures present");
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn canon_arg(name: &str, arg: &DecodedArg) -> Vec<String> {
    let mut out: Vec<String> = vec![name.to_string()];
    match arg {
        DecodedArg::None => out.push("none".into()),
        DecodedArg::Bool(b) => {
            out.push("int".into());
            out.push(if *b { "1" } else { "0" }.into());
        }
        DecodedArg::Int(v) => {
            out.push("int".into());
            out.push(v.to_string());
        }
        DecodedArg::BigInt(s) => {
            out.push("int".into());
            out.push(s.clone());
        }
        DecodedArg::Float(f) => {
            out.push("float".into());
            out.push(hex_lower(&f.to_be_bytes()));
        }
        DecodedArg::Str(s) => {
            out.push("str".into());
            out.push(s.clone());
        }
        DecodedArg::Bytes(b) => {
            out.push("bytes".into());
            out.push(hex_lower(b));
        }
        DecodedArg::GlobalPair { module, name } => {
            out.push("pair".into());
            out.push(module.clone());
            out.push(name.clone());
        }
    }
    out
}

#[test]
fn decoded_args_match_pickletools_reference() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let ref_path: PathBuf = root.join("arg_ref.json");
    let ref_text: String = std::fs::read_to_string(&ref_path).expect("arg_ref.json must exist");
    let reference: std::collections::BTreeMap<String, Vec<Vec<String>>> =
        serde_json::from_str(&ref_text).expect("parse arg_ref.json");
    assert!(
        !reference.is_empty(),
        "arg_ref.json carries no fixture sequences"
    );

    let mut checked_args: usize = 0;
    for (rel, expected) in &reference {
        let path: PathBuf = root.join(rel);
        assert!(path.is_file(), "ref fixture {rel} missing");
        let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
        let dis: Disassembly = disassemble(&bytes).unwrap_or_else(|e| panic!("disasm {rel}: {e}"));
        let actual: Vec<Vec<String>> = dis
            .instructions
            .iter()
            .map(|i| canon_arg(&i.name, &i.arg))
            .collect();
        assert_eq!(
            &actual, expected,
            "decoded argument stream for {rel} diverges from CPython pickletools reference"
        );
        checked_args += expected.len();
    }
    assert!(
        checked_args > 0,
        "no reference argument sequences present to grade"
    );
}

fn trace_fixture(rel: &str) -> VmTrace {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let path: PathBuf = root.join(rel);
    assert!(path.is_file(), "{rel} missing");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    execute(&disassemble(&bytes).expect("disasm")).expect("vm")
}

#[test]
fn cyclic_list_fixture_surfaces_back_edge() {
    let trace: VmTrace = trace_fixture("structural/cyclic_list.pkl");
    assert!(trace.cyclic, "cyclic_list must be flagged cyclic");
    assert_eq!(
        trace.result,
        PickleValue::List(vec![PickleValue::MemoRef { key: 0 }]),
        "real CPython self-referential list must decode to a memo back-edge"
    );
}

#[test]
fn cyclic_dict_fixture_surfaces_back_edge() {
    let trace: VmTrace = trace_fixture("structural/cyclic_dict.pkl");
    assert!(trace.cyclic, "cyclic_dict must be flagged cyclic");
    let PickleValue::Dict(pairs) = &trace.result else {
        panic!("expected dict, got {:?}", trace.result);
    };
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, PickleValue::Str("self".into()));
    assert_eq!(pairs[0].1, PickleValue::MemoRef { key: 0 });
}

#[test]
fn shared_ref_fixture_is_acyclic() {
    let trace: VmTrace = trace_fixture("structural/shared_ref.pkl");
    assert!(
        !trace.cyclic,
        "shared (non-cyclic) reference must not be flagged cyclic"
    );
    let PickleValue::List(items) = &trace.result else {
        panic!("expected list");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0], items[1],
        "both entries must alias the same memo slot, or pickle.loads's shared identity is lost"
    );
    assert!(
        matches!(items[0], PickleValue::MemoRef { .. }),
        "real CPython shares this list by identity (a single PUT, reused via GET); the recovered \
         graph must reference one memo slot from both call sites rather than deep-copy the value, \
         or the rebuilt object silently loses `rebuilt[0] is rebuilt[1]`"
    );
}

#[test]
fn oob_buffer_fixture_marks_out_of_band() {
    let trace: VmTrace = trace_fixture("structural/oob_buffer.pkl");
    assert_eq!(
        trace.oob_buffer_count, 1,
        "real protocol-5 oob fixture must register one out-of-band buffer"
    );
    let PickleValue::Reduce { callable, args } = &trace.result else {
        panic!("expected reduce, got {:?}", trace.result);
    };
    assert_eq!(
        callable.as_ref(),
        &PickleValue::Global {
            module: "builtins".into(),
            name: "bytes".into(),
        }
    );
    let PickleValue::Tuple(t) = args.as_ref() else {
        panic!("expected tuple args");
    };
    assert_eq!(
        t.as_slice(),
        &[PickleValue::OutOfBandBuffer { readonly: true }],
        "the bytes() arg is an out-of-band readonly buffer, not in-stream data"
    );
}

#[test]
fn ext1_fixture_pushes_extension_code() {
    let trace: VmTrace = trace_fixture("structural/ext1.pkl");
    assert_eq!(
        trace.result,
        PickleValue::Ext { code: 16 },
        "EXT1 must surface the registry code; target stays runtime-only"
    );
}

#[test]
fn oob_buffer_call_graph_links_bytes() {
    let trace: VmTrace = trace_fixture("structural/oob_buffer.pkl");
    assert_eq!(trace.call_graph.len(), 1);
    let site: &disrobe_pass_pickle::CallSite = &trace.call_graph[0];
    assert_eq!(site.kind, CallKind::Reduce);
    assert_eq!(
        site.callable,
        CallableRef::Global {
            module: "builtins".into(),
            name: "bytes".into(),
        }
    );
}

#[derive(Debug, Clone, Copy)]
struct PinnedBar {
    num: u64,
    den: u64,
    value: f64,
}

#[derive(Debug)]
struct PickletoolsReference {
    opcodes: BTreeMap<String, Vec<String>>,
    args: BTreeMap<String, Vec<Vec<String>>>,
}

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labeled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

fn pinned_bar() -> PinnedBar {
    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let num: u64 = bar["num"]
        .as_u64()
        .unwrap_or_else(|| panic!("the `{PUBLISHED_BAR}` bar must publish a numerator"));
    let den: u64 = bar["den"]
        .as_u64()
        .unwrap_or_else(|| panic!("the `{PUBLISHED_BAR}` bar must publish a denominator"));
    let value: f64 = bar["value"].as_f64().unwrap_or_else(|| {
        panic!("the `{PUBLISHED_BAR}` bar must publish the percentage it plots")
    });
    PinnedBar { num, den, value }
}

fn load_reference(root: &Path) -> PickletoolsReference {
    let opcode_path: PathBuf = root.join("opcode_ref.json");
    let arg_path: PathBuf = root.join("arg_ref.json");
    let opcode_text: String = std::fs::read_to_string(&opcode_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", opcode_path.display()));
    let arg_text: String = std::fs::read_to_string(&arg_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", arg_path.display()));
    PickletoolsReference {
        opcodes: serde_json::from_str(&opcode_text)
            .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", opcode_path.display())),
        args: serde_json::from_str(&arg_text)
            .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", arg_path.display())),
    }
}

fn relative_key(root: &Path, file: &Path) -> String {
    let rel: &Path = file
        .strip_prefix(root)
        .unwrap_or_else(|e: StripPrefixError| {
            panic!("{} sits under the corpus root: {e}", file.display())
        });
    let parts: Vec<String> = rel
        .components()
        .map(|part: Component<'_>| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    parts.join("/")
}

fn present_fixtures(root: &Path) -> BTreeSet<String> {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_pkl(root, &mut files);
    files
        .iter()
        .map(|file: &PathBuf| relative_key(root, file))
        .collect()
}

fn membership_defects(reference: &PickletoolsReference, present: &BTreeSet<String>) -> Vec<String> {
    let opcode_keys: BTreeSet<String> = reference.opcodes.keys().cloned().collect();
    let arg_keys: BTreeSet<String> = reference.args.keys().cloned().collect();
    let mut defects: Vec<String> = Vec::new();
    for (name, keys) in [
        ("opcode_ref.json", &opcode_keys),
        ("arg_ref.json", &arg_keys),
    ] {
        for absent in present.difference(keys) {
            defects.push(format!(
                "{absent} is committed under corpus/pickle but corpus/pickle/{name} carries no \
                 CPython pickletools reference for it, so grading it would compare nothing"
            ));
        }
        for orphan in keys.difference(present) {
            defects.push(format!(
                "corpus/pickle/{name} references {orphan}, which is no longer committed; the \
                 published figure names this fixture set, so a removed fixture is a regression \
                 rather than a smaller population"
            ));
        }
    }
    defects
}

fn shape_defects(present: &BTreeSet<String>) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    for protocol in BENIGN_PROTOCOLS {
        let prefix: String = format!("benign/{protocol}/");
        let count: usize = present
            .iter()
            .filter(|rel: &&String| rel.starts_with(&prefix))
            .count();
        if count != BENIGN_FIXTURES_PER_PROTOCOL {
            defects.push(format!(
                "benign/{protocol} must carry {BENIGN_FIXTURES_PER_PROTOCOL} fixtures, one per \
                 benign Python type emitted at that protocol; it carries {count}"
            ));
        }
    }
    let structural: usize = present
        .iter()
        .filter(|rel: &&String| rel.starts_with("structural/"))
        .count();
    if structural != STRUCTURAL_FIXTURES {
        defects.push(format!(
            "structural/ must carry {STRUCTURAL_FIXTURES} fixtures (memo cycles, shared identity, \
             deep nesting, an out-of-band buffer and an extension code); it carries {structural}"
        ));
    }
    let malicious: BTreeSet<String> = present
        .iter()
        .filter(|rel: &&String| rel.starts_with("malicious/"))
        .cloned()
        .collect();
    let expected: BTreeSet<String> = MALICIOUS_FIXTURES
        .iter()
        .map(|rel: &&str| (*rel).to_owned())
        .collect();
    if malicious != expected {
        defects.push(format!(
            "the malicious half of the corpus is pinned by name, so a fixture cannot be renamed out \
             of the strict classification leg; expected {expected:?}, found {malicious:?}"
        ));
    }
    defects
}

fn grade_fixture(root: &Path, rel: &str, reference: &PickletoolsReference) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    let path: PathBuf = root.join(rel);
    let bytes: Vec<u8> = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            defects.push(format!(
                "{rel}: the committed fixture could not be read ({error}); an unreadable fixture is \
                 how a truncated or quarantined sample stops being graded while the figure stands"
            ));
            return defects;
        }
    };
    let dis: Disassembly = match disassemble(&bytes) {
        Ok(dis) => dis,
        Err(error) => {
            defects.push(format!("{rel}: disassembly failed ({error})"));
            return defects;
        }
    };
    let terminated: bool = dis.stop_offset.is_some();
    if !terminated {
        defects.push(format!(
            "{rel}: the opcode stream carries no STOP, so the pickle never terminates"
        ));
    }
    match reference.opcodes.get(rel) {
        Some(expected) => {
            let actual: Vec<String> = dis
                .instructions
                .iter()
                .map(|insn: &Insn| insn.name.clone())
                .collect();
            if &actual != expected {
                defects.push(format!(
                    "{rel}: the opcode stream diverges from the CPython pickletools reference"
                ));
            }
        }
        None => defects.push(format!(
            "{rel}: corpus/pickle/opcode_ref.json carries no opcode stream to grade against"
        )),
    }
    match reference.args.get(rel) {
        Some(expected) => {
            let actual: Vec<Vec<String>> = dis
                .instructions
                .iter()
                .map(|insn: &Insn| canon_arg(&insn.name, &insn.arg))
                .collect();
            if &actual != expected {
                defects.push(format!(
                    "{rel}: the decoded argument stream diverges from the CPython pickletools \
                     reference"
                ));
            }
        }
        None => defects.push(format!(
            "{rel}: corpus/pickle/arg_ref.json carries no argument stream to grade against"
        )),
    }
    let trace: VmTrace = match execute(&dis) {
        Ok(trace) => trace,
        Err(error) => {
            defects.push(format!("{rel}: the trace stopped short ({error})"));
            return defects;
        }
    };
    let source: String = to_python(&trace.result);
    if source.is_empty() {
        defects.push(format!(
            "{rel}: the traced value rendered to empty Python, so nothing was recovered to read"
        ));
    }
    let report: SafetyReport = analyze_safety(&trace);
    let flagged: bool = report.severity == Severity::OvertlyMalicious;
    let expect_flagged: bool = MALICIOUS_FIXTURES.contains(&rel);
    if flagged != expect_flagged {
        defects.push(format!(
            "{rel}: classification disagrees with the fixture's own label; expected \
             OvertlyMalicious={expect_flagged}, got {:?}",
            report.severity
        ));
    }
    defects
}

fn bar_defects(graded: usize, population: usize, bar: PinnedBar) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    let measured_population: u64 =
        u64::try_from(population).expect("the committed fixture count fits u64");
    let measured_graded: u64 = u64::try_from(graded).expect("the graded fixture count fits u64");
    if measured_population != bar.den {
        defects.push(format!(
            "xtask/data/recovery.json publishes a denominator of {} committed pickle fixtures and \
             every document renders that number, but corpus/pickle carries {measured_population}. A \
             run that inspects fewer fixtures must score worse, never shrink what it is measured \
             against",
            bar.den
        ));
    }
    if measured_graded < bar.num {
        defects.push(format!(
            "recovery.json publishes {} of {} fixtures disassembled, traced and classified against \
             the pickletools reference; this run graded {measured_graded}. Raise the recovery or \
             correct the published figure, never the reverse",
            bar.num, bar.den
        ));
    }
    let derived: f64 = 100.0 * bar.num as f64 / bar.den as f64;
    if (derived - bar.value).abs() >= PUBLISHED_VALUE_TOLERANCE {
        defects.push(format!(
            "the plotted value {} must equal its own {}/{} = {derived:.4}",
            bar.value, bar.num, bar.den
        ));
    }
    defects
}

#[test]
fn published_pickle_corpus_bar_is_pinned_to_the_graded_fixture_set() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let bar: PinnedBar = pinned_bar();
    let reference: PickletoolsReference = load_reference(&root);
    let present: BTreeSet<String> = present_fixtures(&root);
    let mut defects: Vec<String> = membership_defects(&reference, &present);
    defects.extend(shape_defects(&present));
    let mut graded: BTreeSet<String> = BTreeSet::new();
    for rel in &present {
        let per_fixture: Vec<String> = grade_fixture(&root, rel, &reference);
        if per_fixture.is_empty() {
            graded.insert(rel.clone());
        }
        defects.extend(per_fixture);
    }
    defects.extend(bar_defects(graded.len(), present.len(), bar));
    eprintln!(
        "pickle corpus: {} of {} committed fixtures disassemble, trace and classify against the \
         CPython pickletools reference; published {}/{} = {}",
        graded.len(),
        present.len(),
        bar.num,
        bar.den,
        bar.value
    );
    assert!(
        defects.is_empty(),
        "the published `{PUBLISHED_BAR}` figure is {} of {} against the committed corpus, and that \
         figure is this named fixture set rather than a bare count:\n{}",
        bar.num,
        bar.den,
        defects.join("\n")
    );
}

#[test]
fn the_pinned_corpus_check_rejects_a_dropped_fixture_and_a_shrunken_denominator() {
    let bar: PinnedBar = pinned_bar();
    let graded: usize = usize::try_from(bar.num).expect("the published numerator fits usize");
    let population: usize = usize::try_from(bar.den).expect("the published denominator fits usize");
    assert!(
        bar_defects(graded, population, bar).is_empty(),
        "the check must accept the published measurement unchanged"
    );

    let dropped: Vec<String> = bar_defects(graded - 1, population, bar);
    assert!(
        dropped
            .iter()
            .any(|d: &String| d.contains("this run graded")),
        "losing one graded fixture must be reported as a shortfall against the published \
         numerator, got {dropped:?}"
    );

    let shrunk: Vec<String> = bar_defects(graded - 1, population - 1, bar);
    assert!(
        shrunk
            .iter()
            .any(|d: &String| d.contains("never shrink what it is measured against")),
        "dropping a fixture from the graded population must be rejected on the denominator rather \
         than absorbed as a better ratio, got {shrunk:?}"
    );

    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let reference: PickletoolsReference = load_reference(&root);
    let present: BTreeSet<String> = present_fixtures(&root);
    let removed: &str = MALICIOUS_FIXTURES[0];
    let seeded: BTreeSet<String> = present
        .iter()
        .filter(|rel: &&String| rel.as_str() != removed)
        .cloned()
        .collect();
    let by_name: Vec<String> = membership_defects(&reference, &seeded);
    assert!(
        by_name.iter().any(|d: &String| d.contains(removed)),
        "removing {removed} must be reported by name, got {by_name:?}"
    );
    let by_shape: Vec<String> = shape_defects(&seeded);
    assert!(
        by_shape
            .iter()
            .any(|d: &String| d.contains("pinned by name")),
        "removing a malicious fixture must also fail the pinned malicious set, got {by_shape:?}"
    );
}
