#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_as3::AbcFile;
use disrobe_pass_as3::abc::{self, ConstantPool, MethodBody, MethodInfo};
use disrobe_pass_as3::lifter::{CaseLabel, Expr, LiftedBody, Stmt, SwitchCase, lift_body};
use disrobe_pass_as3::swf::{self, Swf};

const MERGE_PREFIX: &str = "_temp";

const CONTROL_SHAPES: &[u8] =
    include_bytes!("../../../corpus/flash/avm2_disasm_oracle/control_shapes.swf");
const OPCODE_BREADTH: &[u8] =
    include_bytes!("../../../corpus/flash/avm2_disasm_oracle/opcode_breadth.swf");
const SWITCH_MERGE: &[u8] = include_bytes!("fixtures/switch_merge.swf");
const DISPATCH_SHAPES: &[u8] = include_bytes!("fixtures/dispatch_shapes.swf");
const WHITESPACE_SHORT_CIRCUIT: &[u8] = include_bytes!("fixtures/whitespace_short_circuit.swf");
const JSON_TOKENIZER: &[u8] = include_bytes!("fixtures/json_tokenizer_postincrement.swf");

#[derive(Debug, Default)]
struct TemporaryTally {
    bodies: usize,
    bodies_using_a_temporary: usize,
    temporaries: usize,
    undefined: Vec<String>,
}

fn is_merge_temporary(name: &str) -> bool {
    name.strip_prefix(MERGE_PREFIX)
        .is_some_and(|tail: &str| !tail.is_empty() && tail.bytes().all(|b: u8| b.is_ascii_digit()))
}

fn read_names(expression: &Expr, out: &mut BTreeSet<String>) {
    match expression {
        Expr::Name(name) | Expr::Lex(name) => {
            if is_merge_temporary(name) {
                out.insert(name.clone());
            }
        }
        Expr::Unary { operand, .. }
        | Expr::Update { operand, .. }
        | Expr::Coerce { operand, .. }
        | Expr::Typeof(operand)
        | Expr::Get {
            object: operand, ..
        }
        | Expr::Delete {
            object: operand, ..
        }
        | Expr::Descendants {
            object: operand, ..
        } => read_names(operand, out),
        Expr::Binary { lhs, rhs, .. }
        | Expr::Index {
            object: lhs,
            index: rhs,
        } => {
            read_names(lhs, out);
            read_names(rhs, out);
        }
        Expr::IsType { operand, ty } | Expr::AsType { operand, ty } => {
            read_names(operand, out);
            read_names(ty, out);
        }
        Expr::Ternary {
            cond,
            then_value,
            else_value,
        } => {
            read_names(cond, out);
            read_names(then_value, out);
            read_names(else_value, out);
        }
        Expr::Call { callee, args, .. } | Expr::Construct { callee, args, .. } => {
            read_names(callee, out);
            for argument in args {
                read_names(argument, out);
            }
        }
        Expr::New { ty: base, args } | Expr::Applied { base, args } => {
            read_names(base, out);
            for argument in args {
                read_names(argument, out);
            }
        }
        Expr::Array(items) => {
            for item in items {
                read_names(item, out);
            }
        }
        Expr::Object(pairs) => {
            for (key, value) in pairs {
                read_names(key, out);
                read_names(value, out);
            }
        }
        _ => {}
    }
}

fn collect_names(stmts: &[Stmt], written: &mut BTreeSet<String>, read: &mut BTreeSet<String>) {
    for statement in stmts {
        match statement {
            Stmt::Assign { target, value } => {
                match target {
                    Expr::Name(name) if is_merge_temporary(name) => {
                        written.insert(name.clone());
                    }
                    other => read_names(other, read),
                }
                read_names(value, read);
            }
            Stmt::AssignProperty { object, value, .. } => {
                read_names(object, read);
                read_names(value, read);
            }
            Stmt::AssignIndex {
                object,
                index,
                value,
            } => {
                read_names(object, read);
                read_names(index, read);
                read_names(value, read);
            }
            Stmt::Expression(value) | Stmt::Throw(value) => read_names(value, read),
            Stmt::Return(value) => {
                if let Some(value) = value {
                    read_names(value, read);
                }
            }
            Stmt::If { cond, .. } => read_names(cond, read),
            Stmt::IfBlock { cond, body }
            | Stmt::While { cond, body }
            | Stmt::DoWhile { cond, body } => {
                read_names(cond, read);
                collect_names(body, written, read);
            }
            Stmt::IfElse {
                cond,
                then_body,
                else_body,
            } => {
                read_names(cond, read);
                collect_names(then_body, written, read);
                collect_names(else_body, written, read);
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
            } => {
                collect_names(std::slice::from_ref(init), written, read);
                read_names(cond, read);
                collect_names(std::slice::from_ref(update), written, read);
                collect_names(body, written, read);
            }
            Stmt::ForEach {
                var,
                collection,
                body,
            }
            | Stmt::ForIn {
                var,
                collection,
                body,
            } => {
                read_names(var, read);
                read_names(collection, read);
                collect_names(body, written, read);
            }
            Stmt::With { object, body } => {
                read_names(object, read);
                collect_names(body, written, read);
            }
            Stmt::Try { body, catches } => {
                collect_names(body, written, read);
                for clause in catches {
                    collect_names(&clause.body, written, read);
                }
            }
            Stmt::Switch { selector, .. } => read_names(selector, read),
            Stmt::StructuredSwitch { selector, cases } => {
                read_names(selector, read);
                for case in cases {
                    for label in &case.labels {
                        if let CaseLabel::Expr(value) = label {
                            read_names(value, read);
                        }
                    }
                    collect_names(&case.body, written, read);
                }
            }
            Stmt::Jump { .. }
            | Stmt::Label(_)
            | Stmt::Comment(_)
            | Stmt::Break
            | Stmt::Continue => {}
        }
    }
}

fn grade_abc(abc: &AbcFile, label: &str, tally: &mut TemporaryTally) {
    for (index, body) in abc.method_bodies.iter().enumerate() {
        let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
        let Ok(lifted): Result<LiftedBody, _> = lift_body(abc, body, info) else {
            continue;
        };
        tally.bodies += 1;
        let mut written: BTreeSet<String> = BTreeSet::new();
        let mut read: BTreeSet<String> = BTreeSet::new();
        collect_names(&lifted.statements, &mut written, &mut read);
        if read.is_empty() && written.is_empty() {
            continue;
        }
        tally.bodies_using_a_temporary += 1;
        tally.temporaries += written.len();
        for name in read.difference(&written) {
            tally.undefined.push(format!("{label}#{index}:{name}"));
        }
    }
}

fn grade_swf(bytes: &[u8], label: &str, tally: &mut TemporaryTally) {
    let parsed: Swf = swf::parse(bytes).expect("tracked fixture must parse");
    for blob in parsed.collect_do_abc() {
        let abc: AbcFile = abc::parse(&blob.abc_bytes).expect("tracked fixture ABC must parse");
        grade_abc(&abc, label, tally);
    }
}

#[test]
fn every_tracked_body_writes_the_merge_temporaries_it_reads() {
    let mut tally: TemporaryTally = TemporaryTally::default();
    grade_swf(CONTROL_SHAPES, "control_shapes", &mut tally);
    grade_swf(OPCODE_BREADTH, "opcode_breadth", &mut tally);
    grade_swf(SWITCH_MERGE, "switch_merge", &mut tally);
    grade_swf(DISPATCH_SHAPES, "dispatch_shapes", &mut tally);
    grade_swf(
        WHITESPACE_SHORT_CIRCUIT,
        "whitespace_short_circuit",
        &mut tally,
    );
    grade_swf(JSON_TOKENIZER, "json_tokenizer", &mut tally);
    eprintln!("AS3 tracked merge temporaries: {tally:?}");
    assert!(
        tally.bodies >= 200,
        "this gate reads every body in the tracked compiler fixtures, so a shrinking population \
         would let it pass over almost nothing; got {}",
        tally.bodies
    );
    assert!(
        tally.bodies_using_a_temporary > 0,
        "no tracked body reached a merge or a stale-read hoist, so this gate graded nothing"
    );
    assert_eq!(
        tally.undefined,
        Vec::<String>::new(),
        "a recovered body read a temporary no path in it writes. A merge operand that names a \
         value without producing it is not recovered ActionScript: the reader cannot tell what \
         the join carried, and the text does not recompile"
    );
}

#[test]
fn every_corpus_body_writes_the_merge_temporaries_it_reads() {
    let dir: PathBuf = common::as3_corpus_root();
    if !common::require_corpus("as3 merge temporaries", &dir) {
        return;
    }
    let mut tally: TemporaryTally = TemporaryTally::default();
    let mut files: usize = 0;
    for entry in std::fs::read_dir(&dir).expect("read corpus") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) != Some("swf") {
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        files += 1;
        let label: String = path.file_name().map_or_else(
            || "?".to_owned(),
            |name: &std::ffi::OsStr| name.to_string_lossy().into_owned(),
        );
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            grade_abc(&abc, &label, &mut tally);
        }
    }
    eprintln!("AS3 corpus merge temporaries: files={files} {tally:?}");
    assert!(files >= 5, "the corpus must supply several real files");
    assert!(
        tally.bodies > 1000,
        "the corpus population must stay large enough to measure; got {}",
        tally.bodies
    );
    assert!(
        tally.bodies_using_a_temporary >= 100,
        "real compiler output must keep reaching merges and hoists, or this gate stopped \
         exercising the reconciler; got {}",
        tally.bodies_using_a_temporary
    );
    let sample: &[String] = tally
        .undefined
        .get(..10.min(tally.undefined.len()))
        .unwrap_or_default();
    assert!(
        tally.undefined.is_empty(),
        "{} recovered bodies read a temporary no path in them writes; first offenders: {sample:?}",
        tally.undefined.len()
    );
}

const fn merge_body(code: Vec<u8>) -> MethodBody {
    MethodBody {
        method: 0,
        max_stack: 8,
        local_count: 3,
        init_scope_depth: 0,
        max_scope_depth: 8,
        code,
        exceptions: Vec::new(),
        traits: Vec::new(),
    }
}

fn bare_abc() -> AbcFile {
    AbcFile {
        minor: abc::ABC_MINOR,
        major: abc::ABC_MAJOR,
        cpool: ConstantPool::default(),
        methods: Vec::new(),
        metadata_count: 0,
        instances: Vec::new(),
        classes: Vec::new(),
        scripts: Vec::new(),
        method_bodies: Vec::new(),
    }
}

#[test]
fn an_encoded_merge_writes_its_temporary_on_every_incoming_path() {
    let shapes: [(&str, Vec<u8>, usize); 2] = [
        (
            "two-way branch join",
            vec![
                0x24, 0x00, 0x11, 0x06, 0x00, 0x00, 0x24, 0x01, 0x10, 0x07, 0x00, 0x00, 0x29, 0x24,
                0x02, 0x10, 0x00, 0x00, 0x00, 0x48,
            ],
            2,
        ),
        (
            "three-case lookupswitch join",
            vec![
                0x24, 0x00, 0x1B, 0x17, 0x00, 0x00, 0x01, 0x0B, 0x00, 0x00, 0x11, 0x00, 0x00, 0x24,
                0x0A, 0x10, 0x08, 0x00, 0x00, 0x24, 0x14, 0x10, 0x02, 0x00, 0x00, 0x24, 0x1E, 0x48,
            ],
            3,
        ),
    ];
    let abc: AbcFile = bare_abc();
    for (label, code, predecessors) in shapes {
        let body: MethodBody = merge_body(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("encoded merge must lift");
        let mut written: BTreeSet<String> = BTreeSet::new();
        let mut read: BTreeSet<String> = BTreeSet::new();
        collect_names(&lifted.statements, &mut written, &mut read);
        assert_eq!(
            read.len(),
            1,
            "{label}: the join must carry exactly one merged operand: {:?}",
            lifted.statements
        );
        assert_eq!(
            read.difference(&written).count(),
            0,
            "{label}: the merged operand is read but no path writes it: {:?}",
            lifted.statements
        );
        let name: &String = read.iter().next().expect("one merged operand");
        assert_eq!(
            common::merge_definitions(&lifted.statements, &Expr::Name(name.clone())).len(),
            predecessors,
            "{label}: every incoming path must write the merged operand exactly once, so a \
             partial reconciler that writes only the path it visited last cannot pass: {:?}",
            lifted.statements
        );
        assert_eq!(
            lifted.opaque_operands, 0,
            "{label}: a merge resolved into a written temporary is not a fabricated operand: \
             {:?}",
            lifted.statements
        );
    }
}

#[test]
fn the_gate_reports_a_temporary_that_no_path_writes() {
    let stmts: Vec<Stmt> = vec![
        Stmt::StructuredSwitch {
            selector: Expr::Local(1),
            cases: vec![SwitchCase {
                labels: vec![CaseLabel::Value(0)],
                body: vec![Stmt::Assign {
                    target: Expr::Name("_temp0".to_owned()),
                    value: Expr::IntLit(1),
                }],
                breaks: true,
            }],
        },
        Stmt::Return(Some(Expr::Name("_temp1".to_owned()))),
    ];
    let mut written: BTreeSet<String> = BTreeSet::new();
    let mut read: BTreeSet<String> = BTreeSet::new();
    collect_names(&stmts, &mut written, &mut read);
    assert_eq!(
        written.iter().cloned().collect::<Vec<String>>(),
        vec!["_temp0".to_owned()]
    );
    assert_eq!(
        read.iter().cloned().collect::<Vec<String>>(),
        vec!["_temp1".to_owned()]
    );
    assert_eq!(
        read.difference(&written).cloned().collect::<Vec<String>>(),
        vec!["_temp1".to_owned()],
        "the gate must name a temporary that is read without being written, or it cannot fail \
         on the defect it exists to catch"
    );
}
