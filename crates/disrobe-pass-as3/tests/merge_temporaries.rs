#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_as3::AbcFile;
use disrobe_pass_as3::abc::{self, ConstantPool, ExceptionInfo, MethodBody, MethodInfo};
use disrobe_pass_as3::lifter::{
    CaseLabel, Expr, LiftedBody, Stmt, SwitchCase, lift_body, lift_body_raw,
};
use disrobe_pass_as3::swf::{self, Swf};

const MERGE_PREFIX: &str = "_merge";

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
    assert_eq!(
        tally.bodies_using_a_temporary, 0,
        "no compiler fixture tracked here emits a merge join whose operands disagree, so this \
         case grades the ABSENCE of an undefined merge read over 555 bodies and nothing more. \
         The merge machinery itself is graded by an_encoded_merge_writes_its_temporary_on_every_incoming_path, \
         which builds the join from ABC bytes and cannot skip. If a fixture ever does produce \
         one, this number moves and the pin above starts carrying real weight"
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

fn patch_branch_target(code: &mut [u8], operand: usize, target: usize) {
    let after_operand: usize = operand.saturating_add(3);
    let relative: i32 = i32::try_from(target)
        .and_then(|target: i32| {
            i32::try_from(after_operand).map(|after_operand: i32| target - after_operand)
        })
        .expect("fixture branch must fit s24");
    let encoded: [u8; 4] = relative.to_le_bytes();
    code[operand..operand + 3].copy_from_slice(&encoded[..3]);
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
fn an_encoded_null_coalescing_merge_preserves_null_and_falsy_values() {
    let mut code: Vec<u8> = vec![0xD1, 0x2A, 0x20, 0x14];
    let present_operand: usize = code.len();
    code.extend_from_slice(&[0x00, 0x00, 0x00, 0x29, 0xD2]);
    let merge: usize = code.len();
    code.push(0x48);
    let after_present: usize = present_operand.saturating_add(3);
    let relative: i32 = i32::try_from(merge)
        .and_then(|target: i32| i32::try_from(after_present).map(|after: i32| target - after))
        .expect("fixture branch must fit s24");
    let encoded: [u8; 4] = relative.to_le_bytes();
    code[present_operand..present_operand + 3].copy_from_slice(&encoded[..3]);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = merge_body(code);
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("null-coalescing merge must lift");
    let mut written: BTreeSet<String> = BTreeSet::new();
    let mut read: BTreeSet<String> = BTreeSet::new();
    collect_names(&lifted.statements, &mut written, &mut read);

    assert_eq!(read.len(), 1, "the join must carry one value: {lifted:#?}");
    assert_eq!(read.difference(&written).count(), 0, "{lifted:#?}");
    let name: &String = read.iter().next().expect("one merged operand");
    assert_eq!(
        common::merge_definitions(&lifted.statements, &Expr::Name(name.clone())),
        vec![Expr::Local(1), Expr::Local(2)],
        "the present value and fallback must each define the join once in bytecode order: \
         {lifted:#?}"
    );
    assert_eq!(lifted.opaque_operands, 0, "{lifted:#?}");

    for (value, fallback, expected) in [
        (common::Value::Null, 7i64, 7i64),
        (common::Value::Int(3), 7i64, 3i64),
        (common::Value::Int(0), 7i64, 0i64),
    ] {
        let observed: common::Value = common::evaluate(
            &lifted.statements,
            "null coalescing",
            &[(1, value), (2, common::Value::Int(fallback))],
        );
        assert_eq!(observed, common::Value::Int(expected), "{lifted:#?}");
    }
}

fn encoded_ternary_chain(levels: usize) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::with_capacity(levels.saturating_mul(12));
    let mut join_operands: Vec<usize> = Vec::with_capacity(levels);
    for level in 0..levels {
        code.extend_from_slice(&[0xD1, 0x12]);
        let next_operand: usize = code.len();
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x24]);
        code.push(u8::try_from(level.saturating_add(1)).expect("bounded branch value"));
        code.push(0x10);
        let join_operand: usize = code.len();
        code.extend_from_slice(&[0x00, 0x00, 0x00]);
        join_operands.push(join_operand);
        let next_test: usize = code.len();
        patch_branch_target(&mut code, next_operand, next_test);
    }
    code.extend_from_slice(&[0x24, 0x00]);
    let join: usize = code.len();
    code.push(0x48);
    for operand in join_operands {
        patch_branch_target(&mut code, operand, join);
    }
    code
}

#[test]
fn ternary_folding_stops_at_its_encoded_input_ceiling() {
    const WITHIN_CEILING: usize = 64;
    const BEYOND_CEILING: usize = WITHIN_CEILING.saturating_add(1);

    let abc: AbcFile = bare_abc();
    let within_body: MethodBody = merge_body(encoded_ternary_chain(WITHIN_CEILING));
    let within: LiftedBody =
        lift_body(&abc, &within_body, None).expect("ternary chain at ceiling must lift");
    assert!(within.fully_structured, "{within:#?}");
    assert!(within.structurally_recovered, "{within:#?}");
    assert_eq!(within.opaque_operands, 0, "{within:#?}");
    for (selector, expected) in [(false, 0i64), (true, 1i64)] {
        let observed: common::Value = common::evaluate(
            &within.statements,
            "ternary chain at ceiling",
            &[(1, common::Value::Bool(selector))],
        );
        assert_eq!(observed, common::Value::Int(expected), "{within:#?}");
    }

    let beyond_body: MethodBody = merge_body(encoded_ternary_chain(BEYOND_CEILING));
    let beyond: LiftedBody =
        lift_body(&abc, &beyond_body, None).expect("ternary chain beyond ceiling must lift");

    assert!(beyond.reached_terminator, "{beyond:#?}");
    assert!(!beyond.fully_structured, "{beyond:#?}");
    assert!(!beyond.structurally_recovered, "{beyond:#?}");
    assert_eq!(beyond.opaque_operands, 2, "{beyond:#?}");
    assert!(
        beyond
            .statements
            .iter()
            .any(|statement: &Stmt| matches!(statement, Stmt::If { .. })),
        "the fold beyond the fixed ceiling must remain explicit control flow: {beyond:#?}"
    );
    assert!(
        beyond.statements.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == "unreconciled stack height"
        )),
        "the bounded refusal must name the unresolved join: {beyond:#?}"
    );
}

#[test]
fn an_encoded_merge_inside_an_exception_range_keeps_both_normal_values() {
    let code: Vec<u8> = vec![
        0xD1, 0x11, 0x06, 0x00, 0x00, 0x24, 0x01, 0x10, 0x07, 0x00, 0x00, 0x29, 0x24, 0x02, 0x10,
        0x00, 0x00, 0x00, 0x48, 0x29, 0x24, 0x09, 0x48,
    ];
    let mut body: MethodBody = merge_body(code);
    body.exceptions.push(ExceptionInfo {
        from: 0,
        to: 19,
        target: 19,
        exc_type: 0,
        var_name: 0,
    });
    let abc: AbcFile = bare_abc();
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("protected merge must lift");
    let mut written: BTreeSet<String> = BTreeSet::new();
    let mut read: BTreeSet<String> = BTreeSet::new();
    collect_names(&lifted.statements, &mut written, &mut read);

    assert_eq!(
        read.len(),
        1,
        "the protected join must carry one value: {lifted:#?}"
    );
    assert_eq!(read.difference(&written).count(), 0, "{lifted:#?}");
    let name: &String = read.iter().next().expect("one protected merge operand");
    assert_eq!(
        common::merge_definitions(&lifted.statements, &Expr::Name(name.clone())),
        vec![Expr::IntLit(1), Expr::IntLit(2)],
        "both normal paths must define the protected join once: {lifted:#?}"
    );
    assert_eq!(lifted.opaque_operands, 0, "{lifted:#?}");

    for (selector, expected) in [(false, 1i64), (true, 2i64)] {
        let observed: common::Value = common::evaluate(
            &lifted.statements,
            "protected merge",
            &[(1, common::Value::Bool(selector))],
        );
        assert_eq!(observed, common::Value::Int(expected), "{lifted:#?}");
    }
}

fn restated_definitions(stmts: &[Stmt], out: &mut Vec<(String, String)>) {
    for statement in stmts {
        match statement {
            Stmt::Assign {
                target: Expr::Name(name),
                value,
            } if is_merge_temporary(name) && !value_is_a_leaf(value) => {
                out.push((name.clone(), format!("{value:?}")));
            }
            Stmt::IfBlock { body, .. }
            | Stmt::While { body, .. }
            | Stmt::DoWhile { body, .. }
            | Stmt::ForEach { body, .. }
            | Stmt::ForIn { body, .. }
            | Stmt::With { body, .. }
            | Stmt::For { body, .. } => restated_definitions(body, out),
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                restated_definitions(then_body, out);
                restated_definitions(else_body, out);
            }
            Stmt::Try { body, catches } => {
                restated_definitions(body, out);
                for clause in catches {
                    restated_definitions(&clause.body, out);
                }
            }
            Stmt::StructuredSwitch { cases, .. } => {
                for case in cases {
                    restated_definitions(&case.body, out);
                }
            }
            _ => {}
        }
    }
}

const fn value_is_a_leaf(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::This
            | Expr::Local(_)
            | Expr::Param(_)
            | Expr::IntLit(_)
            | Expr::UintLit(_)
            | Expr::DoubleLit(_)
            | Expr::StringLit(_)
            | Expr::BoolLit(_)
            | Expr::Null
            | Expr::Undefined
            | Expr::NaN
    )
}

#[test]
fn no_corpus_body_restates_one_merge_value_on_two_paths() {
    let dir: PathBuf = common::as3_corpus_root();
    if !common::require_corpus("as3 merge duplication", &dir) {
        return;
    }
    let mut bodies: usize = 0;
    let mut restated: usize = 0;
    let mut duplicated: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read corpus") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) != Some("swf") {
            continue;
        }
        let label: String = path.file_stem().map_or_else(
            || "?".to_owned(),
            |name: &std::ffi::OsStr| name.to_string_lossy().into_owned(),
        );
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            for (index, body) in abc.method_bodies.iter().enumerate() {
                let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
                let Ok(lifted): Result<LiftedBody, _> = lift_body(&abc, body, info) else {
                    continue;
                };
                bodies += 1;
                let mut found: Vec<(String, String)> = Vec::new();
                restated_definitions(&lifted.statements, &mut found);
                restated += found.len();
                let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
                for pair in found {
                    if !seen.insert(pair.clone()) {
                        duplicated.push(format!("{label}#{index}:{}", pair.0));
                    }
                }
            }
        }
    }
    eprintln!("AS3 corpus restated merge writes: bodies={bodies} non_leaf_definitions={restated}");
    assert!(bodies > 1000, "the population must stay large enough");
    assert!(
        duplicated.is_empty(),
        "a merge value that is not a simple leaf was written on more than one incoming path with \
         the same expression, so one evaluation in the bytecode became two in the recovered \
         source. A property read can run a getter, so this is observable even when nothing is \
         assigned. Offenders: {duplicated:?}"
    );
}

#[test]
fn the_gate_reports_one_merge_value_restated_on_two_paths() {
    let read: Expr = Expr::Get {
        object: Box::new(Expr::Local(1)),
        property: "length".to_owned(),
    };
    let stmts: Vec<Stmt> = vec![
        Stmt::IfElse {
            cond: Expr::Local(2),
            then_body: vec![Stmt::Assign {
                target: Expr::Name("_merge0".to_owned()),
                value: read.clone(),
            }],
            else_body: vec![Stmt::Assign {
                target: Expr::Name("_merge0".to_owned()),
                value: read,
            }],
        },
        Stmt::Return(Some(Expr::Name("_merge0".to_owned()))),
    ];
    let mut found: Vec<(String, String)> = Vec::new();
    restated_definitions(&stmts, &mut found);
    assert_eq!(
        found.len(),
        2,
        "both arms write the same property read, and a property read is not a simple leaf"
    );
    assert_eq!(
        found[0], found[1],
        "the two writes must be indistinguishable, which is what makes one bytecode evaluation \
         two evaluations in the recovered source"
    );

    let leaf_only: Vec<Stmt> = vec![Stmt::Assign {
        target: Expr::Name("_merge0".to_owned()),
        value: Expr::Local(4),
    }];
    let mut leaves: Vec<(String, String)> = Vec::new();
    restated_definitions(&leaf_only, &mut leaves);
    assert!(
        leaves.is_empty(),
        "re-reading a local on two paths costs nothing observable, so the gate must not report \
         it or it would forbid the reconciler's ordinary case"
    );
}

#[test]
fn every_corpus_merge_write_sits_at_the_end_of_its_path() {
    let dir: PathBuf = common::as3_corpus_root();
    if !common::require_corpus("as3 merge write placement", &dir) {
        return;
    }
    let mut writes: usize = 0;
    let mut leaf: usize = 0;
    let mut misplaced: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read corpus") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) != Some("swf") {
            continue;
        }
        let label: String = path.file_stem().map_or_else(
            || "?".to_owned(),
            |name: &std::ffi::OsStr| name.to_string_lossy().into_owned(),
        );
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            for (index, body) in abc.method_bodies.iter().enumerate() {
                let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
                let Ok(raw): Result<Vec<Stmt>, _> = lift_body_raw(&abc, body, info) else {
                    continue;
                };
                for (position, statement) in raw.iter().enumerate() {
                    let Stmt::Assign {
                        target: Expr::Name(name),
                        value,
                    } = statement
                    else {
                        continue;
                    };
                    if !is_merge_temporary(name) {
                        continue;
                    }
                    writes += 1;
                    if value_is_a_leaf(value) {
                        leaf += 1;
                    }
                    let mut next: usize = position + 1;
                    loop {
                        match raw.get(next) {
                            Some(Stmt::Comment(_)) => next += 1,
                            Some(Stmt::Assign {
                                target: Expr::Name(sibling),
                                ..
                            }) if is_merge_temporary(sibling) => next += 1,
                            _ => break,
                        }
                    }
                    let terminal: bool = matches!(
                        raw.get(next),
                        Some(
                            Stmt::Jump { .. }
                                | Stmt::If { .. }
                                | Stmt::Label(_)
                                | Stmt::Switch { .. }
                        )
                    ) || raw.get(next).is_none();
                    if !terminal {
                        misplaced.push(format!("{label}#{index}:{name}"));
                    }
                }
            }
        }
    }
    eprintln!(
        "AS3 corpus merge write placement: writes={writes} leaf={leaf} non_leaf={}",
        writes - leaf
    );
    assert!(
        writes >= 100,
        "the placement invariant must be exercised by real merges, got {writes}"
    );
    assert!(
        misplaced.is_empty(),
        "a merge value was written somewhere other than the last position on its incoming path. \
         That placement is the whole reason relocating the expression cannot read different state \
         than the join would have read: with nothing between the write and the join, no \
         assignment can come between them. A write that is not terminal breaks that argument and \
         the recovered value may differ from what the program computed. Offenders: {misplaced:?}"
    );
}

#[test]
fn a_recovered_merge_computes_what_the_bytecode_computes() {
    let abc: AbcFile = bare_abc();

    for (selector, expected) in [(0u8, 1i64), (1u8, 2i64)] {
        let code: Vec<u8> = vec![
            0x24, selector, 0x11, 0x06, 0x00, 0x00, 0x24, 0x01, 0x10, 0x07, 0x00, 0x00, 0x29, 0x24,
            0x02, 0x10, 0x00, 0x00, 0x00, 0x48,
        ];
        let body: MethodBody = merge_body(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("branch join must lift");
        let produced: common::Value = common::evaluate(&lifted.statements, "branch join", &[]);
        assert_eq!(
            produced,
            common::Value::Int(expected),
            "iftrue on {selector} reaches the arm that pushes {expected}, so the recovered body \
             must compute {expected}. A merge that names an operand without writing it, or that \
             writes the wrong arm's value, is invisible to a control-flow comparison and shows \
             up only here: {:?}",
            lifted.statements
        );
    }

    for (selector, expected) in [(0u8, 10i64), (1u8, 20i64), (2u8, 30i64)] {
        let code: Vec<u8> = vec![
            0x24, selector, 0x1B, 0x17, 0x00, 0x00, 0x01, 0x0B, 0x00, 0x00, 0x11, 0x00, 0x00, 0x24,
            0x0A, 0x10, 0x08, 0x00, 0x00, 0x24, 0x14, 0x10, 0x02, 0x00, 0x00, 0x24, 0x1E, 0x48,
        ];
        let body: MethodBody = merge_body(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("switch join must lift");
        let produced: common::Value = common::evaluate(&lifted.statements, "switch join", &[]);
        assert_eq!(
            produced,
            common::Value::Int(expected),
            "lookupswitch on {selector} reaches the case that pushes {expected}, so the recovered \
             body must compute {expected}: {:?}",
            lifted.statements
        );
    }
}

fn expr_reads_slot(expression: &Expr, slot: u32) -> bool {
    let mut found: bool = false;
    walk_expr(expression, &mut |inner: &Expr| {
        if matches!(inner, Expr::Local(index) | Expr::Param(index) if *index == slot) {
            found = true;
        }
    });
    found
}

fn expr_reads_property(expression: &Expr, property: &str) -> bool {
    let mut found: bool = false;
    walk_expr(expression, &mut |inner: &Expr| match inner {
        Expr::Get { property: name, .. } | Expr::Descendants { property: name, .. }
            if name == property =>
        {
            found = true;
        }
        Expr::Name(name) | Expr::Lex(name) if name == property => found = true,
        _ => {}
    });
    found
}

fn expr_reads_an_element(expression: &Expr) -> bool {
    let mut found: bool = false;
    walk_expr(expression, &mut |inner: &Expr| {
        if matches!(inner, Expr::Index { .. }) {
            found = true;
        }
    });
    found
}

fn walk_expr(expression: &Expr, visit: &mut impl FnMut(&Expr)) {
    visit(expression);
    match expression {
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
        } => walk_expr(operand, visit),
        Expr::Binary { lhs, rhs, .. }
        | Expr::Index {
            object: lhs,
            index: rhs,
        } => {
            walk_expr(lhs, visit);
            walk_expr(rhs, visit);
        }
        Expr::IsType { operand, ty } | Expr::AsType { operand, ty } => {
            walk_expr(operand, visit);
            walk_expr(ty, visit);
        }
        Expr::Ternary {
            cond,
            then_value,
            else_value,
        } => {
            walk_expr(cond, visit);
            walk_expr(then_value, visit);
            walk_expr(else_value, visit);
        }
        Expr::Call { callee, args, .. } | Expr::Construct { callee, args, .. } => {
            walk_expr(callee, visit);
            for argument in args {
                walk_expr(argument, visit);
            }
        }
        Expr::New { ty: base, args } | Expr::Applied { base, args } => {
            walk_expr(base, visit);
            for argument in args {
                walk_expr(argument, visit);
            }
        }
        Expr::Array(items) => {
            for item in items {
                walk_expr(item, visit);
            }
        }
        Expr::Object(pairs) => {
            for (key, value) in pairs {
                walk_expr(key, visit);
                walk_expr(value, visit);
            }
        }
        _ => {}
    }
}

fn clobbers(statement: &Stmt, value: &Expr) -> bool {
    match statement {
        Stmt::Assign {
            target: Expr::Local(slot) | Expr::Param(slot),
            ..
        } => expr_reads_slot(value, *slot),
        Stmt::AssignProperty { property, .. } => expr_reads_property(value, property),
        Stmt::AssignIndex { .. } => expr_reads_an_element(value),
        _ => false,
    }
}

#[test]
fn nothing_between_a_merge_write_and_its_block_head_changes_what_it_reads() {
    let dir: PathBuf = common::as3_corpus_root();
    if !common::require_corpus("as3 merge read window", &dir) {
        return;
    }
    let mut writes: usize = 0;
    let mut with_a_gap: usize = 0;
    let mut effectful_with_a_gap: usize = 0;
    let mut clobbered: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read corpus") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) != Some("swf") {
            continue;
        }
        let label: String = path.file_stem().map_or_else(
            || "?".to_owned(),
            |name: &std::ffi::OsStr| name.to_string_lossy().into_owned(),
        );
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            for (index, body) in abc.method_bodies.iter().enumerate() {
                let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
                let Ok(raw): Result<Vec<Stmt>, _> = lift_body_raw(&abc, body, info) else {
                    continue;
                };
                for (position, statement) in raw.iter().enumerate() {
                    let Stmt::Assign {
                        target: Expr::Name(name),
                        value,
                    } = statement
                    else {
                        continue;
                    };
                    if !is_merge_temporary(name) {
                        continue;
                    }
                    writes += 1;
                    let mut scan: usize = position;
                    let mut gap: usize = 0;
                    while scan > 0 {
                        let previous: &Stmt = &raw[scan - 1];
                        if matches!(
                            previous,
                            Stmt::Label(_)
                                | Stmt::Jump { .. }
                                | Stmt::If { .. }
                                | Stmt::Switch { .. }
                        ) {
                            break;
                        }
                        if !matches!(previous, Stmt::Comment(_))
                            && !matches!(previous, Stmt::Assign { target: Expr::Name(sibling), .. } if is_merge_temporary(sibling))
                        {
                            gap += 1;
                            if clobbers(previous, value) {
                                clobbered.push(format!("{label}#{index}:{name}"));
                            }
                        }
                        scan -= 1;
                    }
                    if gap > 0 {
                        with_a_gap += 1;
                        if !value_is_a_leaf(value) {
                            effectful_with_a_gap += 1;
                        }
                    }
                }
            }
        }
    }
    eprintln!(
        "AS3 merge read window: writes={writes} with_statements_before_them={with_a_gap} of_those_non_leaf={effectful_with_a_gap} clobbered={}",
        clobbered.len()
    );
    assert!(writes >= 100, "the window must be exercised, got {writes}");
    assert!(
        clobbered.is_empty(),
        "a merge value reads state that a statement earlier in its own block assigns, so writing \
         it at the edge evaluates it against state the original push never saw. This is the data \
         hazard a control-flow comparison cannot see. Offenders: {clobbered:?}"
    );
}

#[test]
fn the_gate_reports_a_temporary_that_no_path_writes() {
    let stmts: Vec<Stmt> = vec![
        Stmt::StructuredSwitch {
            selector: Expr::Local(1),
            cases: vec![SwitchCase {
                labels: vec![CaseLabel::Value(0)],
                body: vec![Stmt::Assign {
                    target: Expr::Name("_merge0".to_owned()),
                    value: Expr::IntLit(1),
                }],
                breaks: true,
            }],
        },
        Stmt::Return(Some(Expr::Name("_merge1".to_owned()))),
    ];
    let mut written: BTreeSet<String> = BTreeSet::new();
    let mut read: BTreeSet<String> = BTreeSet::new();
    collect_names(&stmts, &mut written, &mut read);
    assert_eq!(
        written.iter().cloned().collect::<Vec<String>>(),
        vec!["_merge0".to_owned()]
    );
    assert_eq!(
        read.iter().cloned().collect::<Vec<String>>(),
        vec!["_merge1".to_owned()]
    );
    assert_eq!(
        read.difference(&written).cloned().collect::<Vec<String>>(),
        vec!["_merge1".to_owned()],
        "the gate must name a temporary that is read without being written, or it cannot fail \
         on the defect it exists to catch"
    );
}
