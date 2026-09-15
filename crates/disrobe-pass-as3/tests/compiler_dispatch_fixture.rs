#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use common::{Value, evaluate};
use disrobe_pass_as3::abc::{self, AbcFile, ClassInfo, MethodBody, MethodInfo, TraitInfo};
use disrobe_pass_as3::lifter::{
    CaseLabel, LiftedBody, LocalNames, Stmt, SwitchCase, lift_body, local_names_for, render_body,
};
use disrobe_pass_as3::swf::{self, DoAbc, Swf, SwfCompression};

const CLASS_NAME: &str = "DispatchShapes";
const HAXE_SOURCE: &str = include_str!("fixtures/DispatchShapes.hx");
const PROBE_SOURCE: &str = include_str!("fixtures/DispatchShapesProbe.hx");
const PROVENANCE: &str = include_str!("fixtures/dispatch_shapes.provenance");
const EXPECTED_OUTPUT: &str = include_str!("fixtures/dispatch_shapes.expected");
const SWF_BYTES: &[u8] = include_bytes!("fixtures/dispatch_shapes.swf");

const EXPECTED_PROVENANCE: &str = "compiler=haxe 4.3.7\ncommand=haxe -cp crates/disrobe-pass-as3/tests/fixtures -main DispatchShapes -swf crates/disrobe-pass-as3/tests/fixtures/dispatch_shapes.swf\nexpected=haxe -cp crates/disrobe-pass-as3/tests/fixtures -main DispatchShapesProbe --interp\ngenerated=2026-08-19\n";

const EXPECTED_SPARSE_SOURCE: &str = "\tpublic static function sparse(selector:Int):Int {\n\t\treturn switch (selector) {\n\t\t\tcase 7: 70;\n\t\t\tcase 9: 90;\n\t\t\tdefault: 0;\n\t\t};\n\t}\n";

const EXPECTED_UNORDERED_SOURCE: &str = "\tpublic static function unordered(selector:Int):Int {\n\t\treturn switch (selector) {\n\t\t\tcase 5: 500;\n\t\t\tcase 1: 100;\n\t\t\tcase 3: 300;\n\t\t\tdefault: 0;\n\t\t};\n\t}\n";

const EXPECTED_SPARSE_RECOVERY: &str = "switch (arg1) {\n    default:\n        return 0;\n    case 7:\n        return 70;\n    case 9:\n        return 90;\n}\n";

fn pinned_sources() {
    assert_eq!(
        PROVENANCE, EXPECTED_PROVENANCE,
        "the compiler provenance changed; regenerate and revalidate this grade"
    );
    assert!(
        HAXE_SOURCE.contains(EXPECTED_SPARSE_SOURCE),
        "the reference source no longer declares the pinned sparse dispatch"
    );
    assert!(
        HAXE_SOURCE.contains(EXPECTED_UNORDERED_SOURCE),
        "the reference source no longer declares the pinned out-of-order dispatch"
    );
    assert!(
        PROBE_SOURCE.contains("DispatchShapes.sparse(index)"),
        "the probe that produced the expected output no longer exercises the pinned dispatch"
    );
}

fn parse_fixture() -> AbcFile {
    assert_eq!(
        SWF_BYTES.get(..3),
        Some(b"CWS".as_slice()),
        "the committed Haxe fixture must remain zlib-compressed SWF output"
    );
    let parsed: Swf = swf::parse(SWF_BYTES).expect("the committed Haxe SWF must parse");
    assert_eq!(parsed.header.compression, SwfCompression::Zlib);
    let blocks: Vec<DoAbc> = parsed.collect_do_abc();
    assert_eq!(blocks.len(), 1);
    abc::parse(&blocks[0].abc_bytes).expect("the committed Haxe ABC must parse")
}

fn static_method<'a>(abc: &'a AbcFile, method_name: &str) -> (&'a MethodBody, &'a MethodInfo) {
    let class_indices: Vec<usize> = abc
        .instances
        .iter()
        .enumerate()
        .filter_map(|(index, instance)| {
            let name: String = abc
                .cpool
                .render_multiname(instance.name_index)
                .expect("the fixture instance name must render");
            (name == CLASS_NAME).then_some(index)
        })
        .collect();
    assert_eq!(class_indices.len(), 1);
    let class: &ClassInfo = abc
        .classes
        .get(class_indices[0])
        .expect("the pinned class must have static traits");
    let methods: Vec<&TraitInfo> = class
        .traits
        .iter()
        .filter(|trait_info| trait_info.kind & 0x0F == 1)
        .filter(|trait_info| {
            let name: String = abc
                .cpool
                .render_multiname_property(trait_info.name_index)
                .expect("the fixture static method name must render");
            name == method_name
        })
        .collect();
    assert_eq!(
        methods.len(),
        1,
        "the fixture must expose exactly one {CLASS_NAME}::{method_name} static method"
    );
    let bodies: Vec<&MethodBody> = abc
        .method_bodies
        .iter()
        .filter(|body| body.method == methods[0].method_index)
        .collect();
    assert_eq!(bodies.len(), 1);
    let info: &MethodInfo = abc
        .methods
        .get(methods[0].method_index as usize)
        .expect("the pinned method must have method info");
    (bodies[0], info)
}

fn recovered(abc: &AbcFile, method_name: &str) -> (LiftedBody, String) {
    let (body, info): (&MethodBody, &MethodInfo) = static_method(abc, method_name);
    let lifted: LiftedBody =
        lift_body(abc, body, Some(info)).expect("the pinned method body must lift");
    let names: LocalNames = local_names_for(abc, Some(info));
    let text: String = render_body(&lifted, &names, "");
    (lifted, text)
}

fn argument_of(method: &str, raw: &str) -> Vec<(u32, Value)> {
    match method {
        "shared" => vec![(1, Value::Str(raw.to_owned()))],
        _ => vec![(
            1,
            Value::Int(raw.parse::<i64>().expect("numeric probe argument")),
        )],
    }
}

fn switch_cases(stmts: &[Stmt]) -> Vec<SwitchCase> {
    stmts
        .iter()
        .find_map(|stmt: &Stmt| match stmt {
            Stmt::StructuredSwitch { cases, .. } => Some(cases.clone()),
            _ => None,
        })
        .expect("the recovered body must carry a structured switch")
}

#[test]
fn the_recovered_dispatch_computes_what_the_authored_program_prints() {
    pinned_sources();
    let abc: AbcFile = parse_fixture();
    let mut agreed: usize = 0;
    let mut graded: usize = 0;
    for line in EXPECTED_OUTPUT.lines() {
        let line: &str = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(' ').collect();
        let (method, expected): (&str, i64) = match parts.as_slice() {
            [method, _, expected] | [method, _, _, expected] => (
                *method,
                expected.parse::<i64>().expect("numeric expected value"),
            ),
            _ => panic!("unparsable expected-output line: {line}"),
        };
        if method == "coalesce" {
            continue;
        }
        graded += 1;
        let (lifted, text): (LiftedBody, String) = recovered(&abc, method);
        let observed: Value = evaluate(&lifted.statements, method, &argument_of(method, parts[1]));
        assert_eq!(
            observed,
            Value::Int(expected),
            "recovered {method}({}) disagrees with what the authored program printed: {text}",
            parts[1]
        );
        agreed += 1;
    }
    assert_eq!(
        graded, 56,
        "the committed expected output must keep grading every probed dispatch input"
    );
    assert_eq!(
        agreed, graded,
        "recovered dispatch agreement against the authored program: {agreed}/{graded}"
    );
}

#[test]
fn the_recovered_null_coalescing_merge_computes_what_the_authored_program_prints() {
    pinned_sources();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "coalesce");
    let mut agreed: usize = 0;
    let mut graded: usize = 0;
    for line in EXPECTED_OUTPUT.lines() {
        let parts: Vec<&str> = line.trim_end_matches('\r').split(' ').collect();
        let ["coalesce", value, fallback, expected] = parts.as_slice() else {
            continue;
        };
        graded += 1;
        let first: Value = if *value == "null" {
            Value::Null
        } else {
            Value::Int(value.parse::<i64>().expect("numeric probe argument"))
        };
        let observed: Value = evaluate(
            &lifted.statements,
            "coalesce",
            &[
                (1, first),
                (
                    2,
                    Value::Int(fallback.parse::<i64>().expect("numeric probe argument")),
                ),
            ],
        );
        assert_eq!(
            observed,
            Value::Int(expected.parse::<i64>().expect("numeric expected value")),
            "recovered coalesce({value}, {fallback}) disagrees with the authored program: {text}"
        );
        agreed += 1;
    }
    assert_eq!(graded, 3);
    assert_eq!(
        agreed, graded,
        "recovered null-coalescing agreement: {agreed}/{graded}"
    );
    assert!(lifted.structurally_recovered);
}

#[test]
fn a_dispatch_table_entry_that_lands_on_the_default_never_becomes_a_case_label() {
    pinned_sources();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "sparse");
    let cases: Vec<SwitchCase> = switch_cases(&lifted.statements);
    let labels: Vec<Vec<CaseLabel>> = cases
        .iter()
        .map(|case: &SwitchCase| case.labels.clone())
        .collect();
    assert_eq!(
        labels,
        vec![
            vec![CaseLabel::Default],
            vec![CaseLabel::Value(7)],
            vec![CaseLabel::Value(9)],
        ],
        "the authored source declares two cases and a default; the recovered switch must not \
         invent a case label for every dispatch-table slot that lands on the default: {text}"
    );
    assert_eq!(text, EXPECTED_SPARSE_RECOVERY);
    assert!(lifted.structurally_recovered);
}

#[test]
fn recovered_case_order_follows_the_bytecode_layout_not_the_case_values() {
    pinned_sources();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "unordered");
    let cases: Vec<SwitchCase> = switch_cases(&lifted.statements);
    let labels: Vec<Vec<CaseLabel>> = cases
        .iter()
        .map(|case: &SwitchCase| case.labels.clone())
        .collect();
    assert_eq!(
        labels,
        vec![
            vec![CaseLabel::Default],
            vec![CaseLabel::Value(1)],
            vec![CaseLabel::Value(3)],
            vec![CaseLabel::Value(5)],
        ],
        "the recovered case order must follow the order the compiler laid the bodies out: {text}"
    );
    let bodies: Vec<String> = cases
        .iter()
        .map(|case: &SwitchCase| format!("{:?}", case.body))
        .collect();
    assert!(
        bodies[0].contains("IntLit(0)")
            && bodies[1].contains("IntLit(100)")
            && bodies[2].contains("IntLit(300)")
            && bodies[3].contains("IntLit(500)"),
        "each recovered case must keep the statements the compiler placed under it: {text}"
    );
}

#[test]
fn a_dispatch_nested_in_a_loop_keeps_its_break_edges() {
    pinned_sources();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "inLoop");
    let loops: usize = lifted
        .statements
        .iter()
        .filter(|stmt: &&Stmt| matches!(stmt, Stmt::While { .. }))
        .count();
    assert_eq!(loops, 1, "the recovered body must keep one loop: {text}");
    let Some(Stmt::While { body, .. }): Option<&Stmt> = lifted
        .statements
        .iter()
        .find(|stmt: &&Stmt| matches!(stmt, Stmt::While { .. }))
    else {
        panic!("the recovered body must keep its loop");
    };
    let cases: Vec<SwitchCase> = switch_cases(body);
    assert_eq!(
        cases.len(),
        3,
        "the switch inside the loop must keep its two cases and a default: {text}"
    );
    assert!(
        cases[0].breaks && cases[1].breaks,
        "each non-final arm must keep the break the compiler emitted: {text}"
    );
    assert!(lifted.structurally_recovered);
}
