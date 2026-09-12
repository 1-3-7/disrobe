#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![allow(clippy::manual_clamp, clippy::comparison_chain)]

mod common;

use common::{Value, evaluate};
use disrobe_pass_as3::abc::{self, AbcFile, ClassInfo, MethodBody, MethodInfo, TraitInfo};
use disrobe_pass_as3::lifter::{
    CatchClause, Expr, LiftedBody, LocalNames, Stmt, lift_body, local_names_for, render_body,
};
use disrobe_pass_as3::swf::{self, DoAbc, Swf, SwfCompression};

const CLASS_NAME: &str = "ControlShapes";
const HAXE_SOURCE: &str = include_str!("../../../corpus/flash/avm2_disasm_oracle/ControlShapes.hx");
const SWF_BYTES: &[u8] =
    include_bytes!("../../../corpus/flash/avm2_disasm_oracle/control_shapes.swf");

const EXPECTED_TERNARIES_SOURCE: &str = "\tstatic function ternaries(a:Int, b:Int):Int {\n\t\tvar pick:Int = a > b ? a : b;\n\t\tvar clamp:Int = pick > 10 ? 10 : (pick < 0 ? 0 : pick);\n\t\treturn pick + clamp + (a == b ? 1 : (a < b ? 2 : 3));\n\t}\n";

const EXPECTED_SHORT_CIRCUIT_SOURCE: &str = "\tstatic function shortCircuit(left:Bool, right:Bool, value:Int):Bool {\n\t\treturn (left && value > 3) || (right && value < 9) || (!left && !right);\n\t}\n";

const EXPECTED_WORDS_SOURCE: &str = "\tstatic function words(token:String):Int {\n\t\treturn switch (token) {\n\t\t\tcase \"alpha\": 1;\n\t\t\tcase \"beta\": 2;\n\t\t\tcase \"gamma\": 3;\n\t\t\tcase \"delta\" | \"epsilon\": 4;\n\t\t\tdefault: 0;\n\t\t};\n\t}\n";

const EXPECTED_WORDS_RECOVERY: &str = "loc2 = String(arg1);\nif ((loc2 == \"alpha\")) {\n    return 1;\n}\nif ((loc2 == \"beta\")) {\n    return 2;\n}\nif (((loc2 == \"delta\") || (loc2 == \"epsilon\"))) {\n    return 4;\n}\nif ((loc2 == \"gamma\")) {\n    return 3;\n}\nreturn 0;\n";

const EXPECTED_TERNARIES_RECOVERY: &str = "loc3 = int(((arg1 > arg2) ? arg1 : arg2));\nloc4 = int(((loc3 > 10) ? 10 : ((loc3 < 0) ? 0 : loc3)));\nreturn ((loc3 + loc4) + ((arg1 == arg2) ? 1 : ((arg1 < arg2) ? 2 : 3)));\n";

const fn reference_ternaries(a: i64, b: i64) -> i64 {
    let pick: i64 = if a > b { a } else { b };
    let clamp: i64 = if pick > 10 {
        10
    } else if pick < 0 {
        0
    } else {
        pick
    };
    pick + clamp
        + if a == b {
            1
        } else if a < b {
            2
        } else {
            3
        }
}

fn reference_words(token: &str) -> i64 {
    match token {
        "alpha" => 1,
        "beta" => 2,
        "gamma" => 3,
        "delta" | "epsilon" => 4,
        _ => 0,
    }
}

const fn reference_short_circuit(left: bool, right: bool, value: i64) -> bool {
    (left && value > 3) || (right && value < 9) || (!left && !right)
}

fn pinned_source() {
    assert_eq!(
        HAXE_SOURCE.len(),
        2602,
        "the reference source changed size; the committed SWF is no longer compiled from it"
    );
    assert!(
        HAXE_SOURCE.contains(EXPECTED_TERNARIES_SOURCE),
        "the reference source no longer declares the pinned nested-conditional method; \
         regenerate the corpus entry and revalidate this grade"
    );
    assert!(
        HAXE_SOURCE.contains(EXPECTED_SHORT_CIRCUIT_SOURCE),
        "the reference source no longer declares the pinned short-circuit method"
    );
    assert!(
        HAXE_SOURCE.contains(EXPECTED_WORDS_SOURCE),
        "the reference source no longer declares the pinned string-dispatch method"
    );
}

fn parse_fixture() -> AbcFile {
    assert_eq!(
        SWF_BYTES.get(..3),
        Some(b"CWS".as_slice()),
        "the committed Haxe fixture must remain zlib-compressed SWF output"
    );
    assert_eq!(
        SWF_BYTES.len(),
        6477,
        "the committed Haxe fixture changed size; regenerate and revalidate this grade"
    );
    let parsed: Swf = swf::parse(SWF_BYTES).expect("the committed Haxe SWF must parse");
    assert_eq!(parsed.header.compression, SwfCompression::Zlib);
    let blocks: Vec<DoAbc> = parsed.collect_do_abc();
    assert_eq!(
        blocks.len(),
        1,
        "the compiler fixture must carry exactly one ABC payload"
    );
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
    assert_eq!(
        class_indices.len(),
        1,
        "the fixture must define exactly one {CLASS_NAME} instance, found {class_indices:?}"
    );
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
    assert_eq!(
        bodies.len(),
        1,
        "{CLASS_NAME}::{method_name} must have exactly one method body"
    );
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

fn conditionals_in_expr(expr: &Expr) -> usize {
    match expr {
        Expr::Ternary {
            cond,
            then_value,
            else_value,
        } => {
            1 + conditionals_in_expr(cond)
                + conditionals_in_expr(then_value)
                + conditionals_in_expr(else_value)
        }
        Expr::Binary { lhs, rhs, .. } => conditionals_in_expr(lhs) + conditionals_in_expr(rhs),
        Expr::Unary { operand, .. } | Expr::Coerce { operand, .. } => conditionals_in_expr(operand),
        _ => 0,
    }
}

fn conditional_expressions_in(stmts: &[Stmt]) -> usize {
    stmts
        .iter()
        .map(|stmt: &Stmt| match stmt {
            Stmt::Assign { value, .. } | Stmt::Return(Some(value)) => conditionals_in_expr(value),
            _ => 0,
        })
        .sum()
}

fn residual_control_flow(stmts: &[Stmt]) -> usize {
    stmts
        .iter()
        .filter(|stmt: &&Stmt| {
            matches!(
                stmt,
                Stmt::Jump { .. } | Stmt::If { .. } | Stmt::Label(_) | Stmt::Comment(_)
            )
        })
        .count()
}

#[test]
fn nested_conditional_merges_recover_every_arm_the_compiler_was_given() {
    pinned_source();
    let declared: usize = EXPECTED_TERNARIES_SOURCE.matches(" ? ").count();
    assert_eq!(
        declared, 5,
        "the pinned reference source must declare five conditional expressions"
    );

    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "ternaries");

    let recovered_conditionals: usize = conditional_expressions_in(&lifted.statements);
    assert_eq!(
        recovered_conditionals, declared,
        "recovered conditional expressions must match the reference source: \
         {recovered_conditionals}/{declared}"
    );
    assert_eq!(
        residual_control_flow(&lifted.statements),
        0,
        "a fully folded conditional chain must leave no branch, jump, label or refusal marker \
         behind, got: {text}"
    );
    assert_eq!(
        text, EXPECTED_TERNARIES_RECOVERY,
        "the recovered body must reproduce the reference source expression by expression"
    );
    assert_eq!(lifted.opaque_operands, 0);
    assert!(lifted.fully_structured);
    assert!(lifted.structurally_recovered);
}

#[test]
fn the_recovered_conditional_chain_computes_what_the_reference_source_computes() {
    pinned_source();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "ternaries");
    let mut agreed: usize = 0;
    let mut graded: usize = 0;
    for a in -3i64..=13 {
        for b in -3i64..=13 {
            graded += 1;
            let observed: Value = evaluate(
                &lifted.statements,
                "ternaries",
                &[(1, Value::Int(a)), (2, Value::Int(b))],
            );
            let expected: i64 = reference_ternaries(a, b);
            assert_eq!(
                observed,
                Value::Int(expected),
                "recovered ternaries({a}, {b}) disagrees with the reference source: {text}"
            );
            agreed += 1;
        }
    }
    assert_eq!(graded, 289);
    assert_eq!(
        agreed, graded,
        "recovered conditional chain agreement: {agreed}/{graded}"
    );
}

#[test]
fn the_recovered_short_circuit_chain_computes_what_the_reference_source_computes() {
    pinned_source();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "shortCircuit");
    let mut agreed: usize = 0;
    let mut graded: usize = 0;
    for left in [false, true] {
        for right in [false, true] {
            for value in -2i64..=12 {
                graded += 1;
                let observed: Value = evaluate(
                    &lifted.statements,
                    "shortCircuit",
                    &[
                        (1, Value::Bool(left)),
                        (2, Value::Bool(right)),
                        (3, Value::Int(value)),
                    ],
                );
                let expected: bool = reference_short_circuit(left, right, value);
                assert_eq!(
                    observed.as_bool(),
                    expected,
                    "recovered shortCircuit({left}, {right}, {value}) disagrees with the \
                     reference source: {text}"
                );
                agreed += 1;
            }
        }
    }
    assert_eq!(graded, 60);
    assert_eq!(
        agreed, graded,
        "recovered short-circuit chain agreement: {agreed}/{graded}"
    );
}

#[test]
fn a_shared_target_string_dispatch_group_recovers_as_one_guarded_case() {
    pinned_source();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "words");
    assert_eq!(
        residual_control_flow(&lifted.statements),
        0,
        "a dispatch chain whose cases share a body must leave no goto behind, got: {text}"
    );
    assert_eq!(
        text, EXPECTED_WORDS_RECOVERY,
        "the recovered dispatch must keep the compiler's test order and group the shared case"
    );
    assert!(lifted.fully_structured);
    assert!(lifted.structurally_recovered);
    assert_eq!(lifted.opaque_operands, 0);
}

#[test]
fn the_recovered_string_dispatch_computes_what_the_reference_source_computes() {
    pinned_source();
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "words");
    let mut agreed: usize = 0;
    let mut graded: usize = 0;
    for token in [
        "alpha",
        "beta",
        "gamma",
        "delta",
        "epsilon",
        "zeta",
        "",
        "Alpha",
        "alpha ",
        "deltaepsilon",
    ] {
        graded += 1;
        let observed: Value = evaluate(
            &lifted.statements,
            "words",
            &[(1, Value::Str(token.to_owned()))],
        );
        assert_eq!(
            observed,
            Value::Int(reference_words(token)),
            "recovered words({token:?}) disagrees with the reference source: {text}"
        );
        agreed += 1;
    }
    assert_eq!(graded, 10);
    assert_eq!(
        agreed, graded,
        "recovered string dispatch agreement: {agreed}/{graded}"
    );
}

const AUTHORED_METHODS: [&str; 8] = [
    "labelled",
    "words",
    "guarded",
    "recurse",
    "ternaries",
    "shortCircuit",
    "tables",
    "enums",
];
const FULLY_STRUCTURED_FLOOR: usize = 8;

fn squeeze(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut pending_space: bool = false;
    for character in text.chars() {
        if character.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(character);
    }
    out
}

fn renders_an_empty_operand(text: &str) -> bool {
    text.lines()
        .any(|line: &str| line.trim_end().ends_with("= ;"))
}

#[test]
fn no_recovered_method_leaves_an_operand_without_a_spelling() {
    let abc: AbcFile = parse_fixture();
    let offenders: Vec<&str> = AUTHORED_METHODS
        .into_iter()
        .filter(|method_name: &&str| {
            let (_, text): (LiftedBody, String) = recovered(&abc, method_name);
            renders_an_empty_operand(&text)
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "an AVM2 value with no ActionScript spelling must reach the output as a named operand, \
         never as nothing: {offenders:?}"
    );
}

#[test]
fn the_activation_scope_reconciles_across_the_handler_merge() {
    assert!(
        HAXE_SOURCE.contains("} catch (fault:CustomFault) {"),
        "the authored program must still be the layered try and catch this grade reads"
    );
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "guarded");
    assert!(
        text.contains("$activation"),
        "the activation object this NEED_ACTIVATION method allocates must reach the output as a \
         named operand: {text}"
    );
    assert!(
        !text.contains("unreconciled scope"),
        "the try path allocates the activation and the handler re-pushes it from its local, so \
         the scope stack must reconcile at the merge instead of refusing: {text}"
    );
    assert_eq!(
        lifted.opaque_operands, 0,
        "reconciling that merge must leave no seeded operand behind: {text}"
    );
}

#[test]
fn the_authored_control_shapes_hold_their_measured_structuring_floor() {
    let abc: AbcFile = parse_fixture();
    let unstructured: Vec<&str> = AUTHORED_METHODS
        .into_iter()
        .filter(|method_name: &&str| {
            let (lifted, _): (LiftedBody, String) = recovered(&abc, method_name);
            residual_control_flow(&lifted.statements) > 0 || !lifted.structurally_recovered
        })
        .collect();
    let structured: usize = AUTHORED_METHODS.len() - unstructured.len();
    assert!(
        structured >= FULLY_STRUCTURED_FLOOR,
        "recovery of the authored control shapes must hold its measured floor of \
         {FULLY_STRUCTURED_FLOOR}/{}; got {structured}/{}, with residual control flow left in \
         {unstructured:?}",
        AUTHORED_METHODS.len(),
        AUTHORED_METHODS.len()
    );
}

const EXPECTED_LABELLED_SOURCE: &str =
    "\t\t\t\tif (row * column > 12) {\n\t\t\t\t\tstopped = true;\n\t\t\t\t\tbreak;\n\t\t\t\t}\n";

#[test]
fn the_inner_loop_exit_recovers_as_the_break_the_compiler_was_given() {
    assert!(
        HAXE_SOURCE.contains(EXPECTED_LABELLED_SOURCE),
        "the authored program must still end its inner loop with a break, which is what this \
         grade reads"
    );
    let abc: AbcFile = parse_fixture();
    let (_, text): (LiftedBody, String) = recovered(&abc, "labelled");
    let squeezed: String = squeeze(&text);
    assert!(
        squeezed.contains("= Boolean(true); break;"),
        "the authored source sets its flag and then BREAKS the inner loop; recovering that jump \
         as a continue would rebind it to the inner loop head and change what the program does: \
         {text}"
    );
    assert!(
        squeezed.contains("== 2)) { continue;"),
        "the authored continue must stay a continue, so this grade cannot pass by turning every \
         loop exit into a break: {text}"
    );
}

const EXPECTED_GUARDED_SOURCE: &str = "\t\ttry {\n\t\t\tif (value < 0)\n\t\t\t\tthrow new CustomFault(\"negative\");\n\t\t\tif (value == 0)\n\t\t\t\tthrow \"zero\";\n\t\t\toutcome = \"positive\";\n\t\t}";

#[test]
fn the_guarded_region_recovers_without_a_residual_branch_graph() {
    assert!(
        HAXE_SOURCE.contains(EXPECTED_GUARDED_SOURCE),
        "the authored program must still guard two throws inside a try, which is what this grade \
         reads"
    );
    let abc: AbcFile = parse_fixture();
    let (lifted, text): (LiftedBody, String) = recovered(&abc, "guarded");
    assert_eq!(
        residual_control_flow(&lifted.statements),
        0,
        "the authored try and its handler chain are ordinary structured control flow, so neither \
         region may keep a goto or a bare label: {text}"
    );
    assert!(
        lifted.structurally_recovered,
        "with both regions structured the body must report structural recovery: {text}"
    );
    let squeezed: String = squeeze(&text);
    assert!(
        squeezed.contains("try {") && squeezed.contains("catch"),
        "the recovered shape must still be a try with a handler: {text}"
    );
}

fn only_try(stmts: &[Stmt]) -> &Stmt {
    fn find<'a>(stmts: &'a [Stmt], out: &mut Vec<&'a Stmt>) {
        for stmt in stmts {
            match stmt {
                Stmt::Try { body, catches } => {
                    out.push(stmt);
                    find(body, out);
                    for clause in catches {
                        find(&clause.body, out);
                    }
                }
                Stmt::IfBlock { body, .. } | Stmt::With { body, .. } => find(body, out),
                Stmt::IfElse {
                    then_body,
                    else_body,
                    ..
                } => {
                    find(then_body, out);
                    find(else_body, out);
                }
                _ => {}
            }
        }
    }
    let mut found: Vec<&Stmt> = Vec::new();
    find(stmts, &mut found);
    assert_eq!(
        found.len(),
        1,
        "this grade reads the one guarded region in the authored program: {stmts:#?}"
    );
    found[0]
}

#[test]
fn a_haxe_handler_keeps_the_any_type_the_compiler_actually_emitted() {
    assert!(
        HAXE_SOURCE.contains("} catch (fault:CustomFault) {")
            && HAXE_SOURCE.contains("} catch (text:String) {")
            && HAXE_SOURCE.contains("} catch (rest:Dynamic) {"),
        "the authored program must still declare three typed catch clauses, because the point of \
         this grade is that the compiler did not encode them as three typed handlers"
    );
    let abc: AbcFile = parse_fixture();
    let (body, _): (&MethodBody, &MethodInfo) = static_method(&abc, "guarded");
    assert_eq!(
        body.exceptions.len(),
        1,
        "three authored catch clauses compiled to ONE handler; the type dispatch lives in code, \
         not in the exception table"
    );
    assert_eq!(
        body.exceptions[0].exc_type, 0,
        "that single handler is untyped in the ABC, so `*` is the accurate rendering of what the \
         compiler emitted and not a degraded fallback"
    );

    let (lifted, text): (LiftedBody, String) = recovered(&abc, "guarded");
    let Stmt::Try { catches, .. } = only_try(&lifted.statements) else {
        panic!("the guarded region must recover as a try: {text}");
    };
    let types: Vec<&str> = catches
        .iter()
        .map(|clause: &CatchClause| clause.type_name.as_str())
        .collect();
    assert_eq!(
        types,
        vec!["*"],
        "the recovery must report the one untyped handler the machine has. Inventing \
         `catch (fault:CustomFault)` here would be wrong: the try throws \
         haxe.Exception.thrown(...), so the value the machine catches is the wrapper, while the \
         authored type names describe the payload: {text}"
    );

    let squeezed: String = squeeze(&text);
    let unwrap_at: usize = squeezed
        .find(".unwrap()")
        .unwrap_or_else(|| panic!("the handler must recover its payload unwrap: {text}"));
    let first_type_test: usize = squeezed
        .find(" is ")
        .unwrap_or_else(|| panic!("the handler must recover its type tests: {text}"));
    assert!(
        unwrap_at < first_type_test,
        "the handler unwraps the payload BEFORE it tests any type, which is why those tests \
         cannot be lifted into typed catch clauses: an AS3 catch type tests the thrown value, \
         not the unwrapped one: {text}"
    );
}
