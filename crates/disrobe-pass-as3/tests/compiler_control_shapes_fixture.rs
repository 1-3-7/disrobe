#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![allow(clippy::manual_clamp, clippy::comparison_chain)]

use std::collections::BTreeMap;

use disrobe_pass_as3::abc::{self, AbcFile, ClassInfo, MethodBody, MethodInfo, TraitInfo};
use disrobe_pass_as3::lifter::{
    Expr, LiftedBody, LocalNames, Stmt, lift_body, local_names_for, render_body,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Int(i64),
    Bool(bool),
    Str(String),
}

impl Value {
    fn as_int(&self) -> i64 {
        match self {
            Self::Int(value) => *value,
            Self::Bool(true) => 1,
            Self::Bool(false) => 0,
            Self::Str(value) => panic!("a recovered body used string {value:?} as a number"),
        }
    }

    const fn as_bool(&self) -> bool {
        match self {
            Self::Int(value) => *value != 0,
            Self::Bool(value) => *value,
            Self::Str(value) => !value.is_empty(),
        }
    }

    fn equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Str(left), Self::Str(right)) => left == right,
            (Self::Str(_), _) | (_, Self::Str(_)) => {
                panic!("a recovered body compared a string against a non-string")
            }
            _ => self.as_int() == other.as_int(),
        }
    }
}

enum Flow {
    Fell,
    Returned(Value),
}

struct Machine {
    slots: BTreeMap<u32, Value>,
    steps: usize,
}

impl Machine {
    fn new(arguments: &[(u32, Value)]) -> Self {
        Self {
            slots: arguments.iter().cloned().collect(),
            steps: 0,
        }
    }

    fn charge(&mut self, method: &str) {
        const MAX_STEPS: usize = 4096;
        self.steps += 1;
        assert!(
            self.steps <= MAX_STEPS,
            "evaluating the recovered {method} body exceeded {MAX_STEPS} steps"
        );
    }

    fn slot(&self, index: u32, method: &str) -> Value {
        self.slots
            .get(&index)
            .unwrap_or_else(|| {
                panic!("the recovered {method} body reads slot {index} before assigning it")
            })
            .clone()
    }

    fn eval(&mut self, expr: &Expr, method: &str) -> Value {
        self.charge(method);
        match expr {
            Expr::IntLit(value) => Value::Int(*value),
            Expr::BoolLit(value) => Value::Bool(*value),
            Expr::StringLit(value) => Value::Str(value.clone()),
            Expr::Local(index) | Expr::Param(index) => self.slot(*index, method),
            Expr::Coerce { ty, operand } => {
                let inner: Value = self.eval(operand, method);
                match ty.as_str() {
                    "int" => Value::Int(inner.as_int()),
                    "Boolean" => Value::Bool(inner.as_bool()),
                    "String" => inner,
                    other => {
                        panic!("the recovered {method} body coerces to unmodelled type {other}")
                    }
                }
            }
            Expr::Unary { op, operand } => {
                let inner: Value = self.eval(operand, method);
                match *op {
                    "!" => Value::Bool(!inner.as_bool()),
                    "-" => Value::Int(-inner.as_int()),
                    other => panic!("the recovered {method} body uses unmodelled unary {other}"),
                }
            }
            Expr::Ternary {
                cond,
                then_value,
                else_value,
            } => {
                if self.eval(cond, method).as_bool() {
                    self.eval(then_value, method)
                } else {
                    self.eval(else_value, method)
                }
            }
            Expr::Binary { op, lhs, rhs } => self.eval_binary(op, lhs, rhs, method),
            other => panic!("the recovered {method} body uses unmodelled expression {other:?}"),
        }
    }

    fn eval_binary(&mut self, op: &str, lhs: &Expr, rhs: &Expr, method: &str) -> Value {
        if op == "&&" {
            let left: Value = self.eval(lhs, method);
            return if left.as_bool() {
                self.eval(rhs, method)
            } else {
                left
            };
        }
        if op == "||" {
            let left: Value = self.eval(lhs, method);
            return if left.as_bool() {
                left
            } else {
                self.eval(rhs, method)
            };
        }
        let left: Value = self.eval(lhs, method);
        let right: Value = self.eval(rhs, method);
        match op {
            "+" => Value::Int(left.as_int() + right.as_int()),
            "-" => Value::Int(left.as_int() - right.as_int()),
            "*" => Value::Int(left.as_int() * right.as_int()),
            ">" => Value::Bool(left.as_int() > right.as_int()),
            "<" => Value::Bool(left.as_int() < right.as_int()),
            ">=" => Value::Bool(left.as_int() >= right.as_int()),
            "<=" => Value::Bool(left.as_int() <= right.as_int()),
            "==" | "===" => Value::Bool(left.equals(&right)),
            "!=" | "!==" => Value::Bool(!left.equals(&right)),
            other => panic!("the recovered {method} body uses unmodelled operator {other}"),
        }
    }

    fn run(&mut self, stmts: &[Stmt], method: &str) -> Flow {
        for stmt in stmts {
            self.charge(method);
            match stmt {
                Stmt::Assign {
                    target: Expr::Local(index) | Expr::Param(index),
                    value,
                } => {
                    let evaluated: Value = self.eval(value, method);
                    self.slots.insert(*index, evaluated);
                }
                Stmt::Return(Some(value)) => {
                    let evaluated: Value = self.eval(value, method);
                    return Flow::Returned(evaluated);
                }
                Stmt::IfBlock { cond, body } => {
                    if self.eval(cond, method).as_bool()
                        && let Flow::Returned(value) = self.run(body, method)
                    {
                        return Flow::Returned(value);
                    }
                }
                Stmt::IfElse {
                    cond,
                    then_body,
                    else_body,
                } => {
                    let taken: &Vec<Stmt> = if self.eval(cond, method).as_bool() {
                        then_body
                    } else {
                        else_body
                    };
                    if let Flow::Returned(value) = self.run(taken, method) {
                        return Flow::Returned(value);
                    }
                }
                other => panic!("the recovered {method} body uses unmodelled statement {other:?}"),
            }
        }
        Flow::Fell
    }
}

fn evaluate(stmts: &[Stmt], method: &str, arguments: &[(u32, Value)]) -> Value {
    let mut machine: Machine = Machine::new(arguments);
    match machine.run(stmts, method) {
        Flow::Returned(value) => value,
        Flow::Fell => panic!("the recovered {method} body fell off the end without returning"),
    }
}

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
