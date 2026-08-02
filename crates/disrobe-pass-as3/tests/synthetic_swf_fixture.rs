#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_as3::abc::{
    self, ABC_MAJOR, ABC_MINOR, AbcFile, DisasmLine, MethodBody, MethodInfo, disasm,
};
use disrobe_pass_as3::lifter::{Expr, LiftedBody, Stmt, lift_body};
use disrobe_pass_as3::swf::{self, DoAbc, Swf, SwfCompression};

#[derive(Debug, Clone, Copy)]
enum RecoveryShape {
    Constructor,
    SumTo,
}

#[derive(Debug, Clone, Copy)]
struct RecoveryMember {
    fixture: &'static str,
    compression: SwfCompression,
    method: u32,
    label: &'static str,
    shape: RecoveryShape,
}

const RECOVERY_MEMBERS: [RecoveryMember; 4] = [
    RecoveryMember {
        fixture: "synthetic_counter_fws.swf",
        compression: SwfCompression::None,
        method: 0,
        label: "Counter::constructor",
        shape: RecoveryShape::Constructor,
    },
    RecoveryMember {
        fixture: "synthetic_counter_fws.swf",
        compression: SwfCompression::None,
        method: 1,
        label: "Counter::sumTo",
        shape: RecoveryShape::SumTo,
    },
    RecoveryMember {
        fixture: "synthetic_counter_cws.swf",
        compression: SwfCompression::Zlib,
        method: 0,
        label: "Counter::constructor",
        shape: RecoveryShape::Constructor,
    },
    RecoveryMember {
        fixture: "synthetic_counter_cws.swf",
        compression: SwfCompression::Zlib,
        method: 1,
        label: "Counter::sumTo",
        shape: RecoveryShape::SumTo,
    },
];

fn fixture_dir() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
        .join("synthetic")
}

fn load(name: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "committed synthetic fixture {} must exist: {error}",
            path.display()
        )
    })
}

fn load_abc(name: &str, expected_compression: SwfCompression) -> AbcFile {
    let bytes: Vec<u8> = load(name);
    let swf: Swf = swf::parse(&bytes).expect("committed synthetic SWF must parse");
    assert_eq!(swf.header.compression, expected_compression);
    assert_eq!(swf.header.version, 13, "fixture pins SWF version 13");

    let attrs: disrobe_pass_as3::swf::FileAttributes = swf
        .file_attributes()
        .expect("FileAttributes tag must parse");
    assert!(
        attrs.action_script3,
        "FileAttributes must flag the SWF as ActionScript 3"
    );

    let symbols: Vec<disrobe_pass_as3::swf::SymbolClassEntry> = swf.symbol_classes();
    assert_eq!(
        symbols
            .iter()
            .map(|symbol: &disrobe_pass_as3::swf::SymbolClassEntry| symbol.class_name.as_str())
            .collect::<Vec<&str>>(),
        vec!["Counter"],
        "SymbolClass must bind exactly the Counter class"
    );

    let blobs: Vec<DoAbc> = swf.collect_do_abc();
    assert_eq!(blobs.len(), 1, "exactly one DoABC tag");
    let blob: &DoAbc = &blobs[0];
    assert_eq!(blob.name, "CounterScript");

    let abc: AbcFile = abc::parse(&blob.abc_bytes).expect("DoABC payload must parse as ABC");
    assert_eq!(abc.minor, ABC_MINOR);
    assert_eq!(abc.major, ABC_MAJOR);
    assert_eq!(abc.class_names(), vec!["Counter"]);
    abc
}

fn method_body(abc: &AbcFile, method: u32) -> &MethodBody {
    abc.method_bodies
        .iter()
        .find(|body: &&MethodBody| body.method == method)
        .expect("fixture must contain the pinned method body")
}

fn member_label(abc: &AbcFile, body: &MethodBody) -> String {
    if body.method == 0 {
        return "Counter::constructor".to_owned();
    }
    let info: &MethodInfo = abc
        .methods
        .get(body.method as usize)
        .expect("method body must have method metadata");
    let name: String = abc
        .cpool
        .render_multiname(info.name_index)
        .expect("pinned method name must render");
    format!("Counter::{name}")
}

fn lift(abc: &AbcFile, body: &MethodBody) -> LiftedBody {
    let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
    lift_body(abc, body, info).expect("pinned method body must lift")
}

fn expected_statements(shape: RecoveryShape) -> Vec<Stmt> {
    match shape {
        RecoveryShape::Constructor => vec![Stmt::Return(None)],
        RecoveryShape::SumTo => vec![
            Stmt::For {
                init: Box::new(Stmt::Assign {
                    target: Expr::Local(2),
                    value: Expr::IntLit(0),
                }),
                cond: Expr::Binary {
                    op: "<",
                    lhs: Box::new(Expr::Local(2)),
                    rhs: Box::new(Expr::Local(1)),
                },
                update: Box::new(Stmt::Assign {
                    target: Expr::Local(2),
                    value: Expr::Binary {
                        op: "+",
                        lhs: Box::new(Expr::Local(2)),
                        rhs: Box::new(Expr::IntLit(1)),
                    },
                }),
                body: vec![Stmt::AssignProperty {
                    object: Expr::This,
                    property: "total".to_owned(),
                    value: Expr::Local(2),
                }],
            },
            Stmt::Return(Some(Expr::Get {
                object: Box::new(Expr::This),
                property: "total".to_owned(),
            })),
        ],
    }
}

fn check_recovery(lifted: &LiftedBody, expected: &[Stmt]) -> Result<(), String> {
    if !lifted.structurally_recovered {
        return Err(format!(
            "structural recovery was partial: {:?}",
            lifted.fidelity_warning()
        ));
    }
    if !lifted.fully_structured {
        return Err("recovery retained raw control flow".to_owned());
    }
    if !lifted.reached_terminator {
        return Err("recovery did not reach a terminator".to_owned());
    }
    if !lifted.dropped_opcodes.is_empty() {
        return Err(format!(
            "recovery dropped opcodes: {:?}",
            lifted.dropped_opcodes
        ));
    }
    if lifted.opaque_operands != 0 {
        return Err(format!(
            "recovery fabricated {} operand(s)",
            lifted.opaque_operands
        ));
    }
    if lifted.statements != expected {
        return Err(format!(
            "statement mismatch\nexpected: {expected:#?}\nactual: {:#?}",
            lifted.statements
        ));
    }
    Ok(())
}

fn expected_member_labels() -> BTreeSet<String> {
    RECOVERY_MEMBERS
        .iter()
        .map(|member: &RecoveryMember| format!("{}::{}", member.fixture, member.label))
        .collect()
}

#[test]
fn committed_swf_recovery_matches_the_pinned_member_contract() {
    let fixtures: [&str; 2] = ["synthetic_counter_fws.swf", "synthetic_counter_cws.swf"];
    let mut recovered: BTreeSet<String> = BTreeSet::new();

    for fixture in fixtures {
        let members: Vec<&RecoveryMember> = RECOVERY_MEMBERS
            .iter()
            .filter(|member: &&RecoveryMember| member.fixture == fixture)
            .collect();
        let compression: SwfCompression = members
            .first()
            .expect("every fixture must have pinned members")
            .compression;
        assert!(
            members
                .iter()
                .all(|member: &&RecoveryMember| member.compression == compression),
            "each fixture must have one compression mode"
        );

        let abc: AbcFile = load_abc(fixture, compression);
        assert_eq!(
            abc.method_bodies.len(),
            members.len(),
            "every fixture method body must have a pinned membership entry"
        );

        for body in &abc.method_bodies {
            let lifted: LiftedBody = lift(&abc, body);
            if lifted.structurally_recovered {
                recovered.insert(format!("{fixture}::{}", member_label(&abc, body)));
            }
        }

        for member in members {
            let body: &MethodBody = method_body(&abc, member.method);
            assert_eq!(member_label(&abc, body), member.label);
            let expected: Vec<Stmt> = expected_statements(member.shape);
            let lifted: LiftedBody = lift(&abc, body);
            let result: Result<(), String> = check_recovery(&lifted, &expected);
            assert!(result.is_ok(), "{}: {}", member.label, result.unwrap_err());
        }
    }

    let expected: BTreeSet<String> = expected_member_labels();
    assert_eq!(recovered, expected, "recovered membership changed");
}

#[test]
fn recovery_grader_rejects_a_corrupted_expected_sum_to_body() {
    let member: &RecoveryMember = RECOVERY_MEMBERS
        .iter()
        .find(|member: &&RecoveryMember| member.label == "Counter::sumTo")
        .expect("sumTo membership entry must exist");
    let abc: AbcFile = load_abc(member.fixture, member.compression);
    let body: &MethodBody = method_body(&abc, member.method);
    let lifted: LiftedBody = lift(&abc, body);
    let mut corrupted: Vec<Stmt> = expected_statements(member.shape);
    let removed: Option<Stmt> = corrupted.pop();
    assert!(matches!(removed, Some(Stmt::Return(_))));

    let result: Result<(), String> = check_recovery(&lifted, &corrupted);
    let error: String = result.expect_err("corrupted expected output must be rejected");
    assert!(
        error.contains("statement mismatch"),
        "the grader must report the mismatched recovery, got: {error}"
    );
}

#[test]
fn synthetic_swf_disassembles_to_a_real_opcode_stream() {
    let bytes: Vec<u8> = load("synthetic_counter_fws.swf");
    let swf: Swf = swf::parse(&bytes).expect("parse");
    let blobs: Vec<DoAbc> = swf.collect_do_abc();
    let abc: AbcFile = abc::parse(&blobs[0].abc_bytes).expect("abc");
    let mut total_ops: usize = 0;
    let mut saw_back_branch: bool = false;
    for body in &abc.method_bodies {
        let lines: Vec<DisasmLine> = disasm(&body.code).expect("disasm");
        total_ops += lines.len();
        saw_back_branch |= lines.iter().any(|line: &DisasmLine| line.opcode == 0x0F);
    }
    assert!(total_ops >= 10, "real opcode stream, got {total_ops}");
    assert!(
        saw_back_branch,
        "the sumTo body must carry the iflt back-edge that drives the loop"
    );
}
