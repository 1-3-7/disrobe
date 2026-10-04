#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

#[cfg(not(target_arch = "wasm32"))]
use disrobe_core::chain::{ChildArtifact, Pass};
#[cfg(not(target_arch = "wasm32"))]
use disrobe_core::{Artifact, Rung};
#[cfg(not(target_arch = "wasm32"))]
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::cil::{MethodBody, ONE_BYTE_OPCODES, OpcodeDef, parse_method_body};
use disrobe_pass_dotnet::cil_emulator::{EmulationError, StubInput, StubOutput, emulate_stub};
use disrobe_pass_dotnet::peel::eazvm::grade::{
    OrderedInstr, OrderedScore, grade_ordered_lifted, known_method_ordered, ordered_lifted,
};
use disrobe_pass_dotnet::peel::eazvm::lift::{LiftedBody, LiftedInstr, LiftedOperand};
use disrobe_pass_dotnet::peel::eazvm::opcodes::{CilOp, CilOperand};
use disrobe_pass_dotnet::peel::eazvm::{
    EazVmDetection, EazVmMethod, EazVmRecovery, detect, devirtualize, lookup_method,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy, peel_eazfuscator};

const EXPECTED_STDOUT: &str = "5\n69\n2147483647\n55\n-1\n9\n";
const CLEAN_BASELINE_INSTRUCTIONS: u32 = 67;

fn corpus_dir() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/eazvm");
    path
}

fn corpus(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_dir().join(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("missing eazvm corpus file {}: {e}", path.display())
    })
}

const TINY_HEADER_CODE_LIMIT: usize = 64;

fn opcode_byte(op: CilOp) -> u8 {
    let key: &str = op.handler_key();
    let definition: &OpcodeDef = ONE_BYTE_OPCODES
        .iter()
        .find(|definition: &&OpcodeDef| definition.name == key)
        .unwrap_or_else(|| panic!("{key} is not a one-byte CIL opcode"));
    u8::try_from(definition.code)
        .unwrap_or_else(|_| panic!("{key} has the two-byte code {:#x}", definition.code))
}

const fn operand_len(op: CilOp) -> usize {
    match op.operand() {
        CilOperand::None => 0,
        CilOperand::InlineI8 | CilOperand::VarByte | CilOperand::ShortBranch => 1,
        CilOperand::VarWord => 2,
        CilOperand::InlineI32 | CilOperand::InlineMember | CilOperand::InlineString => 4,
    }
}

fn encode_code(method: &str, body: &LiftedBody) -> Vec<u8> {
    let mut offsets: Vec<usize> = Vec::with_capacity(body.instrs.len() + 1);
    let mut end: usize = 0;
    for instr in &body.instrs {
        offsets.push(end);
        end += 1 + operand_len(instr.op);
    }
    offsets.push(end);
    let mut code: Vec<u8> = Vec::with_capacity(end);
    for (index, instr) in body.instrs.iter().enumerate() {
        code.push(opcode_byte(instr.op));
        match (instr.op.operand(), &instr.operand) {
            (CilOperand::None, LiftedOperand::None) => {}
            (CilOperand::InlineI8, LiftedOperand::I32(value)) => {
                let short: i8 = i8::try_from(*value)
                    .unwrap_or_else(|_| panic!("{method}: ldc.i4.s operand {value} overflows i8"));
                code.extend_from_slice(&short.to_le_bytes());
            }
            (CilOperand::InlineI32, LiftedOperand::I32(value)) => {
                code.extend_from_slice(&value.to_le_bytes());
            }
            (CilOperand::VarByte, LiftedOperand::Var(slot)) => {
                code.push(
                    u8::try_from(*slot)
                        .unwrap_or_else(|_| panic!("{method}: slot {slot} overflows a byte")),
                );
            }
            (CilOperand::VarWord, LiftedOperand::Var(slot)) => {
                code.extend_from_slice(&slot.to_le_bytes());
            }
            (CilOperand::ShortBranch, LiftedOperand::BranchTo(target)) => {
                let target_offset: usize = *offsets
                    .get(*target)
                    .unwrap_or_else(|| panic!("{method}: branch to missing instruction {target}"));
                let displacement: i64 = i64::try_from(target_offset).expect("offset fits i64")
                    - i64::try_from(offsets[index + 1]).expect("offset fits i64");
                let short: i8 = i8::try_from(displacement).unwrap_or_else(|_| {
                    panic!("{method}: short branch displacement {displacement} overflows i8")
                });
                code.extend_from_slice(&short.to_le_bytes());
            }
            (CilOperand::InlineMember, LiftedOperand::Member(token))
            | (CilOperand::InlineString, LiftedOperand::StringLit(token)) => {
                code.extend_from_slice(&token.to_le_bytes());
            }
            (expected, found) => panic!(
                "{method}: {} carries {found:?} where its encoding needs {expected:?}",
                instr.op.handler_key()
            ),
        }
    }
    code
}

fn method_body(method: &str, body: &LiftedBody) -> MethodBody {
    let code: Vec<u8> = encode_code(method, body);
    assert!(
        code.len() < TINY_HEADER_CODE_LIMIT,
        "{method}: code exceeds the tiny-header limit"
    );
    let mut image: Vec<u8> = Vec::with_capacity(code.len() + 1);
    image.push(u8::try_from((code.len() << 2) | 0x02).expect("a tiny header fits a byte"));
    image.extend_from_slice(&code);
    parse_method_body(&image).unwrap_or_else(|error: disrobe_pass_dotnet::Error| {
        panic!("{method}: the re-encoded CIL body does not decode: {error}")
    })
}

fn evaluate(method: &str, body: &LiftedBody, arguments: &[i32]) -> Result<i32, EmulationError> {
    let input: StubInput = StubInput {
        int_args: arguments
            .iter()
            .map(|argument: &i32| i64::from(*argument))
            .collect(),
        ..StubInput::default()
    };
    match emulate_stub(&method_body(method, body), &input)? {
        StubOutput::Int(value) => Ok(i32::try_from(value)
            .unwrap_or_else(|_| panic!("{method}: the emulator returned {value}, outside i4"))),
        other => panic!("{method}: the emulator returned {other:?} for an i4 method"),
    }
}

fn typed_body(method: &str, recovered: &disrobe_pass_dotnet::RecoveredMethod) -> LiftedBody {
    let body: LiftedBody = recovered
        .lifted_cil
        .clone()
        .unwrap_or_else(|| panic!("{method}: an EazVM recovery carries its lifted body"));
    assert_eq!(
        body.render(),
        recovered.cil,
        "{method}: the rendered CIL is the lifted body's rendering"
    );
    body
}

const fn clean_poly_i4(argument: i32) -> i32 {
    argument
        .wrapping_mul(argument)
        .wrapping_add(3_i32.wrapping_mul(argument))
        .wrapping_sub(1)
}

const fn clean_classify(value: i32) -> i32 {
    if value < 0 {
        -1
    } else if value == 0 {
        0
    } else {
        1
    }
}

const fn clean_max3(a: i32, b: i32, c: i32) -> i32 {
    let mut m: i32 = a;
    if b > m {
        m = b;
    }
    if c > m {
        m = c;
    }
    m
}

const fn clean_sum_to(n: i32) -> i32 {
    let mut total: i32 = 0;
    let mut i: i32 = 1;
    while i <= n {
        total = total.wrapping_add(i);
        i += 1;
    }
    total
}

#[test]
fn detect_reports_full_vm_structure() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let d: EazVmDetection = detect(&image);
    assert!(d.embedded_resource_present);
    assert!(d.dispatch_table_present);
    assert_eq!(d.identified_opcodes, 51);
    assert_eq!(d.stub_count, 6);
}

#[test]
fn clean_assembly_is_not_seen_as_eazvm() {
    let image: Vec<u8> = corpus("EazSample.clean.dll");
    let d: EazVmDetection = detect(&image);
    assert!(
        !d.dispatch_table_present,
        "the unobfuscated baseline must not expose a VM dispatch table"
    );
    assert_eq!(d.stub_count, 0);
    assert!(devirtualize(&image).is_err());
}

#[test]
fn devirtualizes_every_method_to_ordered_cil() {
    let vm: Vec<u8> = corpus("EazSample.eazvm.dll");
    let clean: Vec<u8> = corpus("EazSample.clean.dll");
    let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
    assert!(
        recovery.undecoded.is_empty(),
        "undecoded={:?}",
        recovery.undecoded
    );
    assert_eq!(recovery.methods.len(), 6);

    let known: BTreeMap<String, Vec<OrderedInstr>> = known_method_ordered(&clean, "Compute");
    let mut total_matched: u32 = 0;
    let mut total_length: u32 = 0;
    for m in &recovery.methods {
        let expected: &Vec<OrderedInstr> = known
            .get(&m.name)
            .unwrap_or_else(|| panic!("{} absent from known CIL", m.name));
        let score: OrderedScore = grade_ordered_lifted(expected, &m.lifted, None);
        total_matched += score.matched;
        total_length += score.length;
        assert!(
            score.is_exact(),
            "{} ordered mismatch {}/{}: recovered={:?} expected={:?}",
            m.name,
            score.matched,
            score.length,
            ordered_lifted(&m.lifted, None),
            expected
        );
    }
    let pct: f64 = f64::from(total_matched) / f64::from(total_length) * 100.0;
    println!(
        "ordered CIL recovery: {total_matched}/{total_length} instructions matched in order ({pct:.2}%)"
    );
    assert_eq!(
        total_length, CLEAN_BASELINE_INSTRUCTIONS,
        "the six Compute bodies hold {CLEAN_BASELINE_INSTRUCTIONS} instructions in the clean \
         baseline, and that count is the denominator the documents publish, so a shorter baseline \
         must fail here rather than raise the rate against a smaller population"
    );
    assert!(
        (pct - 100.0).abs() < f64::EPSILON,
        "ordered CIL recovery against the known original must be 100%; got {pct:.2}% \
         ({total_matched}/{total_length})"
    );
}

#[test]
fn branch_targets_resolve_within_method() {
    let vm: Vec<u8> = corpus("EazSample.eazvm.dll");
    let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
    let sumto: &EazVmMethod = lookup_method(&recovery, "SumTo").expect("SumTo recovered");
    let branch_count: usize = sumto
        .lifted
        .instrs
        .iter()
        .filter(|i| i.op.is_branch())
        .count();
    assert!(
        branch_count >= 2,
        "SumTo loop must recover at least two branches; got {branch_count}"
    );
}

#[test]
fn peel_path_surfaces_vm_tier_recovery() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    assert_eq!(
        report.strategy,
        PeelStrategy::EncryptedResourceExtracted,
        "VM-tier recovery must flip the strategy off report-only"
    );
    assert!(
        report.recovered_decoders >= 5,
        "peel must count the recovered virtualized method bodies; got {}",
        report.recovered_decoders
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("VM-tier") && n.contains("lifted")),
        "peel notes must describe the VM-tier lift; got {:?}",
        report.notes
    );
    assert!(
        report.notes.iter().any(|note: &String| {
            note.contains("canonical handler analysis completed for 3 of 6 method body")
        }),
        "the committed EazVM image must reach canonical handler analysis through the public peel caller; got {:?}",
        report.notes
    );
    assert!(
        report.notes.iter().any(|note: &String| {
            note.contains("canonical handler analysis and output refusals:")
                && note.contains("Add: integer width metadata unavailable")
                && note.contains("Classify: virtual instruction has an unknown handler effect")
        }),
        "the public caller must retain the typed refusal when it preserves the ordered lift; got {:?}",
        report.notes
    );
    let add: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Add")
        .expect("Add recovery");
    assert!(
        add.cil.iter().any(|line: &String| line == "IL_0002 add")
            && !add.cil.iter().any(|line: &String| line.contains("int64")),
        "the public EazVM peel output must retain the ordered i4 lift until exact integer widths are known; got {:?}",
        add.cil
    );
    let classify: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Classify")
        .expect("Classify recovery");
    assert!(
        classify
            .cil
            .iter()
            .any(|line: &String| line.starts_with("IL_")),
        "a refused handler analysis must preserve the ordered opcode lift; got {:?}",
        classify.cil
    );
}

#[test]
fn peel_keeps_i4_overflow_semantics_when_handler_analysis_succeeds() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    let poly: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Poly")
        .expect("Poly recovery");
    assert!(
        report
            .notes
            .iter()
            .any(|note: &String| { note.contains("Poly: integer width metadata unavailable") })
    );

    let argument: i32 = 50_000;
    let recovered: i32 = evaluate("Poly", &typed_body("Poly", poly), &[argument])
        .expect("the product CIL emulator evaluates the recovered Poly body");
    let clean_reference: i32 = clean_poly_i4(argument);
    let promoted_i64: i64 =
        i64::from(argument) * i64::from(argument) + 3_i64 * i64::from(argument) - 1_i64;

    assert_eq!(clean_reference, -1_794_817_297);
    assert_eq!(recovered, clean_reference);
    assert_eq!(promoted_i64, 2_500_149_999);
    assert_ne!(i64::from(recovered), promoted_i64);
}

#[test]
fn peel_simplifies_real_mixed_i4_body_before_rendering() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    let mixed: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Mixed")
        .expect("Mixed recovery");

    assert_eq!(
        mixed.cil,
        vec![
            "IL_0000 ldarg.0".to_string(),
            "IL_0001 ldarg.1".to_string(),
            "IL_0002 add".to_string(),
            "IL_0003 ret".to_string(),
        ]
    );
}

#[test]
fn mixed_differential_rejects_a_deliberate_operator_mutation() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    let mixed: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Mixed")
        .expect("Mixed recovery");
    let recovered: LiftedBody = typed_body("Mixed", mixed);
    assert_eq!(recovered.instrs[2].op, CilOp::Add);
    let mut mutated: LiftedBody = recovered.clone();
    mutated.instrs[2].op = CilOp::Sub;

    for argument in [0, 1, -1, i32::MIN, i32::MAX, 0x5555_5555] {
        let reference: i32 = argument.wrapping_add(-1);
        assert_eq!(
            evaluate("Mixed", &recovered, &[argument, -1]),
            Ok(reference)
        );
        let changed: i32 = evaluate("Mixed", &mutated, &[argument, -1])
            .expect("the mutated CIL must still execute");
        assert_ne!(changed, reference);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn auto_chain_emits_width_preserving_eazvm_cil() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let artifact: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    let children: Vec<ChildArtifact> = DOTNET_PASS
        .extract_children(&artifact)
        .expect("EazVM child extraction");
    let recovered_cil: &ChildArtifact = children
        .iter()
        .find(|child: &&ChildArtifact| child.handle.relative_path.ends_with(".recovered-cil.txt"))
        .expect("recovered CIL child");
    let text: &str = std::str::from_utf8(&recovered_cil.bytes).expect("UTF-8 recovered CIL");
    assert!(
        text.contains("method Add token=")
            && text.contains("IL_0000 ldarg.0")
            && text.contains("IL_0001 ldarg.1")
            && text.contains("IL_0002 add")
            && !text.contains("int64"),
        "the auto/chain artifact must retain the width-preserving ordered Add method; got {text}"
    );
    assert!(
        text.contains("method Classify token=") && text.contains("IL_"),
        "the auto/chain artifact must retain the ordered lift for refused handlers; got {text}"
    );
}

const MAIN_CALLS: [(&str, &[i32]); 6] = [
    ("Add", &[2, 3]),
    ("Poly", &[7]),
    ("Mixed", &[i32::MIN, -1]),
    ("SumTo", &[10]),
    ("Classify", &[-5]),
    ("Max3", &[3, 9, 4]),
];

fn main_output(bodies: &BTreeMap<String, LiftedBody>) -> String {
    let mut out: String = String::new();
    for (name, arguments) in MAIN_CALLS {
        let body: &LiftedBody = bodies
            .get(name)
            .unwrap_or_else(|| panic!("{name} was not recovered"));
        match evaluate(name, body, arguments) {
            Ok(value) => writeln!(out, "{value}").expect("write an output line"),
            Err(error) => writeln!(out, "{name}: {error:?}").expect("write an output line"),
        }
    }
    out
}

fn recovered_bodies() -> BTreeMap<String, LiftedBody> {
    let vm: Vec<u8> = corpus("EazSample.eazvm.dll");
    let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
    assert_eq!(
        recovery.methods.len(),
        6,
        "all six bodies must devirtualize"
    );
    recovery
        .methods
        .iter()
        .map(|method: &EazVmMethod| (method.name.clone(), method.lifted.clone()))
        .collect()
}

#[test]
fn recovered_cil_computes_the_clean_baseline_output() {
    let bodies: BTreeMap<String, LiftedBody> = recovered_bodies();
    assert_eq!(
        main_output(&bodies),
        EXPECTED_STDOUT,
        "the devirtualized CIL, evaluated by the product CIL emulator with Main's arguments, must \
         print what EazSample.cs prints"
    );
}

#[derive(Debug, Clone, Copy)]
enum BranchMutation {
    Opcode { from: CilOp, to: CilOp },
    Retarget { from: usize, to: usize },
}

struct BranchCase {
    method: &'static str,
    index: usize,
    mutation: BranchMutation,
}

const BRANCH_CASES: [BranchCase; 6] = [
    BranchCase {
        method: "Classify",
        index: 2,
        mutation: BranchMutation::Opcode {
            from: CilOp::BgeS,
            to: CilOp::BgtS,
        },
    },
    BranchCase {
        method: "Classify",
        index: 6,
        mutation: BranchMutation::Opcode {
            from: CilOp::BrtrueS,
            to: CilOp::BrfalseS,
        },
    },
    BranchCase {
        method: "Max3",
        index: 4,
        mutation: BranchMutation::Opcode {
            from: CilOp::BleS,
            to: CilOp::BgtS,
        },
    },
    BranchCase {
        method: "Max3",
        index: 9,
        mutation: BranchMutation::Opcode {
            from: CilOp::BleS,
            to: CilOp::BgtS,
        },
    },
    BranchCase {
        method: "SumTo",
        index: 4,
        mutation: BranchMutation::Retarget { from: 13, to: 5 },
    },
    BranchCase {
        method: "SumTo",
        index: 15,
        mutation: BranchMutation::Opcode {
            from: CilOp::BleS,
            to: CilOp::BltS,
        },
    },
];

fn battery(method: &str) -> Vec<(Vec<i32>, i32)> {
    match method {
        "Classify" => [-5, -1, 0, 1, 7, i32::MIN, i32::MAX]
            .into_iter()
            .map(|value: i32| (vec![value], clean_classify(value)))
            .collect(),
        "Max3" => [
            [1, 2, 3],
            [1, 3, 2],
            [2, 1, 3],
            [2, 3, 1],
            [3, 1, 2],
            [3, 2, 1],
            [3, 9, 4],
            [2, 2, 1],
            [1, 2, 2],
            [2, 1, 2],
            [5, 5, 5],
            [i32::MIN, 0, i32::MAX],
        ]
        .into_iter()
        .map(|[a, b, c]: [i32; 3]| (vec![a, b, c], clean_max3(a, b, c)))
        .collect(),
        "SumTo" => [-3, 0, 1, 2, 10, 100]
            .into_iter()
            .map(|n: i32| (vec![n], clean_sum_to(n)))
            .collect(),
        other => panic!("no battery for {other}"),
    }
}

fn disagreements(method: &str, body: &LiftedBody) -> Vec<String> {
    battery(method)
        .into_iter()
        .filter_map(|(arguments, expected): (Vec<i32>, i32)| {
            let got: Result<i32, EmulationError> = evaluate(method, body, &arguments);
            (got != Ok(expected))
                .then(|| format!("{method}{arguments:?}: expected {expected}, got {got:?}"))
        })
        .collect()
}

#[test]
fn every_recovered_branch_is_graded_on_both_sides() {
    let bodies: BTreeMap<String, LiftedBody> = recovered_bodies();
    let recovered_branches: BTreeSet<(&str, usize)> = bodies
        .iter()
        .flat_map(|(method, body): (&String, &LiftedBody)| {
            body.instrs.iter().enumerate().filter_map(
                move |(index, instr): (usize, &LiftedInstr)| {
                    instr.op.is_branch().then_some((method.as_str(), index))
                },
            )
        })
        .collect();
    let graded_branches: BTreeSet<(&str, usize)> = BRANCH_CASES
        .iter()
        .map(|case: &BranchCase| (case.method, case.index))
        .collect();
    assert_eq!(
        graded_branches.len(),
        BRANCH_CASES.len(),
        "duplicate branch grade"
    );
    assert_eq!(
        recovered_branches, graded_branches,
        "every recovered branch needs a mutation grade"
    );
    for method in ["Classify", "Max3", "SumTo"] {
        let body: &LiftedBody = bodies
            .get(method)
            .unwrap_or_else(|| panic!("{method} was not recovered"));
        assert_eq!(
            disagreements(method, body),
            Vec::<String>::new(),
            "the recovered {method} must agree with EazSample.cs on every input of its battery"
        );
    }
    for case in &BRANCH_CASES {
        let mut mutated: LiftedBody = bodies
            .get(case.method)
            .unwrap_or_else(|| panic!("{} was not recovered", case.method))
            .clone();
        let instr: &mut LiftedInstr = &mut mutated.instrs[case.index];
        match case.mutation {
            BranchMutation::Opcode { from, to } => {
                assert_eq!(
                    instr.op, from,
                    "{} IL_{:04} must hold the branch this mutation targets",
                    case.method, case.index
                );
                instr.op = to;
            }
            BranchMutation::Retarget { from, to } => {
                assert_eq!(
                    instr.operand,
                    LiftedOperand::BranchTo(from),
                    "{} IL_{:04} must jump where this mutation expects",
                    case.method,
                    case.index
                );
                instr.operand = LiftedOperand::BranchTo(to);
            }
        }
        assert!(
            !disagreements(case.method, &mutated).is_empty(),
            "mutating {} IL_{:04} with {:?} changes no result on its battery, so the battery does \
             not exercise both sides of that branch",
            case.method,
            case.index,
            case.mutation
        );
    }
}
