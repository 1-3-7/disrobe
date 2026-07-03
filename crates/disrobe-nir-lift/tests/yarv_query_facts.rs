#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_nir::{NirModule, NirOp};
use disrobe_nir_lift::lift_ruby_iseq;
use disrobe_pass_ruby::{
    RubyAnalysis, YarvAnalysis, YarvDisasm, YarvInstruction, YarvIseqBody, analyze_bytes,
    disassemble_body,
};

fn fixture_bytes() -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    p.push("mri");
    p.push("yarv");
    p.push("opassign.rb.yarvc");
    std::fs::read(&p).expect("committed opassign YARV fixture present")
}

fn lifted() -> NirModule {
    lift_ruby_iseq(&fixture_bytes()).expect("lift YARV ISeq image to NIR")
}

struct OracleFacts {
    callees: BTreeSet<String>,
    string_constants: BTreeSet<String>,
    ivars: BTreeSet<String>,
    gvars: BTreeSet<String>,
    constants: BTreeSet<String>,
    branch_count: usize,
}

fn strip_quotes(s: &str) -> Option<String> {
    let bytes: &[u8] = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        Some(s[1..s.len() - 1].to_owned())
    } else {
        None
    }
}

fn calldata_method(s: &str) -> Option<String> {
    let rest: &str = s.strip_prefix("<calldata :")?;
    let end: usize = rest.find(' ')?;
    Some(rest[..end].to_owned())
}

fn independent_oracle() -> OracleFacts {
    let analysis: YarvAnalysis = analyze_bytes(&fixture_bytes(), "opassign.rb.yarvc")
        .expect("analyze YARV fixture")
        .yarv
        .expect("yarv analysis present");

    let mut callees: BTreeSet<String> = BTreeSet::new();
    let mut string_constants: BTreeSet<String> = BTreeSet::new();
    let mut ivars: BTreeSet<String> = BTreeSet::new();
    let mut gvars: BTreeSet<String> = BTreeSet::new();
    let mut constants: BTreeSet<String> = BTreeSet::new();
    let mut branch_count: usize = 0;

    for body in &analysis.ibf.iseqs {
        let body: &YarvIseqBody = body;
        let disasm: YarvDisasm = disassemble_body(body, analysis.version, "<oracle>");
        for instr in &disasm.instructions {
            let instr: &YarvInstruction = instr;
            let name: &str = instr.mnemonic.as_str();
            match name {
                "jump" | "branchif" | "branchunless" | "branchnil" => branch_count += 1,
                "putstring" | "putchilledstring" => {
                    for op in &instr.operands {
                        if let Some(lit) = strip_quotes(op) {
                            string_constants.insert(lit);
                        }
                    }
                }
                "opt_plus" | "opt_minus" | "opt_mult" | "opt_div" | "opt_mod" | "opt_and"
                | "opt_or" | "opt_aref" => {}
                "getinstancevariable" | "setinstancevariable" => {
                    if let Some(op) = instr.operands.first() {
                        ivars.insert(op.trim_start_matches(':').to_owned());
                    }
                }
                "getglobal" | "setglobal" => {
                    if let Some(op) = instr.operands.first() {
                        gvars.insert(op.trim_start_matches(':').to_owned());
                    }
                }
                "opt_getconstant_path" => {
                    if let Some(op) = instr.operands.first() {
                        constants.insert(op.clone());
                    }
                }
                _ => {
                    for op in &instr.operands {
                        if let Some(m) = calldata_method(op) {
                            callees.insert(m);
                        }
                    }
                }
            }
        }
    }

    OracleFacts {
        callees,
        string_constants,
        ivars,
        gvars,
        constants,
        branch_count,
    }
}

fn lifted_callees(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Call { .. })
                && let Some(name) = ins.operands.first()
            {
                out.insert(name.clone());
            }
        }
    }
    out
}

fn lifted_string_constants(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if ins.op == NirOp::Const
                && matches!(ins.mnemonic.as_str(), "putstring" | "putchilledstring")
                && let Some(v) = ins.operands.first()
            {
                out.insert(v.clone());
            }
        }
    }
    out
}

fn lifted_access(nir: &NirModule, mnemonics: &[&str]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Load | NirOp::Store)
                && mnemonics.contains(&ins.mnemonic.as_str())
                && let Some(v) = ins.operands.first()
            {
                out.insert(v.clone());
            }
        }
    }
    out
}

fn lifted_branch_count(nir: &NirModule) -> usize {
    nir.functions
        .iter()
        .flat_map(|f| f.instructions.iter())
        .filter(|ins| matches!(ins.op, NirOp::Branch { .. } | NirOp::CondBranch { .. }))
        .count()
}

#[test]
fn input_is_a_real_compiled_ruby_yarv_image() {
    let analysis: RubyAnalysis =
        analyze_bytes(&fixture_bytes(), "opassign.rb.yarvc").expect("analyze");
    let yarv: YarvAnalysis = analysis.yarv.expect("yarv flavor");
    assert_eq!(yarv.header.magic, *b"YARB", "real YARB image");
    assert!(
        yarv.ibf.iseqs.len() >= 3,
        "opassign compiles to a top iseq plus the singleton-method iseqs"
    );
}

#[test]
fn lifted_callees_equal_the_independent_yarv_decode() {
    let oracle: OracleFacts = independent_oracle();
    let lifted: BTreeSet<String> = lifted_callees(&lifted());
    assert!(
        !oracle.callees.is_empty(),
        "the source issues real method sends"
    );
    assert_eq!(
        lifted, oracle.callees,
        "lifted Mir call targets must equal the YARV calldata method-id set exactly"
    );
    for expected in ["new", "value", "value="] {
        assert!(
            oracle.callees.iter().any(|c: &String| c == expected),
            "the source calls {expected}: {:?}",
            oracle.callees
        );
    }
}

#[test]
fn lifted_string_constants_equal_the_independent_yarv_decode() {
    let oracle: OracleFacts = independent_oracle();
    let lifted: BTreeSet<String> = lifted_string_constants(&lifted());
    assert!(
        !oracle.string_constants.is_empty(),
        "the source has at least one string literal"
    );
    assert_eq!(
        lifted, oracle.string_constants,
        "lifted Mir string constants must equal the YARV put-string literal set exactly"
    );
    assert!(
        oracle.string_constants.iter().any(|s: &String| s == "x"),
        "the source assigns $global the literal \"x\": {:?}",
        oracle.string_constants
    );
}

#[test]
fn lifted_ivar_accesses_equal_the_independent_yarv_decode() {
    let oracle: OracleFacts = independent_oracle();
    let lifted: BTreeSet<String> =
        lifted_access(&lifted(), &["getinstancevariable", "setinstancevariable"]);
    assert!(!oracle.ivars.is_empty(), "the source touches @store");
    assert_eq!(
        lifted, oracle.ivars,
        "lifted Mir ivar accesses must equal the YARV get/set-instancevariable set exactly"
    );
    assert!(
        oracle.ivars.iter().any(|s: &String| s == "@store"),
        "the source reads and writes @store: {:?}",
        oracle.ivars
    );
}

#[test]
fn lifted_gvar_accesses_equal_the_independent_yarv_decode() {
    let oracle: OracleFacts = independent_oracle();
    let lifted: BTreeSet<String> = lifted_access(&lifted(), &["getglobal", "setglobal"]);
    assert!(!oracle.gvars.is_empty(), "the source touches $global");
    assert_eq!(
        lifted, oracle.gvars,
        "lifted Mir global accesses must equal the YARV get/set-global set exactly"
    );
    assert!(
        oracle.gvars.iter().any(|s: &String| s == "$global"),
        "the source reads and writes $global: {:?}",
        oracle.gvars
    );
}

#[test]
fn lifted_constant_accesses_equal_the_independent_yarv_decode() {
    let oracle: OracleFacts = independent_oracle();
    let lifted: BTreeSet<String> = lifted_access(&lifted(), &["opt_getconstant_path"]);
    assert!(!oracle.constants.is_empty(), "the source references Object");
    assert_eq!(
        lifted, oracle.constants,
        "lifted Mir constant-path accesses must equal the YARV opt_getconstant_path set exactly"
    );
}

#[test]
fn lifted_branch_count_equals_the_independent_yarv_decode() {
    let oracle: OracleFacts = independent_oracle();
    assert!(
        oracle.branch_count >= 3,
        "the ||= / &&= forms compile to several branches"
    );
    assert_eq!(
        lifted_branch_count(&lifted()),
        oracle.branch_count,
        "lifted Mir branch/cond-branch count must equal the YARV branch-instruction count exactly"
    );
}

#[test]
fn conditional_branch_targets_resolve_to_real_lifted_instructions() {
    let nir: NirModule = lifted();
    let mut checked: usize = 0;
    for f in &nir.functions {
        for ins in &f.instructions {
            if let NirOp::CondBranch {
                target: Some(target),
            }
            | NirOp::Branch {
                target: Some(target),
            } = ins.op
            {
                assert!(
                    f.instructions.iter().any(|other| other.address == target),
                    "branch at {:#x} must target a real lifted instruction, got {target:#x}",
                    ins.address
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 3,
        "the fixture has resolvable jump and conditional-branch targets"
    );
}

#[test]
fn top_iseq_lifts_as_an_exported_function() {
    let nir: NirModule = lifted();
    assert_eq!(nir.lang, disrobe_nir::SourceLang::Yarv);
    let top: &disrobe_nir::NirFunction = nir
        .functions
        .iter()
        .find(|f| f.name == "<top>")
        .expect("top-level iseq present");
    assert!(top.is_export, "the top-level iseq is the module entry");
    assert!(top.instructions.iter().any(|i| i.op == NirOp::Return));
}

#[test]
fn lift_is_deterministic() {
    assert_eq!(lifted(), lifted(), "the YARV lift must be byte-stable");
}
