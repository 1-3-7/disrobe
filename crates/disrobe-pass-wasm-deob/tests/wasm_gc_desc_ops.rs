#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body, lift_module_to_wat,
};
use wasmparser::{FunctionBody, Parser, Payload};

const BR_ON_CAST: &str = r"
(module
  (type $t (sub (struct (field i32))))
  (func $classify (param $r anyref) (result i32)
    (block $hit (result (ref $t))
      local.get $r
      br_on_cast $hit anyref (ref $t)
      drop
      i32.const 0
      return)
    struct.get $t 0
    return)
  (func $reject (param $r anyref) (result i32)
    (block $miss (result anyref)
      local.get $r
      br_on_cast_fail $miss anyref (ref $t)
      struct.get $t 0
      return)
    drop
    i32.const -1))
";

const DESC_OPS: &str = r"
(module
  (rec
    (type $d (descriptor $t) (struct))
    (type $t (describes $d) (struct (field i32))))
  (func $make (result (ref $t))
    i32.const 7
    ref.null (exact $d)
    struct.new_desc $t)
  (func $make_default (result (ref $t))
    ref.null (exact $d)
    struct.new_default_desc $t)
  (func $get_desc (param $r (ref $t)) (result (ref $d))
    local.get $r
    ref.get_desc $t)
  (func $cast_desc (param $r anyref) (param $desc (ref $d)) (result (ref $t))
    local.get $r
    local.get $desc
    ref.cast_desc_eq (ref $t))
  (func $br_cast_desc (param $r anyref) (param $desc (ref $d)) (result i32)
    (block $hit (result (ref $t))
      local.get $r
      local.get $desc
      br_on_cast_desc_eq $hit anyref (ref $t)
      drop
      i32.const 0
      return)
    struct.get $t 0))
";

const ABSTRACT_REF_NULLS: &str = r"
(module
  (func $any (result anyref)
    ref.null any)
  (func $eq (result eqref)
    ref.null eq)
  (func $struct (result structref)
    ref.null struct)
  (func $array (result arrayref)
    ref.null array))
";

const PLACEHOLDERS: &[&str] = &[
    "todo!(",
    "DR-WASMDEOB-UNRECOVERED",
    "no lifter for op",
    "__builtin_trap()",
    "untranslated op",
];

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn assert_recovery(name: &str, wat: &str, targets: &[LiftTarget]) {
    let bytes: Vec<u8> = wat::parse_str(wat).unwrap_or_else(|e| panic!("assemble {name}: {e}"));
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let cs: CalleeNames = callees(&sigs);
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(&bytes);
    assert!(!bodies.is_empty(), "{name}: no functions");

    for target in targets.iter().copied() {
        for (i, body) in bodies.iter().enumerate() {
            let sig: &FunctionSig = &defined[i];
            let lifted: LiftResult = lift_function_body(body, sig, &cs, target);
            for needle in PLACEHOLDERS {
                assert!(
                    !lifted.pseudo_source.contains(needle),
                    "{name}:{}:{target:?} emitted placeholder `{needle}`:\n{}",
                    sig.name,
                    lifted.pseudo_source
                );
            }
            assert!(
                lifted.coverage.fully_recovered(),
                "{name}:{}:{target:?} left untranslated ops: {:?}",
                sig.name,
                lifted.coverage.untranslated
            );
        }
    }
}

const STRUCTURED_TARGETS: &[LiftTarget] =
    &[LiftTarget::Rust, LiftTarget::TypeScript, LiftTarget::C];
const ALL_TARGETS: &[LiftTarget] = &[
    LiftTarget::Rust,
    LiftTarget::TypeScript,
    LiftTarget::C,
    LiftTarget::Wat,
];

fn assert_no_placeholder_in_wat(name: &str, wat: &str) {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let cs: CalleeNames = callees(&sigs);
    for (i, body) in defined_bodies(&bytes).iter().enumerate() {
        let lifted: LiftResult = lift_function_body(body, &defined[i], &cs, LiftTarget::Wat);
        for needle in PLACEHOLDERS {
            assert!(
                !lifted.pseudo_source.contains(needle),
                "{name}: WAT target emitted placeholder `{needle}`:\n{}",
                lifted.pseudo_source
            );
        }
    }
}

fn lifted_wat_reparses(name: &str, wat: &str) {
    let out_wat: String = lift_module_wat(wat);
    let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&out_wat);
    assert!(
        reparsed.is_ok(),
        "{name}: lifted WAT must reparse: {:?}\n{out_wat}",
        reparsed.err()
    );
}

fn lift_module_wat(wat: &str) -> String {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(&bytes);
    let pairs: Vec<(FunctionBody<'_>, FunctionSig)> =
        bodies.into_iter().zip(defined.iter().cloned()).collect();
    lift_module_to_wat(&pairs, 0)
}

#[test]
fn br_on_cast_family_recovers_on_all_targets() {
    assert_recovery("br_on_cast", BR_ON_CAST, ALL_TARGETS);
}

#[test]
fn custom_descriptor_ops_recover_on_structured_targets() {
    assert_recovery("desc_ops", DESC_OPS, STRUCTURED_TARGETS);
    assert_no_placeholder_in_wat("desc_ops", DESC_OPS);
}

#[test]
fn br_on_cast_lifted_wat_reassembles() {
    lifted_wat_reparses("br_on_cast", BR_ON_CAST);
}

#[test]
fn desc_ops_lifted_wat_reassembles() {
    lifted_wat_reparses("desc_ops", DESC_OPS);
}

#[test]
fn abstract_ref_null_heap_types_survive_wat_lift() {
    let lifted: String = lift_module_wat(ABSTRACT_REF_NULLS);
    assert!(lifted.contains("ref.null any"), "{lifted}");
    assert!(lifted.contains("ref.null eq"), "{lifted}");
    assert!(lifted.contains("ref.null struct"), "{lifted}");
    assert!(lifted.contains("ref.null array"), "{lifted}");
    let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&lifted);
    assert!(
        reparsed.is_ok(),
        "abstract ref.null WAT must reparse: {:?}\n{lifted}",
        reparsed.err()
    );
}
