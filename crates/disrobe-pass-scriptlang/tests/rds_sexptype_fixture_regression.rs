#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::r_rds::{RdsObject, read_rds};

const COMPILED_CLOSURE: &[u8] = include_bytes!("fixtures/compiled_closure.rds");
const BYTECODE_OBJ: &[u8] = include_bytes!("fixtures/bytecode_obj.rds");
const EXPRESSION_VEC: &[u8] = include_bytes!("fixtures/expression_vec.rds");
const S4_OBJECT: &[u8] = include_bytes!("fixtures/s4_object.rds");
const NAMESPACE_FN: &[u8] = include_bytes!("fixtures/namespace_fn.rds");
const NESTED_LIST: &[u8] = include_bytes!("fixtures/nested_list.rds");
const COMPLEX_VEC: &[u8] = include_bytes!("fixtures/complex_vec.rds");
const RAW_AND_LOGICAL: &[u8] = include_bytes!("fixtures/raw_and_logical.rds");
const RAW_VECTOR: &[u8] = include_bytes!("fixtures/raw_vector.rds");
const COMPLEX_VECTOR: &[u8] = include_bytes!("fixtures/complex_vector.rds");
const S4_POINT: &[u8] = include_bytes!("fixtures/s4_point.rds");
const ENVIRONMENT: &[u8] = include_bytes!("fixtures/environment.rds");
const ALTREP_INTSEQ: &[u8] = include_bytes!("fixtures/altrep_intseq.rds");
const EXTPTR: &[u8] = include_bytes!("fixtures/extptr.rds");

#[test]
fn committed_compiled_closure_fixture_parses() {
    let obj: RdsObject = read_rds(COMPILED_CLOSURE).expect("compiler::cmpfun output must parse");
    assert_eq!(obj.root_type, "closure");
    assert_eq!(obj.closures.len(), 1, "one compiled closure expected");
    let names: &Vec<String> = &obj.symbols;
    for sym in ["x", "y"] {
        assert!(
            names.iter().any(|s: &String| s == sym),
            "formal '{sym}' from cmpfun(function(x, y) x + y * 2) must survive in symbols: {names:?}"
        );
    }
}

#[test]
fn committed_standalone_bytecode_fixture_parses() {
    let obj: RdsObject = read_rds(BYTECODE_OBJ).expect("compiler::compile output must parse");
    assert_eq!(
        obj.root_type, "bytecode",
        "a top-level BCODESXP must be recognized as bytecode"
    );
    assert!(
        obj.symbols.iter().any(|s: &String| s == "print")
            || obj.symbols.iter().any(|s: &String| s == "i"),
        "bytecode constant-pool symbols (print/i from the for loop) must be recovered: {:?}",
        obj.symbols
    );
}

#[test]
fn committed_expression_vector_fixture_recovers_symbols() {
    let obj: RdsObject = read_rds(EXPRESSION_VEC).expect("EXPRSXP must parse");
    assert_eq!(obj.root_type, "expression");
    assert_eq!(obj.root_length, Some(3), "expression(a+b, sqrt(c), f(x,y))");
    for sym in ["a", "b", "sqrt", "c", "f", "x", "y"] {
        assert!(
            obj.symbols.iter().any(|s: &String| s == sym),
            "symbol '{sym}' from the expression vector must be recovered: {:?}",
            obj.symbols
        );
    }
}

#[test]
fn committed_s4_fixture_parses_with_slots_as_attributes() {
    let obj: RdsObject = read_rds(S4_OBJECT).expect("S4SXP must parse");
    assert_eq!(obj.root_type, "S4");
    assert!(
        obj.class.iter().any(|c: &String| c == "DisrobeS4"),
        "the S4 class set via setClass must round-trip: {:?}",
        obj.class
    );
    assert!(
        obj.symbols.iter().any(|s: &String| s == "label")
            && obj.symbols.iter().any(|s: &String| s == "value"),
        "S4 slot names are serialized as the attribute tags: {:?}",
        obj.symbols
    );
    assert!(
        obj.string_values.iter().any(|s: &String| s == "demo"),
        "slot value 'demo' must be recovered: {:?}",
        obj.string_values
    );
}

#[test]
fn committed_namespace_function_fixture_parses() {
    let obj: RdsObject =
        read_rds(NAMESPACE_FN).expect("closure with a NAMESPACESXP env must parse");
    assert_eq!(obj.root_type, "closure");
    let c: &disrobe_pass_scriptlang::lang::r_rds::RdsClosure = &obj.closures[0];
    let names: Vec<&str> = c.formals.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["n", "mean", "sd"],
        "stats::rnorm formals must be recovered from the pairlist"
    );
}

#[test]
fn committed_nested_list_fixture_parses() {
    let obj: RdsObject = read_rds(NESTED_LIST).expect("nested list with cmpfun member must parse");
    assert_eq!(obj.root_type, "list");
    for n in ["name", "fn", "exprs", "data"] {
        assert!(
            obj.names.iter().any(|x: &String| x == n),
            "top list name '{n}' must be recovered: {:?}",
            obj.names
        );
    }
    assert!(
        obj.closures.len() == 1,
        "the compiled fn member is one closure: {}",
        obj.closures.len()
    );
    assert!(
        obj.string_values.iter().any(|s: &String| s == "disrobe"),
        "string member value must be recovered: {:?}",
        obj.string_values
    );
}

#[test]
fn committed_complex_vector_fixture_parses() {
    let obj: RdsObject = read_rds(COMPLEX_VEC).expect("CPLXSXP root must parse");
    assert_eq!(obj.root_type, "complex");
    assert_eq!(obj.root_length, Some(3));
    assert_eq!(obj.complex_vectors.len(), 1);
    assert_eq!(obj.complex_vectors[0].length, 3);
}

#[test]
fn committed_raw_and_logical_fixture_parses() {
    let obj: RdsObject = read_rds(RAW_AND_LOGICAL).expect("raw + logical list must parse");
    assert_eq!(obj.root_type, "list");
    assert!(obj.names.iter().any(|n: &String| n == "bytes"));
    assert!(obj.names.iter().any(|n: &String| n == "flags"));
    assert!(
        !obj.raw_vectors.is_empty(),
        "a raw vector nested in the list must surface in the inventory"
    );
}

#[test]
fn committed_raw_vector_fixture_bytes_recovered_exactly() {
    let obj: RdsObject = read_rds(RAW_VECTOR).expect("RAWSXP root must parse");
    assert_eq!(obj.root_type, "raw");
    assert_eq!(obj.root_length, Some(8));
    assert_eq!(obj.raw_vectors.len(), 1, "one raw vector expected");
    let rv: &disrobe_pass_scriptlang::lang::r_rds::RdsRawVector = &obj.raw_vectors[0];
    assert_eq!(rv.length, 8);
    assert!(!rv.truncated);
    assert_eq!(
        rv.bytes,
        vec![0x00, 0x01, 0x7f, 0xff, 0xde, 0xad, 0xbe, 0xef],
        "as.raw(c(0x00,0x01,0x7f,0xff,0xde,0xad,0xbe,0xef)) must round-trip byte-exact"
    );
}

#[test]
fn committed_complex_vector_fixture_values_recovered() {
    let obj: RdsObject = read_rds(COMPLEX_VECTOR).expect("CPLXSXP root must parse");
    assert_eq!(obj.root_type, "complex");
    assert_eq!(obj.root_length, Some(3));
    assert_eq!(obj.complex_vectors.len(), 1);
    let cv: &disrobe_pass_scriptlang::lang::r_rds::RdsComplexVector = &obj.complex_vectors[0];
    assert_eq!(cv.length, 3);
    let pairs: Vec<(&str, &str)> = cv
        .values
        .iter()
        .map(|c| (c.re.as_str(), c.im.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![("1", "0"), ("-2.5", "3.25"), ("0", "-1")],
        "complex(real=c(1,-2.5,0), imaginary=c(0,3.25,-1)) must round-trip"
    );
}

#[test]
fn committed_s4_point_fixture_class_and_slots_recovered() {
    let obj: RdsObject = read_rds(S4_POINT).expect("S4SXP root must parse");
    assert_eq!(obj.root_type, "S4");
    assert_eq!(obj.s4_objects.len(), 1, "one S4 object expected");
    let s4: &disrobe_pass_scriptlang::lang::r_rds::RdsS4Object = &obj.s4_objects[0];
    assert_eq!(
        s4.class.as_deref(),
        Some("DisrobePoint"),
        "S4 class set via setClass must be recovered: {s4:?}"
    );
    for slot in ["x", "y", "label"] {
        assert!(
            s4.slots.iter().any(|s: &String| s == slot),
            "S4 slot '{slot}' must be recovered: {:?}",
            s4.slots
        );
    }
    assert!(
        !s4.slots.iter().any(|s: &String| s == "class"),
        "the 'class' attribute must not be reported as a data slot: {:?}",
        s4.slots
    );
}

#[test]
fn committed_environment_fixture_bindings_recovered() {
    let obj: RdsObject = read_rds(ENVIRONMENT).expect("ENVSXP root must parse");
    assert_eq!(obj.root_type, "environment");
    assert_eq!(obj.environments.len(), 1, "one environment expected");
    let env: &disrobe_pass_scriptlang::lang::r_rds::RdsEnvironmentInfo = &obj.environments[0];
    for binding in ["alpha", "beta", "gamma"] {
        assert!(
            env.bindings.iter().any(|b: &String| b == binding),
            "environment binding '{binding}' must be recovered: {:?}",
            env.bindings
        );
    }
    assert_eq!(
        env.enclosing, "environment",
        "the enclosing global environment must be labelled"
    );
}

#[test]
fn committed_altrep_fixture_materializes_a_compact_intseq() {
    let obj: RdsObject = read_rds(ALTREP_INTSEQ).expect("ALTREP root must parse");
    assert_eq!(obj.altrep_objects.len(), 1, "one altrep object expected");
    let alt: &disrobe_pass_scriptlang::lang::r_rds::RdsAltrep = &obj.altrep_objects[0];
    assert_eq!(
        alt.class.as_deref(),
        Some("compact_intseq"),
        "the altrep class id must be recovered: {alt:?}"
    );
    assert_eq!(alt.package.as_deref(), Some("base"));
    assert_eq!(
        alt.materialized.as_deref(),
        Some("1:1000"),
        "1:1000 is a compact_intseq whose (n,start,step) statically materializes the range"
    );
    assert!(
        alt.note.is_none(),
        "a statically materialized altrep needs no caveat note"
    );
}

#[test]
fn committed_external_pointer_fixture_marks_a_runtime_address() {
    let obj: RdsObject = read_rds(EXTPTR).expect("list with EXTPTRSXP must parse");
    assert_eq!(
        obj.external_pointers.len(),
        1,
        "one external pointer expected: {:?}",
        obj.external_pointers
    );
    let ep: &disrobe_pass_scriptlang::lang::r_rds::RdsExternalPointer = &obj.external_pointers[0];
    assert!(
        ep.note.contains("runtime"),
        "the extptr address must be honestly marked as a non-serialized runtime value: {}",
        ep.note
    );
}
