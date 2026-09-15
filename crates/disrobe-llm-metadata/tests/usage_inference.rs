#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_llm_metadata::usage_inference::UsageInferenceEngine;
use disrobe_llm_metadata::{
    Category, FunctionUsage, InferredType, LlmMetadataEmitter, SelectionBuilder, UsageObservation,
    VariableUsage,
};
use serde_json::Value as Json;

use UsageObservation as Obs;

fn var(name: &str, obs: &[UsageObservation]) -> VariableUsage {
    let mut v: VariableUsage = VariableUsage::new(name);
    for o in obs {
        v.observe(*o);
    }
    v
}

#[test]
fn string_concat_evidence_infers_string() {
    let v: VariableUsage = var("greeting", &[Obs::StringConcat, Obs::StringConcat]);
    assert_eq!(v.infer(), InferredType::String);
}

#[test]
fn string_format_evidence_infers_string() {
    let v: VariableUsage = var("fmt", &[Obs::StringFormat]);
    assert_eq!(v.infer(), InferredType::String);
}

#[test]
fn integer_arithmetic_evidence_infers_integer() {
    let v: VariableUsage = var("counter", &[Obs::IntegerArith, Obs::IntegerArith]);
    assert_eq!(v.infer(), InferredType::Integer);
}

#[test]
fn bitwise_and_shift_evidence_infers_integer() {
    let v: VariableUsage = var("flags", &[Obs::BitwiseArith, Obs::ShiftArith]);
    assert_eq!(v.infer(), InferredType::Integer);
}

#[test]
fn float_division_evidence_infers_float() {
    let v: VariableUsage = var("ratio", &[Obs::FloatDivision, Obs::FloatArith]);
    assert_eq!(v.infer(), InferredType::Float);
}

#[test]
fn field_access_evidence_infers_struct_pointer() {
    let v: VariableUsage = var("node", &[Obs::FieldAccess, Obs::FieldAccess]);
    assert_eq!(v.infer(), InferredType::StructPointer);
}

#[test]
fn array_index_evidence_infers_array() {
    let v: VariableUsage = var("buf", &[Obs::ArrayIndex, Obs::ArrayIndex]);
    assert_eq!(
        v.infer(),
        InferredType::Array(Box::new(InferredType::Unknown))
    );
}

#[test]
fn pure_pointer_deref_infers_pointer() {
    let v: VariableUsage = var("p", &[Obs::PointerDeref]);
    assert_eq!(v.infer(), InferredType::Pointer);
}

#[test]
fn called_as_function_infers_function() {
    let v: VariableUsage = var("cb", &[Obs::CalledAsFunction]);
    assert_eq!(v.infer(), InferredType::Function);
}

#[test]
fn boolean_logic_only_infers_boolean() {
    let v: VariableUsage = var("enabled", &[Obs::BooleanLogic, Obs::BooleanLogic]);
    assert_eq!(v.infer(), InferredType::Boolean);
}

#[test]
fn integer_with_compatible_comparison_stays_integer() {
    let v: VariableUsage = var("idx", &[Obs::IntegerArith, Obs::OrderedComparison]);
    assert_eq!(v.infer(), InferredType::Integer);
}

#[test]
fn string_with_length_query_stays_string() {
    let v: VariableUsage = var("name", &[Obs::StringConcat, Obs::LengthQuery]);
    assert_eq!(v.infer(), InferredType::String);
}

#[test]
fn no_evidence_is_unknown_not_a_guess() {
    let v: VariableUsage = VariableUsage::new("opaque");
    assert!(v.infer().is_unknown());
}

#[test]
fn comparison_only_is_ambiguous_unknown() {
    let v: VariableUsage = var("x", &[Obs::OrderedComparison]);
    assert!(
        v.infer().is_unknown(),
        "a bare comparison cannot pin int vs float vs string; must be Unknown"
    );
}

#[test]
fn equality_only_is_ambiguous_unknown() {
    let v: VariableUsage = var("token", &[Obs::EqualityComparison]);
    assert!(v.infer().is_unknown());
}

#[test]
fn length_query_only_is_ambiguous_unknown() {
    let v: VariableUsage = var("seq", &[Obs::LengthQuery]);
    assert!(
        v.infer().is_unknown(),
        "length applies to both strings and arrays; alone it is ambiguous"
    );
}

#[test]
fn conflicting_string_and_integer_yields_unknown() {
    let v: VariableUsage = var("mixed", &[Obs::StringConcat, Obs::IntegerArith]);
    assert!(
        v.infer().is_unknown(),
        "string-concat and integer-add on one value conflict; a wrong confident type is worse than Unknown"
    );
}

#[test]
fn conflicting_integer_and_float_yields_unknown() {
    let v: VariableUsage = var("n", &[Obs::IntegerArith, Obs::FloatArith]);
    assert!(v.infer().is_unknown());
}

#[test]
fn conflicting_field_access_and_integer_arith_yields_unknown() {
    let v: VariableUsage = var("ambig", &[Obs::FieldAccess, Obs::IntegerArith]);
    assert!(
        v.infer().is_unknown(),
        "struct-field-access and integer-arith on the same value conflict"
    );
}

#[test]
fn struct_pointer_with_pointer_arith_is_not_a_conflict() {
    let v: VariableUsage = var("cursor", &[Obs::FieldAccess, Obs::PointerArith]);
    assert_eq!(v.infer(), InferredType::StructPointer);
}

#[test]
fn callee_argument_type_resolves_when_usage_is_silent() {
    let v: VariableUsage =
        VariableUsage::new("arg").passed_to_typed_parameter(InferredType::String);
    assert_eq!(v.infer(), InferredType::String);
}

#[test]
fn callee_argument_disagreeing_with_usage_yields_unknown() {
    let mut v: VariableUsage =
        VariableUsage::new("arg").passed_to_typed_parameter(InferredType::String);
    v.observe(Obs::IntegerArith);
    v.observe(Obs::IntegerArith);
    assert!(
        v.infer().is_unknown(),
        "callee says string, local use says integer: conflict must be Unknown"
    );
}

#[test]
fn declared_type_overrides_usage() {
    let mut v: VariableUsage = VariableUsage::new("x").with_declared_type("u32");
    v.observe(Obs::StringConcat);
    assert_eq!(v.infer(), InferredType::Integer);
}

#[test]
fn declared_type_parser_accepts_case_variants_without_usage() {
    let string_v: VariableUsage = VariableUsage::new("s").with_declared_type(" Const Char* ");
    let pointer_v: VariableUsage = VariableUsage::new("p").with_declared_type("VOID *");
    let array_v: VariableUsage = VariableUsage::new("items").with_declared_type("Widget[]");
    assert_eq!(string_v.infer(), InferredType::String);
    assert_eq!(pointer_v.infer(), InferredType::Pointer);
    assert_eq!(
        array_v.infer(),
        InferredType::Array(Box::new(InferredType::Unknown))
    );
}

#[test]
fn oversized_declared_type_is_not_classified() {
    let huge_declared: String = "u32".repeat(100);
    let v: VariableUsage = VariableUsage::new("x").with_declared_type(huge_declared);
    assert!(v.infer().is_unknown());
}

#[test]
fn return_type_flows_from_return_value_usage() {
    let func: FunctionUsage =
        FunctionUsage::new("compute").returning(var("rv", &[Obs::IntegerArith, Obs::ShiftArith]));
    assert_eq!(func.infer_return_type(), InferredType::Integer);
}

#[test]
fn missing_return_value_is_unknown_return() {
    let func: FunctionUsage = FunctionUsage::new("noret");
    assert!(func.infer_return_type().is_unknown());
}

#[test]
fn signatures_emit_obvious_types_and_null_for_ambiguous() {
    let engine: UsageInferenceEngine = UsageInferenceEngine::new().function(
        FunctionUsage::new("build_label")
            .parameter(var("prefix", &[Obs::StringConcat]))
            .parameter(var("count", &[Obs::IntegerArith]))
            .parameter(var("flag", &[Obs::OrderedComparison]))
            .returning(var("out", &[Obs::StringConcat])),
    );
    let sig: Json = engine.signatures().expect("non-empty");
    let entry: &Json = sig.as_array().unwrap().first().unwrap();
    assert_eq!(entry.get("function").unwrap().as_str(), Some("build_label"));
    assert_eq!(entry.get("return_type").unwrap().as_str(), Some("string"));
    let params: &Vec<Json> = entry.get("parameters").unwrap().as_array().unwrap();
    assert_eq!(params[0].get("type").unwrap().as_str(), Some("string"));
    assert_eq!(params[1].get("type").unwrap().as_str(), Some("int"));
    assert!(
        params[2].get("type").unwrap().is_null(),
        "an ambiguous param must emit a null type, never a confident wrong guess"
    );
}

#[test]
fn empty_engine_emits_nothing() {
    let engine: UsageInferenceEngine = UsageInferenceEngine::new();
    assert!(engine.signatures().is_none());
    assert!(engine.types().is_none());
    assert!(engine.is_empty());
}

#[test]
fn types_emit_named_struct_pointers_only() {
    let engine: UsageInferenceEngine = UsageInferenceEngine::new().function(
        FunctionUsage::new("walk")
            .parameter(var("node", &[Obs::FieldAccess, Obs::FieldAccess]))
            .parameter(var("i", &[Obs::IntegerArith])),
    );
    let types: Json = engine.types().expect("a struct pointer must surface");
    let named: &Vec<Json> = types.get("named_types").unwrap().as_array().unwrap();
    assert_eq!(named.len(), 1);
    assert_eq!(named[0].get("name").unwrap().as_str(), Some("walk::node"));
    assert_eq!(named[0].get("shape").unwrap().as_str(), Some("struct*"));
}

#[test]
fn emits_through_standard_metadata_envelope() {
    let engine: UsageInferenceEngine = UsageInferenceEngine::new().function(
        FunctionUsage::new("concat_names")
            .parameter(var("a", &[Obs::StringConcat]))
            .parameter(var("b", &[Obs::StringConcat]))
            .returning(var("out", &[Obs::StringConcat])),
    );
    let sel: disrobe_llm_metadata::MetadataSelection = SelectionBuilder::new()
        .category(Category::Signatures)
        .category(Category::Types)
        .build();
    let bundle: Json = engine.emit_metadata(&sel);

    let sig_env: &Json = bundle.get("signatures").expect("signatures present");
    assert_eq!(sig_env.get("applicable").unwrap().as_bool(), Some(true));
    assert_eq!(
        sig_env.get("pass").unwrap().as_str(),
        Some("disrobe-resym-usage-inference")
    );
    let sig_val: &Json = sig_env.get("value").unwrap();
    assert_eq!(
        sig_val.as_array().unwrap()[0]
            .get("return_type")
            .unwrap()
            .as_str(),
        Some("string")
    );

    let types_env: &Json = bundle.get("types").expect("types present");
    assert_eq!(
        types_env.get("applicable").unwrap().as_bool(),
        Some(false),
        "no struct pointers here, so types is supported-but-empty"
    );
    assert!(
        types_env
            .get("reason")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("produced no data")
    );
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage_inference_expected.json")
}

#[test]
fn graded_against_hand_labeled_fixture() {
    let bytes: Vec<u8> = std::fs::read(fixture_root()).expect("read fixture");
    let fixture: Json = serde_json::from_slice(&bytes).expect("fixture parses");
    let cases: &Vec<Json> = fixture.get("cases").unwrap().as_array().unwrap();

    let mut correct: usize = 0;
    let mut ambiguous_to_unknown: usize = 0;
    let mut ambiguous_total: usize = 0;
    let total: usize = cases.len();

    for case in cases {
        let name: &str = case.get("var").unwrap().as_str().unwrap();
        let obs: Vec<UsageObservation> = case
            .get("observations")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|o: &Json| serde_json::from_value(o.clone()).expect("known observation"))
            .collect();
        let expected: &str = case.get("expected").unwrap().as_str().unwrap();

        let v: VariableUsage = var(name, &obs);
        let got: Option<String> = v.infer().native();
        let got_label: &str = got.as_deref().map_or("unknown", |value: &str| value);

        let is_ambiguous: bool = expected == "unknown";
        if is_ambiguous {
            ambiguous_total += 1;
            if got_label == "unknown" {
                ambiguous_to_unknown += 1;
            }
        }
        assert_eq!(
            got_label, expected,
            "case `{name}` ({obs:?}): inferred `{got_label}`, hand-labeled `{expected}`"
        );
        if got_label == expected {
            correct += 1;
        }
    }

    assert_eq!(correct, total, "every hand-labeled case must match");
    assert_eq!(
        ambiguous_to_unknown, ambiguous_total,
        "every genuinely-ambiguous case must resolve to Unknown, never a confident guess"
    );
    assert!(ambiguous_total > 0, "fixture must include ambiguous cases");
}
