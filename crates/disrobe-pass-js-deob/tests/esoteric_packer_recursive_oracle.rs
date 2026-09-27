#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{PackerDecode, PackerDetection, detect_packer, unpack_packer};
use sha2::{Digest, Sha256};

const AUTHORED_REFERENCE: &str = include_str!("../../../corpus/js/packer/real/ground-truth.js");
const AUTHORED_REFERENCE_SHA256: &str =
    "737c57e181b1d1c0171b5d600411e919944ca8554cc1a82e528cbb6e7a0725e6";
const REFERENCE_OUTPUT: &str = "Hello, Alice! Welcome aboard.\u{1}Sum is 68";
const SINGLE: &str = include_str!("../../../corpus/js/packer/real/single-layer.packed.js");
const SINGLE_SHA256: &str = "7c27aaa178e1c159a55d04fbda2582a99a301c7bba2138f61330d82f22492a72";
const DOUBLE: &str = include_str!("../../../corpus/js/packer/real/double-layer.packed.js");
const DOUBLE_SHA256: &str = "1261b6f7ca909afcc6cd27de3491f7bb2976ced6c8a2c4b5a8a235585b545486";
const TRIPLE: &str = include_str!("../../../corpus/js/packer/real/triple-layer.packed.js");
const TRIPLE_SHA256: &str = "ce182be3bd2a80d7c4713e9671a0a0d890bf0cdb64edeb3c00735c18d2eacf80";

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 200_000;

fn eval_console(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!(
        "var __out = []; var console = {{ log: function() {{ var parts = []; for (var i = 0; i < arguments.length; i++) {{ parts.push(String(arguments[i])); }} __out.push(parts.join(' ')); }} }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn assert_fixture_identity(label: &str, fixture: &str, expected_sha256: &str) {
    assert_eq!(
        format!("{:x}", Sha256::digest(fixture.as_bytes())),
        expected_sha256,
        "{label}: the tracked fixture changed without revalidating its reference"
    );
}

fn authored_reference_output() -> String {
    assert_fixture_identity(
        "authored reference",
        AUTHORED_REFERENCE,
        AUTHORED_REFERENCE_SHA256,
    );
    let output: String = eval_console(AUTHORED_REFERENCE)
        .expect("the bounded authored reference evaluation must finish");
    assert_eq!(
        output, REFERENCE_OUTPUT,
        "the authored reference must produce its pinned output"
    );
    output
}

fn assert_recovered_behavior(label: &str, recovered: &str) {
    let want: String = authored_reference_output();
    let got: String = eval_console(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must re-evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered behavior diverged from ground truth\n--want--\n{want}\n--got--\n{got}"
    );
    let mutated: String = recovered.replacen("Hello, ", "Goodbye, ", 1);
    assert_ne!(
        mutated, recovered,
        "{label}: recovered output must retain the greeting literal"
    );
    assert_ne!(
        eval_console(&mutated),
        Some(want),
        "{label}: the reference grade must reject a changed recovered greeting"
    );
}

#[test]
fn packed_samples_are_pinned_to_the_authored_reference() {
    let output: String = authored_reference_output();
    assert_fixture_identity("single-layer packed input", SINGLE, SINGLE_SHA256);
    assert_fixture_identity("double-layer packed input", DOUBLE, DOUBLE_SHA256);
    assert_fixture_identity("triple-layer packed input", TRIPLE, TRIPLE_SHA256);
    assert_eq!(output, REFERENCE_OUTPUT);
}

#[test]
fn single_layer_recovers_to_one_unpacked_layer() {
    assert_fixture_identity("single-layer packed input", SINGLE, SINGLE_SHA256);
    let det: PackerDetection = detect_packer(SINGLE);
    assert!(det.matched, "single-layer must detect: {det:?}");

    let decode: PackerDecode = unpack_packer(SINGLE);
    let recovered: String = decode.recovered.expect("single-layer must recover");
    assert_eq!(
        decode.detection.layers, 1,
        "single-layer packer must report exactly one peeled layer"
    );
    assert!(
        !recovered.contains("function(p,a,c,k,e,"),
        "no packer signature may remain after a single peel:\n{recovered}"
    );
    assert!(recovered.contains("function greet"));
    assert!(recovered.contains("function compute"));
    assert_recovered_behavior("single-layer", &recovered);
}

#[test]
fn double_layer_recovers_through_both_nested_packers() {
    assert_fixture_identity("double-layer packed input", DOUBLE, DOUBLE_SHA256);
    let decode: PackerDecode = unpack_packer(DOUBLE);
    let recovered: String = decode.recovered.expect("double-layer must recover");
    assert_eq!(
        decode.detection.layers, 2,
        "double-layer packer must report exactly two peeled layers; got {}",
        decode.detection.layers
    );
    assert!(
        !recovered.contains("function(p,a,c,k,e,"),
        "the inner packer must also be peeled; signature still present:\n{recovered}"
    );
    assert!(recovered.contains("function greet"));
    assert!(recovered.contains("function compute"));
    assert!(recovered.contains("console"));
    assert_recovered_behavior("double-layer", &recovered);
}

#[test]
fn triple_layer_recovers_through_three_nested_packers() {
    assert_fixture_identity("triple-layer packed input", TRIPLE, TRIPLE_SHA256);
    let decode: PackerDecode = unpack_packer(TRIPLE);
    let recovered: String = decode.recovered.expect("triple-layer must recover");
    assert_eq!(
        decode.detection.layers, 3,
        "triple-layer packer must report exactly three peeled layers; got {}",
        decode.detection.layers
    );
    assert!(
        !recovered.contains("function(p,a,c,k,e,"),
        "all three packer layers must be peeled:\n{recovered}"
    );
    assert!(recovered.contains("function greet"));
    assert!(recovered.contains("function compute"));
    assert_recovered_behavior("triple-layer", &recovered);
}

#[test]
fn non_packer_input_reports_no_layers() {
    let plain: &str = "function add(a, b) { return a + b; }";
    let decode: PackerDecode = unpack_packer(plain);
    assert!(!decode.detection.matched);
    assert_eq!(decode.detection.layers, 0);
    assert!(decode.recovered.is_none());
}
