#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{PackerDecode, PackerDetection, detect_packer, unpack_packer};

const GROUND_TRUTH: &str = include_str!("../../../corpus/js/packer/real/ground-truth.js");
const SINGLE: &str = include_str!("../../../corpus/js/packer/real/single-layer.packed.js");
const DOUBLE: &str = include_str!("../../../corpus/js/packer/real/double-layer.packed.js");
const TRIPLE: &str = include_str!("../../../corpus/js/packer/real/triple-layer.packed.js");

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

fn re_evals_equivalent(label: &str, recovered: &str) {
    let want: String =
        eval_console(GROUND_TRUTH).unwrap_or_else(|| panic!("{label}: ground truth must evaluate"));
    let got: String = eval_console(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must re-evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered behavior diverged from ground truth\n--want--\n{want}\n--got--\n{got}"
    );
}

#[test]
fn ground_truth_and_packed_samples_are_behaviorally_identical() {
    let truth: String = eval_console(GROUND_TRUTH).expect("ground truth evals");
    let single_live: String = eval_console(SINGLE).expect("single-layer evals");
    let double_live: String = eval_console(DOUBLE).expect("double-layer evals");
    assert_eq!(
        truth, single_live,
        "the real single-layer packer fixture must run identically to its source"
    );
    assert_eq!(
        truth, double_live,
        "the real double-layer packer fixture must run identically to its source"
    );
}

#[test]
fn single_layer_recovers_to_one_unpacked_layer() {
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
    re_evals_equivalent("single-layer", &recovered);
}

#[test]
fn double_layer_recovers_through_both_nested_packers() {
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
    re_evals_equivalent("double-layer", &recovered);
}

#[test]
fn triple_layer_recovers_through_three_nested_packers() {
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
    re_evals_equivalent("triple-layer", &recovered);
}

#[test]
fn non_packer_input_reports_no_layers() {
    let plain: &str = "function add(a, b) { return a + b; }";
    let decode: PackerDecode = unpack_packer(plain);
    assert!(!decode.detection.matched);
    assert_eq!(decode.detection.layers, 0);
    assert!(decode.recovered.is_none());
}
