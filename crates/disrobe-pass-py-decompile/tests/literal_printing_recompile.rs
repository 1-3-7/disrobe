#![allow(clippy::panic, clippy::print_stderr, clippy::print_stdout)]

mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const ALL_STABLE: &[&str] = &["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"];

fn assert_recompiles(label: &str, versions: &[&'static str], program: &str) {
    let band: Vec<BandInterpreter> = resolve_band(versions, &[]);
    let missing: Vec<&str> = versions
        .iter()
        .copied()
        .filter(|v: &&str| !band.iter().any(|i: &BandInterpreter| i.alias == *v))
        .collect();
    assert!(
        missing.is_empty(),
        "{label}: CPython {missing:?} not installed; install with `uv python install {}`",
        missing.join(" ")
    );
    let scratch: PathBuf = band_scratch(label);
    let mut failures: Vec<String> = Vec::new();
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {}
            BandOutcome::Tolerated(reason) | BandOutcome::Failed(reason) => {
                failures.push(format!(
                    "py{}: {reason}\n--- recovered:\n{source}",
                    interp.alias
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{label}: {} of {} interpreters differ\n{}",
        failures.len(),
        band.len(),
        failures.join("\n")
    );
}

#[test]
fn big_integer_constants_print_at_full_precision() {
    assert_recompiles(
        "big_int",
        ALL_STABLE,
        "P = 57896044618658097711785492504343953926634992332820282019728792003956564819949\n\
         Q = -340282366920938463463374607431768211457\n\
         R = 2 ** 100 - 19\n\
         S = (1 << 127) + 1\n",
    );
}

#[test]
fn integers_past_the_decimal_literal_limit_still_recompile() {
    let program: String = format!("W = 0x{}\n", "f".repeat(4000));
    assert_recompiles("wide_int", ALL_STABLE, &program);
}

#[test]
fn integral_floats_beyond_1e16_stay_floats() {
    assert_recompiles(
        "float_repr",
        ALL_STABLE,
        "A = 1e16\nB = 1e22\nC = 1.5e300\nD = 1e-05\nE = 123456789012345678.0\n\
         F = -0.0\nG = 1e309\nH = 2.5e-320\nI = 1e20j\n",
    );
}

#[test]
fn negative_constant_power_base_keeps_parentheses() {
    assert_recompiles(
        "neg_pow_base",
        ALL_STABLE,
        "def f(n):\n    return (-1) ** n\n\ndef g(n):\n    return (-2.5) ** n\n",
    );
}

#[test]
fn negative_constant_attribute_receiver_keeps_parentheses() {
    assert_recompiles(
        "neg_attr_receiver",
        ALL_STABLE,
        "def f():\n    return (-2.5).hex()\n\ndef g():\n    return (-1).bit_length()\n\n\
         def h():\n    return (-(2 ** 200)).bit_length()\n",
    );
}

#[test]
fn lone_formatted_value_uses_a_delimiter_its_field_allows() {
    assert_recompiles(
        "lone_format_value",
        ALL_STABLE,
        "def f(d):\n    return f\"{d['k']}\"\n\ndef g(d, w):\n    return f\"{d['k']:>{w}}\"\n",
    );
}

#[test]
fn positional_only_defaults_index_from_the_first_positional() {
    assert_recompiles(
        "posonly_defaults",
        ALL_STABLE,
        "def f(a, b=1, /, c=2):\n    return (a, b, c)\n\n\
         def g(a=3, /, b=4, c=5):\n    return (a, b, c)\n",
    );
}

#[test]
fn keyword_call_inside_comprehension_keeps_its_keywords() {
    assert_recompiles(
        "comp_kw_names",
        ALL_STABLE,
        "def f(g, y):\n    return list((g(x, key=1) for x in y))\n\n\
         def h(g, y):\n    return [g(x, key=x, other=2) for x in y]\n",
    );
}

#[test]
fn calls_with_more_than_255_arguments_keep_every_argument() {
    let args: String = (0..300)
        .map(|i: i32| format!("a{}", i % 7))
        .collect::<Vec<String>>()
        .join(", ");
    let program: String = format!(
        "def f(g, a0, a1, a2, a3, a4, a5, a6):\n    return g({args})\n\n\
         def m(o, a0, a1, a2, a3, a4, a5, a6):\n    return o.m({args})\n"
    );
    assert_recompiles("call_argc_u32", ALL_STABLE, &program);
}
