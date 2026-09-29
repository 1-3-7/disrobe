#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const STABLE_VERSIONS: &[&str] = &["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_recompiles(label: &str, program: &str) {
    assert_recompiles_on(label, program, STABLE_VERSIONS, PRERELEASE);
}

fn assert_recompiles_on(
    label: &str,
    program: &str,
    versions: &[&'static str],
    prerelease: &[&'static str],
) {
    let band: Vec<BandInterpreter> = resolve_band(versions, prerelease);
    assert!(
        !band.is_empty(),
        "{label}: no requested CPython interpreter installed; cannot prove recompile-equivalence"
    );
    let scratch: PathBuf = band_scratch(label);
    let mut checked_stable: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {
                if !interp.is_prerelease {
                    checked_stable += 1;
                }
            }
            BandOutcome::Tolerated(_) if interp.is_prerelease => {}
            BandOutcome::Failed(reason) if interp.is_prerelease => {
                eprintln!("SKIP prerelease {label} py{}: {reason}", interp.alias);
            }
            other => failures.push(format!(
                "py{}: expected recompile-equivalence, got {other:?}\n--- recovered:\n{source}",
                interp.alias
            )),
        }
        assert!(
            !source.contains("__DR_"),
            "{label} py{}: unrecovered marker leaked in:\n{source}",
            interp.alias
        );
    }
    assert!(failures.is_empty(), "{label}:\n{}", failures.join("\n\n"));
    assert!(
        checked_stable > 0,
        "{label}: no stable interpreter validated the recovery (vacuous)"
    );
}

#[test]
fn nested_conditional_break_before_a_returning_loop_exit() {
    assert_recompiles(
        "nested_conditional_break_return_tail",
        "def f(xs, a, b, c):\n    for x in xs:\n        if a(x):\n            if b(x):\n                break\n            c(x)\n    return 0\n",
    );
}

#[test]
fn trailing_conditional_break_after_a_statement() {
    assert_recompiles(
        "statement_then_conditional_break_return_tail",
        "def f(xs, b, c):\n    for x in xs:\n        c(x)\n        if b(x):\n            break\n    c(0)\n",
    );
}

#[test]
fn conditional_break_in_a_while_loop_before_a_returning_exit() {
    assert_recompiles(
        "while_conditional_break_return_tail",
        "def f(it, b, c):\n    while it.more():\n        v = it.next()\n        if b(v):\n            break\n        c(v)\n    return it.total\n",
    );
}

#[test]
fn guarded_break_inside_a_guard_before_an_inlined_return() {
    assert_recompiles(
        "guarded_break_inside_guard_inlined_return",
        "def f(xs, a, b, g):\n    for x in xs:\n        if a(x):\n            g(x)\n            if b(x):\n                break\n    return 1\n",
    );
}

#[test]
fn short_circuit_break_test_keeps_both_operands() {
    assert_recompiles(
        "short_circuit_break_keeps_operands",
        "def f(xs, a, b, g):\n    for x in xs:\n        g(x)\n        if a(x) or b(x):\n            break\n    g(0)\n",
    );
}

#[test]
fn chained_comparison_guard_after_a_handled_call_keeps_its_test() {
    assert_recompiles_on(
        "chained_comparison_guard_in_loop",
        "def getnode(getters):\n    node = None\n    for getter in getters:\n        try:\n            node = getter()\n        except:\n            continue\n        if node is not None and 0 <= node < 281474976710656:\n            return node\n    return None\n",
        &["3.8", "3.9"],
        &[],
    );
}

#[test]
fn a_break_after_a_statement_before_a_returning_exit_stays_a_break() {
    assert_recompiles(
        "break_after_statement_returning_exit",
        "def f(xs, a, g):\n    for x in xs:\n        if a(x):\n            g(x)\n            break\n    return 0\n",
    );
}

#[test]
fn an_unconditional_break_before_a_returning_exit_stays_a_break() {
    assert_recompiles(
        "unconditional_break_returning_exit",
        "def f(xs, g):\n    for x in xs:\n        g(x)\n        break\n    return g\n",
    );
}

#[test]
fn a_break_in_an_else_arm_before_a_returning_exit_stays_a_break() {
    assert_recompiles(
        "else_arm_break_returning_exit",
        "def f(xs, a, g):\n    for x in xs:\n        if a(x):\n            g(x)\n        else:\n            break\n    return 1\n",
    );
}

#[test]
fn a_break_in_the_last_arm_of_an_elif_chain_stays_a_break() {
    assert_recompiles(
        "elif_chain_else_break_returning_exit",
        "def f(xs, a, g, h):\n    for x in xs:\n        if a(x):\n            g(x)\n        elif h(x):\n            h(g)\n        else:\n            break\n    return g\n",
    );
}

#[test]
fn an_unconditional_break_ending_a_for_else_body_keeps_the_else() {
    assert_recompiles(
        "unconditional_break_for_else",
        "def f(xs, g, h):\n    for x in xs:\n        g(x)\n        break\n    else:\n        h()\n    return g\n",
    );
}

#[test]
fn an_inner_loop_ending_in_a_break_stays_a_loop() {
    assert_recompiles(
        "inner_loop_unconditional_break",
        "def f(ys, xs, g, h):\n    for y in ys:\n        for x in xs:\n            g(x)\n            break\n        h(y)\n    return 0\n",
    );
}

#[test]
fn an_unconditional_break_before_a_statement_tail_stays_a_break() {
    assert_recompiles(
        "unconditional_break_statement_tail",
        "def f(xs, g):\n    for x in xs:\n        g(x)\n        break\n    g(0)\n",
    );
}

#[test]
fn a_return_in_a_loop_before_an_equal_exit_stays_a_return() {
    assert_recompiles_on(
        "return_before_equal_exit",
        "def f(xs, a, g):\n    for x in xs:\n        if a(x):\n            g(x)\n            return 1\n    return 1\n",
        &["3.8", "3.9"],
        &[],
    );
}

#[test]
fn an_unconditional_break_ending_a_while_body_stays_a_break() {
    assert_recompiles_on(
        "while_unconditional_break",
        "def f(it, g):\n    while it.more():\n        g(it)\n        break\n    return g\n",
        &["3.8", "3.9"],
        &[],
    );
}

#[test]
fn an_unconditional_break_ending_an_infinite_while_body_stays_a_break() {
    assert_recompiles(
        "infinite_while_unconditional_break",
        "def f(g):\n    while True:\n        g(1)\n        break\n    return g\n",
    );
}

#[test]
fn a_break_in_an_else_arm_before_an_implicit_return_stays_a_break() {
    assert_recompiles(
        "else_arm_break_implicit_return",
        "def f(xs, a, g):\n    for x in xs:\n        if a(x):\n            g(x)\n        else:\n            break\n",
    );
}

#[test]
fn a_break_after_a_with_block_stays_a_break() {
    assert_recompiles(
        "break_after_with",
        "def f(xs, m, g):\n    for x in xs:\n        with m:\n            g(x)\n        break\n    return 1\n",
    );
}

#[test]
fn a_while_loop_ending_in_a_break_stays_a_loop() {
    assert_recompiles(
        "while_ending_in_break",
        "def f(n, g):\n    while n > 0:\n        g(n)\n        n -= 1\n        break\n    return n\n",
    );
}

#[test]
fn a_break_ending_an_except_handler_stays_a_break() {
    assert_recompiles(
        "break_ending_except_handler",
        "def f(xs, g):\n    for x in xs:\n        try:\n            g(x)\n        except ValueError:\n            break\n    return 0\n",
    );
}

#[test]
fn a_try_else_ending_in_a_break_keeps_the_for_else() {
    assert_recompiles(
        "try_else_break_for_else",
        "def f(xs, g, h):\n    for x in xs:\n        try:\n            g(x)\n        except ValueError:\n            pass\n        else:\n            break\n    else:\n        h()\n    return 0\n",
    );
}

#[test]
fn a_break_ending_a_named_except_handler_stays_a_break() {
    assert_recompiles(
        "break_ending_named_except_handler",
        "def f(xs, g):\n    for x in xs:\n        try:\n            g(x)\n        except ValueError as e:\n            g(e)\n            break\n    return 0\n",
    );
}
