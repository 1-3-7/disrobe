#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::literal_string_with_formatting_args
)]

//! Recompile-equivalence coverage for Python decompilation edge cases drawn from other decompilers' documented bug histories.

mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const TARGET_VERSIONS: &[&str] = &["3.12", "3.13", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_recompiles(label: &str, program: &str) {
    let band: Vec<BandInterpreter> = resolve_band(TARGET_VERSIONS, PRERELEASE);
    assert!(
        !band.is_empty(),
        "{label}: no 3.12-3.15 interpreter installed; cannot prove recompile-equivalence. \
         Install one (uv python install 3.14) - never silently pass."
    );
    let scratch: PathBuf = band_scratch(label);
    let mut checked_stable: usize = 0;
    let mut tolerated_prerelease: usize = 0;
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {
                if !interp.is_prerelease {
                    checked_stable += 1;
                }
            }
            BandOutcome::SourceTokenMatch => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: token-match in an interpreter-present band is not allowed; \
                     expected recompile-equivalence\n--- recovered:\n{source}",
                    interp.alias
                );
            }
            BandOutcome::Tolerated(detail) => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: Tolerated outcome from a stable interpreter is a real failure: \
                     {detail}\n--- recovered:\n{source}",
                    interp.alias
                );
                tolerated_prerelease += 1;
            }
            BandOutcome::Failed(reason) => {
                if interp.is_prerelease {
                    eprintln!("SKIP prerelease {label} py{}: {reason}", interp.alias);
                } else {
                    panic!(
                        "{label} py{}: {reason}\n--- recovered:\n{source}",
                        interp.alias
                    );
                }
            }
        }
        assert!(
            !source.contains("__DR_"),
            "{label} py{}: unrecovered marker leaked in:\n{source}",
            interp.alias
        );
    }
    if tolerated_prerelease > 0 {
        eprintln!("{label}: {tolerated_prerelease} prerelease CodeDiff(s) tolerated (non-gating)");
    }
    assert!(
        checked_stable > 0,
        "{label}: no stable interpreter validated the recovery (vacuous)"
    );
}

#[test]
fn empty_body_try_simple_except() {
    assert_recompiles(
        "edge_empty_try_simple",
        "def f():\n    try:\n        pass\n    except ValueError:\n        x = 1\n    return 0\n",
    );
}

#[test]
fn empty_body_try_except_as_with_body() {
    assert_recompiles(
        "edge_empty_try_except_as",
        "def f(log):\n    try:\n        pass\n    except ValueError as e:\n        log(e)\n",
    );
}

#[test]
fn empty_body_try_raise_from() {
    assert_recompiles(
        "edge_empty_try_raise_from",
        "def f():\n    try:\n        pass\n    except ValueError as e:\n        raise RuntimeError('x') from e\n",
    );
}

#[test]
fn empty_body_try_two_handlers_and_continuation() {
    assert_recompiles(
        "edge_empty_try_two_handlers",
        "def f():\n    try:\n        pass\n    except ValueError:\n        x = 1\n    except KeyError:\n        x = 2\n    y = 3\n    return y\n",
    );
}

#[test]
fn empty_body_try_module_level() {
    assert_recompiles(
        "edge_empty_try_module",
        "try:\n    pass\nexcept ImportError:\n    fallback = 1\n",
    );
}

#[test]
fn empty_body_except_star_tuple() {
    assert_recompiles(
        "edge_empty_except_star",
        "def f():\n    try:\n        pass\n    except* (TypeError, KeyError) as e:\n        pass\n",
    );
}

#[test]
fn except_star_multiple_handlers() {
    assert_recompiles(
        "edge_except_star_multi",
        "def f(g):\n    try:\n        g()\n    except* ValueError as e:\n        pass\n    except* (TypeError, KeyError) as e:\n        pass\n",
    );
}

#[test]
fn lambda_body_dict_comprehension() {
    assert_recompiles(
        "edge_lambda_dictcomp",
        "g = lambda seq: {k: k * k for k in seq}\n",
    );
}

#[test]
fn lambda_body_list_comprehension() {
    assert_recompiles(
        "edge_lambda_listcomp",
        "h = lambda seq: [x for x in seq if x > 0]\n",
    );
}

#[test]
fn lambda_body_set_comprehension() {
    assert_recompiles("edge_lambda_setcomp", "s = lambda seq: {x for x in seq}\n");
}

#[test]
fn lambda_returns_none_and_constant() {
    assert_recompiles(
        "edge_lambda_none",
        "f = lambda: None\ng = lambda: True\nh = lambda x: None\n",
    );
}

#[test]
fn lambda_in_default_argument() {
    assert_recompiles(
        "edge_lambda_in_default",
        "def f(cb=lambda x: x + 1):\n    return cb(1)\n",
    );
}

#[test]
fn if_return_falsy_no_short_circuit_fold() {
    assert_recompiles(
        "edge_if_return_falsy",
        "def falsy_x(cond):\n    x = 1\n    if cond:\n        return x\n    return 0\n\ndef none_x(cond):\n    if cond:\n        return\n    return 'fallback'\n\ndef real_short_circuit(cond, x):\n    return cond and x\n",
    );
}

#[test]
fn keyword_argument_call_shapes() {
    assert_recompiles(
        "edge_kw_names",
        "def func(*a, **kw):\n    return (a, kw)\nsingle = func(b=2)\nmixed_one = func(1, b=2)\nmixed_many = func(1, 2, a=3, b=4)\nmany_kwargs = dict(a=1, b=2, c=3)\nbuiltin = print('hi', end='', flush=True)\n",
    );
}

#[test]
fn big_list_set_dict_with_leading_name() {
    assert_recompiles(
        "edge_big_collections",
        "a = '0'\nb = 'x'\nlst = [a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]\nbig_set = {a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}\nbig_dict = {a: 0, 'k1': 1, 'k15': b, 'k16': 16}\n",
    );
}

#[test]
fn free_variable_with_inner_import() {
    assert_recompiles(
        "edge_freevar_import",
        "def func(a, b):\n    import c\n    a.f = lambda: c(a, b)\n\ndef with_local(x, y):\n    z = x + y\n    def inner():\n        return (z, x)\n    return inner\n",
    );
}

#[test]
fn match_guard_with_capture_patterns() {
    assert_recompiles(
        "edge_match_guard_capture",
        "def f(p):\n    match p:\n        case [x, y] if x > y:\n            return x\n        case {'k': v} if v:\n            return v\n        case _ as z:\n            return z\n",
    );
}

#[test]
fn nested_walrus_in_comprehension() {
    assert_recompiles(
        "edge_nested_walrus_comp",
        "def f(data):\n    return [y for x in data if (y := x * 2) > 3]\n",
    );
}

#[test]
fn walrus_in_generator_expression() {
    assert_recompiles(
        "edge_walrus_genexpr",
        "def f(data):\n    return list(y for x in data if (y := x + 1))\n",
    );
}

#[test]
fn positional_only_parameters() {
    assert_recompiles(
        "edge_posonly",
        "def greet(name, /, greeting='Hello'):\n    return greeting + name\n\ndef mixed(a, b, /, c, *, d):\n    return (a, b, c, d)\n",
    );
}

#[test]
fn dict_merge_operators() {
    assert_recompiles(
        "edge_dict_merge",
        "def f(a, b):\n    c = a | b\n    a |= b\n    return (a, c)\n",
    );
}

#[test]
fn union_type_annotations() {
    assert_recompiles(
        "edge_union_types",
        "def f(x: int | str) -> int | None:\n    return None\n",
    );
}

#[test]
fn parenthesized_context_managers() {
    assert_recompiles(
        "edge_paren_with",
        "def f():\n    with (open('a') as x, open('b') as y):\n        return (x, y)\n",
    );
}

#[test]
fn dead_code_after_return() {
    assert_recompiles(
        "edge_dead_code",
        "def f(x):\n    return x\n    x = 1\n    return x\n",
    );
}

#[test]
fn try_except_continue_in_loop() {
    assert_recompiles(
        "edge_try_except_continue",
        "def f(items):\n    total = 0\n    for it in items:\n        try:\n            total += int(it)\n        except ValueError:\n            continue\n    return total\n",
    );
}

#[test]
fn finally_with_return() {
    assert_recompiles(
        "edge_finally_return",
        "def f(x):\n    try:\n        return x\n    finally:\n        x = 0\n",
    );
}

#[test]
fn conditional_import_in_branch() {
    assert_recompiles(
        "edge_conditional_import",
        "def f(flag):\n    if flag:\n        import os\n        return os.getpid()\n    return 0\n",
    );
}

#[test]
fn chained_comparison() {
    assert_recompiles(
        "edge_chained_compare",
        "def f(a, b, c):\n    return a < b < c <= a\n",
    );
}

#[test]
fn generator_with_return_value() {
    assert_recompiles(
        "edge_generator_return",
        "def gen():\n    yield 1\n    return 42\n",
    );
}

#[test]
fn decorator_expression_with_call() {
    assert_recompiles(
        "edge_decorator_expr",
        "import functools\n@functools.lru_cache(maxsize=None)\ndef f(x):\n    return x\n",
    );
}

#[test]
fn nested_fstring_quote_flip() {
    assert_recompiles(
        "edge_nested_fstring",
        "def f(d):\n    return f\"{d['key']!r:>{d['w']}}\"\n",
    );
}

#[test]
fn mixed_boolean_precedence_in_assignment() {
    assert_recompiles(
        "edge_mixed_bool_assign",
        "def f(b, c, d):\n    x = b or c and d\n    return x\n",
    );
}

#[test]
fn mixed_boolean_precedence_and_then_or() {
    assert_recompiles(
        "edge_mixed_bool_and_or",
        "def f(b, c, d):\n    x = b and c or d\n    return x\n",
    );
}

#[test]
fn mixed_boolean_precedence_in_call_argument() {
    assert_recompiles(
        "edge_mixed_bool_arg",
        "def f(b, c, d):\n    return print(b or c and d)\n",
    );
}

#[test]
fn mixed_boolean_precedence_nested_and_or_and() {
    assert_recompiles(
        "edge_mixed_bool_nested",
        "def f(a, b, c, e):\n    z = a and b or c and e\n    return z\n",
    );
}

#[test]
fn mixed_boolean_precedence_deep_chain() {
    assert_recompiles(
        "edge_mixed_bool_deep",
        "def f(a, b, c, d, e, g):\n    return a and b or c and d or e and g\n",
    );
}

#[test]
fn ternary_inside_boolean_test() {
    assert_recompiles(
        "edge_ternary_in_bool",
        "def f(a, b, x, y):\n    return x if a or b else y\n",
    );
}

#[test]
fn ternary_inside_boolean_test_assigned() {
    assert_recompiles(
        "edge_ternary_in_bool_assign",
        "def f(a, b, x, y):\n    z = x if a or b else y\n    return z\n",
    );
}

#[test]
fn fstring_single_part_no_buildstring() {
    assert_recompiles(
        "edge_fstring_single_part",
        "def f(x):\n    return f\"{x}\"\n",
    );
}

#[test]
fn fstring_plain_multi_part() {
    assert_recompiles(
        "edge_fstring_plain_multi",
        "def f(name, count):\n    return f\"{name}: {count}\"\n",
    );
}

#[test]
fn fstring_repr_conversion_single() {
    assert_recompiles(
        "edge_fstring_conv_repr",
        "def f(x):\n    return f\"{x!r}\"\n",
    );
}

#[test]
fn fstring_all_conversions_single_level() {
    assert_recompiles(
        "edge_fstring_all_conv",
        "def f(a, b, c):\n    return f\"{a!s}-{b!r}-{c!a}\"\n",
    );
}

#[test]
fn fstring_constant_format_spec() {
    assert_recompiles(
        "edge_fstring_const_spec",
        "def f(x):\n    return f\"{x:.2f}\"\n",
    );
}

#[test]
fn fstring_conversion_and_nested_spec() {
    assert_recompiles(
        "edge_fstring_conv_nested_spec",
        "def f(x, w):\n    return f\"{x!r:>{w}}\"\n",
    );
}

#[test]
fn fstring_debug_self_documenting() {
    assert_recompiles("edge_fstring_debug_eq", "def f(x):\n    return f\"{x=}\"\n");
}

#[test]
fn fstring_nested_computed_spec() {
    assert_recompiles(
        "edge_fstring_nested_spec",
        "def f(x, w, p):\n    return f\"{x:{w}.{p}f}\"\n",
    );
}

#[test]
fn fstring_adjacent_fields_no_literal() {
    assert_recompiles(
        "edge_fstring_adjacent",
        "def f(a, b):\n    return f\"{a}{b}\"\n",
    );
}

#[test]
fn fstring_nested_fstring_in_field() {
    assert_recompiles(
        "edge_fstring_nested_in_field",
        "def f(x):\n    return f\"{f'{x}'}\"\n",
    );
}
