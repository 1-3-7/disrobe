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
const LOOP_REFUSAL: &str = "decompile-error: the structured body keeps 0 loops but the bytecode \
                            holds 1 separate loop cycles";

fn assert_recovers(label: &str, program: &str, required: &[&str], refused_on: &[&str]) {
    let band: Vec<BandInterpreter> = resolve_band(STABLE_VERSIONS, &[]);
    let resolved: Vec<&str> = band
        .iter()
        .map(|interpreter: &BandInterpreter| interpreter.alias)
        .collect();
    assert_eq!(
        resolved.as_slice(),
        STABLE_VERSIONS,
        "{label}: loop and handler recovery requires CPython 3.8 through 3.14"
    );
    let scratch: PathBuf = band_scratch(label);
    let mut failures: Vec<String> = Vec::new();
    for interpreter in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interpreter, program, label, &scratch);
        if refused_on.contains(&interpreter.alias) {
            if !source.contains(LOOP_REFUSAL) {
                failures.push(format!(
                    "py{}: expected the typed loop refusal, got {outcome:?}\n--- recovered:\n{source}",
                    interpreter.alias
                ));
            }
            continue;
        }
        if !matches!(outcome, BandOutcome::RecompileEquiv) {
            failures.push(format!(
                "py{}: expected recompile-equivalence, got {outcome:?}\n--- recovered:\n{source}",
                interpreter.alias
            ));
            continue;
        }
        let missing: Vec<&&str> = required
            .iter()
            .filter(|fragment: &&&str| !source.contains(**fragment))
            .collect();
        if !missing.is_empty() {
            failures.push(format!(
                "py{}: recovered source lost {missing:?}\n--- recovered:\n{source}",
                interpreter.alias
            ));
        }
    }
    assert!(failures.is_empty(), "{label}:\n{}", failures.join("\n\n"));
}

#[test]
fn a_named_handler_break_leaves_an_infinite_while() {
    assert_recovers(
        "named_handler_break_while_true",
        concat!(
            "def f(read, sink):\n",
            "    while True:\n",
            "        try:\n",
            "            sink(read())\n",
            "        except LookupError as error:\n",
            "            sink(error)\n",
            "            break\n",
            "    return 1\n",
        ),
        &["while True:", "except LookupError as error:"],
        &[],
    );
}

#[test]
fn a_named_handler_break_before_a_returning_tail_stays_a_break() {
    assert_recovers(
        "named_handler_break_return_tail",
        concat!(
            "def f(n, read, sink):\n",
            "    while n < 10:\n",
            "        try:\n",
            "            sink(read(n))\n",
            "        except LookupError as error:\n",
            "            break\n",
            "        n += 1\n",
            "    return n\n",
        ),
        &["while n < 10:", "except LookupError as error:", "break"],
        &[],
    );
}

#[test]
fn a_named_handler_break_ending_the_function_keeps_the_while() {
    assert_recovers(
        "named_handler_break_function_end",
        concat!(
            "def f(active, read, sink):\n",
            "    while active():\n",
            "        try:\n",
            "            sink(read())\n",
            "        except LookupError as error:\n",
            "            sink(error)\n",
            "            break\n",
        ),
        &["while active():", "except LookupError as error:", "break"],
        &["3.12", "3.13"],
    );
}

#[test]
fn a_for_try_body_ending_in_break_keeps_the_break() {
    assert_recovers(
        "for_try_body_break",
        concat!(
            "def f(xs, g, h):\n",
            "    for x in xs:\n",
            "        try:\n",
            "            g(x)\n",
            "            break\n",
            "        except ValueError:\n",
            "            h(x)\n",
            "    h(None)\n",
        ),
        &["for x in xs:", "except ValueError:", "break"],
        &[],
    );
}

#[test]
fn a_while_try_body_ending_in_break_keeps_the_break_or_is_refused() {
    assert_recovers(
        "while_try_body_break",
        concat!(
            "def f(active, g, h):\n",
            "    while active():\n",
            "        try:\n",
            "            g()\n",
            "            break\n",
            "        except ValueError:\n",
            "            h()\n",
            "    h(None)\n",
        ),
        &["while active():", "except ValueError:", "break"],
        &["3.12", "3.13", "3.14"],
    );
}

#[test]
fn a_break_before_an_inlined_return_tail_stays_a_break() {
    assert_recovers(
        "try_body_break_inlined_return",
        concat!(
            "def f(xs, g, h):\n",
            "    for x in xs:\n",
            "        try:\n",
            "            g(x)\n",
            "            break\n",
            "        except ValueError:\n",
            "            pass\n",
            "    return h\n",
        ),
        &["for x in xs:", "break", "return h"],
        &[],
    );
}

#[test]
fn statements_after_an_async_with_inside_a_try_stay_in_the_try() {
    assert_recovers(
        "async_with_in_try_tail",
        concat!(
            "async def f(m, g, h):\n",
            "    try:\n",
            "        async with m:\n",
            "            await g()\n",
            "        h()\n",
            "    except ValueError:\n",
            "        h(1)\n",
            "\n",
            "async def k(m, g, h):\n",
            "    try:\n",
            "        async with m:\n",
            "            await g()\n",
            "        h()\n",
            "    except ValueError:\n",
            "        h(1)\n",
            "    h(2)\n",
        ),
        &["async with m:", "h()", "h(2)"],
        &[],
    );
}

#[test]
fn a_statement_after_a_try_holding_a_with_stays_after_the_try() {
    assert_recovers(
        "with_in_try_then_statement",
        concat!(
            "def f(m, g, h):\n",
            "    try:\n",
            "        with m:\n",
            "            g()\n",
            "        h()\n",
            "    except ValueError:\n",
            "        h(1)\n",
            "    h(2)\n",
        ),
        &["with m:", "except ValueError:", "h(2)"],
        &[],
    );
}

#[test]
fn a_for_loop_before_a_with_keeps_its_loop() {
    assert_recovers(
        "for_before_with",
        concat!(
            "def f(xs, m, g):\n",
            "    for x in xs:\n",
            "        g(x)\n",
            "    with m:\n",
            "        g(0)\n",
            "\n",
            "def k(xs, m, g):\n",
            "    for x in xs:\n",
            "        g(x)\n",
            "    with m as v:\n",
            "        g(v)\n",
            "    return 1\n",
        ),
        &["for x in xs:", "with m:", "with m as v:"],
        &[],
    );
}

#[test]
fn an_explicit_return_none_after_a_breaking_loop_is_kept() {
    assert_recovers(
        "explicit_return_none_after_break",
        concat!(
            "def f(xs, g):\n",
            "    for x in xs:\n",
            "        g(x)\n",
            "        break\n",
            "    return None\n",
            "\n",
            "def k(xs, g):\n",
            "    for x in xs:\n",
            "        if g(x):\n",
            "            g(0)\n",
            "            break\n",
            "    return None\n",
        ),
        &["for x in xs:", "break"],
        &[],
    );
}

#[test]
fn a_while_loop_ending_the_function_is_not_wrapped_in_its_entry_test() {
    assert_recovers(
        "while_function_end",
        concat!("def f(a, g):\n", "    while a():\n", "        g()\n",),
        &["while a():"],
        &[],
    );
}

#[test]
fn a_continue_inside_a_named_handler_stays_in_the_handler() {
    assert_recovers(
        "named_handler_continue",
        concat!(
            "def f(items, read, sink):\n",
            "    for item in items:\n",
            "        try:\n",
            "            value = read(item)\n",
            "        except LookupError as error:\n",
            "            sink(error)\n",
            "            continue\n",
            "        sink(value)\n",
            "    sink('done')\n",
            "\n",
            "def k(items, read, sink):\n",
            "    for item in items:\n",
            "        try:\n",
            "            value = read(item)\n",
            "        except LookupError as error:\n",
            "            continue\n",
            "        sink(value)\n",
            "    sink('done')\n",
        ),
        &["except LookupError as error:", "continue"],
        &[],
    );
}

#[test]
fn a_statement_after_a_named_handler_stays_inside_the_loop_once() {
    assert_recovers(
        "named_handler_then_statement",
        concat!(
            "def f(items, read, sink):\n",
            "    for item in items:\n",
            "        try:\n",
            "            value = read(item)\n",
            "        except LookupError as error:\n",
            "            sink(error)\n",
            "        sink(value)\n",
            "    sink('done')\n",
        ),
        &["for item in items:", "except LookupError as error:"],
        &[],
    );
}

#[test]
fn a_compare_headed_while_with_a_breaking_handler_keeps_its_header() {
    assert_recovers(
        "compare_while_handler_break",
        concat!(
            "def f(n, read, sink):\n",
            "    while n < 10:\n",
            "        try:\n",
            "            sink(read(n))\n",
            "        except LookupError:\n",
            "            break\n",
            "        n += 1\n",
            "    return n\n",
        ),
        &["while n < 10:", "except LookupError:", "break"],
        &[],
    );
}

#[test]
fn a_conditional_break_inside_a_handler_stays_in_the_handler() {
    assert_recovers(
        "handler_conditional_break",
        concat!(
            "def f(items, read, fatal, sink):\n",
            "    for item in items:\n",
            "        try:\n",
            "            sink(read(item))\n",
            "        except LookupError:\n",
            "            if fatal(item):\n",
            "                break\n",
            "            sink(None)\n",
            "    sink('done')\n",
        ),
        &["except LookupError:", "if fatal(item):", "break"],
        &[],
    );
}

#[test]
fn listed_loop_and_with_shapes_recompile() {
    assert_recovers(
        "listed_loop_with_shapes",
        concat!(
            "def with_break(xs, m, g):\n",
            "    for x in xs:\n",
            "        with m:\n",
            "            g(x)\n",
            "            break\n",
            "\n",
            "def for_else_try(xs, g):\n",
            "    for x in xs:\n",
            "        try:\n",
            "            g(x)\n",
            "        except ValueError:\n",
            "            pass\n",
            "        else:\n",
            "            break\n",
            "    else:\n",
            "        return 1\n",
            "    return 0\n",
            "\n",
            "def with_in_try(m, g, h):\n",
            "    try:\n",
            "        with m:\n",
            "            g()\n",
            "        h()\n",
            "    except ValueError:\n",
            "        pass\n",
            "\n",
            "def comprehension_in_for(xs, g):\n",
            "    for x in xs:\n",
            "        ys = [y for y in x]\n",
            "        g(ys)\n",
            "\n",
            "def return_after_with(m, g):\n",
            "    with m as v:\n",
            "        g(v)\n",
            "    return v\n",
        ),
        &["with m:", "else:", "ys = [y for y in x]", "return v"],
        &[],
    );
}

#[test]
fn a_loop_inside_a_finally_is_counted_once_across_its_two_copies() {
    assert_recovers(
        "finally_loop_counted_once",
        concat!(
            "def suspend(self, fields, restore, prepare):\n",
            "    prev_state = {f: getattr(self, f) for f in fields}\n",
            "    try:\n",
            "        restore()\n",
            "        yield None\n",
            "    finally:\n",
            "        for arg in (\"msg\", \"ps1\", \"ps2\"):\n",
            "            setattr(self, arg, prev_state[arg])\n",
            "        prepare()\n",
        ),
        &["finally:", "for arg in"],
        &[],
    );
}
