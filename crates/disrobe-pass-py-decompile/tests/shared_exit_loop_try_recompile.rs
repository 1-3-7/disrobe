#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const UUID_FIND_MAC_NEAR_KEYWORD: &str = r#"
def _find_mac_near_keyword(command, args, keywords, get_word_index):
    """Searches a command's output for a MAC address near a keyword.

    Each line of words in the output is case-insensitively searched for
    any of the given keywords. Upon a match, get_word_index is invoked
    to pick a word from the line, given the index of the match.
    """
    stdout = _get_command_stdout(command, args)
    if stdout is None:
        return None
    first_local_mac = None
    for line in stdout:
        words = line.lower().rstrip().split()
        for i in range(len(words)):
            if words[i] in keywords:
                try:
                    word = words[get_word_index(i)]
                    mac = int(word.replace(_MAC_DELIM, b''), 16)
                except (ValueError, IndexError):
                    pass
                else:
                    if _is_universal(mac):
                        return mac
                    first_local_mac = first_local_mac or mac
    return first_local_mac or None
"#;

const LIVE_TRY_ELSE_RETURN: &str = r"
def retain_live_try_else(values):
    for value in values:
        if value is None:
            break
        try:
            check(value)
        except ValueError:
            continue
        else:
            return value
    return None
";

const MULTI_STATEMENT_POST_LOOP_TAIL: &str = r"
def retain_multi_statement_post_loop_tail(values, fallback):
    for value in values:
        try:
            check(value)
        except ValueError:
            return fallback
        else:
            return fallback
    record(fallback)
    return fallback
";

const FOR_TRY_EXCEPT: &str = r"
def for_try_except(values, fallback):
    for value in values:
        try:
            probe(value)
        except ValueError:
            pass
    return fallback
";

const ASYNC_FOR_TRY_EXCEPT: &str = r"
async def async_for_try_except(values, fallback):
    async for value in values:
        try:
            await probe(value)
        except ValueError:
            pass
    return fallback
";

const WHILE_LOOP: &str = r"
def while_loop(index, limit, fallback):
    while index < limit:
        index = index + 1
    return fallback
";

const INFINITE_LOOP: &str = r"
def infinite_loop(data, index, fallback):
    while True:
        value = data[index]
        if not value:
            return fallback
        if value.isspace():
            index = index + 1
        else:
            break
    data.mark(index)
    return fallback
";

const FOR_TRY_ELSE: &str = r"
def for_try_else(values, fallback):
    for value in values:
        try:
            probe(value)
        except ValueError:
            pass
        else:
            observe(value)
    return fallback
";

const FOR_TRY_FINALLY: &str = r"
def for_try_finally(values, fallback):
    for value in values:
        try:
            probe(value)
        finally:
            cleanup(value)
    return fallback
";

const FOR_TRY_EXCEPT_FINALLY: &str = r"
def for_try_except_finally(values, fallback):
    for value in values:
        try:
            probe(value)
        except ValueError:
            recover(value)
        finally:
            cleanup(value)
    return fallback
";

const FOR_EXCEPT_STAR: &str = r"
def for_except_star(values, fallback):
    for value in values:
        try:
            probe(value)
        except* ValueError:
            pass
    return fallback
";

const FOR_WITH: &str = r"
def for_with(values, fallback, manager):
    for value in values:
        with manager(value):
            probe(value)
    return fallback
";

fn python_314() -> BandInterpreter {
    resolve_band(&["3.14"], &[])
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("CPython 3.14 is required for the shared-exit regression"))
}

fn recover(interpreter: &BandInterpreter, source: &str, label: &str) -> String {
    let scratch: PathBuf = band_scratch(label);
    let (outcome, recovered): (BandOutcome, String) =
        recompile_equiv_inline(interpreter, source, label, &scratch);
    assert!(
        matches!(outcome, BandOutcome::RecompileEquiv),
        "{label} py{}: {outcome:?}\n--- recovered:\n{recovered}",
        interpreter.alias
    );
    recovered
}

fn assert_post_loop_return_outside_the_construct(
    interpreter: &BandInterpreter,
    source: &str,
    label: &str,
    required: &[&str],
    expected_return_indents: &[usize],
) {
    let recovered: String = recover(interpreter, source, label);
    for expected in required {
        assert!(
            recovered.contains(expected),
            "{label} lost its declared construct `{expected}`:\n{recovered}"
        );
    }
    let tail: &str = "return fallback";
    let return_indents: Vec<usize> = recovered
        .match_indices(tail)
        .map(|(tail_offset, _): (usize, &str)| {
            let tail_line_start: usize = recovered[..tail_offset]
                .rfind('\n')
                .map_or(0, |offset: usize| offset + 1);
            recovered[tail_line_start..tail_offset]
                .chars()
                .take_while(|ch: &char| *ch == ' ')
                .count()
        })
        .collect();
    assert_eq!(
        return_indents, expected_return_indents,
        "{label} recovered an unexpected return-fallback occurrence or indentation:\n{recovered}"
    );
}

#[test]
fn uuid_find_mac_near_keyword_keeps_the_post_loop_return_outside_the_inner_try_else() {
    let interpreter: BandInterpreter = python_314();
    let recovered: String = recover(
        &interpreter,
        UUID_FIND_MAC_NEAR_KEYWORD,
        "uuid_find_mac_near_keyword_shared_exit",
    );
    let tail: &str = "return first_local_mac or None";
    assert_eq!(
        recovered.matches(tail).count(),
        1,
        "the post-loop return must occur exactly once before checking its indentation:\n{recovered}"
    );
    let tail_offset: usize = recovered
        .rfind(tail)
        .unwrap_or_else(|| panic!("missing post-loop return:\n{recovered}"));
    let loop_offset: usize = recovered
        .find("for line in stdout:")
        .unwrap_or_else(|| panic!("missing outer loop:\n{recovered}"));
    let tail_line_start: usize = recovered[..tail_offset]
        .rfind('\n')
        .map_or(0, |offset: usize| offset + 1);
    let tail_indent: usize = recovered[tail_line_start..tail_offset]
        .chars()
        .take_while(|ch: &char| *ch == ' ')
        .count();
    assert!(
        tail_offset > loop_offset && tail_indent == 4,
        "the shared exit must remain after the outer loop, not in a try else:\n{recovered}"
    );
}

#[test]
fn a_multi_statement_loop_tail_does_not_prove_ownership_of_its_return_alone() {
    let interpreter: BandInterpreter = python_314();
    let recovered: String = recover(
        &interpreter,
        MULTI_STATEMENT_POST_LOOP_TAIL,
        "multi_statement_post_loop_tail",
    );
    assert!(
        recovered.contains("except ValueError:\n            return fallback"),
        "the handler return must remain distinct from a multi-statement post-loop tail:\n{recovered}"
    );
    assert!(
        recovered.contains("record(fallback)\n    return fallback"),
        "the complete multi-statement tail must remain outside the loop:\n{recovered}"
    );
}

#[test]
fn declared_loop_shapes_keep_the_post_loop_return_outside_nested_constructs() {
    let interpreter: BandInterpreter = python_314();
    for (label, source, required, expected_return_indents) in [
        (
            "loop_for_try_except",
            FOR_TRY_EXCEPT,
            &["for value in values:"][..],
            &[4][..],
        ),
        (
            "loop_async_for_try_except",
            ASYNC_FOR_TRY_EXCEPT,
            &["async for value in values:"][..],
            &[4][..],
        ),
        (
            "loop_infinite",
            INFINITE_LOOP,
            &["while True:"][..],
            &[12, 4][..],
        ),
        (
            "loop_while",
            WHILE_LOOP,
            &["while index < limit:"][..],
            &[4][..],
        ),
    ] {
        assert_post_loop_return_outside_the_construct(
            &interpreter,
            source,
            label,
            required,
            expected_return_indents,
        );
    }
}

#[test]
fn declared_try_shapes_keep_the_post_loop_return_outside_the_construct() {
    let interpreter: BandInterpreter = python_314();
    for (label, source, required) in [
        (
            "try_for_except",
            FOR_TRY_EXCEPT,
            &["except ValueError:"][..],
        ),
        ("try_for_else", FOR_TRY_ELSE, &["try:"][..]),
        ("try_for_finally", FOR_TRY_FINALLY, &["finally:"][..]),
        (
            "try_for_except_finally",
            FOR_TRY_EXCEPT_FINALLY,
            &["except ValueError:", "finally:"][..],
        ),
        (
            "try_for_except_star",
            FOR_EXCEPT_STAR,
            &["except* ValueError:"][..],
        ),
        ("try_for_with", FOR_WITH, &["with manager(value):"][..]),
    ] {
        assert_post_loop_return_outside_the_construct(&interpreter, source, label, required, &[4]);
    }
}

#[test]
fn a_live_try_else_return_after_a_break_is_not_stripped_as_a_loop_exit() {
    let interpreter: BandInterpreter = python_314();
    let recovered: String = recover(
        &interpreter,
        LIVE_TRY_ELSE_RETURN,
        "live_try_else_return_after_break",
    );
    assert!(
        recovered.contains("else:\n            return value"),
        "the try else owns its return and must not lose it to the loop:\n{recovered}"
    );
}
