#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const TARGET_VERSIONS: &[&str] = &["3.12", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_recompiles(label: &str, program: &str) {
    let band: Vec<BandInterpreter> = resolve_band(TARGET_VERSIONS, PRERELEASE);
    if band.is_empty() {
        return;
    }
    let scratch: PathBuf = band_scratch(label);
    let mut checked: usize = 0usize;
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {}
            BandOutcome::SourceTokenMatch => panic!(
                "{label} py{}: token-match, not recompile-equivalent:\n{source}",
                interp.alias
            ),
            BandOutcome::Tolerated(detail) => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: Tolerated from a stable interpreter is a real failure: \
                     {detail}\n{source}",
                    interp.alias
                );
            }
            BandOutcome::Failed(reason) => {
                panic!(
                    "{label} py{}: {reason}\n--- recovered:\n{source}",
                    interp.alias
                )
            }
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "{label}: no interpreter validated the recovery"
    );
}

#[test]
fn try_except_else_with_real_else_body() {
    let program: &str = "\
def f(x):
    try:
        y = compute(x)
    except ValueError:
        return 0
    else:
        record(y)
    return y
";
    assert_recompiles("try_else_real_body", program);
}

#[test]
fn try_except_else_tail_not_swallowed() {
    let program: &str = "\
def f(x):
    try:
        y = compute(x)
    except ValueError:
        return None
    else:
        if guard(y):
            return None
    finalize(x)
    return y
";
    assert_recompiles("try_else_tail", program);
}

#[test]
fn try_body_normal_exit_not_return_none() {
    let program: &str = "\
def f(seq):
    for item in seq:
        try:
            handle(item)
        except KeyError:
            continue
        emit(item)
    return len(seq)
";
    assert_recompiles("try_normal_exit", program);
}

#[test]
fn nested_try_inside_else_entangled() {
    let program: &str = "\
import os, stat
def ismount(path):
    try:
        s1 = os.lstat(path)
    except (OSError, ValueError):
        return False
    else:
        if stat.S_ISLNK(s1.st_mode):
            return False
    path = os.fspath(path)
    if isinstance(path, bytes):
        parent = join(path, b'..')
    else:
        parent = join(path, '..')
    try:
        s2 = os.lstat(parent)
    except OSError:
        parent = realpath(parent)
        try:
            s2 = os.lstat(parent)
        except OSError:
            return False
    return s1.st_dev != s2.st_dev or s1.st_ino == s2.st_ino
";
    assert_recompiles("nested_try_in_else", program);
}

#[test]
fn terminating_handler_no_else_tail_is_sibling_try() {
    let program: &str = "\
cache = {}
def checkcache(filename=None):
    if filename is None:
        filenames = cache.copy().keys()
    else:
        filenames = [filename]
    for filename in filenames:
        entry = cache.get(filename, None)
        if entry is None or len(entry) == 1:
            continue
        size, mtime, lines, fullname = entry
        if mtime is None:
            continue
        try:
            import os
        except ImportError:
            return
        try:
            stat = os.stat(fullname)
        except (OSError, ValueError):
            cache.pop(filename, None)
            continue
        if size != stat.st_size or mtime != stat.st_mtime:
            cache.pop(filename, None)
";
    assert_recompiles("terminating_handler_sibling_try", program);
}

#[test]
fn else_arm_with_after_inlined_return_then() {
    let program: &str = "\
def f(argv):
    if len(argv) == 1:
        show(default_source())
    else:
        fn = argv[1]
        with open(fn) as handle:
            show(parse(handle, fn))
";
    assert_recompiles("else_arm_with_inlined_return", program);
}

#[test]
fn else_arm_try_after_inlined_return_then() {
    let program: &str = "\
def f(argv):
    if len(argv) == 1:
        show(default_source())
    else:
        try:
            fn = argv[1]
            show(parse(fn))
        except OSError as exc:
            raise SystemExit(exc) from exc
";
    assert_recompiles("else_arm_try_inlined_return", program);
}
