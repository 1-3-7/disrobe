#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const LINECACHE_ENTRY: &str = r"def _make_lazycache_entry(filename, module_globals):
    if not filename or (filename.startswith('<') and filename.endswith('>')):
        return None
    if module_globals and '__name__' in module_globals:
        spec = module_globals.get('__spec__')
        name = getattr(spec, 'name', None) or module_globals['__name__']
        loader = getattr(spec, 'loader', None)
        if loader is None:
            loader = module_globals.get('__loader__')
        get_source = getattr(loader, 'get_source', None)

        if name and get_source:
            def get_lines(name=name, *args, **kwargs):
                return get_source(name, *args, **kwargs)
            return (get_lines,)
    return None
";

const IMPLICIT_TAIL_CONTROL: &str = r"def _make_lazycache_entry(filename, module_globals):
    if not filename or (filename.startswith('<') and filename.endswith('>')):
        return None
    if module_globals and '__name__' in module_globals:
        spec = module_globals.get('__spec__')
        name = getattr(spec, 'name', None) or module_globals['__name__']
        loader = getattr(spec, 'loader', None)
        if loader is None:
            loader = module_globals.get('__loader__')
        get_source = getattr(loader, 'get_source', None)

        if name and get_source:
            def get_lines(name=name, *args, **kwargs):
                return get_source(name, *args, **kwargs)
            return (get_lines,)
";

fn cpython_314() -> BandInterpreter {
    resolve_band(&["3.14"], &[]).into_iter().next().unwrap_or_else(|| {
        panic!(
            "linecache explicit None tail requires CPython 3.14; install it with `uv python install 3.14`"
        )
    })
}

fn assert_recompile_equiv(label: &str, program: &str) -> String {
    let interpreter: BandInterpreter = cpython_314();
    let scratch: PathBuf = band_scratch(label);
    let (outcome, recovered): (BandOutcome, String) =
        recompile_equiv_inline(&interpreter, program, label, &scratch);
    match outcome {
        BandOutcome::RecompileEquiv => {}
        other => panic!(
            "{label} py{} did not preserve its real CPython code object: {other:?}\n--- recovered:\n{recovered}",
            interpreter.alias
        ),
    }
    assert!(
        !recovered.contains("__DR_"),
        "{label} leaked an unrecovered marker:\n{recovered}"
    );
    recovered
}

#[test]
fn linecache_entry_preserves_explicit_none_tail() {
    let recovered: String = assert_recompile_equiv("linecache_explicit_none_tail", LINECACHE_ENTRY);
    assert!(
        recovered.trim_end().ends_with("    return None"),
        "the named linecache failure lost its explicit final return:\n{recovered}"
    );
}

#[test]
fn linecache_entry_keeps_implicit_tail_implicit() {
    let recovered: String =
        assert_recompile_equiv("linecache_implicit_none_tail", IMPLICIT_TAIL_CONTROL);
    assert!(
        recovered
            .trim_end()
            .ends_with("            return (get_lines,)"),
        "the implicit-tail control gained a return statement:\n{recovered}"
    );
}
