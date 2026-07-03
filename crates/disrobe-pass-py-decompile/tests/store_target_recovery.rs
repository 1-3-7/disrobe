#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const TARGET_VERSIONS: &[&str] = &["3.9", "3.12", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_recovers(label: &str, program: &str, must_contain: &[&str]) {
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
            BandOutcome::RecompileEquiv | BandOutcome::SourceTokenMatch => {}
            BandOutcome::Tolerated(detail) => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: Tolerated outcome from a stable interpreter is a real failure: \
                     {detail}\n--- recovered:\n{source}",
                    interp.alias
                );
                eprintln!("{detail}");
            }
            BandOutcome::Failed(reason) => {
                panic!(
                    "{label} py{}: {reason}\n--- recovered:\n{source}",
                    interp.alias
                );
            }
        }
        for needle in must_contain {
            assert!(
                source.contains(needle),
                "{label} py{}: expected recovered target `{needle}` in:\n{source}",
                interp.alias
            );
        }
        assert!(
            !source.contains("__DR_"),
            "{label} py{}: unrecovered marker leaked in:\n{source}",
            interp.alias
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "{label}: no interpreter validated the recovery"
    );
}

#[test]
fn comprehension_attribute_target() {
    let program: &str = "\
class O:
    pass

def f(seq):
    o = O()
    return [o.attr for o.attr in seq]
";
    assert_recovers("comp_attr_target", program, &["for o.attr in"]);
}

#[test]
fn comprehension_subscript_target() {
    let program: &str = "\
def f(seq, d):
    return [d['k'] for d['k'] in seq]
";
    assert_recovers("comp_subscript_target", program, &["for d[\"k\"] in"]);
}

#[test]
fn comprehension_tuple_attribute_target() {
    let program: &str = "\
class O:
    pass

def f(pairs):
    o = O()
    return [o.a for o.a, o.b in pairs]
";
    assert_recovers(
        "comp_tuple_attr_target",
        program,
        &["for (o.a, o.b) in", "o.a"],
    );
}

#[test]
fn dict_comprehension_subscript_value_target() {
    let program: &str = "\
def f(items, d):
    return {k: d[k] for k, d[k] in items}
";
    assert_recovers(
        "dictcomp_subscript_target",
        program,
        &["d[k]", "for (k, d[k]) in"],
    );
}

#[test]
fn for_loop_attribute_target() {
    let program: &str = "\
class O:
    pass

def f(seq):
    o = O()
    for o.cursor in seq:
        pass
    return o
";
    assert_recovers("for_attr_target", program, &["for o.cursor in"]);
}

#[test]
fn for_loop_tuple_attribute_subscript_target() {
    let program: &str = "\
class O:
    pass

def f(rows):
    o = O()
    d = {}
    lst = [0]
    for o.x, d['y'], lst[0] in rows:
        pass
    return o
";
    assert_recovers(
        "for_tuple_mixed_target",
        program,
        &["o.x", "d[\"y\"]", "lst[0]"],
    );
}

#[test]
fn async_for_attribute_target() {
    let program: &str = "\
class O:
    pass

async def f(ait):
    o = O()
    async for o.item in ait:
        pass
    return o
";
    assert_recovers("async_for_attr_target", program, &["async for o.item in"]);
}
