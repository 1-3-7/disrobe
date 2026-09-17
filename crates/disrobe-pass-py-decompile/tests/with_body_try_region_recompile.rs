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

const BAND: &[&str] = &["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"];
const PRERELEASE: &[&str] = &["3.15"];
const POST_38: &[&str] = &["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"];
const ASYNC_EXCEPT_OK: &[&str] = &["3.11"];
const ASYNC_FINALLY_OK: &[&str] = &["3.8", "3.9", "3.10", "3.11"];

struct WithBodyTryCase {
    label: &'static str,
    program: &'static str,
    required: &'static [&'static str],
    equivalent_on: &'static [&'static str],
    open_reason: &'static str,
}

const CASES: &[WithBodyTryCase] = &[
    WithBodyTryCase {
        label: "with_body_try_except",
        program: concat!(
            "def f(stream):\n",
            "    passwd = None\n",
            "    with ctx() as stack:\n",
            "        try:\n",
            "            fd = g(1)\n",
            "        except OSError:\n",
            "            fd = None\n",
            "    return passwd\n",
        ),
        required: &["with ctx() as stack:", "try:", "except OSError:"],
        equivalent_on: POST_38,
        open_reason: "3.8 lowers the with exit to WITH_CLEANUP_START, WITH_CLEANUP_FINISH \n                      and END_FINALLY, which the canonical stream maps to Nop, so the \n                      statement after the cleanup has no anchor to be attributed to",
    },
    WithBodyTryCase {
        label: "with_body_try_finally",
        program: concat!(
            "def f(stream):\n",
            "    with ctx() as stack:\n",
            "        try:\n",
            "            fd = g(1)\n",
            "        finally:\n",
            "            k()\n",
        ),
        required: &["with ctx() as stack:", "try:", "finally:"],
        equivalent_on: BAND,
        open_reason: "",
    },
    WithBodyTryCase {
        label: "with_body_try_between_statements",
        program: concat!(
            "def f(stream):\n",
            "    with ctx() as stack:\n",
            "        a = 1\n",
            "        try:\n",
            "            fd = g(1)\n",
            "        except OSError:\n",
            "            fd = None\n",
            "        b = 2\n",
        ),
        required: &["a = 1", "try:", "except OSError:", "b = 2"],
        equivalent_on: BAND,
        open_reason: "",
    },
    WithBodyTryCase {
        label: "with_body_try_guarded_tail",
        program: concat!(
            "def f(stream):\n",
            "    with ctx() as stack:\n",
            "        try:\n",
            "            fd = g(1)\n",
            "        except OSError:\n",
            "            fd = None\n",
            "        if fd is not None:\n",
            "            old = g(2)\n",
            "    return stream\n",
        ),
        required: &["try:", "except OSError:", "if fd is not None:"],
        equivalent_on: POST_38,
        open_reason: "3.8 lowers the with exit to WITH_CLEANUP_START, WITH_CLEANUP_FINISH \n                      and END_FINALLY, which the canonical stream maps to Nop, so the \n                      statement after the cleanup has no anchor to be attributed to",
    },
    WithBodyTryCase {
        label: "with_body_try_nested_handler_try",
        program: concat!(
            "def f(stream):\n",
            "    with ctx() as stack:\n",
            "        try:\n",
            "            fd = g(1)\n",
            "        except OSError:\n",
            "            stack.close()\n",
            "            try:\n",
            "                fd = g(2)\n",
            "            except ValueError:\n",
            "                fd = None\n",
            "            stream = g(3)\n",
            "    return stream\n",
        ),
        required: &["except OSError:", "except ValueError:"],
        equivalent_on: POST_38,
        open_reason: "3.8 lowers the with exit to WITH_CLEANUP_START, WITH_CLEANUP_FINISH \n                      and END_FINALLY, which the canonical stream maps to Nop, so the \n                      statement after the cleanup has no anchor to be attributed to",
    },
    WithBodyTryCase {
        label: "async_with_body_try_except",
        program: concat!(
            "async def f(stream):\n",
            "    passwd = None\n",
            "    async with ctx() as stack:\n",
            "        try:\n",
            "            fd = g(1)\n",
            "        except OSError:\n",
            "            fd = None\n",
            "    return passwd\n",
        ),
        required: &["async with ctx() as stack:", "try:", "except OSError:"],
        equivalent_on: ASYNC_EXCEPT_OK,
        open_reason: "the async with body is built by structure_async_with, which has no \n                      inline-cleanup elision, so a nested handler emitted after the with \n                      cleanup is still outside the body window",
    },
    WithBodyTryCase {
        label: "async_with_body_try_finally",
        program: concat!(
            "async def f(stream):\n",
            "    async with ctx() as stack:\n",
            "        try:\n",
            "            fd = g(1)\n",
            "        finally:\n",
            "            k()\n",
        ),
        required: &["async with ctx() as stack:", "try:", "finally:"],
        equivalent_on: ASYNC_FINALLY_OK,
        open_reason: "the async with body is built by structure_async_with, which has no \n                      inline-cleanup elision, so a nested handler emitted after the with \n                      cleanup is still outside the body window",
    },
];

#[test]
fn a_try_region_inside_a_with_body_survives_recovery_on_every_banded_interpreter() {
    let band: Vec<BandInterpreter> = resolve_band(BAND, PRERELEASE);
    let resolved: Vec<&str> = band.iter().map(|b: &BandInterpreter| b.alias).collect();
    assert_eq!(
        band.len(),
        BAND.len(),
        "every interpreter in {BAND:?} is required to prove that a try region nested inside a \
         with body survives on both the pre-3.11 block decoder and the post-3.11 exception-table \
         decoder; resolved {resolved:?}. Install the missing ones with `uv python install <x.y>`"
    );
    let scratch: PathBuf = band_scratch("with-body-try-region");
    let mut failures: Vec<String> = Vec::new();
    for interp in &band {
        for case in CASES {
            let pinned: bool = case.equivalent_on.contains(&interp.alias);
            assert!(
                pinned || !case.open_reason.is_empty(),
                "{}/{} is not pinned equivalent and states no reason",
                interp.alias,
                case.label
            );
            let (outcome, source): (BandOutcome, String) =
                recompile_equiv_inline(interp, case.program, case.label, &scratch);
            let equivalent: bool = matches!(outcome, BandOutcome::RecompileEquiv);
            if !pinned {
                println!(
                    "OPEN {}/{}: {} (equivalent={equivalent})",
                    interp.alias, case.label, case.open_reason
                );
                continue;
            }
            if !equivalent {
                failures.push(format!(
                    "{}/{}: did not recompile equivalently: {outcome:?}\n--- recovered:\n{source}",
                    interp.alias, case.label
                ));
                continue;
            }
            for needle in case.required {
                if !source.contains(needle) {
                    failures.push(format!(
                        "{}/{}: recovered source lost `{needle}`:\n{source}",
                        interp.alias, case.label
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a with body that contains a try region must recover that region, not truncate the body \
         at the first protected handler it meets: {}",
        failures.join("\n\n")
    );
}
