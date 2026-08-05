#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HermesModule, SmallFunctionHeader,
    decompile_hermes_module, parse_hermes_module,
};

const FIXTURE_SOURCES: &[&str] = &["src/hermes/decompile.rs", "src/hermes/structure.rs"];

struct Evidence {
    sample: DecompileReport,
    regexes: DecompileReport,
    bundle: DecompileReport,
    utf16_strings: usize,
    debug_info_offsets: Vec<u32>,
    debug_info_flags: Vec<bool>,
    exception_handler_flags: Vec<bool>,
}

impl Evidence {
    fn named(&self, name: &str) -> Option<&DecompiledFunction> {
        self.sample
            .functions
            .iter()
            .find(|f: &&DecompiledFunction| f.name == name)
    }

    fn source_of(&self, name: &str) -> &str {
        self.named(name)
            .map_or("", |f: &DecompiledFunction| f.source.as_str())
    }
}

enum Coverage {
    Corpus(fn(&Evidence) -> bool),
    Fixture(&'static str),
    Uncovered(&'static str),
}

const SHAPES: &[(&str, Coverage)] = &[
    (
        "function kind: top-level module body",
        Coverage::Corpus(|e: &Evidence| {
            e.named("global")
                .is_some_and(|f: &DecompiledFunction| f.structured)
        }),
    ),
    (
        "function kind: nested closure",
        Coverage::Corpus(|e: &Evidence| e.source_of("global").contains("function sumRange(")),
    ),
    (
        "function kind: constructor called through new",
        Coverage::Corpus(|e: &Evidence| e.source_of("main").contains("new ")),
    ),
    (
        "function kind: prototype method",
        Coverage::Corpus(|e: &Evidence| {
            e.named("increment").is_some() && e.named("label").is_some()
        }),
    ),
    (
        "function kind: generator",
        Coverage::Fixture("decompile_generator_function"),
    ),
    (
        "function kind: async function",
        Coverage::Uncovered(
            "no committed bundle compiles an async function; hermes lowers one to a generator \
             state machine and that re-sugar is not implemented",
        ),
    ),
    (
        "function kind: async generator",
        Coverage::Uncovered(
            "no committed bundle compiles an async generator, and it shares the unimplemented \
             state-machine re-sugar with the async row above",
        ),
    ),
    (
        "function kind: class method",
        Coverage::Uncovered(
            "no committed bundle uses ES class syntax; hermes lowers a class method to the \
             prototype-method shape the row above covers, so this row is unproven rather than \
             assumed",
        ),
    ),
    (
        "function kind: getter and setter",
        Coverage::Uncovered("no committed bundle defines an accessor property"),
    ),
    (
        "function kind: arrow function",
        Coverage::Uncovered(
            "no committed bundle compiles an arrow function; hermes emits the closure shape the \
             nested-closure row covers, so this row is unproven rather than assumed",
        ),
    ),
    (
        "function kind: body containing a with block",
        Coverage::Uncovered(
            "no committed bundle uses with, and scope recovery does not model the dynamic scope it \
             introduces",
        ),
    ),
    (
        "function kind: body calling eval",
        Coverage::Uncovered(
            "no committed bundle calls eval; the evaluated text is not present in the bytecode",
        ),
    ),
    (
        "control flow: straight line",
        Coverage::Corpus(|e: &Evidence| {
            e.named("add")
                .is_some_and(|f: &DecompiledFunction| f.structured && !f.has_if && !f.has_loop)
        }),
    ),
    (
        "control flow: if and else",
        Coverage::Fixture("structured_branch_recovers_an_if_without_goto_edges"),
    ),
    (
        "control flow: counted loop",
        Coverage::Corpus(|e: &Evidence| {
            e.named("sumRange").is_some_and(|f: &DecompiledFunction| {
                f.structured
                    && f.has_loop
                    && !f.source.contains("goto ")
                    && f.source.contains("do {")
                    && f.source.contains("} while (")
            })
        }),
    ),
    (
        "control flow: loop recovered from a back edge in a fixture",
        Coverage::Fixture("structured_counted_loop_recovers_a_loop_keyword"),
    ),
    (
        "control flow: switch statement",
        Coverage::Fixture("structured_switch_imm_recovers_a_switch_statement"),
    ),
    (
        "control flow: SwitchImm jump table splits the graph",
        Coverage::Fixture("switch_imm_case_targets_become_block_leaders"),
    ),
    (
        "control flow: irreducible graph is refused by name",
        Coverage::Fixture("irreducible_control_flow_is_declined_by_name"),
    ),
    (
        "control flow: try, catch and finally",
        Coverage::Uncovered(
            "the exception-handler table is not parsed, so a try region is reported through the \
             function header flag and its handler edges never enter the graph; no committed \
             bundle compiles a try region either, so the table layout has no compiled input to \
             read it against and a reader built here would be checked only against its own writer",
        ),
    ),
    (
        "control flow: labelled break and continue",
        Coverage::Uncovered(
            "labels would only be needed for graphs the structurer refuses, and those are refused \
             by name instead of relabelled",
        ),
    ),
    (
        "value shape: BigInt literal",
        Coverage::Fixture("decompile_bigint_literal_synthesis"),
    ),
    (
        "value shape: regular expression literal",
        Coverage::Corpus(|e: &Evidence| !e.regexes.regexps.is_empty()),
    ),
    (
        "value shape: template literal",
        Coverage::Fixture("decompile_callbuiltin_template_object_marks_template_literal"),
    ),
    (
        "value shape: serialized object literal buffer",
        Coverage::Fixture("decompile_object_literal_from_buffers"),
    ),
    (
        "value shape: serialized array literal buffer",
        Coverage::Fixture("decompile_array_literal_from_buffer"),
    ),
    (
        "value shape: UTF-16 string table entry",
        Coverage::Uncovered(
            "every committed bundle stores its strings in the one-byte form, so the UTF-16 branch \
             of the string reader has no real input here",
        ),
    ),
    (
        "container: bare hbc file",
        Coverage::Corpus(|e: &Evidence| e.sample.function_count > 0),
    ),
    (
        "container: android asset bundle",
        Coverage::Corpus(|e: &Evidence| e.bundle.functions_with_body > 0),
    ),
    (
        "container: iOS application resource",
        Coverage::Uncovered(
            "no committed application bundle carries hermes bytecode; the ipa walker itself is \
             graded in real_ipa_primary_executable.rs",
        ),
    ),
    (
        "container: source map beside the bundle",
        Coverage::Uncovered(
            "no committed bundle ships a source map; recovered names come from the string table \
             rather than from a map",
        ),
    ),
    (
        "container: bundle with a debug info section",
        Coverage::Corpus(|e: &Evidence| {
            e.debug_info_offsets.iter().all(|offset: &u32| *offset != 0)
                && e.debug_info_flags.iter().all(|flag: &bool| *flag)
        }),
    ),
    (
        "container: bundle stripped of its debug info section",
        Coverage::Uncovered(
            "every committed bundle was compiled with debug info, so no committed input has the \
             stripped shape; recovered names come from the function name index into the string \
             table rather than from the debug section, and a header declaring a zero debug info \
             offset is read in hermes_reader_versions.rs",
        ),
    ),
];

fn corpus(parts: &[&str]) -> PathBuf {
    let mut path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes");
    for part in parts {
        path = path.join(part);
    }
    path
}

fn module_for(parts: &[&str]) -> HermesModule {
    let path: PathBuf = corpus(parts);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "this ledger states what committed bytecode proves, so a run that cannot read \
             {} must fail rather than report a green over fewer bundles: {error}",
            path.display()
        )
    });
    parse_hermes_module(&bytes)
        .unwrap_or_else(|error: disrobe_pass_mobile::Error| panic!("{}: {error}", path.display()))
}

fn evidence() -> Evidence {
    let modules: [HermesModule; 3] = [
        module_for(&["sample", "sample.hbc.v96"]),
        module_for(&["regex", "regexes.hbc.v96"]),
        module_for(&["hello", "index.android.bundle"]),
    ];
    let utf16_strings: usize = modules
        .iter()
        .map(|module: &HermesModule| module.utf16_strings)
        .sum();
    let debug_info_offsets: Vec<u32> = modules
        .iter()
        .map(|module: &HermesModule| module.header.debug_info_offset)
        .collect();
    let debug_info_flags: Vec<bool> = modules
        .iter()
        .flat_map(|module: &HermesModule| module.functions.iter())
        .map(|function: &SmallFunctionHeader| function.has_debug_info)
        .collect();
    let exception_handler_flags: Vec<bool> = modules
        .iter()
        .flat_map(|module: &HermesModule| module.functions.iter())
        .map(|function: &SmallFunctionHeader| function.has_exception_handler)
        .collect();
    let [sample, regexes, bundle]: [HermesModule; 3] = modules;
    Evidence {
        sample: decompile_hermes_module(&sample),
        regexes: decompile_hermes_module(&regexes),
        bundle: decompile_hermes_module(&bundle),
        utf16_strings,
        debug_info_offsets,
        debug_info_flags,
        exception_handler_flags,
    }
}

fn fixture_sources() -> String {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut joined: String = String::new();
    for relative in FIXTURE_SOURCES {
        let path: PathBuf = root.join(relative);
        let text: String =
            std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
                panic!(
                    "this ledger binds shapes to named in-crate cases, so a run that cannot read \
                 {relative} must fail rather than report a green that checked nothing: {error} at \
                 {}",
                    path.display()
                )
            });
        joined.push_str(&text);
    }
    joined
}

#[test]
fn the_shape_ledger_names_each_shape_once() {
    let mut seen: Vec<&str> = Vec::with_capacity(SHAPES.len());
    for (shape, _) in SHAPES {
        assert!(
            !seen.contains(shape),
            "`{shape}` is listed twice, so one of the two statuses would never be read"
        );
        seen.push(shape);
    }
    assert!(seen.len() >= 30, "the ledger lost rows: {}", seen.len());
}

#[test]
fn every_named_shape_is_either_proven_here_or_states_why_it_is_not() {
    let evidence: Evidence = evidence();
    let sources: String = fixture_sources();

    let mut proven_by_corpus: usize = 0;
    let mut proven_by_fixture: usize = 0;
    let mut uncovered: Vec<&str> = Vec::new();
    for (shape, coverage) in SHAPES {
        match coverage {
            Coverage::Corpus(check) => {
                assert!(
                    check(&evidence),
                    "`{shape}` claims a committed bundle proves it, but the check over that bundle \
                     is false, so the claim is stale"
                );
                proven_by_corpus += 1;
            }
            Coverage::Fixture(case) => {
                assert!(
                    sources.contains(&format!("fn {case}(")),
                    "`{shape}` is bound to the case `{case}`, which no longer exists in \
                     {FIXTURE_SOURCES:?}, so the shape is claimed against nothing"
                );
                proven_by_fixture += 1;
            }
            Coverage::Uncovered(reason) => {
                assert!(
                    reason.len() > 20,
                    "`{shape}` is uncovered, so it must carry a reason a reader can act on"
                );
                uncovered.push(shape);
            }
        }
    }

    assert_eq!(
        proven_by_corpus + proven_by_fixture + uncovered.len(),
        SHAPES.len(),
        "every row lands in exactly one column"
    );
    eprintln!(
        "hermes recovery shapes: {proven_by_corpus} proven against a committed bundle, \
         {proven_by_fixture} proven against a named in-crate case, {} listed as uncovered",
        uncovered.len()
    );
    for shape in &uncovered {
        eprintln!("  uncovered: {shape}");
    }
    assert_eq!(
        evidence.utf16_strings, 0,
        "the UTF-16 row is listed as uncovered because no committed bundle has such an entry; a \
         bundle that does means the row must be promoted rather than left listed"
    );
    assert!(
        evidence.debug_info_flags.iter().all(|flag: &bool| *flag),
        "the stripped-debug-info row is listed as uncovered because every function in every \
         committed bundle carries debug info; a function that does not means the row must be \
         promoted rather than left listed"
    );
    assert!(
        evidence
            .exception_handler_flags
            .iter()
            .all(|flag: &bool| !*flag),
        "the try row is listed as uncovered because no function in any committed bundle declares \
         an exception handler; a bundle that does gives the handler table a compiled input to be \
         read against, and the row must then be built rather than left listed"
    );
}
