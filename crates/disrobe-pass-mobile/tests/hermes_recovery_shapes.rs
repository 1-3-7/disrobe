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
    longtail: DecompileReport,
    shapes: DecompileReport,
    shapes_bigints: usize,
    shapes_utf16_strings: usize,
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

    fn recovered<'a>(report: &'a DecompileReport, name: &str) -> Option<&'a DecompiledFunction> {
        report
            .functions
            .iter()
            .find(|f: &&DecompiledFunction| f.name == name)
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
        Coverage::Corpus(|e: &Evidence| {
            Evidence::recovered(&e.shapes, "seq").is_some()
                && e.shapes
                    .functions
                    .iter()
                    .any(|f: &DecompiledFunction| f.is_generator)
        }),
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
            "hermesc v0.13.0, the newest release this crate transcribes an opcode table from, \
             rejects a class declaration with `invalid statement encountered`, so no bundle it \
             compiles can carry one and this row cannot be raised at the versions in the band",
        ),
    ),
    (
        "function kind: getter and setter",
        Coverage::Corpus(|e: &Evidence| {
            Evidence::recovered(&e.shapes, "get twice").is_some()
                && Evidence::recovered(&e.shapes, "set twice").is_some()
        }),
    ),
    (
        "function kind: arrow function",
        Coverage::Corpus(|e: &Evidence| {
            Evidence::recovered(&e.shapes, "arrow")
                .is_some_and(|f: &DecompiledFunction| f.structured)
        }),
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
        Coverage::Corpus(|e: &Evidence| {
            Evidence::recovered(&e.longtail, "classify")
                .is_some_and(|f: &DecompiledFunction| f.structured && f.source.contains("=== "))
        }),
    ),
    (
        "control flow: SwitchImm jump table splits the graph",
        Coverage::Corpus(|e: &Evidence| {
            Evidence::recovered(&e.longtail, "pick").is_some_and(|f: &DecompiledFunction| {
                f.structured
                    && f.source.contains("switch (")
                    && (0..16u32).all(|v: u32| f.source.contains(&format!("case {v}:")))
            })
        }),
    ),
    (
        "control flow: irreducible graph is refused by name",
        Coverage::Fixture("irreducible_control_flow_is_declined_by_name"),
    ),
    (
        "control flow: try and catch",
        Coverage::Corpus(|e: &Evidence| {
            Evidence::recovered(&e.longtail, "guarded").is_some_and(|f: &DecompiledFunction| {
                f.structured && f.has_try_catch && f.source.contains("catch (")
            })
        }),
    ),
    (
        "control flow: finally",
        Coverage::Uncovered(
            "hermesc lowers a finally block by copying it into the normal path and into the \
             handler path, so recovering the single source block means proving the two copies are \
             the same body; no committed bundle carries one and that comparison is not implemented",
        ),
    ),
    (
        "control flow: labelled break and continue",
        Coverage::Corpus(|e: &Evidence| {
            Evidence::recovered(&e.longtail, "firstPair").is_some_and(|f: &DecompiledFunction| {
                f.structured
                    && f.structure_decline.is_none()
                    && !f.source.contains("goto ")
                    && f.source.contains("break $loop")
            })
        }),
    ),
    (
        "value shape: BigInt literal",
        Coverage::Corpus(|e: &Evidence| {
            e.shapes_bigints > 0
                && Evidence::recovered(&e.shapes, "bigText").is_some_and(
                    |f: &DecompiledFunction| {
                        f.structured && f.source.contains("123456789012345678901234567890n")
                    },
                )
        }),
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
        Coverage::Corpus(|e: &Evidence| {
            e.shapes_utf16_strings > 0
                && Evidence::recovered(&e.shapes, "surrogate")
                    .is_some_and(|f: &DecompiledFunction| f.structured)
        }),
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
                && e.debug_info_flags.iter().any(|flag: &bool| *flag)
        }),
    ),
    (
        "container: function inside a bundle that carries no debug info of its own",
        Coverage::Corpus(|e: &Evidence| e.debug_info_flags.iter().any(|flag: &bool| !*flag)),
    ),
    (
        "container: bundle stripped of its debug info section",
        Coverage::Uncovered(
            "every committed bundle declares a non-zero debug info offset in its header, so no \
             committed input has the whole-section stripped shape; recovered names come from the \
             function name index into the string table rather than from the debug section, and a \
             header declaring a zero debug info offset is read in hermes_reader_versions.rs",
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

fn crate_fixture(name: &str) -> HermesModule {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("hermes")
        .join(name);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "this ledger states what committed bytecode proves, so a run that cannot read {} must \
             fail rather than report a green over fewer bundles: {error}",
            path.display()
        )
    });
    parse_hermes_module(&bytes)
        .unwrap_or_else(|error: disrobe_pass_mobile::Error| panic!("{}: {error}", path.display()))
}

fn evidence() -> Evidence {
    let longtail: HermesModule = crate_fixture("longtail.hbc");
    let shapes: HermesModule = crate_fixture("shapes.hbc");
    let shapes_bigints: usize = shapes.big_int_table.len();
    let shapes_utf16_strings: usize = shapes.utf16_strings;
    let modules: [HermesModule; 5] = [
        module_for(&["sample", "sample.hbc.v96"]),
        module_for(&["regex", "regexes.hbc.v96"]),
        module_for(&["hello", "index.android.bundle"]),
        longtail,
        shapes,
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
    let [sample, regexes, bundle, longtail, shapes]: [HermesModule; 5] = modules;
    Evidence {
        sample: decompile_hermes_module(&sample),
        regexes: decompile_hermes_module(&regexes),
        bundle: decompile_hermes_module(&bundle),
        longtail: decompile_hermes_module(&longtail),
        shapes: decompile_hermes_module(&shapes),
        shapes_bigints,
        shapes_utf16_strings,
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
        evidence.utf16_strings, evidence.shapes_utf16_strings,
        "the UTF-16 row is proven by the one committed bundle whose string table holds such an \
         entry, so a second bundle gaining one means the row is measured over a population it \
         does not name"
    );
    assert!(
        evidence.shapes_utf16_strings > 0,
        "the UTF-16 row claims a committed bundle stores a string in the two-byte form; a run \
         that finds none is grading that row against nothing"
    );
    assert_eq!(
        evidence
            .exception_handler_flags
            .iter()
            .filter(|flag: &&bool| **flag)
            .count(),
        2,
        "the try and catch row is proven against the two functions in the committed bundles that \
         declare an exception handler, the explicit try in longtail.js and the for-of loop in \
         shapes.js that hermesc guards so it can close its iterator, so a change in that count \
         means the row is measured over a different population than the one it names"
    );
}
