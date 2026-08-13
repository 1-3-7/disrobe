#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::band_gate::{
    BandRelease, CPYTHON_SERIES, FIRST_CACHED_SERIES, SeriesMagic, parse_magic,
    resolve_band_interpreter,
};
use common::stdlib_measure::{MEASURE_HARNESS, interpreter_version, manifest_dir};

const DIFFERENTIAL_HARNESS: &str = "tests/harness/py_tier_differential.py";
const OPTIMIZE_LEVELS: [u8; 3] = [0, 1, 2];
const EXCLUDED_DIMENSIONS: &str = "co_filename,co_linetable,co_firstlineno";
const BYTE_DIMENSIONS: &str = "co_code,co_argcount,co_posonlyargcount,co_kwonlyargcount,\
                               co_nlocals,co_stacksize,co_flags,co_name,co_names,co_varnames,\
                               co_freevars,co_cellvars,co_qualname,co_exceptiontable,co_consts";
const DEPTH_LIMIT_DIMENSION: &str = "co_consts_depth_limit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lines {
    AllMatch,
    SomeMismatch,
    Unconstrained,
}

#[derive(Debug, Clone, Copy)]
enum Dimensions {
    None,
    Any,
    Contains {
        required: &'static [&'static str],
        forbidden: &'static [&'static str],
    },
}

#[derive(Debug, Clone, Copy)]
struct LevelExpectation {
    normalized_detects: bool,
    strict: Dimensions,
    lines: Lines,
    firstlineno_equal: bool,
}

#[derive(Debug, Clone, Copy)]
struct CaseExpectation {
    case: &'static str,
    mechanism: &'static str,
    available_from: (u8, u8),
    levels: [LevelExpectation; 3],
}

const fn every_level(level: LevelExpectation) -> [LevelExpectation; 3] {
    [level, level, level]
}

const fn strict_only(dimension: &'static [&'static str], lines: Lines) -> LevelExpectation {
    LevelExpectation {
        normalized_detects: false,
        strict: Dimensions::Contains {
            required: dimension,
            forbidden: &[],
        },
        lines,
        firstlineno_equal: true,
    }
}

const fn caught_by_both(dimension: &'static [&'static str], lines: Lines) -> LevelExpectation {
    LevelExpectation {
        normalized_detects: true,
        strict: Dimensions::Contains {
            required: dimension,
            forbidden: &[],
        },
        lines,
        firstlineno_equal: true,
    }
}

const fn caught_by_neither() -> LevelExpectation {
    LevelExpectation {
        normalized_detects: false,
        strict: Dimensions::None,
        lines: Lines::AllMatch,
        firstlineno_equal: true,
    }
}

const fn docstring_already_stripped() -> LevelExpectation {
    LevelExpectation {
        normalized_detects: false,
        strict: Dimensions::Contains {
            required: &[],
            forbidden: &["co_consts"],
        },
        lines: Lines::AllMatch,
        firstlineno_equal: true,
    }
}

const ESCALATIONS: [(&str, (u8, u8), Dimensions); 1] =
    [("class_body_line_shifted", (3, 13), Dimensions::Any)];

fn strict_expectation(case: &str, band: (u8, u8), base: Dimensions) -> Dimensions {
    ESCALATIONS
        .iter()
        .find(|(name, from, _): &&(&str, (u8, u8), Dimensions)| *name == case && band >= *from)
        .map_or(base, |(_, _, escalated): &(&str, (u8, u8), Dimensions)| {
            *escalated
        })
}

const CASES: [CaseExpectation; 20] = [
    CaseExpectation {
        case: "jump_target_nesting",
        mechanism: "the normalized tier folds every jump into a target-free JUMP token, so a \
                    recovery that nests the second `if` inside the first keeps the whole opcode \
                    sequence and only moves a jump target; the byte tier reads co_code and sees \
                    it. The line leg is left unconstrained here because moving a branch target \
                    also moves which source line the exit path is attributed to, and releases \
                    differ on where they put it",
        available_from: (3, 8),
        levels: every_level(strict_only(&["co_code"], Lines::Unconstrained)),
    },
    CaseExpectation {
        case: "docstring_dropped",
        mechanism: "a function docstring is co_consts[0] and emits no instruction, so dropping it \
                    leaves the normalized opcode sequence untouched; -OO strips it from the \
                    original too, so at optimize 2 co_consts can no longer carry the loss and the \
                    measurement has to be taken at optimize 0 to see it. Some releases leave a NOP \
                    where the stripped docstring statement stood, which co_code still reports and \
                    the normalized tier still hides, so co_code is not asserted absent there",
        available_from: (3, 8),
        levels: [
            strict_only(&["co_consts"], Lines::AllMatch),
            strict_only(&["co_consts"], Lines::AllMatch),
            docstring_already_stripped(),
        ],
    },
    CaseExpectation {
        case: "docstring_invented",
        mechanism: "the same blindness in the other direction: a recovery that adds a docstring \
                    the original never had leaves an orphan constant in co_consts that no \
                    instruction references, and -OO removes that constant from both sides",
        available_from: (3, 8),
        levels: [
            strict_only(&["co_consts"], Lines::AllMatch),
            strict_only(&["co_consts"], Lines::AllMatch),
            docstring_already_stripped(),
        ],
    },
    CaseExpectation {
        case: "assert_dropped",
        mechanism: "at optimize 0 a dropped assert removes real opcodes, so both tiers reject it; \
                    -O strips the assert from the original as well, so from optimize 1 upward \
                    neither tier can see the loss and a measurement taken under those flags would \
                    score an assert-dropping recovery as perfect",
        available_from: (3, 8),
        levels: [
            caught_by_both(&["co_code"], Lines::AllMatch),
            caught_by_neither(),
            caught_by_neither(),
        ],
    },
    CaseExpectation {
        case: "statement_reorder",
        mechanism: "reordering two independent assignments moves the STORE opcodes, which the \
                    normalized tier compares in order, so this loss class is not strict-only",
        available_from: (3, 8),
        levels: every_level(caught_by_both(&["co_code"], Lines::SomeMismatch)),
    },
    CaseExpectation {
        case: "comprehension_scope_collapsed",
        mechanism: "rewriting a comprehension as an explicit loop changes the opcode sequence \
                    outright, so this loss class is not strict-only either",
        available_from: (3, 8),
        levels: every_level(caught_by_both(&["co_code"], Lines::SomeMismatch)),
    },
    CaseExpectation {
        case: "line_shifted_body",
        mechanism: "a blank line inside the body leaves co_code and every structural field \
                    identical and moves only the line table, so the byte tier stays quiet and the \
                    position leg is the only thing that can report it",
        available_from: (3, 8),
        levels: every_level(LevelExpectation {
            normalized_detects: false,
            strict: Dimensions::None,
            lines: Lines::SomeMismatch,
            firstlineno_equal: true,
        }),
    },
    CaseExpectation {
        case: "class_body_line_shifted",
        mechanism: "moving a class down by one line changes nothing the class body executes. From \
                    3.13 the compiler bakes the class's first line into the code object to feed \
                    __firstlineno__, as a co_consts entry on 3.13 and as a LOAD_SMALL_INT operand \
                    inside co_code from 3.14, and the normalized tier pops that load in both \
                    forms, so the byte tier is the only tier that reports the shift on those \
                    releases; before 3.13 nothing carries the line and only the line tier sees it",
        available_from: (3, 8),
        levels: every_level(LevelExpectation {
            normalized_detects: false,
            strict: Dimensions::None,
            lines: Lines::SomeMismatch,
            firstlineno_equal: false,
        }),
    },
    CaseExpectation {
        case: "control_recompiled_twice",
        mechanism: "the same source compiled twice produces equal-but-distinct string constants; \
                    a tier that reported interning as a byte difference, or that simply answered \
                    `different` to everything, would fail here",
        available_from: (3, 8),
        levels: every_level(caught_by_neither()),
    },
    CaseExpectation {
        case: "control_comment_only",
        mechanism: "a comment changes the source text and nothing the compiler emits, so both \
                    tiers must stay quiet",
        available_from: (3, 8),
        levels: every_level(caught_by_neither()),
    },
    CaseExpectation {
        case: "mutant_stacksize",
        mechanism: "co_stacksize never reaches dis.get_instructions, so the normalized tier cannot \
                    read it",
        available_from: (3, 8),
        levels: every_level(strict_only(&["co_stacksize"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_flags",
        mechanism: "co_flags carries generator, coroutine and docstring bits the opcode stream \
                    does not repeat",
        available_from: (3, 8),
        levels: every_level(strict_only(&["co_flags"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_names_appended",
        mechanism: "an unreferenced entry appended to co_names changes no argrepr, so only a \
                    field-by-field comparison sees it",
        available_from: (3, 8),
        levels: every_level(strict_only(&["co_names"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_varnames_appended",
        mechanism: "an unreferenced local widens co_varnames and co_nlocals without touching a \
                    single LOAD_FAST argrepr",
        available_from: (3, 8),
        levels: every_level(strict_only(&["co_varnames", "co_nlocals"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_consts_orphan",
        mechanism: "an orphan constant no instruction loads is exactly what a docstring loss looks \
                    like at the field level",
        available_from: (3, 8),
        levels: every_level(strict_only(&["co_consts"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_consts_reordered",
        mechanism: "the same constant values in a different order is a real difference the item \
                    calls out; no instruction references either entry, so the normalized tier is \
                    blind to it",
        available_from: (3, 8),
        levels: every_level(strict_only(&["co_consts"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_argcount",
        mechanism: "own_equiv compares argcount, posonlyargcount and kwonlyargcount itself, so \
                    this one must be reported by both tiers; a row that came back strict-only here \
                    would mean the normalized signature leg had stopped working",
        available_from: (3, 8),
        levels: every_level(caught_by_both(&["co_argcount"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_firstlineno",
        mechanism: "co_firstlineno is excluded from the byte tier on purpose and belongs to the \
                    line tier, so the byte dimensions stay empty while every reported position \
                    shifts",
        available_from: (3, 8),
        levels: every_level(LevelExpectation {
            normalized_detects: false,
            strict: Dimensions::None,
            lines: Lines::SomeMismatch,
            firstlineno_equal: false,
        }),
    },
    CaseExpectation {
        case: "mutant_qualname",
        mechanism: "co_qualname exists from 3.11 and is never rendered into the opcode stream",
        available_from: (3, 11),
        levels: every_level(strict_only(&["co_qualname"], Lines::AllMatch)),
    },
    CaseExpectation {
        case: "mutant_exceptiontable",
        mechanism: "the zero-cost exception table exists from 3.11 and dis.get_instructions never \
                    shows it, so a recovery that loses a handler range can still look equivalent",
        available_from: (3, 11),
        levels: every_level(strict_only(&["co_exceptiontable"], Lines::AllMatch)),
    },
];

#[derive(Debug)]
struct Row {
    case: String,
    optimize: u8,
    available: bool,
    unavailable_reason: String,
    normalized_ok: bool,
    dimensions: Vec<String>,
    firstlineno_equal: bool,
    position_lines_ok: u64,
    position_lines_total: u64,
    unknown_opcode_units: u64,
}

#[derive(Debug)]
struct Report {
    cpython_version: String,
    cpython_release: String,
    magic_number: String,
    position_full_supported: bool,
    probe_inline_cache_units: u64,
    probe_unknown_opcode_units: u64,
    excluded_dimensions: String,
    byte_dimensions: String,
    rows: Vec<Row>,
}

fn field<'a>(doc: &'a serde_json::Value, key: &str, context: &str) -> &'a serde_json::Value {
    doc.get(key)
        .unwrap_or_else(|| panic!("{context} carries no `{key}`: {doc}"))
}

fn text(doc: &serde_json::Value, key: &str, context: &str) -> String {
    field(doc, key, context)
        .as_str()
        .unwrap_or_else(|| panic!("{context} field `{key}` is not a string"))
        .to_owned()
}

fn count(doc: &serde_json::Value, key: &str, context: &str) -> u64 {
    field(doc, key, context)
        .as_u64()
        .unwrap_or_else(|| panic!("{context} field `{key}` is not an unsigned integer"))
}

fn flag(doc: &serde_json::Value, key: &str, context: &str) -> bool {
    match count(doc, key, context) {
        0 => false,
        1 => true,
        other => panic!("{context} field `{key}` is {other}, not the 0 or 1 a flag may carry"),
    }
}

fn parse_row(doc: &serde_json::Value) -> Row {
    let case: String = text(doc, "case", "differential row");
    let context: String = format!("differential row `{case}`");
    let raw: &Vec<serde_json::Value> = field(doc, "dimensions", &context)
        .as_array()
        .unwrap_or_else(|| panic!("{context} field `dimensions` is not an array"));
    Row {
        optimize: u8::try_from(count(doc, "optimize", &context))
            .unwrap_or_else(|e: std::num::TryFromIntError| panic!("{context} optimize: {e}")),
        available: flag(doc, "available", &context),
        unavailable_reason: text(doc, "unavailable_reason", &context),
        normalized_ok: flag(doc, "normalized_ok", &context),
        dimensions: raw
            .iter()
            .map(|entry: &serde_json::Value| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("{context} names a non-string dimension"))
                    .to_owned()
            })
            .collect(),
        firstlineno_equal: flag(doc, "firstlineno_equal", &context),
        position_lines_ok: count(doc, "position_lines_ok", &context),
        position_lines_total: count(doc, "position_lines_total", &context),
        unknown_opcode_units: count(doc, "unknown_opcode_units", &context),
        case,
    }
}

fn parse_report(stdout: &str) -> Report {
    let line: &str = stdout
        .lines()
        .find(|entry: &&str| entry.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON object on the differential harness stdout:\n{stdout}"));
    let doc: serde_json::Value = serde_json::from_str(line)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse differential report: {e}\n{line}"));
    let rows: &Vec<serde_json::Value> = field(&doc, "rows", "differential report")
        .as_array()
        .unwrap_or_else(|| panic!("differential report field `rows` is not an array"));
    Report {
        cpython_version: text(&doc, "cpython_version", "differential report"),
        cpython_release: text(&doc, "cpython_release", "differential report"),
        magic_number: text(&doc, "magic_number", "differential report"),
        position_full_supported: flag(&doc, "position_full_supported", "differential report"),
        probe_inline_cache_units: count(&doc, "probe_inline_cache_units", "differential report"),
        probe_unknown_opcode_units: count(
            &doc,
            "probe_unknown_opcode_units",
            "differential report",
        ),
        excluded_dimensions: text(&doc, "excluded_dimensions", "differential report"),
        byte_dimensions: text(&doc, "byte_dimensions", "differential report"),
        rows: rows.iter().map(parse_row).collect(),
    }
}

fn run_differential(python: &Path) -> Output {
    let harness: PathBuf = manifest_dir().join(DIFFERENTIAL_HARNESS);
    assert!(
        harness.is_file(),
        "differential harness missing at {}",
        harness.display()
    );
    let levels: String = OPTIMIZE_LEVELS
        .iter()
        .map(u8::to_string)
        .collect::<Vec<String>>()
        .join(",");
    Command::new(python)
        .arg(&harness)
        .arg("--optimize-levels")
        .arg(&levels)
        .stdin(Stdio::null())
        .output()
        .expect("spawn the tier differential harness")
}

fn magic_value(raw: &str, band: (u8, u8)) -> u16 {
    parse_magic(raw).unwrap_or_else(|complaint: String| {
        panic!(
            "CPython {}.{} reported a pyc magic this gate cannot read: {complaint}",
            band.0, band.1
        )
    })
}

fn expectation_for(case: &str) -> &'static CaseExpectation {
    CASES
        .iter()
        .find(|entry: &&CaseExpectation| entry.case == case)
        .unwrap_or_else(|| {
            panic!(
                "the differential harness reported a case `{case}` this gate holds no expectation \
                 for; every graded row needs a recorded verdict or the table can grow a row nobody \
                 checks"
            )
        })
}

fn judge(band: (u8, u8), release: &str, row: &Row) {
    let expectation: &CaseExpectation = expectation_for(&row.case);
    let level: usize = usize::from(row.optimize);
    let expected: LevelExpectation = expectation.levels[level];
    let where_: String = format!(
        "CPython {release} case `{}` at optimize {}",
        row.case, row.optimize
    );

    if band < expectation.available_from {
        assert!(
            !row.available,
            "{where_} was graded, but {}.{} is older than the {}.{} this comparison dimension \
             first exists on, so a verdict here would be measuring something that cannot be there",
            band.0, band.1, expectation.available_from.0, expectation.available_from.1
        );
        assert!(
            !row.unavailable_reason.is_empty(),
            "{where_} is unavailable without saying why; an unexplained blank row is how a \
             comparison dimension quietly stops being measured"
        );
        return;
    }

    assert!(
        row.available,
        "{where_} came back unavailable on a band that carries the dimension: {}",
        row.unavailable_reason
    );
    assert_eq!(
        row.normalized_ok,
        !expected.normalized_detects,
        "{where_}: the normalized tier {} it, expected it to {}. {}",
        if row.normalized_ok {
            "accepted"
        } else {
            "rejected"
        },
        if expected.normalized_detects {
            "reject it"
        } else {
            "accept it"
        },
        expectation.mechanism
    );

    match strict_expectation(&row.case, band, expected.strict) {
        Dimensions::None => assert!(
            row.dimensions.is_empty(),
            "{where_}: the byte tier reported {:?} where it must report nothing. {}",
            row.dimensions,
            expectation.mechanism
        ),
        Dimensions::Any => assert!(
            !row.dimensions.is_empty(),
            "{where_}: the byte tier reported nothing where it must report the loss on whichever \
             field this release encodes it in. {}",
            expectation.mechanism
        ),
        Dimensions::Contains {
            required,
            forbidden,
        } => {
            for dimension in required {
                assert!(
                    row.dimensions
                        .iter()
                        .any(|found: &String| found == dimension),
                    "{where_}: the byte tier never reported `{dimension}`, it reported {:?}. {}",
                    row.dimensions,
                    expectation.mechanism
                );
            }
            for dimension in forbidden {
                assert!(
                    !row.dimensions
                        .iter()
                        .any(|found: &String| found == dimension),
                    "{where_}: the byte tier reported `{dimension}`, which cannot differ here. {}",
                    expectation.mechanism
                );
            }
        }
    }

    assert!(
        !row.dimensions
            .iter()
            .any(|found: &String| found == DEPTH_LIMIT_DIMENSION),
        "{where_}: the constant walk hit its depth ceiling and returned `{DEPTH_LIMIT_DIMENSION}` \
         instead of a comparison; the verdict on this row means nothing"
    );

    assert!(
        row.position_lines_total > 0,
        "{where_}: the position leg aligned no instruction pairs, so its verdict is vacuous"
    );
    match expected.lines {
        Lines::AllMatch => assert_eq!(
            row.position_lines_ok, row.position_lines_total,
            "{where_}: {} of {} aligned instructions carry the original line, expected every one \
             of them to. {}",
            row.position_lines_ok, row.position_lines_total, expectation.mechanism
        ),
        Lines::SomeMismatch => assert!(
            row.position_lines_ok < row.position_lines_total,
            "{where_}: all {} aligned instructions carry the original line, so the line tier saw \
             nothing where it must see a shift. {}",
            row.position_lines_total,
            expectation.mechanism
        ),
        Lines::Unconstrained => assert!(
            row.position_lines_ok <= row.position_lines_total,
            "{where_}: {} of {} aligned instructions match on line, which is more matches than \
             there are pairs",
            row.position_lines_ok,
            row.position_lines_total
        ),
    }
    assert_eq!(
        row.firstlineno_equal,
        expected.firstlineno_equal,
        "{where_}: co_firstlineno {} where the case requires it to {}. {}",
        if row.firstlineno_equal {
            "matched"
        } else {
            "differed"
        },
        if expected.firstlineno_equal {
            "match"
        } else {
            "differ"
        },
        expectation.mechanism
    );
    assert_eq!(
        row.unknown_opcode_units, 0,
        "{where_}: {} code units carry an opcode absent from dis.opmap, which is what an adaptive \
         or instrumented opcode looks like; the strict tier compares freshly compiled objects only \
         and a specialised one has no business being here",
        row.unknown_opcode_units
    );
}

fn measure_band(band: BandRelease, python: &Path) -> (u16, usize, usize) {
    let output: Output = run_differential(python);
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "the tier differential harness exited {:?} on CPython {}.{}\nstdout:\n{stdout}\nstderr:\n\
         {stderr}",
        output.status.code(),
        band.version.0,
        band.version.1
    );
    let report: Report = parse_report(&stdout);
    println!("--- CPython {} ---\n{stderr}", report.cpython_release);

    assert_eq!(
        report.cpython_version,
        format!("{}.{}", band.version.0, band.version.1),
        "the harness ran on CPython {} while this gate resolved the {}.{} band; a row attributed \
         to the wrong band measures a different interpreter generation",
        report.cpython_version,
        band.version.0,
        band.version.1
    );
    assert_eq!(
        report.excluded_dimensions, EXCLUDED_DIMENSIONS,
        "the byte tier excludes {} but this gate records {EXCLUDED_DIMENSIONS}; a dimension may \
         only leave the comparison together with the reason recorded here",
        report.excluded_dimensions
    );
    assert_eq!(
        report.byte_dimensions, BYTE_DIMENSIONS,
        "the byte tier compares {} but this gate records {BYTE_DIMENSIONS}; a dimension that \
         disappears from the comparison must fail here rather than quietly stop being measured",
        report.byte_dimensions
    );
    assert_eq!(
        report.probe_unknown_opcode_units, 0,
        "{} code units in the probe object carry an opcode absent from dis.opmap",
        report.probe_unknown_opcode_units
    );

    let cached: bool = band.version >= FIRST_CACHED_SERIES;
    assert_eq!(
        report.position_full_supported, cached,
        "CPython {} reports co_positions() support {}, expected {cached}; before 3.11 there are no \
         column ranges and the tier must say so rather than score a line-only band as a full match",
        report.cpython_release, report.position_full_supported
    );
    if cached {
        assert!(
            report.probe_inline_cache_units > 0,
            "CPython {} put no CACHE code unit in the probe object's co_code, so the claim that \
             the byte tier compares inline caches rather than stripping them is untestable on this \
             band",
            report.cpython_release
        );
    } else {
        assert_eq!(
            report.probe_inline_cache_units, 0,
            "CPython {} reports {} inline cache units, but the CACHE opcode does not exist before \
             3.11",
            report.cpython_release, report.probe_inline_cache_units
        );
    }

    let magic: u16 = magic_value(&report.magic_number, band.version);
    if let SeriesMagic::Released(expected) = band.magic {
        assert_eq!(
            magic, expected,
            "CPython {} stamps pyc magic {magic} ({}), but the {}.{} series was released with \
             {expected}; the band either ran on an interpreter from another generation or the \
             recorded magic is wrong, and either way the rows above are attributed to the wrong \
             band",
            report.cpython_release, report.magic_number, band.version.0, band.version.1
        );
    }

    let mut strict_only_rows: usize = 0;
    let mut quiet_rows: usize = 0;
    for row in &report.rows {
        judge(band.version, &report.cpython_release, row);
        if !row.available {
            continue;
        }
        let strict_saw_it: bool =
            !row.dimensions.is_empty() || row.position_lines_ok != row.position_lines_total;
        if row.normalized_ok && strict_saw_it {
            strict_only_rows += 1;
        }
        if row.normalized_ok && !strict_saw_it {
            quiet_rows += 1;
        }
    }

    let graded: usize = report
        .rows
        .iter()
        .filter(|row: &&Row| row.available)
        .count();
    let expected_rows: usize = OPTIMIZE_LEVELS.len() * CASES.len();
    assert_eq!(
        report.rows.len(),
        expected_rows,
        "the harness graded {} rows where this gate holds {expected_rows} expectations",
        report.rows.len()
    );
    assert!(
        strict_only_rows > 0,
        "CPython {} produced no row the strict tier caught and the normalized tier accepted, so \
         this band proves nothing about the gap between them",
        report.cpython_release
    );
    assert!(
        quiet_rows > 0,
        "CPython {} produced no row both tiers accepted, so a strict tier that answered \
         `different` to every input would pass this band unchallenged",
        report.cpython_release
    );
    println!(
        "CPython {}: {graded} rows graded, {strict_only_rows} caught by the byte or line tier \
         alone, {quiet_rows} accepted by both, pyc magic {magic}",
        report.cpython_release
    );
    (magic, strict_only_rows, quiet_rows)
}

#[test]
fn the_strict_tier_catches_losses_the_normalized_tier_accepts_on_every_installed_band() {
    println!("=== STRICT TIER DIFFERENTIAL ===");
    let mut measured: Vec<((u8, u8), u16)> = Vec::new();
    for band in CPYTHON_SERIES {
        let graded: String = format!(
            "the strict-tier differential over CPython {}.{}",
            band.version.0, band.version.1
        );
        let Some(python): Option<PathBuf> = resolve_band_interpreter(&band.toolchain, &graded)
        else {
            continue;
        };
        let Some(resolved): Option<(u8, u8)> = interpreter_version(&python) else {
            panic!(
                "could not read the version of the interpreter at {}",
                python.display()
            );
        };
        assert_eq!(
            resolved,
            band.version,
            "`uv python find {}` resolved {}, which reports {}.{}",
            band.toolchain.alias,
            python.display(),
            resolved.0,
            resolved.1
        );
        let (magic, _, _): (u16, usize, usize) = measure_band(band, &python);
        measured.push((band.version, magic));
    }

    assert!(
        !measured.is_empty(),
        "no CPython interpreter between 3.8 and 3.15 could be resolved, so the strict tier was \
         compared against nothing; this case grades a real interpreter or it fails, it never \
         reports success on an empty measurement"
    );
    for window in measured.windows(2) {
        let (earlier, earlier_magic): ((u8, u8), u16) = window[0];
        let (later, later_magic): ((u8, u8), u16) = window[1];
        assert!(
            later_magic > earlier_magic,
            "CPython {}.{} stamps pyc magic {later_magic} and {}.{} stamps {earlier_magic}; \
             CPython raises the magic with every bytecode change, so a band that does not exceed \
             its predecessor is the same interpreter standing in for two bands",
            later.0,
            later.1,
            earlier.0,
            earlier.1
        );
    }
    println!(
        "bands measured: {}",
        measured
            .iter()
            .map(|((major, minor), magic): &((u8, u8), u16)| format!("{major}.{minor}={magic}"))
            .collect::<Vec<String>>()
            .join(" ")
    );
}

fn first_resolvable_interpreter() -> Option<(BandRelease, PathBuf)> {
    for band in CPYTHON_SERIES {
        let graded: String = format!(
            "the interpreter-mismatch refusal on CPython {}.{}",
            band.version.0, band.version.1
        );
        if let Some(python) = resolve_band_interpreter(&band.toolchain, &graded) {
            return Some((band, python));
        }
    }
    None
}

fn assert_refusal(output: &Output, harness: &str, demand: &str) {
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{harness} exited {:?} when handed {demand}; a harness that cannot prove it is the \
         interpreter the caller asked for must refuse, not measure\nstdout:\n{stdout}\nstderr:\n\
         {stderr}",
        output.status.code()
    );
    assert!(
        stderr.contains("REFUSED"),
        "{harness} exited non-zero on {demand} without saying it refused: {stderr}"
    );
    assert!(
        !stdout
            .lines()
            .any(|line: &str| line.trim_start().starts_with('{')),
        "{harness} refused {demand} and still emitted a measurement on stdout:\n{stdout}"
    );
}

#[test]
fn a_harness_handed_the_wrong_interpreter_refuses_instead_of_measuring() {
    let Some((band, python)): Option<(BandRelease, PathBuf)> = first_resolvable_interpreter()
    else {
        panic!(
            "no CPython interpreter between 3.8 and 3.15 could be resolved, so the refusal path \
             was never exercised"
        );
    };
    println!("=== INTERPRETER MISMATCH REFUSAL ===");
    println!(
        "driving CPython {}.{} at {}",
        band.version.0,
        band.version.1,
        python.display()
    );

    let differential: PathBuf = manifest_dir().join(DIFFERENTIAL_HARNESS);
    let corpus: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let absent_version: &str = "2.7";
    let absent_magic: &str = "deadbeef";

    for (harness, extra) in [
        (&differential, Vec::new()),
        (
            &corpus,
            vec![
                "--disrobe".to_owned(),
                "no-such-binary".to_owned(),
                "--lib".to_owned(),
                "no-such-lib".to_owned(),
                "--modules".to_owned(),
                "no-such-modules".to_owned(),
            ],
        ),
    ] {
        let name: String = harness
            .file_name()
            .map(|entry: &std::ffi::OsStr| entry.to_string_lossy().into_owned())
            .unwrap_or_default();
        let magic_run: Output = Command::new(&python)
            .arg(harness)
            .args(&extra)
            .arg("--require-magic")
            .arg(absent_magic)
            .stdin(Stdio::null())
            .output()
            .expect("spawn the harness with a magic it cannot satisfy");
        assert_refusal(&magic_run, &name, "a pyc magic no interpreter stamps");

        let version_run: Output = Command::new(&python)
            .arg(harness)
            .args(&extra)
            .arg("--require-version")
            .arg(absent_version)
            .stdin(Stdio::null())
            .output()
            .expect("spawn the harness with a version it cannot satisfy");
        assert_refusal(&version_run, &name, "an interpreter version it is not");

        println!("{name} refuses a wrong magic and a wrong version before measuring anything");
    }
}
