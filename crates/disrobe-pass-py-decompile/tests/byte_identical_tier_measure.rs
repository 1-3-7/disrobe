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

use std::io::Write;
use std::path::PathBuf;

use common::band_gate::{
    BandRelease, BandRequirement, CPYTHON_SERIES, FIRST_CACHED_SERIES, PINNED_MODULE_LIST,
    REQUIRE_EVERY_BAND_VAR, SeriesMagic, magic_hex, parse_magic, requirement_from_values,
    resolve_band_interpreter,
};
use common::stdlib_measure::{
    HarnessRun, MEASURE_HARNESS, find_disrobe, interpreter_stdlib, interpreter_version,
    manifest_dir, run_strict_measure, workspace_target,
};

const FIRST_PINNED_SERIES: (u8, u8) = (3, 8);
const GATE_PREFIX: &str = "arbitrary_recompile_gate";
const UNSUFFIXED_GATE_SERIES: (u8, u8) = (3, 14);
const EXCLUDED_DIMENSIONS: &str = "co_filename,co_linetable,co_firstlineno";
const DEPTH_LIMIT_KEY: &str = "strict_dim_co_consts_depth_limit";
const THIN_SAMPLE_MODULES: u64 = 100;
const THIN_SAMPLE_OBJECTS: u64 = 1_000;

const DIMENSION_KEYS: [&str; 16] = [
    "strict_dim_co_code",
    "strict_dim_co_argcount",
    "strict_dim_co_posonlyargcount",
    "strict_dim_co_kwonlyargcount",
    "strict_dim_co_nlocals",
    "strict_dim_co_stacksize",
    "strict_dim_co_flags",
    "strict_dim_co_name",
    "strict_dim_co_names",
    "strict_dim_co_varnames",
    "strict_dim_co_freevars",
    "strict_dim_co_cellvars",
    "strict_dim_co_qualname",
    "strict_dim_co_exceptiontable",
    "strict_dim_co_consts",
    DEPTH_LIMIT_KEY,
];

#[derive(Debug)]
struct StrictMeasurement {
    modules: u64,
    code_objects: u64,
    objects_ok: u64,
    object_pct: f64,
    optimize_level: u64,
    strict_recompile_equivalent: u64,
    strict_byte_identical: u64,
    strict_byte_identical_pct: f64,
    strict_population_total: u64,
    strict_population_pct: f64,
    strict_firstlineno_ok: u64,
    strict_position_lines_ok: u64,
    strict_position_lines_total: u64,
    strict_position_lines_pct: f64,
    strict_position_full_ok: u64,
    strict_position_full_total: u64,
    strict_position_full_pct: f64,
    strict_position_full_supported: bool,
    strict_alignment_coverage_pct: f64,
    strict_no_debug_ranges_objects: u64,
    strict_inline_cache_units: u64,
    strict_unknown_opcode_units: u64,
    strict_excluded_dimensions: String,
    dimension_hits: Vec<(&'static str, u64)>,
    cpython_version: String,
    magic_number: String,
}

fn field<'a>(doc: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    doc.get(key)
        .unwrap_or_else(|| panic!("the strict-tier measurement carries no `{key}`: {doc}"))
}

fn count(doc: &serde_json::Value, key: &str) -> u64 {
    field(doc, key)
        .as_u64()
        .unwrap_or_else(|| panic!("measurement field `{key}` is not an unsigned integer"))
}

fn ratio(doc: &serde_json::Value, key: &str) -> f64 {
    field(doc, key)
        .as_f64()
        .unwrap_or_else(|| panic!("measurement field `{key}` is not a number"))
}

fn text(doc: &serde_json::Value, key: &str) -> String {
    field(doc, key)
        .as_str()
        .unwrap_or_else(|| panic!("measurement field `{key}` is not a string"))
        .to_owned()
}

fn parse_strict_measurement(stdout: &str) -> StrictMeasurement {
    let line: &str = stdout
        .lines()
        .find(|entry: &&str| entry.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON object on the harness stdout:\n{stdout}"));
    let doc: serde_json::Value = serde_json::from_str(line)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse strict measurement: {e}\n{line}"));
    StrictMeasurement {
        modules: count(&doc, "modules"),
        code_objects: count(&doc, "code_objects"),
        objects_ok: count(&doc, "objects_ok"),
        object_pct: ratio(&doc, "object_pct"),
        optimize_level: count(&doc, "optimize_level"),
        strict_recompile_equivalent: count(&doc, "strict_recompile_equivalent"),
        strict_byte_identical: count(&doc, "strict_byte_identical"),
        strict_byte_identical_pct: ratio(&doc, "strict_byte_identical_pct"),
        strict_population_total: count(&doc, "strict_population_total"),
        strict_population_pct: ratio(&doc, "strict_population_pct"),
        strict_firstlineno_ok: count(&doc, "strict_firstlineno_ok"),
        strict_position_lines_ok: count(&doc, "strict_position_lines_ok"),
        strict_position_lines_total: count(&doc, "strict_position_lines_total"),
        strict_position_lines_pct: ratio(&doc, "strict_position_lines_pct"),
        strict_position_full_ok: count(&doc, "strict_position_full_ok"),
        strict_position_full_total: count(&doc, "strict_position_full_total"),
        strict_position_full_pct: ratio(&doc, "strict_position_full_pct"),
        strict_position_full_supported: count(&doc, "strict_position_full_supported") == 1,
        strict_alignment_coverage_pct: ratio(&doc, "strict_alignment_coverage_pct"),
        strict_no_debug_ranges_objects: count(&doc, "strict_no_debug_ranges_objects"),
        strict_inline_cache_units: count(&doc, "strict_inline_cache_units"),
        strict_unknown_opcode_units: count(&doc, "strict_unknown_opcode_units"),
        strict_excluded_dimensions: text(&doc, "strict_excluded_dimensions"),
        dimension_hits: DIMENSION_KEYS
            .iter()
            .map(|key: &&'static str| (*key, count(&doc, key)))
            .collect(),
        cpython_version: text(&doc, "cpython_version"),
        magic_number: text(&doc, "magic_number"),
    }
}

fn announce_unmeasurable(defect: &str) {
    let blanket: Option<std::ffi::OsString> = std::env::var_os(REQUIRE_EVERY_BAND_VAR);
    assert!(
        requirement_from_values(None, blanket.as_deref()) == BandRequirement::Optional,
        "{REQUIRE_EVERY_BAND_VAR} makes every band mandatory for this run, so the byte-identical \
         and line-table tiers measured nothing and this case must not report success: {defect}"
    );
    let line: String = format!(
        "\nNOT MEASURED: the byte-identical and line-table tiers compared nothing, because \
         {defect}. Set {REQUIRE_EVERY_BAND_VAR}=1 to fail instead of announcing when the tiers \
         cannot be re-derived on this machine.\n"
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

fn required_magic(band: BandRelease) -> Option<String> {
    match band.magic {
        SeriesMagic::Released(value) => Some(magic_hex(value)),
        SeriesMagic::PreRelease => None,
    }
}

fn assert_band_invariants(band: BandRelease, measurement: &StrictMeasurement) {
    let series: String = format!("{}.{}", band.version.0, band.version.1);
    let release: &str = &measurement.cpython_version;

    assert_eq!(
        measurement.optimize_level, 0,
        "CPython {release} measured the {series} band at optimize {}; -O strips asserts and -OO \
         strips docstrings, so a recovery that always drops them scores perfectly under those \
         flags and the published figure has to be the optimize 0 one",
        measurement.optimize_level
    );

    assert_eq!(
        measurement.strict_recompile_equivalent, measurement.objects_ok,
        "the strict tier graded {} code objects while the normalized tier passed {}; a strict tier \
         that walks fewer objects than the tier it sits on top of reports a flattering rate over a \
         population nobody published",
        measurement.strict_recompile_equivalent, measurement.objects_ok
    );
    assert_eq!(
        measurement.strict_population_total, measurement.code_objects,
        "the strict tier reports over {} code objects while the normalized tier walked {}; both \
         tiers have to answer on one denominator or their percentages cannot be compared",
        measurement.strict_population_total, measurement.code_objects
    );
    assert!(
        measurement.strict_byte_identical <= measurement.strict_recompile_equivalent,
        "byte-identical count {} passes its own denominator {}",
        measurement.strict_byte_identical,
        measurement.strict_recompile_equivalent
    );
    assert!(
        measurement.strict_firstlineno_ok <= measurement.strict_recompile_equivalent,
        "co_firstlineno match count {} passes its own denominator {}",
        measurement.strict_firstlineno_ok,
        measurement.strict_recompile_equivalent
    );
    assert!(
        measurement.strict_position_lines_ok <= measurement.strict_position_lines_total,
        "position line-match count {} passes its own denominator {}",
        measurement.strict_position_lines_ok,
        measurement.strict_position_lines_total
    );
    assert!(
        measurement.strict_position_full_ok <= measurement.strict_position_full_total,
        "position full-match count {} passes its own denominator {}",
        measurement.strict_position_full_ok,
        measurement.strict_position_full_total
    );

    assert!(
        measurement.strict_recompile_equivalent > 0,
        "the {series} band handed the strict tier no code object at all, so every count below it \
         is zero over zero and every leg of this case passes without comparing anything; a band \
         that recovers nothing must fail here rather than report a tier it never ran"
    );
    assert!(
        measurement.strict_position_lines_total > 0,
        "the {series} band aligned no instruction pairs, so the line tier scored nothing and its \
         percentage is vacuous"
    );

    assert!(
        measurement.modules >= THIN_SAMPLE_MODULES
            && measurement.code_objects >= THIN_SAMPLE_OBJECTS,
        "the {series} band measured {} modules and {} code objects, too thin a sample for the \
         strict tier to say anything about this interpreter",
        measurement.modules,
        measurement.code_objects
    );

    assert_eq!(
        measurement.strict_excluded_dimensions, EXCLUDED_DIMENSIONS,
        "the byte tier excludes {} on this run and {EXCLUDED_DIMENSIONS} in this gate; a field may \
         only leave the comparison together with a recorded reason",
        measurement.strict_excluded_dimensions
    );
    assert_eq!(
        measurement.strict_unknown_opcode_units, 0,
        "{} compared code units carry an opcode absent from dis.opmap, which is what an adaptive \
         or instrumented opcode looks like; the strict tier compares freshly compiled objects only",
        measurement.strict_unknown_opcode_units
    );

    let depth_limited: u64 = measurement
        .dimension_hits
        .iter()
        .find(|(key, _): &&(&str, u64)| *key == DEPTH_LIMIT_KEY)
        .map_or(0, |(_, hits): &(&str, u64)| *hits)
        .to_owned();
    assert_eq!(
        depth_limited, 0,
        "{depth_limited} objects hit the constant-nesting ceiling instead of being compared, so \
         their verdicts mean nothing"
    );

    let unequal: u64 = measurement.strict_recompile_equivalent - measurement.strict_byte_identical;
    let hits: u64 = measurement
        .dimension_hits
        .iter()
        .map(|(_, count): &(&str, u64)| *count)
        .sum();
    assert!(
        hits >= unequal,
        "{unequal} objects were not byte-identical but only {hits} dimension hits were recorded; \
         every object the byte tier rejects has to name at least one field it rejected it on"
    );

    let cached: bool = band.version >= FIRST_CACHED_SERIES;
    assert_eq!(
        measurement.strict_position_full_supported, cached,
        "CPython {release} reports co_positions() support {}, expected {cached}; before 3.11 there \
         are no column ranges, and a band scored line-only must say so rather than publish a full \
         position rate it cannot measure",
        measurement.strict_position_full_supported
    );
    if cached {
        assert!(
            measurement.strict_inline_cache_units > 0,
            "CPython {release} compared {} code objects and found no CACHE code unit in any of \
             them; inline caches are part of co_code from 3.11 and the byte tier compares co_code \
             raw, so a run that sees none is not comparing what it claims to",
            measurement.strict_recompile_equivalent
        );
    } else {
        assert_eq!(
            measurement.strict_inline_cache_units, 0,
            "CPython {release} reports {} inline cache units, but the CACHE opcode does not exist \
             before 3.11",
            measurement.strict_inline_cache_units
        );
    }

    let magic: u16 = parse_magic(&measurement.magic_number).unwrap_or_else(|complaint: String| {
        panic!("CPython {release} reported a pyc magic this gate cannot read: {complaint}")
    });
    if let SeriesMagic::Released(expected) = band.magic {
        assert_eq!(
            magic, expected,
            "CPython {release} stamps pyc magic {magic}, but the {series} series was released with \
             {expected}; the counts above would be attributed to a band this interpreter does not \
             belong to"
        );
    }
    assert!(
        measurement.cpython_version.starts_with(&series),
        "the harness measured CPython {release} under the {series} band"
    );
}

fn report_band(band: BandRelease, measurement: &StrictMeasurement) {
    let series: String = format!("{}.{}", band.version.0, band.version.1);
    println!(
        "band {series} (CPython {}, pyc magic {}):",
        measurement.cpython_version, measurement.magic_number
    );
    println!(
        "  normalized recompile-equivalence {} / {} code objects ({:.2}%) over {} modules at \
         optimize {}",
        measurement.objects_ok,
        measurement.code_objects,
        measurement.object_pct,
        measurement.modules,
        measurement.optimize_level
    );
    println!(
        "  byte tier {} / {} of the recompile-equivalent objects ({:.2}%), and {} / {} of the \
         whole normalized population ({:.2}%)",
        measurement.strict_byte_identical,
        measurement.strict_recompile_equivalent,
        measurement.strict_byte_identical_pct,
        measurement.strict_byte_identical,
        measurement.strict_population_total,
        measurement.strict_population_pct
    );
    println!(
        "  line tier co_firstlineno {} / {}, positions lines {} / {} ({:.2}%), full {} / {} \
         ({:.2}%), alignment coverage {:.2}%, {} objects scored lines-only",
        measurement.strict_firstlineno_ok,
        measurement.strict_recompile_equivalent,
        measurement.strict_position_lines_ok,
        measurement.strict_position_lines_total,
        measurement.strict_position_lines_pct,
        measurement.strict_position_full_ok,
        measurement.strict_position_full_total,
        measurement.strict_position_full_pct,
        measurement.strict_alignment_coverage_pct,
        measurement.strict_no_debug_ranges_objects
    );
    println!(
        "  inline cache units in the compared streams {}, opcode units absent from dis.opmap {}",
        measurement.strict_inline_cache_units, measurement.strict_unknown_opcode_units
    );
    for (key, hits) in &measurement.dimension_hits {
        if *hits > 0 {
            println!("  fidelity lost on {key}: {hits} objects");
        }
    }
}

#[test]
fn byte_identical_tier_over_every_measured_band() {
    println!("=== BYTE-IDENTICAL AND LINE-TABLE TIERS (MEASUREMENT, NON-GATING) ===");
    println!(
        "These tiers report; they gate nothing and they never lower the normalized floor the \
         arbitrary_recompile_gate_* cases enforce. What is asserted here is the bookkeeping: one \
         denominator shared with the normalized tier, an optimize level that cannot flatter a \
         recovery, a pyc magic that belongs to the band, and inline caches inside the compared \
         bytes rather than stripped out of them."
    );

    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        announce_unmeasurable(&format!(
            "no disrobe binary sits under {}/(release|debug), and these tiers grade the real CLI's \
             recovered source (build it with `cargo build --release -p disrobe-cli --bin disrobe`)",
            workspace_target().display()
        ));
        return;
    };

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let modules: PathBuf = manifest_dir().join(PINNED_MODULE_LIST);
    assert!(
        harness.is_file(),
        "harness missing at {}",
        harness.display()
    );
    assert!(
        modules.is_file(),
        "pinned module list missing at {}",
        modules.display()
    );

    let mut measured: Vec<(u8, u8)> = Vec::new();
    for band in CPYTHON_SERIES {
        if band.version < FIRST_PINNED_SERIES {
            continue;
        }
        let series: String = format!("{}.{}", band.version.0, band.version.1);
        let graded: String =
            format!("the byte-identical and line-table tiers over the CPython {series} band");
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
        let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
            panic!(
                "could not resolve the stdlib Lib directory of {}",
                python.display()
            );
        };

        let magic: Option<String> = required_magic(band);
        let run: HarnessRun =
            run_strict_measure(&python, &disrobe, &lib, &modules, &series, magic.as_deref());
        println!("--- CPython {series} harness taxonomy ---\n{}", run.stderr);
        assert!(
            run.success,
            "the strict-tier harness exited {:?} on the {series} band\nstdout:\n{}\nstderr:\n{}",
            run.code, run.stdout, run.stderr
        );

        let measurement: StrictMeasurement = parse_strict_measurement(&run.stdout);
        report_band(band, &measurement);
        assert_band_invariants(band, &measurement);
        measured.push(band.version);
    }

    assert!(
        !measured.is_empty(),
        "a disrobe binary was found but no CPython between {}.{} and 3.15 could be resolved, so \
         the strict tiers graded nothing on any band",
        FIRST_PINNED_SERIES.0,
        FIRST_PINNED_SERIES.1
    );
    println!(
        "bands measured by the strict tiers: {}",
        measured
            .iter()
            .map(|(major, minor): &(u8, u8)| format!("{major}.{minor}"))
            .collect::<Vec<String>>()
            .join(" ")
    );
}

fn band_of_gate_file(stem: &str) -> (u8, u8) {
    let name: &str = stem;
    let Some(suffix): Option<&str> = stem.strip_prefix(GATE_PREFIX) else {
        panic!("`{name}` does not start with `{GATE_PREFIX}`")
    };
    if suffix.is_empty() {
        return UNSUFFIXED_GATE_SERIES;
    }
    let digits: &str = suffix.strip_prefix('_').unwrap_or_else(|| {
        panic!(
            "`{name}` carries the suffix `{suffix}` where a band gate names its series as \
             `_3NN`, so this gate cannot tell which interpreter it measures"
        )
    });
    let (major, minor): (&str, &str) = digits.split_at(1);
    (
        major
            .parse::<u8>()
            .unwrap_or_else(|e: std::num::ParseIntError| {
                panic!("`{name}` major version `{major}`: {e}")
            }),
        minor
            .parse::<u8>()
            .unwrap_or_else(|e: std::num::ParseIntError| {
                panic!("`{name}` minor version `{minor}`: {e}")
            }),
    )
}

fn normalized_gate_bands() -> Vec<(u8, u8)> {
    let tests: PathBuf = manifest_dir().join("tests");
    let entries: std::fs::ReadDir = std::fs::read_dir(&tests)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", tests.display()));
    let mut found: Vec<(u8, u8)> = Vec::new();
    for entry in entries {
        let path: PathBuf = entry
            .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", tests.display()))
            .path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
            continue;
        }
        let stem: String = path
            .file_stem()
            .map(|entry: &std::ffi::OsStr| entry.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !stem.starts_with(GATE_PREFIX) {
            continue;
        }
        found.push(band_of_gate_file(&stem));
    }
    found.sort_unstable();
    found
}

#[test]
fn every_band_the_normalized_tier_measures_is_a_band_the_strict_tier_reaches() {
    let pinned: Vec<(u8, u8)> = CPYTHON_SERIES
        .iter()
        .map(|band: &BandRelease| band.version)
        .filter(|version: &(u8, u8)| *version >= FIRST_PINNED_SERIES)
        .collect();
    let gates: Vec<(u8, u8)> = normalized_gate_bands();
    assert!(
        !gates.is_empty(),
        "no `{GATE_PREFIX}*.rs` case was found beside this one, so this check compares the strict \
         band set against nothing"
    );
    assert_eq!(
        pinned, gates,
        "the strict tiers walk {pinned:?} while the crate ships normalized band gates for \
         {gates:?}; the strict tier has to run wherever the normalized tier runs, so a band gate \
         added or removed on disk has to move the strict band set with it"
    );
    for version in gates {
        let band: &BandRelease = CPYTHON_SERIES
            .iter()
            .find(|entry: &&BandRelease| entry.version == version)
            .unwrap_or_else(|| panic!("no series entry for CPython {}.{}", version.0, version.1));
        match band.magic {
            SeriesMagic::Released(value) => {
                let hex: String = magic_hex(value);
                assert_eq!(
                    parse_magic(&hex),
                    Ok(value),
                    "the magic this gate demands of CPython {}.{} does not survive a round trip \
                     through its own hex form, so the harness would be handed a demand it can \
                     never satisfy",
                    version.0,
                    version.1
                );
            }
            SeriesMagic::PreRelease => assert_eq!(
                version,
                (3, 15),
                "CPython {}.{} is recorded as pre-release, but only 3.15 is unreleased; a released \
                 series with no recorded magic lets a band run on the wrong interpreter unnoticed",
                version.0,
                version.1
            ),
        }
    }
}
