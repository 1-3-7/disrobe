#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate,
    clippy::doc_markdown
)]

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;

use super::band::{find_interpreter, interpreter_hidden};
use super::stdlib_measure::{BandReach, PublishedBar, bar_disagreements, published_detail};

pub(crate) const REQUIRE_EVERY_BAND_VAR: &str = "DISROBE_REQUIRE_PY_BANDS";

pub(crate) const PINNED_MODULE_LIST: &str = "tests/harness/pinned_modules_314.txt";
pub(crate) const PINNED_MODULE_COUNT: u64 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BandToolchain {
    pub alias: &'static str,
    pub release: &'static str,
    pub require_var: &'static str,
    pub install_hint: &'static str,
}

pub(crate) const CPYTHON_38: BandToolchain = BandToolchain {
    alias: "3.8",
    release: "3.8.20",
    require_var: "DISROBE_REQUIRE_PY_38",
    install_hint: "install it with `uv python install 3.8`",
};

pub(crate) const CPYTHON_39: BandToolchain = BandToolchain {
    alias: "3.9",
    release: "3.9.25",
    require_var: "DISROBE_REQUIRE_PY_39",
    install_hint: "install it with `uv python install 3.9`",
};

pub(crate) const CPYTHON_310: BandToolchain = BandToolchain {
    alias: "3.10",
    release: "3.10.20",
    require_var: "DISROBE_REQUIRE_PY_310",
    install_hint: "install it with `uv python install 3.10`",
};

pub(crate) const CPYTHON_311: BandToolchain = BandToolchain {
    alias: "3.11",
    release: "3.11.15",
    require_var: "DISROBE_REQUIRE_PY_311",
    install_hint: "install it with `uv python install 3.11`",
};

pub(crate) const CPYTHON_312: BandToolchain = BandToolchain {
    alias: "3.12",
    release: "3.12.13",
    require_var: "DISROBE_REQUIRE_PY_312",
    install_hint: "install it with `uv python install 3.12`",
};

pub(crate) const CPYTHON_313: BandToolchain = BandToolchain {
    alias: "3.13",
    release: "3.13.14",
    require_var: "DISROBE_REQUIRE_PY_313",
    install_hint: "install it with `uv python install 3.13`",
};

pub(crate) const CPYTHON_314: BandToolchain = BandToolchain {
    alias: "3.14",
    release: "3.14.5",
    require_var: "DISROBE_REQUIRE_PY_314",
    install_hint: "install it with `uv python install 3.14`",
};

pub(crate) const CPYTHON_315: BandToolchain = BandToolchain {
    alias: "3.15",
    release: "3.15.0b4",
    require_var: "DISROBE_REQUIRE_PY_315",
    install_hint: "install it with `uv python install 3.15`",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeriesMagic {
    Released(u16),
    PreRelease,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BandRelease {
    pub version: (u8, u8),
    pub toolchain: BandToolchain,
    pub magic: SeriesMagic,
}

pub(crate) const CPYTHON_SERIES: [BandRelease; 8] = [
    BandRelease {
        version: (3, 8),
        toolchain: CPYTHON_38,
        magic: SeriesMagic::Released(3413),
    },
    BandRelease {
        version: (3, 9),
        toolchain: CPYTHON_39,
        magic: SeriesMagic::Released(3425),
    },
    BandRelease {
        version: (3, 10),
        toolchain: CPYTHON_310,
        magic: SeriesMagic::Released(3439),
    },
    BandRelease {
        version: (3, 11),
        toolchain: CPYTHON_311,
        magic: SeriesMagic::Released(3495),
    },
    BandRelease {
        version: (3, 12),
        toolchain: CPYTHON_312,
        magic: SeriesMagic::Released(3531),
    },
    BandRelease {
        version: (3, 13),
        toolchain: CPYTHON_313,
        magic: SeriesMagic::Released(3571),
    },
    BandRelease {
        version: (3, 14),
        toolchain: CPYTHON_314,
        magic: SeriesMagic::Released(3627),
    },
    BandRelease {
        version: (3, 15),
        toolchain: CPYTHON_315,
        magic: SeriesMagic::PreRelease,
    },
];

pub(crate) const FIRST_CACHED_SERIES: (u8, u8) = (3, 11);

#[must_use]
pub(crate) fn magic_hex(value: u16) -> String {
    format!("{:02x}{:02x}0d0a", value & 0x00FF, value >> 8)
}

pub(crate) fn parse_magic(raw: &str) -> Result<u16, String> {
    if raw.len() != 8 {
        return Err(format!(
            "`{raw}` is not the four bytes every pyc magic number is made of"
        ));
    }
    if !raw.ends_with("0d0a") {
        return Err(format!(
            "`{raw}` does not end in the CR LF pair every CPython magic number carries"
        ));
    }
    let low: u16 = u16::from_str_radix(&raw[0..2], 16)
        .map_err(|e: std::num::ParseIntError| format!("`{raw}` low byte: {e}"))?;
    let high: u16 = u16::from_str_radix(&raw[2..4], 16)
        .map_err(|e: std::num::ParseIntError| format!("`{raw}` high byte: {e}"))?;
    Ok(low | (high << 8))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BandRequirement {
    Optional,
    Mandatory,
}

fn demands_it(value: Option<&OsStr>) -> bool {
    let Some(raw): Option<&OsStr> = value else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

#[must_use]
pub(crate) fn requirement_from_values(
    per_band: Option<&OsStr>,
    blanket: Option<&OsStr>,
) -> BandRequirement {
    if demands_it(per_band) || demands_it(blanket) {
        BandRequirement::Mandatory
    } else {
        BandRequirement::Optional
    }
}

#[must_use]
pub(crate) fn requirement(toolchain: &BandToolchain) -> BandRequirement {
    let per_band: Option<OsString> = std::env::var_os(toolchain.require_var);
    let blanket: Option<OsString> = std::env::var_os(REQUIRE_EVERY_BAND_VAR);
    requirement_from_values(per_band.as_deref(), blanket.as_deref())
}

pub(crate) fn enforce_requirement(
    toolchain: &BandToolchain,
    graded: &str,
    defect: &str,
    requirement: BandRequirement,
) {
    assert!(
        requirement == BandRequirement::Optional,
        "{var} (or {all}) makes CPython {alias} mandatory for this run, so {graded} was measured \
         against nothing and this case must not report success: {defect}. To fix it, {hint}; to \
         permit a run that re-derives nothing on this band, clear both variables.",
        var = toolchain.require_var,
        all = REQUIRE_EVERY_BAND_VAR,
        alias = toolchain.alias,
        hint = toolchain.install_hint,
    );
    announce_unmeasured(toolchain, graded, defect);
}

fn announce_unmeasured(toolchain: &BandToolchain, graded: &str, defect: &str) {
    let line: String = format!(
        "\nNOT MEASURED: {graded} compared nothing and graded nothing, because {defect}. The \
         published counts are still bound to this crate's constants by the checks that need no \
         interpreter, but nothing on this machine re-derived them from bytecode. Set {var}=1 (or \
         {all}=1) to fail instead of skipping when CPython {alias} cannot be run.\n",
        alias = toolchain.alias,
        var = toolchain.require_var,
        all = REQUIRE_EVERY_BAND_VAR,
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

#[must_use]
pub(crate) fn resolve_band_interpreter(toolchain: &BandToolchain, graded: &str) -> Option<PathBuf> {
    if !interpreter_hidden(toolchain.alias)
        && let Some(pinned) = find_interpreter(toolchain.release)
    {
        return Some(pinned);
    }
    let resolved: Option<PathBuf> = find_interpreter(toolchain.alias);
    if let Some(path) = resolved {
        return Some(path);
    }
    let defect: String = if interpreter_hidden(toolchain.alias) {
        format!(
            "DISROBE_TEST_HIDE_PY hides CPython {alias} from this run",
            alias = toolchain.alias
        )
    } else {
        format!(
            "`uv python find {alias}` resolved nothing and no known install path holds a CPython \
             {alias}",
            alias = toolchain.alias
        )
    };
    enforce_requirement(toolchain, graded, &defect, requirement(toolchain));
    None
}

pub(crate) fn release_mismatch(measured: &str, toolchain: &BandToolchain) -> Option<String> {
    if measured == toolchain.release {
        return None;
    }
    Some(format!(
        "this run measured CPython {measured}, but the band is pinned to CPython {pinned}. A \
         different patch release ships a different Lib and a different compiler, so the counts \
         this run produced describe a different population and cannot be compared to the \
         published ones. This is NOT a recovery regression and the numerator below is not \
         evidence of one. Install the pinned release with `uv python install {pinned}`; the \
         resolver prefers it over any newer {alias} once it is present.",
        pinned = toolchain.release,
        alias = toolchain.alias
    ))
}

pub(crate) fn assert_measurement_is_comparable(
    measured: &str,
    toolchain: &BandToolchain,
    graded: &str,
) {
    let mismatch: Option<String> = release_mismatch(measured, toolchain);
    assert!(
        mismatch.is_none(),
        "{graded} was measured against an interpreter it is not pinned to: {}",
        mismatch.unwrap_or_default()
    );
}

fn parenthesized(label: &str) -> &str {
    let Some(open): Option<usize> = label.find('(') else {
        panic!(
            "the band label `{label}` carries no parenthesized module count, which is the only \
             place the published module count appears; xtask/data/recovery.json gives these bars a \
             `num` and a `den` but no `modules` field, so the label text is what this gate reads"
        );
    };
    let rest: &str = &label[open + 1..];
    let Some(close): Option<usize> = rest.find(')') else {
        panic!("the band label `{label}` opens a parenthesis it never closes");
    };
    &rest[..close]
}

fn module_count_in_label(label: &str) -> u64 {
    let inside: &str = parenthesized(label);
    let Some(digits): Option<&str> = inside
        .split(|c: char| !c.is_ascii_digit())
        .find(|run: &&str| !run.is_empty())
    else {
        panic!(
            "the band label `{label}` states no module count between its parentheses, so the \
             published population has a numerator and a denominator but no count of the modules \
             they were drawn from"
        );
    };
    digits
        .parse::<u64>()
        .unwrap_or_else(|e: std::num::ParseIntError| {
            panic!("the module count in band label `{label}` does not parse: {e}")
        })
}

fn sole_band_bar<'a>(doc: &'a serde_json::Value, label: &str) -> &'a serde_json::Value {
    let Some(groups): Option<&Vec<serde_json::Value>> =
        doc.get("groups").and_then(serde_json::Value::as_array)
    else {
        panic!("xtask/data/recovery.json carries no groups array");
    };
    let mut found: Vec<&'a serde_json::Value> = Vec::new();
    for group in groups {
        let Some(bars): Option<&Vec<serde_json::Value>> =
            group.get("bars").and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for bar in bars {
            if bar.get("label").and_then(serde_json::Value::as_str) == Some(label) {
                found.push(bar);
            }
        }
    }
    match found.len() {
        1 => found[0],
        0 => panic!("xtask/data/recovery.json carries no bar labelled {label}"),
        n => panic!(
            "xtask/data/recovery.json carries {n} bars labelled {label}; a duplicated label lets \
             one band be read where another was published"
        ),
    }
}

fn band_scalar(bar: &serde_json::Value, label: &str, key: &str) -> u64 {
    let Some(value): Option<u64> = bar.get(key).and_then(serde_json::Value::as_u64) else {
        panic!("bar {label} carries no {key}");
    };
    value
}

fn published_module_count(bar: &serde_json::Value, label: &str) -> u64 {
    let from_label: u64 = module_count_in_label(label);
    let Some(from_field): Option<u64> = bar.get("modules").and_then(serde_json::Value::as_u64)
    else {
        return from_label;
    };
    assert_eq!(
        from_field, from_label,
        "bar {label} carries a `modules` field of {from_field} while its own label states \
         {from_label}; the chart renders the label and a gate reads the field, so the two homes of \
         one count have to agree"
    );
    from_field
}

#[must_use]
pub(crate) fn published_band_bar(doc: &serde_json::Value, label: &str) -> PublishedBar {
    let bar: &serde_json::Value = sole_band_bar(doc, label);
    let Some(value): Option<f64> = bar.get("value").and_then(serde_json::Value::as_f64) else {
        panic!("bar {label} carries no numeric value");
    };
    PublishedBar {
        value,
        num: band_scalar(bar, label, "num"),
        den: band_scalar(bar, label, "den"),
        modules: published_module_count(bar, label),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BandPopulation {
    pub objects_ok: u64,
    pub code_objects: u64,
    pub modules: u64,
}

impl BandPopulation {
    #[must_use]
    pub(crate) fn object_pct(&self) -> f64 {
        if self.code_objects == 0 {
            0.0
        } else {
            (self.objects_ok as f64) * 100.0 / (self.code_objects as f64)
        }
    }
}

#[must_use]
pub(crate) fn published_population(bar: &PublishedBar) -> BandPopulation {
    BandPopulation {
        objects_ok: bar.num,
        code_objects: bar.den,
        modules: bar.modules,
    }
}

#[must_use]
pub(crate) fn population_disagreements(
    measured: &BandPopulation,
    published: &PublishedBar,
) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    if measured.objects_ok != published.num {
        found.push(format!(
            "numerator {} is not the published {}",
            measured.objects_ok, published.num
        ));
    }
    if measured.code_objects != published.den {
        found.push(format!(
            "denominator {} is not the published {}",
            measured.code_objects, published.den
        ));
    }
    if measured.modules != published.modules {
        found.push(format!(
            "module count {} is not the published {}",
            measured.modules, published.modules
        ));
    }
    found
}

pub(crate) fn assert_population_pin_rejects_shrinkage(
    published: &PublishedBar,
    floor: f64,
    band: &str,
) {
    let truthful: BandPopulation = published_population(published);
    assert!(
        population_disagreements(&truthful, published).is_empty(),
        "the {band} counts this gate enforces must agree with the published bar before any mutant \
         is judged against them"
    );
    assert!(
        truthful.modules > 1 && truthful.code_objects > 1,
        "the {band} band publishes {} code objects over {} modules, too small to seed a dropped \
         module and a shrunken denominator against",
        truthful.code_objects,
        truthful.modules
    );

    let one_module_dropped: BandPopulation = BandPopulation {
        modules: published.modules - 1,
        ..truthful
    };
    assert_eq!(
        population_disagreements(&one_module_dropped, published).len(),
        1,
        "a run that graded {} of the {band} band's {} modules must be rejected: the module count is \
         part of the published figure, not a caption on it",
        one_module_dropped.modules,
        published.modules
    );

    let one_object_fewer: BandPopulation = BandPopulation {
        code_objects: published.den - 1,
        ..truthful
    };
    assert_eq!(
        population_disagreements(&one_object_fewer, published).len(),
        1,
        "a run that walked {} code objects instead of the published {} must be rejected",
        one_object_fewer.code_objects,
        published.den
    );

    let unrecovered: u64 = published.den - published.num;
    assert!(
        unrecovered > 0,
        "the {band} band publishes {} of {} code objects, leaving nothing unrecovered for the \
         shrinkage mutant to drop",
        published.num,
        published.den
    );
    let unrecovered_dropped: BandPopulation = BandPopulation {
        objects_ok: published.num,
        code_objects: published.den - unrecovered,
        modules: published.modules - 1,
    };
    assert!(
        unrecovered_dropped.object_pct() >= floor,
        "the {band} shrinkage mutant scores {:.2}%, under the {floor}% floor, so the percentage \
         floor would catch it and this control would prove nothing about the equality pin",
        unrecovered_dropped.object_pct()
    );
    assert_eq!(
        population_disagreements(&unrecovered_dropped, published).len(),
        2,
        "dropping the {band} band's {unrecovered} unrecovered code objects and the module that held \
         them scores {:.2}%, above the {floor}% floor, so a percentage floor alone passes it. The \
         denominator and module-count equality legs are what must reject it, and they did not",
        unrecovered_dropped.object_pct()
    );
}

fn sibling_band_labels(doc: &serde_json::Value, label: &str) -> Vec<String> {
    let Some(groups): Option<&Vec<serde_json::Value>> =
        doc.get("groups").and_then(serde_json::Value::as_array)
    else {
        panic!("xtask/data/recovery.json carries no groups array");
    };
    for group in groups {
        let Some(bars): Option<&Vec<serde_json::Value>> =
            group.get("bars").and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        let labels: Vec<String> = bars
            .iter()
            .filter_map(|bar: &serde_json::Value| {
                bar.get("label")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        if labels.iter().any(|other: &String| other == label) {
            return labels;
        }
    }
    panic!("xtask/data/recovery.json carries no group holding a bar labelled {label}");
}

pub(crate) fn assert_bands_are_distinct_populations(doc: &serde_json::Value, label: &str) {
    let labels: Vec<String> = sibling_band_labels(doc, label);
    assert!(
        labels.len() > 1,
        "the group holding `{label}` carries a single bar, so this check compares it against \
         nothing; the interpreter bands are published as a set and a set of one is a copy waiting \
         to happen"
    );

    let mut seen: Vec<(&str, BandPopulation)> = Vec::new();
    for sibling in &labels {
        let bar: PublishedBar = published_band_bar(doc, sibling);
        let population: BandPopulation = published_population(&bar);
        let duplicate: Option<&(&str, BandPopulation)> = seen
            .iter()
            .find(|(_, earlier): &&(&str, BandPopulation)| *earlier == population);
        if let Some((other, _)) = duplicate {
            panic!(
                "the `{sibling}` and `{other}` bars both publish {} / {} code objects over {} \
                 modules, so one band's measurement is standing in for another's and only one of \
                 the two figures was ever measured",
                population.objects_ok, population.code_objects, population.modules
            );
        }
        seen.push((sibling.as_str(), population));
    }
}

pub(crate) const OPCODES_RETIRED_AFTER_3_8: &[&str] = &[
    "BEGIN_FINALLY",
    "BUILD_LIST_UNPACK",
    "BUILD_MAP_UNPACK",
    "BUILD_MAP_UNPACK_WITH_CALL",
    "BUILD_TUPLE_UNPACK_WITH_CALL",
    "CALL_FINALLY",
    "END_FINALLY",
    "POP_FINALLY",
    "WITH_CLEANUP_FINISH",
    "WITH_CLEANUP_START",
];

pub(crate) const OPCODES_INTRODUCED_IN_3_9: &[&str] = &[
    "CONTAINS_OP",
    "DICT_MERGE",
    "DICT_UPDATE",
    "IS_OP",
    "JUMP_IF_NOT_EXC_MATCH",
    "LIST_EXTEND",
    "LIST_TO_TUPLE",
    "LOAD_ASSERTION_ERROR",
    "RERAISE",
    "SET_UPDATE",
    "WITH_EXCEPT_START",
];

pub(crate) fn assert_band_reaches_its_own_bytecode(
    reach: &BandReach,
    carried: &[&str],
    never_carried: &[&str],
    band: &str,
) {
    assert!(
        !carried.is_empty() && !never_carried.is_empty(),
        "the {band} reach check was handed {} opcodes the population must carry and {} it must \
         not; an empty list accepts whatever the population happens to contain and separates this \
         band from no other",
        carried.len(),
        never_carried.len()
    );

    let overlap: Vec<&str> = carried
        .iter()
        .copied()
        .filter(|op: &&str| never_carried.contains(op))
        .collect();
    assert!(
        overlap.is_empty(),
        "the {band} reach check names {overlap:?} as both carried and never carried, so it can \
         only ever contradict itself"
    );

    let absent: Vec<&str> = carried
        .iter()
        .copied()
        .filter(|op: &&str| !reach.opnames.contains(*op))
        .collect();
    assert!(
        absent.is_empty(),
        "the {band} population never reaches {absent:?}, so the band's measurement grades only \
         bytecode it shares with its neighbours and the figure says nothing about the constructs \
         this interpreter version actually compiles differently. It walked {} modules and {} code \
         objects carrying {} distinct opcodes",
        reach.modules,
        reach.code_objects,
        reach.opnames.len()
    );

    let intruders: Vec<&str> = never_carried
        .iter()
        .copied()
        .filter(|op: &&str| reach.opnames.contains(*op))
        .collect();
    assert!(
        intruders.is_empty(),
        "the {band} population carries {intruders:?}, which this interpreter version does not \
         emit, so the modules were compiled by a different CPython than the one this band names \
         (measured on CPython {})",
        reach.cpython_version
    );
}

#[derive(Debug, Clone)]
pub(crate) enum BandPublication {
    Published { label: String, bar: PublishedBar },
    Unpublished,
}

fn labels_with_prefix(doc: &serde_json::Value, prefix: &str) -> Vec<String> {
    let Some(groups): Option<&Vec<serde_json::Value>> =
        doc.get("groups").and_then(serde_json::Value::as_array)
    else {
        panic!("xtask/data/recovery.json carries no groups array");
    };
    let mut found: Vec<String> = Vec::new();
    for group in groups {
        let Some(bars): Option<&Vec<serde_json::Value>> =
            group.get("bars").and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for bar in bars {
            let Some(label): Option<&str> = bar.get("label").and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            if label.starts_with(prefix) {
                found.push(label.to_owned());
            }
        }
    }
    found.sort();
    found
}

#[must_use]
pub(crate) fn band_publication(doc: &serde_json::Value, prefix: &str) -> BandPublication {
    let labels: Vec<String> = labels_with_prefix(doc, prefix);
    match labels.len() {
        0 => BandPublication::Unpublished,
        1 => {
            let label: String = labels
                .into_iter()
                .next()
                .unwrap_or_else(|| panic!("a one-element label list yielded nothing"));
            let bar: PublishedBar = published_band_bar(doc, &label);
            BandPublication::Published { label, bar }
        }
        n => panic!(
            "xtask/data/recovery.json carries {n} bars whose label starts `{prefix}`: {labels:?}. \
             One interpreter band publishes one population, so a second bar under the same prefix \
             means one of the two figures was never measured"
        ),
    }
}

fn announce_unpublished(
    prefix: &str,
    expected_label: &str,
    enforced: &BandPopulation,
    cpython: &str,
) {
    let line: String = format!(
        "\nNOT PUBLISHED: no bar in xtask/data/recovery.json starts `{prefix}`, so the CPython \
         {cpython} figure of {} / {} code objects over {} modules lives only in this gate. Nothing \
         is claimed for this band on the recovery chart or in the docs. Publishing it means adding \
         a bar labelled `{expected_label}` with those exact counts; this case starts enforcing \
         equality against it the moment one exists.\n",
        enforced.objects_ok, enforced.code_objects, enforced.modules,
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

pub(crate) fn assert_publication_matches_the_gate(
    doc: &serde_json::Value,
    prefix: &str,
    expected_label: &str,
    enforced: &BandPopulation,
    floor: f64,
    cpython: &str,
) -> BandPublication {
    let publication: BandPublication = band_publication(doc, prefix);
    match &publication {
        BandPublication::Unpublished => {
            announce_unpublished(prefix, expected_label, enforced, cpython);
        }
        BandPublication::Published { label, bar } => {
            assert_eq!(
                label, expected_label,
                "xtask/data/recovery.json publishes this band as `{label}` and the gate names \
                 `{expected_label}`. The label carries the module count, so two spellings are two \
                 different published populations"
            );
            let against_floor: Vec<String> = bar_disagreements(bar, floor);
            assert!(
                against_floor.is_empty(),
                "the published `{label}` bar and the floor this gate enforces describe different \
                 numbers, and the recovery chart renders the JSON: {against_floor:?}"
            );
            let against_counts: Vec<String> = population_disagreements(enforced, bar);
            assert!(
                against_counts.is_empty(),
                "the published `{label}` bar reads {} / {} over {} modules, but this gate enforces \
                 {} / {} over {}: {against_counts:?}",
                bar.num,
                bar.den,
                bar.modules,
                enforced.objects_ok,
                enforced.code_objects,
                enforced.modules
            );
            let detail: String =
                published_detail(doc, label).unwrap_or_else(|e: String| panic!("{e}"));
            assert_detail_states_its_own_counts(&detail, bar, label);
            assert!(
                detail.contains(cpython),
                "the `{label}` detail never names the interpreter release the counts were measured \
                 on, so a re-measurement on another patch release cannot be told apart from this \
                 one: {detail}"
            );
            assert_bands_are_distinct_populations(doc, label);
        }
    }
    publication
}

pub(crate) fn assert_detail_states_its_own_counts(
    detail: &str,
    published: &PublishedBar,
    band: &str,
) {
    let fraction: String = format!("{} / {} code objects", published.num, published.den);
    assert!(
        detail.contains(&fraction),
        "the `{band}` detail never states its own `{fraction}`, so the chart shows a percentage \
         whose population is only readable from the JSON a reader never sees: {detail}"
    );

    let population: String = format!("over {} modules", published.modules);
    assert!(
        detail.contains(&population),
        "the `{band}` detail never states `{population}`, and the module count has no field of its \
         own in xtask/data/recovery.json, so the label and this sentence are the only places it is \
         published and they have to agree: {detail}"
    );
}
