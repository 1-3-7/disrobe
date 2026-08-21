use std::path::{Path, PathBuf};

use eyre::{Result, bail};
use serde::Deserialize;

use crate::datamodel::{VerificationDoc, VerificationRow};
use crate::fileio::read_text_bounded;

const MAX_DATA_JSON_BYTES: u64 = 4 * 1024 * 1024;
const AGREEMENT_TOLERANCE: f64 = 0.005;

#[derive(Debug, Deserialize)]
struct Recovery {
    groups: Vec<RecoveryGroup>,
}

#[derive(Debug, Deserialize)]
struct RecoveryGroup {
    heading: String,
    bars: Vec<RecoveryBar>,
}

#[derive(Debug, Deserialize)]
struct RecoveryBar {
    label: String,
    #[serde(default)]
    value: Option<f64>,
    #[serde(default)]
    num: Option<u64>,
    #[serde(default)]
    den: Option<u64>,
    #[serde(default)]
    detected: Option<u64>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Ecosystems {
    cells: Vec<EcosystemCell>,
}

#[derive(Debug, Deserialize)]
struct EcosystemCell {
    label: String,
    #[serde(default)]
    note: String,
}

enum Expected {
    Detected {
        heading: &'static str,
        label: &'static str,
    },
    Percent {
        heading: &'static str,
        label: &'static str,
    },
}

struct CrossClaim {
    file: &'static str,
    row: &'static str,
    unit: &'static str,
    expected: Expected,
}

#[derive(Debug)]
struct MirrorClaim {
    truth_heading: &'static str,
    truth_label: &'static str,
    copy_heading: &'static str,
    copy_label: &'static str,
    why: &'static str,
}

const MIRRORS: [MirrorClaim; 1] = [MirrorClaim {
    truth_heading: "Python bytecode (CPython 3.14 stdlib",
    truth_label: "200-module pinned corpus",
    copy_heading: "Python bytecode by interpreter band",
    copy_label: "CPython 3.14 (all 200 pinned modules)",
    why: "the interpreter-band chart re-plots the pinned-corpus measurement for 3.14, so the two \
          bars are one measurement published twice and only the first is asserted by a gate",
}];

const CLAIMS: [CrossClaim; 2] = [
    CrossClaim {
        file: "ecosystems.json",
        row: "Containers",
        unit: "formats",
        expected: Expected::Detected {
            heading: "Detection and extraction breadth",
            label: "Containers",
        },
    },
    CrossClaim {
        file: "verification.json",
        row: "Python",
        unit: "%",
        expected: Expected::Percent {
            heading: "Python bytecode",
            label: "200-module pinned corpus",
        },
    },
];

fn find_bar<'a>(doc: &'a Recovery, heading: &str, label: &str) -> Option<&'a RecoveryBar> {
    doc.groups
        .iter()
        .filter(|group: &&RecoveryGroup| group.heading.contains(heading))
        .flat_map(|group: &RecoveryGroup| group.bars.iter())
        .find(|bar: &&RecoveryBar| bar.label == label)
}

fn first_number(text: &str) -> Option<f64> {
    let mut digits: String = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() || (ch == '.' && !digits.is_empty()) {
            digits.push(ch);
        } else if !digits.is_empty() {
            break;
        }
    }
    digits.parse::<f64>().ok()
}

fn resolve(doc: &Recovery, expected: &Expected) -> Option<f64> {
    match expected {
        Expected::Detected { heading, label } => find_bar(doc, heading, label)?
            .detected
            .map(|v: u64| v as f64),
        Expected::Percent { heading, label } => find_bar(doc, heading, label)?.value,
    }
}

fn mirrored_fields(bar: &RecoveryBar) -> [(&'static str, Option<f64>); 3] {
    [
        ("value", bar.value),
        ("num", bar.num.map(|raw: u64| raw as f64)),
        ("den", bar.den.map(|raw: u64| raw as f64)),
    ]
}

fn check_mirrors(recovery: &Recovery, issues: &mut Vec<String>) {
    for mirror in &MIRRORS {
        let Some(truth): Option<&RecoveryBar> =
            find_bar(recovery, mirror.truth_heading, mirror.truth_label)
        else {
            issues.push(format!(
                "recovery.json has no `{}` bar under a heading containing `{}`, so the `{}` bar \
                 that re-plots it is compared against nothing",
                mirror.truth_label, mirror.truth_heading, mirror.copy_label
            ));
            continue;
        };
        let Some(copy): Option<&RecoveryBar> =
            find_bar(recovery, mirror.copy_heading, mirror.copy_label)
        else {
            issues.push(format!(
                "recovery.json has no `{}` bar under a heading containing `{}`, so the check that \
                 holds it in step with `{}` covers nothing",
                mirror.copy_label, mirror.copy_heading, mirror.truth_label
            ));
            continue;
        };

        for ((field, stated), (_, expected)) in mirrored_fields(copy)
            .into_iter()
            .zip(mirrored_fields(truth))
        {
            match (stated, expected) {
                (Some(stated), Some(expected))
                    if (stated - expected).abs() > AGREEMENT_TOLERANCE =>
                {
                    issues.push(format!(
                        "bar `{}` states `{field}` {stated} while `{}` states {expected}; {}",
                        mirror.copy_label, mirror.truth_label, mirror.why
                    ));
                }
                (None, Some(expected)) => issues.push(format!(
                    "bar `{}` carries no `{field}` while `{}` states {expected}; {}",
                    mirror.copy_label, mirror.truth_label, mirror.why
                )),
                (Some(stated), None) => issues.push(format!(
                    "bar `{}` states `{field}` {stated} while `{}` carries none, so the bar the \
                     gate asserts no longer records the figure its copy plots",
                    mirror.copy_label, mirror.truth_label
                )),
                _ => {}
            }
        }
    }
}

fn cites_a_line_number(text: &str) -> Option<String> {
    let bytes: &[u8] = text.as_bytes();
    let mut at: usize = 0;
    while let Some(found) = text.get(at..).and_then(|rest: &str| rest.find(".rs:")) {
        let colon: usize = at.saturating_add(found).saturating_add(3);
        let digits: usize = bytes
            .get(colon.saturating_add(1)..)
            .map_or(0, |rest: &[u8]| {
                rest.iter().take_while(|b: &&u8| b.is_ascii_digit()).count()
            });
        if digits != 0 {
            let start: usize = text[..colon]
                .rfind(|c: char| c.is_whitespace() || c == '(')
                .map_or(0, |at: usize| at.saturating_add(1));
            let end: usize = colon.saturating_add(1).saturating_add(digits);
            return text.get(start..end).map(str::to_owned);
        }
        at = colon;
    }
    None
}

fn check_line_citations(recovery: &Recovery, issues: &mut Vec<String>) {
    for group in &recovery.groups {
        for bar in &group.bars {
            for (field, text) in [("detail", &bar.detail), ("source", &bar.source)] {
                let Some(text) = text.as_deref() else {
                    continue;
                };
                let Some(citation) = cites_a_line_number(text) else {
                    continue;
                };
                issues.push(format!(
                    "{} / {}: the {field} cites `{citation}`, and a line number is a position that \
                     moves on any edit above it. Three such citations had already drifted, one of \
                     them naming a file the constant had left entirely, so a reader following it \
                     found nothing. Cite the constant by name instead",
                    group.heading, bar.label
                ));
            }
        }
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let data: PathBuf = root.join("xtask").join("data");
    let recovery: Recovery = serde_json::from_str(&read_text_bounded(
        &data.join("recovery.json"),
        MAX_DATA_JSON_BYTES,
    )?)?;
    let ecosystems: Ecosystems = serde_json::from_str(&read_text_bounded(
        &data.join("ecosystems.json"),
        MAX_DATA_JSON_BYTES,
    )?)?;
    let verification: VerificationDoc = serde_json::from_str(&read_text_bounded(
        &data.join("verification.json"),
        MAX_DATA_JSON_BYTES,
    )?)?;

    let mut issues: Vec<String> = Vec::new();
    check_line_citations(&recovery, &mut issues);

    for claim in &CLAIMS {
        let text: Option<&str> = match claim.file {
            "ecosystems.json" => ecosystems
                .cells
                .iter()
                .find(|cell: &&EcosystemCell| cell.label == claim.row)
                .map(|cell: &EcosystemCell| cell.note.as_str()),
            _ => verification
                .rows
                .iter()
                .find(|row: &&VerificationRow| row.ecosystem == claim.row)
                .map(|row: &VerificationRow| row.result.as_str()),
        };

        let Some(text): Option<&str> = text else {
            issues.push(format!(
                "{} no longer has a row named `{}`, so the number it used to carry is unchecked",
                claim.file, claim.row
            ));
            continue;
        };

        let Some(stated): Option<f64> = first_number(text) else {
            issues.push(format!(
                "{} row `{}` reads `{text}`, which carries no number to compare",
                claim.file, claim.row
            ));
            continue;
        };

        let Some(truth): Option<f64> = resolve(&recovery, &claim.expected) else {
            issues.push(format!(
                "{} row `{}` cannot be checked because the bar it mirrors is missing from recovery.json",
                claim.file, claim.row
            ));
            continue;
        };

        if (stated - truth).abs() > AGREEMENT_TOLERANCE {
            issues.push(format!(
                "{} row `{}` states {stated} {} while recovery.json says {truth}; the same \
                 measurement is published twice and the copies have drifted apart",
                claim.file, claim.row, claim.unit
            ));
        }
    }

    check_mirrors(&recovery, &mut issues);

    if issues.is_empty() {
        println!(
            "xtask regen: cross-data cross-check ok ({} number(s) shared between recovery.json, \
             ecosystems.json and verification.json agree, and {} bar(s) that re-plot a measurement \
             recovery.json already carries agree with it)",
            CLAIMS.len(),
            MIRRORS.len()
        );
        Ok(())
    } else {
        bail!(
            "xtask regen: {} shared number(s) disagree between the chart data files:\n  {}",
            issues.len(),
            issues.join("\n  ")
        )
    }
}
