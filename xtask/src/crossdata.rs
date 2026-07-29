use std::path::{Path, PathBuf};

use eyre::{Result, bail};
use serde::Deserialize;

use crate::fileio::read_text_bounded;

const MAX_DATA_JSON_BYTES: u64 = 4 * 1024 * 1024;

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
    detected: Option<u64>,
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

#[derive(Debug, Deserialize)]
struct Verification {
    rows: Vec<VerificationRow>,
}

#[derive(Debug, Deserialize)]
struct VerificationRow {
    ecosystem: String,
    #[serde(default)]
    result: String,
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
    Numerator {
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
        Expected::Numerator { heading, label } => {
            find_bar(doc, heading, label)?.num.map(|v: u64| v as f64)
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
    let verification: Verification = serde_json::from_str(&read_text_bounded(
        &data.join("verification.json"),
        MAX_DATA_JSON_BYTES,
    )?)?;

    let mut issues: Vec<String> = Vec::new();

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

        if (stated - truth).abs() > 0.005 {
            issues.push(format!(
                "{} row `{}` states {stated} {} while recovery.json says {truth}; the same \
                 measurement is published twice and the copies have drifted apart",
                claim.file, claim.row, claim.unit
            ));
        }
    }

    if issues.is_empty() {
        println!(
            "xtask regen: cross-data cross-check ok ({} number(s) shared between recovery.json, \
             ecosystems.json and verification.json agree)",
            CLAIMS.len()
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
