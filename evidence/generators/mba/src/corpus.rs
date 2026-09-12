use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::equiv::{check_vectors, equivalent};
use crate::error::{GeneratorError, GeneratorResult};
use crate::term::{Term, Width};

pub const SOURCE_EXTERNAL_OBFUSCATOR: &str = "external-obfuscator";
pub const SOURCE_PUBLIC_DATASET: &str = "public-dataset";
pub const SOURCE_IN_HOUSE: &str = "in-house";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    pub generator: String,
    pub id: String,
    pub obfuscated: String,
    pub obfuscated_nodes: usize,
    pub seed: u64,
    pub source: String,
    pub transform: String,
    pub var_count: u32,
    pub width: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub inputs: Vec<u64>,
    pub output: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truth {
    pub checks: Vec<Check>,
    pub id: String,
    pub original: String,
    pub original_nodes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub case: Case,
    pub truth: Truth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance<'a> {
    pub source: &'a str,
    pub generator: &'a str,
    pub transform: &'a str,
    pub seed: u64,
}

pub fn build_entry(
    id: &str,
    provenance: Provenance<'_>,
    original: &Term,
    obfuscated: &Term,
    width: Width,
) -> GeneratorResult<Entry> {
    if original == obfuscated {
        return Err(GeneratorError::DegenerateEntry { id: id.to_owned() });
    }
    let var_count: u32 = original.var_count().max(obfuscated.var_count());
    if !equivalent(original, obfuscated, width, var_count) {
        return Err(GeneratorError::NotAnIdentity {
            id: id.to_owned(),
            bits: width.bits(),
        });
    }
    let vectors: Vec<Vec<u64>> = check_vectors(provenance.seed, width, var_count);
    let checks: Vec<Check> = vectors
        .into_iter()
        .map(|inputs: Vec<u64>| {
            let output: u64 = original.eval(&inputs, width);
            Check { inputs, output }
        })
        .collect();
    Ok(Entry {
        case: Case {
            generator: provenance.generator.to_owned(),
            id: id.to_owned(),
            obfuscated: obfuscated.to_prefix(),
            obfuscated_nodes: obfuscated.node_count(),
            seed: provenance.seed,
            source: provenance.source.to_owned(),
            transform: provenance.transform.to_owned(),
            var_count,
            width: width.bits(),
        },
        truth: Truth {
            checks,
            id: id.to_owned(),
            original: original.to_prefix(),
            original_nodes: original.node_count(),
        },
    })
}

pub fn render(entries: &[Entry]) -> GeneratorResult<(String, String)> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for entry in entries {
        if !seen.insert(entry.case.id.as_str()) {
            return Err(GeneratorError::DuplicateId {
                id: entry.case.id.clone(),
            });
        }
    }
    let mut cases: String = String::new();
    let mut truths: String = String::new();
    for entry in entries {
        let case_line: String =
            serde_json::to_string(&entry.case).map_err(|error| GeneratorError::Invalid {
                detail: format!("case {} does not serialize: {error}", entry.case.id),
            })?;
        let truth_line: String =
            serde_json::to_string(&entry.truth).map_err(|error| GeneratorError::Invalid {
                detail: format!("truth {} does not serialize: {error}", entry.truth.id),
            })?;
        cases.push_str(&case_line);
        cases.push('\n');
        truths.push_str(&truth_line);
        truths.push('\n');
    }
    Ok((cases, truths))
}

pub fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|left: &Entry, right: &Entry| left.case.id.cmp(&right.case.id));
}
