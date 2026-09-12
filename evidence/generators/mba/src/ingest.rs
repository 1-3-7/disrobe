use std::collections::BTreeSet;

use serde::Deserialize;

use crate::corpus::{Entry, Provenance, build_entry};
use crate::error::GeneratorError;
use crate::parse::{VarMap, parse_infix, scan_identifiers};
use crate::term::{Term, Width};

#[derive(Debug, Clone)]
pub struct DatasetSpec {
    pub source: String,
    pub generator: String,
    pub transform: String,
    pub id_prefix: String,
    pub widths: Vec<Width>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ingested {
    pub entries: Vec<Entry>,
    pub rejects: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ToolRow {
    kernel: String,
    mode: String,
    obfuscated: String,
    seed: u64,
}

fn stable_seed(text: &str) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn pair_terms(
    original_text: &str,
    obfuscated_text: &str,
    context: &str,
) -> Result<(Term, Term), GeneratorError> {
    let mut names: BTreeSet<String> = scan_identifiers(original_text);
    names.extend(scan_identifiers(obfuscated_text));
    let vars: VarMap = VarMap::from_names(&names);
    let original: Term = parse_infix(original_text, &vars, context)?;
    let obfuscated: Term = parse_infix(obfuscated_text, &vars, context)?;
    Ok((original, obfuscated))
}

fn accept_pair(
    into: &mut Ingested,
    spec: &DatasetSpec,
    id_stem: &str,
    original_text: &str,
    obfuscated_text: &str,
) {
    let (original, obfuscated): (Term, Term) =
        match pair_terms(original_text, obfuscated_text, id_stem) {
            Ok(parsed) => parsed,
            Err(error) => {
                into.rejects.push(format!("{id_stem}: {error}"));
                return;
            }
        };
    let mut accepted_any: bool = false;
    for width in &spec.widths {
        let id: String = format!("{}-{id_stem}-w{}", spec.id_prefix, width.bits());
        let seed: u64 = stable_seed(&id);
        let provenance: Provenance<'_> = Provenance {
            source: &spec.source,
            generator: &spec.generator,
            transform: &spec.transform,
            seed,
        };
        match build_entry(&id, provenance, &original, &obfuscated, *width) {
            Ok(entry) => {
                into.entries.push(entry);
                accepted_any = true;
            }
            Err(error) => into.rejects.push(format!("{id}: {error}")),
        }
    }
    if !accepted_any {
        into.rejects
            .push(format!("{id_stem}: no width accepted this pair"));
    }
}

#[must_use]
pub fn ingest_pair_dataset(text: &str, spec: &DatasetSpec) -> Ingested {
    let mut result: Ingested = Ingested::default();
    for (line_number, line) in text.lines().enumerate() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split(',');
        let (Some(obfuscated_text), Some(original_text)) = (fields.next(), fields.next()) else {
            result
                .rejects
                .push(format!("line {}: fewer than two fields", line_number + 1));
            continue;
        };
        let id_stem: String = format!("{:04}", line_number + 1);
        accept_pair(
            &mut result,
            spec,
            &id_stem,
            original_text.trim(),
            obfuscated_text.trim(),
        );
    }
    result
}

#[must_use]
pub fn ingest_named_original(text: &str, original_text: &str, spec: &DatasetSpec) -> Ingested {
    let mut result: Ingested = Ingested::default();
    for (line_number, line) in text.lines().enumerate() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let id_stem: String = format!("{:04}", line_number + 1);
        accept_pair(&mut result, spec, &id_stem, original_text, trimmed);
    }
    result
}

#[must_use]
pub fn ingest_tool_rows(text: &str, spec: &DatasetSpec) -> Ingested {
    let mut result: Ingested = Ingested::default();
    for (line_number, line) in text.lines().enumerate() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let row: ToolRow = match serde_json::from_str::<ToolRow>(trimmed) {
            Ok(parsed) => parsed,
            Err(error) => {
                result
                    .rejects
                    .push(format!("line {}: {error}", line_number + 1));
                continue;
            }
        };
        let id_stem: String = format!("{}-{:04}", row.mode, row.seed % 10_000);
        let mut scoped: DatasetSpec = spec.clone();
        scoped.transform.clone_from(&row.mode);
        accept_pair(
            &mut result,
            &scoped,
            &id_stem,
            row.kernel.trim(),
            row.obfuscated.trim(),
        );
    }
    result
}
