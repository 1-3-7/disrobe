use std::path::Path;

use crate::corpus::{Entry, SOURCE_PUBLIC_DATASET, sort_entries};
use crate::error::{GeneratorError, GeneratorResult};
use crate::ingest::{DatasetSpec, Ingested, ingest_named_original, ingest_pair_dataset};
use crate::term::Width;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    ObfuscatedThenOriginal,
    NamedOriginal(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetFile {
    pub file_name: &'static str,
    pub id_prefix: &'static str,
    pub generator: &'static str,
    pub transform: &'static str,
    pub shape: Shape,
}

pub const DATASET_WIDTHS: [Width; 3] = [Width::W8, Width::W32, Width::W64];

pub const DATASET_FILES: [DatasetFile; 6] = [
    DatasetFile {
        file_name: "mba-blast-dataset1.txt",
        id_prefix: "blast1",
        generator: "MBA-Blast dataset 1 (USENIX Security 2021)",
        transform: "linear",
        shape: Shape::ObfuscatedThenOriginal,
    },
    DatasetFile {
        file_name: "mba-solver-linear.txt",
        id_prefix: "solverlin",
        generator: "MBA-Solver linear dataset",
        transform: "linear",
        shape: Shape::ObfuscatedThenOriginal,
    },
    DatasetFile {
        file_name: "mba-solver-poly.txt",
        id_prefix: "solverpoly",
        generator: "MBA-Solver polynomial dataset",
        transform: "polynomial",
        shape: Shape::ObfuscatedThenOriginal,
    },
    DatasetFile {
        file_name: "mba-solver-nonpoly.txt",
        id_prefix: "solvernonpoly",
        generator: "MBA-Solver non-polynomial dataset",
        transform: "nonpolynomial",
        shape: Shape::ObfuscatedThenOriginal,
    },
    DatasetFile {
        file_name: "loki-add-depth1.txt",
        id_prefix: "lokiadd1",
        generator: "Loki MBA formula set, addition at rewriting depth 1",
        transform: "recursive",
        shape: Shape::NamedOriginal("x+y"),
    },
    DatasetFile {
        file_name: "loki-add-depth2.txt",
        id_prefix: "lokiadd2",
        generator: "Loki MBA formula set, addition at rewriting depth 2",
        transform: "recursive",
        shape: Shape::NamedOriginal("x+y"),
    },
];

fn spec_for(file: &DatasetFile) -> DatasetSpec {
    DatasetSpec {
        source: SOURCE_PUBLIC_DATASET.to_owned(),
        generator: file.generator.to_owned(),
        transform: file.transform.to_owned(),
        id_prefix: file.id_prefix.to_owned(),
        widths: DATASET_WIDTHS.to_vec(),
    }
}

pub fn ingest_directory(directory: &Path, limit: usize) -> GeneratorResult<Ingested> {
    let mut combined: Ingested = Ingested::default();
    let mut present: usize = 0;
    for file in DATASET_FILES {
        let path: std::path::PathBuf = directory.join(file.file_name);
        if !path.is_file() {
            combined
                .rejects
                .push(format!("{}: absent from the dataset cache", file.file_name));
            continue;
        }
        present += 1;
        let text: String = std::fs::read_to_string(&path).map_err(|source: std::io::Error| {
            GeneratorError::Io {
                path: path.display().to_string(),
                source,
            }
        })?;
        let capped: String = text.lines().take(limit).collect::<Vec<&str>>().join("\n");
        let spec: DatasetSpec = spec_for(&file);
        let ingested: Ingested = match file.shape {
            Shape::ObfuscatedThenOriginal => ingest_pair_dataset(&capped, &spec),
            Shape::NamedOriginal(original) => ingest_named_original(&capped, original, &spec),
        };
        combined.entries.extend(ingested.entries);
        combined.rejects.extend(ingested.rejects);
    }
    if present == 0 {
        return Err(GeneratorError::Invalid {
            detail: format!(
                "no dataset file was found under {}; run fetch_datasets.py first",
                directory.display()
            ),
        });
    }
    let mut entries: Vec<Entry> = std::mem::take(&mut combined.entries);
    sort_entries(&mut entries);
    combined.entries = entries;
    Ok(combined)
}
