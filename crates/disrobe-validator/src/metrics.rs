use serde::Serialize;

use crate::corpus::{CorpusEntry, CorpusKind};

#[derive(Debug, Clone, Default, Serialize)]
pub struct PassMetrics {
    pub pass_name: String,
    pub samples_run: usize,
    pub samples_ok: usize,
    pub samples_failed: usize,
    pub total_input_bytes: u64,
    pub total_output_bytes: u64,
    pub total_micros: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampleMetrics {
    pub entry: CorpusEntry,
    pub pass_name: String,
    pub ok: bool,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub micros: u128,
    pub blake3_input: String,
    pub blake3_output: Option<String>,
    pub message: Option<String>,
}

pub fn aggregate(samples: &[SampleMetrics]) -> Vec<PassMetrics> {
    use std::collections::BTreeMap;
    let mut by_pass: BTreeMap<String, PassMetrics> = BTreeMap::new();
    for s in samples {
        let entry: &mut PassMetrics =
            by_pass
                .entry(s.pass_name.clone())
                .or_insert_with(|| PassMetrics {
                    pass_name: s.pass_name.clone(),
                    ..PassMetrics::default()
                });
        entry.samples_run += 1;
        if s.ok {
            entry.samples_ok += 1;
        } else {
            entry.samples_failed += 1;
        }
        entry.total_input_bytes = entry.total_input_bytes.saturating_add(s.input_bytes);
        entry.total_output_bytes = entry.total_output_bytes.saturating_add(s.output_bytes);
        entry.total_micros = entry.total_micros.saturating_add(s.micros);
    }
    by_pass.into_values().collect()
}

#[allow(dead_code)]
pub(crate) const fn _unused_corpus_kind_helper(_k: CorpusKind) {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample(pass: &str, ok: bool) -> SampleMetrics {
        SampleMetrics {
            entry: CorpusEntry {
                kind: CorpusKind::JsObfuscatorIo,
                path: PathBuf::from("x.js"),
                size_bytes: 100,
            },
            pass_name: pass.to_owned(),
            ok,
            input_bytes: 100,
            output_bytes: 80,
            micros: 1_000,
            blake3_input: "deadbeef".to_owned(),
            blake3_output: Some("cafebabe".to_owned()),
            message: None,
        }
    }

    #[test]
    fn aggregates_correctly() {
        let samples: Vec<SampleMetrics> = vec![
            sample("js", true),
            sample("js", true),
            sample("js", false),
            sample("pyarmor", true),
        ];
        let agg: Vec<PassMetrics> = aggregate(&samples);
        assert_eq!(agg.len(), 2);
        let js: &PassMetrics = agg.iter().find(|m| m.pass_name == "js").unwrap();
        assert_eq!(js.samples_run, 3);
        assert_eq!(js.samples_ok, 2);
        assert_eq!(js.samples_failed, 1);
    }
}
