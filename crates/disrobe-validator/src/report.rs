use serde::Serialize;

use crate::metrics::{PassMetrics, SampleMetrics};

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub schema: String,
    pub run_at: String,
    pub total_samples: usize,
    pub total_ok: usize,
    pub total_recovered: usize,
    pub total_failed: usize,
    pub per_pass: Vec<PassMetrics>,
    pub samples: Vec<SampleMetrics>,
}

#[must_use]
pub fn build_report(samples: Vec<SampleMetrics>) -> ValidationReport {
    let per_pass: Vec<PassMetrics> = crate::metrics::aggregate(&samples);
    let total_ok: usize = samples.iter().filter(|s| s.ok).count();
    let total_recovered: usize = samples.iter().filter(|s| s.recovered).count();
    let total_failed: usize = samples.len() - total_ok;
    ValidationReport {
        schema: "disrobe.validation.report/v1".to_owned(),
        run_at: chrono_compat_iso(),
        total_samples: samples.len(),
        total_ok,
        total_recovered,
        total_failed,
        per_pass,
        samples,
    }
}

fn chrono_compat_iso() -> String {
    #[allow(
        clippy::disallowed_methods,
        reason = "the validation report records the genuine wall-clock run time; SOURCE_DATE_EPOCH still pins it for reproducible builds"
    )]
    let secs: u64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v: String| v.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d: std::time::Duration| d.as_secs())
        });
    format!("epoch+{secs}")
}
