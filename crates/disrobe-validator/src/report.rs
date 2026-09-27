use disrobe_core::time::{SourceDate, SourceDateError, source_date};
use serde::Serialize;

use crate::metrics::{PassMetrics, SampleMetrics};

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_at: Option<String>,
    pub total_samples: usize,
    pub total_ok: usize,
    pub total_recovered: usize,
    pub total_failed: usize,
    pub per_pass: Vec<PassMetrics>,
    pub samples: Vec<SampleMetrics>,
}

pub fn build_report(samples: Vec<SampleMetrics>) -> Result<ValidationReport, SourceDateError> {
    let per_pass: Vec<PassMetrics> = crate::metrics::aggregate(&samples);
    let total_ok: usize = samples.iter().filter(|s| s.ok).count();
    let total_recovered: usize = samples.iter().filter(|s| s.recovered).count();
    let total_failed: usize = samples.len() - total_ok;
    let run_at: Option<String> = source_date()?.map(SourceDate::rfc3339);
    Ok(ValidationReport {
        schema: "disrobe.validation.report/v1".to_owned(),
        run_at,
        total_samples: samples.len(),
        total_ok,
        total_recovered,
        total_failed,
        per_pass,
        samples,
    })
}
