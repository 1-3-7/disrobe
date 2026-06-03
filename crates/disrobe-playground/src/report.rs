use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::oracle::{OracleKind, OracleResult, OracleVerdict};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleKindRow {
    pub oracle: OracleKind,
    pub evaluated: u32,
    pub recovered: u32,
    pub byte_identical: u32,
    pub detect_correct: u32,
    pub tool_missing: u32,
    pub fixture_absent: u32,
    pub lossy: u32,
    pub no_recovery: u32,
    pub pass_error: u32,
    pub ceiling_residual_bp: u32,
}

impl OracleKindRow {
    #[must_use]
    pub const fn new(oracle: OracleKind) -> Self {
        Self {
            oracle,
            evaluated: 0,
            recovered: 0,
            byte_identical: 0,
            detect_correct: 0,
            tool_missing: 0,
            fixture_absent: 0,
            lossy: 0,
            no_recovery: 0,
            pass_error: 0,
            ceiling_residual_bp: 0,
        }
    }

    fn record(&mut self, verdict: &OracleVerdict) {
        if verdict.counts_in_denominator() {
            self.evaluated += 1;
        }
        match verdict {
            OracleVerdict::Recovered => self.recovered += 1,
            OracleVerdict::ByteIdentical => {
                self.recovered += 1;
                self.byte_identical += 1;
            }
            OracleVerdict::DetectCorrect => {
                self.recovered += 1;
                self.detect_correct += 1;
            }
            OracleVerdict::Lossy { residual_bp, .. } => {
                self.lossy += 1;
                self.ceiling_residual_bp = self.ceiling_residual_bp.max(*residual_bp);
            }
            OracleVerdict::DetectWrong { .. } | OracleVerdict::NoRecovery { .. } => {
                self.no_recovery += 1;
            }
            OracleVerdict::ToolMissing { .. } => self.tool_missing += 1,
            OracleVerdict::FixtureAbsent { .. } => self.fixture_absent += 1,
            OracleVerdict::PassError { .. } => self.pass_error += 1,
        }
    }

    #[must_use]
    pub fn recovery_bp(&self) -> u32 {
        if self.evaluated == 0 {
            return 0;
        }
        let raw: u32 = ((u64::from(self.recovered) * 10_000) / u64::from(self.evaluated)) as u32;
        if raw >= 10_000 && (self.lossy > 0 || self.no_recovery > 0 || self.pass_error > 0) {
            return 9_999;
        }
        raw
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaygroundReport {
    pub rows: Vec<OracleKindRow>,
    pub results: Vec<OracleResult>,
    pub circularity_count: usize,
    pub manifests_parsed: usize,
}

impl PlaygroundReport {
    #[must_use]
    pub fn from_results(
        results: Vec<OracleResult>,
        circularity_count: usize,
        manifests_parsed: usize,
    ) -> Self {
        let mut rows_map: BTreeMap<OracleKind, OracleKindRow> = OracleKind::all()
            .into_iter()
            .map(|k: OracleKind| (k, OracleKindRow::new(k)))
            .collect();
        for r in &results {
            if let Some(row) = rows_map.get_mut(&r.oracle) {
                row.record(&r.verdict);
            }
        }
        let rows: Vec<OracleKindRow> = rows_map.into_values().collect();
        Self {
            rows,
            results,
            circularity_count,
            manifests_parsed,
        }
    }

    #[must_use]
    pub fn headline_vector(&self) -> Vec<(OracleKind, u32, u32, u32)> {
        self.rows
            .iter()
            .map(|r: &OracleKindRow| (r.oracle, r.recovered, r.evaluated, r.recovery_bp()))
            .collect()
    }

    #[must_use]
    pub fn row(&self, kind: OracleKind) -> Option<&OracleKindRow> {
        self.rows.iter().find(|r: &&OracleKindRow| r.oracle == kind)
    }
}

#[must_use]
pub fn render_tsv(report: &PlaygroundReport) -> String {
    let mut out: String = String::with_capacity(1024);
    out.push_str(
        "oracle\tevaluated\trecovered\tbyte_identical\tdetect_correct\tlossy\tno_recovery\tpass_error\ttool_missing\tfixture_absent\tceiling_residual_bp\trecovery_bp\n",
    );
    for row in &report.rows {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.oracle.label(),
            row.evaluated,
            row.recovered,
            row.byte_identical,
            row.detect_correct,
            row.lossy,
            row.no_recovery,
            row.pass_error,
            row.tool_missing,
            row.fixture_absent,
            row.ceiling_residual_bp,
            row.recovery_bp(),
        );
    }
    out
}

#[must_use]
pub fn render_json(report: &PlaygroundReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_owned())
}
