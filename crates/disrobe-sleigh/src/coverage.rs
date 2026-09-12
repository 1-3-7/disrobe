use std::collections::BTreeMap;

use crate::decode_block;
use crate::lifter::{Language, decode_block_for_language};
use crate::pcode::{DecodeStatus, PcodeInstr, PcodeOp};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatusCounts {
    pub ambiguous: usize,
    pub callother: usize,
    pub no_match: usize,
    pub spec_error: usize,
    pub supported: usize,
    pub truncated: usize,
    pub unsupported: usize,
}

impl StatusCounts {
    #[must_use]
    pub const fn total(self) -> usize {
        self.ambiguous
            .saturating_add(self.callother)
            .saturating_add(self.no_match)
            .saturating_add(self.spec_error)
            .saturating_add(self.supported)
            .saturating_add(self.truncated)
            .saturating_add(self.unsupported)
    }

    #[must_use]
    pub const fn matched(self) -> usize {
        self.supported
            .saturating_add(self.callother)
            .saturating_add(self.unsupported)
    }

    #[must_use]
    pub const fn count_of(self, status: DecodeStatus) -> usize {
        match status {
            DecodeStatus::Ambiguous => self.ambiguous,
            DecodeStatus::CallOther => self.callother,
            DecodeStatus::NoMatch => self.no_match,
            DecodeStatus::SpecError => self.spec_error,
            DecodeStatus::Supported => self.supported,
            DecodeStatus::Truncated => self.truncated,
            DecodeStatus::Unsupported => self.unsupported,
        }
    }

    const fn tally(&mut self, status: DecodeStatus) {
        let slot: &mut usize = match status {
            DecodeStatus::Ambiguous => &mut self.ambiguous,
            DecodeStatus::CallOther => &mut self.callother,
            DecodeStatus::NoMatch => &mut self.no_match,
            DecodeStatus::SpecError => &mut self.spec_error,
            DecodeStatus::Supported => &mut self.supported,
            DecodeStatus::Truncated => &mut self.truncated,
            DecodeStatus::Unsupported => &mut self.unsupported,
        };
        *slot = slot.saturating_add(1);
    }
}

pub const DECODE_STATUSES: [DecodeStatus; 7] = [
    DecodeStatus::Ambiguous,
    DecodeStatus::CallOther,
    DecodeStatus::NoMatch,
    DecodeStatus::SpecError,
    DecodeStatus::Supported,
    DecodeStatus::Truncated,
    DecodeStatus::Unsupported,
];

#[must_use]
pub const fn status_name(status: DecodeStatus) -> &'static str {
    match status {
        DecodeStatus::Ambiguous => "ambiguous",
        DecodeStatus::CallOther => "callother",
        DecodeStatus::NoMatch => "no_match",
        DecodeStatus::SpecError => "spec_error",
        DecodeStatus::Supported => "supported",
        DecodeStatus::Truncated => "truncated",
        DecodeStatus::Unsupported => "unsupported",
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DecodeCoverage {
    pub callother_ops: usize,
    pub matched: usize,
    pub status: StatusCounts,
    pub total: usize,
    pub unsupported: usize,
}

impl DecodeCoverage {
    #[must_use]
    pub fn decode_coverage_percent(self) -> f64 {
        percentage(self.matched, self.total)
    }

    #[must_use]
    pub fn callother_percent(self) -> f64 {
        percentage(self.callother_ops, self.total)
    }

    #[must_use]
    pub fn unsupported_percent(self) -> f64 {
        percentage(self.unsupported, self.total)
    }

    #[must_use]
    pub fn semantic_percent(self) -> f64 {
        percentage(self.status.supported, self.total)
    }

    #[must_use]
    pub fn status_percent(self, status: DecodeStatus) -> f64 {
        percentage(self.status.count_of(status), self.total)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DecodeReport {
    pub coverage: DecodeCoverage,
    pub instructions: Vec<PcodeInstr>,
    pub unlifted: BTreeMap<String, usize>,
}

pub fn decode_block_with_coverage(bytes: &[u8], address: u64) -> DecodeReport {
    report_of(decode_block(bytes, address))
}

pub fn decode_block_with_coverage_for_language(
    language: Language,
    bytes: &[u8],
    address: u64,
) -> DecodeReport {
    report_of(decode_block_for_language(language, bytes, address).instructions)
}

fn report_of(instructions: Vec<PcodeInstr>) -> DecodeReport {
    let coverage: DecodeCoverage = measure_coverage(&instructions);
    let unlifted: BTreeMap<String, usize> = unlifted_mnemonics(&instructions);
    DecodeReport {
        coverage,
        instructions,
        unlifted,
    }
}

pub fn measure_coverage(instructions: &[PcodeInstr]) -> DecodeCoverage {
    let mut status: StatusCounts = StatusCounts::default();
    let mut callother_ops: usize = 0;
    for instruction in instructions {
        status.tally(instruction.status);
        if instruction.ops.iter().any(PcodeOp::is_callother) {
            callother_ops = callother_ops.saturating_add(1);
        }
    }
    DecodeCoverage {
        callother_ops,
        matched: status.matched(),
        status,
        total: instructions.len(),
        unsupported: status.unsupported,
    }
}

pub fn unlifted_mnemonics(instructions: &[PcodeInstr]) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for instruction in instructions {
        if instruction.status.supported() {
            continue;
        }
        let slot: &mut usize = counts.entry(instruction.mnemonic.clone()).or_default();
        *slot = slot.saturating_add(1);
    }
    counts
}

fn percentage(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    let numerator_f64: f64 = numerator as f64;
    let denominator_f64: f64 = denominator as f64;
    numerator_f64 * 100.0 / denominator_f64
}
