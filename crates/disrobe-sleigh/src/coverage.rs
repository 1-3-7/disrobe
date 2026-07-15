use crate::decode_block;
use crate::lifter::{Language, decode_block_for_language};
use crate::pcode::{DecodeStatus, PcodeInstr, PcodeOp};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DecodeCoverage {
    pub callother: usize,
    pub matched: usize,
    pub total: usize,
    pub unsupported: usize,
}

impl DecodeCoverage {
    pub fn decode_coverage_percent(self) -> f64 {
        percentage(self.matched, self.total)
    }

    pub fn callother_percent(self) -> f64 {
        percentage(self.callother, self.total)
    }

    pub fn unsupported_percent(self) -> f64 {
        percentage(self.unsupported, self.total)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeReport {
    pub coverage: DecodeCoverage,
    pub instructions: Vec<PcodeInstr>,
}

pub fn decode_block_with_coverage(bytes: &[u8], address: u64) -> DecodeReport {
    let instructions: Vec<PcodeInstr> = decode_block(bytes, address);
    let coverage: DecodeCoverage = measure_coverage(&instructions);
    DecodeReport {
        coverage,
        instructions,
    }
}

pub fn decode_block_with_coverage_for_language(
    language: Language,
    bytes: &[u8],
    address: u64,
) -> DecodeReport {
    let instructions: Vec<PcodeInstr> =
        decode_block_for_language(language, bytes, address).instructions;
    let coverage: DecodeCoverage = measure_coverage(&instructions);
    DecodeReport {
        coverage,
        instructions,
    }
}

pub fn measure_coverage(instructions: &[PcodeInstr]) -> DecodeCoverage {
    let total_instructions: usize = instructions.len();
    let matched_instructions: usize = instructions
        .iter()
        .filter(|instruction: &&PcodeInstr| instruction.status.matched_constructor())
        .count();
    let callother_instructions: usize = instructions
        .iter()
        .filter(|instruction: &&PcodeInstr| instruction.ops.iter().any(PcodeOp::is_callother))
        .count();
    let unsupported_instructions: usize = instructions
        .iter()
        .filter(|instruction: &&PcodeInstr| instruction.status == DecodeStatus::Unsupported)
        .count();
    DecodeCoverage {
        callother: callother_instructions,
        matched: matched_instructions,
        total: total_instructions,
        unsupported: unsupported_instructions,
    }
}

fn percentage(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    let numerator_f64: f64 = numerator as f64;
    let denominator_f64: f64 = denominator as f64;
    numerator_f64 * 100.0 / denominator_f64
}
