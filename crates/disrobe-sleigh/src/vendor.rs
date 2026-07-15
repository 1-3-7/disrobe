use std::collections::BTreeMap;

use crate::SleighError;
use crate::preprocessor::{PreprocessorLimits, preprocess_sources};

pub fn aarch64_sources() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "AARCH64.slaspec".to_owned(),
            include_str!("../vendor/aarch64/AARCH64.slaspec").to_owned(),
        ),
        (
            "AARCH64instructions.sinc".to_owned(),
            include_str!("../vendor/aarch64/AARCH64instructions.sinc").to_owned(),
        ),
        (
            "AARCH64_base_PACoptions.sinc".to_owned(),
            include_str!("../vendor/aarch64/AARCH64_base_PACoptions.sinc").to_owned(),
        ),
        (
            "AARCH64base.sinc".to_owned(),
            include_str!("../vendor/aarch64/AARCH64base.sinc").to_owned(),
        ),
        (
            "AARCH64ldst.sinc".to_owned(),
            include_str!("../vendor/aarch64/AARCH64ldst.sinc").to_owned(),
        ),
    ])
}

pub fn preprocessed_aarch64_source() -> Result<String, SleighError> {
    let sources: BTreeMap<String, String> = aarch64_sources();
    preprocess_sources("AARCH64.slaspec", &sources, PreprocessorLimits::default())
}

pub fn arm32_sources() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "ARM7_le.slaspec".to_owned(),
            include_str!("../vendor/arm/ARM7_le.slaspec").to_owned(),
        ),
        (
            "ARM.sinc".to_owned(),
            include_str!("../vendor/arm/ARM.sinc").to_owned(),
        ),
        (
            "ARMinstructions.sinc".to_owned(),
            include_str!("../vendor/arm/ARMinstructions.sinc").to_owned(),
        ),
        (
            "ARMTHUMBinstructions.sinc".to_owned(),
            include_str!("../vendor/arm/ARMTHUMBinstructions.sinc").to_owned(),
        ),
    ])
}

pub fn mips32_sources(entry: &str) -> Result<BTreeMap<String, String>, SleighError> {
    let root: String = match entry {
        "mips32be.slaspec" => include_str!("../vendor/mips/mips32be.slaspec").to_owned(),
        "mips32le.slaspec" => include_str!("../vendor/mips/mips32le.slaspec").to_owned(),
        _ => {
            return Err(SleighError::MissingSource {
                path: entry.to_owned(),
            });
        }
    };
    Ok(BTreeMap::from([
        (entry.to_owned(), root),
        (
            "mips.sinc".to_owned(),
            include_str!("../vendor/mips/mips.sinc").to_owned(),
        ),
        (
            "mips32Instructions.sinc".to_owned(),
            include_str!("../vendor/mips/mips32Instructions.sinc").to_owned(),
        ),
        (
            "mipsfloat.sinc".to_owned(),
            include_str!("../vendor/mips/mipsfloat.sinc").to_owned(),
        ),
    ]))
}

pub fn preprocessed_arm32_source() -> Result<String, SleighError> {
    let sources: BTreeMap<String, String> = arm32_sources();
    preprocess_sources("ARM7_le.slaspec", &sources, PreprocessorLimits::default())
}

pub fn preprocessed_mips32be_source() -> Result<String, SleighError> {
    let sources: BTreeMap<String, String> = mips32_sources("mips32be.slaspec")?;
    preprocess_sources("mips32be.slaspec", &sources, PreprocessorLimits::default())
}

pub fn preprocessed_mips32le_source() -> Result<String, SleighError> {
    let sources: BTreeMap<String, String> = mips32_sources("mips32le.slaspec")?;
    preprocess_sources("mips32le.slaspec", &sources, PreprocessorLimits::default())
}

pub fn riscv_sources(entry: &str) -> Result<BTreeMap<String, String>, SleighError> {
    let root: String = match entry {
        "riscv32.slaspec" => include_str!("../vendor/riscv/riscv32.slaspec").to_owned(),
        "riscv64.slaspec" => include_str!("../vendor/riscv/riscv64.slaspec").to_owned(),
        _ => {
            return Err(SleighError::MissingSource {
                path: entry.to_owned(),
            });
        }
    };
    Ok(BTreeMap::from([
        (entry.to_owned(), root),
        (
            "riscv.reg.sinc".to_owned(),
            include_str!("../vendor/riscv/riscv.reg.sinc").to_owned(),
        ),
        (
            "riscv.table.sinc".to_owned(),
            include_str!("../vendor/riscv/riscv.table.sinc").to_owned(),
        ),
        (
            "riscv.rv32i.sinc".to_owned(),
            include_str!("../vendor/riscv/riscv.rv32i.sinc").to_owned(),
        ),
        (
            "riscv.rv32m.sinc".to_owned(),
            include_str!("../vendor/riscv/riscv.rv32m.sinc").to_owned(),
        ),
        (
            "riscv.rv64i.sinc".to_owned(),
            include_str!("../vendor/riscv/riscv.rv64i.sinc").to_owned(),
        ),
        (
            "riscv.rv64m.sinc".to_owned(),
            include_str!("../vendor/riscv/riscv.rv64m.sinc").to_owned(),
        ),
    ]))
}

pub fn preprocessed_riscv32_source() -> Result<String, SleighError> {
    let sources: BTreeMap<String, String> = riscv_sources("riscv32.slaspec")?;
    preprocess_sources("riscv32.slaspec", &sources, PreprocessorLimits::default())
}

pub fn preprocessed_riscv64_source() -> Result<String, SleighError> {
    let sources: BTreeMap<String, String> = riscv_sources("riscv64.slaspec")?;
    preprocess_sources("riscv64.slaspec", &sources, PreprocessorLimits::default())
}

pub fn powerpc32be_sources() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "ppc32be.slaspec".to_owned(),
            include_str!("../vendor/powerpc/ppc32be.slaspec").to_owned(),
        ),
        (
            "ppc_common.sinc".to_owned(),
            include_str!("../vendor/powerpc/ppc_common.sinc").to_owned(),
        ),
        (
            "ppc_instructions.sinc".to_owned(),
            include_str!("../vendor/powerpc/ppc_instructions.sinc").to_owned(),
        ),
        (
            "lmwInstructions.sinc".to_owned(),
            include_str!("../vendor/powerpc/lmwInstructions.sinc").to_owned(),
        ),
        (
            "lswInstructions.sinc".to_owned(),
            include_str!("../vendor/powerpc/lswInstructions.sinc").to_owned(),
        ),
        (
            "mulhwInstructions.sinc".to_owned(),
            include_str!("../vendor/powerpc/mulhwInstructions.sinc").to_owned(),
        ),
        (
            "stmwInstructions.sinc".to_owned(),
            include_str!("../vendor/powerpc/stmwInstructions.sinc").to_owned(),
        ),
        (
            "stswiInstructions.sinc".to_owned(),
            include_str!("../vendor/powerpc/stswiInstructions.sinc").to_owned(),
        ),
    ])
}

pub fn preprocessed_powerpc32be_source() -> Result<String, SleighError> {
    let sources: BTreeMap<String, String> = powerpc32be_sources();
    preprocess_sources("ppc32be.slaspec", &sources, PreprocessorLimits::default())
}
