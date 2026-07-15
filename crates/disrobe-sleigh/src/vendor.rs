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
