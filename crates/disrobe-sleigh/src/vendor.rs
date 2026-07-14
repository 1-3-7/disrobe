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
