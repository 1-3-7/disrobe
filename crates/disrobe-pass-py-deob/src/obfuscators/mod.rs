use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::Result;

pub mod berserker;
pub mod blankobf;
pub(crate) mod de4py_family;
pub mod jawbreaker;
pub mod kramer;
pub mod manglify;
pub mod obfuxtreme;
pub mod online_family;
pub mod oxyry;
pub mod plusobf;
pub mod py_mauricelambert;
pub mod pyminifier;
pub mod pyminifier_variants;
pub mod pyobfuscate_com;
pub mod python_obfuscator_pypi;
pub mod wodx;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Quality {
    Full,
    Partial,
    DetectOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Obfuscator {
    Kramer,
    Berserker,
    Jawbreaker,
    BlankObf,
    PlusObf,
    Wodx,
    PyobfuscateCom,
    PyObfuscatorMauricelambert,
    PythonObfuscatorPypi,
    ObfuXtreme,
    Manglify,
    Oxyry,
    Pyminifier,
    OnlineFamily,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectReport {
    pub obfuscator: Obfuscator,
    pub matched: bool,
    pub confidence: f32,
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeelOutcome {
    pub obfuscator: Obfuscator,
    pub stages_applied: Vec<String>,
    pub recovered_source: String,
    pub confidence: f32,
    pub quality: Quality,
    pub lossy_notes: Vec<String>,
    pub diagnostics: BTreeMap<String, String>,
}

pub trait ObfuscatorPass {
    fn id(&self) -> Obfuscator;
    fn detect(&self, source: &[u8]) -> DetectReport;
    fn peel(&self, source: &[u8]) -> Result<PeelOutcome>;
}

#[inline]
pub fn iter_passes() -> Vec<&'static dyn ObfuscatorPass> {
    let v: Vec<&'static dyn ObfuscatorPass> = vec![
        &kramer::KramerPass,
        &berserker::BerserkerPass,
        &jawbreaker::JawbreakerPass,
        &blankobf::BlankObfPass,
        &plusobf::PlusObfPass,
        &wodx::WodxPass,
        &pyobfuscate_com::PyobfuscateComPass,
        &py_mauricelambert::PyObfuscatorMauricelambertPass,
        &python_obfuscator_pypi::PythonObfuscatorPypiPass,
        &obfuxtreme::ObfuXtremePass,
        &manglify::ManglifyPass,
        &oxyry::OxyryPass,
        &pyminifier::PyminifierPass,
        &online_family::OnlineFamilyPass,
    ];
    v
}
