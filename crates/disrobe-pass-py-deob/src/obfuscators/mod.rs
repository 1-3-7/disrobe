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
pub mod patchwork;
pub mod plusobf;
pub mod py_mauricelambert;
pub mod pyc_zipper;
pub mod pyminifier;
pub mod pyminifier_variants;
pub mod pyobfus;
pub mod pyobfuscate_com;
pub mod pyobfuscate_com_xor;
pub mod pypacker;
pub mod python_obfuscator_pypi;
pub mod wodx;
pub mod xindex;

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
    PyobfuscateComXor,
    PyObfuscatorMauricelambert,
    PythonObfuscatorPypi,
    ObfuXtreme,
    Manglify,
    Oxyry,
    Pyminifier,
    OnlineFamily,
    XindexObf,
    Pyobfus,
    Pypacker,
    Patchwork,
    PycZipper,
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
#[must_use]
pub fn iter_passes() -> Vec<&'static dyn ObfuscatorPass> {
    let v: Vec<&'static dyn ObfuscatorPass> = vec![
        &kramer::KramerPass,
        &berserker::BerserkerPass,
        &jawbreaker::JawbreakerPass,
        &blankobf::BlankObfPass,
        &plusobf::PlusObfPass,
        &wodx::WodxPass,
        &pyobfuscate_com::PyobfuscateComPass,
        &pyobfuscate_com_xor::PyobfuscateComXorPass,
        &py_mauricelambert::PyObfuscatorMauricelambertPass,
        &python_obfuscator_pypi::PythonObfuscatorPypiPass,
        &obfuxtreme::ObfuXtremePass,
        &manglify::ManglifyPass,
        &oxyry::OxyryPass,
        &pyminifier::PyminifierPass,
        &online_family::OnlineFamilyPass,
        &xindex::XindexObfPass,
        &pyobfus::PyobfusPass,
        &pypacker::PypackerPass,
        &patchwork::PatchworkPass,
        &pyc_zipper::PycZipperPass,
    ];
    v
}
