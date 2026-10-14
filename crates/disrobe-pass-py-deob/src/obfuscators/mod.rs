use std::collections::BTreeMap;

use disrobe_core::codec::hex::push_byte as push_lower_hex_byte;
use serde::Serialize;

use crate::error::Result;

pub(crate) fn replace_identifier(text: &str, needle: &str, replacement: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let n: &[u8] = needle.as_bytes();
    if n.is_empty() {
        return text.to_owned();
    }
    let mut out: String = String::with_capacity(text.len());
    let mut run_start: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let end: usize = i + n.len();
        if bytes.get(i..end) == Some(n)
            && (i == 0 || !is_identifier_byte(bytes[i - 1]))
            && bytes
                .get(end)
                .is_none_or(|next: &u8| !is_identifier_byte(*next))
        {
            out.push_str(text.get(run_start..i).unwrap_or_default());
            out.push_str(replacement);
            i = end;
            run_start = i;
        } else {
            i += 1;
        }
    }
    out.push_str(text.get(run_start..).unwrap_or_default());
    out
}

pub(crate) fn render_str_literal(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\x");
                push_lower_hex_byte(&mut out, c as u8);
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

pub mod berserker;
pub mod blankobf;
pub(crate) mod blankobf_layers;
pub(crate) mod builtins_view;
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
pub(crate) mod python_obfuscator_junk;
pub mod python_obfuscator_pypi;
pub mod xindex;

pub const REFUSAL_KEY: &str = "refusal";
pub const REMOTE_PAYLOAD_REFUSAL: &str = "remote-payload";

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
