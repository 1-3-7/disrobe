#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["BabelAttribute", "BabelObfuscatorAttribute", "Babel.Module"];

pub fn peel_babel_net(bytes: &[u8]) -> Result<PeelReport> {
    let report: PeelReport = report_only_encrypted_resource(
        Protector::BabelDotnet,
        bytes,
        WATERMARKS,
        "Babel marker detection is report-only. Header-only resource recovery is disabled because \
         the resource is self-describing but unauthenticated: its IV, key, ciphertext, and record \
         framing can agree without proving a Babel decoder selected it; no authenticated \
         decoder/callsite-to-resource chain or authentic protected/plain sample is committed.",
    )?;
    Ok(report)
}
