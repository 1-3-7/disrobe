//! Babel.NET peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["BabelAttribute", "BabelObfuscatorAttribute", "Babel.Module"];

pub fn peel_babel_net(bytes: &[u8]) -> Result<PeelReport> {
    report_only_encrypted_resource(
        Protector::BabelDotnet,
        bytes,
        WATERMARKS,
        "Babel encrypts strings via RC4(SHA1(resource)[..8]); method bodies via Blowfish-CFB \
         keyed off PE-header constants; constants via static-field-keyed XOR chains. Inflater \
         tables are shuffled per build and recovered by signature scan.",
    )
}
