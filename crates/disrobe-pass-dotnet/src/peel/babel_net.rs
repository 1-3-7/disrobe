#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::crypto_obfuscator::apply_resource_strings;
use crate::peel::protector_resources::recover_babel_strings;
use crate::peel::{PeelReport, report_only_encrypted_resource, try_managed_string_decryptor};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["BabelAttribute", "BabelObfuscatorAttribute", "Babel.Module"];

pub fn peel_babel_net(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_encrypted_resource(
        Protector::BabelDotnet,
        bytes,
        WATERMARKS,
        "Babel stores its strings in an embedded resource encrypted with DES-CBC: a small header \
         carries the IV and, when present, the embedded key, followed by BinaryReader UTF-8 \
         records. The static IV+key are read from the resource header and fed to the DES engine \
         below; an unsigned image that keys off the assembly PublicKey is walled honestly.",
    )?;
    try_managed_string_decryptor(&mut report, bytes, "Babel.NET");
    apply_resource_strings(&mut report, recover_babel_strings(bytes));
    Ok(report)
}
