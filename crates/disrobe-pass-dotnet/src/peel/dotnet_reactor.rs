#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::crypto_obfuscator::apply_resource_strings;
use crate::peel::protector_resources::recover_dotnet_reactor_strings;
use crate::peel::{PeelReport, report_only_encrypted_resource, try_managed_string_decryptor};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[
    "Eziriz",
    ".NET Reactor",
    "protect_resource",
    "Reactor.Compiler",
];

pub fn peel_dotnet_reactor(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_encrypted_resource(
        Protector::DotnetReactor,
        bytes,
        WATERMARKS,
        "Reactor stores its strings in an embedded resource encrypted with AES-256-CBC; the \
         32-byte key and 16-byte IV live in initialized-data fields referenced by the resource \
         decrypter, and the records are int32-length-prefixed UTF-16. The static key+IV are read \
         from those fields and fed to the AES engine below. Builds that reverse the IV or mix the \
         assembly PublicKeyToken into it are walled honestly because that material is not fully \
         present in an unsigned static image.",
    )?;
    try_managed_string_decryptor(&mut report, bytes, ".NET Reactor");
    apply_resource_strings(&mut report, recover_dotnet_reactor_strings(bytes));
    Ok(report)
}
