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
        "The selected Reactor v4 static resource slice binds a straight-line Int32/UTF-16 entry to \
         one embedded resource and one reachable AES key/IV helper. It requires unique provenance, \
         CBC with PKCS#7, exact FieldRVA layouts, and any IV reversal before set_IV. Ambiguous, \
         PublicKeyToken-mixed, NecroBit/native-keyed, and VM variants remain explicit Unknown. \
         Missing or conflicting selected invariants also remain Unknown.",
    )?;
    try_managed_string_decryptor(&mut report, bytes, ".NET Reactor");
    apply_resource_strings(&mut report, recover_dotnet_reactor_strings(bytes));
    Ok(report)
}
