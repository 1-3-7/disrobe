#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel, try_managed_string_decryptor};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[
    "DotfuscatorAttribute",
    "DotfuscatorEnhanced",
    "DotfuscatorCE",
];

pub fn peel_dotfuscator(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        Protector::Dotfuscator,
        bytes,
        WATERMARKS,
        vec![
            "Dotfuscator strings: XOR with 4-byte ldc.i4 key (Pro) or plaintext (CE). The Pro XOR \
             decoder is a pure char[]/byte[] transform and is executed below; the keyed Rijndael \
             resource tier derives its key in the decrypter method, so static recovery requires \
             emulating that method's CIL. Marquee feature is overload-induction renaming. CE \
             bundled with Visual Studio."
                .to_string(),
        ],
    )?;
    try_managed_string_decryptor(&mut report, bytes, "Dotfuscator");
    Ok(report)
}
