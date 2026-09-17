#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel, try_managed_string_decryptor};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["Goliath.NET", "Goliath"];

pub fn peel_goliath(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        Protector::Goliath,
        bytes,
        WATERMARKS,
        vec![
            "Goliath.NET strings: XOR with SHA1(index), so the per-index key comes from a SHA1 \
             expansion of the string index. Resources: Rijndael-CBC per-resource with the key \
             derived in the decrypter method, so static recovery requires emulating that method's \
             CIL. Generic-shadowing renamer. Discontinued."
                .to_string(),
        ],
    )?;
    try_managed_string_decryptor(&mut report, bytes, "Goliath.NET");
    Ok(report)
}
