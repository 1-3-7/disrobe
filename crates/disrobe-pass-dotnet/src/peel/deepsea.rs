#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel, try_managed_string_decryptor};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["DeepSea", "DeepSeaObfuscator"];

pub fn peel_deepsea(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        Protector::DeepSea,
        bytes,
        WATERMARKS,
        vec![
            "DeepSea strings: XOR-32bit-key (v1.x) or Rijndael-CBC (v3+). The v1.x XOR decoder is a \
             pure char[]/byte[] transform and is executed below. The v3+ Rijndael-CBC tier derives \
             its key in the decrypter method, so static recovery requires emulating that method's \
             CIL. Resources: LZMA. Discontinued protector."
                .to_string(),
        ],
    )?;
    try_managed_string_decryptor(&mut report, bytes, "DeepSea");
    Ok(report)
}
