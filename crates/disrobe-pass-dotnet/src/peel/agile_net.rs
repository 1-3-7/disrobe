#![allow(clippy::doc_markdown)]
use crate::debug::{dbg_kv, dbg_kv_guarded};
use crate::error::Result;
use crate::peel::agile_net_bodies::{AgileCodeHeader, locate_agile_code_header};
use crate::peel::{PeelReport, report_only_encrypted_resource, try_managed_string_decryptor};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["AgileDotNet", "CliSecure"];

pub fn peel_agile_net(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_encrypted_resource(
        Protector::AgileNet,
        bytes,
        WATERMARKS,
        "Agile.NET (CliSecure) encrypts each method body in place after the metadata stream, \
         keyed by a 16-byte value in a code-header that the in-assembly loader reads at runtime; \
         the per-method body offsets/sizes live in a method table after the encrypted code, and \
         the cipher is single-XOR (<=4.5), dual-XOR (5.0), or additive big-endian XTEA (5.4 Pro), \
         selected by the header signature. Strings are XOR-encrypted by an in-assembly managed \
         decryptor over the #US table and are recovered by executing that decryptor's CIL.",
    )?;

    try_managed_string_decryptor(&mut report, bytes, "Agile.NET");

    if let Some(header) = locate_agile_code_header(bytes) {
        let AgileCodeHeader {
            variant,
            file_offset,
            method_count,
            total_code_size,
            ..
        }: AgileCodeHeader = header;
        dbg_kv("agile-net-classify", || {
            format!(
                "variant={} cipher={} code_header@0x{file_offset:x} methods={method_count} code_bytes={total_code_size}",
                variant.label(),
                match variant {
                    crate::peel::agile_net_bodies::CliSecureVariant::Old => "single-xor",
                    crate::peel::agile_net_bodies::CliSecureVariant::Normal => "dual-xor",
                    crate::peel::agile_net_bodies::CliSecureVariant::Pro => "xtea-be",
                }
            )
        });
        dbg_kv_guarded("agile-net-key", || hex_of(&header.key));
        report.notes.push(format!(
            "Agile.NET code-header located at file offset 0x{file_offset:x} ({}); embedded \
             16-byte key, {method_count} method bodies over {total_code_size} bytes of encrypted \
             code. Body decryption needs the per-method codeOffs/codeSize from the method table \
             that the runtime loader walks; not reconstructed here without a real protected \
             sample to ground the table layout.",
            variant.label(),
        ));
    }

    Ok(report)
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
