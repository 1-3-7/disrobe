use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::static_unpack::decrypt_v8;
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{DecryptStatus, UnpackConfig, VersionedOutcome};

pub(crate) fn run(
    bytes: &[u8],
    detection: &Detection,
    runtime: Option<&RuntimeInfoSummary>,
    cfg: &UnpackConfig,
) -> Result<VersionedOutcome> {
    let Some(runtime_info): Option<&RuntimeInfoSummary> = runtime else {
        if cfg.strict {
            return Err(Error::RuntimeNotFound {
                searched: vec!["<runtime not supplied to unpack_static_with_config>".to_owned()],
            });
        }
        return Ok(VersionedOutcome {
            plaintext: Vec::new(),
            original_bytecode: None,
            bcc_blobs: Vec::new(),
            encrypted_funcs_recovered: 0,
            inner_cipher_stats: crate::static_unpack::InnerCipherStats::empty(),
            status: DecryptStatus::DetectOnly,
            diagnostics: vec![
                "DR-PYARM-STATIC: v9 detect-only (no runtime supplied; pass UnpackConfig.runtime_bytes for full decrypt)"
                    .to_owned(),
            ],
        });
    };

    let base_status: DecryptStatus = DecryptStatus::Functional;
    let mut outcome: VersionedOutcome =
        decrypt_v8::decrypt_with_runtime_key(bytes, &runtime_info.aes_key, base_status)?;

    let (mask, ran): ([u8; 12], bool) =
        crate::inner_cipher::parse_plaintext_xor_procedure(&outcome.plaintext);
    if ran {
        outcome.diagnostics.push(format!(
            "DR-PYARM-STATIC: v9 RFT/BCC nonce-XOR microVM ran, mask={}",
            hex_short(&mask)
        ));
    }

    if !outcome.bcc_blobs.is_empty() && !cfg.allow_bcc {
        outcome
            .diagnostics
            .push("DR-PYARM-STATIC: BCC blobs present; native lift gated behind allow_bcc=true (in-crate x86-64 pseudo-C)".to_owned());
    }

    let _ = detection;
    Ok(outcome)
}

fn hex_short(b: &[u8]) -> String {
    let mut s: String = String::with_capacity(b.len() * 2);
    for byte in b {
        let upper: u8 = (byte >> 4) & 0x0f;
        let lower: u8 = byte & 0x0f;
        s.push(nibble_to_char(upper));
        s.push(nibble_to_char(lower));
    }
    s
}

const fn nibble_to_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hex_short_lowercase() {
        let s: String = hex_short(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(s, "deadbeef");
    }

    #[test]
    fn diagnostic_reads_region_at_code_offset_via_canonical_vm() {
        let proc_body: [u8; 8] = [0x07, 0x1c, 0xef, 0xbe, 0xad, 0xde, 0x09, 0x01];
        let proc_length: usize = 16 + proc_body.len();
        let code_offset: usize = 8;
        let mut plaintext: Vec<u8> = vec![0u8; code_offset + proc_length];
        plaintext[..4].copy_from_slice(&u32::try_from(code_offset).unwrap().to_le_bytes());
        plaintext[4..8].copy_from_slice(&u32::try_from(proc_length).unwrap().to_le_bytes());
        plaintext[code_offset + 16..code_offset + 16 + proc_body.len()].copy_from_slice(&proc_body);
        let (mask, ran): ([u8; 12], bool) =
            crate::inner_cipher::parse_plaintext_xor_procedure(&plaintext);
        assert!(ran);
        assert_eq!(&mask[..4], &[0xef, 0xbe, 0xad, 0xde]);
    }
}
