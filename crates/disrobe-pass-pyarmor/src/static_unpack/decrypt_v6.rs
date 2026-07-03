use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::key::scan_v6v7_rdata_for_key;
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{DecryptStatus, InnerCipherStats, UnpackConfig, VersionedOutcome};
use crate::{MAX_RUNTIME_FILE_BYTES, read_file_bounded};

pub(crate) fn run(
    bytes: &[u8],
    detection: &Detection,
    runtime: Option<&RuntimeInfoSummary>,
    cfg: &UnpackConfig,
) -> Result<VersionedOutcome> {
    decrypt_v6v7(bytes, detection, runtime, cfg, "v6")
}

pub(crate) fn decrypt_v6v7(
    bytes: &[u8],
    detection: &Detection,
    runtime: Option<&RuntimeInfoSummary>,
    cfg: &UnpackConfig,
    label: &str,
) -> Result<VersionedOutcome> {
    let runtime_bytes: Option<Vec<u8>> =
        match (cfg.runtime_bytes.as_deref(), cfg.runtime_path.as_deref()) {
            (Some(rb), _) => Some(rb.to_vec()),
            (None, Some(rp)) => Some(read_file_bounded(rp, MAX_RUNTIME_FILE_BYTES)?),
            (None, None) => None,
        };

    let Some(runtime_bytes): Option<Vec<u8>> = runtime_bytes else {
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
            inner_cipher_stats: InnerCipherStats::empty(),
            status: DecryptStatus::DetectOnly,
            diagnostics: vec![format!(
                "DR-PYARM-STATIC: {label} in-memory decrypt requires runtime bytes; supply UnpackConfig.runtime_bytes / runtime_path or use unpack_wrapper_text_with_options for the file-based flow"
            )],
        });
    };

    let key: [u8; 16] = scan_v6v7_rdata_for_key(&runtime_bytes)?;
    let _ = runtime;

    let plaintext: Vec<u8> = decrypt_payload_with_static_key(bytes, detection, &key)?;
    let original_bytecode: Option<Vec<u8>> = Some(plaintext.clone());

    Ok(VersionedOutcome {
        plaintext,
        original_bytecode,
        bcc_blobs: Vec::new(),
        encrypted_funcs_recovered: 0,
        inner_cipher_stats: InnerCipherStats::empty(),
        status: DecryptStatus::Functional,
        diagnostics: vec![format!(
            "DR-PYARM-STATIC: {label} AES-128-CTR (initial=2) decrypted with static key recovered from runtime .rdata"
        )],
    })
}

pub(crate) fn decrypt_payload_with_static_key(
    payload: &[u8],
    detection: &Detection,
    key: &[u8; 16],
) -> Result<Vec<u8>> {
    let offset: usize = detection.payload_offset_in_payload;
    let size: usize = detection.payload_size_in_payload;
    let end: usize = offset.checked_add(size).ok_or(Error::HeaderTruncated {
        need: usize::MAX,
        got: payload.len(),
    })?;
    let ciphertext_slice: &[u8] = payload.get(offset..end).ok_or(Error::HeaderTruncated {
        need: end,
        got: payload.len(),
    })?;

    let mut iv: [u8; 16] = [0u8; 16];
    iv[15] = 0x02;

    let mut buffer: Vec<u8> = ciphertext_slice.to_vec();
    let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(key.into(), &iv.into());
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::detect::{DetectionConfidence, ProtectionKind, PyarmorVersion};

    fn dummy_detection() -> Detection {
        Detection {
            version: PyarmorVersion::V6,
            protection: ProtectionKind::Standard,
            serial: None,
            python_major: Some(3),
            python_minor: Some(7),
            pyc_magic: Some(0x0d42),
            payload_offset_in_payload: 16,
            payload_size_in_payload: 0,
            iv: None,
            raw_header: Vec::new(),
            confidence: DetectionConfidence::High,
            diagnostics: Vec::new(),
        }
    }

    fn synth_runtime_with_static_key(key: &[u8; 16]) -> Vec<u8> {
        crate::key::tests_support::synth_elf64_rdata_adjacent_to_rcon(key)
    }

    #[test]
    fn detect_only_when_no_runtime() {
        let outcome: VersionedOutcome =
            run(&[], &dummy_detection(), None, &UnpackConfig::default()).unwrap();
        assert_eq!(outcome.status, DecryptStatus::DetectOnly);
        assert!(outcome.plaintext.is_empty());
    }

    #[test]
    fn strict_without_runtime_errors() {
        let cfg: UnpackConfig = UnpackConfig {
            strict: true,
            ..UnpackConfig::default()
        };
        let err: Error = run(&[], &dummy_detection(), None, &cfg).unwrap_err();
        assert!(matches!(err, Error::RuntimeNotFound { .. }));
    }

    #[test]
    fn static_key_ctr_roundtrip() {
        let key: [u8; 16] = [
            0x4f, 0xa1, 0x39, 0x7c, 0x12, 0xb8, 0xe5, 0x6d, 0x90, 0x3a, 0x77, 0xfe, 0x21, 0xc4,
            0x88, 0x05,
        ];
        let plaintext_marshal: &[u8] = b"\xe3\x00\x00\x00 imaginary v6 marshal stream body";
        let mut detection: Detection = dummy_detection();
        detection.payload_size_in_payload = plaintext_marshal.len();
        let mut payload: Vec<u8> = vec![0u8; 16 + plaintext_marshal.len()];
        payload[..7].copy_from_slice(b"PYARMOR");
        let mut encrypted: Vec<u8> = plaintext_marshal.to_vec();
        let mut iv: [u8; 16] = [0u8; 16];
        iv[15] = 0x02;
        let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(&key.into(), &iv.into());
        cipher.apply_keystream(&mut encrypted);
        payload[16..].copy_from_slice(&encrypted);

        let recovered: Vec<u8> =
            decrypt_payload_with_static_key(&payload, &detection, &key).unwrap();
        assert_eq!(recovered, plaintext_marshal);
    }

    #[test]
    fn runtime_bytes_thread_through_to_functional_decrypt() {
        let key: [u8; 16] = [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
            0x8f, 0x90,
        ];
        let plaintext_marshal: &[u8] = b"\xe3\x00\x00\x00 v6 module marshal payload bytes";
        let mut detection: Detection = dummy_detection();
        detection.payload_size_in_payload = plaintext_marshal.len();
        let mut payload: Vec<u8> = vec![0u8; 16 + plaintext_marshal.len()];
        payload[..7].copy_from_slice(b"PYARMOR");
        let mut encrypted: Vec<u8> = plaintext_marshal.to_vec();
        let mut iv: [u8; 16] = [0u8; 16];
        iv[15] = 0x02;
        let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(&key.into(), &iv.into());
        cipher.apply_keystream(&mut encrypted);
        payload[16..].copy_from_slice(&encrypted);

        let cfg: UnpackConfig = UnpackConfig {
            runtime_bytes: Some(synth_runtime_with_static_key(&key)),
            ..UnpackConfig::default()
        };
        let outcome: VersionedOutcome = run(&payload, &detection, None, &cfg).unwrap();
        assert_eq!(outcome.status, DecryptStatus::Functional);
        assert_eq!(outcome.plaintext, plaintext_marshal);
        assert_eq!(
            outcome.original_bytecode.as_deref(),
            Some(plaintext_marshal)
        );
    }

    #[test]
    fn truncated_payload_errors() {
        let key: [u8; 16] = [7u8; 16];
        let mut detection: Detection = dummy_detection();
        detection.payload_offset_in_payload = 16;
        detection.payload_size_in_payload = 64;
        let payload: Vec<u8> = vec![0u8; 20];
        let err: Error = decrypt_payload_with_static_key(&payload, &detection, &key).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { .. }));
    }
}
