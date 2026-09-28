use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{DecryptStatus, InnerCipherStats, UnpackConfig, VersionedOutcome};
use crate::v8v9::{DecryptedBody, decrypt_body};

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
            inner_cipher_stats: InnerCipherStats::empty(),
            status: DecryptStatus::DetectOnly,
            diagnostics: vec![
                "DR-PYARM-STATIC: v8 detect-only. The AES key is not present in the payload; it is derived from the pyarmor_runtime native module. Supply that runtime (UnpackConfig.runtime_bytes / --runtime pyarmor_runtime.{so,pyd,dylib}) for static decrypt, OR run the target under the dynamic capture path (disrobe-pyarmor-cextract / disrobe-pyarmor-pytrace) to snapshot the decrypted code objects. No plaintext is emitted without one of these."
                    .to_owned(),
            ],
        });
    };

    if detection.serial.as_deref().is_some()
        && detection
            .serial
            .as_deref()
            .is_some_and(|s: &str| s != runtime_info.serial)
    {
        tracing::warn!(
            payload_serial = ?detection.serial,
            runtime_serial = %runtime_info.serial,
            "v8 payload serial does not match runtime serial"
        );
    }

    decrypt_with_runtime_key(bytes, &runtime_info.aes_key, DecryptStatus::Functional)
}

pub(crate) fn decrypt_with_runtime_key(
    bytes: &[u8],
    aes_key: &[u8; 16],
    base_status: DecryptStatus,
) -> Result<VersionedOutcome> {
    if bytes.len() < 64 {
        return Err(Error::HeaderTruncated {
            need: 64,
            got: bytes.len(),
        });
    }
    let body: DecryptedBody = decrypt_body(bytes, aes_key)?;
    let status: DecryptStatus = if body.bcc_mode {
        DecryptStatus::BccPartial
    } else {
        base_status
    };
    let mut diagnostics: Vec<String> = Vec::new();
    if !body.body_encrypted {
        diagnostics.push(
            "DR-PYARM-STATIC: obf_mod 0 plaintext module body (encrypt-flag clear); AES step skipped, marshal lifted directly"
                .to_owned(),
        );
    }
    if body.bcc_mode {
        diagnostics.push(format!(
            "DR-PYARM-STATIC: BCC mode payload - {} native segment(s) extracted; Python bytecode after BCC decrypted, native functions remain opaque without --allow-bcc",
            body.bcc_blobs.len()
        ));
    }
    Ok(VersionedOutcome {
        original_bytecode: Some(body.plaintext.clone()),
        plaintext: body.plaintext,
        bcc_blobs: body.bcc_blobs,
        encrypted_funcs_recovered: 0,
        inner_cipher_stats: InnerCipherStats::empty(),
        status,
        diagnostics,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::detect::{DetectionConfidence, ProtectionKind, PyarmorVersion};

    fn detection() -> Detection {
        Detection {
            version: PyarmorVersion::V8,
            protection: ProtectionKind::Standard,
            serial: Some("008106".to_owned()),
            python_major: Some(3),
            python_minor: Some(11),
            pyc_magic: Some(0xa70d),
            payload_offset_in_payload: 64,
            payload_size_in_payload: 0,
            iv: None,
            raw_header: Vec::new(),
            confidence: DetectionConfidence::High,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn detect_only_without_runtime_nonstrict() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..8].copy_from_slice(b"PY008106");
        bytes[20] = 0x08;
        let outcome: VersionedOutcome =
            run(&bytes, &detection(), None, &UnpackConfig::default()).unwrap();
        assert_eq!(outcome.status, DecryptStatus::DetectOnly);
        assert!(
            outcome.plaintext.is_empty(),
            "no plaintext without a runtime"
        );
        let verdict: &str = outcome.diagnostics.first().map_or("", String::as_str);
        assert!(
            verdict.contains("pyarmor_runtime") && verdict.contains("cextract"),
            "no-runtime verdict must name both the runtime-key static path and the dynamic capture route: {verdict}"
        );
    }

    #[test]
    fn strict_without_runtime_errors() {
        let cfg: UnpackConfig = UnpackConfig {
            strict: true,
            ..UnpackConfig::default()
        };
        let err: Error = run(&[], &detection(), None, &cfg).unwrap_err();
        assert!(matches!(err, Error::RuntimeNotFound { .. }));
    }

    #[test]
    fn plaintext_body_when_encrypt_flag_clear() {
        let key: [u8; 16] = [0x99u8; 16];
        let plaintext_marshal: &[u8] = b"\x20\x00\x00\x00 plaintext obf_mod 0 marshal body";
        let cipher_offset: u32 = 64u32;
        let cipher_len: u32 = u32::try_from(plaintext_marshal.len()).unwrap();
        let mut payload: Vec<u8> = vec![0u8; 64 + plaintext_marshal.len()];
        payload[..8].copy_from_slice(b"PY008106");
        payload[20] = 0x08;
        payload[36] = 0x12;
        payload[37] = 0x08;
        payload[28..32].copy_from_slice(&cipher_offset.to_le_bytes());
        payload[32..36].copy_from_slice(&cipher_len.to_le_bytes());
        payload[64..].copy_from_slice(plaintext_marshal);

        let outcome: VersionedOutcome =
            decrypt_with_runtime_key(&payload, &key, DecryptStatus::Functional).unwrap();
        assert_eq!(outcome.plaintext, plaintext_marshal);
        assert_eq!(outcome.status, DecryptStatus::Functional);
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|d: &String| d.contains("obf_mod 0")),
            "plaintext-body path emits the obf_mod 0 diagnostic"
        );
    }

    #[test]
    fn decrypt_with_runtime_key_roundtrip() {
        let key: [u8; 16] = [0x99u8; 16];
        let plaintext_marshal: &[u8] = b"\xe3\x00\x00\x00\x00 imaginary marshal stream body";
        let nonce: [u8; 12] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        let cipher_offset: u32 = 64u32;
        let cipher_len: u32 = u32::try_from(plaintext_marshal.len()).unwrap();
        let mut payload: Vec<u8> = vec![0u8; 64 + plaintext_marshal.len()];
        payload[..8].copy_from_slice(b"PY008106");
        payload[20] = 0x08;
        payload[28..32].copy_from_slice(&cipher_offset.to_le_bytes());
        payload[32..36].copy_from_slice(&cipher_len.to_le_bytes());
        payload[36..40].copy_from_slice(&nonce[..4]);
        payload[44..52].copy_from_slice(&nonce[4..]);
        assert!(nonce[1] & 0x01 != 0, "fixture nonce keeps encrypt flag set");
        let mut encrypted: Vec<u8> = plaintext_marshal.to_vec();
        crate::v8v9::aes_ctr_init2(&key, &nonce, &mut encrypted);
        payload[64..].copy_from_slice(&encrypted);

        let outcome: VersionedOutcome =
            decrypt_with_runtime_key(&payload, &key, DecryptStatus::Functional).unwrap();
        assert_eq!(outcome.plaintext, plaintext_marshal);
        assert_eq!(outcome.status, DecryptStatus::Functional);
    }
}
