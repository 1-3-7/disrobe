use crate::detect::Detection;
use crate::error::Result;
use crate::static_unpack::decrypt_v6::decrypt_v6v7;
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{UnpackConfig, VersionedOutcome};

pub(crate) fn run(
    bytes: &[u8],
    detection: &Detection,
    runtime: Option<&RuntimeInfoSummary>,
    cfg: &UnpackConfig,
) -> Result<VersionedOutcome> {
    decrypt_v6v7(bytes, detection, runtime, cfg, "v7")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use aes::Aes128;
    use ctr::Ctr128BE;
    use ctr::cipher::{KeyIvInit, StreamCipher};

    use super::*;
    use crate::detect::{DetectionConfidence, ProtectionKind, PyarmorVersion};
    use crate::error::Error;
    use crate::static_unpack::DecryptStatus;

    fn dummy_detection() -> Detection {
        Detection {
            version: PyarmorVersion::V7,
            protection: ProtectionKind::Standard,
            serial: None,
            python_major: Some(3),
            python_minor: Some(9),
            pyc_magic: Some(0x0d42),
            payload_offset_in_payload: 16,
            payload_size_in_payload: 0,
            iv: None,
            raw_header: Vec::new(),
            confidence: DetectionConfidence::High,
            diagnostics: Vec::new(),
        }
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
    fn runtime_bytes_thread_through_to_functional_decrypt() {
        let key: [u8; 16] = [
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
            0x12, 0x23,
        ];
        let plaintext_marshal: &[u8] = b"\xe3\x00\x00\x00 v7 module marshal payload bytes";
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
            runtime_bytes: Some(
                crate::key::tests_support::synth_elf64_rdata_adjacent_to_rcon(&key),
            ),
            ..UnpackConfig::default()
        };
        let outcome: VersionedOutcome = run(&payload, &detection, None, &cfg).unwrap();
        assert_eq!(outcome.status, DecryptStatus::Functional);
        assert_eq!(outcome.plaintext, plaintext_marshal);
    }
}
