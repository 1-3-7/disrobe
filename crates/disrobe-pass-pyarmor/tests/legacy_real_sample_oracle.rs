#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pyarmor::{
    Detection, DetectionConfidence, PyarmorVersion, UnpackOptions, UnpackOutput,
    detect_from_wrapper, unpack_wrapper_text_with_options,
};

const V3_MODE8_PAYLOAD_B64: &str = "5VCMZCZC1gHoS2LcmbFhH9my/0FP4VbiZjuvtE5e24tPwjVhE0rq3wiYdrYRc2YygKcDPuUWn3EC70iTW2oSY89mNqZjwLcPcA4JcxKoOO+742Stzk7QeNti2unMSl8+Quj0KUwx7hRGxg5535zvxu6JCLWEe7oZ42eMDIkh0qnCkk/3UtGIAW0rdbweWxWzo02icqKwYw9R6zdr3g+RaR0rtfOGdq0lBoKQpaPKBSwZlmKrDEZmX4OVFV2yhzN781pJlSlnaFsAJiqyeHN0IQRXfKHQV6ATmuHy3zcY1PZ6IrrGEXcCkRTpUxS7tyc54yvkCU6H5SA+Q3xoNbzE0Ii5z3wvf13OCO+jPi5mQc+Aydn8nR5eV8tNaPf7C43tR93jiDFqxU+hdOs47ReN946a3LLAjNsv1AkKWKZqQFUV4cJh8NCKkLWdJYZPSWiUVvuyw42UVvlpf7fjeFHwjSc16v4NLJGeVoiZY5fO3XTeskZRrjtvZxaO1I3gVZbgg37sItfFuHbAy0rVzECxozWJ3H6P53sdw8E33oCA2QytsPSz0rKojvIOLF3BhaQIT5M7DdDkONybp+Mdma0wSefteOprk0zz7+V6gmztiqZ+J7VxJxxAM96654Q4FGiv/b0BSj2iRNl8CYL75XZkJBZL+B9ug8lQXWTmZFxTV9Jb5g9f+Fj/f65+1Sn6FHiWag4GYQ5Czto+DRDgWD+bK69Hnb7NCQ+kRYeFjBEnrlY3lP5i5MUJglGa3aOEOkhRHSNOtCaC1gNK/VOoeNuW59jLFbylB3jlaHTGNXFc";

const V5_PAYLOAD_B64: &str = "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";

fn make_scratch_dir(name: &str) -> ScratchDir {
    ScratchDir::create(&format!("pyarmor-{name}")).expect("scratch dir")
}

fn escape_bytes(payload: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut escaped: String = String::with_capacity(payload.len() * 4);
    for byte in payload.iter().copied() {
        escaped.push('\\');
        escaped.push('x');
        escaped.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        escaped.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    escaped
}

fn wrapper_text(payload: &[u8]) -> String {
    format!(
        "from pytransform import pyarmor_runtime\npyarmor_runtime()\n__pyarmor__(__name__, __file__, b'{}', 1)\n",
        escape_bytes(payload)
    )
}

#[test]
fn real_v5_wrapper_detects_as_pyarmor_header_family() {
    let payload: Vec<u8> = B64.decode(V5_PAYLOAD_B64).expect("decode v5");
    assert_eq!(
        &payload[..8],
        b"PYARMOR\x00",
        "real v5 carries PYARMOR\\0 magic"
    );
    assert!(
        payload[36..64].iter().all(|&b| b == 0),
        "real PyArmor 5.x zeroes the inline key region [36..64]"
    );

    let text: String = wrapper_text(&payload);
    let (det, parsed): (Detection, Vec<u8>) = detect_from_wrapper(&text).expect("detects");
    assert_eq!(parsed, payload);
    assert!(
        matches!(det.version, PyarmorVersion::V6 | PyarmorVersion::V7),
        "PyArmor 5.x emits the PYARMOR\\0 header that disrobe classifies in the v6/v7 family; got {:?}",
        det.version
    );
    assert_eq!(det.python_major, Some(3));
    assert_eq!(det.python_minor, Some(7));
}

#[test]
fn real_v5_wrapper_walls_static_decryption_without_runtime() {
    let payload: Vec<u8> = B64.decode(V5_PAYLOAD_B64).expect("decode v5");
    let text: String = wrapper_text(&payload);
    let scratch: ScratchDir = make_scratch_dir("v5-no-runtime");
    let tmp: &Path = scratch.path();
    let wrapper: PathBuf = tmp.join("hello.py");
    fs::write(&wrapper, &text).expect("write wrapper");

    let result: Result<UnpackOutput, _> =
        unpack_wrapper_text_with_options(&text, &wrapper, &UnpackOptions::default());
    assert!(
        result.is_err(),
        "no sibling _pytransform runtime present, so the v5 key cannot be recovered; must error rather than fabricate a plaintext"
    );
}

#[test]
fn real_v3_mode8_payload_is_bare_ctr_stream_sharing_keystream_prefix_with_v5() {
    let v3: Vec<u8> = B64.decode(V3_MODE8_PAYLOAD_B64).expect("decode v3");
    let v5: Vec<u8> = B64.decode(V5_PAYLOAD_B64).expect("decode v5");
    assert_ne!(
        &v3[..7],
        b"PYARMOR",
        "PyArmor 3.x mode-8 emits a bare ciphertext blob with no PYARMOR header"
    );
    assert_ne!(
        v3.len() % 16,
        0,
        "PyArmor code-object cipher is AES-CTR (stream): ciphertext length is not block-aligned"
    );
    assert_eq!(
        &v3[..8],
        &v5[0x40..0x48],
        "v3 bare blob and v5 ciphertext-region share the first 8 keystream bytes (same plaintext marshal header XOR same per-machine capsule keystream)"
    );
}

#[test]
fn legacy_leading_byte_wrapper_is_detect_only_never_fabricated() {
    let mut payload: Vec<u8> = vec![0u8; 80];
    payload[0] = 0x05;
    let text: String = format!(
        "from pytransform import __pyarmor__\n__pyarmor__(__name__, __file__, b'{}')\n",
        escape_bytes(&payload)
    );
    let (det, _): (Detection, Vec<u8>) = detect_from_wrapper(&text).expect("detects");
    assert_eq!(det.version, PyarmorVersion::V5);
    assert_eq!(det.confidence, DetectionConfidence::Low);

    let scratch: ScratchDir = make_scratch_dir("legacy-leadbyte");
    let tmp: &Path = scratch.path();
    let wrapper: PathBuf = tmp.join("hello.py");
    fs::write(&wrapper, &text).expect("write wrapper");
    let out: UnpackOutput =
        unpack_wrapper_text_with_options(&text, &wrapper, &UnpackOptions::default())
            .expect("legacy detect-only succeeds without error");
    assert!(
        out.pyc.is_none(),
        "legacy static path must not emit a fabricated .pyc"
    );
    assert!(out.plaintext.iter().all(|&b| b == 0) || out.plaintext == payload);
    let reason: String = out.fallback_reason.expect("carries a wall reason");
    assert!(
        reason.contains("information-theoretic wall") || reason.contains("RSA-wrapped"),
        "wall reason must state the genuine cause; got: {reason}"
    );
}
