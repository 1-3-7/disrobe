use disrobe_pass_sourcedefender::{
    ContainerVariant, GcmFramingShape, LayerKind, LayeredRecovery, LayeredWallReason,
    ModernGcmFraming, classify_container, frame_modern_gcm_body, recover_layered,
    recover_layered_with_modern_key,
};

const MODERN_TRIAL: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/known_v16_trial.pye");
const LEGACY_HELLO: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");
const CRAFTED_MODERN_KNOWN_KEY: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/crafted_modern_aesgcm_known_key.pye");

#[test]
fn classifies_real_modern_container_as_hex() {
    assert_eq!(
        classify_container(MODERN_TRIAL),
        Some(ContainerVariant::ModernHex)
    );
    assert_eq!(
        classify_container(LEGACY_HELLO),
        Some(ContainerVariant::LegacyArmored)
    );
}

#[test]
fn modern_trial_peels_hex_layer_then_honest_walls_aes_gcm_body() {
    let Ok(rec): Result<LayeredRecovery, _> = recover_layered(MODERN_TRIAL, "known.pye") else {
        unreachable!("recover_layered failed on real modern sample")
    };

    assert_eq!(rec.variant, ContainerVariant::ModernHex);
    assert!(
        !rec.is_fully_recovered(),
        "modern licensed body must not claim full recovery"
    );
    assert!(
        rec.is_honest_wall(),
        "the wall must be an info-theoretic wall, not a soft failure"
    );

    let peeled_hex: bool = rec
        .layers
        .iter()
        .any(|l| l.kind == LayerKind::HexBody && l.output_len == 229);
    assert!(peeled_hex, "the static hex layer must peel to 229 bytes");

    let Some(wall) = rec.wall.as_ref() else {
        unreachable!("modern sample must carry a wall")
    };
    assert_eq!(wall.reason, LayeredWallReason::RuntimeLicenseKey);
    assert_eq!(wall.ciphertext_len, 229);
    assert!(wall.reason.is_info_theoretic());

    let peeled_framing: bool = rec.layers.iter().any(|l| l.kind == LayerKind::GcmFraming);
    assert!(
        peeled_framing,
        "the modern body must statically peel its aes-gcm salt/nonce/ciphertext/tag framing"
    );
    let Some(framing) = wall.gcm_framing.as_ref() else {
        unreachable!("well-formed modern body must carry framing in the wall")
    };
    assert_eq!(framing.shape, GcmFramingShape::SaltNonceCiphertextTag);
}

#[test]
fn modern_body_frames_as_real_aes_gcm_layout() {
    let framing: ModernGcmFraming = frame_modern_gcm_body(&[0u8; 229]);
    assert!(framing.is_well_formed());
    assert_eq!(framing.body_len, 229);
    assert_eq!(framing.shape, GcmFramingShape::SaltNonceCiphertextTag);
    assert_eq!(framing.ciphertext_len, 229 - 16 - 12 - 16);
}

#[test]
fn modern_aes_gcm_body_decrypts_statically_with_a_supplied_key() {
    let mut key: [u8; 32] = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap_or(0);
    }
    let Ok(rec): Result<LayeredRecovery, _> =
        recover_layered_with_modern_key(CRAFTED_MODERN_KNOWN_KEY, "crafted.pye", &key)
    else {
        unreachable!("keyed modern recovery failed")
    };
    assert_eq!(rec.variant, ContainerVariant::ModernHex);
    assert!(
        rec.wall.is_none(),
        "with the correct key the modern body must fully recover, not wall"
    );
    assert!(rec.is_fully_recovered());
    let Some(source) = rec.recovered_source.as_deref() else {
        unreachable!("the modern free/source body must recover its original source string")
    };
    assert_eq!(
        source.trim_end(),
        "def greet(name):\n    return \"hi \" + name\n\n\nprint(greet(\"world\"))"
    );
    assert!(
        rec.layers
            .iter()
            .any(|l| l.kind == LayerKind::GcmCtrDecrypt)
    );
}

#[test]
fn modern_body_with_wrong_key_does_not_falsely_recover() {
    let Ok(rec): Result<LayeredRecovery, _> =
        recover_layered_with_modern_key(CRAFTED_MODERN_KNOWN_KEY, "crafted.pye", &[0xFFu8; 32])
    else {
        unreachable!("recover_layered_with_modern_key must still peel layers with a wrong key")
    };
    assert!(
        rec.recovered_source.is_none(),
        "a wrong key must not yield a parseable msgpack source envelope"
    );
}

#[test]
fn legacy_free_sample_recovers_known_plaintext_oracle() {
    let Ok(rec): Result<LayeredRecovery, _> = recover_layered(LEGACY_HELLO, "hello.pye") else {
        unreachable!("recover_layered failed on legacy free sample")
    };
    assert!(rec.wall.is_none());
    let Some(source) = rec.recovered_source.as_deref() else {
        unreachable!("legacy free sample must recover an inline source string")
    };
    assert_eq!(source.trim_end(), "print(\"Hello World!\")");
}
