#![allow(clippy::expect_used, clippy::panic)]

use std::path::Path;

use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::containers::luks1::{
    MAX_LUKS1_DIGEST_ITERATIONS, MAX_LUKS1_PAYLOAD_BYTES, MAX_LUKS1_PAYLOAD_OFFSET_BYTES,
    decrypt_luks1_aes_cbc_plain_with_raw_volume_key,
    extract_luks1_aes_cbc_plain_with_raw_volume_key, luks1_raw_volume_key_wall, parse_luks1,
};
use disrobe_binfmt::{Error, ExtractionQuota, ExtractionResult};
use disrobe_core::CryptoWallKind;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

const FIXTURE: &[u8] = include_bytes!("fixtures/luks1/aes128-cbc-plain.luks1");
const PLAINTEXT: &[u8] = include_bytes!("../../../corpus/binfmt/disk/fat-dynamic.vhd");
const RAW_VOLUME_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const DIGEST_SALT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[test]
fn reference_luks1_volume_decrypts_byte_exact_and_enters_vhd_extraction() {
    assert_eq!(
        disrobe_binfmt::detect_container(FIXTURE),
        Some(ContainerKind::Luks1)
    );
    let decrypted: Vec<u8> =
        decrypt_luks1_aes_cbc_plain_with_raw_volume_key(FIXTURE, &RAW_VOLUME_KEY)
            .expect("reference raw volume key");
    assert_eq!(decrypted, PLAINTEXT);

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("real-luks1-extract").expect("scratch");
    let result: ExtractionResult = extract_luks1_aes_cbc_plain_with_raw_volume_key(
        FIXTURE,
        &RAW_VOLUME_KEY,
        scratch.path(),
        ExtractionQuota::default_safe(),
    )
    .expect("decrypted VHD enters the existing extractor");
    assert_eq!(result.kind, ContainerKind::Vhd);
    assert!(result.entries.iter().any(|entry| {
        entry
            .disk_path
            .as_ref()
            .is_some_and(|path| Path::is_file(path))
    }));
}

#[test]
fn keyless_luks1_is_a_raw_volume_key_wall_with_header_metadata() {
    let wall: disrobe_core::CryptoWall =
        luks1_raw_volume_key_wall(FIXTURE).expect("valid LUKS1 header");
    assert_eq!(wall.kind, CryptoWallKind::Luks1RawVolumeKey);
    assert!(wall.runtime_key_absent);
    assert!(wall.evidence.contains("raw volume key"));
    assert!(wall.evidence.contains("cipher=aes"));
    assert!(wall.evidence.contains("mode=cbc-plain"));
    assert!(wall.evidence.contains("kdf=pbkdf2-sha256"));
}

#[test]
fn wrong_raw_volume_key_is_rejected_before_any_output_is_written() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("real-luks1-wrong-key").expect("scratch");
    let wrong: [u8; 16] = [0x41; 16];
    let error: Error = extract_luks1_aes_cbc_plain_with_raw_volume_key(
        FIXTURE,
        &wrong,
        scratch.path(),
        ExtractionQuota::default_safe(),
    )
    .expect_err("wrong raw volume key must not decrypt");
    assert!(matches!(error, Error::Luks1WrongKey));
    assert_eq!(
        std::fs::read_dir(scratch.path())
            .expect("read scratch")
            .count(),
        0
    );
}

#[test]
fn unsupported_mode_is_named_before_payload_decryption() {
    let mut image: Vec<u8> = FIXTURE.to_vec();
    image[40..72].fill(0);
    image[40..52].copy_from_slice(b"xts-plain64\0");
    let error: Error = decrypt_luks1_aes_cbc_plain_with_raw_volume_key(&image, &RAW_VOLUME_KEY)
        .expect_err("XTS is outside this slice");
    assert!(matches!(
        error,
        Error::Luks1UnsupportedCipher { ref cipher, ref mode }
            if cipher == "aes" && mode == "xts-plain64"
    ));
}

#[test]
fn unsupported_hash_is_named_before_key_derivation() {
    let mut image: Vec<u8> = FIXTURE.to_vec();
    image[72..104].fill(0);
    image[72..82].copy_from_slice(b"ripemd160\0");
    let error: Error = decrypt_luks1_aes_cbc_plain_with_raw_volume_key(&image, &RAW_VOLUME_KEY)
        .expect_err("RIPEMD-160 is outside this slice");
    assert!(matches!(
        error,
        Error::Luks1UnsupportedHash { ref hash } if hash == "ripemd160"
    ));
}

#[test]
fn keyless_unsupported_headers_are_typed_errors_instead_of_walls() {
    let mut xts: Vec<u8> = FIXTURE.to_vec();
    xts[40..72].fill(0);
    xts[40..52].copy_from_slice(b"xts-plain64\0");
    assert!(matches!(
        luks1_raw_volume_key_wall(&xts),
        Err(Error::Luks1UnsupportedCipher { .. })
    ));

    let mut unknown_hash: Vec<u8> = FIXTURE.to_vec();
    unknown_hash[72..104].fill(0);
    unknown_hash[72..82].copy_from_slice(b"ripemd160\0");
    assert!(matches!(
        luks1_raw_volume_key_wall(&unknown_hash),
        Err(Error::Luks1UnsupportedHash { .. })
    ));
}

#[test]
fn unsupported_volume_key_size_is_named() {
    let mut image: Vec<u8> = FIXTURE.to_vec();
    image[108..112].copy_from_slice(&20_u32.to_be_bytes());
    let raw_volume_key: [u8; 20] = [0; 20];
    let error: Error = decrypt_luks1_aes_cbc_plain_with_raw_volume_key(&image, &raw_volume_key)
        .expect_err("160-bit AES keys are outside this slice");
    assert!(matches!(
        error,
        Error::Luks1UnsupportedKeyBytes { key_bytes: 20 }
    ));
}

#[test]
fn header_payload_and_active_keyslot_offsets_are_bounded() {
    let mut header_overlap: Vec<u8> = FIXTURE.to_vec();
    header_overlap[104..108].copy_from_slice(&1_u32.to_be_bytes());
    assert!(matches!(
        parse_luks1(&header_overlap),
        Err(Error::Luks1Malformed)
    ));

    let mut keyslot_overlap: Vec<u8> = FIXTURE.to_vec();
    keyslot_overlap[208..212].copy_from_slice(&0x00ac_71f3_u32.to_be_bytes());
    keyslot_overlap[212..216].copy_from_slice(&1_000_u32.to_be_bytes());
    keyslot_overlap[248..252].copy_from_slice(&7_u32.to_be_bytes());
    keyslot_overlap[252..256].copy_from_slice(&4_000_u32.to_be_bytes());
    assert!(matches!(
        parse_luks1(&keyslot_overlap),
        Err(Error::Luks1Malformed)
    ));
}

#[test]
fn keyslot_states_alignment_overlap_and_unused_kdf_cost_are_validated() {
    let mut disabled: Vec<u8> = FIXTURE.to_vec();
    disabled[208..212].copy_from_slice(&0x0000_dead_u32.to_be_bytes());
    disabled[212..216].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_luks1(&disabled).is_ok());

    let mut unknown_state: Vec<u8> = FIXTURE.to_vec();
    unknown_state[208..212].copy_from_slice(&0x0000_cafe_u32.to_be_bytes());
    assert!(matches!(
        parse_luks1(&unknown_state),
        Err(Error::Luks1Malformed)
    ));

    let mut misaligned: Vec<u8> = FIXTURE.to_vec();
    misaligned[104..108].copy_from_slice(&32_u32.to_be_bytes());
    set_active_keyslot(&mut misaligned, 0, 2_000_000, 9, 16);
    assert!(matches!(
        parse_luks1(&misaligned),
        Err(Error::Luks1Malformed)
    ));

    let mut overlapping: Vec<u8> = FIXTURE.to_vec();
    overlapping[104..108].copy_from_slice(&32_u32.to_be_bytes());
    set_active_keyslot(&mut overlapping, 0, 2_000_000, 8, 16);
    set_active_keyslot(&mut overlapping, 1, 3_000_000, 8, 16);
    assert!(matches!(
        parse_luks1(&overlapping),
        Err(Error::Luks1Malformed)
    ));

    let mut unused_high_cost: Vec<u8> = FIXTURE.to_vec();
    unused_high_cost[104..108].copy_from_slice(&32_u32.to_be_bytes());
    set_active_keyslot(&mut unused_high_cost, 0, u32::MAX, 8, 16);
    assert!(parse_luks1(&unused_high_cost).is_ok());
}

#[test]
fn header_c_strings_require_printable_nul_terminated_ascii() {
    let mut unterminated: Vec<u8> = FIXTURE.to_vec();
    unterminated[8..40].fill(b'a');
    assert!(matches!(
        parse_luks1(&unterminated),
        Err(Error::Luks1Malformed)
    ));

    let mut control: Vec<u8> = FIXTURE.to_vec();
    control[8] = 0x1f;
    assert!(matches!(parse_luks1(&control), Err(Error::Luks1Malformed)));

    let mut trailing_bytes: Vec<u8> = FIXTURE.to_vec();
    trailing_bytes[12] = b'x';
    assert!(parse_luks1(&trailing_bytes).is_ok());

    let mut unterminated_uuid: Vec<u8> = FIXTURE.to_vec();
    unterminated_uuid[168..208].fill(b'a');
    assert!(matches!(
        parse_luks1(&unterminated_uuid),
        Err(Error::Luks1Malformed)
    ));

    let mut control_uuid: Vec<u8> = FIXTURE.to_vec();
    control_uuid[168] = 0x1f;
    assert!(matches!(
        parse_luks1(&control_uuid),
        Err(Error::Luks1Malformed)
    ));
}

#[test]
fn detached_and_over_cap_payload_offsets_are_typed() {
    let mut luks2: Vec<u8> = FIXTURE.to_vec();
    luks2[6..8].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        parse_luks1(&luks2),
        Err(Error::LuksUnsupportedVersion { version: 2 })
    ));

    let mut detached: Vec<u8> = FIXTURE.to_vec();
    detached[104..108].copy_from_slice(&0_u32.to_be_bytes());
    set_active_keyslot(&mut detached, 0, 1_000, 8, 16);
    assert!(matches!(
        parse_luks1(&detached),
        Err(Error::Luks1DetachedPayload)
    ));

    let over_cap_sectors: u32 =
        u32::try_from(MAX_LUKS1_PAYLOAD_OFFSET_BYTES / 512 + 1).expect("offset fits u32");
    let mut over_cap: Vec<u8> = FIXTURE.to_vec();
    over_cap[104..108].copy_from_slice(&over_cap_sectors.to_be_bytes());
    assert!(matches!(
        parse_luks1(&over_cap),
        Err(Error::Luks1PayloadOffsetTooLarge { .. })
    ));

    let cap_sectors: u32 =
        u32::try_from(MAX_LUKS1_PAYLOAD_OFFSET_BYTES / 512).expect("offset fits u32");
    let mut at_cap: Vec<u8> = FIXTURE.to_vec();
    at_cap[104..108].copy_from_slice(&cap_sectors.to_be_bytes());
    assert!(parse_luks1(&at_cap).is_ok());
}

#[test]
fn every_advertised_key_size_and_header_hash_decrypts_known_plaintext() {
    let plaintext: [u8; 512] = std::array::from_fn(|index: usize| index as u8);
    for key_bytes in [16_usize, 24, 32] {
        let key: Vec<u8> = (0..key_bytes).map(|index: usize| index as u8).collect();
        for hash_spec in ["sha1", "sha256", "sha512"] {
            let image: Vec<u8> = build_known_plaintext_image(&plaintext, &key, hash_spec);
            let decrypted: Vec<u8> = decrypt_luks1_aes_cbc_plain_with_raw_volume_key(&image, &key)
                .expect("advertised raw-key combination");
            assert_eq!(
                decrypted, plaintext,
                "{key_bytes}-byte key with {hash_spec}"
            );
        }
    }
}

#[test]
fn payload_recovery_cap_is_enforced_before_decryption() {
    let payload_offset: usize = 8 * 512;
    let mut oversized: Vec<u8> = vec![0; payload_offset + MAX_LUKS1_PAYLOAD_BYTES + 512];
    oversized[..payload_offset].copy_from_slice(&FIXTURE[..payload_offset]);
    let error: Error = decrypt_luks1_aes_cbc_plain_with_raw_volume_key(&oversized, &RAW_VOLUME_KEY)
        .expect_err("payload cap must precede decryption");
    assert!(matches!(
        error,
        Error::Luks1PayloadTooLarge {
            bytes,
            cap: MAX_LUKS1_PAYLOAD_BYTES
        } if bytes == MAX_LUKS1_PAYLOAD_BYTES + 512
    ));
}

#[test]
fn oversized_header_digest_kdf_is_rejected_before_derivation() {
    let mut image: Vec<u8> = FIXTURE.to_vec();
    image[164..168].copy_from_slice(&(MAX_LUKS1_DIGEST_ITERATIONS + 1).to_be_bytes());
    let error: Error = parse_luks1(&image).expect_err("KDF cost must be bounded");
    assert!(matches!(
        error,
        Error::Luks1KdfCost { iterations }
            if iterations == MAX_LUKS1_DIGEST_ITERATIONS + 1
    ));
}

#[test]
fn truncated_and_partial_sector_payloads_are_rejected() {
    let truncated: &[u8] = &FIXTURE[..4095];
    assert!(matches!(
        decrypt_luks1_aes_cbc_plain_with_raw_volume_key(truncated, &RAW_VOLUME_KEY),
        Err(Error::Luks1TruncatedPayload)
    ));
    let partial: &[u8] = &FIXTURE[..FIXTURE.len() - 1];
    assert!(matches!(
        decrypt_luks1_aes_cbc_plain_with_raw_volume_key(partial, &RAW_VOLUME_KEY),
        Err(Error::Luks1TruncatedPayload)
    ));
}

fn set_active_keyslot(
    image: &mut [u8],
    slot: usize,
    iterations: u32,
    material_offset: u32,
    stripes: u32,
) {
    let base: usize = 208 + slot * 48;
    image[base..base + 4].copy_from_slice(&0x00ac_71f3_u32.to_be_bytes());
    image[base + 4..base + 8].copy_from_slice(&iterations.to_be_bytes());
    image[base + 40..base + 44].copy_from_slice(&material_offset.to_be_bytes());
    image[base + 44..base + 48].copy_from_slice(&stripes.to_be_bytes());
}

fn build_known_plaintext_image(plaintext: &[u8; 512], key: &[u8], hash_spec: &str) -> Vec<u8> {
    let payload_offset: usize = 8 * 512;
    let mut image: Vec<u8> = vec![0; payload_offset + plaintext.len()];
    image[..payload_offset].copy_from_slice(&FIXTURE[..payload_offset]);
    image[72..104].fill(0);
    image[72..72 + hash_spec.len()].copy_from_slice(hash_spec.as_bytes());
    image[108..112].copy_from_slice(&(key.len() as u32).to_be_bytes());
    let mut digest: [u8; 20] = [0; 20];
    match hash_spec {
        "sha1" => pbkdf2_hmac::<Sha1>(key, &DIGEST_SALT, 1_000, &mut digest),
        "sha256" => pbkdf2_hmac::<Sha256>(key, &DIGEST_SALT, 1_000, &mut digest),
        "sha512" => pbkdf2_hmac::<Sha512>(key, &DIGEST_SALT, 1_000, &mut digest),
        _ => panic!("unsupported test hash"),
    }
    image[112..132].copy_from_slice(&digest);
    let mut sector: [u8; 512] = *plaintext;
    let iv: [u8; 16] = [0; 16];
    match key.len() {
        16 => {
            cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &iv)
                .expect("AES-128 key")
                .encrypt_padded_mut::<NoPadding>(&mut sector, plaintext.len())
                .expect("sector-aligned plaintext");
        }
        24 => {
            cbc::Encryptor::<aes::Aes192>::new_from_slices(key, &iv)
                .expect("AES-192 key")
                .encrypt_padded_mut::<NoPadding>(&mut sector, plaintext.len())
                .expect("sector-aligned plaintext");
        }
        32 => {
            cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv)
                .expect("AES-256 key")
                .encrypt_padded_mut::<NoPadding>(&mut sector, plaintext.len())
                .expect("sector-aligned plaintext");
        }
        _ => panic!("unsupported test key size"),
    }
    image[payload_offset..].copy_from_slice(&sector);
    image
}
