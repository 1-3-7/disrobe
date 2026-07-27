#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::firmware::{
    FirmwareExtraction, FirmwareKind, detect_firmware, extract_firmware,
};
use disrobe_binfmt::{ExtractionResult, extract_to};

const SQUASHFS_MAGIC: [u8; 4] = [0x68, 0x73, 0x71, 0x73];

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-firmware-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn inner_plaintext(total_len: usize) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::with_capacity(total_len);
    data.extend_from_slice(&SQUASHFS_MAGIC);
    let body: &[u8] = b"disrobe spec-constructed firmware inner payload; ";
    while data.len() < total_len {
        data.push(body[data.len() % body.len()]);
    }
    data.truncate(total_len);
    data
}

fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
    type Enc = cbc::Encryptor<aes::Aes128>;
    assert_eq!(plaintext.len() % 16, 0);
    let mut buf: Vec<u8> = plaintext.to_vec();
    let len: usize = buf.len();
    Enc::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
        .expect("aes128 encrypt");
    buf
}

fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
    type Enc = cbc::Encryptor<aes::Aes256>;
    assert_eq!(plaintext.len() % 16, 0);
    let mut buf: Vec<u8> = plaintext.to_vec();
    let len: usize = buf.len();
    Enc::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
        .expect("aes256 encrypt");
    buf
}

const SHRS_KEY: [u8; 16] = [
    0xc0, 0x5f, 0xbf, 0x19, 0x36, 0xc9, 0x94, 0x29, 0xce, 0x2a, 0x07, 0x81, 0xf0, 0x8d, 0x6a, 0xd8,
];
const SHRS_IV: [u8; 16] = [
    0x98, 0xc9, 0xd8, 0xf0, 0x13, 0x3d, 0x06, 0x95, 0xe2, 0xa7, 0x09, 0xc8, 0xb6, 0x96, 0x82, 0xd4,
];

#[test]
fn dlink_shrs_spec_constructed_decrypts_to_inner_squashfs() {
    let plaintext: Vec<u8> = inner_plaintext(96);
    let ciphertext: Vec<u8> = aes128_cbc_encrypt(&SHRS_KEY, &SHRS_IV, &plaintext);
    let mut image: Vec<u8> = vec![0u8; 1756];
    image[0..4].copy_from_slice(b"SHRS");
    image[4..8].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    image[8..12].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    image[0x0c..0x0c + 16].copy_from_slice(&SHRS_IV);
    image.extend_from_slice(&ciphertext);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::DlinkShrs));
    assert_eq!(detect_container(&image), Some(ContainerKind::FwDlinkShrs));

    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::DlinkShrs, &image).expect("shrs decrypt");
    assert_eq!(out.members.len(), 1);
    assert_eq!(out.members[0].data, plaintext);
    assert_eq!(out.inner_kind_hint.as_deref(), Some("squashfs"));
}

const ENCRPTED_KEY: [u8; 32] = *b"he9-4+M!)d6=m~we1,q2a3d1n&2*Z^%8";
const ENCRPTED_IV: [u8; 16] = *b"J%1iQl8$=lm-;8AE";
const UBI_HEAD: [u8; 16] = [
    0x55, 0x42, 0x49, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn dlink_encrpted_img_spec_constructed_restores_ubi_head() {
    let mut plaintext: Vec<u8> = inner_plaintext(128);
    plaintext[..16].copy_from_slice(&UBI_HEAD);
    let ciphertext: Vec<u8> = aes256_cbc_encrypt(&ENCRPTED_KEY, &ENCRPTED_IV, &plaintext);
    let mut image: Vec<u8> = Vec::new();
    image.extend_from_slice(b"encrpted_img");
    image.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    image.extend_from_slice(&ciphertext);

    assert_eq!(
        detect_firmware(&image),
        Some(FirmwareKind::DlinkEncrptedImg)
    );
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::DlinkEncrptedImg, &image).expect("encrpted_img decrypt");
    assert_eq!(out.members[0].data, plaintext);
    assert_eq!(out.inner_kind_hint.as_deref(), Some("ubi"));
}

const ALPHA_XOR_RANGE: usize = 0xfc;

fn alpha_mangle(signature: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| {
            b ^ (((i + 1) % ALPHA_XOR_RANGE) as u8) ^ signature[i % signature.len()]
        })
        .collect()
}

#[test]
fn dlink_alpha_v1_spec_constructed_decrypts_with_device_table() {
    let signature: &[u8] = b"wrgac43s_dlink.2015_dir822c1";
    let key: [u8; 32] = *b"KNpsEntCcsep1jdFIs3wnXySKRGNCGmf";
    let iv: [u8; 16] = *b"uph587JdKHrtAUlr";

    let mut mkey: [u8; 32] = [0u8; 32];
    mkey.copy_from_slice(&alpha_mangle(signature, &key));
    let mut miv: [u8; 16] = [0u8; 16];
    miv.copy_from_slice(&alpha_mangle(signature, &iv));

    let plaintext: Vec<u8> = inner_plaintext(80);
    let ciphertext: Vec<u8> = aes256_cbc_encrypt(&mkey, &miv, &plaintext);

    assert_eq!(
        detect_firmware(&ciphertext),
        Some(FirmwareKind::DlinkAlphaV1)
    );
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::DlinkAlphaV1, &ciphertext).expect("alpha v1 decrypt");
    assert_eq!(out.members[0].data, plaintext);
    assert_eq!(out.inner_kind_hint.as_deref(), Some("squashfs"));
}

#[test]
fn dlink_alpha_v2_spec_constructed_decrypts_fixed_key_with_wrgg_signature() {
    let signature: &[u8] = b"wapac99_dlink.2099_dapXXXX";
    let key: [u8; 32] = *b"oVhq0hvXHdfaGFLdubM4/QvuVHdKee7v";
    let iv: [u8; 16] = *b"0BO5nlYankuVBe4s";
    let mut mkey: [u8; 32] = [0u8; 32];
    mkey.copy_from_slice(&alpha_mangle(signature, &key));
    let mut miv: [u8; 16] = [0u8; 16];
    miv.copy_from_slice(&alpha_mangle(signature, &iv));

    let plaintext: Vec<u8> = inner_plaintext(128);
    let ciphertext: Vec<u8> = aes256_cbc_encrypt(&mkey, &miv, &plaintext);

    let mut image: Vec<u8> = vec![0u8; 0xa0];
    image[0..signature.len()].copy_from_slice(signature);
    image.extend_from_slice(&ciphertext);

    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::DlinkAlphaV2, &image).expect("alpha v2 decrypt");
    assert_eq!(out.members[0].data, plaintext);
    assert_eq!(out.inner_kind_hint.as_deref(), Some("squashfs"));
}

const ENGENIUS_XOR_KEY: [u8; 8] = [0xac, 0x78, 0x3c, 0x9e, 0xcf, 0x67, 0xb3, 0x59];

#[test]
fn engenius_spec_constructed_rolling_xor_decrypts() {
    let fixed_header_len: usize = 136;
    let plaintext: Vec<u8> = inner_plaintext(64);
    let total_length: u32 = (fixed_header_len + plaintext.len()) as u32;

    let mut image: Vec<u8> = vec![0u8; fixed_header_len];
    image[0x5c..0x5c + 7].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x61, 0x6c, 0x6c]);
    image[32..36].copy_from_slice(&total_length.to_be_bytes());
    image[132..136].copy_from_slice(&0u32.to_le_bytes());
    let reference: usize = 0x10;
    image[reference..reference + 8].copy_from_slice(&ENGENIUS_XOR_KEY);

    for (i, plain) in plaintext.iter().enumerate() {
        let offset: usize = fixed_header_len + i;
        image.push(plain ^ ENGENIUS_XOR_KEY[(offset - reference) % ENGENIUS_XOR_KEY.len()]);
    }

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::EnGenius));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::EnGenius, &image).expect("engenius decrypt");
    assert_eq!(out.members[0].data, plaintext);
    assert_eq!(out.inner_kind_hint.as_deref(), Some("squashfs"));
}

const AUTEL_KEYS: [(u8, u8); 256] = [
    (54, 147),
    (96, 129),
    (59, 193),
    (191, 0),
    (45, 130),
    (96, 144),
    (27, 129),
    (152, 0),
    (44, 180),
    (118, 141),
    (115, 129),
    (210, 0),
    (13, 164),
    (27, 133),
    (20, 192),
    (139, 0),
    (28, 166),
    (17, 133),
    (19, 193),
    (224, 0),
    (20, 161),
    (145, 0),
    (14, 193),
    (12, 132),
    (18, 161),
    (17, 140),
    (29, 192),
    (246, 0),
    (115, 178),
    (28, 132),
    (155, 0),
    (12, 132),
    (31, 165),
    (20, 136),
    (27, 193),
    (142, 0),
    (96, 164),
    (18, 133),
    (145, 0),
    (23, 132),
    (13, 165),
    (13, 148),
    (23, 193),
    (19, 132),
    (27, 178),
    (83, 137),
    (146, 0),
    (145, 0),
    (18, 166),
    (96, 148),
    (13, 193),
    (159, 0),
    (96, 166),
    (20, 129),
    (20, 193),
    (27, 132),
    (9, 160),
    (96, 148),
    (13, 192),
    (159, 0),
    (96, 180),
    (142, 0),
    (31, 193),
    (155, 0),
    (7, 166),
    (224, 0),
    (20, 192),
    (27, 132),
    (28, 160),
    (17, 149),
    (19, 193),
    (96, 132),
    (76, 164),
    (208, 0),
    (80, 192),
    (78, 132),
    (96, 160),
    (27, 144),
    (24, 193),
    (140, 0),
    (96, 178),
    (17, 141),
    (12, 193),
    (224, 0),
    (14, 161),
    (17, 141),
    (151, 0),
    (14, 132),
    (16, 165),
    (96, 137),
    (13, 193),
    (155, 0),
    (20, 161),
    (29, 141),
    (23, 192),
    (24, 132),
    (27, 178),
    (10, 133),
    (96, 192),
    (140, 0),
    (14, 180),
    (17, 133),
    (16, 192),
    (144, 0),
    (11, 163),
    (13, 141),
    (96, 192),
    (17, 132),
    (12, 178),
    (96, 141),
    (28, 192),
    (27, 132),
    (27, 130),
    (18, 141),
    (96, 193),
    (31, 132),
    (96, 181),
    (13, 140),
    (23, 193),
    (224, 0),
    (27, 166),
    (142, 0),
    (27, 192),
    (24, 132),
    (12, 183),
    (96, 133),
    (84, 192),
    (14, 132),
    (27, 178),
    (10, 140),
    (155, 0),
    (9, 132),
    (17, 160),
    (56, 133),
    (96, 192),
    (82, 132),
    (13, 160),
    (27, 137),
    (20, 193),
    (139, 0),
    (28, 161),
    (145, 0),
    (19, 192),
    (118, 132),
    (115, 165),
    (20, 132),
    (145, 0),
    (14, 132),
    (12, 167),
    (146, 0),
    (17, 193),
    (29, 132),
    (96, 176),
    (28, 144),
    (27, 193),
    (140, 0),
    (31, 180),
    (148, 0),
    (27, 192),
    (14, 132),
    (83, 160),
    (18, 137),
    (17, 193),
    (23, 132),
    (13, 165),
    (13, 145),
    (151, 0),
    (147, 0),
    (27, 178),
    (96, 137),
    (19, 193),
    (159, 0),
    (14, 160),
    (25, 148),
    (17, 193),
    (142, 0),
    (16, 180),
    (27, 136),
    (14, 193),
    (224, 0),
    (17, 178),
    (12, 144),
    (224, 0),
    (28, 132),
    (27, 160),
    (13, 141),
    (11, 193),
    (96, 132),
    (27, 165),
    (30, 140),
    (224, 0),
    (146, 0),
    (31, 165),
    (29, 129),
    (96, 192),
    (140, 0),
    (31, 161),
    (24, 145),
    (140, 0),
    (96, 132),
    (27, 165),
    (29, 140),
    (31, 192),
    (154, 0),
    (14, 161),
    (27, 145),
    (140, 0),
    (18, 132),
    (23, 167),
    (96, 140),
    (21, 129),
    (14, 132),
    (17, 165),
    (9, 137),
    (12, 193),
    (155, 0),
    (18, 161),
    (96, 141),
    (27, 192),
    (148, 0),
    (29, 178),
    (23, 133),
    (24, 192),
    (155, 0),
    (10, 180),
    (96, 133),
    (28, 192),
    (14, 132),
    (31, 130),
    (28, 129),
    (18, 193),
    (31, 132),
    (12, 180),
    (13, 144),
    (96, 193),
    (31, 132),
    (96, 160),
    (13, 141),
    (27, 193),
    (18, 132),
    (23, 181),
    (26, 140),
    (27, 193),
    (156, 0),
    (96, 166),
    (79, 141),
    (211, 0),
    (76, 132),
    (77, 160),
    (75, 133),
    (206, 0),
    (182, 0),
    (96, 129),
    (59, 133),
    (191, 0),
    (173, 0),
];

#[test]
fn autel_ecc_spec_constructed_table_decrypts() {
    let plaintext: Vec<u8> = inner_plaintext(200);
    let encrypted: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, p): (usize, &u8)| {
            let (a, b): (u8, u8) = AUTEL_KEYS[i % 256];
            (p ^ b).wrapping_sub(a)
        })
        .collect();

    let mut image: Vec<u8> = Vec::new();
    image.extend_from_slice(b"ECC0101\x00");
    image.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    image.extend_from_slice(&0x20u32.to_le_bytes());
    image.extend_from_slice(&[0u8; 16]);
    image.extend_from_slice(&encrypted);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::AutelEcc));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::AutelEcc, &image).expect("autel decrypt");
    assert_eq!(out.members[0].data, plaintext);
    assert_eq!(out.inner_kind_hint.as_deref(), Some("squashfs"));
}

struct QnapCryptor {
    secret: Vec<i32>,
    n: usize,
    k: Vec<Vec<(u16, u16)>>,
    acc: usize,
    y: u16,
    z: u16,
}

impl QnapCryptor {
    fn new(secret: &[u8]) -> Self {
        let mut s: Vec<i32> = secret.iter().map(|b: &u8| i32::from(*b)).collect();
        let n: usize = secret.len() / 2;
        if n.is_multiple_of(2) {
            s.push(0);
        }
        let mut c: Self = Self {
            secret: s,
            n,
            k: Vec::new(),
            acc: 0,
            y: 0,
            z: 0,
        };
        c.k = (0..256).map(|a: i32| c.table_for_acc(a)).collect();
        c
    }
    const fn promote(c: i32) -> i32 {
        if c < 0x80 { c } else { c - 0x101 }
    }
    fn lcg(x: u16) -> u16 {
        (0x4e35u32.wrapping_mul(u32::from(x)).wrapping_add(1) & 0xffff) as u16
    }
    fn table_for_acc(&self, a: i32) -> Vec<(u16, u16)> {
        let ks: Vec<u16> = (0..self.n)
            .map(|i: usize| {
                let hi: i32 = Self::promote(self.secret[2 * i] ^ a) << 8;
                let lo: i32 = self.secret[2 * i + 1] ^ a;
                (hi + lo) as u16
            })
            .collect();
        let mut out: Vec<(u16, u16)> = Vec::with_capacity(self.n);
        let mut st: u16 = 0;
        for q in ks {
            let x: u16 = st ^ q;
            let y: u16 = Self::lcg(x);
            let z: u16 = (0x15au32.wrapping_mul(u32::from(x)) & 0xffff) as u16;
            out.push((z, y));
            st = y;
        }
        out
    }
    fn kdf(&mut self) -> u8 {
        let tt: Vec<(u16, u16)> = self.k[self.acc].clone();
        let mut res: u16 = 0;
        for (i, e) in tt.iter().enumerate() {
            let yy: u16 = self.y;
            self.y = e.1;
            let t2: u16 = e.1;
            self.z = (u32::from(self.y)
                .wrapping_add(u32::from(yy))
                .wrapping_add(0x4e35u32.wrapping_mul(u32::from(self.z).wrapping_add(i as u32)))
                & 0xffff) as u16;
            res = res ^ t2 ^ self.z;
        }
        ((res >> 8) ^ (res & 0xff)) as u8
    }
    fn encrypt_byte(&mut self, plaintext: u8) -> u8 {
        let k: u8 = self.kdf();
        let c: u8 = plaintext ^ k;
        self.acc ^= plaintext as usize;
        c
    }
}

#[test]
fn qnap_spec_constructed_pc1_decrypts() {
    let plaintext: Vec<u8> = inner_plaintext(96);
    let secret: &[u8] = b"QNAPNASVERSION4";

    let mut encryptor: QnapCryptor = QnapCryptor::new(secret);
    let ciphertext: Vec<u8> = plaintext
        .iter()
        .map(|p: &u8| encryptor.encrypt_byte(*p))
        .collect();

    let mut full: Vec<u8> = Vec::new();
    full.extend_from_slice(&ciphertext);
    full.extend_from_slice(b"TRAILER-BYTES");

    let mut footer: Vec<u8> = vec![0u8; 74];
    footer[0..6].copy_from_slice(b"icpnas");
    footer[6..10].copy_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    footer[26] = b'4';
    full.extend_from_slice(&footer);

    assert_eq!(detect_firmware(&full), Some(FirmwareKind::Qnap));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::Qnap, &full).expect("qnap decrypt");
    assert_eq!(
        &out.members[0].data[..plaintext.len()],
        plaintext.as_slice()
    );
    assert_eq!(out.inner_kind_hint.as_deref(), Some("squashfs"));
}

fn chk_checksum(data: &[u8]) -> u32 {
    let mut c0: u32 = 0;
    let mut c1: u32 = 0;
    for &b in data {
        c0 = c0.wrapping_add(u32::from(b));
        c1 = c1.wrapping_add(c0);
    }
    let b: u32 = (c0 & 65535).wrapping_add(c0 >> 16);
    let lo: u32 = (b & 255).wrapping_add(b >> 8) & 255;
    let b1: u32 = (c1 & 65535).wrapping_add(c1 >> 16);
    let hi: u32 = (b1 & 255).wrapping_add(b1 >> 8) & 255;
    (hi << 8) | lo
}

#[test]
fn netgear_chk_spec_constructed_carves_and_verifies_checksum() {
    let board_id: &[u8] = b"R7800";
    let header_len: usize = 40 + board_id.len();
    let kernel: Vec<u8> = inner_plaintext(64);
    let rootfs: &[u8] = b"rootfs-squashfs-bytes-here-padding-padding-padding";

    let mut image: Vec<u8> = vec![0u8; header_len];
    image[0..4].copy_from_slice(&[0x2a, 0x23, 0x24, 0x5e]);
    image[4..8].copy_from_slice(&(header_len as u32).to_be_bytes());
    image[24..28].copy_from_slice(&(kernel.len() as u32).to_be_bytes());
    image[28..32].copy_from_slice(&(rootfs.len() as u32).to_be_bytes());
    image[40..40 + board_id.len()].copy_from_slice(board_id);
    image.extend_from_slice(&kernel);
    image.extend_from_slice(rootfs);

    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&kernel);
    payload.extend_from_slice(rootfs);
    let checksum: u32 = chk_checksum(&payload);
    image[32..36].copy_from_slice(&checksum.to_be_bytes());

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::NetgearChk));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::NetgearChk, &image).expect("chk carve");
    let kern: &disrobe_binfmt::containers::firmware::FirmwareMember = out
        .members
        .iter()
        .find(|m| m.name == "kernel.bin")
        .expect("kernel member");
    assert_eq!(kern.data, kernel);
    assert_eq!(kern.crc_ok, Some(true));
    let root: &disrobe_binfmt::containers::firmware::FirmwareMember = out
        .members
        .iter()
        .find(|m| m.name == "rootfs.bin")
        .expect("rootfs member");
    assert_eq!(root.data, rootfs);
}

#[test]
fn netgear_trx_v1_spec_constructed_carves_partitions_and_verifies_crc() {
    let header_len: usize = 28;
    let part0: Vec<u8> = inner_plaintext(48);
    let part1: &[u8] = b"rootfs-region-trx-v1-payload-bytes";

    let off0: u32 = header_len as u32;
    let off1: u32 = off0 + part0.len() as u32;
    let total: u32 = off1 + part1.len() as u32;

    let mut image: Vec<u8> = vec![0u8; header_len];
    image[0..4].copy_from_slice(b"HDR0");
    image[4..8].copy_from_slice(&total.to_le_bytes());
    image[14..16].copy_from_slice(&1u16.to_le_bytes());
    image[16..20].copy_from_slice(&off0.to_le_bytes());
    image[20..24].copy_from_slice(&off1.to_le_bytes());
    image.extend_from_slice(&part0);
    image.extend_from_slice(part1);

    let crc: u32 = !crc32fast::hash(&image[12..total as usize]);
    image[8..12].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::NetgearTrxV1));
    assert_eq!(
        detect_container(&image),
        Some(ContainerKind::FwNetgearTrxV1)
    );
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::NetgearTrxV1, &image).expect("trx carve");
    assert_eq!(out.members[0].data, part0);
    assert_eq!(out.members[0].crc_ok, Some(true));
    assert_eq!(out.members[1].data, part1);
}

#[test]
fn xiaomi_hdr1_spec_constructed_carves_blob_and_verifies_crc() {
    let header_len: usize = 0x30;
    let blob_payload: Vec<u8> = inner_plaintext(64);
    let blob_name: &[u8] = b"rootfs0";

    let blob_offset: u32 = header_len as u32;
    let mut image: Vec<u8> = vec![0u8; header_len];
    image[0..4].copy_from_slice(b"HDR1");
    image[0x10..0x14].copy_from_slice(&blob_offset.to_le_bytes());

    let mut blob_header: Vec<u8> = vec![0u8; 48];
    blob_header[0..4].copy_from_slice(&0x0000_babeu32.to_le_bytes());
    blob_header[8..12].copy_from_slice(&(blob_payload.len() as u32).to_le_bytes());
    blob_header[16..16 + blob_name.len()].copy_from_slice(blob_name);
    image.extend_from_slice(&blob_header);
    image.extend_from_slice(&blob_payload);

    let signature_offset: u32 = image.len() as u32;
    image[4..8].copy_from_slice(&signature_offset.to_le_bytes());
    image.extend_from_slice(&[0u8; 272]);

    let crc_end: usize = signature_offset as usize + 272;
    let crc: u32 = !crc32fast::hash(&image[12..crc_end]);
    image[8..12].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::XiaomiHdr1));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::XiaomiHdr1, &image).expect("hdr1 carve");
    assert_eq!(out.members[0].name, "rootfs0");
    assert_eq!(out.members[0].data, blob_payload);
    assert_eq!(out.members[0].crc_ok, Some(true));
}

#[test]
fn tesla_sbfh_spec_constructed_carves_mrvl_segments_with_crc() {
    let header_size: u32 = 0x120;
    let seg0: Vec<u8> = inner_plaintext(48);
    let seg1: &[u8] = b"second-mrvl-segment-arm-v7-code-bytes";

    let sbfh_len: usize = 0x120;
    let mrvl_len: usize = 0x14;
    let seg_hdr_len: usize = 0x14;
    let mut image: Vec<u8> = vec![0u8; sbfh_len];
    image[0..4].copy_from_slice(b"SBFH");
    image[4..8].copy_from_slice(&header_size.to_le_bytes());

    let mut mrvl: Vec<u8> = vec![0u8; mrvl_len];
    mrvl[0..4].copy_from_slice(b"MRVL");
    mrvl[4..8].copy_from_slice(&0x2e9c_f17bu32.to_le_bytes());
    mrvl[12..16].copy_from_slice(&2u32.to_le_bytes());
    image.extend_from_slice(&mrvl);

    let seg0_offset: u32 = (image.len() + seg_hdr_len * 2 - header_size as usize) as u32;
    let seg1_offset: u32 = seg0_offset + seg0.len() as u32;

    let mut e0: Vec<u8> = vec![0u8; seg_hdr_len];
    e0[0..4].copy_from_slice(&2u32.to_le_bytes());
    e0[4..8].copy_from_slice(&seg0_offset.to_le_bytes());
    e0[8..12].copy_from_slice(&(seg0.len() as u32).to_le_bytes());
    e0[12..16].copy_from_slice(&0x1000_0000u32.to_le_bytes());
    e0[16..20].copy_from_slice(&crc32fast::hash(&seg0).to_le_bytes());
    image.extend_from_slice(&e0);

    let mut e1: Vec<u8> = vec![0u8; seg_hdr_len];
    e1[0..4].copy_from_slice(&2u32.to_le_bytes());
    e1[4..8].copy_from_slice(&seg1_offset.to_le_bytes());
    e1[8..12].copy_from_slice(&(seg1.len() as u32).to_le_bytes());
    e1[12..16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    e1[16..20].copy_from_slice(&crc32fast::hash(seg1).to_le_bytes());
    image.extend_from_slice(&e1);

    assert_eq!(image.len(), header_size as usize + seg0_offset as usize);
    image.extend_from_slice(&seg0);
    image.extend_from_slice(seg1);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::TeslaSbfh));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::TeslaSbfh, &image).expect("sbfh carve");
    assert_eq!(out.members.len(), 2);
    assert_eq!(out.members[0].data, seg0);
    assert_eq!(out.members[0].crc_ok, Some(true));
    assert_eq!(out.members[1].data, seg1);
    assert_eq!(out.members[1].crc_ok, Some(true));
}

#[test]
fn hp_bdl_spec_constructed_carves_toc_members() {
    let toc_offset: u32 = 0x600;
    let member0: Vec<u8> = inner_plaintext(64);
    let member1: &[u8] = b"second ipkg member bytes here";

    let mut image: Vec<u8> = vec![0u8; toc_offset as usize];
    image[0..8].copy_from_slice(&[0x69, 0x62, 0x64, 0x6c, 0x01, 0x00, 0x01, 0x00]);
    image[8..12].copy_from_slice(&toc_offset.to_le_bytes());
    image[16..20].copy_from_slice(&2u32.to_le_bytes());

    let data_start: u64 = toc_offset as u64 + 2 * 16;
    let off0: u64 = data_start;
    let off1: u64 = off0 + member0.len() as u64;
    image.extend_from_slice(&off0.to_le_bytes());
    image.extend_from_slice(&(member0.len() as u64).to_le_bytes());
    image.extend_from_slice(&off1.to_le_bytes());
    image.extend_from_slice(&(member1.len() as u64).to_le_bytes());
    image.extend_from_slice(&member0);
    image.extend_from_slice(member1);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::HpBdl));
    let out: FirmwareExtraction = extract_firmware(FirmwareKind::HpBdl, &image).expect("bdl carve");
    assert_eq!(out.members[0].data, member0);
    assert_eq!(out.members[1].data, member1);
}

#[test]
fn hp_ipkg_spec_constructed_carves_named_members_with_crc() {
    let toc_offset: u32 = 0x500;
    let payload: Vec<u8> = inner_plaintext(80);
    let name: &[u8] = b"kernel.img";

    let mut image: Vec<u8> = vec![0u8; toc_offset as usize];
    image[0..8].copy_from_slice(&[0x69, 0x70, 0x6b, 0x67, 0x01, 0x00, 0x03, 0x00]);
    image[8..12].copy_from_slice(&toc_offset.to_le_bytes());
    image[16..20].copy_from_slice(&1u32.to_le_bytes());

    let data_start: u64 = toc_offset as u64 + 276;
    let mut entry: Vec<u8> = vec![0u8; 276];
    entry[..name.len()].copy_from_slice(name);
    entry[256..264].copy_from_slice(&data_start.to_le_bytes());
    entry[264..272].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    entry[272..276].copy_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    image.extend_from_slice(&entry);
    image.extend_from_slice(&payload);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::HpIpkg));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::HpIpkg, &image).expect("ipkg carve");
    assert_eq!(out.members[0].name, "kernel.img");
    assert_eq!(out.members[0].data, payload);
    assert_eq!(out.members[0].crc_ok, Some(true));
}

#[test]
fn moxa_frm_spec_constructed_carves_sections() {
    let header_len: usize = 0x60;
    let fw: Vec<u8> = inner_plaintext(48);
    let fs: &[u8] = b"webserver-filesystem-section-bytes-padding";

    let table_len: usize = 2 * 16;
    let mut image: Vec<u8> = vec![0u8; header_len];
    image[0..4].copy_from_slice(b"*FRM");
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[12..14].copy_from_slice(&(header_len as u16).to_le_bytes());
    image[14..16].copy_from_slice(&2u16.to_le_bytes());

    let fw_offset: u32 = (header_len + table_len) as u32;
    let fs_offset: u32 = fw_offset + fw.len() as u32;
    let total: u32 = fs_offset + fs.len() as u32;
    image[8..12].copy_from_slice(&total.to_le_bytes());

    let mut s0: Vec<u8> = vec![0u8; 16];
    s0[0..4].copy_from_slice(&1u32.to_le_bytes());
    s0[4..8].copy_from_slice(&fw_offset.to_le_bytes());
    s0[8..12].copy_from_slice(&(fw.len() as u32).to_le_bytes());
    image.extend_from_slice(&s0);

    let mut s1: Vec<u8> = vec![0u8; 16];
    s1[0..4].copy_from_slice(&2u32.to_le_bytes());
    s1[4..8].copy_from_slice(&fs_offset.to_le_bytes());
    s1[8..12].copy_from_slice(&(fs.len() as u32).to_le_bytes());
    image.extend_from_slice(&s1);

    image.extend_from_slice(&fw);
    image.extend_from_slice(fs);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::MoxaFrm));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::MoxaFrm, &image).expect("frm carve");
    assert_eq!(out.members[0].data, fw);
    assert_eq!(out.members[1].data, fs);
}

#[test]
fn instar_bneg_spec_constructed_carves_two_partitions() {
    let part1: Vec<u8> = inner_plaintext(48);
    let part2: &[u8] = b"second-partition-bytes-instar-bneg";

    let mut image: Vec<u8> = vec![0u8; 20];
    image[0..4].copy_from_slice(b"BNEG");
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[8..12].copy_from_slice(&1u32.to_le_bytes());
    image[12..16].copy_from_slice(&(part1.len() as u32).to_le_bytes());
    image[16..20].copy_from_slice(&(part2.len() as u32).to_le_bytes());
    image.extend_from_slice(&part1);
    image.extend_from_slice(part2);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::InstarBneg));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::InstarBneg, &image).expect("bneg carve");
    assert_eq!(out.members[0].data, part1);
    assert_eq!(out.members[1].data, part2);
}

#[test]
fn instar_hd_spec_constructed_rewrites_zip_signatures() {
    let mut zip: Vec<u8> = Vec::new();
    zip.extend_from_slice(b"PK\x03\x04");
    zip.extend_from_slice(b"payload-1");
    zip.extend_from_slice(b"PK\x01\x02");
    zip.extend_from_slice(b"central-dir");
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&[0u8; 18]);

    let mut instar: Vec<u8> = zip.clone();
    instar[3] = 0x07;
    let cd: usize = 4 + 9;
    instar[cd + 3] = 0x08;
    let eocd: usize = cd + 4 + 11;
    instar[eocd + 3] = 0x09;

    assert_eq!(detect_firmware(&instar), Some(FirmwareKind::InstarHd));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::InstarHd, &instar).expect("instar hd");
    assert_eq!(out.members[0].data, zip);
    assert_eq!(out.inner_kind_hint.as_deref(), Some("zip"));
}

#[test]
fn dlink_deafbead_spec_constructed_decompresses_files() {
    use std::io::Write as _;
    let inner: &[u8] = b"hello deafbead inner file contents";
    let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(inner).unwrap();
    let gz: Vec<u8> = encoder.finish().unwrap();

    let name: &[u8] = b"etc/config";
    let mut image: Vec<u8> = Vec::new();
    image.extend_from_slice(&[0xde, 0xaf, 0xbe, 0xad]);
    image.push(0x87);
    image.extend_from_slice(&(name.len() as u16).to_le_bytes());
    image.extend_from_slice(name);
    image.extend_from_slice(&(gz.len() as u32).to_le_bytes());
    image.extend_from_slice(&gz);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::DlinkDeafbead));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::DlinkDeafbead, &image).expect("deafbead carve");
    assert_eq!(out.members[0].data, inner);
}

#[test]
fn dlink_fpkg_spec_constructed_carves_named_entries() {
    let first_entry_offset: u32 = 0x20;
    let payload: Vec<u8> = inner_plaintext(48);
    let name: &[u8] = b"rootfs";

    let mut image: Vec<u8> = vec![0u8; first_entry_offset as usize];
    image[0..4].copy_from_slice(b"FPKG");
    image[4..8].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    image[8..12].copy_from_slice(&first_entry_offset.to_be_bytes());

    let header_len: u32 = 0x1c;
    image.extend_from_slice(&header_len.to_be_bytes());
    image.extend_from_slice(&0x0100u16.to_be_bytes());
    image.extend_from_slice(&0u16.to_be_bytes());
    image.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    let mut name_field: Vec<u8> = vec![0u8; 16];
    name_field[..name.len()].copy_from_slice(name);
    image.extend_from_slice(&name_field);
    image.extend_from_slice(&payload);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::DlinkFpkg));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::DlinkFpkg, &image).expect("fpkg carve");
    assert_eq!(out.members[0].name, "rootfs");
    assert_eq!(out.members[0].data, payload);
}

#[test]
fn airoha_lzma_aes_is_carve_only_with_documented_physical_reason() {
    let prelude: usize = 256;
    let blob: &[u8] = b"AES-encrypted-airoha-section-bytes-not-decryptable";
    let firmware_offset: u32 = (prelude + 16) as u32;

    let mut image: Vec<u8> = vec![0u8; firmware_offset as usize];
    for b in image.iter_mut().skip(32).take(224) {
        *b = 0xff;
    }
    image[prelude..prelude + 4].copy_from_slice(&[0x11, 0x00, 0x0a, 0x00]);
    image[prelude + 4] = 2;
    image[prelude + 5] = 0;
    image[prelude + 6..prelude + 10].copy_from_slice(&firmware_offset.to_le_bytes());
    image[prelude + 10..prelude + 14].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    image.extend_from_slice(blob);

    assert_eq!(detect_firmware(&image), Some(FirmwareKind::Airoha));
    let out: FirmwareExtraction =
        extract_firmware(FirmwareKind::Airoha, &image).expect("airoha carve");
    assert_eq!(out.members[0].data, blob);
    assert!(
        out.notes
            .iter()
            .any(|n: &String| n.contains("information-theoretic")),
        "airoha LZMA_AES must document the physical key-absence reason: {:?}",
        out.notes
    );
}

#[test]
fn firmware_extract_to_writes_members_to_disk() {
    let plaintext: Vec<u8> = inner_plaintext(96);
    let ciphertext: Vec<u8> = aes128_cbc_encrypt(&SHRS_KEY, &SHRS_IV, &plaintext);
    let mut image: Vec<u8> = vec![0u8; 1756];
    image[0..4].copy_from_slice(b"SHRS");
    image[4..8].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    image[8..12].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    image[0x0c..0x0c + 16].copy_from_slice(&SHRS_IV);
    image.extend_from_slice(&ciphertext);

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("shrs-e2e");

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::FwDlinkShrs, &image, &out).expect("extract shrs");
    assert_eq!(result.kind, ContainerKind::FwDlinkShrs);
    let written: Vec<u8> = std::fs::read(out.join("shrs-decrypted.bin")).expect("decrypted file");
    assert_eq!(written, plaintext);
    assert!(out.join(".disrobe-firmware.json").is_file());
}
