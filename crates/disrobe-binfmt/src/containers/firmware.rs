use disrobe_core::codec::{CbcPadding, aes_cbc_decrypt, crc32_ieee};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirmwareKind {
    DlinkShrs,
    DlinkEncrptedImg,
    DlinkAlphaV1,
    DlinkAlphaV2,
    DlinkDeafbead,
    DlinkFpkg,
    EnGenius,
    AutelEcc,
    Qnap,
    NetgearChk,
    NetgearTrxV1,
    NetgearTrxV2,
    XiaomiHdr1,
    XiaomiHdr2,
    TeslaSbfh,
    HpBdl,
    HpIpkg,
    MoxaFrm,
    InstarBneg,
    InstarHd,
    Airoha,
}

impl FirmwareKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DlinkShrs => "dlink-shrs",
            Self::DlinkEncrptedImg => "dlink-encrpted-img",
            Self::DlinkAlphaV1 => "dlink-alpha-v1",
            Self::DlinkAlphaV2 => "dlink-alpha-v2",
            Self::DlinkDeafbead => "dlink-deafbead",
            Self::DlinkFpkg => "dlink-fpkg",
            Self::EnGenius => "engenius",
            Self::AutelEcc => "autel-ecc",
            Self::Qnap => "qnap",
            Self::NetgearChk => "netgear-chk",
            Self::NetgearTrxV1 => "netgear-trx-v1",
            Self::NetgearTrxV2 => "netgear-trx-v2",
            Self::XiaomiHdr1 => "xiaomi-hdr1",
            Self::XiaomiHdr2 => "xiaomi-hdr2",
            Self::TeslaSbfh => "tesla-sbfh",
            Self::HpBdl => "hp-bdl",
            Self::HpIpkg => "hp-ipkg",
            Self::MoxaFrm => "moxa-frm",
            Self::InstarBneg => "instar-bneg",
            Self::InstarHd => "instar-hd",
            Self::Airoha => "airoha",
        }
    }

    #[must_use]
    pub const fn is_decryptor(self) -> bool {
        matches!(
            self,
            Self::DlinkShrs
                | Self::DlinkEncrptedImg
                | Self::DlinkAlphaV1
                | Self::DlinkAlphaV2
                | Self::EnGenius
                | Self::AutelEcc
                | Self::Qnap
        )
    }

    pub const ALL: [Self; 21] = [
        Self::DlinkShrs,
        Self::DlinkEncrptedImg,
        Self::DlinkAlphaV1,
        Self::DlinkAlphaV2,
        Self::DlinkDeafbead,
        Self::DlinkFpkg,
        Self::EnGenius,
        Self::AutelEcc,
        Self::Qnap,
        Self::NetgearChk,
        Self::NetgearTrxV1,
        Self::NetgearTrxV2,
        Self::XiaomiHdr1,
        Self::XiaomiHdr2,
        Self::TeslaSbfh,
        Self::HpBdl,
        Self::HpIpkg,
        Self::MoxaFrm,
        Self::InstarBneg,
        Self::InstarHd,
        Self::Airoha,
    ];
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareMember {
    pub name: String,
    pub offset: u64,
    pub length: u64,
    pub data: Vec<u8>,
    pub crc_expected: Option<u32>,
    pub crc_actual: Option<u32>,
    pub crc_ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareExtraction {
    pub kind: FirmwareKind,
    pub members: Vec<FirmwareMember>,
    pub notes: Vec<String>,
    pub inner_kind_hint: Option<String>,
}

const SHRS_MAGIC: &[u8; 4] = b"SHRS";
const ENCRPTED_MAGIC: &[u8; 12] = b"encrpted_img";
const ENGENIUS_MAGIC_FULL: &[u8; 7] = &[0x12, 0x34, 0x56, 0x78, 0x61, 0x6c, 0x6c];
const AUTEL_ECC_MAGIC: &[u8; 8] = b"ECC0101\x00";
const NETGEAR_CHK_MAGIC: &[u8; 4] = &[0x2a, 0x23, 0x24, 0x5e];
const TRX_MAGIC: &[u8; 4] = b"HDR0";
const XIAOMI_HDR1_MAGIC: &[u8; 4] = b"HDR1";
const XIAOMI_HDR2_MAGIC: &[u8; 4] = b"HDR2";
const TESLA_SBFH_MAGIC: &[u8; 4] = b"SBFH";
const HP_BDL_MAGIC: &[u8; 8] = &[0x69, 0x62, 0x64, 0x6c, 0x01, 0x00, 0x01, 0x00];
const HP_IPKG_MAGIC: &[u8; 8] = &[0x69, 0x70, 0x6b, 0x67, 0x01, 0x00, 0x03, 0x00];
const MOXA_FRM_MAGIC: &[u8; 4] = b"*FRM";
const INSTAR_BNEG_MAGIC: &[u8; 4] = b"BNEG";
const INSTAR_HD_MAGIC: &[u8; 4] = &[0x50, 0x4b, 0x03, 0x07];
const DLINK_DEAFBEAD_MAGIC: &[u8; 4] = &[0xde, 0xaf, 0xbe, 0xad];
const FPKG_MAGIC: &[u8; 4] = b"FPKG";
const CPKG_MAGIC: &[u8; 4] = b"CPKG";
const QNAP_FOOTER_MAGIC: &[u8; 6] = b"icpnas";
const AIROHA_BASIC_INFO_TLV: &[u8; 4] = &[0x11, 0x00, 0x0a, 0x00];

#[must_use]
pub fn detect_firmware(bytes: &[u8]) -> Option<FirmwareKind> {
    if bytes.starts_with(SHRS_MAGIC) {
        return Some(FirmwareKind::DlinkShrs);
    }
    if bytes.starts_with(ENCRPTED_MAGIC) && encrpted_img_header_valid(bytes) {
        return Some(FirmwareKind::DlinkEncrptedImg);
    }
    if bytes.starts_with(DLINK_DEAFBEAD_MAGIC) && matches!(bytes.get(4), Some(0x86 | 0x87)) {
        return Some(FirmwareKind::DlinkDeafbead);
    }
    if (bytes.starts_with(FPKG_MAGIC) || bytes.starts_with(CPKG_MAGIC))
        && u32_le(bytes, 4) == Some(0x0000_0001)
    {
        return Some(FirmwareKind::DlinkFpkg);
    }
    if alpha_v1_detect(bytes) {
        return Some(FirmwareKind::DlinkAlphaV1);
    }
    if bytes.len() >= DLINK_ALPHA_V2_HEADER_LEN
        && bytes.starts_with(b"wap")
        && alpha_v2_header_shape(bytes)
    {
        return Some(FirmwareKind::DlinkAlphaV2);
    }
    if engenius_header_offset(bytes).is_some() && find_subslice(bytes, &ENGENIUS_XOR_KEY).is_some()
    {
        return Some(FirmwareKind::EnGenius);
    }
    if bytes.starts_with(AUTEL_ECC_MAGIC) {
        return Some(FirmwareKind::AutelEcc);
    }
    if bytes.starts_with(NETGEAR_CHK_MAGIC) {
        return Some(FirmwareKind::NetgearChk);
    }
    if bytes.starts_with(TRX_MAGIC) {
        return Some(trx_version(bytes));
    }
    if bytes.starts_with(XIAOMI_HDR1_MAGIC) {
        return Some(FirmwareKind::XiaomiHdr1);
    }
    if bytes.starts_with(XIAOMI_HDR2_MAGIC) {
        return Some(FirmwareKind::XiaomiHdr2);
    }
    if bytes.starts_with(TESLA_SBFH_MAGIC) {
        return Some(FirmwareKind::TeslaSbfh);
    }
    if bytes.starts_with(HP_BDL_MAGIC) {
        return Some(FirmwareKind::HpBdl);
    }
    if bytes.starts_with(HP_IPKG_MAGIC) {
        return Some(FirmwareKind::HpIpkg);
    }
    if bytes.starts_with(MOXA_FRM_MAGIC) {
        return Some(FirmwareKind::MoxaFrm);
    }
    if bytes.starts_with(INSTAR_BNEG_MAGIC) {
        return Some(FirmwareKind::InstarBneg);
    }
    if bytes.starts_with(INSTAR_HD_MAGIC) {
        return Some(FirmwareKind::InstarHd);
    }
    if detect_airoha(bytes) {
        return Some(FirmwareKind::Airoha);
    }
    if detect_qnap(bytes) {
        return Some(FirmwareKind::Qnap);
    }
    None
}

fn u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    disrobe_bytes::read_u16_le_at(bytes, off).ok()
}

fn u32_be(bytes: &[u8], off: usize) -> Option<u32> {
    disrobe_bytes::read_u32_be_at(bytes, off).ok()
}

fn u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(bytes, off).ok()
}

fn u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    disrobe_bytes::read_u64_le_at(bytes, off).ok()
}

fn crc32(data: &[u8]) -> u32 {
    crc32_ieee(data)
}

fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(Error::Firmware(format!(
            "aes-128-cbc: ciphertext length {} is not a positive multiple of the 16-byte block size",
            ciphertext.len()
        )));
    }
    aes_cbc_decrypt(key, iv, ciphertext, CbcPadding::NoPadding)
        .map_err(|e| Error::Firmware(format!("aes-128-cbc decrypt failed: {e}")))
}

fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(Error::Firmware(format!(
            "aes-256-cbc: ciphertext length {} is not a positive multiple of the 16-byte block size",
            ciphertext.len()
        )));
    }
    aes_cbc_decrypt(key, iv, ciphertext, CbcPadding::NoPadding)
        .map_err(|e| Error::Firmware(format!("aes-256-cbc decrypt failed: {e}")))
}

const DLINK_SHRS_KEY: [u8; 16] = [
    0xc0, 0x5f, 0xbf, 0x19, 0x36, 0xc9, 0x94, 0x29, 0xce, 0x2a, 0x07, 0x81, 0xf0, 0x8d, 0x6a, 0xd8,
];
const SHRS_HEADER_LEN: usize = 1756;
const SHRS_FILE_SIZE_OFFSET: usize = 4;
const SHRS_IV_OFFSET: usize = 0x0c;

fn decrypt_dlink_shrs(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < SHRS_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "dlink-shrs: input {} bytes is shorter than the {SHRS_HEADER_LEN}-byte SHRS header",
            bytes.len()
        )));
    }
    let file_size: u32 = u32_be(bytes, SHRS_FILE_SIZE_OFFSET)
        .ok_or_else(|| Error::Firmware("dlink-shrs: truncated file-size field".to_owned()))?;
    let mut iv: [u8; 16] = [0u8; 16];
    iv.copy_from_slice(&bytes[SHRS_IV_OFFSET..SHRS_IV_OFFSET + 16]);
    let ciphertext: &[u8] = &bytes[SHRS_HEADER_LEN..];
    let aligned_len: usize = ciphertext.len() - (ciphertext.len() % 16);
    if aligned_len == 0 {
        return Err(Error::Firmware(
            "dlink-shrs: no full cipher block follows the header".to_owned(),
        ));
    }
    let mut plaintext: Vec<u8> =
        aes128_cbc_decrypt(&DLINK_SHRS_KEY, &iv, &ciphertext[..aligned_len])?;
    let mut notes: Vec<String> = Vec::new();
    if (file_size as usize) <= plaintext.len() {
        plaintext.truncate(file_size as usize);
    } else {
        notes.push(format!(
            "dlink-shrs: header file-size {file_size} exceeds the {} recovered bytes; keeping the full block",
            plaintext.len()
        ));
    }
    Ok(decrypt_result(
        FirmwareKind::DlinkShrs,
        "shrs-decrypted.bin",
        plaintext,
        notes,
    ))
}

const DLINK_ENCRPTED_KEY: [u8; 32] = *b"he9-4+M!)d6=m~we1,q2a3d1n&2*Z^%8";
const DLINK_ENCRPTED_IV: [u8; 16] = *b"J%1iQl8$=lm-;8AE";
const ENCRPTED_HEADER_LEN: usize = 16;
const ENCRPTED_PEB_SIZE: usize = 0x20000;
const UBI_HEAD: [u8; 16] = [
    0x55, 0x42, 0x49, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn encrpted_img_header_valid(bytes: &[u8]) -> bool {
    let Some(file_size): Option<u32> = u32_be(bytes, ENCRPTED_MAGIC.len()) else {
        return false;
    };
    file_size as usize >= ENCRPTED_HEADER_LEN && bytes.len() > ENCRPTED_HEADER_LEN
}

fn decrypt_dlink_encrpted_img(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let body: &[u8] = bytes.get(ENCRPTED_HEADER_LEN..).ok_or_else(|| {
        Error::Firmware("dlink-encrpted-img: input shorter than the 16-byte header".to_owned())
    })?;
    let mut plaintext: Vec<u8> = Vec::with_capacity(body.len());
    let mut peb_index: usize = 0;
    for chunk in body.chunks(ENCRPTED_PEB_SIZE) {
        let aligned: usize = chunk.len() - (chunk.len() % 16);
        if aligned == 0 {
            break;
        }
        let decoded: Vec<u8> =
            aes256_cbc_decrypt(&DLINK_ENCRPTED_KEY, &DLINK_ENCRPTED_IV, &chunk[..aligned])?;
        let mut block: Vec<u8> = decoded;
        if block.len() >= UBI_HEAD.len() {
            block[..UBI_HEAD.len()].copy_from_slice(&UBI_HEAD);
        }
        plaintext.extend_from_slice(&block);
        peb_index += 1;
    }
    let mut notes: Vec<String> = Vec::new();
    if peb_index == 0 {
        return Err(Error::Firmware(
            "dlink-encrpted-img: no full cipher block follows the header".to_owned(),
        ));
    }
    notes.push(format!(
        "dlink-encrpted-img: decrypted {peb_index} PEB block(s); the first 16 bytes of each 0x20000 block are restored to the UBI superblock magic per the format"
    ));
    Ok(decrypt_result(
        FirmwareKind::DlinkEncrptedImg,
        "encrpted_img-decrypted.bin",
        plaintext,
        notes,
    ))
}

const DLINK_ALPHA_XOR_RANGE: usize = 0xfc;
const DLINK_ALPHA_V2_HEADER_LEN: usize = 0xa0;
const DLINK_ALPHA_V2_KEY: [u8; 32] = *b"oVhq0hvXHdfaGFLdubM4/QvuVHdKee7v";
const DLINK_ALPHA_V2_IV: [u8; 16] = *b"0BO5nlYankuVBe4s";

struct AlphaDevice {
    enc_start: [u8; 4],
    signature: &'static [u8],
    key: [u8; 32],
    iv: [u8; 16],
}

const ALPHA_V1_DEVICES: &[AlphaDevice] = &[
    AlphaDevice {
        enc_start: [0x35, 0x66, 0x6f, 0x68],
        signature: b"wapac25_dlink.2015_dap1665",
        key: *b"EfCHXytwsC6F0zsedwZc+9vDbCjE3ge4",
        iv: *b"ggPy917jwESpnfXm",
    },
    AlphaDevice {
        enc_start: [0x68, 0x01, 0xcc, 0xfb],
        signature: b"wapac28_dlink.2015_dap1720",
        key: *b"qBiz6o/1RVQTtJBd3FS7FDbqogE8yoBm",
        iv: *b"EfDMqWWxHCOhEqgY",
    },
    AlphaDevice {
        enc_start: [0xdf, 0x8c, 0x39, 0x0d],
        signature: b"wrgac43s_dlink.2015_dir822c1",
        key: *b"KNpsEntCcsep1jdFIs3wnXySKRGNCGmf",
        iv: *b"uph587JdKHrtAUlr",
    },
    AlphaDevice {
        enc_start: [0xf5, 0x2a, 0xa0, 0xb4],
        signature: b"wrgac65_dlink.2015_dir842",
        key: *b"xQYoRZeD726UAbRb846kO7TeNw8eZa6u",
        iv: *b"zufEbNF3kUafxFiE",
    },
    AlphaDevice {
        enc_start: [0x21, 0xdd, 0xda, 0x00],
        signature: b"wrgac65_dlink.2015_dir842EU",
        key: *b"xQYoRZeD726UAbRb846kO7TeNw8eZa6u",
        iv: *b"zufEbNF3kUafxFiE",
    },
    AlphaDevice {
        enc_start: [0xe3, 0x13, 0x00, 0x5b],
        signature: b"wrgac05_dlob.hans_dir850l",
        key: *b"BIuS1CVMEQG+0pUeE99jnR+vLlLd9unr",
        iv: *b"f3+odwHhmJL1ceW1",
    },
    AlphaDevice {
        enc_start: [0x0a, 0x14, 0xe4, 0x24],
        signature: b"wrgac25_dlink.2013gui_dir850l",
        key: *b"qQehHMEmEPQ5izL+cabn8bNHZXHjkp6W",
        iv: *b"Mmb+IKQgnO8OuF4b",
    },
    AlphaDevice {
        enc_start: [0x4c, 0x1b, 0x95, 0xaf],
        signature: b"wrgac37_dlink.2013gui_dir859",
        key: *b"KY0H9R2PDL3eu1J4uCVd1CK7BJ7vF1kc",
        iv: *b"qbStAzIRvWeQHz5U",
    },
];

fn alpha_v1_device_for(enc_start: &[u8]) -> Option<&'static AlphaDevice> {
    ALPHA_V1_DEVICES
        .iter()
        .find(|d: &&AlphaDevice| enc_start.len() >= 4 && enc_start[..4] == d.enc_start)
}

fn alpha_v1_detect(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    ALPHA_V1_DEVICES
        .iter()
        .any(|d: &AlphaDevice| alpha_v1_first_block_matches(d, bytes))
}

fn alpha_mangle(signature: &[u8], data: &[u8]) -> Vec<u8> {
    let sign_len: usize = signature.len();
    data.iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| {
            b ^ (((i + 1) % DLINK_ALPHA_XOR_RANGE) as u8) ^ signature[i % sign_len]
        })
        .collect()
}

fn alpha_mangled_key32(signature: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mangled: Vec<u8> = alpha_mangle(signature, key);
    let mut out: [u8; 32] = [0u8; 32];
    out.copy_from_slice(&mangled);
    out
}

fn alpha_mangled_iv(signature: &[u8], iv: &[u8; 16]) -> [u8; 16] {
    let mangled: Vec<u8> = alpha_mangle(signature, iv);
    let mut out: [u8; 16] = [0u8; 16];
    out.copy_from_slice(&mangled);
    out
}

fn alpha_v2_header_shape(bytes: &[u8]) -> bool {
    let signature: &[u8] = signature_from_wrgg(bytes);
    let key: [u8; 32] = alpha_mangled_key32(signature, &DLINK_ALPHA_V2_KEY);
    let iv: [u8; 16] = alpha_mangled_iv(signature, &DLINK_ALPHA_V2_IV);
    let body: &[u8] = match bytes.get(DLINK_ALPHA_V2_HEADER_LEN..) {
        Some(b) if !b.is_empty() && b.len().is_multiple_of(16) => b,
        _ => return false,
    };
    let probe_len: usize = body.len().min(16);
    aes256_cbc_decrypt(&key, &iv, &body[..probe_len])
        .ok()
        .is_some_and(|p: Vec<u8>| inner_magic_present(&p))
}

fn signature_from_wrgg(bytes: &[u8]) -> &[u8] {
    let raw: &[u8] = bytes.get(0..32).map_or(bytes, |value: &[u8]| value);
    let end: usize = raw
        .iter()
        .position(|b: &u8| *b == 0)
        .map_or(raw.len(), |value: usize| value);
    &raw[..end]
}

fn alpha_v1_first_block_matches(device: &AlphaDevice, bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    let key: [u8; 32] = alpha_mangled_key32(device.signature, &device.key);
    let iv: [u8; 16] = alpha_mangled_iv(device.signature, &device.iv);
    aes256_cbc_decrypt(&key, &iv, &bytes[..16])
        .ok()
        .is_some_and(|p: Vec<u8>| inner_magic_present(&p))
}

fn select_alpha_v1_device(bytes: &[u8]) -> Option<&'static AlphaDevice> {
    if let Some(device) = alpha_v1_device_for(bytes) {
        return Some(device);
    }
    ALPHA_V1_DEVICES
        .iter()
        .find(|d: &&AlphaDevice| alpha_v1_first_block_matches(d, bytes))
}

fn decrypt_dlink_alpha_v1(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let device: &AlphaDevice = select_alpha_v1_device(bytes).ok_or_else(|| {
        Error::Firmware(
            "dlink-alpha-v1: leading ciphertext matches no known Alpha device key-table entry and no device key recovers a known inner-format magic".to_owned(),
        )
    })?;
    let key: [u8; 32] = alpha_mangled_key32(device.signature, &device.key);
    let iv: [u8; 16] = alpha_mangled_iv(device.signature, &device.iv);
    let aligned: usize = bytes.len() - (bytes.len() % 16);
    if aligned == 0 {
        return Err(Error::Firmware(
            "dlink-alpha-v1: input is shorter than one cipher block".to_owned(),
        ));
    }
    let plaintext: Vec<u8> = aes256_cbc_decrypt(&key, &iv, &bytes[..aligned])?;
    let name: String = format!("{}.bin", String::from_utf8_lossy(device.signature));
    Ok(decrypt_result(
        FirmwareKind::DlinkAlphaV1,
        &name,
        plaintext,
        Vec::new(),
    ))
}

fn decrypt_dlink_alpha_v2(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < DLINK_ALPHA_V2_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "dlink-alpha-v2: input {} bytes is shorter than the {DLINK_ALPHA_V2_HEADER_LEN}-byte WRGG header",
            bytes.len()
        )));
    }
    let signature: &[u8] = signature_from_wrgg(bytes);
    let key: [u8; 32] = alpha_mangled_key32(signature, &DLINK_ALPHA_V2_KEY);
    let iv: [u8; 16] = alpha_mangled_iv(signature, &DLINK_ALPHA_V2_IV);
    let body: &[u8] = &bytes[DLINK_ALPHA_V2_HEADER_LEN..];
    let aligned: usize = body.len() - (body.len() % 16);
    if aligned == 0 {
        return Err(Error::Firmware(
            "dlink-alpha-v2: no full cipher block follows the WRGG header".to_owned(),
        ));
    }
    let plaintext: Vec<u8> = aes256_cbc_decrypt(&key, &iv, &body[..aligned])?;
    let name: String = if signature.is_empty() {
        "alpha-v2-decrypted.bin".to_owned()
    } else {
        format!("{}.bin", String::from_utf8_lossy(signature))
    };
    Ok(decrypt_result(
        FirmwareKind::DlinkAlphaV2,
        &name,
        plaintext,
        Vec::new(),
    ))
}

const ENGENIUS_XOR_KEY: [u8; 8] = [0xac, 0x78, 0x3c, 0x9e, 0xcf, 0x67, 0xb3, 0x59];
const ENGENIUS_PATTERN_MATCH_OFFSET: usize = 0x5c;
const ENGENIUS_LENGTH_FIELD_OFFSET: usize = 32;
const ENGENIUS_MODEL_LEN_FIELD_OFFSET: usize = 132;
const ENGENIUS_FIXED_HEADER_LEN: usize = 136;

fn engenius_header_offset(bytes: &[u8]) -> Option<usize> {
    let pos: usize = find_subslice(bytes, ENGENIUS_MAGIC_FULL)?;
    pos.checked_sub(ENGENIUS_PATTERN_MATCH_OFFSET)
}

fn decrypt_engenius(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let header_start: usize = engenius_header_offset(bytes).ok_or_else(|| {
        Error::Firmware(
            "engenius: the `\\x124Vxall` magic was not found at the documented header offset"
                .to_owned(),
        )
    })?;
    let length: u32 = u32_be(bytes, header_start + ENGENIUS_LENGTH_FIELD_OFFSET)
        .ok_or_else(|| Error::Firmware("engenius: truncated length field".to_owned()))?;
    let model_len: u32 = u32_le(bytes, header_start + ENGENIUS_MODEL_LEN_FIELD_OFFSET)
        .ok_or_else(|| Error::Firmware("engenius: truncated model-length field".to_owned()))?;
    let header_end: usize = header_start + ENGENIUS_FIXED_HEADER_LEN + model_len as usize;
    let reference: usize = find_subslice(bytes, &ENGENIUS_XOR_KEY).ok_or_else(|| {
        Error::Firmware(
            "engenius: the 8-byte XOR key string is not present in the image to anchor the keystream"
                .to_owned(),
        )
    })?;
    let body_end: usize = (header_start + length as usize).min(bytes.len());
    if body_end <= header_end {
        return Err(Error::Firmware(format!(
            "engenius: declared length {length} yields an empty payload region after the {header_end}-byte header"
        )));
    }
    let plaintext: Vec<u8> = (header_end..body_end)
        .map(|offset: usize| {
            bytes[offset] ^ ENGENIUS_XOR_KEY[(offset - reference) % ENGENIUS_XOR_KEY.len()]
        })
        .collect();
    Ok(decrypt_result(
        FirmwareKind::EnGenius,
        "engenius-decrypted.bin",
        plaintext,
        Vec::new(),
    ))
}

const AUTEL_HEADER_LEN: usize = 0x20;
const AUTEL_FILE_SIZE_OFFSET: usize = 8;
const AUTEL_HEADER_SIZE_OFFSET: usize = 12;
const AUTEL_BLOCK: usize = 256;

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

fn decrypt_autel_ecc(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let file_size: u32 = u32_le(bytes, AUTEL_FILE_SIZE_OFFSET)
        .ok_or_else(|| Error::Firmware("autel-ecc: truncated file-size field".to_owned()))?;
    let header_size: u32 = u32_le(bytes, AUTEL_HEADER_SIZE_OFFSET)
        .ok_or_else(|| Error::Firmware("autel-ecc: truncated header-size field".to_owned()))?;
    if header_size as usize != AUTEL_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "autel-ecc: header_size {header_size} is not the expected 0x20"
        )));
    }
    let start: usize = header_size as usize;
    let end: usize = start
        .checked_add(file_size as usize)
        .ok_or_else(|| Error::Firmware("autel-ecc: file-size overflow".to_owned()))?;
    let body: &[u8] = bytes.get(start..end.min(bytes.len())).ok_or_else(|| {
        Error::Firmware("autel-ecc: payload region runs past the image".to_owned())
    })?;
    if body.is_empty() {
        return Err(Error::Firmware(
            "autel-ecc: no payload follows the header".to_owned(),
        ));
    }
    let plaintext: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(i, value): (usize, &u8)| {
            let (a, b): (u8, u8) = AUTEL_KEYS[i % AUTEL_BLOCK];
            (value.wrapping_add(a)) ^ b
        })
        .collect();
    Ok(decrypt_result(
        FirmwareKind::AutelEcc,
        "autel-ecc-decrypted.bin",
        plaintext,
        Vec::new(),
    ))
}

const QNAP_SECRET: &[u8] = b"QNAPNASVERSION";
const QNAP_FOOTER_LEN: usize = 74;
const QNAP_ENCRYPTED_LEN_OFFSET: usize = 6;
const QNAP_FILE_VERSION_OFFSET: usize = 26;

fn detect_qnap(bytes: &[u8]) -> bool {
    if bytes.len() < QNAP_FOOTER_LEN {
        return false;
    }
    if bytes.starts_with(&[0xf5, 0x7b, 0x47, 0x03]) {
        return true;
    }
    let footer_start: usize = bytes.len() - QNAP_FOOTER_LEN;
    &bytes[footer_start..footer_start + QNAP_FOOTER_MAGIC.len()] == QNAP_FOOTER_MAGIC
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
        let mut secret_vals: Vec<i32> = secret.iter().map(|b: &u8| i32::from(*b)).collect();
        let n: usize = secret.len() / 2;
        if n.is_multiple_of(2) {
            secret_vals.push(0);
        }
        let mut cryptor: Self = Self {
            secret: secret_vals,
            n,
            k: Vec::new(),
            acc: 0,
            y: 0,
            z: 0,
        };
        cryptor.precompute_k();
        cryptor
    }

    const fn promote(char: i32) -> i32 {
        if char < 0x80 { char } else { char - 0x101 }
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

    fn precompute_k(&mut self) {
        self.k = (0..256).map(|acc: i32| self.table_for_acc(acc)).collect();
    }

    fn kdf(&mut self) -> u8 {
        let tt: Vec<(u16, u16)> = self.k[self.acc].clone();
        let mut res: u16 = 0;
        for (i, entry) in tt.iter().enumerate() {
            let yy: u16 = self.y;
            self.y = entry.1;
            let t2: u16 = entry.1;
            self.z = (u32::from(self.y)
                .wrapping_add(u32::from(yy))
                .wrapping_add(0x4e35u32.wrapping_mul((u32::from(self.z)).wrapping_add(i as u32)))
                & 0xffff) as u16;
            res = res ^ t2 ^ self.z;
        }
        let hi: u16 = res >> 8;
        let lo: u16 = res & 0xff;
        (hi ^ lo) as u8
    }

    fn decrypt_byte(&mut self, v: u8) -> u8 {
        let k: u8 = self.kdf();
        let r: u8 = v ^ k;
        self.acc ^= r as usize;
        r
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|b: &u8| self.decrypt_byte(*b)).collect()
    }
}

fn decrypt_qnap(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < QNAP_FOOTER_LEN {
        return Err(Error::Firmware(format!(
            "qnap: input {} bytes is shorter than the {QNAP_FOOTER_LEN}-byte footer",
            bytes.len()
        )));
    }
    let footer_start: usize = bytes.len() - QNAP_FOOTER_LEN;
    let footer: &[u8] = &bytes[footer_start..];
    let encrypted_len: u32 = u32_le(footer, QNAP_ENCRYPTED_LEN_OFFSET)
        .ok_or_else(|| Error::Firmware("qnap: truncated encrypted-length field".to_owned()))?;
    let version_first: u8 = footer
        .get(QNAP_FILE_VERSION_OFFSET)
        .copied()
        .ok_or_else(|| Error::Firmware("qnap: truncated file-version field".to_owned()))?;
    let mut secret: Vec<u8> = QNAP_SECRET.to_vec();
    secret.push(version_first);
    let enc_end: usize = (encrypted_len as usize).min(footer_start);
    let ciphertext: &[u8] = &bytes[..enc_end];
    if ciphertext.is_empty() {
        return Err(Error::Firmware(
            "qnap: header declares a zero-length encrypted region".to_owned(),
        ));
    }
    let mut cryptor: QnapCryptor = QnapCryptor::new(&secret);
    let mut plaintext: Vec<u8> = cryptor.decrypt(ciphertext);
    let trailer: &[u8] = &bytes[enc_end..footer_start];
    plaintext.extend_from_slice(trailer);
    Ok(decrypt_result(
        FirmwareKind::Qnap,
        "qnap-decrypted.bin",
        plaintext,
        Vec::new(),
    ))
}

fn decrypt_result(
    kind: FirmwareKind,
    name: &str,
    plaintext: Vec<u8>,
    mut notes: Vec<String>,
) -> FirmwareExtraction {
    let inner_kind_hint: Option<String> = inner_magic_label(&plaintext);
    if inner_kind_hint.is_none() {
        notes.push(format!(
            "{}: decrypted {} bytes but no known inner-format magic was recognized at offset 0",
            kind.label(),
            plaintext.len()
        ));
    }
    let length: u64 = plaintext.len() as u64;
    FirmwareExtraction {
        kind,
        members: vec![FirmwareMember {
            name: name.to_owned(),
            offset: 0,
            length,
            data: plaintext,
            crc_expected: None,
            crc_actual: None,
            crc_ok: None,
        }],
        notes,
        inner_kind_hint,
    }
}

const INNER_MAGICS: &[(&[u8], &str)] = &[
    (&[0x68, 0x73, 0x71, 0x73], "squashfs"),
    (&[0x73, 0x71, 0x73, 0x68], "squashfs-be"),
    (&[0x73, 0x68, 0x73, 0x71], "squashfs-v3"),
    (&[0x1f, 0x8b], "gzip"),
    (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], "xz"),
    (&[0x28, 0xb5, 0x2f, 0xfd], "zstd"),
    (&[0x42, 0x5a, 0x68], "bzip2"),
    (&[0x55, 0x42, 0x49, 0x23], "ubi"),
    (&[0x31, 0x18, 0x10, 0x06], "ubifs"),
    (&[0x27, 0x05, 0x19, 0x56], "uimage"),
    (&[0xd0, 0x0d, 0xfe, 0xed], "dtb"),
    (&[0x7f, b'E', b'L', b'F'], "elf"),
    (&[0x28, 0xcd, 0x3d, 0x45], "cramfs"),
    (&[0x45, 0x3d, 0xcd, 0x28], "cramfs-be"),
    (&[0x85, 0x19, 0x03, 0x20], "jffs2-le"),
    (b"PK\x03\x04", "zip"),
    (b"SHRS", "dlink-shrs"),
];

fn inner_magic_present(plaintext: &[u8]) -> bool {
    inner_magic_label(plaintext).is_some()
}

fn inner_magic_label(plaintext: &[u8]) -> Option<String> {
    INNER_MAGICS
        .iter()
        .find(|(magic, _): &&(&[u8], &str)| plaintext.starts_with(magic))
        .map(|(_, label): &(&[u8], &str)| (*label).to_owned())
}

const CHK_FIXED_HEADER_LEN: usize = 40;

fn carve_netgear_chk(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < CHK_FIXED_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "netgear-chk: input {} bytes is shorter than the 40-byte fixed header",
            bytes.len()
        )));
    }
    let header_len: u32 = u32_be(bytes, 4)
        .ok_or_else(|| Error::Firmware("netgear-chk: truncated header-length field".to_owned()))?;
    let kernel_chksum: u32 = u32_be(bytes, 16).map_or(0, |value: u32| value);
    let rootfs_chksum: u32 = u32_be(bytes, 20).map_or(0, |value: u32| value);
    let kernel_len: u32 = u32_be(bytes, 24)
        .ok_or_else(|| Error::Firmware("netgear-chk: truncated kernel-length field".to_owned()))?;
    let rootfs_len: u32 = u32_be(bytes, 28)
        .ok_or_else(|| Error::Firmware("netgear-chk: truncated rootfs-length field".to_owned()))?;
    let image_chksum: u32 = u32_be(bytes, 32).map_or(0, |value: u32| value);
    if (header_len as usize) < CHK_FIXED_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "netgear-chk: declared header length {header_len} is below the 40-byte fixed header"
        )));
    }
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    if header_len as usize > CHK_FIXED_HEADER_LEN
        && let Some(board) = bytes.get(CHK_FIXED_HEADER_LEN..header_len as usize)
    {
        members.push(plain_member(
            "board-id",
            CHK_FIXED_HEADER_LEN as u64,
            board.to_vec(),
        ));
    }
    let kernel_start: usize = header_len as usize;
    let kernel_end: usize = kernel_start
        .checked_add(kernel_len as usize)
        .ok_or_else(|| Error::Firmware("netgear-chk: kernel length overflow".to_owned()))?;
    let kernel: &[u8] = bytes.get(kernel_start..kernel_end).ok_or_else(|| {
        Error::Firmware(format!(
            "netgear-chk: kernel region [{kernel_start}, {kernel_end}) exceeds the {}-byte image",
            bytes.len()
        ))
    })?;
    members.push(plain_member(
        "kernel.bin",
        kernel_start as u64,
        kernel.to_vec(),
    ));
    let mut rootfs_end: usize = kernel_end;
    if rootfs_len > 0 {
        rootfs_end = kernel_end.saturating_add(rootfs_len as usize);
        if let Some(rootfs) = bytes.get(kernel_end..rootfs_end) {
            members.push(plain_member(
                "rootfs.bin",
                kernel_end as u64,
                rootfs.to_vec(),
            ));
        } else {
            notes.push(format!(
                "netgear-chk: rootfs region [{kernel_end}, {rootfs_end}) exceeds the image; skipped"
            ));
        }
    }
    let image: &[u8] = bytes
        .get(kernel_start..rootfs_end.min(bytes.len()))
        .map_or(&[] as &[u8], |value: &[u8]| value);
    let computed: u32 = chk_checksum(image);
    notes.push(format!(
        "netgear-chk: image checksum field 0x{image_chksum:08x}, sum over [{kernel_start}, {}) = 0x{computed:08x}; kernel-sum field 0x{kernel_chksum:08x}, rootfs-sum field 0x{rootfs_chksum:08x}",
        rootfs_end.min(bytes.len())
    ));
    if let Some(first) = members
        .iter_mut()
        .find(|m: &&mut FirmwareMember| m.name == "kernel.bin")
    {
        first.crc_expected = Some(image_chksum);
        first.crc_actual = Some(computed);
        first.crc_ok = Some(computed == image_chksum);
    }
    Ok(FirmwareExtraction {
        kind: FirmwareKind::NetgearChk,
        members,
        notes,
        inner_kind_hint: None,
    })
}

fn chk_checksum(data: &[u8]) -> u32 {
    let mut c0: u32 = 0;
    let mut c1: u32 = 0;
    for &byte in data {
        c0 = c0.wrapping_add(u32::from(byte));
        c1 = c1.wrapping_add(c0);
    }
    let b: u32 = (c0 & 65535).wrapping_add(c0 >> 16);
    let lo: u32 = (b & 255).wrapping_add(b >> 8) & 255;
    let b1: u32 = (c1 & 65535).wrapping_add(c1 >> 16);
    let hi: u32 = (b1 & 255).wrapping_add(b1 >> 8) & 255;
    (hi << 8) | lo
}

const TRX_CRC_CONTENT_OFFSET: usize = 12;
const TRX_HEADER_V1_LEN: usize = 28;
const TRX_HEADER_V2_LEN: usize = 32;

fn trx_version(bytes: &[u8]) -> FirmwareKind {
    match u16_le(bytes, 14) {
        Some(2) => FirmwareKind::NetgearTrxV2,
        _ => FirmwareKind::NetgearTrxV1,
    }
}

fn carve_trx(bytes: &[u8], kind: FirmwareKind) -> Result<FirmwareExtraction> {
    let part_count: usize = if kind == FirmwareKind::NetgearTrxV2 {
        4
    } else {
        3
    };
    let header_len: usize = if kind == FirmwareKind::NetgearTrxV2 {
        TRX_HEADER_V2_LEN
    } else {
        TRX_HEADER_V1_LEN
    };
    if bytes.len() < header_len {
        return Err(Error::Firmware(format!(
            "{}: input {} bytes is shorter than the {header_len}-byte header",
            kind.label(),
            bytes.len()
        )));
    }
    let total_len: u32 = u32_le(bytes, 4)
        .ok_or_else(|| Error::Firmware("trx: truncated length field".to_owned()))?;
    let stored_crc: u32 =
        u32_le(bytes, 8).ok_or_else(|| Error::Firmware("trx: truncated crc field".to_owned()))?;
    let version: u16 = u16_le(bytes, 14).map_or(0, |value: u16| value);
    let mut offsets: Vec<u32> = Vec::with_capacity(part_count);
    for i in 0..part_count {
        offsets.push(u32_le(bytes, 16 + i * 4).map_or(0, |value: u32| value));
    }
    let total: usize = total_len as usize;
    if total > bytes.len() || total <= TRX_CRC_CONTENT_OFFSET {
        return Err(Error::Firmware(format!(
            "{}: declared total length {total} is out of range for the {}-byte image",
            kind.label(),
            bytes.len()
        )));
    }
    let crc_region: &[u8] = &bytes[TRX_CRC_CONTENT_OFFSET..total];
    let computed: u32 = !crc32(crc_region);
    let crc_ok: bool = computed == stored_crc;
    let mut notes: Vec<String> = vec![format!(
        "{}: v{version}, header crc32 field 0x{stored_crc:08x}, computed crc32 over [12, {total}) = 0x{computed:08x} ({})",
        kind.label(),
        if crc_ok { "match" } else { "mismatch" }
    )];
    let mut bounds: Vec<usize> = offsets
        .iter()
        .copied()
        .filter(|o: &u32| *o != 0)
        .map(|o: u32| o as usize)
        .collect();
    bounds.push(total);
    bounds.sort_unstable();
    bounds.dedup();
    let mut members: Vec<FirmwareMember> = Vec::new();
    for (i, win) in bounds.windows(2).enumerate() {
        let (start, end): (usize, usize) = (win[0], win[1]);
        if let Some(part) = bytes.get(start..end) {
            let mut member: FirmwareMember =
                plain_member(&format!("part{i}.bin"), start as u64, part.to_vec());
            member.crc_expected = Some(stored_crc);
            members.push(member);
        } else {
            notes.push(format!(
                "{}: part{i} region [{start}, {end}) exceeds the image; skipped",
                kind.label()
            ));
        }
    }
    if let Some(first) = members.first_mut() {
        first.crc_actual = Some(computed);
        first.crc_ok = Some(crc_ok);
    }
    if members.is_empty() {
        return Err(Error::Firmware(format!(
            "{}: header parsed but no partition offset produced an in-range member",
            kind.label()
        )));
    }
    Ok(FirmwareExtraction {
        kind,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const XIAOMI_BLOB_MAGIC: u32 = 0x0000_babe;
const XIAOMI_BLOB_HEADER_LEN: usize = 48;
const XIAOMI_CRC_CONTENT_OFFSET: usize = 12;
const XIAOMI_SIGNATURE_LEN: usize = 272;
const XIAOMI_BLOB_OFFSET_COUNT: usize = 8;

fn carve_xiaomi(bytes: &[u8], kind: FirmwareKind) -> Result<FirmwareExtraction> {
    let header_len: usize = if kind == FirmwareKind::XiaomiHdr2 {
        0x40
    } else {
        0x30
    };
    let blob_table_off: usize = if kind == FirmwareKind::XiaomiHdr2 {
        0x30
    } else {
        0x10
    };
    if bytes.len() < header_len {
        return Err(Error::Firmware(format!(
            "{}: input {} bytes is shorter than the {header_len}-byte header",
            kind.label(),
            bytes.len()
        )));
    }
    let signature_offset: u32 = u32_le(bytes, 4)
        .ok_or_else(|| Error::Firmware("xiaomi: truncated signature-offset field".to_owned()))?;
    let stored_crc: u32 = u32_le(bytes, 8)
        .ok_or_else(|| Error::Firmware("xiaomi: truncated crc field".to_owned()))?;
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for index in 0..XIAOMI_BLOB_OFFSET_COUNT {
        let Some(blob_offset): Option<u32> = u32_le(bytes, blob_table_off + index * 4) else {
            break;
        };
        if blob_offset == 0 {
            break;
        }
        let bh: usize = blob_offset as usize;
        let Some(header) = bytes.get(bh..bh + XIAOMI_BLOB_HEADER_LEN) else {
            notes.push(format!(
                "{}: blob {index} header at offset {bh} runs past the image; stopping",
                kind.label()
            ));
            break;
        };
        let blob_magic: u32 = u32_le(header, 0).map_or(0, |value: u32| value);
        let blob_size: u32 = u32_le(header, 8).map_or(0, |value: u32| value);
        if blob_magic != XIAOMI_BLOB_MAGIC || blob_size == 0 {
            notes.push(format!(
                "{}: blob {index} at offset {bh} has magic 0x{blob_magic:08x} size {blob_size}; skipped",
                kind.label()
            ));
            continue;
        }
        let name_raw: &[u8] = &header[16..48];
        let name: String = sanitize_member_name(&String::from_utf8_lossy(
            name_raw
                .split(|b: &u8| *b == 0)
                .next()
                .map_or(name_raw, |value: &[u8]| value),
        ));
        let data_start: usize = bh + XIAOMI_BLOB_HEADER_LEN;
        let data_end: usize = data_start.saturating_add(blob_size as usize);
        if let Some(blob) = bytes.get(data_start..data_end) {
            let final_name: String = if name.is_empty() {
                format!("blob{index}.bin")
            } else {
                name
            };
            members.push(plain_member(&final_name, data_start as u64, blob.to_vec()));
        } else {
            notes.push(format!(
                "{}: blob {index} data [{data_start}, {data_end}) exceeds the image; skipped",
                kind.label()
            ));
        }
    }
    let crc_end: usize = (signature_offset as usize + XIAOMI_SIGNATURE_LEN).min(bytes.len());
    if crc_end > XIAOMI_CRC_CONTENT_OFFSET {
        let computed: u32 = !crc32(&bytes[XIAOMI_CRC_CONTENT_OFFSET..crc_end]);
        notes.push(format!(
            "{}: header crc32 field 0x{stored_crc:08x}, crc32 over [12, {crc_end}) = 0x{computed:08x} ({})",
            kind.label(),
            if computed == stored_crc { "match" } else { "mismatch" }
        ));
        if let Some(first) = members.first_mut() {
            first.crc_expected = Some(stored_crc);
            first.crc_actual = Some(computed);
            first.crc_ok = Some(computed == stored_crc);
        }
    }
    if members.is_empty() {
        return Err(Error::Firmware(format!(
            "{}: header parsed but the blob table held no valid blob",
            kind.label()
        )));
    }
    Ok(FirmwareExtraction {
        kind,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const SBFH_HEADER_LEN: usize = 0x120;
const MRVL_MAGIC: &[u8; 4] = b"MRVL";
const MRVL_HEADER_LEN: usize = 0x14;
const MRVL_SEGMENT_HEADER_LEN: usize = 0x14;

fn carve_tesla_sbfh(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < SBFH_HEADER_LEN + MRVL_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "tesla-sbfh: input {} bytes is shorter than the SBFH + MRVL headers",
            bytes.len()
        )));
    }
    let header_size: u32 = u32_le(bytes, 4)
        .ok_or_else(|| Error::Firmware("tesla-sbfh: truncated header-size field".to_owned()))?;
    let mrvl_off: usize = SBFH_HEADER_LEN;
    if &bytes[mrvl_off..mrvl_off + 4] != MRVL_MAGIC {
        return Err(Error::Firmware(
            "tesla-sbfh: SBFH header is not followed by the MRVL magic".to_owned(),
        ));
    }
    let num_segments: u32 = u32_le(bytes, mrvl_off + 12)
        .ok_or_else(|| Error::Firmware("tesla-sbfh: truncated MRVL segment-count".to_owned()))?;
    if num_segments == 0 || num_segments > 9 {
        return Err(Error::Firmware(format!(
            "tesla-sbfh: implausible MRVL segment count {num_segments}"
        )));
    }
    let seg_table_off: usize = mrvl_off + MRVL_HEADER_LEN;
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for index in 0..num_segments as usize {
        let entry_off: usize = seg_table_off + index * MRVL_SEGMENT_HEADER_LEN;
        let Some(entry) = bytes.get(entry_off..entry_off + MRVL_SEGMENT_HEADER_LEN) else {
            notes.push(format!(
                "tesla-sbfh: segment {index} table row is truncated; stopping"
            ));
            break;
        };
        let seg_offset: u32 = u32_le(entry, 4).map_or(0, |value: u32| value);
        let seg_size: u32 = u32_le(entry, 8).map_or(0, |value: u32| value);
        let vaddr: u32 = u32_le(entry, 12).map_or(0, |value: u32| value);
        let seg_crc: u32 = u32_le(entry, 16).map_or(0, |value: u32| value);
        let data_start: usize = (header_size as usize).saturating_add(seg_offset as usize);
        let data_end: usize = data_start.saturating_add(seg_size as usize);
        if let Some(seg) = bytes.get(data_start..data_end) {
            let computed: u32 = crc32(seg);
            let mut member: FirmwareMember = plain_member(
                &format!("mrvl-segment{index}.{vaddr:08x}.bin"),
                data_start as u64,
                seg.to_vec(),
            );
            member.crc_expected = Some(seg_crc);
            member.crc_actual = Some(computed);
            member.crc_ok = Some(computed == seg_crc);
            members.push(member);
        } else {
            notes.push(format!(
                "tesla-sbfh: segment {index} region [{data_start}, {data_end}) exceeds the image; skipped"
            ));
        }
    }
    if members.is_empty() {
        return Err(Error::Firmware(
            "tesla-sbfh: SBFH/MRVL headers parsed but no segment was carved".to_owned(),
        ));
    }
    Ok(FirmwareExtraction {
        kind: FirmwareKind::TeslaSbfh,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const HP_BDL_TOC_OFFSET_FIELD: usize = 8;
const HP_BDL_TOC_ENTRIES_FIELD: usize = 16;
const HP_BDL_TOC_ENTRY_LEN: usize = 16;

fn carve_hp_bdl(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let toc_offset: u32 = u32_le(bytes, HP_BDL_TOC_OFFSET_FIELD)
        .ok_or_else(|| Error::Firmware("hp-bdl: truncated toc-offset field".to_owned()))?;
    let toc_entries: u32 = u32_le(bytes, HP_BDL_TOC_ENTRIES_FIELD)
        .ok_or_else(|| Error::Firmware("hp-bdl: truncated toc-entries field".to_owned()))?;
    if toc_offset == 0 || toc_entries == 0 || toc_entries > 65536 {
        return Err(Error::Firmware(format!(
            "hp-bdl: implausible toc_offset {toc_offset} / toc_entries {toc_entries}"
        )));
    }
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for index in 0..toc_entries as usize {
        let entry_off: usize = toc_offset as usize + index * HP_BDL_TOC_ENTRY_LEN;
        let Some(offset): Option<u64> = u64_le(bytes, entry_off) else {
            notes.push(format!("hp-bdl: TOC entry {index} is truncated; stopping"));
            break;
        };
        let Some(entry_size): Option<u64> = u64_le(bytes, entry_off + 8) else {
            break;
        };
        let start: usize = offset as usize;
        let end: usize = start.saturating_add(entry_size as usize);
        if let Some(data) = bytes.get(start..end) {
            members.push(plain_member(
                &format!("ipkg{index:03}"),
                start as u64,
                data.to_vec(),
            ));
        } else {
            notes.push(format!(
                "hp-bdl: member {index} region [{start}, {end}) exceeds the image; skipped"
            ));
        }
    }
    if members.is_empty() {
        return Err(Error::Firmware(
            "hp-bdl: TOC parsed but no in-range member was carved".to_owned(),
        ));
    }
    Ok(FirmwareExtraction {
        kind: FirmwareKind::HpBdl,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const HP_IPKG_TOC_OFFSET_FIELD: usize = 8;
const HP_IPKG_TOC_ENTRIES_FIELD: usize = 16;
const HP_IPKG_ENTRY_LEN: usize = 276;
const HP_IPKG_NAME_LEN: usize = 256;

fn carve_hp_ipkg(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let toc_offset: u32 = u32_le(bytes, HP_IPKG_TOC_OFFSET_FIELD)
        .ok_or_else(|| Error::Firmware("hp-ipkg: truncated toc-offset field".to_owned()))?;
    let toc_entries: u32 = u32_le(bytes, HP_IPKG_TOC_ENTRIES_FIELD)
        .ok_or_else(|| Error::Firmware("hp-ipkg: truncated toc-entries field".to_owned()))?;
    if toc_offset == 0 || toc_entries == 0 || toc_entries > 65536 {
        return Err(Error::Firmware(format!(
            "hp-ipkg: implausible toc_offset {toc_offset} / toc_entries {toc_entries}"
        )));
    }
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for index in 0..toc_entries as usize {
        let entry_off: usize = toc_offset as usize + index * HP_IPKG_ENTRY_LEN;
        let Some(entry) = bytes.get(entry_off..entry_off + HP_IPKG_ENTRY_LEN) else {
            notes.push(format!("hp-ipkg: TOC entry {index} is truncated; stopping"));
            break;
        };
        let name_raw: &[u8] = &entry[..HP_IPKG_NAME_LEN];
        let name: String = sanitize_member_name(&String::from_utf8_lossy(
            name_raw
                .split(|b: &u8| *b == 0)
                .next()
                .map_or(name_raw, |value: &[u8]| value),
        ));
        let offset: u64 = u64_le(entry, HP_IPKG_NAME_LEN).map_or(0, |value: u64| value);
        let entry_size: u64 = u64_le(entry, HP_IPKG_NAME_LEN + 8).map_or(0, |value: u64| value);
        let crc_expected: u32 = u32_le(entry, HP_IPKG_NAME_LEN + 16).map_or(0, |value: u32| value);
        let start: usize = offset as usize;
        let end: usize = start.saturating_add(entry_size as usize);
        if let Some(data) = bytes.get(start..end) {
            let computed: u32 = crc32(data);
            let final_name: String = if name.is_empty() {
                format!("ipkg-member{index}.bin")
            } else {
                name
            };
            let mut member: FirmwareMember = plain_member(&final_name, start as u64, data.to_vec());
            if crc_expected != 0 {
                member.crc_expected = Some(crc_expected);
                member.crc_actual = Some(computed);
                member.crc_ok = Some(computed == crc_expected);
            }
            members.push(member);
        } else {
            notes.push(format!(
                "hp-ipkg: member {index} region [{start}, {end}) exceeds the image; skipped"
            ));
        }
    }
    if members.is_empty() {
        return Err(Error::Firmware(
            "hp-ipkg: TOC parsed but no in-range member was carved".to_owned(),
        ));
    }
    Ok(FirmwareExtraction {
        kind: FirmwareKind::HpIpkg,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const MOXA_CONTAINER_HEADER_LEN: usize = 0x60;
const MOXA_SECTION_ENTRY_LEN: usize = 16;
const MOXA_SECTION_FW_BINARY: u32 = 1;
const MOXA_SECTION_FILESYSTEM: u32 = 2;
const GZIP_MAGIC: &[u8; 2] = &[0x1f, 0x8b];

fn carve_moxa_frm(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < MOXA_CONTAINER_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "moxa-frm: input {} bytes is shorter than the 0x60-byte container header",
            bytes.len()
        )));
    }
    let section_count: u16 = u16_le(bytes, 14)
        .ok_or_else(|| Error::Firmware("moxa-frm: truncated section-count field".to_owned()))?;
    if section_count == 0 || section_count > 64 {
        return Err(Error::Firmware(format!(
            "moxa-frm: implausible section count {section_count}"
        )));
    }
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for index in 0..section_count as usize {
        let entry_off: usize = MOXA_CONTAINER_HEADER_LEN + index * MOXA_SECTION_ENTRY_LEN;
        let Some(entry) = bytes.get(entry_off..entry_off + MOXA_SECTION_ENTRY_LEN) else {
            notes.push(format!(
                "moxa-frm: section {index} entry is truncated; stopping"
            ));
            break;
        };
        let section_type: u32 = u32_le(entry, 0).map_or(0, |value: u32| value);
        let offset: u32 = u32_le(entry, 4).map_or(0, |value: u32| value);
        let length: u32 = u32_le(entry, 8).map_or(0, |value: u32| value);
        let start: usize = offset as usize;
        let end: usize = start.saturating_add(length as usize);
        let Some(section_data) = bytes.get(start..end) else {
            notes.push(format!(
                "moxa-frm: section {index} region [{start}, {end}) exceeds the image; skipped"
            ));
            continue;
        };
        let name: String = match section_type {
            MOXA_SECTION_FW_BINARY => format!("section{index}.firmware.bin"),
            MOXA_SECTION_FILESYSTEM => format!("section{index}.filesystem.bin"),
            other => format!("section{index}.type{other}.bin"),
        };
        members.push(plain_member(&name, start as u64, section_data.to_vec()));
    }
    if members.is_empty() {
        return Err(Error::Firmware(
            "moxa-frm: container header parsed but no in-range section was carved".to_owned(),
        ));
    }
    let has_gzip: bool = members
        .iter()
        .any(|m: &FirmwareMember| m.data.starts_with(GZIP_MAGIC));
    notes.push(format!(
        "moxa-frm: carved {} section(s); embedded files inside the filesystem section may be individually gzip-compressed",
        members.len()
    ));
    Ok(FirmwareExtraction {
        kind: FirmwareKind::MoxaFrm,
        members,
        notes,
        inner_kind_hint: if has_gzip {
            Some("gzip".to_owned())
        } else {
            None
        },
    })
}

const BNEG_HEADER_LEN: usize = 20;

fn carve_instar_bneg(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < BNEG_HEADER_LEN {
        return Err(Error::Firmware(format!(
            "instar-bneg: input {} bytes is shorter than the 20-byte header",
            bytes.len()
        )));
    }
    let part1_size: u32 = u32_le(bytes, 12)
        .ok_or_else(|| Error::Firmware("instar-bneg: truncated partition-1 size".to_owned()))?;
    let part2_size: u32 = u32_le(bytes, 16)
        .ok_or_else(|| Error::Firmware("instar-bneg: truncated partition-2 size".to_owned()))?;
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let p1_start: usize = BNEG_HEADER_LEN;
    let p1_end: usize = p1_start.saturating_add(part1_size as usize);
    if let Some(p1) = bytes.get(p1_start..p1_end) {
        members.push(plain_member("part1.bin", p1_start as u64, p1.to_vec()));
    } else {
        notes.push("instar-bneg: partition 1 region exceeds the image; skipped".to_owned());
    }
    let p2_start: usize = p1_end;
    let p2_end: usize = p2_start.saturating_add(part2_size as usize);
    if let Some(p2) = bytes.get(p2_start..p2_end) {
        members.push(plain_member("part2.bin", p2_start as u64, p2.to_vec()));
    } else {
        notes.push("instar-bneg: partition 2 region exceeds the image; skipped".to_owned());
    }
    if members.is_empty() {
        return Err(Error::Firmware(
            "instar-bneg: header parsed but neither partition was in range".to_owned(),
        ));
    }
    Ok(FirmwareExtraction {
        kind: FirmwareKind::InstarBneg,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const INSTAR_HD_SIG_REPLACEMENTS: &[([u8; 4], [u8; 4])] = &[
    ([0x50, 0x4b, 0x03, 0x07], [0x50, 0x4b, 0x03, 0x04]),
    ([0x50, 0x4b, 0x05, 0x09], [0x50, 0x4b, 0x05, 0x06]),
    ([0x50, 0x4b, 0x01, 0x08], [0x50, 0x4b, 0x01, 0x02]),
];

fn carve_instar_hd(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let mut out: Vec<u8> = bytes.to_vec();
    let mut total: usize = 0;
    for (from, to) in INSTAR_HD_SIG_REPLACEMENTS {
        let mut search: usize = 0;
        while let Some(rel) = find_subslice(&out[search..], from) {
            let at: usize = search + rel;
            out[at..at + 4].copy_from_slice(to);
            total += 1;
            search = at + 4;
        }
    }
    if total == 0 {
        return Err(Error::Firmware(
            "instar-hd: no non-standard zip signature (PK\\x03\\x07 / PK\\x05\\x09 / PK\\x01\\x08) was present to rewrite".to_owned(),
        ));
    }
    let inner_kind_hint: Option<String> = if out.starts_with(b"PK\x03\x04") {
        Some("zip".to_owned())
    } else {
        None
    };
    let notes: Vec<String> = vec![format!(
        "instar-hd: rewrote {total} non-standard zip signature(s) (PK\\x03\\x07, PK\\x05\\x09, PK\\x01\\x08) back to the standard PK markers"
    )];
    Ok(FirmwareExtraction {
        kind: FirmwareKind::InstarHd,
        members: vec![plain_member("instar-hd.zip", 0, out)],
        notes,
        inner_kind_hint,
    })
}

const DEAFBEAD_HEADER_LEN: usize = 4;
const DEAFBEAD_DIR_MAGIC: u8 = 0x86;
const DEAFBEAD_FILE_MAGIC: u8 = 0x87;

fn carve_dlink_deafbead(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let mut cursor: usize = DEAFBEAD_HEADER_LEN;
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    while let Some(&magic) = bytes.get(cursor) {
        match magic {
            DEAFBEAD_DIR_MAGIC => {
                let name_len: u16 = u16_le(bytes, cursor + 1).ok_or_else(|| {
                    Error::Firmware("dlink-deafbead: truncated directory record".to_owned())
                })?;
                cursor += 3 + name_len as usize;
            }
            DEAFBEAD_FILE_MAGIC => {
                let name_len: u16 = u16_le(bytes, cursor + 1).ok_or_else(|| {
                    Error::Firmware("dlink-deafbead: truncated file record".to_owned())
                })?;
                let name_off: usize = cursor + 3;
                let name_end: usize = name_off + name_len as usize;
                let name_raw: &[u8] = bytes.get(name_off..name_end).ok_or_else(|| {
                    Error::Firmware("dlink-deafbead: file name runs past the image".to_owned())
                })?;
                let file_size: u32 = u32_le(bytes, name_end).ok_or_else(|| {
                    Error::Firmware("dlink-deafbead: truncated file-size field".to_owned())
                })?;
                let data_start: usize = name_end + 4;
                let data_end: usize = data_start.saturating_add(file_size as usize);
                let raw: &[u8] = bytes.get(data_start..data_end).ok_or_else(|| {
                    Error::Firmware("dlink-deafbead: file contents run past the image".to_owned())
                })?;
                let name: String = sanitize_member_name(&String::from_utf8_lossy(name_raw));
                let decompressed: Vec<u8> = match gunzip(raw) {
                    Ok(d) => d,
                    Err(e) => {
                        notes.push(format!("dlink-deafbead: `{name}` gzip decode failed: {e}"));
                        cursor = data_end;
                        continue;
                    }
                };
                let final_name: String = if name.is_empty() {
                    format!("file{}.bin", members.len())
                } else {
                    name
                };
                members.push(plain_member(&final_name, data_start as u64, decompressed));
                cursor = data_end;
            }
            _ => break,
        }
    }
    if members.is_empty() {
        return Err(Error::Firmware(
            "dlink-deafbead: header present but no file record was decoded".to_owned(),
        ));
    }
    Ok(FirmwareExtraction {
        kind: FirmwareKind::DlinkDeafbead,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const FPKG_CPKG_HEADER_MIN: usize = 12;
const FPKG_FILE_HEADER_LEN: usize = 0x1c;

fn carve_dlink_fpkg(bytes: &[u8]) -> Result<FirmwareExtraction> {
    let first_entry_offset: u32 = u32_be(bytes, 8).ok_or_else(|| {
        Error::Firmware("dlink-fpkg: truncated first-entry-offset field".to_owned())
    })?;
    if (first_entry_offset as usize) < FPKG_CPKG_HEADER_MIN {
        return Err(Error::Firmware(format!(
            "dlink-fpkg: first_entry_offset {first_entry_offset} is below the 12-byte header"
        )));
    }
    let mut members: Vec<FirmwareMember> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut cursor: usize = first_entry_offset as usize;
    let mut index: usize = 0;
    while cursor + FPKG_FILE_HEADER_LEN <= bytes.len() {
        let header_len: u32 = u32_be(bytes, cursor).map_or(0, |value: u32| value);
        if header_len as usize != FPKG_FILE_HEADER_LEN {
            notes.push(format!(
                "dlink-fpkg: entry {index} header_len {header_len} is not 0x1C; stopping"
            ));
            break;
        }
        let file_size: u32 = u32_be(bytes, cursor + 8).map_or(0, |value: u32| value);
        let name_raw: &[u8] = bytes
            .get(cursor + 12..cursor + FPKG_FILE_HEADER_LEN)
            .map_or(&[] as &[u8], |value: &[u8]| value);
        let name: String = sanitize_member_name(&String::from_utf8_lossy(
            name_raw
                .split(|b: &u8| *b == 0)
                .next()
                .map_or(name_raw, |value: &[u8]| value),
        ));
        let data_start: usize = cursor + header_len as usize;
        let data_end: usize = data_start.saturating_add(file_size as usize);
        if let Some(data) = bytes.get(data_start..data_end) {
            let final_name: String = if name.is_empty() {
                format!("fpkg-member{index}.bin")
            } else {
                name
            };
            members.push(plain_member(&final_name, data_start as u64, data.to_vec()));
        } else {
            notes.push(format!(
                "dlink-fpkg: member {index} region [{data_start}, {data_end}) exceeds the image; stopping"
            ));
            break;
        }
        cursor = data_end;
        index += 1;
    }
    if members.is_empty() {
        return Err(Error::Firmware(
            "dlink-fpkg: header parsed but no in-range file entry was carved".to_owned(),
        ));
    }
    Ok(FirmwareExtraction {
        kind: FirmwareKind::DlinkFpkg,
        members,
        notes,
        inner_kind_hint: None,
    })
}

const AIROHA_PRELUDE_SIZE: usize = 256;
const AIROHA_BASIC_INFO_OFFSET: usize = 256;
const AIROHA_COMPRESSION_NONE: u8 = 0;
const AIROHA_COMPRESSION_LZMA: u8 = 1;
const AIROHA_COMPRESSION_LZMA_AES: u8 = 2;

fn detect_airoha(bytes: &[u8]) -> bool {
    if bytes.len() < AIROHA_BASIC_INFO_OFFSET + 4 {
        return false;
    }
    &bytes[AIROHA_BASIC_INFO_OFFSET..AIROHA_BASIC_INFO_OFFSET + 4] == AIROHA_BASIC_INFO_TLV
        && bytes[..224 + 32]
            .iter()
            .skip(32)
            .take(16)
            .all(|b: &u8| *b == 0xff)
}

fn carve_airoha(bytes: &[u8]) -> Result<FirmwareExtraction> {
    if bytes.len() < AIROHA_BASIC_INFO_OFFSET + 12 {
        return Err(Error::Firmware(format!(
            "airoha: input {} bytes is shorter than the prelude + BASIC_INFO TLV",
            bytes.len()
        )));
    }
    let compression_type: u8 = bytes[AIROHA_BASIC_INFO_OFFSET + 4];
    let firmware_offset: u32 = u32_le(bytes, AIROHA_BASIC_INFO_OFFSET + 6)
        .ok_or_else(|| Error::Firmware("airoha: truncated firmware-offset field".to_owned()))?;
    let firmware_size: u32 = u32_le(bytes, AIROHA_BASIC_INFO_OFFSET + 10)
        .ok_or_else(|| Error::Firmware("airoha: truncated firmware-size field".to_owned()))?;
    if (firmware_offset as usize) < AIROHA_PRELUDE_SIZE {
        return Err(Error::Firmware(format!(
            "airoha: firmware_offset {firmware_offset} is inside the 256-byte prelude"
        )));
    }
    let start: usize = firmware_offset as usize;
    let end: usize = start.saturating_add(firmware_size as usize);
    let blob: &[u8] = bytes.get(start..end.min(bytes.len())).ok_or_else(|| {
        Error::Firmware("airoha: firmware blob region runs past the image".to_owned())
    })?;
    let mut notes: Vec<String> = Vec::new();
    let (name, inner_hint): (&str, Option<String>) = match compression_type {
        AIROHA_COMPRESSION_LZMA_AES => {
            notes.push("airoha: BASIC_INFO declares LZMA_AES; the firmware blob is AES-encrypted under a per-vendor key/IV that is not present anywhere in the firmware file (it ships in the SoC bootloader / device key store), so the blob is carved verbatim - this is an information-theoretic limit, not a missing implementation".to_owned());
            ("airoha-firmware.encrypted.bin", None)
        }
        AIROHA_COMPRESSION_LZMA => {
            notes.push("airoha: BASIC_INFO declares LZMA; the carved blob is a raw LZMA stream that the recursion can decompress".to_owned());
            ("airoha-firmware.lzma", Some("lzma".to_owned()))
        }
        AIROHA_COMPRESSION_NONE => ("airoha-firmware.bin", inner_magic_label(blob)),
        other => {
            notes.push(format!(
                "airoha: unknown compression_type {other}; blob carved verbatim"
            ));
            ("airoha-firmware.bin", None)
        }
    };
    Ok(FirmwareExtraction {
        kind: FirmwareKind::Airoha,
        members: vec![plain_member(name, start as u64, blob.to_vec())],
        notes,
        inner_kind_hint: inner_hint,
    })
}

fn plain_member(name: &str, offset: u64, data: Vec<u8>) -> FirmwareMember {
    let length: u64 = data.len() as u64;
    FirmwareMember {
        name: name.to_owned(),
        offset,
        length,
        data,
        crc_expected: None,
        crc_actual: None,
        crc_ok: None,
    }
}

fn sanitize_member_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect();
    cleaned
        .split('/')
        .filter(|s: &&str| !s.is_empty() && *s != "." && *s != "..")
        .collect::<Vec<&str>>()
        .join("/")
        .trim_matches(['_', '.'])
        .to_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    disrobe_core::byte_search::find(haystack, needle)
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let mut decoder: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(data);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::Firmware(format!("gzip decode: {e}")))?;
    Ok(out)
}

pub fn extract_firmware(kind: FirmwareKind, bytes: &[u8]) -> Result<FirmwareExtraction> {
    match kind {
        FirmwareKind::DlinkShrs => decrypt_dlink_shrs(bytes),
        FirmwareKind::DlinkEncrptedImg => decrypt_dlink_encrpted_img(bytes),
        FirmwareKind::DlinkAlphaV1 => decrypt_dlink_alpha_v1(bytes),
        FirmwareKind::DlinkAlphaV2 => decrypt_dlink_alpha_v2(bytes),
        FirmwareKind::DlinkDeafbead => carve_dlink_deafbead(bytes),
        FirmwareKind::DlinkFpkg => carve_dlink_fpkg(bytes),
        FirmwareKind::EnGenius => decrypt_engenius(bytes),
        FirmwareKind::AutelEcc => decrypt_autel_ecc(bytes),
        FirmwareKind::Qnap => decrypt_qnap(bytes),
        FirmwareKind::NetgearChk => carve_netgear_chk(bytes),
        FirmwareKind::NetgearTrxV1 => carve_trx(bytes, FirmwareKind::NetgearTrxV1),
        FirmwareKind::NetgearTrxV2 => carve_trx(bytes, FirmwareKind::NetgearTrxV2),
        FirmwareKind::XiaomiHdr1 => carve_xiaomi(bytes, FirmwareKind::XiaomiHdr1),
        FirmwareKind::XiaomiHdr2 => carve_xiaomi(bytes, FirmwareKind::XiaomiHdr2),
        FirmwareKind::TeslaSbfh => carve_tesla_sbfh(bytes),
        FirmwareKind::HpBdl => carve_hp_bdl(bytes),
        FirmwareKind::HpIpkg => carve_hp_ipkg(bytes),
        FirmwareKind::MoxaFrm => carve_moxa_frm(bytes),
        FirmwareKind::InstarBneg => carve_instar_bneg(bytes),
        FirmwareKind::InstarHd => carve_instar_hd(bytes),
        FirmwareKind::Airoha => carve_airoha(bytes),
    }
}
