use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
pub const APK_SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109_871a;
pub const APK_SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf053_68c0;
pub const APK_SIGNATURE_SCHEME_V3_1_BLOCK_ID: u32 = 0x1b93_ad61;
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x4272_6577;

const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const EOCD_MIN_LEN: usize = 22;
const ZIP_MAX_COMMENT: usize = 0xFFFF;
const SIGNING_BLOCK_FOOTER: usize = 24;
const MAX_PAIRS: usize = 4096;
const MAX_SIGNERS: usize = 4096;
const MAX_CERTS_PER_SIGNER: usize = 256;
const MAX_DIGESTS_PER_SIGNER: usize = 256;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

fn push_lower_hex_byte(out: &mut String, byte: u8) {
    out.push(LOWER_HEX[(byte >> 4) as usize] as char);
    out.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureScheme {
    V2,
    V3,
    V3_1,
}

impl SignatureScheme {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V3_1 => "v3.1",
        }
    }

    #[inline]
    #[must_use]
    const fn block_id(self) -> u32 {
        match self {
            Self::V2 => APK_SIGNATURE_SCHEME_V2_BLOCK_ID,
            Self::V3 => APK_SIGNATURE_SCHEME_V3_BLOCK_ID,
            Self::V3_1 => APK_SIGNATURE_SCHEME_V3_1_BLOCK_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    RsaPssSha256,
    RsaPssSha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha512,
    EcdsaSha256,
    EcdsaSha512,
    DsaSha256,
    Unknown,
}

impl SignatureAlgorithm {
    #[inline]
    #[must_use]
    const fn from_id(id: u32) -> Self {
        match id {
            0x0101 => Self::RsaPssSha256,
            0x0102 => Self::RsaPssSha512,
            0x0103 => Self::RsaPkcs1Sha256,
            0x0104 => Self::RsaPkcs1Sha512,
            0x0201 => Self::EcdsaSha256,
            0x0202 => Self::EcdsaSha512,
            0x0301 => Self::DsaSha256,
            _ => Self::Unknown,
        }
    }

    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RsaPssSha256 => "RSASSA-PSS-SHA256",
            Self::RsaPssSha512 => "RSASSA-PSS-SHA512",
            Self::RsaPkcs1Sha256 => "RSASSA-PKCS1v1.5-SHA256",
            Self::RsaPkcs1Sha512 => "RSASSA-PKCS1v1.5-SHA512",
            Self::EcdsaSha256 => "ECDSA-SHA256",
            Self::EcdsaSha512 => "ECDSA-SHA512",
            Self::DsaSha256 => "DSA-SHA256",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub sha256_fingerprint: String,
    pub der_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerRecord {
    pub algorithms: Vec<SignatureAlgorithm>,
    pub certificates: Vec<SignerCertificate>,
    pub min_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeBlock {
    pub scheme: SignatureScheme,
    pub block_id: u32,
    pub signers: Vec<SignerRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApkSigningBlockReport {
    pub signing_block_present: bool,
    pub block_offset: u64,
    pub block_size: u64,
    pub block_ids: Vec<u32>,
    pub verity_padding_present: bool,
    pub schemes: Vec<SchemeBlock>,
}

impl ApkSigningBlockReport {
    #[inline]
    #[must_use]
    pub fn scheme(&self, scheme: SignatureScheme) -> Option<&SchemeBlock> {
        self.schemes
            .iter()
            .find(|s: &&SchemeBlock| s.scheme == scheme)
    }

    #[inline]
    #[must_use]
    pub fn has_scheme(&self, scheme: SignatureScheme) -> bool {
        self.scheme(scheme).is_some()
    }

    #[must_use]
    pub fn signer_fingerprints(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for scheme in &self.schemes {
            for signer in &scheme.signers {
                for cert in &signer.certificates {
                    out.push(cert.sha256_fingerprint.as_str());
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZipLayout {
    central_dir_offset: usize,
    eocd_offset: usize,
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < EOCD_MIN_LEN {
        return None;
    }
    let scan_start: usize = bytes.len().saturating_sub(EOCD_MIN_LEN + ZIP_MAX_COMMENT);
    let mut i: usize = bytes.len() - EOCD_MIN_LEN;
    loop {
        if bytes[i..i + 4] == EOCD_SIGNATURE {
            let comment_len: usize = u16::from_le_bytes([bytes[i + 20], bytes[i + 21]]) as usize;
            if i + EOCD_MIN_LEN + comment_len == bytes.len() {
                return Some(i);
            }
        }
        if i == scan_start {
            return None;
        }
        i -= 1;
    }
}

fn parse_zip_layout(bytes: &[u8]) -> Option<ZipLayout> {
    let eocd_offset: usize = find_eocd(bytes)?;
    let cd_offset: usize = u32::from_le_bytes(read4(bytes, eocd_offset + 16)?) as usize;
    if cd_offset > eocd_offset {
        return None;
    }
    Some(ZipLayout {
        central_dir_offset: cd_offset,
        eocd_offset,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SigningBlockLocation {
    block_start: usize,
    contents_start: usize,
    contents_end: usize,
}

fn locate_signing_block(bytes: &[u8], layout: ZipLayout) -> Option<SigningBlockLocation> {
    let cd_offset: usize = layout.central_dir_offset;
    if cd_offset < SIGNING_BLOCK_FOOTER {
        return None;
    }
    let footer_size_pos: usize = cd_offset - SIGNING_BLOCK_FOOTER;
    if bytes.get(footer_size_pos + 8..cd_offset)? != APK_SIG_BLOCK_MAGIC.as_slice() {
        return None;
    }
    let block_size_footer: u64 = u64::from_le_bytes(
        bytes
            .get(footer_size_pos..footer_size_pos + 8)?
            .try_into()
            .ok()?,
    );
    let block_size: usize = usize::try_from(block_size_footer).ok()?;
    if block_size < SIGNING_BLOCK_FOOTER || block_size > cd_offset {
        return None;
    }
    let block_start: usize = cd_offset - 8 - block_size;
    let header_size: u64 =
        u64::from_le_bytes(bytes.get(block_start..block_start + 8)?.try_into().ok()?);
    if usize::try_from(header_size).ok()? != block_size {
        return None;
    }
    Some(SigningBlockLocation {
        block_start,
        contents_start: block_start + 8,
        contents_end: footer_size_pos,
    })
}

fn parse_id_value_pairs(bytes: &[u8], loc: SigningBlockLocation) -> Option<BTreeMap<u32, Vec<u8>>> {
    let mut pairs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut cursor: usize = loc.contents_start;
    let mut seen: usize = 0;
    while cursor + 8 <= loc.contents_end {
        if seen >= MAX_PAIRS {
            break;
        }
        seen += 1;
        let pair_len: u64 = u64::from_le_bytes(bytes.get(cursor..cursor + 8)?.try_into().ok()?);
        let pair_len: usize = usize::try_from(pair_len).ok()?;
        if pair_len < 4 {
            return None;
        }
        let value_start: usize = cursor + 8 + 4;
        let pair_end: usize = cursor.checked_add(8)?.checked_add(pair_len)?;
        if pair_end > loc.contents_end || value_start > pair_end {
            return None;
        }
        let id: u32 = u32::from_le_bytes(read4(bytes, cursor + 8)?);
        pairs.insert(id, bytes.get(value_start..pair_end)?.to_vec());
        cursor = pair_end;
    }
    Some(pairs)
}

#[inline]
fn read4(bytes: &[u8], off: usize) -> Option<[u8; 4]> {
    bytes
        .get(off..off + 4)
        .and_then(|s: &[u8]| s.try_into().ok())
}

#[inline]
fn take_len_prefixed<'a>(buf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let start: usize = *cursor;
    if start + 4 > buf.len() {
        return None;
    }
    let len: usize = u32::from_le_bytes(buf[start..start + 4].try_into().ok()?) as usize;
    let value_start: usize = start + 4;
    let end: usize = value_start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    *cursor = end;
    Some(&buf[value_start..end])
}

fn parse_signer(signer: &[u8]) -> Option<SignerRecord> {
    let mut cursor: usize = 0;
    let signed_data: &[u8] = take_len_prefixed(signer, &mut cursor)?;
    let mut sd_cursor: usize = 0;

    let digests_seq: &[u8] = take_len_prefixed(signed_data, &mut sd_cursor)?;
    let mut algorithms: Vec<SignatureAlgorithm> = Vec::new();
    let mut dc: usize = 0;
    while dc < digests_seq.len() {
        if algorithms.len() >= MAX_DIGESTS_PER_SIGNER {
            break;
        }
        let entry: &[u8] = take_len_prefixed(digests_seq, &mut dc)?;
        if entry.len() < 4 {
            return None;
        }
        let alg_id: u32 = u32::from_le_bytes(entry[..4].try_into().ok()?);
        algorithms.push(SignatureAlgorithm::from_id(alg_id));
    }

    let certs_seq: &[u8] = take_len_prefixed(signed_data, &mut sd_cursor)?;
    let mut certificates: Vec<SignerCertificate> = Vec::new();
    let mut cc: usize = 0;
    while cc < certs_seq.len() {
        if certificates.len() >= MAX_CERTS_PER_SIGNER {
            break;
        }
        let cert: &[u8] = take_len_prefixed(certs_seq, &mut cc)?;
        certificates.push(parse_certificate(cert));
    }

    let (min_sdk, max_sdk): (Option<u32>, Option<u32>) =
        parse_signed_data_sdks(signed_data, &mut sd_cursor);

    Some(SignerRecord {
        algorithms,
        certificates,
        min_sdk,
        max_sdk,
    })
}

fn parse_signed_data_sdks(signed_data: &[u8], cursor: &mut usize) -> (Option<u32>, Option<u32>) {
    let _attributes: Option<&[u8]> = take_len_prefixed(signed_data, cursor);
    let start: usize = *cursor;
    if start + 8 <= signed_data.len() {
        let min: u32 =
            u32::from_le_bytes(signed_data[start..start + 4].try_into().unwrap_or([0u8; 4]));
        let max: u32 = u32::from_le_bytes(
            signed_data[start + 4..start + 8]
                .try_into()
                .unwrap_or([0u8; 4]),
        );
        (Some(min), Some(max))
    } else {
        (None, None)
    }
}

fn parse_scheme(scheme: SignatureScheme, value: &[u8]) -> Option<SchemeBlock> {
    let mut cursor: usize = 0;
    let signers_seq: &[u8] = take_len_prefixed(value, &mut cursor)?;
    let mut signers: Vec<SignerRecord> = Vec::new();
    let mut sc: usize = 0;
    while sc < signers_seq.len() {
        if signers.len() >= MAX_SIGNERS {
            break;
        }
        let Some(signer): Option<&[u8]> = take_len_prefixed(signers_seq, &mut sc) else {
            break;
        };
        if let Some(record) = parse_signer(signer) {
            signers.push(record);
        }
    }
    Some(SchemeBlock {
        scheme,
        block_id: scheme.block_id(),
        signers,
    })
}

#[must_use]
pub fn parse(bytes: &[u8]) -> ApkSigningBlockReport {
    let mut report: ApkSigningBlockReport = ApkSigningBlockReport::default();
    let Some(layout): Option<ZipLayout> = parse_zip_layout(bytes) else {
        return report;
    };
    let Some(loc): Option<SigningBlockLocation> = locate_signing_block(bytes, layout) else {
        return report;
    };
    let Some(pairs): Option<BTreeMap<u32, Vec<u8>>> = parse_id_value_pairs(bytes, loc) else {
        return report;
    };

    report.signing_block_present = true;
    report.block_offset = loc.block_start as u64;
    report.block_size = (loc.contents_end + 8 - loc.block_start) as u64;
    report.block_ids = pairs.keys().copied().collect();
    report.verity_padding_present = pairs.contains_key(&VERITY_PADDING_BLOCK_ID);

    for scheme in [
        SignatureScheme::V2,
        SignatureScheme::V3,
        SignatureScheme::V3_1,
    ] {
        if let Some(value) = pairs.get(&scheme.block_id())
            && let Some(block) = parse_scheme(scheme, value)
        {
            report.schemes.push(block);
        }
    }
    report
}

fn parse_certificate(cert_der: &[u8]) -> SignerCertificate {
    let sha256_fingerprint: String = sha256_hex(cert_der);
    let der_len: usize = cert_der.len();
    let (subject, issuer, serial_hex): (String, String, String) =
        der::parse_tbs_identity(cert_der).unwrap_or_default();
    SignerCertificate {
        subject,
        issuer,
        serial_hex,
        sha256_fingerprint,
        der_len,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out: String = String::with_capacity(64);
    for b in digest {
        push_lower_hex_byte(&mut out, b);
    }
    out
}

mod der {
    const TAG_INTEGER: u8 = 0x02;
    const TAG_OID: u8 = 0x06;
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_SET: u8 = 0x31;
    const CLASS_CONTEXT: u8 = 0x80;
    const MAX_LEN_BYTES: usize = 4;

    struct Tlv<'a> {
        tag: u8,
        content: &'a [u8],
        total_len: usize,
    }

    fn read_tlv(buf: &[u8]) -> Option<Tlv<'_>> {
        let tag: u8 = *buf.first()?;
        let len_byte: u8 = *buf.get(1)?;
        let (len, header_len): (usize, usize) = if len_byte & 0x80 == 0 {
            (usize::from(len_byte), 2)
        } else {
            let num_bytes: usize = usize::from(len_byte & 0x7F);
            if num_bytes == 0 || num_bytes > MAX_LEN_BYTES {
                return None;
            }
            let mut len: usize = 0;
            for i in 0..num_bytes {
                len = (len << 8) | usize::from(*buf.get(2 + i)?);
            }
            (len, 2 + num_bytes)
        };
        let end: usize = header_len.checked_add(len)?;
        let content: &[u8] = buf.get(header_len..end)?;
        Some(Tlv {
            tag,
            content,
            total_len: end,
        })
    }

    struct SeqReader<'a> {
        rest: &'a [u8],
    }

    impl<'a> SeqReader<'a> {
        const fn new(content: &'a [u8]) -> Self {
            Self { rest: content }
        }

        fn next(&mut self) -> Option<Tlv<'a>> {
            if self.rest.is_empty() {
                return None;
            }
            let tlv: Tlv<'a> = read_tlv(self.rest)?;
            self.rest = self.rest.get(tlv.total_len..)?;
            Some(tlv)
        }
    }

    pub(super) fn parse_tbs_identity(cert_der: &[u8]) -> Option<(String, String, String)> {
        let certificate: Tlv<'_> = read_tlv(cert_der)?;
        if certificate.tag != TAG_SEQUENCE {
            return None;
        }
        let mut top: SeqReader<'_> = SeqReader::new(certificate.content);
        let tbs: Tlv<'_> = top.next()?;
        if tbs.tag != TAG_SEQUENCE {
            return None;
        }
        let mut tbs_reader: SeqReader<'_> = SeqReader::new(tbs.content);
        let mut first: Tlv<'_> = tbs_reader.next()?;
        if first.tag & CLASS_CONTEXT != 0 {
            first = tbs_reader.next()?;
        }
        let serial_hex: String = if first.tag == TAG_INTEGER {
            hex_upper(first.content)
        } else {
            String::new()
        };
        let _signature: Tlv<'_> = tbs_reader.next()?;
        let issuer_tlv: Tlv<'_> = tbs_reader.next()?;
        let _validity: Tlv<'_> = tbs_reader.next()?;
        let subject_tlv: Tlv<'_> = tbs_reader.next()?;
        let issuer: String = parse_name(issuer_tlv.content);
        let subject: String = parse_name(subject_tlv.content);
        Some((subject, issuer, serial_hex))
    }

    fn parse_name(name_content: &[u8]) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut rdns: SeqReader<'_> = SeqReader::new(name_content);
        while let Some(rdn) = rdns.next() {
            if rdn.tag != TAG_SET {
                continue;
            }
            let mut atvs: SeqReader<'_> = SeqReader::new(rdn.content);
            while let Some(atv) = atvs.next() {
                if atv.tag != TAG_SEQUENCE {
                    continue;
                }
                if let Some((key, value)) = parse_attribute_type_value(atv.content) {
                    parts.push(format!("{key}={value}"));
                }
            }
        }
        parts.reverse();
        parts.join(",")
    }

    fn parse_attribute_type_value(content: &[u8]) -> Option<(String, String)> {
        let mut reader: SeqReader<'_> = SeqReader::new(content);
        let oid_tlv: Tlv<'_> = reader.next()?;
        if oid_tlv.tag != TAG_OID {
            return None;
        }
        let value_tlv: Tlv<'_> = reader.next()?;
        let key: String = oid_short_name(oid_tlv.content);
        let value: String = String::from_utf8_lossy(value_tlv.content).into_owned();
        Some((key, value))
    }

    fn oid_short_name(oid: &[u8]) -> String {
        match oid {
            [0x55, 0x04, 0x03] => "CN".to_owned(),
            [0x55, 0x04, 0x04] => "SN".to_owned(),
            [0x55, 0x04, 0x06] => "C".to_owned(),
            [0x55, 0x04, 0x07] => "L".to_owned(),
            [0x55, 0x04, 0x08] => "ST".to_owned(),
            [0x55, 0x04, 0x0A] => "O".to_owned(),
            [0x55, 0x04, 0x0B] => "OU".to_owned(),
            [0x55, 0x04, 0x05] => "SERIALNUMBER".to_owned(),
            [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01] => "UID".to_owned(),
            [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => "EMAILADDRESS".to_owned(),
            other => oid_to_dotted(other),
        }
    }

    fn oid_to_dotted(oid: &[u8]) -> String {
        if oid.is_empty() {
            return String::new();
        }
        let first: u32 = u32::from(oid[0]);
        let mut nums: Vec<u32> = vec![first / 40, first % 40];
        let mut acc: u32 = 0;
        for &b in &oid[1..] {
            acc = (acc << 7) | u32::from(b & 0x7F);
            if b & 0x80 == 0 {
                nums.push(acc);
                acc = 0;
            }
        }
        nums.iter()
            .map(u32::to_string)
            .collect::<Vec<String>>()
            .join(".")
    }

    fn hex_upper(data: &[u8]) -> String {
        let mut out: String = String::with_capacity(data.len() * 2);
        for b in data {
            super::push_lower_hex_byte(&mut out, *b);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_id_mapping() {
        assert_eq!(
            SignatureAlgorithm::from_id(0x0103),
            SignatureAlgorithm::RsaPkcs1Sha256
        );
        assert_eq!(
            SignatureAlgorithm::from_id(0x0201),
            SignatureAlgorithm::EcdsaSha256
        );
        assert_eq!(
            SignatureAlgorithm::from_id(0xdead),
            SignatureAlgorithm::Unknown
        );
    }

    #[test]
    fn scheme_block_ids_are_canonical() {
        assert_eq!(SignatureScheme::V2.block_id(), 0x7109_871a);
        assert_eq!(SignatureScheme::V3.block_id(), 0xf053_68c0);
        assert_eq!(SignatureScheme::V3_1.block_id(), 0x1b93_ad61);
    }

    #[test]
    fn non_zip_yields_empty_report() {
        let report: ApkSigningBlockReport = parse(b"definitely not a zip");
        assert!(!report.signing_block_present);
        assert!(report.schemes.is_empty());
    }

    #[test]
    fn truncated_len_prefix_is_none() {
        let buf: [u8; 2] = [0x04, 0x00];
        let mut cursor: usize = 0;
        assert!(take_len_prefixed(&buf, &mut cursor).is_none());
    }

    #[test]
    fn len_prefix_overrun_is_none() {
        let buf: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00];
        let mut cursor: usize = 0;
        assert!(take_len_prefixed(&buf, &mut cursor).is_none());
    }
}
