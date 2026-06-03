#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

pub const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

pub const APK_SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109_871a;
pub const APK_SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf053_68c0;
pub const APK_SIGNATURE_SCHEME_V3_1_BLOCK_ID: u32 = 0x1b93_ad61;
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x4272_6577;

const CHUNK_SIZE: usize = 1024 * 1024;
const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const EOCD_MIN_LEN: usize = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SignatureScheme {
    V1JarSigning,
    V2,
    V3,
    V3_1,
    V4,
}

impl SignatureScheme {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V1JarSigning => "v1 (JAR signing)",
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V3_1 => "v3.1",
            Self::V4 => "v4",
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
}

impl SignatureAlgorithm {
    #[inline]
    #[must_use]
    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            0x0101 => Some(Self::RsaPssSha256),
            0x0102 => Some(Self::RsaPssSha512),
            0x0103 => Some(Self::RsaPkcs1Sha256),
            0x0104 => Some(Self::RsaPkcs1Sha512),
            0x0201 => Some(Self::EcdsaSha256),
            0x0202 => Some(Self::EcdsaSha512),
            0x0301 => Some(Self::DsaSha256),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn content_digest_is_sha512(self) -> bool {
        matches!(
            self,
            Self::RsaPssSha512 | Self::RsaPkcs1Sha512 | Self::EcdsaSha512
        )
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerDigest {
    pub algorithm: SignatureAlgorithm,
    pub signed_digest: Vec<u8>,
    pub computed_digest: Vec<u8>,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeReport {
    pub scheme: SignatureScheme,
    pub signer_count: usize,
    pub digests: Vec<SignerDigest>,
    pub certificate_count: usize,
    pub integrity_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApkSignatureReport {
    pub v1_present: bool,
    pub v1_entries: BTreeSet<String>,
    pub schemes: Vec<SchemeReport>,
    pub overall_integrity_verified: bool,
    pub notes: Vec<String>,
}

impl ApkSignatureReport {
    #[inline]
    #[must_use]
    pub fn scheme(&self, scheme: SignatureScheme) -> Option<&SchemeReport> {
        self.schemes
            .iter()
            .find(|s: &&SchemeReport| s.scheme == scheme)
    }

    #[inline]
    #[must_use]
    pub fn has_scheme(&self, scheme: SignatureScheme) -> bool {
        self.scheme(scheme).is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZipLayout {
    central_dir_offset: usize,
    central_dir_size: usize,
    eocd_offset: usize,
}

fn find_eocd(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < EOCD_MIN_LEN {
        return Err(Error::Zip("file too small for EOCD".to_string()));
    }
    let scan_start: usize = bytes.len().saturating_sub(EOCD_MIN_LEN + 0xFFFF);
    let mut i: usize = bytes.len() - EOCD_MIN_LEN;
    loop {
        if bytes[i..i + 4] == EOCD_SIGNATURE {
            let comment_len: usize = u16::from_le_bytes([bytes[i + 20], bytes[i + 21]]) as usize;
            if i + EOCD_MIN_LEN + comment_len == bytes.len() {
                return Ok(i);
            }
        }
        if i == scan_start {
            break;
        }
        i -= 1;
    }
    Err(Error::Zip(
        "end-of-central-directory record not found".to_string(),
    ))
}

fn parse_zip_layout(bytes: &[u8]) -> Result<ZipLayout> {
    let eocd_offset: usize = find_eocd(bytes)?;
    let cd_size: usize = u32::from_le_bytes(read4(bytes, eocd_offset + 12)?) as usize;
    let cd_offset: usize = u32::from_le_bytes(read4(bytes, eocd_offset + 16)?) as usize;
    if cd_offset > eocd_offset || cd_offset.saturating_add(cd_size) > bytes.len() {
        return Err(Error::Zip(
            "central directory offset out of range".to_string(),
        ));
    }
    Ok(ZipLayout {
        central_dir_offset: cd_offset,
        central_dir_size: cd_size,
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
    if cd_offset < 24 {
        return None;
    }
    let footer_size_pos: usize = cd_offset - 24;
    if &bytes[footer_size_pos + 8..cd_offset] != APK_SIG_BLOCK_MAGIC {
        return None;
    }
    let block_size_footer: u64 = u64::from_le_bytes(
        bytes[footer_size_pos..footer_size_pos + 8]
            .try_into()
            .ok()?,
    );
    let block_size: usize = usize::try_from(block_size_footer).ok()?;
    if block_size < 24 || block_size > cd_offset {
        return None;
    }
    let block_start: usize = cd_offset - 8 - block_size;
    let header_size: u64 = u64::from_le_bytes(bytes[block_start..block_start + 8].try_into().ok()?);
    if usize::try_from(header_size).ok()? != block_size {
        return None;
    }
    Some(SigningBlockLocation {
        block_start,
        contents_start: block_start + 8,
        contents_end: footer_size_pos,
    })
}

fn parse_id_value_pairs(bytes: &[u8], loc: SigningBlockLocation) -> Result<BTreeMap<u32, Vec<u8>>> {
    let mut pairs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut cursor: usize = loc.contents_start;
    while cursor + 8 <= loc.contents_end {
        let pair_len: u64 = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| Error::Zip("signing block pair length truncated".to_string()))?,
        );
        let pair_len: usize = usize::try_from(pair_len)
            .map_err(|_| Error::Zip("signing block pair length overflow".to_string()))?;
        if pair_len < 4 {
            return Err(Error::Zip("signing block pair too short".to_string()));
        }
        let value_start: usize = cursor + 8 + 4;
        let pair_end: usize = cursor + 8 + pair_len;
        if pair_end > loc.contents_end || value_start > pair_end {
            return Err(Error::Zip("signing block pair overruns block".to_string()));
        }
        let id: u32 = u32::from_le_bytes(read4(bytes, cursor + 8)?);
        pairs.insert(id, bytes[value_start..pair_end].to_vec());
        cursor = pair_end;
    }
    Ok(pairs)
}

#[inline]
fn chunk_digest_sha256(prefix: u8, chunk: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update([prefix]);
    hasher.update((chunk.len() as u32).to_le_bytes());
    hasher.update(chunk);
    hasher.finalize().into()
}

#[inline]
fn chunk_digest_sha512(prefix: u8, chunk: &[u8]) -> [u8; 64] {
    let mut hasher: Sha512 = Sha512::new();
    hasher.update([prefix]);
    hasher.update((chunk.len() as u32).to_le_bytes());
    hasher.update(chunk);
    let out: [u8; 64] = hasher.finalize().into();
    out
}

fn collect_chunks(bytes: &[u8], block_start: usize, layout: ZipLayout) -> [&[u8]; 3] {
    let section1: &[u8] = &bytes[..block_start];
    let section_cd: &[u8] =
        &bytes[layout.central_dir_offset..layout.central_dir_offset + layout.central_dir_size];
    let section_eocd: &[u8] = &bytes[layout.eocd_offset..];
    [section1, section_cd, section_eocd]
}

fn patched_eocd(eocd: &[u8], block_start: usize) -> Vec<u8> {
    let mut out: Vec<u8> = eocd.to_vec();
    if out.len() >= 20 {
        out[16..20].copy_from_slice(&(block_start as u32).to_le_bytes());
    }
    out
}

fn compute_content_digest_sha256(bytes: &[u8], block_start: usize, layout: ZipLayout) -> [u8; 32] {
    let [section1, section_cd, eocd_raw]: [&[u8]; 3] = collect_chunks(bytes, block_start, layout);
    let eocd_patched: Vec<u8> = patched_eocd(eocd_raw, block_start);
    let mut chunk_digests: Vec<u8> = Vec::new();
    let mut chunk_count: u32 = 0;
    for section in [section1, section_cd, eocd_patched.as_slice()] {
        for chunk in section.chunks(CHUNK_SIZE) {
            chunk_digests.extend_from_slice(&chunk_digest_sha256(0xa5, chunk));
            chunk_count += 1;
        }
    }
    let mut top: Sha256 = Sha256::new();
    top.update([0x5a]);
    top.update(chunk_count.to_le_bytes());
    top.update(&chunk_digests);
    top.finalize().into()
}

fn compute_content_digest_sha512(bytes: &[u8], block_start: usize, layout: ZipLayout) -> [u8; 64] {
    let [section1, section_cd, eocd_raw]: [&[u8]; 3] = collect_chunks(bytes, block_start, layout);
    let eocd_patched: Vec<u8> = patched_eocd(eocd_raw, block_start);
    let mut chunk_digests: Vec<u8> = Vec::new();
    let mut chunk_count: u32 = 0;
    for section in [section1, section_cd, eocd_patched.as_slice()] {
        for chunk in section.chunks(CHUNK_SIZE) {
            chunk_digests.extend_from_slice(&chunk_digest_sha512(0xa5, chunk));
            chunk_count += 1;
        }
    }
    let mut top: Sha512 = Sha512::new();
    top.update([0x5a]);
    top.update(chunk_count.to_le_bytes());
    top.update(&chunk_digests);
    let out: [u8; 64] = top.finalize().into();
    out
}

#[inline]
fn read4(bytes: &[u8], off: usize) -> Result<[u8; 4]> {
    bytes
        .get(off..off + 4)
        .and_then(|s: &[u8]| s.try_into().ok())
        .ok_or_else(|| Error::Truncated {
            offset: off,
            needed: 4,
            had: bytes.len().saturating_sub(off),
        })
}

#[inline]
fn take_len_prefixed<'a>(buf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    if *cursor + 4 > buf.len() {
        return None;
    }
    let len: usize = u32::from_le_bytes(buf[*cursor..*cursor + 4].try_into().ok()?) as usize;
    *cursor += 4;
    if *cursor + len > buf.len() {
        return None;
    }
    let slice: &[u8] = &buf[*cursor..*cursor + len];
    *cursor += len;
    Some(slice)
}

struct ParsedSignerDigests {
    digests: Vec<(SignatureAlgorithm, Vec<u8>)>,
    certificate_count: usize,
}

fn parse_signer_block(signer: &[u8]) -> Option<ParsedSignerDigests> {
    let mut cursor: usize = 0;
    let signed_data: &[u8] = take_len_prefixed(signer, &mut cursor)?;
    let mut sd_cursor: usize = 0;
    let digests_seq: &[u8] = take_len_prefixed(signed_data, &mut sd_cursor)?;
    let mut digests: Vec<(SignatureAlgorithm, Vec<u8>)> = Vec::new();
    let mut dc: usize = 0;
    while dc < digests_seq.len() {
        let entry: &[u8] = take_len_prefixed(digests_seq, &mut dc)?;
        if entry.len() < 4 {
            return None;
        }
        let alg_id: u32 = u32::from_le_bytes(entry[..4].try_into().ok()?);
        let mut ec: usize = 4;
        let digest: &[u8] = take_len_prefixed(entry, &mut ec)?;
        if let Some(alg) = SignatureAlgorithm::from_id(alg_id) {
            digests.push((alg, digest.to_vec()));
        }
    }
    let certs_seq: &[u8] = take_len_prefixed(signed_data, &mut sd_cursor)?;
    let mut cc: usize = 0;
    let mut certificate_count: usize = 0;
    while cc < certs_seq.len() {
        let _cert: &[u8] = take_len_prefixed(certs_seq, &mut cc)?;
        certificate_count += 1;
    }
    Some(ParsedSignerDigests {
        digests,
        certificate_count,
    })
}

fn verify_scheme(
    bytes: &[u8],
    block_start: usize,
    layout: ZipLayout,
    scheme: SignatureScheme,
    value: &[u8],
) -> SchemeReport {
    let mut cursor: usize = 0;
    let mut signer_count: usize = 0;
    let mut digests_out: Vec<SignerDigest> = Vec::new();
    let mut certificate_count: usize = 0;
    if let Some(signers_seq) = take_len_prefixed(value, &mut cursor) {
        let mut sc: usize = 0;
        while sc < signers_seq.len() {
            let Some(signer): Option<&[u8]> = take_len_prefixed(signers_seq, &mut sc) else {
                break;
            };
            signer_count += 1;
            if let Some(parsed) = parse_signer_block(signer) {
                certificate_count += parsed.certificate_count;
                for (alg, signed_digest) in parsed.digests {
                    let computed: Vec<u8> = if alg.content_digest_is_sha512() {
                        compute_content_digest_sha512(bytes, block_start, layout).to_vec()
                    } else {
                        compute_content_digest_sha256(bytes, block_start, layout).to_vec()
                    };
                    let matches: bool = computed == signed_digest;
                    digests_out.push(SignerDigest {
                        algorithm: alg,
                        signed_digest,
                        computed_digest: computed,
                        matches,
                    });
                }
            }
        }
    }
    let integrity_verified: bool =
        !digests_out.is_empty() && digests_out.iter().all(|d: &SignerDigest| d.matches);
    SchemeReport {
        scheme,
        signer_count,
        digests: digests_out,
        certificate_count,
        integrity_verified,
    }
}

pub fn verify(bytes: &[u8]) -> Result<ApkSignatureReport> {
    if bytes.len() < 4 || bytes[..4] != [0x50, 0x4b, 0x03, 0x04] {
        return Err(Error::Zip(
            "not a ZIP/APK archive (missing PK\\x03\\x04)".to_string(),
        ));
    }
    let layout: ZipLayout = parse_zip_layout(bytes)?;
    let mut report: ApkSignatureReport = ApkSignatureReport::default();

    let v1: V1Inventory = scan_v1_signing(bytes)?;
    report.v1_present = v1.has_manifest && !v1.signature_files.is_empty();
    for name in v1.signature_files {
        report.v1_entries.insert(name);
    }
    if report.v1_present {
        report
            .notes
            .push("v1 JAR signing present (META-INF .SF + .RSA/.DSA/.EC)".to_string());
    }

    let Some(loc): Option<SigningBlockLocation> = locate_signing_block(bytes, layout) else {
        if !report.v1_present {
            report
                .notes
                .push("no APK Signing Block and no v1 JAR signature found".to_string());
        }
        return Ok(report);
    };
    let pairs: BTreeMap<u32, Vec<u8>> = parse_id_value_pairs(bytes, loc)?;
    for (scheme, id) in [
        (SignatureScheme::V2, APK_SIGNATURE_SCHEME_V2_BLOCK_ID),
        (SignatureScheme::V3, APK_SIGNATURE_SCHEME_V3_BLOCK_ID),
        (SignatureScheme::V3_1, APK_SIGNATURE_SCHEME_V3_1_BLOCK_ID),
    ] {
        if let Some(value) = pairs.get(&id) {
            let sr: SchemeReport = verify_scheme(bytes, loc.block_start, layout, scheme, value);
            report.schemes.push(sr);
        }
    }

    let scheme_count: usize = report.schemes.len();
    let all_schemes_ok: bool = scheme_count > 0
        && report
            .schemes
            .iter()
            .all(|s: &SchemeReport| s.integrity_verified);
    report.overall_integrity_verified = all_schemes_ok || (scheme_count == 0 && report.v1_present);
    Ok(report)
}

struct V1Inventory {
    has_manifest: bool,
    signature_files: Vec<String>,
}

fn scan_v1_signing(bytes: &[u8]) -> Result<V1Inventory> {
    use std::io::Cursor;
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(|e| Error::Zip(e.to_string()))?;
    let mut has_manifest: bool = false;
    let mut signature_files: Vec<String> = Vec::new();
    for i in 0..zip.len() {
        let file: zip::read::ZipFile<'_> =
            zip.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
        let name: &str = file.name();
        if name == "META-INF/MANIFEST.MF" {
            has_manifest = true;
        }
        if name.starts_with("META-INF/")
            && (name.ends_with(".SF")
                || name.ends_with(".RSA")
                || name.ends_with(".DSA")
                || name.ends_with(".EC"))
        {
            signature_files.push(name.to_string());
        }
    }
    Ok(V1Inventory {
        has_manifest,
        signature_files,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_id_mapping() {
        assert_eq!(
            SignatureAlgorithm::from_id(0x0103),
            Some(SignatureAlgorithm::RsaPkcs1Sha256)
        );
        assert_eq!(
            SignatureAlgorithm::from_id(0x0201),
            Some(SignatureAlgorithm::EcdsaSha256)
        );
        assert_eq!(SignatureAlgorithm::from_id(0xdead), None);
    }

    #[test]
    fn sha512_algorithms_flagged() {
        assert!(SignatureAlgorithm::RsaPkcs1Sha512.content_digest_is_sha512());
        assert!(SignatureAlgorithm::EcdsaSha512.content_digest_is_sha512());
        assert!(!SignatureAlgorithm::EcdsaSha256.content_digest_is_sha512());
    }

    #[test]
    fn rejects_non_zip() {
        let err: Error = verify(b"not a zip at all").expect_err("must reject");
        assert!(matches!(err, Error::Zip(_)));
    }

    #[test]
    fn chunk_digest_is_deterministic() {
        let a: [u8; 32] = chunk_digest_sha256(0xa5, b"hello");
        let b: [u8; 32] = chunk_digest_sha256(0xa5, b"hello");
        assert_eq!(a, b);
        let c: [u8; 32] = chunk_digest_sha256(0xa5, b"hellp");
        assert_ne!(a, c);
    }
}
