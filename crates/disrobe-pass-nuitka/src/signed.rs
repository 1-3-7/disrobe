use serde::Serialize;

use crate::error::{Error, Result};

const PE_MAGIC: &[u8; 2] = b"MZ";
const PE_NT_MAGIC: u32 = 0x0000_4550u32;
const OPTIONAL_HEADER_MAGIC_PE32: u16 = 0x010Bu16;
const OPTIONAL_HEADER_MAGIC_PE32PLUS: u16 = 0x020Bu16;
const SECURITY_DIRECTORY_INDEX: usize = 4usize;
const MIN_WIN_CERT_HEADER: usize = 8usize;
const PKCS7_SIGNED_DATA_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateRevision {
    Unknown,
    V1_0,
    V2_0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateType {
    Unknown,
    X509,
    PkcsSignedData,
    Reserved1,
    TsStackSigned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticodeSummary {
    pub cert_table_file_offset: u32,
    pub cert_table_size: u32,
    pub revision: CertificateRevision,
    pub cert_type: CertificateType,
    pub looks_like_pkcs7: bool,
    pub trailing_payload_offset: u64,
}

pub fn detect_authenticode(image: &[u8]) -> Result<Option<AuthenticodeSummary>> {
    let Some(pe): Option<PeHeaders<'_>> = parse_pe_headers(image)? else {
        return Ok(None);
    };
    let cert_dir: DataDirectory = pe.security_directory;
    if cert_dir.virtual_address == 0 || cert_dir.size == 0 {
        return Ok(None);
    }
    let file_off: usize = usize::try_from(cert_dir.virtual_address)
        .map_err(|_| Error::ObjectParse("cert va overflow".to_owned()))?;
    let size: usize = usize::try_from(cert_dir.size)
        .map_err(|_| Error::ObjectParse("cert size overflow".to_owned()))?;
    let end: usize = file_off
        .checked_add(size)
        .ok_or_else(|| Error::ObjectParse("cert end overflow".to_owned()))?;
    if end > image.len() || size < MIN_WIN_CERT_HEADER {
        return Ok(None);
    }
    let slice: &[u8] = &image[file_off..end];
    let length: u32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    let revision_raw: u16 = u16::from_le_bytes([slice[4], slice[5]]);
    let cert_type_raw: u16 = u16::from_le_bytes([slice[6], slice[7]]);
    let revision: CertificateRevision = match revision_raw {
        0x0100u16 => CertificateRevision::V1_0,
        0x0200u16 => CertificateRevision::V2_0,
        _ => CertificateRevision::Unknown,
    };
    let cert_type: CertificateType = match cert_type_raw {
        0x0001u16 => CertificateType::X509,
        0x0002u16 => CertificateType::PkcsSignedData,
        0x0003u16 => CertificateType::Reserved1,
        0x0004u16 => CertificateType::TsStackSigned,
        _ => CertificateType::Unknown,
    };
    let cert_body: &[u8] = if slice.len() > MIN_WIN_CERT_HEADER {
        &slice[MIN_WIN_CERT_HEADER..]
    } else {
        &[]
    };
    let looks_like_pkcs7: bool = scan_for_pkcs7_oid(cert_body);
    Ok(Some(AuthenticodeSummary {
        cert_table_file_offset: cert_dir.virtual_address,
        cert_table_size: length,
        revision,
        cert_type,
        looks_like_pkcs7,
        trailing_payload_offset: u64::from(cert_dir.virtual_address) + u64::from(cert_dir.size),
    }))
}

pub fn strip_authenticode<'a>(image: &'a [u8], summary: &AuthenticodeSummary) -> Result<&'a [u8]> {
    let off: usize = usize::try_from(summary.cert_table_file_offset)
        .map_err(|_| Error::ObjectParse("cert off overflow".to_owned()))?;
    if off > image.len() {
        return Err(Error::ObjectParse("cert offset out of bounds".to_owned()));
    }
    Ok(&image[..off])
}

#[derive(Debug, Clone, Copy)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

struct PeHeaders<'a> {
    #[allow(dead_code)]
    image: &'a [u8],
    security_directory: DataDirectory,
}

fn parse_pe_headers(image: &[u8]) -> Result<Option<PeHeaders<'_>>> {
    if image.len() < 0x40 || &image[0..2] != PE_MAGIC {
        return Ok(None);
    }
    let e_lfanew: u32 = u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]);
    let pe_off: usize = usize::try_from(e_lfanew)
        .map_err(|_| Error::ObjectParse("e_lfanew overflow".to_owned()))?;
    if pe_off
        .checked_add(0x18)
        .is_none_or(|end: usize| end > image.len())
    {
        return Ok(None);
    }
    let nt_magic: u32 = u32::from_le_bytes([
        image[pe_off],
        image[pe_off + 1],
        image[pe_off + 2],
        image[pe_off + 3],
    ]);
    if nt_magic != PE_NT_MAGIC {
        return Ok(None);
    }
    let size_of_optional_header: u16 =
        u16::from_le_bytes([image[pe_off + 0x14], image[pe_off + 0x15]]);
    let optional_off: usize = pe_off + 0x18;
    if optional_off + usize::from(size_of_optional_header) > image.len()
        || size_of_optional_header < 0x70
    {
        return Ok(None);
    }
    let magic: u16 = u16::from_le_bytes([image[optional_off], image[optional_off + 1]]);
    let data_dirs_off: usize = match magic {
        OPTIONAL_HEADER_MAGIC_PE32 => optional_off + 0x60,
        OPTIONAL_HEADER_MAGIC_PE32PLUS => optional_off + 0x70,
        _ => return Ok(None),
    };
    let num_dirs_off: usize = data_dirs_off.saturating_sub(4);
    let number_of_rva_and_sizes: u32 = u32::from_le_bytes([
        image[num_dirs_off],
        image[num_dirs_off + 1],
        image[num_dirs_off + 2],
        image[num_dirs_off + 3],
    ]);
    let security_index: u32 = u32::try_from(SECURITY_DIRECTORY_INDEX)
        .map_err(|_| Error::ObjectParse("security index overflow".to_owned()))?;
    if security_index >= number_of_rva_and_sizes {
        return Ok(None);
    }
    let dir_off: usize = data_dirs_off + SECURITY_DIRECTORY_INDEX * 8;
    if dir_off + 8 > image.len() {
        return Ok(None);
    }
    let virtual_address: u32 = u32::from_le_bytes([
        image[dir_off],
        image[dir_off + 1],
        image[dir_off + 2],
        image[dir_off + 3],
    ]);
    let size: u32 = u32::from_le_bytes([
        image[dir_off + 4],
        image[dir_off + 5],
        image[dir_off + 6],
        image[dir_off + 7],
    ]);
    Ok(Some(PeHeaders {
        image,
        security_directory: DataDirectory {
            virtual_address,
            size,
        },
    }))
}

fn scan_for_pkcs7_oid(body: &[u8]) -> bool {
    if body.len() < PKCS7_SIGNED_DATA_OID_DER.len() {
        return false;
    }
    let needle: &[u8] = PKCS7_SIGNED_DATA_OID_DER;
    body.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    fn build_minimal_pe(cert_va: u32, cert_size: u32, cert_blob: &[u8]) -> Vec<u8> {
        let mut image: Vec<u8> = vec![0u8; 0x600];
        image[0..2].copy_from_slice(b"MZ");
        let e_lfanew: u32 = 0x80u32;
        image[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        image[pe_off..pe_off + 4].copy_from_slice(&PE_NT_MAGIC.to_le_bytes());
        image[pe_off + 0x14..pe_off + 0x16].copy_from_slice(&0x00F0u16.to_le_bytes());
        let opt_off: usize = pe_off + 0x18;
        image[opt_off..opt_off + 2].copy_from_slice(&OPTIONAL_HEADER_MAGIC_PE32PLUS.to_le_bytes());
        let num_dirs_off: usize = opt_off + 0x70 - 4;
        image[num_dirs_off..num_dirs_off + 4].copy_from_slice(&16u32.to_le_bytes());
        let data_dirs_off: usize = opt_off + 0x70;
        let dir_off: usize = data_dirs_off + SECURITY_DIRECTORY_INDEX * 8;
        image[dir_off..dir_off + 4].copy_from_slice(&cert_va.to_le_bytes());
        image[dir_off + 4..dir_off + 8].copy_from_slice(&cert_size.to_le_bytes());
        if !cert_blob.is_empty() && cert_va as usize + cert_blob.len() <= image.len() {
            image[cert_va as usize..cert_va as usize + cert_blob.len()].copy_from_slice(cert_blob);
        }
        image
    }

    fn build_win_cert(length: u32, revision: u16, cert_type: u16, body: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(MIN_WIN_CERT_HEADER + body.len());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&revision.to_le_bytes());
        out.extend_from_slice(&cert_type.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn non_pe_returns_none() {
        let bytes: [u8; 16] = [0u8; 16];
        let res: Option<AuthenticodeSummary> = detect_authenticode(&bytes).expect("ok");
        assert!(res.is_none());
    }

    #[test]
    fn pe_without_cert_directory_returns_none() {
        let image: Vec<u8> = build_minimal_pe(0, 0, &[]);
        assert!(detect_authenticode(&image).expect("ok").is_none());
    }

    #[test]
    fn pe_with_v2_pkcs7_cert_detected() {
        let body_with_oid: Vec<u8> =
            [&[0u8; 32][..], PKCS7_SIGNED_DATA_OID_DER, &[0u8; 16][..]].concat();
        let cert_size: u32 = MIN_WIN_CERT_HEADER as u32 + body_with_oid.len() as u32;
        let cert_blob: Vec<u8> = build_win_cert(cert_size, 0x0200, 0x0002, &body_with_oid);
        let cert_va: u32 = 0x300u32;
        let image: Vec<u8> = build_minimal_pe(cert_va, cert_size, &cert_blob);
        let summary: AuthenticodeSummary =
            detect_authenticode(&image).expect("ok").expect("present");
        assert_eq!(summary.cert_table_file_offset, cert_va);
        assert_eq!(summary.cert_table_size, cert_size);
        assert_eq!(summary.revision, CertificateRevision::V2_0);
        assert_eq!(summary.cert_type, CertificateType::PkcsSignedData);
        assert!(summary.looks_like_pkcs7);
        assert_eq!(
            summary.trailing_payload_offset,
            u64::from(cert_va) + u64::from(cert_size)
        );
    }

    #[test]
    fn strip_authenticode_truncates_at_cert_offset() {
        let body: Vec<u8> = vec![0u8; 32];
        let cert_size: u32 = MIN_WIN_CERT_HEADER as u32 + body.len() as u32;
        let cert_blob: Vec<u8> = build_win_cert(cert_size, 0x0200, 0x0001, &body);
        let cert_va: u32 = 0x280u32;
        let image: Vec<u8> = build_minimal_pe(cert_va, cert_size, &cert_blob);
        let summary: AuthenticodeSummary =
            detect_authenticode(&image).expect("ok").expect("present");
        let stripped: &[u8] = strip_authenticode(&image, &summary).expect("strip");
        assert_eq!(stripped.len(), cert_va as usize);
    }

    #[test]
    fn unknown_revision_and_type_classify_as_unknown() {
        let cert_blob: Vec<u8> =
            build_win_cert(MIN_WIN_CERT_HEADER as u32, 0xABCDu16, 0x1234u16, &[]);
        let cert_va: u32 = 0x300u32;
        let image: Vec<u8> = build_minimal_pe(cert_va, MIN_WIN_CERT_HEADER as u32, &cert_blob);
        let summary: AuthenticodeSummary =
            detect_authenticode(&image).expect("ok").expect("present");
        assert_eq!(summary.revision, CertificateRevision::Unknown);
        assert_eq!(summary.cert_type, CertificateType::Unknown);
        assert!(!summary.looks_like_pkcs7);
    }
}
