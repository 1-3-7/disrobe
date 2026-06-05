use crate::error::{Error, Result};
use crate::static_unpack::bcdetect::WrapperMagic;

#[derive(Debug, Clone)]
pub struct HeaderMetadata {
    pub magic: WrapperMagic,
    pub raw_header: Vec<u8>,
    pub serial: Option<String>,
    pub python_major: Option<u8>,
    pub python_minor: Option<u8>,
    pub pyc_magic: Option<u16>,
    pub protection_type: Option<u8>,
    pub cipher_text_offset: Option<u32>,
    pub cipher_text_length: Option<u32>,
    pub nonce: Option<[u8; 12]>,
    pub next_segment_offset: Option<u32>,
}

const PY8_HEADER_LEN: usize = 64;
const V6_HEADER_LEN: usize = 20;

pub fn parse_header(bytes: &[u8], magic: WrapperMagic) -> Result<HeaderMetadata> {
    match magic {
        WrapperMagic::Py8Or9 => parse_py8_header(bytes),
        WrapperMagic::PyArmor6Or7 => parse_pyarmor_v6v7_header(bytes),
        WrapperMagic::LegacyDes | WrapperMagic::LegacyMixed | WrapperMagic::LegacyAesCbc => {
            Ok(HeaderMetadata {
                magic,
                raw_header: bytes[..bytes.len().min(64)].to_vec(),
                serial: None,
                python_major: None,
                python_minor: None,
                pyc_magic: None,
                protection_type: bytes.first().copied(),
                cipher_text_offset: None,
                cipher_text_length: None,
                nonce: None,
                next_segment_offset: None,
            })
        }
    }
}

fn parse_py8_header(bytes: &[u8]) -> Result<HeaderMetadata> {
    if bytes.len() < PY8_HEADER_LEN {
        return Err(Error::HeaderTruncated {
            need: PY8_HEADER_LEN,
            got: bytes.len(),
        });
    }
    let serial: String = core::str::from_utf8(&bytes[2..8])
        .map_err(|_e| {
            Error::BadV8Magic([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        })?
        .to_owned();
    let python_major: u8 = bytes[9];
    let python_minor: u8 = bytes[10];
    let pyc_magic: u16 = u16::from_le_bytes([bytes[12], bytes[13]]);
    let protection_type: u8 = bytes[20];
    let cipher_text_offset: u32 = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    let cipher_text_length: u32 = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
    let next_segment_offset: u32 = u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]);
    let mut nonce: [u8; 12] = [0u8; 12];
    nonce[..4].copy_from_slice(&bytes[36..40]);
    nonce[4..].copy_from_slice(&bytes[44..52]);
    Ok(HeaderMetadata {
        magic: WrapperMagic::Py8Or9,
        raw_header: bytes[..PY8_HEADER_LEN].to_vec(),
        serial: Some(serial),
        python_major: Some(python_major),
        python_minor: Some(python_minor),
        pyc_magic: Some(pyc_magic),
        protection_type: Some(protection_type),
        cipher_text_offset: Some(cipher_text_offset),
        cipher_text_length: Some(cipher_text_length),
        nonce: Some(nonce),
        next_segment_offset: Some(next_segment_offset),
    })
}

fn parse_pyarmor_v6v7_header(bytes: &[u8]) -> Result<HeaderMetadata> {
    if bytes.len() < V6_HEADER_LEN {
        return Err(Error::HeaderTruncated {
            need: V6_HEADER_LEN,
            got: bytes.len(),
        });
    }
    let python_major: u8 = bytes[9];
    let python_minor: u8 = bytes[10];
    let pyc_magic: u16 = u16::from_le_bytes([bytes[12], bytes[13]]);
    Ok(HeaderMetadata {
        magic: WrapperMagic::PyArmor6Or7,
        raw_header: bytes[..V6_HEADER_LEN].to_vec(),
        serial: None,
        python_major: Some(python_major),
        python_minor: Some(python_minor),
        pyc_magic: Some(pyc_magic),
        protection_type: None,
        cipher_text_offset: Some(16u32),
        cipher_text_length: Some(u32::try_from(bytes.len().saturating_sub(16)).unwrap_or(u32::MAX)),
        nonce: None,
        next_segment_offset: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_v8_header() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..8].copy_from_slice(b"PY008106");
        bytes[9] = 3;
        bytes[10] = 11;
        bytes[12] = 0xa7;
        bytes[13] = 0x0d;
        bytes[20] = 0x08;
        bytes[28..32].copy_from_slice(&64u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&256u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&[1, 2, 3, 4]);
        bytes[44..52].copy_from_slice(&[5, 6, 7, 8, 9, 10, 11, 12]);
        let header: HeaderMetadata = parse_header(&bytes, WrapperMagic::Py8Or9).unwrap();
        assert_eq!(header.serial.as_deref(), Some("008106"));
        assert_eq!(header.python_major, Some(3));
        assert_eq!(header.python_minor, Some(11));
        assert_eq!(header.protection_type, Some(0x08));
        assert_eq!(header.cipher_text_offset, Some(64));
        assert_eq!(header.cipher_text_length, Some(256));
        assert_eq!(header.nonce.unwrap()[..4], [1, 2, 3, 4]);
        assert_eq!(header.nonce.unwrap()[4..], [5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn parse_v6v7_header_basic() {
        let mut bytes: Vec<u8> = vec![0u8; 32];
        bytes[..8].copy_from_slice(b"PYARMOR\0");
        bytes[9] = 3;
        bytes[10] = 7;
        bytes[12] = 0x42;
        bytes[13] = 0x0d;
        let header: HeaderMetadata = parse_header(&bytes, WrapperMagic::PyArmor6Or7).unwrap();
        assert_eq!(header.python_major, Some(3));
        assert_eq!(header.python_minor, Some(7));
        assert_eq!(header.cipher_text_offset, Some(16));
    }

    #[test]
    fn parse_truncated_v8_fails() {
        let bytes: Vec<u8> = b"PY009070".to_vec();
        let err: Error = parse_header(&bytes, WrapperMagic::Py8Or9).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { .. }));
    }
}
