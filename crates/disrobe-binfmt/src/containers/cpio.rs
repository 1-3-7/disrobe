use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const NEWC_MAGIC: &[u8; 6] = b"070701";
pub const CRC_MAGIC: &[u8; 6] = b"070702";
pub const ODC_MAGIC: &[u8; 6] = b"070707";
pub const BIN_MAGIC_LE: u16 = 0x71c7;
pub const BIN_MAGIC_BE: u16 = 0xc771;
pub const TRAILER_NAME: &str = "TRAILER!!!";

const NEWC_HEADER_LEN: usize = 110;
const ODC_HEADER_LEN: usize = 76;
const BIN_HEADER_LEN: usize = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CpioVariant {
    Newc,
    Crc,
    Odc,
    BinLittleEndian,
    BinBigEndian,
}

impl CpioVariant {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Newc => "newc",
            Self::Crc => "newc-crc",
            Self::Odc => "odc",
            Self::BinLittleEndian => "bin-le",
            Self::BinBigEndian => "bin-be",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpioEntry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u64,
    pub file_size: u64,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpioArchive {
    pub variant: CpioVariant,
    pub entries: Vec<CpioEntry>,
}

#[must_use]
pub fn detect_cpio_variant(bytes: &[u8]) -> Option<CpioVariant> {
    if bytes.len() >= 6 {
        if bytes[..6] == *NEWC_MAGIC {
            return Some(CpioVariant::Newc);
        }
        if bytes[..6] == *CRC_MAGIC {
            return Some(CpioVariant::Crc);
        }
        if bytes[..6] == *ODC_MAGIC {
            return Some(CpioVariant::Odc);
        }
    }
    if bytes.len() >= 2 {
        let magic: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
        if magic == BIN_MAGIC_LE {
            return Some(CpioVariant::BinLittleEndian);
        }
        if magic == BIN_MAGIC_BE {
            return Some(CpioVariant::BinBigEndian);
        }
    }
    None
}

pub fn parse_cpio(bytes: &[u8]) -> Result<CpioArchive> {
    let variant: CpioVariant = detect_cpio_variant(bytes)
        .ok_or_else(|| Error::Tar("cpio magic not recognized".to_owned()))?;
    let entries: Vec<CpioEntry> = match variant {
        CpioVariant::Newc | CpioVariant::Crc => parse_newc(bytes, variant)?,
        CpioVariant::Odc => parse_odc(bytes)?,
        CpioVariant::BinLittleEndian => parse_bin(bytes, false)?,
        CpioVariant::BinBigEndian => parse_bin(bytes, true)?,
    };
    Ok(CpioArchive { variant, entries })
}

fn hex_field(bytes: &[u8], offset: usize) -> Result<u64> {
    let end: usize = offset
        .checked_add(8)
        .ok_or_else(|| Error::Tar("cpio newc field offset overflow".to_owned()))?;
    let slice: &[u8] = bytes
        .get(offset..end)
        .ok_or_else(|| Error::Tar("cpio newc header truncated".to_owned()))?;
    let text: &str = core::str::from_utf8(slice)
        .map_err(|_| Error::Tar("cpio newc field not ascii".to_owned()))?;
    u64::from_str_radix(text, 16)
        .map_err(|_| Error::Tar(format!("cpio newc field not hex: {text:?}")))
}

fn hex_field_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let value: u64 = hex_field(bytes, offset)?;
    u32::try_from(value).map_err(|_error: std::num::TryFromIntError| {
        Error::Tar(format!("cpio {field} exceeds 32 bits"))
    })
}

fn align4_checked(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|aligned: usize| aligned & !3)
        .ok_or_else(|| Error::Tar("cpio alignment overflow".to_owned()))
}

fn require_zero_padding(bytes: &[u8], start: usize, end: usize, subject: &str) -> Result<()> {
    let padding: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Tar(format!("cpio {subject} padding is truncated")))?;
    if padding.iter().any(|byte: &u8| *byte != 0) {
        return Err(Error::Tar(format!(
            "cpio {subject} padding contains nonzero bytes"
        )));
    }
    Ok(())
}

fn parse_newc(bytes: &[u8], variant: CpioVariant) -> Result<Vec<CpioEntry>> {
    parse_newc_with_name_cap(bytes, variant, super::MAX_CONTAINER_METADATA_BYTES)
}

fn parse_newc_with_name_cap(
    bytes: &[u8],
    variant: CpioVariant,
    name_metadata_cap: usize,
) -> Result<Vec<CpioEntry>> {
    let mut entries: Vec<CpioEntry> = Vec::new();
    let mut pos: usize = 0;
    let mut metadata_bytes: usize = 0;
    loop {
        let header_end: usize = pos
            .checked_add(NEWC_HEADER_LEN)
            .ok_or_else(|| Error::Tar("cpio newc header offset overflow".to_owned()))?;
        let header: &[u8] = bytes
            .get(pos..header_end)
            .ok_or_else(|| Error::Tar("cpio newc trailer missing or truncated".to_owned()))?;
        let expected_magic: &[u8; 6] = match variant {
            CpioVariant::Newc => NEWC_MAGIC,
            CpioVariant::Crc => CRC_MAGIC,
            CpioVariant::Odc | CpioVariant::BinLittleEndian | CpioVariant::BinBigEndian => {
                return Err(Error::Tar(
                    "cpio newc parser received another variant".to_owned(),
                ));
            }
        };
        if header.get(..6) != Some(expected_magic.as_slice()) {
            return Err(Error::Tar(format!(
                "cpio newc member magic mismatch at offset {pos}"
            )));
        }
        let _inode: u32 = hex_field_u32(bytes, pos + 6, "inode")?;
        let mode: u32 = hex_field_u32(bytes, pos + 14, "mode")?;
        let uid: u32 = hex_field_u32(bytes, pos + 22, "uid")?;
        let gid: u32 = hex_field_u32(bytes, pos + 30, "gid")?;
        let nlink: u32 = hex_field_u32(bytes, pos + 38, "link count")?;
        let mtime: u64 = hex_field(bytes, pos + 46)?;
        let file_size: u64 = hex_field(bytes, pos + 54)?;
        let _device_major: u32 = hex_field_u32(bytes, pos + 62, "device major")?;
        let _device_minor: u32 = hex_field_u32(bytes, pos + 70, "device minor")?;
        let _special_device_major: u32 = hex_field_u32(bytes, pos + 78, "special device major")?;
        let _special_device_minor: u32 = hex_field_u32(bytes, pos + 86, "special device minor")?;
        let expected_checksum: u32 = hex_field_u32(bytes, pos + 102, "checksum")?;
        let name_size: usize = usize::try_from(hex_field(bytes, pos + 94)?).map_err(
            |_e: std::num::TryFromIntError| Error::Tar("cpio name size overflow".to_owned()),
        )?;
        if name_size == 0 {
            return Err(Error::Tar(
                "cpio newc name is not nul terminated".to_owned(),
            ));
        }
        let name_start: usize = header_end;
        let name_end: usize = name_start
            .checked_add(name_size)
            .ok_or_else(|| Error::Tar("cpio name length overflow".to_owned()))?;
        let name_bytes: &[u8] = bytes
            .get(name_start..name_end)
            .ok_or_else(|| Error::Tar("cpio name out of bounds".to_owned()))?;
        if name_bytes.last() != Some(&0) {
            return Err(Error::Tar(
                "cpio newc name is not canonically terminated".to_owned(),
            ));
        }
        let name_content: &[u8] = &name_bytes[..name_bytes.len() - 1];
        if name_content.contains(&0) {
            return Err(Error::UnsafeEntryPath(
                String::from_utf8_lossy(name_content).into_owned(),
            ));
        }
        if name_size > crate::quota::MAX_ENTRY_PATH_BYTES + 1 {
            return Err(Error::Tar(format!(
                "cpio newc name length {name_size} exceeds path bound {}",
                crate::quota::MAX_ENTRY_PATH_BYTES
            )));
        }
        let decoded_name_bound: usize = name_size
            .checked_mul(3)
            .ok_or_else(|| Error::Tar("cpio name allocation bound overflow".to_owned()))?;
        super::admit_metadata_bytes(
            &mut metadata_bytes,
            decoded_name_bound,
            name_metadata_cap,
            "<cpio-names>",
        )?;
        let name: String = decode_name(name_bytes);
        let data_start: usize = align4_checked(name_end)?;
        require_zero_padding(bytes, name_end, data_start, "name")?;
        let file_size_usize: usize =
            usize::try_from(file_size).map_err(|_error: std::num::TryFromIntError| {
                Error::Tar("cpio data size overflow".to_owned())
            })?;
        let data_end: usize = data_start
            .checked_add(file_size_usize)
            .ok_or_else(|| Error::Tar("cpio data length overflow".to_owned()))?;
        let data: &[u8] = bytes
            .get(data_start..data_end)
            .ok_or_else(|| Error::Tar("cpio data out of bounds".to_owned()))?;
        let actual_checksum: u32 = data.iter().fold(0u32, |sum: u32, byte: &u8| {
            sum.wrapping_add(u32::from(*byte))
        });
        match variant {
            CpioVariant::Crc if actual_checksum != expected_checksum => {
                return Err(Error::Tar(format!(
                    "cpio checksum mismatch for `{name}`: expected {expected_checksum:08x}, computed {actual_checksum:08x}"
                )));
            }
            CpioVariant::Newc if expected_checksum != 0 => {
                return Err(Error::Tar(format!(
                    "cpio newc checksum field for `{name}` must be zero"
                )));
            }
            CpioVariant::Newc | CpioVariant::Crc => {}
            CpioVariant::Odc | CpioVariant::BinLittleEndian | CpioVariant::BinBigEndian => {
                return Err(Error::Tar(
                    "cpio newc parser received another variant".to_owned(),
                ));
            }
        }
        if name == TRAILER_NAME {
            if file_size != 0 {
                return Err(Error::Tar("cpio trailer carries file data".to_owned()));
            }
            let archive_end: usize = align4_checked(data_end)?;
            require_zero_padding(bytes, data_end, archive_end, "trailer")?;
            let padding: &[u8] = bytes
                .get(archive_end..)
                .ok_or_else(|| Error::Tar("cpio trailer padding out of bounds".to_owned()))?;
            if padding.iter().any(|byte: &u8| *byte != 0) {
                return Err(Error::Tar("cpio trailer has nonzero padding".to_owned()));
            }
            return Ok(entries);
        }
        if entries.len() >= crate::quota::DEFAULT_MAX_ENTRIES {
            return Err(Error::Tar(format!(
                "cpio entry count exceeds cap {}",
                crate::quota::DEFAULT_MAX_ENTRIES
            )));
        }
        entries.push(CpioEntry {
            name,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            file_size,
            data_offset: data_start,
        });
        let next: usize = align4_checked(data_end)?;
        require_zero_padding(bytes, data_end, next, "member")?;
        pos = next;
    }
}

fn oct_field(bytes: &[u8], offset: usize, width: usize) -> Result<u64> {
    let slice: &[u8] = bytes
        .get(offset..offset + width)
        .ok_or_else(|| Error::Tar("cpio odc header truncated".to_owned()))?;
    let text: &str = core::str::from_utf8(slice)
        .map_err(|_| Error::Tar("cpio odc field not ascii".to_owned()))?;
    u64::from_str_radix(text.trim(), 8)
        .map_err(|_| Error::Tar(format!("cpio odc field not octal: {text:?}")))
}

fn parse_odc(bytes: &[u8]) -> Result<Vec<CpioEntry>> {
    let mut entries: Vec<CpioEntry> = Vec::new();
    let mut pos: usize = 0;
    loop {
        if pos + ODC_HEADER_LEN > bytes.len() {
            break;
        }
        let mode: u32 = oct_field(bytes, pos + 18, 6)? as u32;
        let uid: u32 = oct_field(bytes, pos + 24, 6)? as u32;
        let gid: u32 = oct_field(bytes, pos + 30, 6)? as u32;
        let nlink: u32 = oct_field(bytes, pos + 36, 6)? as u32;
        let mtime: u64 = oct_field(bytes, pos + 48, 11)?;
        let name_size: usize = oct_field(bytes, pos + 59, 6)? as usize;
        let file_size: u64 = oct_field(bytes, pos + 65, 11)?;
        let name_start: usize = pos + ODC_HEADER_LEN;
        let name_end: usize = name_start
            .checked_add(name_size)
            .ok_or_else(|| Error::Tar("cpio odc name length overflow".to_owned()))?;
        let name_bytes: &[u8] = bytes
            .get(name_start..name_end)
            .ok_or_else(|| Error::Tar("cpio odc name out of bounds".to_owned()))?;
        let name: String = decode_name(name_bytes);
        let data_start: usize = name_end;
        if name == TRAILER_NAME {
            break;
        }
        let data_end: usize = data_start
            .checked_add(file_size as usize)
            .ok_or_else(|| Error::Tar("cpio odc data length overflow".to_owned()))?;
        entries.push(CpioEntry {
            name,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            file_size,
            data_offset: data_start,
        });
        pos = data_end;
    }
    Ok(entries)
}

fn parse_bin(bytes: &[u8], big_endian: bool) -> Result<Vec<CpioEntry>> {
    let read_u16 = |slice: &[u8]| -> u16 {
        if big_endian {
            u16::from_be_bytes([slice[0], slice[1]])
        } else {
            u16::from_le_bytes([slice[0], slice[1]])
        }
    };
    let read_u32_pdp = |hi: u16, lo: u16| -> u32 { (u32::from(hi) << 16) | u32::from(lo) };
    let mut entries: Vec<CpioEntry> = Vec::new();
    let mut pos: usize = 0;
    loop {
        if pos + BIN_HEADER_LEN > bytes.len() {
            break;
        }
        let header: &[u8] = &bytes[pos..pos + BIN_HEADER_LEN];
        let mode: u32 = u32::from(read_u16(&header[6..8]));
        let uid: u32 = u32::from(read_u16(&header[8..10]));
        let gid: u32 = u32::from(read_u16(&header[10..12]));
        let nlink: u32 = u32::from(read_u16(&header[12..14]));
        let mtime_hi: u16 = read_u16(&header[16..18]);
        let mtime_lo: u16 = read_u16(&header[18..20]);
        let mtime: u64 = u64::from(read_u32_pdp(mtime_hi, mtime_lo));
        let name_size: usize = usize::from(read_u16(&header[20..22]));
        let size_hi: u16 = read_u16(&header[22..24]);
        let size_lo: u16 = read_u16(&header[24..26]);
        let file_size: u64 = u64::from(read_u32_pdp(size_hi, size_lo));
        let name_start: usize = pos + BIN_HEADER_LEN;
        let name_end: usize = name_start
            .checked_add(name_size)
            .ok_or_else(|| Error::Tar("cpio bin name length overflow".to_owned()))?;
        let name_bytes: &[u8] = bytes
            .get(name_start..name_end)
            .ok_or_else(|| Error::Tar("cpio bin name out of bounds".to_owned()))?;
        let name: String = decode_name(name_bytes);
        let data_start: usize = align2(name_end);
        if name == TRAILER_NAME {
            break;
        }
        let data_end: usize = data_start
            .checked_add(file_size as usize)
            .ok_or_else(|| Error::Tar("cpio bin data length overflow".to_owned()))?;
        entries.push(CpioEntry {
            name,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            file_size,
            data_offset: data_start,
        });
        pos = align2(data_end);
    }
    Ok(entries)
}

#[inline]
const fn align2(value: usize) -> usize {
    (value + 1) & !1
}

fn decode_name(name_bytes: &[u8]) -> String {
    let trimmed: &[u8] = name_bytes
        .iter()
        .position(|&b| b == 0)
        .map_or(name_bytes, |nul: usize| &name_bytes[..nul]);
    String::from_utf8_lossy(trimmed).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn newc_header(name: &str, mode: u32, file_size: u32) -> Vec<u8> {
        let name_size: u32 = name.len() as u32 + 1;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(NEWC_MAGIC);
        let mut field = |value: u32| out.extend_from_slice(format!("{value:08X}").as_bytes());
        field(0);
        field(mode);
        field(0);
        field(0);
        field(1);
        field(0);
        field(file_size);
        field(0);
        field(0);
        field(0);
        field(0);
        field(name_size);
        field(0);
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    fn push_data(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    #[test]
    fn parses_newc_two_entries_and_trailer() {
        let mut archive: Vec<u8> = Vec::new();
        archive.extend_from_slice(&newc_header("etc/hello.txt", 0o100_644, 5));
        push_data(&mut archive, b"hello");
        archive.extend_from_slice(&newc_header("etc/dir", 0o040_755, 0));
        archive.extend_from_slice(&newc_header(TRAILER_NAME, 0, 0));

        let parsed: CpioArchive = parse_cpio(&archive).expect("parse newc");
        assert_eq!(parsed.variant, CpioVariant::Newc);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "etc/hello.txt");
        assert_eq!(parsed.entries[0].file_size, 5);
        assert_eq!(parsed.entries[0].mode, 0o100_644);
        assert_eq!(parsed.entries[1].name, "etc/dir");
        assert_eq!(parsed.entries[1].file_size, 0);
        let data: &[u8] = &archive[parsed.entries[0].data_offset
            ..parsed.entries[0].data_offset + parsed.entries[0].file_size as usize];
        assert_eq!(data, b"hello");
    }

    #[test]
    fn detects_crc_variant() {
        let mut archive: Vec<u8> = Vec::new();
        archive.extend_from_slice(CRC_MAGIC);
        archive.extend_from_slice(&newc_header(TRAILER_NAME, 0, 0)[6..]);
        let parsed: CpioArchive = parse_cpio(&archive).expect("parse crc");
        assert_eq!(parsed.variant, CpioVariant::Crc);
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn crc_variant_rejects_a_wrong_member_checksum() {
        let mut archive: Vec<u8> = newc_header("checked.bin", 0o100_644, 3);
        archive[..CRC_MAGIC.len()].copy_from_slice(CRC_MAGIC);
        push_data(&mut archive, b"abc");
        let mut trailer: Vec<u8> = newc_header(TRAILER_NAME, 0, 0);
        trailer[..CRC_MAGIC.len()].copy_from_slice(CRC_MAGIC);
        archive.extend_from_slice(&trailer);

        let error: Error = parse_cpio(&archive).expect_err("checksum mismatch must fail");
        assert!(error.to_string().contains("checksum"), "{error}");
    }

    #[test]
    fn newc_requires_one_complete_trailer() {
        let mut archive: Vec<u8> = newc_header("file.bin", 0o100_644, 3);
        push_data(&mut archive, b"abc");

        let error: Error = parse_cpio(&archive).expect_err("missing trailer must fail");
        assert!(error.to_string().contains("trailer"), "{error}");
    }

    #[test]
    fn newc_rejects_nonzero_bytes_after_trailer_padding() {
        let mut archive: Vec<u8> = newc_header(TRAILER_NAME, 0, 0);
        archive.extend_from_slice(b"suffix");

        let error: Error = parse_cpio(&archive).expect_err("suffix must fail");
        assert!(error.to_string().contains("padding"), "{error}");
    }

    #[test]
    fn newc_rejects_nonzero_name_padding() {
        let mut archive: Vec<u8> = newc_header("ab", 0o100_644, 0);
        let padding: usize = archive.len() - 1;
        archive[padding] = 1;
        archive.extend_from_slice(&newc_header(TRAILER_NAME, 0, 0));

        let error: Error = parse_cpio(&archive).expect_err("name padding must fail");
        assert!(error.to_string().contains("name padding"), "{error}");
    }

    #[test]
    fn newc_rejects_nonzero_member_padding() {
        let mut archive: Vec<u8> = newc_header("x", 0o100_644, 1);
        push_data(&mut archive, b"a");
        let padding: usize = archive.len() - 1;
        archive[padding] = 1;
        archive.extend_from_slice(&newc_header(TRAILER_NAME, 0, 0));

        let error: Error = parse_cpio(&archive).expect_err("member padding must fail");
        assert!(error.to_string().contains("member padding"), "{error}");
    }

    #[test]
    fn newc_requires_exact_hex_fields() {
        let mut archive: Vec<u8> = newc_header(TRAILER_NAME, 0, 0);
        archive[6..14].copy_from_slice(b"       0");

        let error: Error = parse_cpio(&archive).expect_err("spaced field must fail");
        assert!(error.to_string().contains("not hex"), "{error}");
    }

    #[test]
    fn newc_refuses_a_name_above_the_shared_path_bound() {
        let name: String = "a".repeat(crate::quota::MAX_ENTRY_PATH_BYTES + 1);
        let mut archive: Vec<u8> = newc_header(&name, 0o100_644, 0);
        archive.extend_from_slice(&newc_header(TRAILER_NAME, 0, 0));

        let error: Error = parse_cpio(&archive).expect_err("oversized name must fail");
        assert!(error.to_string().contains("name length"), "{error}");
    }

    #[test]
    fn newc_names_obey_the_exact_aggregate_metadata_boundary() {
        let mut archive: Vec<u8> = newc_header("a", 0o100_644, 0);
        archive.extend_from_slice(&newc_header("b", 0o100_644, 0));
        archive.extend_from_slice(&newc_header(TRAILER_NAME, 0, 0));

        let entries: Vec<CpioEntry> = parse_newc_with_name_cap(&archive, CpioVariant::Newc, 45)
            .expect("exact CPIO name metadata boundary");
        assert_eq!(entries.len(), 2);
        let error: Error = parse_newc_with_name_cap(&archive, CpioVariant::Newc, 44)
            .expect_err("aggregate CPIO name metadata must stay bounded");
        assert!(error.to_string().contains("metadata"), "{error}");
    }

    #[test]
    fn parses_odc_entry() {
        fn odc_header(name: &str, mode: u32, file_size: u32) -> Vec<u8> {
            let name_size: u32 = name.len() as u32 + 1;
            let mut out: Vec<u8> = Vec::new();
            out.extend_from_slice(ODC_MAGIC);
            let mut o6 = |value: u32| out.extend_from_slice(format!("{value:06o}").as_bytes());
            o6(0);
            o6(0);
            o6(mode);
            o6(0);
            o6(0);
            o6(1);
            o6(0);
            out.extend_from_slice(format!("{:011o}", 0).as_bytes());
            out.extend_from_slice(format!("{name_size:06o}").as_bytes());
            out.extend_from_slice(format!("{file_size:011o}").as_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out
        }
        let mut archive: Vec<u8> = Vec::new();
        archive.extend_from_slice(&odc_header("a.txt", 0o100_644, 3));
        archive.extend_from_slice(b"abc");
        archive.extend_from_slice(&odc_header(TRAILER_NAME, 0, 0));
        let parsed: CpioArchive = parse_cpio(&archive).expect("parse odc");
        assert_eq!(parsed.variant, CpioVariant::Odc);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "a.txt");
        assert_eq!(parsed.entries[0].file_size, 3);
        assert_eq!(
            &archive[parsed.entries[0].data_offset..parsed.entries[0].data_offset + 3],
            b"abc"
        );
    }

    #[test]
    fn parses_bin_le_entry() {
        fn bin_header(name: &str, mode: u16, file_size: u32) -> Vec<u8> {
            let name_size: u16 = name.len() as u16 + 1;
            let mut out: Vec<u8> = Vec::new();
            out.extend_from_slice(&BIN_MAGIC_LE.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&mode.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&1u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&name_size.to_le_bytes());
            out.extend_from_slice(&((file_size >> 16) as u16).to_le_bytes());
            out.extend_from_slice(&((file_size & 0xffff) as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            while !out.len().is_multiple_of(2) {
                out.push(0);
            }
            out
        }
        let mut archive: Vec<u8> = Vec::new();
        archive.extend_from_slice(&bin_header("z", 0o100_644, 2));
        archive.extend_from_slice(b"hi");
        archive.extend_from_slice(&bin_header(TRAILER_NAME, 0, 0));
        let parsed: CpioArchive = parse_cpio(&archive).expect("parse bin");
        assert_eq!(parsed.variant, CpioVariant::BinLittleEndian);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "z");
        assert_eq!(parsed.entries[0].file_size, 2);
    }

    #[test]
    fn rejects_non_cpio() {
        assert!(detect_cpio_variant(b"not a cpio archive at all").is_none());
        assert!(parse_cpio(b"xxxxxx").is_err());
    }
}
