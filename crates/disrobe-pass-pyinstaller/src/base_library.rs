use std::io::Read;

use flate2::read::DeflateDecoder;

use crate::debug::{dbg_kv, dbg_line, dbg_section};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_DIR_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_FILE_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_MIN_LEN: usize = 22;
const CENTRAL_DIR_FIXED_LEN: usize = 46;
const LOCAL_FILE_FIXED_LEN: usize = 30;
const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const MAX_ZIP_ENTRIES: usize = 1 << 20;
const MAX_ZIP_COMMENT: usize = u16::MAX as usize;
const ZIP64_SENTINEL_U16: u16 = 0xffff;
const ZIP64_SENTINEL_U32: u32 = 0xffff_ffff;
const MEMBER_CAPACITY_HINT: usize = 1 << 20;

#[derive(Debug)]
pub(crate) struct ZipMember {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) stored: bool,
    pub(crate) compressed_len: usize,
}

#[derive(Debug, Clone, Copy)]
struct CentralRecord {
    method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
    name_start: usize,
    name_len: usize,
}

pub(crate) fn read_base_library_pyc_members(zip: &[u8], budget: &mut u64) -> Vec<ZipMember> {
    dbg_section("base_library.zip");
    let Some(eocd_offset): Option<usize> = find_eocd(zip) else {
        dbg_line(|| "no end-of-central-directory record: not a pkzip archive".to_owned());
        return Vec::new();
    };
    let total_entries: u16 = read_u16_le(zip, eocd_offset + 10).unwrap_or(0);
    let cd_offset_raw: u32 = read_u32_le(zip, eocd_offset + 16).unwrap_or(ZIP64_SENTINEL_U32);
    if total_entries == ZIP64_SENTINEL_U16 || cd_offset_raw == ZIP64_SENTINEL_U32 {
        dbg_line(|| "zip64 base_library.zip is out of scope for the plain-pkzip reader".to_owned());
        return Vec::new();
    }
    let Ok(cd_offset): core::result::Result<usize, _> = usize::try_from(cd_offset_raw) else {
        return Vec::new();
    };
    let records: Vec<CentralRecord> = walk_central_directory(zip, cd_offset, total_entries);
    let mut out: Vec<ZipMember> = Vec::with_capacity(records.len());
    for record in &records {
        let Some(member): Option<ZipMember> = decode_member(zip, record, budget) else {
            continue;
        };
        out.push(member);
    }
    dbg_kv("pyc_members", || out.len().to_string());
    out
}

fn find_eocd(zip: &[u8]) -> Option<usize> {
    if zip.len() < EOCD_MIN_LEN {
        return None;
    }
    let highest: usize = zip.len() - EOCD_MIN_LEN;
    let lowest: usize = highest.saturating_sub(MAX_ZIP_COMMENT);
    let mut offset: usize = highest;
    loop {
        if read_u32_le(zip, offset) == Some(EOCD_SIGNATURE) {
            let comment_len: usize = read_u16_le(zip, offset + 20).map_or(0, usize::from);
            if offset + EOCD_MIN_LEN + comment_len == zip.len() {
                return Some(offset);
            }
        }
        if offset == lowest {
            return None;
        }
        offset -= 1;
    }
}

fn walk_central_directory(zip: &[u8], cd_offset: usize, declared: u16) -> Vec<CentralRecord> {
    let cap: usize = usize::from(declared).min(MAX_ZIP_ENTRIES);
    let mut records: Vec<CentralRecord> = Vec::with_capacity(cap);
    let mut cursor: usize = cd_offset;
    while records.len() < MAX_ZIP_ENTRIES {
        if read_u32_le(zip, cursor) != Some(CENTRAL_DIR_SIGNATURE) {
            break;
        }
        let (Some(method), Some(compressed_size), Some(uncompressed_size)): (
            Option<u16>,
            Option<u32>,
            Option<u32>,
        ) = (
            read_u16_le(zip, cursor + 10),
            read_u32_le(zip, cursor + 20),
            read_u32_le(zip, cursor + 24),
        ) else {
            break;
        };
        let (Some(name_len_u16), Some(extra_len_u16), Some(comment_len_u16)): (
            Option<u16>,
            Option<u16>,
            Option<u16>,
        ) = (
            read_u16_le(zip, cursor + 28),
            read_u16_le(zip, cursor + 30),
            read_u16_le(zip, cursor + 32),
        ) else {
            break;
        };
        let Some(local_header_offset): Option<u32> = read_u32_le(zip, cursor + 42) else {
            break;
        };
        let name_len: usize = usize::from(name_len_u16);
        let name_start: usize = cursor + CENTRAL_DIR_FIXED_LEN;
        if name_start + name_len > zip.len() {
            break;
        }
        records.push(CentralRecord {
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            name_start,
            name_len,
        });
        cursor = name_start + name_len + usize::from(extra_len_u16) + usize::from(comment_len_u16);
    }
    records
}

fn decode_member(zip: &[u8], record: &CentralRecord, budget: &mut u64) -> Option<ZipMember> {
    let raw_name: &[u8] = zip.get(record.name_start..record.name_start + record.name_len)?;
    let name: String = String::from_utf8_lossy(raw_name).into_owned();
    let is_pyc: bool = std::path::Path::new(&name)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("pyc"));
    if !is_pyc {
        return None;
    }
    let Some(safe_name): Option<String> = sanitize_zip_path(&name) else {
        dbg_line(|| format!("skipping base_library member with unsafe path '{name}'"));
        return None;
    };
    let local_offset: usize = usize::try_from(record.local_header_offset).ok()?;
    if read_u32_le(zip, local_offset) != Some(LOCAL_FILE_SIGNATURE) {
        dbg_line(|| format!("member '{safe_name}' local header signature mismatch; skipping"));
        return None;
    }
    let local_name_len: usize = usize::from(read_u16_le(zip, local_offset + 26)?);
    let local_extra_len: usize = usize::from(read_u16_le(zip, local_offset + 28)?);
    let data_start: usize = local_offset
        .checked_add(LOCAL_FILE_FIXED_LEN)?
        .checked_add(local_name_len)?
        .checked_add(local_extra_len)?;
    let compressed_len: usize = usize::try_from(record.compressed_size).ok()?;
    let data_end: usize = data_start.checked_add(compressed_len)?;
    let compressed: &[u8] = zip.get(data_start..data_end)?;
    let expected: usize = usize::try_from(record.uncompressed_size).ok()?;
    let (data, stored): (Vec<u8>, bool) = match record.method {
        METHOD_STORE => {
            if compressed.len() != expected {
                dbg_line(|| format!("stored member '{safe_name}' size mismatch; skipping"));
                return None;
            }
            (inflate_stored(compressed, budget)?, true)
        }
        METHOD_DEFLATE => (inflate_deflate(compressed, expected, budget)?, false),
        other => {
            dbg_line(|| format!("member '{safe_name}' uses unsupported method {other}; skipping"));
            return None;
        }
    };
    Some(ZipMember {
        name: safe_name,
        data,
        stored,
        compressed_len,
    })
}

fn inflate_stored(compressed: &[u8], budget: &mut u64) -> Option<Vec<u8>> {
    let needed: u64 = u64::try_from(compressed.len()).ok()?;
    if needed > *budget {
        return None;
    }
    *budget = budget.saturating_sub(needed);
    Some(compressed.to_vec())
}

fn inflate_deflate(compressed: &[u8], expected: usize, budget: &mut u64) -> Option<Vec<u8>> {
    let expected_u64: u64 = u64::try_from(expected).ok()?;
    if expected_u64 > *budget {
        return None;
    }
    let decoder: DeflateDecoder<&[u8]> = DeflateDecoder::new(compressed);
    let mut limited: std::io::Take<DeflateDecoder<&[u8]>> =
        decoder.take(expected_u64.saturating_add(1));
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(MEMBER_CAPACITY_HINT));
    limited.read_to_end(&mut out).ok()?;
    if u64::try_from(out.len()).ok()? != expected_u64 {
        return None;
    }
    *budget = budget.saturating_sub(expected_u64);
    Some(out)
}

fn sanitize_zip_path(name: &str) -> Option<String> {
    if name.starts_with('/') || name.starts_with('\\') {
        return None;
    }
    let mut normalized: String = String::with_capacity(name.len());
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':']) {
            return None;
        }
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

fn read_u16_le(buf: &[u8], at: usize) -> Option<u16> {
    let slice: &[u8] = buf.get(at..at + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], at: usize) -> Option<u32> {
    let slice: &[u8] = buf.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    const MAX_BUDGET: u64 = 8 * 1024 * 1024 * 1024;

    fn deflate(input: &[u8]) -> Vec<u8> {
        let mut enc: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(input).expect("deflate write");
        enc.finish().expect("deflate finish")
    }

    struct MemberSpec {
        name: &'static str,
        body: Vec<u8>,
        stored: bool,
    }

    fn build_zip(members: &[MemberSpec]) -> Vec<u8> {
        let mut local: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        for member in members {
            let name_bytes: &[u8] = member.name.as_bytes();
            let (payload, method): (Vec<u8>, u16) = if member.stored {
                (member.body.clone(), METHOD_STORE)
            } else {
                (deflate(&member.body), METHOD_DEFLATE)
            };
            let local_offset: u32 = u32::try_from(local.len()).expect("local offset fits");
            let compressed_size: u32 = u32::try_from(payload.len()).expect("csize fits");
            let uncompressed_size: u32 = u32::try_from(member.body.len()).expect("usize fits");
            let name_len: u16 = u16::try_from(name_bytes.len()).expect("name len fits");

            local.extend_from_slice(&LOCAL_FILE_SIGNATURE.to_le_bytes());
            local.extend_from_slice(&20u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&method.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u32.to_le_bytes());
            local.extend_from_slice(&compressed_size.to_le_bytes());
            local.extend_from_slice(&uncompressed_size.to_le_bytes());
            local.extend_from_slice(&name_len.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name_bytes);
            local.extend_from_slice(&payload);

            central.extend_from_slice(&CENTRAL_DIR_SIGNATURE.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&compressed_size.to_le_bytes());
            central.extend_from_slice(&uncompressed_size.to_le_bytes());
            central.extend_from_slice(&name_len.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name_bytes);
        }
        let cd_offset: u32 = u32::try_from(local.len()).expect("cd offset fits");
        let cd_size: u32 = u32::try_from(central.len()).expect("cd size fits");
        let count: u16 = u16::try_from(members.len()).expect("entry count fits");
        let mut zip: Vec<u8> = Vec::with_capacity(local.len() + central.len() + EOCD_MIN_LEN);
        zip.extend_from_slice(&local);
        zip.extend_from_slice(&central);
        zip.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&count.to_le_bytes());
        zip.extend_from_slice(&count.to_le_bytes());
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&cd_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip
    }

    #[test]
    fn reads_deflate_and_store_pyc_members() {
        let members: [MemberSpec; 3] = [
            MemberSpec {
                name: "abc.pyc",
                body: b"deflated pyc body bytes for abc module".to_vec(),
                stored: false,
            },
            MemberSpec {
                name: "encodings/__init__.pyc",
                body: b"stored package init body".to_vec(),
                stored: true,
            },
            MemberSpec {
                name: "notes.txt",
                body: b"not a pyc".to_vec(),
                stored: false,
            },
        ];
        let zip: Vec<u8> = build_zip(&members);
        let mut budget: u64 = MAX_BUDGET;
        let recovered: Vec<ZipMember> = read_base_library_pyc_members(&zip, &mut budget);
        assert_eq!(recovered.len(), 2, "only the two .pyc members must surface");
        let abc: &ZipMember = recovered
            .iter()
            .find(|m: &&ZipMember| m.name == "abc.pyc")
            .expect("abc.pyc surfaced");
        assert_eq!(abc.data, b"deflated pyc body bytes for abc module");
        assert!(!abc.stored, "abc.pyc was deflate-compressed");
        let init: &ZipMember = recovered
            .iter()
            .find(|m: &&ZipMember| m.name == "encodings/__init__.pyc")
            .expect("package init surfaced");
        assert_eq!(init.data, b"stored package init body");
        assert!(init.stored, "the package init was stored");
    }

    #[test]
    fn non_zip_input_yields_no_members() {
        let mut budget: u64 = MAX_BUDGET;
        assert!(read_base_library_pyc_members(b"not a zip at all", &mut budget).is_empty());
    }

    #[test]
    fn traversal_named_member_is_skipped() {
        let members: [MemberSpec; 1] = [MemberSpec {
            name: "../evil.pyc",
            body: b"payload".to_vec(),
            stored: true,
        }];
        let zip: Vec<u8> = build_zip(&members);
        let mut budget: u64 = MAX_BUDGET;
        assert!(
            read_base_library_pyc_members(&zip, &mut budget).is_empty(),
            "a path-traversal member name must be rejected, never surfaced",
        );
    }

    #[test]
    fn deflate_member_is_bounded_by_budget() {
        let members: [MemberSpec; 1] = [MemberSpec {
            name: "big.pyc",
            body: vec![0u8; 4096],
            stored: false,
        }];
        let zip: Vec<u8> = build_zip(&members);
        let mut budget: u64 = 1024;
        assert!(
            read_base_library_pyc_members(&zip, &mut budget).is_empty(),
            "a member larger than the remaining budget must not be materialized",
        );
    }

    #[test]
    fn sanitize_rejects_absolute_and_backslash() {
        assert_eq!(
            sanitize_zip_path("pkg/mod.pyc"),
            Some("pkg/mod.pyc".to_owned())
        );
        assert!(sanitize_zip_path("/abs.pyc").is_none());
        assert!(sanitize_zip_path("pkg\\mod.pyc").is_none());
        assert!(sanitize_zip_path("a/../b.pyc").is_none());
        assert!(sanitize_zip_path("").is_none());
    }
}
