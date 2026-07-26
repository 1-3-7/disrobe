use crate::error::{Error, Result};
use disrobe_bytes::{ByteReadError, ByteReader};

pub const LZOP_MAGIC: &[u8; 9] = &[0x89, b'L', b'Z', b'O', 0x00, 0x0d, 0x0a, 0x1a, 0x0a];

const F_ADLER32_D: u32 = 0x0000_0001;
const F_ADLER32_C: u32 = 0x0000_0002;
const F_H_FILTER: u32 = 0x0000_0800;
const F_CRC32_D: u32 = 0x0000_0100;
const F_CRC32_C: u32 = 0x0000_0200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzopFile {
    pub name: String,
    pub method: u8,
    pub level: u8,
    pub data: Vec<u8>,
}

#[must_use]
pub fn detect_lzop(bytes: &[u8]) -> bool {
    bytes.starts_with(LZOP_MAGIC)
}

fn lzop_truncated(field: &'static str) -> Error {
    Error::Lzop(format!("lzop: truncated {field}"))
}

fn lzop_data_run_error(error: ByteReadError) -> Error {
    if error.offset.checked_add(error.needed).is_none() {
        Error::Lzop("lzop: length overflow".to_owned())
    } else {
        lzop_truncated("data run")
    }
}

pub fn parse_lzop(bytes: &[u8], max_total: u64) -> Result<LzopFile> {
    if !detect_lzop(bytes) {
        return Err(Error::Lzop("lzop: missing magic".to_owned()));
    }
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    r.skip(LZOP_MAGIC.len())
        .map_err(|_| Error::Lzop("lzop: missing magic".to_owned()))?;
    let _version: u16 = r.read_u16_be().map_err(|_| lzop_truncated("u16"))?;
    let _lib_version: u16 = r.read_u16_be().map_err(|_| lzop_truncated("u16"))?;
    let version_needed: u16 = r.read_u16_be().map_err(|_| lzop_truncated("u16"))?;
    if version_needed > 0x0940 {
        return Err(Error::Lzop(format!(
            "lzop: version-needed 0x{version_needed:04x} newer than supported 0x0940"
        )));
    }
    let method: u8 = r.read_u8().map_err(|_| lzop_truncated("u8"))?;
    let level: u8 = r.read_u8().map_err(|_| lzop_truncated("u8"))?;
    let flags: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
    if flags & F_H_FILTER != 0 {
        let _filter: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
    }
    let _mode: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
    let _mtime_low: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
    let _mtime_high: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
    let name_len: usize = usize::from(r.read_u8().map_err(|_| lzop_truncated("u8"))?);
    let name: String = if name_len > 0 {
        String::from_utf8_lossy(r.read_bytes(name_len).map_err(lzop_data_run_error)?).into_owned()
    } else {
        String::new()
    };
    let _header_checksum: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;

    let has_dest_check: bool = flags & (F_ADLER32_D | F_CRC32_D) != 0;
    let has_src_check: bool = flags & (F_ADLER32_C | F_CRC32_C) != 0;

    let mut out: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    loop {
        let dst_len: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
        if dst_len == 0 {
            break;
        }
        let src_len: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
        if src_len == 0 || src_len > dst_len {
            return Err(Error::Lzop(format!(
                "lzop: implausible block lengths dst={dst_len} src={src_len}"
            )));
        }
        if has_dest_check {
            let _dst_check: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
        }
        if has_src_check && src_len < dst_len {
            let _src_check: u32 = r.read_u32_be().map_err(|_| lzop_truncated("u32"))?;
        }
        let block: &[u8] = r
            .read_bytes(src_len as usize)
            .map_err(lzop_data_run_error)?;
        total = total.saturating_add(u64::from(dst_len));
        if total > max_total {
            return Err(Error::Lzop(format!(
                "lzop: decompressed size exceeds quota ({total} > {max_total})"
            )));
        }
        if src_len == dst_len {
            out.extend_from_slice(block);
        } else {
            if dst_len as usize > crate::quota::MAX_ENTRY_PREALLOC {
                return Err(Error::Lzop(format!(
                    "lzop: block declares {dst_len} bytes, past the {} byte block limit",
                    crate::quota::MAX_ENTRY_PREALLOC
                )));
            }
            let mut dst: Vec<u8> = vec![0u8; dst_len as usize];
            let written: usize =
                lzokay::decompress::decompress(block, &mut dst).map_err(|e: lzokay::Error| {
                    Error::Lzop(format!("lzop: lzo1x decode failed: {e:?}"))
                })?;
            if written != dst_len as usize {
                return Err(Error::Lzop(format!(
                    "lzop: decoded {written} bytes, expected {dst_len}"
                )));
            }
            out.extend_from_slice(&dst);
        }
    }

    Ok(LzopFile {
        name,
        method,
        level,
        data: out,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_matches_magic() {
        let mut bytes: Vec<u8> = LZOP_MAGIC.to_vec();
        bytes.extend([0u8; 16]);
        assert!(detect_lzop(&bytes));
        assert!(!detect_lzop(b"not lzop"));
    }

    fn build_stored_lzop(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = LZOP_MAGIC.to_vec();
        out.extend_from_slice(&0x1030u16.to_be_bytes());
        out.extend_from_slice(&0x2080u16.to_be_bytes());
        out.extend_from_slice(&0x0940u16.to_be_bytes());
        out.push(1);
        out.push(5);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0o100_644_u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    #[test]
    fn parses_stored_block_payload() {
        let payload: &[u8] = b"uncompressed lzop block payload, stored verbatim";
        let lzo: Vec<u8> = build_stored_lzop("hello.txt", payload);
        let file: LzopFile = parse_lzop(&lzo, 1 << 20).expect("parse stored lzop");
        assert_eq!(file.name, "hello.txt");
        assert_eq!(file.data, payload);
    }
}
