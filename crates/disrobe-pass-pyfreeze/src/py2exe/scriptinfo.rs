use disrobe_bytes::{ByteReadError, read_u32_le_at};

use crate::error::{Error, Result};

pub const PY2EXE_MAGIC_TAG: u32 = 0x7856_3412;

#[derive(Debug, Clone)]
pub struct ScriptInfo {
    pub magic_tag: u32,
    pub optimize_level: u32,
    pub unbuffered_flag: u32,
    pub script_data_len: u32,
    pub zip_archive_name: String,
    pub marshalled_code: Vec<u8>,
}

pub fn parse(bytes: &[u8]) -> Result<ScriptInfo> {
    if bytes.len() < 16 {
        return Err(Error::Py2exeScriptInfoTruncated {
            need: 16,
            got: bytes.len(),
        });
    }
    let field = |offset: usize| -> Result<u32> {
        read_u32_le_at(bytes, offset).map_err(|_: ByteReadError| Error::Py2exeScriptInfoTruncated {
            need: 16,
            got: bytes.len(),
        })
    };
    let magic: u32 = field(0)?;
    if magic != PY2EXE_MAGIC_TAG {
        return Err(Error::Py2exeScriptInfoBadTag(magic));
    }
    let optimize_level: u32 = field(4)?;
    let unbuffered: u32 = field(8)?;
    let script_data_len: u32 = field(12)?;

    let mut cursor: usize = 16usize;
    let zip_name: String = read_cstring(bytes, &mut cursor)?;
    let script_len: usize = usize::try_from(script_data_len).unwrap_or(usize::MAX);
    let end: usize = cursor.saturating_add(script_len.max(1));
    let script: &[u8] = bytes
        .get(cursor..end)
        .ok_or(Error::Py2exeScriptInfoTruncated {
            need: end,
            got: bytes.len(),
        })?;

    Ok(ScriptInfo {
        magic_tag: magic,
        optimize_level,
        unbuffered_flag: unbuffered,
        script_data_len,
        zip_archive_name: zip_name,
        marshalled_code: script.to_vec(),
    })
}

fn read_cstring(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    let start: usize = *cursor;
    while *cursor < bytes.len() && bytes[*cursor] != 0 {
        *cursor += 1;
    }
    if *cursor >= bytes.len() {
        return Err(Error::Py2exeScriptInfoTruncated {
            need: *cursor + 1,
            got: bytes.len(),
        });
    }
    let s: String = String::from_utf8_lossy(&bytes[start..*cursor]).into_owned();
    *cursor += 1;
    Ok(s)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimum_header() {
        let mut buf: Vec<u8> = vec![];
        buf.extend_from_slice(&PY2EXE_MAGIC_TAG.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(b"app.zip\0");
        buf.extend_from_slice(&[0xE3, 0x00, 0x00, 0x00, 0x00]);
        let info: ScriptInfo = parse(&buf).expect("parse");
        assert_eq!(info.zip_archive_name, "app.zip");
        assert_eq!(info.script_data_len, 4);
        assert_eq!(info.marshalled_code, vec![0xE3, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn rejects_script_data_longer_than_the_resource() {
        let mut buf: Vec<u8> = vec![];
        buf.extend_from_slice(&PY2EXE_MAGIC_TAG.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&9u32.to_le_bytes());
        buf.extend_from_slice(b"library.zip\0");
        buf.extend_from_slice(&[0xDB, 0x03, 0x00, 0x00, 0x00]);
        let err: Error = parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            Error::Py2exeScriptInfoTruncated { need: 37, got: 33 }
        ));
    }

    #[test]
    fn rejects_wrong_magic() {
        let buf: Vec<u8> = vec![0u8; 32];
        let err: Error = parse(&buf).unwrap_err();
        assert!(matches!(err, Error::Py2exeScriptInfoBadTag(_)));
    }

    #[test]
    fn rejects_short_buffer() {
        let buf: Vec<u8> = vec![0u8; 4];
        let err: Error = parse(&buf).unwrap_err();
        assert!(matches!(err, Error::Py2exeScriptInfoTruncated { .. }));
    }
}
