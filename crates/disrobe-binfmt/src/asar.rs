use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::{Error, Result};

const ALIGNMENT_PREFIX: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

#[derive(Debug, Clone)]
pub struct AsarEntry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
    pub executable: bool,
}

#[derive(Debug, Clone)]
pub struct AsarLayout {
    pub data_offset: usize,
    pub entries: Vec<AsarEntry>,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    #[serde(default)]
    files: Option<BTreeMap<String, Self>>,
    #[serde(default)]
    offset: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    executable: Option<bool>,
    #[serde(default)]
    unpacked: Option<bool>,
}

pub fn parse(bytes: &[u8]) -> Result<AsarLayout> {
    if bytes.len() < 16 {
        return Err(Error::AsarHeader("truncated prefix".to_owned()));
    }
    if bytes[0..4] != ALIGNMENT_PREFIX {
        return Err(Error::AsarHeader("missing 0x04 outer marker".to_owned()));
    }
    let pickle_size: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if pickle_size < 8 {
        return Err(Error::AsarHeader("pickle size too small".to_owned()));
    }
    if bytes[8..12] != ALIGNMENT_PREFIX {
        return Err(Error::AsarHeader("missing 0x04 inner marker".to_owned()));
    }
    let header_size: u32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let header_start: usize = 16;
    let header_end: usize = header_start
        .checked_add(header_size as usize)
        .ok_or_else(|| Error::AsarHeader("header size overflow".to_owned()))?;
    if header_end > bytes.len() {
        return Err(Error::AsarHeader("header extends past file end".to_owned()));
    }
    let aligned_header_size: usize = align_up(header_size as usize, 4);
    let data_offset: usize = header_start
        .checked_add(aligned_header_size)
        .ok_or_else(|| Error::AsarHeader("data offset overflow".to_owned()))?;
    let header_json: &[u8] = &bytes[header_start..header_end];
    let root: RawNode = serde_json::from_slice(header_json)?;
    let mut entries: Vec<AsarEntry> = Vec::new();
    let mut path_stack: Vec<String> = Vec::new();
    walk(&root, &mut path_stack, &mut entries);
    Ok(AsarLayout {
        data_offset,
        entries,
    })
}

const fn align_up(value: usize, align: usize) -> usize {
    let rem: usize = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn walk(node: &RawNode, path_stack: &mut Vec<String>, entries: &mut Vec<AsarEntry>) {
    if let Some(children) = node.files.as_ref() {
        for (name, child) in children {
            path_stack.push(name.clone());
            walk(child, path_stack, entries);
            path_stack.pop();
        }
        return;
    }
    if node.unpacked.unwrap_or(false) {
        return;
    }
    let Some(offset_str) = node.offset.as_deref() else {
        return;
    };
    let Ok(offset) = offset_str.parse::<u64>() else {
        return;
    };
    let size: u64 = node.size.unwrap_or(0);
    let executable: bool = node.executable.unwrap_or(false);
    let path: String = path_stack.join("/");
    entries.push(AsarEntry {
        path,
        offset,
        size,
        executable,
    });
}

pub fn read_entry<'a>(bytes: &'a [u8], layout: &AsarLayout, entry: &AsarEntry) -> Result<&'a [u8]> {
    let start_off: usize = usize::try_from(entry.offset).map_err(|_| Error::AsarOutOfBounds {
        name: entry.path.clone(),
    })?;
    let size: usize = usize::try_from(entry.size).map_err(|_| Error::AsarOutOfBounds {
        name: entry.path.clone(),
    })?;
    let absolute: usize =
        layout
            .data_offset
            .checked_add(start_off)
            .ok_or_else(|| Error::AsarOutOfBounds {
                name: entry.path.clone(),
            })?;
    let end: usize = absolute
        .checked_add(size)
        .ok_or_else(|| Error::AsarOutOfBounds {
            name: entry.path.clone(),
        })?;
    if end > bytes.len() {
        return Err(Error::AsarOutOfBounds {
            name: entry.path.clone(),
        });
    }
    Ok(&bytes[absolute..end])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut header: String = String::from(r#"{"files":{"#);
        let mut offset: u64 = 0;
        for (i, (name, body)) in files.iter().enumerate() {
            if i > 0 {
                header.push(',');
            }
            let size: usize = body.len();
            let _ = write!(header, r#""{name}":{{"size":{size},"offset":"{offset}"}}"#);
            offset += body.len() as u64;
        }
        header.push_str("}}");
        let header_bytes: &[u8] = header.as_bytes();
        let header_size: u32 = u32::try_from(header_bytes.len()).expect("len fits");
        let aligned: u32 = u32::try_from(align_up(header_bytes.len(), 4)).expect("len fits");
        let pickle_size: u32 = 8 + aligned;
        let mut out: Vec<u8> = Vec::with_capacity(16 + aligned as usize);
        out.extend_from_slice(&ALIGNMENT_PREFIX);
        out.extend_from_slice(&pickle_size.to_le_bytes());
        out.extend_from_slice(&ALIGNMENT_PREFIX);
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(header_bytes);
        let padding: usize = (aligned - header_size) as usize;
        out.extend(std::iter::repeat_n(0u8, padding));
        for (_, body) in files {
            out.extend_from_slice(body);
        }
        out
    }

    #[test]
    fn truncated_rejects() {
        let err: Error = parse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, Error::AsarHeader(_)));
    }

    #[test]
    fn missing_outer_marker_rejects() {
        let mut bytes: Vec<u8> = vec![0u8; 32];
        bytes[0] = 1;
        let err: Error = parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::AsarHeader(_)));
    }

    #[test]
    fn parses_single_file() {
        let body: &[u8] = b"hello asar";
        let bytes: Vec<u8> = synth_asar(&[("a.txt", body)]);
        let layout: AsarLayout = parse(&bytes).expect("parse ok");
        assert_eq!(layout.entries.len(), 1);
        assert_eq!(layout.entries[0].path, "a.txt");
        assert_eq!(layout.entries[0].size, body.len() as u64);
        let view: &[u8] = read_entry(&bytes, &layout, &layout.entries[0]).expect("entry ok");
        assert_eq!(view, body);
    }

    #[test]
    fn parses_two_files_with_offsets() {
        let bytes: Vec<u8> = synth_asar(&[("a.txt", b"aaa"), ("b.txt", b"bbbb")]);
        let layout: AsarLayout = parse(&bytes).expect("parse ok");
        assert_eq!(layout.entries.len(), 2);
        let a: &[u8] = read_entry(&bytes, &layout, &layout.entries[0]).expect("a");
        let b: &[u8] = read_entry(&bytes, &layout, &layout.entries[1]).expect("b");
        assert_eq!(a, b"aaa");
        assert_eq!(b, b"bbbb");
    }

    #[test]
    fn entry_out_of_bounds_errors() {
        let bytes: Vec<u8> = synth_asar(&[("a.txt", b"aaa")]);
        let layout: AsarLayout = parse(&bytes).expect("parse ok");
        let mut bad: AsarEntry = layout.entries[0].clone();
        bad.size = bytes.len() as u64 + 9999;
        let err: Error = read_entry(&bytes, &layout, &bad).unwrap_err();
        assert!(matches!(err, Error::AsarOutOfBounds { .. }));
    }
}
