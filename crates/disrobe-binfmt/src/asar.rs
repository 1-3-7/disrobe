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
    let header_pickle_size: usize =
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let string_pickle_size: usize =
        u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let json_len: usize = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    if Some(header_pickle_size) != string_pickle_size.checked_add(4) {
        return Err(Error::AsarHeader(
            "header pickle size disagrees with string pickle".to_owned(),
        ));
    }
    if !matches!(string_pickle_size.checked_sub(json_len), Some(4..=7)) {
        return Err(Error::AsarHeader(
            "string pickle size disagrees with json length".to_owned(),
        ));
    }
    let header_start: usize = 16;
    let header_end: usize = header_start
        .checked_add(json_len)
        .ok_or_else(|| Error::AsarHeader("json length overflow".to_owned()))?;
    if header_end > bytes.len() {
        return Err(Error::AsarHeader("header extends past file end".to_owned()));
    }
    let data_offset: usize = 8usize
        .checked_add(header_pickle_size)
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

#[cfg(test)]
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
    if node.unpacked.is_some_and(|value: bool| value) {
        return;
    }
    let Some(offset_str) = node.offset.as_deref() else {
        return;
    };
    let Ok(offset) = offset_str.parse::<u64>() else {
        return;
    };
    let size: u64 = node.size.map_or(0, |value: u64| value);
    let executable: bool = node.executable.is_some_and(|value: bool| value);
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
        let mut header: String = String::from(r#"{"files":{"#);
        let mut offset: u64 = 0;
        for (i, (name, body)) in files.iter().enumerate() {
            if i > 0 {
                header.push(',');
            }
            let size: usize = body.len();
            push_asar_entry(&mut header, name, size, offset);
            offset += body.len() as u64;
        }
        header.push_str("}}");
        let header_bytes: &[u8] = header.as_bytes();
        let header_size: u32 = u32::try_from(header_bytes.len()).expect("len fits");
        let aligned: u32 = u32::try_from(align_up(header_bytes.len(), 4)).expect("len fits");
        let string_pickle_size: u32 = aligned + 4;
        let header_pickle_size: u32 = string_pickle_size + 4;
        let mut out: Vec<u8> = Vec::with_capacity(16 + aligned as usize);
        out.extend_from_slice(&ALIGNMENT_PREFIX);
        out.extend_from_slice(&header_pickle_size.to_le_bytes());
        out.extend_from_slice(&string_pickle_size.to_le_bytes());
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(header_bytes);
        let padding: usize = (aligned - header_size) as usize;
        out.extend(std::iter::repeat_n(0u8, padding));
        for (_, body) in files {
            out.extend_from_slice(body);
        }
        out
    }

    fn push_asar_entry(header: &mut String, name: &str, size: usize, offset: u64) {
        header.push('"');
        header.push_str(name);
        header.push_str(r#"":{"size":"#);
        header.push_str(&size.to_string());
        header.push_str(r#","offset":""#);
        header.push_str(&offset.to_string());
        header.push_str(r#""}"#);
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

    #[test]
    fn emits_variable_string_pickle_size_not_constant() {
        let bytes: Vec<u8> = synth_asar(&[("a.txt", b"aaa")]);
        assert_eq!(bytes[0..4], ALIGNMENT_PREFIX);
        assert_ne!(bytes[8..12], ALIGNMENT_PREFIX);
        let header_pickle: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let string_pickle: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let json_len: u32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(header_pickle, string_pickle + 4);
        assert!((4..=7).contains(&(string_pickle - json_len)));
    }

    #[test]
    fn rejects_constant_inner_marker_shape() {
        let header: &[u8] = br#"{"files":{"a.txt":{"size":3,"offset":"0"}}}"#;
        let aligned: usize = align_up(header.len(), 4);
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&ALIGNMENT_PREFIX);
        out.extend_from_slice(&(8 + aligned as u32).to_le_bytes());
        out.extend_from_slice(&ALIGNMENT_PREFIX);
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(header);
        out.extend(std::iter::repeat_n(0u8, aligned - header.len()));
        out.extend_from_slice(b"aaa");
        let err: Error = parse(&out).unwrap_err();
        assert!(matches!(err, Error::AsarHeader(_)));
    }

    #[test]
    fn parses_real_electron_asar() {
        let bytes: &[u8] = include_bytes!("../tests/fixtures/asar/real_electron.asar");
        let layout: AsarLayout = parse(bytes).expect("parse real asar");
        let by_path: BTreeMap<&str, &AsarEntry> = layout
            .entries
            .iter()
            .map(|e: &AsarEntry| (e.path.as_str(), e))
            .collect();
        let a: &AsarEntry = by_path.get("a.txt").expect("a.txt entry");
        let b: &AsarEntry = by_path.get("b.js").expect("b.js entry");
        assert_eq!(
            read_entry(bytes, &layout, a).expect("a bytes"),
            b"hello asar body\n"
        );
        assert_eq!(read_entry(bytes, &layout, b).expect("b bytes"), b"second\n");
    }
}
