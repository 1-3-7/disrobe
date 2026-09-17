use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const ASAR_OUTER_MARKER: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
pub const ASAR_HEADER_PREFIX_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsarListingEntry {
    pub path: String,
    pub size: u64,
    pub offset: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsarListing {
    pub data_offset: u64,
    pub entries: Vec<AsarListingEntry>,
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

pub fn list_asar(bytes: &[u8]) -> Result<AsarListing> {
    if bytes.len() < ASAR_HEADER_PREFIX_LEN {
        return Err(Error::OxcParse(
            "asar prefix truncated (<16 bytes)".to_owned(),
        ));
    }
    if bytes[0..4] != ASAR_OUTER_MARKER {
        return Err(Error::OxcParse(
            "asar missing outer 0x04 marker at offset 0".to_owned(),
        ));
    }
    if bytes[8..12] != ASAR_OUTER_MARKER {
        return Err(Error::OxcParse(
            "asar missing inner 0x04 marker at offset 8".to_owned(),
        ));
    }
    let header_size: u32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let header_end: usize = ASAR_HEADER_PREFIX_LEN
        .checked_add(header_size as usize)
        .ok_or_else(|| Error::OxcParse("asar header end overflows usize".to_owned()))?;
    if header_end > bytes.len() {
        return Err(Error::OxcParse(
            "asar header extends past end of input".to_owned(),
        ));
    }
    let aligned: usize = align_up(header_size as usize, 4);
    let data_offset: usize = ASAR_HEADER_PREFIX_LEN
        .checked_add(aligned)
        .ok_or_else(|| Error::OxcParse("asar data offset overflows usize".to_owned()))?;
    let header_json: &[u8] = &bytes[ASAR_HEADER_PREFIX_LEN..header_end];
    let root: RawNode = serde_json::from_slice(header_json)
        .map_err(|e: serde_json::Error| Error::OxcParse(format!("asar header json: {e}")))?;
    let mut entries: Vec<AsarListingEntry> = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    walk(&root, &mut stack, &mut entries);
    Ok(AsarListing {
        data_offset: data_offset as u64,
        entries,
    })
}

pub fn carve_entry<'a>(
    bytes: &'a [u8],
    listing: &AsarListing,
    entry: &AsarListingEntry,
) -> Result<&'a [u8]> {
    let start: usize = usize::try_from(listing.data_offset.saturating_add(entry.offset)).map_err(
        |_: std::num::TryFromIntError| {
            Error::OxcParse("asar entry offset overflows usize".to_owned())
        },
    )?;
    let size: usize = usize::try_from(entry.size).map_err(|_: std::num::TryFromIntError| {
        Error::OxcParse("asar entry size overflows usize".to_owned())
    })?;
    let end: usize = start
        .checked_add(size)
        .ok_or_else(|| Error::OxcParse("asar entry end overflows usize".to_owned()))?;
    if end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "asar entry {} carve out of bounds: end={end}, len={}",
            entry.path,
            bytes.len()
        )));
    }
    Ok(&bytes[start..end])
}

const fn align_up(value: usize, align: usize) -> usize {
    let rem: usize = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn walk(node: &RawNode, stack: &mut Vec<String>, out: &mut Vec<AsarListingEntry>) {
    if let Some(children) = node.files.as_ref() {
        for (name, child) in children {
            stack.push(name.clone());
            walk(child, stack, out);
            stack.pop();
        }
        return;
    }
    if node.unpacked.unwrap_or(false) {
        return;
    }
    let Some(offset_str): Option<&str> = node.offset.as_deref() else {
        return;
    };
    let Ok(offset): std::result::Result<u64, _> = offset_str.parse::<u64>() else {
        return;
    };
    out.push(AsarListingEntry {
        path: stack.join("/"),
        size: node.size.unwrap_or(0),
        offset,
        executable: node.executable.unwrap_or(false),
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
        let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
        if let Err(error) = result {
            unreachable!("string formatting failed: {error}");
        }
    }

    fn synth_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut header: String = String::from(r#"{"files":{"#);
        let mut offset: u64 = 0;
        for (i, (name, body)) in files.iter().enumerate() {
            if i > 0 {
                header.push(',');
            }
            let size: usize = body.len();
            push_format(
                &mut header,
                format_args!(r#""{name}":{{"size":{size},"offset":"{offset}"}}"#),
            );
            offset += body.len() as u64;
        }
        header.push_str("}}");
        let header_bytes: &[u8] = header.as_bytes();
        let header_size: u32 = u32::try_from(header_bytes.len()).unwrap();
        let aligned: u32 = u32::try_from(align_up(header_bytes.len(), 4)).unwrap();
        let pickle_size: u32 = 8 + aligned;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&ASAR_OUTER_MARKER);
        out.extend_from_slice(&pickle_size.to_le_bytes());
        out.extend_from_slice(&ASAR_OUTER_MARKER);
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(header_bytes);
        out.extend(std::iter::repeat_n(0u8, (aligned - header_size) as usize));
        for (_, body) in files {
            out.extend_from_slice(body);
        }
        out
    }

    #[test]
    fn lists_two_entries_with_offsets() {
        let bytes: Vec<u8> = synth_asar(&[("a.js", b"alert(1)"), ("b.txt", b"plain")]);
        let listing: AsarListing = list_asar(&bytes).expect("list");
        assert_eq!(listing.entries.len(), 2);
        assert!(listing.data_offset >= ASAR_HEADER_PREFIX_LEN as u64);
        assert_eq!(listing.entries[0].path, "a.js");
        assert_eq!(listing.entries[1].path, "b.txt");
    }

    #[test]
    fn carves_each_entry_to_its_original_bytes() {
        let bytes: Vec<u8> = synth_asar(&[("a.js", b"alert(1)"), ("b.txt", b"plain")]);
        let listing: AsarListing = list_asar(&bytes).expect("list");
        let a: &[u8] = carve_entry(&bytes, &listing, &listing.entries[0]).expect("carve a");
        let b: &[u8] = carve_entry(&bytes, &listing, &listing.entries[1]).expect("carve b");
        assert_eq!(a, b"alert(1)");
        assert_eq!(b, b"plain");
    }

    #[test]
    fn rejects_short_prefix() {
        let err: Error = list_asar(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, Error::OxcParse(_)));
    }
}
