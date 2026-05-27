use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const SEA_MAGIC: &[u8; 8] = b"NODE_SEA";
pub const SEA_RESOURCE_TAG_V1: u32 = 0x143A_3170;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeaBlobLocation {
    pub blob_offset: u64,
    pub blob_size: u64,
    pub flag_offset: Option<u64>,
}

#[must_use]
pub fn detect_node_sea_blob(bytes: &[u8]) -> Option<SeaBlobLocation> {
    let magic_off: usize = locate_magic(bytes)?;
    let tag_off: usize = magic_off
        .checked_sub(8)
        .filter(|&off: &usize| off + 4 <= bytes.len())?;
    if tag_off + 4 > bytes.len() {
        return None;
    }
    let tag: u32 = u32::from_le_bytes([
        bytes[tag_off],
        bytes[tag_off + 1],
        bytes[tag_off + 2],
        bytes[tag_off + 3],
    ]);
    if tag != SEA_RESOURCE_TAG_V1 {
        return Some(SeaBlobLocation {
            blob_offset: magic_off as u64,
            blob_size: (bytes.len() - magic_off) as u64,
            flag_offset: None,
        });
    }
    let blob_size: u32 = u32::from_le_bytes([
        bytes[tag_off + 4],
        bytes[tag_off + 5],
        bytes[tag_off + 6],
        bytes[tag_off + 7],
    ]);
    Some(SeaBlobLocation {
        blob_offset: magic_off as u64,
        blob_size: u64::from(blob_size),
        flag_offset: Some(tag_off as u64),
    })
}

fn locate_magic(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(SEA_MAGIC.len())
        .enumerate()
        .find_map(|(i, w): (usize, &[u8])| if w == SEA_MAGIC { Some(i) } else { None })
}

pub fn carve_sea_payload(bytes: &[u8]) -> Result<Vec<u8>> {
    let loc: SeaBlobLocation = detect_node_sea_blob(bytes)
        .ok_or_else(|| Error::OxcParse("NODE_SEA magic not found in binary".to_owned()))?;
    let start: usize = usize::try_from(loc.blob_offset)
        .map_err(|_| Error::OxcParse("sea blob offset overflows usize".to_owned()))?;
    let size: usize = usize::try_from(loc.blob_size)
        .map_err(|_| Error::OxcParse("sea blob size overflows usize".to_owned()))?;
    let end: usize = start
        .checked_add(size)
        .ok_or_else(|| Error::OxcParse("sea blob end overflows usize".to_owned()))?;
    if end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "sea blob extends past binary: end={end}, len={}",
            bytes.len()
        )));
    }
    Ok(bytes[start..end].to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_sea_binary(payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 64];
        out.extend_from_slice(&SEA_RESOURCE_TAG_V1.to_le_bytes());
        let blob_size: u32 = u32::try_from(payload.len() + SEA_MAGIC.len()).unwrap();
        out.extend_from_slice(&blob_size.to_le_bytes());
        out.extend_from_slice(SEA_MAGIC);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn detects_tagged_sea_blob() {
        let payload: &[u8] = b"console.log('hi from sea');\n";
        let bytes: Vec<u8> = synth_sea_binary(payload);
        let loc: SeaBlobLocation = detect_node_sea_blob(&bytes).expect("sea detected");
        assert!(loc.flag_offset.is_some());
        assert_eq!(
            usize::try_from(loc.blob_size).unwrap(),
            payload.len() + SEA_MAGIC.len()
        );
    }

    #[test]
    fn carves_sea_payload_including_magic() {
        let payload: &[u8] = b"abc";
        let bytes: Vec<u8> = synth_sea_binary(payload);
        let carved: Vec<u8> = carve_sea_payload(&bytes).expect("carve");
        assert!(carved.starts_with(SEA_MAGIC));
        assert!(carved.ends_with(payload));
    }

    #[test]
    fn returns_none_on_non_sea_binary() {
        assert!(detect_node_sea_blob(&[0u8; 256]).is_none());
    }
}
