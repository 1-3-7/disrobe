use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuvitBundle {
    pub format: LuvitFormat,
    pub manifest: BTreeMap<String, String>,
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LuvitFormat {
    LitZip,
    LitTar,
    LuviAppended,
}

pub const LIT_ZIP_MAGIC: [u8; 4] = [b'L', b'I', b'T', 0x01];
pub const LUVI_TRAILER_MAGIC: [u8; 4] = [b'L', b'I', b'T', b'!'];

pub fn detect(bytes: &[u8]) -> Option<LuvitFormat> {
    if bytes.starts_with(&LIT_ZIP_MAGIC) {
        return Some(LuvitFormat::LitZip);
    }
    if bytes.len() >= 4 && bytes[bytes.len() - 4..] == LUVI_TRAILER_MAGIC {
        return Some(LuvitFormat::LuviAppended);
    }
    if bytes.starts_with(b"./package.lua\0") {
        return Some(LuvitFormat::LitTar);
    }
    None
}

pub fn extract(bytes: &[u8]) -> Result<LuvitBundle> {
    let format: LuvitFormat = detect(bytes).ok_or(Error::LuvitMalformed("no lit/luvi magic"))?;
    let manifest: BTreeMap<String, String> = BTreeMap::new();
    let files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    Ok(LuvitBundle {
        format,
        manifest,
        files,
    })
}
