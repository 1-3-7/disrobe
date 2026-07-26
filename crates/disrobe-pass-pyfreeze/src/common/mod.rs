use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

pub mod manifest;
pub mod pyc;
pub mod quota;
pub mod read_bounded;
pub mod shebang;
pub mod zip_tail;

pub(crate) const MAX_JSON_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn parse_json_manifest<T>(bytes: &[u8], resource: &'static str) -> Result<T>
where
    T: DeserializeOwned,
{
    if bytes.len() > MAX_JSON_MANIFEST_BYTES {
        return Err(Error::JsonManifestTooLarge {
            resource,
            bytes: bytes.len(),
            max_bytes: MAX_JSON_MANIFEST_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(Error::from)
}
