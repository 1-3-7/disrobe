use rkyv::rancor::Error as RkyvError;

use crate::types::{ArchivedNirModule, NirModule};

#[derive(Debug, thiserror::Error)]
pub enum NirCodecError {
    #[error("rkyv serialize nir module: {0}")]
    Serialize(String),
    #[error("rkyv access nir module: {0}")]
    Access(String),
    #[error("rkyv deserialize nir module: {0}")]
    Deserialize(String),
}

pub fn encode_nir(module: &NirModule) -> Result<Vec<u8>, NirCodecError> {
    rkyv::to_bytes::<RkyvError>(module)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| NirCodecError::Serialize(e.to_string()))
}

pub fn decode_nir(bytes: &[u8]) -> Result<NirModule, NirCodecError> {
    let archived: &ArchivedNirModule = rkyv::access::<ArchivedNirModule, RkyvError>(bytes)
        .map_err(|e| NirCodecError::Access(e.to_string()))?;
    rkyv::deserialize::<NirModule, RkyvError>(archived)
        .map_err(|e| NirCodecError::Deserialize(e.to_string()))
}
