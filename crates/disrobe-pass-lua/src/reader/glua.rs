use crate::error::Result;
use crate::reader::common::{LuaChunk, LuaDialect};
use crate::reader::lua51;

pub const GLUA_HEADER_OFFSET: usize = 1;
pub const GLUA_PREFIX_BYTE: u8 = 0x1C;

#[must_use]
pub fn looks_like_glua(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(&GLUA_PREFIX_BYTE))
        && bytes.get(1..5).is_some_and(|s| s == b"\x1BLua")
}

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let trimmed: &[u8] = if looks_like_glua(bytes) {
        &bytes[GLUA_HEADER_OFFSET..]
    } else {
        bytes
    };
    let mut chunk: LuaChunk = lua51::read(trimmed)?;
    chunk.dialect = LuaDialect::GLua;
    Ok(chunk)
}
