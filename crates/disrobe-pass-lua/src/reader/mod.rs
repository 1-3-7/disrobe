pub mod common;
pub mod glua;
pub mod lua51;
pub mod lua52;
pub mod lua53;
pub mod lua54;
pub mod luajit;
pub mod luau;

pub use common::{
    LUA_SIGNATURE, LUAC_DATA_TAIL, LUAJIT_SIGNATURE, LuaChunk, LuaConstant, LuaDialect, LuaLocal,
    LuaProto, LuaUpvalueName,
};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    Lua51,
    Lua52,
    Lua53,
    Lua54,
    LuaJit,
    Luau,
    GLua,
    Unknown,
}

#[must_use]
pub fn detect(bytes: &[u8]) -> DetectedFormat {
    if glua::looks_like_glua(bytes) {
        return DetectedFormat::GLua;
    }
    if bytes.starts_with(&LUAJIT_SIGNATURE) {
        return DetectedFormat::LuaJit;
    }
    if bytes.starts_with(&LUA_SIGNATURE) {
        return match bytes.get(4) {
            Some(0x51) => DetectedFormat::Lua51,
            Some(0x52) => DetectedFormat::Lua52,
            Some(0x53) => DetectedFormat::Lua53,
            Some(0x54) => DetectedFormat::Lua54,
            _ => DetectedFormat::Unknown,
        };
    }
    match bytes.first() {
        Some(&v) if (1u8..=11).contains(&v) => DetectedFormat::Luau,
        _ => DetectedFormat::Unknown,
    }
}

pub fn read_auto(bytes: &[u8]) -> Result<LuaChunk> {
    match detect(bytes) {
        DetectedFormat::Lua51 => lua51::read(bytes),
        DetectedFormat::Lua52 => lua52::read(bytes),
        DetectedFormat::Lua53 => lua53::read(bytes),
        DetectedFormat::Lua54 => lua54::read(bytes),
        DetectedFormat::LuaJit => luajit::read(bytes),
        DetectedFormat::Luau => luau::read(bytes),
        DetectedFormat::GLua => glua::read(bytes),
        DetectedFormat::Unknown => Err(Error::BadSignature),
    }
}
