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

use crate::debug::{dbg_hex, dbg_kv, dbg_line, dbg_section};
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
    dbg_section("lua.detect");
    dbg_kv("input_len", || bytes.len().to_string());
    dbg_hex("signature", bytes, 8);
    if glua::looks_like_glua(bytes) {
        dbg_kv("classify", || "glua".to_owned());
        return DetectedFormat::GLua;
    }
    if bytes.starts_with(&LUAJIT_SIGNATURE) {
        dbg_kv("classify", || "luajit".to_owned());
        dbg_kv("luajit_version_byte", || {
            bytes
                .get(3)
                .map_or_else(|| "?".to_owned(), |b: &u8| format!("0x{b:02x}"))
        });
        return DetectedFormat::LuaJit;
    }
    if bytes.starts_with(&LUA_SIGNATURE) {
        let version: Option<&u8> = bytes.get(4);
        dbg_kv("standard_version_byte", || {
            version.map_or_else(|| "?".to_owned(), |b: &u8| format!("0x{b:02x}"))
        });
        let fmt: DetectedFormat = match version {
            Some(0x51) => DetectedFormat::Lua51,
            Some(0x52) => DetectedFormat::Lua52,
            Some(0x53) => DetectedFormat::Lua53,
            Some(0x54) => DetectedFormat::Lua54,
            _ => DetectedFormat::Unknown,
        };
        dbg_kv("classify", || format!("{fmt:?}"));
        return fmt;
    }
    match bytes.first() {
        Some(&v) if (1u8..=11).contains(&v) => {
            dbg_kv("classify", || "luau".to_owned());
            dbg_kv("luau_bytecode_version", || v.to_string());
            DetectedFormat::Luau
        }
        _ => {
            dbg_line(|| "no standard/luajit/luau signature: not lua bytecode".to_owned());
            DetectedFormat::Unknown
        }
    }
}

pub fn read_auto(bytes: &[u8]) -> Result<LuaChunk> {
    let format: DetectedFormat = detect(bytes);
    dbg_kv("read_auto.dispatch", || format!("{format:?}"));
    let result: Result<LuaChunk> = match format {
        DetectedFormat::Lua51 => lua51::read(bytes),
        DetectedFormat::Lua52 => lua52::read(bytes),
        DetectedFormat::Lua53 => lua53::read(bytes),
        DetectedFormat::Lua54 => lua54::read(bytes),
        DetectedFormat::LuaJit => luajit::read(bytes),
        DetectedFormat::Luau => luau::read(bytes),
        DetectedFormat::GLua => glua::read(bytes),
        DetectedFormat::Unknown => Err(Error::BadSignature),
    };
    match &result {
        Ok(chunk) => dbg_kv("read_auto.dialect", || format!("{:?}", chunk.dialect)),
        Err(e) => dbg_line(|| format!("read_auto failed: {e}")),
    }
    result
}
