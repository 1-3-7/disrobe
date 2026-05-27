use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LuaDialect {
    Lua51,
    Lua52,
    Lua53,
    Lua54,
    LuaJit20,
    LuaJit21,
    Luau,
    GLua,
}

impl LuaDialect {
    #[inline]
    #[must_use]
    pub const fn marketing_name(self) -> &'static str {
        match self {
            Self::Lua51 => "Lua 5.1",
            Self::Lua52 => "Lua 5.2",
            Self::Lua53 => "Lua 5.3",
            Self::Lua54 => "Lua 5.4",
            Self::LuaJit20 => "LuaJIT 2.0",
            Self::LuaJit21 => "LuaJIT 2.1",
            Self::Luau => "Roblox Luau",
            Self::GLua => "Garry's Mod Lua",
        }
    }

    #[inline]
    #[must_use]
    pub const fn version_byte(self) -> Option<u8> {
        match self {
            Self::Lua51 => Some(0x51),
            Self::Lua52 => Some(0x52),
            Self::Lua53 => Some(0x53),
            Self::Lua54 => Some(0x54),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LuaConstant {
    Nil,
    Bool(bool),
    Integer(i64),
    Number(f64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaLocal {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaUpvalueName {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LuaProto {
    pub source: Option<String>,
    pub line_defined: u32,
    pub last_line_defined: u32,
    pub num_params: u8,
    pub is_vararg: u8,
    pub max_stack_size: u8,
    pub code: Vec<u32>,
    pub constants: Vec<LuaConstant>,
    pub protos: Vec<LuaProto>,
    pub source_lines: Vec<u32>,
    pub locals: Vec<LuaLocal>,
    pub upvalues: Vec<LuaUpvalueName>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LuaChunk {
    pub dialect: LuaDialect,
    pub version_byte: u8,
    pub format: u8,
    pub little_endian: bool,
    pub size_of_int: u8,
    pub size_of_size_t: u8,
    pub size_of_instruction: u8,
    pub size_of_lua_integer: u8,
    pub size_of_lua_number: u8,
    pub integral_number: bool,
    pub main: LuaProto,
}

pub const LUA_SIGNATURE: [u8; 4] = [0x1B, b'L', b'u', b'a'];
pub const LUAC_DATA_TAIL: [u8; 6] = [0x19, 0x93, b'\r', b'\n', 0x1A, b'\n'];
pub const LUAJIT_SIGNATURE: [u8; 3] = [0x1B, b'L', b'J'];
