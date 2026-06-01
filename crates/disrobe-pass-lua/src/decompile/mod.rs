pub mod lift;
pub mod lua51;
pub mod luajit21;
pub mod luajit_lift;
pub mod luau_lift;
pub mod opcode;

use serde::{Deserialize, Serialize};

use crate::decompile::lift::{LiftedProto, lift_proto_dialect};
use crate::error::Result;
use crate::reader::common::{LuaChunk, LuaDialect, LuaProto};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledChunk {
    pub source: String,
    pub fidelity: Fidelity,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Fidelity {
    Lossless,
    Lossy,
    BestEffort,
}

#[must_use]
fn lifter_banner(dialect: LuaDialect) -> &'static str {
    match dialect {
        LuaDialect::Lua51 | LuaDialect::GLua => {
            "-- decompiled by disrobe (lua 5.1 register lifter)\n"
        }
        LuaDialect::Lua52 => "-- decompiled by disrobe (lua 5.2 register lifter)\n",
        LuaDialect::Lua53 => "-- decompiled by disrobe (lua 5.3 register lifter)\n",
        LuaDialect::Lua54 => "-- decompiled by disrobe (lua 5.4 register lifter)\n",
        _ => "-- decompiled by disrobe (lua register lifter)\n",
    }
}

#[must_use]
fn main_signature(main: &LuaProto) -> String {
    let params: String = (0..main.num_params)
        .map(|i: u8| format!("p{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    match (params.is_empty(), main.is_vararg != 0) {
        (true, false) => "function _main()".to_owned(),
        (true, true) => "function _main(...)".to_owned(),
        (false, false) => format!("function _main({params})"),
        (false, true) => format!("function _main({params}, ...)"),
    }
}

pub fn decompile_chunk(chunk: &LuaChunk) -> Result<DecompiledChunk> {
    if matches!(chunk.dialect, LuaDialect::Luau) {
        return luau_lift::decompile(chunk);
    }
    let mut out: String = String::new();
    let mut warnings: Vec<String> = Vec::new();
    out.push_str(lifter_banner(chunk.dialect));
    out.push_str(&main_signature(&chunk.main));
    out.push('\n');

    let lifted: LiftedProto = lift_proto_dialect(&chunk.main, chunk.dialect, 0);
    warnings.extend(lifted.warnings);
    for ln in lifted.source.lines() {
        out.push_str(ln);
        out.push('\n');
    }
    out.push_str("end\n");

    let fidelity: Fidelity = if warnings.is_empty() && lifted.fully_structured {
        Fidelity::Lossless
    } else if lifted.fully_structured {
        Fidelity::Lossy
    } else {
        Fidelity::BestEffort
    };
    Ok(DecompiledChunk {
        source: out,
        fidelity,
        warnings,
    })
}

pub fn decompile_luajit_bytes(bytes: &[u8]) -> Result<DecompiledChunk> {
    luajit_lift::decompile(bytes)
}
