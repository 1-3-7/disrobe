pub mod lift;
pub mod lua51;
pub mod luajit21;
pub mod luajit_lift;
pub mod luau_lift;
pub(crate) mod luau_structure;
pub mod opcode;
pub mod struct_lift;

use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::decompile::lift::{LiftedProto, lift_proto_dialect};
use crate::error::{Error, Result};
use crate::reader::common::{LuaChunk, LuaDialect, LuaProto};
use crate::reader::{DetectedFormat, detect, read_auto};

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
    let params: String = (0..u32::from(main.num_params))
        .map(|i: u32| crate::decompile::lift::proto_param_name(main, i))
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
    dbg_section("lua.decompile_chunk");
    dbg_kv("dialect", || format!("{:?}", chunk.dialect));
    if matches!(chunk.dialect, LuaDialect::Luau) {
        dbg_kv("lifter", || "luau-structure".to_owned());
        return luau_lift::decompile(chunk);
    }
    dbg_kv("lifter", || "register".to_owned());
    dbg_kv("main_instructions", || chunk.main.code.len().to_string());
    dbg_kv("main_constants", || chunk.main.constants.len().to_string());
    let mut out: String = String::new();
    let mut warnings: Vec<String> = Vec::new();
    out.push_str(lifter_banner(chunk.dialect));
    out.push_str(&main_signature(&chunk.main));
    out.push('\n');

    let structured: Option<LiftedProto> =
        crate::decompile::struct_lift::lift_structured(&chunk.main, chunk.dialect, 0);
    let lifted: LiftedProto = match structured {
        Some(s) => {
            dbg_kv("lifter_mode", || "structured".to_owned());
            s
        }
        None => {
            dbg_kv("lifter_mode", || "linear-fallback".to_owned());
            lift_proto_dialect(&chunk.main, chunk.dialect, 0)
        }
    };
    dbg_kv("fully_structured", || lifted.fully_structured.to_string());
    dbg_kv("warnings", || lifted.warnings.len().to_string());
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
    dbg_kv("fidelity", || format!("{fidelity:?}"));
    Ok(DecompiledChunk {
        source: out,
        fidelity,
        warnings,
    })
}

pub fn decompile_luajit_bytes(bytes: &[u8]) -> Result<DecompiledChunk> {
    luajit_lift::decompile(bytes)
}

pub fn decompile_auto(bytes: &[u8]) -> Result<DecompiledChunk> {
    let format: DetectedFormat = detect(bytes);
    dbg_kv("decompile_auto.format", || format!("{format:?}"));
    match format {
        DetectedFormat::LuaJit => {
            dbg_kv("decompile_auto.path", || "luajit-lift".to_owned());
            luajit_lift::decompile(bytes)
        }
        DetectedFormat::Unknown => {
            dbg_line(|| "decompile_auto: unknown format, not decompilable".to_owned());
            Err(Error::BadSignature)
        }
        _ => {
            dbg_kv("decompile_auto.path", || {
                "standard-register-lift".to_owned()
            });
            let chunk: LuaChunk = read_auto(bytes)?;
            decompile_chunk(&chunk)
        }
    }
}
