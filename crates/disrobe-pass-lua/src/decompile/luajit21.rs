use crate::decompile::{DecompiledChunk, Fidelity};
use crate::error::Result;
use crate::reader::common::{LuaChunk, LuaConstant, LuaProto};

pub fn decompile(chunk: &LuaChunk) -> Result<DecompiledChunk> {
    let mut out: String = String::new();
    let mut warnings: Vec<String> = Vec::new();
    out.push_str("-- decompiled by disrobe (luajit-decompiler-v2 port, stripped-chunk mode)\n");
    emit_proto(&chunk.main, 0, &mut out, &mut warnings);
    Ok(DecompiledChunk {
        source: out,
        fidelity: Fidelity::BestEffort,
        warnings,
    })
}

fn emit_proto(p: &LuaProto, indent: usize, out: &mut String, warnings: &mut Vec<String>) {
    let pad: String = "  ".repeat(indent);
    out.push_str(&pad);
    out.push_str(&format!(
        "function _ljp_{}({}) -- framesize={}\n",
        p.line_defined,
        (0..p.num_params)
            .map(|i: u8| format!("a{i}"))
            .collect::<Vec<String>>()
            .join(", "),
        p.max_stack_size
    ));
    for (i, k) in p.constants.iter().enumerate() {
        out.push_str(&pad);
        out.push_str(&format!("  local _k{i} = {}\n", format_const(k)));
    }
    if p.code.is_empty() {
        out.push_str(&pad);
        out.push_str("  return\n");
    } else {
        warnings.push(format!(
            "ljproto has {} BC ops; bytecode→source lifter pending",
            p.code.len()
        ));
        for (pc, inst) in p.code.iter().enumerate() {
            out.push_str(&pad);
            out.push_str(&format!("  -- BC pc={pc} word=0x{inst:08X}\n"));
        }
    }
    out.push_str(&pad);
    out.push_str("end\n");
}

fn format_const(k: &LuaConstant) -> String {
    match k {
        LuaConstant::Nil => "nil".to_owned(),
        LuaConstant::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
        LuaConstant::Integer(i) => i.to_string(),
        LuaConstant::Number(n) => format!("{n}"),
        LuaConstant::Str(s) => format!("{s:?}"),
    }
}
