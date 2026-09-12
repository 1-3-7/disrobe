use crate::decompile::{DecompiledChunk, Fidelity};
use crate::error::Result;
use crate::reader::common::{LuaChunk, LuaConstant, LuaProto};

pub fn decompile(chunk: &LuaChunk) -> Result<DecompiledChunk> {
    let mut out: String = String::new();
    let mut warnings: Vec<String> = Vec::new();
    out.push_str(
        "-- disrobe luajit bytecode disassembly (register lifter for luajit ISA pending)\n",
    );
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
            "ljproto has {} BC ops; emitting disassembly (luajit register lifter pending)",
            p.code.len()
        ));
        for (pc, inst) in p.code.iter().enumerate() {
            let op: u8 = (*inst & 0xFF) as u8;
            let a: u8 = ((*inst >> 8) & 0xFF) as u8;
            let cd: u16 = ((*inst >> 16) & 0xFFFF) as u16;
            let b: u8 = ((*inst >> 24) & 0xFF) as u8;
            out.push_str(&pad);
            out.push_str(&format!(
                "  -- {pc:04} {:<10} A={a} B={b} C/D={cd}\n",
                lj_mnemonic(op)
            ));
        }
    }
    out.push_str(&pad);
    out.push_str("end\n");
}

#[must_use]
fn lj_mnemonic(op: u8) -> &'static str {
    LJ_OPCODES.get(op as usize).copied().unwrap_or("UNKNOWN")
}

const LJ_OPCODES: [&str; 92] = [
    "ISLT", "ISGE", "ISLE", "ISGT", "ISEQV", "ISNEV", "ISEQS", "ISNES", "ISEQN", "ISNEN", "ISEQP",
    "ISNEP", "ISTC", "ISFC", "IST", "ISF", "ISTYPE", "ISNUM", "MOV", "NOT", "UNM", "LEN", "ADDVN",
    "SUBVN", "MULVN", "DIVVN", "MODVN", "ADDNV", "SUBNV", "MULNV", "DIVNV", "MODNV", "ADDVV",
    "SUBVV", "MULVV", "DIVVV", "MODVV", "POW", "CAT", "KSTR", "KCDATA", "KSHORT", "KNUM", "KPRI",
    "KNIL", "UGET", "USETV", "USETS", "USETN", "USETP", "UCLO", "FNEW", "TNEW", "TDUP", "GGET",
    "GSET", "TGETV", "TGETS", "TGETB", "TGETR", "TSETV", "TSETS", "TSETB", "TSETM", "TSETR",
    "CALLM", "CALL", "CALLMT", "CALLT", "ITERC", "ITERN", "VARG", "ISNEXT", "RETM", "RET", "RET0",
    "RET1", "FORI", "JFORI", "FORL", "IFORL", "JFORL", "ITERL", "IITERL", "JITERL", "LOOP",
    "ILOOP", "JLOOP", "JMP", "FUNCF", "IFUNCF", "JFUNCF",
];

fn format_const(k: &LuaConstant) -> String {
    match k {
        LuaConstant::Nil => "nil".to_owned(),
        LuaConstant::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
        LuaConstant::Integer(i) => i.to_string(),
        LuaConstant::Number(n) => format!("{n}"),
        LuaConstant::Str(s) => format!("{s:?}"),
        LuaConstant::Import(_) | LuaConstant::ClosureRef(_) | LuaConstant::Vector(_) => {
            "nil".to_owned()
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_table_known_ops() {
        assert_eq!(lj_mnemonic(0), "ISLT");
        assert_eq!(lj_mnemonic(18), "MOV");
        assert_eq!(lj_mnemonic(88), "JMP");
        assert_eq!(lj_mnemonic(74), "RET");
        assert_eq!(lj_mnemonic(66), "CALL");
    }

    #[test]
    fn mnemonic_out_of_range_is_unknown() {
        assert_eq!(lj_mnemonic(200), "UNKNOWN");
    }
}
