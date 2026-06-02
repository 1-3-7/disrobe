use crate::cursor::ByteCursor;
use crate::decompile::{DecompiledChunk, Fidelity};
use crate::error::{Error, Result};
use crate::reader::common::{LUAJIT_SIGNATURE, LuaDialect};

const FLAG_STRIPPED: u32 = 0x02;
const PROTO_VARARG: u8 = 0x02;

const KGC_CHILD: u64 = 0;
const KGC_TAB: u64 = 1;
const KGC_I64: u64 = 2;
const KGC_U64: u64 = 3;
const KGC_COMPLEX: u64 = 4;
const KGC_STR_BASE: u64 = 5;

const KTAB_NIL: u64 = 0;
const KTAB_FALSE: u64 = 1;
const KTAB_TRUE: u64 = 2;
const KTAB_INT: u64 = 3;
const KTAB_NUM: u64 = 4;
const KTAB_STR_BASE: u64 = 5;

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum LjKgc {
    Child(u32),
    Table,
    I64(i64),
    U64(u64),
    Complex,
    Str(String),
}

#[derive(Debug, Clone)]
enum LjKn {
    Int(i32),
    Num(f64),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct LjProto {
    flags: u8,
    num_params: u8,
    framesize: u8,
    num_uv: u8,
    code: Vec<u32>,
    uv_refs: Vec<u16>,
    uv_names: Vec<String>,
    kgc: Vec<LjKgc>,
    kn: Vec<LjKn>,
    strings_reversed: Vec<String>,
    local_names: Vec<String>,
    first_line: u32,
}

impl LjProto {
    #[inline]
    fn is_vararg(&self) -> bool {
        self.flags & PROTO_VARARG != 0
    }

    #[inline]
    fn kstr(&self, d: u32) -> Option<&str> {
        self.strings_reversed.get(d as usize).map(String::as_str)
    }

    #[inline]
    fn knum(&self, d: u32) -> Option<&LjKn> {
        self.kn.get(d as usize)
    }
}

pub fn decompile(bytes: &[u8]) -> Result<DecompiledChunk> {
    let mut warnings: Vec<String> = Vec::new();
    let protos: Vec<LjProto> = parse_chunk(bytes, &mut warnings)?;
    let Some(main): Option<&LjProto> = protos.last() else {
        return Ok(DecompiledChunk {
            source: "-- disrobe luajit decompiler: empty chunk\n".to_owned(),
            fidelity: Fidelity::BestEffort,
            warnings,
        });
    };
    let mut out: String = String::new();
    out.push_str("-- decompiled by disrobe (luajit 2.x register lifter)\n");
    let header: String = main_signature(main);
    out.push_str(&header);
    out.push('\n');
    let mut fully_structured: bool = true;
    let body: String = lift_proto(main, &protos, 0, &mut warnings, &mut fully_structured);
    for ln in body.lines() {
        out.push_str(ln);
        out.push('\n');
    }
    out.push_str("end\n");
    let fidelity: Fidelity = if warnings.is_empty() && fully_structured {
        Fidelity::Lossless
    } else if fully_structured {
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

#[must_use]
fn main_signature(main: &LjProto) -> String {
    let params: String = (0..main.num_params)
        .map(|i: u8| format!("p{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    match (params.is_empty(), main.is_vararg()) {
        (true, false) => "function _main()".to_owned(),
        (true, true) => "function _main(...)".to_owned(),
        (false, false) => format!("function _main({params})"),
        (false, true) => format!("function _main({params}, ...)"),
    }
}

fn parse_chunk(bytes: &[u8], _warnings: &mut [String]) -> Result<Vec<LjProto>> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let sig: &[u8] = c.read_bytes(3)?;
    if sig != LUAJIT_SIGNATURE {
        return Err(Error::BadLuaJitSignature);
    }
    let version: u8 = c.read_u8()?;
    let _dialect: LuaDialect = match version {
        1 => LuaDialect::LuaJit20,
        2 => LuaDialect::LuaJit21,
        other => return Err(Error::UnsupportedLuaJitVersion(other)),
    };
    let flags: u64 = c.read_uleb128()?;
    let stripped: bool = (flags as u32) & FLAG_STRIPPED != 0;
    if !stripped {
        let src_len: u64 = c.read_uleb128()?;
        if src_len > 0 {
            let _src: &[u8] = c.read_bytes(usize::try_from(src_len).unwrap_or(0))?;
        }
    }
    let mut protos: Vec<LjProto> = Vec::new();
    loop {
        if c.remaining() == 0 {
            break;
        }
        let proto_len: u64 = c.read_uleb128()?;
        if proto_len == 0 {
            break;
        }
        let proto_end: usize = c
            .position()
            .checked_add(usize::try_from(proto_len).unwrap_or(0))
            .unwrap_or(usize::MAX);
        let p: LjProto = parse_proto(&mut c, stripped, proto_end)?;
        protos.push(p);
    }
    Ok(protos)
}

fn parse_proto(c: &mut ByteCursor<'_>, stripped: bool, proto_end: usize) -> Result<LjProto> {
    let flags: u8 = c.read_u8()?;
    let num_params: u8 = c.read_u8()?;
    let framesize: u8 = c.read_u8()?;
    let size_uv: u8 = c.read_u8()?;
    let size_kgc: u64 = c.read_uleb128()?;
    let size_kn: u64 = c.read_uleb128()?;
    let size_bc: u64 = c.read_uleb128()?;

    let size_dbg: u64 = if stripped { 0 } else { c.read_uleb128()? };
    let first_line: u64 = if stripped || size_dbg == 0 {
        0
    } else {
        c.read_uleb128()?
    };
    let _num_line: u64 = if stripped || size_dbg == 0 {
        0
    } else {
        c.read_uleb128()?
    };

    let mut code: Vec<u32> = Vec::with_capacity(c.bounded_capacity(size_bc, 4));
    for _ in 0..size_bc {
        code.push(c.read_u32()?);
    }

    let mut uv_refs: Vec<u16> = Vec::with_capacity(usize::from(size_uv));
    for _ in 0..size_uv {
        uv_refs.push(c.read_u16()?);
    }

    let mut kgc: Vec<LjKgc> = Vec::new();
    let mut child_idx: u32 = 0;
    for _ in 0..size_kgc {
        let tag: u64 = c.read_uleb128()?;
        match tag {
            KGC_CHILD => {
                kgc.push(LjKgc::Child(child_idx));
                child_idx = child_idx.wrapping_add(1);
            }
            KGC_TAB => {
                skip_ktab(c)?;
                kgc.push(LjKgc::Table);
            }
            KGC_I64 => {
                let lo: u64 = c.read_uleb128()?;
                let hi: u64 = c.read_uleb128()?;
                let raw: u64 = (hi << 32) | (lo & 0xFFFF_FFFF);
                kgc.push(LjKgc::I64(raw as i64));
            }
            KGC_U64 => {
                let lo: u64 = c.read_uleb128()?;
                let hi: u64 = c.read_uleb128()?;
                let raw: u64 = (hi << 32) | (lo & 0xFFFF_FFFF);
                kgc.push(LjKgc::U64(raw));
            }
            KGC_COMPLEX => {
                let _re_lo: u64 = c.read_uleb128()?;
                let _re_hi: u64 = c.read_uleb128()?;
                let _im_lo: u64 = c.read_uleb128()?;
                let _im_hi: u64 = c.read_uleb128()?;
                kgc.push(LjKgc::Complex);
            }
            t => {
                let strlen_raw: u64 = t.saturating_sub(KGC_STR_BASE);
                let strlen: usize = usize::try_from(strlen_raw).unwrap_or(0);
                let raw: &[u8] = c.read_bytes(strlen)?;
                let s: String = String::from_utf8_lossy(raw).into_owned();
                kgc.push(LjKgc::Str(s));
            }
        }
    }

    let mut kn: Vec<LjKn> = Vec::with_capacity(c.bounded_capacity(size_kn, 8));
    for _ in 0..size_kn {
        let lo: u64 = c.read_uleb128()?;
        if lo & 1 != 0 {
            let hi: u64 = c.read_uleb128()?;
            let raw_bits: u64 = (hi << 32) | (lo >> 1);
            kn.push(LjKn::Num(f64::from_bits(raw_bits)));
        } else {
            let signed: i32 = (lo >> 1) as i32;
            kn.push(LjKn::Int(signed));
        }
    }

    let strings_reversed: Vec<String> = kgc
        .iter()
        .rev()
        .filter_map(|e: &LjKgc| match e {
            LjKgc::Str(s) => Some(s.clone()),
            _ => None,
        })
        .collect();

    while c.position() < proto_end {
        let _: u8 = c.read_u8()?;
    }

    Ok(LjProto {
        flags,
        num_params,
        framesize,
        num_uv: size_uv,
        code,
        uv_refs,
        uv_names: Vec::new(),
        kgc,
        kn,
        strings_reversed,
        local_names: Vec::new(),
        first_line: u32::try_from(first_line).unwrap_or(0),
    })
}

fn skip_ktab_entry(c: &mut ByteCursor<'_>) -> Result<()> {
    let tp: u64 = c.read_uleb128()?;
    match tp {
        KTAB_NIL | KTAB_FALSE | KTAB_TRUE => Ok(()),
        KTAB_INT => {
            let _v: u64 = c.read_uleb128()?;
            Ok(())
        }
        KTAB_NUM => {
            let _lo: u64 = c.read_uleb128()?;
            let _hi: u64 = c.read_uleb128()?;
            Ok(())
        }
        _ => {
            let len: u64 = tp.saturating_sub(KTAB_STR_BASE);
            let n: usize = usize::try_from(len).unwrap_or(0);
            let _raw: &[u8] = c.read_bytes(n)?;
            Ok(())
        }
    }
}

fn skip_ktab(c: &mut ByteCursor<'_>) -> Result<()> {
    let narray: u64 = c.read_uleb128()?;
    let nhash: u64 = c.read_uleb128()?;
    for _ in 0..narray {
        skip_ktab_entry(c)?;
    }
    for _ in 0..nhash {
        skip_ktab_entry(c)?;
        skip_ktab_entry(c)?;
    }
    Ok(())
}

const OP_ISLT: u8 = 0;
const OP_ISGE: u8 = 1;
const OP_ISLE: u8 = 2;
const OP_ISGT: u8 = 3;
const OP_ISEQV: u8 = 4;
const OP_ISNEV: u8 = 5;
const OP_ISEQS: u8 = 6;
const OP_ISNES: u8 = 7;
const OP_ISEQN: u8 = 8;
const OP_ISNEN: u8 = 9;
const OP_ISEQP: u8 = 10;
const OP_ISNEP: u8 = 11;
const OP_ISTC: u8 = 12;
const OP_ISFC: u8 = 13;
const OP_IST: u8 = 14;
const OP_ISF: u8 = 15;
const OP_ISTYPE: u8 = 16;
const OP_ISNUM: u8 = 17;
const OP_MOV: u8 = 18;
const OP_NOT: u8 = 19;
const OP_UNM: u8 = 20;
const OP_LEN: u8 = 21;
const OP_ADDVN: u8 = 22;
const OP_SUBVN: u8 = 23;
const OP_MULVN: u8 = 24;
const OP_DIVVN: u8 = 25;
const OP_MODVN: u8 = 26;
const OP_ADDNV: u8 = 27;
const OP_SUBNV: u8 = 28;
const OP_MULNV: u8 = 29;
const OP_DIVNV: u8 = 30;
const OP_MODNV: u8 = 31;
const OP_ADDVV: u8 = 32;
const OP_SUBVV: u8 = 33;
const OP_MULVV: u8 = 34;
const OP_DIVVV: u8 = 35;
const OP_MODVV: u8 = 36;
const OP_POW: u8 = 37;
const OP_CAT: u8 = 38;
const OP_KSTR: u8 = 39;
const OP_KCDATA: u8 = 40;
const OP_KSHORT: u8 = 41;
const OP_KNUM: u8 = 42;
const OP_KPRI: u8 = 43;
const OP_KNIL: u8 = 44;
const OP_UGET: u8 = 45;
const OP_USETV: u8 = 46;
const OP_USETS: u8 = 47;
const OP_USETN: u8 = 48;
const OP_USETP: u8 = 49;
const OP_UCLO: u8 = 50;
const OP_FNEW: u8 = 51;
const OP_TNEW: u8 = 52;
const OP_TDUP: u8 = 53;
const OP_GGET: u8 = 54;
const OP_GSET: u8 = 55;
const OP_TGETV: u8 = 56;
const OP_TGETS: u8 = 57;
const OP_TGETB: u8 = 58;
const OP_TGETR: u8 = 59;
const OP_TSETV: u8 = 60;
const OP_TSETS: u8 = 61;
const OP_TSETB: u8 = 62;
const OP_TSETM: u8 = 63;
const OP_TSETR: u8 = 64;
const OP_CALLM: u8 = 65;
const OP_CALL: u8 = 66;
const OP_CALLMT: u8 = 67;
const OP_CALLT: u8 = 68;
const OP_ITERC: u8 = 69;
const OP_ITERN: u8 = 70;
const OP_VARG: u8 = 71;
const OP_ISNEXT: u8 = 72;
const OP_RETM: u8 = 73;
const OP_RET: u8 = 74;
const OP_RET0: u8 = 75;
const OP_RET1: u8 = 76;
const OP_FORI: u8 = 77;
const OP_JFORI: u8 = 78;
const OP_FORL: u8 = 79;
const OP_IFORL: u8 = 80;
const OP_JFORL: u8 = 81;
const OP_ITERL: u8 = 82;
const OP_IITERL: u8 = 83;
const OP_JITERL: u8 = 84;
const OP_LOOP: u8 = 85;
const OP_ILOOP: u8 = 86;
const OP_JLOOP: u8 = 87;
const OP_JMP: u8 = 88;
const OP_FUNCF: u8 = 89;

const KPRI_NIL: u32 = 0;
const KPRI_FALSE: u32 = 1;
const KPRI_TRUE: u32 = 2;

#[derive(Debug, Clone, Copy)]
struct LjInst {
    op: u8,
    a: u8,
    b: u8,
    c: u8,
    d: u16,
}

#[inline]
fn decode_inst(raw: u32) -> LjInst {
    LjInst {
        op: (raw & 0xFF) as u8,
        a: ((raw >> 8) & 0xFF) as u8,
        c: ((raw >> 16) & 0xFF) as u8,
        b: ((raw >> 24) & 0xFF) as u8,
        d: ((raw >> 16) & 0xFFFF) as u16,
    }
}

#[inline]
fn sj16(d: u16) -> i32 {
    i32::from(d) - 0x8000
}

#[inline]
fn s16(d: u16) -> i32 {
    d as i16 as i32
}

const MAX_LIFT_DEPTH: usize = 200;

#[derive(Debug, Clone)]
struct LjState {
    regs: Vec<String>,
    lines: Vec<String>,
    indent: usize,
}

impl LjState {
    fn new(framesize: u8) -> Self {
        Self {
            regs: vec![String::new(); usize::from(framesize).max(2)],
            lines: Vec::new(),
            indent: 1,
        }
    }

    #[inline]
    fn reg(&self, i: u32) -> String {
        let idx: usize = i as usize;
        match self.regs.get(idx) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => format!("r{idx}"),
        }
    }

    #[inline]
    fn set_reg(&mut self, i: u32, value: String) {
        let idx: usize = i as usize;
        if idx >= self.regs.len() {
            self.regs.resize(idx + 1, String::new());
        }
        self.regs[idx] = value;
    }

    #[inline]
    fn push(&mut self, stmt: &str) {
        let pad: String = "  ".repeat(self.indent);
        self.lines.push(format!("{pad}{stmt}"));
    }
}

#[must_use]
fn quote_lua(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\{}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[must_use]
fn fmt_kn(kn: &LjKn) -> String {
    match kn {
        LjKn::Int(i) => i.to_string(),
        LjKn::Num(n) => fmt_num(*n),
    }
}

#[must_use]
fn fmt_num(n: f64) -> String {
    if n.is_nan() {
        return "(0/0)".to_owned();
    }
    if n.is_infinite() {
        return if n > 0.0 {
            "math.huge".to_owned()
        } else {
            "-math.huge".to_owned()
        };
    }
    if n.fract() == 0.0 && n.abs() < 1e15 {
        return format!("{}", n as i64);
    }
    format!("{n}")
}

#[must_use]
fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

#[must_use]
fn kpri_value(d: u16) -> &'static str {
    match d as u32 {
        KPRI_NIL => "nil",
        KPRI_FALSE => "false",
        KPRI_TRUE => "true",
        _ => "nil",
    }
}

#[derive(Debug)]
struct LiftCtx<'a> {
    all_protos: &'a [LjProto],
    depth: usize,
    warnings: &'a mut Vec<String>,
    fully_structured: &'a mut bool,
}

fn lift_proto(
    proto: &LjProto,
    all_protos: &[LjProto],
    depth: usize,
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) -> String {
    if depth > MAX_LIFT_DEPTH {
        warnings.push("proto nesting exceeds lift depth limit".to_owned());
        *fully_structured = false;
        return "  -- (proto nesting limit reached)\n".to_owned();
    }
    let mut state: LjState = LjState::new(proto.framesize);
    for i in 0..u32::from(proto.num_params) {
        state.set_reg(i, format!("p{i}"));
    }
    let jump_targets: Vec<bool> = compute_jump_targets(&proto.code);
    let mut pc: usize = 0;
    let n: usize = proto.code.len();
    let mut ctx: LiftCtx<'_> = LiftCtx {
        all_protos,
        depth,
        warnings,
        fully_structured,
    };

    while pc < n {
        if jump_targets.get(pc).copied().unwrap_or(false) {
            state.push(&format!("::lj_{pc}::"));
        }
        let raw: u32 = proto.code[pc];
        let inst: LjInst = decode_inst(raw);
        let advance: usize = handle_inst(proto, inst, pc, n, &mut state, &mut ctx);
        pc += advance;
    }

    let mut source: String = String::new();
    for ln in &state.lines {
        source.push_str(ln);
        source.push('\n');
    }
    source
}

fn handle_inst(
    proto: &LjProto,
    inst: LjInst,
    pc: usize,
    code_len: usize,
    state: &mut LjState,
    ctx: &mut LiftCtx<'_>,
) -> usize {
    match inst.op {
        OP_MOV => {
            let src: String = state.reg(u32::from(inst.d));
            state.set_reg(u32::from(inst.a), src);
            1
        }
        OP_NOT => {
            let v: String = state.reg(u32::from(inst.d));
            state.set_reg(u32::from(inst.a), format!("(not {v})"));
            1
        }
        OP_UNM => {
            let v: String = state.reg(u32::from(inst.d));
            state.set_reg(u32::from(inst.a), format!("-({v})"));
            1
        }
        OP_LEN => {
            let v: String = state.reg(u32::from(inst.d));
            state.set_reg(u32::from(inst.a), format!("#({v})"));
            1
        }
        OP_KSTR => {
            let lit: String = proto
                .kstr(u32::from(inst.d))
                .map_or_else(|| format!("kstr({})", inst.d), quote_lua);
            state.set_reg(u32::from(inst.a), lit);
            1
        }
        OP_KSHORT => {
            let v: i32 = s16(inst.d);
            state.set_reg(u32::from(inst.a), v.to_string());
            1
        }
        OP_KNUM => {
            let lit: String = proto
                .knum(u32::from(inst.d))
                .map_or_else(|| format!("knum({})", inst.d), fmt_kn);
            state.set_reg(u32::from(inst.a), lit);
            1
        }
        OP_KPRI => {
            state.set_reg(u32::from(inst.a), kpri_value(inst.d).to_owned());
            1
        }
        OP_KNIL => {
            let start: u32 = u32::from(inst.a);
            let end: u32 = u32::from(inst.d);
            for r in start..=end {
                state.set_reg(r, "nil".to_owned());
            }
            1
        }
        OP_KCDATA => {
            state.set_reg(u32::from(inst.a), format!("--[[cdata({})]] nil", inst.d));
            1
        }
        OP_ADDVN | OP_SUBVN | OP_MULVN | OP_DIVVN | OP_MODVN => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = proto
                .knum(u32::from(inst.c))
                .map_or_else(|| format!("knum({})", inst.c), fmt_kn);
            let sym: &str = arith_sym(inst.op).unwrap_or("?");
            state.set_reg(u32::from(inst.a), format!("({lhs} {sym} {rhs})"));
            1
        }
        OP_ADDNV | OP_SUBNV | OP_MULNV | OP_DIVNV | OP_MODNV => {
            let lhs: String = proto
                .knum(u32::from(inst.c))
                .map_or_else(|| format!("knum({})", inst.c), fmt_kn);
            let rhs: String = state.reg(u32::from(inst.b));
            let sym: &str = nv_arith_sym(inst.op).unwrap_or("?");
            state.set_reg(u32::from(inst.a), format!("({lhs} {sym} {rhs})"));
            1
        }
        OP_ADDVV | OP_SUBVV | OP_MULVV | OP_DIVVV | OP_MODVV => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = vv_arith_sym(inst.op).unwrap_or("?");
            state.set_reg(u32::from(inst.a), format!("({lhs} {sym} {rhs})"));
            1
        }
        OP_POW => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            state.set_reg(u32::from(inst.a), format!("({lhs} ^ {rhs})"));
            1
        }
        OP_CAT => {
            let start: u32 = u32::from(inst.b);
            let end: u32 = u32::from(inst.c);
            let parts: Vec<String> = (start..=end).map(|r: u32| state.reg(r)).collect();
            state.set_reg(u32::from(inst.a), format!("({})", parts.join(" .. ")));
            1
        }
        OP_UGET => {
            state.set_reg(u32::from(inst.a), upval_name(proto, u32::from(inst.d)));
            1
        }
        OP_USETV => {
            let name: String = upval_name(proto, u32::from(inst.a));
            let val: String = state.reg(u32::from(inst.d));
            state.push(&format!("{name} = {val}"));
            1
        }
        OP_USETS => {
            let name: String = upval_name(proto, u32::from(inst.a));
            let lit: String = proto
                .kstr(u32::from(inst.d))
                .map_or_else(|| format!("kstr({})", inst.d), quote_lua);
            state.push(&format!("{name} = {lit}"));
            1
        }
        OP_USETN => {
            let name: String = upval_name(proto, u32::from(inst.a));
            let lit: String = proto
                .knum(u32::from(inst.d))
                .map_or_else(|| format!("knum({})", inst.d), fmt_kn);
            state.push(&format!("{name} = {lit}"));
            1
        }
        OP_USETP => {
            let name: String = upval_name(proto, u32::from(inst.a));
            state.push(&format!("{name} = {}", kpri_value(inst.d)));
            1
        }
        OP_GGET => {
            let name: String = proto
                .kstr(u32::from(inst.d))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("_G[kstr({})]", inst.d));
            state.set_reg(u32::from(inst.a), name);
            1
        }
        OP_GSET => {
            let name: String = proto
                .kstr(u32::from(inst.d))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("_G[kstr({})]", inst.d));
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{name} = {val}"));
            1
        }
        OP_TGETV => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            state.set_reg(u32::from(inst.a), format!("{table}[{key}]"));
            1
        }
        OP_TGETS => {
            let table: String = state.reg(u32::from(inst.b));
            let key_raw: Option<&str> = proto.kstr(u32::from(inst.c));
            let expr: String = match key_raw {
                Some(k) if is_ident(k) => format!("{table}.{k}"),
                Some(k) => format!("{table}[{}]", quote_lua(k)),
                None => format!("{table}[kstr({})]", inst.c),
            };
            state.set_reg(u32::from(inst.a), expr);
            1
        }
        OP_TGETB => {
            let table: String = state.reg(u32::from(inst.b));
            state.set_reg(u32::from(inst.a), format!("{table}[{}]", inst.c));
            1
        }
        OP_TGETR => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            state.set_reg(u32::from(inst.a), format!("rawget({table}, {key})"));
            1
        }
        OP_TSETV => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{table}[{key}] = {val}"));
            1
        }
        OP_TSETS => {
            let table: String = state.reg(u32::from(inst.b));
            let val: String = state.reg(u32::from(inst.a));
            let key_raw: Option<&str> = proto.kstr(u32::from(inst.c));
            let lhs: String = match key_raw {
                Some(k) if is_ident(k) => format!("{table}.{k}"),
                Some(k) => format!("{table}[{}]", quote_lua(k)),
                None => format!("{table}[kstr({})]", inst.c),
            };
            state.push(&format!("{lhs} = {val}"));
            1
        }
        OP_TSETB => {
            let table: String = state.reg(u32::from(inst.b));
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{table}[{}] = {val}", inst.c));
            1
        }
        OP_TSETM => {
            let table: String = state.reg(u32::from(inst.a).saturating_sub(1));
            state.push(&format!("-- TSETM into {table} (multi-result tail set)"));
            1
        }
        OP_TSETR => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("rawset({table}, {key}, {val})"));
            1
        }
        OP_TNEW => {
            state.push(&format!("local r{} = {{}}", inst.a));
            state.set_reg(u32::from(inst.a), format!("r{}", inst.a));
            1
        }
        OP_TDUP => {
            state.push(&format!(
                "local r{} = {{}} -- template kgc[{}]",
                inst.a, inst.d
            ));
            state.set_reg(u32::from(inst.a), format!("r{}", inst.a));
            1
        }
        OP_FNEW => {
            emit_fnew(proto, inst, state, ctx);
            1
        }
        OP_CALL | OP_CALLM => {
            emit_call(proto, inst, state, false, false);
            1
        }
        OP_CALLT | OP_CALLMT => {
            emit_call(proto, inst, state, true, false);
            1
        }
        OP_RET0 => {
            if pc + 1 != code_len {
                state.push("return");
            }
            1
        }
        OP_RET1 => {
            state.push(&format!("return {}", state.reg(u32::from(inst.a))));
            1
        }
        OP_RET | OP_RETM => {
            emit_return(inst, state);
            1
        }
        OP_FORI | OP_JFORI => {
            let a: u32 = u32::from(inst.a);
            let init: String = state.reg(a);
            let limit: String = state.reg(a + 1);
            let step: String = state.reg(a + 2);
            let var: String = format!("fv_{a}");
            state.set_reg(a + 3, var.clone());
            state.push(&format!("for {var} = {init}, {limit}, {step} do"));
            state.indent += 1;
            1
        }
        OP_FORL | OP_IFORL | OP_JFORL => {
            if state.indent > 1 {
                state.indent -= 1;
            }
            state.push("end");
            1
        }
        OP_ITERL | OP_IITERL | OP_JITERL => {
            if state.indent > 1 {
                state.indent -= 1;
            }
            state.push("end");
            1
        }
        OP_ITERC | OP_ITERN => {
            let a: u32 = u32::from(inst.a);
            let nvars: u32 = u32::from(inst.b).max(2).saturating_sub(1);
            let vars: Vec<String> = (0..nvars).map(|i: u32| format!("iv_{}", a + i)).collect();
            for (i, name) in vars.iter().enumerate() {
                state.set_reg(a + i as u32, name.clone());
            }
            let iter_fn: String = state.reg(a.saturating_sub(3));
            let iter_state: String = state.reg(a.saturating_sub(2));
            let iter_ctrl: String = state.reg(a.saturating_sub(1));
            state.push(&format!(
                "for {names} in {iter_fn}, {iter_state}, {iter_ctrl} do",
                names = vars.join(", ")
            ));
            state.indent += 1;
            *ctx.fully_structured = false;
            1
        }
        OP_ISNEXT => {
            state.push("-- isnext (specialized pairs setup)");
            1
        }
        OP_LOOP | OP_ILOOP | OP_JLOOP => {
            state.push(&format!("-- loop header (target {})", sj16(inst.d)));
            1
        }
        OP_VARG => {
            state.set_reg(u32::from(inst.a), "...".to_owned());
            1
        }
        OP_UCLO => {
            let target: i32 = sj16(inst.d);
            if target != 0 {
                let t: i64 = pc as i64 + 1 + i64::from(target);
                if t >= 0 {
                    state.push(&format!("goto lj_{t}"));
                    *ctx.fully_structured = false;
                }
            }
            1
        }
        OP_JMP => {
            let t: i64 = pc as i64 + 1 + i64::from(sj16(inst.d));
            if t >= 0 {
                state.push(&format!("goto lj_{t}"));
            }
            *ctx.fully_structured = false;
            1
        }
        OP_ISLT | OP_ISGE | OP_ISLE | OP_ISGT | OP_ISEQV | OP_ISNEV => {
            let lhs: String = state.reg(u32::from(inst.a));
            let rhs: String = state.reg(u32::from(inst.d));
            let sym: &str = cmp_var_var_sym(inst.op);
            emit_cond_jump(proto, pc, state, &lhs, sym, &rhs, ctx.fully_structured);
            if next_is_jmp(&proto.code, pc) { 2 } else { 1 }
        }
        OP_ISEQS | OP_ISNES => {
            let lhs: String = state.reg(u32::from(inst.a));
            let rhs: String = proto
                .kstr(u32::from(inst.d))
                .map_or_else(|| format!("kstr({})", inst.d), quote_lua);
            let sym: &str = if inst.op == OP_ISEQS { "==" } else { "~=" };
            emit_cond_jump(proto, pc, state, &lhs, sym, &rhs, ctx.fully_structured);
            if next_is_jmp(&proto.code, pc) { 2 } else { 1 }
        }
        OP_ISEQN | OP_ISNEN => {
            let lhs: String = state.reg(u32::from(inst.a));
            let rhs: String = proto
                .knum(u32::from(inst.d))
                .map_or_else(|| format!("knum({})", inst.d), fmt_kn);
            let sym: &str = if inst.op == OP_ISEQN { "==" } else { "~=" };
            emit_cond_jump(proto, pc, state, &lhs, sym, &rhs, ctx.fully_structured);
            if next_is_jmp(&proto.code, pc) { 2 } else { 1 }
        }
        OP_ISEQP | OP_ISNEP => {
            let lhs: String = state.reg(u32::from(inst.a));
            let rhs: &str = kpri_value(inst.d);
            let sym: &str = if inst.op == OP_ISEQP { "==" } else { "~=" };
            emit_cond_jump(proto, pc, state, &lhs, sym, rhs, ctx.fully_structured);
            if next_is_jmp(&proto.code, pc) { 2 } else { 1 }
        }
        OP_IST => {
            let val: String = state.reg(u32::from(inst.d));
            emit_cond_jump_truth(proto, pc, state, &val, true, ctx.fully_structured);
            if next_is_jmp(&proto.code, pc) { 2 } else { 1 }
        }
        OP_ISF => {
            let val: String = state.reg(u32::from(inst.d));
            emit_cond_jump_truth(proto, pc, state, &val, false, ctx.fully_structured);
            if next_is_jmp(&proto.code, pc) { 2 } else { 1 }
        }
        OP_ISTC | OP_ISFC => {
            let val: String = state.reg(u32::from(inst.d));
            state.set_reg(u32::from(inst.a), val.clone());
            let truthy: bool = inst.op == OP_ISTC;
            emit_cond_jump_truth(proto, pc, state, &val, truthy, ctx.fully_structured);
            if next_is_jmp(&proto.code, pc) { 2 } else { 1 }
        }
        OP_ISTYPE | OP_ISNUM => {
            state.push(&format!("-- type assert r{} kind={}", inst.a, inst.d));
            1
        }
        OP_FUNCF => 1,
        op if op >= OP_FUNCF => 1,
        op => {
            state.push(&format!(
                "-- unknown luajit op {op} a={} b={} c={} d={}",
                inst.a, inst.b, inst.c, inst.d
            ));
            ctx.warnings
                .push(format!("unknown luajit opcode {op} at pc={pc}"));
            *ctx.fully_structured = false;
            1
        }
    }
}

#[inline]
fn arith_sym(op: u8) -> Option<&'static str> {
    Some(match op {
        OP_ADDVN => "+",
        OP_SUBVN => "-",
        OP_MULVN => "*",
        OP_DIVVN => "/",
        OP_MODVN => "%",
        _ => return None,
    })
}

#[inline]
fn nv_arith_sym(op: u8) -> Option<&'static str> {
    Some(match op {
        OP_ADDNV => "+",
        OP_SUBNV => "-",
        OP_MULNV => "*",
        OP_DIVNV => "/",
        OP_MODNV => "%",
        _ => return None,
    })
}

#[inline]
fn vv_arith_sym(op: u8) -> Option<&'static str> {
    Some(match op {
        OP_ADDVV => "+",
        OP_SUBVV => "-",
        OP_MULVV => "*",
        OP_DIVVV => "/",
        OP_MODVV => "%",
        _ => return None,
    })
}

#[inline]
fn cmp_var_var_sym(op: u8) -> &'static str {
    match op {
        OP_ISLT => "<",
        OP_ISGE => ">=",
        OP_ISLE => "<=",
        OP_ISGT => ">",
        OP_ISEQV => "==",
        OP_ISNEV => "~=",
        _ => "==",
    }
}

#[inline]
fn next_is_jmp(code: &[u32], pc: usize) -> bool {
    code.get(pc + 1)
        .is_some_and(|raw: &u32| decode_inst(*raw).op == OP_JMP)
}

fn emit_cond_jump(
    proto: &LjProto,
    pc: usize,
    state: &mut LjState,
    lhs: &str,
    sym: &str,
    rhs: &str,
    fully_structured: &mut bool,
) {
    let next_jmp: Option<i64> = proto.code.get(pc + 1).and_then(|raw2: &u32| {
        let dj: LjInst = decode_inst(*raw2);
        if dj.op == OP_JMP {
            Some(pc as i64 + 2 + i64::from(sj16(dj.d)))
        } else {
            None
        }
    });
    match next_jmp {
        Some(t) if t >= 0 => {
            state.push(&format!("if {lhs} {sym} {rhs} then goto lj_{t} end"));
        }
        _ => {
            state.push(&format!("-- cmp {lhs} {sym} {rhs}"));
        }
    }
    *fully_structured = false;
}

fn emit_cond_jump_truth(
    proto: &LjProto,
    pc: usize,
    state: &mut LjState,
    val: &str,
    truthy: bool,
    fully_structured: &mut bool,
) {
    let next_jmp: Option<i64> = proto.code.get(pc + 1).and_then(|raw2: &u32| {
        let dj: LjInst = decode_inst(*raw2);
        if dj.op == OP_JMP {
            Some(pc as i64 + 2 + i64::from(sj16(dj.d)))
        } else {
            None
        }
    });
    let neg: &str = if truthy { "" } else { "not " };
    match next_jmp {
        Some(t) if t >= 0 => {
            state.push(&format!("if {neg}{val} then goto lj_{t} end"));
        }
        _ => {
            state.push(&format!("-- test {neg}{val}"));
        }
    }
    *fully_structured = false;
}

fn emit_call(proto: &LjProto, inst: LjInst, state: &mut LjState, tail: bool, _is_m: bool) {
    let a: u32 = u32::from(inst.a);
    let _ = proto;
    let func: String = state.reg(a);
    let nrets_plus1: u8 = inst.b;
    let nargs_plus1: u8 = inst.c;
    let nargs: u32 = if nargs_plus1 == 0 {
        let mut r: u32 = a + 2;
        while (r as usize) < state.regs.len() && !state.regs[r as usize].is_empty() {
            r += 1;
        }
        r.saturating_sub(a + 2)
    } else {
        u32::from(nargs_plus1) - 1
    };
    let args: Vec<String> = (0..nargs).map(|i: u32| state.reg(a + 2 + i)).collect();
    let call: String = format!("{func}({})", args.join(", "));
    if tail {
        state.push(&format!("return {call}"));
        return;
    }
    let nrets: u32 = if nrets_plus1 == 0 {
        0
    } else {
        u32::from(nrets_plus1) - 1
    };
    match nrets {
        0 => {
            state.push(&call);
        }
        1 => {
            state.push(&format!("local r{a} = {call}"));
            state.set_reg(a, format!("r{a}"));
        }
        _ => {
            let targets: Vec<String> = (0..nrets)
                .map(|i: u32| format!("r{}_{}", a + i, state.lines.len()))
                .collect();
            state.push(&format!("local {} = {call}", targets.join(", ")));
            for (i, t) in targets.iter().enumerate() {
                state.set_reg(a + i as u32, t.clone());
            }
        }
    }
}

fn emit_return(inst: LjInst, state: &mut LjState) {
    let a: u32 = u32::from(inst.a);
    let d: u32 = u32::from(inst.d);
    if d == 0 {
        let mut vals: Vec<String> = Vec::new();
        let mut r: u32 = a;
        while (r as usize) < state.regs.len() {
            vals.push(state.reg(r));
            r += 1;
        }
        state.push(&format!("return {}", vals.join(", ")));
    } else if d == 1 {
        state.push("return");
    } else {
        let vals: Vec<String> = (0..d.saturating_sub(1))
            .map(|i: u32| state.reg(a + i))
            .collect();
        state.push(&format!("return {}", vals.join(", ")));
    }
}

fn emit_fnew(proto: &LjProto, inst: LjInst, state: &mut LjState, ctx: &mut LiftCtx<'_>) {
    let kgc_idx: usize = inst.d as usize;
    match proto.kgc.get(kgc_idx) {
        Some(LjKgc::Child(child_idx)) => {
            let child_opt: Option<&LjProto> = resolve_child(*child_idx, ctx.all_protos);
            match child_opt {
                Some(child) => {
                    let body: String = lift_proto(
                        child,
                        ctx.all_protos,
                        ctx.depth + 1,
                        ctx.warnings,
                        ctx.fully_structured,
                    );
                    let params: String = (0..child.num_params)
                        .map(|i: u8| format!("p{i}"))
                        .collect::<Vec<String>>()
                        .join(", ");
                    let header: String = if child.is_vararg() {
                        if params.is_empty() {
                            "function(...)".to_owned()
                        } else {
                            format!("function({params}, ...)")
                        }
                    } else {
                        format!("function({params})")
                    };
                    let mut block: String = format!("{header}\n");
                    for ln in body.lines() {
                        block.push_str("  ");
                        block.push_str(ln);
                        block.push('\n');
                    }
                    block.push_str("end");
                    state.set_reg(u32::from(inst.a), block);
                }
                None => {
                    state.set_reg(
                        u32::from(inst.a),
                        format!("function() --[[ luajit child {child_idx} missing ]] end"),
                    );
                    *ctx.fully_structured = false;
                }
            }
        }
        _ => {
            state.set_reg(
                u32::from(inst.a),
                format!("function() --[[ luajit fnew kgc[{kgc_idx}] not a child ]] end"),
            );
            *ctx.fully_structured = false;
        }
    }
}

#[must_use]
fn resolve_child(child_idx: u32, all_protos: &[LjProto]) -> Option<&LjProto> {
    all_protos.iter().rev().skip(1).nth(child_idx as usize)
}

#[must_use]
fn upval_name(proto: &LjProto, idx: u32) -> String {
    proto
        .uv_names
        .get(idx as usize)
        .cloned()
        .filter(|s: &String| !s.is_empty())
        .unwrap_or_else(|| format!("uv_{idx}"))
}

#[must_use]
fn compute_jump_targets(code: &[u32]) -> Vec<bool> {
    let n: usize = code.len();
    let mut targets: Vec<bool> = vec![false; n + 1];
    for (pc, raw) in code.iter().enumerate() {
        let inst: LjInst = decode_inst(*raw);
        let mark_jd = |t: i64, targets: &mut [bool]| {
            if t >= 0 && (t as usize) <= n {
                targets[t as usize] = true;
            }
        };
        match inst.op {
            OP_JMP | OP_UCLO => {
                let t: i64 = pc as i64 + 1 + i64::from(sj16(inst.d));
                mark_jd(t, &mut targets);
            }
            OP_FORI | OP_JFORI | OP_FORL | OP_IFORL | OP_JFORL | OP_ITERL | OP_IITERL
            | OP_JITERL | OP_LOOP | OP_ILOOP | OP_JLOOP => {
                let t: i64 = pc as i64 + 1 + i64::from(sj16(inst.d));
                mark_jd(t, &mut targets);
            }
            _ => {}
        }
        if matches!(
            inst.op,
            OP_ISLT
                | OP_ISGE
                | OP_ISLE
                | OP_ISGT
                | OP_ISEQV
                | OP_ISNEV
                | OP_ISEQS
                | OP_ISNES
                | OP_ISEQN
                | OP_ISNEN
                | OP_ISEQP
                | OP_ISNEP
                | OP_IST
                | OP_ISF
                | OP_ISTC
                | OP_ISFC
        ) && let Some(raw2) = code.get(pc + 1)
        {
            let dj: LjInst = decode_inst(*raw2);
            if dj.op == OP_JMP {
                let t: i64 = pc as i64 + 2 + i64::from(sj16(dj.d));
                mark_jd(t, &mut targets);
            }
        }
    }
    targets
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decodes_simple_inst_layout() {
        let raw: u32 = u32::from(OP_MOV) | (5 << 8) | (7 << 16);
        let inst: LjInst = decode_inst(raw);
        assert_eq!(inst.op, OP_MOV);
        assert_eq!(inst.a, 5);
        assert_eq!(inst.d, 7);
    }

    #[test]
    fn ks16_is_signed() {
        assert_eq!(s16(0xFFFF), -1);
        assert_eq!(s16(0x0001), 1);
        assert_eq!(s16(0x7FFF), 32767);
    }

    #[test]
    fn sj16_centered_on_8000() {
        assert_eq!(sj16(0x8000), 0);
        assert_eq!(sj16(0x8001), 1);
        assert_eq!(sj16(0x7FFF), -1);
    }

    #[test]
    fn quote_lua_escapes_specials() {
        assert_eq!(quote_lua("a\"b\nc"), "\"a\\\"b\\nc\"");
    }

    #[test]
    fn kpri_returns_lua_keywords() {
        assert_eq!(kpri_value(0), "nil");
        assert_eq!(kpri_value(1), "false");
        assert_eq!(kpri_value(2), "true");
    }
}
