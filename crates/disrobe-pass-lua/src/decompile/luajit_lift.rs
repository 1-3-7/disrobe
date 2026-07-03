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
enum LjKgc {
    Child,
    Table(LjTab),
    I64(i64),
    U64(u64),
    Complex,
    Str(String),
}

#[derive(Debug, Clone)]
enum LjKTabKey {
    Nil,
    False,
    True,
    Int(i64),
    Num(f64),
    Str(String),
}

#[derive(Debug, Clone)]
struct LjTab {
    array: Vec<LjKTabKey>,
    hash: Vec<(LjKTabKey, LjKTabKey)>,
}

#[derive(Debug, Clone)]
enum LjKn {
    Int(i32),
    Num(f64),
}

const PROTO_UV_LOCAL: u16 = 0x8000;

#[derive(Debug, Clone)]
struct LjProto {
    index: usize,
    flags: u8,
    num_params: u8,
    framesize: u8,
    code: Vec<u32>,
    kgc: Vec<LjKgc>,
    kgc_rev: Vec<usize>,
    kn: Vec<LjKn>,
    uv_slots: Vec<u16>,
    var_names: Vec<String>,
    child_indices: Vec<usize>,
}

impl LjProto {
    #[inline]
    fn is_vararg(&self) -> bool {
        self.flags & PROTO_VARARG != 0
    }

    #[inline]
    fn kgc_at(&self, d: u32) -> Option<&LjKgc> {
        self.kgc_rev
            .get(d as usize)
            .and_then(|idx: &usize| self.kgc.get(*idx))
    }

    #[inline]
    fn kstr(&self, d: u32) -> Option<&str> {
        match self.kgc_at(d) {
            Some(LjKgc::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    #[inline]
    fn ktab(&self, d: u32) -> Option<&LjTab> {
        match self.kgc_at(d) {
            Some(LjKgc::Table(t)) => Some(t),
            _ => None,
        }
    }

    #[inline]
    fn knum(&self, d: u32) -> Option<&LjKn> {
        self.kn.get(d as usize)
    }
}

pub fn decompile(bytes: &[u8]) -> Result<DecompiledChunk> {
    let mut warnings: Vec<String> = Vec::new();
    let (protos, version): (Vec<LjProto>, u8) = parse_chunk(bytes, &mut warnings)?;
    let Some(main_idx): Option<usize> = protos.len().checked_sub(1) else {
        return Ok(DecompiledChunk {
            source: "-- disrobe luajit decompiler: empty chunk\n".to_owned(),
            fidelity: Fidelity::BestEffort,
            warnings,
        });
    };
    let dialect_label: &str = if version == 1 { "2.0" } else { "2.1" };
    let mut out: String = String::new();
    out.push_str(&format!(
        "-- decompiled by disrobe (luajit {dialect_label} register lifter)\n"
    ));
    let mut fully_structured: bool = true;
    let main: &LjProto = &protos[main_idx];
    let body: String = lift_proto(main, &protos, 0, &[], &mut warnings, &mut fully_structured);
    out.push_str(&body);
    if main.is_vararg() {
        out.push_str("return _main(...)\n");
    } else {
        out.push_str("return _main()\n");
    }
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

fn parse_chunk(bytes: &[u8], warnings: &mut Vec<String>) -> Result<(Vec<LjProto>, u8)> {
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
            let src_size: usize = usize_from_uleb(src_len, c.position())?;
            let _src: &[u8] = c.read_bytes(src_size)?;
        }
    }
    let mut protos: Vec<LjProto> = Vec::new();
    let mut avail: Vec<usize> = Vec::new();
    loop {
        if c.remaining() == 0 {
            break;
        }
        let proto_len: u64 = c.read_uleb128()?;
        if proto_len == 0 {
            break;
        }
        let proto_size: usize = usize::try_from(proto_len).map_err(|_| Error::Truncated {
            offset: c.position(),
            needed: usize::MAX,
            had: c.remaining(),
        })?;
        let proto_bytes: &[u8] = c.read_bytes(proto_size)?;
        let mut proto_cursor: ByteCursor<'_> = ByteCursor::new(proto_bytes);
        let idx: usize = protos.len();
        let mut p: LjProto = parse_proto(&mut proto_cursor, stripped, proto_size, idx, warnings)?;
        let child_count: usize = p
            .kgc
            .iter()
            .filter(|e: &&LjKgc| matches!(e, LjKgc::Child))
            .count();
        let mut popped: Vec<usize> = Vec::with_capacity(child_count);
        for _ in 0..child_count {
            match avail.pop() {
                Some(child) => popped.push(child),
                None => {
                    warnings.push("luajit child proto stack underflow".to_owned());
                    break;
                }
            }
        }
        p.child_indices = popped;
        avail.push(idx);
        protos.push(p);
    }
    Ok((protos, version))
}

fn parse_proto(
    c: &mut ByteCursor<'_>,
    stripped: bool,
    proto_len: usize,
    self_index: usize,
    warnings: &mut Vec<String>,
) -> Result<LjProto> {
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
    let num_line: u64 = if stripped || size_dbg == 0 {
        0
    } else {
        c.read_uleb128()?
    };

    let mut code: Vec<u32> = Vec::with_capacity(c.bounded_capacity::<u32>(size_bc, 4));
    for _ in 0..size_bc {
        code.push(c.read_u32()?);
    }

    let mut uv_slots: Vec<u16> = Vec::with_capacity(usize::from(size_uv));
    for _ in 0..size_uv {
        uv_slots.push(c.read_u16()?);
    }

    let mut kgc: Vec<LjKgc> = Vec::with_capacity(c.bounded_capacity::<LjKgc>(size_kgc, 1));
    for _ in 0..size_kgc {
        let tag: u64 = c.read_uleb128()?;
        match tag {
            KGC_CHILD => {
                kgc.push(LjKgc::Child);
            }
            KGC_TAB => {
                let tab: LjTab = read_ktab(c)?;
                kgc.push(LjKgc::Table(tab));
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
                let strlen: usize = usize_from_uleb(strlen_raw, c.position())?;
                let raw: &[u8] = c.read_bytes(strlen)?;
                let s: String = String::from_utf8_lossy(raw).into_owned();
                kgc.push(LjKgc::Str(s));
            }
        }
    }

    let mut kn: Vec<LjKn> = Vec::with_capacity(c.bounded_capacity::<LjKn>(size_kn, 8));
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

    let _ = (size_dbg, first_line, num_line, warnings, self_index);
    let var_names: Vec<String> = Vec::new();

    let kgc_rev: Vec<usize> = (0..kgc.len()).rev().collect();

    while c.position() < proto_len {
        let _: u8 = c.read_u8()?;
    }

    Ok(LjProto {
        index: self_index,
        flags,
        num_params,
        framesize,
        code,
        kgc,
        kgc_rev,
        kn,
        uv_slots,
        var_names,
        child_indices: Vec::new(),
    })
}

fn read_ktab(c: &mut ByteCursor<'_>) -> Result<LjTab> {
    let narray: u64 = c.read_uleb128()?;
    let nhash: u64 = c.read_uleb128()?;
    let mut array: Vec<LjKTabKey> = Vec::with_capacity(c.bounded_capacity::<LjKTabKey>(narray, 1));
    for _ in 0..narray {
        array.push(read_ktab_entry(c)?);
    }
    let mut hash: Vec<(LjKTabKey, LjKTabKey)> =
        Vec::with_capacity(c.bounded_capacity::<(LjKTabKey, LjKTabKey)>(nhash, 2));
    for _ in 0..nhash {
        let k: LjKTabKey = read_ktab_entry(c)?;
        let v: LjKTabKey = read_ktab_entry(c)?;
        hash.push((k, v));
    }
    Ok(LjTab { array, hash })
}

fn read_ktab_entry(c: &mut ByteCursor<'_>) -> Result<LjKTabKey> {
    let tp: u64 = c.read_uleb128()?;
    match tp {
        KTAB_NIL => Ok(LjKTabKey::Nil),
        KTAB_FALSE => Ok(LjKTabKey::False),
        KTAB_TRUE => Ok(LjKTabKey::True),
        KTAB_INT => {
            let v: u64 = c.read_uleb128()?;
            Ok(LjKTabKey::Int(v as i32 as i64))
        }
        KTAB_NUM => {
            let lo: u64 = c.read_uleb128()?;
            let hi: u64 = c.read_uleb128()?;
            let raw: u64 = (hi << 32) | (lo & 0xFFFF_FFFF);
            Ok(LjKTabKey::Num(f64::from_bits(raw)))
        }
        _ => {
            let len: u64 = tp.saturating_sub(KTAB_STR_BASE);
            let n: usize = usize_from_uleb(len, c.position())?;
            let raw: &[u8] = c.read_bytes(n)?;
            Ok(LjKTabKey::Str(String::from_utf8_lossy(raw).into_owned()))
        }
    }
}

fn usize_from_uleb(value: u64, offset: usize) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::Truncated {
        offset,
        needed: usize::MAX,
        had: 0,
    })
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
    set: Vec<bool>,
    declared: Vec<bool>,
    var_names: Vec<String>,
    uv_names: Vec<String>,
    scope_id: usize,
    lines: Vec<String>,
    indent: usize,
    open_multi: Option<(u32, String)>,
    last_multi: Option<(u32, String)>,
}

impl LjState {
    fn new(framesize: u8, var_names: &[String], uv_names: &[String], scope_id: usize) -> Self {
        let size: usize = usize::from(framesize).max(2);
        Self {
            regs: vec![String::new(); size],
            set: vec![false; size],
            declared: vec![false; size],
            var_names: var_names.to_vec(),
            uv_names: uv_names.to_vec(),
            scope_id,
            lines: Vec::new(),
            indent: 1,
            open_multi: None,
            last_multi: None,
        }
    }

    #[inline]
    fn set_open_multi(&mut self, slot: u32, expr: String) {
        self.open_multi = Some((slot, expr.clone()));
        self.last_multi = Some((slot, expr));
    }

    #[inline]
    fn uv(&self, idx: u32) -> String {
        match self.uv_names.get(idx as usize) {
            Some(name) if !name.is_empty() => name.clone(),
            _ => format!("uv{idx}"),
        }
    }

    #[inline]
    fn take_open_multi(&mut self, slot: u32) -> Option<String> {
        match self.open_multi.take() {
            Some((s, expr)) if s == slot => Some(expr),
            _ => None,
        }
    }

    #[inline]
    fn reg(&self, i: u32) -> String {
        let idx: usize = i as usize;
        match self.regs.get(idx) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => self.slot_name(i),
        }
    }

    #[inline]
    fn slot_name(&self, i: u32) -> String {
        match self.var_names.get(i as usize) {
            Some(name) if !name.is_empty() => name.clone(),
            _ if self.scope_id == 0 => format!("r{i}"),
            _ => format!("v{}_{i}", self.scope_id),
        }
    }

    #[inline]
    fn declared(&self, i: u32) -> bool {
        self.declared.get(i as usize).copied().unwrap_or(false)
    }

    #[inline]
    fn is_set(&self, i: u32) -> bool {
        self.set.get(i as usize).copied().unwrap_or(false)
    }

    #[inline]
    fn mark_declared(&mut self, i: u32) {
        let idx: usize = i as usize;
        if idx >= self.declared.len() {
            self.declared.resize(idx + 1, false);
        }
        self.declared[idx] = true;
    }

    #[inline]
    fn set_reg(&mut self, i: u32, value: String) {
        let idx: usize = i as usize;
        if idx >= self.regs.len() {
            self.regs.resize(idx + 1, String::new());
            self.set.resize(idx + 1, false);
            self.declared.resize(idx + 1, false);
        }
        self.regs[idx] = value;
        self.set[idx] = true;
    }

    #[inline]
    fn push(&mut self, stmt: &str) {
        let pad: String = "  ".repeat(self.indent);
        self.lines.push(format!("{pad}{stmt}"));
    }

    fn declare_local(&mut self, slot: u32, value: &str) {
        let name: String = self.slot_name(slot);
        if self.declared(slot) {
            if name != value {
                self.push(&format!("{name} = {value}"));
            }
        } else {
            self.push(&format!("local {name} = {value}"));
            self.mark_declared(slot);
        }
        self.set_reg(slot, name);
    }
}

#[must_use]
fn quote_lua(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(b as char),
            other => out.push_str(&format!("\\{other}")),
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
    for precision in 1..=17 {
        let candidate: String = format!("{n:.precision$}");
        if candidate.parse::<f64>() == Ok(n) {
            return candidate;
        }
    }
    format!("{n}")
}

#[must_use]
fn fmt_tab_key(k: &LjKTabKey) -> String {
    match k {
        LjKTabKey::Nil => "nil".to_owned(),
        LjKTabKey::False => "false".to_owned(),
        LjKTabKey::True => "true".to_owned(),
        LjKTabKey::Int(i) => i.to_string(),
        LjKTabKey::Num(n) => fmt_num(*n),
        LjKTabKey::Str(s) => quote_lua(s),
    }
}

#[must_use]
fn render_ktab(t: &LjTab) -> String {
    let mut parts: Vec<String> = Vec::new();
    for entry in &t.array {
        if matches!(entry, LjKTabKey::Nil) {
            continue;
        }
        parts.push(fmt_tab_key(entry));
    }
    for (k, v) in &t.hash {
        match k {
            LjKTabKey::Str(s) if is_ident(s) => parts.push(format!("{s} = {}", fmt_tab_key(v))),
            _ => parts.push(format!("[{}] = {}", fmt_tab_key(k), fmt_tab_key(v))),
        }
    }
    format!("{{{}}}", parts.join(", "))
}

#[must_use]
fn is_ident(s: &str) -> bool {
    if is_lua_keyword(s) {
        return false;
    }
    let mut chars: core::str::Chars<'_> = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

#[must_use]
fn is_lua_keyword(s: &str) -> bool {
    matches!(
        s,
        "and"
            | "break"
            | "do"
            | "else"
            | "elseif"
            | "end"
            | "false"
            | "for"
            | "function"
            | "goto"
            | "if"
            | "in"
            | "local"
            | "nil"
            | "not"
            | "or"
            | "repeat"
            | "return"
            | "then"
            | "true"
            | "until"
            | "while"
    )
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
    uv_names: &[String],
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) -> String {
    let header: String = proto_header(proto, depth);
    if depth > MAX_LIFT_DEPTH {
        warnings.push("proto nesting exceeds lift depth limit".to_owned());
        *fully_structured = false;
        return format!("{header}\n  -- (proto nesting limit reached)\nend\n");
    }
    let mut state: LjState = LjState::new(proto.framesize, &proto.var_names, uv_names, proto.index);
    for i in 0..u32::from(proto.num_params) {
        let name: String = state.slot_name(i);
        state.set_reg(i, name);
        state.mark_declared(i);
    }
    let loops: Vec<LoopRegion> = detect_loops(&proto.code);
    let jump_targets: Vec<bool> = compute_jump_targets(&proto.code, &loops);
    let predeclare: Vec<u32> = compute_predeclare(proto, &loops);
    for slot in &predeclare {
        let name: String = state.slot_name(*slot);
        state.push(&format!("local {name}"));
        state.set_reg(*slot, name);
        state.mark_declared(*slot);
    }
    let mut ctx: LiftCtx<'_> = LiftCtx {
        all_protos,
        depth,
        warnings,
        fully_structured,
    };
    emit_range(
        proto,
        0,
        proto.code.len(),
        &loops,
        &jump_targets,
        &mut state,
        &mut ctx,
    );

    let mut out: String = String::new();
    out.push_str(&header);
    out.push('\n');
    for ln in &state.lines {
        out.push_str(ln);
        out.push('\n');
    }
    out.push_str("end\n");
    out
}

#[must_use]
fn param_name(proto: &LjProto, i: u32) -> String {
    match proto.var_names.get(i as usize) {
        Some(name) if !name.is_empty() => name.clone(),
        _ if proto.index == 0 => format!("r{i}"),
        _ => format!("v{}_{i}", proto.index),
    }
}

fn proto_header(proto: &LjProto, depth: usize) -> String {
    let params: Vec<String> = (0..u32::from(proto.num_params))
        .map(|i: u32| param_name(proto, i))
        .collect();
    let joined: String = params.join(", ");
    if depth == 0 {
        match (joined.is_empty(), proto.is_vararg()) {
            (true, false) => "local function _main()".to_owned(),
            (true, true) => "local function _main(...)".to_owned(),
            (false, false) => format!("local function _main({joined})"),
            (false, true) => format!("local function _main({joined}, ...)"),
        }
    } else {
        match (joined.is_empty(), proto.is_vararg()) {
            (true, false) => "function()".to_owned(),
            (true, true) => "function(...)".to_owned(),
            (false, false) => format!("function({joined})"),
            (false, true) => format!("function({joined}, ...)"),
        }
    }
}

#[inline]
fn touches_open_multi(op: u8) -> bool {
    matches!(
        op,
        OP_CALL
            | OP_CALLM
            | OP_CALLMT
            | OP_CALLT
            | OP_RET
            | OP_RETM
            | OP_RET1
            | OP_RET0
            | OP_VARG
            | OP_TSETM
            | OP_UCLO
    )
}

fn handle_inst(
    proto: &LjProto,
    inst: LjInst,
    pc: usize,
    code_len: usize,
    state: &mut LjState,
    ctx: &mut LiftCtx<'_>,
) -> usize {
    if !touches_open_multi(inst.op) {
        state.open_multi = None;
    }
    match inst.op {
        OP_MOV => {
            let src: String = state.reg(u32::from(inst.d));
            state.declare_local(u32::from(inst.a), &src);
            1
        }
        OP_NOT => {
            let v: String = state.reg(u32::from(inst.d));
            state.declare_local(u32::from(inst.a), &format!("(not {v})"));
            1
        }
        OP_UNM => {
            let v: String = state.reg(u32::from(inst.d));
            state.declare_local(u32::from(inst.a), &format!("(-{v})"));
            1
        }
        OP_LEN => {
            let v: String = state.reg(u32::from(inst.d));
            state.declare_local(u32::from(inst.a), &format!("(#{v})"));
            1
        }
        OP_KSTR => {
            let lit: String = proto
                .kstr(u32::from(inst.d))
                .map_or_else(|| "nil".to_owned(), quote_lua);
            state.declare_local(u32::from(inst.a), &lit);
            1
        }
        OP_KSHORT => {
            let v: i32 = s16(inst.d);
            state.declare_local(u32::from(inst.a), &v.to_string());
            1
        }
        OP_KNUM => {
            let lit: String = proto
                .knum(u32::from(inst.d))
                .map_or_else(|| "0".to_owned(), fmt_kn);
            state.declare_local(u32::from(inst.a), &lit);
            1
        }
        OP_KPRI => {
            let v: &str = kpri_value(inst.d);
            state.declare_local(u32::from(inst.a), v);
            1
        }
        OP_KNIL => {
            let start: u32 = u32::from(inst.a);
            let end: u32 = u32::from(inst.d);
            for r in start..=end {
                state.declare_local(r, "nil");
            }
            1
        }
        OP_KCDATA => {
            let lit: String = match proto.kgc_at(u32::from(inst.d)) {
                Some(LjKgc::I64(v)) => format!("{v}LL"),
                Some(LjKgc::U64(v)) => format!("{v}ULL"),
                _ => "nil".to_owned(),
            };
            state.declare_local(u32::from(inst.a), &lit);
            1
        }
        OP_ADDVN | OP_SUBVN | OP_MULVN | OP_DIVVN | OP_MODVN => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = proto
                .knum(u32::from(inst.c))
                .map_or_else(|| "0".to_owned(), fmt_kn);
            let sym: &str = arith_sym(inst.op).unwrap_or("+");
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        OP_ADDNV | OP_SUBNV | OP_MULNV | OP_DIVNV | OP_MODNV => {
            let rhs: String = state.reg(u32::from(inst.b));
            let lhs: String = proto
                .knum(u32::from(inst.c))
                .map_or_else(|| "0".to_owned(), fmt_kn);
            let sym: &str = nv_arith_sym(inst.op).unwrap_or("+");
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        OP_ADDVV | OP_SUBVV | OP_MULVV | OP_DIVVV | OP_MODVV => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = vv_arith_sym(inst.op).unwrap_or("+");
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        OP_POW => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            state.declare_local(u32::from(inst.a), &format!("({lhs} ^ {rhs})"));
            1
        }
        OP_CAT => {
            let start: u32 = u32::from(inst.b);
            let end: u32 = u32::from(inst.c);
            let parts: Vec<String> = (start..=end).map(|r: u32| state.reg(r)).collect();
            state.declare_local(u32::from(inst.a), &format!("({})", parts.join(" .. ")));
            1
        }
        OP_UGET => {
            let v: String = state.uv(u32::from(inst.d));
            state.declare_local(u32::from(inst.a), &v);
            1
        }
        OP_USETV => {
            let name: String = state.uv(u32::from(inst.a));
            let val: String = state.reg(u32::from(inst.d));
            state.push(&format!("{name} = {val}"));
            1
        }
        OP_USETS => {
            let name: String = state.uv(u32::from(inst.a));
            let lit: String = proto
                .kstr(u32::from(inst.d))
                .map_or_else(|| "nil".to_owned(), quote_lua);
            state.push(&format!("{name} = {lit}"));
            1
        }
        OP_USETN => {
            let name: String = state.uv(u32::from(inst.a));
            let lit: String = proto
                .knum(u32::from(inst.d))
                .map_or_else(|| "0".to_owned(), fmt_kn);
            state.push(&format!("{name} = {lit}"));
            1
        }
        OP_USETP => {
            let name: String = state.uv(u32::from(inst.a));
            state.push(&format!("{name} = {}", kpri_value(inst.d)));
            1
        }
        OP_GGET => {
            let name: String = proto
                .kstr(u32::from(inst.d))
                .map(str::to_owned)
                .unwrap_or_else(|| "_G".to_owned());
            state.declare_local(u32::from(inst.a), &name);
            1
        }
        OP_GSET => {
            let name: String = proto
                .kstr(u32::from(inst.d))
                .map(str::to_owned)
                .unwrap_or_else(|| "_G".to_owned());
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{name} = {val}"));
            1
        }
        OP_TGETV => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            state.declare_local(u32::from(inst.a), &format!("{table}[{key}]"));
            1
        }
        OP_TGETS => {
            let table: String = state.reg(u32::from(inst.b));
            let expr: String = index_field(&table, proto.kstr(u32::from(inst.c)));
            state.declare_local(u32::from(inst.a), &expr);
            1
        }
        OP_TGETB => {
            let table: String = state.reg(u32::from(inst.b));
            state.declare_local(u32::from(inst.a), &format!("{table}[{}]", inst.c));
            1
        }
        OP_TGETR => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            state.declare_local(u32::from(inst.a), &format!("{table}[{key}]"));
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
            let lhs: String = index_field(&table, proto.kstr(u32::from(inst.c)));
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
            let base: u32 = u32::from(inst.a);
            let table: String = state.reg(base.saturating_sub(1));
            let start_idx: i64 = match proto.knum(u32::from(inst.d)) {
                Some(LjKn::Int(i)) => i64::from(*i),
                Some(LjKn::Num(n)) => i64::from((n.to_bits() & 0xFFFF_FFFF) as u32),
                None => 1,
            };
            let multi: String = state
                .take_open_multi(base)
                .unwrap_or_else(|| "...".to_owned());
            let offset: i64 = start_idx.saturating_sub(1);
            if offset == 0 {
                state.push(&format!(
                    "do local _m = {{{multi}}}; for _i = 1, #_m do {table}[_i] = _m[_i] end end"
                ));
            } else {
                state.push(&format!(
                    "do local _m = {{{multi}}}; for _i = 1, #_m do {table}[{offset} + _i] = _m[_i] end end"
                ));
            }
            1
        }
        OP_TSETR => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{table}[{key}] = {val}"));
            1
        }
        OP_TNEW => {
            state.declare_local(u32::from(inst.a), "{}");
            1
        }
        OP_TDUP => {
            let lit: String = proto
                .ktab(u32::from(inst.d))
                .map_or_else(|| "{}".to_owned(), render_ktab);
            state.declare_local(u32::from(inst.a), &lit);
            1
        }
        OP_FNEW => {
            emit_fnew(proto, inst, state, ctx);
            1
        }
        OP_CALL => {
            emit_call(inst, state, false);
            1
        }
        OP_CALLM => {
            emit_callm(inst, state, false);
            1
        }
        OP_CALLT => {
            emit_call(inst, state, true);
            1
        }
        OP_CALLMT => {
            emit_callm(inst, state, true);
            1
        }
        OP_RET0 => {
            if pc + 1 != code_len {
                state.push("do return end");
            }
            1
        }
        OP_RET1 => {
            state.push(&format!("do return {} end", state.reg(u32::from(inst.a))));
            1
        }
        OP_RET => {
            emit_return(inst, state, false);
            1
        }
        OP_RETM => {
            emit_return(inst, state, true);
            1
        }
        OP_FORI | OP_JFORI | OP_FORL | OP_IFORL | OP_JFORL => 1,
        OP_ITERL | OP_IITERL | OP_JITERL | OP_ITERC | OP_ITERN | OP_ISNEXT => 1,
        OP_LOOP | OP_ILOOP | OP_JLOOP => 1,
        OP_VARG => {
            emit_vararg(inst, state);
            1
        }
        OP_UCLO => {
            let target: i32 = sj16(inst.d);
            let t: i64 = pc as i64 + 1 + i64::from(target);
            if target != 0 && t >= 0 && t as usize != pc + 1 {
                state.push(&format!("goto lj_{t}"));
                *ctx.fully_structured = false;
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
            emit_cond_jump(proto, pc, state, &format!("{lhs} {sym} {rhs}"));
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_ISEQS | OP_ISNES => {
            let lhs: String = state.reg(u32::from(inst.a));
            let rhs: String = proto
                .kstr(u32::from(inst.d))
                .map_or_else(|| "nil".to_owned(), quote_lua);
            let sym: &str = if inst.op == OP_ISEQS { "==" } else { "~=" };
            emit_cond_jump(proto, pc, state, &format!("{lhs} {sym} {rhs}"));
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_ISEQN | OP_ISNEN => {
            let lhs: String = state.reg(u32::from(inst.a));
            let rhs: String = proto
                .knum(u32::from(inst.d))
                .map_or_else(|| "0".to_owned(), fmt_kn);
            let sym: &str = if inst.op == OP_ISEQN { "==" } else { "~=" };
            emit_cond_jump(proto, pc, state, &format!("{lhs} {sym} {rhs}"));
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_ISEQP | OP_ISNEP => {
            let lhs: String = state.reg(u32::from(inst.a));
            let rhs: &str = kpri_value(inst.d);
            let sym: &str = if inst.op == OP_ISEQP { "==" } else { "~=" };
            emit_cond_jump(proto, pc, state, &format!("{lhs} {sym} {rhs}"));
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_IST => {
            let val: String = state.reg(u32::from(inst.d));
            emit_cond_jump(proto, pc, state, &val);
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_ISF => {
            let val: String = state.reg(u32::from(inst.d));
            emit_cond_jump(proto, pc, state, &format!("not ({val})"));
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_ISTC => {
            let val: String = state.reg(u32::from(inst.d));
            state.declare_local(u32::from(inst.a), &val);
            emit_cond_jump(proto, pc, state, &val);
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_ISFC => {
            let val: String = state.reg(u32::from(inst.d));
            state.declare_local(u32::from(inst.a), &val);
            emit_cond_jump(proto, pc, state, &format!("not ({val})"));
            *ctx.fully_structured = false;
            cond_advance(&proto.code, pc)
        }
        OP_ISTYPE | OP_ISNUM => 1,
        op if op >= OP_FUNCF => 1,
        op => {
            state.push(&format!("-- unknown luajit op {op}"));
            ctx.warnings
                .push(format!("unknown luajit opcode {op} at pc={pc}"));
            *ctx.fully_structured = false;
            1
        }
    }
}

#[inline]
fn cond_advance(code: &[u32], pc: usize) -> usize {
    if next_is_jmp(code, pc) { 2 } else { 1 }
}

#[must_use]
fn index_field(table: &str, key: Option<&str>) -> String {
    match key {
        Some(k) if is_ident(k) => format!("{table}.{k}"),
        Some(k) => format!("{table}[{}]", quote_lua(k)),
        None => format!("{table}[nil]"),
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

fn emit_cond_jump(proto: &LjProto, pc: usize, state: &mut LjState, cond: &str) {
    let next_jmp: Option<i64> = proto.code.get(pc + 1).and_then(|raw2: &u32| {
        let dj: LjInst = decode_inst(*raw2);
        if dj.op == OP_JMP {
            Some(pc as i64 + 2 + i64::from(sj16(dj.d)))
        } else {
            None
        }
    });
    match next_jmp {
        Some(t) if t >= 0 => state.push(&format!("if {cond} then goto lj_{t} end")),
        _ => state.push(&format!("-- test {cond}")),
    }
}

const CALL_ARG_BASE: u32 = 2;

fn collect_args(state: &mut LjState, base: u32, count: u32) -> Vec<String> {
    (0..count)
        .map(|i: u32| {
            let slot: u32 = base + i;
            if i + 1 == count {
                state
                    .take_open_multi(slot)
                    .unwrap_or_else(|| state.reg(slot))
            } else {
                state.reg(slot)
            }
        })
        .collect()
}

fn emit_call(inst: LjInst, state: &mut LjState, tail: bool) {
    let a: u32 = u32::from(inst.a);
    let func: String = state.reg(a);
    let nargs: u32 = u32::from(inst.c).saturating_sub(1);
    let args: Vec<String> = collect_args(state, a + CALL_ARG_BASE, nargs);
    let call: String = format!("{}({})", paren_callee(&func), args.join(", "));
    if tail {
        state.push(&format!("do return {call} end"));
        return;
    }
    let nrets: u32 = u32::from(inst.b);
    if nrets == 0 {
        state.set_reg(a, call.clone());
        state.set_open_multi(a, call);
        return;
    }
    emit_call_results(state, a, nrets - 1, &call);
}

fn emit_callm(inst: LjInst, state: &mut LjState, tail: bool) {
    let a: u32 = u32::from(inst.a);
    let func: String = state.reg(a);
    let fixed: u32 = u32::from(inst.c);
    let multi_slot: u32 = a + CALL_ARG_BASE + fixed;
    let tail_expr: String = state
        .take_open_multi(multi_slot)
        .unwrap_or_else(|| "...".to_owned());
    let mut args: Vec<String> = (0..fixed)
        .map(|i: u32| state.reg(a + CALL_ARG_BASE + i))
        .collect();
    args.push(tail_expr);
    let call: String = format!("{}({})", paren_callee(&func), args.join(", "));
    if tail {
        state.push(&format!("do return {call} end"));
        return;
    }
    let nrets: u32 = u32::from(inst.b);
    if nrets == 0 {
        state.set_reg(a, call.clone());
        state.set_open_multi(a, call);
        return;
    }
    emit_call_results(state, a, nrets - 1, &call);
}

#[must_use]
fn paren_callee(func: &str) -> String {
    if func.starts_with("function") {
        format!("({func})")
    } else {
        func.to_owned()
    }
}

fn emit_call_results(state: &mut LjState, base: u32, nrets: u32, call: &str) {
    match nrets {
        0 => state.push(call),
        1 => state.declare_local(base, call),
        _ => {
            let targets: Vec<String> = (0..nrets).map(|i: u32| state.slot_name(base + i)).collect();
            let all_declared: bool = (0..nrets).all(|i: u32| state.declared(base + i));
            let prefix: &str = if all_declared { "" } else { "local " };
            state.push(&format!("{prefix}{} = {call}", targets.join(", ")));
            for (i, t) in targets.iter().enumerate() {
                state.set_reg(base + i as u32, t.clone());
                state.mark_declared(base + i as u32);
            }
        }
    }
}

fn emit_return(inst: LjInst, state: &mut LjState, multi: bool) {
    let a: u32 = u32::from(inst.a);
    let d: u32 = u32::from(inst.d);
    if multi {
        let open: Option<(u32, String)> =
            state.open_multi.take().or_else(|| state.last_multi.clone());
        match open {
            Some((open_slot, expr)) if open_slot >= a => {
                let mut vals: Vec<String> = (a..open_slot).map(|r: u32| state.reg(r)).collect();
                vals.push(expr);
                state.push(&format!("do return {} end", vals.join(", ")));
            }
            _ => {
                let mut vals: Vec<String> = Vec::new();
                let mut r: u32 = a;
                while state.is_set(r) {
                    vals.push(state.reg(r));
                    r += 1;
                }
                vals.push("...".to_owned());
                state.push(&format!("do return {} end", vals.join(", ")));
            }
        }
        return;
    }
    let nret: u32 = d.saturating_sub(1);
    if nret == 0 {
        state.push("do return end");
    } else {
        let vals: Vec<String> = collect_args(state, a, nret);
        state.push(&format!("do return {} end", vals.join(", ")));
    }
}

fn emit_for_header(_proto: &LjProto, inst: LjInst, state: &mut LjState) {
    let a: u32 = u32::from(inst.a);
    let init: String = state.reg(a);
    let limit: String = state.reg(a + 1);
    let step: String = state.reg(a + 2);
    let var: String = state.slot_name(a + 3);
    state.set_reg(a + 3, var.clone());
    state.mark_declared(a + 3);
    let header: String = if step == "1" {
        format!("for {var} = {init}, {limit} do")
    } else {
        format!("for {var} = {init}, {limit}, {step} do")
    };
    state.push(&header);
    state.indent += 1;
}

fn emit_generic_for_header(_proto: &LjProto, inst: LjInst, state: &mut LjState) {
    let a: u32 = u32::from(inst.a);
    let nvars: u32 = u32::from(inst.b).saturating_sub(1).max(1);
    let iter_fn: String = state.reg(a.saturating_sub(3));
    let iter_state: String = state.reg(a.saturating_sub(2));
    let iter_ctrl: String = state.reg(a.saturating_sub(1));
    let vars: Vec<String> = (0..nvars).map(|i: u32| state.slot_name(a + i)).collect();
    for (i, name) in vars.iter().enumerate() {
        state.set_reg(a + i as u32, name.clone());
        state.mark_declared(a + i as u32);
    }
    state.push(&format!(
        "for {} in {iter_fn}, {iter_state}, {iter_ctrl} do",
        vars.join(", ")
    ));
    state.indent += 1;
}

fn emit_vararg(inst: LjInst, state: &mut LjState) {
    let a: u32 = u32::from(inst.a);
    let b: u32 = u32::from(inst.b);
    if b == 0 {
        state.set_reg(a, "...".to_owned());
        state.set_open_multi(a, "...".to_owned());
        return;
    }
    let nvals: u32 = b.saturating_sub(1);
    if nvals == 1 {
        state.declare_local(a, "...");
    } else {
        let targets: Vec<String> = (0..nvals).map(|i: u32| state.slot_name(a + i)).collect();
        let all_declared: bool = (0..nvals).all(|i: u32| state.declared(a + i));
        let prefix: &str = if all_declared { "" } else { "local " };
        state.push(&format!("{prefix}{} = ...", targets.join(", ")));
        for (i, t) in targets.iter().enumerate() {
            state.set_reg(a + i as u32, t.clone());
            state.mark_declared(a + i as u32);
        }
    }
}

fn emit_fnew(proto: &LjProto, inst: LjInst, state: &mut LjState, ctx: &mut LiftCtx<'_>) {
    let child: Option<&LjProto> = match proto.kgc_at(u32::from(inst.d)) {
        Some(LjKgc::Child) => resolve_child(proto, u32::from(inst.d), ctx.all_protos),
        _ => None,
    };
    match child {
        Some(child_proto) => {
            let dst: u32 = u32::from(inst.a);
            let name: String = state.slot_name(dst);
            let self_ref: bool = child_proto
                .uv_slots
                .iter()
                .any(|raw: &u16| raw & PROTO_UV_LOCAL != 0 && u32::from(raw & 0x3FFF) == dst);
            if self_ref && !state.declared(dst) {
                state.push(&format!("local {name}"));
                state.set_reg(dst, name.clone());
                state.mark_declared(dst);
            }
            let child_uv: Vec<String> = child_proto
                .uv_slots
                .iter()
                .map(|raw: &u16| {
                    if raw & PROTO_UV_LOCAL != 0 {
                        let slot: u32 = u32::from(raw & 0x3FFF);
                        state.reg(slot)
                    } else {
                        state.uv(u32::from(raw & 0x3FFF))
                    }
                })
                .collect();
            let body: String = lift_proto(
                child_proto,
                ctx.all_protos,
                ctx.depth + 1,
                &child_uv,
                ctx.warnings,
                ctx.fully_structured,
            );
            let trimmed: &str = body.strip_suffix('\n').unwrap_or(&body);
            let prefix: &str = if state.declared(dst) { "" } else { "local " };
            let mut lines: std::str::Lines<'_> = trimmed.lines();
            if let Some(first) = lines.next() {
                state.push(&format!("{prefix}{name} = {first}"));
            }
            for ln in lines {
                state.push(ln);
            }
            state.set_reg(dst, name);
            state.mark_declared(dst);
        }
        None => {
            let name: String = state.slot_name(u32::from(inst.a));
            state.declare_local(u32::from(inst.a), "function() end");
            state.set_reg(u32::from(inst.a), name);
            ctx.warnings
                .push("luajit FNEW child proto unresolved".to_owned());
            *ctx.fully_structured = false;
        }
    }
}

#[must_use]
fn resolve_child<'a>(proto: &LjProto, d: u32, all_protos: &'a [LjProto]) -> Option<&'a LjProto> {
    let kgc_idx: usize = *proto.kgc_rev.get(d as usize)?;
    let mut child_rank: usize = 0;
    for (i, entry) in proto.kgc.iter().enumerate() {
        if matches!(entry, LjKgc::Child) {
            if i == kgc_idx {
                return proto
                    .child_indices
                    .get(child_rank)
                    .and_then(|idx: &usize| all_protos.get(*idx));
            }
            child_rank += 1;
        }
    }
    None
}

#[inline]
fn writes_dst(op: u8) -> bool {
    matches!(
        op,
        OP_MOV
            | OP_NOT
            | OP_UNM
            | OP_LEN
            | OP_ISTC
            | OP_ISFC
            | OP_KSTR
            | OP_KCDATA
            | OP_KSHORT
            | OP_KNUM
            | OP_KPRI
            | OP_ADDVN
            | OP_SUBVN
            | OP_MULVN
            | OP_DIVVN
            | OP_MODVN
            | OP_ADDNV
            | OP_SUBNV
            | OP_MULNV
            | OP_DIVNV
            | OP_MODNV
            | OP_ADDVV
            | OP_SUBVV
            | OP_MULVV
            | OP_DIVVV
            | OP_MODVV
            | OP_POW
            | OP_CAT
            | OP_UGET
            | OP_GGET
            | OP_TGETV
            | OP_TGETS
            | OP_TGETB
            | OP_TGETR
            | OP_TNEW
            | OP_TDUP
            | OP_FNEW
    )
}

#[must_use]
fn compute_predeclare(proto: &LjProto, loops: &[LoopRegion]) -> Vec<u32> {
    let frame: usize = usize::from(proto.framesize).max(2);
    let mut counts: Vec<u32> = vec![0; frame + 1];
    let bump = |slot: usize, counts: &mut [u32]| {
        if slot < counts.len() {
            counts[slot] += 1;
        }
    };
    for raw in &proto.code {
        let inst: LjInst = decode_inst(*raw);
        match inst.op {
            OP_CALL | OP_CALLM => {
                let nrets: u32 = u32::from(inst.b).saturating_sub(1);
                for i in 0..nrets {
                    bump(usize::from(inst.a) + i as usize, &mut counts);
                }
                if nrets == 0 {
                    bump(usize::from(inst.a), &mut counts);
                }
            }
            OP_VARG => {
                let nvals: u32 = u32::from(inst.b).saturating_sub(1).max(1);
                for i in 0..nvals {
                    bump(usize::from(inst.a) + i as usize, &mut counts);
                }
            }
            OP_KNIL => {
                for r in usize::from(inst.a)..=usize::from(inst.d) {
                    bump(r, &mut counts);
                }
            }
            op if writes_dst(op) => bump(usize::from(inst.a), &mut counts),
            _ => {}
        }
    }
    let num_params: u32 = u32::from(proto.num_params);
    let _ = loops;
    (0..frame as u32)
        .filter(|slot: &u32| {
            counts.get(*slot as usize).copied().unwrap_or(0) >= 1 && *slot >= num_params
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum LoopKind {
    Numeric,
    Generic,
}

#[derive(Debug, Clone, Copy)]
struct LoopRegion {
    kind: LoopKind,
    header_pc: usize,
    body_start: usize,
    body_end: usize,
    end_pc: usize,
    iterc_pc: usize,
}

#[must_use]
fn detect_loops(code: &[u32]) -> Vec<LoopRegion> {
    let mut loops: Vec<LoopRegion> = Vec::new();
    for (pc, raw) in code.iter().enumerate() {
        let inst: LjInst = decode_inst(*raw);
        match inst.op {
            OP_FORI | OP_JFORI => {
                let end_target: i64 = pc as i64 + 1 + i64::from(sj16(inst.d));
                if end_target < 1 || end_target as usize > code.len() {
                    continue;
                }
                let forl_pc: usize = (end_target as usize).saturating_sub(1);
                if !matches!(
                    code.get(forl_pc).map(|r: &u32| decode_inst(*r).op),
                    Some(OP_FORL | OP_IFORL | OP_JFORL)
                ) {
                    continue;
                }
                loops.push(LoopRegion {
                    kind: LoopKind::Numeric,
                    header_pc: pc,
                    body_start: pc + 1,
                    body_end: forl_pc,
                    end_pc: forl_pc + 1,
                    iterc_pc: forl_pc,
                });
            }
            OP_JMP => {
                let target: i64 = pc as i64 + 1 + i64::from(sj16(inst.d));
                if target < 0 || target as usize >= code.len() {
                    continue;
                }
                let iterc_pc: usize = target as usize;
                if !matches!(
                    code.get(iterc_pc).map(|r: &u32| decode_inst(*r).op),
                    Some(OP_ITERC | OP_ITERN)
                ) {
                    continue;
                }
                let iterl_pc: usize = iterc_pc + 1;
                if !matches!(
                    code.get(iterl_pc).map(|r: &u32| decode_inst(*r).op),
                    Some(OP_ITERL | OP_IITERL | OP_JITERL)
                ) {
                    continue;
                }
                loops.push(LoopRegion {
                    kind: LoopKind::Generic,
                    header_pc: pc,
                    body_start: pc + 1,
                    body_end: iterc_pc,
                    end_pc: iterl_pc + 1,
                    iterc_pc,
                });
            }
            _ => {}
        }
    }
    loops
}

#[must_use]
fn loop_at(loops: &[LoopRegion], pc: usize) -> Option<LoopRegion> {
    loops
        .iter()
        .copied()
        .find(|l: &LoopRegion| l.header_pc == pc)
}

fn emit_range(
    proto: &LjProto,
    start: usize,
    end: usize,
    loops: &[LoopRegion],
    jump_targets: &[bool],
    state: &mut LjState,
    ctx: &mut LiftCtx<'_>,
) {
    let mut pc: usize = start;
    let mut dead: bool = false;
    while pc < end {
        if jump_targets.get(pc).copied().unwrap_or(false) {
            state.push(&format!("::lj_{pc}::"));
            dead = false;
        }
        if let Some(region) = loop_at(loops, pc) {
            emit_loop(proto, region, loops, jump_targets, state, ctx);
            pc = region.end_pc;
            dead = false;
            continue;
        }
        let raw: u32 = proto.code[pc];
        let inst: LjInst = decode_inst(raw);
        if dead {
            pc += inst_advance(&proto.code, pc, inst.op);
            continue;
        }
        let advance: usize = handle_inst(proto, inst, pc, proto.code.len(), state, ctx);
        if is_terminator(inst.op) {
            dead = true;
        }
        pc += advance;
    }
}

#[inline]
fn inst_advance(code: &[u32], pc: usize, op: u8) -> usize {
    if is_cond(op) && next_is_jmp(code, pc) {
        2
    } else {
        1
    }
}

#[inline]
fn is_terminator(op: u8) -> bool {
    matches!(
        op,
        OP_RET | OP_RET0 | OP_RET1 | OP_RETM | OP_CALLT | OP_CALLMT | OP_JMP
    )
}

fn emit_loop(
    proto: &LjProto,
    region: LoopRegion,
    loops: &[LoopRegion],
    jump_targets: &[bool],
    state: &mut LjState,
    ctx: &mut LiftCtx<'_>,
) {
    match region.kind {
        LoopKind::Numeric => {
            let inst: LjInst = decode_inst(proto.code[region.header_pc]);
            emit_for_header(proto, inst, state);
        }
        LoopKind::Generic => {
            let iterc: LjInst = decode_inst(proto.code[region.iterc_pc]);
            emit_generic_for_header(proto, iterc, state);
        }
    }
    emit_range(
        proto,
        region.body_start,
        region.body_end,
        loops,
        jump_targets,
        state,
        ctx,
    );
    if jump_targets.get(region.body_end).copied().unwrap_or(false) {
        state.push(&format!("::lj_{}::", region.body_end));
    }
    if state.indent > 1 {
        state.indent -= 1;
    }
    state.push("end");
}

#[must_use]
fn compute_jump_targets(code: &[u32], loops: &[LoopRegion]) -> Vec<bool> {
    let n: usize = code.len();
    let mut targets: Vec<bool> = vec![false; n + 1];
    let mark = |t: i64, targets: &mut [bool]| {
        if t >= 0 && (t as usize) <= n {
            targets[t as usize] = true;
        }
    };
    for (pc, raw) in code.iter().enumerate() {
        let inst: LjInst = decode_inst(*raw);
        if matches!(inst.op, OP_JMP | OP_UCLO) {
            let t: i64 = pc as i64 + 1 + i64::from(sj16(inst.d));
            if !is_loop_internal_jump(loops, pc) {
                mark(t, &mut targets);
            }
        }
        if is_cond(inst.op)
            && let Some(raw2) = code.get(pc + 1)
        {
            let dj: LjInst = decode_inst(*raw2);
            if dj.op == OP_JMP {
                let t: i64 = pc as i64 + 2 + i64::from(sj16(dj.d));
                mark(t, &mut targets);
            }
        }
    }
    for region in loops {
        if let Some(t) = targets.get_mut(region.header_pc) {
            *t = false;
        }
        if let Some(t) = targets.get_mut(region.body_start) {
            *t = false;
        }
    }
    targets
}

#[must_use]
fn is_loop_internal_jump(loops: &[LoopRegion], pc: usize) -> bool {
    loops
        .iter()
        .any(|l: &LoopRegion| matches!(l.kind, LoopKind::Generic) && l.header_pc == pc)
}

#[inline]
fn is_cond(op: u8) -> bool {
    matches!(
        op,
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
    )
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

    #[test]
    fn keyword_is_not_identifier() {
        assert!(!is_ident("end"));
        assert!(!is_ident("function"));
        assert!(is_ident("foo"));
        assert!(is_ident("_bar1"));
    }

    #[test]
    fn fmt_num_roundtrips_fraction() {
        assert_eq!(fmt_num(1.5), "1.5");
        assert_eq!(fmt_num(3.0), "3");
        assert_eq!(fmt_num(0.1), "0.1");
    }

    #[test]
    fn source_length_must_fit_remaining_bytes() {
        let bytes: Vec<u8> = vec![0x1B, b'L', b'J', 0x02, 0x00, 0x20];
        let mut warnings: Vec<String> = Vec::new();
        let err: Error = parse_chunk(&bytes, &mut warnings).expect_err("truncated source");
        assert!(matches!(err, Error::Truncated { .. }));
    }
}
