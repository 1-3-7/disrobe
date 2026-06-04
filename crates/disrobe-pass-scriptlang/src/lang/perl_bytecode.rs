use serde::Serialize;

use crate::error::{Error, Result};
use crate::lang::perl::{PerlOp, PerlOpTree, PerlSub};

const MAGIC_NATIVE: u32 = 0x43424c50;
const MAGIC_LE_BYTES: [u8; 4] = [0x50, 0x4c, 0x42, 0x43];
const MAGIC_BE_BYTES: [u8; 4] = [0x43, 0x42, 0x4c, 0x50];
const SHEBANG_USE_BYTELOADER: &[u8] = b"use ByteLoader";
const MAX_OPS: usize = 1_000_000usize;

const OP_RET: u8 = 0u8;
const OP_LDSV: u8 = 1u8;
const OP_LDOP: u8 = 2u8;
const OP_STSV: u8 = 3u8;
const OP_STOP: u8 = 4u8;
const OP_STPV: u8 = 5u8;
const OP_LDSPECSV: u8 = 6u8;
const OP_LDSPECSVX: u8 = 7u8;
const OP_NEWSV: u8 = 8u8;
const OP_NEWSVX: u8 = 9u8;
const OP_NEWOP: u8 = 11u8;
const OP_NEWOPX: u8 = 12u8;
const OP_NEWOPN: u8 = 13u8;
const OP_NEWPV: u8 = 14u8;
const OP_PV_CUR: u8 = 15u8;
const OP_PV_FREE: u8 = 16u8;
const OP_SV_UPGRADE: u8 = 17u8;
const OP_SV_REFCNT: u8 = 18u8;
const OP_SV_REFCNT_ADD: u8 = 19u8;
const OP_SV_FLAGS: u8 = 20u8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BytecodeHeader {
    pub byte_order: ByteOrder,
    pub archname: Option<String>,
    pub byteloader_version: Option<String>,
    pub ivsize: Option<u32>,
    pub ptrsize: Option<u32>,
    pub byteorder_field: Option<String>,
    pub perl_version: Option<String>,
}

#[must_use]
pub fn is_bytecode(bytes: &[u8]) -> bool {
    find_magic(bytes).is_some()
}

fn find_magic(bytes: &[u8]) -> Option<(usize, ByteOrder)> {
    let scan_limit: usize = bytes.len().min(4096);
    let window: &[u8] = &bytes[..scan_limit];
    window
        .windows(4)
        .enumerate()
        .find_map(|(i, w): (usize, &[u8])| {
            if w == MAGIC_LE_BYTES {
                Some((i, ByteOrder::Little))
            } else if w == MAGIC_BE_BYTES {
                Some((i, ByteOrder::Big))
            } else {
                None
            }
        })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    order: ByteOrder,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8], pos: usize, order: ByteOrder) -> Self {
        Self { bytes, pos, order }
    }

    fn u8(&mut self) -> Result<u8> {
        let b: u8 = *self
            .bytes
            .get(self.pos)
            .ok_or(Error::PerlBytecodeTruncated(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        let raw: [u8; 2] = self
            .bytes
            .get(self.pos..self.pos + 2)
            .ok_or(Error::PerlBytecodeTruncated(self.pos))?
            .try_into()
            .map_err(|_| Error::PerlBytecodeTruncated(self.pos))?;
        self.pos += 2;
        Ok(match self.order {
            ByteOrder::Little => u16::from_le_bytes(raw),
            ByteOrder::Big => u16::from_be_bytes(raw),
        })
    }

    fn u32(&mut self) -> Result<u32> {
        let raw: [u8; 4] = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or(Error::PerlBytecodeTruncated(self.pos))?
            .try_into()
            .map_err(|_| Error::PerlBytecodeTruncated(self.pos))?;
        self.pos += 4;
        Ok(match self.order {
            ByteOrder::Little => u32::from_le_bytes(raw),
            ByteOrder::Big => u32::from_be_bytes(raw),
        })
    }

    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    fn pv(&mut self) -> Result<Vec<u8>> {
        let len: usize = self.u32()? as usize;
        let end: usize = self
            .pos
            .checked_add(len)
            .ok_or(Error::PerlBytecodeTruncated(self.pos))?;
        let slice: &[u8] = self
            .bytes
            .get(self.pos..end)
            .ok_or(Error::PerlBytecodeTruncated(self.pos))?;
        let out: Vec<u8> = slice.to_vec();
        self.pos = end;
        Ok(out)
    }

    fn asciiz(&mut self) -> Result<String> {
        let start: usize = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.bytes.len() {
            return Err(Error::PerlBytecodeTruncated(start));
        }
        let s: String = String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
        self.pos += 1;
        Ok(s)
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }
}

pub fn read_bytecode(bytes: &[u8]) -> Result<PerlOpTree> {
    let (magic_off, order): (usize, ByteOrder) = find_magic(bytes).ok_or(Error::NotPerlBytecode)?;
    let mut c: Cursor<'_> = Cursor::new(bytes, magic_off, order);
    let magic: u32 = c.u32()?;
    if magic != MAGIC_NATIVE && magic.swap_bytes() != MAGIC_NATIVE {
        return Err(Error::NotPerlBytecode);
    }

    let header: BytecodeHeader = read_header(&mut c);
    let source_hint: Option<String> = header
        .archname
        .clone()
        .or_else(|| header.perl_version.clone());

    let mut ops: Vec<PerlOp> = Vec::new();
    let mut pvs: Vec<String> = Vec::new();
    let mut op_count: usize = 0usize;

    while c.remaining() > 0 && op_count < MAX_OPS {
        let opcode: u8 = c.u8()?;
        let (name, detail): (&'static str, Option<String>) = decode_insn(&mut c, opcode, &mut pvs)?;
        ops.push(PerlOp {
            seq: op_count.to_string(),
            name: name.to_owned(),
            flags: String::new(),
            detail,
        });
        op_count += 1;
        if opcode == OP_RET {
            break;
        }
    }

    if op_count == 0 {
        return Err(Error::PerlBytecodeEmpty);
    }

    let mut constants: Vec<String> = pvs;
    constants.sort_unstable();
    constants.dedup();

    let sub: PerlSub = PerlSub {
        name: "main program".to_owned(),
        is_main_program: true,
        ops,
        pad_vars: Vec::new(),
        constants,
        called_subs: Vec::new(),
    };

    Ok(PerlOpTree {
        source_hint,
        subs: vec![sub],
        op_count,
    })
}

fn read_header(c: &mut Cursor<'_>) -> BytecodeHeader {
    let archname: Option<String> = c.asciiz().ok().filter(|s: &String| !s.is_empty());
    let byteloader_version: Option<String> = c.asciiz().ok().filter(|s: &String| !s.is_empty());
    let ivsize: Option<u32> = c.u32().ok();
    let ptrsize: Option<u32> = c.u32().ok();
    let byteorder_field: Option<String> = c.asciiz().ok().filter(|s: &String| !s.is_empty());
    let perl_version: Option<String> = c.asciiz().ok().filter(|s: &String| !s.is_empty());
    BytecodeHeader {
        byte_order: c.order,
        archname,
        byteloader_version,
        ivsize,
        ptrsize,
        byteorder_field,
        perl_version,
    }
}

fn decode_insn(
    c: &mut Cursor<'_>,
    opcode: u8,
    pvs: &mut Vec<String>,
) -> Result<(&'static str, Option<String>)> {
    let result: (&'static str, Option<String>) = match opcode {
        OP_RET => ("ret", None),
        OP_LDSV => ("ldsv", Some(format!("sv#{}", c.u32()?))),
        OP_LDOP => ("ldop", Some(format!("op#{}", c.u32()?))),
        OP_STSV => ("stsv", Some(format!("sv#{}", c.u32()?))),
        OP_STOP => ("stop", Some(format!("op#{}", c.u32()?))),
        OP_STPV => ("stpv", Some(format!("pv#{}", c.u32()?))),
        OP_LDSPECSV => ("ldspecsv", Some(format!("spec#{}", c.u8()?))),
        OP_LDSPECSVX => ("ldspecsvx", Some(format!("spec#{}", c.u8()?))),
        OP_NEWSV => ("newsv", Some(format!("type={}", c.u8()?))),
        OP_NEWSVX => ("newsvx", Some(format!("flags={:#x}", c.u32()?))),
        OP_NEWOP => ("newop", Some(format!("type={}", c.u8()?))),
        OP_NEWOPX => ("newopx", Some(format!("type={}", c.u16()?))),
        OP_NEWOPN => ("newopn", Some(format!("type={}", c.u8()?))),
        OP_NEWPV => {
            let raw: Vec<u8> = c.pv()?;
            let s: String = String::from_utf8_lossy(&raw).into_owned();
            if !s.is_empty() {
                pvs.push(s.clone());
            }
            ("newpv", Some(format!("PV \"{s}\"")))
        }
        OP_PV_CUR => ("pv_cur", Some(format!("cur={}", c.u32()?))),
        OP_PV_FREE => ("pv_free", None),
        OP_SV_UPGRADE => ("sv_upgrade", Some(format!("to={}", c.u8()?))),
        OP_SV_REFCNT => ("sv_refcnt", Some(format!("rc={}", c.u32()?))),
        OP_SV_REFCNT_ADD => ("sv_refcnt_add", Some(format!("delta={}", c.i32()?))),
        OP_SV_FLAGS => ("sv_flags", Some(format!("flags={:#x}", c.u32()?))),
        other => return Err(Error::PerlBytecodeUnknownOp(other)),
    };
    Ok(result)
}

#[must_use]
pub fn looks_like_byteloader_script(bytes: &[u8]) -> bool {
    let head: &[u8] = &bytes[..bytes.len().min(256)];
    head.windows(SHEBANG_USE_BYTELOADER.len())
        .any(|w: &[u8]| w == SHEBANG_USE_BYTELOADER)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn put_u32(out: &mut Vec<u8>, v: u32, order: ByteOrder) {
        match order {
            ByteOrder::Little => out.extend_from_slice(&v.to_le_bytes()),
            ByteOrder::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put_asciiz(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    fn put_pv(out: &mut Vec<u8>, s: &str, order: ByteOrder) {
        put_u32(out, s.len() as u32, order);
        out.extend_from_slice(s.as_bytes());
    }

    fn minimal_bytecode(order: ByteOrder) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"#! /usr/bin/perl\nuse ByteLoader 0.06;\n");
        put_u32(&mut out, MAGIC_NATIVE, order);
        put_asciiz(&mut out, "x86_64-linux");
        put_asciiz(&mut out, "0.06");
        put_u32(&mut out, 8, order);
        put_u32(&mut out, 8, order);
        put_asciiz(&mut out, "12345678");
        put_asciiz(&mut out, "5.036000");

        out.push(OP_NEWSVX);
        put_u32(&mut out, 0x0c, order);
        out.push(OP_NEWPV);
        put_pv(&mut out, "Hello, disrobe!", order);
        out.push(OP_PV_CUR);
        put_u32(&mut out, 15, order);
        out.push(OP_NEWPV);
        put_pv(&mut out, "main::greet", order);
        out.push(OP_RET);
        out
    }

    #[test]
    fn detects_le_and_be_magic() {
        assert!(is_bytecode(&minimal_bytecode(ByteOrder::Little)));
        assert!(is_bytecode(&minimal_bytecode(ByteOrder::Big)));
    }

    #[test]
    fn rejects_concise_text() {
        assert!(!is_bytecode(b"hello.pl syntax OK\nmain program:\n"));
    }

    #[test]
    fn parses_header_le() {
        let bc: Vec<u8> = minimal_bytecode(ByteOrder::Little);
        let tree: PerlOpTree = read_bytecode(&bc).expect("parse le");
        assert_eq!(tree.subs.len(), 1);
        assert!(tree.subs[0].is_main_program);
        assert_eq!(tree.source_hint.as_deref(), Some("x86_64-linux"));
    }

    #[test]
    fn recovers_pv_constants_both_orders() {
        for order in [ByteOrder::Little, ByteOrder::Big] {
            let bc: Vec<u8> = minimal_bytecode(order);
            let tree: PerlOpTree = read_bytecode(&bc).expect("parse");
            let main: &PerlSub = &tree.subs[0];
            assert!(
                main.constants
                    .iter()
                    .any(|c: &String| c == "Hello, disrobe!"),
                "PV must be recovered for {order:?}: {:?}",
                main.constants
            );
            assert!(
                main.constants.iter().any(|c: &String| c == "main::greet"),
                "sub-name PV must be recovered for {order:?}: {:?}",
                main.constants
            );
        }
    }

    #[test]
    fn walks_full_op_stream_to_ret() {
        let bc: Vec<u8> = minimal_bytecode(ByteOrder::Little);
        let tree: PerlOpTree = read_bytecode(&bc).expect("parse");
        assert_eq!(tree.op_count, 5);
        assert_eq!(
            tree.subs[0].ops.last().map(|o| o.name.as_str()),
            Some("ret")
        );
    }

    #[test]
    fn unknown_opcode_fails_fast() {
        let mut bc: Vec<u8> = Vec::new();
        put_u32(&mut bc, MAGIC_NATIVE, ByteOrder::Little);
        put_asciiz(&mut bc, "arch");
        put_asciiz(&mut bc, "0.06");
        put_u32(&mut bc, 8, ByteOrder::Little);
        put_u32(&mut bc, 8, ByteOrder::Little);
        put_asciiz(&mut bc, "order");
        put_asciiz(&mut bc, "ver");
        bc.push(200u8);
        assert!(matches!(
            read_bytecode(&bc),
            Err(Error::PerlBytecodeUnknownOp(200))
        ));
    }

    #[test]
    fn detects_byteloader_script_marker() {
        assert!(looks_like_byteloader_script(
            b"#!/usr/bin/perl\nuse ByteLoader 0.06;\n"
        ));
        assert!(!looks_like_byteloader_script(
            b"#!/usr/bin/perl\nprint 1;\n"
        ));
    }
}
