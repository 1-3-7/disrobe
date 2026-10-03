use crate::decompile::{DecompiledChunk, Fidelity, decompile_chunk};
use crate::error::{Error, Result};
use crate::reader::{LuaChunk, LuaConstant, LuaDialect, LuaProto, LuaUpvalueName};

const MAX_PROTO_DEPTH: usize = 200;
const MAX_ENCODED_BYTES: usize = 64 << 20;
const MIN_INSTRUCTION_BYTES: usize = 12;
const OP_VARARG: u32 = 37;
const OP_MAX: u32 = 37;

#[derive(Debug)]
pub(crate) struct Devirtualized {
    pub(crate) source: String,
    pub(crate) fidelity: Fidelity,
    pub(crate) protos: usize,
    pub(crate) instructions: usize,
}

pub(crate) fn devirtualize(bytecode: &[u8], charset: &[u8]) -> Result<Devirtualized> {
    let stream: Vec<u8> = decode_payload(bytecode, charset)?;
    let main: LuaProto = Stream::new(&stream).chunk()?;
    let (protos, instructions): (usize, usize) = census(&main);
    let chunk: LuaChunk = LuaChunk {
        dialect: LuaDialect::Lua51,
        version_byte: 0x51,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 4,
        size_of_instruction: 4,
        size_of_lua_integer: 0,
        size_of_lua_number: 8,
        integral_number: false,
        main,
    };
    let decompiled: DecompiledChunk = decompile_chunk(&chunk)?;
    Ok(Devirtualized {
        source: decompiled.source,
        fidelity: decompiled.fidelity,
        protos,
        instructions,
    })
}

fn census(proto: &LuaProto) -> (usize, usize) {
    proto.protos.iter().map(census).fold(
        (1, proto.code.len()),
        |(p, i): (usize, usize), (sp, si): (usize, usize)| (p + sp, i + si),
    )
}

fn decode_payload(bytecode: &[u8], charset: &[u8]) -> Result<Vec<u8>> {
    if bytecode.len() > MAX_ENCODED_BYTES || charset.is_empty() || charset.len() > 255 {
        return Err(Error::DecompileUnsupported(
            "hercules VM payload or charset is outside the decoder bounds",
        ));
    }
    let mut lookup: [Option<u32>; 256] = [None; 256];
    for (digit, byte) in (0u32..).zip(charset) {
        if lookup[usize::from(*byte)].replace(digit).is_some() {
            return Err(Error::DecompileUnsupported(
                "hercules VM charset repeats a digit",
            ));
        }
    }
    let base: u32 = u32::try_from(charset.len())
        .map_err(|_| Error::DecompileUnsupported("hercules VM charset is too long"))?;
    let mut decoded: Vec<u8> = Vec::with_capacity(bytecode.len() / 2);
    for group in bytecode.split(|byte: &u8| *byte == b'_') {
        if group.is_empty() {
            continue;
        }
        let mut value: u32 = 0;
        for byte in group {
            let digit: u32 = lookup[usize::from(*byte)].ok_or(Error::DecompileUnsupported(
                "hercules VM payload uses a byte outside its charset",
            ))?;
            value = value
                .checked_mul(base)
                .and_then(|v: u32| v.checked_add(digit))
                .filter(|v: &u32| *v <= 255)
                .ok_or(Error::DecompileUnsupported(
                    "hercules VM payload digit group exceeds a byte",
                ))?;
        }
        decoded.push(u8::try_from(value).map_err(|_| {
            Error::DecompileUnsupported("hercules VM payload digit group exceeds a byte")
        })?);
    }
    if !decoded.len().is_multiple_of(2) {
        return Err(Error::DecompileUnsupported(
            "hercules VM payload does not pair every byte with its separator",
        ));
    }
    let mut stream: Vec<u8> = Vec::with_capacity(decoded.len() / 2);
    for pair in decoded.chunks_exact(2) {
        if pair[1] != b'\\' {
            return Err(Error::DecompileUnsupported(
                "hercules VM payload byte is not followed by its separator",
            ));
        }
        stream.push(pair[0]);
    }
    Ok(stream)
}

#[derive(Debug)]
struct Stream<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Stream<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end: usize = self
            .pos
            .checked_add(len)
            .filter(|end: &usize| *end <= self.bytes.len())
            .ok_or(Error::DecompileUnsupported(
                "hercules VM payload is truncated",
            ))?;
        let slice: &'a [u8] = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b: &[u8] = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b: &[u8] = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn count(&mut self, min_item_bytes: usize) -> Result<usize> {
        let count: usize = usize::try_from(self.u32()?)
            .map_err(|_| Error::DecompileUnsupported("hercules VM count overflows"))?;
        if count.saturating_mul(min_item_bytes) > self.remaining() {
            return Err(Error::DecompileUnsupported(
                "hercules VM count exceeds the remaining payload",
            ));
        }
        Ok(count)
    }

    fn chunk(&mut self) -> Result<LuaProto> {
        let main: LuaProto = self.proto(0)?;
        if self.remaining() != 0 {
            return Err(Error::DecompileUnsupported(
                "hercules VM payload carries bytes after its main function",
            ));
        }
        Ok(main)
    }

    fn proto(&mut self, depth: usize) -> Result<LuaProto> {
        if depth > MAX_PROTO_DEPTH {
            return Err(Error::DecompileUnsupported(
                "hercules VM functions nest past the depth budget",
            ));
        }
        let upvalues: u8 = self.u8()?;
        let num_params: u8 = self.u8()?;
        let max_stack_size: u8 = self.u8()?;
        let instruction_count: usize = self.count(MIN_INSTRUCTION_BYTES)?;
        let mut code: Vec<u32> = Vec::with_capacity(instruction_count);
        for _ in 0..instruction_count {
            code.push(self.instruction()?);
        }
        let constant_count: usize = self.count(2)?;
        let mut constants: Vec<LuaConstant> = Vec::with_capacity(constant_count);
        for _ in 0..constant_count {
            constants.push(self.constant()?);
        }
        let proto_count: usize = self.count(MIN_INSTRUCTION_BYTES)?;
        let mut protos: Vec<LuaProto> = Vec::with_capacity(proto_count);
        for _ in 0..proto_count {
            protos.push(self.proto(depth + 1)?);
        }
        let is_vararg: u8 = if depth == 0 || code.iter().any(|word: &u32| word & 0x3F == OP_VARARG)
        {
            2
        } else {
            0
        };
        Ok(LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params,
            is_vararg,
            max_stack_size,
            code,
            constants,
            protos,
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: vec![
                LuaUpvalueName {
                    name: String::new(),
                    descriptor: None,
                };
                usize::from(upvalues)
            ],
        })
    }

    fn instruction(&mut self) -> Result<u32> {
        let word: u32 = self.u32()?;
        let op: u8 = self.u8()?;
        let shape: u8 = self.u8()?;
        let a: u16 = self.u16()?;
        let _mode_b: u8 = self.u8()?;
        let _mode_c: u8 = self.u8()?;
        let consistent: bool = u32::from(op) == word & 0x3F
            && u32::from(op) <= OP_MAX
            && u32::from(a) == (word >> 6) & 0xFF
            && shape == operand_shape(u32::from(op));
        let operands_match: bool = match shape {
            1 => {
                let b: u16 = self.u16()?;
                let c: u16 = self.u16()?;
                u32::from(b) == (word >> 23) & 0x1FF && u32::from(c) == (word >> 14) & 0x1FF
            }
            2 | 3 => self.u32()? == word >> 14,
            _ => false,
        };
        if consistent && operands_match {
            Ok(word)
        } else {
            Err(Error::DecompileUnsupported(
                "hercules VM instruction fields disagree with its Lua 5.1 instruction word",
            ))
        }
    }

    fn constant(&mut self) -> Result<LuaConstant> {
        match self.u8()? {
            1 => Ok(LuaConstant::Bool(self.u8()? != 0)),
            3 => {
                let low: u32 = self.u32()?;
                let high: u32 = self.u32()?;
                Ok(LuaConstant::Number(f64::from_bits(
                    (u64::from(high) << 32) | u64::from(low),
                )))
            }
            4 => {
                let len: usize = usize::try_from(self.u32()?).map_err(|_| {
                    Error::DecompileUnsupported("hercules VM string length overflows")
                })?;
                let bytes: &[u8] = self.take(len)?;
                String::from_utf8(bytes.to_vec())
                    .map(LuaConstant::Str)
                    .map_err(|_| {
                        Error::DecompileUnsupported("hercules VM string constant is not UTF-8")
                    })
            }
            _ => Err(Error::DecompileUnsupported(
                "hercules VM constant has an unknown type tag",
            )),
        }
    }
}

const fn operand_shape(op: u32) -> u8 {
    match op {
        1 | 5 | 7 | 36 => 2,
        22 | 31 | 32 => 3,
        _ => 1,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{Stream, decode_payload};

    #[test]
    fn payload_decodes_base_n_groups_and_byte_separators() {
        let charset: &[u8] = b"ab";
        let encoded: Vec<u8> = [0x41u8, b'\\', 0x5C, b'\\']
            .iter()
            .map(|byte: &u8| {
                (0..8)
                    .rev()
                    .map(|bit: u32| if (byte >> bit) & 1 == 1 { 'b' } else { 'a' })
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("_")
            .into_bytes();
        assert_eq!(
            decode_payload(&encoded, charset).expect("decode"),
            vec![0x41, 0x5C]
        );
        assert!(decode_payload(b"c", charset).is_err());
        assert!(decode_payload(b"bbbbbbbbb", charset).is_err());
    }

    #[test]
    fn instruction_fields_must_match_the_word() {
        let word: u32 = 1 | (2 << 6) | (3 << 14);
        let mut bytes: Vec<u8> = word.to_le_bytes().to_vec();
        bytes.extend([1, 2]);
        bytes.extend(2u16.to_le_bytes());
        bytes.extend([1, 0]);
        bytes.extend(3u32.to_le_bytes());
        assert_eq!(Stream::new(&bytes).instruction().expect("loadk"), word);
        let mut forged: Vec<u8> = bytes.clone();
        forged[6] = 9;
        assert!(Stream::new(&forged).instruction().is_err());
    }

    #[test]
    fn truncated_and_oversized_counts_are_errors() {
        assert!(Stream::new(&[0, 0, 2]).chunk().is_err());
        let mut bytes: Vec<u8> = vec![0, 0, 2];
        bytes.extend(u32::MAX.to_le_bytes());
        assert!(Stream::new(&bytes).chunk().is_err());
    }
}
