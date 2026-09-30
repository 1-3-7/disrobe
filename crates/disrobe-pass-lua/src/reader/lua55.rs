use crate::cursor::{ByteCursor, MAX_PROTO_DEPTH};
use crate::error::{Error, Result};
use crate::reader::common::{
    LUA_SIGNATURE, LUAC_DATA_TAIL, LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto,
    LuaUpvalueName, UpvalueDescriptor, capped_u32,
};

const LUAC_VERSION_5_5: u8 = 0x55;
const LUAC_INT_5_5: i64 = -0x5678;
const LUAC_INST_5_5: u64 = 0x1234_5678;
const LUAC_NUM_5_5: f64 = -370.5_f64;
const INT_VARINT_LIMIT: u64 = i32::MAX as u64;
const INSTRUCTION_BYTES: usize = 4;
const ABS_LINE_BYTES: usize = 8;
const FIXED_MEMORY_FLAG: u8 = 4;
const MAX_MATERIALIZED_STRING_BYTES: usize = 64 << 20;

struct Loader<'a> {
    cursor: ByteCursor<'a>,
    saved: Vec<String>,
    materialized: usize,
    number_bytes: u8,
}

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let sig: &[u8] = c.read_bytes(4)?;
    if sig != LUA_SIGNATURE {
        return Err(Error::BadSignature);
    }
    let version: u8 = c.read_u8()?;
    if version != LUAC_VERSION_5_5 {
        return Err(Error::UnsupportedLuaVersion(version));
    }
    let format: u8 = c.read_u8()?;
    if format != 0x00 {
        return Err(Error::UnsupportedFormat(format));
    }
    let tail_off: usize = c.position();
    let tail: &[u8] = c.read_bytes(6)?;
    if tail != LUAC_DATA_TAIL {
        return Err(Error::BadLuacData(tail_off));
    }
    let size_int: u8 = read_int_check(&mut c, "int")?;
    let size_instr: u8 = c.read_u8()?;
    if usize::from(size_instr) != INSTRUCTION_BYTES {
        return Err(Error::HeaderSizeMismatch {
            what: "instruction",
            got: size_instr,
            expected: "4",
        });
    }
    if u64::from(c.read_u32()?) != LUAC_INST_5_5 {
        return Err(Error::HeaderCheckMismatch {
            what: "instruction",
        });
    }
    let size_lua_integer: u8 = read_int_check(&mut c, "Lua integer")?;
    let size_lua_number: u8 = c.read_u8()?;
    let number_check: f64 = match size_lua_number {
        8 => c.read_f64()?,
        4 => f64::from(f32::from_bits(c.read_u32()?)),
        other => return Err(Error::BadNumberSize(other)),
    };
    if number_check.to_bits() != LUAC_NUM_5_5.to_bits() {
        return Err(Error::FloatMismatch { got: number_check });
    }
    let main_upvalues: u8 = c.read_u8()?;
    let mut loader: Loader<'_> = Loader {
        cursor: c,
        saved: Vec::new(),
        materialized: 0,
        number_bytes: size_lua_number,
    };
    let main: LuaProto = loader.function(0)?;
    if main.upvalues.len() != usize::from(main_upvalues) {
        return Err(Error::MainUpvalueMismatch {
            header: main_upvalues,
            declared: main.upvalues.len(),
        });
    }
    Ok(LuaChunk {
        dialect: LuaDialect::Lua55,
        version_byte: LUAC_VERSION_5_5,
        format,
        little_endian: true,
        size_of_int: size_int,
        size_of_size_t: 0,
        size_of_instruction: size_instr,
        size_of_lua_integer: size_lua_integer,
        size_of_lua_number: size_lua_number,
        integral_number: false,
        main,
    })
}

fn read_int_check(c: &mut ByteCursor<'_>, what: &'static str) -> Result<u8> {
    let size: u8 = c.read_u8()?;
    let value: i64 = match size {
        4 => i64::from(i32::from_le_bytes(c.read_u32()?.to_le_bytes())),
        8 => i64::from_le_bytes(c.read_u64()?.to_le_bytes()),
        other => {
            return Err(Error::HeaderSizeMismatch {
                what,
                got: other,
                expected: "4 or 8",
            });
        }
    };
    if value != LUAC_INT_5_5 {
        return Err(Error::HeaderCheckMismatch { what });
    }
    Ok(size)
}

fn read_varint(c: &mut ByteCursor<'_>, limit: u64) -> Result<u64> {
    let offset: usize = c.position();
    let shifted_limit: u64 = limit >> 7;
    let mut value: u64 = 0;
    loop {
        let byte: u8 = c.read_u8()?;
        if value > shifted_limit {
            return Err(Error::VarintOverflow { offset, limit });
        }
        value = (value << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
}

const fn zigzag_integer(coded: u64) -> i64 {
    let magnitude: u64 = coded >> 1;
    let bits: u64 = if coded & 1 != 0 {
        !magnitude
    } else {
        magnitude
    };
    bits as i64
}

impl Loader<'_> {
    fn int(&mut self) -> Result<u64> {
        read_varint(&mut self.cursor, INT_VARINT_LIMIT)
    }

    fn count<T>(&mut self, section: &'static str, elem_bytes: usize) -> Result<usize> {
        let n: u64 = self.int()?;
        self.cursor.checked_count::<T>(section, n, elem_bytes)
    }

    fn align(&mut self, align: usize) -> Result<()> {
        let misalignment: usize = self.cursor.position() % align;
        if misalignment != 0 {
            let _: &[u8] = self.cursor.read_bytes(align - misalignment)?;
        }
        Ok(())
    }

    fn string(&mut self) -> Result<Option<String>> {
        let size: u64 = read_varint(&mut self.cursor, u64::MAX)?;
        if size == 0 {
            let offset: usize = self.cursor.position();
            let index: u64 = read_varint(&mut self.cursor, u64::MAX)?;
            if index == 0 {
                return Ok(None);
            }
            let Some(text): Option<&String> = usize::try_from(index - 1)
                .ok()
                .and_then(|slot: usize| self.saved.get(slot))
            else {
                return Err(Error::BadStringReference {
                    index,
                    offset,
                    saved: self.saved.len(),
                });
            };
            let text: String = text.clone();
            self.charge_string(text.len())?;
            return Ok(Some(text));
        }
        let len: usize = self.cursor.checked_len("lua55 string length", size)?;
        let raw: &[u8] = self.cursor.read_bytes(len)?;
        let body: &[u8] = raw.split_last().map_or(raw, |(_, body): (&u8, &[u8])| body);
        let text: String = String::from_utf8_lossy(body).into_owned();
        self.charge_string(text.len())?;
        self.saved.push(text.clone());
        Ok(Some(text))
    }

    fn charge_string(&mut self, len: usize) -> Result<()> {
        let total: usize = self.materialized.saturating_add(len);
        if total > MAX_MATERIALIZED_STRING_BYTES {
            return Err(Error::LimitExceeded {
                section: "lua55 materialized string bytes",
                count: u64::try_from(total).unwrap_or(u64::MAX),
                limit: MAX_MATERIALIZED_STRING_BYTES,
            });
        }
        self.materialized = total;
        Ok(())
    }

    fn function(&mut self, depth: usize) -> Result<LuaProto> {
        if depth > MAX_PROTO_DEPTH {
            return Err(Error::ProtoNestingTooDeep(depth));
        }
        let line_defined: u32 = capped_u32(self.int()?);
        let last_line_defined: u32 = capped_u32(self.int()?);
        let num_params: u8 = self.cursor.read_u8()?;
        let is_vararg: u8 = self.cursor.read_u8()? & !FIXED_MEMORY_FLAG;
        let max_stack_size: u8 = self.cursor.read_u8()?;

        let code_len: usize = self.count::<u32>("lua55 code", INSTRUCTION_BYTES)?;
        self.align(INSTRUCTION_BYTES)?;
        let mut code: Vec<u32> = Vec::with_capacity(code_len);
        for _ in 0..code_len {
            code.push(self.cursor.read_u32()?);
        }

        let const_count: usize = self.count::<LuaConstant>("lua55 constant", 1)?;
        let mut constants: Vec<LuaConstant> = Vec::with_capacity(const_count);
        for _ in 0..const_count {
            let tag_offset: usize = self.cursor.position();
            let tag: u8 = self.cursor.read_u8()?;
            let value: LuaConstant = match tag {
                0x00 => LuaConstant::Nil,
                0x01 => LuaConstant::Bool(false),
                0x11 => LuaConstant::Bool(true),
                0x03 => {
                    let coded: u64 = read_varint(&mut self.cursor, u64::MAX)?;
                    LuaConstant::Integer(zigzag_integer(coded))
                }
                0x13 => {
                    if self.number_bytes == 8 {
                        LuaConstant::Number(self.cursor.read_f64()?)
                    } else {
                        let raw: u32 = self.cursor.read_u32()?;
                        LuaConstant::Number(f64::from(f32::from_bits(raw)))
                    }
                }
                0x04 | 0x14 => match self.string()? {
                    Some(text) => LuaConstant::Str(text),
                    None => return Err(Error::NullConstantString(tag_offset)),
                },
                other => return Err(Error::BadConstantTag(other, tag_offset)),
            };
            constants.push(value);
        }

        let upval_count: usize = self.count::<LuaUpvalueName>("lua55 upvalue", 3)?;
        let mut upvalues: Vec<LuaUpvalueName> = Vec::with_capacity(upval_count);
        for _ in 0..upval_count {
            let in_stack: u8 = self.cursor.read_u8()?;
            let index: u8 = self.cursor.read_u8()?;
            let kind: u8 = self.cursor.read_u8()?;
            upvalues.push(LuaUpvalueName {
                name: String::new(),
                descriptor: Some(UpvalueDescriptor {
                    in_stack,
                    index,
                    kind,
                }),
            });
        }

        let proto_count: usize = self.count::<LuaProto>("lua55 proto", 1)?;
        let mut protos: Vec<LuaProto> = Vec::with_capacity(proto_count);
        for _ in 0..proto_count {
            protos.push(self.function(depth + 1)?);
        }

        let source: Option<String> = self.string()?;

        let line_info_count: usize = self.count::<u8>("lua55 line delta", 1)?;
        let _: &[u8] = self.cursor.read_bytes(line_info_count)?;
        let abs_line_count: usize = self.count::<u32>("lua55 absolute line", ABS_LINE_BYTES)?;
        let mut source_lines: Vec<u32> = Vec::with_capacity(abs_line_count);
        if abs_line_count > 0 {
            self.align(4)?;
            for _ in 0..abs_line_count {
                let _pc: u32 = self.cursor.read_u32()?;
                source_lines.push(self.cursor.read_u32()?);
            }
        }

        let local_count: usize = self.count::<LuaLocal>("lua55 local", 3)?;
        let mut locals: Vec<LuaLocal> = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            let name: String = self.string()?.unwrap_or_default();
            let start_pc: u32 = capped_u32(self.int()?);
            let end_pc: u32 = capped_u32(self.int()?);
            locals.push(LuaLocal {
                name,
                start_pc,
                end_pc,
            });
        }

        if self.int()? != 0 {
            for upvalue in &mut upvalues {
                upvalue.name = self.string()?.unwrap_or_default();
            }
        }

        Ok(LuaProto {
            source,
            line_defined,
            last_line_defined,
            num_params,
            is_vararg,
            max_stack_size,
            code,
            constants,
            protos,
            source_lines,
            locals,
            upvalues,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const RETURN0: u32 = 71;

    fn header(main_upvalues: u8) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0x1B, b'L', b'u', b'a', 0x55, 0x00];
        out.extend_from_slice(&LUAC_DATA_TAIL);
        out.push(4);
        out.extend_from_slice(&(-0x5678_i32).to_le_bytes());
        out.push(4);
        out.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
        out.push(8);
        out.extend_from_slice(&(-0x5678_i64).to_le_bytes());
        out.push(8);
        out.extend_from_slice(&(-370.5_f64).to_le_bytes());
        out.push(main_upvalues);
        out
    }

    fn pad_to_word(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn chunk_with(code_count: &[u8], constants: &[u8], source: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = header(1);
        out.extend_from_slice(&[0, 0, 0, 1, 2]);
        out.extend_from_slice(code_count);
        pad_to_word(&mut out);
        out.extend_from_slice(&RETURN0.to_le_bytes());
        out.extend_from_slice(constants);
        out.extend_from_slice(&[1, 1, 0, 0]);
        out.push(0);
        out.extend_from_slice(source);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }

    fn valid_chunk() -> Vec<u8> {
        chunk_with(
            &[1],
            &[3, 0x04, 3, b'a', b'b', 0, 0x04, 0, 1, 0x03, 0x82, 0x01],
            &[0, 0],
        )
    }

    #[test]
    fn a_minimal_chunk_reads_back_references_and_zigzag_integers() {
        let chunk: LuaChunk = read(&valid_chunk()).expect("the minimal 5.5 chunk reads");
        assert_eq!(chunk.dialect, LuaDialect::Lua55);
        assert_eq!(chunk.main.code, vec![RETURN0]);
        assert_eq!(
            chunk.main.constants,
            vec![
                LuaConstant::Str("ab".to_owned()),
                LuaConstant::Str("ab".to_owned()),
                LuaConstant::Integer(-129),
            ]
        );
        assert_eq!(chunk.main.source, None);
        assert_eq!(chunk.main.is_vararg, 1);
    }

    #[test]
    fn every_truncated_header_is_a_typed_error() {
        let full: Vec<u8> = valid_chunk();
        let header_len: usize = header(1).len();
        for len in 0..header_len {
            let result: Result<LuaChunk> = read(&full[..len]);
            assert!(
                matches!(result, Err(Error::Truncated { .. })),
                "a header cut to {len} bytes must read as truncated, got {result:?}"
            );
        }
        for len in header_len..full.len() {
            assert!(
                read(&full[..len]).is_err(),
                "a chunk cut to {len} bytes must be refused"
            );
        }
    }

    #[test]
    fn a_string_back_reference_past_the_saved_table_is_refused() {
        let bytes: Vec<u8> = chunk_with(&[1], &[1, 0x04, 0, 2], &[0, 0]);
        let result: Result<LuaChunk> = read(&bytes);
        assert!(
            matches!(
                result,
                Err(Error::BadStringReference {
                    index: 2,
                    saved: 0,
                    ..
                })
            ),
            "got {result:?}"
        );
        let past_one: Vec<u8> = chunk_with(&[1], &[1, 0x04, 2, b'x', 0], &[0, 2]);
        let result: Result<LuaChunk> = read(&past_one);
        assert!(
            matches!(
                result,
                Err(Error::BadStringReference {
                    index: 2,
                    saved: 1,
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn a_null_constant_string_is_refused() {
        let bytes: Vec<u8> = chunk_with(&[1], &[1, 0x04, 0, 0], &[0, 0]);
        assert!(matches!(read(&bytes), Err(Error::NullConstantString(_))));
    }

    #[test]
    fn an_oversized_count_is_refused_before_allocation() {
        let bytes: Vec<u8> = chunk_with(&[0x87, 0xFF, 0xFF, 0xFF, 0x7F], &[0], &[0, 0]);
        let result: Result<LuaChunk> = read(&bytes);
        assert!(
            matches!(
                result,
                Err(Error::LimitExceeded {
                    section: "lua55 code",
                    count: 0x7FFF_FFFF,
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn a_count_past_int_max_is_a_varint_overflow() {
        let bytes: Vec<u8> = chunk_with(&[0x88, 0x80, 0x80, 0x80, 0x00], &[0], &[0, 0]);
        let result: Result<LuaChunk> = read(&bytes);
        assert!(
            matches!(
                result,
                Err(Error::VarintOverflow {
                    limit: INT_VARINT_LIMIT,
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn repeated_back_references_stop_at_the_materialized_byte_budget() {
        let big: usize = 1 << 20;
        let copies: usize = MAX_MATERIALIZED_STRING_BYTES / big + 1;
        let mut constants: Vec<u8> = Vec::new();
        let mut count: Vec<u8> = Vec::new();
        let mut n: u64 = copies as u64 + 1;
        let mut groups: Vec<u8> = vec![(n & 0x7F) as u8];
        n >>= 7;
        while n != 0 {
            groups.push(((n & 0x7F) as u8) | 0x80);
            n >>= 7;
        }
        groups.reverse();
        count.extend_from_slice(&groups);
        constants.extend_from_slice(&count);
        constants.push(0x04);
        let size: u64 = big as u64 + 1;
        constants.extend_from_slice(&[
            0x80 | ((size >> 14) & 0x7F) as u8,
            0x80 | ((size >> 7) & 0x7F) as u8,
            (size & 0x7F) as u8,
        ]);
        constants.extend(std::iter::repeat_n(b'z', big));
        constants.push(0);
        for _ in 0..copies {
            constants.extend_from_slice(&[0x04, 0, 1]);
        }
        let bytes: Vec<u8> = chunk_with(&[1], &constants, &[0, 0]);
        let result: Result<LuaChunk> = read(&bytes);
        assert!(
            matches!(
                result,
                Err(Error::LimitExceeded {
                    section: "lua55 materialized string bytes",
                    ..
                })
            ),
            "got {:?}",
            result.map(|chunk: LuaChunk| chunk.main.constants.len())
        );
    }

    #[test]
    fn a_main_upvalue_count_that_disagrees_with_the_header_is_refused() {
        let mut bytes: Vec<u8> = valid_chunk();
        let at: usize = header(1).len() - 1;
        bytes[at] = 2;
        assert!(matches!(
            read(&bytes),
            Err(Error::MainUpvalueMismatch {
                header: 2,
                declared: 1
            })
        ));
    }

    #[test]
    fn header_check_values_are_verified() {
        let mut bytes: Vec<u8> = valid_chunk();
        bytes[13] ^= 0x01;
        assert!(matches!(
            read(&bytes),
            Err(Error::HeaderCheckMismatch { what: "int" })
        ));
        let mut bytes: Vec<u8> = valid_chunk();
        bytes[17] = 8;
        assert!(matches!(
            read(&bytes),
            Err(Error::HeaderSizeMismatch {
                what: "instruction",
                ..
            })
        ));
    }
}
