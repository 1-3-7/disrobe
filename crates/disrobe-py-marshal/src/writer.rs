use crate::error::{Error, Result};
use crate::object::{BigInt, CodeEra, CodeObject, Object};
use crate::version::PyVersion;

fn len_as_u32(actual: usize) -> Result<u32> {
    u32::try_from(actual).map_err(|_| Error::WriterLengthOverflow {
        actual,
        max: u32::MAX,
    })
}

fn len_as_u8(actual: usize) -> Result<u8> {
    u8::try_from(actual).map_err(|_| Error::WriterShortLengthOverflow {
        actual,
        max: u8::MAX,
    })
}

pub fn dump(obj: &Object, _version: PyVersion) -> Result<Vec<u8>> {
    let mut w: Writer = Writer {
        out: Vec::with_capacity(256),
    };
    w.write_object(obj)?;
    Ok(w.out)
}

struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn push_tag(&mut self, tag: u8) {
        self.out.push(tag);
    }

    fn push_i16(&mut self, era: CodeEra, field: &'static str, v: i32) -> Result<()> {
        let narrowed: i16 = i16::try_from(v).map_err(|_| Error::CodeFieldWidth {
            era,
            field,
            value: v,
        })?;
        self.out.extend_from_slice(&narrowed.to_le_bytes());
        Ok(())
    }

    fn push_i32(&mut self, v: i32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_i64(&mut self, v: i64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_f64(&mut self, v: f64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    #[allow(clippy::too_many_lines)]
    fn write_object(&mut self, obj: &Object) -> Result<()> {
        match obj {
            Object::None => self.push_tag(b'N'),
            Object::StopIteration => self.push_tag(b'S'),
            Object::Ellipsis => self.push_tag(b'.'),
            Object::False => self.push_tag(b'F'),
            Object::True => self.push_tag(b'T'),
            Object::Null => self.push_tag(b'0'),

            Object::Int(n) => {
                self.push_tag(b'i');
                self.push_i32(*n);
            }
            Object::Int64(n) => {
                self.push_tag(b'I');
                self.push_i64(*n);
            }
            Object::Float(f) => {
                self.push_tag(b'g');
                self.push_f64(*f);
            }
            Object::Complex { real, imag } => {
                self.push_tag(b'y');
                self.push_f64(*real);
                self.push_f64(*imag);
            }
            Object::Long(big) => {
                self.push_tag(b'l');
                self.write_long(big)?;
            }

            Object::Bytes(b) => {
                self.push_tag(b's');
                self.push_u32(len_as_u32(b.len())?);
                self.out.extend_from_slice(b);
            }
            Object::String { value, interned } => {
                let tag: u8 = if *interned { b'A' } else { b'a' };
                self.push_tag(tag);
                self.push_u32(len_as_u32(value.len())?);
                self.out.extend_from_slice(value.as_bytes());
            }
            Object::Unicode { value, .. } => {
                self.push_tag(b'u');
                self.push_u32(len_as_u32(value.len())?);
                self.out.extend_from_slice(value.as_bytes());
            }
            Object::ShortAscii { value, interned } => {
                if value.len() > 0xFF {
                    let tag: u8 = if *interned { b'A' } else { b'a' };
                    self.push_tag(tag);
                    self.push_u32(len_as_u32(value.len())?);
                } else {
                    let tag: u8 = if *interned { b'Z' } else { b'z' };
                    self.push_tag(tag);
                    let len_u8: u8 = len_as_u8(value.len())?;
                    self.out.push(len_u8);
                }
                self.out.extend_from_slice(value.as_bytes());
            }

            Object::Tuple(items) => {
                self.write_tuple_items(items)?;
            }
            Object::List(items) => {
                self.push_tag(b'[');
                self.push_u32(len_as_u32(items.len())?);
                for it in items {
                    self.write_object(it)?;
                }
            }
            Object::Set(items) => {
                self.push_tag(b'<');
                self.push_u32(len_as_u32(items.len())?);
                for it in items {
                    self.write_object(it)?;
                }
            }
            Object::FrozenSet(items) => {
                self.push_tag(b'>');
                self.push_u32(len_as_u32(items.len())?);
                for it in items {
                    self.write_object(it)?;
                }
            }
            Object::Dict(d) => {
                self.push_tag(b'{');
                for (k, v) in d {
                    self.write_object(k)?;
                    self.write_object(v)?;
                }
                self.push_tag(b'0');
            }
            Object::FrozenDict(d) => {
                self.push_tag(b'}');
                for (k, v) in d {
                    self.write_object(k)?;
                    self.write_object(v)?;
                }
                self.push_tag(b'0');
            }

            Object::Code(co) => {
                self.push_tag(b'c');
                self.write_code_object(co)?;
            }

            Object::Slice { lower, upper, step } => {
                self.push_tag(b':');
                self.write_object(lower)?;
                self.write_object(upper)?;
                self.write_object(step)?;
            }

            Object::Ref(idx) => {
                self.push_tag(b'r');
                self.push_u32(*idx);
            }
        }
        Ok(())
    }

    fn write_long(&mut self, big: &BigInt) -> Result<()> {
        let digit_count: i32 =
            i32::try_from(big.digits.len()).map_err(|_| Error::WriterLengthOverflow {
                actual: big.digits.len(),
                max: i32::MAX as u32,
            })?;
        let signed_count: i32 = match big.sign.cmp(&0) {
            core::cmp::Ordering::Less => -digit_count,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => digit_count,
        };
        self.push_i32(signed_count);
        for digit in &big.digits {
            self.out.extend_from_slice(&digit.to_le_bytes());
        }
        Ok(())
    }

    fn write_code_object(&mut self, co: &CodeObject) -> Result<()> {
        match co.era {
            CodeEra::Py10to12 => {
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
            }
            CodeEra::Py13to14 => {
                self.push_i16(co.era, "argcount", co.argcount)?;
                self.push_i16(co.era, "nlocals", co.nlocals)?;
                self.push_i16(co.era, "flags", co.flags)?;
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_tuple_items(&co.varnames)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
            }
            CodeEra::Py15to20 => {
                self.push_i16(co.era, "argcount", co.argcount)?;
                self.push_i16(co.era, "nlocals", co.nlocals)?;
                self.push_i16(co.era, "stacksize", co.stacksize)?;
                self.push_i16(co.era, "flags", co.flags)?;
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_tuple_items(&co.varnames)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
                self.push_i16(co.era, "firstlineno", co.firstlineno)?;
                self.write_bytes_field(&co.lnotab)?;
            }
            CodeEra::Py21to22 => {
                self.push_i16(co.era, "argcount", co.argcount)?;
                self.push_i16(co.era, "nlocals", co.nlocals)?;
                self.push_i16(co.era, "stacksize", co.stacksize)?;
                self.push_i16(co.era, "flags", co.flags)?;
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_tuple_items(&co.varnames)?;
                self.write_tuple_items(&co.freevars)?;
                self.write_tuple_items(&co.cellvars)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
                self.push_i16(co.era, "firstlineno", co.firstlineno)?;
                self.write_bytes_field(&co.lnotab)?;
            }
            CodeEra::Py27 => {
                self.push_i32(co.argcount);
                self.push_i32(co.nlocals);
                self.push_i32(co.stacksize);
                self.push_i32(co.flags);
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_tuple_items(&co.varnames)?;
                self.write_tuple_items(&co.freevars)?;
                self.write_tuple_items(&co.cellvars)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
                self.push_i32(co.firstlineno);
                self.write_bytes_field(&co.lnotab)?;
            }
            CodeEra::Py30to37 => {
                self.push_i32(co.argcount);
                self.push_i32(co.kwonlyargcount);
                self.push_i32(co.nlocals);
                self.push_i32(co.stacksize);
                self.push_i32(co.flags);
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_tuple_items(&co.varnames)?;
                self.write_tuple_items(&co.freevars)?;
                self.write_tuple_items(&co.cellvars)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
                self.push_i32(co.firstlineno);
                self.write_bytes_field(&co.lnotab)?;
            }
            CodeEra::Py38to310 => {
                self.push_i32(co.argcount);
                self.push_i32(co.posonlyargcount);
                self.push_i32(co.kwonlyargcount);
                self.push_i32(co.nlocals);
                self.push_i32(co.stacksize);
                self.push_i32(co.flags);
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_tuple_items(&co.varnames)?;
                self.write_tuple_items(&co.freevars)?;
                self.write_tuple_items(&co.cellvars)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
                self.push_i32(co.firstlineno);
                self.write_bytes_field(&co.lnotab)?;
            }
            CodeEra::Py311Plus => {
                self.push_i32(co.argcount);
                self.push_i32(co.posonlyargcount);
                self.push_i32(co.kwonlyargcount);
                self.push_i32(co.stacksize);
                self.push_i32(co.flags);
                self.write_bytes_field(&co.code)?;
                self.write_tuple_items(&co.consts)?;
                self.write_tuple_items(&co.names)?;
                self.write_tuple_items(&co.localsplusnames)?;
                self.write_bytes_field(&co.localspluskinds)?;
                self.write_object(&co.filename)?;
                self.write_object(&co.name)?;
                self.write_object(&co.qualname)?;
                self.push_i32(co.firstlineno);
                self.write_bytes_field(&co.linetable)?;
                self.write_bytes_field(&co.exceptiontable)?;
            }
        }
        Ok(())
    }

    fn write_tuple_items(&mut self, items: &[Object]) -> Result<()> {
        if let Ok(len_u8) = u8::try_from(items.len()) {
            self.push_tag(b')');
            self.out.push(len_u8);
        } else {
            self.push_tag(b'(');
            self.push_u32(len_as_u32(items.len())?);
        }
        for item in items {
            self.write_object(item)?;
        }
        Ok(())
    }

    fn write_bytes_field(&mut self, bytes: &[u8]) -> Result<()> {
        self.push_tag(b's');
        self.push_u32(len_as_u32(bytes.len())?);
        self.out.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn write_none() {
        assert_eq!(dump(&Object::None, PyVersion::PY312).unwrap(), b"N");
    }

    #[test]
    fn round_trip_int() {
        let bytes: Vec<u8> = dump(&Object::Int(42), PyVersion::PY312).unwrap();
        let back: Object = crate::reader::load(&bytes, PyVersion::PY312).unwrap();
        assert_eq!(back, Object::Int(42));
    }

    #[test]
    fn round_trip_small_tuple() {
        let original: Object = Object::Tuple(vec![Object::Int(1), Object::Int(2), Object::Int(3)]);
        let bytes: Vec<u8> = dump(&original, PyVersion::PY312).unwrap();
        let back: Object = crate::reader::load(&bytes, PyVersion::PY312).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn round_trip_string() {
        let original: Object = Object::ShortAscii {
            value: "hello".to_owned(),
            interned: false,
        };
        let bytes: Vec<u8> = dump(&original, PyVersion::PY312).unwrap();
        let back: Object = crate::reader::load(&bytes, PyVersion::PY312).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn len_as_u32_overflows_when_above_u32_max() {
        let actual: usize = (u32::MAX as usize).saturating_add(1);
        let err: Error = len_as_u32(actual).expect_err("must overflow");
        assert!(matches!(
            err,
            Error::WriterLengthOverflow { actual: a, max } if a == actual && max == u32::MAX
        ));
    }

    #[test]
    fn len_as_u32_passes_through_under_u32_max() {
        assert_eq!(len_as_u32(0).unwrap(), 0);
        assert_eq!(len_as_u32(u32::MAX as usize).unwrap(), u32::MAX);
    }

    #[test]
    fn len_as_u8_overflows_when_above_u8_max() {
        let actual: usize = usize::from(u8::MAX) + 1;
        let err: Error = len_as_u8(actual).expect_err("must overflow");
        assert!(matches!(
            err,
            Error::WriterShortLengthOverflow { actual: a, max } if a == actual && max == u8::MAX
        ));
    }

    #[test]
    fn short_ascii_uses_short_length_at_u8_max() {
        let value: String = "a".repeat(usize::from(u8::MAX));
        let obj: Object = Object::ShortAscii {
            value,
            interned: false,
        };
        let bytes: Vec<u8> = dump(&obj, PyVersion::PY312).unwrap();
        assert_eq!(bytes[0], b'z');
        assert_eq!(bytes[1], u8::MAX);
    }

    #[test]
    fn short_ascii_uses_long_length_above_u8_max() {
        let value: String = "a".repeat(usize::from(u8::MAX) + 1);
        let obj: Object = Object::ShortAscii {
            value,
            interned: false,
        };
        let bytes: Vec<u8> = dump(&obj, PyVersion::PY312).unwrap();
        assert_eq!(bytes[0], b'a');
        assert_eq!(&bytes[1..5], &256u32.to_le_bytes());
    }

    #[test]
    fn write_long_normal_path_round_trips() {
        let big: BigInt = BigInt {
            sign: -1,
            digits: vec![1u16, 2, 3],
        };
        let mut w: Writer = Writer {
            out: Vec::with_capacity(16),
        };
        w.write_long(&big).expect("write_long should succeed");
        assert_eq!(&w.out[..4], (-3i32).to_le_bytes().as_slice());
    }

    #[test]
    fn legacy_i16_field_overflow_is_structured_error() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py15to20);
        co.argcount = 70_000;
        let err: Error =
            dump(&Object::Code(Box::new(co)), PyVersion::PY15).expect_err("must overflow");
        assert!(
            matches!(
                err,
                Error::CodeFieldWidth {
                    era: CodeEra::Py15to20,
                    field: "argcount",
                    value: 70_000,
                }
            ),
            "expected CodeFieldWidth, got {err:?}"
        );
    }

    #[test]
    fn legacy_i16_negative_overflow_is_structured_error() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py13to14);
        co.flags = -40_000;
        let err: Error =
            dump(&Object::Code(Box::new(co)), PyVersion::PY13).expect_err("must overflow");
        assert!(matches!(
            err,
            Error::CodeFieldWidth {
                field: "flags",
                value: -40_000,
                ..
            }
        ));
    }

    #[test]
    fn legacy_i16_field_in_range_writes_two_bytes() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py15to20);
        co.argcount = -1;
        co.stacksize = 12345;
        let bytes: Vec<u8> =
            dump(&Object::Code(Box::new(co)), PyVersion::PY15).expect("in-range must succeed");
        assert_eq!(&bytes[1..3], (-1i16).to_le_bytes().as_slice());
        assert_eq!(&bytes[5..7], 12345i16.to_le_bytes().as_slice());
    }
}
