use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::object::Object;
use crate::version::PyVersion;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundTripReport {
    pub encoded_len: usize,
    pub reencoded_len: usize,
    pub object_matches: bool,
    pub bytes_match: bool,
    pub first_diff_offset: Option<usize>,
}

impl RoundTripReport {
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.object_matches && self.bytes_match
    }
}

pub fn validate_roundtrip(obj: &Object, version: PyVersion) -> Result<RoundTripReport> {
    let encoded: Vec<u8> = crate::writer::dump(obj, version)?;
    let decoded: Object = crate::reader::load(&encoded, version)?;
    let reencoded: Vec<u8> = crate::writer::dump(&decoded, version)?;
    let object_matches: bool = objects_semantically_equal(obj, &decoded);
    let first_diff: Option<usize> = first_diff_offset(&encoded, &reencoded);
    Ok(RoundTripReport {
        encoded_len: encoded.len(),
        reencoded_len: reencoded.len(),
        object_matches,
        bytes_match: first_diff.is_none() && encoded.len() == reencoded.len(),
        first_diff_offset: first_diff,
    })
}

pub fn validate_roundtrip_strict(obj: &Object, version: PyVersion) -> Result<Vec<u8>> {
    let report: RoundTripReport = validate_roundtrip(obj, version)?;
    if !report.object_matches {
        return Err(crate::error::Error::UnsupportedPyVersion(version));
    }
    crate::writer::dump(obj, version)
}

fn first_diff_offset(a: &[u8], b: &[u8]) -> Option<usize> {
    let limit: usize = a.len().min(b.len());
    for i in 0..limit {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() == b.len() {
        None
    } else {
        Some(limit)
    }
}

fn objects_semantically_equal(a: &Object, b: &Object) -> bool {
    match (a, b) {
        (Object::None, Object::None)
        | (Object::True, Object::True)
        | (Object::False, Object::False)
        | (Object::StopIteration, Object::StopIteration)
        | (Object::Ellipsis, Object::Ellipsis)
        | (Object::Null, Object::Null) => true,
        (Object::Int(x), Object::Int(y)) => x == y,
        (Object::Int64(x), Object::Int64(y)) => x == y,
        (Object::Long(x), Object::Long(y)) => x == y,
        (Object::Float(x), Object::Float(y)) => {
            x.to_bits() == y.to_bits() || (x.is_nan() && y.is_nan())
        }
        (Object::Complex { real: r1, imag: i1 }, Object::Complex { real: r2, imag: i2 }) => {
            r1.to_bits() == r2.to_bits() && i1.to_bits() == i2.to_bits()
        }
        (Object::Bytes(x), Object::Bytes(y)) => x == y,
        (Object::String { .. }, Object::String { .. })
        | (Object::Unicode { .. }, Object::Unicode { .. })
        | (Object::ShortAscii { .. }, Object::ShortAscii { .. }) => {
            string_with_interned(a) == string_with_interned(b)
        }
        (Object::Tuple(x), Object::Tuple(y))
        | (Object::List(x), Object::List(y))
        | (Object::Set(x), Object::Set(y))
        | (Object::FrozenSet(x), Object::FrozenSet(y)) => sequences_equal(x, y),
        (Object::Dict(x), Object::Dict(y)) | (Object::FrozenDict(x), Object::FrozenDict(y)) => {
            if x.len() != y.len() {
                return false;
            }
            x.iter().zip(y.iter()).all(|((k1, v1), (k2, v2))| {
                objects_semantically_equal(k1, k2) && objects_semantically_equal(v1, v2)
            })
        }
        (Object::Code(a), Object::Code(b)) => a == b,
        (Object::Ref(a), Object::Ref(b)) => a == b,
        (Object::String { value: v1, .. }, Object::ShortAscii { value: v2, .. })
        | (Object::ShortAscii { value: v1, .. }, Object::String { value: v2, .. }) => v1 == v2,
        _ => false,
    }
}

const fn string_with_interned(obj: &Object) -> Option<(&str, bool)> {
    match obj {
        Object::String { value, interned }
        | Object::Unicode { value, interned }
        | Object::ShortAscii { value, interned } => Some((value.as_str(), *interned)),
        _ => None,
    }
}

fn sequences_equal(a: &[Object], b: &[Object]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| objects_semantically_equal(x, y))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::object::{BigInt, CodeEra, CodeObject};

    #[test]
    fn validates_primitive_roundtrip() {
        let report: RoundTripReport =
            validate_roundtrip(&Object::Int(42), PyVersion::PY312).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.encoded_len, 5);
    }

    #[test]
    fn validates_nested_tuple_roundtrip() {
        let obj: Object = Object::Tuple(vec![
            Object::Int(1),
            Object::ShortAscii {
                value: "x".to_owned(),
                interned: false,
            },
            Object::Tuple(vec![Object::None, Object::True]),
        ]);
        let report: RoundTripReport = validate_roundtrip(&obj, PyVersion::PY312).unwrap();
        assert!(report.is_clean());
        assert!(report.first_diff_offset.is_none());
    }

    #[test]
    fn validates_long_int() {
        let big: Object = Object::Long(BigInt {
            sign: 1,
            digits: vec![0x1234, 0x5678],
        });
        let report: RoundTripReport = validate_roundtrip(&big, PyVersion::PY312).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn validates_negative_long_int() {
        let big: Object = Object::Long(BigInt {
            sign: -1,
            digits: vec![0xABCD],
        });
        let report: RoundTripReport = validate_roundtrip(&big, PyVersion::PY312).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn validates_complex_number() {
        let c: Object = Object::Complex {
            real: 1.5,
            imag: -2.25,
        };
        let report: RoundTripReport = validate_roundtrip(&c, PyVersion::PY312).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn detects_byte_length_for_short_ascii() {
        let s: Object = Object::ShortAscii {
            value: "hello".to_owned(),
            interned: false,
        };
        let report: RoundTripReport = validate_roundtrip(&s, PyVersion::PY312).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.encoded_len, 7);
    }

    #[test]
    fn validates_code_object_minimal() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.filename = Object::ShortAscii {
            value: "f.py".to_owned(),
            interned: false,
        };
        co.name = Object::ShortAscii {
            value: "<module>".to_owned(),
            interned: true,
        };
        co.qualname = co.name.clone();
        let report: RoundTripReport =
            validate_roundtrip(&Object::Code(Box::new(co)), PyVersion::PY312).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn strict_mode_returns_bytes_when_clean() {
        let bytes: Vec<u8> = validate_roundtrip_strict(&Object::Int(7), PyVersion::PY312).unwrap();
        assert_eq!(bytes, b"i\x07\x00\x00\x00");
    }
}
