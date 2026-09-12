use core::hash::{Hash, Hasher};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Object {
    None,
    StopIteration,
    Ellipsis,
    False,
    True,
    Int(i32),
    Int64(i64),
    Long(BigInt),
    Float(f64),
    Complex {
        real: f64,
        imag: f64,
    },
    Bytes(Vec<u8>),
    String {
        value: String,
        interned: bool,
    },
    Unicode {
        value: String,
        interned: bool,
    },
    ShortAscii {
        value: String,
        interned: bool,
    },
    Tuple(Vec<Self>),
    List(Vec<Self>),
    Dict(IndexMap<Self, Self>),
    Set(Vec<Self>),
    FrozenSet(Vec<Self>),
    FrozenDict(IndexMap<Self, Self>),
    Code(Box<CodeObject>),
    Slice {
        lower: Box<Self>,
        upper: Box<Self>,
        step: Box<Self>,
    },
    Ref(u32),
    Null,
}

impl Hash for Object {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::None => 0u8.hash(state),
            Self::StopIteration => 1u8.hash(state),
            Self::Ellipsis => 2u8.hash(state),
            Self::False => 3u8.hash(state),
            Self::True => 4u8.hash(state),
            Self::Int(i) => {
                5u8.hash(state);
                i.hash(state);
            }
            Self::Int64(i) => {
                6u8.hash(state);
                i.hash(state);
            }
            Self::Long(big) => {
                7u8.hash(state);
                big.hash(state);
            }
            Self::Float(f) => {
                8u8.hash(state);
                f.to_bits().hash(state);
            }
            Self::Complex { real, imag } => {
                9u8.hash(state);
                real.to_bits().hash(state);
                imag.to_bits().hash(state);
            }
            Self::Bytes(b) => {
                10u8.hash(state);
                b.hash(state);
            }
            Self::String { value, interned } => {
                11u8.hash(state);
                value.hash(state);
                interned.hash(state);
            }
            Self::Unicode { value, interned } => {
                12u8.hash(state);
                value.hash(state);
                interned.hash(state);
            }
            Self::ShortAscii { value, interned } => {
                13u8.hash(state);
                value.hash(state);
                interned.hash(state);
            }
            Self::Tuple(t) => {
                14u8.hash(state);
                t.hash(state);
            }
            Self::List(items) => {
                15u8.hash(state);
                items.hash(state);
            }
            Self::Dict(map) => {
                16u8.hash(state);
                hash_unordered_map(map, state);
            }
            Self::Set(items) => {
                17u8.hash(state);
                items.hash(state);
            }
            Self::FrozenSet(items) => {
                18u8.hash(state);
                items.hash(state);
            }
            Self::FrozenDict(map) => {
                19u8.hash(state);
                hash_unordered_map(map, state);
            }
            Self::Code(co) => {
                20u8.hash(state);
                co.hash(state);
            }
            Self::Slice { lower, upper, step } => {
                21u8.hash(state);
                lower.hash(state);
                upper.hash(state);
                step.hash(state);
            }
            Self::Ref(r) => {
                22u8.hash(state);
                r.hash(state);
            }
            Self::Null => 23u8.hash(state),
        }
    }
}

fn hash_unordered_map<H: Hasher>(map: &IndexMap<Object, Object>, state: &mut H) {
    let mut sum: u64 = 0;
    let mut xor: u64 = 0;
    for (key, value) in map {
        let mut entry_hasher: std::collections::hash_map::DefaultHasher =
            std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut entry_hasher);
        value.hash(&mut entry_hasher);
        let entry_hash: u64 = core::hash::Hasher::finish(&entry_hasher);
        sum = sum.wrapping_add(entry_hash);
        xor ^= entry_hash.rotate_left(17);
    }
    map.len().hash(state);
    sum.hash(state);
    xor.hash(state);
}

impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None)
            | (Self::StopIteration, Self::StopIteration)
            | (Self::Ellipsis, Self::Ellipsis)
            | (Self::False, Self::False)
            | (Self::True, Self::True)
            | (Self::Null, Self::Null) => true,
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::Int64(a), Self::Int64(b)) => a == b,
            (Self::Long(a), Self::Long(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a.to_bits() == b.to_bits(),
            (Self::Complex { real: ar, imag: ai }, Self::Complex { real: br, imag: bi }) => {
                ar.to_bits() == br.to_bits() && ai.to_bits() == bi.to_bits()
            }
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (
                Self::String {
                    value: av,
                    interned: ai,
                },
                Self::String {
                    value: bv,
                    interned: bi,
                },
            )
            | (
                Self::Unicode {
                    value: av,
                    interned: ai,
                },
                Self::Unicode {
                    value: bv,
                    interned: bi,
                },
            )
            | (
                Self::ShortAscii {
                    value: av,
                    interned: ai,
                },
                Self::ShortAscii {
                    value: bv,
                    interned: bi,
                },
            ) => av == bv && ai == bi,
            (Self::Tuple(a), Self::Tuple(b))
            | (Self::List(a), Self::List(b))
            | (Self::Set(a), Self::Set(b))
            | (Self::FrozenSet(a), Self::FrozenSet(b)) => a == b,
            (Self::Dict(a), Self::Dict(b)) | (Self::FrozenDict(a), Self::FrozenDict(b)) => a == b,
            (Self::Code(a), Self::Code(b)) => a == b,
            (
                Self::Slice {
                    lower: al,
                    upper: au,
                    step: as_,
                },
                Self::Slice {
                    lower: bl,
                    upper: bu,
                    step: bs,
                },
            ) => al == bl && au == bu && as_ == bs,
            (Self::Ref(a), Self::Ref(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Object {}

#[derive(Debug, Clone, PartialEq, Eq, core::hash::Hash, Serialize, Deserialize)]
pub struct BigInt {
    pub sign: i8,
    pub digits: Vec<u16>,
}

impl BigInt {
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sign: 0,
            digits: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, core::hash::Hash, Serialize, Deserialize)]
pub enum CodeEra {
    Py10to12,
    Py13to14,
    Py15to20,
    Py21to22,
    Py27,
    Py30to37,
    Py38to310,
    Py311Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, core::hash::Hash, Serialize, Deserialize)]
pub enum LocalKind {
    Local,
    Cell,
    Free,
}

impl LocalKind {
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Local => 0x20,
            Self::Cell => 0x40,
            Self::Free => 0x80,
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b & 0xE0 {
            0x20 => Some(Self::Local),
            0x40 => Some(Self::Cell),
            0x80 => Some(Self::Free),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, core::hash::Hash, Serialize, Deserialize)]
pub struct CodeObject {
    pub era: CodeEra,

    pub argcount: i32,
    pub posonlyargcount: i32,
    pub kwonlyargcount: i32,
    pub nlocals: i32,
    pub stacksize: i32,
    pub flags: i32,

    pub code: Vec<u8>,
    pub consts: Vec<Object>,
    pub names: Vec<Object>,

    pub varnames: Vec<Object>,
    pub freevars: Vec<Object>,
    pub cellvars: Vec<Object>,

    pub localsplusnames: Vec<Object>,
    pub localspluskinds: Vec<u8>,

    pub filename: Object,
    pub name: Object,
    pub qualname: Object,

    pub firstlineno: i32,
    pub lnotab: Vec<u8>,
    pub linetable: Vec<u8>,
    pub exceptiontable: Vec<u8>,

    pub pyarmor_trailer: Vec<u8>,
}

impl CodeObject {
    #[must_use]
    pub const fn new(era: CodeEra) -> Self {
        Self {
            era,
            argcount: 0,
            posonlyargcount: 0,
            kwonlyargcount: 0,
            nlocals: 0,
            stacksize: 0,
            flags: 0,
            code: Vec::new(),
            consts: Vec::new(),
            names: Vec::new(),
            varnames: Vec::new(),
            freevars: Vec::new(),
            cellvars: Vec::new(),
            localsplusnames: Vec::new(),
            localspluskinds: Vec::new(),
            filename: Object::None,
            name: Object::None,
            qualname: Object::None,
            firstlineno: 0,
            lnotab: Vec::new(),
            linetable: Vec::new(),
            exceptiontable: Vec::new(),
            pyarmor_trailer: Vec::new(),
        }
    }
}

#[must_use]
pub const fn code_era_for(version: super::PyVersion) -> CodeEra {
    match (version.major, version.minor) {
        (1, 0..=2) => CodeEra::Py10to12,
        (1, 3..=4) => CodeEra::Py13to14,
        (1, 5..=6) | (2, 0) => CodeEra::Py15to20,
        (2, 1..=2) => CodeEra::Py21to22,
        (2, _) => CodeEra::Py27,
        (3, 0..=7) => CodeEra::Py30to37,
        (3, 8..=10) => CodeEra::Py38to310,
        _ => CodeEra::Py311Plus,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of(obj: &Object) -> u64 {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        obj.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn nan_float_is_reflexively_equal() {
        let nan: Object = Object::Float(f64::NAN);
        assert_eq!(nan, nan);
        assert_eq!(Object::Float(f64::NAN), Object::Float(f64::NAN));
    }

    #[test]
    fn nan_eq_is_hash_consistent() {
        let a: Object = Object::Float(f64::NAN);
        let b: Object = Object::Float(f64::NAN);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn distinct_nan_bit_patterns_are_unequal() {
        let quiet: Object = Object::Float(f64::from_bits(0x7ff8_0000_0000_0001));
        let other: Object = Object::Float(f64::from_bits(0x7ff8_0000_0000_0002));
        assert_ne!(quiet, other);
    }

    #[test]
    fn positive_and_negative_zero_are_distinct() {
        assert_ne!(Object::Float(0.0), Object::Float(-0.0));
        assert_eq!(Object::Float(0.0), Object::Float(0.0));
    }

    #[test]
    fn finite_floats_compare_by_value() {
        assert_eq!(Object::Float(1.5), Object::Float(1.5));
        assert_ne!(Object::Float(1.5), Object::Float(2.5));
    }

    #[test]
    fn nan_complex_components_are_reflexive() {
        let c: Object = Object::Complex {
            real: f64::NAN,
            imag: 1.0,
        };
        assert_eq!(c, c);
    }
}
