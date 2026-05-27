use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    Complex { real: f64, imag: f64 },
    Bytes(Vec<u8>),
    String { value: String, interned: bool },
    ShortAscii { value: String, interned: bool },
    Tuple(Vec<Self>),
    List(Vec<Self>),
    Dict(IndexMap<Self, Self>),
    Set(Vec<Self>),
    FrozenSet(Vec<Self>),
    FrozenDict(IndexMap<Self, Self>),
    Code(Box<CodeObject>),
    Ref(u32),
    Null,
}

impl core::hash::Hash for Object {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::None => 0u8.hash(state),
            Self::False => 1u8.hash(state),
            Self::True => 2u8.hash(state),
            Self::Int(i) => {
                3u8.hash(state);
                i.hash(state);
            }
            Self::Int64(i) => {
                4u8.hash(state);
                i.hash(state);
            }
            Self::String { value, .. } | Self::ShortAscii { value, .. } => {
                5u8.hash(state);
                value.hash(state);
            }
            Self::Bytes(b) => {
                6u8.hash(state);
                b.hash(state);
            }
            Self::Float(f) => {
                7u8.hash(state);
                f.to_bits().hash(state);
            }
            Self::Tuple(t) => {
                8u8.hash(state);
                t.hash(state);
            }
            _ => 0xffu8.hash(state),
        }
    }
}

impl Eq for Object {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeEra {
    Py27,
    Py30to37,
    Py38to310,
    Py311Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        (2, _) => CodeEra::Py27,
        (3, 0..=7) => CodeEra::Py30to37,
        (3, 8..=10) => CodeEra::Py38to310,
        _ => CodeEra::Py311Plus,
    }
}
