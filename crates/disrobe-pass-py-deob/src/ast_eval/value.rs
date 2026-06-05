use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    None,
    Bool(bool),
    Int(i128),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Self>),
    Tuple(Vec<Self>),
    Dict(BTreeMap<Key, Self>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Key {
    None,
    Bool(bool),
    Int(i128),
    Str(String),
    Bytes(Vec<u8>),
    Tuple(Vec<Self>),
}

impl Value {
    pub(crate) fn to_key(&self) -> Option<Key> {
        match self {
            Self::None => Some(Key::None),
            Self::Bool(b) => Some(Key::Bool(*b)),
            Self::Int(n) => Some(Key::Int(*n)),
            Self::Str(s) => Some(Key::Str(s.clone())),
            Self::Bytes(b) => Some(Key::Bytes(b.clone())),
            Self::Tuple(items) => {
                let mut keys: Vec<Key> = Vec::with_capacity(items.len());
                for v in items {
                    keys.push(v.to_key()?);
                }
                Some(Key::Tuple(keys))
            }
            Self::List(_) | Self::Dict(_) => None,
        }
    }

    pub(crate) fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Str(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::List(items) | Self::Tuple(items) => !items.is_empty(),
            Self::Dict(m) => !m.is_empty(),
        }
    }

    pub(crate) fn iter_items(&self) -> Option<Vec<Self>> {
        match self {
            Self::Str(s) => Some(s.chars().map(|c: char| Self::Str(c.to_string())).collect()),
            Self::Bytes(b) => Some(b.iter().map(|x: &u8| Self::Int(i128::from(*x))).collect()),
            Self::List(items) | Self::Tuple(items) => Some(items.clone()),
            Self::Dict(m) => Some(
                m.keys()
                    .map(|k: &Key| Self::from_key(k.clone()))
                    .collect::<Vec<Self>>(),
            ),
            _ => None,
        }
    }

    pub(crate) fn from_key(k: Key) -> Self {
        match k {
            Key::None => Self::None,
            Key::Bool(b) => Self::Bool(b),
            Key::Int(n) => Self::Int(n),
            Key::Str(s) => Self::Str(s),
            Key::Bytes(b) => Self::Bytes(b),
            Key::Tuple(items) => Self::Tuple(items.into_iter().map(Self::from_key).collect()),
        }
    }

    pub(crate) fn len(&self) -> Option<i128> {
        match self {
            Self::Str(s) => i128::try_from(s.chars().count()).ok(),
            Self::Bytes(b) => i128::try_from(b.len()).ok(),
            Self::List(items) | Self::Tuple(items) => i128::try_from(items.len()).ok(),
            Self::Dict(m) => i128::try_from(m.len()).ok(),
            _ => None,
        }
    }
}
