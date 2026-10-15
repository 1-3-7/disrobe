use std::collections::BTreeMap;

use serde::Serialize;

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Metadata {
    pub section: &'static str,
    pub offset: usize,
    pub length: usize,
    pub compiler: Option<Compiler>,
    pub ipfs: Option<String>,
    pub bzzr0: Option<String>,
    pub bzzr1: Option<String>,
    pub experimental: bool,
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Compiler {
    pub name: &'static str,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Uint(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    Bool(bool),
    Null,
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    items: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte: u8 = *self.data.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn take(&mut self, len: usize) -> Option<&[u8]> {
        let end: usize = self.at.checked_add(len)?;
        let slice: &[u8] = self.data.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn argument(&mut self, info: u8) -> Option<u64> {
        match info {
            0..=23 => Some(u64::from(info)),
            24 => self.byte().map(u64::from),
            25 => self
                .take(2)
                .map(|b: &[u8]| u64::from(u16::from_be_bytes([b[0], b[1]]))),
            26 => self
                .take(4)
                .map(|b: &[u8]| u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))),
            27 => self.take(8).map(|b: &[u8]| {
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }),
            _ => None,
        }
    }

    fn item(&mut self, depth: usize) -> Option<Item> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.items += 1;
        if self.items > MAX_ITEMS {
            return None;
        }
        let head: u8 = self.byte()?;
        let major: u8 = head >> 5;
        let info: u8 = head & 0x1f;
        match major {
            0 => self.argument(info).map(Item::Uint),
            1 => self.argument(info).map(Item::Negative),
            2 => {
                let len: usize = usize::try_from(self.argument(info)?).ok()?;
                self.take(len).map(|b: &[u8]| Item::Bytes(b.to_vec()))
            }
            3 => {
                let len: usize = usize::try_from(self.argument(info)?).ok()?;
                let bytes: &[u8] = self.take(len)?;
                String::from_utf8(bytes.to_vec()).ok().map(Item::Text)
            }
            4 => {
                let len: usize = usize::try_from(self.argument(info)?).ok()?;
                if len > MAX_ITEMS {
                    return None;
                }
                let mut items: Vec<Item> = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Some(Item::Array(items))
            }
            5 => {
                let len: usize = usize::try_from(self.argument(info)?).ok()?;
                if len > MAX_ITEMS {
                    return None;
                }
                let mut pairs: Vec<(Item, Item)> = Vec::with_capacity(len);
                for _ in 0..len {
                    let key: Item = self.item(depth + 1)?;
                    let value: Item = self.item(depth + 1)?;
                    pairs.push((key, value));
                }
                Some(Item::Map(pairs))
            }
            7 => match info {
                20 => Some(Item::Bool(false)),
                21 => Some(Item::Bool(true)),
                22 => Some(Item::Null),
                _ => None,
            },
            _ => None,
        }
    }
}

#[must_use]
pub fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let mut carry: u32 = u32::from(*byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros: usize = bytes.iter().take_while(|byte: &&u8| **byte == 0).count();
    let mut out: String = "1".repeat(zeros);
    for digit in digits.iter().rev() {
        out.push(char::from(ALPHABET[usize::from(*digit)]));
    }
    out
}

fn render(item: &Item) -> String {
    match item {
        Item::Uint(value) => value.to_string(),
        Item::Negative(value) => format!("-{}", u128::from(*value) + 1),
        Item::Bytes(bytes) => format!("0x{}", crate::hex_digits(bytes)),
        Item::Text(text) => text.clone(),
        Item::Array(items) => {
            let parts: Vec<String> = items.iter().map(render).collect();
            format!("[{}]", parts.join(", "))
        }
        Item::Map(pairs) => {
            let parts: Vec<String> = pairs
                .iter()
                .map(|(key, value): &(Item, Item)| format!("{}: {}", render(key), render(value)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        Item::Bool(value) => value.to_string(),
        Item::Null => "null".to_owned(),
    }
}

fn version_from(item: &Item) -> Option<String> {
    match item {
        Item::Bytes(bytes) if bytes.len() == 3 => {
            Some(format!("{}.{}.{}", bytes[0], bytes[1], bytes[2]))
        }
        Item::Text(text) => Some(text.clone()),
        Item::Array(parts) if !parts.is_empty() && parts.len() <= 4 => {
            let numbers: Option<Vec<String>> = parts
                .iter()
                .map(|part: &Item| match part {
                    Item::Uint(value) => Some(value.to_string()),
                    _ => None,
                })
                .collect();
            numbers.map(|numbers: Vec<String>| numbers.join("."))
        }
        _ => None,
    }
}

#[must_use]
pub fn parse_trailer(code: &[u8]) -> Option<Metadata> {
    let len: usize = code.len();
    if len < 2 {
        return None;
    }
    let declared: usize = usize::from(u16::from_be_bytes([code[len - 2], code[len - 1]]));
    trailer_of_length(code, declared).or_else(|| {
        declared
            .checked_sub(2)
            .and_then(|inclusive: usize| trailer_of_length(code, inclusive))
    })
}

fn trailer_of_length(code: &[u8], cbor_len: usize) -> Option<Metadata> {
    let len: usize = code.len();
    if cbor_len == 0 || cbor_len + 2 > len {
        return None;
    }
    let start: usize = len - 2 - cbor_len;
    let mut reader: Reader<'_> = Reader {
        data: &code[start..len - 2],
        at: 0,
        items: 0,
    };
    let root: Item = reader.item(0)?;
    if reader.at != cbor_len {
        return None;
    }
    let pairs: &[(Item, Item)] = match &root {
        Item::Map(pairs) => pairs,
        Item::Array(items) => match items.last() {
            Some(Item::Map(pairs)) => pairs,
            _ => return None,
        },
        _ => return None,
    };
    let mut metadata: Metadata = Metadata {
        section: "runtime",
        offset: start,
        length: cbor_len + 2,
        compiler: None,
        ipfs: None,
        bzzr0: None,
        bzzr1: None,
        experimental: false,
        entries: BTreeMap::new(),
    };
    let mut known: bool = false;
    for (key, value) in pairs {
        let Item::Text(key) = key else {
            return None;
        };
        match (key.as_str(), value) {
            ("solc", _) => {
                metadata.compiler = version_from(value).map(|version: String| Compiler {
                    name: "solc",
                    version,
                });
                known = true;
            }
            ("vyper", _) => {
                metadata.compiler = version_from(value).map(|version: String| Compiler {
                    name: "vyper",
                    version,
                });
                known = true;
            }
            ("ipfs", Item::Bytes(bytes)) => {
                metadata.ipfs = Some(base58(bytes));
                known = true;
            }
            ("bzzr0", Item::Bytes(bytes)) => {
                metadata.bzzr0 = Some(crate::hex_digits(bytes));
                known = true;
            }
            ("bzzr1", Item::Bytes(bytes)) => {
                metadata.bzzr1 = Some(crate::hex_digits(bytes));
                known = true;
            }
            ("experimental", Item::Bool(flag)) => {
                metadata.experimental = *flag;
                known = true;
            }
            _ => {}
        }
        metadata.entries.insert(key.clone(), render(value));
    }
    known.then_some(metadata)
}

#[cfg(test)]
mod tests {
    use super::{base58, parse_trailer};

    #[test]
    fn decodes_a_solc_ipfs_trailer() {
        let mut code: Vec<u8> = vec![0x60, 0x80, 0x60, 0x40, 0x52, 0xfe];
        let mut cbor: Vec<u8> = vec![0xa2, 0x64, b'i', b'p', b'f', b's', 0x58, 0x22, 0x12, 0x20];
        cbor.extend(std::iter::repeat_n(0x11, 32));
        cbor.extend([0x64, b's', b'o', b'l', b'c', 0x43, 0, 8, 30]);
        code.extend(&cbor);
        code.extend((cbor.len() as u16).to_be_bytes());
        let metadata = parse_trailer(&code);
        assert_eq!(metadata.as_ref().map(|m| m.offset), Some(6));
        assert_eq!(
            metadata
                .as_ref()
                .and_then(|m| m.compiler.as_ref())
                .map(|c| c.version.as_str()),
            Some("0.8.30")
        );
        assert!(
            metadata
                .as_ref()
                .and_then(|m| m.ipfs.as_deref())
                .is_some_and(|cid| cid.starts_with("Qm") && cid.len() == 46)
        );
        assert_eq!(parse_trailer(&[0x60, 0x80, 0x00, 0x05]), None);
    }

    #[test]
    fn base58_matches_the_bitcoin_alphabet() {
        assert_eq!(base58(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(base58(&[0, 0, 1]), "112");
    }
}
