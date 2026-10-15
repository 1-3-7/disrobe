use std::collections::BTreeMap;
use std::io::Cursor;

use plist::Value;
use serde::Serialize;

use crate::error::{Error, Result};

const MAX_DEPTH: usize = 256;
const MAX_NODES: usize = 1_000_000;
const APPLE_EPOCH_UNIX: f64 = 978_307_200.0;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ArchivedValue {
    Null,
    Bool {
        value: bool,
    },
    Integer {
        value: i128,
    },
    Real {
        value: f64,
    },
    String {
        value: String,
    },
    Data {
        hex: String,
    },
    Date {
        seconds_since_2001: f64,
        unix: f64,
    },
    Array {
        class: String,
        items: Vec<Self>,
    },
    Set {
        class: String,
        items: Vec<Self>,
    },
    Dictionary {
        class: String,
        entries: Vec<(Self, Self)>,
    },
    Url {
        base: Option<Box<Self>>,
        relative: Box<Self>,
    },
    Uuid {
        value: String,
    },
    Value {
        class: String,
        fields: BTreeMap<String, Self>,
    },
    Object {
        class: String,
        superclasses: Vec<String>,
        fields: BTreeMap<String, Self>,
    },
    BackReference {
        uid: u64,
    },
    Dangling {
        uid: u64,
    },
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyedArchive {
    pub archiver: String,
    pub version: Option<i128>,
    pub objects: usize,
    pub top: BTreeMap<String, ArchivedValue>,
    pub problems: Vec<String>,
}

struct Decoder<'a> {
    objects: &'a [Value],
    path: Vec<u64>,
    nodes: usize,
    problems: Vec<String>,
}

fn uid_of(value: &Value) -> Option<u64> {
    if let Some(uid) = value.as_uid() {
        return Some(uid.get());
    }
    let dict: &plist::Dictionary = value.as_dictionary()?;
    if dict.len() != 1 {
        return None;
    }
    dict.get("CF$UID")?.as_unsigned_integer()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::new(), |mut out: String, byte: &u8| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn uuid(bytes: &[u8]) -> Option<String> {
    let raw: &[u8; 16] = bytes.try_into().ok()?;
    let text: String = hex(raw).to_uppercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &text[0..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..32]
    ))
}

impl Decoder<'_> {
    fn reference(&mut self, value: &Value) -> ArchivedValue {
        match uid_of(value) {
            Some(uid) => self.object(uid),
            None => self.plain(value),
        }
    }

    fn plain(&mut self, value: &Value) -> ArchivedValue {
        self.nodes += 1;
        match value {
            Value::Boolean(value) => ArchivedValue::Bool { value: *value },
            Value::Integer(integer) => ArchivedValue::Integer {
                value: integer
                    .as_signed()
                    .map(i128::from)
                    .or_else(|| integer.as_unsigned().map(i128::from))
                    .unwrap_or_default(),
            },
            Value::Real(value) => ArchivedValue::Real { value: *value },
            Value::String(value) => ArchivedValue::String {
                value: value.clone(),
            },
            Value::Data(bytes) => ArchivedValue::Data { hex: hex(bytes) },
            Value::Date(date) => {
                let unix: f64 = std::time::SystemTime::from(*date)
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |elapsed| elapsed.as_secs_f64());
                ArchivedValue::Date {
                    seconds_since_2001: unix - APPLE_EPOCH_UNIX,
                    unix,
                }
            }
            Value::Array(items) => ArchivedValue::Array {
                class: "plist array".to_owned(),
                items: items
                    .iter()
                    .map(|item: &Value| self.reference(item))
                    .collect(),
            },
            Value::Dictionary(dict) => ArchivedValue::Dictionary {
                class: "plist dictionary".to_owned(),
                entries: dict
                    .iter()
                    .map(|(key, item): (&String, &Value)| {
                        (
                            ArchivedValue::String { value: key.clone() },
                            self.reference(item),
                        )
                    })
                    .collect(),
            },
            Value::Uid(uid) => ArchivedValue::Dangling { uid: uid.get() },
            _ => ArchivedValue::Truncated,
        }
    }

    fn object(&mut self, uid: u64) -> ArchivedValue {
        if self.path.contains(&uid) {
            return ArchivedValue::BackReference { uid };
        }
        if self.path.len() >= MAX_DEPTH || self.nodes >= MAX_NODES {
            if self.nodes == MAX_NODES || self.path.len() == MAX_DEPTH {
                self.problems.push(format!(
                    "object graph exceeds {MAX_DEPTH} levels or {MAX_NODES} nodes; deeper objects are truncated"
                ));
            }
            self.nodes += 1;
            return ArchivedValue::Truncated;
        }
        let Some(value): Option<&Value> = usize::try_from(uid)
            .ok()
            .and_then(|index: usize| self.objects.get(index))
        else {
            self.problems.push(format!(
                "UID {uid} points past the {} objects",
                self.objects.len()
            ));
            return ArchivedValue::Dangling { uid };
        };
        self.path.push(uid);
        let decoded: ArchivedValue = self.object_value(value);
        self.path.pop();
        decoded
    }

    fn object_value(&mut self, value: &Value) -> ArchivedValue {
        if value.as_string() == Some("$null") {
            self.nodes += 1;
            return ArchivedValue::Null;
        }
        let Some(dict): Option<&plist::Dictionary> = value.as_dictionary() else {
            return self.plain(value);
        };
        let Some(class_uid): Option<u64> = dict.get("$class").and_then(uid_of) else {
            return self.plain(value);
        };
        self.nodes += 1;
        let (class, superclasses): (String, Vec<String>) = self.class(class_uid);
        let field = |key: &str| dict.get(key);
        match class.as_str() {
            "NSArray" | "NSMutableArray" => ArchivedValue::Array {
                items: self.list(field("NS.objects")),
                class,
            },
            "NSSet" | "NSMutableSet" | "NSOrderedSet" | "NSMutableOrderedSet" | "NSCountedSet" => {
                ArchivedValue::Set {
                    items: self.list(field("NS.objects")),
                    class,
                }
            }
            "NSDictionary" | "NSMutableDictionary" => {
                let keys: Vec<ArchivedValue> = self.list(field("NS.keys"));
                let values: Vec<ArchivedValue> = self.list(field("NS.objects"));
                if keys.len() != values.len() {
                    self.problems.push(format!(
                        "{class} holds {} keys and {} values",
                        keys.len(),
                        values.len()
                    ));
                }
                ArchivedValue::Dictionary {
                    entries: keys.into_iter().zip(values).collect(),
                    class,
                }
            }
            "NSString" | "NSMutableString" => match (field("NS.string"), field("NS.bytes")) {
                (Some(text), _) => self.reference(text),
                (None, Some(Value::Data(bytes))) => ArchivedValue::String {
                    value: String::from_utf8_lossy(bytes).into_owned(),
                },
                _ => ArchivedValue::String {
                    value: String::new(),
                },
            },
            "NSData" | "NSMutableData" => field("NS.data").map_or_else(
                || ArchivedValue::Data { hex: String::new() },
                |data: &Value| self.reference(data),
            ),
            "NSDate" => {
                let seconds: f64 = field("NS.time")
                    .and_then(Value::as_real)
                    .unwrap_or_default();
                ArchivedValue::Date {
                    seconds_since_2001: seconds,
                    unix: seconds + APPLE_EPOCH_UNIX,
                }
            }
            "NSURL" => {
                let base: Option<Box<ArchivedValue>> = field("NS.base")
                    .map(|base: &Value| self.reference(base))
                    .filter(|base: &ArchivedValue| *base != ArchivedValue::Null)
                    .map(Box::new);
                let relative: ArchivedValue = field("NS.relative")
                    .map_or(ArchivedValue::Null, |relative: &Value| {
                        self.reference(relative)
                    });
                ArchivedValue::Url {
                    base,
                    relative: Box::new(relative),
                }
            }
            "NSUUID" => match field("NS.uuidbytes") {
                Some(Value::Data(bytes)) => uuid(bytes).map_or_else(
                    || ArchivedValue::Data { hex: hex(bytes) },
                    |value: String| ArchivedValue::Uuid { value },
                ),
                _ => ArchivedValue::Truncated,
            },
            "NSNull" => ArchivedValue::Null,
            "NSValue" => ArchivedValue::Value {
                fields: self.fields(dict),
                class,
            },
            _ => ArchivedValue::Object {
                fields: self.fields(dict),
                class,
                superclasses,
            },
        }
    }

    fn fields(&mut self, dict: &plist::Dictionary) -> BTreeMap<String, ArchivedValue> {
        dict.iter()
            .filter(|(key, _): &(&String, &Value)| key.as_str() != "$class")
            .map(|(key, value): (&String, &Value)| (key.clone(), self.reference(value)))
            .collect()
    }

    fn list(&mut self, value: Option<&Value>) -> Vec<ArchivedValue> {
        value
            .and_then(Value::as_array)
            .map(|items: &Vec<Value>| {
                items
                    .iter()
                    .map(|item: &Value| self.reference(item))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn class(&mut self, uid: u64) -> (String, Vec<String>) {
        let class: Option<&plist::Dictionary> = usize::try_from(uid)
            .ok()
            .and_then(|index: usize| self.objects.get(index))
            .and_then(Value::as_dictionary);
        let Some(class) = class else {
            self.problems
                .push(format!("class UID {uid} is not a class description"));
            return (format!("<class {uid}>"), Vec::new());
        };
        let name: String = class
            .get("$classname")
            .and_then(Value::as_string)
            .map_or_else(|| format!("<class {uid}>"), str::to_owned);
        let superclasses: Vec<String> = class
            .get("$classes")
            .and_then(Value::as_array)
            .map(|chain: &Vec<Value>| {
                chain
                    .iter()
                    .filter_map(Value::as_string)
                    .skip(1)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        (name, superclasses)
    }
}

pub fn decode_keyed_archive(bytes: &[u8]) -> Result<KeyedArchive> {
    let root: Value = Value::from_reader(Cursor::new(bytes))
        .map_err(|e: plist::Error| Error::Plist(e.to_string()))?;
    let dict: &plist::Dictionary = root
        .as_dictionary()
        .ok_or_else(|| Error::Plist("a keyed archive is a dictionary at the top".to_owned()))?;
    let archiver: String = dict
        .get("$archiver")
        .and_then(Value::as_string)
        .ok_or_else(|| Error::Plist("no $archiver key: not a keyed archive".to_owned()))?
        .to_owned();
    let objects: &[Value] = dict
        .get("$objects")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| Error::Plist("no $objects array".to_owned()))?;
    let top: &plist::Dictionary = dict
        .get("$top")
        .and_then(Value::as_dictionary)
        .ok_or_else(|| Error::Plist("no $top dictionary".to_owned()))?;
    let version: Option<i128> = dict
        .get("$version")
        .and_then(Value::as_signed_integer)
        .map(i128::from);
    let mut decoder: Decoder<'_> = Decoder {
        objects,
        path: Vec::new(),
        nodes: 0,
        problems: Vec::new(),
    };
    let top: BTreeMap<String, ArchivedValue> = top
        .iter()
        .map(|(key, value): (&String, &Value)| (key.clone(), decoder.reference(value)))
        .collect();
    Ok(KeyedArchive {
        archiver,
        version,
        objects: objects.len(),
        top,
        problems: decoder.problems,
    })
}
