use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::marker::PhantomData;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataValueKind {
    PlainString,
    CommaSeparatedList,
    Integer,
    Boolean,
    JsonFragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredKey {
    symbol: &'static str,
    name: &'static str,
    value_kind: MetadataValueKind,
    max_bytes: usize,
    published: bool,
}

impl RegisteredKey {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        self.symbol
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn value_kind(self) -> MetadataValueKind {
        self.value_kind
    }

    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    #[must_use]
    pub const fn published(self) -> bool {
        self.published
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommaSeparatedList;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Integer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boolean;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonFragment;

#[derive(Debug, PartialEq, Eq)]
pub struct MetadataKey<T> {
    name: &'static str,
    max_bytes: usize,
    published: bool,
    value_type: PhantomData<fn() -> T>,
}

impl<T> Copy for MetadataKey<T> {}

impl<T> Clone for MetadataKey<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> MetadataKey<T> {
    const fn new(name: &'static str, max_bytes: usize, published: bool) -> Self {
        assert!(
            valid_key_name(name),
            "metadata keys require a dotted namespace"
        );
        assert!(max_bytes > 0, "metadata keys require a positive size bound");
        Self {
            name,
            max_bytes,
            published,
            value_type: PhantomData,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    #[must_use]
    pub const fn published(self) -> bool {
        self.published
    }
}

trait MetadataMarker {
    const VALUE_KIND: MetadataValueKind;
}

impl MetadataMarker for PlainString {
    const VALUE_KIND: MetadataValueKind = MetadataValueKind::PlainString;
}

impl MetadataMarker for CommaSeparatedList {
    const VALUE_KIND: MetadataValueKind = MetadataValueKind::CommaSeparatedList;
}

impl MetadataMarker for Integer {
    const VALUE_KIND: MetadataValueKind = MetadataValueKind::Integer;
}

impl MetadataMarker for Boolean {
    const VALUE_KIND: MetadataValueKind = MetadataValueKind::Boolean;
}

impl MetadataMarker for JsonFragment {
    const VALUE_KIND: MetadataValueKind = MetadataValueKind::JsonFragment;
}

const fn descriptor<T: MetadataMarker>(key: MetadataKey<T>, symbol: &'static str) -> RegisteredKey {
    RegisteredKey {
        symbol,
        name: key.name,
        value_kind: T::VALUE_KIND,
        max_bytes: key.max_bytes,
        published: key.published,
    }
}

const fn valid_key_name(name: &str) -> bool {
    let bytes: &[u8] = name.as_bytes();
    if bytes.len() < 3 {
        return false;
    }
    let mut index: usize = 0;
    let mut has_separator: bool = false;
    while index < bytes.len() {
        let byte: u8 = bytes[index];
        if byte == b'.' {
            if index == 0 || index.saturating_add(1) == bytes.len() || bytes[index - 1] == b'.' {
                return false;
            }
            has_separator = true;
        } else if !((byte >= b'a' && byte <= b'z')
            || (byte >= b'0' && byte <= b'9')
            || byte == b'_'
            || byte == b'-')
        {
            return false;
        }
        index = index.saturating_add(1);
    }
    has_separator
}

pub mod keys {
    use super::{CommaSeparatedList, MetadataKey, RegisteredKey, descriptor};

    macro_rules! define_metadata_keys {
        ($($legacy:ident, $typed:ident: $value_type:ty => $name:literal, $max_bytes:expr, $published:expr);+ $(;)?) => {
            $(
                pub const $legacy: &str = $name;
                pub const $typed: MetadataKey<$value_type> =
                    MetadataKey::new($name, $max_bytes, $published);
            )+

            pub(super) const REGISTERED: [RegisteredKey; define_metadata_keys!(@count $($typed),+)] = [
                $(descriptor($typed, stringify!($typed))),+
            ];
        };
        (@count $($name:ident),+) => {
            <[()]>::len(&[$(define_metadata_keys!(@unit $name)),+])
        };
        (@unit $name:ident) => { () };
    }

    define_metadata_keys!(
        ANTI_RECOVERED_TECHNIQUES,
        ANTI_RECOVERED_TECHNIQUES_KEY: CommaSeparatedList =>
            "anti.recovered_techniques",
            4_096,
            true;
    );
}

#[must_use]
pub const fn registered_keys() -> &'static [RegisteredKey] {
    &keys::REGISTERED
}

#[must_use]
pub fn get<'metadata>(
    metadata: &'metadata BTreeMap<String, String>,
    key: &str,
) -> Option<&'metadata str> {
    metadata.get(key).map(String::as_str)
}

pub fn get_parsed<T>(metadata: &BTreeMap<String, String>, key: &str) -> Result<Option<T>, T::Err>
where
    T: FromStr,
{
    get(metadata, key).map(str::parse::<T>).transpose()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataValueError {
    ValueTooLong {
        key: &'static str,
        actual_bytes: usize,
        max_bytes: usize,
    },
    JsonTooLarge {
        key: &'static str,
        max_bytes: usize,
    },
    EmptyList {
        key: &'static str,
    },
    EmptyListElement {
        key: &'static str,
        index: usize,
    },
    CommaInListElement {
        key: &'static str,
        index: usize,
    },
    InvalidInteger {
        key: &'static str,
    },
    InvalidBoolean {
        key: &'static str,
    },
    InvalidJson {
        key: &'static str,
    },
}

impl Display for MetadataValueError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValueTooLong {
                key,
                actual_bytes,
                max_bytes,
            } => write!(
                formatter,
                "metadata value for {key} is {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::JsonTooLarge { key, max_bytes } => write!(
                formatter,
                "metadata JSON for {key} exceeded the bounded serialization limit of {max_bytes} bytes"
            ),
            Self::EmptyList { key } => {
                write!(formatter, "metadata list for {key} has no elements")
            }
            Self::EmptyListElement { key, index } => {
                write!(
                    formatter,
                    "metadata list for {key} has an empty element at {index}"
                )
            }
            Self::CommaInListElement { key, index } => write!(
                formatter,
                "metadata list for {key} has a comma in element {index}"
            ),
            Self::InvalidInteger { key } => {
                write!(formatter, "metadata value for {key} is not an integer")
            }
            Self::InvalidBoolean { key } => {
                write!(formatter, "metadata value for {key} is not a boolean")
            }
            Self::InvalidJson { key } => {
                write!(formatter, "metadata value for {key} is not valid JSON")
            }
        }
    }
}

impl std::error::Error for MetadataValueError {}

fn get_bounded<T>(
    metadata: &BTreeMap<String, String>,
    key: MetadataKey<T>,
) -> Result<Option<&str>, MetadataValueError> {
    let Some(value): Option<&String> = metadata.get(key.name()) else {
        return Ok(None);
    };
    validate_size(key, value.len())?;
    Ok(Some(value.as_str()))
}

const fn validate_size<T>(
    key: MetadataKey<T>,
    actual_bytes: usize,
) -> Result<(), MetadataValueError> {
    if actual_bytes > key.max_bytes() {
        return Err(MetadataValueError::ValueTooLong {
            key: key.name(),
            actual_bytes,
            max_bytes: key.max_bytes(),
        });
    }
    Ok(())
}

fn set_bounded<T>(
    metadata: &mut BTreeMap<String, String>,
    key: MetadataKey<T>,
    value: String,
) -> Result<Option<String>, MetadataValueError> {
    validate_size(key, value.len())?;
    Ok(metadata.insert(key.name().to_string(), value))
}

pub fn get_string(
    metadata: &BTreeMap<String, String>,
    key: MetadataKey<PlainString>,
) -> Result<Option<&str>, MetadataValueError> {
    get_bounded(metadata, key)
}

pub fn set_string(
    metadata: &mut BTreeMap<String, String>,
    key: MetadataKey<PlainString>,
    value: &str,
) -> Result<Option<String>, MetadataValueError> {
    validate_size(key, value.len())?;
    set_bounded(metadata, key, value.to_string())
}

pub fn get_comma_list(
    metadata: &BTreeMap<String, String>,
    key: MetadataKey<CommaSeparatedList>,
) -> Result<Option<Vec<&str>>, MetadataValueError> {
    let Some(raw): Option<&str> = get_bounded(metadata, key)? else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Err(MetadataValueError::EmptyList { key: key.name() });
    }
    let mut values: Vec<&str> = Vec::new();
    for (index, raw_value) in raw.split(',').enumerate() {
        let value: &str = raw_value.trim();
        if value.is_empty() {
            return Err(MetadataValueError::EmptyListElement {
                key: key.name(),
                index,
            });
        }
        values.push(value);
    }
    Ok(Some(values))
}

pub fn set_comma_list(
    metadata: &mut BTreeMap<String, String>,
    key: MetadataKey<CommaSeparatedList>,
    values: &[&str],
) -> Result<Option<String>, MetadataValueError> {
    if values.is_empty() {
        return Err(MetadataValueError::EmptyList { key: key.name() });
    }
    let max_elements: usize = key.max_bytes();
    if values.len() > max_elements {
        let actual_bytes: usize = key
            .max_bytes()
            .checked_add(1)
            .map_or(usize::MAX, |value: usize| value);
        return Err(MetadataValueError::ValueTooLong {
            key: key.name(),
            actual_bytes,
            max_bytes: key.max_bytes(),
        });
    }
    let mut encoded_bytes: usize = values.len().saturating_sub(1);
    for (index, raw_value) in values.iter().enumerate() {
        if raw_value.len() > key.max_bytes() {
            return Err(MetadataValueError::ValueTooLong {
                key: key.name(),
                actual_bytes: raw_value.len(),
                max_bytes: key.max_bytes(),
            });
        }
        let value: &str = raw_value.trim();
        if value.is_empty() {
            return Err(MetadataValueError::EmptyListElement {
                key: key.name(),
                index,
            });
        }
        if value.contains(',') {
            return Err(MetadataValueError::CommaInListElement {
                key: key.name(),
                index,
            });
        }
        encoded_bytes = encoded_bytes.checked_add(value.len()).ok_or_else(|| {
            MetadataValueError::ValueTooLong {
                key: key.name(),
                actual_bytes: usize::MAX,
                max_bytes: key.max_bytes(),
            }
        })?;
    }
    if encoded_bytes > key.max_bytes() {
        return Err(MetadataValueError::ValueTooLong {
            key: key.name(),
            actual_bytes: encoded_bytes,
            max_bytes: key.max_bytes(),
        });
    }
    let mut encoded: String = String::with_capacity(encoded_bytes);
    for (index, raw_value) in values.iter().enumerate() {
        if index > 0 {
            encoded.push(',');
        }
        encoded.push_str(raw_value.trim());
    }
    set_bounded(metadata, key, encoded)
}

pub fn get_integer(
    metadata: &BTreeMap<String, String>,
    key: MetadataKey<Integer>,
) -> Result<Option<i64>, MetadataValueError> {
    get_bounded(metadata, key)?
        .map(|value: &str| {
            value.parse::<i64>().map_err(|_: std::num::ParseIntError| {
                MetadataValueError::InvalidInteger { key: key.name() }
            })
        })
        .transpose()
}

pub fn set_integer(
    metadata: &mut BTreeMap<String, String>,
    key: MetadataKey<Integer>,
    value: i64,
) -> Result<Option<String>, MetadataValueError> {
    set_bounded(metadata, key, value.to_string())
}

pub fn get_boolean(
    metadata: &BTreeMap<String, String>,
    key: MetadataKey<Boolean>,
) -> Result<Option<bool>, MetadataValueError> {
    get_bounded(metadata, key)?
        .map(|value: &str| match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(MetadataValueError::InvalidBoolean { key: key.name() }),
        })
        .transpose()
}

pub fn set_boolean(
    metadata: &mut BTreeMap<String, String>,
    key: MetadataKey<Boolean>,
    value: bool,
) -> Result<Option<String>, MetadataValueError> {
    set_bounded(metadata, key, value.to_string())
}

pub fn get_json(
    metadata: &BTreeMap<String, String>,
    key: MetadataKey<JsonFragment>,
) -> Result<Option<serde_json::Value>, MetadataValueError> {
    get_bounded(metadata, key)?
        .map(|value: &str| {
            serde_json::from_str::<serde_json::Value>(value)
                .map_err(|_: serde_json::Error| MetadataValueError::InvalidJson { key: key.name() })
        })
        .transpose()
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    total_bytes: usize,
    overflow_bytes: Option<usize>,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes),
            max_bytes,
            total_bytes: 0,
            overflow_bytes: None,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.overflow_bytes.is_some() {
            return Err(std::io::Error::other("metadata JSON exceeds size bound"));
        }
        let Some(next_len): Option<usize> = self.total_bytes.checked_add(buffer.len()) else {
            return Err(std::io::Error::other("metadata JSON length overflow"));
        };
        if next_len > self.max_bytes {
            self.total_bytes = next_len;
            self.overflow_bytes = Some(next_len);
            return Err(std::io::Error::other("metadata JSON exceeds size bound"));
        }
        self.total_bytes = next_len;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn set_json(
    metadata: &mut BTreeMap<String, String>,
    key: MetadataKey<JsonFragment>,
    value: &serde_json::Value,
) -> Result<Option<String>, MetadataValueError> {
    let mut writer: BoundedJsonWriter = BoundedJsonWriter::new(key.max_bytes());
    if serde_json::to_writer(&mut writer, value).is_err() {
        if writer.overflow_bytes.is_some() {
            return Err(MetadataValueError::JsonTooLarge {
                key: key.name(),
                max_bytes: key.max_bytes(),
            });
        }
        return Err(MetadataValueError::InvalidJson { key: key.name() });
    }
    let encoded: String =
        String::from_utf8(writer.bytes).map_err(|_: std::string::FromUtf8Error| {
            MetadataValueError::InvalidJson { key: key.name() }
        })?;
    set_bounded(metadata, key, encoded)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEXT_KEY: MetadataKey<PlainString> = MetadataKey::new("test.text", 16, false);
    const INTEGER_KEY: MetadataKey<Integer> = MetadataKey::new("test.integer", 16, false);
    const BOOLEAN_KEY: MetadataKey<Boolean> = MetadataKey::new("test.boolean", 5, false);
    const JSON_KEY: MetadataKey<JsonFragment> = MetadataKey::new("test.json", 32, false);
    const SMALL_INTEGER_KEY: MetadataKey<Integer> =
        MetadataKey::new("test.small_integer", 1, false);
    const SMALL_BOOLEAN_KEY: MetadataKey<Boolean> =
        MetadataKey::new("test.small_boolean", 4, false);

    #[test]
    fn registered_keys_have_dotted_names_declared_shapes_and_bounds() {
        let text_descriptor: RegisteredKey = descriptor(TEXT_KEY, "TEXT_KEY");
        assert_eq!(text_descriptor.value_kind(), MetadataValueKind::PlainString);
        assert_eq!(
            descriptor(INTEGER_KEY, "INTEGER_KEY").value_kind(),
            MetadataValueKind::Integer
        );
        assert_eq!(
            descriptor(BOOLEAN_KEY, "BOOLEAN_KEY").value_kind(),
            MetadataValueKind::Boolean
        );
        assert_eq!(
            descriptor(JSON_KEY, "JSON_KEY").value_kind(),
            MetadataValueKind::JsonFragment
        );
        let registered: &[RegisteredKey] = registered_keys();
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].symbol(), "ANTI_RECOVERED_TECHNIQUES_KEY");
        assert_eq!(registered[0].name(), "anti.recovered_techniques");
        assert_eq!(
            registered[0].value_kind(),
            MetadataValueKind::CommaSeparatedList
        );
        assert!(registered[0].max_bytes() > 0);
        assert!(registered[0].published());
        for valid in ["a.b", "anti.recovered_techniques", "format.v2-name"] {
            assert!(valid_key_name(valid));
        }
        for invalid in ["", "plain", ".leading", "trailing.", "two..dots", "Bad.key"] {
            assert!(!valid_key_name(invalid));
        }
    }

    #[test]
    fn legacy_untyped_accessors_remain_compatible() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        metadata.insert("count.value".to_string(), "42".to_string());
        assert_eq!(keys::ANTI_RECOVERED_TECHNIQUES, "anti.recovered_techniques");
        assert_eq!(get(&metadata, "count.value"), Some("42"));
        assert_eq!(
            get_parsed::<u32>(&metadata, "count.value").expect("integer"),
            Some(42)
        );
        assert_eq!(get(&metadata, "missing.value"), None);
        assert_eq!(
            get_parsed::<u32>(&metadata, "missing.value").expect("missing"),
            None
        );
    }

    #[test]
    fn comma_list_round_trips_and_accepts_one_element() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        let previous: Option<String> = set_comma_list(
            &mut metadata,
            keys::ANTI_RECOVERED_TECHNIQUES_KEY,
            &["cff", "opaque"],
        )
        .expect("valid list");
        assert_eq!(previous, None);
        assert_eq!(
            metadata.get(keys::ANTI_RECOVERED_TECHNIQUES),
            Some(&"cff,opaque".to_string())
        );
        assert_eq!(
            get_comma_list(&metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY).expect("stored list"),
            Some(vec!["cff", "opaque"])
        );
        set_comma_list(
            &mut metadata,
            keys::ANTI_RECOVERED_TECHNIQUES_KEY,
            &["single"],
        )
        .expect("single item");
        assert_eq!(
            get_comma_list(&metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY)
                .expect("single stored item"),
            Some(vec!["single"])
        );
    }

    #[test]
    fn comma_list_distinguishes_absent_empty_and_malformed_values() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(
            get_comma_list(&metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY).expect("absent list"),
            None
        );
        for empty in ["", "   "] {
            metadata.insert(
                keys::ANTI_RECOVERED_TECHNIQUES_KEY.name().to_string(),
                empty.to_string(),
            );
            assert_eq!(
                get_comma_list(&metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY),
                Err(MetadataValueError::EmptyList {
                    key: "anti.recovered_techniques"
                })
            );
        }
        for (malformed, index) in [
            ("cff,,opaque", 1),
            ("cff,", 1),
            (",cff", 0),
            ("cff,   ,opaque", 1),
        ] {
            metadata.insert(
                keys::ANTI_RECOVERED_TECHNIQUES_KEY.name().to_string(),
                malformed.to_string(),
            );
            assert_eq!(
                get_comma_list(&metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY),
                Err(MetadataValueError::EmptyListElement {
                    key: "anti.recovered_techniques",
                    index
                }),
                "wrong malformed-list error for {malformed:?}"
            );
        }
    }

    #[test]
    fn comma_list_setter_rejects_empty_comma_bearing_and_oversized_values() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(
            set_comma_list(&mut metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY, &[]),
            Err(MetadataValueError::EmptyList {
                key: "anti.recovered_techniques"
            })
        );
        assert_eq!(
            set_comma_list(
                &mut metadata,
                keys::ANTI_RECOVERED_TECHNIQUES_KEY,
                &["cff,opaque"],
            ),
            Err(MetadataValueError::CommaInListElement {
                key: "anti.recovered_techniques",
                index: 0
            })
        );
        let oversized: String = "x".repeat(
            keys::ANTI_RECOVERED_TECHNIQUES_KEY
                .max_bytes()
                .saturating_add(1),
        );
        assert_eq!(
            set_comma_list(
                &mut metadata,
                keys::ANTI_RECOVERED_TECHNIQUES_KEY,
                &[oversized.as_str()],
            ),
            Err(MetadataValueError::ValueTooLong {
                key: "anti.recovered_techniques",
                actual_bytes: 4_097,
                max_bytes: 4_096
            })
        );
        assert!(metadata.is_empty());
    }

    #[test]
    fn comma_list_setter_validates_elements_and_reports_the_full_encoded_length() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        let oversized: Vec<&str> = vec!["xx"; 2_048];
        assert_eq!(
            set_comma_list(
                &mut metadata,
                keys::ANTI_RECOVERED_TECHNIQUES_KEY,
                &oversized,
            ),
            Err(MetadataValueError::ValueTooLong {
                key: "anti.recovered_techniques",
                actual_bytes: 6_143,
                max_bytes: 4_096
            })
        );
        let mut malformed: Vec<&str> = vec!["xx"; 2_048];
        malformed[2_047] = "";
        assert_eq!(
            set_comma_list(
                &mut metadata,
                keys::ANTI_RECOVERED_TECHNIQUES_KEY,
                &malformed,
            ),
            Err(MetadataValueError::EmptyListElement {
                key: "anti.recovered_techniques",
                index: 2_047
            })
        );
        assert!(metadata.is_empty());
    }

    #[test]
    fn comma_list_setter_bounds_element_work_before_a_later_invalid_element() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        let mut values: Vec<&str> = vec!["x"; 10_000];
        values[9_999] = "";
        assert_eq!(
            set_comma_list(
                &mut metadata,
                keys::ANTI_RECOVERED_TECHNIQUES_KEY,
                values.as_slice(),
            ),
            Err(MetadataValueError::ValueTooLong {
                key: "anti.recovered_techniques",
                actual_bytes: 4_097,
                max_bytes: 4_096
            })
        );
        assert!(metadata.is_empty());
    }

    #[test]
    fn plain_string_preserves_commas_and_distinguishes_empty_from_absent() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(get_string(&metadata, TEXT_KEY).expect("absent"), None);
        set_string(&mut metadata, TEXT_KEY, "").expect("empty string");
        assert_eq!(get_string(&metadata, TEXT_KEY).expect("empty"), Some(""));
        set_string(&mut metadata, TEXT_KEY, "left,right").expect("comma string");
        assert_eq!(
            get_string(&metadata, TEXT_KEY).expect("comma string"),
            Some("left,right")
        );
        assert_eq!(
            set_string(&mut metadata, TEXT_KEY, "0123456789abcdefg"),
            Err(MetadataValueError::ValueTooLong {
                key: "test.text",
                actual_bytes: 17,
                max_bytes: 16
            })
        );
    }

    #[test]
    fn integer_and_boolean_accessors_reject_malformed_values() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(get_integer(&metadata, INTEGER_KEY).expect("absent"), None);
        set_integer(&mut metadata, INTEGER_KEY, -42).expect("integer");
        assert_eq!(
            get_integer(&metadata, INTEGER_KEY).expect("integer"),
            Some(-42)
        );
        for malformed in ["", "one"] {
            metadata.insert(INTEGER_KEY.name().to_string(), malformed.to_string());
            assert_eq!(
                get_integer(&metadata, INTEGER_KEY),
                Err(MetadataValueError::InvalidInteger {
                    key: "test.integer"
                })
            );
        }
        assert_eq!(get_boolean(&metadata, BOOLEAN_KEY).expect("absent"), None);
        set_boolean(&mut metadata, BOOLEAN_KEY, true).expect("boolean");
        assert_eq!(
            get_boolean(&metadata, BOOLEAN_KEY).expect("boolean"),
            Some(true)
        );
        for malformed in ["", "TRUE"] {
            metadata.insert(BOOLEAN_KEY.name().to_string(), malformed.to_string());
            assert_eq!(
                get_boolean(&metadata, BOOLEAN_KEY),
                Err(MetadataValueError::InvalidBoolean {
                    key: "test.boolean"
                })
            );
        }
        assert_eq!(
            set_integer(&mut metadata, SMALL_INTEGER_KEY, -2),
            Err(MetadataValueError::ValueTooLong {
                key: "test.small_integer",
                actual_bytes: 2,
                max_bytes: 1
            })
        );
        assert_eq!(
            set_boolean(&mut metadata, SMALL_BOOLEAN_KEY, false),
            Err(MetadataValueError::ValueTooLong {
                key: "test.small_boolean",
                actual_bytes: 5,
                max_bytes: 4
            })
        );
    }

    #[test]
    fn json_accessors_round_trip_and_reject_empty_or_malformed_fragments() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(get_json(&metadata, JSON_KEY).expect("absent"), None);
        let value: serde_json::Value = serde_json::json!({"ok": true});
        set_json(&mut metadata, JSON_KEY, &value).expect("json");
        assert_eq!(get_json(&metadata, JSON_KEY).expect("json"), Some(value));
        for malformed in ["", "{"] {
            metadata.insert(JSON_KEY.name().to_string(), malformed.to_string());
            assert_eq!(
                get_json(&metadata, JSON_KEY),
                Err(MetadataValueError::InvalidJson { key: "test.json" })
            );
        }
        let oversized: serde_json::Value = serde_json::Value::String("x".repeat(64));
        let error: MetadataValueError =
            set_json(&mut metadata, JSON_KEY, &oversized).expect_err("oversized JSON");
        assert_eq!(
            error,
            MetadataValueError::JsonTooLarge {
                key: "test.json",
                max_bytes: 32
            }
        );

        let mut deeply_nested: serde_json::Value = serde_json::Value::Null;
        for _depth in 0..256 {
            deeply_nested = serde_json::Value::Array(vec![deeply_nested]);
        }
        assert_eq!(
            set_json(&mut metadata, JSON_KEY, &deeply_nested),
            Err(MetadataValueError::JsonTooLarge {
                key: "test.json",
                max_bytes: 32
            })
        );
    }

    #[test]
    fn bounded_getters_reject_oversized_preexisting_values() {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        metadata.insert(TEXT_KEY.name().to_string(), "x".repeat(17));
        assert_eq!(
            get_string(&metadata, TEXT_KEY),
            Err(MetadataValueError::ValueTooLong {
                key: "test.text",
                actual_bytes: 17,
                max_bytes: 16
            })
        );
    }

    #[test]
    fn json_length_counting_keeps_storage_at_the_key_bound() {
        let value: serde_json::Value = serde_json::Value::String("x".repeat(4_096));
        let mut writer: BoundedJsonWriter = BoundedJsonWriter::new(32);
        serde_json::to_writer(&mut writer, &value).expect_err("JSON length bound");
        assert_eq!(writer.total_bytes, 4_097);
        assert_eq!(writer.overflow_bytes, Some(4_097));
        assert!(writer.bytes.len() <= writer.max_bytes);
        assert!(writer.bytes.capacity() <= writer.max_bytes);
    }

    #[test]
    fn bounded_json_writer_rejects_overflow_and_does_not_continue_work() {
        let mut writer: BoundedJsonWriter = BoundedJsonWriter::new(4);
        assert_eq!(writer.write(b"1234").expect("within JSON bound"), 4);
        assert!(writer.write(b"5").is_err());
        assert!(writer.write(b"6").is_err());
        assert_eq!(writer.total_bytes, 5);
        assert_eq!(writer.bytes, b"1234");
    }
}
