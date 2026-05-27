use std::collections::BTreeMap;
use std::io::Cursor;

use plist::Value;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoPlistSummary {
    pub bundle_identifier: Option<String>,
    pub bundle_name: Option<String>,
    pub bundle_display_name: Option<String>,
    pub bundle_executable: Option<String>,
    pub short_version: Option<String>,
    pub bundle_version: Option<String>,
    pub minimum_os_version: Option<String>,
    pub supported_platforms: Vec<String>,
    pub device_family: Vec<i64>,
    pub url_schemes: Vec<String>,
    pub raw_keys: Vec<String>,
}

pub fn parse_info_plist(bytes: &[u8]) -> Result<InfoPlistSummary> {
    let value: Value = Value::from_reader(Cursor::new(bytes))
        .map_err(|e: plist::Error| Error::Plist(e.to_string()))?;
    let dict: &plist::Dictionary = value
        .as_dictionary()
        .ok_or_else(|| Error::Plist("top-level plist is not a dictionary".to_owned()))?;
    let mut raw_keys: Vec<String> = dict.keys().map(String::from).collect();
    raw_keys.sort();

    let supported_platforms: Vec<String> = dict
        .get("CFBundleSupportedPlatforms")
        .and_then(Value::as_array)
        .map(|a: &Vec<Value>| {
            a.iter()
                .filter_map(|v: &Value| v.as_string().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let device_family: Vec<i64> = dict
        .get("UIDeviceFamily")
        .and_then(Value::as_array)
        .map(|a: &Vec<Value>| a.iter().filter_map(Value::as_signed_integer).collect())
        .unwrap_or_default();
    let url_schemes: Vec<String> = dict
        .get("CFBundleURLTypes")
        .and_then(Value::as_array)
        .map(|arr: &Vec<Value>| {
            let mut out: Vec<String> = Vec::new();
            for item in arr {
                let Some(d) = item.as_dictionary() else {
                    continue;
                };
                let Some(schemes) = d.get("CFBundleURLSchemes").and_then(Value::as_array) else {
                    continue;
                };
                for s in schemes {
                    if let Some(text) = s.as_string() {
                        out.push(text.to_owned());
                    }
                }
            }
            out
        })
        .unwrap_or_default();

    Ok(InfoPlistSummary {
        bundle_identifier: string_value(dict, "CFBundleIdentifier"),
        bundle_name: string_value(dict, "CFBundleName"),
        bundle_display_name: string_value(dict, "CFBundleDisplayName"),
        bundle_executable: string_value(dict, "CFBundleExecutable"),
        short_version: string_value(dict, "CFBundleShortVersionString"),
        bundle_version: string_value(dict, "CFBundleVersion"),
        minimum_os_version: string_value(dict, "MinimumOSVersion")
            .or_else(|| string_value(dict, "LSMinimumSystemVersion")),
        supported_platforms,
        device_family,
        url_schemes,
        raw_keys,
    })
}

fn string_value(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key).and_then(Value::as_string).map(str::to_owned)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementsDecode {
    pub xml_blob: String,
    pub keys: Vec<String>,
    pub typed: BTreeMap<String, EntitlementValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntitlementValue {
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<Self>),
    Dict(BTreeMap<String, Self>),
    Other(String),
}

const ENTITLEMENTS_BLOB_MAGIC: u32 = 0xFADE_7171;
const ENTITLEMENTS_DER_MAGIC: u32 = 0xFADE_7172;

pub fn decode_entitlements_from_code_signature(blob: &[u8]) -> Result<EntitlementsDecode> {
    let xml_bytes: &[u8] = locate_entitlements_xml(blob).ok_or(Error::NoEntitlementsBlob)?;
    let xml: String = String::from_utf8_lossy(xml_bytes).into_owned();
    let value: Value = Value::from_reader_xml(Cursor::new(xml_bytes))
        .map_err(|e: plist::Error| Error::Plist(e.to_string()))?;
    let dict: &plist::Dictionary = value
        .as_dictionary()
        .ok_or_else(|| Error::Plist("entitlements not a dictionary".to_owned()))?;
    let mut typed: BTreeMap<String, EntitlementValue> = BTreeMap::new();
    let mut keys: Vec<String> = Vec::with_capacity(dict.len());
    for (k, v) in dict {
        keys.push(k.clone());
        typed.insert(k.clone(), convert_value(v));
    }
    keys.sort();
    Ok(EntitlementsDecode {
        xml_blob: xml,
        keys,
        typed,
    })
}

pub fn decode_entitlements_xml(bytes: &[u8]) -> Result<EntitlementsDecode> {
    let value: Value = Value::from_reader_xml(Cursor::new(bytes))
        .map_err(|e: plist::Error| Error::Plist(e.to_string()))?;
    let dict: &plist::Dictionary = value
        .as_dictionary()
        .ok_or_else(|| Error::Plist("entitlements not a dictionary".to_owned()))?;
    let mut typed: BTreeMap<String, EntitlementValue> = BTreeMap::new();
    let mut keys: Vec<String> = Vec::with_capacity(dict.len());
    for (k, v) in dict {
        keys.push(k.clone());
        typed.insert(k.clone(), convert_value(v));
    }
    keys.sort();
    Ok(EntitlementsDecode {
        xml_blob: String::from_utf8_lossy(bytes).into_owned(),
        keys,
        typed,
    })
}

fn convert_value(v: &Value) -> EntitlementValue {
    if let Some(b) = v.as_boolean() {
        return EntitlementValue::Bool(b);
    }
    if let Some(i) = v.as_signed_integer() {
        return EntitlementValue::Integer(i);
    }
    if let Some(s) = v.as_string() {
        return EntitlementValue::String(s.to_owned());
    }
    if let Some(arr) = v.as_array() {
        return EntitlementValue::Array(arr.iter().map(convert_value).collect());
    }
    if let Some(d) = v.as_dictionary() {
        let mut out: BTreeMap<String, EntitlementValue> = BTreeMap::new();
        for (k, val) in d {
            out.insert(k.clone(), convert_value(val));
        }
        return EntitlementValue::Dict(out);
    }
    EntitlementValue::Other(format!("{v:?}"))
}

fn locate_entitlements_xml(blob: &[u8]) -> Option<&[u8]> {
    let mut cursor: usize = 0;
    while cursor + 8 <= blob.len() {
        let magic_arr: [u8; 4] = [
            blob[cursor],
            blob[cursor + 1],
            blob[cursor + 2],
            blob[cursor + 3],
        ];
        let magic: u32 = u32::from_be_bytes(magic_arr);
        if magic == ENTITLEMENTS_BLOB_MAGIC {
            let len_arr: [u8; 4] = [
                blob[cursor + 4],
                blob[cursor + 5],
                blob[cursor + 6],
                blob[cursor + 7],
            ];
            let len: usize = u32::from_be_bytes(len_arr) as usize;
            let start: usize = cursor + 8;
            let end: usize = cursor + len;
            if end > blob.len() || start > end {
                return None;
            }
            return Some(&blob[start..end]);
        }
        if magic == ENTITLEMENTS_DER_MAGIC {
            cursor += 8;
            continue;
        }
        cursor += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn locate_entitlements_xml_finds_blob() {
        let mut framed: Vec<u8> = Vec::new();
        framed.extend_from_slice(b"\x00\x00\x00\x10pad__\x00\x00");
        let xml: &[u8] = b"<plist><dict></dict></plist>";
        let len: u32 = u32::try_from(xml.len() + 8).expect("test fixture fits in u32");
        framed.extend_from_slice(&ENTITLEMENTS_BLOB_MAGIC.to_be_bytes());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(xml);
        let recovered: &[u8] = locate_entitlements_xml(&framed).expect("found");
        assert_eq!(recovered, xml);
    }
}
