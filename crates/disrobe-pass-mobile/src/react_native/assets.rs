use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::arsc::{ArscEntry, ArscResources};

pub(crate) const PACKAGER_MARKER: &str = "__packager_asset";
pub(crate) const MAX_ASSET_LITERAL_KEYS: usize = 64;
pub(crate) const MAX_SCALES: usize = 16;
const MAX_SOURCE_RECORDS: usize = 1 << 16;
const MAX_RECORD_BYTES: usize = 1 << 13;
const MAX_VALUE_DEPTH: usize = 16;
const MODULE_TAIL_WINDOW: usize = 64;

const ANDROID_DRAWABLE_TYPES: [&str; 9] = [
    "gif", "heic", "heif", "jpeg", "jpg", "ktx", "png", "webp", "xml",
];
const IOS_SCALES: [f64; 3] = [1.0, 2.0, 3.0];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RnAsset {
    pub hermes_function: Option<usize>,
    pub source_offset: Option<usize>,
    pub metro_module: Option<u64>,
    pub http_server_location: String,
    pub name: String,
    pub file_type: String,
    pub hash: Option<String>,
    pub width: Option<f64>,
    pub height: Option<f64>,
    pub scales: Vec<f64>,
}

impl RnAsset {
    #[must_use]
    pub fn android_resource_identifier(&self) -> String {
        let base: &str = self
            .http_server_location
            .strip_prefix('/')
            .unwrap_or(&self.http_server_location);
        let joined: String = format!("{base}/{}", self.name)
            .to_lowercase()
            .replace('/', "_");
        let cleaned: String = joined
            .chars()
            .filter(|c: &char| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        for prefix in ["assets_", "assetsunstable_path_"] {
            if let Some(rest) = cleaned.strip_prefix(prefix) {
                return rest.to_owned();
            }
        }
        cleaned
    }

    #[must_use]
    pub fn android_resource_paths(&self) -> Vec<String> {
        let identifier: String = self.android_resource_identifier();
        let drawable: bool = ANDROID_DRAWABLE_TYPES.contains(&self.file_type.as_str());
        let mut paths: Vec<String> = Vec::new();
        for scale in &self.scales {
            let folder: Option<String> = if drawable {
                android_density(*scale).map(|density: String| format!("drawable-{density}"))
            } else {
                Some("raw".to_owned())
            };
            if let Some(folder) = folder {
                push_unique(
                    &mut paths,
                    format!("res/{folder}/{identifier}.{}", self.file_type),
                );
            }
        }
        paths
    }

    #[must_use]
    pub fn ios_resource_paths(&self) -> Vec<String> {
        let directory: String = self
            .http_server_location
            .chars()
            .skip(1)
            .collect::<String>()
            .replace("../", "_");
        let mut paths: Vec<String> = Vec::new();
        for scale in ios_scales(&self.scales) {
            let suffix: String = if scale.to_bits() == 1.0_f64.to_bits() {
                String::new()
            } else {
                match js_number(scale) {
                    Some(text) => format!("@{text}x"),
                    None => continue,
                }
            };
            let file: String = format!("{}{suffix}.{}", self.name, self.file_type);
            push_unique(&mut paths, posix_join(&directory, &file));
        }
        paths
    }
}

fn push_unique(paths: &mut Vec<String>, path: String) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

fn ios_scales(scales: &[f64]) -> Vec<f64> {
    let allowed: Vec<f64> = scales
        .iter()
        .copied()
        .filter(|scale: &f64| {
            IOS_SCALES
                .iter()
                .any(|known: &f64| known.to_bits() == scale.to_bits())
        })
        .collect();
    if !allowed.is_empty() || scales.is_empty() {
        return allowed;
    }
    let largest_allowed: f64 = IOS_SCALES[IOS_SCALES.len() - 1];
    let chosen: Option<f64> = scales
        .iter()
        .copied()
        .find(|scale: &f64| *scale > largest_allowed)
        .or_else(|| scales.last().copied());
    let Some(chosen) = chosen else {
        return Vec::new();
    };
    scales
        .iter()
        .copied()
        .filter(|scale: &f64| scale.to_bits() == chosen.to_bits())
        .collect()
}

fn js_number(value: f64) -> Option<String> {
    if !value.is_finite() || value.abs() >= 1e21 || (value != 0.0 && value.abs() < 1e-6) {
        return None;
    }
    Some(format!("{value}"))
}

fn posix_join(directory: &str, file: &str) -> String {
    let joined: String = if directory.is_empty() {
        file.to_owned()
    } else {
        format!("{directory}/{file}")
    };
    if joined.is_empty() {
        return ".".to_owned();
    }
    let absolute: bool = joined.starts_with('/');
    let trailing: bool = joined.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for segment in joined.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last: &&str| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let mut normalized: String = parts.join("/");
    if normalized.is_empty() && !absolute {
        normalized.push('.');
    }
    if !normalized.is_empty() && trailing {
        normalized.push('/');
    }
    if absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

fn android_density(scale: f64) -> Option<String> {
    let named: [(f64, &str); 6] = [
        (0.75, "ldpi"),
        (1.0, "mdpi"),
        (1.5, "hdpi"),
        (2.0, "xhdpi"),
        (3.0, "xxhdpi"),
        (4.0, "xxxhdpi"),
    ];
    if let Some((_, name)) = named
        .iter()
        .find(|(value, _): &&(f64, &str)| value.to_bits() == scale.to_bits())
    {
        return Some((*name).to_owned());
    }
    if scale.is_finite() && scale > 0.0 {
        let dpi: f64 = (scale * 160.0).round();
        if dpi <= f64::from(u32::MAX) {
            return Some(format!("{}dpi", dpi as u32));
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RnAssetFile {
    pub path: String,
    pub entry: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RnPackagedAsset {
    pub bundle: String,
    pub asset: RnAsset,
    pub files: Vec<RnAssetFile>,
}

struct AndroidFiles<'a> {
    entries: &'a BTreeSet<String>,
    by_key: BTreeMap<(&'a str, &'a str), Vec<&'a ArscEntry>>,
}

impl<'a> AndroidFiles<'a> {
    fn new(entries: &'a BTreeSet<String>, resources: Option<&'a ArscResources>) -> Self {
        let mut by_key: BTreeMap<(&'a str, &'a str), Vec<&'a ArscEntry>> = BTreeMap::new();
        for entry in resources
            .into_iter()
            .flat_map(|table: &'a ArscResources| table.packages.iter())
            .flat_map(|package| package.entries.iter())
            .filter(|entry: &&ArscEntry| matches!(entry.type_name.as_str(), "drawable" | "raw"))
        {
            by_key
                .entry((entry.type_name.as_str(), entry.key_name.as_str()))
                .or_default()
                .push(entry);
        }
        Self { entries, by_key }
    }

    fn locate(&self, resource_path: &str) -> Option<String> {
        if self.entries.contains(resource_path) {
            return Some(resource_path.to_owned());
        }
        let (folder, file): (&str, &str) = resource_path.strip_prefix("res/")?.split_once('/')?;
        let versioned: String = format!("res/{folder}-v");
        let tail: String = format!("/{file}");
        let qualified: Option<&String> = self
            .entries
            .range(versioned.clone()..)
            .take_while(|entry: &&String| entry.starts_with(&versioned))
            .find(|entry: &&String| {
                entry
                    .strip_prefix(&versioned)
                    .and_then(|rest: &str| rest.strip_suffix(&tail))
                    .is_some_and(|sdk: &str| {
                        !sdk.is_empty() && sdk.bytes().all(|b: u8| b.is_ascii_digit())
                    })
            });
        if let Some(entry) = qualified {
            return Some(entry.clone());
        }
        let (type_name, density): (&str, Option<&str>) = match folder.split_once('-') {
            Some((type_name, density)) => (type_name, Some(density)),
            None => (folder, None),
        };
        let (key, extension): (&str, &str) = file.rsplit_once('.')?;
        let dotted: String = format!(".{extension}");
        self.by_key
            .get(&(type_name, key))?
            .iter()
            .filter(|entry: &&&ArscEntry| config_density_matches(&entry.config, density))
            .filter_map(|entry: &&ArscEntry| entry.value.as_deref())
            .find(|value: &&str| value.ends_with(&dotted) && self.entries.contains(*value))
            .map(str::to_owned)
    }
}

fn config_density_matches(config: &str, density: Option<&str>) -> bool {
    let mut qualifiers = config.split('-');
    match density {
        Some(density) => qualifiers.any(|qualifier: &str| qualifier == density),
        None => !qualifiers.any(|qualifier: &str| qualifier.ends_with("dpi")),
    }
}

#[must_use]
pub fn locate_android_assets(
    bundle: &str,
    assets: Vec<RnAsset>,
    entries: &BTreeSet<String>,
    resources: Option<&ArscResources>,
) -> Vec<RnPackagedAsset> {
    let packaged: AndroidFiles<'_> = AndroidFiles::new(entries, resources);
    assets
        .into_iter()
        .map(|asset: RnAsset| {
            let files: Vec<RnAssetFile> = asset
                .android_resource_paths()
                .into_iter()
                .map(|path: String| RnAssetFile {
                    entry: packaged.locate(&path),
                    path,
                })
                .collect();
            RnPackagedAsset {
                bundle: bundle.to_owned(),
                asset,
                files,
            }
        })
        .collect()
}

#[must_use]
pub fn locate_ios_assets(
    bundle: &str,
    assets: Vec<RnAsset>,
    entries: &BTreeSet<String>,
) -> Vec<RnPackagedAsset> {
    let app: &str = bundle.rsplit_once('/').map_or("", |(app, _)| app);
    assets
        .into_iter()
        .map(|asset: RnAsset| {
            let files: Vec<RnAssetFile> = asset
                .ios_resource_paths()
                .into_iter()
                .map(|path: String| {
                    let entry: String = if app.is_empty() {
                        path.clone()
                    } else {
                        format!("{app}/{path}")
                    };
                    RnAssetFile {
                        entry: entries.contains(&entry).then_some(entry),
                        path,
                    }
                })
                .collect();
            RnPackagedAsset {
                bundle: bundle.to_owned(),
                asset,
                files,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Known {
    Text(String),
    Number(f64),
    Bool(bool),
    Numbers(Vec<f64>),
}

fn field_text(fields: &BTreeMap<String, Known>, key: &str) -> Option<String> {
    match fields.get(key) {
        Some(Known::Text(text)) => Some(text.clone()),
        _ => None,
    }
}

fn field_number(fields: &BTreeMap<String, Known>, key: &str) -> Option<f64> {
    match fields.get(key) {
        Some(Known::Number(n)) => Some(*n),
        _ => None,
    }
}

pub(crate) struct AssetSite {
    pub hermes_function: Option<usize>,
    pub source_offset: Option<usize>,
    pub metro_module: Option<u64>,
}

pub(crate) fn asset_from_fields(
    fields: &BTreeMap<String, Known>,
    site: AssetSite,
) -> Option<RnAsset> {
    if !matches!(fields.get(PACKAGER_MARKER), Some(Known::Bool(true))) {
        return None;
    }
    let scales: Vec<f64> = match fields.get("scales") {
        Some(Known::Numbers(scales)) => scales.clone(),
        _ => Vec::new(),
    };
    Some(RnAsset {
        hermes_function: site.hermes_function,
        source_offset: site.source_offset,
        metro_module: site.metro_module,
        http_server_location: field_text(fields, "httpServerLocation")?,
        name: field_text(fields, "name")?,
        file_type: field_text(fields, "type")?,
        hash: field_text(fields, "hash"),
        width: field_number(fields, "width"),
        height: field_number(fields, "height"),
        scales,
    })
}

#[must_use]
pub fn source_assets(source: &[u8]) -> Vec<RnAsset> {
    let marker: &[u8] = PACKAGER_MARKER.as_bytes();
    let mut out: Vec<RnAsset> = Vec::new();
    let mut from: usize = 0;
    while out.len() < MAX_SOURCE_RECORDS {
        let Some(found) = find(source, marker, from) else {
            break;
        };
        from = found + marker.len();
        let Some(open) = record_start(source, found) else {
            continue;
        };
        let mut parser: Parser<'_> = Parser {
            bytes: source,
            at: open,
            limit: source.len().min(open.saturating_add(MAX_RECORD_BYTES)),
        };
        let Some(fields) = parser.object() else {
            continue;
        };
        let site: AssetSite = AssetSite {
            hermes_function: None,
            source_offset: Some(open),
            metro_module: module_after(source, parser.at),
        };
        if let Some(asset) = asset_from_fields(&fields, site) {
            from = from.max(parser.at);
            out.push(asset);
        }
    }
    out
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
        .map(|at: usize| at + from)
}

fn record_start(source: &[u8], key: usize) -> Option<usize> {
    let mut at: usize = key;
    if at > 0 && matches!(source[at - 1], b'"' | b'\'') {
        at -= 1;
    }
    while at > 0 && source[at - 1].is_ascii_whitespace() {
        at -= 1;
    }
    (at > 0 && source[at - 1] == b'{').then(|| at - 1)
}

fn module_after(source: &[u8], end: usize) -> Option<u64> {
    let window: &[u8] = source.get(end..source.len().min(end + MODULE_TAIL_WINDOW))?;
    let mut tail: Parser<'_> = Parser {
        bytes: window,
        at: 0,
        limit: window.len(),
    };
    if !tail.eat(b')') {
        return None;
    }
    tail.eat(b';');
    if !tail.eat(b'}') || !tail.eat(b',') {
        return None;
    }
    tail.space();
    let start: usize = tail.at;
    while tail.peek().is_some_and(|b: u8| b.is_ascii_digit()) {
        tail.at += 1;
    }
    let digits: &[u8] = &window[start..tail.at];
    if digits.is_empty() || digits.len() > 15 {
        return None;
    }
    tail.space();
    if !matches!(tail.peek(), Some(b',' | b')')) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    limit: usize,
}

enum Value {
    Known(Known),
    Other,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        (self.at < self.limit).then(|| self.bytes[self.at])
    }

    fn space(&mut self) {
        while self.peek().is_some_and(|b: u8| b.is_ascii_whitespace()) {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> bool {
        self.space();
        if self.peek() == Some(byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn object(&mut self) -> Option<BTreeMap<String, Known>> {
        if !self.eat(b'{') {
            return None;
        }
        let mut fields: BTreeMap<String, Known> = BTreeMap::new();
        if self.eat(b'}') {
            return Some(fields);
        }
        loop {
            if fields.len() >= MAX_ASSET_LITERAL_KEYS {
                return None;
            }
            let key: String = self.key()?;
            if !self.eat(b':') {
                return None;
            }
            if let Value::Known(value) = self.value(0)? {
                fields.insert(key, value);
            }
            if self.eat(b',') {
                if self.eat(b'}') {
                    return Some(fields);
                }
                continue;
            }
            return self.eat(b'}').then_some(fields);
        }
    }

    fn key(&mut self) -> Option<String> {
        self.space();
        match self.peek()? {
            b'"' | b'\'' => self.string(),
            b if b.is_ascii_alphabetic() || b == b'_' || b == b'$' => {
                let start: usize = self.at;
                while self
                    .peek()
                    .is_some_and(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
                {
                    self.at += 1;
                }
                std::str::from_utf8(&self.bytes[start..self.at])
                    .ok()
                    .map(str::to_owned)
            }
            _ => None,
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_VALUE_DEPTH {
            return None;
        }
        self.space();
        match self.peek()? {
            b'"' | b'\'' => self
                .string()
                .map(|text: String| Value::Known(Known::Text(text))),
            b'[' => self.array(depth),
            b'{' => {
                self.skip_balanced()?;
                Some(Value::Other)
            }
            b'!' => {
                self.at += 1;
                match self.peek()? {
                    b'0' => {
                        self.at += 1;
                        Some(Value::Known(Known::Bool(true)))
                    }
                    b'1' => {
                        self.at += 1;
                        Some(Value::Known(Known::Bool(false)))
                    }
                    _ => None,
                }
            }
            b'-' | b'.' | b'0'..=b'9' => self.number().map(|n: f64| Value::Known(Known::Number(n))),
            _ => {
                let start: usize = self.at;
                if let Some(value) = self.word() {
                    return Some(value);
                }
                self.at = start;
                self.skip_expression()?;
                Some(Value::Other)
            }
        }
    }

    fn skip_expression(&mut self) -> Option<()> {
        let mut depth: usize = 0;
        loop {
            match self.peek()? {
                b'"' | b'\'' => {
                    self.string()?;
                    continue;
                }
                b'{' | b'[' | b'(' => depth += 1,
                b',' | b'}' | b']' | b')' if depth == 0 => return Some(()),
                b'}' | b']' | b')' => depth -= 1,
                _ => {}
            }
            self.at += 1;
        }
    }

    fn word(&mut self) -> Option<Value> {
        let start: usize = self.at;
        while self
            .peek()
            .is_some_and(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
        {
            self.at += 1;
        }
        match &self.bytes[start..self.at] {
            b"true" => Some(Value::Known(Known::Bool(true))),
            b"false" => Some(Value::Known(Known::Bool(false))),
            b"null" | b"undefined" => Some(Value::Other),
            _ => None,
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        self.at += 1;
        let mut numbers: Option<Vec<f64>> = Some(Vec::new());
        if self.eat(b']') {
            return Some(Value::Known(Known::Numbers(Vec::new())));
        }
        loop {
            match self.value(depth + 1)? {
                Value::Known(Known::Number(n)) => {
                    if let Some(list) = numbers.as_mut() {
                        list.push(n);
                    }
                }
                _ => numbers = None,
            }
            if numbers
                .as_ref()
                .is_some_and(|list: &Vec<f64>| list.len() > MAX_SCALES)
            {
                numbers = None;
            }
            if self.eat(b',') {
                continue;
            }
            if !self.eat(b']') {
                return None;
            }
            return Some(match numbers {
                Some(list) => Value::Known(Known::Numbers(list)),
                None => Value::Other,
            });
        }
    }

    fn skip_balanced(&mut self) -> Option<()> {
        let mut depth: usize = 0;
        loop {
            match self.peek()? {
                b'"' | b'\'' => {
                    self.string()?;
                    continue;
                }
                b'{' | b'[' | b'(' => depth += 1,
                b'}' | b']' | b')' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        self.at += 1;
                        return Some(());
                    }
                }
                _ => {}
            }
            self.at += 1;
        }
    }

    fn number(&mut self) -> Option<f64> {
        let negative: bool = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        let start: usize = self.at;
        if self
            .bytes
            .get(start..start + 2)
            .is_some_and(|p: &[u8]| p.eq_ignore_ascii_case(b"0x"))
        {
            self.at += 2;
            let digits: usize = self.at;
            while self.peek().is_some_and(|b: u8| b.is_ascii_hexdigit()) {
                self.at += 1;
            }
            let text: &str = std::str::from_utf8(&self.bytes[digits..self.at]).ok()?;
            let value: f64 = u64::from_str_radix(text, 16).ok()? as f64;
            return Some(if negative { -value } else { value });
        }
        while self
            .peek()
            .is_some_and(|b: u8| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E'))
        {
            let exponent: bool = matches!(self.bytes[self.at], b'e' | b'E');
            self.at += 1;
            if exponent && matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
        }
        let text: &str = std::str::from_utf8(&self.bytes[start..self.at]).ok()?;
        let value: f64 = text.parse().ok()?;
        Some(if negative { -value } else { value })
    }

    fn string(&mut self) -> Option<String> {
        let quote: u8 = self.peek()?;
        self.at += 1;
        let mut units: Vec<u16> = Vec::new();
        loop {
            let byte: u8 = self.peek()?;
            match byte {
                b'\\' => {
                    self.at += 1;
                    self.escape(&mut units)?;
                }
                b'\n' | b'\r' => return None,
                _ if byte == quote => {
                    self.at += 1;
                    return String::from_utf16(&units).ok();
                }
                _ => {
                    let c: char = self.next_char()?;
                    let mut buffer: [u16; 2] = [0; 2];
                    units.extend_from_slice(c.encode_utf16(&mut buffer));
                    self.at += c.len_utf8();
                }
            }
        }
    }

    fn next_char(&self) -> Option<char> {
        let lead: u8 = self.peek()?;
        let width: usize = match lead {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => return None,
        };
        if self.at + width > self.limit {
            return None;
        }
        std::str::from_utf8(&self.bytes[self.at..self.at + width])
            .ok()?
            .chars()
            .next()
    }

    fn escape(&mut self, units: &mut Vec<u16>) -> Option<()> {
        let byte: u8 = self.peek()?;
        self.at += 1;
        let unit: u16 = match byte {
            b'n' => 0x0a,
            b't' => 0x09,
            b'r' => 0x0d,
            b'b' => 0x08,
            b'f' => 0x0c,
            b'v' => 0x0b,
            b'0' => {
                if self.peek().is_some_and(|b: u8| b.is_ascii_digit()) {
                    return None;
                }
                0
            }
            b'x' => u16::from(self.hex(2)? as u8),
            b'u' => {
                if self.peek() == Some(b'{') {
                    self.at += 1;
                    let start: usize = self.at;
                    while self.peek().is_some_and(|b: u8| b.is_ascii_hexdigit()) {
                        self.at += 1;
                    }
                    let text: &str = std::str::from_utf8(&self.bytes[start..self.at]).ok()?;
                    if text.is_empty() || text.len() > 6 || self.peek() != Some(b'}') {
                        return None;
                    }
                    self.at += 1;
                    let c: char = char::from_u32(u32::from_str_radix(text, 16).ok()?)?;
                    let mut buffer: [u16; 2] = [0; 2];
                    units.extend_from_slice(c.encode_utf16(&mut buffer));
                    return Some(());
                }
                self.hex(4)?
            }
            b'\r' => {
                if self.peek() == Some(b'\n') {
                    self.at += 1;
                }
                return Some(());
            }
            b'\n' => return Some(()),
            b'1'..=b'9' => return None,
            other if other.is_ascii() => u16::from(other),
            _ => {
                self.at -= 1;
                return Some(());
            }
        };
        units.push(unit);
        Some(())
    }

    fn hex(&mut self, count: usize) -> Option<u16> {
        let digits: &[u8] = self.bytes.get(self.at..self.at + count)?;
        if self.at + count > self.limit || !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        self.at += count;
        u16::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
    }
}
