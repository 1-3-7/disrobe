use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use disrobe_bytes::{
    ByteReadError, read_bytes_at, read_f32_le_at, read_f64_le_at, read_u8_at, read_u16_le_at,
    read_u32_be_at, read_u32_le_at,
};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const BOM_MAGIC: &[u8; 8] = b"BOMStore";
const BOM_HEADER_LEN: usize = 32;
const MAX_BLOCKS: usize = 1 << 20;
const MAX_VARIABLES: usize = 1024;
const MAX_TREE_DEPTH: usize = 32;
const MAX_TREE_ENTRIES: usize = 1 << 20;
const CAR_HEADER_LEN: usize = 436;
const CAR_HEADER_TAG: &[u8; 4] = b"RATC";
const KEY_FORMAT_TAG: &[u8; 4] = b"tmfk";
const METADATA_TAG: &[u8; 4] = b"META";
const METADATA_FIELD_LEN: usize = 256;
const CSI_TAG: &[u8; 4] = b"ISTC";
const CSI_HEADER_LEN: usize = 184;
const CSI_NAME_AT: usize = 40;
const CSI_NAME_LEN: usize = 128;
const MAX_KEY_TOKENS: usize = 64;
const MAX_TLVS: usize = 256;
const MAX_COLOR_COMPONENTS: usize = 16;
const MAX_MULTISIZE_ENTRIES: usize = 4096;
const MAX_CHUNKS: usize = 1 << 16;

const ATTRIBUTE_APPEARANCE: u16 = 7;
const ATTRIBUTE_SCALE: u16 = 12;
const ATTRIBUTE_IDIOM: u16 = 15;
const ATTRIBUTE_PART: u16 = 2;

const TLV_BLEND_AND_OPACITY: u32 = 0x3EC;
const TLV_UTI: u32 = 0x3ED;
const TLV_EXIF_ORIENTATION: u32 = 0x3EE;
const TLV_BYTES_PER_ROW: u32 = 0x3EF;
const TLV_INTERNAL_LINK: u32 = 0x3F2;
const LINK_TAG: &[u8; 4] = b"KLNI";
const PART_APP_ICON: u16 = 220;

const COMPRESSIONS: [&str; 12] = [
    "uncompressed",
    "rle",
    "zip",
    "lzvn",
    "lzfse",
    "jpeg-lzfse",
    "blurred",
    "astc",
    "palette-img",
    "hevc",
    "deepmap-lzfse",
    "deepmap2",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogHeader {
    pub core_ui_version: u32,
    pub storage_version: u32,
    pub storage_timestamp: u32,
    pub rendition_count: u32,
    pub main_version: String,
    pub version: String,
    pub uuid: String,
    pub associated_checksum: u32,
    pub schema_version: u32,
    pub color_space_id: u32,
    pub key_semantics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogMetadata {
    pub thinning_arguments: String,
    pub deployment_platform_version: String,
    pub deployment_platform: String,
    pub authoring_tool: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Facet {
    pub name: String,
    pub hot_spot: [u16; 2],
    pub attributes: BTreeMap<String, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenditionTlv {
    pub kind: u32,
    pub name: String,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultisizeEntry {
    pub width: u32,
    pub height: u32,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RenditionPayload {
    Pixels {
        compression: String,
        version: u32,
        length: usize,
        chunks: usize,
    },
    Color {
        color_space_id: u32,
        components: Vec<f64>,
    },
    Data {
        compression: String,
        flags: u32,
        length: usize,
        sha256: String,
    },
    MultisizeImageSet {
        sizes: Vec<MultisizeEntry>,
    },
    Other {
        tag: String,
        name: String,
        length: usize,
    },
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InternalLink {
    pub frame: [u32; 4],
    pub layout: u16,
    pub key: BTreeMap<String, u16>,
    pub target: Option<usize>,
    pub target_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rendition {
    pub asset: Option<String>,
    pub name: String,
    pub kind: String,
    pub key: BTreeMap<String, u16>,
    pub idiom: Option<String>,
    pub scale: Option<u16>,
    pub appearance: Option<String>,
    pub csi_version: u32,
    pub flags: u32,
    pub width: u32,
    pub height: u32,
    pub scale_factor: u32,
    pub pixel_format: String,
    pub encoding: Option<String>,
    pub color_space_id: u32,
    pub color_space: Option<String>,
    pub layout: u16,
    pub layout_name: String,
    pub tlvs: Vec<RenditionTlv>,
    pub bytes_per_row: Option<u32>,
    pub uti: Option<String>,
    pub exif_orientation: Option<u32>,
    pub blend_mode: Option<u32>,
    pub opacity: Option<f32>,
    pub internal_link: Option<InternalLink>,
    pub payload: RenditionPayload,
    pub size_on_disk: usize,
    pub sha1: String,
    pub sha256: String,
    pub trailing_bytes: usize,
    #[serde(skip)]
    pub data_span: Option<Range<usize>>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssetCatalog {
    pub bom_version: u32,
    pub block_count: usize,
    pub variables: BTreeMap<String, u32>,
    pub header: CatalogHeader,
    pub metadata: Option<CatalogMetadata>,
    pub key_format: Vec<String>,
    pub appearances: BTreeMap<String, u16>,
    pub facets: Vec<Facet>,
    pub bitmap_keys: usize,
    pub renditions: Vec<Rendition>,
}

const fn malformed(message: String) -> Error {
    Error::AssetCatalog(message)
}

fn field<T>(result: core::result::Result<T, ByteReadError>, what: &str) -> Result<T> {
    result.map_err(|error: ByteReadError| malformed(format!("{what}: {error}")))
}

fn addressable(value: u32, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| malformed(format!("{what} {value} is not addressable")))
}

fn hex(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 0xf)]));
    }
    out
}

fn fixed_string(bytes: &[u8], what: &str) -> Result<String> {
    let end: usize = bytes
        .iter()
        .position(|byte: &u8| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| malformed(format!("{what} is not UTF-8")))
}

fn fourcc(tag: &[u8]) -> String {
    tag.iter()
        .rev()
        .map(|byte: &u8| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '?'
            }
        })
        .collect()
}

#[must_use]
pub fn is_asset_catalog(bytes: &[u8]) -> bool {
    bytes.starts_with(BOM_MAGIC)
        && decode_bom(bytes).is_ok_and(|bom: Bom<'_>| bom.variables.contains_key("CARHEADER"))
}

struct Bom<'a> {
    bytes: &'a [u8],
    version: u32,
    blocks: Vec<Range<usize>>,
    variables: BTreeMap<String, u32>,
}

fn decode_bom(bytes: &[u8]) -> Result<Bom<'_>> {
    if !bytes.starts_with(BOM_MAGIC) {
        return Err(malformed(
            "the file does not start with BOMStore".to_owned(),
        ));
    }
    if bytes.len() < BOM_HEADER_LEN {
        return Err(malformed(format!(
            "BOM header needs {BOM_HEADER_LEN} bytes, file has {}",
            bytes.len()
        )));
    }
    let version: u32 = field(read_u32_be_at(bytes, 8), "BOM version")?;
    let index_at: usize = addressable(
        field(read_u32_be_at(bytes, 16), "BOM index offset")?,
        "BOM index offset",
    )?;
    let index_len: usize = addressable(
        field(read_u32_be_at(bytes, 20), "BOM index length")?,
        "BOM index length",
    )?;
    let vars_at: usize = addressable(
        field(read_u32_be_at(bytes, 24), "BOM variables offset")?,
        "BOM variables offset",
    )?;
    let vars_len: usize = addressable(
        field(read_u32_be_at(bytes, 28), "BOM variables length")?,
        "BOM variables length",
    )?;
    let index: &[u8] = field(read_bytes_at(bytes, index_at, index_len), "BOM block index")?;
    let count: usize = addressable(
        field(read_u32_be_at(index, 0), "BOM block count")?,
        "BOM block count",
    )?;
    if count > MAX_BLOCKS || count.saturating_mul(8).saturating_add(4) > index.len() {
        return Err(malformed(format!(
            "BOM block count {count} does not fit its {}-byte index",
            index.len()
        )));
    }
    let mut blocks: Vec<Range<usize>> = Vec::with_capacity(count);
    for slot in 0..count {
        let at: usize = 4 + slot * 8;
        let offset: usize = addressable(
            field(read_u32_be_at(index, at), "BOM block offset")?,
            "BOM block offset",
        )?;
        let length: usize = addressable(
            field(read_u32_be_at(index, at + 4), "BOM block length")?,
            "BOM block length",
        )?;
        let end: usize = offset
            .checked_add(length)
            .filter(|end: &usize| *end <= bytes.len())
            .ok_or_else(|| {
                malformed(format!(
                    "BOM block {slot} at {offset} with {length} bytes runs past the file"
                ))
            })?;
        blocks.push(offset..end);
    }
    let table: &[u8] = field(read_bytes_at(bytes, vars_at, vars_len), "BOM variables")?;
    let var_count: usize = addressable(
        field(read_u32_be_at(table, 0), "BOM variable count")?,
        "BOM variable count",
    )?;
    if var_count > MAX_VARIABLES {
        return Err(malformed(format!(
            "BOM declares {var_count} variables, more than {MAX_VARIABLES}"
        )));
    }
    let mut variables: BTreeMap<String, u32> = BTreeMap::new();
    let mut at: usize = 4;
    for _ in 0..var_count {
        let block: u32 = field(read_u32_be_at(table, at), "BOM variable block")?;
        let length: usize = usize::from(field(
            read_u8_at(table, at + 4),
            "BOM variable name length",
        )?);
        let name: &[u8] = field(read_bytes_at(table, at + 5, length), "BOM variable name")?;
        let name: String = std::str::from_utf8(name)
            .map_err(|_| malformed("BOM variable name is not UTF-8".to_owned()))?
            .to_owned();
        if addressable(block, "BOM variable block")? >= blocks.len() {
            return Err(malformed(format!(
                "BOM variable {name} names block {block} of {}",
                blocks.len()
            )));
        }
        if variables.insert(name.clone(), block).is_some() {
            return Err(malformed(format!("BOM variable {name} is declared twice")));
        }
        at += 5 + length;
    }
    Ok(Bom {
        bytes,
        version,
        blocks,
        variables,
    })
}

impl<'a> Bom<'a> {
    fn block(&self, index: u32, what: &str) -> Result<&'a [u8]> {
        let slot: usize = addressable(index, what)?;
        let range: &Range<usize> = self.blocks.get(slot).ok_or_else(|| {
            malformed(format!(
                "{what} names block {index}, the store has {}",
                self.blocks.len()
            ))
        })?;
        Ok(&self.bytes[range.clone()])
    }

    fn block_range(&self, index: u32, what: &str) -> Result<Range<usize>> {
        let slot: usize = addressable(index, what)?;
        self.blocks.get(slot).cloned().ok_or_else(|| {
            malformed(format!(
                "{what} names block {index}, the store has {}",
                self.blocks.len()
            ))
        })
    }

    fn variable(&self, name: &str) -> Option<u32> {
        self.variables.get(name).copied()
    }

    fn tree(&self, name: &str) -> Result<Vec<(u32, u32)>> {
        let Some(head_index) = self.variable(name) else {
            return Ok(Vec::new());
        };
        let head: &[u8] = self.block(head_index, name)?;
        if !head.starts_with(b"tree") {
            return Err(malformed(format!("{name} is not a BOM tree")));
        }
        let mut node: u32 = field(read_u32_be_at(head, 8), "tree root")?;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        let mut depth: usize = 0;
        loop {
            if !visited.insert(node) {
                return Err(malformed(format!("{name} tree revisits block {node}")));
            }
            let paths: &[u8] = self.block(node, name)?;
            let is_leaf: u16 = field(disrobe_bytes::read_u16_be_at(paths, 0), "tree node kind")?;
            if is_leaf != 0 {
                break;
            }
            depth += 1;
            if depth > MAX_TREE_DEPTH {
                return Err(malformed(format!(
                    "{name} tree is deeper than {MAX_TREE_DEPTH} levels"
                )));
            }
            node = field(read_u32_be_at(paths, 12), "tree branch child")?;
        }
        let mut entries: Vec<(u32, u32)> = Vec::new();
        loop {
            let paths: &[u8] = self.block(node, name)?;
            let count: usize = usize::from(field(
                disrobe_bytes::read_u16_be_at(paths, 2),
                "tree leaf count",
            )?);
            let forward: u32 = field(read_u32_be_at(paths, 4), "tree forward link")?;
            if 12 + count * 8 > paths.len() {
                return Err(malformed(format!(
                    "{name} leaf block {node} holds {count} entries in {} bytes",
                    paths.len()
                )));
            }
            if entries.len() + count > MAX_TREE_ENTRIES {
                return Err(malformed(format!(
                    "{name} tree holds more than {MAX_TREE_ENTRIES} entries"
                )));
            }
            for slot in 0..count {
                let value: u32 = field(read_u32_be_at(paths, 12 + slot * 8), "tree value")?;
                let key: u32 = field(read_u32_be_at(paths, 16 + slot * 8), "tree key")?;
                entries.push((value, key));
            }
            if forward == 0 {
                break;
            }
            if !visited.insert(forward) {
                return Err(malformed(format!("{name} tree revisits block {forward}")));
            }
            node = forward;
        }
        Ok(entries)
    }
}

fn attribute_name(id: u32) -> String {
    let name: Option<&str> = match id {
        0 => Some("look"),
        1 => Some("element"),
        2 => Some("part"),
        3 => Some("size"),
        4 => Some("direction"),
        5 => Some("placeholder"),
        6 => Some("value"),
        7 => Some("appearance"),
        8 => Some("dimension1"),
        9 => Some("dimension2"),
        10 => Some("state"),
        11 => Some("layer"),
        12 => Some("scale"),
        13 => Some("localization"),
        14 => Some("presentation-state"),
        15 => Some("idiom"),
        16 => Some("subtype"),
        17 => Some("identifier"),
        18 => Some("previous-value"),
        19 => Some("previous-state"),
        20 => Some("horizontal-size-class"),
        21 => Some("vertical-size-class"),
        22 => Some("memory-level-class"),
        23 => Some("graphics-feature-set-class"),
        24 => Some("display-gamut"),
        25 => Some("deployment-target"),
        26 => Some("glyph-weight"),
        27 => Some("glyph-size"),
        _ => None,
    };
    name.map_or_else(|| format!("attribute-{id}"), str::to_owned)
}

fn idiom_name(value: u16) -> String {
    let name: Option<&str> = match value {
        0 => Some("universal"),
        1 => Some("phone"),
        2 => Some("pad"),
        3 => Some("tv"),
        4 => Some("car"),
        5 => Some("watch"),
        6 => Some("marketing"),
        _ => None,
    };
    name.map_or_else(|| format!("idiom-{value}"), str::to_owned)
}

fn layout_name(layout: u16) -> String {
    let name: Option<&str> = match layout {
        7 => Some("text-effect"),
        9 => Some("vector"),
        10 => Some("one-part-fixed-size"),
        11 => Some("one-part-tile"),
        12 => Some("one-part-scale"),
        20 => Some("three-part-horizontal-tile"),
        21 => Some("three-part-horizontal-scale"),
        22 => Some("three-part-horizontal-uniform"),
        23 => Some("three-part-vertical-tile"),
        24 => Some("three-part-vertical-scale"),
        25 => Some("three-part-vertical-uniform"),
        30 => Some("nine-part-tile"),
        31 => Some("nine-part-scale"),
        32 => Some("nine-part-horizontal-uniform-vertical-scale"),
        33 => Some("nine-part-horizontal-scale-vertical-uniform"),
        34 => Some("nine-part-edges-only"),
        40 => Some("many-part"),
        50 => Some("animation-filmstrip"),
        1000 => Some("data"),
        1001 => Some("external-link"),
        1002 => Some("layer-stack"),
        1003 => Some("internal-reference"),
        1004 => Some("packed-image"),
        1005 => Some("name-list"),
        1007 => Some("texture"),
        1008 => Some("texture-image"),
        1009 => Some("color"),
        1010 => Some("multisize-image-set"),
        1012 => Some("layer-reference"),
        1013 => Some("content-rendition"),
        1014 => Some("recognition-object"),
        _ => None,
    };
    name.map_or_else(|| format!("layout-{layout}"), str::to_owned)
}

fn tlv_name(kind: u32) -> String {
    let name: Option<&str> = match kind {
        0x3E9 => Some("slices"),
        0x3EB => Some("metrics"),
        TLV_BLEND_AND_OPACITY => Some("blend-mode-and-opacity"),
        TLV_UTI => Some("uti"),
        TLV_EXIF_ORIENTATION => Some("exif-orientation"),
        TLV_BYTES_PER_ROW => Some("bytes-per-row"),
        0x3F0 => Some("external-tags"),
        0x3F1 => Some("frame"),
        TLV_INTERNAL_LINK => Some("internal-link"),
        _ => None,
    };
    name.map_or_else(|| format!("tlv-{kind:#x}"), str::to_owned)
}

fn compression_name(kind: u32) -> String {
    usize::try_from(kind)
        .ok()
        .and_then(|slot: usize| COMPRESSIONS.get(slot))
        .map_or_else(
            || format!("compression-{kind}"),
            |name: &&str| (*name).to_owned(),
        )
}

fn decode_header(block: &[u8]) -> Result<CatalogHeader> {
    if block.len() < CAR_HEADER_LEN || !block.starts_with(CAR_HEADER_TAG) {
        return Err(malformed(format!(
            "CARHEADER needs the CTAR tag and {CAR_HEADER_LEN} bytes, block has {}",
            block.len()
        )));
    }
    let word = |at: usize, what: &str| -> Result<u32> { field(read_u32_le_at(block, at), what) };
    Ok(CatalogHeader {
        core_ui_version: word(4, "CoreUI version")?,
        storage_version: word(8, "storage version")?,
        storage_timestamp: word(12, "storage timestamp")?,
        rendition_count: word(16, "rendition count")?,
        main_version: fixed_string(&block[20..148], "main version")?,
        version: fixed_string(&block[148..404], "version string")?,
        uuid: hex(&block[404..420]),
        associated_checksum: word(420, "associated checksum")?,
        schema_version: word(424, "schema version")?,
        color_space_id: word(428, "colour space")?,
        key_semantics: word(432, "key semantics")?,
    })
}

fn decode_metadata(block: &[u8]) -> Result<CatalogMetadata> {
    if block.len() < 4 + 4 * METADATA_FIELD_LEN || !block.starts_with(METADATA_TAG) {
        return Err(malformed(format!(
            "EXTENDED_METADATA needs the META tag and {} bytes, block has {}",
            4 + 4 * METADATA_FIELD_LEN,
            block.len()
        )));
    }
    let text = |slot: usize, what: &str| -> Result<String> {
        let at: usize = 4 + slot * METADATA_FIELD_LEN;
        fixed_string(&block[at..at + METADATA_FIELD_LEN], what)
    };
    Ok(CatalogMetadata {
        thinning_arguments: text(0, "thinning arguments")?,
        deployment_platform_version: text(1, "deployment platform version")?,
        deployment_platform: text(2, "deployment platform")?,
        authoring_tool: text(3, "authoring tool")?,
    })
}

fn decode_key_format(block: &[u8]) -> Result<Vec<u32>> {
    if !block.starts_with(KEY_FORMAT_TAG) {
        return Err(malformed("KEYFORMAT lacks the kfmt tag".to_owned()));
    }
    let count: usize = addressable(
        field(read_u32_le_at(block, 8), "key token count")?,
        "key token count",
    )?;
    if count > MAX_KEY_TOKENS {
        return Err(malformed(format!(
            "KEYFORMAT declares {count} tokens, more than {MAX_KEY_TOKENS}"
        )));
    }
    (0..count)
        .map(|slot: usize| field(read_u32_le_at(block, 12 + slot * 4), "key token"))
        .collect()
}

fn decode_facet(name: &[u8], value: &[u8]) -> Result<Facet> {
    let name: String = std::str::from_utf8(name)
        .map_err(|_| malformed("facet name is not UTF-8".to_owned()))?
        .to_owned();
    let hot_x: u16 = field(read_u16_le_at(value, 0), "facet hot spot")?;
    let hot_y: u16 = field(read_u16_le_at(value, 2), "facet hot spot")?;
    let count: usize = usize::from(field(read_u16_le_at(value, 4), "facet attribute count")?);
    if 6 + count * 4 > value.len() {
        return Err(malformed(format!(
            "facet {name} declares {count} attributes in {} bytes",
            value.len()
        )));
    }
    let mut attributes: BTreeMap<String, u16> = BTreeMap::new();
    for slot in 0..count {
        let id: u16 = field(read_u16_le_at(value, 6 + slot * 4), "facet attribute")?;
        let token: u16 = field(read_u16_le_at(value, 8 + slot * 4), "facet attribute value")?;
        attributes.insert(attribute_name(u32::from(id)), token);
    }
    Ok(Facet {
        name,
        hot_spot: [hot_x, hot_y],
        attributes,
    })
}

fn decode_key(key: &[u8], format: &[u32]) -> Result<BTreeMap<u32, u16>> {
    let needed: usize = format.len() * 2;
    if key.len() < needed || key[needed..].iter().any(|byte: &u8| *byte != 0) {
        return Err(malformed(format!(
            "rendition key has {} bytes for {} tokens",
            key.len(),
            format.len()
        )));
    }
    let mut out: BTreeMap<u32, u16> = BTreeMap::new();
    for (slot, id) in format.iter().enumerate() {
        out.insert(
            *id,
            field(read_u16_le_at(key, slot * 2), "rendition key token")?,
        );
    }
    Ok(out)
}

fn decode_internal_link(value: &[u8]) -> Result<InternalLink> {
    if field(read_bytes_at(value, 0, 4), "internal link tag")? != LINK_TAG {
        return Err(malformed("internal link lacks the INLK tag".to_owned()));
    }
    let mut frame: [u32; 4] = [0; 4];
    for (slot, part) in frame.iter_mut().enumerate() {
        *part = field(read_u32_le_at(value, 8 + slot * 4), "internal link frame")?;
    }
    let layout: u16 = field(read_u16_le_at(value, 24), "internal link layout")?;
    let key_len: usize = addressable(
        field(read_u32_le_at(value, 26), "internal link key length")?,
        "internal link key length",
    )?;
    if !key_len.is_multiple_of(4) || key_len > MAX_KEY_TOKENS * 4 {
        return Err(malformed(format!(
            "internal link key of {key_len} bytes is not a whole list of at most {MAX_KEY_TOKENS} attributes"
        )));
    }
    let pairs: &[u8] = field(read_bytes_at(value, 30, key_len), "internal link key")?;
    let mut key: BTreeMap<String, u16> = BTreeMap::new();
    for pair in pairs.chunks_exact(4) {
        let id: u16 = u16::from_le_bytes([pair[0], pair[1]]);
        let token: u16 = u16::from_le_bytes([pair[2], pair[3]]);
        if id == 0 && token == 0 {
            continue;
        }
        if key.insert(attribute_name(u32::from(id)), token).is_some() {
            return Err(malformed(format!(
                "internal link key names attribute {id} twice"
            )));
        }
    }
    Ok(InternalLink {
        frame,
        layout,
        key,
        target: None,
        target_name: None,
    })
}

fn encoding_name(pixel_format: &str) -> Option<String> {
    match pixel_format {
        "ARGB" => Some("ARGB".to_owned()),
        "GA8 " => Some("Gray".to_owned()),
        "DATA" => Some("Data".to_owned()),
        _ => None,
    }
}

fn color_space_name(id: u32) -> Option<String> {
    match id {
        1 => Some("srgb".to_owned()),
        2 => Some("gray gamma 22".to_owned()),
        _ => None,
    }
}

fn rendition_kind(layout: u16, part: Option<u16>) -> String {
    let kind: &str = match layout {
        1000 => "data",
        1004 => "packed-image",
        1009 => "color",
        1010 => "multisize-image-set",
        1003 | 10..=50 if part == Some(PART_APP_ICON) => "icon-image",
        1003 | 10..=50 => "image",
        _ => return layout_name(layout),
    };
    kind.to_owned()
}

struct Tlvs {
    list: Vec<RenditionTlv>,
    bytes_per_row: Option<u32>,
    uti: Option<String>,
    exif_orientation: Option<u32>,
    blend_mode: Option<u32>,
    opacity: Option<f32>,
    internal_link: Option<InternalLink>,
}

fn decode_tlvs(bytes: &[u8]) -> Result<Tlvs> {
    let mut out: Tlvs = Tlvs {
        list: Vec::new(),
        bytes_per_row: None,
        uti: None,
        exif_orientation: None,
        blend_mode: None,
        opacity: None,
        internal_link: None,
    };
    let mut at: usize = 0;
    while at < bytes.len() {
        if out.list.len() == MAX_TLVS {
            return Err(malformed(format!(
                "rendition holds more than {MAX_TLVS} TLVs"
            )));
        }
        let kind: u32 = field(read_u32_le_at(bytes, at), "TLV type")?;
        let length: usize = addressable(
            field(read_u32_le_at(bytes, at + 4), "TLV length")?,
            "TLV length",
        )?;
        let value: &[u8] = field(read_bytes_at(bytes, at + 8, length), "TLV value")?;
        match kind {
            TLV_BYTES_PER_ROW => {
                out.bytes_per_row = Some(field(read_u32_le_at(value, 0), "bytes per row")?);
            }
            TLV_EXIF_ORIENTATION => {
                out.exif_orientation = Some(field(read_u32_le_at(value, 0), "EXIF orientation")?);
            }
            TLV_BLEND_AND_OPACITY => {
                out.blend_mode = Some(field(read_u32_le_at(value, 0), "blend mode")?);
                out.opacity = Some(field(read_f32_le_at(value, 4), "opacity")?);
            }
            TLV_UTI => {
                let text_len: usize =
                    addressable(field(read_u32_le_at(value, 0), "UTI length")?, "UTI length")?;
                let text: &[u8] = field(read_bytes_at(value, 8, text_len), "UTI text")?;
                out.uti = Some(fixed_string(text, "UTI")?);
            }
            TLV_INTERNAL_LINK => out.internal_link = Some(decode_internal_link(value)?),
            _ => {}
        }
        out.list.push(RenditionTlv {
            kind,
            name: tlv_name(kind),
            length,
        });
        at += 8 + length;
    }
    Ok(out)
}

fn count_chunks(body: &[u8]) -> Result<usize> {
    let mut at: usize = 0;
    let mut chunks: usize = 0;
    while at < body.len() {
        if chunks == MAX_CHUNKS {
            return Err(malformed(format!(
                "pixel data holds more than {MAX_CHUNKS} chunks"
            )));
        }
        if field(read_bytes_at(body, at, 4), "pixel chunk tag")? != b"KCBC" {
            return Err(malformed(format!("pixel chunk at {at} lacks the CBCK tag")));
        }
        let length: usize = addressable(
            field(read_u32_le_at(body, at + 16), "pixel chunk length")?,
            "pixel chunk length",
        )?;
        field(read_bytes_at(body, at + 20, length), "pixel chunk")?;
        at += 20 + length;
        chunks += 1;
    }
    Ok(chunks)
}

fn decode_payload(payload: &[u8], base: usize) -> Result<(RenditionPayload, Option<Range<usize>>)> {
    if payload.is_empty() {
        return Ok((RenditionPayload::Empty, None));
    }
    let tag: &[u8] = field(read_bytes_at(payload, 0, 4), "payload tag")?;
    match tag {
        b"MLEC" => {
            let version: u32 = field(read_u32_le_at(payload, 4), "pixel version")?;
            let compression: u32 = field(read_u32_le_at(payload, 8), "pixel compression")?;
            let length: usize = addressable(
                field(read_u32_le_at(payload, 12), "pixel length")?,
                "pixel length",
            )?;
            let body: &[u8] = field(read_bytes_at(payload, 16, length), "pixel data")?;
            let chunks: usize = if body.starts_with(b"KCBC") {
                count_chunks(&payload[16..])?
            } else {
                0
            };
            let end: usize = if chunks == 0 {
                16 + length
            } else {
                payload.len()
            };
            Ok((
                RenditionPayload::Pixels {
                    compression: compression_name(compression),
                    version,
                    length: end - 16,
                    chunks,
                },
                Some(base + 16..base + end),
            ))
        }
        b"RLOC" => {
            let color_space: u32 = field(read_u32_le_at(payload, 8), "colour space")?;
            let count: usize = addressable(
                field(read_u32_le_at(payload, 12), "colour component count")?,
                "colour component count",
            )?;
            if count > MAX_COLOR_COMPONENTS {
                return Err(malformed(format!(
                    "colour declares {count} components, more than {MAX_COLOR_COMPONENTS}"
                )));
            }
            let components: Vec<f64> = (0..count)
                .map(|slot: usize| {
                    field(read_f64_le_at(payload, 16 + slot * 8), "colour component")
                })
                .collect::<Result<Vec<f64>>>()?;
            Ok((
                RenditionPayload::Color {
                    color_space_id: color_space & 0xff,
                    components,
                },
                None,
            ))
        }
        b"DWAR" => {
            let flags: u32 = field(read_u32_le_at(payload, 4), "data flags")?;
            let length: usize = addressable(
                field(read_u32_le_at(payload, 8), "data length")?,
                "data length",
            )?;
            let data: &[u8] = field(read_bytes_at(payload, 12, length), "data")?;
            let compression: String = if flags == 0 {
                "uncompressed".to_owned()
            } else {
                format!("flags-{flags:#x}")
            };
            Ok((
                RenditionPayload::Data {
                    compression,
                    flags,
                    length,
                    sha256: hex(&Sha256::digest(data)),
                },
                (flags == 0).then_some(base + 12..base + 12 + length),
            ))
        }
        b"SISM" => {
            let count: usize = addressable(
                field(read_u32_le_at(payload, 8), "size count")?,
                "size count",
            )?;
            if count > MAX_MULTISIZE_ENTRIES {
                return Err(malformed(format!(
                    "multisize set declares {count} sizes, more than {MAX_MULTISIZE_ENTRIES}"
                )));
            }
            let sizes: Vec<MultisizeEntry> = (0..count)
                .map(|slot: usize| -> Result<MultisizeEntry> {
                    let at: usize = 12 + slot * 12;
                    Ok(MultisizeEntry {
                        width: field(read_u32_le_at(payload, at), "size width")?,
                        height: field(read_u32_le_at(payload, at + 4), "size height")?,
                        index: field(read_u16_le_at(payload, at + 8), "size index")?,
                    })
                })
                .collect::<Result<Vec<MultisizeEntry>>>()?;
            Ok((RenditionPayload::MultisizeImageSet { sizes }, None))
        }
        _ => {
            let name: &str = match tag {
                b"ARGG" => "gradient",
                b"KLNI" => "internal-link",
                _ => "unrecognised",
            };
            Ok((
                RenditionPayload::Other {
                    tag: fourcc(tag),
                    name: name.to_owned(),
                    length: payload.len(),
                },
                None,
            ))
        }
    }
}

fn decode_rendition(
    key: BTreeMap<u32, u16>,
    value: &[u8],
    base: usize,
    appearances: &BTreeMap<u16, String>,
) -> Result<Rendition> {
    if !value.starts_with(CSI_TAG) || value.len() < CSI_HEADER_LEN {
        return Err(malformed(format!(
            "rendition at {base} lacks the CTSI tag or its {CSI_HEADER_LEN}-byte header"
        )));
    }
    let word = |at: usize, what: &str| -> Result<u32> { field(read_u32_le_at(value, at), what) };
    let name: String = fixed_string(
        &value[CSI_NAME_AT..CSI_NAME_AT + CSI_NAME_LEN],
        "rendition name",
    )?;
    let tlv_len: usize = addressable(word(168, "TLV length")?, "TLV length")?;
    let data_len: usize = addressable(word(180, "rendition length")?, "rendition length")?;
    let tlv_bytes: &[u8] = field(read_bytes_at(value, CSI_HEADER_LEN, tlv_len), "TLV block")?;
    let payload_at: usize = CSI_HEADER_LEN + tlv_len;
    let payload: &[u8] = field(
        read_bytes_at(value, payload_at, data_len),
        "rendition payload",
    )?;
    let tlvs: Tlvs = decode_tlvs(tlv_bytes)?;
    let (payload, data_span): (RenditionPayload, Option<Range<usize>>) =
        decode_payload(payload, base + payload_at)?;
    let pixel_format: u32 = word(24, "pixel format")?;
    let layout: u16 = field(read_u16_le_at(value, 36), "layout")?;
    let named: BTreeMap<String, u16> = key
        .iter()
        .map(|(id, token): (&u32, &u16)| (attribute_name(*id), *token))
        .collect();
    let attribute = |id: u16| -> Option<u16> { key.get(&u32::from(id)).copied() };
    let pixel_format: String = if pixel_format == 0 {
        String::new()
    } else {
        fourcc(&pixel_format.to_le_bytes())
    };
    let color_space_id: u32 = word(28, "colour space")? & 0xf;
    let color_space_id: u32 = match &payload {
        RenditionPayload::Color { color_space_id, .. } => *color_space_id,
        _ => color_space_id,
    };
    Ok(Rendition {
        asset: None,
        name,
        kind: rendition_kind(layout, attribute(ATTRIBUTE_PART)),
        idiom: attribute(ATTRIBUTE_IDIOM).map(idiom_name),
        scale: attribute(ATTRIBUTE_SCALE),
        appearance: attribute(ATTRIBUTE_APPEARANCE)
            .and_then(|token: u16| appearances.get(&token).cloned()),
        key: named,
        csi_version: word(4, "rendition version")?,
        flags: word(8, "rendition flags")?,
        width: word(12, "width")?,
        height: word(16, "height")?,
        scale_factor: word(20, "scale factor")?,
        encoding: encoding_name(&pixel_format),
        pixel_format,
        color_space: color_space_name(color_space_id),
        color_space_id,
        layout,
        layout_name: layout_name(layout),
        tlvs: tlvs.list,
        bytes_per_row: tlvs.bytes_per_row,
        uti: tlvs.uti,
        exif_orientation: tlvs.exif_orientation,
        blend_mode: tlvs.blend_mode,
        opacity: tlvs.opacity,
        internal_link: tlvs.internal_link,
        payload,
        size_on_disk: value.len(),
        sha1: hex(&Sha1::digest(value)),
        sha256: hex(&Sha256::digest(value)),
        trailing_bytes: value.len() - payload_at - data_len,
        data_span,
    })
}

fn link_target(renditions: &[Rendition], link: &InternalLink) -> Option<usize> {
    let found: Vec<usize> = renditions
        .iter()
        .enumerate()
        .filter(|(_, candidate): &(usize, &Rendition)| {
            candidate.internal_link.is_none()
                && candidate.key.iter().all(|(name, token): (&String, &u16)| {
                    link.key.get(name).copied().unwrap_or(0) == *token
                })
                && link
                    .key
                    .keys()
                    .all(|name: &String| candidate.key.contains_key(name))
        })
        .map(|(index, _): (usize, &Rendition)| index)
        .take(2)
        .collect();
    match found.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn resolve_links(renditions: &mut [Rendition]) {
    for index in 0..renditions.len() {
        let target: Option<usize> = renditions
            .get(index)
            .and_then(|rendition: &Rendition| rendition.internal_link.as_ref())
            .and_then(|link: &InternalLink| link_target(renditions, link));
        let target_name: Option<String> = target.and_then(|slot: usize| {
            renditions
                .get(slot)
                .map(|found: &Rendition| found.name.clone())
        });
        if let Some(link) = renditions
            .get_mut(index)
            .and_then(|rendition: &mut Rendition| rendition.internal_link.as_mut())
        {
            link.target = target;
            link.target_name = target_name;
        }
    }
}

fn facet_for(facets: &[Facet], key: &BTreeMap<String, u16>) -> Option<String> {
    facets
        .iter()
        .filter(|facet: &&Facet| {
            !facet.attributes.is_empty()
                && facet
                    .attributes
                    .iter()
                    .all(|(name, token): (&String, &u16)| key.get(name) == Some(token))
        })
        .max_by_key(|facet: &&Facet| facet.attributes.len())
        .map(|facet: &Facet| facet.name.clone())
}

pub fn decode_asset_catalog(bytes: &[u8]) -> Result<AssetCatalog> {
    let bom: Bom<'_> = decode_bom(bytes)?;
    let header_block: u32 = bom
        .variable("CARHEADER")
        .ok_or_else(|| malformed("the BOM store has no CARHEADER".to_owned()))?;
    let header: CatalogHeader = decode_header(bom.block(header_block, "CARHEADER")?)?;
    let metadata: Option<CatalogMetadata> = bom
        .variable("EXTENDED_METADATA")
        .map(|index: u32| -> Result<CatalogMetadata> {
            decode_metadata(bom.block(index, "EXTENDED_METADATA")?)
        })
        .transpose()?;
    let format_block: u32 = bom
        .variable("KEYFORMAT")
        .ok_or_else(|| malformed("the BOM store has no KEYFORMAT".to_owned()))?;
    let format: Vec<u32> = decode_key_format(bom.block(format_block, "KEYFORMAT")?)?;
    let mut appearances: BTreeMap<String, u16> = BTreeMap::new();
    for (value, key) in bom.tree("APPEARANCEKEYS")? {
        let name: &[u8] = bom.block(key, "appearance name")?;
        let name: String = std::str::from_utf8(name)
            .map_err(|_| malformed("appearance name is not UTF-8".to_owned()))?
            .to_owned();
        let token: u16 = field(
            read_u16_le_at(bom.block(value, "appearance value")?, 0),
            "appearance value",
        )?;
        appearances.insert(name, token);
    }
    let by_token: BTreeMap<u16, String> = appearances
        .iter()
        .map(|(name, token): (&String, &u16)| (*token, name.clone()))
        .collect();
    let facets: Vec<Facet> = bom
        .tree("FACETKEYS")?
        .into_iter()
        .map(|(value, key): (u32, u32)| -> Result<Facet> {
            decode_facet(
                bom.block(key, "facet name")?,
                bom.block(value, "facet value")?,
            )
        })
        .collect::<Result<Vec<Facet>>>()?;
    let bitmap_keys: usize = bom.tree("BITMAPKEYS")?.len();
    let mut renditions: Vec<Rendition> = Vec::new();
    for (value, key) in bom.tree("RENDITIONS")? {
        let key: BTreeMap<u32, u16> = decode_key(bom.block(key, "rendition key")?, &format)?;
        let range: Range<usize> = bom.block_range(value, "rendition value")?;
        let mut rendition: Rendition =
            decode_rendition(key, &bytes[range.clone()], range.start, &by_token)?;
        rendition.asset = facet_for(&facets, &rendition.key);
        renditions.push(rendition);
    }
    resolve_links(&mut renditions);
    Ok(AssetCatalog {
        bom_version: bom.version,
        block_count: bom.blocks.len(),
        variables: bom.variables,
        header,
        metadata,
        key_format: format.iter().map(|id: &u32| attribute_name(*id)).collect(),
        appearances,
        facets,
        bitmap_keys,
        renditions,
    })
}

const MAX_PIXEL_BYTES: usize = 256 << 20;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

fn uti_extension(uti: Option<&str>) -> &'static str {
    match uti {
        Some("public.json") => ".json",
        Some("public.plain-text" | "public.utf8-plain-text") => ".txt",
        Some("public.xml") => ".xml",
        Some("com.apple.property-list") => ".plist",
        Some("public.png") => ".png",
        Some("public.jpeg") => ".jpg",
        Some("com.compuserve.gif") => ".gif",
        Some("public.html") => ".html",
        Some("public.svg-image") => ".svg",
        _ => ".bin",
    }
}

fn safe_component(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed: &str = cleaned.trim_start_matches('.');
    if trimmed.is_empty() {
        "unnamed".to_owned()
    } else {
        trimmed.to_owned()
    }
}

struct BoundedSink {
    out: Vec<u8>,
    limit: usize,
}

impl std::io::Write for BoundedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.out.len() + buf.len() > self.limit {
            return Err(std::io::Error::other(format!(
                "decoded pixels exceed the declared {} bytes",
                self.limit
            )));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn inflate_lzfse(stream: &[u8], room: usize, sink: &mut BoundedSink) -> Result<()> {
    sink.limit = sink.out.len() + room;
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(stream);
    let mut decoder: lzfse_rust::LzfseRingDecoder = lzfse_rust::LzfseRingDecoder::default();
    decoder
        .decode(&mut reader, sink)
        .map_err(|error: lzfse_rust::Error| malformed(format!("lzfse pixel stream: {error}")))?;
    Ok(())
}

fn pixel_rows(
    body: &[u8],
    compression: &str,
    chunks: usize,
    total: usize,
) -> Result<Option<Vec<u8>>> {
    let mut sink: BoundedSink = BoundedSink {
        out: Vec::new(),
        limit: total,
    };
    if chunks == 0 {
        match compression {
            "uncompressed" => sink
                .out
                .extend_from_slice(field(read_bytes_at(body, 0, total), "raw pixels")?),
            "lzfse" => inflate_lzfse(body, total, &mut sink)?,
            _ => return Ok(None),
        }
    } else {
        let mut at: usize = 0;
        while at < body.len() {
            let length: usize = addressable(
                field(read_u32_le_at(body, at + 16), "pixel chunk length")?,
                "pixel chunk length",
            )?;
            let chunk: &[u8] = field(read_bytes_at(body, at + 20, length), "pixel chunk")?;
            let room: usize = total - sink.out.len();
            match compression {
                "uncompressed" => {
                    if chunk.len() > room {
                        return Err(malformed(format!(
                            "pixel chunks exceed the declared {total} bytes"
                        )));
                    }
                    sink.out.extend_from_slice(chunk);
                }
                "lzfse" => inflate_lzfse(chunk, room, &mut sink)?,
                _ => return Ok(None),
            }
            at += 20 + length;
        }
    }
    if sink.out.len() != total {
        return Err(malformed(format!(
            "pixel data decodes to {} bytes, the header declares {total}",
            sink.out.len()
        )));
    }
    Ok(Some(sink.out))
}

fn png_chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) -> Result<()> {
    let length: u32 = u32::try_from(data.len())
        .map_err(|_| malformed("PNG chunk is longer than 4 GiB".to_owned()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&kind);
    out.extend_from_slice(data);
    let mut crc: flate2::Crc = flate2::Crc::new();
    crc.update(&kind);
    crc.update(data);
    out.extend_from_slice(&crc.sum().to_be_bytes());
    Ok(())
}

fn encode_png(width: u32, height: u32, row_len: usize, rgba: &[u8]) -> Result<Vec<u8>> {
    let mut header: Vec<u8> = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    for row in rgba.chunks_exact(row_len) {
        std::io::Write::write_all(&mut encoder, &[0])
            .and_then(|()| std::io::Write::write_all(&mut encoder, row))
            .map_err(|error: std::io::Error| malformed(format!("PNG deflate: {error}")))?;
    }
    let compressed: Vec<u8> = encoder
        .finish()
        .map_err(|error: std::io::Error| malformed(format!("PNG deflate: {error}")))?;
    let mut out: Vec<u8> = PNG_SIGNATURE.to_vec();
    png_chunk(&mut out, *b"IHDR", &header)?;
    png_chunk(&mut out, *b"IDAT", &compressed)?;
    png_chunk(&mut out, *b"IEND", &[])?;
    Ok(out)
}

fn unpremultiply(channel: u8, alpha: u8) -> u8 {
    if alpha == 0 {
        return 0;
    }
    let value: u32 = (u32::from(channel) * 255 + u32::from(alpha) / 2) / u32::from(alpha);
    u8::try_from(value.min(255)).unwrap_or(u8::MAX)
}

pub fn decode_rendition_png(bytes: &[u8], rendition: &Rendition) -> Result<Option<Vec<u8>>> {
    let RenditionPayload::Pixels {
        compression,
        chunks,
        ..
    } = &rendition.payload
    else {
        return Ok(None);
    };
    if rendition.pixel_format != "ARGB" || rendition.width == 0 || rendition.height == 0 {
        return Ok(None);
    }
    let Some(span) = rendition.data_span.clone() else {
        return Ok(None);
    };
    let body: &[u8] = bytes.get(span).ok_or_else(|| {
        malformed(format!(
            "rendition {} data lies outside the file",
            rendition.name
        ))
    })?;
    let width: usize = addressable(rendition.width, "width")?;
    let height: usize = addressable(rendition.height, "height")?;
    let packed: usize = width
        .checked_mul(4)
        .ok_or_else(|| malformed("row width overflows".to_owned()))?;
    let stride: usize = match rendition.bytes_per_row {
        Some(declared) => addressable(declared, "bytes per row")?,
        None => packed,
    };
    if stride < packed {
        return Err(malformed(format!(
            "rendition {} declares {stride} bytes per row for {width} ARGB pixels",
            rendition.name
        )));
    }
    let total: usize = stride
        .checked_mul(height)
        .filter(|total: &usize| *total <= MAX_PIXEL_BYTES)
        .ok_or_else(|| {
            malformed(format!(
                "rendition {} needs more than {MAX_PIXEL_BYTES} pixel bytes",
                rendition.name
            ))
        })?;
    let Some(rows) = pixel_rows(body, compression, *chunks, total)? else {
        return Ok(None);
    };
    let mut rgba: Vec<u8> = Vec::with_capacity(packed * height);
    for row in rows.chunks_exact(stride) {
        for pixel in row[..packed].chunks_exact(4) {
            let alpha: u8 = pixel[3];
            rgba.extend_from_slice(&[
                unpremultiply(pixel[2], alpha),
                unpremultiply(pixel[1], alpha),
                unpremultiply(pixel[0], alpha),
                alpha,
            ]);
        }
    }
    encode_png(rendition.width, rendition.height, packed, &rgba).map(Some)
}

pub fn catalog_files(bytes: &[u8], catalog: &AssetCatalog) -> Result<Vec<CatalogFile>> {
    let mut files: Vec<CatalogFile> = Vec::new();
    for (index, rendition) in catalog.renditions.iter().enumerate() {
        let folder: String = safe_component(rendition.asset.as_deref().unwrap_or("unassigned"));
        match &rendition.payload {
            RenditionPayload::Data { .. } => {
                let Some(span) = rendition.data_span.clone() else {
                    continue;
                };
                let name: String = format!(
                    "{index:04}-{}{}",
                    safe_component(rendition.asset.as_deref().unwrap_or(&rendition.name)),
                    uti_extension(rendition.uti.as_deref())
                );
                let data: &[u8] = bytes.get(span).ok_or_else(|| {
                    malformed(format!(
                        "rendition {} data lies outside the file",
                        rendition.name
                    ))
                })?;
                files.push(CatalogFile {
                    path: format!("{folder}/{name}"),
                    bytes: data.to_vec(),
                });
            }
            RenditionPayload::Pixels { .. } => {
                if let Some(png) = decode_rendition_png(bytes, rendition)? {
                    let name: String = format!("{index:04}-{}", safe_component(&rendition.name));
                    let stem: &str = name.strip_suffix(".png").unwrap_or(&name);
                    files.push(CatalogFile {
                        path: format!("{folder}/{stem}.png"),
                        bytes: png,
                    });
                }
            }
            RenditionPayload::Color { .. }
            | RenditionPayload::MultisizeImageSet { .. }
            | RenditionPayload::Other { .. }
            | RenditionPayload::Empty => {}
        }
    }
    Ok(files)
}
