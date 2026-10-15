#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::asset_catalog::{
    AssetCatalog, InternalLink, Rendition, RenditionPayload, decode_asset_catalog,
    decode_rendition_png,
};
use serde_json::{Map, Value};

const UNDECODED_FIELDS: [&str; 4] = ["BitsPerComponent", "ColorModel", "Opaque", "Template Mode"];
const HEADER_FIELDS: [&str; 10] = [
    "Appearances",
    "AssetStorageVersion",
    "Authoring Tool",
    "CoreUIVersion",
    "Key Format",
    "MainVersion",
    "Platform",
    "PlatformVersion",
    "SchemaVersion",
    "StorageVersion",
];
const HEADER_FIELDS_NOT_IN_FILE: [&str; 2] = ["DumpToolVersion", "Timestamp"];

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apple/runner")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("runner fixture {} is required: {error}", path.display()))
}

fn reference() -> Vec<Value> {
    serde_json::from_slice(&fixture("Assets.car.assetutil.json")).expect("assetutil json")
}

fn kind_label(kind: &str) -> &str {
    match kind {
        "image" => "Image",
        "icon-image" => "Icon Image",
        "color" => "Color",
        "data" => "Data",
        "multisize-image-set" => "MultiSized Image",
        "packed-image" => "PackedImage",
        other => other,
    }
}

fn key_format_name(assetutil: &str) -> String {
    let core: &str = assetutil
        .strip_prefix("kCRTheme")
        .and_then(|rest: &str| rest.strip_suffix("Name"))
        .expect("kCRTheme...Name key format entry");
    let mut out: String = String::new();
    for (index, c) in core.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn compression_of<'a>(catalog: &'a AssetCatalog, rendition: &'a Rendition) -> Option<&'a str> {
    match &rendition.payload {
        RenditionPayload::Pixels { compression, .. }
        | RenditionPayload::Data { compression, .. } => Some(compression),
        RenditionPayload::Empty => rendition
            .internal_link
            .as_ref()
            .and_then(|link: &InternalLink| link.target)
            .and_then(|target: usize| catalog.renditions.get(target))
            .and_then(|target: &Rendition| compression_of(catalog, target)),
        _ => None,
    }
}

fn sizes_of(rendition: &Rendition) -> Option<Vec<String>> {
    let idiom: &str = rendition.idiom.as_deref().unwrap_or("?");
    match &rendition.payload {
        RenditionPayload::MultisizeImageSet { sizes } => Some(
            sizes
                .iter()
                .map(|size| {
                    format!(
                        "{}x{} index:{} idiom:{}",
                        size.width, size.height, size.index, idiom
                    )
                })
                .collect(),
        ),
        _ => None,
    }
}

struct Grade {
    graded: usize,
    wrong: Vec<String>,
    undecoded: BTreeSet<String>,
}

impl Grade {
    fn check(&mut self, ok: bool, what: String) {
        self.graded += 1;
        if !ok {
            self.wrong.push(what);
        }
    }
}

fn grade_header(catalog: &AssetCatalog, header: &Map<String, Value>, grade: &mut Grade) {
    let listed: BTreeSet<&str> = header.keys().map(String::as_str).collect();
    let accounted: BTreeSet<&str> = HEADER_FIELDS
        .iter()
        .chain(HEADER_FIELDS_NOT_IN_FILE.iter())
        .copied()
        .collect();
    grade.check(
        listed == accounted,
        format!("assetutil header fields {listed:?} against the graded set {accounted:?}"),
    );
    let metadata = catalog.metadata.as_ref().expect("extended metadata");
    grade.check(
        header["CoreUIVersion"].as_u64() == Some(u64::from(catalog.header.core_ui_version)),
        format!("CoreUIVersion {}", catalog.header.core_ui_version),
    );
    grade.check(
        header["StorageVersion"].as_u64() == Some(u64::from(catalog.header.storage_version)),
        format!("StorageVersion {}", catalog.header.storage_version),
    );
    grade.check(
        header["SchemaVersion"].as_u64() == Some(u64::from(catalog.header.schema_version)),
        format!("SchemaVersion {}", catalog.header.schema_version),
    );
    grade.check(
        header["MainVersion"].as_str() == Some(catalog.header.main_version.as_str()),
        format!("MainVersion {:?}", catalog.header.main_version),
    );
    grade.check(
        header["AssetStorageVersion"].as_str() == Some(catalog.header.version.as_str()),
        format!("AssetStorageVersion {:?}", catalog.header.version),
    );
    grade.check(
        header["Authoring Tool"].as_str() == Some(metadata.authoring_tool.as_str()),
        format!("Authoring Tool {:?}", metadata.authoring_tool),
    );
    grade.check(
        header["Platform"].as_str() == Some(metadata.deployment_platform.as_str()),
        format!("Platform {:?}", metadata.deployment_platform),
    );
    grade.check(
        header["PlatformVersion"].as_str() == Some(metadata.deployment_platform_version.as_str()),
        format!("PlatformVersion {:?}", metadata.deployment_platform_version),
    );
    let key_format: Vec<String> = header["Key Format"]
        .as_array()
        .expect("key format")
        .iter()
        .map(|name: &Value| key_format_name(name.as_str().expect("key format name")))
        .collect();
    grade.check(
        key_format == catalog.key_format,
        format!("Key Format {:?} against {key_format:?}", catalog.key_format),
    );
    let appearances: BTreeMap<String, u16> = header["Appearances"]
        .as_object()
        .expect("appearances")
        .iter()
        .map(|(name, token): (&String, &Value)| {
            (
                name.clone(),
                u16::try_from(token.as_u64().expect("token")).expect("u16 token"),
            )
        })
        .collect();
    grade.check(
        appearances == catalog.appearances,
        format!(
            "Appearances {:?} against {appearances:?}",
            catalog.appearances
        ),
    );
}

fn grade_rendition(catalog: &AssetCatalog, record: &Map<String, Value>, grade: &mut Grade) {
    let digest: &str = record["SHA1Digest"].as_str().expect("digest");
    let idiom: &str = record["Idiom"].as_str().expect("idiom");
    let found: Vec<&Rendition> = catalog
        .renditions
        .iter()
        .filter(|rendition: &&Rendition| {
            rendition.sha256.eq_ignore_ascii_case(digest)
                && rendition.idiom.as_deref() == Some(idiom)
        })
        .collect();
    grade.check(
        found.len() == 1,
        format!(
            "{digest} {idiom}: {} renditions carry this digest",
            found.len()
        ),
    );
    let Some(rendition) = found.first() else {
        return;
    };
    let label: String = format!("{} {}", rendition.name, idiom);
    for (field, expected) in record {
        match field.as_str() {
            "SHA1Digest" | "Idiom" => {}
            "AssetType" => grade.check(
                expected.as_str() == Some(kind_label(&rendition.kind)),
                format!("{label}: AssetType {expected} against {}", rendition.kind),
            ),
            "Name" => grade.check(
                expected.as_str() == Some(rendition.asset.as_deref().unwrap_or(&rendition.name)),
                format!("{label}: Name {expected} against {:?}", rendition.asset),
            ),
            "NameIdentifier" => grade.check(
                expected.as_u64()
                    == rendition
                        .key
                        .get("identifier")
                        .map(|token: &u16| u64::from(*token)),
                format!("{label}: NameIdentifier {expected}"),
            ),
            "Scale" => grade.check(
                expected.as_u64() == rendition.scale.map(u64::from),
                format!("{label}: Scale {expected} against {:?}", rendition.scale),
            ),
            "Icon Index" => grade.check(
                expected.as_u64()
                    == rendition
                        .key
                        .get("dimension2")
                        .map(|token: &u16| u64::from(*token)),
                format!("{label}: Icon Index {expected}"),
            ),
            "Appearance" => grade.check(
                expected.as_str() == rendition.appearance.as_deref(),
                format!(
                    "{label}: Appearance {expected} against {:?}",
                    rendition.appearance
                ),
            ),
            "RenditionName" => grade.check(
                expected.as_str() == Some(rendition.name.as_str()),
                format!("{label}: RenditionName {expected}"),
            ),
            "PixelWidth" => grade.check(
                expected.as_u64() == Some(u64::from(rendition.width)),
                format!("{label}: PixelWidth {expected} against {}", rendition.width),
            ),
            "PixelHeight" => grade.check(
                expected.as_u64() == Some(u64::from(rendition.height)),
                format!(
                    "{label}: PixelHeight {expected} against {}",
                    rendition.height
                ),
            ),
            "Encoding" => grade.check(
                expected.as_str() == rendition.encoding.as_deref(),
                format!(
                    "{label}: Encoding {expected} against {:?}",
                    rendition.encoding
                ),
            ),
            "Compression" => grade.check(
                expected.as_str() == compression_of(catalog, rendition),
                format!(
                    "{label}: Compression {expected} against {:?}",
                    compression_of(catalog, rendition)
                ),
            ),
            "Colorspace" => grade.check(
                expected.as_str() == rendition.color_space.as_deref(),
                format!(
                    "{label}: Colorspace {expected} against {:?}",
                    rendition.color_space
                ),
            ),
            "Color components" => {
                let components: Vec<f64> = expected
                    .as_array()
                    .expect("components")
                    .iter()
                    .map(|value: &Value| value.as_f64().expect("component"))
                    .collect();
                let recovered: Option<&Vec<f64>> = match &rendition.payload {
                    RenditionPayload::Color { components, .. } => Some(components),
                    _ => None,
                };
                grade.check(
                    recovered == Some(&components),
                    format!("{label}: Color components {components:?} against {recovered:?}"),
                );
            }
            "Data Length" => {
                let length: Option<u64> = match &rendition.payload {
                    RenditionPayload::Data { length, .. } => u64::try_from(*length).ok(),
                    _ => None,
                };
                grade.check(
                    expected.as_u64() == length,
                    format!("{label}: Data Length {expected} against {length:?}"),
                );
            }
            "UTI" => grade.check(
                expected.as_str() == rendition.uti.as_deref(),
                format!("{label}: UTI {expected} against {:?}", rendition.uti),
            ),
            "SizeOnDisk" => grade.check(
                expected.as_u64() == u64::try_from(rendition.size_on_disk).ok(),
                format!(
                    "{label}: SizeOnDisk {expected} against {}",
                    rendition.size_on_disk
                ),
            ),
            "Sizes" => {
                let sizes: Vec<String> = expected
                    .as_array()
                    .expect("sizes")
                    .iter()
                    .map(|value: &Value| value.as_str().expect("size").to_owned())
                    .collect();
                grade.check(
                    Some(&sizes) == sizes_of(rendition).as_ref(),
                    format!("{label}: Sizes {sizes:?} against {:?}", sizes_of(rendition)),
                );
            }
            other => {
                grade.undecoded.insert(other.to_owned());
            }
        }
    }
    if !record.contains_key("Appearance") {
        grade.check(
            rendition
                .appearance
                .as_deref()
                .is_none_or(|name: &str| name == "UIAppearanceAny"),
            format!(
                "{label}: assetutil names no appearance, disrobe {:?}",
                rendition.appearance
            ),
        );
    }
}

fn grade_catalog(bytes: &[u8]) -> Grade {
    let records: Vec<Value> = reference();
    let mut grade: Grade = Grade {
        graded: 0,
        wrong: Vec::new(),
        undecoded: BTreeSet::new(),
    };
    let catalog: AssetCatalog = match decode_asset_catalog(bytes) {
        Ok(catalog) => catalog,
        Err(error) => {
            grade.check(false, format!("refused: {error}"));
            return grade;
        }
    };
    grade_header(
        &catalog,
        records[0].as_object().expect("header record"),
        &mut grade,
    );
    grade.check(
        records.len() - 1 == catalog.renditions.len(),
        format!(
            "{} renditions against assetutil {}",
            catalog.renditions.len(),
            records.len() - 1
        ),
    );
    for record in &records[1..] {
        grade_rendition(
            &catalog,
            record.as_object().expect("rendition record"),
            &mut grade,
        );
    }
    grade
}

#[test]
fn every_assetutil_field_matches_the_decoded_catalog() {
    let grade: Grade = grade_catalog(&fixture("Assets.car"));
    assert!(
        grade.wrong.is_empty(),
        "{} of {} assetutil facts differ:\n{}",
        grade.wrong.len(),
        grade.graded,
        grade.wrong.join("\n")
    );
    let undecoded: BTreeSet<String> = UNDECODED_FIELDS
        .iter()
        .map(|name: &&str| (*name).to_owned())
        .collect();
    assert_eq!(
        grade.undecoded, undecoded,
        "assetutil reports a field this grade does not cover"
    );
    assert!(grade.graded >= 150, "only {} facts graded", grade.graded);
}

#[test]
fn a_flipped_byte_inside_a_rendition_is_caught() {
    let mut bytes: Vec<u8> = fixture("Assets.car");
    let catalog: AssetCatalog = decode_asset_catalog(&bytes).expect("decode");
    let colour: &Rendition = catalog
        .renditions
        .iter()
        .find(|rendition: &&Rendition| rendition.kind == "color")
        .expect("a colour rendition");
    let needle: [u8; 8] = match &colour.payload {
        RenditionPayload::Color { components, .. } => components[0].to_le_bytes(),
        _ => unreachable!(),
    };
    let at: usize = bytes
        .windows(8)
        .position(|window: &[u8]| window == needle)
        .expect("component bytes");
    bytes[at + 7] ^= 0x01;
    let grade: Grade = grade_catalog(&bytes);
    assert!(
        !grade.wrong.is_empty(),
        "a changed colour component went unnoticed"
    );
}

fn decode_png(png: &[u8]) -> (u32, u32, Vec<u8>) {
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"), "png signature");
    let mut at: usize = 8;
    let mut size: (u32, u32) = (0, 0);
    let mut idat: Vec<u8> = Vec::new();
    while at + 8 <= png.len() {
        let length: usize =
            usize::try_from(u32::from_be_bytes(png[at..at + 4].try_into().unwrap())).unwrap();
        let kind: &[u8] = &png[at + 4..at + 8];
        let data: &[u8] = &png[at + 8..at + 8 + length];
        if kind == b"IHDR" {
            size = (
                u32::from_be_bytes(data[0..4].try_into().unwrap()),
                u32::from_be_bytes(data[4..8].try_into().unwrap()),
            );
            assert_eq!(&data[8..13], &[8, 6, 0, 0, 0], "8-bit RGBA, no interlace");
        } else if kind == b"IDAT" {
            idat.extend_from_slice(data);
        }
        at += 12 + length;
    }
    let mut raw: Vec<u8> = Vec::new();
    flate2::read::ZlibDecoder::new(idat.as_slice())
        .read_to_end(&mut raw)
        .expect("png deflate stream");
    let row: usize = usize::try_from(size.0).unwrap() * 4 + 1;
    let mut pixels: Vec<u8> = Vec::new();
    for line in raw.chunks_exact(row) {
        assert_eq!(line[0], 0, "the writer emits filter type 0");
        pixels.extend_from_slice(&line[1..]);
    }
    (size.0, size.1, pixels)
}

fn icon_colour(x: u32, y: u32) -> [u8; 4] {
    let red: u32 = (x >> 2) & 0xff;
    let green: u32 = (y >> 2) & 0xff;
    let blue: u32 = (((x >> 6) + (y >> 6)) * 16) & 0xff;
    [
        u8::try_from(red).unwrap(),
        u8::try_from(green).unwrap(),
        u8::try_from(blue).unwrap(),
        255,
    ]
}

fn icon_pixel_mismatches(bytes: &[u8]) -> (usize, usize) {
    let catalog: AssetCatalog = decode_asset_catalog(bytes).expect("decode");
    let icons: Vec<&Rendition> = catalog
        .renditions
        .iter()
        .filter(|rendition: &&Rendition| rendition.kind == "icon-image")
        .collect();
    assert_eq!(icons.len(), 2, "phone and pad icon renditions");
    let mut checked: usize = 0;
    let mut wrong: usize = 0;
    for icon in icons {
        let Ok(Some(png)) = decode_rendition_png(bytes, icon) else {
            return (checked, usize::MAX);
        };
        let (width, height, pixels): (u32, u32, Vec<u8>) = decode_png(&png);
        assert_eq!((width, height), (1024, 1024));
        for y in 0..height {
            for x in 0..width {
                let at: usize = usize::try_from((y * width + x) * 4).unwrap();
                checked += 1;
                if pixels[at..at + 4] != icon_colour(x, y) {
                    wrong += 1;
                }
            }
        }
    }
    (checked, wrong)
}

#[test]
fn the_lzfse_icon_decodes_to_the_authored_pixels() {
    let (checked, wrong): (usize, usize) = icon_pixel_mismatches(&fixture("Assets.car"));
    assert_eq!(
        wrong, 0,
        "{wrong} of {checked} icon pixels differ from make_assets.py icon_colour"
    );
    assert_eq!(checked, 2 * 1024 * 1024);
}

#[test]
fn a_flipped_byte_inside_the_icon_stream_is_caught() {
    let mut bytes: Vec<u8> = fixture("Assets.car");
    let catalog: AssetCatalog = decode_asset_catalog(&bytes).expect("decode");
    let icon: &Rendition = catalog
        .renditions
        .iter()
        .find(|rendition: &&Rendition| rendition.kind == "icon-image")
        .expect("icon");
    let span = icon.data_span.clone().expect("pixel span");
    let middle: usize = span.start + (span.end - span.start) / 2;
    bytes[middle] ^= 0x5a;
    let (_, wrong): (usize, usize) = icon_pixel_mismatches(&bytes);
    assert!(
        wrong > 0,
        "a corrupted lzfse chunk decoded to the authored pixels"
    );
}
