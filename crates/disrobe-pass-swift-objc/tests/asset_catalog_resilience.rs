#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, Pass};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_swift_objc::archive_pass::{APPLE_ARCHIVE_PASS, AppleArchiveDetector};
use disrobe_pass_swift_objc::asset_catalog::{
    AssetCatalog, CatalogFile, RenditionPayload, catalog_files, decode_asset_catalog,
    is_asset_catalog,
};

struct Store {
    blocks: Vec<Vec<u8>>,
}

impl Store {
    fn add(&mut self, bytes: Vec<u8>) -> u32 {
        self.blocks.push(bytes);
        u32::try_from(self.blocks.len() - 1).unwrap()
    }

    fn tree(&mut self, entries: &[(u32, u32)]) -> u32 {
        let mut paths: Vec<u8> = Vec::new();
        paths.extend_from_slice(&1u16.to_be_bytes());
        paths.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_be_bytes());
        paths.extend_from_slice(&0u32.to_be_bytes());
        paths.extend_from_slice(&0u32.to_be_bytes());
        for (value, key) in entries {
            paths.extend_from_slice(&value.to_be_bytes());
            paths.extend_from_slice(&key.to_be_bytes());
        }
        let leaf: u32 = self.add(paths);
        let mut head: Vec<u8> = b"tree".to_vec();
        head.extend_from_slice(&1u32.to_be_bytes());
        head.extend_from_slice(&leaf.to_be_bytes());
        head.extend_from_slice(&4096u32.to_be_bytes());
        head.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
        head.push(0);
        self.add(head)
    }

    fn finish(&self, variables: &[(&str, u32)]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0; 32];
        let mut pointers: Vec<(u32, u32)> = Vec::new();
        for block in &self.blocks {
            pointers.push((
                u32::try_from(out.len()).unwrap(),
                u32::try_from(block.len()).unwrap(),
            ));
            out.extend_from_slice(block);
        }
        let index_at: u32 = u32::try_from(out.len()).unwrap();
        out.extend_from_slice(&u32::try_from(pointers.len()).unwrap().to_be_bytes());
        for (offset, length) in &pointers {
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&length.to_be_bytes());
        }
        let index_len: u32 = u32::try_from(out.len()).unwrap() - index_at;
        let vars_at: u32 = u32::try_from(out.len()).unwrap();
        out.extend_from_slice(&u32::try_from(variables.len()).unwrap().to_be_bytes());
        for (name, block) in variables {
            out.extend_from_slice(&block.to_be_bytes());
            out.push(u8::try_from(name.len()).unwrap());
            out.extend_from_slice(name.as_bytes());
        }
        let vars_len: u32 = u32::try_from(out.len()).unwrap() - vars_at;
        out[..8].copy_from_slice(b"BOMStore");
        out[8..12].copy_from_slice(&1u32.to_be_bytes());
        out[12..16].copy_from_slice(&u32::try_from(pointers.len()).unwrap().to_be_bytes());
        out[16..20].copy_from_slice(&index_at.to_be_bytes());
        out[20..24].copy_from_slice(&index_len.to_be_bytes());
        out[24..28].copy_from_slice(&vars_at.to_be_bytes());
        out[28..32].copy_from_slice(&vars_len.to_be_bytes());
        out
    }
}

fn fixed(text: &str, len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = text.as_bytes().to_vec();
    out.resize(len, 0);
    out
}

fn le(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word: &u32| word.to_le_bytes())
        .collect()
}

fn csi(
    name: &str,
    pixel_format: [u8; 4],
    layout: u16,
    size: [u32; 2],
    tlvs: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut format: [u8; 4] = pixel_format;
    format.reverse();
    let mut out: Vec<u8> = b"ISTC".to_vec();
    out.extend_from_slice(&le(&[1, 0, size[0], size[1], 100]));
    out.extend_from_slice(&format);
    out.extend_from_slice(&le(&[1, 0]));
    out.extend_from_slice(&layout.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&fixed(name, 128));
    out.extend_from_slice(&le(&[
        u32::try_from(tlvs.len()).unwrap(),
        0,
        0,
        u32::try_from(payload.len()).unwrap(),
    ]));
    out.extend_from_slice(tlvs);
    out.extend_from_slice(payload);
    out
}

fn tlv(kind: u32, value: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = le(&[kind, u32::try_from(value.len()).unwrap()]);
    out.extend_from_slice(value);
    out
}

fn key(tokens: &[u16]) -> Vec<u8> {
    tokens
        .iter()
        .flat_map(|token: &u16| token.to_le_bytes())
        .collect()
}

fn catalog() -> Vec<u8> {
    let mut store: Store = Store {
        blocks: vec![Vec::new()],
    };
    let mut header: Vec<u8> = b"RATC".to_vec();
    header.extend_from_slice(&le(&[918, 17, 0, 3]));
    header.extend_from_slice(&fixed("@(#)PROGRAM:CoreUI  PROJECT:CoreUI-918", 128));
    header.extend_from_slice(&fixed("authored test catalog", 256));
    header.extend_from_slice(&[0; 16]);
    header.extend_from_slice(&le(&[0, 2, 1, 2]));
    let header: u32 = store.add(header);
    let mut format: Vec<u8> = b"tmfk".to_vec();
    format.extend_from_slice(&le(&[0, 5, 7, 12, 15, 17, 1]));
    let format: u32 = store.add(format);
    let mut metadata: Vec<u8> = b"META".to_vec();
    for text in ["", "15.0", "ios", "authored"] {
        metadata.extend_from_slice(&fixed(text, 256));
    }
    let metadata: u32 = store.add(metadata);
    let dark_name: u32 = store.add(b"UIAppearanceDark".to_vec());
    let dark_value: u32 = store.add(1u16.to_le_bytes().to_vec());
    let appearances: u32 = store.tree(&[(dark_value, dark_name)]);
    let mut facet: Vec<u8> = Vec::new();
    for value in [0u16, 0, 2, 17, 41, 1, 85] {
        facet.extend_from_slice(&value.to_le_bytes());
    }
    let facet_value: u32 = store.add(facet);
    let facet_name: u32 = store.add(b"AccentTint".to_vec());
    let mut data_facet: Vec<u8> = Vec::new();
    for value in [0u16, 0, 1, 17, 42] {
        data_facet.extend_from_slice(&value.to_le_bytes());
    }
    let data_facet_value: u32 = store.add(data_facet);
    let data_facet_name: u32 = store.add(b"Settings".to_vec());
    let facets: u32 = store.tree(&[
        (facet_value, facet_name),
        (data_facet_value, data_facet_name),
    ]);
    let common: Vec<u8> = [tlv(0x3EC, &[0; 8]), tlv(0x3EE, &le(&[1]))].concat();
    let mut colour: Vec<u8> = b"RLOC".to_vec();
    colour.extend_from_slice(&le(&[1, 1, 4]));
    for component in [0.8f64, 0.4, 0.2, 1.0] {
        colour.extend_from_slice(&component.to_le_bytes());
    }
    let colour_value: u32 = store.add(csi("AccentTint", [0; 4], 1009, [0, 0], &common, &colour));
    let colour_key: u32 = store.add(key(&[1, 1, 0, 41, 85]));
    let json: &[u8] = b"{\"version\": 3}\n";
    let mut data: Vec<u8> = b"DWAR".to_vec();
    data.extend_from_slice(&le(&[0, u32::try_from(json.len()).unwrap()]));
    data.extend_from_slice(json);
    let mut uti: Vec<u8> = le(&[12, 0]);
    uti.extend_from_slice(b"public.json\0");
    let data_tlvs: Vec<u8> = [common.clone(), tlv(0x3ED, &uti)].concat();
    let data_value: u32 = store.add(csi(
        "settings.json",
        *b"DATA",
        1000,
        [0, 0],
        &data_tlvs,
        &data,
    ));
    let data_key: u32 = store.add(key(&[0, 1, 0, 42, 85]));
    let mut pixels: Vec<u8> = Vec::new();
    for y in 0u8..2 {
        for x in 0u8..3 {
            pixels.extend_from_slice(&[x * 40, y * 90, 200, 255]);
        }
    }
    let mut image: Vec<u8> = b"MLEC".to_vec();
    image.extend_from_slice(&le(&[1, 0, u32::try_from(pixels.len()).unwrap()]));
    image.extend_from_slice(&pixels);
    let image_tlvs: Vec<u8> = [common, tlv(0x3EF, &le(&[12]))].concat();
    let image_value: u32 = store.add(csi("badge.png", *b"ARGB", 12, [3, 2], &image_tlvs, &image));
    let image_key: u32 = store.add(key(&[0, 2, 0, 43, 85]));
    let renditions: u32 = store.tree(&[
        (colour_value, colour_key),
        (data_value, data_key),
        (image_value, image_key),
    ]);
    store.finish(&[
        ("CARHEADER", header),
        ("KEYFORMAT", format),
        ("EXTENDED_METADATA", metadata),
        ("APPEARANCEKEYS", appearances),
        ("FACETKEYS", facets),
        ("RENDITIONS", renditions),
    ])
}

#[test]
fn authored_catalog_decodes_every_rendition_kind() {
    let bytes: Vec<u8> = catalog();
    assert!(is_asset_catalog(&bytes));
    let catalog: AssetCatalog = decode_asset_catalog(&bytes).expect("decode");
    assert_eq!(catalog.header.core_ui_version, 918);
    assert_eq!(catalog.header.version, "authored test catalog");
    assert_eq!(
        catalog.key_format,
        ["appearance", "scale", "idiom", "identifier", "element"]
    );
    assert_eq!(
        catalog.metadata.as_ref().unwrap().deployment_platform,
        "ios"
    );
    assert_eq!(catalog.renditions.len(), 3);
    let colour = &catalog.renditions[0];
    assert_eq!(colour.asset.as_deref(), Some("AccentTint"));
    assert_eq!(colour.appearance.as_deref(), Some("UIAppearanceDark"));
    assert_eq!(colour.idiom.as_deref(), Some("universal"));
    assert_eq!(colour.layout_name, "color");
    assert_eq!(
        colour.payload,
        RenditionPayload::Color {
            color_space_id: 1,
            components: vec![0.8, 0.4, 0.2, 1.0],
        }
    );
    let data = &catalog.renditions[1];
    assert_eq!(data.asset.as_deref(), Some("Settings"));
    assert_eq!(data.uti.as_deref(), Some("public.json"));
    assert_eq!(data.pixel_format, "DATA");
    let image = &catalog.renditions[2];
    assert_eq!(image.asset, None);
    assert_eq!(image.scale, Some(2));
    assert_eq!(image.bytes_per_row, Some(12));
    let files: Vec<CatalogFile> = catalog_files(&bytes, &catalog).expect("files");
    let paths: Vec<&str> = files
        .iter()
        .map(|file: &CatalogFile| file.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["Settings/0001-Settings.json", "unassigned/0002-badge.png"]
    );
    assert_eq!(files[0].bytes, b"{\"version\": 3}\n");
    assert!(files[1].bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
}

#[test]
fn corrupted_catalogs_are_refused_or_decoded_without_panicking() {
    let bytes: Vec<u8> = catalog();
    let mut refused: usize = 0;
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for case in 0..400usize {
        let mut mutated: Vec<u8> = bytes.clone();
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let at: usize = usize::try_from(state % u64::try_from(bytes.len()).unwrap()).unwrap();
        if case % 4 == 0 {
            mutated.truncate(at);
        } else {
            mutated[at] ^= u8::try_from(state >> 56).unwrap() | 1;
        }
        match decode_asset_catalog(&mutated) {
            Ok(catalog) => {
                let _files: Result<Vec<CatalogFile>, _> = catalog_files(&mutated, &catalog);
            }
            Err(error) => {
                assert!(error.to_string().contains("DR-IOS-0024"), "{error}");
                refused += 1;
            }
        }
    }
    assert!(
        refused > 100,
        "only {refused} of 400 corruptions were refused"
    );
}

#[test]
fn the_chain_claims_and_reports_an_asset_catalog() {
    let bytes: Vec<u8> = catalog();
    let verdict: DetectVerdict = AppleArchiveDetector
        .detect(&DetectContext {
            bytes: &bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        })
        .expect("claimed");
    assert_eq!(verdict.format_tag, "apple-asset-catalog");
    let report: Artifact = APPLE_ARCHIVE_PASS
        .run(&Artifact::new(Rung::Raw, bytes, [0u8; 32]))
        .expect("report");
    let json: serde_json::Value =
        serde_json::from_slice(report.envelope.as_slice()).expect("json report");
    assert_eq!(json["renditions"].as_array().map(Vec::len), Some(3));
    assert_eq!(json["renditions"][1]["uti"], "public.json");
}
