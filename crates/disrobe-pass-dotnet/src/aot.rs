use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotReport {
    pub is_native_aot: bool,
    pub recovered_symbols: BTreeMap<String, u32>,
    pub modules_table_offset: Option<u32>,
    pub eager_class_constructors: u32,
    pub runtime_label: AotRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AotRuntime {
    Net7,
    Net8,
    Net9,
    Net10,
    Unknown,
}

const AOT_NEEDLES: &[(&[u8], &str)] = &[
    (b"__modules_a", "modules_table"),
    (b"NativeAOT", "aot_marker"),
    (b"RhpNewFast", "rhp_alloc"),
    (b"S_P_CoreLib", "corelib_module"),
    (b"S_P_TypeLoader", "typeloader_module"),
    (b"RhFindBlob", "rh_blob_locator"),
    (b"RhpThrowEx", "rh_throw"),
    (b"RhpReversePInvoke", "reverse_pinvoke"),
];

const EAGER_CCTOR_SCAN_CAP: u32 = 512;

#[must_use]
pub fn detect(image: &[u8]) -> AotReport {
    let mut symbols: BTreeMap<String, u32> = BTreeMap::new();
    let mut modules_table_offset: Option<u32> = None;
    let mut eager: u32 = 0;
    for (needle, label) in AOT_NEEDLES {
        let mut start: usize = 0;
        while start < image.len() {
            let Some(found): Option<usize> = window_find(&image[start..], needle) else {
                break;
            };
            let absolute: u32 = u32::try_from(start + found).unwrap_or(u32::MAX);
            symbols.insert((*label).to_owned(), absolute);
            if *label == "modules_table" && modules_table_offset.is_none() {
                modules_table_offset = Some(absolute);
            }
            start += found + 1;
            if symbols.len() > 64 {
                break;
            }
        }
    }
    let eager_marker: &[u8] = b"EagerCctor";
    let mut cursor: usize = 0;
    while eager < EAGER_CCTOR_SCAN_CAP {
        let Some(pos): Option<usize> = window_find(&image[cursor..], eager_marker) else {
            break;
        };
        eager = eager.saturating_add(1);
        cursor += pos + eager_marker.len();
    }
    let is_native_aot: bool = symbols.contains_key("aot_marker")
        || symbols.contains_key("modules_table")
        || symbols.contains_key("rhp_alloc")
        || symbols.contains_key("corelib_module");
    let runtime: AotRuntime = classify_runtime(image);
    AotReport {
        is_native_aot,
        recovered_symbols: symbols,
        modules_table_offset,
        eager_class_constructors: eager,
        runtime_label: runtime,
    }
}

fn classify_runtime(image: &[u8]) -> AotRuntime {
    if window_find(image, b"net10.0").is_some() {
        AotRuntime::Net10
    } else if window_find(image, b"net9.0").is_some() {
        AotRuntime::Net9
    } else if window_find(image, b"net8.0").is_some() {
        AotRuntime::Net8
    } else if window_find(image, b"net7.0").is_some() {
        AotRuntime::Net7
    } else {
        AotRuntime::Unknown
    }
}

fn window_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_native_aot_when_marker_present() {
        let mut img: Vec<u8> = vec![0u8; 1024];
        img[100..109].copy_from_slice(b"NativeAOT");
        let report: AotReport = detect(&img);
        assert!(report.is_native_aot);
    }

    #[test]
    fn detect_reports_runtime_label_net8() {
        let mut img: Vec<u8> = b"...net8.0...".to_vec();
        img.extend_from_slice(b"NativeAOT");
        let report: AotReport = detect(&img);
        assert_eq!(report.runtime_label, AotRuntime::Net8);
    }

    #[test]
    fn detect_empty_image_is_not_aot() {
        let report: AotReport = detect(&[]);
        assert!(!report.is_native_aot);
    }

    #[test]
    fn eager_class_constructor_scan_is_capped() {
        let mut img: Vec<u8> = Vec::new();
        for _ in 0..600 {
            img.extend_from_slice(b"EagerCctor");
            img.push(0);
        }
        let report: AotReport = detect(&img);
        assert_eq!(report.eager_class_constructors, 512);
    }
}
