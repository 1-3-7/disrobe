use crate::electron;
use crate::model::WebviewFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marker {
    needle: &'static [u8],
    label: &'static str,
    weight: u32,
}

const ELECTRON_MARKERS: [Marker; 4] = [
    Marker {
        needle: b"v8_context_snapshot",
        label: "v8-context-snapshot",
        weight: 30,
    },
    Marker {
        needle: b"electron.asar",
        label: "electron-asar-string",
        weight: 30,
    },
    Marker {
        needle: b"ELECTRON_RUN_AS_NODE",
        label: "electron-run-as-node",
        weight: 25,
    },
    Marker {
        needle: b"app.asar",
        label: "app-asar-string",
        weight: 15,
    },
];

const TAURI_MARKERS: [Marker; 6] = [
    Marker {
        needle: b"__TAURI_INTERNALS__",
        label: "tauri-internals",
        weight: 40,
    },
    Marker {
        needle: b"tauri://localhost",
        label: "tauri-localhost",
        weight: 35,
    },
    Marker {
        needle: b"__TAURI__",
        label: "tauri-global",
        weight: 30,
    },
    Marker {
        needle: b"tauri://",
        label: "tauri-scheme",
        weight: 20,
    },
    Marker {
        needle: b"isTauri",
        label: "is-tauri",
        weight: 10,
    },
    Marker {
        needle: b"wry",
        label: "wry-webview",
        weight: 5,
    },
];

const WAILS_MARKERS: [Marker; 5] = [
    Marker {
        needle: b"/wails/runtime",
        label: "wails-runtime-route",
        weight: 40,
    },
    Marker {
        needle: b"wails://",
        label: "wails-scheme",
        weight: 35,
    },
    Marker {
        needle: b"WailsInvoke",
        label: "wails-invoke",
        weight: 30,
    },
    Marker {
        needle: b"wailsapp/wails",
        label: "wails-module-path",
        weight: 30,
    },
    Marker {
        needle: b"window.runtime",
        label: "wails-window-runtime",
        weight: 10,
    },
];

const DEFAULT_DETECT_SCAN_CANDIDATES: usize = 256;
const ARCHIVE_CONFIDENCE: f32 = 0.97;
const MARKER_CONFIDENCE_BASE: f32 = 0.50;
const MARKER_CONFIDENCE_SPAN: f32 = 0.40;
const MARKER_SCORE_FULL: f32 = 100.0;
const MAX_EVIDENCE_MARKERS: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct FamilyEvidence {
    pub family: WebviewFamily,
    pub confidence: f32,
    pub markers: Vec<&'static str>,
    pub archive_verified: bool,
}

#[must_use]
pub fn detect_family(bytes: &[u8]) -> Option<WebviewFamily> {
    classify(bytes).map(|evidence: FamilyEvidence| evidence.family)
}

#[must_use]
pub fn classify(bytes: &[u8]) -> Option<FamilyEvidence> {
    classify_all(bytes).into_iter().next()
}

#[must_use]
pub fn classify_all(bytes: &[u8]) -> Vec<FamilyEvidence> {
    let mut ranked: Vec<FamilyEvidence> = Vec::new();
    let archive: bool = electron::locate_header(bytes, DEFAULT_DETECT_SCAN_CANDIDATES).is_some();
    let electron_markers: (Vec<&'static str>, u32) = match_markers(bytes, &ELECTRON_MARKERS);
    if archive {
        let mut markers: Vec<&'static str> = vec!["asar-pickle-header"];
        markers.extend(electron_markers.0.iter().copied());
        markers.truncate(MAX_EVIDENCE_MARKERS);
        ranked.push(FamilyEvidence {
            family: WebviewFamily::Electron,
            confidence: ARCHIVE_CONFIDENCE,
            markers,
            archive_verified: true,
        });
    } else if let Some(evidence) = marker_evidence(
        WebviewFamily::Electron,
        &electron_markers.0,
        electron_markers.1,
    ) {
        ranked.push(evidence);
    }
    let tauri: (Vec<&'static str>, u32) = match_markers(bytes, &TAURI_MARKERS);
    if let Some(evidence) = marker_evidence(WebviewFamily::Tauri, &tauri.0, tauri.1) {
        ranked.push(evidence);
    }
    let wails: (Vec<&'static str>, u32) = match_markers(bytes, &WAILS_MARKERS);
    if let Some(evidence) = marker_evidence(WebviewFamily::Wails, &wails.0, wails.1) {
        ranked.push(evidence);
    }
    ranked.sort_by(|a: &FamilyEvidence, b: &FamilyEvidence| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| a.family.label().cmp(b.family.label()))
    });
    ranked
}

pub(crate) fn embedded_family(bytes: &[u8]) -> WebviewFamily {
    classify_all(bytes)
        .into_iter()
        .find(|evidence: &FamilyEvidence| {
            matches!(evidence.family, WebviewFamily::Tauri | WebviewFamily::Wails)
        })
        .map_or(WebviewFamily::Unknown, |evidence: FamilyEvidence| {
            evidence.family
        })
}

fn marker_evidence(
    family: WebviewFamily,
    labels: &[&'static str],
    score: u32,
) -> Option<FamilyEvidence> {
    if labels.is_empty() {
        return None;
    }
    let mut markers: Vec<&'static str> = labels.to_vec();
    markers.truncate(MAX_EVIDENCE_MARKERS);
    Some(FamilyEvidence {
        family,
        confidence: marker_confidence(score),
        markers,
        archive_verified: false,
    })
}

fn marker_confidence(score: u32) -> f32 {
    let ratio: f32 = (score as f32 / MARKER_SCORE_FULL).min(1.0);
    MARKER_CONFIDENCE_SPAN.mul_add(ratio, MARKER_CONFIDENCE_BASE)
}

fn match_markers(hay: &[u8], markers: &[Marker]) -> (Vec<&'static str>, u32) {
    let mut labels: Vec<&'static str> = Vec::new();
    let mut score: u32 = 0;
    for marker in markers {
        if contains(hay, marker.needle) {
            labels.push(marker.label);
            score = score.saturating_add(marker.weight);
        }
    }
    (labels, score)
}

pub(crate) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find_from(hay, needle, 0).is_some()
}

pub(crate) fn find_from(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= hay.len() {
        return None;
    }
    let window: usize = needle.len();
    if hay.len() < window {
        return None;
    }
    let last: usize = hay.len() - window;
    let first: u8 = needle[0];
    let mut index: usize = start;
    while index <= last {
        if hay[index] == first && &hay[index..index + window] == needle {
            return Some(index);
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn no_evidence_yields_no_family() {
        assert!(classify(&[0u8; 512]).is_none());
        assert!(classify(b"").is_none());
        assert!(detect_family(b"a plain text file with no webview markers at all").is_none());
    }

    #[test]
    fn marker_only_hit_is_reported_below_a_verified_archive() {
        let tauri: FamilyEvidence = classify(b"prefix __TAURI_INTERNALS__ suffix").expect("tauri");
        assert_eq!(tauri.family, WebviewFamily::Tauri);
        assert!(!tauri.archive_verified);
        assert!(
            tauri.confidence < ARCHIVE_CONFIDENCE,
            "a marker-only hit must never reach the confidence of a parsed archive header"
        );
    }

    #[test]
    fn more_specific_markers_raise_confidence() {
        let weak: FamilyEvidence = classify(b"isTauri").expect("weak tauri");
        let strong: FamilyEvidence =
            classify(b"__TAURI_INTERNALS__ tauri://localhost __TAURI__").expect("strong tauri");
        assert!(
            strong.confidence > weak.confidence,
            "three specific markers must outrank one generic marker"
        );
        assert!(weak.markers.len() < strong.markers.len());
    }

    #[test]
    fn coexisting_families_are_ranked_not_collapsed() {
        let mixed: Vec<FamilyEvidence> =
            classify_all(b"__TAURI_INTERNALS__ tauri://localhost and window.runtime");
        assert_eq!(mixed.len(), 2, "both families must survive as evidence");
        assert_eq!(
            mixed[0].family,
            WebviewFamily::Tauri,
            "the stronger marker set decides precedence, not the scan order"
        );
        assert_eq!(mixed[1].family, WebviewFamily::Wails);
    }

    #[test]
    fn ranking_is_independent_of_marker_order_in_the_image() {
        let forward: Vec<WebviewFamily> = classify_all(b"wails:// then __TAURI_INTERNALS__")
            .into_iter()
            .map(|e: FamilyEvidence| e.family)
            .collect();
        let reverse: Vec<WebviewFamily> = classify_all(b"__TAURI_INTERNALS__ then wails://")
            .into_iter()
            .map(|e: FamilyEvidence| e.family)
            .collect();
        assert_eq!(forward, reverse);
    }
}
