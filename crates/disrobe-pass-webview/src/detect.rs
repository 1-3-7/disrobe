use crate::electron;
use crate::model::WebviewFamily;

const TAURI_MARKERS: [&[u8]; 5] = [
    b"tauri://localhost",
    b"__TAURI_INTERNALS__",
    b"__TAURI__",
    b"tauri://",
    b"isTauri",
];

const WAILS_MARKERS: [&[u8]; 4] = [
    b"wails://",
    b"/wails/runtime",
    b"window.runtime",
    b"WailsInvoke",
];

const DEFAULT_DETECT_SCAN_CANDIDATES: usize = 256;

#[must_use]
pub fn detect_family(bytes: &[u8]) -> Option<WebviewFamily> {
    if electron::locate_header(bytes, DEFAULT_DETECT_SCAN_CANDIDATES).is_some() {
        return Some(WebviewFamily::Electron);
    }
    if contains_any(bytes, &TAURI_MARKERS) {
        return Some(WebviewFamily::Tauri);
    }
    if contains_any(bytes, &WAILS_MARKERS) {
        return Some(WebviewFamily::Wails);
    }
    None
}

fn contains_any(hay: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle: &&[u8]| contains(hay, needle))
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
