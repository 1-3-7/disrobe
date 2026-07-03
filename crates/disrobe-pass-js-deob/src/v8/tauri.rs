use serde::{Deserialize, Serialize};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PE_MZ: [u8; 2] = [b'M', b'Z'];
const MACHO_LE_32: u32 = 0xFEED_FACE;
const MACHO_LE_64: u32 = 0xFEED_FACF;
const MACHO_BE_32: u32 = 0xCEFA_EDFE;
const MACHO_BE_64: u32 = 0xCFFA_EDFE;
const WRY_MARKER: &[u8] = b"wry::application";
const WEBVIEW2_MARKER: &[u8] = b"WebView2";
const TAURI_MARKER: &[u8] = b"tauri::Builder";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeBinaryKind {
    Pe,
    Elf,
    MachO,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TauriBinaryClass {
    pub kind: NativeBinaryKind,
    pub has_wry_marker: bool,
    pub has_webview2_marker: bool,
    pub has_tauri_builder_marker: bool,
}

impl TauriBinaryClass {
    #[must_use]
    pub const fn is_tauri(self) -> bool {
        self.has_wry_marker || self.has_tauri_builder_marker
    }
}

#[must_use]
pub fn classify_tauri_binary(bytes: &[u8]) -> TauriBinaryClass {
    let kind: NativeBinaryKind = classify_native_kind(bytes);
    TauriBinaryClass {
        kind,
        has_wry_marker: contains_subslice(bytes, WRY_MARKER),
        has_webview2_marker: contains_subslice(bytes, WEBVIEW2_MARKER),
        has_tauri_builder_marker: contains_subslice(bytes, TAURI_MARKER),
    }
}

fn classify_native_kind(bytes: &[u8]) -> NativeBinaryKind {
    if bytes.len() < 4 {
        return NativeBinaryKind::Unknown;
    }
    if bytes.starts_with(&ELF_MAGIC) {
        return NativeBinaryKind::Elf;
    }
    if bytes.starts_with(&PE_MZ) {
        return NativeBinaryKind::Pe;
    }
    let m: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if matches!(m, MACHO_LE_32 | MACHO_LE_64 | MACHO_BE_32 | MACHO_BE_64) {
        return NativeBinaryKind::MachO;
    }
    NativeBinaryKind::Unknown
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn classifies_elf_with_wry_marker() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&ELF_MAGIC);
        bytes.extend(std::iter::repeat_n(0u8, 64));
        bytes.extend_from_slice(WRY_MARKER);
        let class: TauriBinaryClass = classify_tauri_binary(&bytes);
        assert_eq!(class.kind, NativeBinaryKind::Elf);
        assert!(class.has_wry_marker);
        assert!(class.is_tauri());
    }

    #[test]
    fn classifies_pe_with_webview2_marker() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&PE_MZ);
        bytes.extend(std::iter::repeat_n(0u8, 64));
        bytes.extend_from_slice(WEBVIEW2_MARKER);
        let class: TauriBinaryClass = classify_tauri_binary(&bytes);
        assert_eq!(class.kind, NativeBinaryKind::Pe);
        assert!(class.has_webview2_marker);
    }

    #[test]
    fn classifies_macho_le_64() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&MACHO_LE_64.to_le_bytes());
        bytes.extend(std::iter::repeat_n(0u8, 64));
        bytes.extend_from_slice(TAURI_MARKER);
        let class: TauriBinaryClass = classify_tauri_binary(&bytes);
        assert_eq!(class.kind, NativeBinaryKind::MachO);
        assert!(class.has_tauri_builder_marker);
        assert!(class.is_tauri());
    }

    #[test]
    fn unknown_binary_kind_without_native_magic() {
        let bytes: Vec<u8> = vec![0u8; 256];
        let class: TauriBinaryClass = classify_tauri_binary(&bytes);
        assert_eq!(class.kind, NativeBinaryKind::Unknown);
        assert!(!class.is_tauri());
    }
}
