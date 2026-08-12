use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::container::{self, ContainerKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lang {
    Python,
    JavaScript,
    TypeScript,
    Wasm,
    Java,
    DotNet,
    Native,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObfuscatorFamily {
    JavaScriptObfuscator,
    JsConfuser,
    Jscrambler,
    Hyperion,
    PyArmor,
    SourceDefender,
    Wasmixer,
    Wobfuscator,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeFormat {
    Pe,
    Ne,
    Elf,
    MachO,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeLangHint {
    Nim,
    Zig,
    Crystal,
}

impl NativeLangHint {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nim => "nim",
            Self::Zig => "zig",
            Self::Crystal => "crystal",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Action {
    Decompile { lang: Lang },
    Deobfuscate { family: ObfuscatorFamily },
    ExtractArchive { container: ContainerKind },
    ChainExtract { first: Box<Self>, then: Box<Self> },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(pub f32);

#[derive(Debug, Clone, Serialize)]
pub struct InputClassification {
    pub primary_action: Action,
    pub candidates: Vec<(Action, Confidence)>,
    pub reason: String,
    pub native: Option<crate::native::NativeFile>,
    pub native_lang: Option<NativeLangHint>,
}

const PE_MAGIC: &[u8; 2] = b"MZ";
const ELF_MAGIC: &[u8; 4] = &[0x7f, b'E', b'L', b'F'];
const MACHO_64_LE: &[u8; 4] = &[0xcf, 0xfa, 0xed, 0xfe];
const MACHO_32_LE: &[u8; 4] = &[0xce, 0xfa, 0xed, 0xfe];
const MACHO_64_BE: &[u8; 4] = &[0xfe, 0xed, 0xfa, 0xcf];
const MACHO_32_BE: &[u8; 4] = &[0xfe, 0xed, 0xfa, 0xce];
const MACHO_FAT_BE: &[u8; 4] = &[0xca, 0xfe, 0xba, 0xbe];
const MACHO_FAT_LE: &[u8; 4] = &[0xbe, 0xba, 0xfe, 0xca];
const WASM_MAGIC: &[u8; 4] = &[0x00, b'a', b's', b'm'];
const JAVA_CLASS_MAGIC: &[u8; 4] = &[0xca, 0xfe, 0xba, 0xbe];
const PYINSTALLER_COOKIE: &[u8; 8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const SOURCEDEFENDER_MAGIC: &[u8; 8] = b"PYE006.0";
const SOURCE_HEAD_BYTES: usize = 4096;

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn classify_input(path: &Path, bytes: &[u8]) -> InputClassification {
    if bytes.is_empty() {
        return InputClassification {
            primary_action: Action::Unknown,
            candidates: Vec::new(),
            reason: "empty input".to_owned(),
            native: None,
            native_lang: None,
        };
    }

    if let Some(container_kind) = container::detect_container_with_hint(bytes, Some(path)) {
        return InputClassification {
            primary_action: Action::ExtractArchive {
                container: container_kind,
            },
            candidates: vec![(
                Action::ExtractArchive {
                    container: container_kind,
                },
                Confidence(0.95),
            )],
            reason: format!(
                "container magic/tail/extension matched: {}",
                container_kind.label()
            ),
            native: None,
            native_lang: None,
        };
    }

    if let Some(fp) = pyc_fingerprint(bytes) {
        let reason: String = format!("python .pyc magic {fp:#06x} detected - decompile to source");
        return InputClassification {
            primary_action: Action::Decompile { lang: Lang::Python },
            candidates: vec![(Action::Decompile { lang: Lang::Python }, Confidence(0.95))],
            reason,
            native: None,
            native_lang: None,
        };
    }

    if bytes.len() >= 8 && &bytes[..4] == WASM_MAGIC {
        return InputClassification {
            primary_action: Action::Decompile { lang: Lang::Wasm },
            candidates: vec![(Action::Decompile { lang: Lang::Wasm }, Confidence(0.95))],
            reason: "wasm \\0asm magic detected".to_owned(),
            native: None,
            native_lang: None,
        };
    }

    if bytes.len() >= 8 && &bytes[..4] == JAVA_CLASS_MAGIC && looks_like_java_class(bytes) {
        return InputClassification {
            primary_action: Action::Decompile { lang: Lang::Java },
            candidates: vec![(Action::Decompile { lang: Lang::Java }, Confidence(0.95))],
            reason: "java class magic 0xcafebabe detected".to_owned(),
            native: None,
            native_lang: None,
        };
    }

    if let Some(non_native) = classify_non_native_structural(bytes) {
        return non_native;
    }

    if let Some(native) = native_format(bytes) {
        let parsed: Option<crate::native::NativeFile> = crate::native::parse_native(bytes).ok();
        if bytes_contains(bytes, PYINSTALLER_COOKIE) {
            let chain: Action = Action::ChainExtract {
                first: Box::new(Action::ExtractArchive {
                    container: ContainerKind::None,
                }),
                then: Box::new(Action::Decompile { lang: Lang::Python }),
            };
            return InputClassification {
                primary_action: chain.clone(),
                candidates: vec![(chain, Confidence(0.92))],
                reason: format!(
                    "native {native:?} + pyinstaller MEI cookie - extract archive then decompile .pyc"
                ),
                native: parsed,
                native_lang: None,
            };
        }
        if bytes_contains(bytes, b"NUITKA_VERSION") || bytes_contains(bytes, b"Nuitka_VERSION") {
            return InputClassification {
                primary_action: Action::Decompile { lang: Lang::Native },
                candidates: vec![(Action::Decompile { lang: Lang::Native }, Confidence(0.75))],
                reason: "native binary + Nuitka markers - semantic recovery only".to_owned(),
                native: parsed,
                native_lang: None,
            };
        }
        if let Some(autoit_marker) = autoit_compiled_marker(bytes) {
            return InputClassification {
                primary_action: Action::Decompile { lang: Lang::Native },
                candidates: vec![(Action::Decompile { lang: Lang::Native }, Confidence(0.8))],
                reason: format!(
                    "native {native:?} + AutoIt compiled-script marker `{autoit_marker}` - embedded tokenised AutoIt3 script (use an AutoIt decompiler such as myAut2Exe / Exe2Aut on the located overlay)"
                ),
                native: parsed,
                native_lang: None,
            };
        }
        let native_lang: Option<NativeLangHint> = native_lang_fingerprint(bytes);
        let reason: String = native_lang.map_or_else(
            || format!("native {native:?} binary - pass-first native handling"),
            |lang: NativeLangHint| {
                format!(
                    "native {native:?} binary + {} fingerprint - symbol/metadata recovery (source not recoverable)",
                    lang.label()
                )
            },
        );
        let confidence: f32 = if native_lang.is_some() { 0.8 } else { 0.6 };
        return InputClassification {
            primary_action: Action::Decompile { lang: Lang::Native },
            candidates: vec![(
                Action::Decompile { lang: Lang::Native },
                Confidence(confidence),
            )],
            reason,
            native: parsed,
            native_lang,
        };
    }

    if bytes.starts_with(SOURCEDEFENDER_MAGIC) {
        return InputClassification {
            primary_action: Action::ChainExtract {
                first: Box::new(Action::Deobfuscate {
                    family: ObfuscatorFamily::SourceDefender,
                }),
                then: Box::new(Action::Decompile { lang: Lang::Python }),
            },
            candidates: vec![(
                Action::Deobfuscate {
                    family: ObfuscatorFamily::SourceDefender,
                },
                Confidence(0.95),
            )],
            reason: "sourcedefender PYE006.0 magic detected".to_owned(),
            native: None,
            native_lang: None,
        };
    }

    classify_source_text(path, bytes)
}

fn classify_source_text(path: &Path, bytes: &[u8]) -> InputClassification {
    let extension: Option<String> = path
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .map(|s: &str| s.to_ascii_lowercase());
    let text_head: &str = std::str::from_utf8(&bytes[..bytes.len().min(SOURCE_HEAD_BYTES)])
        .map_or("", |value: &str| value);

    match extension.as_deref() {
        Some("ts" | "tsx") => InputClassification {
            primary_action: Action::Decompile {
                lang: Lang::TypeScript,
            },
            candidates: vec![(
                Action::Decompile {
                    lang: Lang::TypeScript,
                },
                Confidence(0.6),
            )],
            reason: "typescript extension - already source, no obfuscator-family heuristic"
                .to_owned(),
            native: None,
            native_lang: None,
        },
        Some("js" | "jsx" | "mjs" | "cjs") => classify_js_text(text_head),
        Some("py") => InputClassification {
            primary_action: Action::Decompile { lang: Lang::Python },
            candidates: vec![(Action::Decompile { lang: Lang::Python }, Confidence(0.6))],
            reason: "python .py extension - already source".to_owned(),
            native: None,
            native_lang: None,
        },
        Some("pyc" | "pyo") => InputClassification {
            primary_action: Action::Decompile { lang: Lang::Python },
            candidates: vec![(Action::Decompile { lang: Lang::Python }, Confidence(0.6))],
            reason: "python .pyc extension".to_owned(),
            native: None,
            native_lang: None,
        },
        Some("pye") => InputClassification {
            primary_action: Action::ChainExtract {
                first: Box::new(Action::Deobfuscate {
                    family: ObfuscatorFamily::SourceDefender,
                }),
                then: Box::new(Action::Decompile { lang: Lang::Python }),
            },
            candidates: vec![(
                Action::Deobfuscate {
                    family: ObfuscatorFamily::SourceDefender,
                },
                Confidence(0.85),
            )],
            reason: "sourcedefender .pye extension - decrypt then decompile".to_owned(),
            native: None,
            native_lang: None,
        },
        Some("wasm") => InputClassification {
            primary_action: Action::Decompile { lang: Lang::Wasm },
            candidates: vec![(Action::Decompile { lang: Lang::Wasm }, Confidence(0.6))],
            reason: ".wasm extension".to_owned(),
            native: None,
            native_lang: None,
        },
        Some("wat") => InputClassification {
            primary_action: Action::Decompile { lang: Lang::Wasm },
            candidates: vec![(Action::Decompile { lang: Lang::Wasm }, Confidence(0.6))],
            reason: ".wat extension".to_owned(),
            native: None,
            native_lang: None,
        },
        Some("class") => InputClassification {
            primary_action: Action::Decompile { lang: Lang::Java },
            candidates: vec![(Action::Decompile { lang: Lang::Java }, Confidence(0.6))],
            reason: ".class extension".to_owned(),
            native: None,
            native_lang: None,
        },
        _ => InputClassification {
            primary_action: Action::Unknown,
            candidates: Vec::new(),
            reason: "no magic, no recognized extension".to_owned(),
            native: None,
            native_lang: None,
        },
    }
}

fn classify_js_text(text_head: &str) -> InputClassification {
    if text_head.contains("obfuscator.io") {
        return InputClassification {
            primary_action: Action::Deobfuscate {
                family: ObfuscatorFamily::JavaScriptObfuscator,
            },
            candidates: vec![(
                Action::Deobfuscate {
                    family: ObfuscatorFamily::JavaScriptObfuscator,
                },
                Confidence(0.95),
            )],
            reason: "obfuscator.io banner present".to_owned(),
            native: None,
            native_lang: None,
        };
    }
    if text_head.contains("jscrambler") {
        return InputClassification {
            primary_action: Action::Deobfuscate {
                family: ObfuscatorFamily::Jscrambler,
            },
            candidates: vec![(
                Action::Deobfuscate {
                    family: ObfuscatorFamily::Jscrambler,
                },
                Confidence(0.95),
            )],
            reason: "jscrambler banner present".to_owned(),
            native: None,
            native_lang: None,
        };
    }
    if has_high_hex_identifier_density(text_head) {
        return InputClassification {
            primary_action: Action::Deobfuscate {
                family: ObfuscatorFamily::JavaScriptObfuscator,
            },
            candidates: vec![(
                Action::Deobfuscate {
                    family: ObfuscatorFamily::JavaScriptObfuscator,
                },
                Confidence(0.85),
            )],
            reason: "high _0xXXXX identifier density + eval/decode shape".to_owned(),
            native: None,
            native_lang: None,
        };
    }
    if text_head.contains("_$_") && text_head.contains("globalThis") {
        return InputClassification {
            primary_action: Action::Deobfuscate {
                family: ObfuscatorFamily::JsConfuser,
            },
            candidates: vec![(
                Action::Deobfuscate {
                    family: ObfuscatorFamily::JsConfuser,
                },
                Confidence(0.7),
            )],
            reason: "js-confuser dispatcher pattern (_$_ + globalThis)".to_owned(),
            native: None,
            native_lang: None,
        };
    }
    InputClassification {
        primary_action: Action::Decompile {
            lang: Lang::JavaScript,
        },
        candidates: vec![(
            Action::Decompile {
                lang: Lang::JavaScript,
            },
            Confidence(0.5),
        )],
        reason: "javascript source, no obfuscator markers - pass-through".to_owned(),
        native: None,
        native_lang: None,
    }
}

fn has_high_hex_identifier_density(text: &str) -> bool {
    let head: &str = disrobe_core::strings::head(text, SOURCE_HEAD_BYTES);
    let occurrences: usize = head.matches("_0x").count();
    let eval_or_decode: bool = head.contains("eval(") || head.contains(".charCodeAt(");
    occurrences >= 6 && eval_or_decode
}

fn pyc_fingerprint(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let suffix: u32 = (magic >> 16) & 0xFFFF;
    if suffix != 0x0A0D {
        return None;
    }
    let lower: u16 = (magic & 0xFFFF) as u16;
    matches!(
        lower,
        62211
            | 3230
            | 3310
            | 3351
            | 3379
            | 3394
            | 3413
            | 3425
            | 3439
            | 3494
            | 3495
            | 3531
            | 3571
            | 3627
    )
    .then_some(magic)
}

fn looks_like_java_class(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let major_be: u16 = u16::from_be_bytes([bytes[6], bytes[7]]);
    matches!(major_be, 45..=80)
}

fn native_format(bytes: &[u8]) -> Option<NativeFormat> {
    if crate::ne::is_ne(bytes) {
        return crate::ne::parse_ne(bytes).ok().map(|_| NativeFormat::Ne);
    }
    if bytes.len() >= 4 && bytes.starts_with(ELF_MAGIC) {
        return Some(NativeFormat::Elf);
    }
    if bytes.len() >= 4
        && (bytes.starts_with(MACHO_64_LE)
            || bytes.starts_with(MACHO_32_LE)
            || bytes.starts_with(MACHO_64_BE)
            || bytes.starts_with(MACHO_32_BE)
            || bytes.starts_with(MACHO_FAT_BE)
            || bytes.starts_with(MACHO_FAT_LE))
    {
        return Some(NativeFormat::MachO);
    }
    if bytes.len() >= 2 && bytes.starts_with(PE_MAGIC) {
        return Some(NativeFormat::Pe);
    }
    native_format_structural(bytes)
}

fn native_format_structural(bytes: &[u8]) -> Option<NativeFormat> {
    match crate::structural::identify_by_structure(bytes)? {
        crate::structural::StructuralFormat::Pe => Some(NativeFormat::Pe),
        crate::structural::StructuralFormat::Elf => Some(NativeFormat::Elf),
        crate::structural::StructuralFormat::MachO
        | crate::structural::StructuralFormat::MachOFat => Some(NativeFormat::MachO),
        _ => None,
    }
}

fn classify_non_native_structural(bytes: &[u8]) -> Option<InputClassification> {
    match crate::structural::identify_by_structure(bytes)? {
        crate::structural::StructuralFormat::Wasm => Some(InputClassification {
            primary_action: Action::Decompile { lang: Lang::Wasm },
            candidates: vec![(Action::Decompile { lang: Lang::Wasm }, Confidence(0.8))],
            reason: "wasm \\0asm magic scrambled - section id/size stream validated structurally"
                .to_owned(),
            native: None,
            native_lang: None,
        }),
        crate::structural::StructuralFormat::JavaClass => Some(InputClassification {
            primary_action: Action::Decompile { lang: Lang::Java },
            candidates: vec![(Action::Decompile { lang: Lang::Java }, Confidence(0.8))],
            reason:
                "java class magic scrambled - constant-pool walk + version range validated structurally"
                    .to_owned(),
            native: None,
            native_lang: None,
        }),
        _ => None,
    }
}

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    disrobe_core::byte_search::contains(haystack, needle)
}

const AUTOIT_MARKERS: &[&[u8]] = &[
    b"AU3!EA06",
    b"AU3!EA05",
    b">>>AUTOIT SCRIPT<<<",
    b"AutoIt v3",
];

fn autoit_compiled_marker(bytes: &[u8]) -> Option<&'static str> {
    AUTOIT_MARKERS
        .iter()
        .find(|m: &&&[u8]| bytes_contains(bytes, m))
        .map(|m: &&[u8]| match *m {
            b"AU3!EA06" => "AU3!EA06",
            b"AU3!EA05" => "AU3!EA05",
            b">>>AUTOIT SCRIPT<<<" => ">>>AUTOIT SCRIPT<<<",
            _ => "AutoIt v3",
        })
}

const NIM_LANG_MARKERS: &[&[u8]] = &[b"NimMainModule", b"NimMainInner", b"PreMainInner"];
const ZIG_LANG_MARKERS: &[&[u8]] = &[
    b"start.posixCallMainAndExit",
    b"start.callMain",
    b"__zig_probe_stack",
];
const CRYSTAL_LANG_MARKERS: &[&[u8]] = &[
    b"__crystal_raise",
    b"Crystal::EventLoop",
    b"Crystal::System",
];

#[must_use]
pub fn native_lang_fingerprint(bytes: &[u8]) -> Option<NativeLangHint> {
    let score = |markers: &[&[u8]]| -> usize {
        markers
            .iter()
            .filter(|m: &&&[u8]| bytes_contains(bytes, m))
            .count()
    };
    let candidates: [(NativeLangHint, usize); 3] = [
        (NativeLangHint::Nim, score(NIM_LANG_MARKERS)),
        (NativeLangHint::Zig, score(ZIG_LANG_MARKERS)),
        (NativeLangHint::Crystal, score(CRYSTAL_LANG_MARKERS)),
    ];
    candidates
        .into_iter()
        .filter(|(_, hits): &(NativeLangHint, usize)| *hits > 0)
        .max_by_key(|(_, hits): &(NativeLangHint, usize)| *hits)
        .map(|(lang, _): (NativeLangHint, usize)| lang)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn empty_input_returns_unknown() {
        let cl: InputClassification = classify_input(&PathBuf::from("a.bin"), &[]);
        assert!(matches!(cl.primary_action, Action::Unknown));
    }

    #[test]
    fn zip_magic_routes_to_extract() {
        let mut bytes: Vec<u8> = b"PK\x03\x04".to_vec();
        bytes.extend([0u8; 256]);
        let cl: InputClassification = classify_input(&PathBuf::from("a.zip"), &bytes);
        let Action::ExtractArchive { container } = cl.primary_action else {
            panic!("expected extract");
        };
        assert_eq!(container, ContainerKind::Zip);
    }

    #[test]
    fn jar_extension_refines_to_jar() {
        let mut bytes: Vec<u8> = b"PK\x03\x04".to_vec();
        bytes.extend([0u8; 256]);
        let cl: InputClassification = classify_input(&PathBuf::from("app.jar"), &bytes);
        let Action::ExtractArchive { container } = cl.primary_action else {
            panic!("expected extract");
        };
        assert_eq!(container, ContainerKind::Jar);
    }

    #[test]
    fn pyc_magic_routes_to_python_decompile() {
        let mut bytes: Vec<u8> = vec![0u8; 16];
        bytes[0..2].copy_from_slice(&3531u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&0x0A0Du16.to_le_bytes());
        let cl: InputClassification = classify_input(&PathBuf::from("mod.pyc"), &bytes);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::Python);
    }

    #[test]
    fn wasm_magic_routes_to_wasm_decompile() {
        let bytes: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let cl: InputClassification = classify_input(&PathBuf::from("a.wasm"), &bytes);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::Wasm);
    }

    #[test]
    fn pe_plus_pyinstaller_cookie_chains() {
        let mut bytes: Vec<u8> = vec![b'M', b'Z'];
        bytes.extend([0u8; 1024]);
        bytes.extend_from_slice(PYINSTALLER_COOKIE);
        let cl: InputClassification = classify_input(&PathBuf::from("app.exe"), &bytes);
        let Action::ChainExtract { first, then } = cl.primary_action else {
            panic!("expected chain");
        };
        assert!(matches!(*first, Action::ExtractArchive { .. }));
        assert!(matches!(*then, Action::Decompile { lang: Lang::Python }));
    }

    #[test]
    fn pe_plus_autoit_marker_surfaces_autoit_hint() {
        let mut bytes: Vec<u8> = vec![b'M', b'Z'];
        bytes.extend([0u8; 1024]);
        bytes.extend_from_slice(b"AU3!EA06");
        bytes.extend([0u8; 64]);
        let cl: InputClassification = classify_input(&PathBuf::from("setup.exe"), &bytes);
        assert!(
            cl.reason.contains("AutoIt") && cl.reason.contains("AU3!EA06"),
            "must surface the AutoIt compiled-script marker: {}",
            cl.reason
        );
    }

    #[test]
    fn pe_only_routes_to_native_decompile() {
        let mut bytes: Vec<u8> = vec![b'M', b'Z'];
        bytes.extend([0u8; 1024]);
        let cl: InputClassification = classify_input(&PathBuf::from("app.exe"), &bytes);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::Native);
    }

    #[test]
    fn elf_with_nuitka_marker_routes_to_native_recovery() {
        let mut bytes: Vec<u8> = ELF_MAGIC.to_vec();
        bytes.extend([0u8; 64]);
        bytes.extend_from_slice(b"...NUITKA_VERSION 2.0...");
        let cl: InputClassification = classify_input(&PathBuf::from("app"), &bytes);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::Native);
        assert!(cl.reason.contains("Nuitka"));
    }

    #[test]
    fn java_class_magic_detected() {
        let bytes: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x37, 0x00, 0x10];
        let cl: InputClassification = classify_input(&PathBuf::from("Foo.class"), &bytes);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::Java);
    }

    #[test]
    fn macho_fat_does_not_collide_with_java() {
        let bytes: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00];
        let cl: InputClassification = classify_input(&PathBuf::from("universal.bin"), &bytes);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::Native);
    }

    #[test]
    fn sourcedefender_pye_chains_decrypt_then_decompile() {
        let mut bytes: Vec<u8> = SOURCEDEFENDER_MAGIC.to_vec();
        bytes.extend([0u8; 64]);
        let cl: InputClassification = classify_input(&PathBuf::from("a.pye"), &bytes);
        let Action::ChainExtract { first, then } = cl.primary_action else {
            panic!("expected chain");
        };
        assert!(matches!(
            *first,
            Action::Deobfuscate {
                family: ObfuscatorFamily::SourceDefender
            }
        ));
        assert!(matches!(*then, Action::Decompile { lang: Lang::Python }));
    }

    #[test]
    fn obfuscated_js_banner_routes_to_deobfuscate() {
        let src: &[u8] = b"// obfuscator.io output\nvar _0x1234 = ['a'];";
        let cl: InputClassification = classify_input(&PathBuf::from("a.js"), src);
        let Action::Deobfuscate { family } = cl.primary_action else {
            panic!("expected deob");
        };
        assert_eq!(family, ObfuscatorFamily::JavaScriptObfuscator);
    }

    #[test]
    fn clean_js_routes_to_passthrough_decompile() {
        let src: &[u8] = b"const x = 1;\nfunction foo() { return x + 1; }";
        let cl: InputClassification = classify_input(&PathBuf::from("a.js"), src);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::JavaScript);
    }

    #[test]
    fn ts_extension_routes_to_typescript_decompile() {
        let src: &[u8] = b"export const x: number = 1;";
        let cl: InputClassification = classify_input(&PathBuf::from("a.ts"), src);
        let Action::Decompile { lang } = cl.primary_action else {
            panic!("expected decompile");
        };
        assert_eq!(lang, Lang::TypeScript);
    }

    #[test]
    fn hex_identifier_density_heuristic_triggers() {
        let mut s: String = String::from("eval(function(){\n");
        for _ in 0..10 {
            s.push_str("var _0x1234 = 'x'; ");
        }
        let cl: InputClassification = classify_input(&PathBuf::from("a.js"), s.as_bytes());
        let Action::Deobfuscate { family } = cl.primary_action else {
            panic!("expected deob");
        };
        assert_eq!(family, ObfuscatorFamily::JavaScriptObfuscator);
    }

    fn corpus_native(rel: &str) -> Option<Vec<u8>> {
        let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("..");
        p.push("..");
        p.push("corpus");
        p.push("native");
        p.push(rel);
        std::fs::read(&p).ok()
    }

    #[test]
    fn native_lang_fingerprint_distinguishes_zig_nim_crystal() {
        let cases: [(&str, NativeLangHint); 3] = [
            ("zig/hello.zig.elf", NativeLangHint::Zig),
            ("nim/hello.nim.elf", NativeLangHint::Nim),
            ("crystal/hello.cr.exe", NativeLangHint::Crystal),
        ];
        for (rel, expected) in cases {
            let Some(bytes): Option<Vec<u8>> = corpus_native(rel) else {
                eprintln!("FIXTURE PENDING: corpus/native/{rel}");
                continue;
            };
            assert_eq!(
                native_lang_fingerprint(&bytes),
                Some(expected),
                "fingerprint mismatch for {rel}"
            );
        }
    }

    #[test]
    fn classify_native_lang_surfaces_hint() {
        let Some(bytes): Option<Vec<u8>> = corpus_native("zig/hello.zig.elf") else {
            return;
        };
        let cl: InputClassification = classify_input(&PathBuf::from("hello"), &bytes);
        assert_eq!(cl.native_lang, Some(NativeLangHint::Zig));
        assert!(matches!(
            cl.primary_action,
            Action::Decompile { lang: Lang::Native }
        ));
    }

    #[test]
    fn malformed_ne_signature_does_not_create_a_native_classification() {
        const REAL_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
        let mut bytes: Vec<u8> = REAL_NE.to_vec();
        bytes[0x08..0x0a].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(native_format(&bytes), None);
        let classified: InputClassification = classify_input(&PathBuf::from("invalid.exe"), &bytes);
        assert!(classified.native.is_none());
    }
}
