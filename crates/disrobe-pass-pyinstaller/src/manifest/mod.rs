mod protection;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cookie::{Cookie, CookieVariant};
use crate::extract::{ExtractOutput, ExtractedEntry};
use crate::toc::EntryType;

pub use protection::{ProtectionReport, ProtectionSignal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryClassification {
    EntryScript,
    Bootstrap,
    StdlibModule,
    UserPackageModule,
    UserPackage,
    PyzNested,
    NativeBinary,
    DataResource,
    SplashScreen,
    SymlinkAlias,
    UnknownAuxiliary,
}

impl EntryClassification {
    pub const fn label(self) -> &'static str {
        match self {
            Self::EntryScript => "entry-script",
            Self::Bootstrap => "bootstrap",
            Self::StdlibModule => "stdlib-module",
            Self::UserPackageModule => "user-package-module",
            Self::UserPackage => "user-package",
            Self::PyzNested => "pyz-nested",
            Self::NativeBinary => "native-binary",
            Self::DataResource => "data-resource",
            Self::SplashScreen => "splash-screen",
            Self::SymlinkAlias => "symlink-alias",
            Self::UnknownAuxiliary => "unknown-auxiliary",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub name: String,
    pub kind: String,
    pub classification: EntryClassification,
    pub size: u64,
    pub compressed_size: u64,
    pub compressed: bool,
    pub decrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyInstallerManifest {
    pub schema: String,
    pub cookie_variant: String,
    pub python_major: u8,
    pub python_minor: u8,
    pub python_libname: Option<String>,
    pub entry_script: Option<String>,
    pub entry_count: usize,
    pub upx_wrapped: bool,
    pub layout_hint: String,
    pub protection: ProtectionReport,
    pub entries: Vec<ManifestEntry>,
    pub kind_histogram: BTreeMap<String, usize>,
}

pub fn build_manifest(image: &[u8], output: &ExtractOutput) -> PyInstallerManifest {
    let cookie: &Cookie = &output.cookie;
    let protection: ProtectionReport = protection::build_protection(image, output);
    let entry_script: Option<String> = output
        .entries
        .iter()
        .find(|e| e.toc.entry_type == EntryType::Script)
        .map(|e| e.toc.name.clone());

    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut entries: Vec<ManifestEntry> = Vec::with_capacity(output.entries.len());
    for e in &output.entries {
        let classification: EntryClassification = classify(e);
        let kind_label: &'static str = e.toc.entry_type.label();
        *histogram.entry(kind_label.to_owned()).or_insert(0) += 1;
        entries.push(ManifestEntry {
            name: e.toc.name.clone(),
            kind: kind_label.to_owned(),
            classification,
            size: u64::from(e.toc.uncompressed_size),
            compressed_size: u64::from(e.toc.compressed_size),
            compressed: e.toc.compressed_flag == 1,
            decrypted: e.decrypted,
        });
    }

    PyInstallerManifest {
        schema: "disrobe.pyinstaller.manifest/v0".to_owned(),
        cookie_variant: cookie_variant_label(cookie).to_owned(),
        python_major: cookie.python_major,
        python_minor: cookie.python_minor,
        python_libname: cookie.python_libname.clone(),
        entry_script,
        entry_count: entries.len(),
        upx_wrapped: protection
            .signals
            .contains(&ProtectionSignal::UpxCompressedWrapper),
        layout_hint: layout_hint(image).to_owned(),
        protection,
        entries,
        kind_histogram: histogram,
    }
}

fn classify(entry: &ExtractedEntry) -> EntryClassification {
    let name: &String = &entry.toc.name;
    match entry.toc.entry_type {
        EntryType::Script => EntryClassification::EntryScript,
        EntryType::Module => {
            if name.starts_with("pyiboot") || name.starts_with("pyimod") || name == "struct" {
                EntryClassification::Bootstrap
            } else {
                EntryClassification::UserPackageModule
            }
        }
        EntryType::Package => EntryClassification::UserPackage,
        EntryType::Pyz | EntryType::PyzZipfile => EntryClassification::PyzNested,
        EntryType::Binary => {
            if looks_like_stdlib_native(name) {
                EntryClassification::StdlibModule
            } else {
                EntryClassification::NativeBinary
            }
        }
        EntryType::Data => EntryClassification::DataResource,
        EntryType::Splash => EntryClassification::SplashScreen,
        EntryType::Symlink => EntryClassification::SymlinkAlias,
        EntryType::Dependency | EntryType::RuntimeOption | EntryType::Unknown(_) => {
            EntryClassification::UnknownAuxiliary
        }
    }
}

fn looks_like_stdlib_native(name: &str) -> bool {
    let lower: String = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "_ssl.pyd"
            | "_hashlib.pyd"
            | "_socket.pyd"
            | "select.pyd"
            | "_bz2.pyd"
            | "_lzma.pyd"
            | "_decimal.pyd"
            | "unicodedata.pyd"
    ) {
        return true;
    }
    if !lower.starts_with("python") {
        return false;
    }
    extension_eq_ignore_case(&lower, "dll") || extension_eq_ignore_case(&lower, "so")
}

fn extension_eq_ignore_case(path: &str, ext: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

const fn cookie_variant_label(cookie: &Cookie) -> &'static str {
    match cookie.variant {
        CookieVariant::Pre21 => "pre-2.1",
        CookieVariant::V21Plus => "2.1+",
    }
}

fn layout_hint(image: &[u8]) -> &'static str {
    if image.len() < 0x40 {
        return "unknown";
    }
    let head: &[u8] = &image[..0x40];
    if head.starts_with(b"MZ") {
        "windows-onefile-exe"
    } else if head.starts_with(b"\x7fELF") {
        "linux-onefile-elf"
    } else if head.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || head.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
    {
        "macos-onefile-macho"
    } else {
        "unknown"
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cookie::Cookie;
    use crate::extract::ExtractOutput;
    use crate::toc::TocEntry;

    fn synthetic_cookie() -> Cookie {
        Cookie {
            variant: CookieVariant::V21Plus,
            magic_offset: 0,
            length_of_package: 0,
            toc_offset: 0,
            toc_length: 0,
            pyver: 312,
            python_libname: Some("python312.dll".to_owned()),
            python_major: 3,
            python_minor: 12,
        }
    }

    fn entry(name: &str, kind: EntryType, decrypted: bool, data: Vec<u8>) -> ExtractedEntry {
        let entry_size: u32 = u32::try_from(18 + name.len()).expect("name fits u32");
        let size_u32: u32 = u32::try_from(data.len()).expect("data fits u32");
        ExtractedEntry {
            toc: TocEntry {
                entry_size,
                entry_position: 0,
                compressed_size: size_u32,
                uncompressed_size: size_u32,
                compressed_flag: 1,
                entry_type: kind,
                name: name.to_owned(),
            },
            data,
            written_path: None,
            decrypted,
        }
    }

    fn output_with(entries: Vec<ExtractedEntry>, key: Option<[u8; 16]>) -> ExtractOutput {
        ExtractOutput {
            cookie: synthetic_cookie(),
            bare_pyc_paths: Vec::new(),
            encryption_key: key,
            entries,
        }
    }

    #[test]
    fn classifies_entry_script_and_pyz() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("main", EntryType::Script, false, vec![0u8; 10]),
            entry("PYZ-00.pyz", EntryType::Pyz, false, vec![0u8; 10]),
            entry("_socket.pyd", EntryType::Binary, false, vec![0u8; 10]),
        ];
        let out: ExtractOutput = output_with(entries, None);
        let m: PyInstallerManifest = build_manifest(&[0u8; 16], &out);
        assert_eq!(m.entry_script.as_deref(), Some("main"));
        assert_eq!(m.entries.len(), 3);
        assert_eq!(m.entries[1].classification, EntryClassification::PyzNested);
        assert_eq!(
            m.entries[2].classification,
            EntryClassification::StdlibModule
        );
    }

    #[test]
    fn protection_unencrypted_default() {
        let entries: Vec<ExtractedEntry> =
            vec![entry("main", EntryType::Script, false, vec![0u8; 10])];
        let out: ExtractOutput = output_with(entries, None);
        let m: PyInstallerManifest = build_manifest(&[0u8; 16], &out);
        assert!(
            m.protection
                .signals
                .contains(&ProtectionSignal::UnencryptedDefault)
        );
        assert!(!m.protection.key_recovered);
        assert!(m.protection.key_hex.is_none());
    }

    #[test]
    fn protection_legacy_keyed_when_key_module_present_and_key_recovered() {
        let entries: Vec<ExtractedEntry> = vec![
            entry(
                "pyimod00_crypto_key",
                EntryType::Module,
                false,
                vec![0u8; 10],
            ),
            entry("main", EntryType::Script, true, vec![0u8; 10]),
        ];
        let key: [u8; 16] = [0x11u8; 16];
        let out: ExtractOutput = output_with(entries, Some(key));
        let m: PyInstallerManifest = build_manifest(&[0u8; 16], &out);
        assert!(
            m.protection
                .signals
                .contains(&ProtectionSignal::LegacyAesCtrKeyed)
        );
        assert!(m.protection.key_recovered);
        assert_eq!(
            m.protection.key_hex.as_deref(),
            Some("11111111111111111111111111111111")
        );
        assert_eq!(m.protection.decrypted_entry_count, 1);
    }

    #[test]
    fn protection_aes_bootstrap_signal_when_marker_present() {
        let mut bootstrap_data: Vec<u8> = b"some AES key derivation here".to_vec();
        bootstrap_data.extend_from_slice(&[0u8; 8]);
        let entries: Vec<ExtractedEntry> = vec![entry(
            "pyiboot01_bootstrap",
            EntryType::Module,
            false,
            bootstrap_data,
        )];
        let out: ExtractOutput = output_with(entries, None);
        let m: PyInstallerManifest = build_manifest(&[0u8; 16], &out);
        assert!(
            m.protection
                .signals
                .contains(&ProtectionSignal::Pyiboot01BootstrapAes)
        );
    }

    #[test]
    fn upx_signal_when_magic_in_head() {
        let mut head: Vec<u8> = b"MZ--padding----------".to_vec();
        head.extend_from_slice(b"UPX!");
        head.extend(std::iter::repeat_n(0u8, 256));
        let entries: Vec<ExtractedEntry> =
            vec![entry("main", EntryType::Script, false, vec![0u8; 10])];
        let out: ExtractOutput = output_with(entries, None);
        let m: PyInstallerManifest = build_manifest(&head, &out);
        assert!(
            m.protection
                .signals
                .contains(&ProtectionSignal::UpxCompressedWrapper)
        );
        assert!(m.upx_wrapped);
        assert_eq!(m.layout_hint, "windows-onefile-exe");
    }

    #[test]
    fn classifies_data_and_splash_and_symlink() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("logo.png", EntryType::Data, false, vec![0u8; 4]),
            entry("splash.bin", EntryType::Splash, false, vec![0u8; 4]),
            entry("alias", EntryType::Symlink, false, vec![0u8; 4]),
        ];
        let out: ExtractOutput = output_with(entries, None);
        let m: PyInstallerManifest = build_manifest(&[0u8; 16], &out);
        assert_eq!(
            m.entries[0].classification,
            EntryClassification::DataResource
        );
        assert_eq!(
            m.entries[1].classification,
            EntryClassification::SplashScreen
        );
        assert_eq!(
            m.entries[2].classification,
            EntryClassification::SymlinkAlias
        );
    }

    #[test]
    fn histogram_counts_each_kind() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("main", EntryType::Script, false, vec![0u8; 4]),
            entry("a", EntryType::Module, false, vec![0u8; 4]),
            entry("b", EntryType::Module, false, vec![0u8; 4]),
            entry("pkg", EntryType::Package, false, vec![0u8; 4]),
        ];
        let out: ExtractOutput = output_with(entries, None);
        let m: PyInstallerManifest = build_manifest(&[0u8; 16], &out);
        assert_eq!(m.kind_histogram.get("script").copied(), Some(1));
        assert_eq!(m.kind_histogram.get("module").copied(), Some(2));
        assert_eq!(m.kind_histogram.get("package").copied(), Some(1));
    }

    #[test]
    fn protection_hex_key_is_lowercase_when_recovered() {
        let entries: Vec<ExtractedEntry> = vec![entry(
            "pyimod00_crypto_key",
            EntryType::Module,
            false,
            vec![0u8; 4],
        )];
        let key: [u8; 16] = [0xAB; 16];
        let out: ExtractOutput = output_with(entries, Some(key));
        let m: PyInstallerManifest = build_manifest(&[0u8; 16], &out);
        let hex: String = m.protection.key_hex.expect("key hex present");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hex.chars().all(|c| !c.is_ascii_uppercase()));
        assert_eq!(hex.len(), 32);
    }
}
