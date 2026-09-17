use disrobe_core::byte_search;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptType {
    Normal,
    Mini,
    Ecc,
}

impl ScriptType {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Mini => "mini",
            Self::Ecc => "ecc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapImport {
    RuntimePackage,
    RuntimePackagePrefixed,
    MiniLegacy,
    MiniNamespaced,
    None,
}

impl BootstrapImport {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RuntimePackage => "pyarmor_runtime_NNNNNN",
            Self::RuntimePackagePrefixed => "<prefix>.pyarmor_runtime_NNNNNN",
            Self::MiniLegacy => "pyarmor_mini",
            Self::MiniNamespaced => "pyarmor.mini.pyarmor_mini",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryDisposition {
    StaticRecoverable,
    RuntimeKeyDependent,
    NativeBodyWall,
    RenameNormalizeOnly,
}

impl RecoveryDisposition {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StaticRecoverable => "static-recoverable",
            Self::RuntimeKeyDependent => "runtime-key-dependent",
            Self::NativeBodyWall => "native-body-wall",
            Self::RenameNormalizeOnly => "rename-normalize-only",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeClassification {
    pub script_type: ScriptType,
    pub bootstrap_import: BootstrapImport,
    pub rft_enabled: bool,
    pub ecc_enabled: bool,
    pub mix_str_enabled: bool,
    pub disposition: RecoveryDisposition,
    pub min_format_version: &'static str,
    pub markers: Vec<String>,
    pub notes: Vec<String>,
}

impl ModeClassification {
    #[must_use]
    pub const fn unclassified() -> Self {
        Self {
            script_type: ScriptType::Normal,
            bootstrap_import: BootstrapImport::None,
            rft_enabled: false,
            ecc_enabled: false,
            mix_str_enabled: false,
            disposition: RecoveryDisposition::StaticRecoverable,
            min_format_version: "9.0.0",
            markers: Vec::new(),
            notes: Vec::new(),
        }
    }
}

const MINI_NAMESPACED_IMPORT: &[u8] = b"from pyarmor.mini.pyarmor_mini import";
const MINI_LEGACY_IMPORT: &[u8] = b"from pyarmor_mini import";
const RUNTIME_PACKAGE_IMPORT: &[u8] = b"from pyarmor_runtime_";

const ECC_MARKERS: &[&[u8]] = &[b"__pyarmor_ecc__", b"pyarmor_ecc", b".pyarmor_ecc"];
const RFT_MARKERS: &[&[u8]] = &[b"rft_exclude_table", b"__pyarmor_rft__", b"pyarmor_rft"];
const MIX_STR_MARKERS: &[&[u8]] = &[b"__mix_str__", b"__pyarmor_str__"];

const SCAN_WINDOW: usize = 256 * 1024;

#[must_use]
pub fn classify_modes(wrapper_text: &str, payload: &[u8]) -> ModeClassification {
    let wrapper_bytes: &[u8] = wrapper_text.as_bytes();
    let bootstrap_import: BootstrapImport = detect_bootstrap_import(wrapper_bytes);

    let head: &[u8] = &payload[..payload.len().min(SCAN_WINDOW)];

    let mut markers: Vec<String> = Vec::new();
    let flags: ModeFlags = ModeFlags {
        ecc: any_marker_present(wrapper_bytes, head, ECC_MARKERS, &mut markers),
        rft: detect_rft(wrapper_bytes, head, &mut markers),
        mix_str: any_marker_present(wrapper_bytes, head, MIX_STR_MARKERS, &mut markers),
    };

    let script_type: ScriptType = classify_script_type(bootstrap_import, flags);
    let disposition: RecoveryDisposition = derive_disposition(script_type, flags);
    let min_format_version: &'static str = derive_min_format_version(bootstrap_import, flags);
    let notes: Vec<String> = build_notes(script_type, bootstrap_import, flags);

    ModeClassification {
        script_type,
        bootstrap_import,
        rft_enabled: flags.rft,
        ecc_enabled: flags.ecc,
        mix_str_enabled: flags.mix_str,
        disposition,
        min_format_version,
        markers,
        notes,
    }
}

#[derive(Debug, Clone, Copy)]
struct ModeFlags {
    ecc: bool,
    rft: bool,
    mix_str: bool,
}

fn detect_bootstrap_import(wrapper_bytes: &[u8]) -> BootstrapImport {
    if byte_search::contains(wrapper_bytes, MINI_NAMESPACED_IMPORT) {
        return BootstrapImport::MiniNamespaced;
    }
    if byte_search::contains(wrapper_bytes, MINI_LEGACY_IMPORT) {
        return BootstrapImport::MiniLegacy;
    }
    if byte_search::contains(wrapper_bytes, RUNTIME_PACKAGE_IMPORT) {
        return BootstrapImport::RuntimePackage;
    }
    if has_prefixed_runtime_package_import(wrapper_bytes) {
        return BootstrapImport::RuntimePackagePrefixed;
    }
    BootstrapImport::None
}

const RUNTIME_PACKAGE_IMPORT_NESTED_NEEDLE: &str = ".pyarmor_runtime_";

fn has_prefixed_runtime_package_import(wrapper_bytes: &[u8]) -> bool {
    if !byte_search::contains(
        wrapper_bytes,
        RUNTIME_PACKAGE_IMPORT_NESTED_NEEDLE.as_bytes(),
    ) {
        return false;
    }
    let Ok(text): core::result::Result<&str, core::str::Utf8Error> =
        core::str::from_utf8(wrapper_bytes)
    else {
        return false;
    };
    text.split_inclusive('\n').any(|line: &str| {
        let trimmed: &str = line.trim_start();
        trimmed.starts_with("from ")
            && trimmed.contains(RUNTIME_PACKAGE_IMPORT_NESTED_NEEDLE)
            && trimmed.contains(" import ")
    })
}

fn detect_rft(wrapper_bytes: &[u8], head: &[u8], markers: &mut Vec<String>) -> bool {
    any_marker_present(wrapper_bytes, head, RFT_MARKERS, markers)
}

fn any_marker_present(
    wrapper_bytes: &[u8],
    head: &[u8],
    needles: &[&[u8]],
    markers: &mut Vec<String>,
) -> bool {
    let mut found: bool = false;
    for needle in needles {
        let in_wrapper: bool = byte_search::contains(wrapper_bytes, needle);
        let in_payload: bool = byte_search::contains(head, needle);
        if (in_wrapper || in_payload)
            && let Ok(s) = core::str::from_utf8(needle)
        {
            markers.push(s.to_owned());
            found = true;
        }
    }
    found
}

const fn classify_script_type(bootstrap: BootstrapImport, flags: ModeFlags) -> ScriptType {
    if flags.ecc {
        return ScriptType::Ecc;
    }
    match bootstrap {
        BootstrapImport::MiniLegacy | BootstrapImport::MiniNamespaced => ScriptType::Mini,
        BootstrapImport::RuntimePackage
        | BootstrapImport::RuntimePackagePrefixed
        | BootstrapImport::None => ScriptType::Normal,
    }
}

const fn derive_disposition(script_type: ScriptType, flags: ModeFlags) -> RecoveryDisposition {
    if flags.ecc || matches!(script_type, ScriptType::Ecc) {
        return RecoveryDisposition::NativeBodyWall;
    }
    if flags.rft {
        return RecoveryDisposition::RenameNormalizeOnly;
    }
    RecoveryDisposition::StaticRecoverable
}

const fn derive_min_format_version(bootstrap: BootstrapImport, flags: ModeFlags) -> &'static str {
    if flags.ecc {
        return "9.2.2";
    }
    match bootstrap {
        BootstrapImport::MiniNamespaced => "9.2.2",
        BootstrapImport::MiniLegacy
        | BootstrapImport::RuntimePackage
        | BootstrapImport::RuntimePackagePrefixed
        | BootstrapImport::None => "9.0.0",
    }
}

fn build_notes(
    script_type: ScriptType,
    bootstrap: BootstrapImport,
    flags: ModeFlags,
) -> Vec<String> {
    let mut notes: Vec<String> = Vec::new();
    match script_type {
        ScriptType::Mini => notes.push(
            "DR-PYARM-MODE: MINI script type (9.2.2+ namespaced bootstrap requires the pyarmor.mini package on the target); code-object blob layout matches the normal runtime-package path"
                .to_owned(),
        ),
        ScriptType::Ecc => notes.push(
            "DR-PYARM-MODE: ECC script type. Despite the initialism this is not elliptic-curve crypto; per the PyArmor docs it converts each function body to C compiled to machine instructions and the transform is irreversible (BCC-class, source compiled away). Only structure/symbols and the still-Python module-level glue are recoverable; per-function logic is a compiler-discarded-source wall like Nuitka native bodies"
                .to_owned(),
        ),
        ScriptType::Normal => {}
    }
    if matches!(bootstrap, BootstrapImport::RuntimePackagePrefixed) {
        notes.push(
            "DR-PYARM-MODE: runtime package relocated under a caller-chosen parent package (pyarmor gen --prefix); the pyarmor_runtime_NNNNNN shared object is nested one directory below the wrapper rather than a sibling, and the import line reads `from <prefix>.pyarmor_runtime_NNNNNN import __pyarmor__`"
                .to_owned(),
        );
    }
    if flags.rft {
        notes.push(
            "DR-PYARM-MODE: RFT (rename-from-table) detected. The original->renamed identifier map is discarded at build time (only the build-time .pyarmor/rft_exclude_table exists and is not shipped), so original names are unrecoverable. Recovery is rename-normalization to consistent readable identifiers; logic and structure are preserved. Args, kwargs, __all__ entries and dunder names are never renamed"
                .to_owned(),
        );
    }
    if flags.ecc {
        notes.push(
            "DR-PYARM-MODE: ECC requires a C compiler at build time and emits an embedded native object (the same emission path as BCC); recover it via the BCC native-lift route (--allow-bcc, in-crate x86-64 pseudo-C), not the bytecode pipeline"
                .to_owned(),
        );
    }
    if flags.mix_str {
        notes.push(
            "DR-PYARM-MODE: mix-str enabled; string constants are stored encrypted and decrypt with the runtime key (docstrings stay plaintext)"
                .to_owned(),
        );
    }
    notes
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn normal_wrapper() -> String {
        "from pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'PY009000')\n".to_owned()
    }

    #[test]
    fn normal_v9_classifies_as_normal_static() {
        let c: ModeClassification = classify_modes(&normal_wrapper(), b"PY009000\x00\x03\x0c");
        assert_eq!(c.script_type, ScriptType::Normal);
        assert_eq!(c.bootstrap_import, BootstrapImport::RuntimePackage);
        assert_eq!(c.disposition, RecoveryDisposition::StaticRecoverable);
        assert_eq!(c.min_format_version, "9.0.0");
        assert!(!c.ecc_enabled && !c.rft_enabled);
    }

    #[test]
    fn mini_namespaced_import_is_922_mini() {
        let wrapper: &str = "from pyarmor.mini.pyarmor_mini import __pyarmor__\n__pyarmor__(__name__, __file__, b'PY009000')\n";
        let c: ModeClassification = classify_modes(wrapper, b"PY009000");
        assert_eq!(c.script_type, ScriptType::Mini);
        assert_eq!(c.bootstrap_import, BootstrapImport::MiniNamespaced);
        assert_eq!(c.min_format_version, "9.2.2");
    }

    #[test]
    fn prefixed_runtime_package_import_is_recognized() {
        let wrapper: &str = "from paypal_runtime.pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'PY009000')\n";
        let c: ModeClassification = classify_modes(wrapper, b"PY009000");
        assert_eq!(c.bootstrap_import, BootstrapImport::RuntimePackagePrefixed);
        assert_eq!(c.script_type, ScriptType::Normal);
        assert_eq!(c.disposition, RecoveryDisposition::StaticRecoverable);
        assert_eq!(c.min_format_version, "9.0.0");
        assert!(c.notes.iter().any(|n| n.contains("--prefix")));
    }

    #[test]
    fn unprefixed_runtime_package_import_is_not_misclassified_as_prefixed() {
        let c: ModeClassification = classify_modes(&normal_wrapper(), b"PY009000");
        assert_eq!(c.bootstrap_import, BootstrapImport::RuntimePackage);
        assert!(!c.notes.iter().any(|n| n.contains("--prefix")));
    }

    #[test]
    fn unrelated_dotted_import_does_not_trigger_prefixed_bootstrap() {
        let wrapper: &str = "import somepkg.pyarmor_runtime_thing_but_not_a_bootstrap_call\n";
        let c: ModeClassification = classify_modes(wrapper, b"");
        assert_eq!(c.bootstrap_import, BootstrapImport::None);
    }

    #[test]
    fn mini_legacy_import_detected() {
        let wrapper: &str =
            "from pyarmor_mini import __pyarmor__\n__pyarmor__(__name__, __file__, b'x')\n";
        let c: ModeClassification = classify_modes(wrapper, b"");
        assert_eq!(c.bootstrap_import, BootstrapImport::MiniLegacy);
        assert_eq!(c.script_type, ScriptType::Mini);
    }

    #[test]
    fn ecc_marker_is_native_body_wall() {
        let wrapper: String = normal_wrapper();
        let payload: &[u8] = b"PY009000 __pyarmor_ecc__ embedded native object";
        let c: ModeClassification = classify_modes(&wrapper, payload);
        assert!(c.ecc_enabled);
        assert_eq!(c.script_type, ScriptType::Ecc);
        assert_eq!(c.disposition, RecoveryDisposition::NativeBodyWall);
        assert!(c.notes.iter().any(|n| n.contains("irreversible")));
    }

    #[test]
    fn rft_marker_is_rename_normalize_only() {
        let wrapper: String = normal_wrapper();
        let payload: &[u8] = b"PY009000 rft_exclude_table reference";
        let c: ModeClassification = classify_modes(&wrapper, payload);
        assert!(c.rft_enabled);
        assert_eq!(c.disposition, RecoveryDisposition::RenameNormalizeOnly);
        assert!(c.notes.iter().any(|n| n.contains("unrecoverable")));
    }

    #[test]
    fn empty_payload_does_not_panic() {
        let c: ModeClassification = classify_modes("", b"");
        assert_eq!(c.bootstrap_import, BootstrapImport::None);
        assert_eq!(c.script_type, ScriptType::Normal);
    }
}
