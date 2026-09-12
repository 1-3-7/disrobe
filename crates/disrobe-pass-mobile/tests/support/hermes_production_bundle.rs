use std::ffi::{OsStr, OsString};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{ErrorKind, Write as IoWrite};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub(crate) const REQUIRE_BUNDLE_VAR: &str = "DISROBE_REQUIRE_HERMES_PRODUCTION_BUNDLE";
pub(crate) const BUNDLE_REPO_PATH: &str = "corpus/mobile/hermes/discord/index.android.bundle";
pub(crate) const BUNDLE_MANIFEST_NAME: &str = "discord/index.android.bundle";
pub(crate) const BUNDLE_SIZE_BYTES: usize = 66_978_165;
pub(crate) const BUNDLE_SHA256: &str =
    "75f377c1ef1c5b7896fe94d748ae23bd555482021fa409d78f3d2afa1b51d2ed";
pub(crate) const PUBLISHED_FUNCTION_COUNT: usize = 122_633;
pub(crate) const PUBLISHED_BAR_HEADING: &str = "Hermes production-bundle parse scale";
pub(crate) const PUBLISHED_BAR_LABEL: &str = "functions parsed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BundleRequirement {
    Optional,
    Mandatory,
}

pub(crate) fn requirement_from_value(value: Option<&OsStr>) -> BundleRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return BundleRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => BundleRequirement::Optional,
        _ => BundleRequirement::Mandatory,
    }
}

pub(crate) fn bundle_requirement() -> BundleRequirement {
    let raw: Option<OsString> = std::env::var_os(REQUIRE_BUNDLE_VAR);
    requirement_from_value(raw.as_deref())
}

pub(crate) fn repo_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("..");
    root.push("..");
    root
}

pub(crate) fn bundle_path() -> PathBuf {
    let mut path: PathBuf = repo_root();
    for part in BUNDLE_REPO_PATH.split('/') {
        path.push(part);
    }
    path
}

pub(crate) fn corpus_manifest_path() -> PathBuf {
    let mut path: PathBuf = repo_root();
    path.push("corpus");
    path.push("mobile");
    path.push("hermes");
    path.push("MANIFEST.toml");
    path
}

pub(crate) fn corpus_manifest_text() -> String {
    let path: PathBuf = corpus_manifest_path();
    fs::read_to_string(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "the Hermes corpus manifest {} must be readable, because it is the tracked declaration \
             of the bytes every pinned figure was measured against ({err})",
            path.display()
        )
    })
}

pub(crate) fn manifest_sample_block<'a>(manifest: &'a str, name: &str) -> Option<&'a str> {
    let needle: String = format!("name = \"{name}\"\n");
    let start: usize = manifest.find(&needle)?;
    let rest: &str = &manifest[start..];
    let end: usize = rest.find("\n[[sample]]").unwrap_or(rest.len());
    Some(&rest[..end])
}

pub(crate) fn enforce_bundle_requirement(case: &str, requirement: BundleRequirement) {
    let path: PathBuf = bundle_path();
    assert!(
        requirement == BundleRequirement::Optional,
        "{REQUIRE_BUNDLE_VAR} makes the production Hermes bundle mandatory for this run, so {case} \
         cannot be graded and must not report success. The bundle is absent: expected it at \
         {resolved}, which is {BUNDLE_REPO_PATH} in the repository. That directory is gitignored and \
         the bundle is never tracked, because it is {BUNDLE_SIZE_BYTES} bytes of proprietary \
         third-party bytecode that this repository has no right to redistribute, so the published \
         {PUBLISHED_FUNCTION_COUNT}-function figure does not reproduce from a clean checkout. Supply \
         the exact sample declared in corpus/mobile/hermes/MANIFEST.toml (sha256 {BUNDLE_SHA256}), \
         or clear {REQUIRE_BUNDLE_VAR} to permit a run that grades nothing here.",
        resolved = path.display(),
    );
    announce_ungraded(case, &path);
}

fn announce_ungraded(case: &str, path: &Path) {
    let line: String = format!(
        "\nUNGRADED {case}: the production Hermes bundle is absent at {resolved} \
         ({BUNDLE_REPO_PATH}), so this case measured nothing and graded nothing. The published \
         {PUBLISHED_FUNCTION_COUNT}-function parse figure is local only and does not reproduce from \
         a clean checkout, because the bundle is proprietary third-party bytecode that is never \
         tracked. Set {REQUIRE_BUNDLE_VAR}=1 to fail instead of skipping when it is absent.\n",
        resolved = path.display(),
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let digest: sha2::digest::Output<Sha256> = hasher.finalize();
    let mut out: String = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn declared_byte_defect(bytes: &[u8]) -> Option<String> {
    if bytes.len() != BUNDLE_SIZE_BYTES {
        return Some(format!(
            "{BUNDLE_REPO_PATH} is {} bytes, expected {BUNDLE_SIZE_BYTES}",
            bytes.len()
        ));
    }
    let digest: String = sha256_hex(bytes);
    (digest != BUNDLE_SHA256)
        .then(|| format!("{BUNDLE_REPO_PATH} has sha256 {digest}, expected {BUNDLE_SHA256}"))
}

fn enforce_declared_bytes(bytes: &[u8]) {
    let Some(defect): Option<String> = declared_byte_defect(bytes) else {
        return;
    };
    panic!(
        "{BUNDLE_REPO_PATH} is not the sample every pinned figure for it was measured against, so \
         grading it would measure a different bundle and the pinned counts could not fail: \
         {defect}. corpus/mobile/hermes/MANIFEST.toml declares the exact sample. Restore those \
         bytes, or re-measure every pinned figure and update the manifest, this registry and the \
         published rows in the same change"
    );
}

pub(crate) fn load_bundle_with_requirement(
    case: &str,
    requirement: BundleRequirement,
) -> Option<Vec<u8>> {
    let path: PathBuf = bundle_path();
    match fs::read(&path) {
        Ok(bytes) => {
            enforce_declared_bytes(&bytes);
            Some(bytes)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            enforce_bundle_requirement(case, requirement);
            None
        }
        Err(err) => panic!(
            "{case}: the production Hermes bundle at {} exists but could not be read ({err}); an \
             unreadable fixture is never a skip, because that is how a quarantined or truncated \
             sample silently stops grading",
            path.display()
        ),
    }
}

pub(crate) fn load_bundle(case: &str) -> Option<Vec<u8>> {
    load_bundle_with_requirement(case, bundle_requirement())
}

pub(crate) fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let mut path: PathBuf = repo_root();
    path.push("xtask");
    path.push("data");
    path.push("recovery.json");
    let raw: String = fs::read_to_string(&path)
        .unwrap_or_else(|err: std::io::Error| panic!("read {}: {err}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err: serde_json::Error| panic!("parse {}: {err}", path.display()));
    let groups: &Vec<serde_json::Value> = doc["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("{} must hold a groups array", path.display()));
    let empty: Vec<serde_json::Value> = Vec::new();
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in groups {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|heading: &str| heading.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&empty) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}
