use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use disrobe_dart::{AttributionResidue, ObfuscationHint};
use serde::Deserialize;

pub(crate) const FIXTURE_SET: &str = "flutter_3_44_6";

const REBUILD_HINT: &str = "restore it with `git checkout -- crates/disrobe-dart/tests/fixtures`, \
                            or rebuild the set with tests/fixtures/flutter_3_44_6/rebuild.ps1 on \
                            the Flutter revision that oracle.json records";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RecoveryOracle {
    pub(crate) snapshot_compatibility_hash: String,
    pub(crate) application_library: String,
    pub(crate) counts_provenance: CountsProvenance,
    pub(crate) perturbation: Perturbation,
    pub(crate) builds: Vec<RecoveryBuild>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CountsProvenance {
    pub(crate) summary: String,
    pub(crate) derivation: Vec<String>,
    pub(crate) toolchain_alternative: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Perturbation {
    pub(crate) from: String,
    pub(crate) to: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PinnedNames {
    Source,
    Opaque,
}

impl PinnedNames {
    pub(crate) const fn hint(self) -> ObfuscationHint {
        match self {
            Self::Source => ObfuscationHint::SourceNames,
            Self::Opaque => ObfuscationHint::OpaqueNames,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RecoveryBuild {
    pub(crate) name: String,
    pub(crate) source: String,
    pub(crate) artifact: String,
    pub(crate) sha256: String,
    pub(crate) names: PinnedNames,
    pub(crate) libraries: usize,
    pub(crate) classes: usize,
    pub(crate) methods: usize,
    pub(crate) fields: usize,
    pub(crate) declared: DeclaredSnapshots,
    pub(crate) attribution_residue: AttributionResidue,
    #[serde(default)]
    pub(crate) known_classes: Vec<String>,
    #[serde(default)]
    pub(crate) known_methods: Vec<KnownMethod>,
    #[serde(default)]
    pub(crate) known_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) struct DeclaredSnapshots {
    pub(crate) vm: DeclaredSnapshot,
    pub(crate) isolate: DeclaredSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) struct DeclaredSnapshot {
    pub(crate) objects: usize,
    pub(crate) base_objects: usize,
    pub(crate) libraries: usize,
    pub(crate) classes: usize,
    pub(crate) patch_classes: usize,
    pub(crate) functions: usize,
    pub(crate) fields: usize,
}

impl DeclaredSnapshot {
    pub(crate) const fn clustered_objects(self) -> usize {
        self.objects.saturating_sub(self.base_objects)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KnownMethod {
    pub(crate) name: String,
    pub(crate) parameter_count: Option<usize>,
}

pub(crate) fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(FIXTURE_SET)
        .join(name)
}

pub(crate) fn relative(name: &str) -> String {
    format!("crates/disrobe-dart/tests/fixtures/{FIXTURE_SET}/{name}")
}

pub(crate) fn read_tracked(name: &str) -> Vec<u8> {
    let path: PathBuf = fixture_path(name);
    let bytes: Vec<u8> = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => panic!(
            "{} is tracked in this repository and every pinned figure is measured against it, so a \
             run that cannot read it must fail rather than measure nothing: nothing exists at {} \
             ({error}). To fix it, {REBUILD_HINT}.",
            relative(name),
            path.display()
        ),
        Err(error) => panic!(
            "{} exists at {} but could not be read ({error}); an unreadable fixture is never a \
             skip, because that is how a quarantined or half-written sample silently stops grading",
            relative(name),
            path.display()
        ),
    };
    assert!(
        !bytes.is_empty(),
        "{} is tracked in this repository and read back empty at {}; a truncated input grades \
         nothing and must never report success",
        relative(name),
        path.display()
    );
    bytes
}

pub(crate) fn read_tracked_text(name: &str) -> String {
    let bytes: Vec<u8> = read_tracked(name);
    String::from_utf8(bytes).unwrap_or_else(|error: std::string::FromUtf8Error| {
        panic!(
            "{} is read as text but is not valid utf-8 ({error}); a fixture that cannot be decoded \
             is never a skip",
            relative(name)
        )
    })
}

pub(crate) fn recovery_oracle() -> RecoveryOracle {
    let bytes: Vec<u8> = read_tracked("oracle.json");
    let oracle: RecoveryOracle =
        serde_json::from_slice(&bytes).unwrap_or_else(|error: serde_json::Error| {
            panic!(
                "{} does not deserialize ({error}); the manifest that carries every pinned figure \
                 must parse or nothing below it is graded",
                relative("oracle.json")
            )
        });
    assert!(
        !oracle.builds.is_empty(),
        "{} records zero builds, so every case that loops over it would pass while grading nothing",
        relative("oracle.json")
    );
    oracle
}

pub(crate) fn oracle_build(oracle: &RecoveryOracle, name: &str) -> RecoveryBuild {
    oracle
        .builds
        .iter()
        .find(|build: &&RecoveryBuild| build.name == name)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "{} records no build named {name}, so this case has nothing to grade against",
                relative("oracle.json")
            )
        })
}
