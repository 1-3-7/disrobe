#![allow(clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::chain::{CatalogEntry, ObfuscatorCatalog, SupportQuality};
use disrobe_pass_dotnet::chain_detector::DotnetDetector;
use disrobe_pass_dotnet::protectors::{DetectionReport, Protector, detect_all};

const CORPUS: &str = "corpus/dotnet";
const REAL_PROVENANCE: &str = "real";
const MAX_MANIFEST_BYTES: u64 = 1 << 20;
const MAX_SAMPLE_BYTES: u64 = 64 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManifestRow {
    manifest: &'static str,
    path: &'static str,
}

const fn row(manifest: &'static str, path: &'static str) -> ManifestRow {
    ManifestRow { manifest, path }
}

const CONFUSEREX2_ROWS: &[ManifestRow] = &[
    row("MANIFEST.toml", "HelloAppLegacy.confuserex2.dll"),
    row("MANIFEST.toml", "SampleConstants.confuserex2.dll"),
    row("MANIFEST.toml", "megafile/EdgeCases.confuserex2.dll"),
    row(
        "confuserex/gauntlet/MANIFEST.toml",
        "GauntletSample.confuserex2.exe",
    ),
];

const CONFUSEREX_ROWS: &[ManifestRow] = &[
    row("cff/MANIFEST.toml", "CffSample.ctrlflow.exe"),
    row("cff/MANIFEST.toml", "CffPred.x86pred.exe"),
    row("cff/MANIFEST.toml", "CffPred.exprpred.exe"),
];

const KOIVM_ROWS: &[ManifestRow] = &[row("koivm/MANIFEST.toml", "KoiSample.koivm.exe")];

const OBFUSCAR_ROWS: &[ManifestRow] = &[
    row("MANIFEST.toml", "HelloAppLegacy.obfuscar.dll"),
    row("MANIFEST.toml", "megafile/EdgeCases.obfuscar.dll"),
    row(
        "obfuscators/obfuscar/gauntlet/MANIFEST.toml",
        "GauntletSample.obfuscar.dll",
    ),
];

const BITMONO_ROWS: &[ManifestRow] = &[row(
    "obfuscators/bitmono/gauntlet/MANIFEST.toml",
    "GauntletBitMono.bitmono.dll",
)];

const SELF_VIRTUALIZED_EAZVM_ROWS: &[ManifestRow] =
    &[row("eazvm/MANIFEST.toml", "EazSample.eazvm.dll")];

const UNPROTECTED_BASELINE_ROWS: &[ManifestRow] = &[row("MANIFEST.toml", "HelloAppLegacy.dll")];

const fn real_sample_rows(protector: Protector) -> &'static [ManifestRow] {
    match protector {
        Protector::ConfuserEx2 => CONFUSEREX2_ROWS,
        Protector::ConfuserEx => CONFUSEREX_ROWS,
        Protector::KoiVm => KOIVM_ROWS,
        Protector::Obfuscar => OBFUSCAR_ROWS,
        Protector::BitMono => BITMONO_ROWS,
        Protector::Dotfuscator
        | Protector::DotfuscatorCe
        | Protector::SmartAssembly
        | Protector::BabelDotnet
        | Protector::DeepSea
        | Protector::SpicesNet
        | Protector::Goliath
        | Protector::Skater
        | Protector::DotnetReactor
        | Protector::EazfuscatorNet
        | Protector::CryptoObfuscator
        | Protector::ArmDot
        | Protector::AgileNet
        | Protector::DotNetPatcher
        | Protector::NetCryptor
        | Protector::ThemidaDotnet
        | Protector::Ilprotector
        | Protector::MaxToCode => &[],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RowDefect {
    ManifestUnreadable(String),
    NoFixtureEntry,
    NotRealProvenance(Option<String>),
    Untracked(String),
    SampleUnreadable(String),
    NotDetectedAsProtector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Violation {
    NoRealSampleRow(Protector),
    BadRow {
        protector: Protector,
        row: ManifestRow,
        defect: RowDefect,
    },
}

struct Corpus {
    root: PathBuf,
    tracked: BTreeSet<String>,
}

impl Corpus {
    fn from_repository() -> Self {
        let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output: Output = Command::new("git")
            .args(["ls-files", "-z", "--", CORPUS])
            .current_dir(&root)
            .output()
            .unwrap_or_else(|error: std::io::Error| {
                panic!("git ls-files is required to prove a real-sample row is committed: {error}")
            });
        assert!(
            output.status.success(),
            "git ls-files failed in {}: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let raw: String =
            String::from_utf8(output.stdout).unwrap_or_else(|error: std::string::FromUtf8Error| {
                panic!("git ls-files returned a non-UTF-8 path: {error}")
            });
        let tracked: BTreeSet<String> = raw
            .split('\0')
            .filter(|entry: &&str| !entry.is_empty())
            .map(|entry: &str| entry.replace('\\', "/"))
            .collect();
        assert!(
            tracked.contains(&format!("{CORPUS}/MANIFEST.toml")),
            "git ls-files does not list {CORPUS}/MANIFEST.toml, so the tracked corpus is not \
             established"
        );
        Self { root, tracked }
    }

    fn row_defect(&self, protector: Protector, row: ManifestRow) -> Option<RowDefect> {
        let manifest_path: PathBuf = self.root.join(CORPUS).join(row.manifest);
        let manifest: toml::Table = match read_manifest(&manifest_path) {
            Ok(table) => table,
            Err(message) => return Some(RowDefect::ManifestUnreadable(message)),
        };
        let Some(entry): Option<&toml::Value> = fixture_entry(&manifest, row.path) else {
            return Some(RowDefect::NoFixtureEntry);
        };
        let provenance: Option<String> = entry
            .get("provenance")
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
        if provenance.as_deref() != Some(REAL_PROVENANCE) {
            return Some(RowDefect::NotRealProvenance(provenance));
        }
        let relative: String = tracked_path(row);
        if !self.tracked.contains(&relative) {
            return Some(RowDefect::Untracked(relative));
        }
        let image: Vec<u8> = match read_bounded(&self.root.join(&relative), MAX_SAMPLE_BYTES) {
            Ok(bytes) => bytes,
            Err(message) => return Some(RowDefect::SampleUnreadable(message)),
        };
        let report: DetectionReport = detect_all(&image);
        if !report.matches.contains_key(&protector) {
            return Some(RowDefect::NotDetectedAsProtector);
        }
        None
    }

    fn full_label_violations(
        &self,
        labels: &[(Protector, SupportQuality)],
        rows_for: fn(Protector) -> &'static [ManifestRow],
    ) -> Vec<Violation> {
        let mut violations: Vec<Violation> = Vec::new();
        for (protector, quality) in labels {
            if *quality != SupportQuality::Full {
                continue;
            }
            let rows: &'static [ManifestRow] = rows_for(*protector);
            if rows.is_empty() {
                violations.push(Violation::NoRealSampleRow(*protector));
            }
            for row in rows {
                if let Some(defect) = self.row_defect(*protector, *row) {
                    violations.push(Violation::BadRow {
                        protector: *protector,
                        row: *row,
                        defect,
                    });
                }
            }
        }
        violations
    }
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let length: u64 = std::fs::metadata(path)
        .map_err(|error: std::io::Error| format!("{}: {error}", path.display()))?
        .len();
    if length > limit {
        return Err(format!(
            "{} is {length} bytes, above the {limit}-byte bound",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|error: std::io::Error| format!("{}: {error}", path.display()))
}

fn read_manifest(path: &Path) -> Result<toml::Table, String> {
    let bytes: Vec<u8> = read_bounded(path, MAX_MANIFEST_BYTES)?;
    let text: String = String::from_utf8(bytes)
        .map_err(|error: std::string::FromUtf8Error| format!("{}: {error}", path.display()))?;
    text.parse::<toml::Table>()
        .map_err(|error: toml::de::Error| format!("{}: {error}", path.display()))
}

fn fixture_entry<'doc>(manifest: &'doc toml::Table, path: &str) -> Option<&'doc toml::Value> {
    manifest
        .get("fixture")?
        .as_array()?
        .iter()
        .find(|entry: &&toml::Value| entry.get("path").and_then(toml::Value::as_str) == Some(path))
}

fn tracked_path(row: ManifestRow) -> String {
    let directory: &str = row
        .manifest
        .strip_suffix("MANIFEST.toml")
        .unwrap_or(row.manifest);
    format!("{CORPUS}/{directory}{}", row.path)
}

fn catalog_labels() -> Vec<(Protector, SupportQuality)> {
    let entries: Vec<&'static dyn CatalogEntry> = DotnetDetector.catalog();
    assert!(
        !entries.is_empty(),
        "the .NET catalog is empty, so no support label would be checked"
    );
    entries
        .iter()
        .map(|entry: &&'static dyn CatalogEntry| {
            let matching: Vec<Protector> = Protector::ALL
                .into_iter()
                .filter(|protector: &Protector| protector.label() == entry.display_name())
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "catalog entry {} must name exactly one protector by label, found {matching:?}",
                entry.id()
            );
            let protector: Protector = matching
                .first()
                .copied()
                .expect("exactly one protector matched");
            (protector, entry.support_quality())
        })
        .collect()
}

const fn eazvm_row_as_evidence(protector: Protector) -> &'static [ManifestRow] {
    match protector {
        Protector::EazfuscatorNet => SELF_VIRTUALIZED_EAZVM_ROWS,
        _ => &[],
    }
}

const fn clean_baseline_as_evidence(protector: Protector) -> &'static [ManifestRow] {
    match protector {
        Protector::DotnetReactor => UNPROTECTED_BASELINE_ROWS,
        _ => &[],
    }
}

#[test]
fn every_full_catalog_label_has_a_tracked_real_sample() {
    let corpus: Corpus = Corpus::from_repository();
    let labels: Vec<(Protector, SupportQuality)> = catalog_labels();
    let violations: Vec<Violation> = corpus.full_label_violations(&labels, real_sample_rows);
    assert!(
        violations.is_empty(),
        "a protector labelled Full must be backed by a tracked real-protector sample recorded \
         under {CORPUS}: {violations:#?}"
    );
}

#[test]
fn every_mapped_real_sample_row_is_tracked_real_and_detected() {
    let corpus: Corpus = Corpus::from_repository();
    let mut checked: usize = 0;
    for protector in Protector::ALL {
        for row in real_sample_rows(protector) {
            checked += 1;
            assert_eq!(
                corpus.row_defect(protector, *row),
                None,
                "{} maps to {row:?}, which is not a tracked real sample detected as that protector",
                protector.label()
            );
        }
    }
    assert!(
        checked > 0,
        "the real-sample table maps no row, so this test would check nothing"
    );
}

#[test]
fn full_label_on_a_synthetic_only_protector_is_rejected() {
    let corpus: Corpus = Corpus::from_repository();
    let labels: [(Protector, SupportQuality); 1] =
        [(Protector::EazfuscatorNet, SupportQuality::Full)];
    let violations: Vec<Violation> = corpus.full_label_violations(&labels, eazvm_row_as_evidence);
    assert_eq!(
        violations,
        vec![Violation::BadRow {
            protector: Protector::EazfuscatorNet,
            row: row("eazvm/MANIFEST.toml", "EazSample.eazvm.dll"),
            defect: RowDefect::NotRealProvenance(Some("self-virtualized".to_owned())),
        }]
    );
}

#[test]
fn full_label_without_any_sample_row_is_rejected() {
    let corpus: Corpus = Corpus::from_repository();
    let labels: [(Protector, SupportQuality); 2] = [
        (Protector::DeepSea, SupportQuality::Full),
        (Protector::Goliath, SupportQuality::Partial),
    ];
    let violations: Vec<Violation> = corpus.full_label_violations(&labels, real_sample_rows);
    assert_eq!(
        violations,
        vec![Violation::NoRealSampleRow(Protector::DeepSea)]
    );
}

#[test]
fn full_label_backed_by_an_unprotected_baseline_is_rejected() {
    let corpus: Corpus = Corpus::from_repository();
    let labels: [(Protector, SupportQuality); 1] =
        [(Protector::DotnetReactor, SupportQuality::Full)];
    let violations: Vec<Violation> =
        corpus.full_label_violations(&labels, clean_baseline_as_evidence);
    assert_eq!(
        violations,
        vec![Violation::BadRow {
            protector: Protector::DotnetReactor,
            row: row("MANIFEST.toml", "HelloAppLegacy.dll"),
            defect: RowDefect::NotDetectedAsProtector,
        }]
    );
}

#[test]
fn full_label_backed_by_an_untracked_file_is_rejected() {
    let mut corpus: Corpus = Corpus::from_repository();
    let removed: String = format!("{CORPUS}/SampleConstants.confuserex2.dll");
    assert!(corpus.tracked.remove(&removed));
    let labels: [(Protector, SupportQuality); 1] = [(Protector::ConfuserEx2, SupportQuality::Full)];
    let violations: Vec<Violation> = corpus.full_label_violations(&labels, real_sample_rows);
    assert_eq!(
        violations,
        vec![Violation::BadRow {
            protector: Protector::ConfuserEx2,
            row: row("MANIFEST.toml", "SampleConstants.confuserex2.dll"),
            defect: RowDefect::Untracked(removed),
        }]
    );
}
