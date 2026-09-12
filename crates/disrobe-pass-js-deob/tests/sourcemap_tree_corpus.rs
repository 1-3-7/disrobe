#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    MergedTreeRecovery, RecoverOptions, RecoveredFile, RecoveryReport, SourceMapLocation,
    SourceTreeRecovery, recover_source_map_json, recover_source_tree_from_chunks,
    recover_source_tree_from_js,
};

fn corpus_dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn grade_bundle_against_disk_originals(bundle_rel: &str, original_basenames: &[&str]) {
    let bundle_dir: PathBuf = corpus_dir(bundle_rel);
    let bundle_js: PathBuf = bundle_dir.join("bundle.js");
    let bundle_text: String = std::fs::read_to_string(&bundle_js)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", bundle_js.display()));

    let map_dir: PathBuf = bundle_dir.clone();
    let recovery: SourceTreeRecovery =
        recover_source_tree_from_js(&bundle_text, RecoverOptions::default(), |url: &str| {
            std::fs::read_to_string(map_dir.join(url)).ok()
        })
        .expect("recover tree from the bundle's sourceMappingURL trailer");

    assert!(
        matches!(recovery.location, SourceMapLocation::External { .. }),
        "{bundle_rel}/bundle.js carries an external //# sourceMappingURL trailer"
    );
    let report: RecoveryReport = recovery
        .report
        .expect("the committed external .map next to the bundle must resolve");

    assert!(
        report.mapped_segments > 0,
        "{bundle_rel}: decoded VLQ mappings must attribute generated ranges to originals"
    );

    let mut graded: usize = 0;
    for basename in original_basenames {
        let on_disk: PathBuf = bundle_dir.join("src").join(basename);
        let ground_truth: Vec<u8> = std::fs::read(&on_disk)
            .unwrap_or_else(|e: std::io::Error| panic!("read original {}: {e}", on_disk.display()));
        let recovered: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| ends_with_basename(&f.relative_path, basename))
            .unwrap_or_else(|| panic!("{bundle_rel}: recovered {basename} from the real map"));
        assert_eq!(
            recovered.bytes, ground_truth,
            "{bundle_rel}/{basename} must reconstruct byte-for-byte from the pre-bundle original on disk"
        );
        assert!(
            !recovered.reconstructed,
            "{bundle_rel}/{basename} had real sourcesContent, not a stub"
        );
        graded += 1;
    }
    assert_eq!(
        graded,
        original_basenames.len(),
        "{bundle_rel}: every listed pre-bundle original must be reconstructed"
    );
}

fn ends_with_basename(relative_path: &str, basename: &str) -> bool {
    Path::new(relative_path)
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .is_some_and(|name: &str| name == basename)
}

fn grade_report_against_disk_originals(
    bundle_rel: &str,
    report: &RecoveryReport,
    original_basenames: &[&str],
) {
    let bundle_dir: PathBuf = corpus_dir(bundle_rel);
    let mut graded: usize = 0;
    for basename in original_basenames {
        let on_disk: PathBuf = bundle_dir.join("src").join(basename);
        let ground_truth: Vec<u8> = std::fs::read(&on_disk)
            .unwrap_or_else(|e: std::io::Error| panic!("read original {}: {e}", on_disk.display()));
        let recovered: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| ends_with_basename(&f.relative_path, basename))
            .unwrap_or_else(|| panic!("{bundle_rel}: recovered {basename} from the real map"));
        assert_eq!(
            recovered.bytes, ground_truth,
            "{bundle_rel}/{basename} must reconstruct byte-for-byte from the on-disk original"
        );
        assert!(
            !recovered.reconstructed,
            "{bundle_rel}/{basename} carried real sourcesContent, not a stub"
        );
        graded += 1;
    }
    assert_eq!(graded, original_basenames.len());
}

#[test]
fn esbuild_corpus_bundle_reconstructs_full_tree_byte_identical() {
    grade_bundle_against_disk_originals("esbuild", &["index.js", "math.js", "util.js", "lazy.js"]);
}

#[test]
fn rollup_corpus_bundle_reconstructs_full_tree_byte_identical() {
    grade_bundle_against_disk_originals("rollup", &["index.js", "math.js", "util.js", "lazy.js"]);
}

#[test]
fn bun_corpus_map_reconstructs_full_tree_byte_identical() {
    let map_path: PathBuf = corpus_dir("bun").join("bundle.js.map");
    let raw_json: String = std::fs::read_to_string(&map_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", map_path.display()));
    let report: RecoveryReport = recover_source_map_json(&raw_json, RecoverOptions::default())
        .expect("bun map recovers its sourcesContent");
    assert!(
        report.mapped_segments > 0,
        "bun map must decode VLQ mappings"
    );
    grade_report_against_disk_originals(
        "bun",
        &report,
        &["index.js", "math.js", "util.js", "lazy.js"],
    );
}

#[test]
fn requirejs_corpus_bundle_reconstructs_full_tree_byte_identical() {
    grade_bundle_against_disk_originals(
        "requirejs",
        &["index.js", "math.js", "util.js", "lazy.js"],
    );
}

#[test]
fn systemjs_corpus_bundle_reconstructs_full_tree_byte_identical() {
    grade_bundle_against_disk_originals("systemjs", &["index.js", "math.js", "util.js", "lazy.js"]);
}

#[test]
fn parcel_multi_chunk_app_merges_into_one_byte_identical_tree() {
    let parcel_dir: PathBuf = corpus_dir("parcel");
    let bundle_js: String =
        std::fs::read_to_string(parcel_dir.join("bundle.js")).expect("read parcel bundle.js");
    let lazy_js: String =
        std::fs::read_to_string(parcel_dir.join("lazy.js")).expect("read parcel lazy.js");
    let map_dir: PathBuf = parcel_dir.clone();
    let merged: MergedTreeRecovery = recover_source_tree_from_chunks(
        [bundle_js.as_str(), lazy_js.as_str()],
        RecoverOptions::default(),
        |url: &str| {
            let direct: PathBuf = map_dir.join(url);
            if let Ok(text) = std::fs::read_to_string(&direct) {
                return Some(text);
            }
            let basename: Option<&str> = Path::new(url)
                .file_name()
                .and_then(|s: &std::ffi::OsStr| s.to_str());
            match basename {
                Some(name) if name.starts_with("lazy") => {
                    std::fs::read_to_string(map_dir.join("lazy.js.map")).ok()
                }
                _ => std::fs::read_to_string(map_dir.join("bundle.js.map")).ok(),
            }
        },
    )
    .expect("merge parcel chunks");

    assert_eq!(
        merged.chunks_with_map, 2,
        "both parcel chunks resolve a map via the mismatched-name fallback resolver"
    );
    assert!(merged.mapped_segments > 0);
    let bundle_dir: PathBuf = parcel_dir;
    let mut graded: usize = 0;
    for basename in ["index.js", "math.js", "util.js", "lazy.js"] {
        let on_disk: PathBuf = bundle_dir.join("src").join(basename);
        let ground_truth: Vec<u8> = std::fs::read(&on_disk)
            .unwrap_or_else(|e: std::io::Error| panic!("read original {basename}: {e}"));
        let recovered: &RecoveredFile = merged
            .files
            .iter()
            .find(|f: &&RecoveredFile| ends_with_basename(&f.relative_path, basename))
            .unwrap_or_else(|| panic!("parcel: merged tree must contain {basename}"));
        assert_eq!(
            recovered.bytes, ground_truth,
            "parcel/{basename} must reconstruct byte-for-byte from the merged multi-chunk tree"
        );
        graded += 1;
    }
    assert_eq!(graded, 4);
}

#[test]
fn webpack5_corpus_bundle_reconstructs_app_sources_byte_identical() {
    let bundle_dir: PathBuf = corpus_dir("webpack5");
    let bundle_text: String =
        std::fs::read_to_string(bundle_dir.join("bundle.js")).expect("read webpack5 bundle");
    let map_dir: PathBuf = bundle_dir.clone();
    let recovery: SourceTreeRecovery =
        recover_source_tree_from_js(&bundle_text, RecoverOptions::default(), |url: &str| {
            std::fs::read_to_string(map_dir.join(url)).ok()
        })
        .expect("recover webpack5 tree");
    let report: RecoveryReport = recovery.report.expect("webpack5 external map resolves");

    for basename in ["index.js", "math.js", "util.js"] {
        let ground_truth: Vec<u8> = std::fs::read(bundle_dir.join("src").join(basename))
            .unwrap_or_else(|e: std::io::Error| panic!("read original {basename}: {e}"));
        let recovered: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| ends_with_basename(&f.relative_path, basename))
            .unwrap_or_else(|| panic!("recovered {basename} from the webpack5 map"));
        assert_eq!(
            recovered.bytes, ground_truth,
            "webpack5/{basename} must reconstruct byte-for-byte from the on-disk original"
        );
    }
}
