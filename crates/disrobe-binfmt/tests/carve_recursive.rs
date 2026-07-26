#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::io::Write as _;

use disrobe_binfmt::{
    CarveConfig, CarveNode, CarveReport, CarvedChunk, ChunkClass, carve_recursive,
};

const INNERMOST: &[u8] =
    b"disrobe recursive carve oracle innermost payload: the byte-exact target 0123456789";
const UNKNOWN_GAP: &[u8] =
    b"this-is-a-non-magic-unknown-region-between-two-real-archives-not-a-container";

fn zip_stored(name: &str, body: &[u8]) -> Vec<u8> {
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    let mut zw: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: zip::write::FileOptions<()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zw.start_file(name, opts).expect("zip start");
    zw.write_all(body).expect("zip write");
    zw.finish().expect("zip finish").into_inner()
}

fn tar_single(name: &str, body: &[u8]) -> Vec<u8> {
    let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
    let mut header: tar::Header = tar::Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, name, body)
        .expect("tar append");
    builder.into_inner().expect("tar finish")
}

fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut enc: flate2::write::GzEncoder<Vec<u8>> =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(payload).expect("gz write");
    enc.finish().expect("gz finish")
}

fn build_nested_gz() -> Vec<u8> {
    let inner_zip: Vec<u8> = zip_stored("secret.txt", INNERMOST);
    let tarball: Vec<u8> = tar_single("payload.zip", &inner_zip);
    gzip(&tarball)
}

fn collect_chunks<'a>(node: &'a CarveNode, out: &mut Vec<&'a CarvedChunk>) {
    for chunk in &node.chunks {
        out.push(chunk);
    }
    for child in &node.children {
        collect_chunks(child, out);
    }
}

fn find_innermost(node: &CarveNode) -> bool {
    if node.source.contains("secret.txt") {
        return true;
    }
    node.children.iter().any(find_innermost)
}

fn max_observed_depth(node: &CarveNode) -> u32 {
    node.children
        .iter()
        .map(max_observed_depth)
        .max()
        .map_or(node.depth, |d: u32| d.max(node.depth))
}

fn innermost_depth(node: &CarveNode) -> Option<u32> {
    if node.source.contains("secret.txt") {
        return Some(node.depth);
    }
    node.children.iter().filter_map(innermost_depth).max()
}

#[test]
fn recurses_zip_in_tar_in_gz_to_innermost_byte_exact() {
    let nested: Vec<u8> = build_nested_gz();
    let report: CarveReport =
        carve_recursive(&nested, "nested.tar.gz", CarveConfig::default(), None);
    assert!(
        find_innermost(&report.root),
        "engine must recurse gz -> tar -> zip and reach secret.txt; tree: {:#?}",
        report.root
    );
    let recovered: Vec<u8> = recover_innermost(&nested);
    assert_eq!(
        recovered, INNERMOST,
        "innermost payload must round-trip byte-exact through the recursion"
    );
}

fn recover_innermost(nested: &[u8]) -> Vec<u8> {
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("scratch");
    let report: CarveReport = carve_recursive(nested, "nested", CarveConfig::default(), None);
    let _ = report;
    let gz_dir: std::path::PathBuf = scratch.path().join("gz");
    let gz_result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(disrobe_binfmt::ContainerKind::Gzip, nested, &gz_dir)
            .expect("gz extract");
    let tar_bytes: Vec<u8> =
        std::fs::read(gz_result.entries[0].disk_path.as_ref().expect("gz path")).expect("read tar");
    let tar_dir: std::path::PathBuf = scratch.path().join("tar");
    let tar_result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(disrobe_binfmt::ContainerKind::Tar, &tar_bytes, &tar_dir)
            .expect("tar extract");
    let zip_bytes: Vec<u8> =
        std::fs::read(tar_result.entries[0].disk_path.as_ref().expect("tar path"))
            .expect("read zip");
    let zip_dir: std::path::PathBuf = scratch.path().join("zip");
    let zip_result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(disrobe_binfmt::ContainerKind::Zip, &zip_bytes, &zip_dir)
            .expect("zip extract");
    std::fs::read(zip_result.entries[0].disk_path.as_ref().expect("zip path")).expect("read inner")
}

#[test]
fn carves_unknown_gap_between_two_real_archives() {
    let gz_a: Vec<u8> = gzip(b"first real gzip member alpha");
    let gz_b: Vec<u8> = gzip(b"second real gzip member bravo");
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&gz_a);
    buf.extend_from_slice(UNKNOWN_GAP);
    buf.extend_from_slice(&gz_b);

    let report: CarveReport = carve_recursive(&buf, "two-gzips", CarveConfig::default(), None);
    let mut chunks: Vec<&CarvedChunk> = Vec::new();
    collect_chunks(&report.root, &mut chunks);

    let valid: usize = report
        .root
        .chunks
        .iter()
        .filter(|c: &&CarvedChunk| c.class == ChunkClass::Valid)
        .count();
    assert_eq!(valid, 2, "must carve both gzip members as valid chunks");

    let unknown: Vec<&&CarvedChunk> = chunks
        .iter()
        .filter(|c: &&&CarvedChunk| c.class == ChunkClass::Unknown)
        .collect();
    let gap_start: u64 = gz_a.len() as u64;
    let gap_end: u64 = gap_start + UNKNOWN_GAP.len() as u64;
    let gap: &&&CarvedChunk = unknown
        .iter()
        .find(|c: &&&&CarvedChunk| c.start == gap_start && c.end == gap_end)
        .unwrap_or_else(|| {
            panic!(
                "the non-magic gap must be one unknown chunk spanning exactly [{gap_start}, {gap_end}); got {:?}",
                unknown
                    .iter()
                    .map(|c: &&&CarvedChunk| (c.class, c.start, c.end))
                    .collect::<Vec<(ChunkClass, u64, u64)>>()
            )
        });
    assert_eq!(
        gap.len(),
        UNKNOWN_GAP.len() as u64,
        "the unknown gap chunk length must equal the literal byte gap"
    );
    assert_eq!(gap.kind, None, "an unknown gap carries no container kind");
    let first_valid_end: u64 = gz_a.len() as u64;
    let second_valid_start: u64 = gap_end;
    assert!(
        report
            .root
            .chunks
            .iter()
            .any(|c: &CarvedChunk| c.class == ChunkClass::Valid
                && c.start == 0
                && c.end == first_valid_end),
        "first gzip must occupy exactly [0, {first_valid_end})"
    );
    assert!(
        report
            .root
            .chunks
            .iter()
            .any(|c: &CarvedChunk| c.class == ChunkClass::Valid && c.start == second_valid_start),
        "second gzip must start exactly where the unknown gap ends ({second_valid_start})"
    );
}

#[test]
fn entropy_recorded_per_chunk_flags_compressed_region() {
    let gz: Vec<u8> = gzip(&b"highly compressible repeated text ".repeat(64));
    let mut buf: Vec<u8> = vec![b'A'; 64];
    buf.extend_from_slice(&gz);
    let report: CarveReport = carve_recursive(&buf, "entropy", CarveConfig::default(), None);
    let mut chunks: Vec<&CarvedChunk> = Vec::new();
    collect_chunks(&report.root, &mut chunks);
    let valid: &&CarvedChunk = chunks
        .iter()
        .find(|c: &&&CarvedChunk| c.class == ChunkClass::Valid)
        .expect("a valid gzip chunk");
    assert!(
        valid.entropy > 5.0,
        "compressed gzip chunk must show high entropy, got {}",
        valid.entropy
    );
    let padding: &&CarvedChunk = chunks
        .iter()
        .find(|c: &&&CarvedChunk| c.class == ChunkClass::Padding)
        .expect("a padding chunk");
    assert!(
        padding.entropy.abs() < f64::EPSILON,
        "single-byte padding run has zero entropy, got {}",
        padding.entropy
    );
}

#[test]
fn max_depth_is_respected() {
    let nested: Vec<u8> = build_nested_gz();
    let shallow: CarveReport = carve_recursive(&nested, "nested", CarveConfig::new(1), None);
    assert_eq!(
        max_observed_depth(&shallow.root),
        0,
        "with max-depth 1 the engine must not descend below the root node"
    );
    assert!(
        shallow.root.children.is_empty(),
        "max-depth 1 leaves the root with no carved children"
    );
    assert!(
        !find_innermost(&shallow.root),
        "depth 1 must not reach the innermost zip member"
    );

    let deep_max: u32 = 10;
    let deep: CarveReport = carve_recursive(&nested, "nested", CarveConfig::new(deep_max), None);
    let observed: u32 = max_observed_depth(&deep.root);
    assert!(
        (2..deep_max).contains(&observed),
        "the gz -> tar -> zip chain must descend at least to depth 2 and never exceed the depth-{deep_max} cap, observed {observed}"
    );
    let secret_depth: u32 =
        innermost_depth(&deep.root).expect("secret.txt must be reached under a generous depth cap");
    assert_eq!(
        secret_depth, observed,
        "the innermost secret.txt node must be the deepest node in the tree"
    );
    assert!(
        secret_depth >= 2,
        "secret.txt sits below gz and tar, so its depth is at least 2, got {secret_depth}"
    );
}

#[test]
fn self_referential_gzip_bomb_terminates_within_work_bound() {
    let mut payload: Vec<u8> = vec![0x1f, 0x8b];
    payload.extend(std::iter::repeat_n(0u8, 4096));
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..256 {
        buf.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00]);
        buf.extend_from_slice(&payload);
    }
    let started: std::time::Instant = std::time::Instant::now();
    let report: CarveReport = carve_recursive(&buf, "bomb", CarveConfig::default(), None);
    let elapsed: std::time::Duration = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "crafted self-referential input must terminate within the work bound, took {elapsed:?}"
    );
    assert!(
        report.nodes_visited < 1_000_000,
        "node visits must stay bounded, got {}",
        report.nodes_visited
    );
}

#[test]
fn deeply_nested_gzip_chain_terminates() {
    let mut layer: Vec<u8> = b"terminal".to_vec();
    for _ in 0..40 {
        layer = gzip(&layer);
    }
    let started: std::time::Instant = std::time::Instant::now();
    let report: CarveReport = carve_recursive(&layer, "deep-gz", CarveConfig::new(10), None);
    let elapsed: std::time::Duration = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "40-deep gzip chain must terminate, took {elapsed:?}"
    );
    assert!(
        max_observed_depth(&report.root) <= 10,
        "recursion must honor the depth cap even on a deeper real chain"
    );
}

#[test]
fn committed_nested_fixture_round_trips() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture("carve", "nested.tar.gz") else {
        panic!(
            "missing committed fixture corpus/binfmt/carve/nested.tar.gz (force-added; regenerate via the carve_recursive oracle)"
        );
    };
    let report: CarveReport =
        carve_recursive(&bytes, "nested.tar.gz", CarveConfig::default(), None);
    assert!(
        find_innermost(&report.root),
        "committed nested fixture must recurse to secret.txt"
    );
    let recovered: Vec<u8> = recover_innermost(&bytes);
    assert_eq!(
        recovered, INNERMOST,
        "committed fixture innermost must be byte-exact"
    );
}

fn claimed_paths(node: &CarveNode, out: &mut Vec<std::path::PathBuf>) {
    for chunk in &node.chunks {
        if let Some(path) = chunk.carved_path.as_ref() {
            out.push(path.clone());
        }
    }
    for child in &node.children {
        claimed_paths(child, out);
    }
}

#[test]
fn a_report_only_carve_claims_no_path_it_is_about_to_invalidate() {
    let nested: Vec<u8> = build_nested_gz();
    let report: CarveReport =
        carve_recursive(&nested, "nested.tar.gz", CarveConfig::default(), None);
    let mut claimed: Vec<std::path::PathBuf> = Vec::new();
    claimed_paths(&report.root, &mut claimed);
    assert!(
        claimed.is_empty(),
        "a carve with no destination owns the only copy and destroys it on return, \
         so it must claim no on-disk path; claimed: {claimed:?}"
    );
    assert!(
        find_innermost(&report.root),
        "dropping the path claim must not cost the recursion"
    );
}

#[test]
fn every_path_a_destination_carve_claims_still_exists_afterwards() {
    let nested: Vec<u8> = build_nested_gz();
    let destination: tempfile::TempDir = tempfile::tempdir().expect("destination");
    let report: CarveReport = carve_recursive(
        &nested,
        "nested.tar.gz",
        CarveConfig::default(),
        Some(destination.path()),
    );
    let mut claimed: Vec<std::path::PathBuf> = Vec::new();
    claimed_paths(&report.root, &mut claimed);
    assert!(
        !claimed.is_empty(),
        "a carve into a caller directory must record where it put the members"
    );
    for path in &claimed {
        assert!(
            path.exists(),
            "the report hands back {} which does not exist, so the member was lost",
            path.display()
        );
        assert!(
            path.starts_with(destination.path()),
            "a claimed path must live under the directory the caller chose, got {}",
            path.display()
        );
    }
}
