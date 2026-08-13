#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

#[path = "support/dyld_cache_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dyld_cache_fixture;

use std::path::PathBuf;

use disrobe_core::chain::{ChildArtifact, DetectContext, DetectVerdict, Detector, Pass};
use disrobe_core::error::CoreError;
use disrobe_core::pass::PassContext;
use disrobe_core::scratch::ScratchDir;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_swift_objc::chain_detector::{SWIFT_OBJC_PASS, SwiftObjcDetector};
use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::pass::{ContainerKind, SwiftObjcReport};

use dyld_cache_fixture::{BuiltCache, CacheSpec};
use macho_corpus::{SWIFT_HELLO_ORIGINAL, read_tracked};

const INSTALL_NAME: &str = "/usr/lib/libSwiftHello.dylib";

const fn ctx(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    }
}

fn built(spec: &CacheSpec) -> (Vec<u8>, BuiltCache) {
    let image: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let cache: BuiltCache = dyld_cache_fixture::build(&image, spec);
    (image, cache)
}

#[test]
fn the_detector_claims_a_dyld_shared_cache_and_names_its_layout() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let verdict: DetectVerdict = Detector::detect(&SwiftObjcDetector, &ctx(&cache.primary))
        .expect("a dyld cache carries the dyld_v1 magic");
    assert_eq!(verdict.format_tag, "dyld-shared-cache");
    assert_eq!(verdict.markers, vec!["dyld-v1-magic"]);
    assert!(verdict.explain.contains("relocated-images"));
    assert!(verdict.explain.contains("images=1"));
}

#[test]
fn the_detector_does_not_claim_a_file_that_only_starts_with_the_magic() {
    let mut bogus: Vec<u8> = vec![0u8; 64];
    bogus[..7].copy_from_slice(b"dyld_v1");
    assert!(
        Detector::detect(&SwiftObjcDetector, &ctx(&bogus)).is_none(),
        "a header that does not parse must not be claimed"
    );
}

#[test]
fn running_the_pass_over_a_cache_reports_the_container_and_its_images() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let artifact: Artifact = Artifact::new(Rung::Raw, cache.primary, [0u8; 32]);
    let output: Artifact = SWIFT_OBJC_PASS.run(&artifact).expect("the pass runs");
    let report: SwiftObjcReport =
        serde_json::from_slice(output.envelope.as_slice()).expect("the report deserializes");
    assert_eq!(report.container, ContainerKind::DyldSharedCache);
    let cache_report = report.dyld_cache.expect("a cache report is attached");
    assert_eq!(cache_report.images, 1);
    assert_eq!(cache_report.install_names, vec![INSTALL_NAME.to_owned()]);
    assert_eq!(cache_report.layout, "relocated-images");
    assert!(cache_report.slide_regions.is_empty());
}

#[test]
fn extracting_children_emits_each_bundled_dylib_as_a_load_ready_child() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let artifact: Artifact = Artifact::new(Rung::Raw, cache.primary, [0u8; 32]);
    let children: Vec<ChildArtifact> = SWIFT_OBJC_PASS
        .extract_children(&artifact)
        .expect("a single-file cache extracts without a path");
    assert_eq!(children.len(), 1);
    let child: &ChildArtifact = &children[0];
    assert_eq!(child.handle.relative_path, "usr/lib/libSwiftHello.dylib");
    let parsed: ParsedSlice =
        macho::parse_slice(&child.bytes).expect("the child parses as a Mach-O");
    let original: ParsedSlice = macho::parse_slice(&image).expect("the original parses");
    assert_eq!(
        macho::symbol_names(&child.bytes, &parsed),
        macho::symbol_names(&image, &original),
        "a child artifact must carry the symbol table the original binary declares"
    );
}

#[test]
fn extracting_children_from_a_split_cache_uses_the_path_the_chain_supplies() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME).split());
    let dir: ScratchDir = ScratchDir::create("dr-dyld-chain").expect("scratch directory");
    let primary: PathBuf = dir.path().join("dyld_shared_cache_arm64e");
    std::fs::write(&primary, &cache.primary).expect("write the primary cache");
    std::fs::write(
        dir.path().join("dyld_shared_cache_arm64e.1"),
        cache
            .sibling
            .as_ref()
            .expect("the split cache has a sibling"),
    )
    .expect("write the sibling cache");

    let artifact: Artifact = Artifact::new(Rung::Raw, cache.primary, [0u8; 32]);
    let hint: String = primary.display().to_string();
    let children: Vec<ChildArtifact> = SWIFT_OBJC_PASS
        .extract_children_with_context(&artifact, PassContext::with_path_hint(Some(&hint)))
        .expect("a split cache extracts through its path");
    assert_eq!(children.len(), 1);
    let parsed: ParsedSlice =
        macho::parse_slice(&children[0].bytes).expect("the child parses as a Mach-O");
    let original: ParsedSlice = macho::parse_slice(&image).expect("the original parses");
    assert_eq!(
        macho::symbol_names(&children[0].bytes, &parsed),
        macho::symbol_names(&image, &original)
    );
}

#[test]
fn a_split_cache_without_a_path_is_refused_by_name_rather_than_half_extracted() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME).split());
    let artifact: Artifact = Artifact::new(Rung::Raw, cache.primary, [0u8; 32]);
    let refusal: CoreError = SWIFT_OBJC_PASS
        .extract_children(&artifact)
        .expect_err("sibling files cannot be located without the primary path");
    let text: String = format!("{refusal}");
    assert!(text.contains("DR-SWOBJ-0910"), "got {text}");
    assert!(text.contains("sibling files"), "got {text}");
}

#[test]
fn a_mach_o_input_still_extracts_no_children() {
    let image: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let artifact: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    assert!(
        SWIFT_OBJC_PASS
            .extract_children(&artifact)
            .expect("a plain Mach-O extracts nothing")
            .is_empty()
    );
}
