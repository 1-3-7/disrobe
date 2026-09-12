#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
mod common;

use common::{
    CRYSTAL_PE, D_PE, NIM_ELF, ZIG_ELF, ZIG_RELEASEFAST_ELF, ZIG_RELEASEFAST_MACHO,
    ZIG_RELEASEFAST_PE, crate_fixture_or_fail, fixture_or_fail,
};
use disrobe_pass_nativelang::{
    ImageKind, LangFingerprint, NativeImage, NativeLang, NativeLangAnalysis, analyze, fingerprint,
    marker_hits, runtime_markers,
};

const CHAIN_MINIMUM_HITS: usize = 2;

#[derive(Debug, Clone, Copy)]
enum Origin {
    Corpus(&'static str),
    CrateFixture(&'static str),
}

impl Origin {
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Corpus(rel) => fixture_or_fail(rel),
            Self::CrateFixture(rel) => crate_fixture_or_fail(rel),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Corpus(rel) | Self::CrateFixture(rel) => rel,
        }
    }
}

struct ZigBuild {
    toolchain: &'static str,
    build: &'static str,
    container: ImageKind,
    origin: Origin,
    hits: usize,
    expected: &'static [&'static str],
}

const ZIG_BUILDS: &[ZigBuild] = &[
    ZigBuild {
        toolchain: "zig 0.13.0",
        build: "safety-checked, unstripped",
        container: ImageKind::Elf,
        origin: Origin::Corpus(ZIG_ELF),
        hits: 12,
        expected: &[
            "__zig_probe_stack",
            "__zig_tag_name_",
            "attempt to unwrap error: ",
            "builtin.zig",
            "compiler_rt",
            "heap.PageAllocator",
            "mem.Allocator.",
            "panicOutOfBounds",
            "panicUnwrap",
            "reached unreachable code",
            "start.callMain",
            "start.posixCallMainAndExit",
        ],
    },
    ZigBuild {
        toolchain: "zig 0.16.0",
        build: "ReleaseFast, debug sections removed",
        container: ImageKind::Elf,
        origin: Origin::CrateFixture(ZIG_RELEASEFAST_ELF),
        hits: 3,
        expected: &[
            "compiler_rt",
            "mem.Allocator.",
            "start.posixCallMainAndExit",
        ],
    },
    ZigBuild {
        toolchain: "zig 0.16.0",
        build: "ReleaseFast, no symbol table and no panic text",
        container: ImageKind::Pe,
        origin: Origin::CrateFixture(ZIG_RELEASEFAST_PE),
        hits: 2,
        expected: &[".buildid", "RtlExitUserProcess"],
    },
    ZigBuild {
        toolchain: "zig 0.16.0",
        build: "ReleaseFast, debug map removed",
        container: ImageKind::MachO,
        origin: Origin::CrateFixture(ZIG_RELEASEFAST_MACHO),
        hits: 2,
        expected: &["mem.Allocator.", "start.main"],
    },
];

const CONTROLS: &[(&str, Origin, NativeLang)] = &[
    ("nim", Origin::Corpus(NIM_ELF), NativeLang::Nim),
    ("crystal", Origin::Corpus(CRYSTAL_PE), NativeLang::Crystal),
    ("d", Origin::Corpus(D_PE), NativeLang::D),
];

const UNRELATED: &[&str] = &[
    "packers/aspack/AccessEnum.original.exe",
    "compilers/go/hello.go.exe",
    "anti-analysis/large-benign-x86_64-pc-windows-msvc.exe",
    "formats/hello.auditable.exe",
];

fn fingerprint_of(bytes: &[u8], label: &str) -> LangFingerprint {
    let image: NativeImage<'_> = NativeImage::parse(bytes)
        .unwrap_or_else(|error| panic!("{label} must parse as a native image, got {error}"));
    fingerprint(&image).unwrap_or_else(|| panic!("{label} must produce a language fingerprint"))
}

#[test]
fn every_committed_zig_build_fingerprints_as_zig_on_its_own_container() {
    for build in ZIG_BUILDS {
        let bytes: Vec<u8> = build.origin.bytes();
        let found: Vec<String> = {
            let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse");
            assert_eq!(
                image.kind,
                build.container,
                "{} must be a {:?}",
                build.origin.label(),
                build.container
            );
            marker_hits(&image, NativeLang::Zig)
        };
        let rendered: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(
            rendered,
            build.expected,
            "{} [{}] [{}]: the recorded zig marker set moved",
            build.origin.label(),
            build.toolchain,
            build.build
        );
        assert_eq!(found.len(), build.hits);
        let fp: LangFingerprint = fingerprint_of(&bytes, build.origin.label());
        assert_eq!(
            fp.lang,
            NativeLang::Zig,
            "{} [{}] must fingerprint as zig, got {:?}",
            build.origin.label(),
            build.build,
            fp.lang
        );
        assert!(
            found.len() >= CHAIN_MINIMUM_HITS,
            "{} [{}] scores {} zig markers, below the {CHAIN_MINIMUM_HITS} the chain detector \
             requires, so the pass would stay unreachable",
            build.origin.label(),
            build.build,
            found.len()
        );
        println!(
            "{} [{}] [{}] [{:?}]: {}/{} zig markers, confidence {:.4}",
            build.origin.label(),
            build.toolchain,
            build.build,
            build.container,
            found.len(),
            runtime_markers(NativeLang::Zig).len(),
            fp.confidence
        );
    }
}

#[test]
fn each_newly_reachable_zig_container_reaches_the_whole_pass_and_not_only_the_fingerprint() {
    for (relative, container) in [
        (ZIG_RELEASEFAST_PE, ImageKind::Pe),
        (ZIG_RELEASEFAST_MACHO, ImageKind::MachO),
    ] {
        let bytes: Vec<u8> = crate_fixture_or_fail(relative);
        let analysis: NativeLangAnalysis = analyze(&bytes).unwrap_or_else(|error| {
            panic!("{relative} must reach the nativelang pass, got a refusal: {error}")
        });
        assert_eq!(analysis.fingerprint.lang, NativeLang::Zig);
        assert_eq!(analysis.image_kind, container);
        assert!(
            !analysis.function_recovery.functions.is_empty(),
            "{relative}: the pass must carve the image, carved {}",
            analysis.function_recovery.functions.len()
        );
        assert!(
            analysis.bodies.arch_supported,
            "{relative}: a zig x86-64 image must reach the body lift"
        );
        assert_eq!(
            analysis.bodies.recovered
                + analysis.bodies.recovered_elided
                + analysis.bodies.rejected
                + analysis.bodies.not_attempted,
            analysis.bodies.function_count
        );
        println!(
            "{relative} [{container:?}]: carved {} functions, recovered {} pseudo-C bodies",
            analysis.function_recovery.functions.len(),
            analysis.bodies.recovered
        );
    }
}

#[test]
fn the_structural_pair_is_what_carries_a_stripped_zig_pe() {
    let bytes: Vec<u8> = crate_fixture_or_fail(ZIG_RELEASEFAST_PE);
    let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse");
    for text in [
        "ZIG_PROGRESS",
        "reached unreachable code",
        "attempt to unwrap error: ",
        "compiler_rt",
        "start.posixCallMainAndExit",
        "mem.Allocator.",
    ] {
        assert!(
            !image.raw_contains(text.as_bytes()),
            "this fixture is the structural-only case; {text} must be absent or it stops \
             exercising the pair"
        );
    }
    for text in [".buildid", "RtlExitUserProcess"] {
        assert!(
            image.raw_contains(text.as_bytes()),
            "the zig windows start path must carry {text}"
        );
    }
}

#[test]
fn no_other_language_or_unrelated_binary_scores_a_zig_marker() {
    for (label, origin, expected) in CONTROLS {
        let bytes: Vec<u8> = origin.bytes();
        let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse a control image");
        let zig: Vec<String> = marker_hits(&image, NativeLang::Zig);
        assert!(
            zig.is_empty(),
            "the {label} fixture scores zig markers {zig:?}; a zig marker that fires on another \
             language can win the fingerprint outright"
        );
        let fp: LangFingerprint = fingerprint_of(&bytes, label);
        assert_eq!(
            fp.lang, *expected,
            "{label} must still fingerprint as {label}"
        );
    }
    for relative in UNRELATED {
        let bytes: Vec<u8> = fixture_or_fail(relative);
        let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse a control image");
        let zig: Vec<String> = marker_hits(&image, NativeLang::Zig);
        assert!(
            zig.is_empty(),
            "{relative} is not a zig binary but scores zig markers {zig:?}"
        );
    }
}

#[test]
fn every_zig_marker_is_carried_by_a_committed_zig_build() {
    let mut unseen: Vec<String> = Vec::new();
    for marker in runtime_markers(NativeLang::Zig) {
        let text: String = String::from_utf8_lossy(marker).into_owned();
        let carried: bool = ZIG_BUILDS
            .iter()
            .any(|build: &ZigBuild| build.expected.contains(&text.as_str()));
        if !carried {
            unseen.push(text);
        }
    }
    assert!(
        unseen.is_empty(),
        "these zig markers are declared but no committed fixture carries them, so nothing proves \
         they match a real build: {unseen:?}"
    );
}
