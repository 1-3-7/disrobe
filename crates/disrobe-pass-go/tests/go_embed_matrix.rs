#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_go::{
    EmbedDigestConstruction, EmbedDigestFamily, EmbedFile, EmbedMap, Endian, GoAnalysis, GoImage,
    ImageKind, ONE_SHOT_MAX_LEN, analyze,
};

const EMBEDDED_FILE_COUNT: usize = 7;
const EMBEDDED_DIRECTORY_COUNT: usize = 2;

struct Target {
    file: &'static str,
    kind: ImageKind,
    pointer_size: u8,
    endian: Endian,
}

const MATRIX: [Target; 7] = [
    Target {
        file: "goembed_pe32_le.exe",
        kind: ImageKind::Pe,
        pointer_size: 4,
        endian: Endian::Little,
    },
    Target {
        file: "goembed_pe64_le.exe",
        kind: ImageKind::Pe,
        pointer_size: 8,
        endian: Endian::Little,
    },
    Target {
        file: "goembed_elf32_le",
        kind: ImageKind::Elf,
        pointer_size: 4,
        endian: Endian::Little,
    },
    Target {
        file: "goembed_elf64_le",
        kind: ImageKind::Elf,
        pointer_size: 8,
        endian: Endian::Little,
    },
    Target {
        file: "goembed_elf32_be",
        kind: ImageKind::Elf,
        pointer_size: 4,
        endian: Endian::Big,
    },
    Target {
        file: "goembed_elf64_be",
        kind: ImageKind::Elf,
        pointer_size: 8,
        endian: Endian::Big,
    },
    Target {
        file: "goembed_macho64_le",
        kind: ImageKind::MachO,
        pointer_size: 8,
        endian: Endian::Little,
    },
];

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/goembed")
}

fn required_bytes(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!(
            "required fixture {} is unreadable: {error}. This matrix grades recovered bytes \
             against the tracked build inputs and cannot report a result without them.",
            path.display()
        ),
    }
}

fn reference_tree() -> BTreeMap<String, Vec<u8>> {
    let root: PathBuf = fixture_dir();
    let mut tree: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = vec![root.join("assets")];
    while let Some(directory) = stack.pop() {
        let entries: std::fs::ReadDir = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => panic!(
                "reference tree {} is unreadable: {error}",
                directory.display()
            ),
        };
        for entry in entries {
            let entry: std::fs::DirEntry = entry.expect("reference tree entry");
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative: &Path = path.strip_prefix(&root).expect("inside the fixture root");
            let key: String = relative
                .components()
                .map(|component: std::path::Component<'_>| {
                    component.as_os_str().to_string_lossy().into_owned()
                })
                .collect::<Vec<String>>()
                .join("/");
            tree.insert(key, required_bytes(&path));
        }
    }
    assert_eq!(
        tree.len(),
        EMBEDDED_FILE_COUNT,
        "the tracked reference tree must hold {EMBEDDED_FILE_COUNT} files"
    );
    tree
}

#[test]
fn every_declared_container_width_and_endianness_recovers_the_tracked_tree() {
    let reference: BTreeMap<String, Vec<u8>> = reference_tree();
    let mut covered: BTreeSet<(ImageKind, u8, Endian)> = BTreeSet::new();
    let mut graded_files: usize = 0;

    for target in &MATRIX {
        let path: PathBuf = fixture_dir().join(target.file);
        let bytes: Vec<u8> = required_bytes(&path);

        let image: GoImage<'_> = GoImage::parse(&bytes)
            .unwrap_or_else(|error| panic!("{}: parse failed: {error}", target.file));
        assert_eq!(image.kind(), target.kind, "{}: container kind", target.file);
        assert_eq!(
            image.ptr_size(),
            target.pointer_size,
            "{}: pointer size",
            target.file
        );
        assert_eq!(image.endian(), target.endian, "{}: endianness", target.file);

        let analysis: GoAnalysis = analyze(&bytes)
            .unwrap_or_else(|error| panic!("{}: analyze failed: {error}", target.file));
        assert_eq!(
            analysis.embed.maps.len(),
            1,
            "{}: expected exactly one embed map, got {:?}",
            target.file,
            analysis.embed.maps
        );
        let map: &EmbedMap = &analysis.embed.maps[0];
        assert_eq!(
            map.file_count, EMBEDDED_FILE_COUNT,
            "{}: file count",
            target.file
        );
        assert_eq!(
            map.directory_count, EMBEDDED_DIRECTORY_COUNT,
            "{}: directory count",
            target.file
        );
        assert_eq!(
            map.verified_files, EMBEDDED_FILE_COUNT,
            "{}: verified {} of {EMBEDDED_FILE_COUNT} against the stored digests",
            target.file, map.verified_files
        );
        assert_eq!(
            map.digest_family,
            Some(EmbedDigestFamily::Sha256LowByte),
            "{}: digest family",
            target.file
        );
        assert!(
            map.digest_family_distinguishable,
            "{}: the map must carry at least one file at or below the one-shot threshold, \
             otherwise the family cannot be told apart from the go1.24 one",
            target.file
        );

        let recovered: BTreeMap<String, Vec<u8>> = analysis
            .embed
            .files
            .iter()
            .filter(|file: &&EmbedFile| !file.is_dir)
            .map(|file: &EmbedFile| (file.name.clone(), file.data.clone()))
            .collect();
        assert_eq!(
            recovered.keys().collect::<Vec<&String>>(),
            reference.keys().collect::<Vec<&String>>(),
            "{}: recovered path set must equal the tracked reference tree exactly",
            target.file
        );
        for (name, want) in &reference {
            let got: &Vec<u8> = recovered.get(name).unwrap_or_else(|| {
                panic!("{}: {name} absent after path-set equality", target.file)
            });
            assert_eq!(
                got,
                want,
                "{}: {name} recovered {} bytes against {} tracked",
                target.file,
                got.len(),
                want.len()
            );
            graded_files += 1;
        }

        covered.insert((target.kind, target.pointer_size, target.endian));
    }

    assert_eq!(
        covered.len(),
        MATRIX.len(),
        "every matrix row must be a distinct container, pointer width and endianness triple"
    );
    assert_eq!(
        graded_files,
        MATRIX.len() * EMBEDDED_FILE_COUNT,
        "byte-identical grade count across the whole matrix"
    );
}

#[test]
fn both_digest_branches_are_exercised_at_the_measured_thousand_and_twenty_four_boundary() {
    assert_eq!(
        ONE_SHOT_MAX_LEN, 1024,
        "the one-shot threshold measured from real go1.26 output"
    );

    let path: PathBuf = fixture_dir().join("goembed_pe64_le.exe");
    let bytes: Vec<u8> = required_bytes(&path);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze the tracked matrix image");
    let family: EmbedDigestFamily = analysis.embed.maps[0]
        .digest_family
        .expect("the matrix image resolves a digest family");

    let mut used: BTreeSet<EmbedDigestConstruction> = BTreeSet::new();
    let mut by_name: BTreeMap<&str, EmbedDigestConstruction> = BTreeMap::new();
    for file in analysis
        .embed
        .files
        .iter()
        .filter(|file: &&EmbedFile| !file.is_dir)
    {
        assert!(
            file.digest_verified,
            "{} did not verify against its stored digest",
            file.name
        );
        let construction: EmbedDigestConstruction =
            family.construction_for_len(usize::try_from(file.size).unwrap_or(usize::MAX));
        used.insert(construction);
        by_name.insert(file.name.as_str(), construction);
    }

    assert_eq!(
        used.len(),
        2,
        "the tracked tree must exercise both the one-shot and the streaming branch; used {used:?}"
    );
    assert_eq!(
        by_name.get("assets/exactly-1024.bin"),
        Some(&EmbedDigestConstruction::Sha256FlipLowByte),
        "a file of exactly 1024 bytes takes the one-shot branch"
    );
    assert_eq!(
        by_name.get("assets/over-1024.bin"),
        Some(&EmbedDigestConstruction::Sha256DomainPrefixed),
        "a file of 1025 bytes takes the streaming branch, which is what pins the boundary at 1024"
    );
    assert_eq!(
        by_name.get("assets/empty.txt"),
        Some(&EmbedDigestConstruction::Sha256FlipLowByte),
        "a zero-length file still carries the digest of its empty contents"
    );
}

#[test]
fn the_slice_header_anchor_rejects_almost_every_pointer_slot_it_examines() {
    for target in &MATRIX {
        let path: PathBuf = fixture_dir().join(target.file);
        let bytes: Vec<u8> = required_bytes(&path);
        let analysis: GoAnalysis = analyze(&bytes).expect("analyze the tracked matrix image");
        let matched: u64 = analysis.embed.scan.anchors_matched;
        assert!(
            matched > 0,
            "{}: the real map must be reached through a matched anchor",
            target.file
        );
        assert!(
            matched < 4096,
            "{}: the self-referential slice-header anchor matched {matched} slots, which is far \
             more than the handful a real image carries; a relaxed anchor sends every slot into \
             full record parsing",
            target.file
        );
    }
}
