#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::iso::{IsoImage, parse_iso};
use disrobe_binfmt::quota::ExtractionQuota;
use disrobe_binfmt::{ExtractionResult, extract_to_with_quota};

const FIXTURE: &str = "joliet-rockridge.iso";
const MEMBERS: [&str; 4] = [
    "hello.txt",
    "lorem.txt",
    "docs/notes.txt",
    "docs/a-fairly-long-joliet-name-1234567890.dat",
];

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-realiso-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join("iso")
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth iso/expected/{rel}"))
}

#[test]
fn real_iso_joliet_rockridge_recovers_members_byte_exact() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture("iso", FIXTURE) else {
        panic!(
            "missing committed fixture corpus/binfmt/iso/{FIXTURE} - see corpus/binfmt/MANIFEST.toml"
        );
    };
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Iso));

    let image: IsoImage = parse_iso(&bytes).expect("parse iso");
    assert!(image.rock_ridge, "fixture carries PVD Rock Ridge metadata");
    assert!(
        !image.joliet,
        "PVD Rock Ridge must take precedence over the Joliet fallback"
    );
    assert_eq!(image.volume_id, "DISROBE_TEST");

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("joliet");

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to_with_quota(
        ContainerKind::Iso,
        &bytes,
        &out,
        ExtractionQuota::unrestricted(),
    )
    .expect("extract iso");
    assert_eq!(result.kind, ContainerKind::Iso);
    assert!(
        result.integrity_violations.is_empty(),
        "iso extraction reported violations: {:?}",
        result.integrity_violations
    );

    for member in MEMBERS {
        let want: Vec<u8> = expected_bytes(member);
        let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
            panic!(
                "member {member} not recovered; entries={:?}",
                result.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from {FIXTURE} must be byte-identical to the source file"
        );
    }
}
