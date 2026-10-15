#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Write as _};
use std::path::Path;

use disrobe_core::chain::{ChildArtifact, Pass};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_mobile::chain_detector::MOBILE_PASS;

fn nib(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/mobile/nib/sdcalertview")
            .join(name),
    )
    .expect("committed nib")
}

fn ipa(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("entry");
        writer.write_all(bytes).expect("write");
    }
    writer.finish().expect("finish").into_inner()
}

#[test]
fn an_ipa_hands_its_compiled_nibs_to_the_chain() {
    let cell: Vec<u8> = nib("TextFieldCell.nib");
    let runtime: Vec<u8> = nib("ActionCell.runtime.nib");
    let bytes: Vec<u8> = ipa(&[
        ("Payload/Runner.app/Info.plist", b"bplist00"),
        ("Payload/Runner.app/Runner", b"\xcf\xfa\xed\xfe"),
        ("Payload/Runner.app/TextFieldCell.nib", &cell),
        (
            "Payload/Runner.app/Base.lproj/Main.storyboardc/Info.plist",
            b"bplist00",
        ),
        ("Payload/Runner.app/ActionCell.nib/runtime.nib", &runtime),
        (
            "Payload/Runner.app/Legacy.nib",
            b"bplist00 keyed archive form",
        ),
        ("Docs/Unrelated.nib", &cell),
    ]);
    let children: Vec<ChildArtifact> = MOBILE_PASS
        .extract_children(&Artifact::new(Rung::Raw, bytes, [0u8; 32]))
        .expect("children");
    let named: Vec<(&str, usize)> = children
        .iter()
        .map(|child: &ChildArtifact| (child.handle.relative_path.as_str(), child.bytes.len()))
        .collect();
    assert_eq!(
        named,
        [
            ("Payload/Runner.app/TextFieldCell.nib", cell.len()),
            (
                "Payload/Runner.app/ActionCell.nib/runtime.nib",
                runtime.len()
            ),
        ]
    );
    assert!(
        children
            .iter()
            .all(|child: &ChildArtifact| child.handle.hint.as_deref() == Some("apple-nib"))
    );
}

#[test]
fn an_ipa_hands_its_asset_catalogs_to_the_chain() {
    let cell: Vec<u8> = nib("TextFieldCell.nib");
    let catalog: &[u8] = b"BOMStore catalog body";
    let bytes: Vec<u8> = ipa(&[
        ("Payload/Runner.app/Assets.car", catalog),
        ("Payload/Runner.app/TextFieldCell.nib", &cell),
        (
            "Payload/Runner.app/Frameworks/Kit.framework/Assets.car",
            catalog,
        ),
        ("Payload/Runner.app/Themes.car", catalog),
        ("Payload/Runner.app/Plugins/Assets.car", b"not a bom store"),
        ("Assets.car", catalog),
    ]);
    let children: Vec<ChildArtifact> = MOBILE_PASS
        .extract_children(&Artifact::new(Rung::Raw, bytes, [0u8; 32]))
        .expect("children");
    let named: Vec<(&str, Option<&str>, u32)> = children
        .iter()
        .map(|child: &ChildArtifact| {
            (
                child.handle.relative_path.as_str(),
                child.handle.hint.as_deref(),
                child.handle.artifact_index,
            )
        })
        .collect();
    assert_eq!(
        named,
        [
            (
                "Payload/Runner.app/Assets.car",
                Some("apple-asset-catalog"),
                0
            ),
            ("Payload/Runner.app/TextFieldCell.nib", Some("apple-nib"), 1),
            (
                "Payload/Runner.app/Frameworks/Kit.framework/Assets.car",
                Some("apple-asset-catalog"),
                2
            ),
        ]
    );
}
