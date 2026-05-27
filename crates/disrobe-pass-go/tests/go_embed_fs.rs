#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::{GoAnalysis, analyze};

#[test]
fn embed_fs_detects_embedded_file() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let names: Vec<&str> = analysis
        .embed
        .files
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(
        names.iter().any(|n| n.contains("embedded.txt")),
        "expected embedded.txt in embed report; got: {names:?}"
    );
}

#[test]
fn embed_fs_strings_with_marker_present() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let any_marker: bool = analysis
        .embed
        .strings_with_embed_marker
        .iter()
        .any(|s| s == "embed.FS");
    assert!(any_marker, "expected embed.FS string in image");
}
