#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{GoAnalysis, analyze};

#[test]
fn embed_fs_walks_real_embedded_files() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_EMBED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze embed fixture");
    assert!(analysis.embed.uses_embed_fs, "embed.FS usage not detected");
    let names: Vec<&str> = analysis
        .embed
        .files
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(
        names.contains(&"assets/note.txt"),
        "expected assets/note.txt; got: {names:?}"
    );
    assert!(
        names.contains(&"assets/data.bin"),
        "expected assets/data.bin; got: {names:?}"
    );
    let note: &disrobe_pass_go::EmbedFile = analysis
        .embed
        .files
        .iter()
        .find(|f| f.name == "assets/note.txt")
        .expect("note.txt entry");
    assert_eq!(note.size, 36, "note.txt size mismatch");
    assert!(!note.is_dir, "note.txt must not be a dir");
    assert!(
        note.preview.starts_with("disrobe embed fixture payload"),
        "preview mismatch: {:?}",
        note.preview
    );
    assert_eq!(
        note.data.len(),
        note.size as usize,
        "carved data must be the full member, not a preview"
    );
    assert_eq!(
        note.data, b"disrobe embed fixture payload alpha\n",
        "carved bytes must be byte-exact source content"
    );
}

#[test]
fn embed_fs_no_false_positives_on_plain_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    assert!(
        analysis.embed.files.is_empty(),
        "plain binary must not report embedded files; got: {:?}",
        analysis
            .embed
            .files
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn embed_fs_does_not_panic_on_stripped() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_STRIPPED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped");
    let _ = analysis.embed.files.len();
}
