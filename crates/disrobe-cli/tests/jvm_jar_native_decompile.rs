#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::io::{Read, Write};
use std::path::PathBuf;

use common::{cli_binary, run_disrobe, temp_dir, temp_path};

fn corpus_jar() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus/jvm/megafile/EdgeCases-baseline.jar");
    p
}

fn class_bytes(jar: &std::path::Path, entry: &str) -> Vec<u8> {
    let file: std::fs::File = std::fs::File::open(jar).expect("open corpus jar");
    let mut zip: zip::ZipArchive<std::fs::File> =
        zip::ZipArchive::new(file).expect("read corpus jar");
    let mut f: zip::read::ZipFile<'_> = zip.by_name(entry).expect("entry present");
    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf).expect("read class entry");
    buf
}

fn build_fixture_jar(entries: &[(&str, Vec<u8>)]) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let (scratch, path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jvm-jar-fixture", "jar");
    let file: std::fs::File = std::fs::File::create(&path).expect("create fixture jar");
    let mut writer: zip::ZipWriter<std::fs::File> = zip::ZipWriter::new(file);
    let options: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("META-INF/MANIFEST.MF", options)
        .expect("start manifest");
    writer
        .write_all(b"Manifest-Version: 1.0\r\n\r\n")
        .expect("write manifest");
    for (name, bytes) in entries {
        writer
            .start_file(*name, options)
            .expect("start class entry");
        writer.write_all(bytes).expect("write class entry");
    }
    writer.finish().expect("finish fixture jar");
    (scratch, path)
}

#[test]
fn native_jar_decompile_emits_real_source_per_class() {
    let corpus: PathBuf = corpus_jar();
    assert!(
        corpus.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        corpus.display()
    );
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing \
         {} would leave this case driving nothing",
        cli_binary().display()
    );

    let main_class: Vec<u8> = class_bytes(&corpus, "EdgeCases.class");
    let vector_class: Vec<u8> = class_bytes(&corpus, "EdgeCases$Vector2D.class");
    let (_jar_scratch, jar): (disrobe_core::scratch::ScratchDir, PathBuf) = build_fixture_jar(&[
        ("EdgeCases.class", main_class),
        ("EdgeCases$Vector2D.class", vector_class),
    ]);

    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-jar-native");

    let out: PathBuf = out_scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        jar.to_str().expect("utf8 path"),
        "--out",
        out.to_str().expect("utf8 out"),
    ]);
    assert_eq!(run.code, 0, "jar decompile failed: {}", run.stderr);
    assert!(
        run.stdout.contains("2 decompiled / 2 total"),
        "stdout must report per-class counts: {}",
        run.stdout
    );

    let main_java: PathBuf = out.join("EdgeCases.java");
    let vector_java: PathBuf = out.join("EdgeCases$Vector2D.java");
    let main_src: String =
        std::fs::read_to_string(&main_java).expect("EdgeCases.java must be emitted");
    let vector_src: String =
        std::fs::read_to_string(&vector_java).expect("EdgeCases$Vector2D.java must be emitted");
    assert!(
        main_src.contains("class EdgeCases"),
        "main source must declare the class: {main_src}"
    );
    assert!(
        vector_src.contains("magnitude") && vector_src.contains("Math.sqrt"),
        "vector source must recover real method bodies: {vector_src}"
    );

    let manifest: String =
        std::fs::read_to_string(out.join("manifest.json")).expect("manifest.json must exist");
    assert!(
        manifest.contains("\"native_classes_decompiled\": 2"),
        "manifest must record decompiled count: {manifest}"
    );
    assert!(
        manifest.contains("\"native_decompiler\": \"disrobe-jvm\""),
        "manifest must record the in-house jvm decompiler: {manifest}"
    );

    let _ = std::fs::remove_dir_all(&out);
    let _ = std::fs::remove_file(&jar);
}

#[test]
fn native_jar_decompile_survives_one_corrupt_class() {
    let corpus: PathBuf = corpus_jar();
    assert!(
        corpus.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        corpus.display()
    );
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing \
         {} would leave this case driving nothing",
        cli_binary().display()
    );

    let good_class: Vec<u8> = class_bytes(&corpus, "EdgeCases$Vector2D.class");
    let corrupt_class: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0xFF, 0xFF];
    let (_jar_scratch, jar): (disrobe_core::scratch::ScratchDir, PathBuf) = build_fixture_jar(&[
        ("EdgeCases$Vector2D.class", good_class),
        ("Broken.class", corrupt_class),
    ]);

    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-jar-corrupt");

    let out: PathBuf = out_scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        jar.to_str().expect("utf8 path"),
        "--out",
        out.to_str().expect("utf8 out"),
    ]);
    assert_eq!(
        run.code, 0,
        "one corrupt class must not abort the whole jar: {}",
        run.stderr
    );
    assert!(
        run.stdout.contains("1 decompiled / 2 total"),
        "stdout must report the partial result: {}",
        run.stdout
    );

    let good_java: PathBuf = out.join("EdgeCases$Vector2D.java");
    assert!(
        good_java.exists(),
        "the good class must still be emitted alongside the failure"
    );
    let broken_java: PathBuf = out.join("Broken.java");
    assert!(
        !broken_java.exists(),
        "the corrupt class must not emit a bogus source file"
    );

    let manifest: String =
        std::fs::read_to_string(out.join("manifest.json")).expect("manifest.json must exist");
    assert!(
        manifest.contains("\"native_classes_failed\": 1") && manifest.contains("Broken.class"),
        "manifest must honestly record the failed class: {manifest}"
    );

    let _ = std::fs::remove_dir_all(&out);
    let _ = std::fs::remove_file(&jar);
}
