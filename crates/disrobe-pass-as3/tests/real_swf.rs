#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::path::PathBuf;

use disrobe_pass_as3::abc::{DisasmLine, disasm};
use disrobe_pass_as3::swf::{Swf, SwfCompression, TagCode};
use disrobe_pass_as3::{AbcFile, DoAbc, abc, decompile, swf};

fn corpus_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
}

fn load_fixture(name: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus_root().join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!("skip: {name} fixture absent ({})", path.display());
            None
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct CorpusTotals {
    files_with_abc: usize,
    abc_blobs: usize,
    methods: usize,
    instances: usize,
    opcodes: usize,
    decompiled_classes: usize,
}

fn parse_corpus() -> Option<CorpusTotals> {
    let dir: PathBuf = corpus_root();
    let entries: std::fs::ReadDir = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(_) => {
            eprintln!("skip: corpus directory absent ({})", dir.display());
            return None;
        }
    };
    let mut totals: CorpusTotals = CorpusTotals::default();
    let mut swf_seen: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("swf") {
            continue;
        }
        swf_seen += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let parsed: Swf =
            swf::parse(&bytes).unwrap_or_else(|e| panic!("swf parse {}: {e}", path.display()));
        let blobs: Vec<DoAbc> = parsed.collect_do_abc();
        if blobs.is_empty() {
            continue;
        }
        totals.files_with_abc += 1;
        for blob in &blobs {
            assert!(
                !blob.abc_bytes.is_empty(),
                "DoABC payload empty in {}",
                path.display()
            );
            let abc: AbcFile = abc::parse(&blob.abc_bytes).unwrap_or_else(|e| {
                panic!(
                    "abc parse must succeed for {} blob '{}': {e}",
                    path.display(),
                    blob.name
                )
            });
            assert_eq!(abc.minor, abc::ABC_MINOR, "{}", path.display());
            assert_eq!(abc.major, abc::ABC_MAJOR, "{}", path.display());
            totals.abc_blobs += 1;
            totals.methods += abc.methods.len();
            totals.instances += abc.instances.len();
            for body in &abc.method_bodies {
                let lines: Vec<DisasmLine> = disasm(&body.code).unwrap_or_else(|e| {
                    panic!("disasm {} blob '{}': {e}", path.display(), blob.name)
                });
                totals.opcodes += lines.len();
            }
            for instance in &abc.instances {
                if let Ok(skel) = decompile::render_class_skeleton(&abc, instance) {
                    assert!(
                        skel.contains("class ") || skel.contains("interface "),
                        "skeleton must declare a class/interface in {}",
                        path.display()
                    );
                    totals.decompiled_classes += 1;
                }
            }
        }
    }
    if swf_seen == 0 {
        eprintln!(
            "skip: corpus directory holds no .swf fixtures ({})",
            dir.display()
        );
        return None;
    }
    Some(totals)
}

#[test]
fn detects_uncompressed_fws_signature() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("A-Blast_Liberation.swf") else {
        return;
    };
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::None);
}

#[test]
fn detects_zlib_cws_signature() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("4_Ball_Pong.swf") else {
        return;
    };
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::Zlib);
}

#[test]
fn detects_lzma_zws_signature() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("10_More_Bullets.swf") else {
        return;
    };
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::Lzma);
}

#[test]
fn parses_real_uncompressed_swf_header_and_tags() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("A-Blast_Liberation.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse FWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::None);
    assert!(parsed.header.version >= 1);
    assert!(parsed.header.frame_count >= 1);
    assert!(
        parsed.tags.len() >= 5,
        "expected non-trivial tag stream, got {}",
        parsed.tags.len()
    );
    assert!(
        parsed
            .tags
            .iter()
            .any(|t: &swf::SwfTag| t.code == TagCode::END)
    );
}

#[test]
fn parses_real_zlib_swf_header_and_tags() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("4_Ball_Pong.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse CWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::Zlib);
    assert!(parsed.header.version >= 6);
    assert!(parsed.tags.len() >= 5);
}

#[test]
fn parses_real_lzma_swf_extracts_and_parses_do_abc() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("10_More_Bullets.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse ZWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::Lzma);
    let abc_blobs: Vec<DoAbc> = parsed.collect_do_abc();
    assert!(
        !abc_blobs.is_empty(),
        "AS3-era LZMA SWF should contain at least one DoABC tag"
    );
    let mut total_opcodes: usize = 0;
    for blob in &abc_blobs {
        assert!(!blob.abc_bytes.is_empty(), "DoABC payload empty");
        let abc: AbcFile = abc::parse(&blob.abc_bytes)
            .unwrap_or_else(|e| panic!("abc parse '{}': {e}", blob.name));
        assert_eq!(abc.minor, abc::ABC_MINOR);
        assert_eq!(abc.major, abc::ABC_MAJOR);
        assert!(
            !abc.cpool.strings.is_empty(),
            "real ABC must have a populated string pool"
        );
        for body in &abc.method_bodies {
            total_opcodes += disasm(&body.code)
                .unwrap_or_else(|e| panic!("disasm '{}': {e}", blob.name))
                .len();
        }
    }
    assert!(
        total_opcodes > 0,
        "real ABC must disassemble to a non-zero opcode stream"
    );
}

#[test]
fn parses_real_zlib_3d_motorbike_walks_tag_counts() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("3D_Motorbike_Racer.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse swf");
    let counts: std::collections::BTreeMap<TagCode, usize> = parsed.tag_counts();
    assert!(!counts.is_empty());
    let total: usize = counts.values().sum();
    assert!(
        total >= 20,
        "expected many tags in 3D_Motorbike_Racer.swf, got {total}"
    );
}

#[test]
fn parses_real_atv_megafile_abc_with_classes_and_opcodes() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("ATV_Cross_Canada.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse megafile swf");
    assert!(parsed.header.version >= 10, "ATV is AS3-era v11");
    let counts: std::collections::BTreeMap<TagCode, usize> = parsed.tag_counts();
    let total: usize = counts.values().sum();
    assert!(
        total >= 50,
        "expected megafile SWF to have many tags, got {total}"
    );
    let abc_blobs: Vec<DoAbc> = parsed.collect_do_abc();
    assert!(
        !abc_blobs.is_empty(),
        "ATV megafile must contain DoABC tags"
    );
    let mut total_classes: usize = 0;
    let mut total_opcodes: usize = 0;
    let mut total_decompiled: usize = 0;
    for blob in &abc_blobs {
        let abc: AbcFile = abc::parse(&blob.abc_bytes)
            .unwrap_or_else(|e| panic!("abc parse '{}': {e}", blob.name));
        assert_eq!(abc.minor, abc::ABC_MINOR);
        assert_eq!(abc.major, abc::ABC_MAJOR);
        total_classes += abc.instances.len();
        for body in &abc.method_bodies {
            total_opcodes += disasm(&body.code)
                .unwrap_or_else(|e| panic!("disasm '{}': {e}", blob.name))
                .len();
        }
        for instance in &abc.instances {
            if let Ok(skel) = decompile::render_class_skeleton(&abc, instance) {
                assert!(skel.contains("class ") || skel.contains("interface "));
                total_decompiled += 1;
            }
        }
    }
    assert!(
        total_classes > 0,
        "ATV megafile ABC must define at least one class"
    );
    assert!(
        total_opcodes > 0,
        "ATV megafile ABC must disassemble to a non-zero opcode stream"
    );
    assert!(
        total_decompiled > 0,
        "ATV megafile ABC must render at least one class skeleton"
    );
}

#[test]
fn corpus_wide_real_abc_parses_and_disassembles() {
    let Some(totals): Option<CorpusTotals> = parse_corpus() else {
        return;
    };
    assert!(
        totals.files_with_abc >= 3,
        "expected multiple AS3-bearing fixtures, got {}",
        totals.files_with_abc
    );
    assert!(
        totals.abc_blobs >= totals.files_with_abc,
        "every ABC-bearing file must yield at least one parsed blob"
    );
    assert!(
        totals.instances > 0,
        "real corpus must define classes across DoABC tags, got {}",
        totals.instances
    );
    assert!(
        totals.opcodes > 0,
        "real corpus must disassemble to a non-zero opcode stream, got {}",
        totals.opcodes
    );
    assert!(
        totals.decompiled_classes > 0,
        "real corpus must render at least one class skeleton, got {}",
        totals.decompiled_classes
    );
    assert!(
        totals.methods > 0,
        "real corpus must declare methods across DoABC tags, got {}",
        totals.methods
    );
}

#[test]
fn rejects_truncated_real_swf() {
    let Some(mut bytes): Option<Vec<u8>> = load_fixture("A-Blast_Liberation.swf") else {
        return;
    };
    bytes.truncate(8);
    let _ = swf::parse(&bytes).expect_err("must fail on truncated body");
}

#[test]
fn rejects_corrupted_magic_signature() {
    let Some(mut bytes): Option<Vec<u8>> = load_fixture("3D_Frogger.swf") else {
        return;
    };
    bytes[0] = b'X';
    let err: disrobe_pass_as3::Error = swf::parse(&bytes).expect_err("must reject bad magic");
    let msg: String = err.to_string();
    assert!(msg.contains("DR-AS3") || msg.contains("signature") || msg.contains("Bad"));
}
