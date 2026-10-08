#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[path = "common/oodle_encoder/mod.rs"]
mod oodle_encoder;
#[path = "common/oodle_fixtures.rs"]
mod oodle_fixtures;

use std::fmt::Write as _;

use common::requirement::required_fixture;
use disrobe_binfmt::containers::oodle::{OodleCensus, OodleError, decode};
use oodle_encoder::entropy::{Form, MultiStyle};
use oodle_encoder::huffman::HuffHeader;
use oodle_encoder::tans::TansTable;
use oodle_encoder::{Block, BlockPlan, Codec, LzStyle, SubBlock, encode_stream, lz_stream};
use oodle_fixtures::{
    FIXTURE_DIR, OODLE_FIXTURES, mixed, noise, payload_for, records, stream_for, text,
};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut out: String = String::with_capacity(64);
    for byte in digest {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn decoded(stream: &[u8], len: usize) -> (Result<Vec<u8>, OodleError>, OodleCensus) {
    let mut census: OodleCensus = OodleCensus::default();
    let result: Result<Vec<u8>, OodleError> = decode(stream, len, &mut census);
    (result, census)
}

fn manifest_row(manifest: &str, name: &str) -> (String, String) {
    let mut lines = manifest.lines();
    while let Some(line) = lines.next() {
        if line.trim() == format!("path = \"{name}\"") {
            let mut sha: Option<String> = None;
            let mut payload: Option<String> = None;
            for row in lines.by_ref().take(6) {
                if let Some(v) = row.strip_prefix("sha256 = \"") {
                    sha = Some(v.trim_end_matches('"').to_owned());
                }
                if let Some(v) = row.strip_prefix("payload_sha256 = \"") {
                    payload = Some(v.trim_end_matches('"').to_owned());
                }
            }
            return (
                sha.unwrap_or_else(|| panic!("sha256 row for {name}")),
                payload.unwrap_or_else(|| panic!("payload_sha256 row for {name}")),
            );
        }
    }
    panic!("MANIFEST.toml has no row for {name}");
}

fn expected_paths(name: &str) -> &'static [&'static str] {
    match name {
        "kraken-sub.oodle" => &["kraken:sub", "huffman:new"],
        "kraken-raw-scaled.oodle" => &[
            "kraken:raw",
            "kraken:scaled-offsets",
            "tans:rice-weights",
            "entropy:rle",
        ],
        "kraken-two-sub-blocks.oodle" => &["kraken:sub", "kraken:raw", "kraken:scaled-offsets"],
        "leviathan-sub.oodle" => &["leviathan:sub"],
        "leviathan-raw-multi-command.oodle" => &["leviathan:raw", "leviathan:multi-command"],
        "leviathan-lamsub.oodle" => &["leviathan:lamsub", "entropy:multi-array"],
        "leviathan-sub-and-3.oodle" => &["leviathan:sub-and-3", "entropy:multi-array"],
        "leviathan-o1.oodle" => &["leviathan:o1", "entropy:multi-array"],
        "leviathan-sub-and-f-scaled.oodle" => &["leviathan:sub-and-f", "leviathan:scaled-offsets"],
        "mermaid-sub.oodle" => &["mermaid:sub"],
        "mermaid-raw-entropy-near.oodle" => &["mermaid:raw", "mermaid:entropy-near-offsets"],
        "kraken-stored-arrays.oodle" => &["kraken:sub", "entropy:stored"],
        "entropy-huffman-old-sparse.oodle" => &["sub-block:entropy-only", "huffman:old-sparse"],
        "entropy-huffman-old-dense.oodle" => &["sub-block:entropy-only", "huffman:old-dense"],
        "entropy-huffman-new.oodle" => &["sub-block:entropy-only", "huffman:new"],
        "entropy-huffman-two-halves.oodle" => &["huffman:two-halves", "huffman:old-dense"],
        "entropy-huffman-memset.oodle" => &["huffman:memset"],
        "entropy-tans-explicit.oodle" => &["entropy:tans", "tans:explicit-weights"],
        "entropy-tans-rice.oodle" => &["entropy:tans", "tans:rice-weights"],
        "entropy-rle.oodle" => &["entropy:rle"],
        "entropy-rle-coded.oodle" => &["entropy:rle", "rle:entropy-coded-commands"],
        "entropy-recursive.oodle" => &["entropy:recursive"],
        "entropy-recursive-multi-array.oodle" => &["entropy:recursive", "entropy:multi-array"],
        "quantum-stored.oodle" => &["quantum:stored"],
        "block-uncompressed.oodle" => &["block:uncompressed"],
        "hydra.oodle" => &[
            "kraken:sub",
            "leviathan:sub",
            "mermaid:raw",
            "quantum:memset",
            "block:uncompressed",
        ],
        other => panic!("no expected decoder paths for {other}"),
    }
}

#[test]
fn committed_oodle_fixtures_decode_to_their_authored_payloads_through_their_named_paths() {
    let manifest: String = String::from_utf8(required_fixture(FIXTURE_DIR, "MANIFEST.toml"))
        .expect("manifest is utf-8");
    for name in OODLE_FIXTURES {
        let committed: Vec<u8> = required_fixture(FIXTURE_DIR, name);
        let payload: Vec<u8> = payload_for(name);
        let (sha, payload_sha): (String, String) = manifest_row(&manifest, name);
        assert_eq!(sha, sha256_hex(&committed), "{name} manifest sha256");
        assert_eq!(payload_sha, sha256_hex(&payload), "{name} payload sha256");
        assert_eq!(
            committed,
            stream_for(name),
            "{name} drifted from its encoder"
        );
        let (result, census) = decoded(&committed, payload.len());
        let output: Vec<u8> = result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(output == payload, "{name} decodes to different bytes");
        for path in expected_paths(name) {
            assert!(
                census.paths.contains_key(*path),
                "{name} never took decoder path {path}: {:?}",
                census.paths
            );
        }
        assert!(
            committed.len() < payload.len()
                || name.contains("stored")
                || name.contains("uncompressed"),
            "{name} does not compress"
        );
    }
}

fn noticed(stream: &[u8], at: usize, flip: u8, payload: &[u8]) -> bool {
    let mut mutated: Vec<u8> = stream.to_vec();
    mutated[at] ^= flip;
    !matches!(decoded(&mutated, payload.len()), (Ok(output), _) if output == payload)
}

#[test]
fn every_wrong_byte_in_every_committed_fixture_is_refused_or_changes_the_output() {
    let mut positions: usize = 0;
    let mut inverted_alone: usize = 0;
    let mut ignored: Vec<String> = Vec::new();
    for name in OODLE_FIXTURES {
        let committed: Vec<u8> = required_fixture(FIXTURE_DIR, name);
        let payload: Vec<u8> = payload_for(name);
        for at in 0..committed.len() {
            positions += 1;
            if noticed(&committed, at, 0xFF, &payload) {
                inverted_alone += 1;
                continue;
            }
            if !(1..=0xFEu8).any(|flip: u8| noticed(&committed, at, flip, &payload)) {
                ignored.push(format!("{name} byte {at}"));
            }
        }
    }
    println!(
        "oodle mutation control: {positions} byte positions, {inverted_alone} refused or changed by inverting the byte, the rest by another wrong value"
    );
    assert!(positions > 10_000, "the control covers too few positions");
    assert!(
        positions - inverted_alone < positions / 1000,
        "too many inverted bytes leave the output unchanged"
    );
    assert!(
        ignored.is_empty(),
        "{} of {positions} byte positions accept every wrong value: {:?}",
        ignored.len(),
        &ignored[..ignored.len().min(20)]
    );
}

fn styles() -> Vec<LzStyle> {
    let base: LzStyle = LzStyle::default();
    vec![
        base.clone(),
        LzStyle {
            literals: Form::Stored,
            commands: Form::Stored,
            offsets: Form::Stored,
            lengths: Form::Stored,
            ..base.clone()
        },
        LzStyle {
            literals: Form::Tans {
                table: TansTable::Rice { q: 2 },
                l_bits: 10,
            },
            commands: Form::Recursive(2),
            offsets: Form::Huffman(HuffHeader::New { forced: 1 }),
            lengths: Form::Huffman(HuffHeader::OldDense { forced: 3 }),
            scale: Some(5),
            multi: MultiStyle::Intervals {
                sources: 2,
                packed: true,
            },
            entropy_near_offsets: true,
            far_matches: true,
            ..base.clone()
        },
        LzStyle {
            literals: Form::RleCodedCommands,
            commands: Form::HuffmanHalves(HuffHeader::New { forced: 0 }),
            max_match: 300,
            multi_commands: true,
            multi: MultiStyle::Intervals {
                sources: 7,
                packed: false,
            },
            ..base
        },
    ]
}

fn payloads() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("text", text(21, 9000)),
        ("records", records(22, 12_000)),
        ("noise", noise(23, 3000)),
        ("mixed", mixed(24, 70_000)),
        ("zeros", vec![0u8; 5000]),
        ("tiny", b"0123456789abcdef0123456789".to_vec()),
        ("large", mixed(25, 300_000)),
    ]
}

#[test]
fn authored_streams_round_trip_for_every_codec_mode_and_style() {
    let mut checked: usize = 0;
    for (label, payload) in payloads() {
        for (codec, modes) in [
            (Codec::Kraken, 0..2u32),
            (Codec::Mermaid, 0..2u32),
            (Codec::Leviathan, 0..6u32),
        ] {
            for mode in modes {
                for (index, style) in styles().into_iter().enumerate() {
                    if label == "large" && index > 0 {
                        continue;
                    }
                    let stream: Vec<u8> = lz_stream(codec, mode, style, &payload);
                    let (result, _) = decoded(&stream, payload.len());
                    let output: Vec<u8> = result.unwrap_or_else(|e| {
                        panic!("{label} {codec:?} mode {mode} style {index}: {e}")
                    });
                    assert!(
                        output == payload,
                        "{label} {codec:?} mode {mode} style {index} round trip"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 200);
}

#[test]
fn entropy_only_sub_blocks_round_trip_for_every_array_form() {
    let forms: Vec<Form> = vec![
        Form::Stored,
        Form::Huffman(HuffHeader::OldSparse),
        Form::Huffman(HuffHeader::OldDense { forced: 0 }),
        Form::Huffman(HuffHeader::OldDense { forced: 3 }),
        Form::Huffman(HuffHeader::New { forced: 2 }),
        Form::HuffmanHalves(HuffHeader::New { forced: 1 }),
        Form::Tans {
            table: TansTable::Rice { q: 3 },
            l_bits: 8,
        },
        Form::Tans {
            table: TansTable::Rice { q: 0 },
            l_bits: 11,
        },
        Form::Rle,
        Form::RleCodedCommands,
        Form::Recursive(5),
        Form::RecursiveMulti(3),
    ];
    for (label, payload) in [
        ("text", text(31, 5000)),
        ("records", records(32, 7000)),
        ("zeros-and-text", {
            let mut v: Vec<u8> = vec![0u8; 3000];
            v.extend(text(33, 2000));
            v
        }),
    ] {
        for form in &forms {
            let stream: Vec<u8> = encode_stream(
                &payload,
                &[BlockPlan {
                    codec: Codec::Kraken,
                    block: Block::Quantum(vec![SubBlock::Entropy(form.clone())]),
                }],
            );
            let (result, _) = decoded(&stream, payload.len());
            assert!(
                result.as_deref() == Ok(payload.as_slice()),
                "{label} {form:?}: {:?}",
                result.err()
            );
        }
    }
}

#[test]
fn decoded_lengths_must_match_the_declared_length_exactly() {
    let payload: Vec<u8> = text(41, 6000);
    let stream: Vec<u8> = lz_stream(Codec::Leviathan, 0, LzStyle::default(), &payload);
    for wrong in [
        0usize,
        1,
        payload.len() - 1,
        payload.len() + 1,
        payload.len() * 2,
    ] {
        let (result, _) = decoded(&stream, wrong);
        assert!(result.is_err(), "declared length {wrong} accepted");
    }
}
