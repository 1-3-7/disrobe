#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::v8::{
    BytenodeCacheBody, HeaderLayout, NodeVersion, V8_HEADER_SIZE_V11, V8_HEADER_SIZE_V12,
    parse_bytenode_full,
};
use sha2::{Digest, Sha256};

struct RealJsc {
    dir: &'static str,
    file: &'static str,
    node: NodeVersion,
    layout: HeaderLayout,
    header_size: usize,
}

const REAL_JSC: [RealJsc; 4] = [
    RealJsc {
        dir: "node-18",
        file: "hello-18.jsc",
        node: NodeVersion::Node18,
        layout: HeaderLayout::V11,
        header_size: 24usize,
    },
    RealJsc {
        dir: "node-20",
        file: "hello-20.jsc",
        node: NodeVersion::Node20,
        layout: HeaderLayout::V11,
        header_size: 24usize,
    },
    RealJsc {
        dir: "node-22",
        file: "hello-22.jsc",
        node: NodeVersion::Node22,
        layout: HeaderLayout::V12,
        header_size: 32usize,
    },
    RealJsc {
        dir: "node-24",
        file: "hello-24.jsc",
        node: NodeVersion::Node24,
        layout: HeaderLayout::V12,
        header_size: 32usize,
    },
];

fn corpus_dir(dir: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap_or(manifest)
        .join("corpus/v8")
        .join(dir)
}

fn read_tracked(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error: std::io::Error| {
        panic!("tracked V8 fixture {} is required: {error}", path.display())
    })
}

fn recorded_sha256_and_size(fixture: &RealJsc) -> (String, usize) {
    let build_path: PathBuf = corpus_dir(fixture.dir).join("BUILD.md");
    let build: String = String::from_utf8(read_tracked(&build_path)).expect("BUILD.md is UTF-8");
    let prefix: String = format!("| {} |", fixture.file);
    let row: &str = build
        .lines()
        .find(|line: &&str| line.starts_with(&prefix))
        .unwrap_or_else(|| {
            panic!(
                "{} records a hash row for {}",
                build_path.display(),
                fixture.file
            )
        });
    let cells: Vec<&str> = row
        .split('|')
        .map(str::trim)
        .filter(|cell: &&str| !cell.is_empty())
        .collect();
    let [_name, sha, bytes] = cells.as_slice() else {
        panic!("hash row must hold file, sha256 and bytes: {row}");
    };
    let size: usize = bytes
        .parse::<usize>()
        .unwrap_or_else(|error| panic!("recorded byte count `{bytes}` must parse: {error}"));
    ((*sha).to_owned(), size)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut hex: String = String::with_capacity(64usize);
    for byte in digest {
        hex.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[test]
fn real_fixtures_split_header_and_payload_where_v8_wrote_them() {
    for fixture in &REAL_JSC {
        let bytes: Vec<u8> = read_tracked(&corpus_dir(fixture.dir).join(fixture.file));
        let (recorded_sha, recorded_size): (String, usize) = recorded_sha256_and_size(fixture);
        assert_eq!(
            sha256_hex(&bytes),
            recorded_sha,
            "{} must be the cache data BUILD.md records",
            fixture.file
        );
        assert_eq!(bytes.len(), recorded_size, "{} size", fixture.file);
        let body: BytenodeCacheBody = parse_bytenode_full(&bytes)
            .unwrap_or_else(|error| panic!("{} must parse: {error}", fixture.file));
        assert_eq!(
            body.header.version_hash.node, fixture.node,
            "{}",
            fixture.file
        );
        assert_eq!(body.header.layout, fixture.layout, "{}", fixture.file);
        assert_eq!(
            body.payload_offset, fixture.header_size,
            "{} payload starts after V8's SerializedCodeData header",
            fixture.file
        );
        assert_eq!(
            body.payload_offset + body.payload_length,
            recorded_size,
            "{} payload runs to the end of the cache data V8 wrote",
            fixture.file
        );
        assert_eq!(
            body.payload,
            bytes[fixture.header_size..],
            "{}",
            fixture.file
        );
    }
    assert_eq!(V8_HEADER_SIZE_V11, REAL_JSC[0].header_size);
    assert_eq!(V8_HEADER_SIZE_V12, REAL_JSC[3].header_size);
}

#[test]
fn declared_payload_length_past_input_is_rejected_not_truncated() {
    for fixture in &REAL_JSC {
        let bytes: Vec<u8> = read_tracked(&corpus_dir(fixture.dir).join(fixture.file));
        let length_at: usize = fixture.layout.payload_length_offset();
        let past_input: u32 = u32::try_from(bytes.len()).expect("fixture fits u32");
        let mut overlong: Vec<u8> = bytes.clone();
        overlong[length_at..length_at + 4usize].copy_from_slice(&past_input.to_le_bytes());
        let truncated: &[u8] = &bytes[..bytes.len() - 1usize];
        for (label, malformed) in [("overlong", overlong.as_slice()), ("truncated", truncated)] {
            let message: String = match parse_bytenode_full(malformed) {
                Ok(body) => panic!(
                    "{} {label} must be rejected, parsed {} payload bytes",
                    fixture.file, body.payload_length
                ),
                Err(error) => format!("{error}"),
            };
            assert!(
                message.contains("exceeds available input"),
                "{} {label} must fail on the declared length, got: {message}",
                fixture.file
            );
        }
    }
}
