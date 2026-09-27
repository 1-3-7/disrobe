#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const RECORDS_SCHEMA: &str = "disrobe.wasm.build-records/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSet {
    Corpus,
    Fixtures,
}

impl RecordSet {
    pub fn root(self) -> PathBuf {
        let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
        match self {
            Self::Corpus => manifest.join("../../corpus/wasm/obf"),
            Self::Fixtures => manifest.join("tests/fixtures"),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Corpus => "corpus/wasm/obf/records.toml",
            Self::Fixtures => "crates/disrobe-pass-wasm-deob/tests/fixtures/records.toml",
        }
    }

    fn cache(self) -> &'static OnceLock<Records> {
        static CORPUS: OnceLock<Records> = OnceLock::new();
        static FIXTURES: OnceLock<Records> = OnceLock::new();
        match self {
            Self::Corpus => &CORPUS,
            Self::Fixtures => &FIXTURES,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Records {
    pub schema: String,
    pub artifact: Vec<Recorded>,
}

#[derive(Debug, Deserialize)]
pub struct Recorded {
    pub path: String,
    pub sha256: String,
}

pub fn records(set: RecordSet) -> &'static Records {
    set.cache().get_or_init(|| {
        let path: PathBuf = set.root().join("records.toml");
        let text: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", set.label()));
        let parsed: Records = toml::from_str(&text)
            .unwrap_or_else(|error: toml::de::Error| panic!("parse {}: {error}", set.label()));
        assert_eq!(
            parsed.schema,
            RECORDS_SCHEMA,
            "{} declares an unknown schema",
            set.label()
        );
        parsed
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn assert_recorded(set: RecordSet, path: &str, bytes: &[u8]) {
    let Some(record): Option<&Recorded> = records(set)
        .artifact
        .iter()
        .find(|record: &&Recorded| record.path == path)
    else {
        panic!(
            "{path} has no build record in {}, so it must not run: a committed wasm module runs \
             only with a record of its source, toolchain, command and sha256, or a note that the \
             WAT was written by hand",
            set.label()
        );
    };
    let actual: String = sha256_hex(bytes);
    assert_eq!(
        actual,
        record.sha256,
        "{path} no longer matches its build record in {}, so it must not run until the record \
         names the build that produced these bytes",
        set.label()
    );
}

pub fn recorded_bytes(set: RecordSet, path: &str) -> Vec<u8> {
    let full: PathBuf = set.root().join(path);
    let bytes: Vec<u8> = std::fs::read(&full)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", full.display()));
    assert_recorded(set, path, &bytes);
    bytes
}

pub fn recorded_text(set: RecordSet, path: &str) -> String {
    String::from_utf8(recorded_bytes(set, path))
        .unwrap_or_else(|error: std::string::FromUtf8Error| panic!("{path} is not UTF-8: {error}"))
}

pub fn recorded_wat(set: RecordSet, path: &str) -> Vec<u8> {
    wat::parse_str(recorded_text(set, path))
        .unwrap_or_else(|error: wat::Error| panic!("assemble {path}: {error}"))
}
