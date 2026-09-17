use std::collections::BTreeMap;
use std::collections::BTreeSet;

use disrobe_bytes::{LebError, read_uleb128_at};
use serde::Serialize;
use wasmparser::{BlockType, Operator, Parser, Payload};

use crate::error::{Error, Result};
use crate::op_names::operator_mnemonic;
use crate::signature::{FunctionSig, extract_signatures};

pub const NGRAM_WINDOW: usize = 3;
pub const MINHASH_WIDTH: usize = 128;
pub const DEFAULT_FUZZY_THRESHOLD: f64 = 0.66;
pub const DEFAULT_MIN_FUZZY_OPS: usize = 6;

const MASK_MARKER: u8 = b'#';
const MAX_BODY_OPS: usize = 2_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MatchTier {
    Exact,
    Fuzzy,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionMatch {
    pub defined_index: u32,
    pub label: String,
    pub confidence: f64,
    pub tier: MatchTier,
    pub ambiguity: usize,
}

#[derive(Debug, Clone)]
pub struct FunctionFingerprint {
    pub defined_index: u32,
    pub exact_hash: [u8; 32],
    pub minhash: [u64; MINHASH_WIDTH],
    pub shingle_count: usize,
    pub opcode_len: usize,
}

impl FunctionFingerprint {
    #[must_use]
    pub fn exact_hash_hex(&self) -> String {
        let mut out: String = String::with_capacity(64);
        for byte in &self.exact_hash {
            out.push(nibble(byte >> 4));
            out.push(nibble(byte & 0x0f));
        }
        out
    }
}

const fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MatchConfig {
    pub fuzzy_threshold: f64,
    pub min_fuzzy_ops: usize,
}

impl Default for MatchConfig {
    fn default() -> Self {
        Self {
            fuzzy_threshold: DEFAULT_FUZZY_THRESHOLD,
            min_fuzzy_ops: DEFAULT_MIN_FUZZY_OPS,
        }
    }
}

#[derive(Debug, Clone)]
struct CorpusEntry {
    label: String,
    minhash: [u64; MINHASH_WIDTH],
    shingle_count: usize,
    opcode_len: usize,
}

#[derive(Debug, Clone, Default)]
pub struct FingerprintDb {
    exact: BTreeMap<[u8; 32], BTreeSet<String>>,
    entries: Vec<CorpusEntry>,
}

impl FingerprintDb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn labels(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .map(|entry: &CorpusEntry| entry.label.clone())
            .collect()
    }

    pub fn insert(&mut self, label: &str, fingerprint: &FunctionFingerprint) {
        self.exact
            .entry(fingerprint.exact_hash)
            .or_default()
            .insert(label.to_owned());
        self.entries.push(CorpusEntry {
            label: label.to_owned(),
            minhash: fingerprint.minhash,
            shingle_count: fingerprint.shingle_count,
            opcode_len: fingerprint.opcode_len,
        });
    }

    pub fn add_labeled_module(&mut self, bytes: &[u8]) -> Result<usize> {
        let sigs: crate::signature::ModuleSignatures = extract_signatures(bytes)?;
        let fingerprints: Vec<FunctionFingerprint> = fingerprint_module(bytes)?;
        let defined: &[FunctionSig] = sigs.defined();
        let mut added: usize = 0;
        for fingerprint in &fingerprints {
            let Some(sig): Option<&FunctionSig> = defined.get(fingerprint.defined_index as usize)
            else {
                continue;
            };
            let Some(label): Option<String> = corpus_label(sig) else {
                continue;
            };
            self.insert(&label, fingerprint);
            added += 1;
        }
        Ok(added)
    }

    #[must_use]
    pub fn match_fingerprint(
        &self,
        fingerprint: &FunctionFingerprint,
        config: &MatchConfig,
    ) -> Option<FunctionMatch> {
        if let Some(labels) = self.exact.get(&fingerprint.exact_hash) {
            if let Some(label) = labels.iter().next() {
                let ambiguity: usize = labels.len();
                return Some(FunctionMatch {
                    defined_index: fingerprint.defined_index,
                    label: label.clone(),
                    confidence: 1.0 / ambiguity as f64,
                    tier: MatchTier::Exact,
                    ambiguity,
                });
            }
        }
        self.fuzzy_match(fingerprint, config)
    }

    fn fuzzy_match(
        &self,
        fingerprint: &FunctionFingerprint,
        config: &MatchConfig,
    ) -> Option<FunctionMatch> {
        if fingerprint.shingle_count == 0 || fingerprint.opcode_len < config.min_fuzzy_ops {
            return None;
        }
        let mut best_label: Option<&str> = None;
        let mut best_slots: usize = 0;
        let mut best_count: usize = 0;
        for entry in &self.entries {
            if entry.shingle_count == 0 || entry.opcode_len < config.min_fuzzy_ops {
                continue;
            }
            let slots: usize = matching_slots(&fingerprint.minhash, &entry.minhash);
            if best_label.is_none() || slots > best_slots {
                best_slots = slots;
                best_label = Some(entry.label.as_str());
                best_count = 1;
            } else if slots == best_slots {
                best_count += 1;
                if let Some(current) = best_label {
                    if entry.label.as_str() < current {
                        best_label = Some(entry.label.as_str());
                    }
                }
            }
        }
        let label: &str = best_label?;
        let score: f64 = best_slots as f64 / MINHASH_WIDTH as f64;
        if score < config.fuzzy_threshold {
            return None;
        }
        Some(FunctionMatch {
            defined_index: fingerprint.defined_index,
            label: label.to_owned(),
            confidence: score,
            tier: MatchTier::Fuzzy,
            ambiguity: best_count,
        })
    }

    pub fn match_module(
        &self,
        bytes: &[u8],
        config: &MatchConfig,
    ) -> Result<Vec<Option<FunctionMatch>>> {
        let fingerprints: Vec<FunctionFingerprint> = fingerprint_module(bytes)?;
        Ok(fingerprints
            .iter()
            .map(|fingerprint: &FunctionFingerprint| self.match_fingerprint(fingerprint, config))
            .collect())
    }
}

pub fn fingerprint_module(bytes: &[u8]) -> Result<Vec<FunctionFingerprint>> {
    let mut out: Vec<FunctionFingerprint> = Vec::new();
    let mut defined_index: u32 = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let fingerprint: FunctionFingerprint = fingerprint_body(defined_index, &body)?;
            out.push(fingerprint);
            defined_index = defined_index.saturating_add(1);
        }
    }
    Ok(out)
}

fn fingerprint_body(
    defined_index: u32,
    body: &wasmparser::FunctionBody<'_>,
) -> Result<FunctionFingerprint> {
    let reader: wasmparser::OperatorsReader<'_> = body
        .get_operators_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;
    let mut normalized: Vec<u8> = Vec::new();
    let mut tokens: Vec<u64> = Vec::new();
    let mut scratch: String = String::new();
    for op_result in reader {
        if tokens.len() >= MAX_BODY_OPS {
            break;
        }
        let op: Operator<'_> = op_result.map_err(|e| Error::Parse(e.to_string()))?;
        normalize_operator(&op, &mut normalized, &mut scratch);
        tokens.push(opcode_token(&op));
    }
    let exact_hash: [u8; 32] = *blake3::hash(&normalized).as_bytes();
    let (minhash, shingle_count): ([u64; MINHASH_WIDTH], usize) = minhash_signature(&tokens);
    Ok(FunctionFingerprint {
        defined_index,
        exact_hash,
        minhash,
        shingle_count,
        opcode_len: tokens.len(),
    })
}

fn normalize_operator(op: &Operator<'_>, out: &mut Vec<u8>, scratch: &mut String) {
    match op {
        Operator::Call { .. }
        | Operator::ReturnCall { .. }
        | Operator::RefFunc { .. }
        | Operator::CallIndirect { .. }
        | Operator::ReturnCallIndirect { .. }
        | Operator::CallRef { .. }
        | Operator::ReturnCallRef { .. }
        | Operator::GlobalGet { .. }
        | Operator::GlobalSet { .. }
        | Operator::MemoryInit { .. }
        | Operator::DataDrop { .. }
        | Operator::TableInit { .. }
        | Operator::ElemDrop { .. }
        | Operator::TableGet { .. }
        | Operator::TableSet { .. }
        | Operator::TableGrow { .. }
        | Operator::TableSize { .. }
        | Operator::TableFill { .. }
        | Operator::TableCopy { .. } => {
            out.extend_from_slice(operator_mnemonic(op).as_bytes());
            out.push(MASK_MARKER);
        }
        Operator::Block { blockty } | Operator::Loop { blockty } | Operator::If { blockty } => {
            out.extend_from_slice(operator_mnemonic(op).as_bytes());
            append_blockty(*blockty, out);
        }
        other => {
            scratch.clear();
            crate::push_string_fmt(scratch, format_args!("{other:?}"));
            out.extend_from_slice(scratch.as_bytes());
        }
    }
    out.push(b'\n');
}

fn append_blockty(blockty: BlockType, out: &mut Vec<u8>) {
    match blockty {
        BlockType::Empty => out.push(b'0'),
        BlockType::Type(valtype) => {
            out.push(b'v');
            match valtype {
                wasmparser::ValType::I32 => out.push(b'i'),
                wasmparser::ValType::I64 => out.push(b'I'),
                wasmparser::ValType::F32 => out.push(b'f'),
                wasmparser::ValType::F64 => out.push(b'F'),
                wasmparser::ValType::V128 => out.push(b'q'),
                wasmparser::ValType::Ref(_) => out.push(b'r'),
            }
        }
        BlockType::FuncType(_) => out.push(MASK_MARKER),
    }
}

fn opcode_token(op: &Operator<'_>) -> u64 {
    fnv1a64(operator_mnemonic(op).as_bytes())
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

const fn splitmix64(value: u64) -> u64 {
    let mut z: u64 = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn shingle_set(tokens: &[u64]) -> BTreeSet<u64> {
    let mut shingles: BTreeSet<u64> = BTreeSet::new();
    if tokens.is_empty() {
        return shingles;
    }
    let window: usize = NGRAM_WINDOW.min(tokens.len());
    for start in 0..=tokens.len() - window {
        let mut acc: u64 = 0xff51_afd7_ed55_8ccd;
        for token in &tokens[start..start + window] {
            acc = splitmix64(acc.wrapping_mul(0x0000_0100_0000_01b3) ^ *token);
        }
        shingles.insert(acc);
    }
    shingles
}

fn minhash_signature(tokens: &[u64]) -> ([u64; MINHASH_WIDTH], usize) {
    let shingles: BTreeSet<u64> = shingle_set(tokens);
    let mut signature: [u64; MINHASH_WIDTH] = [u64::MAX; MINHASH_WIDTH];
    for shingle in &shingles {
        for (slot, value) in signature.iter_mut().enumerate() {
            let seed: u64 = (slot as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let hashed: u64 = splitmix64(shingle.wrapping_add(seed));
            if hashed < *value {
                *value = hashed;
            }
        }
    }
    (signature, shingles.len())
}

fn matching_slots(left: &[u64; MINHASH_WIDTH], right: &[u64; MINHASH_WIDTH]) -> usize {
    let mut equal: usize = 0;
    for (a, b) in left.iter().zip(right.iter()) {
        if a == b {
            equal += 1;
        }
    }
    equal
}

#[must_use]
pub fn canonical_label(raw: &str) -> String {
    if let Some(name) = demangle_rust_legacy(raw) {
        return name;
    }
    if let Some(name) = crate::demangle_symbol(raw) {
        return name;
    }
    raw.to_owned()
}

fn demangle_rust_legacy(raw: &str) -> Option<String> {
    let inner: &str = raw.strip_prefix("_ZN")?.strip_suffix('E')?;
    let bytes: &[u8] = inner.as_bytes();
    let mut components: Vec<&str> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let start: usize = cursor;
        let mut len: usize = 0;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            len = len
                .checked_mul(10)?
                .checked_add(usize::from(bytes[cursor] - b'0'))?;
            cursor += 1;
        }
        if cursor == start {
            return None;
        }
        let end: usize = cursor.checked_add(len)?;
        let component: &str = inner.get(cursor..end)?;
        components.push(component);
        cursor = end;
    }
    if let Some(last) = components.last() {
        if last.len() >= 2
            && last.starts_with('h')
            && last[1..].bytes().all(|b: u8| b.is_ascii_hexdigit())
        {
            components.pop();
        }
    }
    components.last().map(|name: &&str| (*name).to_owned())
}

fn corpus_label(sig: &FunctionSig) -> Option<String> {
    if is_placeholder_name(&sig.name) {
        return None;
    }
    Some(canonical_label(&sig.name))
}

fn is_placeholder_name(name: &str) -> bool {
    for prefix in ["func_", "import_"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return !rest.is_empty() && rest.bytes().all(|b: u8| b.is_ascii_digit());
        }
    }
    false
}

pub fn strip_name_section(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return Err(Error::Parse("not a wasm module".to_owned()));
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[0..8]);
    let mut cursor: usize = 8;
    while cursor < bytes.len() {
        let section_start: usize = cursor;
        let id: u8 = bytes[cursor];
        cursor += 1;
        let (payload_len, len_bytes): (u32, usize) = read_leb_u32(bytes, cursor)?;
        cursor += len_bytes;
        let payload_start: usize = cursor;
        let payload_end: usize = payload_start
            .checked_add(payload_len as usize)
            .ok_or_else(|| Error::Parse("section length overflow".to_owned()))?;
        if payload_end > bytes.len() {
            return Err(Error::Parse("truncated section".to_owned()));
        }
        let is_name_section: bool = id == 0 && section_is_named(&bytes[payload_start..payload_end]);
        if !is_name_section {
            out.extend_from_slice(&bytes[section_start..payload_end]);
        }
        cursor = payload_end;
    }
    Ok(out)
}

fn section_is_named(payload: &[u8]) -> bool {
    let Ok((name_len, len_bytes)): Result<(u32, usize)> = read_leb_u32(payload, 0) else {
        return false;
    };
    let name_start: usize = len_bytes;
    let Some(name_end): Option<usize> = name_start.checked_add(name_len as usize) else {
        return false;
    };
    payload.get(name_start..name_end) == Some(b"name")
}

fn read_leb_u32(bytes: &[u8], start: usize) -> Result<(u32, usize)> {
    if bytes
        .get(start..)
        .and_then(|remaining: &[u8]| remaining.get(..5))
        .is_some_and(|prefix: &[u8]| prefix.iter().all(|byte: &u8| byte & 0x80 != 0))
    {
        return Err(Error::Parse("leb128 too long".to_owned()));
    }
    let (value, consumed): (u64, usize) =
        read_uleb128_at(bytes, start).map_err(|error: LebError| match error {
            LebError::OutOfBounds(_) => Error::Parse("truncated leb128".to_owned()),
            LebError::Overflow { .. } => Error::Parse("leb128 overflow".to_owned()),
        })?;
    if consumed > 5 {
        return Err(Error::Parse("leb128 too long".to_owned()));
    }
    let result: u32 =
        u32::try_from(value).map_err(|_| Error::Parse("leb128 overflow".to_owned()))?;
    Ok((result, consumed))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const ARITH4: &[u8] = include_bytes!("../tests/fixtures/arith4.wasm");

    #[test]
    fn fingerprints_all_defined_bodies() {
        let fingerprints: Vec<FunctionFingerprint> = fingerprint_module(ARITH4).expect("fp");
        assert_eq!(fingerprints.len(), 5);
        for (index, fingerprint) in fingerprints.iter().enumerate() {
            assert_eq!(fingerprint.defined_index, index as u32);
            assert!(fingerprint.opcode_len > 0);
        }
    }

    #[test]
    fn section_leb_rejects_fifth_group_overflow() {
        let overflow: [u8; 5] = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
        assert!(read_leb_u32(&overflow, 0).is_err());
    }

    #[test]
    fn section_leb_preserves_the_five_continuation_error() {
        let error: Error = read_leb_u32(&[0x80; 5], 0).expect_err("five groups are too long");
        assert!(matches!(error, Error::Parse(message) if message == "leb128 too long"));
    }

    #[test]
    fn exact_hash_is_stable_and_body_sensitive() {
        let first: Vec<FunctionFingerprint> = fingerprint_module(ARITH4).expect("fp");
        let second: Vec<FunctionFingerprint> = fingerprint_module(ARITH4).expect("fp");
        assert_eq!(first[0].exact_hash, second[0].exact_hash);
        assert_ne!(first[0].exact_hash, first[4].exact_hash);
        assert_eq!(first[0].exact_hash_hex().len(), 64);
    }

    #[test]
    fn canonical_label_recovers_rust_legacy_identifier() {
        assert_eq!(
            canonical_label("_ZN12corpus_alpha10fnv1a_hash17hf7a7941b844e3cabE"),
            "fnv1a_hash"
        );
        assert_eq!(
            canonical_label("_ZN11corpus_beta9clamp_i3217hf5319a538c049debE"),
            "clamp_i32"
        );
    }

    #[test]
    fn strip_name_section_removes_names_but_keeps_bodies() {
        let stripped: Vec<u8> = strip_name_section(ARITH4).expect("strip");
        let before: Vec<FunctionFingerprint> = fingerprint_module(ARITH4).expect("fp");
        let after: Vec<FunctionFingerprint> = fingerprint_module(&stripped).expect("fp");
        assert_eq!(before.len(), after.len());
        for (a, b) in before.iter().zip(after.iter()) {
            assert_eq!(a.exact_hash, b.exact_hash);
        }
    }

    #[test]
    fn empty_shingle_set_does_not_fuzzy_match() {
        let signature: ([u64; MINHASH_WIDTH], usize) = minhash_signature(&[]);
        assert_eq!(signature.1, 0);
        assert!(signature.0.iter().all(|value: &u64| *value == u64::MAX));
    }

    #[test]
    fn identical_signatures_match_every_slot() {
        let tokens: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let (sig, count): ([u64; MINHASH_WIDTH], usize) = minhash_signature(&tokens);
        assert!(count > 0);
        assert_eq!(matching_slots(&sig, &sig), MINHASH_WIDTH);
    }
}
