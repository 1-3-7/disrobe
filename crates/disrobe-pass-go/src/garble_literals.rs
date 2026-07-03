#![allow(clippy::redundant_pub_crate)]

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SimpleOp {
    Xor,
    Add,
    Sub,
}

impl SimpleOp {
    const ALL: [Self; 3] = [Self::Xor, Self::Add, Self::Sub];

    #[cfg(test)]
    #[inline]
    const fn forward(self, plain: u8, key: u8) -> u8 {
        match self {
            Self::Xor => plain ^ key,
            Self::Add => plain.wrapping_add(key),
            Self::Sub => plain.wrapping_sub(key),
        }
    }

    #[inline]
    const fn invert(self, obfuscated: u8, key: u8) -> u8 {
        match self {
            Self::Xor => obfuscated ^ key,
            Self::Add => obfuscated.wrapping_sub(key),
            Self::Sub => obfuscated.wrapping_add(key),
        }
    }
}

const MIN_PLAINTEXT: usize = 8;
const MIN_BLOB: usize = MIN_PLAINTEXT + MIN_STRING_JUNK_BYTES;
const MAX_BLOB: usize = 256;
const MIN_STRING_JUNK_BYTES: usize = 2;
const MAX_STRING_JUNK_BYTES: usize = 8;
const PARTNER_WINDOW: usize = 64;
const MAX_PERTURBED_BYTES: usize = 12;
const MIN_CLEAN_RUN: usize = 16;
const MIN_CLEAN_RUN_WITH_TOKENS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SimpleRecovery {
    pub(crate) plaintext: String,
    pub(crate) op: SimpleOp,
    pub(crate) data_offset: usize,
    pub(crate) key_offset: usize,
    pub(crate) perturbed_bytes: usize,
}

#[inline]
const fn is_string_byte(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r')
}

const PLAINTEXT_TOKENS: &[&str] = &[
    "error",
    "failed",
    "invalid",
    "cannot",
    "unknown",
    "expected",
    "missing",
    "request",
    "response",
    "connection",
    "timeout",
    "success",
    "warning",
    "config",
    "server",
    "client",
    "address",
    "message",
    "value",
    "string",
    "buffer",
    "format",
    "header",
    "version",
    "token",
    "secret",
    "password",
    "https",
    "http",
    "json",
    "true",
    "false",
    "null",
    "panic",
    "context",
    "package",
    "function",
    "object",
    "default",
    "enable",
    "disable",
    "create",
    "delete",
    "update",
    "the ",
    " and ",
    " for ",
    " with ",
    "://",
    ".com",
    ".go",
    ".exe",
    ".dll",
    "/usr/",
    "c:\\",
    "user",
    "file",
    "data",
    "key",
    "name",
    "type",
    "code",
    "host",
    "port",
    "path",
    "command",
    "exec",
    "shell",
    "registry",
    "process",
    "memory",
    "encrypt",
    "decrypt",
    "payload",
    "beacon",
];

fn token_hits(lowered: &str) -> usize {
    PLAINTEXT_TOKENS
        .iter()
        .filter(|tok: &&&str| lowered.contains(*tok))
        .count()
}

fn english_word_shape(s: &str) -> bool {
    let len: usize = s.len();
    let letters: usize = s.bytes().filter(u8::is_ascii_alphabetic).count();
    let placeholders: usize = s.bytes().filter(|b: &u8| *b == PLACEHOLDER).count();
    let symbols: usize = s
        .bytes()
        .filter(|b: &u8| {
            !b.is_ascii_alphanumeric()
                && !matches!(
                    *b,
                    b' ' | b'/' | b'_' | b'.' | b'-' | b':' | b'\\' | PLACEHOLDER
                )
        })
        .count();
    if letters * 3 < len * 2 || symbols * 6 > len || placeholders * 8 > len {
        return false;
    }
    let vowels: usize = s
        .bytes()
        .filter(|b: &u8| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u'))
        .count();
    if vowels * 5 < letters || vowels * 2 > letters * 3 {
        return false;
    }
    let case_flips: usize = s
        .as_bytes()
        .windows(2)
        .filter(|w: &&[u8]| {
            w[0].is_ascii_alphabetic()
                && w[1].is_ascii_alphabetic()
                && w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase()
        })
        .count();
    case_flips * 4 < len
}

const MAX_PLACEHOLDER_RATIO_PCT: usize = 12;

const GO_TYPE_DESCRIPTOR_MARKERS: &[&str] = &[
    "func(",
    "interface {",
    "go.shape",
    "struct {",
    "runtime.",
    "reflect.",
    "strconv.",
    "compareandswap",
    "nameoff",
    ".rtype",
    ".gobuf",
    "beexported",
    "map[",
    "chan ",
    "[]byte",
    "<-chan",
    " bool)",
    " string)",
    "0x",
];

fn looks_like_go_type_descriptor(lowered: &str) -> bool {
    GO_TYPE_DESCRIPTOR_MARKERS
        .iter()
        .any(|m: &&str| lowered.contains(*m))
}

fn plausible_plaintext(s: &str) -> bool {
    if s.len() < MIN_CLEAN_RUN_WITH_TOKENS {
        return false;
    }
    let placeholders: usize = s.bytes().filter(|b: &u8| *b == PLACEHOLDER).count();
    if placeholders * 100 > s.len() * MAX_PLACEHOLDER_RATIO_PCT {
        return false;
    }
    let lowered: String = s.to_ascii_lowercase();
    if looks_like_go_type_descriptor(&lowered) {
        return false;
    }
    let hits: usize = token_hits(&lowered);
    let strong_marker: bool = ["://", "/usr/", "c:\\", ".com", ".exe", ".dll"]
        .iter()
        .any(|m: &&str| lowered.contains(*m));
    if (hits >= 2 || strong_marker) && english_word_shape(s) {
        return true;
    }
    s.len() >= MIN_CLEAN_RUN && english_word_shape(s) && hits >= 1 && s.contains(' ')
}

const MAX_SIMPLE_RECOVERIES: usize = 1024;

struct PrintablePrefix {
    sums: Vec<u64>,
}

impl PrintablePrefix {
    fn build(buf: &[u8]) -> Self {
        let mut sums: Vec<u64> = Vec::with_capacity(buf.len() + 1);
        let mut acc: u64 = 0;
        sums.push(0);
        for &b in buf {
            acc += u64::from(is_string_byte(b));
            sums.push(acc);
        }
        Self { sums }
    }

    #[inline]
    fn printable_in(&self, start: usize, end: usize) -> usize {
        (self.sums[end] - self.sums[start]) as usize
    }

    #[inline]
    fn may_hold_ciphertext(&self, start: usize, end: usize) -> bool {
        self.printable_in(start, end) * 10 < (end - start) * 9
    }
}

const MAX_BRIDGE_GAP: usize = 1;
const PLACEHOLDER: u8 = b'?';

struct DecodedWindow {
    text: String,
    perturbed: usize,
}

fn extract_string_window(decoded: &[u8]) -> Option<DecodedWindow> {
    let first: usize = decoded.iter().position(|&b: &u8| is_string_byte(b))?;
    let mut chars: Vec<u8> = Vec::with_capacity(decoded.len() - first);
    let mut perturbed: usize = 0;
    let mut i: usize = first;
    while i < decoded.len() {
        if is_string_byte(decoded[i]) {
            chars.push(decoded[i]);
            i += 1;
            continue;
        }
        let gap_start: usize = i;
        while i < decoded.len() && !is_string_byte(decoded[i]) {
            i += 1;
        }
        let gap: usize = i - gap_start;
        let has_more_string: bool = i < decoded.len();
        if gap <= MAX_BRIDGE_GAP && has_more_string {
            chars.extend(std::iter::repeat_n(PLACEHOLDER, gap));
            perturbed += gap;
        } else {
            break;
        }
    }
    let text: String = String::from_utf8(chars).ok()?;
    Some(DecodedWindow { text, perturbed })
}

const PRECHECK_LEN: usize = MIN_CLEAN_RUN;
const PRECHECK_MIN_STRING_PCT: usize = 60;

#[inline]
fn precheck_pair(rodata: &[u8], data_start: usize, key_start: usize, op: SimpleOp) -> bool {
    let span: usize = PRECHECK_LEN
        .min(rodata.len() - data_start)
        .min(rodata.len() - key_start);
    if span < MIN_BLOB {
        return false;
    }
    let mut printable: usize = 0;
    for offset in 0..span {
        let byte: u8 = op.invert(rodata[data_start + offset], rodata[key_start + offset]);
        printable += usize::from(is_string_byte(byte));
    }
    printable * 100 >= span * PRECHECK_MIN_STRING_PCT
}

fn grow_clean_pair(
    rodata: &[u8],
    data_start: usize,
    key_start: usize,
    op: SimpleOp,
    decoded: &mut Vec<u8>,
) -> Option<SimpleRecovery> {
    let span: usize = (rodata.len() - data_start)
        .min(rodata.len() - key_start)
        .min(MAX_BLOB);
    if span < MIN_BLOB {
        return None;
    }
    decoded.clear();
    let mut consecutive_bad: usize = 0;
    for offset in 0..span {
        let byte: u8 = op.invert(rodata[data_start + offset], rodata[key_start + offset]);
        if is_string_byte(byte) {
            consecutive_bad = 0;
        } else {
            consecutive_bad += 1;
            if consecutive_bad > MAX_STRING_JUNK_BYTES {
                let keep: usize = decoded.len().saturating_sub(consecutive_bad - 1);
                decoded.truncate(keep);
                break;
            }
        }
        decoded.push(byte);
    }
    let window: DecodedWindow = extract_string_window(decoded)?;
    if window.text.len() < MIN_CLEAN_RUN || window.perturbed > MAX_PERTURBED_BYTES {
        return None;
    }
    if !plausible_plaintext(&window.text) {
        return None;
    }
    Some(SimpleRecovery {
        plaintext: window.text,
        op,
        data_offset: data_start,
        key_offset: key_start,
        perturbed_bytes: window.perturbed,
    })
}

const WORK_BUDGET: u64 = 48_000_000;

fn collapse_shifted_substrings(mut recs: Vec<SimpleRecovery>) -> Vec<SimpleRecovery> {
    recs.sort_by(|a: &SimpleRecovery, b: &SimpleRecovery| {
        b.plaintext
            .len()
            .cmp(&a.plaintext.len())
            .then_with(|| a.plaintext.cmp(&b.plaintext))
    });
    let mut kept: Vec<SimpleRecovery> = Vec::with_capacity(recs.len());
    for rec in recs {
        let core: &str = rec.plaintext.trim_matches(PLACEHOLDER as char);
        let is_fragment: bool = kept.iter().any(|k: &SimpleRecovery| {
            k.plaintext.len() > rec.plaintext.len()
                && !core.is_empty()
                && k.plaintext.contains(core)
        });
        if !is_fragment {
            kept.push(rec);
        }
    }
    kept.sort_by(|a: &SimpleRecovery, b: &SimpleRecovery| a.plaintext.cmp(&b.plaintext));
    kept
}

const MAX_SIMPLE_SCAN_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn recover_simple_literals(rodata: &[u8]) -> Vec<SimpleRecovery> {
    let mut out: Vec<SimpleRecovery> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if rodata.len() < 2 * MIN_BLOB || rodata.len() > MAX_SIMPLE_SCAN_BYTES {
        return out;
    }
    let prefix: PrintablePrefix = PrintablePrefix::build(rodata);
    let max_data_start: usize = rodata.len() - 2 * MIN_BLOB;
    let mut budget: u64 = WORK_BUDGET;
    let mut scratch: Vec<u8> = Vec::with_capacity(MAX_BLOB);
    let mut data_start: usize = 0;
    while data_start <= max_data_start {
        let probe_end: usize = data_start + MIN_BLOB;
        if prefix.printable_in(data_start, probe_end) == MIN_BLOB {
            data_start += MIN_BLOB;
            continue;
        }
        if !prefix.may_hold_ciphertext(data_start, probe_end) {
            data_start += 1;
            continue;
        }
        let key_limit: usize =
            (data_start + MIN_BLOB + PARTNER_WINDOW).min(rodata.len() - MIN_BLOB);
        for key_start in (data_start + MIN_BLOB)..=key_limit {
            let key_probe_end: usize = key_start + MIN_BLOB;
            if !prefix.may_hold_ciphertext(key_start, key_probe_end) {
                continue;
            }
            for op in SimpleOp::ALL {
                budget = budget.saturating_sub(1);
                if budget == 0 {
                    return collapse_shifted_substrings(out);
                }
                if !precheck_pair(rodata, data_start, key_start, op) {
                    continue;
                }
                if let Some(rec) = grow_clean_pair(rodata, data_start, key_start, op, &mut scratch)
                    && seen.insert(rec.plaintext.clone())
                {
                    out.push(rec);
                    if out.len() >= MAX_SIMPLE_RECOVERIES {
                        return collapse_shifted_substrings(out);
                    }
                }
            }
        }
        data_start += 1;
    }
    collapse_shifted_substrings(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_simple_blob(
        plaintext: &[u8],
        op: SimpleOp,
        key_stream: &[u8],
        junk_lead: &[u8],
        junk_tail: &[u8],
        ext_key_mutations: &[(usize, u8)],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut plain_with_junk: Vec<u8> =
            Vec::with_capacity(junk_lead.len() + plaintext.len() + junk_tail.len());
        plain_with_junk.extend_from_slice(junk_lead);
        plain_with_junk.extend_from_slice(plaintext);
        plain_with_junk.extend_from_slice(junk_tail);
        let len: usize = plain_with_junk.len();
        assert!(key_stream.len() >= len, "key stream too short for fixture");
        let key: Vec<u8> = key_stream[..len].to_vec();
        let mut data: Vec<u8> = Vec::with_capacity(len);
        for i in 0..len {
            data.push(op.forward(plain_with_junk[i], key[i]));
        }
        let mut data_blob: Vec<u8> = data;
        let key_blob: Vec<u8> = key;
        for &(idx, delta) in ext_key_mutations {
            let idx: usize = idx;
            let delta: u8 = delta;
            if idx < data_blob.len() {
                data_blob[idx] = data_blob[idx].wrapping_add(delta);
            }
        }
        (data_blob, key_blob)
    }

    fn embed_fixture(data_blob: &[u8], key_blob: &[u8], gap: usize) -> Vec<u8> {
        let mut rodata: Vec<u8> = Vec::new();
        rodata.extend_from_slice(b"\x00\x01\x02\x03 some go.string header padding \x00\x00");
        rodata.extend_from_slice(data_blob);
        rodata.extend(std::iter::repeat_n(0u8, gap));
        rodata.extend_from_slice(key_blob);
        rodata.extend_from_slice(b"\x00\x00trailing rodata pool bytes\x00");
        rodata
    }

    fn pseudo_key(seed: u64, len: usize) -> Vec<u8> {
        let mut state: u64 = seed;
        let mut key: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            key.push((state >> 33) as u8);
        }
        key
    }

    #[test]
    fn forward_then_invert_round_trips_every_op() {
        for op in SimpleOp::ALL {
            for plain in 0u16..=255 {
                for key in 0u16..=255 {
                    let p: u8 = plain as u8;
                    let k: u8 = key as u8;
                    assert_eq!(op.invert(op.forward(p, k), k), p, "{op:?} must round-trip");
                }
            }
        }
    }

    #[test]
    fn recovers_clean_simple_literal_xor() {
        let plaintext: &[u8] = b"failed to connect to the update server: invalid token";
        let key_stream: Vec<u8> = pseudo_key(0xdead_beef, 80);
        let (data_blob, key_blob): (Vec<u8>, Vec<u8>) = build_simple_blob(
            plaintext,
            SimpleOp::Xor,
            &key_stream,
            b"\x91\x02",
            b"\xff\xfe",
            &[],
        );
        let fixture: Vec<u8> = embed_fixture(&data_blob, &key_blob, 3);
        let recovered: Vec<SimpleRecovery> = recover_simple_literals(&fixture);
        let hit: &SimpleRecovery = recovered
            .iter()
            .find(|r: &&SimpleRecovery| {
                r.plaintext == "failed to connect to the update server: invalid token"
            })
            .expect("known XOR simple literal must be recovered exactly");
        assert_eq!(hit.op, SimpleOp::Xor);
        assert_eq!(hit.perturbed_bytes, 0);
        assert!(
            hit.key_offset > hit.data_offset,
            "key blob follows the data blob in the rodata pool, got {hit:?}"
        );
    }

    #[test]
    fn recovers_simple_literal_under_external_key_perturbation() {
        let plaintext: &[u8] = b"https://malware.example.invalid/c2/beacon";
        let key_stream: Vec<u8> = pseudo_key(0x0123_4567_89ab_cdef, 64);
        let (data_blob, key_blob): (Vec<u8>, Vec<u8>) = build_simple_blob(
            plaintext,
            SimpleOp::Add,
            &key_stream,
            b"\x80\x81\x82",
            b"\x83\x84",
            &[(23, 0x40), (31, 0x40)],
        );
        let fixture: Vec<u8> = embed_fixture(&data_blob, &key_blob, 8);
        let recovered: Vec<SimpleRecovery> = recover_simple_literals(&fixture);
        let rec: &SimpleRecovery = recovered
            .iter()
            .find(|r: &&SimpleRecovery| r.plaintext.starts_with("https://malware"))
            .expect("perturbed simple literal must still surface its bridged plaintext");
        assert!(
            rec.plaintext.contains("malware") && rec.plaintext.contains("beacon"),
            "bridged recovery must span the corruptions and hold both endpoints, got {:?}",
            rec.plaintext
        );
        assert_eq!(
            rec.plaintext.matches('?').count(),
            rec.perturbed_bytes,
            "each bridged corruption must surface as a single placeholder"
        );
        assert!(
            rec.perturbed_bytes >= 1 && rec.perturbed_bytes <= 2,
            "two external-key mutations land in the interior, got {}",
            rec.perturbed_bytes
        );
    }

    #[test]
    fn recovers_simple_literal_sub_op() {
        let plaintext: &[u8] = b"the quick brown fox jumps over the lazy dog";
        let key_stream: Vec<u8> = pseudo_key(0xfeed_face, 80);
        let (data_blob, key_blob): (Vec<u8>, Vec<u8>) = build_simple_blob(
            plaintext,
            SimpleOp::Sub,
            &key_stream,
            b"\x80\x90",
            b"\xa0\xb0",
            &[],
        );
        let fixture: Vec<u8> = embed_fixture(&data_blob, &key_blob, 4);
        let recovered: Vec<SimpleRecovery> = recover_simple_literals(&fixture);
        assert!(
            recovered
                .iter()
                .any(|r: &SimpleRecovery| r.plaintext
                    == "the quick brown fox jumps over the lazy dog"),
            "SUB-op simple literal must be recovered exactly, got {recovered:?}"
        );
    }

    #[test]
    fn quiet_on_random_rodata() {
        let noise: Vec<u8> = pseudo_key(0x9999_8888_7777_6666, 4096);
        let recovered: Vec<SimpleRecovery> = recover_simple_literals(&noise);
        assert!(
            recovered.len() <= 1,
            "pure noise must not manufacture phantom literals, got {}: {recovered:?}",
            recovered.len()
        );
    }

    #[test]
    fn quiet_on_plain_ascii_rodata() {
        let mut rodata: Vec<u8> = Vec::new();
        for _ in 0..64 {
            rodata.extend_from_slice(b"plain ascii rodata string with no obfuscation at all\x00");
        }
        let recovered: Vec<SimpleRecovery> = recover_simple_literals(&rodata);
        assert!(
            recovered.is_empty(),
            "plain ascii rodata is not obfuscated and must yield no simple-scheme pairs, got {recovered:?}"
        );
    }

    #[test]
    fn oversized_rodata_is_size_gated_not_oom() {
        let rodata: Vec<u8> = vec![0x80u8; MAX_SIMPLE_SCAN_BYTES + 1];
        let start: std::time::Instant = std::time::Instant::now();
        let recovered: Vec<SimpleRecovery> = recover_simple_literals(&rodata);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "oversized rodata must be rejected before the prefix-sum allocation"
        );
        assert!(
            recovered.is_empty(),
            "rodata above the scan ceiling must be skipped, never scanned"
        );
    }

    #[test]
    fn prefix_sum_accumulator_does_not_overflow_at_ceiling() {
        let rodata: Vec<u8> = vec![0x41u8; MAX_SIMPLE_SCAN_BYTES];
        let start: std::time::Instant = std::time::Instant::now();
        let _recovered: Vec<SimpleRecovery> = recover_simple_literals(&rodata);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "a fully-printable section at the ceiling must complete within the work budget"
        );
    }
}
