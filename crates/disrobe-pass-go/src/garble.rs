use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::binary::GoImage;
use crate::symbols::{GoFunc, GoSymbols};

/// How much of the original program a garble-processed binary can honestly yield.
///
/// `Full` recovery requires the per-build HMAC seed: only then can renamed
/// package/symbol names be reversed. A seedless garble build (the common
/// `-trimpath` case) is an information-theoretic wall for names, so the best
/// achievable is `Partial` - pclntab-derived structure and decrypted literals,
/// with names unrecoverable. This pass never claims `Full` without a recoverable
/// seed, since it performs no name un-renaming of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GarbleQuality {
    None,
    Detected,
    Partial,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GarbleReport {
    pub quality: GarbleQuality,
    pub detection_score: u32,
    pub stdlib_fingerprints_present: usize,
    pub seed_hash: Option<String>,
    pub seed_recoverable: bool,
    pub name_recovery_wall: Option<String>,
    pub literal_recovery_limit: Option<String>,
    pub surviving_stdlib_names: BTreeSet<String>,
    pub recovered_strings: Vec<String>,
    pub literal_recovery: LiteralRecoveryStats,
}

/// Per-scheme counts of literals recovered by static byte-stream deobfuscation, so a
/// caller can see WHICH transform produced each result rather than a bare total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteralRecoveryStats {
    pub plain_ascii: usize,
    pub single_xor: usize,
    pub single_add: usize,
    pub single_sub: usize,
    pub repeating_xor: usize,
}

const SEEDLESS_WALL: &str = "garble name-hashing is keyed (HMAC-SHA256 over the build seed); with no seed embedded in the \
     binary, original package/symbol names are an information-theoretic wall and cannot be recovered. \
     pclntab-derived structure + literal decryption remain recoverable.";

const LITERAL_RECOVERY_LIMIT: &str = "static literal recovery handles single-byte XOR/ADD/SUB and short repeating-key XOR \
     (the manual and garble-simple cases). garble's full-length-key simple/swap/split/shuffle \
     obfuscators embed a per-literal random key and reverse it in an init thunk; reversing those \
     in general requires emulating the init function, which this static pass does not do.";

const STDLIB_FINGERPRINT_NAMES: &[&str] = &[
    "runtime.main",
    "runtime.goexit",
    "runtime.morestack",
    "runtime.gopanic",
    "runtime.mallocgc",
    "runtime.newobject",
    "runtime.schedinit",
    "runtime.systemstack",
    "fmt.Println",
    "fmt.Printf",
    "fmt.Fprintf",
    "fmt.Sprintf",
    "sync.(*Mutex).Lock",
    "sync.(*Mutex).Unlock",
    "os.Exit",
];

#[must_use]
pub fn analyze(image: &GoImage<'_>, syms: &GoSymbols) -> GarbleReport {
    let detection_score: u32 = score_garble_signals(image, syms);
    let surviving: BTreeSet<String> = surviving_stdlib_names(syms);
    let (recovered_strings, literal_recovery): (Vec<String>, LiteralRecoveryStats) =
        recover_strings(image);
    let stdlib_fingerprints_present: usize = surviving.len();
    let seed_hash: Option<String> = extract_seed_hash(image);
    let total_stdlib: usize = STDLIB_FINGERPRINT_NAMES.len();
    let seed_recoverable: bool = seed_hash.is_some();
    let quality: GarbleQuality = classify(
        detection_score,
        stdlib_fingerprints_present,
        total_stdlib,
        seed_recoverable,
    );
    let name_recovery_wall: Option<String> = match quality {
        GarbleQuality::None => None,
        _ if seed_recoverable => None,
        _ => Some(SEEDLESS_WALL.to_owned()),
    };
    let literal_recovery_limit: Option<String> = match quality {
        GarbleQuality::None => None,
        _ => Some(LITERAL_RECOVERY_LIMIT.to_owned()),
    };
    GarbleReport {
        quality,
        detection_score,
        stdlib_fingerprints_present,
        seed_hash,
        seed_recoverable,
        name_recovery_wall,
        literal_recovery_limit,
        surviving_stdlib_names: surviving,
        recovered_strings,
        literal_recovery,
    }
}

const fn classify(
    score: u32,
    surviving: usize,
    total_stdlib: usize,
    seed_recoverable: bool,
) -> GarbleQuality {
    match (score, surviving) {
        (0, _) => GarbleQuality::None,
        (s, n) if s >= 4 && n * 2 < total_stdlib => {
            if seed_recoverable {
                GarbleQuality::Full
            } else {
                GarbleQuality::Partial
            }
        }
        (s, n) if s >= 2 && n < total_stdlib => GarbleQuality::Partial,
        _ => GarbleQuality::Detected,
    }
}

fn score_garble_signals(image: &GoImage<'_>, syms: &GoSymbols) -> u32 {
    let mut score: u32 = 0;
    if syms.funcs.is_empty() && is_probably_go(image) {
        score += 3;
    }
    let mut goresym_seen: usize = 0;
    let mut total: usize = 0;
    let mut short_pkg_hits: usize = 0;
    let mut user_funcs: usize = 0;
    let mut hashed_funcs: usize = 0;
    for f in &syms.funcs {
        total += 1;
        if f.name.starts_with("runtime.")
            || f.name.starts_with("internal/")
            || f.name.starts_with("type:")
            || f.name.starts_with("go:")
        {
            goresym_seen += 1;
            continue;
        }
        if let Some(idx) = f.name.find('.') {
            let head: &str = &f.name[..idx];
            if head.len() <= 4 && head.chars().all(|c: char| c.is_ascii_lowercase()) {
                short_pkg_hits += 1;
            }
        }
        if !is_known_stdlib_package(&f.name) {
            user_funcs += 1;
            if function_name_looks_garble_hashed(&f.name) {
                hashed_funcs += 1;
            }
        }
    }
    if total > 0 {
        #[allow(clippy::cast_precision_loss)]
        let non_goresym_ratio: f64 = (total - goresym_seen) as f64 / total as f64;
        if non_goresym_ratio < 0.30 && short_pkg_hits * 4 > total {
            score += 2;
        } else if short_pkg_hits * 8 > total {
            score += 1;
        }
    }
    if user_funcs >= 4 && hashed_funcs * 3 >= user_funcs {
        score += 3;
    } else if hashed_funcs >= 2 {
        score += 1;
    }
    let buildinfo_present: bool = image.sections.iter().any(|s: &crate::binary::Section<'_>| {
        s.data.windows(14).any(|w: &[u8]| w == b"\xff Go buildinf:")
    });
    if !buildinfo_present {
        score += 1;
    }
    let garble_marker: bool = image.sections.iter().any(|s: &crate::binary::Section<'_>| {
        s.data.windows(7).any(|w: &[u8]| w == b"garble/")
            || s.data.windows(10).any(|w: &[u8]| w == b"mvdan.cc/g")
    });
    if garble_marker {
        score += 1;
    }
    let trimpath: bool = image
        .sections
        .iter()
        .any(|s: &crate::binary::Section<'_>| s.data.windows(9).any(|w: &[u8]| w == b"-trimpath"));
    if trimpath {
        score += 1;
    }
    score
}

const STDLIB_PACKAGE_ROOTS: &[&str] = &[
    "runtime",
    "internal",
    "sync",
    "syscall",
    "reflect",
    "unicode",
    "encoding",
    "errors",
    "io",
    "os",
    "fmt",
    "strconv",
    "strings",
    "sort",
    "bytes",
    "bufio",
    "context",
    "time",
    "math",
    "crypto",
    "net",
    "path",
    "hash",
    "compress",
    "html",
    "regexp",
    "text",
    "container",
    "embed",
    "iter",
    "slices",
    "maps",
    "cmp",
    "vendor",
    "main",
];

fn is_known_stdlib_package(qualified: &str) -> bool {
    let head: &str = qualified.split('.').next().unwrap_or(qualified);
    let root: &str = head.rsplit('/').next().unwrap_or(head);
    let first_seg: &str = head.split('/').next().unwrap_or(head);
    STDLIB_PACKAGE_ROOTS.contains(&root) || STDLIB_PACKAGE_ROOTS.contains(&first_seg)
}

/// Heuristic flag for a garble-hashed function leaf identifier.
///
/// Garble replaces identifiers with the base64 of a truncated HMAC: an erratically
/// cased token with no readable word. We flag a leaf (last `.`-separated component,
/// receiver markup stripped) that is 7..=24 chars, mixes upper+lower, has NO readable
/// run of >=5 same-case letters, and either alternates case densely or carries an
/// embedded digit. Readable Go names (`expandAVX512`, `parseInt`) keep a long
/// lowercase run and are rejected. This is a detection SIGNAL only; garble seedless
/// names are never recovered.
fn function_name_looks_garble_hashed(name: &str) -> bool {
    let leaf: &str = name
        .rsplit('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(')')
        .trim_start_matches('(')
        .trim_start_matches('*');
    if leaf.len() < 7 || leaf.len() > 24 {
        return false;
    }
    if !leaf
        .bytes()
        .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
    {
        return false;
    }
    let has_upper: bool = leaf.bytes().any(|b: u8| b.is_ascii_uppercase());
    let has_lower: bool = leaf.bytes().any(|b: u8| b.is_ascii_lowercase());
    if !(has_upper && has_lower) {
        return false;
    }
    let letters: usize = leaf
        .bytes()
        .filter(|b: &u8| b.is_ascii_alphabetic())
        .count();
    if letters == 0 {
        return false;
    }
    if longest_lower_run(leaf) >= 5 || longest_upper_run(leaf) >= 5 {
        return false;
    }
    let transitions: usize = leaf
        .as_bytes()
        .windows(2)
        .filter(|w: &&[u8]| {
            w[0].is_ascii_alphabetic()
                && w[1].is_ascii_alphabetic()
                && w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase()
        })
        .count();
    let dense_case_alternation: bool = transitions * 3 >= leaf.len();
    let digit_among_letters: bool = leaf.bytes().any(|b: u8| b.is_ascii_digit());
    dense_case_alternation || digit_among_letters
}

fn longest_lower_run(s: &str) -> usize {
    longest_run(s, u8::is_ascii_lowercase)
}

fn longest_upper_run(s: &str) -> usize {
    longest_run(s, u8::is_ascii_uppercase)
}

fn longest_run(s: &str, pred: fn(&u8) -> bool) -> usize {
    let mut best: usize = 0;
    let mut cur: usize = 0;
    for b in s.bytes() {
        if pred(&b) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn is_probably_go(image: &GoImage<'_>) -> bool {
    image.sections.iter().any(|s: &crate::binary::Section<'_>| {
        s.data.windows(9).any(|w: &[u8]| w == b"runtime.g")
            || s.data.windows(7).any(|w: &[u8]| w == b"go:link")
            || s.data.windows(6).any(|w: &[u8]| {
                w == b"go1.22"
                    || w == b"go1.23"
                    || w == b"go1.24"
                    || w == b"go1.25"
                    || w == b"go1.26"
            })
    })
}

fn surviving_stdlib_names(syms: &GoSymbols) -> BTreeSet<String> {
    let observed: BTreeSet<&str> = syms
        .funcs
        .iter()
        .map(|f: &GoFunc| f.name.as_str())
        .collect();
    STDLIB_FINGERPRINT_NAMES
        .iter()
        .filter(|canonical: &&&str| observed.contains(*canonical))
        .map(|canonical: &&str| (*canonical).to_owned())
        .collect()
}

/// garble's `simple` obfuscator picks one of XOR/ADD/SUB. We reverse each as a
/// single-byte key and as a short repeating key, the cases statically tractable
/// without emulating garble's init thunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralOp {
    Xor,
    Add,
    Sub,
}

impl LiteralOp {
    /// Reverse the obfuscation: recover `plain` from an obfuscated byte and key byte.
    #[inline]
    const fn deobfuscate(self, obfuscated: u8, key: u8) -> u8 {
        match self {
            Self::Xor => obfuscated ^ key,
            Self::Add => obfuscated.wrapping_sub(key),
            Self::Sub => obfuscated.wrapping_add(key),
        }
    }
}

const MIN_LITERAL_LEN: usize = 10;
const MAX_REPEATING_KEY: usize = 8;
const MAX_RECOVERED_STRINGS: usize = 4096;

fn recover_strings(image: &GoImage<'_>) -> (Vec<String>, LiteralRecoveryStats) {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut stats: LiteralRecoveryStats = LiteralRecoveryStats::default();
    for sec in &image.sections {
        let is_rodata: bool = matches!(
            sec.name.as_str(),
            ".rdata" | ".rodata" | "__rodata" | "__const" | ".data.rel.ro"
        );
        if is_rodata {
            stats.plain_ascii += scan_ascii_strings(sec.data, &mut out);
            stats.single_xor += scan_single_op(sec.data, LiteralOp::Xor, &mut out);
            stats.single_add += scan_single_op(sec.data, LiteralOp::Add, &mut out);
            stats.single_sub += scan_single_op(sec.data, LiteralOp::Sub, &mut out);
            stats.repeating_xor += scan_repeating_xor(sec.data, &mut out);
        } else if sec.data.len() < 4 * 1024 * 1024 {
            stats.plain_ascii += scan_ascii_strings(sec.data, &mut out);
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v.truncate(MAX_RECOVERED_STRINGS);
    (v, stats)
}

fn scan_ascii_strings(buf: &[u8], out: &mut BTreeSet<String>) -> usize {
    let mut added: usize = 0;
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < buf.len() {
        if is_printable_ascii(buf[i]) {
            i += 1;
            continue;
        }
        if i - start >= 6
            && let Ok(s) = std::str::from_utf8(&buf[start..i])
            && out.insert(s.to_owned())
        {
            added += 1;
        }
        start = i + 1;
        i += 1;
    }
    if i - start >= 6
        && let Ok(s) = std::str::from_utf8(&buf[start..i])
        && out.insert(s.to_owned())
    {
        added += 1;
    }
    added
}

const SINGLE_KEY_MIN_HITS: usize = 4;
const KEY_OUTLIER_MARGIN: usize = 3;

/// A single-byte transform is only accepted when ONE key is a sharp OUTLIER: it must
/// de-obfuscate at least [`SINGLE_KEY_MIN_HITS`] plausible literals AND beat the
/// median key by [`KEY_OUTLIER_MARGIN`]x. Genuine single-key obfuscation produces a
/// dominant key; random data produces a flat key histogram with no outlier, so this
/// rejects the false-positive avalanche of brute-forcing every key over rodata.
fn scan_single_op(buf: &[u8], op: LiteralOp, out: &mut BTreeSet<String>) -> usize {
    let mut hist: [usize; 256] = [0usize; 256];
    for key in 1u8..=255u8 {
        hist[key as usize] = count_op_literals(buf, op, key);
    }
    let (best_key, best_hits): (u8, usize) = hist
        .iter()
        .enumerate()
        .map(|(k, h): (usize, &usize)| (k as u8, *h))
        .max_by_key(|(_, h): &(u8, usize)| *h)
        .unwrap_or((0, 0));
    if best_hits < SINGLE_KEY_MIN_HITS || !is_outlier(&hist, best_hits) {
        return 0;
    }
    commit_op_literals(buf, op, best_key, out)
}

/// True when `best_hits` dominates the key histogram: it must exceed the median
/// non-zero key count by a wide margin, the fingerprint of a real obfuscation key.
fn is_outlier(hist: &[usize; 256], best_hits: usize) -> bool {
    is_outlier_among(hist, best_hits)
}

fn is_outlier_among(counts: &[usize], best_hits: usize) -> bool {
    let mut nonzero: Vec<usize> = counts.iter().copied().filter(|h: &usize| *h > 0).collect();
    if nonzero.len() < 2 {
        return best_hits >= SINGLE_KEY_MIN_HITS;
    }
    nonzero.sort_unstable();
    let median: usize = nonzero[nonzero.len() / 2];
    best_hits
        >= median
            .saturating_mul(KEY_OUTLIER_MARGIN)
            .max(SINGLE_KEY_MIN_HITS)
}

fn count_op_literals(buf: &[u8], op: LiteralOp, key: u8) -> usize {
    let mut hits: usize = 0;
    let mut run: usize = 0;
    let mut window: Vec<u8> = Vec::with_capacity(64);
    for &byte in buf {
        let decoded: u8 = op.deobfuscate(byte, key);
        if is_printable_ascii(decoded) {
            run += 1;
            window.push(decoded);
            continue;
        }
        if run >= MIN_LITERAL_LEN && std::str::from_utf8(&window).is_ok_and(plausible_string) {
            hits += 1;
        }
        run = 0;
        window.clear();
    }
    if run >= MIN_LITERAL_LEN && std::str::from_utf8(&window).is_ok_and(plausible_string) {
        hits += 1;
    }
    hits
}

fn commit_op_literals(buf: &[u8], op: LiteralOp, key: u8, out: &mut BTreeSet<String>) -> usize {
    let mut added: usize = 0;
    let mut current: Vec<u8> = Vec::with_capacity(64);
    for &byte in buf {
        let decoded: u8 = op.deobfuscate(byte, key);
        if is_printable_ascii(decoded) {
            current.push(decoded);
            continue;
        }
        added += flush_literal(&current, out);
        current.clear();
    }
    added += flush_literal(&current, out);
    added
}

/// Repeating-key XOR (period 2..=8) is accepted only when the winning key is a sharp
/// outlier over all probed keys, the same anti-false-positive gate as single-byte.
fn scan_repeating_xor(buf: &[u8], out: &mut BTreeSet<String>) -> usize {
    let mut counts: Vec<usize> = Vec::new();
    let mut best: Option<(usize, [u8; MAX_REPEATING_KEY], usize)> = None;
    for period in 2..=MAX_REPEATING_KEY {
        for &k0 in &REPEATING_KEY_PROBES {
            let key: [u8; MAX_REPEATING_KEY] = repeating_key(k0, period);
            let hits: usize = count_repeating_literals(buf, key, period);
            counts.push(hits);
            if best.is_none_or(|(h, _, _): (usize, _, _)| hits > h) {
                best = Some((hits, key, period));
            }
        }
    }
    let Some((hits, key, period)): Option<(usize, [u8; MAX_REPEATING_KEY], usize)> = best else {
        return 0;
    };
    if hits < SINGLE_KEY_MIN_HITS || !is_outlier_among(&counts, hits) {
        return 0;
    }
    let mut added: usize = 0;
    let mut current: Vec<u8> = Vec::with_capacity(64);
    for (i, &byte) in buf.iter().enumerate() {
        let decoded: u8 = byte ^ key[i % period];
        if is_printable_ascii(decoded) {
            current.push(decoded);
            continue;
        }
        added += flush_literal(&current, out);
        current.clear();
    }
    added += flush_literal(&current, out);
    added
}

fn count_repeating_literals(buf: &[u8], key: [u8; MAX_REPEATING_KEY], period: usize) -> usize {
    let mut hits: usize = 0;
    let mut run: usize = 0;
    let mut window: Vec<u8> = Vec::with_capacity(64);
    for (i, &byte) in buf.iter().enumerate() {
        let decoded: u8 = byte ^ key[i % period];
        if is_printable_ascii(decoded) {
            run += 1;
            window.push(decoded);
            continue;
        }
        if run >= MIN_LITERAL_LEN && std::str::from_utf8(&window).is_ok_and(plausible_string) {
            hits += 1;
        }
        run = 0;
        window.clear();
    }
    if run >= MIN_LITERAL_LEN && std::str::from_utf8(&window).is_ok_and(plausible_string) {
        hits += 1;
    }
    hits
}

fn repeating_key(k0: u8, period: usize) -> [u8; MAX_REPEATING_KEY] {
    let mut key: [u8; MAX_REPEATING_KEY] = [k0; MAX_REPEATING_KEY];
    for (idx, slot) in key.iter_mut().enumerate().take(period) {
        *slot = k0.wrapping_add(idx as u8);
    }
    key
}

const REPEATING_KEY_PROBES: [u8; 8] = [0x01, 0x10, 0x20, 0x40, 0x55, 0x7f, 0xaa, 0xff];

fn flush_literal(current: &[u8], out: &mut BTreeSet<String>) -> usize {
    if current.len() >= MIN_LITERAL_LEN
        && let Ok(s) = std::str::from_utf8(current)
        && plausible_string(s)
        && out.insert(s.to_owned())
    {
        1
    } else {
        0
    }
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n')
}

/// Common English words and Go-ish tokens. A decoded literal must contain one to be
/// committed: this collapses the false-positive avalanche that single-key brute force
/// produces over arbitrary section bytes (XOR artifacts almost never spell a word).
const DICTIONARY_TOKENS: &[&str] = &[
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
    "/usr/",
    "C:\\",
];

fn plausible_string(s: &str) -> bool {
    let len: usize = s.len();
    if len < MIN_LITERAL_LEN {
        return false;
    }
    let letters: usize = s.bytes().filter(u8::is_ascii_alphabetic).count();
    let symbols: usize = s
        .bytes()
        .filter(|b: &u8| {
            !b.is_ascii_alphanumeric()
                && !matches!(*b, b' ' | b'/' | b'_' | b'.' | b'-' | b':' | b'\\')
        })
        .count();
    if letters * 2 < len || symbols * 8 > len {
        return false;
    }
    let lowered: String = s.to_ascii_lowercase();
    let token_hits: usize = DICTIONARY_TOKENS
        .iter()
        .filter(|tok: &&&str| lowered.contains(*tok))
        .count();
    let strong_marker: bool = ["://", ".com", "/usr/", "c:\\"]
        .iter()
        .any(|m: &&str| lowered.contains(m));
    let multiword_phrase: bool = s.contains(' ') && token_hits >= 1;
    token_hits >= 2 || strong_marker || multiword_phrase
}

fn extract_seed_hash(image: &GoImage<'_>) -> Option<String> {
    let needle: &[u8] = b"GARBLE_SEED";
    for sec in &image.sections {
        let mut i: usize = 0;
        while i + needle.len() <= sec.data.len() {
            if &sec.data[i..i + needle.len()] == needle {
                let start: usize = i + needle.len();
                let tail: &[u8] = sec.data.get(start..start + 64)?;
                let limit: usize = tail.len().min(44);
                let end: usize = tail
                    .iter()
                    .position(|b: &u8| !b.is_ascii_alphanumeric())
                    .unwrap_or(limit);
                if end >= 22
                    && let Ok(s) = std::str::from_utf8(&tail[..end])
                {
                    return Some(s.to_owned());
                }
            }
            i += 1;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn literal_operator_reversal_is_exact() {
        let plain: &[u8] = b"connection failed: invalid server address";
        for op in [LiteralOp::Xor, LiteralOp::Add, LiteralOp::Sub] {
            let key: u8 = 0x5a;
            let obfuscated: Vec<u8> = plain
                .iter()
                .map(|b: &u8| match op {
                    LiteralOp::Xor => b ^ key,
                    LiteralOp::Add => b.wrapping_add(key),
                    LiteralOp::Sub => b.wrapping_sub(key),
                })
                .collect();
            let recovered: Vec<u8> = obfuscated
                .iter()
                .map(|b: &u8| op.deobfuscate(*b, key))
                .collect();
            assert_eq!(recovered, plain, "{op:?} reversal must be exact");
        }
    }

    #[test]
    fn single_op_scan_recovers_known_xor_blob() {
        let literals: [&[u8]; 5] = [
            b"the server connection failed with an invalid request",
            b"unknown config value for the client timeout setting",
            b"https://example.com/secret/token/path/v2",
            b"warning: password missing from the request header",
            b"cannot create the object: address already in use",
        ];
        let key: u8 = 0x37;
        let mut buf: Vec<u8> = Vec::new();
        for lit in literals {
            buf.extend([0xffu8; 8]);
            buf.extend(lit.iter().map(|b: &u8| b ^ key));
        }
        buf.extend([0xffu8; 8]);
        let mut out: BTreeSet<String> = BTreeSet::new();
        let hits: usize = scan_single_op(&buf, LiteralOp::Xor, &mut out);
        assert!(
            hits >= 4,
            "known XOR blob must surface its literals, got {hits}"
        );
        assert!(
            out.iter()
                .any(|s: &String| s.contains("server connection failed")),
            "recovered set must contain a plaintext, got {out:?}"
        );
    }

    #[test]
    fn single_op_scan_quiet_on_random_data() {
        let mut state: u64 = 0xdead_beef_cafe_1234;
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        for _ in 0..8192 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            buf.push((state >> 33) as u8);
        }
        let mut out: BTreeSet<String> = BTreeSet::new();
        let hits: usize = scan_single_op(&buf, LiteralOp::Xor, &mut out);
        assert!(
            hits <= 1,
            "random data must not yield phantom XOR literals, got {hits}: {out:?}"
        );
    }

    #[test]
    fn plausible_string_rejects_xor_artifacts() {
        assert!(!plausible_string("@@@@    @@@@@@@@"));
        assert!(!plausible_string(" !\"#$%&'()*+,-./"));
        assert!(!plausible_string("AARCDE@ABC"));
        assert!(plausible_string("the server connection failed"));
        assert!(plausible_string("https://example.com/path"));
    }

    #[test]
    fn garble_hash_detector_fires_on_obfuscated_leaves() {
        for name in [
            "main.(*mkXHPRuUzL).jiKA6SaXcuN",
            "internal/sync.(*CWQFRMIDV).xYiPuxqUqs",
            "main.nK3dlj0_DVvb",
            "main.qXVft7yaku",
        ] {
            assert!(
                function_name_looks_garble_hashed(name),
                "expected {name} to read as garble-hashed"
            );
        }
    }

    #[test]
    fn garble_hash_detector_rejects_readable_go_names() {
        for name in [
            "main.greet",
            "runtime.expandAVX512_1",
            "fmt.Fprintln",
            "strconv.parseInt",
            "main.describe",
            "net/http.(*Server).ListenAndServe",
        ] {
            assert!(
                !function_name_looks_garble_hashed(name),
                "expected {name} to read as a normal symbol"
            );
        }
    }

    #[test]
    fn stdlib_package_classification() {
        assert!(is_known_stdlib_package("runtime.main"));
        assert!(is_known_stdlib_package("internal/abi.TypeOf"));
        assert!(is_known_stdlib_package("net/http.Serve"));
        assert!(is_known_stdlib_package("main.main"));
        assert!(!is_known_stdlib_package("github.com/x/y.Foo"));
        assert!(!is_known_stdlib_package("mkXHPRuUzL.jiKA6SaXcuN"));
    }

    #[test]
    fn longest_run_counts_consecutive_case() {
        assert_eq!(longest_lower_run("expandAVX"), 6);
        assert_eq!(longest_upper_run("xYZABCd"), 5);
        assert_eq!(longest_lower_run("aBcDeF"), 1);
    }
}
