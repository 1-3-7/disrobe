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
    pub surviving_stdlib_names: BTreeSet<String>,
    pub recovered_strings: Vec<String>,
}

const SEEDLESS_WALL: &str = "garble name-hashing is keyed (HMAC-SHA256 over the build seed); with no seed embedded in the \
     binary, original package/symbol names are an information-theoretic wall and cannot be recovered. \
     pclntab-derived structure + literal decryption remain recoverable.";

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
    let recovered_strings: Vec<String> = recover_strings(image);
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
    GarbleReport {
        quality,
        detection_score,
        stdlib_fingerprints_present,
        seed_hash,
        seed_recoverable,
        name_recovery_wall,
        surviving_stdlib_names: surviving,
        recovered_strings,
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

fn recover_strings(image: &GoImage<'_>) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for sec in &image.sections {
        let is_rodata: bool = matches!(
            sec.name.as_str(),
            ".rdata" | ".rodata" | "__rodata" | "__const" | ".data.rel.ro"
        );
        if is_rodata {
            scan_ascii_strings(sec.data, &mut out);
            scan_xor_strings(sec.data, &mut out);
        } else if sec.data.len() < 4 * 1024 * 1024 {
            scan_ascii_strings(sec.data, &mut out);
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v.truncate(4096);
    v
}

fn scan_ascii_strings(buf: &[u8], out: &mut BTreeSet<String>) {
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < buf.len() {
        if is_printable_ascii(buf[i]) {
            i += 1;
            continue;
        }
        if i - start >= 6
            && let Ok(s) = std::str::from_utf8(&buf[start..i])
        {
            out.insert(s.to_owned());
        }
        start = i + 1;
        i += 1;
    }
    if i - start >= 6
        && let Ok(s) = std::str::from_utf8(&buf[start..i])
    {
        out.insert(s.to_owned());
    }
}

fn scan_xor_strings(buf: &[u8], out: &mut BTreeSet<String>) {
    for key in 1u8..=255u8 {
        let mut i: usize = 0;
        let mut current: Vec<u8> = Vec::with_capacity(32);
        while i < buf.len() {
            let decoded: u8 = buf[i] ^ key;
            if is_printable_ascii(decoded) {
                current.push(decoded);
                i += 1;
                continue;
            }
            if current.len() >= 10
                && let Ok(s) = std::str::from_utf8(&current)
                && plausible_string(s)
            {
                out.insert(s.to_owned());
            }
            current.clear();
            i += 1;
        }
        if current.len() >= 10
            && let Ok(s) = std::str::from_utf8(&current)
            && plausible_string(s)
        {
            out.insert(s.to_owned());
        }
    }
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n')
}

fn plausible_string(s: &str) -> bool {
    let vowels: usize = s
        .bytes()
        .filter(|b: &u8| {
            matches!(
                *b,
                b'a' | b'e' | b'i' | b'o' | b'u' | b'A' | b'E' | b'I' | b'O' | b'U'
            )
        })
        .count();
    let spaces: usize = s.bytes().filter(|b: &u8| *b == b' ').count();
    vowels * 6 >= s.len() || spaces > 0 || s.contains(['/', '_', '.'])
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
