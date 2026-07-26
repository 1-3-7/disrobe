use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::binary::GoImage;
use crate::debug::{dbg_kv, dbg_kv_guarded, dbg_line, dbg_section};
use crate::pclntab::{LocatedPclntab, locate_pclntab};
use crate::symbols::{GoFunc, GoSymbols, parse_symbols};

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
    pub name_recovery: NameRecoveryStats,
    pub residual: GarbleResidual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GarbleResidual {
    None,
    SeedNameHash,
    Incomplete,
}

impl GarbleResidual {
    #[must_use]
    pub const fn describe(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::SeedNameHash => Some(SEED_NAME_RESIDUAL),
            Self::Incomplete => Some(INCOMPLETE_RESIDUAL),
        }
    }
}

const SEED_NAME_RESIDUAL: &str = "complete static recovery: stdlib structure is reconstructed from pclntab and every \
     statically-recoverable literal is decrypted; the only residual is original user \
     package/symbol names, which garble derives through keyed HMAC-SHA256 over a build-time seed \
     that is never embedded in a seedless build, so those names are an information-theoretic wall.";

const INCOMPLETE_RESIDUAL: &str = "recovery is partial: some stdlib structure or obfuscated literals were not fully \
     reconstructed (e.g. a -tiny build that strips the function table the thunk scan keys on, \
     or an unrecognised literal-derivation shape); this is a tooling-depth boundary, not an \
     information-theoretic one.";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteralRecoveryStats {
    pub plain_ascii: usize,
    pub single_xor: usize,
    pub single_add: usize,
    pub single_sub: usize,
    pub repeating_xor: usize,
    pub garble_simple: usize,
    pub garble_thunk: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecoveryStats {
    pub total_funcs: usize,
    pub stdlib_recovered: usize,
    pub user_hashed_erased: usize,
    pub user_readable_surviving: usize,
}

const SEEDLESS_WALL: &str = "garble name-hashing is keyed (HMAC-SHA256 over the build seed); with no seed embedded in the \
     binary, original package/symbol names are an information-theoretic wall and cannot be recovered. \
     pclntab-derived structure + literal decryption remain recoverable.";

const LITERAL_RECOVERY_LIMIT: &str = "garble -literals string encryption is NOT a one-time pad: every per-literal key is derived \
     inside an init-time decrypt thunk from material that is itself present in the binary, so the \
     plaintext is statically recoverable by emulating that derivation. disrobe runs the decrypt \
     thunk concretely: a scoped x86-64 interpreter executes the lambda the go compiler emitted for \
     each obfuscated literal, reading the encrypted data/key/positions/fullData blobs from rodata, \
     pulling the external-key arguments out of the exact call site (immediates plus the \
     proxy-dispatcher struct-field pointer chases through .data, emulated statically), applying every \
     byte op (xor/add/sub/neg), the swap and shuffle index math, and the split jump-table dispatch, \
     modelling newobject/makeslice/growslice into a tracked heap buffer, following the indirect calls \
     into the seed recursive decFunc closure chain and the proxy-dispatcher's hidden string-cast \
     lambda, and harvesting the recovered plaintext from emulated memory (junk-byte padding \
     stripped). this reverses all five obfuscators (simple, swap, shuffle, split, seed) whether the \
     decrypt is a separate closure or inlined into the caller, plus the legacy single-byte \
     XOR/ADD/SUB, repeating-key XOR, and standalone data/key blob cases. the seed obfuscator's \
     immediate-fed byte chain and the proxy dispatcher's indirect dispatch are threaded by the \
     interpreter rather than walled. the key material is in the file in every case, so the only \
     residual is concrete tooling depth (e.g. a -tiny build that strips the function table the \
     thunk scan keys on), never an information-theoretic boundary.";

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
    dbg_section("go.garble");
    let detection_score: u32 = score_garble_signals(image, syms);
    dbg_kv("detection_score", || detection_score.to_string());
    let surviving: BTreeSet<String> = surviving_stdlib_names(syms);
    let garble_literals_likely: bool = detection_score >= GARBLE_LITERAL_RECOVERY_MIN_SCORE;
    dbg_kv("literals_likely", || garble_literals_likely.to_string());
    let (recovered_strings, literal_recovery): (Vec<String>, LiteralRecoveryStats) =
        recover_strings(image, syms, garble_literals_likely);
    dbg_line(|| {
        format!(
            "literal-recovery: plain={} single_xor={} single_add={} single_sub={} \
             repeating_xor={} garble_simple={} garble_thunk={} total_recovered={}",
            literal_recovery.plain_ascii,
            literal_recovery.single_xor,
            literal_recovery.single_add,
            literal_recovery.single_sub,
            literal_recovery.repeating_xor,
            literal_recovery.garble_simple,
            literal_recovery.garble_thunk,
            recovered_strings.len(),
        )
    });
    let name_recovery: NameRecoveryStats = measure_name_recovery(syms);
    dbg_line(|| {
        format!(
            "name-recovery: total={} stdlib_recovered={} user_hashed_erased={} \
             user_readable_surviving={}",
            name_recovery.total_funcs,
            name_recovery.stdlib_recovered,
            name_recovery.user_hashed_erased,
            name_recovery.user_readable_surviving,
        )
    });
    let stdlib_fingerprints_present: usize = surviving.len();
    let seed_hash: Option<String> = extract_seed_hash(image);
    let total_stdlib: usize = STDLIB_FINGERPRINT_NAMES.len();
    let seed_recoverable: bool = seed_hash.is_some();
    dbg_kv("seed_recoverable", || seed_recoverable.to_string());
    if let Some(ref hash) = seed_hash {
        dbg_kv_guarded("seed_hash", || hash.clone());
    }
    let literals_present: bool = garble_literals_likely || literal_recovery.garble_thunk > 0;
    let literals_recovered: bool =
        literal_recovery.garble_thunk > 0 || literal_recovery.garble_simple > 0;
    let (quality, residual): (GarbleQuality, GarbleResidual) = classify(
        detection_score,
        stdlib_fingerprints_present,
        total_stdlib,
        seed_recoverable,
        &name_recovery,
        literals_present,
        literals_recovered,
    );
    dbg_kv("classify", || format!("{quality:?} residual={residual:?}"));
    let name_recovery_wall: Option<String> = match quality {
        GarbleQuality::None => None,
        _ if seed_recoverable => None,
        _ => Some(SEEDLESS_WALL.to_owned()),
    };
    if name_recovery_wall.is_some() {
        dbg_line(|| {
            "seedless-name-wall: keyed HMAC-SHA256 over an absent build seed; original \
             package/symbol names are an information-theoretic wall"
                .to_owned()
        });
    }
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
        name_recovery,
        residual,
    }
}

fn measure_name_recovery(syms: &GoSymbols) -> NameRecoveryStats {
    let mut stats: NameRecoveryStats = NameRecoveryStats {
        total_funcs: syms.funcs.len(),
        ..NameRecoveryStats::default()
    };
    for f in &syms.funcs {
        let unambiguously_stdlib: bool = f.name.starts_with("runtime.")
            || f.name.starts_with("internal/")
            || f.name.starts_with("type:")
            || f.name.starts_with("go:");
        if unambiguously_stdlib {
            stats.stdlib_recovered += 1;
        } else if function_name_looks_garble_hashed(&f.name) {
            stats.user_hashed_erased += 1;
        } else if !f.name.starts_with("main.") && is_known_stdlib_package(&f.name) {
            stats.stdlib_recovered += 1;
        } else {
            stats.user_readable_surviving += 1;
        }
    }
    stats
}

const STRUCTURE_RECOVERY_NUM: usize = 80;
const STRUCTURE_RECOVERY_DEN: usize = 100;
const GARBLE_CONFIDENCE_THRESHOLD: u32 = 2;

#[allow(clippy::too_many_arguments)]
const fn classify(
    score: u32,
    surviving: usize,
    total_stdlib: usize,
    seed_recoverable: bool,
    name_recovery: &NameRecoveryStats,
    literals_present: bool,
    literals_recovered: bool,
) -> (GarbleQuality, GarbleResidual) {
    let _ = (surviving, total_stdlib);
    if score == 0 {
        return (GarbleQuality::None, GarbleResidual::None);
    }
    let confidently_garble: bool = score >= GARBLE_CONFIDENCE_THRESHOLD
        || (literals_recovered && name_recovery.user_hashed_erased > 0);
    if !confidently_garble {
        return (GarbleQuality::Detected, GarbleResidual::Incomplete);
    }
    let structure_recovered: bool = name_recovery.total_funcs > 0
        && name_recovery.stdlib_recovered * STRUCTURE_RECOVERY_DEN
            >= name_recovery.total_funcs * STRUCTURE_RECOVERY_NUM;
    let literals_complete: bool = !literals_present || literals_recovered;
    if structure_recovered && literals_complete {
        let residual: GarbleResidual = if seed_recoverable || name_recovery.user_hashed_erased == 0
        {
            GarbleResidual::None
        } else {
            GarbleResidual::SeedNameHash
        };
        return (GarbleQuality::Full, residual);
    }
    if structure_recovered || literals_recovered {
        return (GarbleQuality::Partial, GarbleResidual::Incomplete);
    }
    (GarbleQuality::Detected, GarbleResidual::Incomplete)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralOp {
    Xor,
    Add,
    Sub,
}

impl LiteralOp {
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
const GARBLE_LITERAL_RECOVERY_MIN_SCORE: u32 = 4;
const MAX_LITERAL_SCAN_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLAIN_STRINGS: usize = MAX_RECOVERED_STRINGS;
const STRING_SCAN_BUDGET: Duration = Duration::from_secs(8);

fn recover_strings(
    image: &GoImage<'_>,
    syms: &GoSymbols,
    garble_literals_likely: bool,
) -> (Vec<String>, LiteralRecoveryStats) {
    let mut decrypted: BTreeSet<String> = BTreeSet::new();
    let mut plain: BTreeSet<String> = BTreeSet::new();
    let mut stats: LiteralRecoveryStats = LiteralRecoveryStats::default();
    for rec in crate::garble_thunk::recover_thunk_literals(image, syms) {
        if decrypted.insert(rec.plaintext) {
            stats.garble_thunk += 1;
        }
    }
    let scan_start: Instant = Instant::now();
    for sec in &image.sections {
        if scan_start.elapsed() > STRING_SCAN_BUDGET {
            break;
        }
        let is_rodata: bool = matches!(
            sec.name.as_str(),
            ".rdata" | ".rodata" | "__rodata" | "__const" | ".data.rel.ro"
        );
        if is_rodata {
            let scan: &[u8] = &sec.data[..sec.data.len().min(MAX_LITERAL_SCAN_BYTES)];
            stats.plain_ascii += scan_ascii_strings(sec.data, &mut plain, MAX_PLAIN_STRINGS);
            stats.single_xor += scan_single_op(scan, LiteralOp::Xor, &mut decrypted);
            stats.single_add += scan_single_op(scan, LiteralOp::Add, &mut decrypted);
            stats.single_sub += scan_single_op(scan, LiteralOp::Sub, &mut decrypted);
            stats.repeating_xor += scan_repeating_xor(scan, &mut decrypted);
            if garble_literals_likely {
                stats.garble_simple += scan_garble_simple(scan, &mut decrypted);
            }
        } else if sec.data.len() < MAX_LITERAL_SCAN_BYTES {
            stats.plain_ascii += scan_ascii_strings(sec.data, &mut plain, MAX_PLAIN_STRINGS);
        }
    }
    for s in &decrypted {
        plain.remove(s);
    }
    let mut v: Vec<String> = decrypted.into_iter().collect();
    v.sort();
    v.truncate(MAX_RECOVERED_STRINGS);
    if v.len() < MAX_RECOVERED_STRINGS {
        let remaining: usize = MAX_RECOVERED_STRINGS - v.len();
        v.extend(plain.into_iter().take(remaining));
    }
    (v, stats)
}

fn scan_garble_simple(buf: &[u8], out: &mut BTreeSet<String>) -> usize {
    let mut added: usize = 0;
    for rec in crate::garble_literals::recover_simple_literals(buf) {
        if out.insert(rec.plaintext) {
            added += 1;
        }
    }
    added
}

pub fn probe_thunk_literals(bytes: &[u8]) -> crate::error::Result<Vec<(String, u64, u64)>> {
    let image: GoImage<'_> = GoImage::parse(bytes)?;
    let Ok(located): crate::error::Result<LocatedPclntab<'_>> = locate_pclntab(&image) else {
        return Ok(Vec::new());
    };
    let syms: GoSymbols = parse_symbols(&image, &located)?;
    Ok(crate::garble_thunk::recover_thunk_literals(&image, &syms)
        .into_iter()
        .map(|r: crate::garble_thunk::ThunkRecovery| (r.plaintext, r.thunk_va, r.data_va))
        .collect())
}

#[must_use]
pub fn probe_simple_literals(rodata: &[u8]) -> Vec<(String, String, usize)> {
    crate::garble_literals::recover_simple_literals(rodata)
        .into_iter()
        .map(|rec: crate::garble_literals::SimpleRecovery| {
            let op: String = match rec.op {
                crate::garble_literals::SimpleOp::Xor => "xor".to_owned(),
                crate::garble_literals::SimpleOp::Add => "add".to_owned(),
                crate::garble_literals::SimpleOp::Sub => "sub".to_owned(),
            };
            (rec.plaintext, op, rec.perturbed_bytes)
        })
        .collect()
}

fn scan_ascii_strings(buf: &[u8], out: &mut BTreeSet<String>, cap: usize) -> usize {
    let mut added: usize = 0;
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < buf.len() {
        if out.len() >= cap {
            return added;
        }
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
    if out.len() < cap
        && i - start >= 6
        && let Ok(s) = std::str::from_utf8(&buf[start..i])
        && out.insert(s.to_owned())
    {
        added += 1;
    }
    added
}

const SINGLE_KEY_MIN_HITS: usize = 4;
const KEY_OUTLIER_MARGIN: usize = 3;

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
                let tail_len: usize = (sec.data.len() - start).min(64);
                let tail: &[u8] = &sec.data[start..start + tail_len];
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
    fn literal_limit_is_reclassified_off_the_one_time_pad_claim() {
        let limit: String = LITERAL_RECOVERY_LIMIT.to_ascii_lowercase();
        assert!(
            limit.contains("not a one-time pad"),
            "the -literals limit must explicitly retire the one-time-pad framing"
        );
        assert!(
            limit.contains("emulat"),
            "the limit must state the init-derived keys are recovered by emulation"
        );
        assert!(
            limit.contains("x86-64 interpreter") && limit.contains("decrypt thunk"),
            "the limit must name the concrete thunk interpreter that defeats the otp claim"
        );
        assert!(
            limit.contains("data/key") || (limit.contains("data") && limit.contains("key")),
            "the limit must name the embedded byte arrays read from rodata"
        );
        assert!(
            limit.contains("seed") && limit.contains("indirect"),
            "the limit must honestly name the residual seed / indirect-call boundary"
        );
        assert!(
            !limit.contains("one-time-pad with no statically recoverable key"),
            "the retired false wall phrasing must not reappear"
        );
    }

    #[test]
    fn name_hash_wall_stays_concretely_seedless() {
        let wall: String = SEEDLESS_WALL.to_ascii_lowercase();
        assert!(
            wall.contains("seed") && wall.contains("not"),
            "the genuine name wall must stay phrased on the seed being absent from the binary"
        );
        assert!(
            wall.contains("hmac-sha256") || wall.contains("keyed"),
            "the name wall must name the keyed hash that makes it information-theoretic"
        );
    }

    #[test]
    fn garble_simple_scan_recovers_embedded_literal() {
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
        let plaintext: &[u8] = b"cannot connect to the command server: invalid token";
        let lead: &[u8] = b"\x80\x90";
        let tail: &[u8] = b"\xa0\xb0";
        let mut plain_with_junk: Vec<u8> = Vec::new();
        plain_with_junk.extend_from_slice(lead);
        plain_with_junk.extend_from_slice(plaintext);
        plain_with_junk.extend_from_slice(tail);
        let key: Vec<u8> = pseudo_key(0x1234_5678, plain_with_junk.len());
        let data: Vec<u8> = plain_with_junk
            .iter()
            .zip(&key)
            .map(|(p, k): (&u8, &u8)| p.wrapping_sub(*k))
            .collect();
        let mut rodata: Vec<u8> = Vec::new();
        rodata.extend_from_slice(b"\x00\x01go.string pool header\x00\x00");
        rodata.extend_from_slice(&data);
        rodata.extend_from_slice(&[0u8; 3]);
        rodata.extend_from_slice(&key);
        rodata.extend_from_slice(b"\x00trailing\x00");
        let mut out: BTreeSet<String> = BTreeSet::new();
        let added: usize = scan_garble_simple(&rodata, &mut out);
        assert!(
            added >= 1,
            "embedded garble simple literal must be recovered"
        );
        assert!(
            out.iter()
                .any(|s: &String| s == "cannot connect to the command server: invalid token"),
            "recovered set must hold the exact plaintext, got {out:?}"
        );
    }

    #[test]
    fn garble_simple_scan_gated_off_for_non_garble_binaries() {
        let plain_section: &[u8] =
            b"plain ascii rodata: cannot connect to the command server: invalid token\x00";
        let image_like: Vec<u8> = plain_section.to_vec();
        let mut out: BTreeSet<String> = BTreeSet::new();
        let added: usize = scan_garble_simple(&image_like, &mut out);
        assert_eq!(
            added, 0,
            "plain ascii rodata holds no encrypted blob pair and must not yield simple recoveries"
        );
    }

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
    fn seed_hash_scan_continues_after_short_tail_marker() {
        let first_data: &[u8] = b"prefixGARBLE_SEEDshort";
        let second_data: &[u8] = b"noiseGARBLE_SEED0123456789abcdefghijklmn";
        let image: GoImage<'_> = GoImage {
            kind: crate::binary::ImageKind::Pe,
            endian: crate::binary::Endian::Little,
            ptr_size: 8,
            sections: vec![
                crate::binary::Section {
                    name: ".rdata".to_owned(),
                    address: 0x1000,
                    data: first_data,
                    mapped_len: u64::try_from(first_data.len()).expect("fixture size fits u64"),
                },
                crate::binary::Section {
                    name: ".rdata".to_owned(),
                    address: 0x2000,
                    data: second_data,
                    mapped_len: u64::try_from(second_data.len()).expect("fixture size fits u64"),
                },
            ],
            raw: b"",
            symbol_addrs: Vec::new(),
            flat: false,
        };
        let seed_hash: Option<String> = extract_seed_hash(&image);
        assert_eq!(seed_hash.as_deref(), Some("0123456789abcdefghijklmn"));
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
    fn name_recovery_splits_stdlib_from_hashed_users() {
        let syms: GoSymbols = GoSymbols {
            version_label: "go1.18".to_owned(),
            ptr_size: 8,
            funcs: vec![
                GoFunc::new(1, 2, "runtime.main".to_owned()),
                GoFunc::new(2, 3, "fmt.Println".to_owned()),
                GoFunc::new(3, 4, "main.(*mkXHPRuUzL).jiKA6SaXcuN".to_owned()),
                GoFunc::new(4, 5, "main.greet".to_owned()),
            ],
            source_files: Vec::new(),
            package_set: Vec::new(),
        };
        let stats: NameRecoveryStats = measure_name_recovery(&syms);
        assert_eq!(stats.total_funcs, 4);
        assert_eq!(stats.stdlib_recovered, 2);
        assert_eq!(stats.user_hashed_erased, 1);
        assert_eq!(stats.user_readable_surviving, 1);
    }

    #[test]
    fn longest_run_counts_consecutive_case() {
        assert_eq!(longest_lower_run("expandAVX"), 6);
        assert_eq!(longest_upper_run("xYZABCd"), 5);
        assert_eq!(longest_lower_run("aBcDeF"), 1);
    }

    fn stats(total: usize, stdlib: usize, hashed: usize) -> NameRecoveryStats {
        NameRecoveryStats {
            total_funcs: total,
            stdlib_recovered: stdlib,
            user_hashed_erased: hashed,
            user_readable_surviving: total.saturating_sub(stdlib).saturating_sub(hashed),
        }
    }

    #[test]
    fn full_recovery_on_seedless_structure_plus_recovered_literals() {
        let s: NameRecoveryStats = stats(1000, 900, 50);
        let (q, r): (GarbleQuality, GarbleResidual) = classify(3, 8, 15, false, &s, true, true);
        assert_eq!(
            q,
            GarbleQuality::Full,
            "stdlib structure recovered + every obfuscated literal decrypted is a full static \
             recovery even with no embedded seed"
        );
        assert_eq!(
            r,
            GarbleResidual::SeedNameHash,
            "the only residual on a seedless build is the keyed-hash user-name wall"
        );
        assert!(
            r.describe()
                .is_some_and(|d: &str| d.contains("information-theoretic")),
            "the residual must name the genuine information-theoretic boundary"
        );
    }

    #[test]
    fn full_recovery_when_no_literal_obfuscation_present() {
        let s: NameRecoveryStats = stats(1000, 870, 60);
        let (q, _): (GarbleQuality, GarbleResidual) = classify(3, 8, 15, false, &s, false, false);
        assert_eq!(
            q,
            GarbleQuality::Full,
            "a plain garble build with no -literals leaves nothing to decrypt; recovering the \
             stdlib structure is the full static recovery"
        );
    }

    #[test]
    fn partial_when_literals_present_but_unrecovered() {
        let s: NameRecoveryStats = stats(1000, 900, 50);
        let (q, r): (GarbleQuality, GarbleResidual) = classify(4, 8, 15, false, &s, true, false);
        assert_eq!(
            q,
            GarbleQuality::Partial,
            "obfuscated literals that were not decrypted hold quality below full"
        );
        assert_eq!(r, GarbleResidual::Incomplete);
    }

    #[test]
    fn partial_when_structure_below_floor() {
        let s: NameRecoveryStats = stats(1000, 500, 50);
        let (q, _): (GarbleQuality, GarbleResidual) = classify(3, 8, 15, false, &s, true, true);
        assert_eq!(
            q,
            GarbleQuality::Partial,
            "literals recovered but stdlib structure below the recovery floor stays partial"
        );
    }

    #[test]
    fn full_residual_is_none_when_no_user_names_were_hashed() {
        let s: NameRecoveryStats = stats(1000, 950, 0);
        let (q, r): (GarbleQuality, GarbleResidual) = classify(3, 8, 15, false, &s, false, false);
        assert_eq!(q, GarbleQuality::Full);
        assert_eq!(
            r,
            GarbleResidual::None,
            "with no garble-hashed user names there is no name wall left to document"
        );
        assert!(r.describe().is_none());
    }

    #[test]
    fn none_when_score_zero() {
        let s: NameRecoveryStats = stats(1000, 900, 0);
        let (q, r): (GarbleQuality, GarbleResidual) = classify(0, 0, 15, false, &s, false, false);
        assert_eq!(q, GarbleQuality::None);
        assert_eq!(r, GarbleResidual::None);
    }

    #[test]
    fn plain_string_scan_stops_at_cap_under_hostile_input() {
        let mut buf: Vec<u8> = Vec::with_capacity(200_000);
        for i in 0..20_000u32 {
            buf.extend_from_slice(format!("string-token-{i:08}").as_bytes());
            buf.push(0);
        }
        let mut out: BTreeSet<String> = BTreeSet::new();
        let cap: usize = 4096;
        let start: std::time::Instant = std::time::Instant::now();
        let _added: usize = scan_ascii_strings(&buf, &mut out, cap);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "plain-string scan must stay bounded"
        );
        assert!(
            out.len() <= cap,
            "plain string set must never grow past the cap, got {}",
            out.len()
        );
    }

    #[test]
    fn single_op_scan_stays_bounded_on_huge_rodata() {
        let scan: Vec<u8> = vec![0u8; MAX_LITERAL_SCAN_BYTES];
        let mut out: BTreeSet<String> = BTreeSet::new();
        let start: std::time::Instant = std::time::Instant::now();
        let _hits: usize = scan_single_op(&scan, LiteralOp::Xor, &mut out);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "single-op scan over the capped ceiling must stay bounded"
        );
    }
}
