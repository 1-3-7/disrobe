#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use common::tokenize::{render, tokenize};

use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const COMPILED_DIR: &str = "../../corpus/python/decompile/legacy/compiled";
const GOLDEN_DIR: &str = "../../corpus/python/decompile/legacy/tokenized";
const SOURCE_DIR: &str = "../../corpus/python/decompile/legacy/source";

/// Per-era floors for tokenized equivalence between disrobe's recovered source and the vendored pycdc
/// goldens. The decode gate (`read_pyc` + frame tree + AST + emit, no error) is exercised
/// unconditionally for every vendored `.pyc` and must stay at zero failures - that is the #22 legacy
/// marshal/structure exerciser. Token-vs-golden equivalence is a SECONDARY signal: the authoritative
/// correctness oracle is `legacy_recompile` (recompile-equivalence + source-token match vs the ORIGINAL
/// `.py`, pycdc-independent). Where disrobe diverges from a pycdc golden because disrobe is
/// recompile-PROVEN-correct and the golden is wrong (e.g. `chain_assignment.3.7`: disrobe emits the
/// module-level `global` decl that recompiles byte-identical, pycdc drops it; `nan_inf`: disrobe emits
/// the folding `1e309` inf literal instead of pycdc's non-round-tripping `float('inf')` call), that is a
/// disrobe WIN, so the golden floor re-baselines DOWN while `legacy_recompile`'s floors ratchet UP. 1.x
/// rose 23->25 (CRLF source-grading fix); 2.x/3.x re-baselined 79/70->77/68 as disrobe outgrew the buggy
/// goldens; 2.x rose 77->78 (pre-3.11 try/except/finally combo merge + phantom-bare-except fix,
/// `try_except_finally.2.6`), then 78->79 (SET_LINENO/CONTINUE_LOOP lowering + try-inside-loop recovery,
/// `test_loops2.2.2`), then 79->80 (pre-3.x inner if/else shared-join else-recovery, `test_nested_ifs.2.5`),
/// then 80->81 (pre-3.0 in-frame `BUILD_LIST 0`/`LIST_APPEND` accumulator folded to a real `ListComp`,
/// `test_listComprehensions.2.7`); then 2.x 81->80 and 3.x 68->67 re-baselined DOWN as disrobe began
/// rendering the empty-unpack target as `[]` not `()` (`unpack_empty.{2.7,3.7}`, `chain_assignment.2.7`):
/// pycdc's golden `() = ...` is a hard SyntaxError on Python 2 ("can't assign to ()"), so disrobe's `[]`
/// is the only recompilable form (proven: `unpack_empty.2.7`/`chain_assignment.2.7` flipped to
/// RecompileEquiv) and also matches the original `[] = ...` source - another disrobe WIN over the golden.
/// Never lower these except for a recompile-proven golden divergence documented here.
const TOKEN_MATCH_FLOOR_1X: usize = 25;
const TOKEN_MATCH_FLOOR_2X: usize = 80;
const TOKEN_MATCH_FLOOR_3X: usize = 67;

/// Fixtures where disrobe's recovered source is byte-for-byte source-correct (verified by the
/// `legacy_recompile` oracle against the ORIGINAL `.py`) but the vendored pycdc golden is objectively
/// worse: pycdc wraps tuple subscripts in spurious parentheses (`testme[(40, 41, 42)]` for source
/// `testme[40, 41, 42]`). Degrading disrobe's output to reproduce the pycdc bug would be wrong, so per
/// the source-grading directive these are graded against the vendored SOURCE tokens instead.
const SOURCE_GRADED_FIXTURES: &[&str] = &[
    "test_del.1.5",
    "test_del.2.2",
    "test_slices.1.5",
    "test_slices.2.2",
];

#[derive(Debug, Clone, Copy, Default)]
struct EraCounts {
    decoded: usize,
    decode_failed: usize,
    token_match: usize,
    token_diff: usize,
    total: usize,
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile =
        read_pyc(&bytes).map_err(|e: disrobe_py_marshal::Error| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn test_name(pyc_name: &str) -> String {
    let no_ext: &str = pyc_name.strip_suffix(".pyc").unwrap_or(pyc_name);
    let parts: Vec<&str> = no_ext.rsplitn(3, '.').collect();
    if parts.len() == 3 {
        parts[2].to_owned()
    } else {
        no_ext.to_owned()
    }
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n").trim_end().to_owned()
}

const fn era_key(ver: MarshalVersion) -> &'static str {
    match ver.major {
        1 => "1.x",
        2 => "2.x",
        _ => "3.x",
    }
}

#[test]
fn legacy_decode_and_token_equivalence() {
    let compiled: PathBuf = PathBuf::from(COMPILED_DIR);
    assert!(
        compiled.is_dir(),
        "vendored legacy corpus missing at {}",
        compiled.display()
    );
    let mut files: Vec<PathBuf> = fs::read_dir(&compiled)
        .expect("read compiled dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("pyc"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 150,
        "expected >= 150 vendored legacy fixtures, got {}",
        files.len()
    );

    let mut per_era: BTreeMap<&'static str, EraCounts> = BTreeMap::new();
    let mut decode_failures: Vec<String> = Vec::new();
    let mut diff_keys: Vec<String> = Vec::new();

    for pyc in &files {
        let name: String = pyc.file_name().unwrap().to_string_lossy().into_owned();
        let (code, ver): (CodeObject, MarshalVersion) = match read_code(pyc) {
            Ok(c) => c,
            Err(e) => {
                decode_failures.push(format!("{name}: {e}"));
                continue;
            }
        };
        let era: &'static str = era_key(ver);
        let counts: &mut EraCounts = per_era.entry(era).or_default();
        counts.total += 1;

        let dver: DecompileVersion = match marshal_to_decompile(ver) {
            Ok(v) => v,
            Err(e) => {
                counts.decode_failed += 1;
                decode_failures.push(format!("{name}: version map {e:?}"));
                continue;
            }
        };
        let recovered: String = match build_real_source(&code, &dver, ver) {
            Ok(s) => s,
            Err(e) => {
                counts.decode_failed += 1;
                decode_failures.push(format!("{name} ({}.{}): {e}", ver.major, ver.minor));
                continue;
            }
        };
        counts.decoded += 1;

        let stem: String = test_name(&name);
        let fixture_key: &str = name.strip_suffix(".pyc").unwrap_or(&name);
        let reference: Option<String> = if SOURCE_GRADED_FIXTURES.contains(&fixture_key) {
            fs::read_to_string(PathBuf::from(SOURCE_DIR).join(format!("{stem}.py"))).ok()
        } else {
            fs::read_to_string(PathBuf::from(GOLDEN_DIR).join(format!("{stem}.txt"))).ok()
        };
        let Some(reference): Option<String> = reference else {
            continue;
        };
        let source_graded: bool = SOURCE_GRADED_FIXTURES.contains(&fixture_key);
        let reference_render: String = if source_graded {
            let reference_lf: String = reference.replace("\r\n", "\n");
            let Ok(ref_tokens) = tokenize(&reference_lf) else {
                counts.token_diff += 1;
                continue;
            };
            render(&ref_tokens)
        } else {
            reference
        };
        let Ok(tokens) = tokenize(&recovered) else {
            counts.token_diff += 1;
            continue;
        };
        if normalize(&render(&tokens)) == normalize(&reference_render) {
            counts.token_match += 1;
        } else {
            counts.token_diff += 1;
            diff_keys.push(format!("{era} {fixture_key}"));
        }
    }
    diff_keys.sort();
    println!("=== TOKEN_DIFF fixtures (vs golden unless source-graded) ===");
    for k in &diff_keys {
        println!("  DIFF {k}");
    }

    let mut total_match: usize = 0;
    let mut total_decoded: usize = 0;
    println!("=== LEGACY TIER-B (vendored pycdc known_open corpus) ===");
    for (era, c) in &per_era {
        total_match += c.token_match;
        total_decoded += c.decoded;
        println!(
            "  era {era:<4} decoded={}/{} decode_fail={} token_match={} token_diff={}",
            c.decoded, c.total, c.decode_failed, c.token_match, c.token_diff
        );
    }
    println!(
        "  TOTAL decoded={total_decoded} token_match={total_match} decode_failures={}",
        decode_failures.len()
    );

    assert!(
        decode_failures.is_empty(),
        "{} legacy decode failures (#22 marshal/structure gaps); each must be fixed, not deferred:\n{}",
        decode_failures.len(),
        decode_failures.join("\n")
    );

    let match_1x: usize = per_era.get("1.x").map_or(0, |c| c.token_match);
    let match_2x: usize = per_era.get("2.x").map_or(0, |c| c.token_match);
    let match_3x: usize = per_era.get("3.x").map_or(0, |c| c.token_match);
    assert!(
        match_1x >= TOKEN_MATCH_FLOOR_1X,
        "1.x token-equivalence regressed: {match_1x} < floor {TOKEN_MATCH_FLOOR_1X}"
    );
    assert!(
        match_2x >= TOKEN_MATCH_FLOOR_2X,
        "2.x token-equivalence regressed: {match_2x} < floor {TOKEN_MATCH_FLOOR_2X}"
    );
    assert!(
        match_3x >= TOKEN_MATCH_FLOOR_3X,
        "3.x token-equivalence regressed: {match_3x} < floor {TOKEN_MATCH_FLOOR_3X}"
    );
}

/// The vendored `xfail/` fixtures are pycdc's own known-open corpus: real legacy `.pyc` files that pycdc
/// itself cannot fully decompile. disrobe must still DECODE them (`read_pyc` + marshal + frame tree +
/// AST + emit) without crashing - that is the #22 exerciser. Token equivalence is not required here
/// (these are expected-fail upstream), but a decode crash on a real legacy `.pyc` is a hard #22 gap.
#[test]
fn legacy_xfail_corpus_decodes_without_crash() {
    let xfail: PathBuf = PathBuf::from("../../corpus/python/decompile/legacy/xfail");
    assert!(xfail.is_dir(), "vendored xfail corpus missing");
    let mut files: Vec<PathBuf> = fs::read_dir(&xfail)
        .expect("read xfail dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("pyc"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no xfail fixtures vendored");

    let mut failures: Vec<String> = Vec::new();
    let mut decoded: usize = 0;
    for pyc in &files {
        let name: String = pyc.file_name().unwrap().to_string_lossy().into_owned();
        let (code, ver): (CodeObject, MarshalVersion) = match read_code(pyc) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("{name}: {e}"));
                continue;
            }
        };
        let dver: DecompileVersion = match marshal_to_decompile(ver) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{name}: version map {e:?}"));
                continue;
            }
        };
        match build_real_source(&code, &dver, ver) {
            Ok(_) => decoded += 1,
            Err(e) => failures.push(format!("{name} ({}.{}): {e}", ver.major, ver.minor)),
        }
    }
    println!("=== LEGACY XFAIL DECODE: {decoded}/{} ok ===", files.len());
    assert!(
        failures.is_empty(),
        "{} xfail fixtures failed to DECODE (#22 gap; pycdc-xfail still must not crash disrobe):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
