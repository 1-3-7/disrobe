#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_pass_nuitka::{ConstantsPool, decode_const_file};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct GroundTruth {
    identifiers: BTreeSet<String>,
    ints: BTreeSet<i64>,
}

fn demangle_segment(seg: &str) -> Option<String> {
    match seg {
        "" => None,
        "underscore" => Some("_".to_owned()),
        other => Some(other.to_owned()),
    }
}

fn ingest_const_symbol(symbol: &str, gt: &mut GroundTruth) {
    if let Some(rest) = symbol.strip_prefix("str_plain_") {
        if let Some(id) = demangle_segment(rest) {
            gt.identifiers.insert(id);
        }
        return;
    }
    if let Some(rest) = symbol.strip_prefix("str_angle_") {
        if let Some(inner) = demangle_segment(rest) {
            gt.identifiers.insert(format!("<{inner}>"));
        }
        return;
    }
    if let Some(rest) = symbol.strip_prefix("int_pos_") {
        if let Ok(n) = rest.parse::<i64>() {
            gt.ints.insert(n);
        }
        return;
    }
    if let Some(rest) = symbol.strip_prefix("int_neg_") {
        if let Ok(n) = rest.parse::<i64>() {
            gt.ints.insert(-n);
        }
        return;
    }
    if let Some(rest) = symbol.strip_prefix("int_") {
        if let Ok(n) = rest.parse::<i64>() {
            gt.ints.insert(n);
        }
        return;
    }
    if let Some(rest) = symbol.strip_prefix("tuple_") {
        ingest_tuple_symbol(rest, gt);
    }
}

fn ingest_tuple_symbol(body: &str, gt: &mut GroundTruth) {
    let inner: &str = body.strip_suffix("_tuple").unwrap_or(body);
    let tokens: Vec<&str> = inner.split('_').collect();
    let mut idx: usize = 0;
    while idx < tokens.len() {
        match tokens[idx] {
            "str" if idx + 1 < tokens.len() && tokens[idx + 1] == "plain" => {
                if let Some(name) = tokens.get(idx + 2)
                    && let Some(id) = demangle_segment(name)
                {
                    gt.identifiers.insert(id);
                }
                idx += 3;
            }
            "str" if idx + 1 < tokens.len() && tokens[idx + 1] == "underscore" => {
                gt.identifiers.insert("_".to_owned());
                idx += 2;
            }
            "int" if idx + 1 < tokens.len() && tokens[idx + 1] == "pos" => {
                if let Some(num) = tokens.get(idx + 2)
                    && let Ok(n) = num.parse::<i64>()
                {
                    gt.ints.insert(n);
                }
                idx += 3;
            }
            "int" if idx + 1 < tokens.len() && tokens[idx + 1] == "neg" => {
                if let Some(num) = tokens.get(idx + 2)
                    && let Ok(n) = num.parse::<i64>()
                {
                    gt.ints.insert(-n);
                }
                idx += 3;
            }
            "int" => {
                if let Some(num) = tokens.get(idx + 1)
                    && let Ok(n) = num.parse::<i64>()
                {
                    gt.ints.insert(n);
                }
                idx += 2;
            }
            _ => idx += 1,
        }
    }
}

fn ground_truth_from_c_source(c_source: &str) -> GroundTruth {
    let mut gt: GroundTruth = GroundTruth::default();
    for line in c_source.lines() {
        let trimmed: &str = line.trim();
        let Some(decl) = trimmed.strip_prefix("PyObject *const_") else {
            continue;
        };
        let symbol: &str = decl.trim_end_matches(';').trim();
        if symbol.contains("digest") || symbol.starts_with("dict_") {
            continue;
        }
        ingest_const_symbol(symbol, &mut gt);
    }
    gt
}

fn annotation_identifiers_from_pyi(pyi_source: &str) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for line in pyi_source.lines() {
        let trimmed: &str = line.trim_start();
        let Some(after_def) = trimmed.strip_prefix("def ") else {
            continue;
        };
        let Some(paren) = after_def.find('(') else {
            continue;
        };
        let params: &str = &after_def[paren + 1..];
        for chunk in params.split([',', ')', '(', ':', '-', '>', ' ']) {
            let token: &str = chunk.trim();
            if matches!(token, "str" | "int" | "bool" | "float" | "bytes") {
                ids.insert(token.to_owned());
            }
        }
        if after_def.contains("-> str") {
            ids.insert("str".to_owned());
        }
        if after_def.contains("-> int") {
            ids.insert("int".to_owned());
        }
    }
    ids
}

fn ground_truth(c_path: &Path, pyi_path: Option<&Path>) -> GroundTruth {
    let c_source: String = std::fs::read_to_string(c_path).expect("read .c ground-truth source");
    let mut gt: GroundTruth = ground_truth_from_c_source(&c_source);
    if let Some(pyi) = pyi_path {
        let pyi_source: String = std::fs::read_to_string(pyi).expect("read .pyi ground truth");
        gt.identifiers
            .extend(annotation_identifiers_from_pyi(&pyi_source));
    }
    gt
}

fn string_digests_from_c_source(c_path: &Path) -> BTreeSet<String> {
    let c_source: String = std::fs::read_to_string(c_path).expect("read .c ground-truth source");
    c_source
        .lines()
        .filter_map(|line: &str| {
            line.trim()
                .strip_prefix("PyObject *const_str_digest_")
                .map(|digest: &str| digest.trim_end_matches(';').trim().to_owned())
        })
        .collect()
}

fn assert_exact_ints_and_digests(pool: &ConstantsPool, gt: &GroundTruth, c_path: &Path) {
    assert_eq!(
        pool.ints,
        gt.ints,
        "recovered ints must equal the int constants the compiler declared in {}",
        c_path.display()
    );
    let declared: BTreeSet<String> = string_digests_from_c_source(c_path);
    let unresolved: Vec<&String> = declared
        .iter()
        .filter(|digest: &&String| !pool.digest_to_string.contains_key(digest.as_str()))
        .collect();
    assert!(
        !declared.is_empty() && unresolved.is_empty(),
        "every const_str_digest_ symbol declared in {} must resolve to a recovered string; \
         unresolved {unresolved:?} of {declared:?}",
        c_path.display()
    );
}

fn assert_pool_superset(pool: &ConstantsPool, gt: &GroundTruth) {
    let missing_ids: Vec<&String> = gt
        .identifiers
        .iter()
        .filter(|id: &&String| !pool.strings.contains(id.as_str()))
        .collect();
    assert!(
        missing_ids.is_empty(),
        "recovered strings missing source identifiers {missing_ids:?}; recovered={:?}",
        pool.strings
    );

    let missing_ints: Vec<&i64> = gt
        .ints
        .iter()
        .filter(|n: &&i64| !pool.ints.contains(n))
        .collect();
    assert!(
        missing_ints.is_empty(),
        "recovered ints missing source ints {missing_ints:?}; recovered={:?}",
        pool.ints
    );
}

#[test]
fn ground_truth_extractor_is_nonempty_and_parser_independent() {
    let c_path: PathBuf = common::tracked("module/hello.build/module.hello.c");
    let pyi_path: PathBuf = common::tracked("module/hello.pyi");
    let gt: GroundTruth = ground_truth(&c_path, Some(&pyi_path));
    assert!(
        gt.identifiers.len() >= 6,
        "C ModuleConstants struct must yield real identifiers, got {:?}",
        gt.identifiers
    );
    for required in ["greet", "fib", "main", "disrobe", "a", "n", "b", "_"] {
        assert!(
            gt.identifiers.contains(required),
            "ground truth from compiler artifacts missing {required:?}: {:?}",
            gt.identifiers
        );
    }
    assert!(gt.ints.contains(&0));
    assert!(gt.ints.contains(&1));
    assert!(gt.ints.contains(&2));
    assert!(gt.ints.contains(&20));
}

#[test]
fn module_const_recovery_is_superset_of_compiler_ground_truth() {
    let const_path: PathBuf = common::tracked("module/hello.build/module.hello.const");
    let c_path: PathBuf = common::tracked("module/hello.build/module.hello.c");
    let pyi_path: PathBuf = common::tracked("module/hello.pyi");

    let bytes: Vec<u8> = std::fs::read(&const_path).expect("read module.hello.const");
    let pool: ConstantsPool = decode_const_file(&bytes, "module.hello.const", "hello")
        .expect("decode module.hello.const");

    assert_eq!(
        pool.bytes_consumed,
        bytes.len(),
        "shared-memo decode must consume every byte (a per-stream memo reset drops trailing streams)"
    );

    let gt: GroundTruth = ground_truth(&c_path, Some(&pyi_path));
    assert_pool_superset(&pool, &gt);
    assert_exact_ints_and_digests(&pool, &gt, &c_path);

    assert!(
        pool.globals
            .contains(&("builtins".to_owned(), "str".to_owned()))
    );
    assert!(
        pool.globals
            .contains(&("builtins".to_owned(), "int".to_owned()))
    );
}

#[test]
fn console_disable_const_recovery_is_superset_of_compiler_ground_truth() {
    let const_path: PathBuf = common::tracked("console-disable/hello.build/module.__main__.const");
    let c_path: PathBuf = common::tracked("console-disable/hello.build/module.__main__.c");

    let bytes: Vec<u8> = std::fs::read(&const_path).expect("read module.__main__.const");
    let pool: ConstantsPool = decode_const_file(&bytes, "module.__main__.const", "__main__")
        .expect("decode module.__main__.const");

    assert_eq!(
        pool.bytes_consumed,
        bytes.len(),
        "shared-memo decode must consume every byte"
    );

    let gt: GroundTruth = ground_truth(&c_path, None);
    assert_pool_superset(&pool, &gt);
    assert_exact_ints_and_digests(&pool, &gt, &c_path);
    for planted in [
        "MARKER",
        "DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c",
        "greet",
        "fib",
        "main",
    ] {
        assert!(
            gt.identifiers.contains(planted),
            "the regen.ps1 source names {planted:?}, so the C ground truth must declare it: {:?}",
            gt.identifiers
        );
    }
}

#[test]
fn ground_truth_uses_real_source_symbols_not_parser_echo() {
    let c_path: PathBuf = common::tracked("module/hello.build/module.hello.c");
    let const_path: PathBuf = common::tracked("module/hello.build/module.hello.const");
    let pyi_path: PathBuf = common::tracked("module/hello.pyi");
    let gt: GroundTruth = ground_truth(&c_path, Some(&pyi_path));
    let bytes: Vec<u8> = std::fs::read(&const_path).expect("read const");
    let pool: ConstantsPool =
        decode_const_file(&bytes, "module.hello.const", "hello").expect("decode");

    assert!(
        gt.identifiers
            .iter()
            .all(|id: &String| pool.strings.contains(id.as_str())),
        "ground truth identifiers must be a subset of recovered strings"
    );
    assert!(
        pool.strings.len() > gt.identifiers.len(),
        "recovered pool surfaces digest-named literals absent from the C-symbol ground truth, \
         proving the assertion target is the compiler artifact, not the parser's own emission"
    );
}
