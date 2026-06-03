#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::io::Read as _;

use disrobe_pass_jvm::{
    ClassFile, DecompiledDex, DexFile, binary_to_source, decompile_dex, parse_classfile,
    parse_code_items, parse_dex,
};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");
const EDGECASES_BASELINE_JAR: &[u8] =
    include_bytes!("../../../corpus/jvm/megafile/EdgeCases-baseline.jar");
const EDGECASES_JAVA: &str = include_str!("../../../corpus/jvm/megafile/EdgeCases.java");

fn recovered() -> DecompiledDex {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse EdgeCases.dex");
    decompile_dex(&dex, EDGECASES_DEX)
}

fn method_body<'a>(source: &'a str, signature_head: &str) -> &'a str {
    let start: usize = source
        .find(signature_head)
        .unwrap_or_else(|| panic!("recovered source must contain `{signature_head}`"));
    let rest: &str = &source[start..];
    let end: usize = rest
        .find("\n    }")
        .map_or(rest.len(), |e| (e + 6).min(rest.len()));
    &rest[..end]
}

struct LeafCheck {
    head: &'static str,
    must_contain: &'static [&'static str],
}

#[test]
fn at_least_eight_leaf_methods_structurally_match_ground_truth() {
    let dex_out: DecompiledDex = recovered();
    let src: &str = &dex_out.source;

    let checks: [LeafCheck; 8] = [
        LeafCheck {
            head: "int gcd(",
            must_contain: &["%", "while", "Math.abs", "return"],
        },
        LeafCheck {
            head: "int fib(",
            must_contain: &["if (", "while", "return"],
        },
        LeafCheck {
            head: "long iterativeFactorial(",
            must_contain: &["*", "while", "return"],
        },
        LeafCheck {
            head: "int[] reverseArray(",
            must_contain: &["[", "while", "return"],
        },
        LeafCheck {
            head: "boolean isPalindrome(",
            must_contain: &["charAt", "while", "return"],
        },
        LeafCheck {
            head: "int countDigits(",
            must_contain: &["/", "while", "return"],
        },
        LeafCheck {
            head: "long sumDigits(",
            must_contain: &["%", "while", "return"],
        },
        LeafCheck {
            head: "int dotInt(",
            must_contain: &["[", "while", "return"],
        },
    ];

    let mut matched: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for check in &checks {
        let body: &str = method_body(src, check.head);
        let mut ok: bool = true;
        for needle in check.must_contain {
            if !body.contains(needle) {
                ok = false;
                failures.push(format!("`{}` missing `{needle}`", check.head));
            }
        }
        if ok {
            matched += 1;
        }
    }

    assert!(
        matched >= 8,
        "expected >=8 leaf methods to structurally match ground-truth bodies, matched {matched}; failures: {failures:?}"
    );
}

#[test]
fn ground_truth_java_declares_the_checked_leaf_methods() {
    for name in [
        "int gcd(",
        "int fib(",
        "long iterativeFactorial(",
        "int[] reverseArray(",
        "boolean isPalindrome(",
        "int countDigits(",
        "long sumDigits(",
        "int dotInt(",
    ] {
        assert!(
            EDGECASES_JAVA.contains(name),
            "ground-truth EdgeCases.java must declare `{name}` (anti-circular: oracle is the real source, not our emitter)"
        );
    }
}

#[test]
fn differential_floor_recovered_text_has_real_dex_identifiers() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse");
    let dex_out: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let src: &str = &dex_out.source;

    for ident in ["Math.abs", "charAt", "length"] {
        assert!(
            src.contains(ident),
            "recovered text must contain real identifier `{ident}` present in dex string/method tables"
        );
        let in_tables: bool = dex.strings.iter().any(|s| s.contains(ident))
            || dex
                .method_ids
                .iter()
                .any(|m| ident.ends_with(m.name.as_str()) && !m.name.is_empty());
        assert!(
            in_tables,
            "identifier `{ident}` must be grounded in the dex tables, not invented"
        );
    }
}

fn class_side_edgecases_methods_with_code() -> usize {
    let reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(EDGECASES_BASELINE_JAR);
    let mut zip: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(reader).expect("open baseline jar");
    for i in 0..zip.len() {
        let mut entry: zip::read::ZipFile<'_> = zip.by_index(i).expect("zip entry");
        if entry.name() != "EdgeCases.class" {
            continue;
        }
        let mut bytes: Vec<u8> = Vec::new();
        entry.read_to_end(&mut bytes).expect("read class");
        let cf: ClassFile = parse_classfile(&bytes).expect("parse EdgeCases.class");
        let mut with_code: usize = 0;
        for method in &cf.methods {
            let has_code: bool = method
                .attributes
                .iter()
                .any(|a| cf.utf8_at(a.name_index).is_ok_and(|n| n == "Code"));
            if has_code {
                with_code += 1;
            }
        }
        return with_code;
    }
    panic!("EdgeCases.class not found in baseline jar");
}

#[test]
fn d8_invertibility_method_count_matches_class_front_end() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse dex");
    let items = parse_code_items(&dex, EDGECASES_DEX);
    let dex_side: usize = items
        .iter()
        .filter(|it| binary_to_source(&it.class) == "EdgeCases")
        .count();

    let class_side: usize = class_side_edgecases_methods_with_code();

    let diff: usize = dex_side.abs_diff(class_side);
    assert!(
        diff <= 1,
        "two independent front-ends (dex lifter vs class lifter) must agree on EdgeCases method-with-code count within 1; dex_side={dex_side} class_side={class_side}"
    );
    eprintln!(
        "d8-invertibility: dex_side={dex_side} class_side={class_side} (diff {diff}) over one ground-truth source"
    );
}

#[test]
fn kotlin_dex_decompiles_without_panic() {
    let dex: DexFile = parse_dex(EDGECASES_KT_DEX).expect("parse EdgeCasesKt.dex");
    let out: DecompiledDex = decompile_dex(&dex, EDGECASES_KT_DEX);
    assert!(
        out.class_count > 0,
        "kotlin dex must yield at least one class"
    );
    assert!(
        out.method_count > 0,
        "kotlin dex must yield at least one method body"
    );
}

#[test]
fn whole_dex_decompiles_without_irreducible_blowup() {
    let dex_out: DecompiledDex = recovered();
    assert!(
        dex_out.method_count > 100,
        "EdgeCases.dex must yield a non-trivial method corpus, got {}",
        dex_out.method_count
    );
    assert!(
        dex_out.source.len() < 8 * 1024 * 1024,
        "recovered source must stay bounded (dup-bomb guard), got {} bytes",
        dex_out.source.len()
    );
    let fully: f64 = dex_out.fully_lifted_methods as f64 / dex_out.method_count as f64 * 100.0;
    eprintln!(
        "dalvik decompile: {}/{} fully-structured = {:.1}%",
        dex_out.fully_lifted_methods, dex_out.method_count, fully
    );
    assert!(
        fully >= 90.0,
        ">=90% of methods must structure without irreducible fallback, got {fully:.1}%"
    );
}
