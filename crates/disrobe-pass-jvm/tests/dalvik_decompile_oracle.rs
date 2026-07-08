#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::collections::BTreeSet;
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

const LEAF_METHOD_NAMES: [&str; 8] = [
    "gcd",
    "fib",
    "iterativeFactorial",
    "reverseArray",
    "isPalindrome",
    "countDigits",
    "sumDigits",
    "dotInt",
];

fn recovered() -> DecompiledDex {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse EdgeCases.dex");
    decompile_dex(&dex, EDGECASES_DEX)
}

fn recovered_body<'a>(source: &'a str, method_name: &str) -> Option<&'a str> {
    let needle: String = format!(" {method_name}(");
    let start: usize = source.find(&needle)?;
    let line_start: usize = source[..start].rfind('\n').map_or(0, |n| n + 1);
    let rest: &str = &source[line_start..];
    let end: usize = rest
        .find("\n    }")
        .map_or(rest.len(), |e| (e + 6).min(rest.len()));
    Some(&rest[..end])
}

struct GroundTruthMethod {
    name: String,
    return_type: String,
    param_types: Vec<String>,
    loop_count: usize,
    has_branch: bool,
    operators: BTreeSet<char>,
    callsites: BTreeSet<String>,
}

fn ground_truth_method(source: &str, method_name: &str) -> GroundTruthMethod {
    let decl_needle: String = format!(" {method_name}(");
    let decl_at: usize = source
        .find(&decl_needle)
        .unwrap_or_else(|| panic!("ground-truth EdgeCases.java must declare `{method_name}`"));
    let line_start: usize = source[..decl_at].rfind('\n').map_or(0, |n| n + 1);
    let sig_end: usize = source[decl_at..]
        .find(')')
        .map(|o| decl_at + o)
        .expect("method signature must close its parameter list");
    let signature: &str = &source[line_start..sig_end];

    let name_pos: usize = signature
        .rfind(&decl_needle)
        .expect("signature contains the method name");
    let head: &str = signature[..name_pos].trim();
    let return_type: String = head
        .split_whitespace()
        .last()
        .expect("declaration carries a return type")
        .to_string();

    let params_src: &str = &signature[name_pos + decl_needle.len()..];
    let param_types: Vec<String> = params_src
        .split(',')
        .filter_map(|raw: &str| {
            let trimmed: &str = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            let ty: &str = trimmed
                .rsplit_once(char::is_whitespace)
                .map_or(trimmed, |(ty, _name)| ty);
            Some(ty.to_string())
        })
        .collect();

    let body_open: usize = source[sig_end..]
        .find('{')
        .map(|o| sig_end + o)
        .expect("method body opens with a brace");
    let mut depth: i32 = 0;
    let mut body_close: usize = source.len();
    for (offset, ch) in source[body_open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    body_close = body_open + offset + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let body: &str = &source[body_open..body_close];

    let loop_count: usize = count_keyword(body, "for") + count_keyword(body, "while");
    let has_branch: bool =
        count_keyword(body, "if") > 0 || count_keyword(body, "switch") > 0 || body.contains('?');

    let operators: BTreeSet<char> = body
        .chars()
        .filter(|c: &char| matches!(c, '%' | '/' | '*'))
        .collect();

    let mut callsites: BTreeSet<String> = BTreeSet::new();
    for probe in ["Math.abs", "charAt", "length"] {
        if body.contains(probe) {
            callsites.insert(probe.to_string());
        }
    }

    GroundTruthMethod {
        name: method_name.to_string(),
        return_type,
        param_types,
        loop_count,
        has_branch,
        operators,
        callsites,
    }
}

fn count_keyword(haystack: &str, keyword: &str) -> usize {
    let bytes: &[u8] = haystack.as_bytes();
    let klen: usize = keyword.len();
    let mut count: usize = 0;
    let mut idx: usize = 0;
    while let Some(found) = haystack[idx..].find(keyword) {
        let abs: usize = idx + found;
        let before_ok: bool = abs == 0 || !is_ident_byte(bytes[abs - 1]);
        let after: usize = abs + klen;
        let after_ok: bool = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if before_ok && after_ok {
            count += 1;
        }
        idx = abs + klen;
    }
    count
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn recovered_operators(body: &str) -> BTreeSet<char> {
    body.chars()
        .filter(|c: &char| matches!(c, '%' | '/' | '*'))
        .collect()
}

fn recovered_callsites(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for probe in ["Math.abs", "charAt", "length"] {
        if body.contains(probe) {
            out.insert(probe.to_string());
        }
    }
    out
}

struct StructuralVerdict {
    name: String,
    signature_ok: bool,
    loop_ok: bool,
    branch_ok: bool,
    operators_ok: bool,
    callsites_ok: bool,
    core_reasons: Vec<String>,
    callsite_reasons: Vec<String>,
}

impl StructuralVerdict {
    const fn core_ok(&self) -> bool {
        self.signature_ok && self.loop_ok && self.branch_ok && self.operators_ok
    }

    const fn full_ok(&self) -> bool {
        self.core_ok() && self.callsites_ok
    }
}

fn grade(gt: &GroundTruthMethod, body: &str) -> StructuralVerdict {
    let mut core_reasons: Vec<String> = Vec::new();

    let signature_ok: bool = signature_matches(gt, body, &mut core_reasons);

    let recovered_loops: usize = count_keyword(body, "for") + count_keyword(body, "while");
    let loop_ok: bool = recovered_loops >= gt.loop_count;
    if !loop_ok {
        core_reasons.push(format!(
            "loop count {recovered_loops} < ground-truth {}",
            gt.loop_count
        ));
    }

    let recovered_branch: bool = count_keyword(body, "if") > 0 || count_keyword(body, "switch") > 0;
    let branch_ok: bool = !gt.has_branch || recovered_branch;
    if !branch_ok {
        core_reasons.push("ground-truth branches but recovered body has none".to_string());
    }

    let recovered_ops: BTreeSet<char> = recovered_operators(body);
    let missing_ops: Vec<char> = gt
        .operators
        .iter()
        .copied()
        .filter(|op: &char| !recovered_ops.contains(op))
        .collect();
    let operators_ok: bool = missing_ops.is_empty();
    if !operators_ok {
        core_reasons.push(format!("missing operators {missing_ops:?}"));
    }

    let mut callsite_reasons: Vec<String> = Vec::new();
    let recovered_calls: BTreeSet<String> = recovered_callsites(body);
    let missing_calls: Vec<String> = gt
        .callsites
        .iter()
        .filter(|c: &&String| !recovered_calls.contains(*c))
        .cloned()
        .collect();
    let callsites_ok: bool = missing_calls.is_empty();
    if !callsites_ok {
        callsite_reasons.push(format!("callsite text not reconstructed {missing_calls:?}"));
    }

    StructuralVerdict {
        name: gt.name.clone(),
        signature_ok,
        loop_ok,
        branch_ok,
        operators_ok,
        callsites_ok,
        core_reasons,
        callsite_reasons,
    }
}

fn signature_matches(gt: &GroundTruthMethod, body: &str, reasons: &mut Vec<String>) -> bool {
    let header: &str = body.lines().next().unwrap_or_default();
    let mut ok: bool = true;

    let expected_head: String = format!("{} {}(", gt.return_type, gt.name);
    if !header.contains(&expected_head) {
        ok = false;
        reasons.push(format!(
            "signature head `{expected_head}` absent from `{header}`"
        ));
    }

    let open: usize = header.find('(').unwrap_or(header.len());
    let close: usize = header.rfind(')').unwrap_or(header.len());
    if open < close {
        let params: &str = &header[open + 1..close];
        let recovered_types: Vec<String> = params
            .split(',')
            .filter_map(|raw: &str| {
                let trimmed: &str = raw.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let ty: &str = trimmed
                    .rsplit_once(char::is_whitespace)
                    .map_or(trimmed, |(ty, _name)| ty);
                Some(ty.to_string())
            })
            .collect();
        if recovered_types != gt.param_types {
            ok = false;
            reasons.push(format!(
                "param types {recovered_types:?} != ground-truth {:?}",
                gt.param_types
            ));
        }
    } else {
        ok = false;
        reasons.push("recovered signature has no parameter list".to_string());
    }

    ok
}

#[test]
fn ground_truth_java_declares_the_checked_leaf_methods() {
    for name in LEAF_METHOD_NAMES {
        let needle: String = format!(" {name}(");
        assert!(
            EDGECASES_JAVA.contains(&needle),
            "ground-truth EdgeCases.java must declare `{name}` (anti-circular: oracle is the real source, not our emitter)"
        );
    }
}

const CALLSITE_RECONSTRUCTION_FLOOR: usize = 8;

#[test]
fn leaf_methods_match_real_java_structure() {
    let dex_out: DecompiledDex = recovered();
    let src: &str = &dex_out.source;

    let mut core_correct: usize = 0;
    let mut full_correct: usize = 0;
    let mut verdicts: Vec<StructuralVerdict> = Vec::new();

    for name in LEAF_METHOD_NAMES {
        let gt: GroundTruthMethod = ground_truth_method(EDGECASES_JAVA, name);
        match recovered_body(src, name) {
            Some(body) => {
                let verdict: StructuralVerdict = grade(&gt, body);
                if verdict.core_ok() {
                    core_correct += 1;
                }
                if verdict.full_ok() {
                    full_correct += 1;
                }
                verdicts.push(verdict);
            }
            None => verdicts.push(StructuralVerdict {
                name: name.to_string(),
                signature_ok: false,
                loop_ok: false,
                branch_ok: false,
                operators_ok: false,
                callsites_ok: false,
                core_reasons: vec!["recovered source does not emit this method".to_string()],
                callsite_reasons: Vec::new(),
            }),
        }
    }

    let total: usize = LEAF_METHOD_NAMES.len();
    eprintln!(
        "dalvik->source vs real EdgeCases.java: core structure (sig+cfg+operators) {}/{} = {:.1}%, full fidelity (+callsite text) {}/{} = {:.1}%",
        core_correct,
        total,
        core_correct as f64 / total as f64 * 100.0,
        full_correct,
        total,
        full_correct as f64 / total as f64 * 100.0
    );
    for verdict in &verdicts {
        if !verdict.full_ok() {
            eprintln!(
                "  gap `{}`: sig={} loop={} branch={} ops={} calls={} :: {}{}",
                verdict.name,
                verdict.signature_ok,
                verdict.loop_ok,
                verdict.branch_ok,
                verdict.operators_ok,
                verdict.callsites_ok,
                verdict.core_reasons.join("; "),
                verdict.callsite_reasons.join("; ")
            );
        }
    }

    let core_failures: Vec<String> = verdicts
        .iter()
        .filter(|v: &&StructuralVerdict| !v.core_ok())
        .map(|v: &StructuralVerdict| format!("{}: {}", v.name, v.core_reasons.join("; ")))
        .collect();

    assert_eq!(
        core_correct, total,
        "every leaf method must match the real EdgeCases.java core structure (signature + control-flow shape + arithmetic operators), graded against the source not our emitter; drops: {core_failures:?}"
    );

    assert!(
        full_correct >= CALLSITE_RECONSTRUCTION_FLOOR,
        "callsite reconstruction regressed below the measured floor {CALLSITE_RECONSTRUCTION_FLOOR}/{total}; got {full_correct}/{total}. array-length and Math.abs callsites both cross a basic-block boundary between where the value is computed and where it is read; this floor pins full recovery of all 8 leaf methods and fails on regression"
    );
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
fn two_front_ends_agree_on_edgecases_method_count() {
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
        "two independent front-ends (dex lifter vs javac-baseline class lifter) must agree on EdgeCases method-with-code count within 1; dex_side={dex_side} class_side={class_side}"
    );
    eprintln!(
        "front-end cross-check: dex_side={dex_side} class_side={class_side} (diff {diff}) against the javac baseline"
    );
}

#[test]
fn kotlin_dex_recovers_the_top_level_class_and_bodies() {
    let dex: DexFile = parse_dex(EDGECASES_KT_DEX).expect("parse EdgeCasesKt.dex");
    let out: DecompiledDex = decompile_dex(&dex, EDGECASES_KT_DEX);

    let facade_present: bool = dex
        .class_descriptors
        .iter()
        .any(|d: &String| binary_to_source(d).ends_with("EdgeCasesKt"));
    assert!(
        facade_present,
        "kotlin dex must carry the compiled EdgeCasesKt facade class"
    );
    assert!(
        out.source.contains("class EdgeCasesKt") || out.source.contains("EdgeCasesKt"),
        "recovered kotlin source must name the EdgeCasesKt class it was compiled from"
    );
    assert!(
        out.method_count >= class_side_edgecases_methods_with_code() / 4,
        "kotlin recovery must lift a non-trivial body corpus, got {}",
        out.method_count
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
