#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic
)]

use disrobe_pass_jvm::{
    CodeItem, DalvikMethodCfg, NaturalLoop, Region, Structurer, build_dalvik_cfg_from_code_item,
    compute_dominators, find_natural_loops, parse_code_items, parse_dex,
};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");

fn code_items() -> Vec<CodeItem> {
    let dex = parse_dex(EDGECASES_DEX).expect("parse edgecases.dex");
    parse_code_items(&dex, EDGECASES_DEX)
}

fn structure_method(item: &CodeItem) -> (Region, bool) {
    let built: DalvikMethodCfg = build_dalvik_cfg_from_code_item(item).expect("build dalvik cfg");
    let dom = compute_dominators(&built.cfg).expect("dominators");
    let loops: Vec<NaturalLoop> = find_natural_loops(&built.cfg, &dom);
    let mut s: Structurer<'_> =
        Structurer::with_switch_map(&built.cfg, &dom, &loops, &[], built.switch_map);
    let root: Region = s.structure();
    (root, s.had_irreducible)
}

fn find(items: &[CodeItem], name: &str) -> CodeItem {
    items
        .iter()
        .find(|i| i.method_name == name)
        .cloned()
        .unwrap_or_else(|| panic!("method {name} present in EdgeCases.dex"))
}

fn count_while(region: &Region, acc: &mut usize) {
    match region {
        Region::While { body, .. } | Region::DoWhile { body, .. } => {
            *acc += 1;
            count_while(body, acc);
        }
        Region::Sequence(seq) => {
            for r in seq {
                count_while(r, acc);
            }
        }
        Region::IfThen { then_body, .. } => count_while(then_body, acc),
        Region::IfThenElse {
            then_body,
            else_body,
            ..
        } => {
            count_while(then_body, acc);
            count_while(else_body, acc);
        }
        Region::Switch { cases, default, .. } => {
            for (_, r) in cases {
                count_while(r, acc);
            }
            if let Some(d) = default {
                count_while(d, acc);
            }
        }
        Region::Try { try_body, handlers } => {
            count_while(try_body, acc);
            for (_, r) in handlers {
                count_while(r, acc);
            }
        }
        Region::Block(_) | Region::Irreducible { .. } => {}
    }
}

fn find_try_handlers(region: &Region) -> Option<Vec<Option<String>>> {
    match region {
        Region::Try { handlers, .. } => Some(handlers.iter().map(|(t, _)| t.clone()).collect()),
        Region::Sequence(seq) => seq.iter().find_map(find_try_handlers),
        Region::IfThen { then_body, .. } => find_try_handlers(then_body),
        Region::IfThenElse {
            then_body,
            else_body,
            ..
        } => find_try_handlers(then_body).or_else(|| find_try_handlers(else_body)),
        Region::While { body, .. } | Region::DoWhile { body, .. } => find_try_handlers(body),
        Region::Switch { cases, default, .. } => cases
            .iter()
            .find_map(|(_, r)| find_try_handlers(r))
            .or_else(|| default.as_deref().and_then(find_try_handlers)),
        Region::Block(_) | Region::Irreducible { .. } => None,
    }
}

#[test]
fn gcd_structures_to_exactly_one_while() {
    let items: Vec<CodeItem> = code_items();
    let gcd: CodeItem = find(&items, "gcd");
    let (region, irreducible): (Region, bool) = structure_method(&gcd);
    assert!(
        !irreducible,
        "gcd must structure cleanly without irreducible fallback"
    );
    let mut whiles: usize = 0;
    count_while(&region, &mut whiles);
    assert_eq!(
        whiles, 1,
        "gcd source `while (b != 0) {{ t=b; b=a%b; a=t; }}` must yield exactly one While region"
    );
}

#[test]
fn divsafe_contains_try_with_arithmetic_handler() {
    let items: Vec<CodeItem> = code_items();
    let divsafe: CodeItem = find(&items, "divSafe");
    assert_eq!(divsafe.tries.len(), 1, "divSafe has exactly one try region");
    let (region, irreducible): (Region, bool) = structure_method(&divsafe);
    assert!(
        !irreducible,
        "divSafe must structure without irreducible fallback"
    );
    let handlers: Vec<Option<String>> =
        find_try_handlers(&region).expect("divSafe must produce a Try region");
    assert!(
        handlers
            .iter()
            .any(|t| t.as_deref() == Some("Ljava/lang/ArithmeticException;")),
        "divSafe try must carry an ArithmeticException handler, got {handlers:?}"
    );
}

#[test]
fn ninety_percent_of_edgecases_methods_are_reducible() {
    let items: Vec<CodeItem> = code_items();
    let mut total: usize = 0;
    let mut reducible: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for item in &items {
        let Some(built): Option<DalvikMethodCfg> = build_dalvik_cfg_from_code_item(item) else {
            continue;
        };
        let Ok(dom) = compute_dominators(&built.cfg) else {
            continue;
        };
        let loops: Vec<NaturalLoop> = find_natural_loops(&built.cfg, &dom);
        let mut s: Structurer<'_> =
            Structurer::with_switch_map(&built.cfg, &dom, &loops, &[], built.switch_map);
        let _root: Region = s.structure();
        total += 1;
        if s.had_irreducible {
            failures.push(format!("{}.{}", item.class, item.method_name));
        } else {
            reducible += 1;
        }
    }
    assert!(
        total > 100,
        "walked a non-trivial method corpus, got {total}"
    );
    let pct: f64 = reducible as f64 / total as f64 * 100.0;
    eprintln!(
        "reducible {reducible}/{total} = {pct:.1}% (irreducible {})",
        failures.len()
    );
    assert!(
        pct >= 90.0,
        ">=90% of {total} EdgeCases methods must structure without irreducible fallback, got {pct:.1}%; sample failures {:?}",
        &failures[..failures.len().min(10)]
    );
}
