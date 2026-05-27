#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{FlattenReversalResult, reverse_flatten};

#[test]
fn collapses_linear_three_state_dispatcher_into_ordered_statements() {
    let src: &str = r"var _s = 0;
while (!![]) {
    switch (_s) {
        case 0: console.log('a'); _s = 1; break;
        case 1: console.log('b'); _s = 2; break;
        case 2: console.log('c'); return;
    }
}";
    let r: FlattenReversalResult = reverse_flatten(src);
    assert_eq!(r.dispatches_collapsed, 1);
    let out: &String = &r.rewritten_source;
    let pa: usize = out.find("console.log('a')").expect("a missing");
    let pb: usize = out.find("console.log('b')").expect("b missing");
    let pc: usize = out.find("console.log('c')").expect("c missing");
    assert!(pa < pb);
    assert!(pb < pc);
    assert!(!out.contains("while (!![])"), "loop must be gone: {out}");
    assert!(!out.contains("switch (_s)"), "switch must be gone: {out}");
}

#[test]
fn collapses_dispatcher_with_unordered_case_labels() {
    let src: &str = r"var _k = 2;
while (true) {
    switch (_k) {
        case 1: doSecond(); _k = 0; break;
        case 0: doThird(); return;
        case 2: doFirst(); _k = 1; break;
    }
}";
    let r: FlattenReversalResult = reverse_flatten(src);
    assert_eq!(r.dispatches_collapsed, 1);
    let out: &String = &r.rewritten_source;
    let p1: usize = out.find("doFirst()").expect("first missing");
    let p2: usize = out.find("doSecond()").expect("second missing");
    let p3: usize = out.find("doThird()").expect("third missing");
    assert!(p1 < p2 && p2 < p3, "wrong order: {out}");
}

#[test]
fn leaves_regular_switch_alone() {
    let src: &str = "switch (mode) { case 0: handleA(); break; case 1: handleB(); break; }";
    let r: FlattenReversalResult = reverse_flatten(src);
    assert_eq!(r.dispatches_collapsed, 0);
    assert_eq!(r.rewritten_source, src);
}

#[test]
fn ignores_loop_with_no_initial_state_assignment() {
    let src: &str = "while (true) { switch (mystery) { case 0: x(); break; case 1: y(); break; } }";
    let r: FlattenReversalResult = reverse_flatten(src);
    assert_eq!(r.dispatches_collapsed, 0);
}

#[test]
fn ignores_loop_with_cyclic_state_transitions() {
    let src: &str = r"var _z = 0;
while (!![]) {
    switch (_z) {
        case 0: pingA(); _z = 1; break;
        case 1: pingB(); _z = 0; break;
    }
}";
    let r: FlattenReversalResult = reverse_flatten(src);
    assert_eq!(r.dispatches_collapsed, 1);
    let out: &String = &r.rewritten_source;
    assert!(out.contains("pingA()"), "first iter must land: {out}");
}
