#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::missing_const_for_fn
)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

use disrobe_pass_as3::AbcFile;
use disrobe_pass_as3::abc::{self, MethodInfo};
use disrobe_pass_as3::lifter::{LiftedBody, Stmt, lift_body, lift_body_raw};
use disrobe_pass_as3::swf::{self, Swf};

const VIRTUAL_EXIT: usize = usize::MAX;

#[derive(Debug, Clone)]
enum FlatNode {
    Leaf(String),
    GotoLabel,
    Goto(usize),
    Branch { taken: usize },
    Switch { targets: Vec<usize> },
    Terminator,
}

#[derive(Debug, Default)]
struct Flat {
    nodes: Vec<FlatNode>,
    label_pos: BTreeMap<usize, usize>,
    next_label: usize,
}

impl Flat {
    fn fresh_label(&mut self) -> usize {
        self.next_label += 1;
        usize::MAX - self.next_label
    }

    fn emit(&mut self, node: FlatNode) -> usize {
        let id: usize = self.nodes.len();
        self.nodes.push(node);
        id
    }

    fn emit_leaf(&mut self, key: String) -> usize {
        self.emit(FlatNode::Leaf(key))
    }

    fn place_label(&mut self, label: usize) {
        let pos: usize = self.nodes.len();
        self.nodes.push(FlatNode::GotoLabel);
        self.label_pos.insert(label, pos);
    }
}

type LeafId = String;

fn is_iterator_binding(stmt: &Stmt) -> bool {
    let Stmt::Assign { value, .. } = stmt else {
        return false;
    };
    let call: &disrobe_pass_as3::Expr = match value {
        disrobe_pass_as3::Expr::Coerce { operand, .. } => operand,
        other => other,
    };
    matches!(
        call,
        disrobe_pass_as3::Expr::Call { property, .. }
            if property == "nextName" || property == "nextValue"
    )
}

fn is_scope_setup(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Assign {
            value: disrobe_pass_as3::Expr::ScopeObject,
            ..
        }
    )
}

fn is_exception_binding(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Assign {
            value: disrobe_pass_as3::Expr::CaughtException,
            ..
        } | Stmt::AssignProperty {
            value: disrobe_pass_as3::Expr::CaughtException,
            ..
        } | Stmt::AssignIndex {
            value: disrobe_pass_as3::Expr::CaughtException,
            ..
        }
    )
}

fn leaf_key(stmt: &Stmt) -> Option<String> {
    if is_iterator_binding(stmt) || is_scope_setup(stmt) || is_exception_binding(stmt) {
        return None;
    }
    match stmt {
        Stmt::Assign { .. }
        | Stmt::AssignProperty { .. }
        | Stmt::AssignIndex { .. }
        | Stmt::Expression(_)
        | Stmt::Return(_)
        | Stmt::Throw(_) => Some(format!("{stmt:?}")),
        _ => None,
    }
}

fn is_terminator(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Return(_) | Stmt::Throw(_))
}

fn lower_raw(stmts: &[Stmt], flat: &mut Flat) {
    for stmt in stmts {
        match stmt {
            Stmt::Label(off) => flat.place_label(*off),
            Stmt::Jump { target_label } => {
                flat.emit(FlatNode::Goto(*target_label));
            }
            Stmt::If { target_label, .. } => {
                flat.emit(FlatNode::Branch {
                    taken: *target_label,
                });
            }
            Stmt::Switch {
                case_labels,
                default_label,
                ..
            } => {
                let mut targets: Vec<usize> = case_labels.clone();
                targets.push(*default_label);
                flat.emit(FlatNode::Switch { targets });
            }
            other => {
                if let Some(key) = leaf_key(other) {
                    flat.emit_leaf(key);
                    if is_terminator(other) {
                        flat.emit(FlatNode::Terminator);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LoopCtx {
    continue_label: usize,
    break_label: usize,
}

fn lower_structured(stmts: &[Stmt], flat: &mut Flat, loop_ctx: Option<LoopCtx>) {
    for stmt in stmts {
        lower_structured_stmt(stmt, flat, loop_ctx);
    }
}

fn lower_structured_stmt(stmt: &Stmt, flat: &mut Flat, loop_ctx: Option<LoopCtx>) {
    match stmt {
        Stmt::Label(off) => flat.place_label(*off),
        Stmt::Jump { target_label } => {
            flat.emit(FlatNode::Goto(*target_label));
        }
        Stmt::If { target_label, .. } => {
            flat.emit(FlatNode::Branch {
                taken: *target_label,
            });
        }
        Stmt::Switch {
            case_labels,
            default_label,
            ..
        } => {
            let mut targets: Vec<usize> = case_labels.clone();
            targets.push(*default_label);
            flat.emit(FlatNode::Switch { targets });
        }
        Stmt::Break => {
            let ctx: LoopCtx = loop_ctx.expect("break outside loop");
            flat.emit(FlatNode::Goto(ctx.break_label));
        }
        Stmt::Continue => {
            let ctx: LoopCtx = loop_ctx.expect("continue outside loop");
            flat.emit(FlatNode::Goto(ctx.continue_label));
        }
        Stmt::IfBlock { body, .. } => {
            let after: usize = flat.fresh_label();
            flat.emit(FlatNode::Branch { taken: after });
            lower_structured(body, flat, loop_ctx);
            flat.place_label(after);
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            let else_l: usize = flat.fresh_label();
            let end_l: usize = flat.fresh_label();
            flat.emit(FlatNode::Branch { taken: else_l });
            lower_structured(then_body, flat, loop_ctx);
            flat.emit(FlatNode::Goto(end_l));
            flat.place_label(else_l);
            lower_structured(else_body, flat, loop_ctx);
            flat.place_label(end_l);
        }
        Stmt::While { body, .. } => {
            let head: usize = flat.fresh_label();
            let after: usize = flat.fresh_label();
            flat.place_label(head);
            flat.emit(FlatNode::Branch { taken: after });
            let ctx: LoopCtx = LoopCtx {
                continue_label: head,
                break_label: after,
            };
            lower_structured(body, flat, Some(ctx));
            flat.emit(FlatNode::Goto(head));
            flat.place_label(after);
        }
        Stmt::DoWhile { body, .. } => {
            let head: usize = flat.fresh_label();
            let after: usize = flat.fresh_label();
            flat.place_label(head);
            let ctx: LoopCtx = LoopCtx {
                continue_label: head,
                break_label: after,
            };
            lower_structured(body, flat, Some(ctx));
            flat.emit(FlatNode::Branch { taken: head });
            flat.place_label(after);
        }
        Stmt::For {
            init, update, body, ..
        } => {
            lower_structured_stmt(init, flat, loop_ctx);
            let head: usize = flat.fresh_label();
            let cont: usize = flat.fresh_label();
            let after: usize = flat.fresh_label();
            flat.place_label(head);
            flat.emit(FlatNode::Branch { taken: after });
            let ctx: LoopCtx = LoopCtx {
                continue_label: cont,
                break_label: after,
            };
            lower_structured(body, flat, Some(ctx));
            flat.place_label(cont);
            lower_structured_stmt(update, flat, Some(ctx));
            flat.emit(FlatNode::Goto(head));
            flat.place_label(after);
        }
        Stmt::ForEach { body, .. } | Stmt::ForIn { body, .. } => {
            let head: usize = flat.fresh_label();
            let after: usize = flat.fresh_label();
            flat.place_label(head);
            flat.emit(FlatNode::Branch { taken: after });
            let ctx: LoopCtx = LoopCtx {
                continue_label: head,
                break_label: after,
            };
            lower_structured(body, flat, Some(ctx));
            flat.emit(FlatNode::Goto(head));
            flat.place_label(after);
        }
        Stmt::Try { body, catches } => {
            let after: usize = flat.fresh_label();
            lower_structured(body, flat, loop_ctx);
            flat.emit(FlatNode::Goto(after));
            for catch in catches {
                lower_structured(&catch.body, flat, loop_ctx);
                flat.emit(FlatNode::Goto(after));
            }
            flat.place_label(after);
        }
        Stmt::With { body, .. } => lower_structured(body, flat, loop_ctx),
        Stmt::StructuredSwitch { cases, .. } => {
            let after: usize = flat.fresh_label();
            let case_labels: Vec<usize> = cases.iter().map(|_| flat.fresh_label()).collect();
            flat.emit(FlatNode::Switch {
                targets: case_labels.clone(),
            });
            let ctx: LoopCtx = LoopCtx {
                continue_label: loop_ctx.map_or(after, |c: LoopCtx| c.continue_label),
                break_label: after,
            };
            for (case, label) in cases.iter().zip(case_labels.iter()) {
                flat.place_label(*label);
                lower_structured(&case.body, flat, Some(ctx));
                if case.breaks {
                    flat.emit(FlatNode::Goto(after));
                }
            }
            flat.place_label(after);
        }
        other => {
            if let Some(key) = leaf_key(other) {
                flat.emit_leaf(key);
                if is_terminator(other) {
                    flat.emit(FlatNode::Terminator);
                }
            }
        }
    }
}

fn succ(flat: &Flat, pos: usize) -> Vec<usize> {
    match &flat.nodes[pos] {
        FlatNode::Terminator => vec![VIRTUAL_EXIT],
        FlatNode::Goto(label) => match flat.label_pos.get(label) {
            Some(p) => vec![*p],
            None => vec![VIRTUAL_EXIT],
        },
        FlatNode::Branch { taken } => {
            let mut out: Vec<usize> = Vec::new();
            match flat.label_pos.get(taken) {
                Some(p) => out.push(*p),
                None => out.push(VIRTUAL_EXIT),
            }
            out.push(fallthrough(flat, pos));
            out
        }
        FlatNode::Switch { targets } => targets
            .iter()
            .map(|t: &usize| flat.label_pos.get(t).copied().unwrap_or(VIRTUAL_EXIT))
            .collect(),
        FlatNode::Leaf(_) | FlatNode::GotoLabel => vec![fallthrough(flat, pos)],
    }
}

fn fallthrough(flat: &Flat, pos: usize) -> usize {
    if pos + 1 < flat.nodes.len() {
        pos + 1
    } else {
        VIRTUAL_EXIT
    }
}

fn exit_leaf() -> LeafId {
    "<exit>".to_owned()
}

fn leaf_at(flat: &Flat, pos: usize) -> Option<LeafId> {
    match &flat.nodes[pos] {
        FlatNode::Leaf(key) => Some(key.clone()),
        _ => None,
    }
}

fn next_leaf_set(flat: &Flat, start: usize) -> BTreeSet<LeafId> {
    let mut out: BTreeSet<LeafId> = BTreeSet::new();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    for s in succ(flat, start) {
        queue.push_back(s);
    }
    while let Some(node) = queue.pop_front() {
        if node == VIRTUAL_EXIT {
            out.insert(exit_leaf());
            continue;
        }
        if !seen.insert(node) {
            continue;
        }
        if let Some(leaf) = leaf_at(flat, node) {
            out.insert(leaf);
        } else {
            for s in succ(flat, node) {
                queue.push_back(s);
            }
        }
    }
    out
}

fn all_leaves(flat: &Flat) -> BTreeSet<LeafId> {
    (0..flat.nodes.len())
        .filter_map(|pos: usize| leaf_at(flat, pos))
        .collect()
}

fn successor_map(flat: &Flat) -> BTreeMap<LeafId, BTreeSet<LeafId>> {
    let reachable_pos: BTreeSet<usize> = {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        if !flat.nodes.is_empty() {
            queue.push_back(0);
        }
        while let Some(node) = queue.pop_front() {
            if node == VIRTUAL_EXIT || !seen.insert(node) {
                continue;
            }
            for s in succ(flat, node) {
                queue.push_back(s);
            }
        }
        seen
    };
    let mut map: BTreeMap<LeafId, BTreeSet<LeafId>> = BTreeMap::new();
    for (pos, _node) in flat.nodes.iter().enumerate() {
        if !reachable_pos.contains(&pos) {
            continue;
        }
        if let Some(leaf) = leaf_at(flat, pos) {
            map.entry(leaf)
                .or_default()
                .extend(next_leaf_set(flat, pos));
        }
    }
    map
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Equivalence {
    Equivalent,
    LeafMismatch,
    SuccessorMismatch,
}

fn classify(raw: &[Stmt], structured: &[Stmt]) -> Equivalence {
    let mut raw_flat: Flat = Flat::default();
    lower_raw(raw, &mut raw_flat);
    let mut str_flat: Flat = Flat::default();
    lower_structured(structured, &mut str_flat, None);

    if all_leaves(&raw_flat) != all_leaves(&str_flat) {
        return Equivalence::LeafMismatch;
    }
    if successor_map(&raw_flat) != successor_map(&str_flat) {
        return Equivalence::SuccessorMismatch;
    }
    Equivalence::Equivalent
}

#[derive(Debug, Default, Clone, Copy)]
struct OracleTotals {
    bodies: usize,
    fully_structured: usize,
    checked: usize,
    equivalent: usize,
    leaf_mismatch: usize,
    successor_mismatch: usize,
    structured_bodies: usize,
}

fn run_oracle() -> Option<OracleTotals> {
    let dir: PathBuf = corpus_root();
    let entries: std::fs::ReadDir = std::fs::read_dir(&dir).ok()?;
    let mut totals: OracleTotals = OracleTotals::default();
    let mut seen: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("swf") {
            continue;
        }
        seen += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            grade_abc(&abc, &mut totals);
        }
    }
    if seen == 0 {
        return None;
    }
    Some(totals)
}

fn grade_abc(abc: &AbcFile, totals: &mut OracleTotals) {
    for body in &abc.method_bodies {
        let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
        let Ok(raw): Result<Vec<Stmt>, _> = lift_body_raw(abc, body, info) else {
            continue;
        };
        let Ok(lifted): Result<LiftedBody, _> = lift_body(abc, body, info) else {
            continue;
        };
        totals.bodies += 1;
        if body_uses_structuring(&lifted.statements) {
            totals.structured_bodies += 1;
        }
        if !lifted.fully_structured {
            continue;
        }
        totals.fully_structured += 1;
        if !lifted.dropped_opcodes.is_empty() || lifted.opaque_operands > 0 {
            continue;
        }
        totals.checked += 1;
        match classify(&raw, &lifted.statements) {
            Equivalence::Equivalent => totals.equivalent += 1,
            Equivalence::LeafMismatch => totals.leaf_mismatch += 1,
            Equivalence::SuccessorMismatch => totals.successor_mismatch += 1,
        }
    }
}

fn body_uses_structuring(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s: &Stmt| {
        matches!(
            s,
            Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::For { .. }
                | Stmt::ForEach { .. }
                | Stmt::ForIn { .. }
                | Stmt::IfBlock { .. }
                | Stmt::IfElse { .. }
                | Stmt::StructuredSwitch { .. }
        ) || matches!(s, Stmt::Try { body, catches }
            if body_uses_structuring(body)
                || catches.iter().any(|c| body_uses_structuring(&c.body)))
    })
}

fn corpus_root() -> PathBuf {
    if let Ok(over) = std::env::var("DR_AS3_CORPUS") {
        return PathBuf::from(over);
    }
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
}

#[test]
fn structured_form_is_cfg_equivalent_to_goto_form_on_real_corpus() {
    let Some(totals): Option<OracleTotals> = run_oracle() else {
        eprintln!("skip: corpus absent");
        return;
    };
    eprintln!("AS3 CFG-equivalence oracle: {totals:?}");
    assert!(totals.bodies > 1000, "must grade many bodies");
    assert!(totals.structured_bodies > 0, "must exercise structuring");
    assert!(
        totals.fully_structured > 1000,
        "the restructurer must fully structure thousands of real bodies"
    );
    assert!(
        totals.checked > 1000,
        "thousands of fully structured bodies must be gradable"
    );
    assert_eq!(
        totals.leaf_mismatch, 0,
        "structuring must never add or drop a computational statement"
    );
    assert_eq!(
        totals.successor_mismatch, 0,
        "structuring must preserve the successor relation over computational statements"
    );
    assert_eq!(totals.equivalent, totals.checked);
}

#[test]
fn oracle_flags_a_corrupted_structuring() {
    let raw: Vec<Stmt> = vec![
        Stmt::Assign {
            target: disrobe_pass_as3::Expr::Name("a".to_owned()),
            value: disrobe_pass_as3::Expr::IntLit(1),
        },
        Stmt::Assign {
            target: disrobe_pass_as3::Expr::Name("b".to_owned()),
            value: disrobe_pass_as3::Expr::IntLit(2),
        },
        Stmt::Return(None),
    ];
    let dropped: Vec<Stmt> = vec![
        Stmt::Assign {
            target: disrobe_pass_as3::Expr::Name("a".to_owned()),
            value: disrobe_pass_as3::Expr::IntLit(1),
        },
        Stmt::Return(None),
    ];
    assert_eq!(classify(&raw, &raw), Equivalence::Equivalent);
    assert_eq!(classify(&raw, &dropped), Equivalence::LeafMismatch);
}

#[test]
fn oracle_passes_a_hand_built_while_with_break() {
    let raw: Vec<Stmt> = vec![
        Stmt::Jump { target_label: 100 },
        Stmt::Label(10),
        Stmt::Assign {
            target: disrobe_pass_as3::Expr::Name("x".to_owned()),
            value: disrobe_pass_as3::Expr::IntLit(1),
        },
        Stmt::If {
            cond: disrobe_pass_as3::Expr::Name("done".to_owned()),
            target_label: 200,
        },
        Stmt::Assign {
            target: disrobe_pass_as3::Expr::Name("y".to_owned()),
            value: disrobe_pass_as3::Expr::IntLit(2),
        },
        Stmt::Label(100),
        Stmt::If {
            cond: disrobe_pass_as3::Expr::Name("cond".to_owned()),
            target_label: 10,
        },
        Stmt::Label(200),
        Stmt::Return(None),
    ];
    let structured: Vec<Stmt> = vec![
        Stmt::While {
            cond: disrobe_pass_as3::Expr::Name("cond".to_owned()),
            body: vec![
                Stmt::Assign {
                    target: disrobe_pass_as3::Expr::Name("x".to_owned()),
                    value: disrobe_pass_as3::Expr::IntLit(1),
                },
                Stmt::IfBlock {
                    cond: disrobe_pass_as3::Expr::Name("done".to_owned()),
                    body: vec![Stmt::Break],
                },
                Stmt::Assign {
                    target: disrobe_pass_as3::Expr::Name("y".to_owned()),
                    value: disrobe_pass_as3::Expr::IntLit(2),
                },
            ],
        },
        Stmt::Return(None),
    ];
    assert_eq!(classify(&raw, &structured), Equivalence::Equivalent);
}
