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
use disrobe_pass_as3::abc::{self, ConstantPool, ExceptionInfo, MethodBody, MethodInfo};
use disrobe_pass_as3::lifter::{
    CaseLabel, CatchClause, Expr, LiftedBody, LocalNames, Stmt, SwitchCase, lift_body,
    lift_body_raw, local_names_for, render_body,
};
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
    let (Stmt::Assign { value, .. }
    | Stmt::AssignProperty { value, .. }
    | Stmt::AssignIndex { value, .. }) = stmt
    else {
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

fn bare_abc() -> AbcFile {
    AbcFile {
        minor: abc::ABC_MINOR,
        major: abc::ABC_MAJOR,
        cpool: ConstantPool::default(),
        methods: Vec::new(),
        metadata_count: 0,
        instances: Vec::new(),
        classes: Vec::new(),
        scripts: Vec::new(),
        method_bodies: Vec::new(),
    }
}

fn switch_body(code: Vec<u8>, local_count: u32) -> MethodBody {
    MethodBody {
        method: 0,
        max_stack: 1,
        local_count,
        init_scope_depth: 0,
        max_scope_depth: 0,
        code,
        exceptions: Vec::new(),
        traits: Vec::new(),
    }
}

fn scope_body(code: Vec<u8>, local_count: u32) -> MethodBody {
    MethodBody {
        method: 0,
        max_stack: 1,
        local_count,
        init_scope_depth: 0,
        max_scope_depth: 1,
        code,
        exceptions: Vec::new(),
        traits: Vec::new(),
    }
}

fn push_s24(out: &mut Vec<u8>, value: i32) {
    let raw: u32 = value as u32;
    out.push((raw & 0xFF) as u8);
    out.push(((raw >> 8) & 0xFF) as u8);
    out.push(((raw >> 16) & 0xFF) as u8);
}

fn patch_switch_target(code: &mut [u8], operand: usize, switch: usize, target: usize) {
    let relative: i32 = target as i32 - switch as i32;
    let raw: u32 = relative as u32;
    code[operand] = (raw & 0xFF) as u8;
    code[operand + 1] = ((raw >> 8) & 0xFF) as u8;
    code[operand + 2] = ((raw >> 16) & 0xFF) as u8;
}

fn patch_branch_target(code: &mut [u8], operand: usize, target: usize) {
    let after: usize = operand + 3;
    let relative: i32 = target as i32 - after as i32;
    let raw: u32 = relative as u32;
    code[operand] = (raw & 0xFF) as u8;
    code[operand + 1] = ((raw >> 8) & 0xFF) as u8;
    code[operand + 2] = ((raw >> 16) & 0xFF) as u8;
}

fn contains_comment(statement: &Stmt, expected: &str) -> bool {
    match statement {
        Stmt::Comment(actual) => actual == expected,
        Stmt::StructuredSwitch { cases, .. } => cases.iter().any(|case: &SwitchCase| {
            case.body
                .iter()
                .any(|nested: &Stmt| contains_comment(nested, expected))
        }),
        Stmt::IfBlock { body, .. }
        | Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::ForIn { body, .. }
        | Stmt::With { body, .. } => body
            .iter()
            .any(|nested: &Stmt| contains_comment(nested, expected)),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => then_body
            .iter()
            .chain(else_body)
            .any(|nested: &Stmt| contains_comment(nested, expected)),
        Stmt::For {
            init, update, body, ..
        } => {
            contains_comment(init, expected)
                || contains_comment(update, expected)
                || body
                    .iter()
                    .any(|nested: &Stmt| contains_comment(nested, expected))
        }
        Stmt::Try { body, catches } => {
            body.iter()
                .any(|nested: &Stmt| contains_comment(nested, expected))
                || catches.iter().any(|catch: &CatchClause| {
                    catch
                        .body
                        .iter()
                        .any(|nested: &Stmt| contains_comment(nested, expected))
                })
        }
        _ => false,
    }
}

#[test]
fn branch_scope_height_conflict_is_local_and_named() {
    let mut code: Vec<u8> = vec![0xD1, 0x12];
    let else_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0xD0, 0x30, 0x24, 0x0A, 0xD6, 0x10]);
    let merge_operand: usize = code.len();
    push_s24(&mut code, 0);
    let else_offset: usize = code.len();
    code.extend_from_slice(&[0x24, 0x14, 0xD6]);
    let merge_offset: usize = code.len();
    code.extend_from_slice(&[0xD2, 0x48]);

    patch_branch_target(&mut code, else_operand, else_offset);
    patch_branch_target(&mut code, merge_operand, merge_offset);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 2);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw scope-conflict lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("scope-conflict lift");

    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled scope height")),
        "the incompatible scope depths must remain a named local refusal: {lifted:#?}"
    );
    assert!(!lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.opaque_operands > 0, "{lifted:#?}");
    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(
        successor_map(&raw_flat),
        successor_map(&structured_flat),
        "raw: {raw_flat:#?}\nstructured: {structured_flat:#?}"
    );
}

#[test]
fn branch_scope_value_conflict_never_selects_one_predecessor() {
    let mut code: Vec<u8> = vec![0xD1, 0x12];
    let else_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0xD0, 0xD6, 0xD2, 0x30, 0x24, 0x0A, 0xD6, 0x10]);
    let merge_operand: usize = code.len();
    push_s24(&mut code, 0);
    let else_offset: usize = code.len();
    code.extend_from_slice(&[0xD1, 0xD6, 0xD2, 0x30, 0x24, 0x14, 0xD6]);
    let merge_offset: usize = code.len();
    code.extend_from_slice(&[0x1D, 0xD2, 0x48]);

    patch_branch_target(&mut code, else_operand, else_offset);
    patch_branch_target(&mut code, merge_operand, merge_offset);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw scope-value lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("scope-value lift");

    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled scope values")),
        "different incoming scope objects must not select a predecessor: {lifted:#?}"
    );
    assert!(!lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.opaque_operands > 0, "{lifted:#?}");
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);
}

#[test]
fn identical_branch_scope_values_reconcile_without_partial_output() {
    let mut code: Vec<u8> = vec![0xD0, 0x30, 0xD1, 0x12];
    let else_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x0A, 0xD6, 0x10]);
    let merge_operand: usize = code.len();
    push_s24(&mut code, 0);
    let else_offset: usize = code.len();
    code.extend_from_slice(&[0x24, 0x14, 0xD6]);
    let merge_offset: usize = code.len();
    code.extend_from_slice(&[0x1D, 0xD2, 0x48]);

    patch_branch_target(&mut code, else_operand, else_offset);
    patch_branch_target(&mut code, merge_operand, merge_offset);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 2);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw scope-merge lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("scope-merge lift");

    assert!(lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.fully_structured, "{lifted:#?}");
    assert_eq!(lifted.opaque_operands, 0, "{lifted:#?}");
    assert!(
        !lifted
            .statements
            .iter()
            .any(|statement: &Stmt| matches!(statement, Stmt::Comment(_))),
        "an identical scope merge must not emit a refusal: {lifted:#?}"
    );
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);
}

#[test]
fn branch_activation_scopes_never_collapse_distinct_allocations() {
    let mut code: Vec<u8> = vec![0xD1, 0x12];
    let else_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x57, 0x30, 0x24, 0x0A, 0xD6, 0x10]);
    let merge_operand: usize = code.len();
    push_s24(&mut code, 0);
    let else_offset: usize = code.len();
    code.extend_from_slice(&[0x57, 0x30, 0x24, 0x14, 0xD6]);
    let merge_offset: usize = code.len();
    code.extend_from_slice(&[0x1D, 0xD2, 0x48]);

    patch_branch_target(&mut code, else_operand, else_offset);
    patch_branch_target(&mut code, merge_operand, merge_offset);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw activation-scope lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("activation-scope lift");

    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled scope values")),
        "separately allocated activation scopes must not compare equal: {lifted:#?}"
    );
    assert!(!lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.opaque_operands > 0, "{lifted:#?}");
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);
}

#[test]
fn branch_with_scopes_are_refused_at_merge() {
    let mut code: Vec<u8> = vec![0xD1, 0x12];
    let else_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0xD0, 0x1C, 0x24, 0x0A, 0xD6, 0x10]);
    let merge_operand: usize = code.len();
    push_s24(&mut code, 0);
    let else_offset: usize = code.len();
    code.extend_from_slice(&[0xD0, 0x1C, 0x24, 0x14, 0xD6]);
    let merge_offset: usize = code.len();
    code.extend_from_slice(&[0x1D, 0xD2, 0x48]);

    patch_branch_target(&mut code, else_operand, else_offset);
    patch_branch_target(&mut code, merge_operand, merge_offset);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw with-scope lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("with-scope lift");

    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled scope values")),
        "path-specific with regions must remain a named local refusal: {lifted:#?}"
    );
    assert!(!lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.opaque_operands > 0, "{lifted:#?}");
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);
}

#[test]
fn switch_scope_value_conflict_is_local_and_named() {
    let mut code: Vec<u8> = vec![0x24, 0x00];
    let switch: usize = code.len();
    code.push(0x1B);
    let default_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.push(1);
    let case_zero_operand: usize = code.len();
    push_s24(&mut code, 0);
    let case_one_operand: usize = code.len();
    push_s24(&mut code, 0);

    let case_zero: usize = code.len();
    code.extend_from_slice(&[0xD0, 0x30, 0x24, 0x0A, 0xD6, 0x10]);
    let case_zero_break: usize = code.len();
    push_s24(&mut code, 0);
    let case_one: usize = code.len();
    code.extend_from_slice(&[0xD1, 0x30, 0x24, 0x14, 0xD6, 0x10]);
    let case_one_break: usize = code.len();
    push_s24(&mut code, 0);
    let default_case: usize = code.len();
    code.extend_from_slice(&[0xD0, 0x30, 0x24, 0x1E, 0xD6]);
    let merge: usize = code.len();
    code.extend_from_slice(&[0x1D, 0xD2, 0x48]);

    patch_switch_target(&mut code, default_operand, switch, default_case);
    patch_switch_target(&mut code, case_zero_operand, switch, case_zero);
    patch_switch_target(&mut code, case_one_operand, switch, case_one);
    patch_branch_target(&mut code, case_zero_break, merge);
    patch_branch_target(&mut code, case_one_break, merge);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw switch-scope lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("switch-scope lift");

    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled scope values")),
        "different switch-arm scopes must remain a named local refusal: {lifted:#?}"
    );
    assert!(!lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.opaque_operands > 0, "{lifted:#?}");
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);
}

#[test]
fn backward_scope_value_conflict_is_local_and_named() {
    let mut code: Vec<u8> = vec![0xD0, 0x30];
    let loop_header: usize = code.len();
    code.extend_from_slice(&[0xD1, 0x12]);
    let exit_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x01, 0xD6, 0x1D, 0xD2, 0x30, 0x24, 0x02, 0xD6, 0x10]);
    let loop_operand: usize = code.len();
    push_s24(&mut code, 0);
    let exit: usize = code.len();
    code.extend_from_slice(&[0x1D, 0x47]);

    patch_branch_target(&mut code, exit_operand, exit);
    patch_branch_target(&mut code, loop_operand, loop_header);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw loop-scope lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("loop-scope lift");

    let refusal: usize = raw
        .iter()
        .position(|statement: &Stmt| {
            matches!(statement, Stmt::Comment(reason) if reason == "unreconciled scope values")
        })
        .expect("raw loop scope refusal");
    let first_assignment: usize = raw
        .iter()
        .position(|statement: &Stmt| matches!(statement, Stmt::Assign { .. }))
        .expect("raw loop assignment");
    assert!(
        refusal < first_assignment,
        "the refusal must precede every statement lifted under the loop-header scope: {raw:#?}"
    );

    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled scope values")),
        "a differing back-edge scope must not reuse the entry predecessor: {lifted:#?}"
    );
    assert!(!lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.opaque_operands > 0, "{lifted:#?}");
    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(
        successor_map(&raw_flat),
        successor_map(&structured_flat),
        "raw: {raw_flat:#?}\nstructured: {structured_flat:#?}"
    );
}

#[test]
fn exception_handler_discards_the_linear_operand_stack() {
    let mut code: Vec<u8> = vec![0x24, 0x07, 0x10];
    let end_operand: usize = code.len();
    push_s24(&mut code, 0);
    let handler: usize = code.len();
    code.extend_from_slice(&[0xD5, 0xD1, 0x48]);
    let end: usize = code.len();
    code.push(0x47);
    patch_branch_target(&mut code, end_operand, end);

    let abc: AbcFile = bare_abc();
    let mut body: MethodBody = switch_body(code, 2);
    body.exceptions.push(ExceptionInfo {
        from: 0,
        to: 2,
        target: handler as u32,
        exc_type: 0,
        var_name: 0,
    });
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw handler-stack lift");

    assert!(
        raw.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Assign {
                target: Expr::Local(1),
                value: Expr::CaughtException,
            }
        )),
        "the handler must consume the caught exception, not a stale linear operand: {raw:#?}"
    );
}

fn exception_value_merge_body(handler_value: u8) -> MethodBody {
    let mut code: Vec<u8> = vec![0x24, 0x07, 0x10];
    let merge_operand: usize = code.len();
    push_s24(&mut code, 0);
    let handler: usize = code.len();
    code.extend_from_slice(&[0xD5, 0x24, handler_value]);
    let merge: usize = code.len();
    code.extend_from_slice(&[0xD6, 0xD2, 0x48]);
    patch_branch_target(&mut code, merge_operand, merge);

    let mut body: MethodBody = switch_body(code, 3);
    body.exceptions.push(ExceptionInfo {
        from: 0,
        to: 2,
        target: handler as u32,
        exc_type: 0,
        var_name: 0,
    });
    body
}

#[test]
fn exception_handler_values_reconcile_at_a_forward_merge() {
    let abc: AbcFile = bare_abc();
    let distinct_body: MethodBody = exception_value_merge_body(9);
    let distinct_raw: Vec<Stmt> =
        lift_body_raw(&abc, &distinct_body, None).expect("raw distinct handler merge lift");
    let distinct: LiftedBody =
        lift_body(&abc, &distinct_body, None).expect("distinct handler merge lift");
    assert!(
        distinct.statements.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Assign {
                target: Expr::Local(2),
                value: Expr::Phi { .. },
            }
        )),
        "distinct normal and handler values must not select one predecessor: {distinct:#?}"
    );
    assert!(
        distinct
            .statements
            .iter()
            .all(|statement: &Stmt| !contains_comment(statement, "unreconciled stack merge"))
    );
    let mut distinct_raw_flat: Flat = Flat::default();
    lower_raw(&distinct_raw, &mut distinct_raw_flat);
    let mut distinct_flat: Flat = Flat::default();
    lower_structured(&distinct.statements, &mut distinct_flat, None);
    assert_eq!(
        successor_map(&distinct_raw_flat),
        successor_map(&distinct_flat)
    );

    let identical_body: MethodBody = exception_value_merge_body(7);
    let identical: LiftedBody =
        lift_body(&abc, &identical_body, None).expect("identical handler merge lift");
    assert!(
        identical.statements.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Assign {
                target: Expr::Local(2),
                value: Expr::IntLit(7),
            }
        )),
        "identical normal and handler values must remain exact: {identical:#?}"
    );
    assert!(
        !identical.statements.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Assign {
                target: Expr::Local(2),
                value: Expr::Phi { .. },
            }
        )),
        "identical values must not be widened to a phi: {identical:#?}"
    );
}

#[test]
fn overlapping_exception_handler_value_merge_is_refused() {
    let abc: AbcFile = bare_abc();
    let mut body: MethodBody = exception_value_merge_body(9);
    body.exceptions.push(body.exceptions[0].clone());
    let raw: Vec<Stmt> =
        lift_body_raw(&abc, &body, None).expect("overlapping handler merge raw lift");
    assert!(
        raw.iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled stack merge")),
        "an excluded overlapping handler shape must not select one predecessor: {raw:#?}"
    );
}

#[test]
fn backward_exception_handler_value_merge_is_refused() {
    let code: Vec<u8> = vec![
        0x24, 0x07, 0x10, 0x00, 0x00, 0x00, 0xD6, 0xD2, 0x48, 0xD5, 0x24, 0x09, 0x10, 0xF6, 0xFF,
        0xFF, 0x47,
    ];
    let mut body: MethodBody = switch_body(code, 3);
    body.exceptions.push(ExceptionInfo {
        from: 0,
        to: 2,
        target: 9,
        exc_type: 0,
        var_name: 0,
    });
    let abc: AbcFile = bare_abc();
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("backward handler merge raw lift");
    assert!(
        raw.iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled stack merge")),
        "an excluded backward handler merge must be refused: {raw:#?}"
    );
    assert!(
        raw.iter().all(|statement: &Stmt| !matches!(
            statement,
            Stmt::Assign {
                target: Expr::Local(2),
                value: Expr::IntLit(7 | 9),
            }
        )),
        "the refusal must not select either predecessor value: {raw:#?}"
    );
}

fn assert_loose_dispatch_tree(statement: &Stmt, expected_comparisons: &[(i64, bool)]) {
    let mut current: &Stmt = statement;
    for (expected_value, selector_on_left) in expected_comparisons {
        let Stmt::IfElse {
            cond: cond @ Expr::Binary { op: "==", lhs, rhs },
            then_body,
            else_body,
        } = current
        else {
            panic!("loose dispatch must remain an ordered equality tree: {current:#?}");
        };
        let comparison_matches: bool = if *selector_on_left {
            matches!(
                (lhs.as_ref(), rhs.as_ref()),
                (Expr::Local(1), Expr::IntLit(value)) if value == expected_value
            )
        } else {
            matches!(
                (lhs.as_ref(), rhs.as_ref()),
                (Expr::IntLit(value), Expr::Local(1)) if value == expected_value
            )
        };
        assert!(
            comparison_matches,
            "loose dispatch comparison changed: {cond:#?}"
        );
        assert!(
            matches!(
                then_body.as_slice(),
                [Stmt::Assign {
                    target: Expr::Local(2),
                    value: Expr::IntLit(value),
                }] if value == &(expected_value.saturating_add(10))
            ),
            "loose dispatch arm changed: {then_body:#?}"
        );
        current = match else_body.as_slice() {
            [nested @ Stmt::IfElse { .. }] => nested,
            [default]
                if expected_comparisons
                    .last()
                    .is_some_and(|last: &(i64, bool)| {
                        last == &(*expected_value, *selector_on_left)
                    }) =>
            {
                assert!(matches!(
                    default,
                    Stmt::Assign {
                        target: Expr::Local(2),
                        value: Expr::IntLit(40),
                    }
                ));
                return;
            }
            other => panic!("loose dispatch else path changed: {other:#?}"),
        };
    }
    panic!("loose dispatch tree has more arms than expected: {current:#?}");
}

#[test]
fn direct_loose_forward_dispatch_preserves_comparisons_and_edges() {
    let mut code: Vec<u8> = Vec::new();

    code.extend_from_slice(&[0xD1, 0x24, 0x00, 0x13]);
    let first_case_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x01, 0xD1, 0x13]);
    let second_case_operand: usize = code.len();
    push_s24(&mut code, 0);

    code.extend_from_slice(&[0x24, 0x28, 0xD6, 0x10]);
    let default_break_operand: usize = code.len();
    push_s24(&mut code, 0);
    let first_case: usize = code.len();
    code.extend_from_slice(&[0x24, 0x0A, 0xD6, 0x10]);
    let first_break_operand: usize = code.len();
    push_s24(&mut code, 0);
    let second_case: usize = code.len();
    code.extend_from_slice(&[0x24, 0x0B, 0xD6]);
    let merge: usize = code.len();
    code.extend_from_slice(&[0xD2, 0x48]);

    patch_branch_target(&mut code, first_case_operand, first_case);
    patch_branch_target(&mut code, second_case_operand, second_case);
    patch_branch_target(&mut code, default_break_operand, merge);
    patch_branch_target(&mut code, first_break_operand, merge);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = switch_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw loose dispatch lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("loose dispatch lift");
    assert!(lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.fully_structured, "{lifted:#?}");
    assert_eq!(lifted.opaque_operands, 0, "{lifted:#?}");
    assert!(
        !lifted
            .statements
            .iter()
            .any(|statement: &Stmt| matches!(statement, Stmt::Comment(_)))
    );
    assert!(
        !lifted
            .statements
            .iter()
            .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
    );
    let tree: &Stmt = lifted
        .statements
        .iter()
        .find(|statement: &&Stmt| matches!(statement, Stmt::IfElse { .. }))
        .unwrap_or_else(|| panic!("loose equality dispatch must structure: {lifted:#?}"));
    assert_loose_dispatch_tree(tree, &[(0, true), (1, false)]);
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);

    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(successor_map(&raw_flat), successor_map(&structured_flat));
}

#[test]
fn inverted_loose_forward_dispatch_preserves_comparisons_and_edges() {
    let mut code: Vec<u8> = Vec::new();

    code.extend_from_slice(&[0xD1, 0x24, 0x00, 0x14]);
    let first_miss_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x0A, 0xD6, 0x10]);
    let first_break_operand: usize = code.len();
    push_s24(&mut code, 0);

    let second_test: usize = code.len();
    code.extend_from_slice(&[0x24, 0x01, 0xD1, 0x14]);
    let second_miss_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x0B, 0xD6, 0x10]);
    let second_break_operand: usize = code.len();
    push_s24(&mut code, 0);

    let default_case: usize = code.len();
    code.extend_from_slice(&[0x24, 0x28, 0xD6]);
    let merge: usize = code.len();
    code.extend_from_slice(&[0xD2, 0x48]);

    patch_branch_target(&mut code, first_miss_operand, second_test);
    patch_branch_target(&mut code, first_break_operand, merge);
    patch_branch_target(&mut code, second_miss_operand, default_case);
    patch_branch_target(&mut code, second_break_operand, merge);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = switch_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw inverted loose lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("inverted loose lift");
    assert!(lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.fully_structured, "{lifted:#?}");
    assert_eq!(lifted.opaque_operands, 0, "{lifted:#?}");
    assert!(
        !lifted
            .statements
            .iter()
            .any(|statement: &Stmt| matches!(statement, Stmt::Comment(_)))
    );
    assert!(
        !lifted
            .statements
            .iter()
            .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
    );
    let tree: &Stmt = lifted
        .statements
        .iter()
        .find(|statement: &&Stmt| matches!(statement, Stmt::IfElse { .. }))
        .unwrap_or_else(|| panic!("loose inequality dispatch must structure: {lifted:#?}"));
    assert_loose_dispatch_tree(tree, &[(0, true), (1, false)]);
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);

    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(successor_map(&raw_flat), successor_map(&structured_flat));
}

#[test]
fn dense_forward_if_dispatch_preserves_shared_and_fallthrough_edges() {
    let mut code: Vec<u8> = Vec::new();
    let mut case_operands: Vec<usize> = Vec::new();
    for value in 0..=2 {
        code.extend_from_slice(&[0xD1, 0x24, value, 0x19]);
        case_operands.push(code.len());
        push_s24(&mut code, 0);
    }
    code.extend_from_slice(&[0x24, 40, 0xD6, 0x10]);
    let default_break_operand: usize = code.len();
    push_s24(&mut code, 0);
    let shared_case: usize = code.len();
    code.extend_from_slice(&[0x24, 10, 0xD6]);
    let fallthrough_case: usize = code.len();
    code.extend_from_slice(&[0x24, 20, 0xD6, 0x10]);
    let case_break_operand: usize = code.len();
    push_s24(&mut code, 0);
    let merge: usize = code.len();
    code.extend_from_slice(&[0xD2, 0x48]);

    patch_branch_target(&mut code, case_operands[0], shared_case);
    patch_branch_target(&mut code, case_operands[1], shared_case);
    patch_branch_target(&mut code, case_operands[2], fallthrough_case);
    patch_branch_target(&mut code, default_break_operand, merge);
    patch_branch_target(&mut code, case_break_operand, merge);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = switch_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw forward dispatch lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("forward dispatch lift");
    let structured: &Stmt = lifted
        .statements
        .iter()
        .find(|statement: &&Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        .unwrap_or_else(|| {
            panic!(
                "dense forward equality dispatch must structure: {:?}",
                lifted.statements
            )
        });
    let Stmt::StructuredSwitch { cases, .. } = structured else {
        unreachable!()
    };
    assert_eq!(cases.len(), 3);
    assert_eq!(
        cases[0].labels,
        vec![CaseLabel::Value(0), CaseLabel::Value(1)]
    );
    assert!(!cases[0].breaks);
    assert_eq!(cases[1].labels, vec![CaseLabel::Value(2)]);
    assert!(cases[1].breaks);
    assert_eq!(cases[2].labels, vec![CaseLabel::Default]);
    assert!(cases[2].breaks);
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);

    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(successor_map(&raw_flat), successor_map(&structured_flat));
}

#[test]
fn inverted_strict_forward_dispatch_preserves_case_order_and_edges() {
    let mut code: Vec<u8> = Vec::new();

    code.extend_from_slice(&[0xD1, 0x24, 0x00, 0x1A]);
    let first_miss_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x0A, 0xD6, 0x10]);
    let first_break_operand: usize = code.len();
    push_s24(&mut code, 0);

    let second_test: usize = code.len();
    code.extend_from_slice(&[0x24, 0x01, 0xD1, 0x1A]);
    let second_miss_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x14, 0xD6, 0x10]);
    let second_break_operand: usize = code.len();
    push_s24(&mut code, 0);

    let default_case: usize = code.len();
    code.extend_from_slice(&[0x24, 0x28, 0xD6]);
    let merge: usize = code.len();
    code.extend_from_slice(&[0xD2, 0x48]);

    patch_branch_target(&mut code, first_miss_operand, second_test);
    patch_branch_target(&mut code, first_break_operand, merge);
    patch_branch_target(&mut code, second_miss_operand, default_case);
    patch_branch_target(&mut code, second_break_operand, merge);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = switch_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw inverted dispatch lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("inverted dispatch lift");
    assert!(lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.fully_structured, "{lifted:#?}");
    assert_eq!(lifted.opaque_operands, 0, "{lifted:#?}");
    let structured: &Stmt = lifted
        .statements
        .iter()
        .find(|statement: &&Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        .unwrap_or_else(|| {
            panic!(
                "inverted strict equality dispatch must structure: {:?}",
                lifted.statements
            )
        });
    let Stmt::StructuredSwitch { selector, cases } = structured else {
        unreachable!()
    };
    assert_eq!(selector, &Expr::Local(1));
    assert_eq!(cases.len(), 3);
    assert_eq!(cases[0].labels, vec![CaseLabel::Value(0)]);
    assert!(cases[0].breaks);
    assert_eq!(cases[1].labels, vec![CaseLabel::Value(1)]);
    assert!(cases[1].breaks);
    assert_eq!(cases[2].labels, vec![CaseLabel::Default]);
    assert!(!cases[2].breaks);
    let assigned_values: Vec<i64> = cases
        .iter()
        .map(|case: &SwitchCase| match case.body.as_slice() {
            [
                Stmt::Assign {
                    target: Expr::Local(2),
                    value: Expr::IntLit(value),
                },
            ] => *value,
            body => panic!("each dispatch arm must retain its assignment: {body:?}"),
        })
        .collect();
    assert_eq!(assigned_values, vec![10, 20, 40]);
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);

    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(successor_map(&raw_flat), successor_map(&structured_flat));
}

#[test]
fn inverted_strict_forward_dispatch_accepts_an_empty_default_at_the_merge() {
    let mut code: Vec<u8> = Vec::new();

    code.extend_from_slice(&[0xD1, 0x24, 0x00, 0x1A]);
    let first_miss_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x0A, 0xD6, 0x10]);
    let first_break_operand: usize = code.len();
    push_s24(&mut code, 0);

    let second_test: usize = code.len();
    code.extend_from_slice(&[0xD1, 0x24, 0x01, 0x1A]);
    let final_miss_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x24, 0x14, 0xD6, 0x10]);
    let second_break_operand: usize = code.len();
    push_s24(&mut code, 0);

    let merge: usize = code.len();
    code.extend_from_slice(&[0xD2, 0x48]);

    patch_branch_target(&mut code, first_miss_operand, second_test);
    patch_branch_target(&mut code, first_break_operand, merge);
    patch_branch_target(&mut code, final_miss_operand, merge);
    patch_branch_target(&mut code, second_break_operand, merge);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = switch_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw empty-default lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("empty-default lift");
    assert!(lifted.structurally_recovered, "{lifted:#?}");
    assert!(lifted.fully_structured, "{lifted:#?}");
    let structured: &Stmt = lifted
        .statements
        .iter()
        .find(|statement: &&Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        .unwrap_or_else(|| {
            panic!("empty-default dispatch must structure: raw={raw:#?} lifted={lifted:#?}")
        });
    let Stmt::StructuredSwitch { selector, cases } = structured else {
        unreachable!()
    };
    assert_eq!(selector, &Expr::Local(1));
    assert_eq!(cases.len(), 3);
    assert_eq!(cases[0].labels, vec![CaseLabel::Value(0)]);
    assert_eq!(cases[1].labels, vec![CaseLabel::Value(1)]);
    assert_eq!(cases[2].labels, vec![CaseLabel::Default]);
    assert!(cases[2].body.is_empty());
    assert!(!cases[2].breaks);
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);

    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(successor_map(&raw_flat), successor_map(&structured_flat));
}

#[test]
fn forward_switch_preserves_the_prior_sixteen_edge_regression() {
    const TARGETS: usize = 16;
    let mut code: Vec<u8> = vec![0x24, 0x00];
    let switch: usize = code.len();
    code.push(0x1B);
    let default_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.push((TARGETS - 1) as u8);
    let mut case_operands: Vec<usize> = Vec::with_capacity(TARGETS);
    for _ in 0..TARGETS {
        case_operands.push(code.len());
        push_s24(&mut code, 0);
    }
    let mut targets: Vec<usize> = Vec::with_capacity(TARGETS);
    for value in 0..TARGETS {
        targets.push(code.len());
        code.extend_from_slice(&[0x24, (value + 1) as u8, 0x48]);
    }
    for (operand, target) in case_operands.into_iter().zip(targets.iter().copied()) {
        patch_switch_target(&mut code, operand, switch, target);
    }
    patch_switch_target(&mut code, default_operand, switch, targets[TARGETS - 1]);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = switch_body(code, 1);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw switch lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("structured switch lift");
    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
    );
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);

    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let raw_switch: usize = raw_flat
        .nodes
        .iter()
        .position(|node: &FlatNode| matches!(node, FlatNode::Switch { .. }))
        .expect("raw dispatch node");
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    let structured_switch: usize = structured_flat
        .nodes
        .iter()
        .position(|node: &FlatNode| matches!(node, FlatNode::Switch { .. }))
        .expect("structured dispatch node");
    assert_eq!(next_leaf_set(&raw_flat, raw_switch).len(), TARGETS);
    assert_eq!(
        next_leaf_set(&structured_flat, structured_switch).len(),
        TARGETS
    );
}

#[test]
fn adjacent_case_fallthrough_preserves_successor_edges() {
    let mut code: Vec<u8> = vec![0x24, 0x00];
    let switch: usize = code.len();
    code.push(0x1B);
    let default_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.push(1);
    let case_zero_operand: usize = code.len();
    push_s24(&mut code, 0);
    let case_one_operand: usize = code.len();
    push_s24(&mut code, 0);

    let case_zero: usize = code.len();
    code.extend_from_slice(&[0x24, 0x0A, 0xD6]);
    let case_one: usize = code.len();
    code.extend_from_slice(&[0x24, 0x14, 0xD6, 0x10]);
    let break_operand: usize = code.len();
    push_s24(&mut code, 0);
    let merge: usize = code.len();
    code.extend_from_slice(&[0xD2, 0x48]);

    patch_switch_target(&mut code, default_operand, switch, merge);
    patch_switch_target(&mut code, case_zero_operand, switch, case_zero);
    patch_switch_target(&mut code, case_one_operand, switch, case_one);
    patch_branch_target(&mut code, break_operand, merge);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = switch_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw fallthrough lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("structured fallthrough lift");
    let structured: &Stmt = lifted
        .statements
        .iter()
        .find(|statement: &&Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        .expect("fallthrough dispatch must structure");
    let Stmt::StructuredSwitch { cases, .. } = structured else {
        unreachable!()
    };
    assert_eq!(cases.len(), 3);
    assert!(!cases[0].breaks);
    assert!(!cases[0].body.is_empty());
    assert!(!cases[1].body.is_empty());
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);

    let mut raw_flat: Flat = Flat::default();
    lower_raw(&raw, &mut raw_flat);
    let mut structured_flat: Flat = Flat::default();
    lower_structured(&lifted.statements, &mut structured_flat, None);
    assert_eq!(successor_map(&raw_flat), successor_map(&structured_flat));
}

#[test]
fn a_scope_object_stored_into_a_local_renders_as_a_named_operand() {
    let code: Vec<u8> = vec![0xD0, 0x30, 0x65, 0x00, 0xD5, 0x47];
    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 2);
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("scope-object value lift");
    let names: LocalNames = local_names_for(&abc, None);
    let rendered: String = render_body(&lifted, &names, "");
    assert!(
        !rendered
            .lines()
            .any(|line: &str| line.trim_end().ends_with("= ;")),
        "an AVM2 scope object reaching a value position must render as a named operand, never as \
         nothing: {rendered}"
    );
    assert!(
        rendered.contains("$scope"),
        "the scope object must keep a spelling that identifies what it is: {rendered}"
    );
}

#[test]
fn an_activation_object_stored_into_a_local_renders_as_a_named_operand() {
    let code: Vec<u8> = vec![0xD0, 0x30, 0x57, 0x2A, 0xD6, 0x30, 0x47];
    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_body(code, 3);
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("activation value lift");
    let names: LocalNames = local_names_for(&abc, None);
    let rendered: String = render_body(&lifted, &names, "");
    assert!(
        !rendered
            .lines()
            .any(|line: &str| line.trim_end().ends_with("= ;")),
        "an AVM2 activation object reaching a value position must render as a named operand, \
         never as nothing: {rendered}"
    );
    assert!(
        rendered.contains("$activation"),
        "the activation object must keep a spelling that identifies what it is: {rendered}"
    );
}

fn scope_conflict_body(code: Vec<u8>, local_count: u32) -> MethodBody {
    MethodBody {
        method: 0,
        max_stack: 3,
        local_count,
        init_scope_depth: 0,
        max_scope_depth: 3,
        code,
        exceptions: Vec::new(),
        traits: Vec::new(),
    }
}

fn binary_ops(stmts: &[Stmt]) -> Vec<&'static str> {
    fn walk_expr(expr: &Expr, out: &mut Vec<&'static str>) {
        match expr {
            Expr::Binary { op, lhs, rhs } => {
                out.push(op);
                walk_expr(lhs, out);
                walk_expr(rhs, out);
            }
            Expr::Unary { operand, .. } | Expr::Coerce { operand, .. } => walk_expr(operand, out),
            _ => {}
        }
    }
    let mut out: Vec<&'static str> = Vec::new();
    for stmt in stmts {
        match stmt {
            Stmt::Return(Some(expr)) => walk_expr(expr, &mut out),
            Stmt::Assign { value, .. } => walk_expr(value, &mut out),
            _ => {}
        }
    }
    out
}

fn mentions_phi(stmts: &[Stmt]) -> bool {
    fn walk_expr(expr: &Expr) -> bool {
        match expr {
            Expr::Phi { .. } => true,
            Expr::Binary { lhs, rhs, .. } => walk_expr(lhs) || walk_expr(rhs),
            Expr::Unary { operand, .. } | Expr::Coerce { operand, .. } => walk_expr(operand),
            _ => false,
        }
    }
    stmts.iter().any(|stmt: &Stmt| match stmt {
        Stmt::Return(Some(expr)) => walk_expr(expr),
        Stmt::Assign { value, .. } => walk_expr(value),
        _ => false,
    })
}

#[test]
fn a_short_circuit_still_resolves_when_its_merge_refuses_a_scope() {
    let mut code: Vec<u8> = vec![0xD0, 0x30, 0xD1, 0x2A, 0x12];
    let merge_operand: usize = code.len();
    push_s24(&mut code, 0);
    code.extend_from_slice(&[0x29, 0xD2, 0xD0, 0x30]);
    let merge_offset: usize = code.len();
    code.push(0x48);
    patch_branch_target(&mut code, merge_operand, merge_offset);

    let abc: AbcFile = bare_abc();
    let body: MethodBody = scope_conflict_body(code, 3);
    let raw: Vec<Stmt> = lift_body_raw(&abc, &body, None).expect("raw short-circuit lift");
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("short-circuit lift");

    assert!(
        lifted
            .statements
            .iter()
            .any(|statement: &Stmt| contains_comment(statement, "unreconciled scope height")),
        "this body is built so the merge refuses its scope; without that refusal the check \
         proves nothing: {lifted:#?}"
    );
    assert!(
        binary_ops(&lifted.statements).contains(&"&&"),
        "a refused scope at the merge must not cost the short-circuit operand its operator: \
         {lifted:#?}"
    );
    assert!(
        !mentions_phi(&lifted.statements),
        "the short-circuit value must resolve to its operands, not stay a merge placeholder: \
         {lifted:#?}"
    );
    assert_eq!(classify(&raw, &lifted.statements), Equivalence::Equivalent);
}

const CONTROL_SHAPES_SWF: &[u8] =
    include_bytes!("../../../corpus/flash/avm2_disasm_oracle/control_shapes.swf");

fn control_shapes_bodies() -> Vec<(String, Vec<Stmt>, LiftedBody)> {
    let parsed: Swf =
        swf::parse(CONTROL_SHAPES_SWF).expect("the tracked control shapes SWF parses");
    let mut out: Vec<(String, Vec<Stmt>, LiftedBody)> = Vec::new();
    for blob in parsed.collect_do_abc() {
        let file: AbcFile =
            abc::parse(&blob.abc_bytes).expect("the tracked control shapes ABC parses");
        for body in &file.method_bodies {
            let info: Option<&MethodInfo> = file.methods.get(body.method as usize);
            let Ok(raw): Result<Vec<Stmt>, _> = lift_body_raw(&file, body, info) else {
                continue;
            };
            let Ok(lifted): Result<LiftedBody, _> = lift_body(&file, body, info) else {
                continue;
            };
            out.push((format!("method {}", body.method), raw, lifted));
        }
    }
    out
}

#[test]
fn the_control_shapes_fixture_structures_without_changing_its_cfg() {
    let bodies: Vec<(String, Vec<Stmt>, LiftedBody)> = control_shapes_bodies();
    assert!(
        bodies.len() >= 100,
        "the control shapes fixture must contribute its whole body population to this check, \
         got {}",
        bodies.len()
    );
    let mut graded: usize = 0;
    let mut mismatched: Vec<(String, Equivalence)> = Vec::new();
    for (name, raw, lifted) in &bodies {
        if !lifted.fully_structured
            || !lifted.dropped_opcodes.is_empty()
            || lifted.opaque_operands > 0
        {
            continue;
        }
        graded += 1;
        let verdict: Equivalence = classify(raw, &lifted.statements);
        if verdict != Equivalence::Equivalent {
            mismatched.push((name.clone(), verdict));
        }
    }
    assert!(
        graded >= 40,
        "the graded population must stay large enough to be meaningful, got {graded} of {}",
        bodies.len()
    );
    assert!(
        mismatched.is_empty(),
        "structuring must preserve the CFG of every gradable body in the authored control shapes \
         program; {} of {graded} disagree: {mismatched:?}",
        mismatched.len()
    );
}
