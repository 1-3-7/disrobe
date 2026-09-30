use std::collections::{BTreeMap, BTreeSet};

use syn::visit::Visit;
use syn::{
    Attribute, BinOp, Block, Expr, ExprAssign, ExprBinary, ExprBreak, ExprCall, ExprContinue,
    ExprIf, ExprMethodCall, ExprPath, ExprReturn, ExprStruct, File, FnArg, Item, Lit, Local,
    Member, Pat, Path, Stmt, UnOp,
};

use super::finder::{Finder, Node, Occurrence, Target};
use super::prepare::{FnRef, Index, macro_name};

const MAX_FOLLOW_DEPTH: usize = 8;
const MAX_CALLEE_CANDIDATES: usize = 4;
const MAX_VARIANTS_PER_SITE: usize = 4;
const RECORD_WORDS: &[&str] = &[
    "truncat",
    "refus",
    "capped",
    "exceed",
    "overflow",
    "partial",
    "incomplete",
    "exhaust",
    "skipped",
    "elided",
    "omitted",
    "clipped",
    "dropped",
    "limit",
    "budget",
    "warning",
    "diagnostic",
    "note",
    "gap",
];
const RECORD_METHOD_PREFIXES: &[&str] = &[
    "record",
    "note_",
    "mark_",
    "flag_",
    "warn",
    "refuse",
    "report",
    "set_truncated",
    "add_note",
    "add_warning",
    "add_gap",
    "push_note",
    "push_warning",
    "push_refusal",
    "push_gap",
];
const COLLECT_METHODS: &[&str] = &["push", "push_back", "insert", "extend", "push_str"];
const TRANSPARENT_METHOD_PREFIXES: &[&str] = &[
    "checked_",
    "saturating_",
    "wrapping_",
    "overflowing_",
    "unwrap_or",
    "map_or",
    "is_",
    "as_",
    "to_",
    "try_",
];
const TRANSPARENT_METHODS: &[&str] = &[
    "abs_diff",
    "entry",
    "extend",
    "insert",
    "push",
    "push_back",
    "push_str",
    "cmp",
    "contains",
    "div_ceil",
    "eq",
    "filter",
    "ge",
    "gt",
    "into",
    "le",
    "lt",
    "map",
    "max",
    "ne",
    "next_multiple_of",
    "partial_cmp",
    "pow",
    "rem_euclid",
    "then",
    "then_some",
];
const TRANSPARENT_CALLS: &[&str] = &["Some", "Ok", "Box", "from", "try_from", "max", "new"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Class {
    Error,
    Record,
    Panic,
    Delegated,
    Silent,
    Unresolved,
    Capacity,
    Unused,
}

impl Class {
    pub(crate) const ALL: [Self; 8] = [
        Self::Error,
        Self::Record,
        Self::Panic,
        Self::Delegated,
        Self::Silent,
        Self::Unresolved,
        Self::Capacity,
        Self::Unused,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Record => "recorded",
            Self::Panic => "panic",
            Self::Delegated => "delegated",
            Self::Silent => "silent",
            Self::Unresolved => "unclassified",
            Self::Capacity => "allocation",
            Self::Unused => "unused",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Consequence {
    pub(crate) class: Class,
    pub(crate) detail: String,
    pub(crate) variants: Vec<(String, String)>,
}

impl Consequence {
    fn new(class: Class, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
            variants: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ModulePath {
    pub(crate) own: String,
    pub(crate) parent: String,
    pub(crate) root: bool,
}

#[derive(Debug)]
pub(crate) struct CrateScan {
    pub(crate) consequences: BTreeMap<(usize, String), Vec<Consequence>>,
    pub(crate) codes: BTreeSet<(String, String, String)>,
}

pub(crate) fn scan_crate(
    files: &[File],
    texts: &[&str],
    modules: &[ModulePath],
    bounds: &BTreeSet<(usize, String)>,
) -> CrateScan {
    let index: Index<'_> = super::prepare::index(files);
    let names: BTreeSet<String> = bounds
        .iter()
        .map(|(_, name): &(usize, String)| name.clone())
        .collect();
    let mut finder: Finder<'_, '_> = Finder::new(Target::Paths(&names), 0, Vec::new());
    for (file_index, file) in files.iter().enumerate() {
        finder.set_file(file_index);
        finder.visit_file(file);
    }
    let mut by_name: BTreeMap<String, Vec<Occurrence<'_>>> = BTreeMap::new();
    for occurrence in finder.finish() {
        by_name
            .entry(occurrence.name.clone())
            .or_default()
            .push(occurrence);
    }
    let mut classifier: Classifier<'_> = Classifier {
        files,
        texts,
        modules,
        index: &index,
        memo: BTreeMap::new(),
    };
    let mut consequences: BTreeMap<(usize, String), Vec<Consequence>> = BTreeMap::new();
    for (file, name) in bounds {
        let occurrences: &[Occurrence<'_>] = by_name.get(name).map_or(&[], Vec::as_slice);
        let mut found: Vec<Consequence> = Vec::new();
        for occurrence in occurrences {
            if classifier.visible(name, *file, occurrence) {
                found.extend(classifier.classify(occurrence, 0, None));
            }
        }
        let reduced: Vec<Consequence> = if found.is_empty() {
            vec![Consequence::new(Class::Unused, "no use in the crate")]
        } else {
            reduce(found)
        };
        consequences.insert((*file, name.clone()), reduced);
    }
    CrateScan {
        consequences,
        codes: index.codes,
    }
}

pub(crate) fn reduce(mut found: Vec<Consequence>) -> Vec<Consequence> {
    let Some(strongest) = found.iter().map(|c: &Consequence| c.class).min() else {
        return found;
    };
    found.retain(|c: &Consequence| c.class == strongest);
    found.sort();
    found.dedup();
    found
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum FollowKey {
    Field(String),
    Call(String),
    Const(String, usize),
    Binding((usize, Option<usize>), String),
}

struct Classifier<'a> {
    files: &'a [File],
    texts: &'a [&'a str],
    modules: &'a [ModulePath],
    index: &'a Index<'a>,
    memo: BTreeMap<(FollowKey, Option<bool>), Option<Vec<Consequence>>>,
}

#[derive(Debug, Default)]
struct Walk {
    polarity: Option<bool>,
    clamp: Option<String>,
    callee: Option<String>,
    ranged: bool,
    returned: bool,
    checked: bool,
}

enum Step<'a> {
    Continue,
    Done(Vec<Consequence>),
    Follow(Follow<'a>),
}

enum Follow<'a> {
    Binding {
        name: String,
        scope: Scope<'a>,
        prefix: Vec<Node<'a>>,
        file: usize,
    },
    Field(String),
    Call(String),
    Const(String, usize),
    Params(Vec<(FnRef<'a>, String)>, String),
}

#[derive(Clone, Copy)]
enum Scope<'a> {
    After(&'a Block, usize),
    Body(&'a Block),
}

impl<'a> Classifier<'a> {
    fn visible(&self, name: &str, defined_in: usize, occurrence: &Occurrence<'a>) -> bool {
        if defined_in == occurrence.file {
            return true;
        }
        let Some(definers) = self.index.const_files.get(name) else {
            return false;
        };
        if definers.len() == 1 && definers.contains(&defined_in) {
            return true;
        }
        if definers.contains(&occurrence.file) {
            return false;
        }
        let (Some(module), Some(user)) = (
            self.modules.get(defined_in),
            self.modules.get(occurrence.file),
        ) else {
            return false;
        };
        let names = |qualifier: &str| -> bool {
            match qualifier {
                "super" => user.parent == module.own,
                "self" => user.own == module.own,
                "crate" => module.root,
                other => other == module.own,
            }
        };
        if let Some(Node::Expr(Expr::Path(path))) = occurrence.stack.last()
            && let Some(qualifier) = path
                .path
                .segments
                .len()
                .checked_sub(2)
                .map(|index: usize| path.path.segments[index].ident.to_string())
        {
            return names(&qualifier);
        }
        self.index.imports.get(&occurrence.file).is_some_and(
            |imports: &BTreeSet<(String, String)>| {
                imports.iter().any(|(qualifier, item): &(String, String)| {
                    (item == name || item == "*") && names(qualifier)
                })
            },
        )
    }

    fn classify(
        &mut self,
        occurrence: &Occurrence<'a>,
        depth: usize,
        seed: Option<bool>,
    ) -> Vec<Consequence> {
        let stack: &[Node<'a>] = &occurrence.stack;
        let location: String = location(stack);
        let Some(last) = stack.len().checked_sub(1) else {
            return vec![Consequence::new(Class::Unresolved, "no context")];
        };
        if is_write(stack) || in_const_assertion(stack) {
            return Vec::new();
        }
        if let Node::Macro(mac) = stack[last] {
            let name: String = mac
                .path
                .segments
                .last()
                .map_or_else(String::new, |s: &syn::PathSegment| s.ident.to_string());
            return vec![Consequence::new(
                Class::Unresolved,
                format!("inside `{name}!` in {location}"),
            )];
        }
        let mut walk: Walk = Walk {
            polarity: seed,
            ..Walk::default()
        };
        for at in (0..last).rev() {
            let child: Node<'a> = stack[at + 1];
            let step: Step<'a> = self.step(stack, at, child, &mut walk, &location, occurrence);
            match step {
                Step::Continue => {}
                Step::Done(found) => return found,
                Step::Follow(follow) => {
                    let found: Vec<Consequence> = if depth >= MAX_FOLLOW_DEPTH {
                        vec![Consequence::new(
                            Class::Unresolved,
                            format!("value flow deeper than {MAX_FOLLOW_DEPTH} steps"),
                        )]
                    } else {
                        self.follow(follow, depth + 1, walk.polarity)
                    };
                    return clamped(found, &walk, &location);
                }
            }
        }
        boundary(&walk, &location)
    }

    fn step(
        &self,
        stack: &[Node<'a>],
        at: usize,
        child: Node<'a>,
        walk: &mut Walk,
        location: &str,
        occurrence: &Occurrence<'a>,
    ) -> Step<'a> {
        match stack[at] {
            Node::Expr(expr) => {
                self.expr_step(stack, at, expr, child, walk, location, occurrence.file)
            }
            Node::Stmt(_) => Step::Continue,
            Node::Local(local) => local_step(stack, at, local, child, walk, location, occurrence),
            Node::Block(block) => {
                let is_tail: bool = match (child, block.stmts.last()) {
                    (Node::Stmt(stmt), Some(last)) => {
                        std::ptr::eq(stmt, last) && matches!(last, Stmt::Expr(_, None))
                    }
                    _ => false,
                };
                if is_tail || walk.returned {
                    Step::Continue
                } else {
                    Step::Done(boundary(walk, location))
                }
            }
            Node::FieldValue(field) => {
                if let Some(Node::Expr(Expr::Struct(parent))) =
                    at.checked_sub(1).map(|i: usize| stack[i])
                    && let Some(found) = path_consequence(&parent.path)
                {
                    return Step::Done(vec![found]);
                }
                let Member::Named(member) = &field.member else {
                    return Step::Done(boundary(walk, location));
                };
                let name: String = member.to_string();
                if walk.polarity.is_some() {
                    return Step::Done(vec![Consequence::new(
                        Class::Record,
                        format!("flag `{name}`"),
                    )]);
                }
                Step::Follow(Follow::Field(name))
            }
            Node::Arm(arm) => {
                if let (Some((_, guard)), Node::Expr(expr)) = (&arm.guard, child)
                    && same_expr(expr, guard)
                {
                    let Some(Node::Expr(Expr::Match(parent))) =
                        at.checked_sub(1).map(|index: usize| stack[index])
                    else {
                        return Step::Done(settle(scan(&[Part::Expr(&arm.body)]), location));
                    };
                    let parts: Vec<Part<'a>> = parent
                        .arms
                        .iter()
                        .filter(|other: &&'a syn::Arm| match walk.polarity {
                            Some(true) => std::ptr::eq(*other, arm),
                            Some(false) => !std::ptr::eq(*other, arm),
                            None => true,
                        })
                        .map(|other: &'a syn::Arm| Part::Expr(&other.body))
                        .collect();
                    let found: Scan = scan(&parts);
                    if found.found.is_empty() && found.exit.is_none() {
                        walk.polarity = None;
                        walk.clamp
                            .get_or_insert_with(|| "fallback value".to_owned());
                        return Step::Continue;
                    }
                    return Step::Done(settle(found, location));
                }
                if let Node::Expr(expr) = child
                    && same_expr(expr, &arm.body)
                {
                    return Step::Continue;
                }
                Step::Done(vec![Consequence::new(
                    Class::Unresolved,
                    format!("match pattern in {location}"),
                )])
            }
            Node::Item(ident) => Step::Follow(Follow::Const(ident.to_string(), occurrence.file)),
            Node::Fn(ident, ..) => Step::Follow(Follow::Call(ident.to_string())),
            Node::Type => Step::Done(vec![Consequence::new(
                Class::Capacity,
                format!("array length in {location}"),
            )]),
            Node::Macro(_) => Step::Done(vec![Consequence::new(
                Class::Unresolved,
                format!("macro in {location}"),
            )]),
        }
    }

    fn expr_step(
        &self,
        stack: &[Node<'a>],
        at: usize,
        expr: &'a Expr,
        child: Node<'a>,
        walk: &mut Walk,
        location: &str,
        file: usize,
    ) -> Step<'a> {
        let child_expr: Option<&'a Expr> = match child {
            Node::Expr(inner) => Some(inner),
            _ => None,
        };
        let is_child =
            |candidate: &Expr| child_expr.is_some_and(|c: &Expr| std::ptr::eq(c, candidate));
        match expr {
            Expr::Binary(binary) => binary_step(binary, &is_child, walk, location),
            Expr::Unary(unary) => {
                if matches!(unary.op, UnOp::Not(_)) {
                    walk.polarity = walk.polarity.map(|p: bool| !p);
                }
                Step::Continue
            }
            Expr::If(expr_if) if is_child(&expr_if.cond) => {
                if let Some(found) = if_consequences(expr_if, walk.polarity, stack, at, location) {
                    Step::Done(found)
                } else {
                    walk.polarity = None;
                    walk.clamp
                        .get_or_insert_with(|| "fallback value".to_owned());
                    Step::Continue
                }
            }
            Expr::While(expr_while) if is_child(&expr_while.cond) => {
                Step::Done(vec![Consequence::new(
                    Class::Silent,
                    format!("`while` condition in {location}"),
                )])
            }
            Expr::ForLoop(expr_for) if is_child(&expr_for.expr) => {
                Step::Done(vec![Consequence::new(
                    Class::Silent,
                    format!("`for` range in {location}"),
                )])
            }
            Expr::Match(expr_match) if is_child(&expr_match.expr) => {
                let arms: Vec<Part<'a>> = expr_match
                    .arms
                    .iter()
                    .map(|arm: &'a syn::Arm| Part::Expr(&arm.body))
                    .collect();
                let found: Scan = scan(&arms);
                if found.found.is_empty() {
                    Step::Continue
                } else {
                    Step::Done(reduce(found.found))
                }
            }
            Expr::Repeat(repeat) if is_child(&repeat.len) => Step::Done(vec![Consequence::new(
                Class::Capacity,
                format!("buffer length in {location}"),
            )]),
            Expr::Range(_) => {
                walk.ranged = true;
                Step::Continue
            }
            Expr::Index(index) if is_child(&index.index) && walk.ranged => {
                Step::Done(vec![Consequence::new(
                    Class::Silent,
                    format!("slice in {location}"),
                )])
            }
            Expr::Try(_) => match &walk.callee {
                Some(callee) => Step::Done(vec![Consequence::new(
                    Class::Delegated,
                    format!("`{callee}()?`"),
                )]),
                None if walk.checked => Step::Done(vec![Consequence::new(
                    Class::Silent,
                    format!("`?` on a checked operation in {location}"),
                )]),
                None => Step::Continue,
            },
            Expr::Return(_) => {
                walk.returned = true;
                Step::Continue
            }
            Expr::Assign(assign) if is_child(&assign.right) => {
                assign_step(stack, at, assign, walk, location, file)
            }
            Expr::Call(call) => self.call_step(call, child_expr, walk, location),
            Expr::MethodCall(call) => self.method_step(call, child_expr, walk, location),
            Expr::Struct(expr_struct) => path_consequence(&expr_struct.path)
                .map_or(Step::Continue, |found: Consequence| Step::Done(vec![found])),
            _ => Step::Continue,
        }
    }

    fn call_step(
        &self,
        call: &'a ExprCall,
        child: Option<&'a Expr>,
        walk: &mut Walk,
        location: &str,
    ) -> Step<'a> {
        let Some(child) = child else {
            return Step::Continue;
        };
        if same_expr(child, &call.func) {
            return Step::Continue;
        }
        if let Some(name) = macro_name(call) {
            return macro_step(&name, call, child, location);
        }
        let Expr::Path(func) = &*call.func else {
            return Step::Continue;
        };
        let Some(last) = func.path.segments.last() else {
            return Step::Continue;
        };
        let name: String = last.ident.to_string();
        match name.as_str() {
            "Err" => return Step::Done(vec![error_site(child)]),
            "with_capacity" => {
                return Step::Done(vec![Consequence::new(
                    Class::Capacity,
                    format!("`with_capacity` in {location}"),
                )]);
            }
            "min" => {
                walk.clamp.get_or_insert_with(|| "`min()` clamp".to_owned());
                return Step::Continue;
            }
            _ => {}
        }
        if is_variant_like(&name) {
            return path_consequence(&func.path)
                .map_or(Step::Continue, |found: Consequence| Step::Done(vec![found]));
        }
        if TRANSPARENT_CALLS.contains(&name.as_str()) {
            return Step::Continue;
        }
        let Some(position) = call
            .args
            .iter()
            .position(|arg: &Expr| std::ptr::eq(arg, child))
        else {
            return Step::Continue;
        };
        let owner: Option<String> = call_owner(&func.path);
        if owner.as_deref() == Some("Self") {
            walk.callee.get_or_insert_with(|| path_text(&func.path));
            return Step::Continue;
        }
        let targets: Vec<(FnRef<'a>, String)> =
            self.params(&name, owner.as_deref(), position, call.args.len(), false);
        if targets.is_empty() {
            walk.callee.get_or_insert_with(|| path_text(&func.path));
            Step::Continue
        } else {
            Step::Follow(Follow::Params(targets, name))
        }
    }

    fn method_step(
        &self,
        call: &'a ExprMethodCall,
        child: Option<&'a Expr>,
        walk: &mut Walk,
        location: &str,
    ) -> Step<'a> {
        let Some(child) = child else {
            return Step::Continue;
        };
        let method: String = call.method.to_string();
        if method.starts_with("checked_") {
            walk.checked = true;
        }
        let position: Option<usize> = call
            .args
            .iter()
            .position(|arg: &Expr| std::ptr::eq(arg, child));
        match method.as_str() {
            "ok_or" | "ok_or_else" => {
                return Step::Done(vec![call.args.first().map_or_else(
                    || Consequence::new(Class::Error, "untyped error"),
                    error_site,
                )]);
            }
            "min" | "clamp" => {
                walk.clamp
                    .get_or_insert_with(|| format!("`.{method}()` clamp"));
                return Step::Continue;
            }
            _ => {}
        }
        let Some(position) = position else {
            return Step::Continue;
        };
        match method.as_str() {
            "take" | "truncate" | "take_while" | "split_off" => {
                return Step::Done(vec![Consequence::new(
                    Class::Silent,
                    format!("`.{method}()` in {location}"),
                )]);
            }
            "with_capacity" | "reserve" | "reserve_exact" | "try_reserve" | "try_reserve_exact"
            | "resize" | "shrink_to" => {
                return Step::Done(vec![Consequence::new(
                    Class::Capacity,
                    format!("`.{method}()` in {location}"),
                )]);
            }
            "get" | "get_mut" if walk.ranged => {
                return Step::Done(vec![Consequence::new(
                    Class::Silent,
                    format!("slice in {location}"),
                )]);
            }
            _ => {}
        }
        if TRANSPARENT_METHODS.contains(&method.as_str())
            || TRANSPARENT_METHOD_PREFIXES
                .iter()
                .any(|prefix: &&str| method.starts_with(prefix))
        {
            return Step::Continue;
        }
        let targets: Vec<(FnRef<'a>, String)> =
            self.params(&method, None, position, call.args.len(), true);
        if targets.is_empty() {
            walk.callee.get_or_insert_with(|| format!(".{method}"));
            Step::Continue
        } else {
            Step::Follow(Follow::Params(targets, method))
        }
    }

    fn params(
        &self,
        name: &str,
        owner: Option<&str>,
        position: usize,
        arity: usize,
        method: bool,
    ) -> Vec<(FnRef<'a>, String)> {
        let Some(candidates) = self.index.fns.get(name) else {
            return Vec::new();
        };
        let mut out: Vec<(FnRef<'a>, String)> = Vec::new();
        for candidate in candidates {
            let has_receiver: bool = candidate
                .sig
                .inputs
                .first()
                .is_some_and(|arg: &FnArg| matches!(arg, FnArg::Receiver(_)));
            let params: Vec<Option<String>> = candidate
                .sig
                .inputs
                .iter()
                .filter(|arg: &&FnArg| !(method && matches!(arg, FnArg::Receiver(_))))
                .map(|arg: &FnArg| match arg {
                    FnArg::Receiver(_) => None,
                    FnArg::Typed(typed) => pat_ident(&typed.pat),
                })
                .collect();
            if method && !has_receiver {
                continue;
            }
            if !method && candidate.owner.as_deref() != owner {
                continue;
            }
            if params.len() != arity {
                continue;
            }
            if let Some(Some(param)) = params.get(position) {
                out.push((candidate.clone(), param.clone()));
            }
        }
        if out.len() > MAX_CALLEE_CANDIDATES {
            return Vec::new();
        }
        out
    }

    fn follow(
        &mut self,
        follow: Follow<'a>,
        depth: usize,
        polarity: Option<bool>,
    ) -> Vec<Consequence> {
        match follow {
            Follow::Binding {
                name,
                scope,
                prefix,
                file,
            } => {
                let key: FollowKey = FollowKey::Binding(scope_key(scope), name.clone());
                self.memoized(
                    (key, polarity),
                    depth,
                    |classifier: &mut Self, depth: usize| {
                        let mut finder: Finder<'a, '_> =
                            Finder::new(Target::Path(&name), file, prefix);
                        match scope {
                            Scope::After(block, index) => {
                                for stmt in block.stmts.iter().skip(index + 1) {
                                    finder.visit_stmt(stmt);
                                }
                            }
                            Scope::Body(block) => finder.visit_block(block),
                        }
                        classifier.classify_all(&finder.finish(), depth, &name, polarity)
                    },
                )
            }
            Follow::Field(name) => {
                let key: FollowKey = FollowKey::Field(name.clone());
                self.memoized(
                    (key, polarity),
                    depth,
                    |classifier: &mut Self, depth: usize| {
                        let occurrences: Vec<Occurrence<'a>> =
                            classifier.crate_wide(&name, Target::Field(&name));
                        classifier.classify_all(&occurrences, depth, &name, polarity)
                    },
                )
            }
            Follow::Call(name) => {
                let key: FollowKey = FollowKey::Call(name.clone());
                self.memoized(
                    (key, polarity),
                    depth,
                    |classifier: &mut Self, depth: usize| {
                        let occurrences: Vec<Occurrence<'a>> =
                            classifier.crate_wide(&name, Target::Call(&name));
                        classifier.classify_all(&occurrences, depth, &format!("{name}()"), polarity)
                    },
                )
            }
            Follow::Const(name, file) => {
                let key: FollowKey = FollowKey::Const(name.clone(), file);
                self.memoized(
                    (key, polarity),
                    depth,
                    |classifier: &mut Self, depth: usize| {
                        let occurrences: Vec<Occurrence<'a>> = classifier
                            .crate_wide(&name, Target::Path(&name))
                            .into_iter()
                            .filter(|o: &Occurrence<'a>| classifier.visible(&name, file, o))
                            .collect();
                        classifier.classify_all(&occurrences, depth, &name, polarity)
                    },
                )
            }
            Follow::Params(targets, callee) => {
                let mut found: Vec<Consequence> = Vec::new();
                for (target, param) in targets {
                    found.extend(self.follow(
                        Follow::Binding {
                            name: param,
                            scope: Scope::Body(target.block),
                            prefix: vec![Node::Fn(target.ident, target.block)],
                            file: target.file,
                        },
                        depth,
                        polarity,
                    ));
                }
                if found.is_empty() {
                    vec![Consequence::new(
                        Class::Unresolved,
                        format!("parameter of `{callee}` with no read found"),
                    )]
                } else {
                    reduce(found)
                }
            }
        }
    }

    fn memoized(
        &mut self,
        key: (FollowKey, Option<bool>),
        depth: usize,
        compute: impl FnOnce(&mut Self, usize) -> Vec<Consequence>,
    ) -> Vec<Consequence> {
        if let Some(entry) = self.memo.get(&key) {
            return entry.clone().unwrap_or_default();
        }
        self.memo.insert(key.clone(), None);
        let found: Vec<Consequence> = compute(self, depth);
        self.memo.insert(key, Some(found.clone()));
        found
    }

    fn crate_wide(&self, name: &str, target: Target<'_>) -> Vec<Occurrence<'a>> {
        let mut finder: Finder<'a, '_> = Finder::new(target, 0, Vec::new());
        for (file_index, (file, text)) in self.files.iter().zip(self.texts).enumerate() {
            if text.contains(name) {
                finder.set_file(file_index);
                finder.visit_file(file);
            }
        }
        finder.finish()
    }

    fn classify_all(
        &mut self,
        occurrences: &[Occurrence<'a>],
        depth: usize,
        name: &str,
        polarity: Option<bool>,
    ) -> Vec<Consequence> {
        let mut found: Vec<Consequence> = Vec::new();
        for occurrence in occurrences {
            found.extend(self.classify(occurrence, depth, polarity));
        }
        if found.is_empty() {
            vec![Consequence::new(
                Class::Unresolved,
                format!("stored in `{name}` with no read found"),
            )]
        } else {
            reduce(found)
        }
    }
}

fn scope_key(scope: Scope<'_>) -> (usize, Option<usize>) {
    match scope {
        Scope::After(block, index) => (std::ptr::from_ref(block).addr(), Some(index)),
        Scope::Body(block) => (std::ptr::from_ref(block).addr(), None),
    }
}

fn same_expr(left: &Expr, right: &Expr) -> bool {
    std::ptr::eq(left, right)
}

fn in_const_assertion(stack: &[Node<'_>]) -> bool {
    stack
        .iter()
        .any(|node: &Node<'_>| matches!(node, Node::Item(ident) if *ident == "_"))
}

fn is_write(stack: &[Node<'_>]) -> bool {
    let [.., parent, Node::Expr(child)] = stack else {
        return false;
    };
    match parent {
        Node::Expr(Expr::Assign(assign)) => same_expr(child, &assign.left),
        Node::Expr(Expr::Binary(binary)) => {
            is_compound_assign(binary.op) && same_expr(child, &binary.left)
        }
        _ => false,
    }
}

fn binary_step<'a>(
    binary: &ExprBinary,
    is_child: &impl Fn(&Expr) -> bool,
    walk: &mut Walk,
    location: &str,
) -> Step<'a> {
    let on_left: bool = is_child(&binary.left);
    if is_compound_assign(binary.op) {
        if on_left {
            return Step::Done(Vec::new());
        }
        return match expr_name(&binary.left) {
            Some(name) if is_flag_name(&name) => Step::Done(vec![Consequence::new(
                Class::Record,
                format!("flag `{name}`"),
            )]),
            _ => Step::Done(vec![Consequence::new(
                Class::Unresolved,
                format!("compound assignment in {location}"),
            )]),
        };
    }
    let exceeded_when_true: Option<bool> = match binary.op {
        BinOp::Gt(_) | BinOp::Ge(_) => Some(!on_left),
        BinOp::Lt(_) | BinOp::Le(_) => Some(on_left),
        BinOp::Eq(_) => Some(true),
        BinOp::Ne(_) => Some(false),
        _ => None,
    };
    if walk.polarity.is_none() {
        walk.polarity = exceeded_when_true;
    }
    Step::Continue
}

fn local_step<'a>(
    stack: &[Node<'a>],
    at: usize,
    local: &'a Local,
    child: Node<'a>,
    walk: &Walk,
    location: &str,
    occurrence: &Occurrence<'a>,
) -> Step<'a> {
    let Some(init) = &local.init else {
        return Step::Continue;
    };
    let Node::Expr(child) = child else {
        return Step::Continue;
    };
    if !same_expr(child, &init.expr) {
        return Step::Continue;
    }
    if let Some((_, diverge)) = &init.diverge {
        return Step::Done(settle(scan(&[Part::Expr(diverge)]), location));
    }
    let Some(name) = pat_ident(&local.pat) else {
        return Step::Done(vec![Consequence::new(
            Class::Unresolved,
            format!("pattern binding in {location}"),
        )]);
    };
    if walk.polarity.is_some() && is_flag_name(&name) {
        return Step::Done(vec![Consequence::new(
            Class::Record,
            format!("flag `{name}`"),
        )]);
    }
    let (Some(Node::Stmt(stmt)), Some(Node::Block(block))) = (
        at.checked_sub(1).map(|i: usize| stack[i]),
        at.checked_sub(2).map(|i: usize| stack[i]),
    ) else {
        return Step::Done(boundary(walk, location));
    };
    let Some(index) = block
        .stmts
        .iter()
        .position(|candidate: &Stmt| std::ptr::eq(candidate, stmt))
    else {
        return Step::Done(boundary(walk, location));
    };
    Step::Follow(Follow::Binding {
        name,
        scope: Scope::After(block, index),
        prefix: stack[..at - 1].to_vec(),
        file: occurrence.file,
    })
}

fn assign_step<'a>(
    stack: &[Node<'a>],
    at: usize,
    assign: &'a ExprAssign,
    walk: &Walk,
    location: &str,
    file: usize,
) -> Step<'a> {
    let Some(name) = expr_name(&assign.left) else {
        return Step::Done(boundary(walk, location));
    };
    if walk.polarity.is_some() && is_flag_name(&name) {
        return Step::Done(vec![Consequence::new(
            Class::Record,
            format!("flag `{name}`"),
        )]);
    }
    if matches!(&*assign.left, Expr::Field(_)) {
        return Step::Follow(Follow::Field(name));
    }
    let Some(fn_at) = stack[..at]
        .iter()
        .rposition(|node: &Node<'a>| matches!(node, Node::Fn(..)))
    else {
        return Step::Done(boundary(walk, location));
    };
    let Node::Fn(_, body) = stack[fn_at] else {
        return Step::Done(boundary(walk, location));
    };
    Step::Follow(Follow::Binding {
        name,
        scope: Scope::Body(body),
        prefix: stack[..=fn_at].to_vec(),
        file,
    })
}

fn macro_step<'a>(name: &str, call: &ExprCall, child: &Expr, location: &str) -> Step<'a> {
    let found: Consequence = match name {
        "ensure" | "anyhow_ensure" | "eyre_ensure" => {
            let is_condition: bool = call
                .args
                .first()
                .is_some_and(|first: &Expr| std::ptr::eq(first, child));
            match call.args.iter().nth(1) {
                Some(error) if is_condition => error_site(error),
                _ => Consequence::new(Class::Error, format!("untyped `{name}!`")),
            }
        }
        "bail" | "eyre" | "anyhow" | "format_err" | "miette" => {
            Consequence::new(Class::Error, format!("untyped `{name}!`"))
        }
        "assert" | "assert_eq" | "assert_ne" | "panic" | "unreachable" => {
            Consequence::new(Class::Panic, format!("`{name}!` in {location}"))
        }
        "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => {
            Consequence::new(Class::Silent, format!("`{name}!` only in {location}"))
        }
        _ => return Step::Continue,
    };
    Step::Done(vec![found])
}

fn clamped(found: Vec<Consequence>, walk: &Walk, location: &str) -> Vec<Consequence> {
    match &walk.clamp {
        Some(clamp)
            if !found.iter().any(|c: &Consequence| {
                c.class <= Class::Delegated || c.class == Class::Capacity
            }) =>
        {
            vec![Consequence::new(
                Class::Silent,
                format!("{clamp} in {location}"),
            )]
        }
        _ => found,
    }
}

fn boundary(walk: &Walk, location: &str) -> Vec<Consequence> {
    if let Some(callee) = &walk.callee {
        return vec![Consequence::new(
            Class::Delegated,
            format!("passed to `{callee}`"),
        )];
    }
    if let Some(clamp) = &walk.clamp {
        return vec![Consequence::new(
            Class::Silent,
            format!("{clamp} in {location}"),
        )];
    }
    vec![Consequence::new(
        Class::Unresolved,
        format!("value in {location}"),
    )]
}

fn location(stack: &[Node<'_>]) -> String {
    stack
        .iter()
        .rev()
        .find_map(|node: &Node<'_>| match node {
            Node::Fn(ident, ..) | Node::Item(ident) => Some(format!("`{ident}`")),
            _ => None,
        })
        .unwrap_or_else(|| "module scope".to_owned())
}

fn if_consequences<'a>(
    expr_if: &'a ExprIf,
    polarity: Option<bool>,
    stack: &[Node<'a>],
    at: usize,
    location: &str,
) -> Option<Vec<Consequence>> {
    let then_scan: Scan = scan(&[Part::Block(&expr_if.then_branch)]);
    let else_scan: Option<Scan> = expr_if
        .else_branch
        .as_ref()
        .map(|(_, branch): &(syn::token::Else, Box<Expr>)| scan(&[Part::Expr(branch)]));
    let following = |then_scan: &Scan| -> Option<Scan> {
        if else_scan.is_some() || !then_scan.diverges() {
            return None;
        }
        following_stmts(stack, at)
    };
    let has_else: bool = else_scan.is_some();
    let chosen: Scan = match polarity {
        Some(true) => then_scan,
        Some(false) => match (&else_scan, following(&then_scan)) {
            (Some(branch), _) => branch.clone(),
            (None, Some(rest)) => rest,
            (None, None) => {
                return Some(vec![Consequence::new(
                    Class::Silent,
                    format!("skipped in {location}"),
                )]);
            }
        },
        None => {
            let rest: Option<Scan> = following(&then_scan);
            let mut merged: Scan = then_scan;
            for other in else_scan.into_iter().chain(rest) {
                merged.found.extend(other.found);
                if merged.exit.is_none() {
                    merged.exit = other.exit;
                }
            }
            merged
        }
    };
    let value_position: bool = !matches!(
        at.checked_sub(1).map(|index: usize| stack[index]),
        Some(Node::Stmt(Stmt::Expr(_, Some(_))))
    );
    if chosen.found.is_empty() && chosen.exit.is_none() && has_else && value_position {
        return None;
    }
    Some(settle(chosen, location))
}

fn following_stmts(stack: &[Node<'_>], at: usize) -> Option<Scan> {
    let Node::Stmt(stmt) = stack.get(at.checked_sub(1)?)? else {
        return None;
    };
    let Node::Block(block) = stack.get(at.checked_sub(2)?)? else {
        return None;
    };
    let index: usize = block
        .stmts
        .iter()
        .position(|candidate: &Stmt| std::ptr::eq(candidate, *stmt))?;
    let mut merged: Scan = Scan::default();
    for next in block.stmts.iter().skip(index + 1) {
        let part: Scan = scan(&[Part::Stmt(next)]);
        let decisive: bool = part.diverges();
        merged.found.extend(part.found);
        if merged.exit.is_none() {
            merged.exit = part.exit;
        }
        if decisive {
            break;
        }
    }
    Some(merged)
}

fn settle(scan: Scan, location: &str) -> Vec<Consequence> {
    if scan.found.is_empty() {
        let what: String = scan
            .exit
            .map_or_else(|| "no action".to_owned(), |exit: &str| format!("`{exit}`"));
        vec![Consequence::new(
            Class::Silent,
            format!("{what} in {location}"),
        )]
    } else {
        reduce(scan.found)
    }
}

#[derive(Debug, Clone, Copy)]
enum Part<'a> {
    Block(&'a Block),
    Expr(&'a Expr),
    Stmt(&'a Stmt),
}

#[derive(Debug, Clone, Default)]
struct Scan {
    found: Vec<Consequence>,
    exit: Option<&'static str>,
}

impl Scan {
    fn diverges(&self) -> bool {
        self.exit.is_some()
            || self
                .found
                .iter()
                .any(|c: &Consequence| matches!(c.class, Class::Error | Class::Panic))
    }
}

fn scan(parts: &[Part<'_>]) -> Scan {
    let mut scanner: Scanner = Scanner::default();
    for part in parts {
        match part {
            Part::Block(block) => scanner.visit_block(block),
            Part::Expr(expr) => scanner.visit_expr(expr),
            Part::Stmt(stmt) => scanner.visit_stmt(stmt),
        }
    }
    scanner.scan
}

#[derive(Default)]
struct Scanner {
    scan: Scan,
}

impl Scanner {
    fn push(&mut self, found: Consequence) {
        self.scan.found.push(found);
    }

    fn exit(&mut self, kind: &'static str) {
        self.scan.exit.get_or_insert(kind);
    }
}

impl<'a> Visit<'a> for Scanner {
    fn visit_attribute(&mut self, _: &'a Attribute) {}

    fn visit_item(&mut self, _: &'a Item) {}

    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        if let Some(name) = macro_name(node) {
            match name.as_str() {
                "bail" | "eyre" | "anyhow" | "format_err" | "miette" | "ensure" => {
                    self.push(Consequence::new(Class::Error, format!("untyped `{name}!`")));
                }
                "panic" | "unreachable" | "assert" | "assert_eq" | "assert_ne" => {
                    self.push(Consequence::new(Class::Panic, format!("`{name}!`")));
                }
                _ => {}
            }
        } else if let Expr::Path(func) = &*node.func {
            if func.path.is_ident("Err") {
                match node.args.first() {
                    Some(arg) => self.push(error_site(arg)),
                    None => self.push(Consequence::new(Class::Error, "untyped error")),
                }
            } else if let Some(found) = path_consequence(&func.path) {
                self.push(found);
            } else if let Some(last) = func.path.segments.last()
                && is_record_call(&last.ident.to_string())
            {
                self.push(Consequence::new(
                    Class::Record,
                    format!("`{}()`", last.ident),
                ));
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'a ExprPath) {
        if let Some(found) = path_consequence(&node.path) {
            self.push(found);
        }
    }

    fn visit_expr_struct(&mut self, node: &'a ExprStruct) {
        if let Some(found) = path_consequence(&node.path) {
            self.push(found);
        }
        for field in &node.fields {
            if let (Member::Named(name), Expr::Lit(lit)) = (&field.member, &field.expr)
                && matches!(lit.lit, Lit::Bool(_))
            {
                self.push(Consequence::new(Class::Record, format!("flag `{name}`")));
            }
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method: String = node.method.to_string();
        if matches!(method.as_str(), "ok_or" | "ok_or_else") {
            if let Some(arg) = node.args.first() {
                self.push(error_site(arg));
            }
        } else if is_record_call(&method) {
            self.push(Consequence::new(Class::Record, format!("`.{method}()`")));
        } else if COLLECT_METHODS.contains(&method.as_str())
            && let Some(receiver) = expr_name(&node.receiver)
            && is_flag_name(&receiver)
        {
            self.push(Consequence::new(Class::Record, format!("`{receiver}`")));
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'a ExprAssign) {
        if let Some(name) = expr_name(&node.left) {
            let literal_bool: bool =
                matches!(&*node.right, Expr::Lit(lit) if matches!(lit.lit, Lit::Bool(_)));
            if literal_bool || is_flag_name(&name) {
                self.push(Consequence::new(Class::Record, format!("flag `{name}`")));
            }
        }
        syn::visit::visit_expr_assign(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'a ExprBinary) {
        if is_compound_assign(node.op)
            && let Some(name) = expr_name(&node.left)
            && is_flag_name(&name)
        {
            self.push(Consequence::new(Class::Record, format!("flag `{name}`")));
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_expr_return(&mut self, node: &'a ExprReturn) {
        self.exit("return");
        syn::visit::visit_expr_return(self, node);
    }

    fn visit_expr_break(&mut self, node: &'a ExprBreak) {
        self.exit("break");
        syn::visit::visit_expr_break(self, node);
    }

    fn visit_expr_continue(&mut self, _: &'a ExprContinue) {
        self.exit("continue");
    }
}

fn error_site(expr: &Expr) -> Consequence {
    let mut collector: VariantCollector = VariantCollector::default();
    collector.visit_expr(expr);
    if let Some((owner, variant)) = collector.variants.first() {
        let detail: String = format!("`{owner}::{variant}`");
        let mut variants: Vec<(String, String)> = collector.variants;
        variants.truncate(MAX_VARIANTS_PER_SITE);
        return Consequence {
            class: Class::Error,
            detail,
            variants,
        };
    }
    let detail: String = collector.untyped.map_or_else(
        || match expr {
            Expr::Call(call) => match (macro_name(call), &*call.func) {
                (Some(name), _) => format!("untyped `{name}!`"),
                (None, Expr::Path(func)) => format!("`{}()`", path_text(&func.path)),
                (None, _) => "untyped error".to_owned(),
            },
            Expr::MethodCall(call) => format!("`.{}()`", call.method),
            Expr::Path(path) => format!("`{}`", path_text(&path.path)),
            _ => "untyped error".to_owned(),
        },
        |name: String| format!("untyped `{name}!`"),
    );
    Consequence::new(Class::Error, detail)
}

#[derive(Default)]
struct VariantCollector {
    variants: Vec<(String, String)>,
    untyped: Option<String>,
}

impl VariantCollector {
    fn path(&mut self, path: &Path) {
        if let Some(pair) = variant_pair(path)
            && !self.variants.contains(&pair)
        {
            self.variants.push(pair);
        }
    }
}

impl<'a> Visit<'a> for VariantCollector {
    fn visit_attribute(&mut self, _: &'a Attribute) {}

    fn visit_expr_path(&mut self, node: &'a ExprPath) {
        self.path(&node.path);
    }

    fn visit_expr_struct(&mut self, node: &'a ExprStruct) {
        self.path(&node.path);
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        if let Some(name) = macro_name(node) {
            if matches!(
                name.as_str(),
                "eyre" | "anyhow" | "format_err" | "miette" | "format"
            ) {
                self.untyped.get_or_insert(name);
            }
        } else if let Expr::Path(func) = &*node.func {
            self.path(&func.path);
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn variant_pair(path: &Path) -> Option<(String, String)> {
    let count: usize = path.segments.len();
    if count < 2 {
        return None;
    }
    let last: String = path.segments[count - 1].ident.to_string();
    let owner: String = path.segments[count - 2].ident.to_string();
    is_variant_like(&last).then_some((owner, last))
}

fn is_variant_like(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_uppercase())
        && name.chars().any(|c: char| c.is_ascii_lowercase())
}

fn is_error_owner(owner: &str) -> bool {
    owner.ends_with("Error") || owner.ends_with("ErrorKind") || owner.ends_with("Err")
}

fn path_consequence(path: &Path) -> Option<Consequence> {
    let (owner, variant): (String, String) = variant_pair(path)?;
    if is_error_owner(&owner) {
        return Some(Consequence {
            class: Class::Error,
            detail: format!("`{owner}::{variant}`"),
            variants: vec![(owner, variant)],
        });
    }
    let text: String = format!("{owner}::{variant}").to_ascii_lowercase();
    RECORD_WORDS
        .iter()
        .any(|word: &&str| text.contains(word))
        .then(|| Consequence::new(Class::Record, format!("`{owner}::{variant}`")))
}

fn is_record_call(name: &str) -> bool {
    name == "note"
        || RECORD_METHOD_PREFIXES
            .iter()
            .any(|prefix: &&str| name.starts_with(prefix))
}

fn is_flag_name(name: &str) -> bool {
    let lower: String = name.to_ascii_lowercase();
    RECORD_WORDS.iter().any(|word: &&str| lower.contains(word))
}

const fn is_compound_assign(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
            | BinOp::BitXorAssign(_)
            | BinOp::BitAndAssign(_)
            | BinOp::BitOrAssign(_)
            | BinOp::ShlAssign(_)
            | BinOp::ShrAssign(_)
    )
}

fn expr_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => match &field.member {
            Member::Named(ident) => Some(ident.to_string()),
            Member::Unnamed(_) => None,
        },
        Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => expr_name(&unary.expr),
        Expr::Paren(paren) => expr_name(&paren.expr),
        _ => None,
    }
}

fn pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => pat_ident(&typed.pat),
        _ => None,
    }
}

fn call_owner(path: &Path) -> Option<String> {
    let count: usize = path.segments.len();
    count
        .checked_sub(2)
        .map(|index: usize| path.segments[index].ident.to_string())
}

fn path_text(path: &Path) -> String {
    let count: usize = path.segments.len();
    path.segments
        .iter()
        .skip(count.saturating_sub(2))
        .map(|segment: &syn::PathSegment| segment.ident.to_string())
        .collect::<Vec<String>>()
        .join("::")
}
