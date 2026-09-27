use std::collections::{BTreeMap, BTreeSet};

use super::render::{Code, LabelId, Piece};

const INDENT_UNIT: &str = "    ";
const MAX_SIMPLIFY_ROUNDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LabelKind {
    Block,
    Loop,
    Try,
    Finally,
}

#[derive(Debug, Clone)]
pub(super) enum Transfer {
    Break(LabelId),
    Continue(LabelId),
    Return(Option<Code>),
}

#[derive(Debug, Clone)]
pub(super) struct Raw {
    pub(super) code: Code,
    pub(super) indent: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct CondTransfer {
    pub(super) test: Code,
    pub(super) negated: Code,
    pub(super) transfer: Transfer,
}

#[derive(Debug, Clone)]
pub(super) struct Handler {
    pub(super) param: Option<Code>,
    pub(super) body: Vec<Out>,
}

#[derive(Debug, Clone)]
pub(super) struct Finalizer {
    pub(super) label: LabelId,
    pub(super) body: Vec<Out>,
}

#[derive(Debug, Clone)]
pub(super) enum LoopHead {
    Infinite,
    While(Code),
    DoWhile(Code),
}

#[derive(Debug, Clone)]
pub(super) enum Out {
    Raw(Raw),
    CondTransfer(CondTransfer),
    Transfer(Transfer),
    Block {
        label: LabelId,
        body: Vec<Self>,
    },
    Loop {
        label: LabelId,
        head: LoopHead,
        body: Vec<Self>,
    },
    If {
        test: Code,
        negated: Code,
        then: Vec<Self>,
        otherwise: Vec<Self>,
    },
    Try {
        label: LabelId,
        block: Vec<Self>,
        handler: Option<Handler>,
        finalizer: Option<Finalizer>,
    },
}

impl Out {
    fn bodies(&self) -> Vec<&Vec<Self>> {
        match self {
            Self::Raw(_) | Self::CondTransfer(_) | Self::Transfer(_) => Vec::new(),
            Self::Block { body, .. } | Self::Loop { body, .. } => vec![body],
            Self::If {
                then, otherwise, ..
            } => vec![then, otherwise],
            Self::Try {
                block,
                handler,
                finalizer,
                ..
            } => {
                let mut bodies: Vec<&Vec<Self>> = vec![block];
                if let Some(handler) = handler {
                    bodies.push(&handler.body);
                }
                if let Some(finalizer) = finalizer {
                    bodies.push(&finalizer.body);
                }
                bodies
            }
        }
    }

    fn bodies_mut(&mut self) -> Vec<&mut Vec<Self>> {
        match self {
            Self::Raw(_) | Self::CondTransfer(_) | Self::Transfer(_) => Vec::new(),
            Self::Block { body, .. } | Self::Loop { body, .. } => vec![body],
            Self::If {
                then, otherwise, ..
            } => vec![then, otherwise],
            Self::Try {
                block,
                handler,
                finalizer,
                ..
            } => {
                let mut bodies: Vec<&mut Vec<Self>> = vec![block];
                if let Some(handler) = handler {
                    bodies.push(&mut handler.body);
                }
                if let Some(finalizer) = finalizer {
                    bodies.push(&mut finalizer.body);
                }
                bodies
            }
        }
    }

    fn codes(&self) -> Vec<&Code> {
        match self {
            Self::Raw(raw) => vec![&raw.code],
            Self::CondTransfer(cond) => {
                let mut codes: Vec<&Code> = vec![&cond.test];
                codes.extend(transfer_code(&cond.transfer));
                codes
            }
            Self::Transfer(transfer) => transfer_code(transfer).into_iter().collect(),
            Self::Block { .. } => Vec::new(),
            Self::Loop { head, .. } => match head {
                LoopHead::Infinite => Vec::new(),
                LoopHead::While(test) | LoopHead::DoWhile(test) => vec![test],
            },
            Self::If { test, .. } => vec![test],
            Self::Try { handler, .. } => handler
                .as_ref()
                .and_then(|handler: &Handler| handler.param.as_ref())
                .into_iter()
                .collect(),
        }
    }

    fn codes_mut(&mut self) -> Vec<&mut Code> {
        match self {
            Self::Raw(raw) => vec![&mut raw.code],
            Self::CondTransfer(cond) => {
                let mut codes: Vec<&mut Code> = vec![&mut cond.test, &mut cond.negated];
                if let Transfer::Return(Some(code)) = &mut cond.transfer {
                    codes.push(code);
                }
                codes
            }
            Self::Transfer(Transfer::Return(Some(code))) => vec![code],
            Self::Transfer(_) | Self::Block { .. } | Self::Try { .. } => Vec::new(),
            Self::Loop { head, .. } => match head {
                LoopHead::Infinite => Vec::new(),
                LoopHead::While(test) | LoopHead::DoWhile(test) => vec![test],
            },
            Self::If { test, negated, .. } => vec![test, negated],
        }
    }

    const fn transfer_mut(&mut self) -> Option<&mut Transfer> {
        match self {
            Self::CondTransfer(cond) => Some(&mut cond.transfer),
            Self::Transfer(transfer) => Some(transfer),
            _ => None,
        }
    }
}

const fn transfer_code(transfer: &Transfer) -> Option<&Code> {
    match transfer {
        Transfer::Return(Some(code)) => Some(code),
        Transfer::Return(None) | Transfer::Break(_) | Transfer::Continue(_) => None,
    }
}

const fn transfer_label(transfer: &Transfer) -> Option<LabelId> {
    match transfer {
        Transfer::Break(label) | Transfer::Continue(label) => Some(*label),
        Transfer::Return(_) => None,
    }
}

#[derive(Debug, Default)]
pub(super) struct Labels {
    kinds: Vec<LabelKind>,
}

impl Labels {
    pub(super) fn fresh(&mut self, kind: LabelKind) -> LabelId {
        self.kinds.push(kind);
        LabelId(self.kinds.len() - 1)
    }
}

fn count_uses(body: &[Out], uses: &mut BTreeMap<LabelId, usize>) {
    for out in body {
        for code in out.codes() {
            for piece in &code.pieces {
                if let Piece::Label(label) = piece {
                    *uses.entry(*label).or_insert(0) += 1;
                }
            }
        }
        let transfer: Option<&Transfer> = match out {
            Out::CondTransfer(cond) => Some(&cond.transfer),
            Out::Transfer(transfer) => Some(transfer),
            _ => None,
        };
        if let Some(label) = transfer.and_then(transfer_label) {
            *uses.entry(label).or_insert(0) += 1;
        }
        for inner in out.bodies() {
            count_uses(inner, uses);
        }
    }
}

fn uses_of(body: &[Out]) -> BTreeMap<LabelId, usize> {
    let mut uses: BTreeMap<LabelId, usize> = BTreeMap::new();
    count_uses(body, &mut uses);
    uses
}

fn mentions(body: &[Out], label: LabelId) -> bool {
    uses_of(body)
        .get(&label)
        .is_some_and(|count: &usize| *count > 0)
}

pub(super) fn simplify(body: &mut Vec<Out>) {
    let mut aliases: BTreeMap<LabelId, LabelId> = BTreeMap::new();
    collect_loop_aliases(body, &mut aliases);
    apply_aliases(body, &aliases);
    recover_loop_tests(body);
    for _ in 0..MAX_SIMPLIFY_ROUNDS {
        let uses: BTreeMap<LabelId, usize> = uses_of(body);
        let mut changed: bool = flatten_unused_blocks(body, &uses);
        changed |= structure_conditionals(body);
        if !changed {
            break;
        }
    }
    recover_do_while(body);
    strip_tail(body, &BTreeSet::new(), &BTreeSet::new(), true);
    let uses: BTreeMap<LabelId, usize> = uses_of(body);
    flatten_unused_blocks(body, &uses);
}

fn collect_loop_aliases(body: &[Out], aliases: &mut BTreeMap<LabelId, LabelId>) {
    for out in body {
        if let Out::Block { label, body } = out
            && let [Out::Loop { label: inner, .. }] = body.as_slice()
        {
            aliases.insert(*label, *inner);
        }
        for inner in out.bodies() {
            collect_loop_aliases(inner, aliases);
        }
    }
}

fn resolve_alias(label: LabelId, aliases: &BTreeMap<LabelId, LabelId>) -> LabelId {
    let mut current: LabelId = label;
    for _ in 0..=aliases.len() {
        match aliases.get(&current) {
            Some(next) => current = *next,
            None => break,
        }
    }
    current
}

fn apply_aliases(body: &mut Vec<Out>, aliases: &BTreeMap<LabelId, LabelId>) {
    let mut index: usize = 0;
    while index < body.len() {
        let unwrap_block: bool = matches!(
            &body[index],
            Out::Block { label, .. } if aliases.contains_key(label)
        );
        if unwrap_block {
            if let Out::Block { body: inner, .. } = body.remove(index) {
                body.splice(index..index, inner);
            }
            continue;
        }
        let out: &mut Out = &mut body[index];
        for code in out.codes_mut() {
            for piece in &mut code.pieces {
                if let Piece::Label(label) = piece {
                    *label = resolve_alias(*label, aliases);
                }
            }
        }
        if let Some(Transfer::Break(label)) = out.transfer_mut() {
            *label = resolve_alias(*label, aliases);
        }
        for inner in out.bodies_mut() {
            apply_aliases(inner, aliases);
        }
        index += 1;
    }
}

fn recover_loop_tests(body: &mut [Out]) {
    for out in body {
        if let Out::Loop { label, head, body } = out
            && matches!(head, LoopHead::Infinite)
            && let Some(Out::CondTransfer(cond)) = body.first()
            && matches!(cond.transfer, Transfer::Break(target) if target == *label)
        {
            let negated: Code = cond.negated.clone();
            body.remove(0);
            *head = LoopHead::While(negated);
        }
        for inner in out.bodies_mut() {
            recover_loop_tests(inner);
        }
    }
}

fn flatten_unused_blocks(body: &mut Vec<Out>, uses: &BTreeMap<LabelId, usize>) -> bool {
    let mut changed: bool = false;
    let mut index: usize = 0;
    while index < body.len() {
        let unused: bool = matches!(
            &body[index],
            Out::Block { label, .. } if uses.get(label).copied().unwrap_or(0) == 0
        );
        if unused {
            if let Out::Block { body: inner, .. } = body.remove(index) {
                body.splice(index..index, inner);
            }
            changed = true;
            continue;
        }
        for inner in body[index].bodies_mut() {
            changed |= flatten_unused_blocks(inner, uses);
        }
        index += 1;
    }
    changed
}

fn structure_conditionals(body: &mut [Out]) -> bool {
    let mut changed: bool = false;
    for out in body.iter_mut() {
        if let Out::Block { label, body } = out {
            changed |= conditional_breaks(*label, body);
        }
        for inner in out.bodies_mut() {
            changed |= structure_conditionals(inner);
        }
    }
    changed
}

fn conditional_breaks(label: LabelId, body: &mut Vec<Out>) -> bool {
    let guard: Option<usize> = body.iter().position(|out: &Out| {
        matches!(out, Out::CondTransfer(cond) if matches!(cond.transfer, Transfer::Break(target) if target == label))
    });
    if let Some(index) = guard
        && index + 1 < body.len()
    {
        let rest: Vec<Out> = body.split_off(index + 1);
        if let Some(Out::CondTransfer(cond)) = body.pop() {
            body.push(Out::If {
                test: cond.negated,
                negated: cond.test,
                then: rest,
                otherwise: Vec::new(),
            });
            return true;
        }
        return false;
    }
    let branch: Option<usize> = body.iter().position(|out: &Out| {
        matches!(out, Out::If { then, otherwise, .. }
            if otherwise.is_empty()
                && matches!(then.last(), Some(Out::Transfer(Transfer::Break(target))) if *target == label))
    });
    if let Some(index) = branch
        && index + 1 < body.len()
    {
        let rest: Vec<Out> = body.split_off(index + 1);
        if let Some(Out::If {
            then, otherwise, ..
        }) = body.last_mut()
        {
            then.pop();
            *otherwise = rest;
            return true;
        }
    }
    false
}

fn recover_do_while(body: &mut Vec<Out>) {
    let mut index: usize = 0;
    while index < body.len() {
        for inner in body[index].bodies_mut() {
            recover_do_while(inner);
        }
        if let Some(exit) = do_while_split(&mut body[index]) {
            let count: usize = exit.len();
            body.splice(index + 1..=index, exit);
            index += count;
        }
        index += 1;
    }
}

fn do_while_split(out: &mut Out) -> Option<Vec<Out>> {
    let Out::Loop { label, head, body } = out else {
        return None;
    };
    if !matches!(head, LoopHead::Infinite) {
        return None;
    }
    let label: LabelId = *label;
    let guard: usize = body.iter().rposition(|out: &Out| {
        matches!(out, Out::CondTransfer(cond) if matches!(cond.transfer, Transfer::Continue(target) if target == label))
    })?;
    let exit_leaves: bool = matches!(
        body.last(),
        Some(Out::Transfer(transfer)) if transfer_label(transfer) != Some(label)
    );
    if guard + 1 >= body.len()
        || !exit_leaves
        || mentions(&body[..guard], label)
        || mentions(&body[guard + 1..], label)
    {
        return None;
    }
    let exit: Vec<Out> = body.split_off(guard + 1);
    let Some(Out::CondTransfer(cond)) = body.pop() else {
        return None;
    };
    *head = LoopHead::DoWhile(cond.test);
    Some(exit)
}

fn strip_tail(
    body: &mut Vec<Out>,
    breaks: &BTreeSet<LabelId>,
    continues: &BTreeSet<LabelId>,
    returns: bool,
) {
    loop {
        let removable: bool = match body.last() {
            Some(Out::Transfer(Transfer::Break(label))) => breaks.contains(label),
            Some(Out::Transfer(Transfer::Continue(label))) => continues.contains(label),
            Some(Out::Transfer(Transfer::Return(None))) => returns,
            _ => false,
        };
        if !removable {
            break;
        }
        body.pop();
    }
    let last: usize = body.len().saturating_sub(1);
    let empty: BTreeSet<LabelId> = BTreeSet::new();
    for (index, out) in body.iter_mut().enumerate() {
        let tail: bool = index == last;
        let outer_breaks: &BTreeSet<LabelId> = if tail { breaks } else { &empty };
        let outer_continues: &BTreeSet<LabelId> = if tail { continues } else { &empty };
        let outer_returns: bool = tail && returns;
        match out {
            Out::Block { label, body } => {
                let mut inner: BTreeSet<LabelId> = outer_breaks.clone();
                inner.insert(*label);
                strip_tail(body, &inner, outer_continues, outer_returns);
            }
            Out::If {
                then, otherwise, ..
            } => {
                strip_tail(then, outer_breaks, outer_continues, outer_returns);
                strip_tail(otherwise, outer_breaks, outer_continues, outer_returns);
            }
            Out::Loop { label, body, .. } => {
                let mut inner: BTreeSet<LabelId> = BTreeSet::new();
                inner.insert(*label);
                strip_tail(body, &BTreeSet::new(), &inner, false);
            }
            Out::Try {
                label,
                block,
                handler,
                finalizer,
            } => {
                let mut inner: BTreeSet<LabelId> = outer_breaks.clone();
                inner.insert(*label);
                strip_tail(block, &inner, outer_continues, outer_returns);
                if let Some(handler) = handler {
                    strip_tail(&mut handler.body, &inner, outer_continues, outer_returns);
                }
                if let Some(finalizer) = finalizer {
                    let mut finally_exit: BTreeSet<LabelId> = BTreeSet::new();
                    finally_exit.insert(finalizer.label);
                    strip_tail(&mut finalizer.body, &finally_exit, &BTreeSet::new(), false);
                }
            }
            Out::Raw(_) | Out::CondTransfer(_) | Out::Transfer(_) => {}
        }
    }
}

pub(super) fn print(
    body: &[Out],
    base_indent: &str,
    reserved: &BTreeSet<String>,
    labels: &Labels,
) -> String {
    let uses: BTreeMap<LabelId, usize> = uses_of(body);
    let mut names: BTreeMap<LabelId, String> = BTreeMap::new();
    let mut counters: BTreeMap<&'static str, usize> = BTreeMap::new();
    for label in uses.keys() {
        let prefix: &'static str = match labels.kinds.get(label.0) {
            Some(LabelKind::Loop) => "loop",
            Some(LabelKind::Try) => "attempt",
            Some(LabelKind::Finally) => "cleanup",
            Some(LabelKind::Block) | None => "block",
        };
        let counter: &mut usize = counters.entry(prefix).or_insert(0);
        let name: String = loop {
            *counter += 1;
            let candidate: String = format!("{prefix}_{counter}");
            if !reserved.contains(&candidate) {
                break candidate;
            }
        };
        names.insert(*label, name);
    }
    let mut printer: Printer<'_> = Printer {
        names: &names,
        uses,
        out: String::new(),
    };
    printer.body(body, &format!("{base_indent}{INDENT_UNIT}"));
    printer.out
}

struct Printer<'n> {
    names: &'n BTreeMap<LabelId, String>,
    uses: BTreeMap<LabelId, usize>,
    out: String,
}

impl Printer<'_> {
    fn used(&self, label: LabelId) -> bool {
        self.uses
            .get(&label)
            .is_some_and(|count: &usize| *count > 0)
    }

    fn name(&self, label: LabelId) -> &str {
        self.names.get(&label).map_or("", String::as_str)
    }

    fn code(&self, code: &Code) -> String {
        let mut text: String = String::new();
        for piece in &code.pieces {
            match piece {
                Piece::Text(chunk) => text.push_str(chunk),
                Piece::Label(label) => text.push_str(self.name(*label)),
            }
        }
        text
    }

    fn line(&mut self, indent: &str, text: &str) {
        self.out.push_str(indent);
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn transfer_text(&self, transfer: &Transfer) -> String {
        match transfer {
            Transfer::Break(label) => format!("break {};", self.name(*label)),
            Transfer::Continue(label) => format!("continue {};", self.name(*label)),
            Transfer::Return(None) => "return;".to_owned(),
            Transfer::Return(Some(code)) => format!("return {};", self.code(code)),
        }
    }

    fn label_prefix(&self, label: LabelId) -> String {
        if self.used(label) {
            format!("{}: ", self.name(label))
        } else {
            String::new()
        }
    }

    fn body(&mut self, body: &[Out], indent: &str) {
        let inner: String = format!("{indent}{INDENT_UNIT}");
        for out in body {
            match out {
                Out::Raw(raw) => {
                    let text: String =
                        reindent(&self.code(&raw.code), raw.indent.as_deref(), indent);
                    self.line(indent, &text);
                }
                Out::CondTransfer(cond) => {
                    let head: String = format!("if ({}) {{", self.code(&cond.test));
                    self.line(indent, &head);
                    let transfer: String = self.transfer_text(&cond.transfer);
                    self.line(&inner, &transfer);
                    self.line(indent, "}");
                }
                Out::Transfer(transfer) => {
                    let text: String = self.transfer_text(transfer);
                    self.line(indent, &text);
                }
                Out::Block { label, body } => {
                    if self.used(*label) {
                        let head: String = format!("{}: {{", self.name(*label));
                        self.line(indent, &head);
                        self.body(body, &inner);
                        self.line(indent, "}");
                    } else {
                        self.body(body, indent);
                    }
                }
                Out::If { .. } => self.conditional(out, indent, ""),
                Out::Loop { label, head, body } => {
                    let prefix: String = self.label_prefix(*label);
                    match head {
                        LoopHead::Infinite => {
                            self.line(indent, &format!("{prefix}while (true) {{"));
                            self.body(body, &inner);
                            self.line(indent, "}");
                        }
                        LoopHead::While(test) => {
                            let head: String = format!("{prefix}while ({}) {{", self.code(test));
                            self.line(indent, &head);
                            self.body(body, &inner);
                            self.line(indent, "}");
                        }
                        LoopHead::DoWhile(test) => {
                            self.line(indent, &format!("{prefix}do {{"));
                            self.body(body, &inner);
                            let tail: String = format!("}} while ({});", self.code(test));
                            self.line(indent, &tail);
                        }
                    }
                }
                Out::Try {
                    label,
                    block,
                    handler,
                    finalizer,
                } => {
                    let head: String = format!("{}try {{", self.label_prefix(*label));
                    self.line(indent, &head);
                    self.body(block, &inner);
                    if let Some(handler) = handler {
                        let head: String = handler.param.as_ref().map_or_else(
                            || "} catch {".to_owned(),
                            |param| format!("}} catch ({}) {{", self.code(param)),
                        );
                        self.line(indent, &head);
                        self.body(&handler.body, &inner);
                    }
                    if let Some(finalizer) = finalizer {
                        self.line(indent, "} finally {");
                        if self.used(finalizer.label) {
                            let head: String = format!("{}: {{", self.name(finalizer.label));
                            self.line(&inner, &head);
                            let deeper: String = format!("{inner}{INDENT_UNIT}");
                            self.body(&finalizer.body, &deeper);
                            self.line(&inner, "}");
                        } else {
                            self.body(&finalizer.body, &inner);
                        }
                    }
                    self.line(indent, "}");
                }
            }
        }
    }

    fn conditional(&mut self, out: &Out, indent: &str, lead: &str) {
        let Out::If {
            test,
            negated,
            then,
            otherwise,
        } = out
        else {
            return;
        };
        let inner: String = format!("{indent}{INDENT_UNIT}");
        let (test, then, otherwise): (&Code, &Vec<Out>, &Vec<Out>) = if then.is_empty() {
            (negated, otherwise, then)
        } else {
            (test, then, otherwise)
        };
        let head: String = format!("{lead}if ({}) {{", self.code(test));
        if lead.is_empty() {
            self.line(indent, &head);
        } else {
            self.out.push_str(&head);
            self.out.push('\n');
        }
        self.body(then, &inner);
        match otherwise.as_slice() {
            [] => self.line(indent, "}"),
            [nested @ Out::If { .. }] => {
                self.out.push_str(indent);
                self.conditional(nested, indent, "} else ");
            }
            _ => {
                self.line(indent, "} else {");
                self.body(otherwise, &inner);
                self.line(indent, "}");
            }
        }
    }
}

fn reindent(text: &str, original: Option<&str>, indent: &str) -> String {
    let Some(original) = original else {
        return text.to_owned();
    };
    if !text.contains('\n') {
        return text.to_owned();
    }
    let mut out: String = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
            match line.strip_prefix(original) {
                Some(rest) => {
                    out.push_str(indent);
                    out.push_str(rest);
                }
                None => out.push_str(line),
            }
        } else {
            out.push_str(line);
        }
    }
    out
}
