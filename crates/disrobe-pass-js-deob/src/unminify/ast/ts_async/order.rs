use std::collections::{BTreeMap, BTreeSet};

use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentOperator, AssignmentTarget, BinaryOperator,
    CallExpression, Expression, Function, IdentifierReference, ObjectPropertyKind, PropertyKey,
    Statement, UnaryOperator,
};
use oxc_ast::{AstKind, Visit, visit::walk};
use oxc_semantic::{ReferenceId, ScopeFlags, ScopeId, Semantic, SymbolFlags, SymbolId};
use oxc_span::{GetSpan, Span};

use super::Refusal;
use super::helpers::{is_void_zero, resolved_symbol};
use super::machine::{Block, Machine, ProloguePlan, Terminator, is_sent_call};
use super::probe::{operand_wrap, primary_wrap};
use super::render::{Callee, Renderer, Replacement, Wrap};

const MAX_WALK_DEPTH: usize = 512;

#[derive(Debug)]
pub(super) struct Locals {
    pub(super) state: SymbolId,
    pub(super) stable: BTreeSet<SymbolId>,
    pub(super) hoisted: BTreeSet<SymbolId>,
    spills: BTreeSet<SymbolId>,
}

impl Locals {
    pub(super) fn collect(
        state: SymbolId,
        callback: &Function<'_>,
        outer_scope: ScopeId,
        prologue: &ProloguePlan<'_>,
        semantic: &Semantic<'_>,
        nested_functions: &[Span],
    ) -> Result<Self, Refusal> {
        let callback_scope: ScopeId = callback.scope_id.get().ok_or(Refusal::MachineShape)?;
        let mut stable: BTreeSet<SymbolId> = BTreeSet::new();
        for scope in [outer_scope, callback_scope] {
            for symbol in semantic.scopes().iter_bindings_in(scope) {
                let captured: bool = references(symbol, semantic).any(|(span, _)| {
                    nested_functions
                        .iter()
                        .any(|function: &Span| contains(*function, span))
                });
                if !captured {
                    stable.insert(symbol);
                }
            }
        }
        let hoisted: BTreeSet<SymbolId> = prologue.hoisted().collect();
        let spills: BTreeSet<SymbolId> = hoisted
            .iter()
            .copied()
            .filter(|symbol: &SymbolId| stable.contains(symbol))
            .filter(|symbol: &SymbolId| {
                let flags: Vec<(bool, bool)> = semantic
                    .symbols()
                    .get_resolved_reference_ids(*symbol)
                    .iter()
                    .map(|reference_id: &ReferenceId| {
                        let reference: &oxc_semantic::Reference =
                            semantic.symbols().get_reference(*reference_id);
                        (reference.is_read(), reference.is_write())
                    })
                    .collect();
                flags.len() == 2 && flags.contains(&(true, false)) && flags.contains(&(false, true))
            })
            .collect();
        Ok(Self {
            state,
            stable,
            hoisted,
            spills,
        })
    }
}

fn references<'s>(
    symbol: SymbolId,
    semantic: &'s Semantic<'_>,
) -> impl Iterator<Item = (Span, ReferenceId)> + 's {
    semantic
        .symbols()
        .get_resolved_reference_ids(symbol)
        .iter()
        .map(move |reference_id: &ReferenceId| {
            let node: oxc_semantic::NodeId =
                semantic.symbols().get_reference(*reference_id).node_id();
            (semantic.nodes().get_node(node).kind().span(), *reference_id)
        })
}

pub(super) const fn contains(outer: Span, inner: Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

#[derive(Debug, Default)]
pub(super) struct FoldPlan {
    pub(super) deleted: BTreeSet<(u32, u32)>,
    pub(super) removed_temps: BTreeSet<SymbolId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Read {
        symbol: SymbolId,
        span: Span,
        conditional: bool,
    },
    Write {
        symbol: SymbolId,
    },
    Effect,
    Lookup {
        call: Span,
    },
    SentBegin {
        sent: Span,
    },
    Await {
        sent: Span,
    },
}

#[derive(Debug, Clone, Copy)]
enum SiteThis {
    Undefined,
    Temp(SymbolId),
}

#[derive(Debug, Clone)]
enum SiteArguments {
    Array(Vec<Span>),
    Concat { temp: SymbolId, tail: Vec<Span> },
}

#[derive(Debug, Clone)]
enum Site {
    Apply {
        call: Span,
        callee: SymbolId,
        this: SiteThis,
        arguments: SiteArguments,
    },
    Concat {
        call: Span,
        temp: SymbolId,
        tail: Vec<Span>,
    },
}

impl Site {
    const fn call(&self) -> Span {
        match self {
            Self::Apply { call, .. } | Self::Concat { call, .. } => *call,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SpillValue<'a> {
    Value(&'a Expression<'a>),
    Member {
        receiver: SymbolId,
        object: &'a Expression<'a>,
        property: MemberProperty<'a>,
    },
}

#[derive(Debug, Clone, Copy)]
enum MemberProperty<'a> {
    Static(&'a str),
    Computed(&'a Expression<'a>),
}

#[derive(Debug, Clone, Copy)]
struct Spill<'a> {
    item: usize,
    statement: Span,
    value: SpillValue<'a>,
    generated: bool,
}

#[derive(Debug, Clone, Copy)]
enum Item<'a> {
    Statement(&'a Statement<'a>),
    Value(&'a Expression<'a>),
}

struct WalkedItem {
    events: Vec<Event>,
    sites: Vec<Site>,
    sent_wraps: BTreeMap<(u32, u32), Wrap>,
    unfoldable: BTreeSet<SymbolId>,
}

pub(super) fn plan<'a>(
    machine: &Machine<'a>,
    semantic: &Semantic<'a>,
    locals: &Locals,
    renderer: &mut Renderer<'_>,
) -> Result<FoldPlan, Refusal> {
    let absorbed: BTreeMap<(u32, u32), &'a Expression<'a>> = absorbed_operands(machine)?;
    let mut plan: FoldPlan = FoldPlan::default();
    for chain in chains(machine) {
        plan_chain(
            machine, &chain, &absorbed, semantic, locals, renderer, &mut plan,
        )?;
    }
    Ok(plan)
}

fn absorbed_operands<'a>(
    machine: &Machine<'a>,
) -> Result<BTreeMap<(u32, u32), &'a Expression<'a>>, Refusal> {
    let mut absorbed: BTreeMap<(u32, u32), &'a Expression<'a>> = BTreeMap::new();
    let mut resumes: BTreeSet<u32> = BTreeSet::new();
    for block in &machine.blocks {
        let Terminator::Await(operand) = block.terminator else {
            continue;
        };
        let resume: &Block<'a> = machine
            .blocks
            .get(block.label as usize + 1)
            .ok_or(Refusal::UnresolvedTransfer)?;
        if resume.region.is_some()
            || resume.catch_entry.is_some()
            || machine.block_part[resume.label as usize] != machine.block_part[block.label as usize]
        {
            return Err(Refusal::SentPlacement);
        }
        let [sent] = resume.sents.as_slice() else {
            return Err(Refusal::SentPlacement);
        };
        let first_item: Span = first_item_span(resume).ok_or(Refusal::SentPlacement)?;
        if !contains(first_item, *sent) {
            return Err(Refusal::SentPlacement);
        }
        absorbed.insert((sent.start, sent.end), operand);
        resumes.insert(resume.label);
    }
    for block in &machine.blocks {
        if !resumes.contains(&block.label) && !block.sents.is_empty() {
            return Err(Refusal::SentPlacement);
        }
    }
    Ok(absorbed)
}

fn first_item_span(block: &Block<'_>) -> Option<Span> {
    if let Some(first) = block.statements.first() {
        return Some(first.span());
    }
    match block.terminator {
        Terminator::Return(Some(value)) | Terminator::Await(value) => Some(value.span()),
        _ => None,
    }
}

fn chains(machine: &Machine<'_>) -> Vec<Vec<u32>> {
    let resumes: BTreeSet<u32> = machine
        .blocks
        .iter()
        .filter(|block: &&Block<'_>| matches!(block.terminator, Terminator::Await(_)))
        .map(|block: &Block<'_>| block.label + 1)
        .collect();
    let mut chains: Vec<Vec<u32>> = Vec::new();
    for block in &machine.blocks {
        if resumes.contains(&block.label) {
            continue;
        }
        let mut chain: Vec<u32> = vec![block.label];
        let mut cursor: &Block<'_> = block;
        while let Terminator::Await(_) = cursor.terminator {
            let Some(next) = machine.blocks.get(cursor.label as usize + 1) else {
                break;
            };
            chain.push(next.label);
            cursor = next;
        }
        chains.push(chain);
    }
    chains
}

fn plan_chain<'a>(
    machine: &Machine<'a>,
    chain: &[u32],
    absorbed: &BTreeMap<(u32, u32), &'a Expression<'a>>,
    semantic: &Semantic<'a>,
    locals: &Locals,
    renderer: &mut Renderer<'_>,
    plan: &mut FoldPlan,
) -> Result<(), Refusal> {
    let mut items: Vec<Item<'a>> = Vec::new();
    for label in chain {
        let block: &Block<'a> = &machine.blocks[*label as usize];
        items.extend(
            block
                .statements
                .iter()
                .map(|statement| Item::Statement(statement)),
        );
        if let (Terminator::Return(Some(value)), Some(last)) = (block.terminator, chain.last())
            && last == label
        {
            items.push(Item::Value(value));
        }
    }
    let mut spills: BTreeMap<SymbolId, Spill<'a>> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        if let Item::Statement(statement) = item
            && let Some((symbol, value)) = spill_statement(statement, locals, semantic)
        {
            spills.insert(
                symbol,
                Spill {
                    item: index,
                    statement: statement.span(),
                    value,
                    generated: is_generated_temp(semantic.symbols().get_name(symbol)),
                },
            );
        }
    }
    let mut walked: Vec<WalkedItem> = Vec::with_capacity(items.len());
    for item in &items {
        let mut walker: Walker<'_, 'a> = Walker {
            semantic,
            locals,
            absorbed,
            events: Vec::new(),
            sites: Vec::new(),
            sent_wraps: BTreeMap::new(),
            unfoldable: BTreeSet::new(),
            depth: 0,
        };
        match item {
            Item::Statement(statement) => walker.statement(statement)?,
            Item::Value(value) => walker.expression(value, false)?,
        }
        walked.push(WalkedItem {
            events: walker.events,
            sites: walker.sites,
            sent_wraps: walker.sent_wraps,
            unfoldable: walker.unfoldable,
        });
    }
    let unfoldable: BTreeSet<SymbolId> = walked
        .iter()
        .flat_map(|item: &WalkedItem| item.unfoldable.iter().copied())
        .collect();
    for (index, item) in walked.iter().enumerate() {
        let folds: ItemFolds = plan_item(index, item, &spills, &unfoldable);
        check_sent_prefixes(item, &folds)?;
        register_folds(item, &folds, &spills, renderer, plan)?;
        for (sent, wrap) in &item.sent_wraps {
            let operand: &Expression<'a> =
                absorbed.get(sent).copied().ok_or(Refusal::SentPlacement)?;
            renderer.insert(
                Span::new(sent.0, sent.1),
                Replacement::Await {
                    operand: operand.span(),
                    operand_wrap: operand_wrap(operand),
                    outer_wrap: *wrap,
                },
            )?;
        }
    }
    Ok(())
}

fn is_generated_temp(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('_') else {
        return false;
    };
    let mut characters = rest.chars();
    match (characters.next(), characters.next()) {
        (Some(letter), None) => letter.is_ascii_lowercase() && letter != 'i' && letter != 'n',
        (Some(first), _) => {
            first.is_ascii_digit() && rest.chars().all(|c: char| c.is_ascii_digit())
        }
        (None, _) => false,
    }
}

fn spill_statement<'a>(
    statement: &'a Statement<'a>,
    locals: &Locals,
    semantic: &Semantic<'a>,
) -> Option<(SymbolId, SpillValue<'a>)> {
    let Statement::ExpressionStatement(expression) = statement else {
        return None;
    };
    let Expression::AssignmentExpression(assignment) = &expression.expression else {
        return None;
    };
    if assignment.operator != AssignmentOperator::Assign {
        return None;
    }
    let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left else {
        return None;
    };
    let symbol: SymbolId = resolved_symbol(target, semantic)?;
    if !locals.spills.contains(&symbol) {
        return None;
    }
    let value: SpillValue<'a> = match member_spill(&assignment.right, locals, semantic) {
        Some(member) => member,
        None if !contains_assignment(&assignment.right) => SpillValue::Value(&assignment.right),
        None => return None,
    };
    Some((symbol, value))
}

fn member_spill<'a>(
    value: &'a Expression<'a>,
    locals: &Locals,
    semantic: &Semantic<'a>,
) -> Option<SpillValue<'a>> {
    let (object, property): (&'a Expression<'a>, MemberProperty<'a>) = match value {
        Expression::StaticMemberExpression(member) if !member.optional => (
            &member.object,
            MemberProperty::Static(member.property.name.as_str()),
        ),
        Expression::ComputedMemberExpression(member) if !member.optional => {
            if contains_assignment(&member.expression) {
                return None;
            }
            (&member.object, MemberProperty::Computed(&member.expression))
        }
        _ => return None,
    };
    let Expression::ParenthesizedExpression(inner) = object else {
        return None;
    };
    let Expression::AssignmentExpression(assignment) = &inner.expression else {
        return None;
    };
    if assignment.operator != AssignmentOperator::Assign || contains_assignment(&assignment.right) {
        return None;
    }
    let AssignmentTarget::AssignmentTargetIdentifier(receiver) = &assignment.left else {
        return None;
    };
    let receiver_symbol: SymbolId = resolved_symbol(receiver, semantic)?;
    if !locals.spills.contains(&receiver_symbol) {
        return None;
    }
    Some(SpillValue::Member {
        receiver: receiver_symbol,
        object: &assignment.right,
        property,
    })
}

fn contains_assignment(expression: &Expression<'_>) -> bool {
    struct Probe {
        found: bool,
    }
    impl<'a> Visit<'a> for Probe {
        fn enter_node(&mut self, kind: AstKind<'a>) {
            if matches!(
                kind,
                AstKind::AssignmentExpression(_) | AstKind::UpdateExpression(_)
            ) {
                self.found = true;
            }
        }

        fn visit_function(&mut self, _function: &Function<'a>, _flags: ScopeFlags) {}

        fn visit_arrow_function_expression(
            &mut self,
            _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
        }
    }
    let mut probe: Probe = Probe { found: false };
    probe.visit_expression(expression);
    probe.found
}

#[derive(Debug, Default)]
struct ItemFolds {
    temps: BTreeSet<SymbolId>,
    sites: Vec<Site>,
}

impl ItemFolds {
    fn realized(&self, call: Span) -> bool {
        self.sites.iter().any(|site: &Site| site.call() == call)
    }
}

fn plan_item(
    index: usize,
    item: &WalkedItem,
    spills: &BTreeMap<SymbolId, Spill<'_>>,
    unfoldable: &BTreeSet<SymbolId>,
) -> ItemFolds {
    let receivers: BTreeSet<SymbolId> = spills
        .values()
        .filter_map(|spill: &Spill<'_>| match spill.value {
            SpillValue::Member { receiver, .. } => Some(receiver),
            SpillValue::Value(_) => None,
        })
        .collect();
    let mut read_positions: BTreeMap<SymbolId, usize> = BTreeMap::new();
    for (position, event) in item.events.iter().enumerate() {
        if let Event::Read {
            symbol,
            conditional: false,
            ..
        } = event
            && spills.contains_key(symbol)
            && !unfoldable.contains(symbol)
            && !receivers.contains(symbol)
        {
            read_positions.insert(*symbol, position);
        }
    }
    let by_item: BTreeMap<usize, SymbolId> = spills
        .iter()
        .map(|(symbol, spill): (&SymbolId, &Spill<'_>)| (spill.item, *symbol))
        .collect();
    let mut run: Vec<SymbolId> = Vec::new();
    let mut cursor: usize = index;
    while cursor > 0 {
        cursor -= 1;
        match by_item.get(&cursor) {
            Some(symbol) if read_positions.contains_key(symbol) => run.push(*symbol),
            _ => break,
        }
    }
    loop {
        let ordered: bool = run
            .windows(2)
            .all(|pair: &[SymbolId]| read_positions.get(&pair[1]) < read_positions.get(&pair[0]));
        if !ordered {
            run.pop();
            continue;
        }
        let temps: BTreeSet<SymbolId> = run.iter().copied().collect();
        let sites: Vec<Site> = item
            .sites
            .iter()
            .filter(|site: &&Site| site_realizable(site, &temps, spills))
            .cloned()
            .collect();
        if let Some(blocked) = run
            .iter()
            .position(|symbol: &SymbolId| !temp_consumable(*symbol, &sites, spills))
        {
            run.truncate(blocked);
            continue;
        }
        let Some(last_read) = run
            .iter()
            .filter_map(|symbol: &SymbolId| read_positions.get(symbol).copied())
            .max()
        else {
            return ItemFolds::default();
        };
        let folds: ItemFolds = ItemFolds { temps, sites };
        let clean_prefix: bool = item.events[..last_read]
            .iter()
            .all(|event: &Event| match event {
                Event::Read { .. } | Event::SentBegin { .. } => true,
                Event::Lookup { call } => folds.realized(*call),
                Event::Write { .. } | Event::Effect | Event::Await { .. } => false,
            });
        return if clean_prefix {
            folds
        } else {
            ItemFolds::default()
        };
    }
}

fn site_realizable(
    site: &Site,
    temps: &BTreeSet<SymbolId>,
    spills: &BTreeMap<SymbolId, Spill<'_>>,
) -> bool {
    match site {
        Site::Apply {
            callee,
            this,
            arguments,
            ..
        } => {
            if !temps.contains(callee) {
                return false;
            }
            let callee_ok: bool = match (spills.get(callee).map(|spill| spill.value), this) {
                (Some(SpillValue::Value(Expression::Identifier(_))), SiteThis::Undefined) => true,
                (Some(SpillValue::Member { receiver, .. }), SiteThis::Temp(this_temp)) => {
                    receiver == *this_temp
                }
                _ => false,
            };
            let arguments_ok: bool = match arguments {
                SiteArguments::Array(_) => true,
                SiteArguments::Concat { temp, .. } => {
                    temps.contains(temp) && is_array_spill(*temp, spills)
                }
            };
            callee_ok && arguments_ok
        }
        Site::Concat { temp, .. } => temps.contains(temp) && is_array_spill(*temp, spills),
    }
}

fn is_array_spill(symbol: SymbolId, spills: &BTreeMap<SymbolId, Spill<'_>>) -> bool {
    matches!(
        spills.get(&symbol).map(|spill: &Spill<'_>| spill.value),
        Some(SpillValue::Value(Expression::ArrayExpression(array)))
            if array.elements.iter().all(|element| !matches!(element, ArrayExpressionElement::Elision(_)))
    )
}

fn temp_consumable(
    symbol: SymbolId,
    sites: &[Site],
    spills: &BTreeMap<SymbolId, Spill<'_>>,
) -> bool {
    let site_consumes: bool = sites.iter().any(|site: &Site| match site {
        Site::Apply {
            callee, arguments, ..
        } => {
            *callee == symbol
                || matches!(arguments, SiteArguments::Concat { temp, .. } if *temp == symbol)
        }
        Site::Concat { temp, .. } => *temp == symbol,
    });
    match spills.get(&symbol) {
        Some(Spill {
            value: SpillValue::Member { .. },
            ..
        }) => site_consumes,
        Some(spill) => site_consumes || spill.generated,
        None => false,
    }
}

fn check_sent_prefixes(item: &WalkedItem, folds: &ItemFolds) -> Result<(), Refusal> {
    for (position, event) in item.events.iter().enumerate() {
        let Event::SentBegin { sent } = event else {
            continue;
        };
        let mut reads: BTreeSet<SymbolId> = BTreeSet::new();
        for earlier in item.events[..position].iter().rev() {
            match earlier {
                Event::SentBegin { .. } => break,
                Event::Read { symbol, .. } => {
                    reads.insert(*symbol);
                }
                Event::Lookup { call } if folds.realized(*call) => {}
                Event::Lookup { .. }
                | Event::Write { .. }
                | Event::Effect
                | Event::Await { .. } => {
                    return Err(Refusal::SentPrefixEffect);
                }
            }
        }
        for later in &item.events[position + 1..] {
            match later {
                Event::Await { sent: done } if done == sent => break,
                Event::Write { symbol } if reads.contains(symbol) => {
                    return Err(Refusal::SentPrefixEffect);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn register_folds(
    item: &WalkedItem,
    folds: &ItemFolds,
    spills: &BTreeMap<SymbolId, Spill<'_>>,
    renderer: &mut Renderer<'_>,
    plan: &mut FoldPlan,
) -> Result<(), Refusal> {
    if folds.temps.is_empty() {
        return Ok(());
    }
    let site_temps: BTreeSet<SymbolId> = folds
        .sites
        .iter()
        .flat_map(|site: &Site| match site {
            Site::Apply {
                callee, arguments, ..
            } => {
                let mut temps: Vec<SymbolId> = vec![*callee];
                if let SiteArguments::Concat { temp, .. } = arguments {
                    temps.push(*temp);
                }
                temps
            }
            Site::Concat { temp, .. } => vec![*temp],
        })
        .collect();
    for site in &folds.sites {
        register_site(site, spills, renderer)?;
    }
    for event in &item.events {
        let Event::Read { symbol, span, .. } = event else {
            continue;
        };
        if !folds.temps.contains(symbol) || site_temps.contains(symbol) {
            continue;
        }
        let Some(Spill {
            value: SpillValue::Value(value),
            ..
        }) = spills.get(symbol)
        else {
            return Err(Refusal::UnfoldedSpill);
        };
        renderer.insert(
            *span,
            Replacement::Moved {
                expression: value.span(),
                wrap: primary_wrap(value),
            },
        )?;
    }
    for symbol in &folds.temps {
        let spill: &Spill<'_> = spills.get(symbol).ok_or(Refusal::UnfoldedSpill)?;
        plan.deleted
            .insert((spill.statement.start, spill.statement.end));
        plan.removed_temps.insert(*symbol);
        if let SpillValue::Member { receiver, .. } = spill.value {
            plan.removed_temps.insert(receiver);
        }
    }
    Ok(())
}

fn register_site(
    site: &Site,
    spills: &BTreeMap<SymbolId, Spill<'_>>,
    renderer: &mut Renderer<'_>,
) -> Result<(), Refusal> {
    let array_elements = |temp: SymbolId| -> Result<Vec<Span>, Refusal> {
        let Some(Spill {
            value: SpillValue::Value(Expression::ArrayExpression(array)),
            ..
        }) = spills.get(&temp)
        else {
            return Err(Refusal::UnfoldedSpill);
        };
        Ok(array.elements.iter().map(GetSpan::span).collect())
    };
    match site {
        Site::Apply {
            call,
            callee,
            arguments,
            ..
        } => {
            let callee_code: Callee = match spills.get(callee).map(|spill: &Spill<'_>| spill.value)
            {
                Some(SpillValue::Value(value)) => Callee::Plain(value.span()),
                Some(SpillValue::Member {
                    object, property, ..
                }) => match property {
                    MemberProperty::Static(name) => Callee::StaticMember {
                        object: object.span(),
                        object_wrap: member_object_wrap(object),
                        property: name.to_owned(),
                    },
                    MemberProperty::Computed(key) => Callee::ComputedMember {
                        object: object.span(),
                        object_wrap: member_object_wrap(object),
                        key: key.span(),
                    },
                },
                None => return Err(Refusal::UnfoldedSpill),
            };
            let argument_spans: Vec<Span> = match arguments {
                SiteArguments::Array(elements) => elements.clone(),
                SiteArguments::Concat { temp, tail } => {
                    let mut elements: Vec<Span> = array_elements(*temp)?;
                    elements.extend(tail.iter().copied());
                    elements
                }
            };
            renderer.insert(
                *call,
                Replacement::Call {
                    callee: callee_code,
                    arguments: argument_spans,
                    wrap: Wrap::Bare,
                },
            )
        }
        Site::Concat { call, temp, tail } => {
            let mut elements: Vec<Span> = array_elements(*temp)?;
            elements.extend(tail.iter().copied());
            renderer.insert(*call, Replacement::Array { elements })
        }
    }
}

const fn member_object_wrap(object: &Expression<'_>) -> Wrap {
    match object {
        Expression::Identifier(_)
        | Expression::ThisExpression(_)
        | Expression::ParenthesizedExpression(_)
        | Expression::CallExpression(_)
        | Expression::StaticMemberExpression(_)
        | Expression::ComputedMemberExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::StringLiteral(_)
        | Expression::TemplateLiteral(_) => Wrap::Bare,
        _ => Wrap::Parenthesized,
    }
}

struct Walker<'s, 'a> {
    semantic: &'s Semantic<'a>,
    locals: &'s Locals,
    absorbed: &'s BTreeMap<(u32, u32), &'a Expression<'a>>,
    events: Vec<Event>,
    sites: Vec<Site>,
    sent_wraps: BTreeMap<(u32, u32), Wrap>,
    unfoldable: BTreeSet<SymbolId>,
    depth: usize,
}

impl<'a> Walker<'_, 'a> {
    const fn enter(&mut self) -> Result<(), Refusal> {
        self.depth += 1;
        if self.depth > MAX_WALK_DEPTH {
            return Err(Refusal::TooDeep);
        }
        Ok(())
    }

    fn statement(&mut self, statement: &'a Statement<'a>) -> Result<(), Refusal> {
        match statement {
            Statement::ExpressionStatement(expression) => {
                self.expression(&expression.expression, false)
            }
            Statement::ThrowStatement(throw) => {
                self.expression(&throw.argument, false)?;
                self.events.push(Event::Effect);
                Ok(())
            }
            Statement::IfStatement(branch) => {
                self.expression(&branch.test, false)?;
                self.opaque_statement(&branch.consequent)?;
                if let Some(alternate) = &branch.alternate {
                    self.opaque_statement(alternate)?;
                }
                Ok(())
            }
            Statement::SwitchStatement(switch) => {
                self.expression(&switch.discriminant, false)?;
                for case in &switch.cases {
                    if let Some(test) = &case.test {
                        self.opaque_expression(test)?;
                    }
                    for inner in &case.consequent {
                        self.opaque_statement(inner)?;
                    }
                }
                Ok(())
            }
            other => self.opaque_statement(other),
        }
    }

    fn opaque_statement(&mut self, statement: &Statement<'a>) -> Result<(), Refusal> {
        let mut scan: OpaqueScan<'_, 'a> = OpaqueScan {
            semantic: self.semantic,
            locals: self.locals,
            events: Vec::new(),
            unfoldable: BTreeSet::new(),
            sent: false,
        };
        scan.visit_statement(statement);
        self.finish_opaque(scan)
    }

    fn opaque_expression(&mut self, expression: &Expression<'a>) -> Result<(), Refusal> {
        let mut scan: OpaqueScan<'_, 'a> = OpaqueScan {
            semantic: self.semantic,
            locals: self.locals,
            events: Vec::new(),
            unfoldable: BTreeSet::new(),
            sent: false,
        };
        scan.visit_expression(expression);
        self.finish_opaque(scan)
    }

    fn finish_opaque(&mut self, scan: OpaqueScan<'_, 'a>) -> Result<(), Refusal> {
        if scan.sent {
            return Err(Refusal::SentPlacement);
        }
        self.events.push(Event::Effect);
        self.events.extend(scan.events);
        self.unfoldable.extend(scan.unfoldable);
        self.events.push(Event::Effect);
        Ok(())
    }

    fn identifier(&mut self, reference: &IdentifierReference<'a>) -> Result<(), Refusal> {
        match resolved_symbol(reference, self.semantic) {
            Some(symbol) if symbol == self.locals.state => Err(Refusal::StateMisuse),
            Some(symbol) if self.locals.stable.contains(&symbol) => {
                self.events.push(Event::Read {
                    symbol,
                    span: reference.span,
                    conditional: false,
                });
                Ok(())
            }
            Some(symbol) if is_constant_function(symbol, self.semantic) => Ok(()),
            None if reference.name == "undefined" => Ok(()),
            _ => {
                self.events.push(Event::Effect);
                Ok(())
            }
        }
    }

    fn expression(&mut self, expression: &'a Expression<'a>, tight: bool) -> Result<(), Refusal> {
        self.enter()?;
        let result: Result<(), Refusal> = self.expression_inner(expression, tight);
        self.depth -= 1;
        result
    }

    fn expression_inner(
        &mut self,
        expression: &'a Expression<'a>,
        tight: bool,
    ) -> Result<(), Refusal> {
        match expression {
            Expression::ParenthesizedExpression(inner) => self.expression(&inner.expression, false),
            Expression::Identifier(reference) => self.identifier(reference),
            Expression::ThisExpression(_)
            | Expression::NullLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_) => Ok(()),
            Expression::ArrayExpression(array) => {
                for element in &array.elements {
                    match element {
                        ArrayExpressionElement::Elision(_) => {}
                        ArrayExpressionElement::SpreadElement(spread) => {
                            self.expression(&spread.argument, false)?;
                            self.events.push(Event::Effect);
                        }
                        other => {
                            let value: &'a Expression<'a> =
                                other.as_expression().ok_or(Refusal::MachineShape)?;
                            self.expression(value, false)?;
                        }
                    }
                }
                Ok(())
            }
            Expression::ObjectExpression(object) => {
                for property in &object.properties {
                    match property {
                        ObjectPropertyKind::ObjectProperty(property) => {
                            if property.computed
                                && let Some(key) = property_key_expression(&property.key)
                            {
                                self.expression(key, false)?;
                            }
                            self.expression(&property.value, false)?;
                        }
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            self.expression(&spread.argument, false)?;
                            self.events.push(Event::Effect);
                        }
                    }
                }
                Ok(())
            }
            Expression::UnaryExpression(unary) => {
                match unary.operator {
                    UnaryOperator::Typeof
                        if matches!(unary.argument, Expression::Identifier(_)) => {}
                    UnaryOperator::LogicalNot | UnaryOperator::Void | UnaryOperator::Typeof => {
                        self.expression(&unary.argument, false)?;
                    }
                    UnaryOperator::Delete => return self.opaque_expression(expression),
                    UnaryOperator::UnaryNegation
                    | UnaryOperator::UnaryPlus
                    | UnaryOperator::BitwiseNot => {
                        self.expression(&unary.argument, false)?;
                        self.events.push(Event::Effect);
                    }
                }
                Ok(())
            }
            Expression::BinaryExpression(binary) => {
                self.expression(&binary.left, binary.operator == BinaryOperator::Exponential)?;
                self.expression(&binary.right, false)?;
                if !matches!(
                    binary.operator,
                    BinaryOperator::StrictEquality | BinaryOperator::StrictInequality
                ) {
                    self.events.push(Event::Effect);
                }
                Ok(())
            }
            Expression::LogicalExpression(logical) => {
                self.expression(&logical.left, false)?;
                self.opaque_expression(&logical.right)
            }
            Expression::ConditionalExpression(conditional) => {
                self.expression(&conditional.test, false)?;
                self.opaque_expression(&conditional.consequent)?;
                self.opaque_expression(&conditional.alternate)
            }
            Expression::SequenceExpression(sequence) => {
                for inner in &sequence.expressions {
                    self.expression(inner, false)?;
                }
                Ok(())
            }
            Expression::AssignmentExpression(assignment) => self.assignment(assignment),
            Expression::CallExpression(call) => self.call(call, tight),
            Expression::NewExpression(construct) => {
                self.expression(&construct.callee, true)?;
                self.arguments(&construct.arguments)?;
                self.events.push(Event::Effect);
                Ok(())
            }
            Expression::StaticMemberExpression(member) => {
                self.expression(&member.object, true)?;
                self.events.push(Event::Effect);
                Ok(())
            }
            Expression::ComputedMemberExpression(member) => {
                self.expression(&member.object, true)?;
                self.expression(&member.expression, false)?;
                self.events.push(Event::Effect);
                Ok(())
            }
            Expression::TemplateLiteral(template) => {
                for inner in &template.expressions {
                    self.expression(inner, false)?;
                }
                self.events.push(Event::Effect);
                Ok(())
            }
            _ => self.opaque_expression(expression),
        }
    }

    fn arguments(&mut self, arguments: &'a [Argument<'a>]) -> Result<(), Refusal> {
        for argument in arguments {
            match argument {
                Argument::SpreadElement(spread) => {
                    self.expression(&spread.argument, false)?;
                    self.events.push(Event::Effect);
                }
                other => {
                    let value: &'a Expression<'a> =
                        other.as_expression().ok_or(Refusal::MachineShape)?;
                    self.expression(value, false)?;
                }
            }
        }
        Ok(())
    }

    fn assignment(
        &mut self,
        assignment: &'a oxc_ast::ast::AssignmentExpression<'a>,
    ) -> Result<(), Refusal> {
        let compound: bool = assignment.operator != AssignmentOperator::Assign;
        let written: Option<SymbolId> = match &assignment.left {
            AssignmentTarget::AssignmentTargetIdentifier(target) => {
                let symbol: Option<SymbolId> = resolved_symbol(target, self.semantic);
                if symbol == Some(self.locals.state) {
                    return Err(Refusal::StateMisuse);
                }
                if compound {
                    self.identifier(target)?;
                }
                symbol.filter(|symbol: &SymbolId| self.locals.stable.contains(symbol))
            }
            AssignmentTarget::StaticMemberExpression(member) => {
                self.expression(&member.object, true)?;
                if compound {
                    self.events.push(Event::Effect);
                }
                None
            }
            AssignmentTarget::ComputedMemberExpression(member) => {
                self.expression(&member.object, true)?;
                self.expression(&member.expression, false)?;
                if compound {
                    self.events.push(Event::Effect);
                }
                None
            }
            _ => return self.opaque_expression_of_assignment(assignment),
        };
        self.expression(&assignment.right, false)?;
        match written {
            Some(symbol) => self.events.push(Event::Write { symbol }),
            None => self.events.push(Event::Effect),
        }
        Ok(())
    }

    fn opaque_expression_of_assignment(
        &mut self,
        assignment: &'a oxc_ast::ast::AssignmentExpression<'a>,
    ) -> Result<(), Refusal> {
        let mut scan: OpaqueScan<'_, 'a> = OpaqueScan {
            semantic: self.semantic,
            locals: self.locals,
            events: Vec::new(),
            unfoldable: BTreeSet::new(),
            sent: false,
        };
        scan.visit_assignment_expression(assignment);
        self.finish_opaque(scan)
    }

    fn call(&mut self, call: &'a CallExpression<'a>, tight: bool) -> Result<(), Refusal> {
        if call.optional {
            return self.opaque_call(call);
        }
        if is_sent_call(call, self.locals.state, self.semantic) {
            let key: (u32, u32) = (call.span.start, call.span.end);
            let operand: &'a Expression<'a> = self
                .absorbed
                .get(&key)
                .copied()
                .ok_or(Refusal::SentPlacement)?;
            self.events.push(Event::SentBegin { sent: call.span });
            self.expression(operand, false)?;
            self.events.push(Event::Await { sent: call.span });
            self.sent_wraps.insert(
                key,
                if tight {
                    Wrap::Parenthesized
                } else {
                    Wrap::Bare
                },
            );
            return Ok(());
        }
        if let Some(site) = self.fold_site(call) {
            let temp: SymbolId = match &site {
                Site::Apply { callee, .. } => *callee,
                Site::Concat { temp, .. } => *temp,
            };
            let Expression::StaticMemberExpression(member) = &call.callee else {
                return Err(Refusal::MachineShape);
            };
            let Expression::Identifier(object) = &member.object else {
                return Err(Refusal::MachineShape);
            };
            self.events.push(Event::Read {
                symbol: temp,
                span: object.span,
                conditional: false,
            });
            self.events.push(Event::Lookup { call: call.span });
            self.sites.push(site);
            self.arguments(&call.arguments)?;
            self.events.push(Event::Effect);
            return Ok(());
        }
        match &call.callee {
            Expression::StaticMemberExpression(member) if !member.optional => {
                self.expression(&member.object, true)?;
                self.events.push(Event::Effect);
            }
            Expression::ComputedMemberExpression(member) if !member.optional => {
                self.expression(&member.object, true)?;
                self.expression(&member.expression, false)?;
                self.events.push(Event::Effect);
            }
            callee => self.expression(callee, true)?,
        }
        self.arguments(&call.arguments)?;
        self.events.push(Event::Effect);
        Ok(())
    }

    fn opaque_call(&mut self, call: &'a CallExpression<'a>) -> Result<(), Refusal> {
        let mut scan: OpaqueScan<'_, 'a> = OpaqueScan {
            semantic: self.semantic,
            locals: self.locals,
            events: Vec::new(),
            unfoldable: BTreeSet::new(),
            sent: false,
        };
        scan.visit_call_expression(call);
        self.finish_opaque(scan)
    }

    fn fold_site(&self, call: &'a CallExpression<'a>) -> Option<Site> {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return None;
        };
        if member.optional {
            return None;
        }
        let Expression::Identifier(object) = &member.object else {
            return None;
        };
        let temp: SymbolId = resolved_symbol(object, self.semantic)?;
        if !self.locals.spills.contains(&temp) {
            return None;
        }
        match (member.property.name.as_str(), call.arguments.as_slice()) {
            ("apply", [this_argument, arguments]) => {
                let this: SiteThis = match this_argument {
                    Argument::Identifier(reference)
                        if reference.name == "undefined"
                            && resolved_symbol(reference, self.semantic).is_none() =>
                    {
                        SiteThis::Undefined
                    }
                    Argument::Identifier(reference) => {
                        let symbol: SymbolId = resolved_symbol(reference, self.semantic)?;
                        if !self.locals.spills.contains(&symbol) {
                            return None;
                        }
                        SiteThis::Temp(symbol)
                    }
                    other if other.as_expression().is_some_and(is_void_zero) => SiteThis::Undefined,
                    _ => return None,
                };
                let arguments: SiteArguments = match arguments {
                    Argument::ArrayExpression(array) => {
                        SiteArguments::Array(plain_elements(array)?)
                    }
                    Argument::CallExpression(inner) => {
                        let Some(Site::Concat { temp, tail, .. }) = self.fold_site(inner) else {
                            return None;
                        };
                        SiteArguments::Concat { temp, tail }
                    }
                    _ => return None,
                };
                Some(Site::Apply {
                    call: call.span,
                    callee: temp,
                    this,
                    arguments,
                })
            }
            ("concat", [Argument::ArrayExpression(array)]) => Some(Site::Concat {
                call: call.span,
                temp,
                tail: plain_elements(array)?,
            }),
            _ => None,
        }
    }
}

fn plain_elements(array: &oxc_ast::ast::ArrayExpression<'_>) -> Option<Vec<Span>> {
    array
        .elements
        .iter()
        .map(|element: &ArrayExpressionElement<'_>| match element {
            ArrayExpressionElement::Elision(_) => None,
            other => Some(other.span()),
        })
        .collect()
}

fn property_key_expression<'b, 'a>(key: &'b PropertyKey<'a>) -> Option<&'b Expression<'a>> {
    match key {
        PropertyKey::StaticIdentifier(_) | PropertyKey::PrivateIdentifier(_) => None,
        other => other.as_expression(),
    }
}

fn is_constant_function(symbol: SymbolId, semantic: &Semantic<'_>) -> bool {
    semantic
        .symbols()
        .get_flags(symbol)
        .contains(SymbolFlags::Function)
        && !semantic.symbols().symbol_is_mutated(symbol)
        && semantic.symbols().get_redeclarations(symbol).is_empty()
}

struct OpaqueScan<'s, 'a> {
    semantic: &'s Semantic<'a>,
    locals: &'s Locals,
    events: Vec<Event>,
    unfoldable: BTreeSet<SymbolId>,
    sent: bool,
}

impl<'a> Visit<'a> for OpaqueScan<'_, 'a> {
    fn visit_function(&mut self, _function: &Function<'a>, _flags: ScopeFlags) {}

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if is_sent_call(call, self.locals.state, self.semantic) {
            self.sent = true;
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        let Some(symbol) = resolved_symbol(reference, self.semantic) else {
            return;
        };
        if !self.locals.stable.contains(&symbol) {
            return;
        }
        self.unfoldable.insert(symbol);
        let reference_id: Option<ReferenceId> = reference.reference_id.get();
        let write: bool = reference_id
            .is_some_and(|id: ReferenceId| self.semantic.symbols().get_reference(id).is_write());
        if write {
            self.events.push(Event::Write { symbol });
        } else {
            self.events.push(Event::Read {
                symbol,
                span: reference.span,
                conditional: true,
            });
        }
    }
}
