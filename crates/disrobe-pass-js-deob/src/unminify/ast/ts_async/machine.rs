use std::collections::{BTreeMap, BTreeSet};

use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentOperator, AssignmentTarget, BindingPatternKind,
    CallExpression, Expression, Function, FunctionBody, IdentifierReference, ReturnStatement,
    Statement, VariableDeclaration,
};
use oxc_ast::{Visit, visit::walk};
use oxc_semantic::{ScopeFlags, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use super::candidate::AwaiterCall;
use super::emit::{Labels, Out};
use super::helpers::{HelperBindings, HelperRole, HelperUse, is_void_zero, resolved_symbol};
use super::order::{self, FoldPlan, Locals};
use super::probe::{Usage, UsageProbe};
use super::render::{Code, Renderer};
use super::structure;
use super::{Refusal, raw_statement, scope_names};

const MAX_BLOCKS: usize = 4096;
const MAX_REGIONS: usize = 512;
const MAX_REGION_DEPTH: usize = 64;

#[derive(Debug)]
pub(super) struct MachineRecovery {
    pub(super) params: Option<(Vec<Code>, usize)>,
    pub(super) body: Vec<Out>,
    pub(super) generator_reference: Span,
    pub(super) uses_this: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Terminator<'a> {
    Return(Option<&'a Expression<'a>>),
    Jump(u32),
    FallThrough(u32),
    Await(&'a Expression<'a>),
    EndFinally,
    Stop,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum NestedKind {
    Return(Option<Span>),
    Jump(u32),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Nested {
    pub(super) statement: Span,
    pub(super) kind: NestedKind,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CatchEntry {
    pub(super) binding: Option<SymbolId>,
    pub(super) name: Option<Span>,
}

#[derive(Debug)]
pub(super) struct Block<'a> {
    pub(super) label: u32,
    pub(super) statements: Vec<&'a Statement<'a>>,
    pub(super) terminator: Terminator<'a>,
    pub(super) nested: Vec<Nested>,
    pub(super) region: Option<usize>,
    pub(super) catch_entry: Option<CatchEntry>,
    pub(super) sents: Vec<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Region {
    pub(super) try_start: u32,
    pub(super) catch_start: Option<u32>,
    pub(super) finally_start: Option<u32>,
    pub(super) end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum PartKind {
    Try,
    Catch,
    Finally,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Part {
    pub(super) region: usize,
    pub(super) kind: PartKind,
}

impl Region {
    pub(super) fn part_range(&self, kind: PartKind) -> Option<(u32, u32)> {
        match kind {
            PartKind::Try => Some((
                self.try_start,
                self.catch_start.or(self.finally_start).unwrap_or(self.end),
            )),
            PartKind::Catch => self
                .catch_start
                .map(|start: u32| (start, self.finally_start.unwrap_or(self.end))),
            PartKind::Finally => self.finally_start.map(|start: u32| (start, self.end)),
        }
    }
}

#[derive(Debug)]
pub(super) struct Machine<'a> {
    pub(super) state: SymbolId,
    pub(super) blocks: Vec<Block<'a>>,
    pub(super) regions: Vec<Region>,
    pub(super) region_parent: Vec<Option<Part>>,
    pub(super) block_part: Vec<Option<Part>>,
}

pub(super) fn recover<'a>(
    call: &AwaiterCall<'a>,
    semantic: &Semantic<'a>,
    helpers: &HelperBindings,
    renderer: &mut Renderer<'_>,
    labels: &mut Labels,
    outer_scope: oxc_semantic::ScopeId,
    functions_inside: &[Span],
) -> Result<MachineRecovery, Refusal> {
    let callback: &'a Function<'a> = call.body;
    let callback_body: &'a FunctionBody<'a> =
        callback.body.as_deref().ok_or(Refusal::MachineShape)?;
    if !callback_body.directives.is_empty() || callback.params.rest.is_some() {
        return Err(Refusal::MachineShape);
    }
    let (last, prologue): (&'a Statement<'a>, &'a [Statement<'a>]) = callback_body
        .statements
        .split_last()
        .ok_or(Refusal::MachineShape)?;
    let Statement::ReturnStatement(ret) = last else {
        return Err(Refusal::MachineShape);
    };
    let Some(Expression::CallExpression(generator_call)) = &ret.argument else {
        return Err(Refusal::MachineShape);
    };
    let generator_use: HelperUse = helpers
        .callee_use(&generator_call.callee, semantic)
        .filter(|found: &HelperUse| found.role == HelperRole::Generator)
        .ok_or(Refusal::MachineShape)?;
    let machine_function: &'a Function<'a> = machine_function(generator_call)?;
    let state: SymbolId = state_symbol(machine_function)?;
    let machine_body: &'a FunctionBody<'a> = machine_function
        .body
        .as_deref()
        .ok_or(Refusal::MachineShape)?;
    if !machine_body.directives.is_empty() {
        return Err(Refusal::MachineShape);
    }
    let uses_this: bool = check_usage(prologue, machine_body, semantic)?;
    let machine_scope: oxc_semantic::ScopeId = machine_function
        .scope_id
        .get()
        .ok_or(Refusal::MachineShape)?;
    if scope_names(machine_scope, semantic).len() != 1 {
        return Err(Refusal::MachineShape);
    }
    let machine: Machine<'a> = parse_machine(machine_body, state, semantic)?;
    let prologue_plan: ProloguePlan<'a> = ProloguePlan::analyze(prologue, callback, semantic)?;
    let nested_functions: Vec<Span> = functions_inside
        .iter()
        .copied()
        .filter(|span: &Span| *span != callback.span && *span != machine_function.span)
        .collect();
    let locals: Locals = Locals::collect(
        state,
        callback,
        outer_scope,
        &prologue_plan,
        semantic,
        &nested_functions,
    )?;
    check_catch_bindings(&machine, &locals, semantic)?;
    let plan: FoldPlan = order::plan(&machine, semantic, &locals, renderer)?;
    let body: Vec<Out> = structure::emit(&machine, &plan, renderer, labels)?;
    let mut removed: BTreeSet<SymbolId> = plan.removed_temps.clone();
    removed.extend(
        machine
            .blocks
            .iter()
            .filter_map(|block: &Block<'a>| block.catch_entry.and_then(|entry| entry.binding)),
    );
    let mut full_body: Vec<Out> = prologue_plan.render(&removed, renderer, semantic)?;
    full_body.extend(body);
    let params: Option<(Vec<Code>, usize)> = prologue_plan.params(callback, renderer)?;
    Ok(MachineRecovery {
        params,
        body: full_body,
        generator_reference: generator_use.reference,
        uses_this,
    })
}

fn machine_function<'a>(call: &'a CallExpression<'a>) -> Result<&'a Function<'a>, Refusal> {
    let [
        Argument::ThisExpression(_),
        Argument::FunctionExpression(function),
    ] = call.arguments.as_slice()
    else {
        return Err(Refusal::MachineShape);
    };
    if function.r#async || function.generator || function.id.is_some() {
        return Err(Refusal::MachineShape);
    }
    Ok(function)
}

fn state_symbol(function: &Function<'_>) -> Result<SymbolId, Refusal> {
    let [param] = function.params.items.as_slice() else {
        return Err(Refusal::MachineShape);
    };
    if function.params.rest.is_some() {
        return Err(Refusal::MachineShape);
    }
    let BindingPatternKind::BindingIdentifier(binding) = &param.pattern.kind else {
        return Err(Refusal::MachineShape);
    };
    binding.symbol_id.get().ok_or(Refusal::MachineShape)
}

fn check_usage<'a>(
    prologue: &'a [Statement<'a>],
    machine_body: &'a FunctionBody<'a>,
    semantic: &Semantic<'a>,
) -> Result<bool, Refusal> {
    let mut probe: UsageProbe<'_, 'a> = UsageProbe::new(semantic);
    for statement in prologue {
        probe.visit_statement(statement);
    }
    probe.visit_function_body(machine_body);
    let usage: Usage = probe.finish();
    if usage.arguments {
        return Err(Refusal::ArgumentsUse);
    }
    if usage.super_or_meta {
        return Err(Refusal::SuperOrMetaProperty);
    }
    if !usage.yields.is_empty() {
        return Err(Refusal::MachineShape);
    }
    Ok(usage.this)
}

fn is_state(expression: &Expression<'_>, state: SymbolId, semantic: &Semantic<'_>) -> bool {
    matches!(expression, Expression::Identifier(reference) if resolved_symbol(reference, semantic) == Some(state))
}

fn state_member<'b>(
    expression: &'b Expression<'_>,
    state: SymbolId,
    semantic: &Semantic<'_>,
) -> Option<&'b str> {
    let Expression::StaticMemberExpression(member) = expression else {
        return None;
    };
    (!member.optional && is_state(&member.object, state, semantic))
        .then_some(member.property.name.as_str())
}

pub(super) fn is_sent_call(
    call: &CallExpression<'_>,
    state: SymbolId,
    semantic: &Semantic<'_>,
) -> bool {
    call.arguments.is_empty()
        && !call.optional
        && state_member(&call.callee, state, semantic) == Some("sent")
}

fn integer(expression: &Expression<'_>) -> Option<u32> {
    let Expression::NumericLiteral(literal) = expression else {
        return None;
    };
    let value: f64 = literal.value;
    if value.fract() != 0.0 || !(0.0..=f64::from(u32::MAX)).contains(&value) {
        return None;
    }
    Some(value as u32)
}

enum Instruction<'a> {
    Return(Option<&'a Expression<'a>>),
    Jump(u32),
    Await(&'a Expression<'a>),
    EndFinally,
}

fn instruction<'a>(ret: &'a ReturnStatement<'a>) -> Result<Instruction<'a>, Refusal> {
    let Some(Expression::ArrayExpression(array)) = &ret.argument else {
        return Err(Refusal::MisplacedInstruction);
    };
    let mut elements: Vec<&'a Expression<'a>> = Vec::with_capacity(array.elements.len());
    for element in &array.elements {
        match element {
            ArrayExpressionElement::SpreadElement(_) | ArrayExpressionElement::Elision(_) => {
                return Err(Refusal::UnknownInstruction);
            }
            other => elements.push(other.as_expression().ok_or(Refusal::UnknownInstruction)?),
        }
    }
    let (opcode, operands): (&&'a Expression<'a>, &[&'a Expression<'a>]) =
        elements.split_first().ok_or(Refusal::UnknownInstruction)?;
    match (integer(opcode), operands) {
        (Some(2), []) => Ok(Instruction::Return(None)),
        (Some(2), [value]) => Ok(Instruction::Return(Some(value))),
        (Some(3), [target]) => integer(target)
            .map(Instruction::Jump)
            .ok_or(Refusal::UnknownInstruction),
        (Some(4), [value]) => Ok(Instruction::Await(value)),
        (Some(7), []) => Ok(Instruction::EndFinally),
        _ => Err(Refusal::UnknownInstruction),
    }
}

fn label_set(statement: &Statement<'_>, state: SymbolId, semantic: &Semantic<'_>) -> Option<u32> {
    let Statement::ExpressionStatement(expression) = statement else {
        return None;
    };
    let Expression::AssignmentExpression(assignment) = &expression.expression else {
        return None;
    };
    if assignment.operator != AssignmentOperator::Assign {
        return None;
    }
    let AssignmentTarget::StaticMemberExpression(member) = &assignment.left else {
        return None;
    };
    if member.property.name != "label" || !is_state(&member.object, state, semantic) {
        return None;
    }
    integer(&assignment.right)
}

fn trys_push(
    statement: &Statement<'_>,
    state: SymbolId,
    semantic: &Semantic<'_>,
) -> Result<Option<Region>, Refusal> {
    let Statement::ExpressionStatement(expression) = statement else {
        return Ok(None);
    };
    let Expression::CallExpression(call) = &expression.expression else {
        return Ok(None);
    };
    let Expression::StaticMemberExpression(push) = &call.callee else {
        return Ok(None);
    };
    if push.property.name != "push" || state_member(&push.object, state, semantic) != Some("trys") {
        return Ok(None);
    }
    let [Argument::ArrayExpression(array)] = call.arguments.as_slice() else {
        return Err(Refusal::RegionShape);
    };
    let mut slots: [Option<u32>; 4] = [None; 4];
    if array.elements.len() != 4 {
        return Err(Refusal::RegionShape);
    }
    for (slot, element) in slots.iter_mut().zip(array.elements.iter()) {
        *slot = match element {
            ArrayExpressionElement::Elision(_) => None,
            other => Some(
                other
                    .as_expression()
                    .and_then(integer)
                    .ok_or(Refusal::RegionShape)?,
            ),
        };
    }
    let [Some(try_start), catch_start, finally_start, Some(end)] = slots else {
        return Err(Refusal::RegionShape);
    };
    if catch_start.is_none() && finally_start.is_none() {
        return Err(Refusal::RegionShape);
    }
    Ok(Some(Region {
        try_start,
        catch_start,
        finally_start,
        end,
    }))
}

fn completes_normally(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => false,
        Statement::IfStatement(branch) => {
            branch.alternate.as_ref().is_none_or(completes_normally)
                || completes_normally(&branch.consequent)
        }
        Statement::BlockStatement(block) => block.body.last().is_none_or(completes_normally),
        _ => true,
    }
}

fn parse_machine<'a>(
    body: &'a FunctionBody<'a>,
    state: SymbolId,
    semantic: &Semantic<'a>,
) -> Result<Machine<'a>, Refusal> {
    let mut discriminant_uses: usize = 0;
    let groups: Vec<&'a [Statement<'a>]> = match body.statements.as_slice() {
        [Statement::SwitchStatement(switch)]
            if state_member(&switch.discriminant, state, semantic) == Some("label") =>
        {
            discriminant_uses = 1;
            let mut groups: Vec<&'a [Statement<'a>]> = Vec::with_capacity(switch.cases.len());
            for (index, case) in switch.cases.iter().enumerate() {
                let label: Option<u32> = case.test.as_ref().and_then(integer);
                if label != u32::try_from(index).ok() || case.consequent.is_empty() {
                    return Err(Refusal::MachineShape);
                }
                groups.push(case.consequent.as_slice());
            }
            groups
        }
        statements => vec![statements],
    };
    if groups.len() > MAX_BLOCKS {
        return Err(Refusal::TooLarge);
    }
    let count: u32 = u32::try_from(groups.len()).map_err(|_| Refusal::TooLarge)?;
    let mut blocks: Vec<Block<'a>> = Vec::with_capacity(groups.len());
    let mut regions: Vec<Region> = Vec::new();
    for (label, statements) in (0..count).zip(groups) {
        blocks.push(parse_block(
            label,
            statements,
            count,
            state,
            semantic,
            &mut regions,
        )?);
    }
    let label_sets: usize = blocks
        .iter()
        .filter(|block: &&Block<'a>| matches!(block.terminator, Terminator::FallThrough(_)))
        .count();
    let sents: usize = blocks
        .iter()
        .map(|block: &Block<'a>| block.sents.len())
        .sum();
    let expected: usize = discriminant_uses + label_sets + regions.len() + sents;
    if semantic.symbols().get_resolved_reference_ids(state).len() != expected {
        return Err(Refusal::StateMisuse);
    }
    let (region_parent, block_part): (Vec<Option<Part>>, Vec<Option<Part>>) =
        region_layout(&regions, count)?;
    let mut machine: Machine<'a> = Machine {
        state,
        blocks,
        regions,
        region_parent,
        block_part,
    };
    attach_catch_entries(&mut machine, semantic)?;
    Ok(machine)
}

fn parse_block<'a>(
    label: u32,
    statements: &'a [Statement<'a>],
    count: u32,
    state: SymbolId,
    semantic: &Semantic<'a>,
    regions: &mut Vec<Region>,
) -> Result<Block<'a>, Refusal> {
    let mut rest: &'a [Statement<'a>] = statements;
    let mut region: Option<usize> = None;
    if let Some(first) = rest.first()
        && let Some(entry) = trys_push(first, state, semantic)?
    {
        if entry.try_start != label || regions.len() >= MAX_REGIONS {
            return Err(Refusal::RegionShape);
        }
        region = Some(regions.len());
        regions.push(entry);
        rest = &rest[1..];
    }
    let (last, body): (&'a Statement<'a>, &'a [Statement<'a>]) =
        rest.split_last().ok_or(Refusal::ImplicitFallThrough)?;
    let mut kept: Vec<&'a Statement<'a>> = body.iter().collect();
    let terminator: Terminator<'a> = if let Statement::ReturnStatement(ret) = last {
        match instruction(ret)? {
            Instruction::Return(value) => Terminator::Return(value),
            Instruction::Jump(target) => Terminator::Jump(target),
            Instruction::Await(value) => Terminator::Await(value),
            Instruction::EndFinally => Terminator::EndFinally,
        }
    } else if let Some(target) = label_set(last, state, semantic) {
        if target != label + 1 || target >= count {
            return Err(Refusal::ImplicitFallThrough);
        }
        Terminator::FallThrough(target)
    } else if completes_normally(last) {
        return Err(Refusal::ImplicitFallThrough);
    } else {
        kept.push(last);
        Terminator::Stop
    };
    for target in terminator_targets(&terminator, label) {
        if target >= count {
            return Err(Refusal::UnresolvedTransfer);
        }
    }
    let mut scan: NestedScan = NestedScan::default();
    for statement in &kept {
        scan.statement(statement)?;
    }
    for nested in &scan.nested {
        if let NestedKind::Jump(target) = nested.kind
            && target >= count
        {
            return Err(Refusal::UnresolvedTransfer);
        }
    }
    let mut collector: SentCollector<'_, 'a> = SentCollector {
        state,
        semantic,
        sents: Vec::new(),
    };
    for statement in &kept {
        collector.visit_statement(statement);
    }
    match terminator {
        Terminator::Return(Some(value)) | Terminator::Await(value) => {
            collector.visit_expression(value);
        }
        _ => {}
    }
    Ok(Block {
        label,
        statements: kept,
        terminator,
        nested: scan.nested,
        region,
        catch_entry: None,
        sents: collector.sents,
    })
}

pub(super) fn terminator_targets(terminator: &Terminator<'_>, label: u32) -> Vec<u32> {
    match terminator {
        Terminator::Jump(target) | Terminator::FallThrough(target) => vec![*target],
        Terminator::Await(_) => vec![label + 1],
        Terminator::Return(_) | Terminator::EndFinally | Terminator::Stop => Vec::new(),
    }
}

#[derive(Default)]
struct NestedScan {
    nested: Vec<Nested>,
    loops: usize,
    breakables: usize,
    labels: Vec<String>,
}

impl NestedScan {
    fn statement(&mut self, statement: &Statement<'_>) -> Result<(), Refusal> {
        match statement {
            Statement::ReturnStatement(ret) => {
                let kind: NestedKind = match instruction(ret)? {
                    Instruction::Return(value) => NestedKind::Return(value.map(GetSpan::span)),
                    Instruction::Jump(target) => NestedKind::Jump(target),
                    Instruction::Await(_) | Instruction::EndFinally => {
                        return Err(Refusal::MisplacedInstruction);
                    }
                };
                self.nested.push(Nested {
                    statement: ret.span,
                    kind,
                });
            }
            Statement::BlockStatement(block) => {
                for inner in &block.body {
                    self.statement(inner)?;
                }
            }
            Statement::IfStatement(branch) => {
                self.statement(&branch.consequent)?;
                if let Some(alternate) = &branch.alternate {
                    self.statement(alternate)?;
                }
            }
            Statement::ForStatement(looped) => self.looped(&looped.body)?,
            Statement::ForInStatement(looped) => self.looped(&looped.body)?,
            Statement::ForOfStatement(looped) => self.looped(&looped.body)?,
            Statement::WhileStatement(looped) => self.looped(&looped.body)?,
            Statement::DoWhileStatement(looped) => self.looped(&looped.body)?,
            Statement::SwitchStatement(switch) => {
                self.breakables += 1;
                for case in &switch.cases {
                    for inner in &case.consequent {
                        self.statement(inner)?;
                    }
                }
                self.breakables -= 1;
            }
            Statement::LabeledStatement(labeled) => {
                self.labels.push(labeled.label.name.to_string());
                self.statement(&labeled.body)?;
                self.labels.pop();
            }
            Statement::TryStatement(attempt) => {
                for inner in &attempt.block.body {
                    self.statement(inner)?;
                }
                if let Some(handler) = &attempt.handler {
                    for inner in &handler.body.body {
                        self.statement(inner)?;
                    }
                }
                if let Some(finalizer) = &attempt.finalizer {
                    for inner in &finalizer.body {
                        self.statement(inner)?;
                    }
                }
            }
            Statement::BreakStatement(jump) => {
                let resolved: bool = match &jump.label {
                    Some(label) => self.labels.iter().any(|name| name == label.name.as_str()),
                    None => self.breakables > 0,
                };
                if !resolved {
                    return Err(Refusal::MachineShape);
                }
            }
            Statement::ContinueStatement(jump) => {
                let resolved: bool = match &jump.label {
                    Some(label) => {
                        self.loops > 0 && self.labels.iter().any(|name| name == label.name.as_str())
                    }
                    None => self.loops > 0,
                };
                if !resolved {
                    return Err(Refusal::MachineShape);
                }
            }
            Statement::WithStatement(_) => return Err(Refusal::MachineShape),
            _ => {}
        }
        Ok(())
    }

    fn looped(&mut self, body: &Statement<'_>) -> Result<(), Refusal> {
        self.loops += 1;
        self.breakables += 1;
        let result: Result<(), Refusal> = self.statement(body);
        self.loops -= 1;
        self.breakables -= 1;
        result
    }
}

struct SentCollector<'s, 'a> {
    state: SymbolId,
    semantic: &'s Semantic<'a>,
    sents: Vec<Span>,
}

impl<'a> Visit<'a> for SentCollector<'_, 'a> {
    fn visit_function(&mut self, _function: &Function<'a>, _flags: ScopeFlags) {}

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if is_sent_call(call, self.state, self.semantic) {
            self.sents.push(call.span);
        }
        walk::walk_call_expression(self, call);
    }
}

type RegionLayout = (Vec<Option<Part>>, Vec<Option<Part>>);

fn region_layout(regions: &[Region], count: u32) -> Result<RegionLayout, Refusal> {
    for region in regions {
        let mut previous: u32 = region.try_start;
        for next in [region.catch_start, region.finally_start, Some(region.end)]
            .into_iter()
            .flatten()
        {
            if next <= previous || next >= count {
                return Err(Refusal::RegionShape);
            }
            previous = next;
        }
    }
    let mut region_parent: Vec<Option<Part>> = vec![None; regions.len()];
    for (index, region) in regions.iter().enumerate() {
        let mut parent: Option<(Part, u32)> = None;
        for (other_index, other) in regions.iter().enumerate() {
            if other_index == index {
                continue;
            }
            let disjoint: bool = region.end <= other.try_start || other.end <= region.try_start;
            let encloses: bool = other.try_start < region.try_start && region.end < other.end;
            if disjoint {
                continue;
            }
            if !encloses {
                let enclosed: bool = region.try_start < other.try_start && other.end < region.end;
                if enclosed {
                    continue;
                }
                return Err(Refusal::RegionShape);
            }
            let part: Part = [PartKind::Try, PartKind::Catch, PartKind::Finally]
                .into_iter()
                .find_map(|kind: PartKind| {
                    let (start, end): (u32, u32) = other.part_range(kind)?;
                    (start < region.try_start && region.end < end).then_some(Part {
                        region: other_index,
                        kind,
                    })
                })
                .ok_or(Refusal::RegionShape)?;
            let width: u32 = other.end - other.try_start;
            if parent.is_none_or(|(_, best): (Part, u32)| width < best) {
                parent = Some((part, width));
            }
        }
        region_parent[index] = parent.map(|(part, _): (Part, u32)| part);
    }
    for index in 0..regions.len() {
        let mut depth: usize = 0;
        let mut cursor: Option<Part> = region_parent[index];
        while let Some(part) = cursor {
            depth += 1;
            if depth > MAX_REGION_DEPTH {
                return Err(Refusal::TooDeep);
            }
            cursor = region_parent[part.region];
        }
    }
    let mut block_part: Vec<Option<Part>> = vec![None; count as usize];
    for (label, slot) in (0..count).zip(block_part.iter_mut()) {
        let mut best: Option<(Part, u32)> = None;
        for (index, region) in regions.iter().enumerate() {
            for kind in [PartKind::Try, PartKind::Catch, PartKind::Finally] {
                let Some((start, end)) = region.part_range(kind) else {
                    continue;
                };
                if start <= label && label < end {
                    let width: u32 = end - start;
                    if best.is_none_or(|(_, current): (Part, u32)| width < current) {
                        best = Some((
                            Part {
                                region: index,
                                kind,
                            },
                            width,
                        ));
                    }
                }
            }
        }
        *slot = best.map(|(part, _): (Part, u32)| part);
    }
    Ok((region_parent, block_part))
}

fn attach_catch_entries(machine: &mut Machine<'_>, semantic: &Semantic<'_>) -> Result<(), Refusal> {
    let catch_starts: Vec<u32> = machine
        .regions
        .iter()
        .filter_map(|region: &Region| region.catch_start)
        .collect();
    for start in catch_starts {
        let state: SymbolId = machine.state;
        let block: &mut Block<'_> = machine
            .blocks
            .get_mut(start as usize)
            .ok_or(Refusal::RegionShape)?;
        if block.region.is_some() {
            return Err(Refusal::RegionShape);
        }
        let first: &Statement<'_> = block.statements.first().ok_or(Refusal::CatchBinding)?;
        let Statement::ExpressionStatement(expression) = first else {
            return Err(Refusal::CatchBinding);
        };
        let (entry, sent_span): (CatchEntry, Span) = match &expression.expression {
            Expression::CallExpression(call) if is_sent_call(call, state, semantic) => (
                CatchEntry {
                    binding: None,
                    name: None,
                },
                call.span,
            ),
            Expression::AssignmentExpression(assignment)
                if assignment.operator == AssignmentOperator::Assign =>
            {
                let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left else {
                    return Err(Refusal::CatchBinding);
                };
                let Expression::CallExpression(call) = &assignment.right else {
                    return Err(Refusal::CatchBinding);
                };
                if !is_sent_call(call, state, semantic) {
                    return Err(Refusal::CatchBinding);
                }
                (catch_entry(target, semantic)?, call.span)
            }
            _ => return Err(Refusal::CatchBinding),
        };
        block.statements.remove(0);
        block.sents.retain(|span: &Span| *span != sent_span);
        block.catch_entry = Some(entry);
    }
    Ok(())
}

fn catch_entry(
    target: &IdentifierReference<'_>,
    semantic: &Semantic<'_>,
) -> Result<CatchEntry, Refusal> {
    let symbol: SymbolId = resolved_symbol(target, semantic).ok_or(Refusal::CatchBinding)?;
    Ok(CatchEntry {
        binding: Some(symbol),
        name: Some(target.span),
    })
}

fn check_catch_bindings(
    machine: &Machine<'_>,
    locals: &Locals,
    semantic: &Semantic<'_>,
) -> Result<(), Refusal> {
    for (index, region) in machine.regions.iter().enumerate() {
        let Some(start) = region.catch_start else {
            continue;
        };
        let Some(entry) = machine
            .blocks
            .get(start as usize)
            .and_then(|block: &Block<'_>| block.catch_entry)
        else {
            return Err(Refusal::CatchBinding);
        };
        let Some(symbol) = entry.binding else {
            continue;
        };
        if !locals.hoisted.contains(&symbol) || !locals.stable.contains(&symbol) {
            return Err(Refusal::CatchBinding);
        }
        let catch_part: Part = Part {
            region: index,
            kind: PartKind::Catch,
        };
        let spans: Vec<Span> = machine
            .blocks
            .iter()
            .filter(|block: &&Block<'_>| part_within(machine, block.label, catch_part))
            .flat_map(|block: &Block<'_>| block_spans(block))
            .collect();
        for reference_id in semantic.symbols().get_resolved_reference_ids(symbol) {
            let node: oxc_semantic::NodeId =
                semantic.symbols().get_reference(*reference_id).node_id();
            let span: Span = semantic.nodes().get_node(node).kind().span();
            let inside: bool = span == entry.name.unwrap_or(Span::new(0, 0))
                || spans
                    .iter()
                    .any(|outer: &Span| outer.start <= span.start && span.end <= outer.end);
            if !inside {
                return Err(Refusal::CatchBinding);
            }
        }
    }
    Ok(())
}

pub(super) fn part_within(machine: &Machine<'_>, label: u32, part: Part) -> bool {
    let mut cursor: Option<Part> = machine.block_part.get(label as usize).copied().flatten();
    while let Some(current) = cursor {
        if current == part {
            return true;
        }
        cursor = machine.region_parent.get(current.region).copied().flatten();
    }
    false
}

pub(super) fn block_spans(block: &Block<'_>) -> Vec<Span> {
    let mut spans: Vec<Span> = block
        .statements
        .iter()
        .map(|statement: &&Statement<'_>| statement.span())
        .collect();
    match block.terminator {
        Terminator::Return(Some(value)) | Terminator::Await(value) => spans.push(value.span()),
        _ => {}
    }
    spans
}

#[derive(Debug)]
pub(super) struct ProloguePlan<'a> {
    pub(super) declarations: Vec<&'a VariableDeclaration<'a>>,
    defaults: BTreeMap<SymbolId, &'a Expression<'a>>,
    order: Vec<PrologueItem<'a>>,
}

#[derive(Debug, Clone, Copy)]
enum PrologueItem<'a> {
    Declaration(&'a VariableDeclaration<'a>),
    Default,
    Other(&'a Statement<'a>),
}

impl<'a> ProloguePlan<'a> {
    fn analyze(
        prologue: &'a [Statement<'a>],
        callback: &'a Function<'a>,
        semantic: &Semantic<'a>,
    ) -> Result<Self, Refusal> {
        let params: Vec<SymbolId> = callback
            .params
            .items
            .iter()
            .map(|param| match &param.pattern.kind {
                BindingPatternKind::BindingIdentifier(binding) => {
                    binding.symbol_id.get().ok_or(Refusal::ParameterShape)
                }
                _ => Err(Refusal::ParameterShape),
            })
            .collect::<Result<Vec<SymbolId>, Refusal>>()?;
        let mut plan: Self = Self {
            declarations: Vec::new(),
            defaults: BTreeMap::new(),
            order: Vec::new(),
        };
        let mut leading: bool = true;
        for statement in prologue {
            if leading
                && let Some((symbol, value)) = default_assignment(statement, semantic)
                && let Some(position) = params.iter().position(|param| *param == symbol)
                && !plan.defaults.contains_key(&symbol)
                && default_is_hoistable(value, &params[..position], callback, semantic)
            {
                plan.defaults.insert(symbol, value);
                plan.order.push(PrologueItem::Default);
                continue;
            }
            match statement {
                Statement::VariableDeclaration(declaration)
                    if declaration.declarations.iter().all(|d| d.init.is_none()) =>
                {
                    plan.declarations.push(declaration);
                    plan.order.push(PrologueItem::Declaration(declaration));
                }
                other => {
                    leading = false;
                    plan.order.push(PrologueItem::Other(other));
                }
            }
        }
        Ok(plan)
    }

    fn render(
        &self,
        removed: &BTreeSet<SymbolId>,
        renderer: &Renderer<'_>,
        semantic: &Semantic<'_>,
    ) -> Result<Vec<Out>, Refusal> {
        let mut outs: Vec<Out> = Vec::new();
        for item in &self.order {
            match item {
                PrologueItem::Default => {}
                PrologueItem::Other(statement) => outs.push(raw_statement(statement, renderer)?),
                PrologueItem::Declaration(declaration) => {
                    let kept: Vec<Span> = declaration
                        .declarations
                        .iter()
                        .filter(|declarator| match &declarator.id.kind {
                            BindingPatternKind::BindingIdentifier(binding) => {
                                binding.symbol_id.get().is_none_or(|symbol: SymbolId| {
                                    !removed.contains(&symbol)
                                        && !semantic
                                            .symbols()
                                            .get_resolved_reference_ids(symbol)
                                            .is_empty()
                                })
                            }
                            _ => true,
                        })
                        .map(|declarator| declarator.span)
                        .collect();
                    for span in kept {
                        let mut code: Code = Code::text(declaration.kind.as_str());
                        code.push_str(" ");
                        code.append(renderer.render(span)?);
                        code.push_str(";");
                        outs.push(Out::Raw(super::emit::Raw { code, indent: None }));
                    }
                }
            }
        }
        Ok(outs)
    }

    fn params(
        &self,
        callback: &'a Function<'a>,
        renderer: &Renderer<'_>,
    ) -> Result<Option<(Vec<Code>, usize)>, Refusal> {
        if callback.params.items.is_empty() {
            return Ok(None);
        }
        let mut codes: Vec<Code> = Vec::with_capacity(callback.params.items.len());
        let mut expected: Option<usize> = None;
        for (index, param) in callback.params.items.iter().enumerate() {
            let BindingPatternKind::BindingIdentifier(binding) = &param.pattern.kind else {
                return Err(Refusal::ParameterShape);
            };
            let mut code: Code = renderer.render(param.span)?;
            if let Some(symbol) = binding.symbol_id.get()
                && let Some(value) = self.defaults.get(&symbol)
            {
                code.push_str(" = ");
                code.append(renderer.render(value.span())?);
                expected.get_or_insert(index);
            }
            codes.push(code);
        }
        let expected: usize = expected.unwrap_or(codes.len());
        Ok(Some((codes, expected)))
    }

    pub(super) fn hoisted(&self) -> impl Iterator<Item = SymbolId> + '_ {
        self.declarations
            .iter()
            .flat_map(|declaration| declaration.declarations.iter())
            .filter_map(|declarator| match &declarator.id.kind {
                BindingPatternKind::BindingIdentifier(binding) => binding.symbol_id.get(),
                _ => None,
            })
    }
}

fn default_assignment<'a>(
    statement: &'a Statement<'a>,
    semantic: &Semantic<'a>,
) -> Option<(SymbolId, &'a Expression<'a>)> {
    let Statement::IfStatement(branch) = statement else {
        return None;
    };
    if branch.alternate.is_some() {
        return None;
    }
    let Expression::BinaryExpression(test) = &branch.test else {
        return None;
    };
    let undefined_right: bool = is_void_zero(&test.right)
        || matches!(&test.right, Expression::Identifier(reference)
            if reference.name == "undefined" && resolved_symbol(reference, semantic).is_none());
    if test.operator != oxc_ast::ast::BinaryOperator::StrictEquality || !undefined_right {
        return None;
    }
    let Expression::Identifier(tested) = &test.left else {
        return None;
    };
    let symbol: SymbolId = resolved_symbol(tested, semantic)?;
    let assignment_statement: &'a Statement<'a> = match &branch.consequent {
        Statement::BlockStatement(block) => match block.body.as_slice() {
            [single] => single,
            _ => return None,
        },
        other => other,
    };
    let Statement::ExpressionStatement(expression) = assignment_statement else {
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
    (resolved_symbol(target, semantic) == Some(symbol)).then_some((symbol, &assignment.right))
}

fn default_is_hoistable<'a>(
    value: &Expression<'a>,
    earlier: &[SymbolId],
    callback: &Function<'a>,
    semantic: &Semantic<'a>,
) -> bool {
    struct DefaultProbe<'s, 'a> {
        semantic: &'s Semantic<'a>,
        scope: Span,
        earlier: &'s [SymbolId],
        ok: bool,
    }
    impl<'a> Visit<'a> for DefaultProbe<'_, 'a> {
        fn enter_node(&mut self, kind: AstKind<'a>) {
            match kind {
                AstKind::IdentifierReference(reference) => {
                    if reference.name == "arguments" {
                        self.ok = false;
                    }
                    if let Some(symbol) = resolved_symbol(reference, self.semantic) {
                        let declared: Span = self.semantic.symbols().get_span(symbol);
                        let local: bool =
                            self.scope.start <= declared.start && declared.end <= self.scope.end;
                        if local && !self.earlier.contains(&symbol) {
                            self.ok = false;
                        }
                    }
                }
                AstKind::ThisExpression(_)
                | AstKind::Super(_)
                | AstKind::MetaProperty(_)
                | AstKind::YieldExpression(_)
                | AstKind::AwaitExpression(_) => self.ok = false,
                _ => {}
            }
        }
    }
    let mut probe: DefaultProbe<'_, '_> = DefaultProbe {
        semantic,
        scope: callback.span,
        earlier,
        ok: true,
    };
    probe.visit_expression(value);
    probe.ok
}
