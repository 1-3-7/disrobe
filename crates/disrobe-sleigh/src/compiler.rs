use std::collections::{BTreeMap, BTreeSet};

use crate::SleighError;
use crate::syntax::{
    CompareOp, Constructor, Endian, PatternAtom, PatternExpr, PatternValue, SleighSpec, TokenDef,
};

const MAX_EVALUATION_DEPTH: usize = 128;
const MAX_PATTERN_CLAUSES: usize = 4_096;

pub type ContextState = BTreeMap<String, i64>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictPolicy {
    FirstDefined,
    Strict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionNode {
    Resolve { candidates: Box<[usize]> },
    Test { bit: u16, one: usize, zero: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeMatch {
    pub address: u64,
    pub constructor_id: usize,
    pub length: usize,
    pub mnemonic: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeOutcome {
    Ambiguous { constructors: Vec<usize> },
    Matched(DecodeMatch),
    NoMatch,
    Truncated { available: usize, needed: usize },
}

#[derive(Clone, Debug)]
struct CompiledField {
    endian: Endian,
    high_bit: u8,
    low_bit: u8,
    signed: bool,
    token: usize,
    token_bits: u32,
}

#[derive(Clone, Debug)]
pub struct CompiledSpec {
    conflict_policy: ConflictPolicy,
    fields: BTreeMap<String, CompiledField>,
    nodes: Vec<DecisionNode>,
    pattern_clauses: Vec<Option<Vec<PatternClause>>>,
    root: usize,
    spec: SleighSpec,
    tables: BTreeMap<String, Vec<usize>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PatternConstraint {
    Bit {
        bit: usize,
        value: bool,
    },
    Compare {
        left: String,
        op: CompareOp,
        position: usize,
        right: PatternValue,
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PatternClause {
    constraints: BTreeSet<PatternConstraint>,
    span: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MatchResult {
    ambiguities: BTreeSet<usize>,
    consumed: usize,
    specificity: u32,
}

#[derive(Debug)]
struct Evaluator<'a> {
    bytes: &'a [u8],
    compiled: &'a CompiledSpec,
    context: &'a ContextState,
    needed: usize,
    table_stack: Vec<String>,
}

#[derive(Debug)]
struct ClauseCompiler<'a> {
    constructors: &'a [Constructor],
    contexts: &'a BTreeSet<String>,
    fields: &'a BTreeMap<String, CompiledField>,
    registers: &'a BTreeSet<String>,
    tables: &'a BTreeMap<String, Vec<usize>>,
}

pub fn compile_spec(spec: SleighSpec) -> Result<CompiledSpec, SleighError> {
    compile_spec_with_policy(spec, ConflictPolicy::Strict)
}

pub fn compile_spec_with_policy(
    spec: SleighSpec,
    conflict_policy: ConflictPolicy,
) -> Result<CompiledSpec, SleighError> {
    let mut fields: BTreeMap<String, CompiledField> = BTreeMap::new();
    for (token_index, token) in spec.tokens.iter().enumerate() {
        if token.bits == 0 || token.bits > 64 || !token.bits.is_multiple_of(8) {
            return Err(SleighError::Parse {
                message: format!("unsupported token width {}", token.bits),
                offset: 0,
            });
        }
        let token_endian: Endian =
            token
                .endian
                .or(spec.endian)
                .ok_or_else(|| SleighError::Parse {
                    message: format!("token {} has no effective endian", token.name),
                    offset: 0,
                })?;
        for field in &token.fields {
            if field.high_bit < field.low_bit || u32::from(field.high_bit) >= token.bits {
                return Err(SleighError::Parse {
                    message: format!("invalid token field {}", field.name),
                    offset: 0,
                });
            }
            let definition: CompiledField = CompiledField {
                endian: token_endian,
                high_bit: field.high_bit,
                low_bit: field.low_bit,
                signed: field.signed,
                token: token_index,
                token_bits: token.bits,
            };
            let previous: Option<CompiledField> = fields.insert(field.name.clone(), definition);
            if previous.is_some() {
                return Err(SleighError::Parse {
                    message: format!("duplicate token field {}", field.name),
                    offset: 0,
                });
            }
        }
    }
    let mut tables: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (constructor_id, constructor) in spec.constructors.iter().enumerate() {
        tables
            .entry(constructor.table.clone())
            .or_default()
            .push(constructor_id);
    }
    let contexts: BTreeSet<String> = spec
        .contexts
        .iter()
        .map(|context| context.name.clone())
        .collect();
    let registers: BTreeSet<String> = spec
        .registers
        .iter()
        .map(|register| register.name.clone())
        .collect();
    for constructor in &spec.constructors {
        validate_pattern(
            &constructor.pattern,
            &fields,
            &contexts,
            &registers,
            &tables,
            0,
        )?;
    }
    let clause_compiler: ClauseCompiler<'_> = ClauseCompiler {
        constructors: &spec.constructors,
        contexts: &contexts,
        fields: &fields,
        registers: &registers,
        tables: &tables,
    };
    let pattern_clauses: Vec<Option<Vec<PatternClause>>> = spec
        .constructors
        .iter()
        .map(|constructor: &Constructor| clause_compiler.compile(&constructor.pattern, 0, 0))
        .collect();
    let roots: Vec<usize> = tables.get("instruction").cloned().unwrap_or_default();
    if roots.is_empty() {
        return Err(SleighError::Parse {
            message: "instruction table is empty".to_owned(),
            offset: 0,
        });
    }
    for constructor_id in &roots {
        let constructor: &Constructor = &spec.constructors[*constructor_id];
        let mut visiting: BTreeSet<String> = BTreeSet::new();
        if clause_compiler.can_match_empty(&constructor.pattern, 0, &mut visiting) {
            return Err(SleighError::Parse {
                message: format!(
                    "zero-width instruction constructor {}",
                    constructor.mnemonic
                ),
                offset: 0,
            });
        }
    }
    let constraints: BTreeMap<usize, BTreeMap<u16, bool>> = roots
        .iter()
        .map(|constructor_id: &usize| {
            let mut visiting: BTreeSet<String> = BTreeSet::new();
            let bits: BTreeMap<u16, bool> = fixed_bits(
                &spec.constructors[*constructor_id].pattern,
                &fields,
                &tables,
                &spec.constructors,
                &mut visiting,
                0,
            );
            (*constructor_id, bits)
        })
        .collect();
    let mut nodes: Vec<DecisionNode> = Vec::new();
    let available: BTreeSet<u16> = constraints
        .values()
        .flat_map(|bits: &BTreeMap<u16, bool>| bits.keys().copied())
        .collect();
    let root: usize = build_decision_nodes(&roots, &available, &constraints, &mut nodes, 0);
    Ok(CompiledSpec {
        conflict_policy,
        fields,
        nodes,
        pattern_clauses,
        root,
        spec,
        tables,
    })
}

fn validate_pattern(
    pattern: &PatternExpr,
    fields: &BTreeMap<String, CompiledField>,
    contexts: &BTreeSet<String>,
    registers: &BTreeSet<String>,
    tables: &BTreeMap<String, Vec<usize>>,
    depth: usize,
) -> Result<(), SleighError> {
    if depth >= MAX_EVALUATION_DEPTH {
        return Err(SleighError::Parse {
            message: "pattern nesting limit exceeded".to_owned(),
            offset: 0,
        });
    }
    let validate_value: &dyn Fn(&str) -> Result<(), SleighError> = &|name: &str| {
        if fields.contains_key(name) || contexts.contains(name) {
            Ok(())
        } else {
            Err(SleighError::Parse {
                message: format!("undefined pattern value {name}"),
                offset: 0,
            })
        }
    };
    match pattern {
        PatternExpr::All(parts) | PatternExpr::Any(parts) => {
            for part in parts {
                validate_pattern(
                    part,
                    fields,
                    contexts,
                    registers,
                    tables,
                    depth.saturating_add(1),
                )?;
            }
            Ok(())
        }
        PatternExpr::Atom(PatternAtom::Compare { left, right, .. }) => {
            validate_value(left)?;
            match right {
                PatternValue::Add { identifier, .. } | PatternValue::Identifier(identifier) => {
                    validate_value(identifier)
                }
                PatternValue::Integer(_) => Ok(()),
            }
        }
        PatternExpr::Atom(PatternAtom::Residual(text)) => Err(SleighError::Parse {
            message: format!("unsupported pattern expression {text}"),
            offset: 0,
        }),
        PatternExpr::Atom(PatternAtom::Symbol(name)) => {
            if fields.contains_key(name)
                || contexts.contains(name)
                || registers.contains(name)
                || tables.contains_key(name)
            {
                Ok(())
            } else {
                Err(SleighError::Parse {
                    message: format!("undefined pattern symbol {name}"),
                    offset: 0,
                })
            }
        }
        PatternExpr::Next(left, right) => {
            validate_pattern(
                left,
                fields,
                contexts,
                registers,
                tables,
                depth.saturating_add(1),
            )?;
            validate_pattern(
                right,
                fields,
                contexts,
                registers,
                tables,
                depth.saturating_add(1),
            )
        }
        PatternExpr::True => Ok(()),
    }
}

impl ClauseCompiler<'_> {
    fn compile(
        &self,
        pattern: &PatternExpr,
        position: usize,
        depth: usize,
    ) -> Option<Vec<PatternClause>> {
        let mut visiting: BTreeSet<String> = BTreeSet::new();
        self.compile_inner(pattern, position, depth, &mut visiting)
    }

    fn can_match_empty(
        &self,
        pattern: &PatternExpr,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> bool {
        if depth >= MAX_EVALUATION_DEPTH {
            return false;
        }
        match pattern {
            PatternExpr::True => true,
            PatternExpr::Atom(PatternAtom::Compare { left, right, .. }) => {
                self.symbol_span(left) == Some(0) && self.value_span(right) == Some(0)
            }
            PatternExpr::Atom(PatternAtom::Symbol(name)) => {
                if let Some(span) = self.symbol_span(name) {
                    return span == 0;
                }
                if !visiting.insert(name.clone()) {
                    return false;
                }
                let matches_empty: bool = self.tables.get(name).is_some_and(|constructor_ids| {
                    constructor_ids.iter().any(|constructor_id: &usize| {
                        self.constructors.get(*constructor_id).is_some_and(
                            |constructor: &Constructor| {
                                self.can_match_empty(
                                    &constructor.pattern,
                                    depth.saturating_add(1),
                                    visiting,
                                )
                            },
                        )
                    })
                });
                let removed: bool = visiting.remove(name);
                removed && matches_empty
            }
            PatternExpr::Atom(PatternAtom::Residual(_)) => false,
            PatternExpr::All(parts) => parts.iter().all(|part: &PatternExpr| {
                self.can_match_empty(part, depth.saturating_add(1), visiting)
            }),
            PatternExpr::Any(parts) => parts.iter().any(|part: &PatternExpr| {
                self.can_match_empty(part, depth.saturating_add(1), visiting)
            }),
            PatternExpr::Next(left, right) => {
                self.can_match_empty(left, depth.saturating_add(1), visiting)
                    && self.can_match_empty(right, depth.saturating_add(1), visiting)
            }
        }
    }

    fn compile_inner(
        &self,
        pattern: &PatternExpr,
        position: usize,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Vec<PatternClause>> {
        if depth >= MAX_EVALUATION_DEPTH {
            return None;
        }
        match pattern {
            PatternExpr::All(parts) => {
                self.compile_all(parts, position, depth.saturating_add(1), visiting)
            }
            PatternExpr::Any(parts) => {
                self.compile_any(parts, position, depth.saturating_add(1), visiting)
            }
            PatternExpr::Atom(atom) => {
                self.compile_atom(atom, position, depth.saturating_add(1), visiting)
            }
            PatternExpr::Next(left, right) => {
                self.compile_next(left, right, position, depth.saturating_add(1), visiting)
            }
            PatternExpr::True => Some(vec![PatternClause {
                constraints: BTreeSet::new(),
                span: 0,
            }]),
        }
    }

    fn compile_all(
        &self,
        parts: &[PatternExpr],
        position: usize,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Vec<PatternClause>> {
        let mut combined: Vec<PatternClause> = vec![PatternClause {
            constraints: BTreeSet::new(),
            span: 0,
        }];
        for part in parts {
            let additions: Vec<PatternClause> =
                self.compile_inner(part, position, depth, visiting)?;
            let product: usize = combined.len().checked_mul(additions.len())?;
            if product > MAX_PATTERN_CLAUSES {
                return None;
            }
            let mut next: Vec<PatternClause> = Vec::with_capacity(product);
            for current in &combined {
                for addition in &additions {
                    let mut constraints: BTreeSet<PatternConstraint> = current.constraints.clone();
                    constraints.extend(addition.constraints.iter().cloned());
                    next.push(PatternClause {
                        constraints,
                        span: current.span.max(addition.span),
                    });
                }
            }
            combined = deduplicate_pattern_clauses(next);
        }
        Some(combined)
    }

    fn compile_any(
        &self,
        parts: &[PatternExpr],
        position: usize,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Vec<PatternClause>> {
        let mut clauses: Vec<PatternClause> = Vec::new();
        for part in parts {
            let additions: Vec<PatternClause> =
                self.compile_inner(part, position, depth, visiting)?;
            let total: usize = clauses.len().checked_add(additions.len())?;
            if total > MAX_PATTERN_CLAUSES {
                return None;
            }
            clauses.extend(additions);
        }
        Some(deduplicate_pattern_clauses(clauses))
    }

    fn compile_next(
        &self,
        left: &PatternExpr,
        right: &PatternExpr,
        position: usize,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Vec<PatternClause>> {
        let left_clauses: Vec<PatternClause> =
            self.compile_inner(left, position, depth, visiting)?;
        let mut clauses: Vec<PatternClause> = Vec::new();
        for left_clause in left_clauses {
            let right_position: usize = position.checked_add(left_clause.span)?;
            let right_clauses: Vec<PatternClause> =
                self.compile_inner(right, right_position, depth, visiting)?;
            let total: usize = clauses.len().checked_add(right_clauses.len())?;
            if total > MAX_PATTERN_CLAUSES {
                return None;
            }
            for right_clause in right_clauses {
                let mut constraints: BTreeSet<PatternConstraint> = left_clause.constraints.clone();
                constraints.extend(right_clause.constraints);
                clauses.push(PatternClause {
                    constraints,
                    span: left_clause.span.checked_add(right_clause.span)?,
                });
            }
        }
        Some(deduplicate_pattern_clauses(clauses))
    }

    fn compile_atom(
        &self,
        atom: &PatternAtom,
        position: usize,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Vec<PatternClause>> {
        let clause: PatternClause = match atom {
            PatternAtom::Compare { left, op, right } => {
                let left_span: usize = self.symbol_span(left)?;
                let right_span: usize = self.value_span(right)?;
                PatternClause {
                    constraints: self.comparison_constraints(left, *op, right, position)?,
                    span: left_span.max(right_span),
                }
            }
            PatternAtom::Symbol(name) if self.tables.contains_key(name) => {
                return self.compile_table(name, position, depth, visiting);
            }
            PatternAtom::Symbol(name) => PatternClause {
                constraints: BTreeSet::new(),
                span: self.symbol_span(name)?,
            },
            PatternAtom::Residual(_) => return None,
        };
        Some(vec![clause])
    }

    fn comparison_constraints(
        &self,
        left: &str,
        op: CompareOp,
        right: &PatternValue,
        position: usize,
    ) -> Option<BTreeSet<PatternConstraint>> {
        if op == CompareOp::Equal
            && let PatternValue::Integer(value) = right
            && let Some(field) = self.fields.get(left)
        {
            let width: u8 = field.high_bit.checked_sub(field.low_bit)?.checked_add(1)?;
            let raw: u64 = if field.signed {
                let minimum: i128 = -(1_i128.checked_shl(u32::from(width.saturating_sub(1)))?);
                let maximum: i128 = -minimum - 1;
                let value_i128: i128 = i128::from(*value);
                if value_i128 < minimum || value_i128 > maximum {
                    return None;
                }
                u64::from_ne_bytes(value.to_ne_bytes()) & width_mask(width)
            } else {
                let raw: u64 = u64::try_from(*value).ok()?;
                if raw > width_mask(width) {
                    return None;
                }
                raw
            };
            let position_bits: usize = position.checked_mul(8)?;
            let mut constraints: BTreeSet<PatternConstraint> = BTreeSet::new();
            for relative in 0..width {
                let logical_bit: u32 = u32::from(field.low_bit.checked_add(relative)?);
                let stream_bit: usize = usize::from(decision_bit(field, logical_bit));
                let bit: usize = position_bits.checked_add(stream_bit)?;
                let value: bool = raw & (1_u64.checked_shl(u32::from(relative))?) != 0;
                constraints.insert(PatternConstraint::Bit { bit, value });
            }
            return Some(constraints);
        }
        Some(BTreeSet::from([PatternConstraint::Compare {
            left: left.to_owned(),
            op,
            position,
            right: right.clone(),
        }]))
    }

    fn compile_table(
        &self,
        name: &str,
        position: usize,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Vec<PatternClause>> {
        if !visiting.insert(name.to_owned()) {
            return None;
        }
        let constructor_ids: &Vec<usize> = self.tables.get(name)?;
        let mut clauses: Vec<PatternClause> = Vec::new();
        for constructor_id in constructor_ids {
            let constructor: &Constructor = self.constructors.get(*constructor_id)?;
            let additions: Vec<PatternClause> = self.compile_inner(
                &constructor.pattern,
                position,
                depth.saturating_add(1),
                visiting,
            )?;
            let total: usize = clauses.len().checked_add(additions.len())?;
            if total > MAX_PATTERN_CLAUSES {
                return None;
            }
            clauses.extend(additions);
        }
        let removed: bool = visiting.remove(name);
        if !removed {
            return None;
        }
        Some(deduplicate_pattern_clauses(clauses))
    }

    fn symbol_span(&self, name: &str) -> Option<usize> {
        self.fields.get(name).map_or_else(
            || (self.contexts.contains(name) || self.registers.contains(name)).then_some(0),
            |field: &CompiledField| usize::try_from(field.token_bits / 8).ok(),
        )
    }

    fn value_span(&self, value: &PatternValue) -> Option<usize> {
        match value {
            PatternValue::Add { identifier, .. } | PatternValue::Identifier(identifier) => {
                self.symbol_span(identifier)
            }
            PatternValue::Integer(_) => Some(0),
        }
    }
}

fn deduplicate_pattern_clauses(clauses: Vec<PatternClause>) -> Vec<PatternClause> {
    let unique: BTreeSet<PatternClause> = clauses.into_iter().collect();
    unique.into_iter().collect()
}

impl CompiledSpec {
    pub fn decision_nodes(&self) -> &[DecisionNode] {
        &self.nodes
    }

    pub const fn source(&self) -> &SleighSpec {
        &self.spec
    }

    pub fn decode(&self, bytes: &[u8], address: u64, context: &ContextState) -> DecodeOutcome {
        let candidates: Vec<usize> = self.decision_candidates(bytes).map_or_else(
            || self.tables.get("instruction").cloned().unwrap_or_default(),
            <[usize]>::to_vec,
        );
        let mut matches: Vec<(usize, MatchResult)> = Vec::new();
        let mut truncated_needed: Option<usize> = None;
        for constructor_id in candidates {
            let mut evaluator: Evaluator<'_> = Evaluator {
                bytes,
                compiled: self,
                context,
                needed: 0,
                table_stack: vec!["instruction".to_owned()],
            };
            if let Some(result) =
                evaluator.match_pattern(&self.spec.constructors[constructor_id].pattern, 0, 0)
            {
                matches.push((constructor_id, result));
            } else if evaluator.needed > bytes.len() {
                truncated_needed =
                    Some(truncated_needed.map_or(evaluator.needed, |current: usize| {
                        current.min(evaluator.needed)
                    }));
            }
        }
        if let Some(needed) = truncated_needed {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
                needed,
            };
        }
        if matches.is_empty() {
            return DecodeOutcome::NoMatch;
        }
        let Some(selected_index) = self.select_match(&matches) else {
            let mut constructors: BTreeSet<usize> = matches
                .iter()
                .map(|(constructor_id, _): &(usize, MatchResult)| *constructor_id)
                .collect();
            constructors.extend(
                matches
                    .iter()
                    .flat_map(|(_, result): &(usize, MatchResult)| {
                        result.ambiguities.iter().copied()
                    }),
            );
            return DecodeOutcome::Ambiguous {
                constructors: constructors.into_iter().collect(),
            };
        };
        let Some((constructor_id, result)) = matches.get(selected_index).cloned() else {
            return DecodeOutcome::NoMatch;
        };
        if !result.ambiguities.is_empty() {
            return DecodeOutcome::Ambiguous {
                constructors: result.ambiguities.into_iter().collect(),
            };
        }
        let Some(constructor) = self.spec.constructors.get(constructor_id) else {
            return DecodeOutcome::NoMatch;
        };
        DecodeOutcome::Matched(DecodeMatch {
            address,
            constructor_id,
            length: result.consumed.max(1),
            mnemonic: constructor.mnemonic.clone(),
        })
    }

    fn select_match(&self, matches: &[(usize, MatchResult)]) -> Option<usize> {
        if matches.len() == 1 {
            return Some(0);
        }
        let longest: usize = matches
            .iter()
            .map(|(_, result): &(usize, MatchResult)| result.consumed)
            .max()?;
        let candidates: Vec<usize> = matches
            .iter()
            .enumerate()
            .filter_map(|(index, (_, result))| (result.consumed == longest).then_some(index))
            .collect();
        if candidates.len() == 1 {
            return candidates.first().copied();
        }
        let selected: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|candidate_index: &usize| {
                let Some((candidate_id, _)) = matches.get(*candidate_index) else {
                    return false;
                };
                candidates.iter().copied().all(|other_index: usize| {
                    if *candidate_index == other_index {
                        return true;
                    }
                    let Some((other_id, _)) = matches.get(other_index) else {
                        return false;
                    };
                    self.pattern_strictly_contained(*candidate_id, *other_id)
                })
            })
            .collect();
        if let [selected_index] = selected.as_slice() {
            return Some(*selected_index);
        }
        match self.conflict_policy {
            ConflictPolicy::FirstDefined => candidates.into_iter().min_by_key(|index: &usize| {
                matches
                    .get(*index)
                    .and_then(|(constructor_id, _): &(usize, MatchResult)| {
                        self.spec.constructors.get(*constructor_id)
                    })
                    .map_or(usize::MAX, |constructor: &Constructor| {
                        constructor.source_order
                    })
            }),
            ConflictPolicy::Strict => None,
        }
    }

    fn pattern_strictly_contained(&self, special: usize, general: usize) -> bool {
        let Some(Some(special_clauses)) = self.pattern_clauses.get(special) else {
            return false;
        };
        let Some(Some(general_clauses)) = self.pattern_clauses.get(general) else {
            return false;
        };
        pattern_contained(special_clauses, general_clauses)
            && !pattern_contained(general_clauses, special_clauses)
    }

    fn decision_candidates(&self, bytes: &[u8]) -> Option<&[usize]> {
        let mut node_id: usize = self.root;
        loop {
            let Some(node) = self.nodes.get(node_id) else {
                return Some(&[]);
            };
            match node {
                DecisionNode::Resolve { candidates } => return Some(candidates),
                DecisionNode::Test { bit, one, zero } => {
                    let byte_index: usize = usize::from(*bit / 8);
                    let bit_index: u8 = u8::try_from(*bit % 8).unwrap_or(0);
                    let byte: &u8 = bytes.get(byte_index)?;
                    let value: bool = byte & (1_u8 << bit_index) != 0;
                    node_id = if value { *one } else { *zero };
                }
            }
        }
    }
}

fn pattern_contained(special: &[PatternClause], general: &[PatternClause]) -> bool {
    !special.is_empty()
        && !general.is_empty()
        && special.iter().all(|special_clause: &PatternClause| {
            general.iter().any(|general_clause: &PatternClause| {
                special_clause.span == general_clause.span
                    && general_clause
                        .constraints
                        .is_subset(&special_clause.constraints)
            })
        })
}

impl Evaluator<'_> {
    fn match_pattern(
        &mut self,
        pattern: &PatternExpr,
        cursor: usize,
        depth: usize,
    ) -> Option<MatchResult> {
        if depth >= MAX_EVALUATION_DEPTH {
            return None;
        }
        match pattern {
            PatternExpr::True => Some(MatchResult {
                ambiguities: BTreeSet::new(),
                consumed: 0,
                specificity: 0,
            }),
            PatternExpr::Atom(atom) => self.match_atom(atom, cursor, depth.saturating_add(1)),
            PatternExpr::All(parts) => {
                let mut consumed: usize = 0;
                let mut specificity: u32 = 0;
                let mut ambiguities: BTreeSet<usize> = BTreeSet::new();
                for part in parts {
                    let result: MatchResult =
                        self.match_pattern(part, cursor, depth.saturating_add(1))?;
                    consumed = consumed.max(result.consumed);
                    specificity = specificity.saturating_add(result.specificity);
                    ambiguities.extend(result.ambiguities);
                }
                Some(MatchResult {
                    ambiguities,
                    consumed,
                    specificity,
                })
            }
            PatternExpr::Any(parts) => {
                let mut matches: Vec<MatchResult> = Vec::new();
                let mut truncated_needed: usize = 0;
                for part in parts {
                    let (result, needed): (Option<MatchResult>, usize) =
                        self.isolated_match_pattern(part, cursor, depth.saturating_add(1));
                    truncated_needed = truncated_needed.max(needed);
                    if let Some(result) = result {
                        matches.push(result);
                    }
                }
                if truncated_needed > self.bytes.len() {
                    return None;
                }
                matches
                    .into_iter()
                    .max_by_key(|result: &MatchResult| result.specificity)
            }
            PatternExpr::Next(left, right) => {
                let left_result: MatchResult =
                    self.match_pattern(left, cursor, depth.saturating_add(1))?;
                let next_cursor: usize = cursor.checked_add(left_result.consumed)?;
                let right_result: MatchResult =
                    self.match_pattern(right, next_cursor, depth.saturating_add(1))?;
                let consumed: usize = left_result.consumed.checked_add(right_result.consumed)?;
                let specificity: u32 = left_result
                    .specificity
                    .saturating_add(right_result.specificity);
                let mut ambiguities: BTreeSet<usize> = left_result.ambiguities;
                ambiguities.extend(right_result.ambiguities);
                Some(MatchResult {
                    ambiguities,
                    consumed,
                    specificity,
                })
            }
        }
    }

    fn isolated_match_pattern(
        &mut self,
        pattern: &PatternExpr,
        cursor: usize,
        depth: usize,
    ) -> (Option<MatchResult>, usize) {
        let outer_needed: usize = self.needed;
        self.needed = 0;
        let result: Option<MatchResult> = self.match_pattern(pattern, cursor, depth);
        let attempt_needed: usize = self.needed;
        self.needed = outer_needed.max(attempt_needed);
        (result, attempt_needed)
    }

    fn match_atom(
        &mut self,
        atom: &PatternAtom,
        cursor: usize,
        depth: usize,
    ) -> Option<MatchResult> {
        match atom {
            PatternAtom::Compare { left, op, right } => {
                let (left_value, left_consumed, width): (i64, usize, u8) =
                    self.resolve_value(left, cursor)?;
                let (right_value, right_consumed): (i64, usize) = match right {
                    PatternValue::Integer(value) => (*value, 0),
                    PatternValue::Identifier(name) => {
                        let (value, consumed, _): (i64, usize, u8) =
                            self.resolve_value(name, cursor)?;
                        (value, consumed)
                    }
                    PatternValue::Add { identifier, amount } => {
                        let (value, consumed, _): (i64, usize, u8) =
                            self.resolve_value(identifier, cursor)?;
                        (value.checked_add(*amount)?, consumed)
                    }
                };
                let consumed: usize = left_consumed.max(right_consumed);
                let matched: bool = match op {
                    CompareOp::Equal => left_value == right_value,
                    CompareOp::NotEqual => left_value != right_value,
                    CompareOp::Less => left_value < right_value,
                    CompareOp::LessEqual => left_value <= right_value,
                    CompareOp::Greater => left_value > right_value,
                    CompareOp::GreaterEqual => left_value >= right_value,
                };
                matched.then_some(MatchResult {
                    ambiguities: BTreeSet::new(),
                    consumed,
                    specificity: u32::from(width).max(1),
                })
            }
            PatternAtom::Symbol(name) => {
                if let Some((_, consumed, _)) = self.resolve_value(name, cursor) {
                    return Some(MatchResult {
                        ambiguities: BTreeSet::new(),
                        consumed,
                        specificity: 0,
                    });
                }
                if self
                    .compiled
                    .spec
                    .registers
                    .iter()
                    .any(|register| register.name == *name)
                {
                    return Some(MatchResult {
                        ambiguities: BTreeSet::new(),
                        consumed: 0,
                        specificity: 0,
                    });
                }
                self.match_table(name, cursor, depth.saturating_add(1))
            }
            PatternAtom::Residual(_) => None,
        }
    }

    fn resolve_value(&mut self, name: &str, cursor: usize) -> Option<(i64, usize, u8)> {
        if let Some((field_token, field_endian, high_bit, low_bit, signed)) =
            self.compiled.fields.get(name).map(|field: &CompiledField| {
                (
                    field.token,
                    field.endian,
                    field.high_bit,
                    field.low_bit,
                    field.signed,
                )
            })
        {
            let token: &TokenDef = self.compiled.spec.tokens.get(field_token)?;
            let token_bytes: usize = usize::try_from(token.bits / 8).ok()?;
            let end: usize = cursor.checked_add(token_bytes)?;
            let Some(bytes): Option<&[u8]> = self.bytes.get(cursor..end) else {
                self.needed = self.needed.max(end);
                return None;
            };
            let raw_token: u64 = read_token(bytes, field_endian)?;
            let width: u8 = high_bit.checked_sub(low_bit)?.checked_add(1)?;
            let mask: u64 = width_mask(width);
            let raw_value: u64 = raw_token.checked_shr(u32::from(low_bit))? & mask;
            let value: i64 = if signed {
                sign_extend(raw_value, width)
            } else {
                i64::try_from(raw_value).ok()?
            };
            return Some((value, token_bytes, width));
        }
        self.compiled
            .spec
            .contexts
            .iter()
            .find(|field| field.name == name)
            .map(|field| {
                let width: u8 = field
                    .high_bit
                    .saturating_sub(field.low_bit)
                    .saturating_add(1);
                let value: i64 = self.context.get(name).copied().unwrap_or(0);
                (value, 0, width)
            })
    }

    fn match_table(&mut self, table: &str, cursor: usize, depth: usize) -> Option<MatchResult> {
        if depth >= MAX_EVALUATION_DEPTH {
            return None;
        }
        if self.table_stack.len() >= 64 || self.table_stack.iter().any(|name| name == table) {
            return None;
        }
        let constructors: Vec<usize> = self.compiled.tables.get(table)?.clone();
        self.table_stack.push(table.to_owned());
        let mut matches: Vec<(usize, MatchResult)> = Vec::new();
        let mut truncated_needed: usize = 0;
        for constructor_id in constructors {
            let constructor: &Constructor = &self.compiled.spec.constructors[constructor_id];
            let (result, needed): (Option<MatchResult>, usize) =
                self.isolated_match_pattern(&constructor.pattern, cursor, depth.saturating_add(1));
            truncated_needed = truncated_needed.max(needed);
            if let Some(result) = result {
                matches.push((constructor_id, result));
            }
        }
        let removed: Option<String> = self.table_stack.pop();
        drop(removed);
        if truncated_needed > self.bytes.len() {
            return None;
        }
        if let Some(selected_index) = self.compiled.select_match(&matches) {
            return matches
                .get(selected_index)
                .map(|(_, result)| result.clone());
        }
        let mut result: MatchResult = matches.first()?.1.clone();
        result.consumed = matches
            .iter()
            .map(|(_, candidate): &(usize, MatchResult)| candidate.consumed)
            .max()
            .unwrap_or(result.consumed);
        result.ambiguities.extend(
            matches
                .iter()
                .map(|(constructor_id, _): &(usize, MatchResult)| *constructor_id),
        );
        result.ambiguities.extend(matches.iter().flat_map(
            |(_, candidate): &(usize, MatchResult)| candidate.ambiguities.iter().copied(),
        ));
        Some(result)
    }
}

fn build_decision_nodes(
    candidates: &[usize],
    available: &BTreeSet<u16>,
    constraints: &BTreeMap<usize, BTreeMap<u16, bool>>,
    nodes: &mut Vec<DecisionNode>,
    depth: usize,
) -> usize {
    if candidates.len() <= 1 || available.is_empty() || depth >= 16 || nodes.len() >= 65_000 {
        let node_id: usize = nodes.len();
        nodes.push(DecisionNode::Resolve {
            candidates: candidates.to_vec().into_boxed_slice(),
        });
        return node_id;
    }
    let selected: Option<u16> = available
        .iter()
        .copied()
        .filter_map(|bit: u16| {
            let constrained: usize = candidates
                .iter()
                .filter(|candidate: &&usize| {
                    constraints
                        .get(candidate)
                        .is_some_and(|bits: &BTreeMap<u16, bool>| bits.contains_key(&bit))
                })
                .count();
            let zeros: usize = candidates
                .iter()
                .filter(|candidate: &&usize| {
                    constraints
                        .get(candidate)
                        .and_then(|bits: &BTreeMap<u16, bool>| bits.get(&bit))
                        == Some(&false)
                })
                .count();
            let ones: usize = candidates
                .iter()
                .filter(|candidate: &&usize| {
                    constraints
                        .get(candidate)
                        .and_then(|bits: &BTreeMap<u16, bool>| bits.get(&bit))
                        == Some(&true)
                })
                .count();
            (zeros > 0 && ones > 0).then_some((bit, constrained))
        })
        .max_by_key(|(bit, constrained): &(u16, usize)| (*constrained, u16::MAX - *bit))
        .map(|(bit, _): (u16, usize)| bit);
    let Some(bit) = selected else {
        let node_id: usize = nodes.len();
        nodes.push(DecisionNode::Resolve {
            candidates: candidates.to_vec().into_boxed_slice(),
        });
        return node_id;
    };
    let zero_candidates: Vec<usize> = candidates
        .iter()
        .copied()
        .filter(|candidate: &usize| {
            constraints
                .get(candidate)
                .and_then(|bits: &BTreeMap<u16, bool>| bits.get(&bit))
                .is_none_or(|value: &bool| !*value)
        })
        .collect();
    let one_candidates: Vec<usize> = candidates
        .iter()
        .copied()
        .filter(|candidate: &usize| {
            constraints
                .get(candidate)
                .and_then(|bits: &BTreeMap<u16, bool>| bits.get(&bit))
                .is_none_or(|value: &bool| *value)
        })
        .collect();
    let mut remaining: BTreeSet<u16> = available.clone();
    remaining.remove(&bit);
    let zero: usize = build_decision_nodes(
        &zero_candidates,
        &remaining,
        constraints,
        nodes,
        depth.saturating_add(1),
    );
    let one: usize = build_decision_nodes(
        &one_candidates,
        &remaining,
        constraints,
        nodes,
        depth.saturating_add(1),
    );
    let node_id: usize = nodes.len();
    nodes.push(DecisionNode::Test { bit, one, zero });
    node_id
}

fn fixed_bits(
    pattern: &PatternExpr,
    fields: &BTreeMap<String, CompiledField>,
    tables: &BTreeMap<String, Vec<usize>>,
    constructors: &[Constructor],
    visiting: &mut BTreeSet<String>,
    depth: usize,
) -> BTreeMap<u16, bool> {
    if depth >= MAX_EVALUATION_DEPTH {
        return BTreeMap::new();
    }
    match pattern {
        PatternExpr::Atom(PatternAtom::Compare {
            left,
            op: CompareOp::Equal,
            right: PatternValue::Integer(value),
        }) if *value >= 0 => fields.get(left).map_or_else(BTreeMap::new, |field| {
            let width: u8 = field
                .high_bit
                .saturating_sub(field.low_bit)
                .saturating_add(1);
            let raw: u64 = u64::try_from(*value).unwrap_or(0) & width_mask(width);
            (0..width)
                .map(|relative: u8| {
                    let logical_bit: u32 = u32::from(field.low_bit.saturating_add(relative));
                    let bit: u16 = decision_bit(field, logical_bit);
                    let value: bool = raw & (1_u64 << relative) != 0;
                    (bit, value)
                })
                .collect()
        }),
        PatternExpr::Atom(PatternAtom::Symbol(table)) if tables.contains_key(table) => {
            if !visiting.insert(table.clone()) {
                return BTreeMap::new();
            }
            let alternatives: Vec<BTreeMap<u16, bool>> = tables
                .get(table)
                .into_iter()
                .flatten()
                .map(|constructor_id: &usize| {
                    fixed_bits(
                        &constructors[*constructor_id].pattern,
                        fields,
                        tables,
                        constructors,
                        visiting,
                        depth.saturating_add(1),
                    )
                })
                .collect();
            visiting.remove(table);
            common_bits(&alternatives)
        }
        PatternExpr::True | PatternExpr::Atom(_) => BTreeMap::new(),
        PatternExpr::All(parts) => {
            let mut combined: BTreeMap<u16, bool> = BTreeMap::new();
            for part in parts {
                for (bit, value) in fixed_bits(
                    part,
                    fields,
                    tables,
                    constructors,
                    visiting,
                    depth.saturating_add(1),
                ) {
                    if combined
                        .get(&bit)
                        .is_none_or(|current: &bool| *current == value)
                    {
                        combined.insert(bit, value);
                    }
                }
            }
            combined
        }
        PatternExpr::Any(parts) => {
            let alternatives: Vec<BTreeMap<u16, bool>> = parts
                .iter()
                .map(|part: &PatternExpr| {
                    fixed_bits(
                        part,
                        fields,
                        tables,
                        constructors,
                        visiting,
                        depth.saturating_add(1),
                    )
                })
                .collect();
            common_bits(&alternatives)
        }
        PatternExpr::Next(left, _) => fixed_bits(
            left,
            fields,
            tables,
            constructors,
            visiting,
            depth.saturating_add(1),
        ),
    }
}

fn decision_bit(field: &CompiledField, logical_bit: u32) -> u16 {
    let stream_bit: u32 = match field.endian {
        Endian::Little => logical_bit,
        Endian::Big => {
            let byte_from_end: u32 = logical_bit / 8;
            let byte_index: u32 = field
                .token_bits
                .saturating_div(8)
                .saturating_sub(byte_from_end)
                .saturating_sub(1);
            byte_index.saturating_mul(8).saturating_add(logical_bit % 8)
        }
    };
    u16::try_from(stream_bit).unwrap_or(u16::MAX)
}

fn common_bits(alternatives: &[BTreeMap<u16, bool>]) -> BTreeMap<u16, bool> {
    let Some(first) = alternatives.first() else {
        return BTreeMap::new();
    };
    first
        .iter()
        .filter(|(bit, value): &(&u16, &bool)| {
            alternatives
                .iter()
                .all(|alternative: &BTreeMap<u16, bool>| alternative.get(bit) == Some(*value))
        })
        .map(|(bit, value): (&u16, &bool)| (*bit, *value))
        .collect()
}

fn read_token(bytes: &[u8], endian: Endian) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut value: u64 = 0;
    match endian {
        Endian::Little => {
            for (position, byte) in bytes.iter().enumerate() {
                let shift: u32 = u32::try_from(position.checked_mul(8)?).ok()?;
                value |= u64::from(*byte).checked_shl(shift)?;
            }
        }
        Endian::Big => {
            for byte in bytes {
                value = value.checked_shl(8)? | u64::from(*byte);
            }
        }
    }
    Some(value)
}

fn width_mask(width: u8) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        1_u64
            .checked_shl(u32::from(width))
            .unwrap_or(0)
            .saturating_sub(1)
    }
}

fn sign_extend(value: u64, width: u8) -> i64 {
    if width == 0 {
        return 0;
    }
    if width >= 64 {
        return i64::from_ne_bytes(value.to_ne_bytes());
    }
    let shift: u32 = u32::from(64_u8.saturating_sub(width));
    let shifted: u64 = value.checked_shl(shift).unwrap_or(0);
    i64::from_ne_bytes(shifted.to_ne_bytes()) >> shift
}
