use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use crate::SleighError;
use crate::syntax::{
    CompareOp, Constructor, Endian, PatternAtom, PatternExpr, PatternValue, SleighSpec, TokenDef,
};

const MAX_EVALUATION_DEPTH: usize = 128;
const MAX_PATTERN_CLAUSES: usize = 4_096;
const MAX_TABLE_CONSTRUCTORS: usize = 2_048;
const MAX_DECODE_CONSTRUCTOR_ATTEMPTS: usize = 65_536;
const MAX_TABLE_CLAUSE_MEMO_ENTRIES: usize = 262_144;
const MAX_FIXED_BITS_MEMO_ENTRIES: usize = 262_144;

type TableClauseKey = (String, usize, usize, BTreeSet<String>);
type FixedBitsKey = (String, usize, BTreeSet<String>);

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
    ResourceLimit { attempts: usize },
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
    budget: &'a mut EvaluationBudget,
    bytes: &'a [u8],
    compiled: &'a CompiledSpec,
    context: &'a ContextState,
    needed: usize,
    table_stack: Vec<String>,
}

#[derive(Debug)]
struct EvaluationBudget {
    exceeded: bool,
    remaining: usize,
}

impl EvaluationBudget {
    const fn new() -> Self {
        Self {
            exceeded: false,
            remaining: MAX_DECODE_CONSTRUCTOR_ATTEMPTS,
        }
    }

    const fn consume(&mut self) -> bool {
        if self.remaining == 0 {
            self.exceeded = true;
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[derive(Debug)]
struct ClauseCompiler<'a> {
    constructors: &'a [Constructor],
    contexts: &'a BTreeSet<String>,
    fields: &'a BTreeMap<String, CompiledField>,
    registers: &'a BTreeSet<String>,
    tables: &'a BTreeMap<String, Vec<usize>>,
    table_clauses: RefCell<BTreeMap<TableClauseKey, Option<Vec<PatternClause>>>>,
}

#[derive(Debug)]
struct FixedBitsResolver<'a> {
    constructors: &'a [Constructor],
    fields: &'a BTreeMap<String, CompiledField>,
    memo: BTreeMap<FixedBitsKey, BTreeMap<u16, bool>>,
    tables: &'a BTreeMap<String, Vec<usize>>,
}

enum ComparisonCompilation {
    Exact(BTreeSet<PatternConstraint>),
    Impossible,
    Unavailable,
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
    if let Some((table, constructors)) =
        tables
            .iter()
            .find(|(_, constructors): &(&String, &Vec<usize>)| {
                constructors.len() > MAX_TABLE_CONSTRUCTORS
            })
    {
        return Err(SleighError::Parse {
            message: format!(
                "Sleigh table {table} constructor count {} exceeds {MAX_TABLE_CONSTRUCTORS}",
                constructors.len()
            ),
            offset: 0,
        });
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
    let clause_compiler: ClauseCompiler<'_> = ClauseCompiler {
        constructors: &spec.constructors,
        contexts: &contexts,
        fields: &fields,
        registers: &registers,
        tables: &tables,
        table_clauses: RefCell::new(BTreeMap::new()),
    };
    let mut pattern_clauses: Vec<Option<Vec<PatternClause>>> =
        Vec::with_capacity(spec.constructors.len());
    for constructor in &spec.constructors {
        let clauses: Option<Vec<PatternClause>> =
            clause_compiler.compile(&constructor.pattern, 0, 0)?;
        pattern_clauses.push(clauses);
    }
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
    let mut resolver: FixedBitsResolver<'_> = FixedBitsResolver {
        constructors: &spec.constructors,
        fields: &fields,
        memo: BTreeMap::new(),
        tables: &tables,
    };
    let mut constraints: BTreeMap<usize, BTreeMap<u16, bool>> = BTreeMap::new();
    for constructor_id in &roots {
        let mut visiting: BTreeSet<String> = BTreeSet::new();
        let bits: BTreeMap<u16, bool> = resolver.fixed_bits(
            &spec.constructors[*constructor_id].pattern,
            &mut visiting,
            0,
        );
        constraints.insert(*constructor_id, bits);
    }
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

impl ClauseCompiler<'_> {
    fn compile(
        &self,
        pattern: &PatternExpr,
        position: usize,
        structural_depth: usize,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        let mut visiting: BTreeSet<String> = BTreeSet::new();
        self.compile_inner(pattern, position, structural_depth, 0, &mut visiting)
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
        structural_depth: usize,
        expanded_depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        if structural_depth >= MAX_EVALUATION_DEPTH {
            return Err(SleighError::Parse {
                message: "pattern nesting limit exceeded".to_owned(),
                offset: 0,
            });
        }
        if expanded_depth >= MAX_EVALUATION_DEPTH {
            return Ok(None);
        }
        match pattern {
            PatternExpr::All(parts) => self.compile_all(
                parts,
                position,
                structural_depth.saturating_add(1),
                expanded_depth,
                visiting,
            ),
            PatternExpr::Any(parts) => self.compile_any(
                parts,
                position,
                structural_depth.saturating_add(1),
                expanded_depth,
                visiting,
            ),
            PatternExpr::Atom(atom) => self.compile_atom(atom, position, expanded_depth, visiting),
            PatternExpr::Next(left, right) => self.compile_next(
                left,
                right,
                position,
                structural_depth.saturating_add(1),
                expanded_depth,
                visiting,
            ),
            PatternExpr::True => Ok(Some(vec![PatternClause {
                constraints: BTreeSet::new(),
                span: 0,
            }])),
        }
    }

    fn compile_all(
        &self,
        parts: &[PatternExpr],
        position: usize,
        structural_depth: usize,
        expanded_depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        let mut combined: Option<Vec<PatternClause>> = Some(vec![PatternClause {
            constraints: BTreeSet::new(),
            span: 0,
        }]);
        for part in parts {
            let additions: Option<Vec<PatternClause>> =
                self.compile_inner(part, position, structural_depth, expanded_depth, visiting)?;
            let Some(additions) = additions else {
                combined = None;
                continue;
            };
            let Some(current) = combined.take() else {
                continue;
            };
            let Some(product) = current.len().checked_mul(additions.len()) else {
                continue;
            };
            if product > MAX_PATTERN_CLAUSES {
                continue;
            }
            let mut next: Vec<PatternClause> = Vec::with_capacity(product);
            for current_clause in &current {
                for addition in &additions {
                    let mut constraints: BTreeSet<PatternConstraint> =
                        current_clause.constraints.clone();
                    constraints.extend(addition.constraints.iter().cloned());
                    next.push(PatternClause {
                        constraints,
                        span: current_clause.span.max(addition.span),
                    });
                }
            }
            combined = Some(deduplicate_pattern_clauses(next));
        }
        Ok(combined)
    }

    fn compile_any(
        &self,
        parts: &[PatternExpr],
        position: usize,
        structural_depth: usize,
        expanded_depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        let mut clauses: Vec<PatternClause> = Vec::new();
        let mut unavailable: bool = false;
        for part in parts {
            let additions: Option<Vec<PatternClause>> =
                self.compile_inner(part, position, structural_depth, expanded_depth, visiting)?;
            let Some(additions) = additions else {
                unavailable = true;
                continue;
            };
            if unavailable {
                continue;
            }
            let Some(total) = clauses.len().checked_add(additions.len()) else {
                unavailable = true;
                continue;
            };
            if total > MAX_PATTERN_CLAUSES {
                unavailable = true;
                continue;
            }
            clauses.extend(additions);
        }
        if unavailable {
            Ok(None)
        } else {
            Ok(Some(deduplicate_pattern_clauses(clauses)))
        }
    }

    fn compile_next(
        &self,
        left: &PatternExpr,
        right: &PatternExpr,
        position: usize,
        structural_depth: usize,
        expanded_depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        let left_clauses: Option<Vec<PatternClause>> =
            self.compile_inner(left, position, structural_depth, expanded_depth, visiting)?;
        let Some(left_clauses) = left_clauses else {
            self.compile_inner(right, position, structural_depth, expanded_depth, visiting)?;
            return Ok(None);
        };
        if left_clauses.is_empty() {
            self.compile_inner(right, position, structural_depth, expanded_depth, visiting)?;
            return Ok(Some(Vec::new()));
        }
        let mut clauses: Vec<PatternClause> = Vec::new();
        let mut unavailable: bool = false;
        for left_clause in left_clauses {
            let Some(right_position) = position.checked_add(left_clause.span) else {
                unavailable = true;
                continue;
            };
            let right_clauses: Option<Vec<PatternClause>> = self.compile_inner(
                right,
                right_position,
                structural_depth,
                expanded_depth,
                visiting,
            )?;
            let Some(right_clauses) = right_clauses else {
                unavailable = true;
                continue;
            };
            if unavailable {
                continue;
            }
            let Some(total) = clauses.len().checked_add(right_clauses.len()) else {
                unavailable = true;
                continue;
            };
            if total > MAX_PATTERN_CLAUSES {
                unavailable = true;
                continue;
            }
            for right_clause in right_clauses {
                let mut constraints: BTreeSet<PatternConstraint> = left_clause.constraints.clone();
                constraints.extend(right_clause.constraints);
                let Some(span) = left_clause.span.checked_add(right_clause.span) else {
                    unavailable = true;
                    break;
                };
                clauses.push(PatternClause { constraints, span });
            }
        }
        if unavailable {
            Ok(None)
        } else {
            Ok(Some(deduplicate_pattern_clauses(clauses)))
        }
    }

    fn compile_atom(
        &self,
        atom: &PatternAtom,
        position: usize,
        expanded_depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        match atom {
            PatternAtom::Compare { left, op, right } => {
                let left_span: usize = self.required_value_span(left)?;
                let right_span: usize = self.required_pattern_value_span(right)?;
                let constraints: ComparisonCompilation =
                    self.comparison_constraints(left, *op, right, position);
                match constraints {
                    ComparisonCompilation::Exact(constraints) => Ok(Some(vec![PatternClause {
                        constraints,
                        span: left_span.max(right_span),
                    }])),
                    ComparisonCompilation::Impossible => Ok(Some(Vec::new())),
                    ComparisonCompilation::Unavailable => Ok(None),
                }
            }
            PatternAtom::Symbol(name) if self.tables.contains_key(name) => {
                self.compile_table(name, position, expanded_depth, visiting)
            }
            PatternAtom::Symbol(name) => {
                let span: usize = self.required_symbol_span(name)?;
                Ok(Some(vec![PatternClause {
                    constraints: BTreeSet::new(),
                    span,
                }]))
            }
            PatternAtom::Residual(text) => Err(SleighError::Parse {
                message: format!("unsupported pattern expression {text}"),
                offset: 0,
            }),
        }
    }

    fn comparison_constraints(
        &self,
        left: &str,
        op: CompareOp,
        right: &PatternValue,
        position: usize,
    ) -> ComparisonCompilation {
        if op == CompareOp::Equal
            && let PatternValue::Integer(value) = right
            && let Some(field) = self.fields.get(left)
        {
            let Some(span) = field.high_bit.checked_sub(field.low_bit) else {
                return ComparisonCompilation::Unavailable;
            };
            let Some(width) = span.checked_add(1) else {
                return ComparisonCompilation::Unavailable;
            };
            let raw: u64 = if field.signed {
                let Some(limit) = 1_i128.checked_shl(u32::from(width.saturating_sub(1))) else {
                    return ComparisonCompilation::Unavailable;
                };
                let minimum: i128 = -limit;
                let maximum: i128 = -minimum - 1;
                let value_i128: i128 = i128::from(*value);
                if value_i128 < minimum || value_i128 > maximum {
                    return ComparisonCompilation::Impossible;
                }
                u64::from_ne_bytes(value.to_ne_bytes()) & width_mask(width)
            } else {
                let Ok(raw) = u64::try_from(*value) else {
                    return ComparisonCompilation::Impossible;
                };
                if raw > width_mask(width) {
                    return ComparisonCompilation::Impossible;
                }
                raw
            };
            let Some(position_bits) = position.checked_mul(8) else {
                return ComparisonCompilation::Unavailable;
            };
            let mut constraints: BTreeSet<PatternConstraint> = BTreeSet::new();
            for relative in 0..width {
                let Some(logical_bit) = field.low_bit.checked_add(relative) else {
                    return ComparisonCompilation::Unavailable;
                };
                let logical_bit: u32 = u32::from(logical_bit);
                let stream_bit: usize = usize::from(decision_bit(field, logical_bit));
                let Some(bit) = position_bits.checked_add(stream_bit) else {
                    return ComparisonCompilation::Unavailable;
                };
                let Some(mask) = 1_u64.checked_shl(u32::from(relative)) else {
                    return ComparisonCompilation::Unavailable;
                };
                let value: bool = raw & mask != 0;
                constraints.insert(PatternConstraint::Bit { bit, value });
            }
            return ComparisonCompilation::Exact(constraints);
        }
        ComparisonCompilation::Exact(BTreeSet::from([PatternConstraint::Compare {
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
        expanded_depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        if !visiting.insert(name.to_owned()) {
            return Ok(None);
        }
        let key: TableClauseKey = (
            name.to_owned(),
            position,
            expanded_depth,
            visiting.iter().cloned().collect(),
        );
        if let Some(cached) = self.table_clauses.borrow().get(&key) {
            visiting.remove(name);
            return Ok(cached.clone());
        }
        let result: Result<Option<Vec<PatternClause>>, SleighError> =
            self.compile_table_contents(name, position, expanded_depth, visiting);
        visiting.remove(name);
        if let Ok(value) = &result {
            let mut memo: std::cell::RefMut<
                '_,
                BTreeMap<TableClauseKey, Option<Vec<PatternClause>>>,
            > = self.table_clauses.borrow_mut();
            if memo.len() < MAX_TABLE_CLAUSE_MEMO_ENTRIES {
                memo.insert(key, value.clone());
            }
        }
        result
    }

    fn compile_table_contents(
        &self,
        name: &str,
        position: usize,
        expanded_depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<Vec<PatternClause>>, SleighError> {
        let Some(constructor_ids) = self.tables.get(name) else {
            return Ok(None);
        };
        let mut clauses: Vec<PatternClause> = Vec::new();
        let mut unavailable: bool = false;
        for constructor_id in constructor_ids {
            let Some(constructor) = self.constructors.get(*constructor_id) else {
                unavailable = true;
                continue;
            };
            let additions: Option<Vec<PatternClause>> = self.compile_inner(
                &constructor.pattern,
                position,
                0,
                expanded_depth.saturating_add(1),
                visiting,
            )?;
            let Some(additions) = additions else {
                unavailable = true;
                continue;
            };
            if unavailable {
                continue;
            }
            let Some(total) = clauses.len().checked_add(additions.len()) else {
                unavailable = true;
                continue;
            };
            if total > MAX_PATTERN_CLAUSES {
                unavailable = true;
                continue;
            }
            clauses.extend(additions);
        }
        if unavailable {
            Ok(None)
        } else {
            Ok(Some(deduplicate_pattern_clauses(clauses)))
        }
    }

    fn symbol_span(&self, name: &str) -> Option<usize> {
        self.fields.get(name).map_or_else(
            || (self.contexts.contains(name) || self.registers.contains(name)).then_some(0),
            |field: &CompiledField| usize::try_from(field.token_bits / 8).ok(),
        )
    }

    fn required_symbol_span(&self, name: &str) -> Result<usize, SleighError> {
        self.symbol_span(name).ok_or_else(|| SleighError::Parse {
            message: format!("undefined pattern symbol {name}"),
            offset: 0,
        })
    }

    fn required_value_span(&self, name: &str) -> Result<usize, SleighError> {
        self.fields.get(name).map_or_else(
            || {
                self.contexts
                    .contains(name)
                    .then_some(0)
                    .ok_or_else(|| SleighError::Parse {
                        message: format!("undefined pattern value {name}"),
                        offset: 0,
                    })
            },
            |field: &CompiledField| {
                usize::try_from(field.token_bits / 8).map_err(|_| SleighError::Parse {
                    message: format!("unsupported pattern value span {name}"),
                    offset: 0,
                })
            },
        )
    }

    fn required_pattern_value_span(&self, value: &PatternValue) -> Result<usize, SleighError> {
        match value {
            PatternValue::Add { identifier, .. } | PatternValue::Identifier(identifier) => {
                self.required_value_span(identifier)
            }
            PatternValue::Integer(_) => Ok(0),
        }
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
        self.decode_internal(bytes, address, context, false)
    }

    pub(crate) fn decode_complete(
        &self,
        bytes: &[u8],
        address: u64,
        context: &ContextState,
    ) -> DecodeOutcome {
        self.decode_internal(bytes, address, context, true)
    }

    fn decode_internal(
        &self,
        bytes: &[u8],
        address: u64,
        context: &ContextState,
        complete_before_truncated: bool,
    ) -> DecodeOutcome {
        let mut candidates: Vec<usize> = self.decision_candidates(bytes).map_or_else(
            || self.tables.get("instruction").cloned().unwrap_or_default(),
            <[usize]>::to_vec,
        );
        if self.spec.tokens.len() > 1 {
            let mut merged: BTreeSet<usize> = candidates.into_iter().collect();
            merged.extend(
                self.tables
                    .get("instruction")
                    .into_iter()
                    .flatten()
                    .copied(),
            );
            candidates = merged.into_iter().collect();
        }
        let mut matches: Vec<(usize, MatchResult)> = Vec::new();
        let mut truncated_needed: Option<usize> = None;
        let mut budget: EvaluationBudget = EvaluationBudget::new();
        for constructor_id in candidates {
            if !budget.consume() {
                break;
            }
            let mut evaluator: Evaluator<'_> = Evaluator {
                budget: &mut budget,
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
        if budget.exceeded {
            return DecodeOutcome::ResourceLimit {
                attempts: MAX_DECODE_CONSTRUCTOR_ATTEMPTS,
            };
        }
        if !complete_before_truncated && let Some(needed) = truncated_needed {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
                needed,
            };
        }
        if matches.is_empty() {
            if let Some(needed) = truncated_needed {
                return DecodeOutcome::Truncated {
                    available: bytes.len(),
                    needed,
                };
            }
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
    if general.is_empty() {
        return special.is_empty();
    }
    special.iter().all(|special_clause: &PatternClause| {
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
            if !self.budget.consume() {
                break;
            }
            let constructor: &Constructor = &self.compiled.spec.constructors[constructor_id];
            let (result, needed): (Option<MatchResult>, usize) =
                self.isolated_match_pattern(&constructor.pattern, cursor, depth.saturating_add(1));
            truncated_needed = truncated_needed.max(needed);
            if let Some(result) = result {
                matches.push((constructor_id, result));
            }
        }
        if self.budget.exceeded {
            let removed: Option<String> = self.table_stack.pop();
            drop(removed);
            return None;
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

impl<'a> FixedBitsResolver<'a> {
    fn fixed_bits(
        &mut self,
        pattern: &PatternExpr,
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
            }) if *value >= 0 => self.compared_field_bits(left, *value),
            PatternExpr::Atom(PatternAtom::Symbol(table)) if self.tables.contains_key(table) => {
                self.table_bits(table, visiting, depth)
            }
            PatternExpr::True | PatternExpr::Atom(_) => BTreeMap::new(),
            PatternExpr::All(parts) => {
                let mut combined: BTreeMap<u16, bool> = BTreeMap::new();
                for part in parts {
                    for (bit, value) in self.fixed_bits(part, visiting, depth.saturating_add(1)) {
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
                let mut alternatives: Vec<BTreeMap<u16, bool>> = Vec::with_capacity(parts.len());
                for part in parts {
                    alternatives.push(self.fixed_bits(part, visiting, depth.saturating_add(1)));
                }
                common_bits(&alternatives)
            }
            PatternExpr::Next(left, _) => self.fixed_bits(left, visiting, depth.saturating_add(1)),
        }
    }

    fn compared_field_bits(&self, left: &str, value: i64) -> BTreeMap<u16, bool> {
        self.fields
            .get(left)
            .map_or_else(BTreeMap::new, |field: &CompiledField| {
                let width: u8 = field
                    .high_bit
                    .saturating_sub(field.low_bit)
                    .saturating_add(1);
                let raw: u64 = u64::try_from(value).unwrap_or(0) & width_mask(width);
                (0..width)
                    .map(|relative: u8| {
                        let logical_bit: u32 = u32::from(field.low_bit.saturating_add(relative));
                        let bit: u16 = decision_bit(field, logical_bit);
                        let set: bool = raw & (1_u64 << relative) != 0;
                        (bit, set)
                    })
                    .collect()
            })
    }

    fn table_bits(
        &mut self,
        table: &str,
        visiting: &mut BTreeSet<String>,
        depth: usize,
    ) -> BTreeMap<u16, bool> {
        if !visiting.insert(table.to_owned()) {
            return BTreeMap::new();
        }
        let key: FixedBitsKey = (table.to_owned(), depth, visiting.iter().cloned().collect());
        if let Some(cached) = self.memo.get(&key) {
            let bits: BTreeMap<u16, bool> = cached.clone();
            visiting.remove(table);
            return bits;
        }
        let constructors: &'a [Constructor] = self.constructors;
        let constructor_ids: &'a [usize] = self
            .tables
            .get(table)
            .map_or(&[], |ids: &'a Vec<usize>| ids.as_slice());
        let mut alternatives: Vec<BTreeMap<u16, bool>> = Vec::with_capacity(constructor_ids.len());
        for constructor_id in constructor_ids {
            let Some(constructor) = constructors.get(*constructor_id) else {
                continue;
            };
            alternatives.push(self.fixed_bits(
                &constructor.pattern,
                visiting,
                depth.saturating_add(1),
            ));
        }
        visiting.remove(table);
        let bits: BTreeMap<u16, bool> = common_bits(&alternatives);
        if self.memo.len() < MAX_FIXED_BITS_MEMO_ENTRIES {
            self.memo.insert(key, bits.clone());
        }
        bits
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
