use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::fmt::{Display, Formatter, Write as _};
use std::str::FromStr;
use std::sync::Arc;

use serde::Serialize;

use crate::model::{
    CallGraph, CallGraphEdge, CallGraphNode, Function, InsnClass, Module, SymbolKind,
    function_identity_hash,
};
use crate::query::XrefMatch;

const FUNCTION_ID_PREFIX: &str = "fn1";
const ARC_ALLOCATION_OVERHEAD: usize = std::mem::size_of::<usize>() * 2;
const ANALYSIS_WORK_RECORD_BYTES: usize = 128;

const fn arc_str_retained_bytes(value: &str) -> usize {
    ARC_ALLOCATION_OVERHEAD.saturating_add(value.len())
}

const fn arc_value_retained_bytes<T>() -> usize {
    ARC_ALLOCATION_OVERHEAD.saturating_add(std::mem::size_of::<T>())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct FunctionId {
    source_hash: [u8; 32],
    address: u64,
    discriminator: [u8; 16],
}

impl FunctionId {
    pub const MAX_ENCODED_LEN: usize = 118;

    #[must_use]
    pub const fn new(source_hash: [u8; 32], address: u64) -> Self {
        Self {
            source_hash,
            address,
            discriminator: [0u8; 16],
        }
    }

    #[must_use]
    const fn with_discriminator(
        source_hash: [u8; 32],
        address: u64,
        discriminator: [u8; 16],
    ) -> Self {
        Self {
            source_hash,
            address,
            discriminator,
        }
    }

    #[must_use]
    pub const fn source_hash(self) -> [u8; 32] {
        self.source_hash
    }

    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }

    #[must_use]
    pub const fn discriminator(self) -> [u8; 16] {
        self.discriminator
    }
}

impl Display for FunctionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(FUNCTION_ID_PREFIX)?;
        formatter.write_char(':')?;
        for byte in self.source_hash {
            write!(formatter, "{byte:02x}")?;
        }
        write!(formatter, ":{:016x}", self.address)?;
        if self.discriminator != [0u8; 16] {
            formatter.write_char(':')?;
            for byte in self.discriminator {
                write!(formatter, "{byte:02x}")?;
            }
        }
        Ok(())
    }
}

impl FromStr for FunctionId {
    type Err = FunctionIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts: std::str::Split<'_, char> = value.split(':');
        let prefix: Option<&str> = parts.next();
        let hash_text: Option<&str> = parts.next();
        let address_text: Option<&str> = parts.next();
        let discriminator_text: Option<&str> = parts.next();
        if prefix != Some(FUNCTION_ID_PREFIX) || parts.next().is_some() {
            return Err(FunctionIdParseError);
        }
        let source_hash: [u8; 32] = hash_text
            .and_then(decode_hash)
            .ok_or(FunctionIdParseError)?;
        let address: u64 = address_text
            .filter(|text: &&str| text.len() == 16)
            .and_then(|text: &str| u64::from_str_radix(text, 16).ok())
            .ok_or(FunctionIdParseError)?;
        let discriminator: [u8; 16] = discriminator_text.map_or(Ok([0u8; 16]), |text: &str| {
            decode_discriminator(text).ok_or(FunctionIdParseError)
        })?;
        Ok(Self::with_discriminator(
            source_hash,
            address,
            discriminator,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("function id must match fn1:<64 hex digits>:<16 hex digits>[:<32 nonzero hex digits>]")]
pub struct FunctionIdParseError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FunctionLookupError {
    #[error("function id belongs to a different source")]
    SourceMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("no function starts at address {address:#x}")]
    NotFound { address: u64 },
    #[error("more than one function starts at address {address:#x}")]
    Ambiguous { address: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionIdentity {
    pub id: FunctionId,
    pub name: Arc<str>,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CallOutcome {
    FunctionStart {
        function_id: FunctionId,
        name: Arc<str>,
        address: u64,
    },
    FunctionInterior {
        function_id: FunctionId,
        name: Arc<str>,
        function_address: u64,
        target_address: u64,
    },
    AmbiguousFunction {
        target_address: u64,
        candidates: Vec<FunctionIdentity>,
    },
    Symbol {
        name: Arc<str>,
        address: u64,
        symbol_kind: SymbolKind,
    },
    Unresolved {
        address: u64,
    },
    Indirect,
}

impl CallOutcome {
    #[must_use]
    pub const fn target_address(&self) -> Option<u64> {
        match self {
            Self::FunctionStart { address, .. }
            | Self::Symbol { address, .. }
            | Self::Unresolved { address } => Some(*address),
            Self::FunctionInterior { target_address, .. }
            | Self::AmbiguousFunction { target_address, .. } => Some(*target_address),
            Self::Indirect => None,
        }
    }

    #[must_use]
    pub const fn resolved_function_id(&self) -> Option<FunctionId> {
        match self {
            Self::FunctionStart { function_id, .. }
            | Self::FunctionInterior { function_id, .. } => Some(*function_id),
            Self::AmbiguousFunction { .. }
            | Self::Symbol { .. }
            | Self::Unresolved { .. }
            | Self::Indirect => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NavigationCall {
    pub caller_id: FunctionId,
    pub caller_name: Arc<str>,
    pub caller_address: u64,
    pub call_site: u64,
    pub outcome: Arc<CallOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NavigationXref {
    pub from_function_id: FunctionId,
    pub from_function_name: Arc<str>,
    pub from_offset: u64,
    pub mnemonic: Arc<str>,
    pub to_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionSummary {
    pub id: FunctionId,
    pub name: Arc<str>,
    pub address: u64,
    pub end: u64,
    pub is_export: bool,
    pub instruction_count: usize,
    pub basic_block_count: usize,
    pub cyclomatic_complexity: u32,
    pub incoming_calls: usize,
    pub outgoing_calls: usize,
    pub indirect_calls: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NeighborhoodDirection {
    Callers,
    Callees,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborhoodLimits {
    pub max_nodes: usize,
    pub max_calls: usize,
    pub analysis: NavigationLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NavigationLimits {
    pub functions: usize,
    pub instructions: usize,
    pub calls: usize,
    pub candidate_records: usize,
    pub retained_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NavigationLimitError {
    #[error("navigation function count {actual} exceeds limit {limit}")]
    Functions { actual: usize, limit: usize },
    #[error("navigation call count exceeds limit {limit}")]
    Calls { limit: usize },
    #[error("navigation instruction count exceeds limit {limit}")]
    Instructions { limit: usize },
    #[error("navigation candidate work exceeds limit {limit}")]
    CandidateRecords { limit: usize },
    #[error("navigation analysis working set exceeds {limit} retained bytes")]
    RetainedBytes { limit: usize },
    #[error("cross-reference count exceeds limit {limit}")]
    Xrefs { limit: usize },
    #[error("neighborhood entry count {actual} exceeds node limit {limit}")]
    NeighborhoodNodes { actual: usize, limit: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NavigationQueryError {
    #[error(transparent)]
    Lookup(#[from] FunctionLookupError),
    #[error(transparent)]
    Limit(#[from] NavigationLimitError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationAnalysis {
    functions: Vec<FunctionSummary>,
    calls: Vec<NavigationCall>,
    working_set_bytes: usize,
}

impl NavigationAnalysis {
    #[must_use]
    pub fn functions(&self) -> &[FunctionSummary] {
        &self.functions
    }

    #[must_use]
    pub fn calls(&self) -> &[NavigationCall] {
        &self.calls
    }

    #[must_use]
    pub const fn working_set_bytes(&self) -> usize {
        self.working_set_bytes
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<FunctionSummary>, Vec<NavigationCall>) {
        (self.functions, self.calls)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NavigationProgress {
    Functions(usize),
    Instructions(usize),
    Calls(usize),
    CandidateRecords(usize),
    RetainedBytes(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NeighborhoodNode {
    pub function: FunctionSummary,
    pub depth: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Neighborhood {
    pub nodes: Vec<NeighborhoodNode>,
    pub calls: Vec<NavigationCall>,
    pub truncated: bool,
}

impl Module {
    #[must_use]
    pub fn call_graph(&self) -> CallGraph {
        let analysis: NavigationAnalysis =
            match self.build_navigation_analysis(|_: NavigationProgress| {
                Ok::<(), std::convert::Infallible>(())
            }) {
                Ok(value) => value,
                Err(error) => match error {},
            };
        let nodes: Vec<CallGraphNode> = analysis
            .functions()
            .iter()
            .map(|function: &FunctionSummary| CallGraphNode {
                name: function.name.to_string(),
                address: function.address,
                is_export: function.is_export,
            })
            .collect();
        let mut edges: Vec<CallGraphEdge> = analysis
            .calls()
            .iter()
            .filter_map(|call: &NavigationCall| {
                let target: u64 = call.outcome.target_address()?;
                let callee: String = match call.outcome.as_ref() {
                    CallOutcome::FunctionStart { name, .. } | CallOutcome::Symbol { name, .. } => {
                        name.to_string()
                    }
                    _ => format!("sub_{target:x}"),
                };
                Some(CallGraphEdge {
                    caller: call.caller_name.to_string(),
                    caller_address: call.caller_id.address(),
                    call_site: call.call_site,
                    callee,
                    callee_address: target,
                })
            })
            .collect();
        edges.sort_by(|left: &CallGraphEdge, right: &CallGraphEdge| {
            left.call_site
                .cmp(&right.call_site)
                .then(left.callee_address.cmp(&right.callee_address))
        });
        CallGraph { nodes, edges }
    }

    #[must_use]
    pub fn function_id(&self, function: &Function) -> FunctionId {
        let duplicate_address: bool = self
            .functions()
            .iter()
            .filter(|candidate: &&Function| candidate.address == function.address)
            .take(2)
            .count()
            > 1;
        let discriminator: [u8; 16] = if duplicate_address {
            function_identity_hash(function)
        } else {
            [0u8; 16]
        };
        FunctionId::with_discriminator(self.source_hash, function.address, discriminator)
    }

    pub fn function_by_id(&self, id: &FunctionId) -> Result<&Function, FunctionLookupError> {
        if id.source_hash != self.source_hash {
            return Err(FunctionLookupError::SourceMismatch {
                expected: self.source_hash,
                actual: id.source_hash,
            });
        }
        let mut found: Option<&Function> = None;
        for function in self.functions() {
            if function.address != id.address {
                continue;
            }
            if id.discriminator != [0u8; 16] && function_identity_hash(function) == id.discriminator
            {
                return Ok(function);
            }
            if id.discriminator == [0u8; 16] {
                if found.is_some() {
                    return Err(FunctionLookupError::Ambiguous {
                        address: id.address,
                    });
                }
                found = Some(function);
            }
        }
        found.ok_or(FunctionLookupError::NotFound {
            address: id.address,
        })
    }

    pub fn navigation_calls(
        &self,
        limits: NavigationLimits,
    ) -> Result<Vec<NavigationCall>, NavigationLimitError> {
        let (_, calls): (Vec<FunctionSummary>, Vec<NavigationCall>) =
            self.navigation_analysis(limits)?.into_parts();
        Ok(calls)
    }

    pub fn function_summaries(
        &self,
        limits: NavigationLimits,
    ) -> Result<Vec<FunctionSummary>, NavigationLimitError> {
        let (functions, _): (Vec<FunctionSummary>, Vec<NavigationCall>) =
            self.navigation_analysis(limits)?.into_parts();
        Ok(functions)
    }

    pub fn navigation_analysis(
        &self,
        limits: NavigationLimits,
    ) -> Result<NavigationAnalysis, NavigationLimitError> {
        self.build_navigation_analysis(|progress: NavigationProgress| match progress {
            NavigationProgress::Functions(actual) if actual > limits.functions => {
                Err(NavigationLimitError::Functions {
                    actual,
                    limit: limits.functions,
                })
            }
            NavigationProgress::Instructions(actual) if actual > limits.instructions => {
                Err(NavigationLimitError::Instructions {
                    limit: limits.instructions,
                })
            }
            NavigationProgress::Calls(actual) if actual > limits.calls => {
                Err(NavigationLimitError::Calls {
                    limit: limits.calls,
                })
            }
            NavigationProgress::CandidateRecords(actual) if actual > limits.candidate_records => {
                Err(NavigationLimitError::CandidateRecords {
                    limit: limits.candidate_records,
                })
            }
            NavigationProgress::RetainedBytes(actual) if actual > limits.retained_bytes => {
                Err(NavigationLimitError::RetainedBytes {
                    limit: limits.retained_bytes,
                })
            }
            NavigationProgress::Functions(_)
            | NavigationProgress::Instructions(_)
            | NavigationProgress::Calls(_)
            | NavigationProgress::CandidateRecords(_)
            | NavigationProgress::RetainedBytes(_) => Ok(()),
        })
    }

    pub fn function_summary(
        &self,
        id: &FunctionId,
        limits: NavigationLimits,
    ) -> Result<FunctionSummary, NavigationQueryError> {
        let function: &Function = self.function_by_id(id)?;
        let analysis: NavigationAnalysis = self.navigation_analysis(limits)?;
        let (summaries, _): (Vec<FunctionSummary>, Vec<NavigationCall>) = analysis.into_parts();
        summaries
            .into_iter()
            .find(|summary: &FunctionSummary| summary.id == *id)
            .ok_or(FunctionLookupError::NotFound {
                address: function.address,
            })
            .map_err(Into::into)
    }

    pub fn bounded_xrefs_to_function(
        &self,
        id: &FunctionId,
        limit: usize,
    ) -> Result<Vec<XrefMatch>, NavigationQueryError> {
        let function: &Function = self.function_by_id(id)?;
        crate::eval::bounded_xrefs_to_address(self, function.address, &function.name, limit)
            .map_err(|limit: usize| NavigationLimitError::Xrefs { limit }.into())
    }

    pub fn bounded_navigation_xrefs_to_function(
        &self,
        id: &FunctionId,
        limit: usize,
        retained_byte_limit: usize,
    ) -> Result<Vec<NavigationXref>, NavigationQueryError> {
        let function: &Function = self.function_by_id(id)?;
        let mut xrefs: Vec<NavigationXref> = Vec::new();
        let mut retained_bytes: usize = 0;
        let mut caller: Option<(FunctionId, Arc<str>)> = None;
        let mut failure: Option<NavigationLimitError> = None;
        let _: bool = crate::eval::for_each_xref_to_address(
            self,
            function.address,
            |source: &Function, instruction: &crate::model::InsnView| {
                if xrefs.len() >= limit {
                    failure = Some(NavigationLimitError::Xrefs { limit });
                    return false;
                }
                let source_id: FunctionId = self.function_id(source);
                let needs_caller: bool = caller.as_ref().is_none_or(
                    |(current_id, current_name): &(FunctionId, Arc<str>)| {
                        *current_id != source_id || current_name.as_ref() != source.name
                    },
                );
                let caller_bytes: usize = if needs_caller {
                    arc_str_retained_bytes(&source.name)
                } else {
                    0
                };
                let record_bytes: usize = std::mem::size_of::<NavigationXref>()
                    .saturating_mul(2)
                    .saturating_add(caller_bytes)
                    .saturating_add(arc_str_retained_bytes(&instruction.mnemonic));
                let next_retained_bytes: usize = retained_bytes.saturating_add(record_bytes);
                if next_retained_bytes > retained_byte_limit {
                    failure = Some(NavigationLimitError::RetainedBytes {
                        limit: retained_byte_limit,
                    });
                    return false;
                }
                if needs_caller {
                    caller = Some((source_id, Arc::from(source.name.as_str())));
                }
                let Some((from_function_id, from_function_name)) = caller.as_ref() else {
                    failure = Some(NavigationLimitError::RetainedBytes {
                        limit: retained_byte_limit,
                    });
                    return false;
                };
                retained_bytes = next_retained_bytes;
                xrefs.push(NavigationXref {
                    from_function_id: *from_function_id,
                    from_function_name: Arc::clone(from_function_name),
                    from_offset: instruction.offset,
                    mnemonic: Arc::from(instruction.mnemonic.as_str()),
                    to_address: function.address,
                });
                true
            },
        );
        if let Some(error) = failure {
            return Err(error.into());
        }
        xrefs.sort_by(|left: &NavigationXref, right: &NavigationXref| {
            left.from_offset
                .cmp(&right.from_offset)
                .then(left.from_function_id.cmp(&right.from_function_id))
                .then(left.mnemonic.cmp(&right.mnemonic))
        });
        Ok(xrefs)
    }

    pub fn neighborhood(
        &self,
        entries: &[FunctionId],
        max_depth: u8,
        direction: NeighborhoodDirection,
        limits: NeighborhoodLimits,
    ) -> Result<Neighborhood, NavigationQueryError> {
        let sorted_entries: Vec<FunctionId> =
            self.validate_neighborhood_entries(entries, limits)?;
        let analysis: NavigationAnalysis = self.navigation_analysis(limits.analysis)?;
        Self::neighborhood_from_validated_entries(
            &analysis,
            &sorted_entries,
            max_depth,
            direction,
            limits,
        )
    }

    pub fn neighborhood_from_analysis(
        &self,
        analysis: &NavigationAnalysis,
        entries: &[FunctionId],
        max_depth: u8,
        direction: NeighborhoodDirection,
        limits: NeighborhoodLimits,
    ) -> Result<Neighborhood, NavigationQueryError> {
        let sorted_entries: Vec<FunctionId> =
            self.validate_neighborhood_entries(entries, limits)?;
        Self::neighborhood_from_validated_entries(
            analysis,
            &sorted_entries,
            max_depth,
            direction,
            limits,
        )
    }

    fn validate_neighborhood_entries(
        &self,
        entries: &[FunctionId],
        limits: NeighborhoodLimits,
    ) -> Result<Vec<FunctionId>, NavigationQueryError> {
        let mut sorted_entries: BTreeSet<FunctionId> = BTreeSet::new();
        for entry in entries {
            if sorted_entries.contains(entry) {
                continue;
            }
            let actual: usize = sorted_entries.len().saturating_add(1);
            if actual > limits.max_nodes {
                return Err(NavigationLimitError::NeighborhoodNodes {
                    actual,
                    limit: limits.max_nodes,
                }
                .into());
            }
            let _: &Function = self.function_by_id(entry)?;
            sorted_entries.insert(*entry);
        }
        Ok(sorted_entries.into_iter().collect())
    }

    fn neighborhood_from_validated_entries(
        analysis: &NavigationAnalysis,
        entries: &[FunctionId],
        max_depth: u8,
        direction: NeighborhoodDirection,
        limits: NeighborhoodLimits,
    ) -> Result<Neighborhood, NavigationQueryError> {
        Self::validate_neighborhood_analysis(analysis, limits)?;
        let calls: &[NavigationCall] = analysis.calls();
        let mut outgoing: BTreeMap<FunctionId, Vec<usize>> = BTreeMap::new();
        let mut incoming: BTreeMap<FunctionId, Vec<usize>> = BTreeMap::new();
        for (index, call) in calls.iter().enumerate() {
            outgoing.entry(call.caller_id).or_default().push(index);
            if let Some(callee_id) = call.outcome.resolved_function_id() {
                incoming.entry(callee_id).or_default().push(index);
            }
        }

        let summaries_by_id: BTreeMap<FunctionId, usize> = analysis
            .functions()
            .iter()
            .enumerate()
            .map(|(index, summary): (usize, &FunctionSummary)| (summary.id, index))
            .collect();
        let mut visited: BTreeMap<FunctionId, u8> = BTreeMap::new();
        let mut queue: VecDeque<(FunctionId, u8)> = VecDeque::new();
        for entry in entries {
            visited.insert(*entry, 0);
            queue.push_back((*entry, 0));
        }

        let mut truncated: bool = false;
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            let mut neighbors: BTreeSet<FunctionId> = BTreeSet::new();
            if matches!(
                direction,
                NeighborhoodDirection::Callees | NeighborhoodDirection::Both
            ) && let Some(indices) = outgoing.get(&current)
            {
                for index in indices {
                    if let Some(callee_id) = calls
                        .get(*index)
                        .and_then(|call: &NavigationCall| call.outcome.resolved_function_id())
                    {
                        neighbors.insert(callee_id);
                    }
                }
            }
            if matches!(
                direction,
                NeighborhoodDirection::Callers | NeighborhoodDirection::Both
            ) && let Some(indices) = incoming.get(&current)
            {
                for index in indices {
                    if let Some(call) = calls.get(*index) {
                        neighbors.insert(call.caller_id);
                    }
                }
            }
            for neighbor in neighbors {
                if visited.contains_key(&neighbor) {
                    continue;
                }
                if visited.len() >= limits.max_nodes {
                    truncated = true;
                    continue;
                }
                let next_depth: u8 = depth.saturating_add(1);
                visited.insert(neighbor, next_depth);
                queue.push_back((neighbor, next_depth));
            }
        }

        let mut nodes: Vec<NeighborhoodNode> = visited
            .iter()
            .filter_map(|(id, depth): (&FunctionId, &u8)| {
                summaries_by_id
                    .get(id)
                    .and_then(|index: &usize| analysis.functions().get(*index))
                    .cloned()
                    .map(|summary: FunctionSummary| NeighborhoodNode {
                        function: summary,
                        depth: *depth,
                    })
            })
            .collect();
        nodes.sort_by(|left: &NeighborhoodNode, right: &NeighborhoodNode| {
            left.depth
                .cmp(&right.depth)
                .then(left.function.address.cmp(&right.function.address))
                .then(left.function.name.cmp(&right.function.name))
        });

        let mut selected_calls: Vec<NavigationCall> = Vec::new();
        for call in calls {
            if !visited.contains_key(&call.caller_id) {
                continue;
            }
            let include: bool = call
                .outcome
                .resolved_function_id()
                .is_none_or(|callee_id: FunctionId| visited.contains_key(&callee_id));
            if !include {
                continue;
            }
            if selected_calls.len() >= limits.max_calls {
                truncated = true;
                break;
            }
            selected_calls.push(call.clone());
        }

        Ok(Neighborhood {
            nodes,
            calls: selected_calls,
            truncated,
        })
    }

    fn validate_neighborhood_analysis(
        analysis: &NavigationAnalysis,
        limits: NeighborhoodLimits,
    ) -> Result<(), NavigationLimitError> {
        let function_count: usize = analysis.functions().len();
        if function_count > limits.analysis.functions {
            return Err(NavigationLimitError::Functions {
                actual: function_count,
                limit: limits.analysis.functions,
            });
        }
        let call_count: usize = analysis.calls().len();
        if call_count > limits.analysis.calls {
            return Err(NavigationLimitError::Calls {
                limit: limits.analysis.calls,
            });
        }
        let resolved_call_count: usize = analysis
            .calls()
            .iter()
            .filter(|call: &&NavigationCall| call.outcome.resolved_function_id().is_some())
            .count();
        let node_bound: usize = function_count.min(limits.max_nodes);
        let call_bound: usize = call_count.min(limits.max_calls);
        let work_records: usize = call_count
            .saturating_add(resolved_call_count)
            .saturating_add(function_count.saturating_mul(2))
            .saturating_add(node_bound.saturating_mul(4))
            .saturating_add(call_bound);
        let additional_bytes: usize = work_records
            .saturating_mul(ANALYSIS_WORK_RECORD_BYTES)
            .saturating_add(node_bound.saturating_mul(std::mem::size_of::<NeighborhoodNode>()))
            .saturating_add(call_bound.saturating_mul(std::mem::size_of::<NavigationCall>()));
        let working_set_bytes: usize = analysis
            .working_set_bytes()
            .saturating_add(additional_bytes);
        if working_set_bytes > limits.analysis.retained_bytes {
            return Err(NavigationLimitError::RetainedBytes {
                limit: limits.analysis.retained_bytes,
            });
        }
        Ok(())
    }

    fn build_navigation_analysis<E, G>(&self, mut guard: G) -> Result<NavigationAnalysis, E>
    where
        G: FnMut(NavigationProgress) -> Result<(), E>,
    {
        let function_count: usize = self.functions().len();
        guard(NavigationProgress::Functions(function_count))?;
        let mut retained_bytes: usize = function_count
            .saturating_mul(std::mem::size_of::<FunctionSummary>())
            .saturating_add(arc_value_retained_bytes::<CallOutcome>());
        guard(NavigationProgress::RetainedBytes(retained_bytes))?;
        let mut instruction_count: usize = 0;
        let mut call_count: usize = 0;
        for function in self.functions() {
            retained_bytes = retained_bytes.saturating_add(arc_str_retained_bytes(&function.name));
            guard(NavigationProgress::RetainedBytes(retained_bytes))?;
            instruction_count = instruction_count.saturating_add(function.instructions.len());
            guard(NavigationProgress::Instructions(instruction_count))?;
            for instruction in &function.instructions {
                if instruction.class == InsnClass::Call {
                    call_count = call_count.saturating_add(1);
                    guard(NavigationProgress::Calls(call_count))?;
                }
            }
        }
        retained_bytes = retained_bytes
            .saturating_add(call_count.saturating_mul(std::mem::size_of::<NavigationCall>()));
        let work_records: usize = function_count
            .saturating_mul(3)
            .saturating_add(instruction_count)
            .saturating_add(call_count.saturating_mul(3));
        retained_bytes =
            retained_bytes.saturating_add(work_records.saturating_mul(ANALYSIS_WORK_RECORD_BYTES));
        guard(NavigationProgress::RetainedBytes(retained_bytes))?;

        let address_counts: BTreeMap<u64, usize> = self.functions().iter().fold(
            BTreeMap::new(),
            |mut counts: BTreeMap<u64, usize>, function: &Function| {
                let count: &mut usize = counts.entry(function.address).or_default();
                *count = count.saturating_add(1);
                counts
            },
        );
        let mut summaries: Vec<FunctionSummary> = self
            .functions()
            .iter()
            .map(|function: &Function| {
                let duplicate_address: bool = address_counts
                    .get(&function.address)
                    .copied()
                    .unwrap_or_default()
                    > 1;
                let discriminator: [u8; 16] = if duplicate_address {
                    function_identity_hash(function)
                } else {
                    [0u8; 16]
                };
                let (basic_block_count, cyclomatic_complexity): (usize, u32) =
                    function.navigation_metrics();
                FunctionSummary {
                    id: FunctionId::with_discriminator(
                        self.source_hash,
                        function.address,
                        discriminator,
                    ),
                    name: Arc::from(function.name.as_str()),
                    address: function.address,
                    end: function.end,
                    is_export: function.is_export,
                    instruction_count: function.instruction_count(),
                    basic_block_count,
                    cyclomatic_complexity,
                    incoming_calls: 0,
                    outgoing_calls: 0,
                    indirect_calls: 0,
                }
            })
            .collect();
        let mut call_locations: Vec<(usize, usize)> = Vec::with_capacity(call_count);
        let mut direct_targets: BTreeSet<u64> = BTreeSet::new();
        for (function_index, function) in self.functions().iter().enumerate() {
            for (instruction_index, instruction) in function.instructions.iter().enumerate() {
                if instruction.class != InsnClass::Call {
                    continue;
                }
                call_locations.push((function_index, instruction_index));
                if let Some(target) = instruction.branch_target {
                    direct_targets.insert(target);
                }
            }
        }

        let mut exact: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut intervals: Vec<(u64, u64, usize)> = Vec::new();
        let mut instruction_memberships: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();
        for (function_index, function) in self.functions().iter().enumerate() {
            exact
                .entry(function.address)
                .or_default()
                .push(function_index);
            if function.end > function.address {
                intervals.push((function.address, function.end, function_index));
            }
            for instruction in &function.instructions {
                let inside_range: bool =
                    instruction.offset >= function.address && instruction.offset < function.end;
                if !inside_range && direct_targets.contains(&instruction.offset) {
                    instruction_memberships
                        .entry(instruction.offset)
                        .or_default()
                        .insert(function_index);
                }
            }
        }
        intervals.sort_unstable();

        let mut outcomes: BTreeMap<u64, Arc<CallOutcome>> = BTreeMap::new();
        let mut interval_index: usize = 0;
        let mut active: BTreeSet<usize> = BTreeSet::new();
        let mut endings: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
        let mut candidate_records: usize = 0;
        for target in direct_targets {
            while let Some((start, end, function_index)) = intervals.get(interval_index).copied() {
                if start > target {
                    break;
                }
                active.insert(function_index);
                endings.push(Reverse((end, function_index)));
                interval_index = interval_index.saturating_add(1);
            }
            while let Some(Reverse((end, function_index))) = endings.peek().copied() {
                if end > target {
                    break;
                }
                let _: Option<Reverse<(u64, usize)>> = endings.pop();
                active.remove(&function_index);
            }
            let is_exact: bool = exact.contains_key(&target);
            let candidate_indices: BTreeSet<usize> = exact
                .get(&target)
                .into_iter()
                .flatten()
                .copied()
                .chain(active.iter().copied())
                .chain(
                    instruction_memberships
                        .get(&target)
                        .into_iter()
                        .flatten()
                        .copied(),
                )
                .collect();
            candidate_records = candidate_records.saturating_add(candidate_indices.len().max(1));
            guard(NavigationProgress::CandidateRecords(candidate_records))?;
            let mut outcome_bytes: usize = arc_value_retained_bytes::<CallOutcome>();
            if candidate_indices.len() > 1 {
                outcome_bytes = outcome_bytes.saturating_add(
                    candidate_indices.len().saturating_mul(
                        std::mem::size_of::<FunctionIdentity>()
                            .saturating_add(ANALYSIS_WORK_RECORD_BYTES),
                    ),
                );
            } else if candidate_indices.is_empty()
                && let Some(symbol) = self.symbol_ref(target)
            {
                outcome_bytes = outcome_bytes.saturating_add(arc_str_retained_bytes(&symbol.name));
            }
            retained_bytes = retained_bytes.saturating_add(outcome_bytes);
            guard(NavigationProgress::RetainedBytes(retained_bytes))?;
            outcomes.insert(
                target,
                Arc::new(self.classify_indexed_target(
                    target,
                    is_exact,
                    &candidate_indices,
                    &summaries,
                )),
            );
        }

        let summary_indices: BTreeMap<FunctionId, Vec<usize>> =
            summaries
                .iter()
                .enumerate()
                .fold(BTreeMap::new(), |mut map, (index, summary)| {
                    map.entry(summary.id).or_default().push(index);
                    map
                });
        let mut calls: Vec<NavigationCall> = Vec::with_capacity(call_locations.len());
        let indirect_outcome: Arc<CallOutcome> = Arc::new(CallOutcome::Indirect);
        for (function_index, instruction_index) in call_locations {
            let Some(caller) = self.functions().get(function_index) else {
                continue;
            };
            let Some(instruction) = caller.instructions.get(instruction_index) else {
                continue;
            };
            let Some(caller_summary) = summaries.get(function_index) else {
                continue;
            };
            let caller_name: Arc<str> = Arc::clone(&caller_summary.name);
            let outcome: Arc<CallOutcome> = instruction.branch_target.map_or_else(
                || Arc::clone(&indirect_outcome),
                |target: u64| {
                    outcomes.get(&target).map_or_else(
                        || Arc::new(CallOutcome::Unresolved { address: target }),
                        Arc::clone,
                    )
                },
            );
            if let Some(summary) = summaries.get_mut(function_index) {
                summary.outgoing_calls = summary.outgoing_calls.saturating_add(1);
                if matches!(outcome.as_ref(), CallOutcome::Indirect) {
                    summary.indirect_calls = summary.indirect_calls.saturating_add(1);
                }
            }
            if let Some(callee_id) = outcome.resolved_function_id()
                && let Some(indices) = summary_indices.get(&callee_id)
                && let [index] = indices.as_slice()
                && let Some(summary) = summaries.get_mut(*index)
            {
                summary.incoming_calls = summary.incoming_calls.saturating_add(1);
            }
            calls.push(NavigationCall {
                caller_id: self.function_id(caller),
                caller_name,
                caller_address: caller.address,
                call_site: instruction.offset,
                outcome,
            });
        }
        calls.sort_by(compare_calls);
        summaries.sort_by(|left: &FunctionSummary, right: &FunctionSummary| {
            left.address
                .cmp(&right.address)
                .then(left.name.cmp(&right.name))
        });
        Ok(NavigationAnalysis {
            functions: summaries,
            calls,
            working_set_bytes: retained_bytes,
        })
    }

    fn classify_indexed_target(
        &self,
        target: u64,
        is_exact: bool,
        candidate_indices: &BTreeSet<usize>,
        summaries: &[FunctionSummary],
    ) -> CallOutcome {
        let mut candidates: Vec<FunctionIdentity> = candidate_indices
            .iter()
            .filter_map(|index: &usize| summaries.get(*index))
            .map(|summary: &FunctionSummary| FunctionIdentity {
                id: summary.id,
                name: Arc::clone(&summary.name),
                address: summary.address,
            })
            .collect();
        candidates.sort_by(|left: &FunctionIdentity, right: &FunctionIdentity| {
            left.address
                .cmp(&right.address)
                .then(left.name.cmp(&right.name))
        });
        if let [function] = candidates.as_slice() {
            return if is_exact {
                CallOutcome::FunctionStart {
                    function_id: function.id,
                    name: function.name.clone(),
                    address: function.address,
                }
            } else {
                CallOutcome::FunctionInterior {
                    function_id: function.id,
                    name: function.name.clone(),
                    function_address: function.address,
                    target_address: target,
                }
            };
        }
        if !candidates.is_empty() {
            return CallOutcome::AmbiguousFunction {
                target_address: target,
                candidates,
            };
        }
        self.symbol_ref(target).map_or(
            CallOutcome::Unresolved { address: target },
            |symbol: &crate::model::SymbolRef| CallOutcome::Symbol {
                name: Arc::from(symbol.name.as_str()),
                address: target,
                symbol_kind: symbol.kind,
            },
        )
    }
}

fn compare_calls(left: &NavigationCall, right: &NavigationCall) -> std::cmp::Ordering {
    left.call_site
        .cmp(&right.call_site)
        .then(
            left.outcome
                .target_address()
                .cmp(&right.outcome.target_address()),
        )
        .then(left.caller_address.cmp(&right.caller_address))
        .then(left.caller_name.cmp(&right.caller_name))
}

fn decode_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded: [u8; 32] = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high: u8 = decode_nibble(*pair.first()?)?;
        let low: u8 = decode_nibble(*pair.get(1)?)?;
        let byte: &mut u8 = decoded.get_mut(index)?;
        *byte = high.checked_shl(4)?.checked_add(low)?;
    }
    Some(decoded)
}

fn decode_discriminator(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut decoded: [u8; 16] = [0u8; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high: u8 = decode_nibble(*pair.first()?)?;
        let low: u8 = decode_nibble(*pair.get(1)?)?;
        let byte: &mut u8 = decoded.get_mut(index)?;
        *byte = high.checked_shl(4)?.checked_add(low)?;
    }
    (decoded != [0u8; 16]).then_some(decoded)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
