use std::str::FromStr as _;

use disrobe_query::{
    CallOutcome, FunctionId, FunctionLookupError, FunctionSummary, Module, NavigationAnalysis,
    NavigationCall, NavigationLimitError, NavigationLimits, NavigationQueryError, NavigationXref,
    NeighborhoodDirection, NeighborhoodLimits, NeighborhoodNode, module_from_bytes,
};
use rmcp::ErrorData;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};

use super::{decode_inline_bytes, ensure_text_bytes, hex32};

const DEFAULT_TOKEN_BUDGET: usize = 4_096;
const MIN_TOKEN_BUDGET: usize = 2_048;
const MAX_TOKEN_BUDGET: usize = 32_768;
const MAX_CURSOR_BYTES: usize = 256;
const MAX_CURSOR_OFFSET: usize = 1_000_000;
const MAX_ENTRY_IDS: usize = 64;
const MAX_NEIGHBORHOOD_DEPTH: u8 = 32;
const MAX_ANALYSIS_FUNCTIONS: usize = 8_192;
const MAX_ANALYSIS_INSTRUCTIONS: usize = 262_144;
const MAX_ANALYSIS_CALLS: usize = 32_768;
const MAX_ANALYSIS_CANDIDATE_RECORDS: usize = 65_536;
const MAX_ANALYSIS_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_XREFS: usize = 32_768;
const MAX_OUTPUT_TEXT_BYTES: usize = 160;
const MAX_AMBIGUOUS_CANDIDATES: usize = 8;
const BUDGET_MEASURE: &str = "complete-call-tool-result-serialized-utf8-bytes";
const TOKENIZER: &str = "o200k_base";
const CURSOR_PREFIX: &str = "nav1";

pub(super) struct Json<T>(T);

impl<T> Json<T> {
    pub(super) const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: Serialize> IntoCallToolResult for Json<T> {
    fn into_call_tool_result(self) -> Result<CallToolResult, ErrorData> {
        let value: serde_json::Value =
            serde_json::to_value(self.0).map_err(|error: serde_json::Error| {
                ErrorData::internal_error(
                    format!("DR-MCP-0660: navigation response serialize: {error}"),
                    None,
                )
            })?;
        let text: String = serde_json::to_string(&value).map_err(|error: serde_json::Error| {
            ErrorData::internal_error(
                format!("DR-MCP-0660: navigation response serialize: {error}"),
                None,
            )
        })?;
        let mut result: CallToolResult = CallToolResult::success(vec![Content::text(text)]);
        result.structured_content = Some(value);
        Ok(result)
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct CallGraphParams {
    pub bytes_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct XrefsParams {
    pub bytes_b64: String,
    pub function_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FunctionSummaryParams {
    pub bytes_b64: String,
    pub function_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct NeighborhoodParams {
    pub bytes_b64: String,
    pub entry_ids: Vec<String>,
    pub depth: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FunctionSummaryOut {
    pub id: String,
    pub name: String,
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

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FunctionIdentityOut {
    pub id: String,
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[schemars(crate = "rmcp::schemars")]
pub(super) enum CallOutcomeOut {
    FunctionStart {
        function_id: String,
        name: String,
        address: u64,
    },
    FunctionInterior {
        function_id: String,
        name: String,
        function_address: u64,
        target_address: u64,
    },
    AmbiguousFunction {
        target_address: u64,
        candidates: Vec<FunctionIdentityOut>,
        omitted_candidates: usize,
    },
    Symbol {
        name: String,
        address: u64,
        symbol_kind: String,
    },
    Unresolved {
        address: u64,
    },
    Indirect,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct NavigationCallOut {
    pub caller_id: String,
    pub caller_name: String,
    pub caller_address: u64,
    pub call_site: u64,
    pub outcome: CallOutcomeOut,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct XrefOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_function_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_function: Option<String>,
    pub from_offset: u64,
    pub mnemonic: String,
    pub to_address: u64,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct NeighborhoodFunctionOut {
    pub depth: u8,
    pub function: FunctionSummaryOut,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct CallGraphOut {
    pub schema: String,
    pub source_hash: String,
    pub token_budget: usize,
    pub tokenizer: String,
    pub budget_measure: String,
    pub total_functions: usize,
    pub total_calls: usize,
    pub functions: Vec<FunctionSummaryOut>,
    pub calls: Vec<NavigationCallOut>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct XrefsOut {
    pub schema: String,
    pub source_hash: String,
    pub function_id: String,
    pub token_budget: usize,
    pub tokenizer: String,
    pub budget_measure: String,
    pub total: usize,
    pub xrefs: Vec<XrefOut>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FunctionSummaryResponse {
    pub schema: String,
    pub source_hash: String,
    pub token_budget: usize,
    pub tokenizer: String,
    pub budget_measure: String,
    pub function: FunctionSummaryOut,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct NeighborhoodOut {
    pub schema: String,
    pub source_hash: String,
    pub direction: String,
    pub depth: u8,
    pub token_budget: usize,
    pub tokenizer: String,
    pub budget_measure: String,
    pub total_functions: usize,
    pub total_calls: usize,
    pub functions: Vec<NeighborhoodFunctionOut>,
    pub calls: Vec<NavigationCallOut>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

pub(super) fn call_graph(params: CallGraphParams) -> Result<CallGraphOut, ErrorData> {
    let module: Module = decode_module(&params.bytes_b64)?;
    let budget: usize = token_budget(params.token_budget)?;
    let scope: [u8; 32] = scope_hash(&["call_graph"]);
    let mut index: usize =
        cursor_offset(params.cursor.as_deref(), "cg", &module.source_hash, &scope)?;
    let analysis: NavigationAnalysis = module
        .navigation_analysis(navigation_limits())
        .map_err(navigation_limit_error)?;
    let (summaries, calls): (Vec<FunctionSummary>, Vec<NavigationCall>) = analysis.into_parts();
    let total: usize = summaries.len().saturating_add(calls.len());
    if index > total {
        return Err(cursor_error("cursor is beyond the call-graph result"));
    }
    let mut response: CallGraphOut = CallGraphOut {
        schema: "disrobe.mcp.call-graph/v1".to_owned(),
        source_hash: hex32(&module.source_hash),
        token_budget: budget,
        tokenizer: TOKENIZER.to_owned(),
        budget_measure: BUDGET_MEASURE.to_owned(),
        total_functions: summaries.len(),
        total_calls: calls.len(),
        functions: Vec::new(),
        calls: Vec::new(),
        truncated: index < total,
        next_cursor: (index < total)
            .then(|| encode_cursor("cg", &module.source_hash, &scope, index)),
    };
    ensure_response_budget(&response, budget)?;
    let page_start: usize = index;
    while index < total {
        let is_function: bool = index < summaries.len();
        if is_function {
            if let Some(summary) = summaries.get(index) {
                let row: FunctionSummaryOut = function_summary_out(summary);
                let next_index: usize = index.saturating_add(1);
                response.next_cursor =
                    Some(encode_cursor("cg", &module.source_hash, &scope, next_index));
                if !append_bounded_row(
                    &mut response,
                    row,
                    budget,
                    index,
                    page_start,
                    "call-graph",
                    |output: &mut CallGraphOut, value: FunctionSummaryOut| {
                        output.functions.push(value);
                    },
                    |output: &mut CallGraphOut| {
                        let _: Option<FunctionSummaryOut> = output.functions.pop();
                    },
                )? {
                    response.next_cursor =
                        Some(encode_cursor("cg", &module.source_hash, &scope, index));
                    break;
                }
                index = next_index;
            }
        } else if let Some(call) = calls.get(index.saturating_sub(summaries.len())) {
            let row: NavigationCallOut = navigation_call_out(call);
            let next_index: usize = index.saturating_add(1);
            response.next_cursor =
                Some(encode_cursor("cg", &module.source_hash, &scope, next_index));
            if !append_bounded_row(
                &mut response,
                row,
                budget,
                index,
                page_start,
                "call-graph",
                |output: &mut CallGraphOut, value: NavigationCallOut| output.calls.push(value),
                |output: &mut CallGraphOut| {
                    let _: Option<NavigationCallOut> = output.calls.pop();
                },
            )? {
                response.next_cursor =
                    Some(encode_cursor("cg", &module.source_hash, &scope, index));
                break;
            }
            index = next_index;
        }
    }
    response.truncated = index < total;
    if !response.truncated {
        response.next_cursor = None;
    }
    ensure_response_budget(&response, budget)?;
    Ok(response)
}

pub(super) fn xrefs(params: XrefsParams) -> Result<XrefsOut, ErrorData> {
    let module: Module = decode_module(&params.bytes_b64)?;
    let budget: usize = token_budget(params.token_budget)?;
    let id: FunctionId = parse_function_id(&params.function_id)?;
    let _: NavigationAnalysis = module
        .navigation_analysis(navigation_limits())
        .map_err(navigation_limit_error)?;
    let xrefs: Vec<NavigationXref> = module
        .bounded_navigation_xrefs_to_function(&id, MAX_XREFS, MAX_ANALYSIS_RETAINED_BYTES)
        .map_err(navigation_query_error)?;
    let canonical_id: String = id.to_string();
    let scope: [u8; 32] = scope_hash(&["xrefs", &canonical_id]);
    let mut index: usize =
        cursor_offset(params.cursor.as_deref(), "xr", &module.source_hash, &scope)?;
    if index > xrefs.len() {
        return Err(cursor_error("cursor is beyond the cross-reference result"));
    }
    let mut response: XrefsOut = XrefsOut {
        schema: "disrobe.mcp.xrefs/v1".to_owned(),
        source_hash: hex32(&module.source_hash),
        function_id: canonical_id,
        token_budget: budget,
        tokenizer: TOKENIZER.to_owned(),
        budget_measure: BUDGET_MEASURE.to_owned(),
        total: xrefs.len(),
        xrefs: Vec::new(),
        truncated: index < xrefs.len(),
        next_cursor: (index < xrefs.len())
            .then(|| encode_cursor("xr", &module.source_hash, &scope, index)),
    };
    ensure_response_budget(&response, budget)?;
    let page_start: usize = index;
    while let Some(xref) = xrefs.get(index) {
        let row: XrefOut = xref_out(xref);
        let next_index: usize = index.saturating_add(1);
        response.next_cursor = Some(encode_cursor("xr", &module.source_hash, &scope, next_index));
        if !append_bounded_row(
            &mut response,
            row,
            budget,
            index,
            page_start,
            "cross-reference",
            |output: &mut XrefsOut, value: XrefOut| output.xrefs.push(value),
            |output: &mut XrefsOut| {
                let _: Option<XrefOut> = output.xrefs.pop();
            },
        )? {
            response.next_cursor = Some(encode_cursor("xr", &module.source_hash, &scope, index));
            break;
        }
        index = next_index;
    }
    response.truncated = index < xrefs.len();
    if !response.truncated {
        response.next_cursor = None;
    }
    ensure_response_budget(&response, budget)?;
    Ok(response)
}

pub(super) fn function_summary(
    params: FunctionSummaryParams,
) -> Result<FunctionSummaryResponse, ErrorData> {
    let module: Module = decode_module(&params.bytes_b64)?;
    let budget: usize = token_budget(params.token_budget)?;
    let id: FunctionId = parse_function_id(&params.function_id)?;
    let canonical_id: String = id.to_string();
    let scope: [u8; 32] = scope_hash(&["function_summary", &canonical_id]);
    let offset: usize = cursor_offset(params.cursor.as_deref(), "fs", &module.source_hash, &scope)?;
    if offset != 0 {
        return Err(cursor_error("function-summary cursor must start at zero"));
    }
    let _: &disrobe_query::Function = module.function_by_id(&id).map_err(function_lookup_error)?;
    let analysis: NavigationAnalysis = module
        .navigation_analysis(navigation_limits())
        .map_err(navigation_limit_error)?;
    let (summaries, _): (Vec<FunctionSummary>, Vec<NavigationCall>) = analysis.into_parts();
    let summary: FunctionSummary = summaries
        .into_iter()
        .find(|summary: &FunctionSummary| summary.id == id)
        .ok_or_else(|| {
            function_lookup_error(FunctionLookupError::NotFound {
                address: id.address(),
            })
        })?;
    let response: FunctionSummaryResponse = FunctionSummaryResponse {
        schema: "disrobe.mcp.function-summary/v1".to_owned(),
        source_hash: hex32(&module.source_hash),
        token_budget: budget,
        tokenizer: TOKENIZER.to_owned(),
        budget_measure: BUDGET_MEASURE.to_owned(),
        function: function_summary_out(&summary),
        truncated: false,
        next_cursor: None,
    };
    if serialized_len(&response)? > budget {
        return Err(row_too_large("function-summary", 0, budget));
    }
    Ok(response)
}

pub(super) fn neighborhood(params: NeighborhoodParams) -> Result<NeighborhoodOut, ErrorData> {
    let module: Module = decode_module(&params.bytes_b64)?;
    let budget: usize = token_budget(params.token_budget)?;
    if params.entry_ids.is_empty() || params.entry_ids.len() > MAX_ENTRY_IDS {
        return Err(ErrorData::invalid_params(
            format!("DR-MCP-0658: entry_ids must contain 1..={MAX_ENTRY_IDS} function ids"),
            None,
        ));
    }
    if params.depth > MAX_NEIGHBORHOOD_DEPTH {
        return Err(ErrorData::invalid_params(
            format!("DR-MCP-0657: depth must be in 0..={MAX_NEIGHBORHOOD_DEPTH}"),
            None,
        ));
    }
    let direction_text: &str = params.direction.as_deref().unwrap_or("both");
    let direction: NeighborhoodDirection = parse_direction(direction_text)?;
    let mut entries: Vec<FunctionId> = params
        .entry_ids
        .iter()
        .map(|value: &String| parse_function_id(value))
        .collect::<Result<Vec<FunctionId>, ErrorData>>()?;
    entries.sort_unstable();
    entries.dedup();
    let mut scope_parts: Vec<String> = vec![
        "neighborhood".to_owned(),
        direction_text.to_owned(),
        params.depth.to_string(),
    ];
    scope_parts.extend(entries.iter().map(ToString::to_string));
    let scope_refs: Vec<&str> = scope_parts.iter().map(String::as_str).collect();
    let scope: [u8; 32] = scope_hash(&scope_refs);
    let mut index: usize =
        cursor_offset(params.cursor.as_deref(), "nb", &module.source_hash, &scope)?;
    let analysis: NavigationAnalysis = module
        .navigation_analysis(navigation_limits())
        .map_err(navigation_limit_error)?;
    let result: disrobe_query::Neighborhood = module
        .neighborhood_from_analysis(
            &analysis,
            &entries,
            params.depth,
            direction,
            NeighborhoodLimits {
                max_nodes: MAX_ANALYSIS_FUNCTIONS,
                max_calls: MAX_ANALYSIS_CALLS,
                analysis: navigation_limits(),
            },
        )
        .map_err(navigation_query_error)?;
    if result.truncated {
        return Err(ErrorData::internal_error(
            "DR-MCP-0661: neighborhood exceeds the bounded analysis record limit".to_owned(),
            None,
        ));
    }
    let total: usize = result.nodes.len().saturating_add(result.calls.len());
    if index > total {
        return Err(cursor_error("cursor is beyond the neighborhood result"));
    }
    let mut response: NeighborhoodOut = NeighborhoodOut {
        schema: "disrobe.mcp.neighborhood/v1".to_owned(),
        source_hash: hex32(&module.source_hash),
        direction: direction_text.to_owned(),
        depth: params.depth,
        token_budget: budget,
        tokenizer: TOKENIZER.to_owned(),
        budget_measure: BUDGET_MEASURE.to_owned(),
        total_functions: result.nodes.len(),
        total_calls: result.calls.len(),
        functions: Vec::new(),
        calls: Vec::new(),
        truncated: index < total,
        next_cursor: (index < total)
            .then(|| encode_cursor("nb", &module.source_hash, &scope, index)),
    };
    ensure_response_budget(&response, budget)?;
    let page_start: usize = index;
    while index < total {
        let is_function: bool = index < result.nodes.len();
        if is_function {
            if let Some(node) = result.nodes.get(index) {
                let row: NeighborhoodFunctionOut = neighborhood_function_out(node);
                let next_index: usize = index.saturating_add(1);
                response.next_cursor =
                    Some(encode_cursor("nb", &module.source_hash, &scope, next_index));
                if !append_bounded_row(
                    &mut response,
                    row,
                    budget,
                    index,
                    page_start,
                    "neighborhood",
                    |output: &mut NeighborhoodOut, value: NeighborhoodFunctionOut| {
                        output.functions.push(value);
                    },
                    |output: &mut NeighborhoodOut| {
                        let _: Option<NeighborhoodFunctionOut> = output.functions.pop();
                    },
                )? {
                    response.next_cursor =
                        Some(encode_cursor("nb", &module.source_hash, &scope, index));
                    break;
                }
                index = next_index;
            }
        } else if let Some(call) = result.calls.get(index.saturating_sub(result.nodes.len())) {
            let row: NavigationCallOut = navigation_call_out(call);
            let next_index: usize = index.saturating_add(1);
            response.next_cursor =
                Some(encode_cursor("nb", &module.source_hash, &scope, next_index));
            if !append_bounded_row(
                &mut response,
                row,
                budget,
                index,
                page_start,
                "neighborhood",
                |output: &mut NeighborhoodOut, value: NavigationCallOut| output.calls.push(value),
                |output: &mut NeighborhoodOut| {
                    let _: Option<NavigationCallOut> = output.calls.pop();
                },
            )? {
                response.next_cursor =
                    Some(encode_cursor("nb", &module.source_hash, &scope, index));
                break;
            }
            index = next_index;
        }
    }
    response.truncated = index < total;
    if !response.truncated {
        response.next_cursor = None;
    }
    ensure_response_budget(&response, budget)?;
    Ok(response)
}

fn decode_module(bytes_b64: &str) -> Result<Module, ErrorData> {
    let bytes: Vec<u8> = decode_inline_bytes(bytes_b64)?;
    module_from_bytes(&bytes).map_err(|error: disrobe_query::QueryError| {
        ErrorData::invalid_params(
            format!("DR-MCP-0650: navigation requires a Disasm- or Mir-rung .dr envelope: {error}"),
            None,
        )
    })
}

fn token_budget(value: Option<usize>) -> Result<usize, ErrorData> {
    let budget: usize = value.unwrap_or(DEFAULT_TOKEN_BUDGET);
    if !(MIN_TOKEN_BUDGET..=MAX_TOKEN_BUDGET).contains(&budget) {
        return Err(ErrorData::invalid_params(
            format!("DR-MCP-0651: token_budget must be in {MIN_TOKEN_BUDGET}..={MAX_TOKEN_BUDGET}"),
            None,
        ));
    }
    Ok(budget)
}

const fn navigation_limits() -> NavigationLimits {
    NavigationLimits {
        functions: MAX_ANALYSIS_FUNCTIONS,
        instructions: MAX_ANALYSIS_INSTRUCTIONS,
        calls: MAX_ANALYSIS_CALLS,
        candidate_records: MAX_ANALYSIS_CANDIDATE_RECORDS,
        retained_bytes: MAX_ANALYSIS_RETAINED_BYTES,
    }
}

fn navigation_limit_error(error: NavigationLimitError) -> ErrorData {
    ErrorData::invalid_params(
        format!("DR-MCP-0661: navigation analysis limit exceeded: {error}"),
        None,
    )
}

fn navigation_query_error(error: NavigationQueryError) -> ErrorData {
    match error {
        NavigationQueryError::Lookup(error) => function_lookup_error(error),
        NavigationQueryError::Limit(error) => navigation_limit_error(error),
    }
}

fn row_too_large(kind: &str, index: usize, budget: usize) -> ErrorData {
    ErrorData::invalid_params(
        format!(
            "DR-MCP-0662: {kind} row {index} cannot fit the {budget}-byte serialized UTF-8 ceiling"
        ),
        None,
    )
}

fn ensure_page_progress(
    index: usize,
    page_start: usize,
    kind: &str,
    budget: usize,
) -> Result<(), ErrorData> {
    if index == page_start {
        return Err(row_too_large(kind, index, budget));
    }
    Ok(())
}

fn append_bounded_row<T, R, P, O>(
    response: &mut T,
    row: R,
    budget: usize,
    index: usize,
    page_start: usize,
    kind: &str,
    push: P,
    pop: O,
) -> Result<bool, ErrorData>
where
    T: Serialize,
    P: FnOnce(&mut T, R),
    O: FnOnce(&mut T),
{
    push(response, row);
    if serialized_len(response)? <= budget {
        return Ok(true);
    }
    pop(response);
    ensure_page_progress(index, page_start, kind, budget)?;
    Ok(false)
}

fn parse_function_id(value: &str) -> Result<FunctionId, ErrorData> {
    ensure_text_bytes(
        "function_id",
        value,
        FunctionId::MAX_ENCODED_LEN,
        "DR-MCP-0654",
    )?;
    FunctionId::from_str(value).map_err(|error: disrobe_query::FunctionIdParseError| {
        ErrorData::invalid_params(format!("DR-MCP-0654: invalid function_id: {error}"), None)
    })
}

fn function_lookup_error(error: FunctionLookupError) -> ErrorData {
    match error {
        FunctionLookupError::SourceMismatch { .. } => ErrorData::invalid_params(
            "DR-MCP-0655: function_id belongs to a different source".to_owned(),
            None,
        ),
        FunctionLookupError::NotFound { address } => ErrorData::invalid_params(
            format!("DR-MCP-0656: no function starts at {address:#x}"),
            None,
        ),
        FunctionLookupError::Ambiguous { address } => ErrorData::invalid_params(
            format!("DR-MCP-0656: multiple functions start at {address:#x}"),
            None,
        ),
    }
}

fn parse_direction(value: &str) -> Result<NeighborhoodDirection, ErrorData> {
    match value {
        "callers" => Ok(NeighborhoodDirection::Callers),
        "callees" => Ok(NeighborhoodDirection::Callees),
        "both" => Ok(NeighborhoodDirection::Both),
        _ => Err(ErrorData::invalid_params(
            "DR-MCP-0659: direction must be callers, callees, or both".to_owned(),
            None,
        )),
    }
}

fn cursor_offset(
    cursor: Option<&str>,
    kind: &str,
    source_hash: &[u8; 32],
    scope: &[u8; 32],
) -> Result<usize, ErrorData> {
    let Some(value) = cursor else {
        return Ok(0);
    };
    ensure_text_bytes("cursor", value, MAX_CURSOR_BYTES, "DR-MCP-0652")?;
    let mut parts: std::str::Split<'_, char> = value.split(':');
    let prefix: Option<&str> = parts.next();
    let cursor_kind: Option<&str> = parts.next();
    let cursor_source: Option<&str> = parts.next();
    let cursor_scope: Option<&str> = parts.next();
    let offset_text: Option<&str> = parts.next();
    if prefix != Some(CURSOR_PREFIX)
        || cursor_kind != Some(kind)
        || parts.next().is_some()
        || offset_text.is_none_or(|text: &str| text.len() != 16)
    {
        return Err(cursor_error(
            "cursor shape or tool does not match this request",
        ));
    }
    if cursor_source != Some(hex32(source_hash).as_str()) {
        return Err(ErrorData::invalid_params(
            "DR-MCP-0653: cursor belongs to a different source".to_owned(),
            None,
        ));
    }
    if cursor_scope != Some(hex32(scope).as_str()) {
        return Err(cursor_error("cursor parameters do not match this request"));
    }
    let offset_u64: u64 = offset_text
        .and_then(|text: &str| u64::from_str_radix(text, 16).ok())
        .ok_or_else(|| cursor_error("cursor offset is not hexadecimal"))?;
    let offset: usize = usize::try_from(offset_u64)
        .map_err(|_: std::num::TryFromIntError| cursor_error("cursor offset is too large"))?;
    if offset > MAX_CURSOR_OFFSET {
        return Err(cursor_error("cursor offset exceeds the navigation limit"));
    }
    Ok(offset)
}

fn encode_cursor(kind: &str, source_hash: &[u8; 32], scope: &[u8; 32], offset: usize) -> String {
    format!(
        "{CURSOR_PREFIX}:{kind}:{}:{}:{offset:016x}",
        hex32(source_hash),
        hex32(scope)
    )
}

fn cursor_error(message: &str) -> ErrorData {
    ErrorData::invalid_params(format!("DR-MCP-0652: {message}"), None)
}

fn scope_hash(parts: &[&str]) -> [u8; 32] {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    for part in parts {
        let length: u64 = u64::try_from(part.len()).map_or(u64::MAX, |value: u64| value);
        hasher.update(&length.to_le_bytes());
        hasher.update(part.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn serialized_len<T: Serialize>(value: &T) -> Result<usize, ErrorData> {
    let structured: serde_json::Value = serde_json::to_value(value).map_err(serialization_error)?;
    let text: String = serde_json::to_string(&structured).map_err(serialization_error)?;
    let mut result: CallToolResult = CallToolResult::success(vec![Content::text(text)]);
    result.structured_content = Some(structured);
    serde_json::to_vec(&result)
        .map(|encoded: Vec<u8>| encoded.len())
        .map_err(serialization_error)
}

fn serialization_error(error: serde_json::Error) -> ErrorData {
    ErrorData::internal_error(
        format!("DR-MCP-0660: navigation response serialize: {error}"),
        None,
    )
}

fn ensure_response_budget<T: Serialize>(value: &T, budget: usize) -> Result<(), ErrorData> {
    let length: usize = serialized_len(value)?;
    if length > budget {
        return Err(ErrorData::internal_error(
            format!(
                "DR-MCP-0660: bounded navigation response needs {length} bytes but budget is {budget}"
            ),
            None,
        ));
    }
    Ok(())
}

fn function_summary_out(summary: &FunctionSummary) -> FunctionSummaryOut {
    let name: String = bounded_one_line(&summary.name, MAX_OUTPUT_TEXT_BYTES);
    FunctionSummaryOut {
        id: summary.id.to_string(),
        name,
        address: summary.address,
        end: summary.end,
        is_export: summary.is_export,
        instruction_count: summary.instruction_count,
        basic_block_count: summary.basic_block_count,
        cyclomatic_complexity: summary.cyclomatic_complexity,
        incoming_calls: summary.incoming_calls,
        outgoing_calls: summary.outgoing_calls,
        indirect_calls: summary.indirect_calls,
    }
}

fn navigation_call_out(call: &NavigationCall) -> NavigationCallOut {
    NavigationCallOut {
        caller_id: call.caller_id.to_string(),
        caller_name: bounded_one_line(&call.caller_name, MAX_OUTPUT_TEXT_BYTES),
        caller_address: call.caller_address,
        call_site: call.call_site,
        outcome: call_outcome_out(call.outcome.as_ref()),
    }
}

fn call_outcome_out(outcome: &CallOutcome) -> CallOutcomeOut {
    match outcome {
        CallOutcome::FunctionStart {
            function_id,
            name,
            address,
        } => CallOutcomeOut::FunctionStart {
            function_id: function_id.to_string(),
            name: bounded_one_line(name, MAX_OUTPUT_TEXT_BYTES),
            address: *address,
        },
        CallOutcome::FunctionInterior {
            function_id,
            name,
            function_address,
            target_address,
        } => CallOutcomeOut::FunctionInterior {
            function_id: function_id.to_string(),
            name: bounded_one_line(name, MAX_OUTPUT_TEXT_BYTES),
            function_address: *function_address,
            target_address: *target_address,
        },
        CallOutcome::AmbiguousFunction {
            target_address,
            candidates,
        } => {
            let bounded: Vec<FunctionIdentityOut> = candidates
                .iter()
                .take(MAX_AMBIGUOUS_CANDIDATES)
                .map(
                    |candidate: &disrobe_query::FunctionIdentity| FunctionIdentityOut {
                        id: candidate.id.to_string(),
                        name: bounded_one_line(&candidate.name, MAX_OUTPUT_TEXT_BYTES),
                        address: candidate.address,
                    },
                )
                .collect();
            CallOutcomeOut::AmbiguousFunction {
                target_address: *target_address,
                omitted_candidates: candidates.len().saturating_sub(bounded.len()),
                candidates: bounded,
            }
        }
        CallOutcome::Symbol {
            name,
            address,
            symbol_kind,
        } => CallOutcomeOut::Symbol {
            name: bounded_one_line(name, MAX_OUTPUT_TEXT_BYTES),
            address: *address,
            symbol_kind: format!("{symbol_kind:?}").to_ascii_lowercase(),
        },
        CallOutcome::Unresolved { address } => CallOutcomeOut::Unresolved { address: *address },
        CallOutcome::Indirect => CallOutcomeOut::Indirect,
    }
}

fn xref_out(xref: &NavigationXref) -> XrefOut {
    XrefOut {
        from_function_id: Some(xref.from_function_id.to_string()),
        from_function: Some(bounded_one_line(
            &xref.from_function_name,
            MAX_OUTPUT_TEXT_BYTES,
        )),
        from_offset: xref.from_offset,
        mnemonic: bounded_one_line(&xref.mnemonic, MAX_OUTPUT_TEXT_BYTES),
        to_address: xref.to_address,
    }
}

fn neighborhood_function_out(node: &NeighborhoodNode) -> NeighborhoodFunctionOut {
    NeighborhoodFunctionOut {
        depth: node.depth,
        function: function_summary_out(&node.function),
    }
}

fn bounded_one_line(value: &str, max_bytes: usize) -> String {
    let mut output: String = String::with_capacity(value.len().min(max_bytes));
    let mut truncated: bool = false;
    for character in value.chars() {
        let normalized: char = if character.is_control() {
            ' '
        } else {
            character
        };
        let needed: usize = normalized.len_utf8();
        if output.len().saturating_add(needed) > max_bytes.saturating_sub(3) {
            truncated = true;
            break;
        }
        output.push(normalized);
    }
    if truncated {
        output.push_str("...");
    }
    output
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use disrobe_ir::payload::{
        DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
    };
    use disrobe_ir::{Envelope, Rung};

    fn fixture_params_with_source_and_operand_bytes(
        source_hash: [u8; 32],
        budget: usize,
        cursor: Option<String>,
        operand_bytes: usize,
    ) -> CallGraphParams {
        let mut instructions: Vec<DisasmInstruction> = Vec::new();
        let mut symbols: Vec<DisasmSymbol> = Vec::new();
        for index in 0u64..96 {
            let address: u64 = index.saturating_mul(0x10);
            symbols.push(DisasmSymbol {
                address,
                name: format!("函数_{index:03}_🙂_with_a_long_name"),
                kind: if index == 0 {
                    DisasmSymbolKind::Export
                } else {
                    DisasmSymbolKind::Function
                },
            });
            if index < 95 {
                instructions.push(DisasmInstruction {
                    offset: address,
                    bytes: vec![0xe8],
                    mnemonic: "call".to_owned(),
                    operands: vec![format!(
                        "0x{:x}{}",
                        address.saturating_add(0x10),
                        "x".repeat(operand_bytes)
                    )],
                    flow: InsnFlow::Call,
                    branch_target: Some(address.saturating_add(0x10)),
                    ..DisasmInstruction::default()
                });
            }
            instructions.push(DisasmInstruction {
                offset: address.saturating_add(1),
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: Vec::new(),
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            });
        }
        let payload: DisasmPayload = DisasmPayload {
            source_hash,
            instructions,
            symbol_table: symbols,
        };
        let hot: Vec<u8> = encode_disasm(&payload).expect("encode disasm");
        let bytes: Vec<u8> = Envelope::new(Rung::Disasm, hot, Vec::new())
            .encode()
            .expect("encode envelope");
        CallGraphParams {
            bytes_b64: BASE64_STANDARD.encode(bytes),
            token_budget: Some(budget),
            cursor,
        }
    }

    fn fixture_params(budget: usize, cursor: Option<String>) -> CallGraphParams {
        fixture_params_with_source_and_operand_bytes([0x44u8; 32], budget, cursor, 0)
    }

    fn xref_fixture_params(function_id: String, cursor: Option<String>) -> XrefsParams {
        let instructions: Vec<DisasmInstruction> = (0u64..96)
            .map(|index: u64| DisasmInstruction {
                offset: index,
                bytes: vec![0xe8],
                mnemonic: "call".to_owned(),
                operands: vec!["0x1abc".to_owned()],
                flow: InsnFlow::Call,
                branch_target: Some(0x1abc),
                ..DisasmInstruction::default()
            })
            .collect();
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0xabu8; 32],
            instructions,
            symbol_table: vec![
                DisasmSymbol {
                    address: 0,
                    name: "caller".to_owned(),
                    kind: DisasmSymbolKind::Function,
                },
                DisasmSymbol {
                    address: 0x1abc,
                    name: "target".to_owned(),
                    kind: DisasmSymbolKind::Function,
                },
            ],
        };
        let hot: Vec<u8> = encode_disasm(&payload).expect("encode xref disasm");
        let bytes: Vec<u8> = Envelope::new(Rung::Disasm, hot, Vec::new())
            .encode()
            .expect("encode xref envelope");
        XrefsParams {
            bytes_b64: BASE64_STANDARD.encode(bytes),
            function_id,
            token_budget: Some(MIN_TOKEN_BUDGET),
            cursor,
        }
    }

    #[test]
    fn utf8_bounding_preserves_codepoints_and_removes_lines() {
        let bounded: String = bounded_one_line("函数\n🙂函数🙂函数🙂函数", 16);
        assert!(bounded.len() <= 16);
        assert!(!bounded.contains('\n'));
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
    }

    #[test]
    fn cursor_is_bound_to_source_scope_and_offset_limit() {
        let source: [u8; 32] = [0x11u8; 32];
        let scope: [u8; 32] = scope_hash(&["call_graph"]);
        let cursor: String = encode_cursor("cg", &source, &scope, 17);
        assert_eq!(
            cursor_offset(Some(&cursor), "cg", &source, &scope).expect("valid cursor"),
            17
        );
        let foreign: ErrorData =
            cursor_offset(Some(&cursor), "cg", &[0x22u8; 32], &scope).expect_err("foreign source");
        assert!(foreign.message.contains("DR-MCP-0653"));
    }

    #[test]
    fn response_budget_is_structural_and_cursor_resumes_without_overlap() {
        let first: CallGraphOut =
            call_graph(fixture_params(MIN_TOKEN_BUDGET, None)).expect("first bounded page");
        assert!(first.truncated);
        assert!(serialized_len(&first).expect("measure first") <= MIN_TOKEN_BUDGET);
        let cursor: String = first.next_cursor.clone().expect("continuation");
        let first_ids: Vec<String> = first
            .functions
            .iter()
            .map(|function: &FunctionSummaryOut| function.id.clone())
            .collect();

        let second: CallGraphOut = call_graph(fixture_params(MIN_TOKEN_BUDGET, Some(cursor)))
            .expect("second bounded page");
        assert!(serialized_len(&second).expect("measure second") <= MIN_TOKEN_BUDGET);
        assert!(
            second
                .functions
                .iter()
                .all(|function: &FunctionSummaryOut| { !first_ids.contains(&function.id) })
        );
    }

    #[test]
    fn cursor_from_a_different_module_is_rejected() {
        let first: CallGraphOut =
            call_graph(fixture_params(MIN_TOKEN_BUDGET, None)).expect("first page");
        let cursor: String = first.next_cursor.expect("continuation");
        let params: CallGraphParams = fixture_params_with_source_and_operand_bytes(
            [0x45u8; 32],
            MIN_TOKEN_BUDGET,
            Some(cursor),
            0,
        );
        let error: ErrorData = call_graph(params).expect_err("foreign source cursor");
        assert!(
            error.message.contains("DR-MCP-0653"),
            "valid foreign source must be rejected: {}",
            error.message
        );
    }

    #[test]
    fn xref_cursor_accepts_canonical_id_after_uppercase_id_request() {
        let canonical: String = FunctionId::new([0xabu8; 32], 0x1abc).to_string();
        let mut parts: std::str::Split<'_, char> = canonical.split(':');
        let _: Option<&str> = parts.next();
        let hash: &str = parts.next().expect("hash");
        let address: &str = parts.next().expect("address");
        let uppercase: String = format!(
            "fn1:{}:{}",
            hash.to_ascii_uppercase(),
            address.to_ascii_uppercase()
        );
        let first: XrefsOut = xrefs(xref_fixture_params(uppercase, None)).expect("first page");
        assert!(first.truncated);
        let cursor: String = first.next_cursor.expect("xref continuation");
        let second: XrefsOut = xrefs(xref_fixture_params(canonical, Some(cursor)))
            .expect("canonical id must replay uppercase request cursor");
        assert!(!second.xrefs.is_empty());
    }

    #[test]
    fn oversized_single_row_returns_typed_error_instead_of_replaying_a_cursor() {
        let source_hash: [u8; 32] = [0x46u8; 32];
        let candidates: Vec<FunctionIdentityOut> = (0..MAX_AMBIGUOUS_CANDIDATES)
            .map(|index: usize| FunctionIdentityOut {
                id: FunctionId::new(source_hash, u64::try_from(index).unwrap_or_default())
                    .to_string(),
                name: "x".repeat(MAX_OUTPUT_TEXT_BYTES),
                address: u64::try_from(index).unwrap_or_default(),
            })
            .collect();
        let mut response: CallGraphOut = CallGraphOut {
            schema: "disrobe.mcp.call-graph/v1".to_owned(),
            source_hash: hex32(&source_hash),
            token_budget: MIN_TOKEN_BUDGET,
            tokenizer: TOKENIZER.to_owned(),
            budget_measure: BUDGET_MEASURE.to_owned(),
            total_functions: 1,
            total_calls: 1,
            functions: Vec::new(),
            calls: Vec::new(),
            truncated: true,
            next_cursor: Some("same-cursor".to_owned()),
        };
        let row: NavigationCallOut = NavigationCallOut {
            caller_id: FunctionId::new(source_hash, 0).to_string(),
            caller_name: "x".repeat(MAX_OUTPUT_TEXT_BYTES),
            caller_address: 0,
            call_site: 0,
            outcome: CallOutcomeOut::AmbiguousFunction {
                target_address: 1,
                candidates,
                omitted_candidates: 0,
            },
        };
        let error: ErrorData = append_bounded_row(
            &mut response,
            row,
            MIN_TOKEN_BUDGET,
            17,
            17,
            "call-graph",
            |output: &mut CallGraphOut, value: NavigationCallOut| output.calls.push(value),
            |output: &mut CallGraphOut| {
                let _: Option<NavigationCallOut> = output.calls.pop();
            },
        )
        .expect_err("oversized first row must fail");
        assert!(response.calls.is_empty());
        assert!(
            error.message.contains("DR-MCP-0662"),
            "oversized row must not return the same continuation forever: {}",
            error.message
        );
        assert!(error.message.contains("serialized UTF-8 ceiling"));
    }
}
