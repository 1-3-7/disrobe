#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeSet;
use std::io::Write as _;
use std::process::{Child, ChildStdin, Command, Output, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use disrobe_ir::payload::{DisasmPayload, encode_disasm};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SectionKind, SymbolKind};
use rmcp::ServiceExt as _;
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use rmcp::{RoleClient, ServiceError};
use serde_json::{Map, Value};

type Client = RunningService<RoleClient, ()>;

const ATOMIC_WAIT_NOTIFY_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x02, 0x60, 0x03, 0x7f, 0x7f, 0x7e,
    0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x03, 0x02, 0x00, 0x01, 0x05, 0x04, 0x01,
    0x03, 0x01, 0x01, 0x07, 0x13, 0x02, 0x06, 0x77, 0x61, 0x69, 0x74, 0x33, 0x32, 0x00, 0x00, 0x06,
    0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x00, 0x01, 0x0a, 0x19, 0x02, 0x0c, 0x00, 0x20, 0x00, 0x20,
    0x01, 0x20, 0x02, 0xfe, 0x01, 0x02, 0x00, 0x0b, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0xfe, 0x00,
    0x02, 0x00, 0x0b,
];

fn server_command() -> tokio::process::Command {
    let mut cmd: tokio::process::Command =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_disrobe-mcp"));
    cmd.kill_on_drop(true);
    cmd
}

async fn connect() -> Client {
    let transport: TokioChildProcess =
        TokioChildProcess::new(server_command()).expect("spawn disrobe-mcp over piped stdio");
    ().serve(transport)
        .await
        .expect("JSON-RPC initialize handshake with disrobe-mcp")
}

fn args(pairs: &[(&str, Value)]) -> Map<String, Value> {
    let mut map: Map<String, Value> = Map::new();
    for (k, v) in pairs {
        map.insert((*k).to_owned(), v.clone());
    }
    map
}

async fn call(
    client: &Client,
    tool: &'static str,
    arguments: Map<String, Value>,
) -> CallToolResult {
    let params: CallToolRequestParams = CallToolRequestParams::new(tool).with_arguments(arguments);
    let result: CallToolResult = client
        .call_tool(params)
        .await
        .unwrap_or_else(|e: ServiceError| panic!("tools/call {tool} over stdio failed: {e}"));
    assert_ne!(
        result.is_error,
        Some(true),
        "tools/call {tool} returned an error result: {result:?}"
    );
    result
}

fn structured(result: &CallToolResult) -> Value {
    result
        .structured_content
        .clone()
        .expect("tool result must carry structured_content")
}

fn navigation_structured(result: &CallToolResult) -> Value {
    let value: Value = structured(result);
    let mirrored: &str = result
        .content
        .as_slice()
        .first()
        .and_then(|content: &rmcp::model::Content| content.raw.as_text())
        .map(|text: &rmcp::model::RawTextContent| text.text.as_str())
        .expect("navigation output must mirror structured content as text");
    assert_eq!(
        serde_json::from_str::<Value>(mirrored).expect("mirrored navigation JSON"),
        value
    );
    let budget: usize = value
        .get("token_budget")
        .and_then(Value::as_u64)
        .and_then(|raw: u64| usize::try_from(raw).ok())
        .expect("navigation response token budget");
    let encoded: Vec<u8> = serde_json::to_vec(result).expect("serialize complete tool result");
    assert!(
        encoded.len() <= budget,
        "complete tool result {} exceeds declared UTF-8 byte budget {budget}",
        encoded.len()
    );
    value
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected string field `{key}` in {value}"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("expected integer field `{key}` in {value}"))
}

fn navigation_envelope(native: &[u8]) -> Vec<u8> {
    let payload: DisasmPayload =
        disrobe_pass_native::build_disasm_payload(native).expect("analyse committed native image");
    let hot: Vec<u8> = encode_disasm(&payload).expect("encode analysed disassembly");
    disrobe_ir::Envelope::new(disrobe_ir::Rung::Disasm, hot, Vec::new())
        .encode()
        .expect("encode navigation envelope")
}

fn executable_sections(elf: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let file: object::File<'_> = object::File::parse(elf).expect("parse ELF");
    file.sections()
        .filter(|section: &object::Section<'_, '_>| section.kind() == SectionKind::Text)
        .map(|section: object::Section<'_, '_>| {
            (
                section.address(),
                section.data().expect("read executable section").to_vec(),
            )
        })
        .collect()
}

fn validated_text_symbol_extent(
    file: &object::File<'_>,
    symbol: &object::Symbol<'_, '_>,
) -> Option<(object::SectionIndex, usize, usize)> {
    if symbol.kind() != SymbolKind::Text || symbol.address() == 0 || symbol.size() == 0 {
        return None;
    }
    let section_index: object::SectionIndex = symbol.section_index()?;
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    if section.kind() != SectionKind::Text {
        return None;
    }
    let data: &[u8] = section.data().ok()?;
    let relative: u64 = symbol.address().checked_sub(section.address())?;
    let start: usize = usize::try_from(relative).ok()?;
    let size: usize = usize::try_from(symbol.size()).ok()?;
    let end: usize = start.checked_add(size)?;
    data.get(start..end)?;
    Some((section_index, start, end))
}

fn toolchain_direct_edges(unstripped_elf: &[u8]) -> BTreeSet<(u64, u64, u64, &'static str)> {
    let file: object::File<'_> = object::File::parse(unstripped_elf).expect("parse reference ELF");
    let function_starts: BTreeSet<u64> = file
        .symbols()
        .filter(|symbol: &object::Symbol<'_, '_>| {
            validated_text_symbol_extent(&file, symbol).is_some()
        })
        .map(|symbol: object::Symbol<'_, '_>| symbol.address())
        .collect();
    let mut edges: BTreeSet<(u64, u64, u64, &'static str)> = BTreeSet::new();
    for symbol in file.symbols() {
        let Some((section_index, start, end)): Option<(object::SectionIndex, usize, usize)> =
            validated_text_symbol_extent(&file, &symbol)
        else {
            continue;
        };
        let section: object::Section<'_, '_> = file
            .section_by_index(section_index)
            .expect("resolve function section");
        let data: &[u8] = section.data().expect("read function section");
        let bytes: &[u8] = data.get(start..end).expect("function bytes fit section");
        let mut decoder: Decoder<'_> =
            Decoder::with_ip(64, bytes, symbol.address(), DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction: Instruction = decoder.decode();
            let direct_call: bool = instruction.flow_control() == FlowControl::Call
                && matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                );
            if !direct_call {
                continue;
            }
            let target: u64 = instruction.near_branch_target();
            if function_starts.contains(&target) {
                edges.insert((symbol.address(), instruction.ip(), target, "function-start"));
            }
        }
    }
    edges
}

fn assert_budget(value: &Value, budget: usize) {
    let encoded: Vec<u8> = serde_json::to_vec(value).expect("serialize structured result");
    assert!(
        encoded.len() <= budget,
        "serialized response {} exceeds declared UTF-8 byte budget {budget}: {value}",
        encoded.len()
    );
    assert_eq!(
        value.get("token_budget").and_then(Value::as_u64),
        Some(budget as u64)
    );
    assert_eq!(
        value.get("budget_measure").and_then(Value::as_str),
        Some("complete-call-tool-result-serialized-utf8-bytes")
    );
    assert_eq!(
        value.get("tokenizer").and_then(Value::as_str),
        Some("o200k_base")
    );
}

fn o200k_token_count<T: serde::Serialize>(value: &T) -> usize {
    let encoded: Vec<u8> = serde_json::to_vec(value).expect("serialize tokenizer input");
    let script: &str = "import sys,tiktoken;text=sys.stdin.buffer.read().decode('utf-8');print(len(tiktoken.get_encoding('o200k_base').encode_ordinary(text)))";
    let mut child: Child = Command::new("uv")
        .args([
            "run",
            "--isolated",
            "--with",
            "tiktoken==0.11.0",
            "python",
            "-c",
            script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pinned o200k_base tokenizer through uv");
    let mut stdin: ChildStdin = child.stdin.take().expect("tokenizer stdin");
    stdin
        .write_all(&encoded)
        .expect("send structured response to tokenizer");
    drop(stdin);
    let output: Output = child.wait_with_output().expect("wait for tokenizer");
    assert!(
        output.status.success(),
        "o200k_base tokenizer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let count: String = String::from_utf8(output.stdout).expect("tokenizer count is UTF-8");
    count.trim().parse().expect("tokenizer count is an integer")
}

#[tokio::test]
async fn initialize_advertises_real_analysis_tools_over_stdio() {
    let client: Client = connect().await;

    let info: &rmcp::model::ServerInfo = client
        .peer_info()
        .expect("server must return ServerInfo from the initialize handshake");
    assert!(
        info.capabilities.tools.is_some(),
        "server must advertise the tools capability"
    );

    let tools: Vec<Tool> = client
        .list_all_tools()
        .await
        .expect("tools/list over stdio");
    let names: Vec<&str> = tools.iter().map(|t: &Tool| t.name.as_ref()).collect();
    for expected in ["ioc", "strings", "behavior", "verify"] {
        assert!(
            names.contains(&expected),
            "missing tool {expected} in {names:?}"
        );
    }

    client.cancel().await.expect("graceful client shutdown");
}

#[cfg(feature = "wasm")]
#[tokio::test]
async fn wasm_lift_returns_atomic_wait_and_notify_source_over_stdio() {
    let client: Client = connect().await;
    let result: CallToolResult = call(
        &client,
        "wasm_lift",
        args(&[
            (
                "bytes_b64",
                Value::String(BASE64_STANDARD.encode(ATOMIC_WAIT_NOTIFY_WASM)),
            ),
            ("target", Value::String("typescript".to_owned())),
        ]),
    )
    .await;
    let value: Value = structured(&result);
    let source: &str = str_field(&value, "source");

    assert_eq!(str_field(&value, "schema"), "disrobe.wasm.lift/v1");
    assert_eq!(str_field(&value, "target"), "typescript");
    assert_eq!(u64_field(&value, "function_count"), 2);
    assert_eq!(value["coverage"]["fully_recovered"], Value::Bool(true));
    assert!(source.contains("wasmMemoryAtomicWait32"));
    assert!(source.contains("wasmMemoryAtomicNotify"));
    assert!(source.contains("Atomics.wait"));
    assert!(source.contains("Atomics.notify"));
}

#[tokio::test]
async fn ioc_tool_call_returns_correct_indicators_over_stdio() {
    let client: Client = connect().await;

    let payload: &[u8] = b"beacon to https://c2.evil.example/gate.php then 198.51.100.23 fallback";
    let b64: String = BASE64_STANDARD.encode(payload);
    let result: CallToolResult =
        call(&client, "ioc", args(&[("bytes_b64", Value::String(b64))])).await;

    let out: Value = structured(&result);
    assert_eq!(
        u64_field(&out, "byte_len"),
        payload.len() as u64,
        "the server analyzed the exact bytes we sent over the wire"
    );
    let indicators: &Vec<Value> = out
        .get("indicators")
        .and_then(Value::as_array)
        .expect("indicators array");
    let kinds: Vec<&str> = indicators
        .iter()
        .map(|i: &Value| str_field(i, "kind"))
        .collect();
    assert!(
        kinds.contains(&"url"),
        "expected a url indicator, got {kinds:?}"
    );
    assert!(
        kinds.contains(&"ipv4"),
        "expected an ipv4 indicator, got {kinds:?}"
    );
    assert!(
        indicators
            .iter()
            .any(|i: &Value| str_field(i, "value").contains("c2.evil.example")),
        "the recovered url must be the one we sent: {indicators:?}"
    );
    assert!(
        indicators
            .iter()
            .any(|i: &Value| str_field(i, "value") == "198.51.100.23"),
        "the recovered ipv4 must be the one we sent: {indicators:?}"
    );

    client.cancel().await.expect("graceful client shutdown");
}

#[tokio::test]
async fn strings_tool_call_extracts_payload_over_stdio() {
    let client: Client = connect().await;

    let payload: &[u8] = b"\x00\x01ab\x00mcp_protocol_roundtrip_marker_string\x00\xff";
    let b64: String = BASE64_STANDARD.encode(payload);
    let result: CallToolResult = call(
        &client,
        "strings",
        args(&[
            ("bytes_b64", Value::String(b64)),
            ("min_len", Value::from(8u64)),
            ("decode", Value::Bool(false)),
        ]),
    )
    .await;

    let out: Value = structured(&result);
    assert_eq!(u64_field(&out, "min_len"), 8);
    assert_eq!(u64_field(&out, "byte_len"), payload.len() as u64);
    let strings: &Vec<Value> = out
        .get("strings")
        .and_then(Value::as_array)
        .expect("strings array");
    assert!(
        strings
            .iter()
            .any(|s: &Value| str_field(s, "value").contains("mcp_protocol_roundtrip_marker_string")),
        "the marker string we sent must come back: {strings:?}"
    );
    assert!(
        strings
            .iter()
            .all(|s: &Value| str_field(s, "value") != "ab"),
        "min_len=8 must filter the short run"
    );

    client.cancel().await.expect("graceful client shutdown");
}

#[tokio::test]
async fn verify_tool_call_round_trips_a_real_envelope_over_stdio() {
    let env: disrobe_ir::Envelope =
        disrobe_ir::Envelope::new(disrobe_ir::Rung::Disasm, vec![9, 8, 7, 6, 5], vec![4, 3, 2]);
    let encoded: Vec<u8> = env.encode().expect("encode envelope");
    let b64: String = BASE64_STANDARD.encode(&encoded);

    let client: Client = connect().await;
    let result: CallToolResult = call(
        &client,
        "verify",
        args(&[("bytes_b64", Value::String(b64))]),
    )
    .await;

    let out: Value = structured(&result);
    assert_eq!(out.get("verified").and_then(Value::as_bool), Some(true));
    assert_eq!(u64_field(&out, "hot_bytes"), 5);
    assert_eq!(u64_field(&out, "cold_bytes"), 3);
    assert_eq!(str_field(&out, "rung"), "Disasm");

    client.cancel().await.expect("graceful client shutdown");
}

#[tokio::test]
async fn invalid_base64_tool_call_surfaces_a_protocol_error_over_stdio() {
    let client: Client = connect().await;

    let params: CallToolRequestParams =
        CallToolRequestParams::new("ioc").with_arguments(args(&[(
            "bytes_b64",
            Value::String("@@@not-base64@@@".to_owned()),
        )]));
    let err: ServiceError = client
        .call_tool(params)
        .await
        .expect_err("garbage base64 must come back as a JSON-RPC error, not a success result");
    let ServiceError::McpError(data) = err else {
        panic!("expected an McpError from the server, got {err:?}");
    };
    assert!(
        data.message.contains("DR-MCP-0181"),
        "the server's invalid-base64 error must travel back over the wire: {}",
        data.message
    );

    client.cancel().await.expect("graceful client shutdown");
}

#[tokio::test]
async fn navigation_tools_round_trip_a_committed_stripped_elf_over_stdio() {
    const REAL_ELF: &[u8] = include_bytes!("../../../corpus/native/discovery/disc.stripped.elf");
    const TOOLCHAIN_REFERENCE_ELF: &[u8] =
        include_bytes!("../../../corpus/native/discovery/disc.unstripped.elf");
    const BUDGET: usize = 16_384;

    assert_ne!(REAL_ELF, TOOLCHAIN_REFERENCE_ELF);
    assert!(REAL_ELF.len() < TOOLCHAIN_REFERENCE_ELF.len());
    assert_eq!(
        executable_sections(REAL_ELF),
        executable_sections(TOOLCHAIN_REFERENCE_ELF),
        "stripped subject and unstripped reference must contain identical executable sections"
    );
    let twin_direct_edges: BTreeSet<(u64, u64, u64, &str)> =
        toolchain_direct_edges(TOOLCHAIN_REFERENCE_ELF);
    let dr: Vec<u8> = navigation_envelope(REAL_ELF);
    let bytes_b64: String = BASE64_STANDARD.encode(&dr);
    let client: Client = connect().await;
    let graph_result: CallToolResult = call(
        &client,
        "call_graph",
        args(&[
            ("bytes_b64", Value::String(bytes_b64.clone())),
            ("token_budget", Value::from(BUDGET as u64)),
        ]),
    )
    .await;
    let graph: Value = navigation_structured(&graph_result);
    assert_budget(&graph, BUDGET);
    let functions: &Vec<Value> = graph
        .get("functions")
        .and_then(Value::as_array)
        .expect("function summaries");
    assert!(
        !functions.is_empty(),
        "real ELF must expose functions: {graph}"
    );
    let first_id: String = str_field(&functions[0], "id").to_owned();

    let graph_again: Value = navigation_structured(
        &call(
            &client,
            "call_graph",
            args(&[
                ("bytes_b64", Value::String(bytes_b64.clone())),
                ("token_budget", Value::from(BUDGET as u64)),
            ]),
        )
        .await,
    );
    let first_id_again: &str = graph_again
        .get("functions")
        .and_then(Value::as_array)
        .and_then(|rows: &Vec<Value>| rows.first())
        .map(|row: &Value| str_field(row, "id"))
        .expect("repeat function id");
    assert_eq!(first_id_again, first_id);

    let calls: &Vec<Value> = graph
        .get("calls")
        .and_then(Value::as_array)
        .expect("call rows");
    let observed_direct_edges: BTreeSet<(u64, u64, u64, &str)> = calls
        .iter()
        .filter_map(|row: &Value| {
            let caller_address: u64 = row.get("caller_address")?.as_u64()?;
            let call_site: u64 = row.get("call_site")?.as_u64()?;
            let outcome: &Value = row.get("outcome")?;
            let kind: &str = outcome.get("kind")?.as_str()?;
            let target: u64 = match kind {
                "function-start" | "symbol" | "unresolved" => outcome.get("address")?.as_u64()?,
                "function-interior" | "ambiguous-function" => {
                    outcome.get("target_address")?.as_u64()?
                }
                "indirect" => return None,
                unexpected => panic!("unexpected call outcome kind {unexpected}"),
            };
            Some((caller_address, call_site, target, kind))
        })
        .collect();
    let toolchain_direct_edges: BTreeSet<(u64, u64, u64, &str)> = [
        (0x20_1160, 0x20_1161, 0x20_1180, "function-start"),
        (0x20_1180, 0x20_1186, 0x20_11b0, "function-start"),
        (0x20_1180, 0x20_118f, 0x20_11e0, "function-start"),
        (0x20_1180, 0x20_119b, 0x20_11f0, "function-start"),
        (0x20_11b0, 0x20_11c4, 0x20_1240, "function-start"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        twin_direct_edges, toolchain_direct_edges,
        "the pinned grade inventory must remain derived from the committed unstripped twin"
    );
    let false_positive_count: usize = observed_direct_edges.difference(&twin_direct_edges).count();
    let false_negative_count: usize = twin_direct_edges.difference(&observed_direct_edges).count();
    assert_eq!(false_positive_count, 0, "unexpected direct-call edges");
    assert_eq!(false_negative_count, 0, "missing direct-call edges");
    let precision_numerator: usize = observed_direct_edges.len() - false_positive_count;
    let precision_denominator: usize = observed_direct_edges.len();
    let recall_numerator: usize = twin_direct_edges.len() - false_negative_count;
    let recall_denominator: usize = twin_direct_edges.len();
    assert_eq!(
        (precision_numerator, precision_denominator),
        (5, 5),
        "precision"
    );
    assert_eq!((recall_numerator, recall_denominator), (5, 5), "recall");
    assert_eq!(
        observed_direct_edges, toolchain_direct_edges,
        "stripped subject must match direct-call addresses and classifications derived from its committed unstripped toolchain twin"
    );
    let xref_id: String = calls
        .iter()
        .find_map(|row: &Value| {
            let outcome: &Value = row.get("outcome")?;
            let kind: &str = outcome.get("kind")?.as_str()?;
            matches!(kind, "function-start" | "function-interior")
                .then(|| outcome.get("function_id")?.as_str().map(str::to_owned))
                .flatten()
        })
        .expect("real ELF must have a resolved direct call");

    let summary: Value = navigation_structured(
        &call(
            &client,
            "function_summary",
            args(&[
                ("bytes_b64", Value::String(bytes_b64.clone())),
                ("function_id", Value::String(first_id.clone())),
                ("token_budget", Value::from(BUDGET as u64)),
            ]),
        )
        .await,
    );
    assert_budget(&summary, BUDGET);
    assert_eq!(
        summary
            .get("function")
            .map(|row: &Value| str_field(row, "id")),
        Some(first_id.as_str())
    );

    let xrefs: Value = navigation_structured(
        &call(
            &client,
            "xrefs",
            args(&[
                ("bytes_b64", Value::String(bytes_b64.clone())),
                ("function_id", Value::String(xref_id.clone())),
                ("token_budget", Value::from(BUDGET as u64)),
            ]),
        )
        .await,
    );
    assert_budget(&xrefs, BUDGET);
    assert!(
        xrefs
            .get("xrefs")
            .and_then(Value::as_array)
            .is_some_and(|rows: &Vec<Value>| !rows.is_empty()),
        "resolved call target must have an xref: {xrefs}"
    );
    assert!(
        xrefs
            .get("xrefs")
            .and_then(Value::as_array)
            .is_some_and(|rows: &Vec<Value>| {
                rows.iter().all(|row: &Value| {
                    row.get("from_function_id")
                        .and_then(Value::as_str)
                        .is_some_and(|id: &str| id.starts_with("fn1:"))
                })
            }),
        "xref rows inside functions must expose stable source ids: {xrefs}"
    );

    let neighborhood: Value = navigation_structured(
        &call(
            &client,
            "neighborhood",
            args(&[
                ("bytes_b64", Value::String(bytes_b64.clone())),
                ("entry_ids", Value::Array(vec![Value::String(xref_id)])),
                ("depth", Value::from(8u64)),
                ("direction", Value::String("both".to_owned())),
                ("token_budget", Value::from(BUDGET as u64)),
            ]),
        )
        .await,
    );
    assert_budget(&neighborhood, BUDGET);
    assert!(
        neighborhood
            .get("functions")
            .and_then(Value::as_array)
            .is_some_and(|rows: &Vec<Value>| !rows.is_empty()),
        "neighborhood must retain its entry: {neighborhood}"
    );

    client.cancel().await.expect("graceful client shutdown");
}

#[tokio::test]
async fn same_address_ids_returned_by_call_graph_are_accepted_by_summary() {
    const BUDGET: usize = 8_192;
    let source: disrobe_nir::SourceRef =
        disrobe_nir::SourceRef::new(disrobe_nir::SourceLang::NativeX86, 0x40);
    let module: disrobe_nir::NirModule = disrobe_nir::NirModule {
        source_hash: [0x63u8; 32],
        lang: disrobe_nir::SourceLang::NativeX86,
        functions: vec![
            disrobe_nir::NirFunction {
                address: 0x40,
                name: "first".to_owned(),
                end: 0x40,
                is_export: false,
                instructions: Vec::new(),
                source: source.clone(),
            },
            disrobe_nir::NirFunction {
                address: 0x40,
                name: "second".to_owned(),
                end: 0x41,
                is_export: false,
                instructions: Vec::new(),
                source,
            },
        ],
        symbols: Vec::new(),
    };
    let hot: Vec<u8> = disrobe_nir::encode_nir(&module).expect("encode same-address NIR");
    let dr: Vec<u8> = disrobe_ir::Envelope::new(disrobe_ir::Rung::Mir, hot, Vec::new())
        .encode()
        .expect("encode same-address envelope");
    let bytes_b64: String = BASE64_STANDARD.encode(dr);
    let client: Client = connect().await;
    let graph_result: CallToolResult = call(
        &client,
        "call_graph",
        args(&[
            ("bytes_b64", Value::String(bytes_b64.clone())),
            ("token_budget", Value::from(BUDGET as u64)),
        ]),
    )
    .await;
    let graph: Value = navigation_structured(&graph_result);
    let ids: Vec<String> = graph
        .get("functions")
        .and_then(Value::as_array)
        .expect("same-address summaries")
        .iter()
        .map(|row: &Value| str_field(row, "id").to_owned())
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    for id in ids {
        let result: CallToolResult = call(
            &client,
            "function_summary",
            args(&[
                ("bytes_b64", Value::String(bytes_b64.clone())),
                ("function_id", Value::String(id)),
                ("token_budget", Value::from(BUDGET as u64)),
            ]),
        )
        .await;
        let _: Value = navigation_structured(&result);
    }
    client.cancel().await.expect("graceful client shutdown");
}

#[tokio::test]
async fn call_graph_budget_and_cursor_hold_on_a_committed_large_image() {
    const REAL_NIM_ELF: &[u8] = include_bytes!("../../../corpus/native/nim/hello.nim.elf");
    const BUDGET: usize = 2_048;

    let dr: Vec<u8> = navigation_envelope(REAL_NIM_ELF);
    let bytes_b64: String = BASE64_STANDARD.encode(&dr);
    let client: Client = connect().await;
    let first_result: CallToolResult = call(
        &client,
        "call_graph",
        args(&[
            ("bytes_b64", Value::String(bytes_b64.clone())),
            ("token_budget", Value::from(BUDGET as u64)),
        ]),
    )
    .await;
    let first: Value = navigation_structured(&first_result);
    assert_budget(&first, BUDGET);
    assert_eq!(first.get("truncated").and_then(Value::as_bool), Some(true));
    let cursor: String = str_field(&first, "next_cursor").to_owned();
    let second: Value = navigation_structured(
        &call(
            &client,
            "call_graph",
            args(&[
                ("bytes_b64", Value::String(bytes_b64)),
                ("token_budget", Value::from(BUDGET as u64)),
                ("cursor", Value::String(cursor.clone())),
            ]),
        )
        .await,
    );
    assert_budget(&second, BUDGET);
    assert_ne!(
        second.get("next_cursor").and_then(Value::as_str),
        Some(cursor.as_str())
    );

    client.cancel().await.expect("graceful client shutdown");
}

#[tokio::test]
#[ignore = "requires uv and PyPI; run explicitly for the external tokenizer gate"]
async fn o200k_tokenizer_confirms_large_image_response_budget() {
    const REAL_NIM_ELF: &[u8] = include_bytes!("../../../corpus/native/nim/hello.nim.elf");
    const BUDGET: usize = 2_048;

    let dr: Vec<u8> = navigation_envelope(REAL_NIM_ELF);
    let bytes_b64: String = BASE64_STANDARD.encode(&dr);
    let client: Client = connect().await;
    let first_result: CallToolResult = call(
        &client,
        "call_graph",
        args(&[
            ("bytes_b64", Value::String(bytes_b64.clone())),
            ("token_budget", Value::from(BUDGET as u64)),
        ]),
    )
    .await;
    let first: Value = navigation_structured(&first_result);
    let cursor: String = str_field(&first, "next_cursor").to_owned();
    let second_result: CallToolResult = call(
        &client,
        "call_graph",
        args(&[
            ("bytes_b64", Value::String(bytes_b64.clone())),
            ("token_budget", Value::from(BUDGET as u64)),
            ("cursor", Value::String(cursor)),
        ]),
    )
    .await;
    let _: Value = navigation_structured(&second_result);
    let function_id: String = first
        .get("functions")
        .and_then(Value::as_array)
        .and_then(|rows: &Vec<Value>| rows.first())
        .map(|row: &Value| str_field(row, "id").to_owned())
        .expect("large image function id");
    let summary_result: CallToolResult = call(
        &client,
        "function_summary",
        args(&[
            ("bytes_b64", Value::String(bytes_b64.clone())),
            ("function_id", Value::String(function_id.clone())),
            ("token_budget", Value::from(BUDGET as u64)),
        ]),
    )
    .await;
    let _: Value = navigation_structured(&summary_result);
    let xrefs_result: CallToolResult = call(
        &client,
        "xrefs",
        args(&[
            ("bytes_b64", Value::String(bytes_b64.clone())),
            ("function_id", Value::String(function_id.clone())),
            ("token_budget", Value::from(BUDGET as u64)),
        ]),
    )
    .await;
    let _: Value = navigation_structured(&xrefs_result);
    let neighborhood_result: CallToolResult = call(
        &client,
        "neighborhood",
        args(&[
            ("bytes_b64", Value::String(bytes_b64)),
            ("entry_ids", Value::Array(vec![Value::String(function_id)])),
            ("depth", Value::from(8u64)),
            ("direction", Value::String("both".to_owned())),
            ("token_budget", Value::from(BUDGET as u64)),
        ]),
    )
    .await;
    let _: Value = navigation_structured(&neighborhood_result);
    let token_counts: Vec<(&str, usize)> = [
        ("call_graph[0]", &first_result),
        ("call_graph[1]", &second_result),
        ("function_summary", &summary_result),
        ("xrefs", &xrefs_result),
        ("neighborhood", &neighborhood_result),
    ]
    .into_iter()
    .map(|(tool, value): (&str, &CallToolResult)| (tool, o200k_token_count(value)))
    .collect();
    for (tool, tokens) in &token_counts {
        assert!(
            *tokens <= BUDGET,
            "o200k_base counted {tokens} tokens for {tool} above the declared {BUDGET}-token budget"
        );
    }
    println!("o200k_base tool token counts {token_counts:?} under budget {BUDGET}");

    client.cancel().await.expect("graceful client shutdown");
}
