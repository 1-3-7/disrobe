#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rmcp::ServiceExt as _;
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use rmcp::{RoleClient, ServiceError};
use serde_json::{Map, Value};

type Client = RunningService<RoleClient, ()>;

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
