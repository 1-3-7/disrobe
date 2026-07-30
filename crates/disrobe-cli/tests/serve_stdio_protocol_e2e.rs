#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};

use common::StdioServer;

mod common;

const LSP_ADVERTISED_METHODS: [&str; 2] = ["disrobe/analyze", "disrobe/explain"];

const MCP_TOOL_NAMES: [&str; 9] = [
    "annot",
    "auto",
    "behavior",
    "decompile",
    "ioc",
    "provenance_lookup",
    "rename",
    "strings",
    "verify",
];

const MCP_CLIENT_PROTOCOL: &str = "2025-06-18";

const LOG_LEVEL_THAT_MUST_STAY_OFF_THE_PROTOCOL_STREAM: [(&str, &str); 1] = [("RUST_LOG", "info")];

const WASM_ACTION: &str = "Decompile { lang: Wasm }";
const WASM_REASON: &str = "wasm \\0asm magic detected";

fn wasm_probe(tail: &[u8]) -> Vec<u8> {
    let mut probe: Vec<u8> = common::minimal_wasm();
    probe.extend_from_slice(tail);
    probe
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn wire_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("a probe payload length fits in u64")
}

fn spawn_lsp() -> StdioServer {
    StdioServer::spawn(
        "disrobe serve --stdio",
        &["serve", "--stdio"],
        &LOG_LEVEL_THAT_MUST_STAY_OFF_THE_PROTOCOL_STREAM,
    )
}

fn spawn_mcp() -> StdioServer {
    StdioServer::spawn(
        "disrobe serve --mcp",
        &["serve", "--mcp"],
        &LOG_LEVEL_THAT_MUST_STAY_OFF_THE_PROTOCOL_STREAM,
    )
}

fn lsp_frame(message: &Value) -> Vec<u8> {
    let body: String = serde_json::to_string(message).expect("serialize an lsp message");
    let mut framed: Vec<u8> = Vec::with_capacity(body.len() + 48);
    framed.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    framed.extend_from_slice(body.as_bytes());
    framed
}

fn read_lsp_message(server: &mut StdioServer) -> Value {
    let mut content_length: Option<usize> = None;
    loop {
        let raw: Vec<u8> = server.read_line_bytes();
        let header: String = String::from_utf8_lossy(&raw)
            .trim_end_matches(['\r', '\n'])
            .to_ascii_lowercase();
        if header.is_empty() {
            break;
        }
        if let Some(rest) = header.strip_prefix("content-length:") {
            let parsed: Result<usize, std::num::ParseIntError> = rest.trim().parse::<usize>();
            content_length = Some(match parsed {
                Ok(n) => n,
                Err(e) => panic!("Content-Length `{rest}` is not a byte count: {e}"),
            });
        } else {
            assert!(
                header.starts_with("content-type:"),
                "{}: stdout carried `{header}` where an LSP header belongs, so non-protocol output is contaminating the JSON-RPC stream",
                server.label()
            );
        }
    }
    let len: usize = content_length.unwrap_or_else(|| {
        panic!(
            "{}: an LSP message arrived with no Content-Length header",
            server.label()
        )
    });
    let body: Vec<u8> = server.read_exact_bytes(len);
    match serde_json::from_slice::<Value>(&body) {
        Ok(v) => v,
        Err(e) => panic!(
            "an LSP message body is not JSON: {e}; body={}",
            String::from_utf8_lossy(&body)
        ),
    }
}

fn lsp_round_trip(server: &mut StdioServer, id: u32, method: &str, params: Value) -> Value {
    let request: Value = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    server.send(&lsp_frame(&request));
    loop {
        let message: Value = read_lsp_message(server);
        let arrived: Option<u64> = message.get("id").and_then(Value::as_u64);
        if arrived == Some(u64::from(id)) {
            return message;
        }
        assert!(
            arrived.is_none(),
            "{}: expected the response to `{method}` id {id}, got id {arrived:?}: {message}",
            server.label()
        );
    }
}

fn lsp_result(response: &Value, method: &str) -> Value {
    assert!(
        response.get("error").is_none(),
        "`{method}` must not return a JSON-RPC error: {response}"
    );
    response
        .get("result")
        .unwrap_or_else(|| panic!("`{method}` returned neither a result nor an error: {response}"))
        .clone()
}

fn lsp_initialize(server: &mut StdioServer) -> Value {
    let response: Value = lsp_round_trip(
        server,
        1,
        "initialize",
        json!({
            "processId": Value::Null,
            "rootUri": Value::Null,
            "capabilities": {},
            "clientInfo": { "name": "disrobe-lsp-protocol-test", "version": "1" }
        }),
    );
    let result: Value = lsp_result(&response, "initialize");
    server.send(&lsp_frame(
        &json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    ));
    result
}

fn lsp_analyze(server: &mut StdioServer, id: u32, label: &str, payload: &[u8]) -> Value {
    let response: Value = lsp_round_trip(
        server,
        id,
        "disrobe/analyze",
        json!({ "bytes_b64": BASE64_STANDARD.encode(payload), "label": label }),
    );
    lsp_result(&response, "disrobe/analyze")
}

fn lsp_shutdown_and_exit(server: &mut StdioServer, id: u32) {
    let response: Value = lsp_round_trip(server, id, "shutdown", Value::Null);
    let result: Value = lsp_result(&response, "shutdown");
    assert_eq!(
        result,
        Value::Null,
        "the LSP spec requires a null result for `shutdown`: {result}"
    );
    server.send(&lsp_frame(&json!({ "jsonrpc": "2.0", "method": "exit" })));
    let code: i32 = server.wait_for_exit();
    assert_eq!(
        code,
        0,
        "`disrobe serve --stdio` must exit 0 after shutdown then exit, not linger until it is killed; stderr={}",
        server.stderr_text()
    );
}

fn mcp_send(server: &mut StdioServer, message: &Value) {
    let mut line: Vec<u8> = serde_json::to_vec(message).expect("serialize an mcp message");
    line.push(b'\n');
    server.send(&line);
}

fn mcp_read(server: &mut StdioServer, id: u32) -> Value {
    loop {
        let raw: Vec<u8> = server.read_line_bytes();
        let text: String = String::from_utf8_lossy(&raw).trim().to_owned();
        if text.is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str::<Value>(&text) {
            Ok(v) => v,
            Err(e) => panic!(
                "{}: stdout line `{text}` is not a JSON-RPC message, so non-protocol output is contaminating the MCP stream: {e}",
                server.label()
            ),
        };
        let arrived: Option<u64> = message.get("id").and_then(Value::as_u64);
        if arrived == Some(u64::from(id)) {
            return message;
        }
        assert!(
            arrived.is_none(),
            "{}: expected the response to id {id}, got id {arrived:?}: {message}",
            server.label()
        );
    }
}

fn mcp_initialize(server: &mut StdioServer) -> Value {
    mcp_send(
        server,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_CLIENT_PROTOCOL,
                "capabilities": {},
                "clientInfo": { "name": "disrobe-mcp-protocol-test", "version": "1" }
            }
        }),
    );
    let response: Value = mcp_read(server, 1);
    assert!(
        response.get("error").is_none(),
        "the MCP initialize handshake must not error: {response}"
    );
    let result: Value = response
        .get("result")
        .unwrap_or_else(|| panic!("the MCP initialize response carries no result: {response}"))
        .clone();
    mcp_send(
        server,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    result
}

fn mcp_call_tool(server: &mut StdioServer, id: u32, tool: &str, arguments: Value) -> Value {
    mcp_send(
        server,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }),
    );
    mcp_read(server, id)
}

fn mcp_structured(response: &Value, tool: &str) -> Value {
    assert!(
        response.get("error").is_none(),
        "`tools/call {tool}` must not return a JSON-RPC error: {response}"
    );
    assert_ne!(
        response.pointer("/result/isError").and_then(Value::as_bool),
        Some(true),
        "`tools/call {tool}` came back flagged as a tool error: {response}"
    );
    response
        .pointer("/result/structuredContent")
        .unwrap_or_else(|| panic!("`tools/call {tool}` returned no structuredContent: {response}"))
        .clone()
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected a string field `{key}` in {value}"))
        .to_owned()
}

#[test]
fn lsp_stdio_round_trips_a_framed_initialize_analyze_explain_shutdown_exchange() {
    let mut server: StdioServer = spawn_lsp();

    let init: Value = lsp_initialize(&mut server);
    assert_eq!(
        init.pointer("/serverInfo/name").and_then(Value::as_str),
        Some("disrobe-serve"),
        "an LSP client reads the server name at result.serverInfo.name, so it must not be nested elsewhere: {init}"
    );
    assert_eq!(
        init.pointer("/serverInfo/version").and_then(Value::as_str),
        Some(env!("CARGO_PKG_VERSION")),
        "the initialize result must carry the daemon version: {init}"
    );
    let mut advertised: Vec<String> = init
        .pointer("/capabilities/experimental/disrobe/methods")
        .and_then(Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "result.capabilities.experimental.disrobe.methods must be advertised where a client can find it: {init}"
            )
        })
        .iter()
        .map(|m: &Value| m.as_str().unwrap_or_default().to_owned())
        .collect();
    advertised.sort();
    assert_eq!(
        advertised,
        LSP_ADVERTISED_METHODS
            .iter()
            .map(|m: &&str| (*m).to_owned())
            .collect::<Vec<String>>(),
        "the advertised custom method set must equal the set exercised below, so an advertised-but-unimplemented method fails here"
    );

    let payload: Vec<u8> = wasm_probe(b"disrobe-lsp-analyze-probe");
    let analyzed: Value = lsp_analyze(&mut server, 2, "probe.wasm", &payload);
    assert_eq!(
        analyzed.get("label").and_then(Value::as_str),
        Some("probe.wasm"),
        "the analyze result must echo the label sent over the wire: {analyzed}"
    );
    assert_eq!(
        analyzed.get("bytes").and_then(Value::as_u64),
        Some(wire_len(&payload)),
        "the server must report the exact byte count it received: {analyzed}"
    );
    assert_eq!(
        analyzed.get("blake3").and_then(Value::as_str),
        Some(blake3_hex(&payload).as_str()),
        "the server must hash the exact bytes sent over the wire: {analyzed}"
    );
    assert_eq!(
        analyzed.get("action").and_then(Value::as_str),
        Some(WASM_ACTION),
        "a wasm payload must classify as a wasm decompile: {analyzed}"
    );
    assert_eq!(
        analyzed.get("reason").and_then(Value::as_str),
        Some(WASM_REASON),
        "the classification reason must travel back over the wire: {analyzed}"
    );

    let explained: Value = lsp_result(
        &lsp_round_trip(
            &mut server,
            3,
            "disrobe/explain",
            json!({ "code": "pyarm-0007" }),
        ),
        "disrobe/explain",
    );
    assert_eq!(
        explained.get("code").and_then(Value::as_str),
        Some("DR-PYARM-0007"),
        "the server must normalize a bare code to its DR- form: {explained}"
    );
    assert_eq!(
        explained.get("known").and_then(Value::as_bool),
        Some(true),
        "DR-PYARM-0007 is a registered code and must resolve: {explained}"
    );
    assert!(
        !string_field(&explained, "title").is_empty(),
        "a known code must come back with a non-empty title: {explained}"
    );

    let unsupported: Value = lsp_round_trip(&mut server, 4, "textDocument/hover", json!({}));
    assert_eq!(
        unsupported.pointer("/error/code").and_then(Value::as_i64),
        Some(-32_601),
        "an unimplemented method must come back as JSON-RPC MethodNotFound: {unsupported}"
    );

    lsp_shutdown_and_exit(&mut server, 5);
}

#[test]
fn mcp_stdio_round_trips_initialize_tools_list_and_a_real_tool_call() {
    let mut server: StdioServer = spawn_mcp();

    let init: Value = mcp_initialize(&mut server);
    assert_eq!(
        init.get("protocolVersion").and_then(Value::as_str),
        Some(MCP_CLIENT_PROTOCOL),
        "the server must negotiate down to the protocol version the client offered: {init}"
    );
    assert!(
        init.pointer("/capabilities/tools").is_some(),
        "the server must advertise the tools capability: {init}"
    );
    assert!(
        init.pointer("/serverInfo/name")
            .and_then(Value::as_str)
            .is_some_and(|name: &str| !name.is_empty()),
        "the initialize result must identify the server: {init}"
    );
    let instructions: String = string_field(&init, "instructions");
    assert!(
        instructions.contains("disrobe"),
        "the server instructions must describe the disrobe tool surface: {instructions}"
    );

    mcp_send(
        &mut server,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    let listed: Value = mcp_read(&mut server, 2);
    assert!(
        listed.pointer("/result/nextCursor").is_none(),
        "tools/list came back paginated, so the name set below is not the whole set: {listed}"
    );
    let tools: Vec<Value> = listed
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("tools/list returned no tools array: {listed}"))
        .clone();
    let mut names: Vec<String> = tools
        .iter()
        .map(|t: &Value| string_field(t, "name"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        MCP_TOOL_NAMES
            .iter()
            .map(|t: &&str| (*t).to_owned())
            .collect::<Vec<String>>(),
        "the advertised tool set must equal the published set exactly, so a dropped or renamed tool fails here"
    );
    for tool in &tools {
        assert!(
            !string_field(tool, "description").is_empty(),
            "every advertised tool needs a description an MCP client can show: {tool}"
        );
        assert!(
            tool.get("inputSchema").is_some(),
            "every advertised tool needs an inputSchema: {tool}"
        );
    }

    let payload: &[u8] =
        b"stage two beacons to https://c2.probe.example/gate.php and 198.51.100.23";
    let called: Value = mcp_call_tool(
        &mut server,
        3,
        "ioc",
        json!({ "bytes_b64": BASE64_STANDARD.encode(payload) }),
    );
    let out: Value = mcp_structured(&called, "ioc");
    assert_eq!(
        out.get("byte_len").and_then(Value::as_u64),
        Some(wire_len(payload)),
        "the server must have analyzed the exact bytes sent over the wire: {out}"
    );
    let indicators: Vec<Value> = out
        .get("indicators")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the ioc tool returned no indicators array: {out}"))
        .clone();
    let values: Vec<String> = indicators
        .iter()
        .map(|i: &Value| string_field(i, "value"))
        .collect();
    let kinds: Vec<String> = indicators
        .iter()
        .map(|i: &Value| string_field(i, "kind"))
        .collect();
    assert!(
        values
            .iter()
            .any(|v: &String| v.contains("c2.probe.example/gate.php")),
        "the full recovered url must come back unredacted and untruncated: {values:?}"
    );
    assert!(
        values.iter().any(|v: &String| v == "198.51.100.23"),
        "the recovered ipv4 must be the one sent: {values:?}"
    );
    assert!(
        kinds.iter().any(|k: &String| k == "url"),
        "expected a url indicator kind: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k: &String| k == "ipv4"),
        "expected an ipv4 indicator kind: {kinds:?}"
    );

    let rejected: Value = mcp_call_tool(
        &mut server,
        4,
        "ioc",
        json!({ "bytes_b64": "@@@not-base64@@@" }),
    );
    let message: String = rejected
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("garbage base64 must come back as a JSON-RPC error: {rejected}"))
        .to_owned();
    assert!(
        message.contains("DR-MCP-0181"),
        "the decode error the server raised must travel back over the wire: {message}"
    );

    let code: i32 = server.wait_for_exit();
    assert_eq!(
        code,
        0,
        "`disrobe serve --mcp` must exit 0 once the client closes stdin; stderr={}",
        server.stderr_text()
    );
}

#[test]
fn stdio_protocol_answers_bind_to_the_request_payload_on_both_surfaces() {
    let first: Vec<u8> = wasm_probe(b"control-payload-one");
    let second: Vec<u8> = wasm_probe(b"control-payload-two-is-longer");
    assert_ne!(
        first, second,
        "the control needs two distinct payloads to be worth running"
    );

    let mut lsp: StdioServer = spawn_lsp();
    let _: Value = lsp_initialize(&mut lsp);
    let one: Value = lsp_analyze(&mut lsp, 2, "one.wasm", &first);
    let two: Value = lsp_analyze(&mut lsp, 3, "two.wasm", &second);
    assert_eq!(
        one.get("blake3").and_then(Value::as_str),
        Some(blake3_hex(&first).as_str()),
        "lsp: the first answer must hash the first payload: {one}"
    );
    assert_eq!(
        two.get("blake3").and_then(Value::as_str),
        Some(blake3_hex(&second).as_str()),
        "lsp: the second answer must hash the second payload: {two}"
    );
    assert_ne!(
        one.get("blake3"),
        two.get("blake3"),
        "lsp: two different payloads produced one canned answer, so the analyze assertions above prove nothing"
    );
    assert_ne!(
        one.get("bytes"),
        two.get("bytes"),
        "lsp: the reported byte count did not follow the payload: one={one} two={two}"
    );
    lsp_shutdown_and_exit(&mut lsp, 4);

    let mut mcp: StdioServer = spawn_mcp();
    let _: Value = mcp_initialize(&mut mcp);
    let marker: &[u8] = b"reach https://control.one.example/a then 203.0.113.7 now";
    let other: &[u8] = b"reach https://control.two.example/b then 203.0.113.9 now";
    let one_out: Value = mcp_structured(
        &mcp_call_tool(
            &mut mcp,
            2,
            "ioc",
            json!({ "bytes_b64": BASE64_STANDARD.encode(marker) }),
        ),
        "ioc",
    );
    let two_out: Value = mcp_structured(
        &mcp_call_tool(
            &mut mcp,
            3,
            "ioc",
            json!({ "bytes_b64": BASE64_STANDARD.encode(other) }),
        ),
        "ioc",
    );
    let one_values: String = one_out
        .get("indicators")
        .map_or_else(String::new, ToString::to_string);
    let two_values: String = two_out
        .get("indicators")
        .map_or_else(String::new, ToString::to_string);
    assert!(
        one_values.contains("control.one.example") && one_values.contains("203.0.113.7"),
        "mcp: the first answer must carry the first payload's indicators: {one_values}"
    );
    assert!(
        two_values.contains("control.two.example") && two_values.contains("203.0.113.9"),
        "mcp: the second answer must carry the second payload's indicators: {two_values}"
    );
    assert!(
        !one_values.contains("control.two.example") && !two_values.contains("control.one.example"),
        "mcp: the two answers bled into each other, so the tool-call assertions above prove nothing: one={one_values} two={two_values}"
    );

    let code: i32 = mcp.wait_for_exit();
    assert_eq!(
        code,
        0,
        "mcp: the control session must also shut down cleanly; stderr={}",
        mcp.stderr_text()
    );
}
