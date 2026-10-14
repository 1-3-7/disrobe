#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_core::scratch::ScratchDir;
use rmcp::ServiceExt as _;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use rmcp::{RoleClient, ServiceError};
use serde_json::{Map, Value, json};

type Client = RunningService<RoleClient, ()>;

const ELF: &[u8] = include_bytes!("../../../corpus/native/discovery/disc.unstripped.elf");

async fn serve(root: &ScratchDir) -> Client {
    std::fs::write(root.path().join("disc.elf"), ELF).expect("stage fixture");
    let mut command: tokio::process::Command =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_disrobe-mcp"));
    command
        .current_dir(root.path())
        .env_remove("DISROBE_MCP_ROOTS")
        .kill_on_drop(true);
    let transport: TokioChildProcess =
        TokioChildProcess::new(command).expect("spawn disrobe-mcp over piped stdio");
    ().serve(transport).await.expect("initialize handshake")
}

async fn call_raw(
    client: &Client,
    tool: &'static str,
    arguments: Value,
) -> Result<CallToolResult, ServiceError> {
    let Value::Object(arguments) = arguments else {
        panic!("tool arguments must be an object");
    };
    let arguments: Map<String, Value> = arguments;
    client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(arguments))
        .await
}

async fn call(client: &Client, tool: &'static str, arguments: Value) -> Value {
    let result: CallToolResult = call_raw(client, tool, arguments)
        .await
        .unwrap_or_else(|error: ServiceError| panic!("tools/call {tool} failed: {error}"));
    assert_ne!(
        result.is_error,
        Some(true),
        "{tool} returned an error: {result:?}"
    );
    result.structured_content.expect("structured content")
}

async fn refusal(client: &Client, tool: &'static str, arguments: Value) -> String {
    match call_raw(client, tool, arguments).await {
        Err(error) => error.to_string(),
        Ok(result) => {
            assert_eq!(
                result.is_error,
                Some(true),
                "{tool} should refuse: {result:?}"
            );
            format!("{result:?}")
        }
    }
}

#[tokio::test]
async fn unknowns_stay_open_until_a_resolution_with_evidence_closes_them() {
    let root: ScratchDir = ScratchDir::create("mcp-notes").expect("scratch root");
    std::fs::create_dir_all(root.path().join(".disrobe")).expect("workspace");
    let client: Client = serve(&root).await;
    let opened: Value = call(&client, "open_target", json!({ "path": "disc.elf" })).await;
    let target_id: &str = opened["target_id"].as_str().expect("target id");

    let first: Value = call(
        &client,
        "add_note",
        json!({ "target_id": target_id, "kind": "unknown", "address": "0x201180", "text": "what does compute return for negative n" }),
    )
    .await;
    assert_eq!(first["open_unknowns"], json!([1]));
    let comment: Value = call(
        &client,
        "add_note",
        json!({ "target_id": target_id, "kind": "comment", "address": "0x201240", "text": "adds its two arguments" }),
    )
    .await;
    assert_eq!(comment["records"].as_array().expect("records").len(), 2);

    let unsupported: String = refusal(
        &client,
        "add_note",
        json!({ "target_id": target_id, "kind": "resolution", "resolves": 1, "text": "it returns zero" }),
    )
    .await;
    assert!(unsupported.contains("DR-MCP-0731"), "{unsupported}");
    let dangling: String = refusal(
        &client,
        "add_note",
        json!({ "target_id": target_id, "kind": "resolution", "resolves": 7, "text": "x", "evidence": "y" }),
    )
    .await;
    assert!(dangling.contains("DR-MCP-0731"), "{dangling}");

    let closed: Value = call(
        &client,
        "add_note",
        json!({
            "target_id": target_id,
            "kind": "resolution",
            "resolves": 1,
            "text": "sum_to never iterates for n <= 0, so compute returns dispatch(0, 0)",
            "evidence": "disassemble_function sum_to: the loop guard compares n against zero before the first add",
        }),
    )
    .await;
    assert_eq!(closed["open_unknowns"], json!([]));

    let comments: Value = call(
        &client,
        "list_notes",
        json!({ "target_id": target_id, "kind": "comment" }),
    )
    .await;
    assert_eq!(comments["records"].as_array().expect("records").len(), 1);

    let stored: Value = serde_json::from_slice(
        &std::fs::read(
            root.path()
                .join(".disrobe")
                .join("notes")
                .join("targets")
                .join(format!("{target_id}.json")),
        )
        .expect("notes file"),
    )
    .expect("notes JSON");
    assert_eq!(stored["schema"], json!("disrobe.target-notes/v1"));
    assert_eq!(stored["records"].as_array().expect("records").len(), 3);
    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn notes_need_an_open_target_and_a_workspace() {
    let root: ScratchDir = ScratchDir::create("mcp-notes-bare").expect("scratch root");
    let client: Client = serve(&root).await;
    let stale: String = refusal(
        &client,
        "add_note",
        json!({ "target_id": "0".repeat(64), "kind": "comment", "text": "x" }),
    )
    .await;
    assert!(stale.contains("DR-MCP-0707"), "{stale}");
    let opened: Value = call(&client, "open_target", json!({ "path": "disc.elf" })).await;
    let missing: String = refusal(
        &client,
        "add_note",
        json!({ "target_id": opened["target_id"], "kind": "comment", "text": "x" }),
    )
    .await;
    assert!(missing.contains("DR-MCP-0323"), "{missing}");
    client.cancel().await.expect("shutdown");
}
