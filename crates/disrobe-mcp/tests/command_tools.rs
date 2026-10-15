#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use rmcp::ServiceExt as _;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, GetPromptRequestParams, GetPromptResult, Prompt, Tool,
};
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use rmcp::{RoleClient, ServiceError};
use serde_json::{Map, Value, json};

type Client = RunningService<RoleClient, ()>;

const FIXTURE: &str = "native/discovery/disc.unstripped.elf";

struct Session {
    client: Client,
    root: ScratchDir,
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .canonicalize()
        .expect("committed corpus directory")
}

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(
        std::env::var_os("DISROBE_BIN")
            .expect("DISROBE_BIN must name the current disrobe binary built for this caller test"),
    );
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

async fn connect(mut command: tokio::process::Command, root: &Path) -> Client {
    command
        .current_dir(root)
        .env_remove("DISROBE_MCP_ROOTS")
        .kill_on_drop(true);
    let transport: TokioChildProcess =
        TokioChildProcess::new(command).expect("spawn the MCP server over piped stdio");
    ().serve(transport).await.expect("initialize handshake")
}

async fn session() -> Session {
    let root: ScratchDir = ScratchDir::create("mcp-command-tools").expect("scratch root");
    let mut command: tokio::process::Command = tokio::process::Command::new(disrobe_bin());
    command.arg("mcp").arg("--root").arg(corpus_dir());
    let client: Client = connect(command, root.path()).await;
    Session { client, root }
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

fn printable_runs(bytes: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut runs: Vec<(usize, String)> = Vec::new();
    let mut start: usize = 0;
    for (index, byte) in bytes.iter().chain(std::iter::once(&0)).enumerate() {
        if (0x20..0x7f).contains(byte) {
            continue;
        }
        if index - start >= min_len {
            runs.push((
                start,
                String::from_utf8_lossy(&bytes[start..index]).into_owned(),
            ));
        }
        start = index + 1;
    }
    runs
}

#[tokio::test]
async fn the_protocol_lists_command_target_tools_and_workflow_prompts() {
    let session: Session = session().await;
    let tools: Vec<Tool> = session.client.list_all_tools().await.expect("tools/list");
    let names: BTreeSet<&str> = tools.iter().map(|tool: &Tool| tool.name.as_ref()).collect();
    for expected in [
        "list_commands",
        "run_command",
        "open_target",
        "decompile_function",
    ] {
        assert!(
            names.contains(expected),
            "tools/list lacks {expected}: {names:?}"
        );
    }
    let prompts: Vec<Prompt> = session
        .client
        .list_all_prompts()
        .await
        .expect("prompts/list");
    let prompt_names: BTreeSet<&str> = prompts.iter().map(|p: &Prompt| p.name.as_str()).collect();
    assert_eq!(
        prompt_names,
        BTreeSet::from([
            "explain_function",
            "trace_feature",
            "triage",
            "unpack_and_decompile"
        ])
    );
    for prompt in &prompts {
        assert!(
            prompt.arguments.as_ref().is_some_and(|args| args
                .iter()
                .any(|arg| arg.name == "path" && arg.required == Some(true))),
            "{} takes a required path: {prompt:?}",
            prompt.name
        );
    }
    let mut arguments: Map<String, Value> = Map::new();
    arguments.insert("path".to_owned(), Value::from("sample.bin"));
    let triage: GetPromptResult = session
        .client
        .get_prompt(GetPromptRequestParams::new("triage").with_arguments(arguments))
        .await
        .expect("prompts/get triage");
    let text: String = serde_json::to_string(&triage.messages).unwrap();
    for tool in [
        "open_target",
        "target_layout",
        "find_strings",
        "behavior",
        "run_command",
    ] {
        assert!(
            names.contains(tool),
            "triage cites {tool}, which tools/list lacks"
        );
        assert!(text.contains(tool), "triage steps omit {tool}: {text}");
    }
    assert!(text.contains("sample.bin"));
}

#[tokio::test]
async fn list_commands_carries_the_read_only_allowlist() {
    let session: Session = session().await;
    let listing: Value = call(&session.client, "list_commands", json!({})).await;
    let commands: BTreeSet<String> = listing["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command: &Value| {
            command["command"]
                .as_array()
                .unwrap()
                .iter()
                .map(|word: &Value| word.as_str().unwrap())
                .collect::<Vec<&str>>()
                .join(" ")
        })
        .collect();
    for expected in [
        "strings",
        "identify",
        "auto",
        "native symbols",
        "py deob",
        "flutter identity",
        "macho nib",
        "macho keyed-archive",
        "resources",
        "electron",
        "crash",
        "capture",
        "dotnet interop",
        "evm decompile",
    ] {
        assert!(commands.contains(expected), "allowlist lacks {expected}");
    }
    for denied in [
        "install",
        "install-deps ghidra",
        "self-update",
        "serve",
        "mcp",
        "agent setup",
        "plugin run",
        "native patch",
        "init",
        "rename",
        "config init",
        "prowl",
    ] {
        assert!(!commands.contains(denied), "allowlist carries {denied}");
    }
    let strings: &Value = listing["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command: &&Value| command["command"] == json!(["strings"]))
        .unwrap();
    let path_arg: &Value = strings["args"]
        .as_array()
        .unwrap()
        .iter()
        .find(|arg: &&Value| arg["positional"] == Value::Bool(true))
        .expect("strings takes a positional input");
    assert_eq!(path_arg["path"], Value::Bool(true));
    assert_eq!(path_arg["required"], Value::Bool(true));
    let filtered: Value = call(
        &session.client,
        "list_commands",
        json!({"filter": "native"}),
    )
    .await;
    let kept: Vec<String> = filtered["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command: &Value| {
            command["command"]
                .as_array()
                .unwrap()
                .iter()
                .map(|word: &Value| word.as_str().unwrap())
                .collect::<Vec<&str>>()
                .join(" ")
        })
        .collect();
    assert!(
        kept.iter()
            .any(|command: &String| command == "native symbols")
    );
    assert!(
        kept.iter()
            .all(|command: &String| command.contains("native")),
        "{kept:?}"
    );
}

#[tokio::test]
async fn run_command_strings_returns_parsed_json_that_matches_the_file() {
    let session: Session = session().await;
    let fixture: PathBuf = corpus_dir().join(FIXTURE);
    let bytes: Vec<u8> = std::fs::read(&fixture).unwrap();
    let run: Value = call(
        &session.client,
        "run_command",
        json!({"command": ["strings"], "args": [fixture.display().to_string(), "--no-decode"]}),
    )
    .await;
    assert_eq!(run["success"], Value::Bool(true), "{run}");
    assert_eq!(run["exit_code"], Value::from(0));
    assert!(
        run["argv"]
            .as_array()
            .unwrap()
            .contains(&Value::from("--json"))
    );
    let report: &Value = &run["json"];
    assert_eq!(report["byte_len"], Value::from(bytes.len()));
    let found: &Vec<Value> = report["strings"].as_array().expect("strings array");
    assert_eq!(report["total"], Value::from(found.len()));
    for entry in found
        .iter()
        .filter(|entry: &&Value| entry["wide"] == Value::Bool(false))
    {
        let offset: usize = usize::try_from(entry["offset"].as_u64().unwrap()).unwrap();
        let value: &str = entry["value"].as_str().unwrap();
        assert_eq!(
            &bytes[offset..offset + value.len()],
            value.as_bytes(),
            "string at {offset} is not the file's bytes"
        );
    }
    let reference: Vec<(usize, String)> = printable_runs(&bytes, 4);
    assert!(!reference.is_empty());
    for (offset, text) in reference {
        assert!(
            found.iter().any(|entry: &Value| {
                let start: u64 = entry["offset"].as_u64().unwrap();
                let value: &str = entry["value"].as_str().unwrap();
                start <= offset as u64 && value.contains(text.as_str())
            }),
            "printable run {text:?} at {offset} is missing"
        );
    }
    let run_dir: PathBuf = PathBuf::from(run["run_dir"].as_str().unwrap());
    let expected_parent: PathBuf = session
        .root
        .path()
        .canonicalize()
        .unwrap()
        .join(".disrobe")
        .join("mcp");
    assert_eq!(run_dir.parent(), Some(expected_parent.as_path()), "{run}");
    assert!(run_dir.is_dir());
}

#[tokio::test]
async fn run_command_resolves_relative_inputs_and_redirects_outputs_into_the_run_directory() {
    let session: Session = session().await;
    let fixture: PathBuf = corpus_dir().join(FIXTURE);
    std::fs::copy(&fixture, session.root.path().join("local.elf")).unwrap();
    let run: Value = call(
        &session.client,
        "run_command",
        json!({"command": ["extract"], "args": ["local.elf", "--out", "../elsewhere"]}),
    )
    .await;
    let argv: Vec<&str> = run["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word: &Value| word.as_str().unwrap())
        .collect();
    let run_dir: &str = run["run_dir"].as_str().unwrap();
    assert!(
        argv.contains(&format!("--out={run_dir}").as_str()),
        "output not redirected: {argv:?}"
    );
    let staged: String = session
        .root
        .path()
        .canonicalize()
        .unwrap()
        .join("local.elf")
        .display()
        .to_string();
    assert_eq!(argv.last().copied(), Some(staged.as_str()), "{argv:?}");
    assert!(!session.root.path().join("..").join("elsewhere").exists());
}

#[tokio::test]
async fn run_command_redirects_resource_extraction_into_the_run_directory() {
    let session: Session = session().await;
    let pe: PathBuf = corpus_dir().join("native/resources/resources.exe");
    let run: Value = call(
        &session.client,
        "run_command",
        json!({"command": ["resources"], "args": [pe.display().to_string(), "--extract", "../escaped"]}),
    )
    .await;
    assert_eq!(run["success"], Value::Bool(true), "{run}");
    let run_dir: PathBuf = PathBuf::from(run["run_dir"].as_str().unwrap());
    let payload: Vec<u8> = std::fs::read(run_dir.join("RCDATA-PAYLOAD-1033.pe")).expect("payload");
    let source: Vec<u8> =
        std::fs::read(corpus_dir().join("native/resources/src/payload.bin")).expect("source");
    assert_eq!(payload, source);
    assert!(!session.root.path().join("..").join("escaped").exists());
    assert!(
        run["json"]["entries"]
            .as_array()
            .is_some_and(|entries: &Vec<Value>| !entries.is_empty()),
        "{run}"
    );
}

#[tokio::test]
async fn run_command_refuses_outside_paths_denied_flags_and_unlisted_commands() {
    let session: Session = session().await;
    let outside: ScratchDir = ScratchDir::create("mcp-command-outside").expect("outside dir");
    let stray: PathBuf = outside.path().join("stray.bin");
    std::fs::write(&stray, b"not in any root").unwrap();
    let fixture: String = corpus_dir().join(FIXTURE).display().to_string();
    let cases: [(Value, &str); 7] = [
        (
            json!({"command": ["strings"], "args": [stray.display().to_string()]}),
            "DR-MCP-0811",
        ),
        (
            json!({"command": ["strings"], "args": ["../../../outside.bin"]}),
            "DR-MCP-0811",
        ),
        (
            json!({"command": ["pyarmor", "unpack"], "args": [fixture.clone(), "--allow-dynamic"]}),
            "DR-MCP-0807",
        ),
        (
            json!({"command": ["strings"], "args": [fixture.clone(), "--in-place"]}),
            "DR-MCP-0807",
        ),
        (
            json!({"command": ["install"], "args": ["ghidra"]}),
            "DR-MCP-0804",
        ),
        (
            json!({"command": ["serve"], "args": ["--mcp"]}),
            "DR-MCP-0804",
        ),
        (
            json!({"command": ["strings"], "args": [fixture, "--no-such-flag"]}),
            "DR-MCP-0809",
        ),
    ];
    for (arguments, code) in cases {
        let message: String = refusal(&session.client, "run_command", arguments.clone()).await;
        assert!(
            message.contains(code),
            "{arguments} refused without {code}: {message}"
        );
    }
    let mcp_dir: PathBuf = session.root.path().join(".disrobe").join("mcp");
    let runs: usize =
        std::fs::read_dir(&mcp_dir).map_or(0, |entries: std::fs::ReadDir| entries.count());
    assert_eq!(runs, 0, "a refused run must not create a run directory");
}

#[tokio::test]
async fn the_standalone_server_names_the_missing_catalog() {
    let root: ScratchDir = ScratchDir::create("mcp-command-standalone").expect("scratch root");
    let command: tokio::process::Command =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_disrobe-mcp"));
    let client: Client = connect(command, root.path()).await;
    let message: String = refusal(&client, "list_commands", json!({})).await;
    assert!(
        message.contains("DR-MCP-0800") && message.contains("disrobe mcp"),
        "{message}"
    );
    let message: String = refusal(
        &client,
        "run_command",
        json!({"command": ["strings"], "args": []}),
    )
    .await;
    assert!(message.contains("DR-MCP-0800"), "{message}");
}
