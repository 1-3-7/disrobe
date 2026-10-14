#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use disrobe_core::scratch::ScratchDir;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SectionKind, SymbolKind};
use rmcp::ServiceExt as _;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use rmcp::{RoleClient, ServiceError};
use serde_json::{Map, Value, json};
use sha2::Digest as _;

type Client = RunningService<RoleClient, ()>;

const ELF: &[u8] = include_bytes!("../../../corpus/native/discovery/disc.unstripped.elf");
const AARCH64_ELF: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64.unstripped.elf");

struct Session {
    client: Client,
    root: ScratchDir,
}

async fn session() -> Session {
    let root: ScratchDir = ScratchDir::create("mcp-target-tools").expect("scratch root");
    std::fs::write(root.path().join("disc.elf"), ELF).expect("stage x86-64 fixture");
    std::fs::write(root.path().join("disc_aarch64.elf"), AARCH64_ELF)
        .expect("stage aarch64 fixture");
    let mut command: tokio::process::Command =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_disrobe-mcp"));
    command
        .current_dir(root.path())
        .env_remove("DISROBE_MCP_ROOTS")
        .kill_on_drop(true);
    let transport: TokioChildProcess =
        TokioChildProcess::new(command).expect("spawn disrobe-mcp over piped stdio");
    let client: Client = ().serve(transport).await.expect("initialize handshake");
    Session { client, root }
}

async fn call_raw(
    client: &Client,
    tool: &'static str,
    arguments: Value,
) -> Result<CallToolResult, ServiceError> {
    let arguments: Map<String, Value> = match arguments {
        Value::Object(map) => map,
        other => panic!("tool arguments must be an object, got {other}"),
    };
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

fn hex(address: u64) -> String {
    format!("{address:#x}")
}

fn parse_hex(value: &Value) -> u64 {
    let text: &str = value.as_str().expect("hex string");
    u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("hex address")
}

fn reference_functions(elf: &[u8]) -> BTreeMap<u64, (String, u64)> {
    let file: object::File<'_> = object::File::parse(elf).expect("parse reference ELF");
    file.symbols()
        .filter(|symbol: &object::Symbol<'_, '_>| {
            symbol.kind() == SymbolKind::Text && symbol.size() > 0 && symbol.address() != 0
        })
        .map(|symbol: object::Symbol<'_, '_>| {
            (
                symbol.address(),
                (
                    symbol.name().expect("symbol name").to_owned(),
                    symbol.size(),
                ),
            )
        })
        .collect()
}

fn reference_bytes(elf: &[u8], address: u64, len: usize) -> Vec<u8> {
    let file: object::File<'_> = object::File::parse(elf).expect("parse reference ELF");
    for section in file.sections() {
        let start: u64 = section.address();
        if address >= start && address < start + section.size() {
            let data: &[u8] = section.data().expect("section data");
            let offset: usize = usize::try_from(address - start).expect("offset");
            return data[offset..(offset + len).min(data.len())].to_vec();
        }
    }
    panic!("no section holds {address:#x}");
}

fn reference_direct_calls(elf: &[u8]) -> BTreeSet<(u64, u64)> {
    let functions: BTreeMap<u64, (String, u64)> = reference_functions(elf);
    let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    for (address, (_, size)) in &functions {
        let bytes: Vec<u8> = reference_bytes(elf, *address, usize::try_from(*size).expect("size"));
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, &bytes, *address, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction: Instruction = decoder.decode();
            if instruction.flow_control() == FlowControl::Call
                && matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch64 | OpKind::NearBranch32
                )
                && functions.contains_key(&instruction.near_branch_target())
            {
                edges.insert((*address, instruction.near_branch_target()));
            }
        }
    }
    edges
}

async fn open(client: &Client, path: &str) -> (String, Value) {
    let opened: Value = call(client, "open_target", json!({ "path": path })).await;
    (
        opened["target_id"].as_str().expect("target id").to_owned(),
        opened,
    )
}

#[tokio::test]
async fn open_target_reports_the_file_identity_and_native_shape() {
    let session: Session = session().await;
    let (target_id, opened): (String, Value) = open(&session.client, "disc.elf").await;
    let sha256: String =
        sha2::Sha256::digest(ELF)
            .iter()
            .fold(String::new(), |mut text: String, byte: &u8| {
                let _ = write!(text, "{byte:02x}");
                text
            });
    assert_eq!(opened["sha256"], json!(sha256));
    assert_eq!(opened["size"], json!(ELF.len()));
    assert_eq!(target_id, blake3::hash(ELF).to_hex().to_string());
    let reference: object::File<'_> = object::File::parse(ELF).expect("parse reference");
    assert_eq!(
        opened["native"]["sections"],
        json!(reference.sections().count())
    );
    assert!(
        opened["native"]["functions"]
            .as_u64()
            .expect("function count")
            > 0
    );
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn layout_sections_match_an_independent_parser() {
    let session: Session = session().await;
    let (target_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let layout: Value = call(
        &session.client,
        "target_layout",
        json!({ "target_id": target_id }),
    )
    .await;
    let reported: BTreeMap<String, (u64, u64, Option<u64>)> = layout["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .map(|row: &Value| {
            (
                row["name"].as_str().expect("name").to_owned(),
                (
                    parse_hex(&row["address"]),
                    row["size"].as_u64().expect("size"),
                    row.get("file_offset").and_then(Value::as_u64),
                ),
            )
        })
        .collect();
    let reference: object::File<'_> = object::File::parse(ELF).expect("parse reference");
    let mut compared: usize = 0;
    for section in reference.sections() {
        let name: &str = section.name().expect("section name");
        if section.address() == 0 || name.is_empty() {
            continue;
        }
        let Some((address, size, file_offset)) = reported.get(name) else {
            continue;
        };
        assert_eq!(*address, section.address(), "{name} address");
        assert_eq!(*size, section.size(), "{name} size");
        if section.kind() != SectionKind::UninitializedData {
            assert_eq!(
                *file_offset,
                section.file_range().map(|(offset, _)| offset),
                "{name} offset"
            );
        }
        compared += 1;
    }
    let allocated: usize = reference
        .sections()
        .filter(|section: &object::Section<'_, '_>| section.address() != 0)
        .count();
    assert!(
        allocated >= 2,
        "the fixture holds {allocated} allocated sections"
    );
    assert_eq!(compared, allocated, "every allocated section is reported");
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn every_symbol_table_function_is_listed_at_its_address_and_disassembles_like_iced() {
    let session: Session = session().await;
    let (target_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let reference: BTreeMap<u64, (String, u64)> = reference_functions(ELF);
    assert!(
        reference.len() >= 7,
        "reference holds {} functions",
        reference.len()
    );
    let mut listed: BTreeMap<u64, String> = BTreeMap::new();
    let mut offset: u64 = 0;
    loop {
        let page: Value = call(
            &session.client,
            "list_functions",
            json!({ "target_id": target_id, "offset": offset, "limit": 500 }),
        )
        .await;
        for row in page["functions"].as_array().expect("functions") {
            listed.insert(
                parse_hex(&row["address"]),
                row["name"].as_str().expect("name").to_owned(),
            );
        }
        match page.get("next_offset").and_then(Value::as_u64) {
            Some(next) => offset = next,
            None => break,
        }
    }
    for (address, (name, size)) in &reference {
        assert_eq!(
            listed.get(address),
            Some(name),
            "function {name} at {address:#x}"
        );
        let listing: Value = call(
            &session.client,
            "disassemble_function",
            json!({ "target_id": target_id, "function": name, "max_instructions": 4096 }),
        )
        .await;
        let reported: Vec<u64> = listing["instructions"]
            .as_array()
            .expect("instructions")
            .iter()
            .map(|row: &Value| parse_hex(&row["address"]))
            .collect();
        let bytes: Vec<u8> = reference_bytes(ELF, *address, usize::try_from(*size).expect("size"));
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, &bytes, *address, DecoderOptions::NONE);
        let mut expected: Vec<u64> = Vec::new();
        while decoder.can_decode() {
            expected.push(decoder.decode().ip());
        }
        assert_eq!(
            reported.get(..expected.len()),
            Some(expected.as_slice()),
            "{name}: instruction starts differ from iced-x86"
        );
    }
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn read_bytes_locate_and_search_agree_with_the_file() {
    let session: Session = session().await;
    let (target_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let reference: BTreeMap<u64, (String, u64)> = reference_functions(ELF);
    let (address, (name, _)): (&u64, &(String, u64)) = reference
        .iter()
        .find(|(_, (name, _)): &(&u64, &(String, u64))| name == "compute")
        .expect("compute in the symbol table");
    let expected: Vec<u8> = reference_bytes(ELF, *address, 16);
    let read: Value = call(
        &session.client,
        "read_bytes",
        json!({ "target_id": target_id, "address": hex(*address), "length": 16 }),
    )
    .await;
    let expected_hex: String = expected
        .iter()
        .map(|b: &u8| format!("{b:02X}"))
        .collect::<Vec<String>>()
        .join(" ");
    assert_eq!(read["hex"], json!(expected_hex));
    let file_offset: u64 = read["offset"].as_u64().expect("offset");
    let start: usize = usize::try_from(file_offset).expect("offset");
    assert_eq!(&ELF[start..start + 16], expected.as_slice());
    let located: Value = call(
        &session.client,
        "locate",
        json!({ "target_id": target_id, "offset": file_offset }),
    )
    .await;
    assert_eq!(parse_hex(&located["address"]), *address);
    assert_eq!(located["function"], json!(name));
    let pattern: String = expected[..8]
        .iter()
        .enumerate()
        .map(|(index, byte): (usize, &u8)| {
            if index == 3 || index == 4 {
                "??".to_owned()
            } else {
                format!("{byte:02x}")
            }
        })
        .collect::<Vec<String>>()
        .join(" ");
    let found: Value = call(
        &session.client,
        "search_bytes",
        json!({ "target_id": target_id, "pattern": pattern, "max_hits": 1024 }),
    )
    .await;
    let hits: BTreeSet<u64> = found["hits"]
        .as_array()
        .expect("hits")
        .iter()
        .map(|hit: &Value| hit["offset"].as_u64().expect("hit offset"))
        .collect();
    let naive: BTreeSet<u64> = (0..=ELF.len() - 8)
        .filter(|&i: &usize| (0..8).all(|j: usize| j == 3 || j == 4 || ELF[i + j] == expected[j]))
        .map(|i: usize| i as u64)
        .collect();
    assert!(naive.contains(&file_offset));
    assert_eq!(hits, naive);
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn call_path_follows_reference_direct_calls() {
    let session: Session = session().await;
    let (target_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let edges: BTreeSet<(u64, u64)> = reference_direct_calls(ELF);
    assert!(
        edges.len() >= 4,
        "reference holds {} direct call edges",
        edges.len()
    );
    for (caller, callee) in &edges {
        if caller == callee {
            continue;
        }
        let path: Value = call(
            &session.client,
            "call_path",
            json!({ "target_id": target_id, "from": hex(*caller), "to": hex(*callee), "max_depth": 1 }),
        )
        .await;
        assert_eq!(path["found"], json!(true), "{caller:#x} -> {callee:#x}");
        let chain: Vec<u64> = path["path"]
            .as_array()
            .expect("path")
            .iter()
            .map(|row: &Value| parse_hex(&row["address"]))
            .collect();
        assert_eq!(chain, vec![*caller, *callee]);
    }
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn decompile_function_lifts_x86_64_and_refuses_other_architectures_by_name() {
    let session: Session = session().await;
    let (target_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let lifted: Value = call(
        &session.client,
        "decompile_function",
        json!({ "target_id": target_id, "function": "add" }),
    )
    .await;
    match lifted.get("source").and_then(Value::as_str) {
        Some(source) => assert!(source.contains("add"), "{source}"),
        None => assert!(
            lifted["refusal"]
                .as_str()
                .is_some_and(|reason: &str| !reason.is_empty())
        ),
    }
    let (arm_id, _): (String, Value) = open(&session.client, "disc_aarch64.elf").await;
    let refused: String = refusal(
        &session.client,
        "decompile_function",
        json!({ "target_id": arm_id, "function": "table_zero" }),
    )
    .await;
    assert!(refused.contains("DR-MCP-0720"), "{refused}");
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn paths_outside_the_roots_and_stale_ids_are_refused() {
    let session: Session = session().await;
    let outside: String = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("Cargo.toml")
        .display()
        .to_string();
    let refused: String = refusal(&session.client, "open_target", json!({ "path": outside })).await;
    assert!(refused.contains("DR-MCP-0703"), "{refused}");
    let escaped: String = refusal(&session.client, "open_target", json!({ "path": "../" })).await;
    assert!(escaped.contains("DR-MCP-070"), "{escaped}");
    let stale: String = refusal(
        &session.client,
        "list_functions",
        json!({ "target_id": "0".repeat(64) }),
    )
    .await;
    assert!(stale.contains("DR-MCP-0707"), "{stale}");
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn a_changed_file_is_a_new_target_whose_bytes_carry_the_change() {
    let session: Session = session().await;
    let (first_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let mut mutated: Vec<u8> = ELF.to_vec();
    let flipped: usize = mutated.len() / 2;
    mutated[flipped] ^= 0xFF;
    std::fs::write(session.root.path().join("disc.elf"), &mutated).expect("rewrite fixture");
    let (second_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    assert_ne!(first_id, second_id);
    let read: Value = call(
        &session.client,
        "read_bytes",
        json!({ "target_id": second_id, "offset": flipped, "length": 1 }),
    )
    .await;
    assert_eq!(read["hex"], json!(format!("{:02X}", ELF[flipped] ^ 0xFF)));
    let original: Value = call(
        &session.client,
        "read_bytes",
        json!({ "target_id": first_id, "offset": flipped, "length": 1 }),
    )
    .await;
    assert_eq!(original["hex"], json!(format!("{:02X}", ELF[flipped])));
    session.client.cancel().await.expect("shutdown");
}

const RUST_PE: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/guardian-rs/sample.clean.exe");

fn pointer_at(image: &[u8], address: u64) -> u64 {
    let bytes: Vec<u8> = reference_bytes(image, address, 8);
    u64::from_le_bytes(bytes.try_into().expect("eight pointer bytes"))
}

fn decode_at(image: &[u8], address: u64) -> Instruction {
    let file: object::File<'_> = object::File::parse(image).expect("parse reference image");
    let bytes: Vec<u8> = file
        .sections()
        .find_map(|section: object::Section<'_, '_>| {
            let start: u64 = section.address();
            (address >= start && address < start + section.size()).then(|| {
                let data: &[u8] = section.data().expect("section data");
                let offset: usize = usize::try_from(address - start).expect("offset");
                data[offset..(offset + 15).min(data.len())].to_vec()
            })
        })
        .expect("a section holds the referencing instruction");
    let bitness: u32 = if file.is_64() { 64 } else { 32 };
    Decoder::with_ip(bitness, &bytes, address, DecoderOptions::NONE).decode()
}

#[tokio::test]
async fn references_to_a_function_cover_every_reference_call_site() {
    let session: Session = session().await;
    let (target_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let functions: BTreeMap<u64, (String, u64)> = reference_functions(ELF);
    let mut sites: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (address, (_, size)) in &functions {
        let bytes: Vec<u8> = reference_bytes(ELF, *address, usize::try_from(*size).expect("size"));
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, &bytes, *address, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction: Instruction = decoder.decode();
            if instruction.flow_control() == FlowControl::Call
                && matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch64 | OpKind::NearBranch32
                )
                && functions.contains_key(&instruction.near_branch_target())
            {
                sites
                    .entry(instruction.near_branch_target())
                    .or_default()
                    .insert(instruction.ip());
            }
        }
    }
    assert!(
        sites.len() >= 3,
        "reference holds {} called functions",
        sites.len()
    );
    for (callee, expected) in &sites {
        let found: Value = call(
            &session.client,
            "references_to",
            json!({ "target_id": target_id, "address": hex(*callee) }),
        )
        .await;
        let calls: BTreeSet<u64> = found["references"]
            .as_array()
            .expect("references")
            .iter()
            .filter(|row: &&Value| row["kind"] == json!("call"))
            .map(|row: &Value| parse_hex(&row["from"]))
            .collect();
        assert_eq!(&calls, expected, "call sites of {callee:#x}");
    }
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn every_string_reference_decodes_to_an_operand_that_addresses_the_string() {
    let session: Session = session().await;
    std::fs::write(session.root.path().join("sample.exe"), RUST_PE).expect("stage PE fixture");
    let (target_id, _): (String, Value) = open(&session.client, "sample.exe").await;
    let page: Value = call(
        &session.client,
        "find_strings",
        json!({ "target_id": target_id, "referenced_only": true, "min_len": 8, "limit": 200 }),
    )
    .await;
    let rows: &Vec<Value> = page["strings"].as_array().expect("strings");
    assert!(
        rows.len() >= 5,
        "only {} referenced strings: {page}",
        rows.len()
    );
    let mut checked: usize = 0;
    for row in rows {
        let address: u64 = parse_hex(&row["address"]);
        let offset: usize =
            usize::try_from(row["offset"].as_u64().expect("offset")).expect("offset");
        let value: &str = row["value"].as_str().expect("value");
        if row["encoding"] == json!("plain") {
            assert_eq!(&RUST_PE[offset..offset + value.len()], value.as_bytes());
        }
        let end: u64 = address + value.len() as u64;
        for reference in row["references"].as_array().expect("references") {
            let from: u64 = parse_hex(&reference["from"]);
            let to: u64 = parse_hex(&reference["to"]);
            assert!(
                (address..end).contains(&to),
                "{to:#x} outside {address:#x}..{end:#x}"
            );
            let operand_target: u64 = match reference["kind"].as_str().expect("kind") {
                "data" => to,
                "via-pointer" => {
                    let slot: u64 = parse_hex(&reference["via"]);
                    assert_eq!(pointer_at(RUST_PE, slot), to, "slot {slot:#x}");
                    slot
                }
                "pointer-slot" => {
                    assert_eq!(pointer_at(RUST_PE, from), to, "slot {from:#x}");
                    checked += 1;
                    continue;
                }
                other => panic!("unexpected reference kind {other}"),
            };
            let instruction: Instruction = decode_at(RUST_PE, from);
            let addressed: bool = (0..instruction.op_count()).any(|operand: u32| {
                instruction.op_kind(operand) == OpKind::Memory
                    && instruction.memory_displacement64() == operand_target
            });
            assert!(
                addressed,
                "{from:#x} ({instruction}) does not address {operand_target:#x}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 5, "only {checked} references were checked");
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn native_match_reads_both_sides_from_targets_and_paths() {
    let session: Session = session().await;
    let (target_id, _): (String, Value) = open(&session.client, "disc.elf").await;
    let reported: Value = call(
        &session.client,
        "native_match",
        json!({ "a_target_id": target_id, "b_path": "disc.elf", "limit": 5 }),
    )
    .await;
    let expected = disrobe_pass_native::match_native_images(
        "a",
        ELF,
        "b",
        ELF,
        disrobe_pass_native::NativeMatchOptions {
            limit: Some(5),
            function: None,
            stage: None,
        },
    )
    .expect("library match");
    assert_eq!(reported, serde_json::to_value(expected).expect("serialize"));
    let mixed: String = refusal(
        &session.client,
        "native_match",
        json!({ "a_target_id": target_id, "a_path": "disc.elf", "b_path": "disc.elf" }),
    )
    .await;
    assert!(mixed.contains("DR-MCP-0709"), "{mixed}");
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn identify_target_reports_the_library_verdict_with_the_commands_that_handle_it() {
    let session: Session = session().await;
    std::fs::write(session.root.path().join("sample.exe"), RUST_PE).expect("stage PE fixture");
    let (target_id, _): (String, Value) = open(&session.client, "sample.exe").await;
    let reported: Value = call(
        &session.client,
        "identify_target",
        json!({ "target_id": target_id }),
    )
    .await;
    let now: u64 = disrobe_core::time::now_secs().expect("clock");
    let expected: disrobe_pass_native::IdentityReport =
        disrobe_pass_native::detect_identity(RUST_PE, now);
    assert!(
        !expected.hits.is_empty(),
        "the Rust PE carries identity hits"
    );
    assert_eq!(reported["format"], json!(expected.format));
    let rows: &Vec<Value> = reported["hits"].as_array().expect("hits");
    assert_eq!(rows.len(), expected.hits.len());
    for (row, hit) in rows.iter().zip(&expected.hits) {
        assert_eq!(row["name"], json!(hit.name));
        assert_eq!(row["confidence"], json!(hit.confidence));
        assert_eq!(row["commands"], json!(hit.support.invocations()));
    }
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn inspect_sqlite_reads_rows_written_by_cpython_sqlite3() {
    let session: Session = session().await;
    let db: std::path::PathBuf = session.root.path().join("app.db");
    let script: String = format!(
        "import sqlite3\nc = sqlite3.connect(r'{}')\nc.execute('CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, n REAL)')\nc.executemany('INSERT INTO notes (body, n) VALUES (?, ?)', [('first', 1.5), ('second', -2.0)])\nc.commit()\nc.close()\n",
        db.display()
    );
    let python: &str = ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| {
            std::process::Command::new(candidate)
                .args(["-c", "import sqlite3"])
                .status()
                .is_ok_and(|status: std::process::ExitStatus| status.success())
        })
        .expect("the SQLite case needs CPython 3 with sqlite3 as its reference writer");
    let status: std::process::ExitStatus = std::process::Command::new(python)
        .args(["-c", &script])
        .status()
        .expect("run the reference writer");
    assert!(status.success());
    let report: Value = call(
        &session.client,
        "inspect_sqlite",
        json!({ "path": "app.db", "rows": 10 }),
    )
    .await;
    let table: &Value = &report["tables"][0];
    assert_eq!(table["name"], json!("notes"));
    assert_eq!(table["row_count"], json!(2));
    assert_eq!(
        table["rows"],
        json!([
            { "rowid": 1, "values": [{ "type": "integer", "value": 1 }, { "type": "text", "value": "first" }, { "type": "real", "value": 1.5 }] },
            { "rowid": 2, "values": [{ "type": "integer", "value": 2 }, { "type": "text", "value": "second" }, { "type": "real", "value": -2.0 }] }
        ])
    );
    session.client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn inspect_capture_decodes_a_reference_capture() {
    let session: Session = session().await;
    let script: std::path::PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-dataforensics/tests/support/make_captures.py");
    let python: &str = ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| {
            std::process::Command::new(candidate)
                .args(["-c", "import gzip"])
                .status()
                .is_ok_and(|status: std::process::ExitStatus| status.success())
        })
        .expect("the capture case needs CPython 3 as its reference writer");
    let status: std::process::ExitStatus = std::process::Command::new(python)
        .arg(&script)
        .arg(session.root.path())
        .status()
        .expect("run the capture writer");
    assert!(status.success());
    let report: Value = call(
        &session.client,
        "inspect_capture",
        json!({ "path": "capture.pcapng" }),
    )
    .await;
    assert_eq!(report["format"], json!("pcapng"));
    assert_eq!(
        report["tls"][0]["hello"]["sni"],
        json!("secure.example.org")
    );
    assert_eq!(report["http"].as_array().expect("http").len(), 2);
    session.client.cancel().await.expect("shutdown");
}
