#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_capabilities::{
    CapabilitiesReport, CapabilityMatch, Evidence, Feature, ImportMap, ScopedFeatures,
};
use disrobe_ir::payload::{DisasmInstruction, DisasmPayload};
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::Module;

const WRITEFILE: &[u8] = include_bytes!("fixtures/writefile.exe");
const CONNECT: &[u8] = include_bytes!("fixtures/connect.exe");
const XORDECRYPT: &[u8] = include_bytes!("fixtures/xordecrypt.exe");
const CLEAN: &[u8] = include_bytes!("fixtures/clean.exe");
const PEBCHECK: &[u8] = include_bytes!("fixtures/pebcheck.exe");
const STACKSTR: &[u8] = include_bytes!("fixtures/stackstr.exe");
const EMBEDPE: &[u8] = include_bytes!("fixtures/embedpe.exe");
const STACKSTR_EXPECTED: &str = "injected";

fn analyze(bytes: &[u8]) -> CapabilitiesReport {
    disrobe_capabilities::analyze(bytes).expect("analyze native binary")
}

fn rule<'a>(report: &'a CapabilitiesReport, name: &str) -> Option<&'a CapabilityMatch> {
    report
        .capabilities
        .iter()
        .find(|c: &&CapabilityMatch| c.rule == name)
}

fn evidence_addrs(m: &CapabilityMatch) -> Vec<u64> {
    let mut addrs: Vec<u64> = m.evidence.iter().map(|e: &Evidence| e.address).collect();
    addrs.sort_unstable();
    addrs
}

fn independent_iat_call_site(bytes: &[u8], import: &str) -> u64 {
    let imports: ImportMap = ImportMap::from_bytes(bytes);
    let target_va: u64 =
        iat_va_for(bytes, &imports, import).unwrap_or_else(|| panic!("no IAT slot for {import}"));
    let payload: DisasmPayload = build_disasm_payload(bytes).expect("payload");
    let site: &DisasmInstruction = payload
        .instructions
        .iter()
        .find(|i: &&DisasmInstruction| {
            i.mnemonic == "call"
                && i.operands.iter().any(|op: &String| {
                    disrobe_capabilities::imports::parse_operand_memory_address(op)
                        == Some(target_va)
                })
        })
        .unwrap_or_else(|| panic!("no call site to {import} (va {target_va:#x})"));
    site.offset
}

fn iat_va_for(bytes: &[u8], imports: &ImportMap, import: &str) -> Option<u64> {
    let goblin::Object::PE(pe) = goblin::Object::parse(bytes).expect("pe") else {
        panic!("not a PE");
    };
    pe.imports
        .iter()
        .map(|i: &goblin::pe::import::Import<'_>| pe.image_base + i.offset as u64)
        .find(|va: &u64| {
            imports
                .name_at_iat(*va)
                .is_some_and(|name: &str| name.eq_ignore_ascii_case(import))
        })
}

fn image_base_of(bytes: &[u8]) -> u64 {
    let goblin::Object::PE(pe) = goblin::Object::parse(bytes).expect("pe") else {
        panic!("not a PE");
    };
    pe.image_base
}

fn disasm_va_span(bytes: &[u8]) -> (u64, u64) {
    let payload: DisasmPayload = build_disasm_payload(bytes).expect("payload");
    let mut min: u64 = u64::MAX;
    let mut max: u64 = 0;
    for insn in &payload.instructions {
        let end: u64 = insn.offset + insn.bytes.len() as u64;
        min = min.min(insn.offset);
        max = max.max(end);
    }
    assert!(min <= max, "disassembly produced no instructions");
    (min, max)
}

fn assert_addr_in_image(label: &str, addr: u64, bytes: &[u8]) {
    let base: u64 = image_base_of(bytes);
    let (lo, hi): (u64, u64) = disasm_va_span(bytes);
    assert!(
        addr >= base,
        "{label} address {addr:#x} must be a mapped virtual address (>= image base {base:#x})"
    );
    assert!(
        (lo..=hi).contains(&addr),
        "{label} address {addr:#x} must fall inside the disassembled code span [{lo:#x}, {hi:#x}]"
    );
}

#[test]
fn writefile_oracle_fires_write_file_at_real_call_sites() {
    let report: CapabilitiesReport = analyze(WRITEFILE);

    let create: &CapabilityMatch = rule(&report, "create or open file").expect("create or open");
    let write: &CapabilityMatch = rule(&report, "write file").expect("write file");

    let create_site: u64 = independent_iat_call_site(WRITEFILE, "kernel32!CreateFileW");
    let write_site: u64 = independent_iat_call_site(WRITEFILE, "kernel32!WriteFile");

    assert_eq!(
        create.address, create_site,
        "create/open must anchor at the real CreateFileW call site"
    );
    let write_addrs: Vec<u64> = evidence_addrs(write);
    assert!(
        write_addrs.len() >= 2,
        "write-file must cite at least the CreateFileW and WriteFile call sites, got {write_addrs:?}"
    );
    assert!(
        write_addrs.contains(&create_site),
        "write-file evidence must include the CreateFileW call site"
    );
    assert!(
        write_addrs.contains(&write_site),
        "write-file evidence must include the WriteFile call site"
    );
    assert_addr_in_image("write-file match", write.address, WRITEFILE);
    for addr in &write_addrs {
        assert_addr_in_image("write-file evidence", *addr, WRITEFILE);
    }
    let func_addr: u64 = write.function_address.expect("function address");
    assert!(
        create_site >= func_addr && write_site >= func_addr,
        "both call sites live inside the matched function"
    );
    assert!(write.attack.contains(&"T1105".to_owned()));
    assert!(write.mbc.contains(&"C0052".to_owned()));

    assert!(
        rule(&report, "connect to network resource").is_none(),
        "a file writer must not match the network rule"
    );
}

#[test]
fn connect_oracle_fires_socket_and_connect_at_real_call_sites() {
    let report: CapabilitiesReport = analyze(CONNECT);

    let socket: &CapabilityMatch = rule(&report, "open network socket").expect("open socket");
    let connect: &CapabilityMatch = rule(&report, "connect to network resource").expect("connect");

    let socket_site: u64 = independent_iat_call_site(CONNECT, "ws2_32!socket");
    let connect_site: u64 = independent_iat_call_site(CONNECT, "ws2_32!connect");

    let socket_addrs: Vec<u64> = evidence_addrs(socket);
    assert!(
        !socket_addrs.is_empty(),
        "the socket capability must cite at least one call site"
    );
    assert!(
        socket_addrs.contains(&socket_site),
        "socket evidence must include the real socket() call site"
    );
    assert_addr_in_image("socket match", socket.address, CONNECT);
    for addr in &socket_addrs {
        assert_addr_in_image("socket evidence", *addr, CONNECT);
    }
    assert_eq!(
        connect.address, connect_site,
        "connect must anchor at the real connect() call site"
    );
    assert!(
        !connect.evidence.is_empty(),
        "the connect capability must cite at least one call site"
    );
    assert_addr_in_image("connect match", connect.address, CONNECT);
    assert!(connect.attack.contains(&"T1071".to_owned()));

    assert!(
        rule(&report, "write file").is_none(),
        "a network client must not match the write-file rule"
    );
}

#[test]
fn xordecrypt_oracle_fires_inside_the_decode_loop() {
    let report: CapabilitiesReport = analyze(XORDECRYPT);
    let xor: &CapabilityMatch = rule(&report, "encode data using xor").expect("xor decode");

    let func_addr: u64 = xor.function_address.expect("function address");
    assert!(
        xor.address >= func_addr,
        "xor match must anchor inside the decode function"
    );
    assert!(
        xor.evidence
            .iter()
            .any(|e: &Evidence| e.feature.contains("non-zeroing-xor")),
        "evidence must cite the non-zeroing xor: {:?}",
        xor.evidence
    );
    assert!(
        xor.evidence
            .iter()
            .any(|e: &Evidence| e.feature.contains("tight-loop")),
        "evidence must cite the tight loop: {:?}",
        xor.evidence
    );
    assert!(xor.attack.contains(&"T1027".to_owned()));

    assert!(rule(&report, "write file").is_none());
    assert!(rule(&report, "connect to network resource").is_none());
}

#[test]
fn clean_oracle_matches_no_behavior_rule() {
    let report: CapabilitiesReport = analyze(CLEAN);
    assert_eq!(
        report.matched_rules, 0,
        "the clean control binary must match no capability: {:?}",
        report.capabilities
    );
    assert!(report.attack.is_empty());
    assert!(report.mbc.is_empty());
}

fn independent_segment_access_site(bytes: &[u8], segment: &str) -> u64 {
    let payload: DisasmPayload = build_disasm_payload(bytes).expect("payload");
    let needle: String = format!("{segment}:");
    let Some(site): Option<&DisasmInstruction> =
        payload.instructions.iter().find(|i: &&DisasmInstruction| {
            i.operands
                .iter()
                .any(|op: &String| op.to_ascii_lowercase().contains(&needle))
        })
    else {
        panic!("no {segment} segment access in fixture");
    };
    site.offset
}

struct StackStringStore {
    site: u64,
    instruction: Vec<u8>,
}

fn independent_stack_string_store(bytes: &[u8]) -> StackStringStore {
    let payload: DisasmPayload = build_disasm_payload(bytes).expect("payload");
    payload
        .instructions
        .iter()
        .find(|insn: &&DisasmInstruction| {
            insn.mnemonic.eq_ignore_ascii_case("mov")
                && insn.operands.len() == 2
                && insn.operands[0].contains("rsp")
                && insn.operands[0].contains("dword")
                && insn.operands[1]
                    .trim_end_matches('h')
                    .bytes()
                    .all(|byte: u8| byte.is_ascii_hexdigit())
        })
        .map(|insn: &DisasmInstruction| StackStringStore {
            site: insn.offset,
            instruction: insn.bytes.clone(),
        })
        .expect("fixture retains the first inlined stack-string store")
}

fn replace_stack_string_immediate(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let store: StackStringStore = independent_stack_string_store(bytes);
    assert!(store.instruction.ends_with(from));
    let mut mutated: Vec<u8> = bytes.to_vec();
    let matches: Vec<usize> = mutated
        .windows(store.instruction.len())
        .enumerate()
        .filter_map(|(offset, window): (usize, &[u8])| {
            (window == store.instruction.as_slice()).then_some(offset)
        })
        .collect();
    assert_eq!(matches.len(), 1);
    let offset: usize = matches[0];
    let immediate_start: usize = offset + store.instruction.len() - from.len();
    mutated[immediate_start..immediate_start + from.len()].copy_from_slice(to);
    mutated
}

fn independent_embedded_pe_offset(bytes: &[u8]) -> u64 {
    let mut at: usize = 1;
    while at + 0x40 < bytes.len() {
        if &bytes[at..at + 2] == b"MZ" {
            let e_lfanew: usize =
                u32::from_le_bytes(bytes[at + 0x3c..at + 0x40].try_into().unwrap()) as usize;
            let pe: usize = at + e_lfanew;
            if pe + 4 <= bytes.len() && &bytes[pe..pe + 4] == b"PE\0\0" {
                return at as u64;
            }
        }
        at += 1;
    }
    panic!("no embedded PE in fixture");
}

#[test]
fn pebcheck_oracle_fires_at_real_segment_read() {
    let report: CapabilitiesReport = analyze(PEBCHECK);
    let peb: &CapabilityMatch =
        rule(&report, "access process environment block").expect("peb-access capability fires");
    let site: u64 = independent_segment_access_site(PEBCHECK, "gs");
    assert_eq!(
        peb.address, site,
        "peb-access must anchor at the real gs-segment read"
    );
    assert!(
        peb.evidence
            .iter()
            .any(|e: &Evidence| e.feature.contains("peb-access")),
        "evidence must cite the peb-access characteristic: {:?}",
        peb.evidence
    );
    assert_addr_in_image("peb-access match", peb.address, PEBCHECK);
    assert!(peb.attack.contains(&"T1106".to_owned()));
    assert!(rule(&report, "write file").is_none());
    assert!(rule(&report, "connect to network resource").is_none());
}

#[test]
fn stackstr_oracle_reassembles_the_real_inlined_string() {
    let report: CapabilitiesReport = analyze(STACKSTR);
    let stack: &CapabilityMatch =
        rule(&report, "build string on the stack").expect("stack-string capability fires");
    let store: StackStringStore = independent_stack_string_store(STACKSTR);
    let site: u64 = store.site;
    let expected: String = STACKSTR_EXPECTED.to_owned();
    let payload: DisasmPayload = build_disasm_payload(STACKSTR).expect("payload");
    let module: Module = Module::from_disasm(&payload);
    let imports: ImportMap = ImportMap::from_bytes(STACKSTR);
    let scoped: ScopedFeatures = disrobe_capabilities::extract(&module, STACKSTR, &imports);
    assert!(
        scoped
            .file
            .matches(&Feature::StringExact(expected.clone()))
            .contains(&site),
        "stack-string reconstruction must emit the source-defined text {expected:?} at {site:#x}"
    );
    assert_eq!(
        stack.address, site,
        "stack-string must anchor at the first immediate store"
    );
    assert!(
        stack
            .evidence
            .iter()
            .any(|e: &Evidence| e.feature.contains("stack-string")),
        "evidence must cite the stack-string characteristic: {:?}",
        stack.evidence
    );
    assert_addr_in_image("stack-string match", stack.address, STACKSTR);
    assert!(rule(&report, "write file").is_none());
    assert!(rule(&report, "connect to network resource").is_none());
}

#[test]
fn stackstr_oracle_tracks_a_mutated_immediate_store() {
    let mutated: Vec<u8> = replace_stack_string_immediate(STACKSTR, b"inje", b"inj!");
    let store: StackStringStore = independent_stack_string_store(&mutated);
    let site: u64 = store.site;
    let expected: String = "inj!cted".to_owned();
    let payload: DisasmPayload = build_disasm_payload(&mutated).expect("payload");
    let module: Module = Module::from_disasm(&payload);
    let imports: ImportMap = ImportMap::from_bytes(&mutated);
    let scoped: ScopedFeatures = disrobe_capabilities::extract(&module, &mutated, &imports);
    assert!(
        scoped
            .file
            .matches(&Feature::StringExact(expected))
            .contains(&site),
        "the altered immediate store must alter the recovered stack string"
    );
    assert!(
        !scoped
            .file
            .matches(&Feature::StringExact("injected".to_owned()))
            .contains(&site),
        "the original stack string must not survive the altered immediate store"
    );
}

#[test]
fn embedpe_oracle_anchors_at_the_carried_image() {
    let report: CapabilitiesReport = analyze(EMBEDPE);
    let embed: &CapabilityMatch =
        rule(&report, "contain an embedded pe").expect("embedded-pe capability fires");
    let offset: u64 = independent_embedded_pe_offset(EMBEDPE);
    assert_eq!(
        embed.address, offset,
        "embedded-pe must anchor at the carried MZ header"
    );
    assert!(
        offset != 0,
        "the carried image must sit at a non-zero offset"
    );
    assert!(
        embed
            .evidence
            .iter()
            .any(|e: &Evidence| e.feature.contains("embedded-pe")),
        "evidence must cite the embedded-pe characteristic: {:?}",
        embed.evidence
    );
    assert!(rule(&report, "write file").is_none());
    assert!(rule(&report, "connect to network resource").is_none());
}

#[test]
fn global_and_file_features_reflect_the_real_pe_target() {
    let payload: DisasmPayload = build_disasm_payload(WRITEFILE).expect("payload");
    let module: Module = Module::from_disasm(&payload);
    let imports: ImportMap = ImportMap::from_bytes(WRITEFILE);
    let scoped: ScopedFeatures = disrobe_capabilities::extract(&module, WRITEFILE, &imports);

    assert!(
        !scoped
            .file
            .matches(&Feature::Os("windows".to_owned()))
            .is_empty(),
        "a real PE must carry the windows os global feature"
    );
    assert!(
        !scoped
            .file
            .matches(&Feature::Arch("amd64".to_owned()))
            .is_empty(),
        "a 64-bit PE must carry the amd64 arch global feature"
    );
    assert!(
        !scoped
            .file
            .matches(&Feature::Format("pe".to_owned()))
            .is_empty(),
        "a PE must carry the pe format global feature"
    );
    assert!(
        scoped
            .file
            .matches(&Feature::Os("linux".to_owned()))
            .is_empty(),
        "a PE must not claim a linux os"
    );
    assert!(
        !scoped
            .file
            .matches(&Feature::Import("kernel32!WriteFile".to_owned()))
            .is_empty(),
        "the real import table must surface as import features"
    );
    assert!(
        !scoped
            .file
            .matches(&Feature::Section(".text".to_owned()))
            .is_empty(),
        "the real section table must surface as section features"
    );
}

#[test]
fn clean_oracle_still_matches_nothing_after_new_features() {
    let report: CapabilitiesReport = analyze(CLEAN);
    assert_eq!(
        report.matched_rules, 0,
        "clean control must match no capability even with the new feature classes: {:?}",
        report.capabilities
    );
}

#[test]
fn report_serializes_with_schema_and_addresses() {
    let report: CapabilitiesReport = analyze(WRITEFILE);
    let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
    assert_eq!(
        value["schema"],
        serde_json::json!("disrobe.capabilities/v0")
    );
    let caps: &Vec<serde_json::Value> = value["capabilities"].as_array().expect("capabilities");
    assert!(!caps.is_empty());
    for cap in caps {
        let addr: u64 = cap
            .get("address")
            .and_then(serde_json::Value::as_u64)
            .expect("capability address");
        assert_addr_in_image("serialized capability", addr, WRITEFILE);
        let ev: &Vec<serde_json::Value> = cap["evidence"].as_array().expect("evidence array");
        assert!(
            !ev.is_empty(),
            "every serialized capability must carry at least one evidence record"
        );
        for e in ev {
            let ev_addr: u64 = e
                .get("address")
                .and_then(serde_json::Value::as_u64)
                .expect("evidence address");
            assert_addr_in_image("serialized evidence", ev_addr, WRITEFILE);
            let feature: &str = e
                .get("feature")
                .and_then(serde_json::Value::as_str)
                .expect("evidence feature");
            assert!(!feature.is_empty(), "evidence feature must be non-empty");
        }
    }
}
