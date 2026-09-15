#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::Path;

use disrobe_pass_wasm_deob::lift_module_faithful_wat;
use wasmparser::{MemArg, Operator, Parser, Payload, Validator, WasmFeatures};

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../corpus/wasm/wat/{name}"))
}

fn lift(name: &str) -> (Vec<u8>, Vec<u8>, String) {
    let text: String = fs::read_to_string(corpus(name)).expect("read corpus wat");
    let original: Vec<u8> = wat::parse_str(&text).expect("source wat must assemble");
    let lifted_wat: String =
        lift_module_faithful_wat(&original).expect("faithful lift must produce output");
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must re-assemble: {e}\n{lifted_wat}"));
    (original, lifted, lifted_wat)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MemFact {
    MemAccess { mnemonic: &'static str, memory: u32 },
    MemorySize(u32),
    MemoryGrow(u32),
    MemoryFill(u32),
    MemoryCopy { dst: u32, src: u32 },
    MemoryInit { mem: u32, data: u32 },
}

const fn mem_access(mnemonic: &'static str, memarg: &MemArg) -> MemFact {
    MemFact::MemAccess {
        mnemonic,
        memory: memarg.memory,
    }
}

#[allow(clippy::too_many_lines)]
const fn classify(op: &Operator<'_>) -> Option<MemFact> {
    Some(match op {
        Operator::I32Load { memarg } => mem_access("i32.load", memarg),
        Operator::I64Load { memarg } => mem_access("i64.load", memarg),
        Operator::F32Load { memarg } => mem_access("f32.load", memarg),
        Operator::F64Load { memarg } => mem_access("f64.load", memarg),
        Operator::I32Load8U { memarg } => mem_access("i32.load8_u", memarg),
        Operator::I32Load8S { memarg } => mem_access("i32.load8_s", memarg),
        Operator::I32Load16U { memarg } => mem_access("i32.load16_u", memarg),
        Operator::I32Load16S { memarg } => mem_access("i32.load16_s", memarg),
        Operator::I64Load8U { memarg } => mem_access("i64.load8_u", memarg),
        Operator::I64Load16U { memarg } => mem_access("i64.load16_u", memarg),
        Operator::I64Load32U { memarg } => mem_access("i64.load32_u", memarg),
        Operator::I32Store { memarg } => mem_access("i32.store", memarg),
        Operator::I64Store { memarg } => mem_access("i64.store", memarg),
        Operator::F32Store { memarg } => mem_access("f32.store", memarg),
        Operator::F64Store { memarg } => mem_access("f64.store", memarg),
        Operator::I32Store8 { memarg } => mem_access("i32.store8", memarg),
        Operator::I32Store16 { memarg } => mem_access("i32.store16", memarg),
        Operator::I64Store8 { memarg } => mem_access("i64.store8", memarg),
        Operator::I64Store16 { memarg } => mem_access("i64.store16", memarg),
        Operator::I64Store32 { memarg } => mem_access("i64.store32", memarg),
        Operator::MemorySize { mem } => MemFact::MemorySize(*mem),
        Operator::MemoryGrow { mem } => MemFact::MemoryGrow(*mem),
        Operator::MemoryFill { mem } => MemFact::MemoryFill(*mem),
        Operator::MemoryCopy { dst_mem, src_mem } => MemFact::MemoryCopy {
            dst: *dst_mem,
            src: *src_mem,
        },
        Operator::MemoryInit { data_index, mem } => MemFact::MemoryInit {
            mem: *mem,
            data: *data_index,
        },
        _ => return None,
    })
}

fn mem_facts(bytes: &[u8]) -> Vec<MemFact> {
    let mut facts: Vec<MemFact> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("payload parses") {
            let reader: wasmparser::OperatorsReader<'_> =
                body.get_operators_reader().expect("ops reader");
            for op in reader {
                if let Some(fact) = classify(&op.expect("op")) {
                    facts.push(fact);
                }
            }
        }
    }
    facts
}

fn memory_count(bytes: &[u8]) -> u32 {
    let mut count: u32 = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::MemorySection(reader) = payload.expect("payload parses") {
            for mem in reader {
                let _ = mem.expect("memory entry");
                count += 1;
            }
        }
    }
    count
}

#[test]
fn multi_memory_operands_survive_faithful_roundtrip() {
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift("multi_memory.wat");
    validate(&original).expect("source module validates");
    validate(&lifted).unwrap_or_else(|e| panic!("lifted module must validate: {e}\n{lifted_wat}"));

    assert_eq!(
        memory_count(&original),
        2,
        "fixture must declare two memories"
    );
    assert_eq!(
        memory_count(&lifted),
        memory_count(&original),
        "lifted module must preserve the memory count:\n{lifted_wat}"
    );

    let original_facts: Vec<MemFact> = mem_facts(&original);
    let lifted_facts: Vec<MemFact> = mem_facts(&lifted);
    assert_eq!(
        original_facts, lifted_facts,
        "every memory-index operand must round-trip identically:\n{lifted_wat}"
    );

    let referenced_second_memory: bool = original_facts.iter().any(|f| {
        matches!(
            f,
            MemFact::MemAccess { memory: 1, .. }
                | MemFact::MemorySize(1)
                | MemFact::MemoryGrow(1)
                | MemFact::MemoryFill(1)
                | MemFact::MemoryCopy { dst: 1, .. }
                | MemFact::MemoryInit { mem: 1, .. }
        )
    });
    assert!(
        referenced_second_memory,
        "fixture must exercise the non-zero memory index so the test is meaningful"
    );
}
