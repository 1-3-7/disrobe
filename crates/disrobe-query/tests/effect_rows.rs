use std::mem::size_of;

use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind};
use disrobe_nir::{
    EffectContext, EffectContextError, EffectRow, HardEffect, HardEffects, ImportEffectModel,
    ImportKey, NirFunction, NirInstr, NirModule, NirOp, SourceLang, SourceRef,
};
use disrobe_query::{Function, FunctionId, InsnView, Module};

fn native_instruction(address: u64, op: NirOp) -> NirInstr {
    NirInstr {
        address,
        op,
        source: SourceRef::new(SourceLang::NativeX86, address),
        ..NirInstr::default()
    }
}

fn native_module(instructions: Vec<NirInstr>) -> NirModule {
    let source: SourceRef = SourceRef::new(SourceLang::NativeX86, 0x1000);
    NirModule {
        source_hash: [0x43; 32],
        lang: SourceLang::NativeX86,
        functions: vec![NirFunction {
            name: "entry".to_owned(),
            address: 0x1000,
            end: 0x1010,
            is_export: true,
            instructions,
            source,
        }],
        symbols: Vec::new(),
    }
}

#[test]
fn query_instructions_expose_canonical_rows_with_unknown_distinct_from_none() {
    let module: Module = Module::from_nir(&native_module(vec![
        native_instruction(0x1000, NirOp::Nop),
        native_instruction(
            0x1001,
            NirOp::ExternCall {
                symbol: "recv".to_owned(),
            },
        ),
        native_instruction(0x1002, NirOp::Return),
    ]));
    let instructions: &[InsnView] = &module.functions()[0].instructions;

    assert!(instructions[0].effects.is_effect_free());
    assert!(!instructions[0].effects.is_unknown());
    assert!(instructions[1].effects.contains(HardEffect::ImportCall));
    assert!(instructions[1].effects.is_unknown());
    assert!(instructions[2].effects.contains(HardEffect::Return));
}

#[test]
fn query_effect_context_resolves_import_provenance_without_changing_instruction_identity()
-> Result<(), &'static str> {
    let nir: NirModule = native_module(vec![native_instruction(
        0x1000,
        NirOp::ExternCall {
            symbol: "recv".to_owned(),
        },
    )]);
    let mut duplicated: NirModule = nir;
    duplicated.functions.push(NirFunction {
        name: "same_address_peer".to_owned(),
        address: 0x1000,
        end: 0x1001,
        is_export: false,
        instructions: vec![native_instruction(0x1000, NirOp::Return)],
        source: SourceRef::new(SourceLang::NativeX86, 0x1000),
    });
    let unresolved: Module = Module::from_nir(&duplicated);
    let unresolved_function: Option<&Function> = unresolved
        .functions()
        .iter()
        .find(|function: &&Function| function.name == "entry");
    let unresolved_function: &Function =
        unresolved_function.ok_or("entry function is missing from the unresolved query module")?;
    let unresolved_id: FunctionId = unresolved.function_id(unresolved_function);
    let mut context: EffectContext = EffectContext::new();
    let inserted: Result<(), EffectContextError> = context.insert_import(
        ImportKey::new("recv"),
        ImportEffectModel::new(HardEffects::of(HardEffect::MemoryWrite)),
    );
    assert!(inserted.is_ok(), "{inserted:?}");

    let resolved: Module = Module::from_nir_with_effect_context(&duplicated, &context);
    let resolved_function: Option<&Function> = resolved
        .functions()
        .iter()
        .find(|function: &&Function| function.name == "entry");
    let resolved_function: &Function =
        resolved_function.ok_or("entry function is missing from the resolved query module")?;
    let row: EffectRow = resolved_function.instructions[0].effects;
    assert!(row.contains(HardEffect::ImportCall));
    assert!(row.contains(HardEffect::MemoryWrite));
    assert!(!row.is_unknown());
    assert_eq!(resolved.function_id(resolved_function), unresolved_id);
    let encoded_result: Result<serde_json::Value, serde_json::Error> =
        serde_json::to_value(&resolved);
    assert!(encoded_result.is_ok(), "{encoded_result:?}");
    let encoded: serde_json::Value = encoded_result.unwrap_or(serde_json::Value::Null);
    assert_eq!(
        encoded["functions"][0]["instructions"][0]["effects"]["import"],
        serde_json::json!(["memory-write"])
    );
    Ok(())
}

#[test]
fn disasm_query_modules_use_the_authoritative_nir_effect_derivation() {
    let payload: DisasmPayload = DisasmPayload {
        source_hash: [0x44; 32],
        instructions: vec![DisasmInstruction {
            offset: 0x2000,
            bytes: vec![0xc3],
            mnemonic: "ret".to_owned(),
            operands: Vec::new(),
            flow: disrobe_ir::payload::InsnFlow::Return,
            ..DisasmInstruction::default()
        }],
        symbol_table: vec![DisasmSymbol {
            address: 0x2000,
            name: "entry".to_owned(),
            kind: DisasmSymbolKind::Export,
        }],
    };
    let unknown: Module = Module::from_disasm(&payload);
    let unknown_row: EffectRow = unknown.functions()[0].instructions[0].effects;
    assert_eq!(unknown_row.lang(), SourceLang::Unknown);
    assert!(unknown_row.is_unknown());

    let arm: Module = Module::from_disasm_as(&payload, SourceLang::NativeArm);
    let arm_row: EffectRow = arm.functions()[0].instructions[0].effects;
    assert_eq!(arm_row.lang(), SourceLang::NativeArm);
    assert!(arm_row.contains(HardEffect::Return));
    assert!(arm_row.contains(HardEffect::RegisterRead));
}

#[test]
fn attached_effect_rows_remain_compact() {
    println!("effect_row_bytes={}", size_of::<EffectRow>());
    assert!(size_of::<EffectRow>() <= 32, "{}", size_of::<EffectRow>());
}
