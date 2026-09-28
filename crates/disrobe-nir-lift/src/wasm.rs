use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_wasm_deob::{FunctionSig, ModuleSignatures, extract_signatures};
use wasmparser::{FunctionBody, Operator, Parser, Payload};

use crate::error::{LiftError, Result};
use crate::operand::{f32_operand, f64_operand};

const FUNCTION_STRIDE: u64 = 1 << 20;
const MAX_WASM_OPERATORS_PER_FUNCTION: usize = 1 << 18;

pub fn lift_wasm_module(bytes: &[u8]) -> Result<NirModule> {
    let signatures: ModuleSignatures =
        extract_signatures(bytes).map_err(|e: disrobe_pass_wasm_deob::Error| {
            LiftError::Source(format!("wasm signature extraction: {e}"))
        })?;
    let imported_count: u32 = count_u32("imported function", signatures.imported_function_count())?;

    let source_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Wasm);

    register_symbols(&signatures, &mut module)?;

    let mut defined_index: u32 = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> =
            payload.map_err(|e| LiftError::Source(format!("wasm parse: {e}")))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let Some(function_index): Option<u32> = imported_count.checked_add(defined_index)
            else {
                return Err(LiftError::Source(
                    "wasm function index exceeds u32".to_owned(),
                ));
            };
            let function: NirFunction = lift_body(&body, function_index, &signatures)?;
            module.functions.push(function);
            let Some(next_index): Option<u32> = defined_index.checked_add(1) else {
                return Err(LiftError::Source(
                    "wasm defined function count exceeds u32".to_owned(),
                ));
            };
            defined_index = next_index;
        }
    }

    if module.functions.is_empty() {
        return Err(LiftError::Empty);
    }
    Ok(module)
}

fn count_u32(label: &str, value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| LiftError::Source(format!("wasm {label} count exceeds u32")))
}

#[must_use]
pub const fn function_address(function_index: u32) -> u64 {
    (function_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

fn register_symbols(signatures: &ModuleSignatures, module: &mut NirModule) -> Result<()> {
    let Some(total_usize): Option<usize> = signatures
        .imported_function_count()
        .checked_add(signatures.defined().len())
    else {
        return Err(LiftError::Source(
            "wasm function count overflows usize".to_owned(),
        ));
    };
    let total: u32 = count_u32("function", total_usize)?;
    for function_index in 0..total {
        let Some(sig): Option<&FunctionSig> = signatures.by_function_index(function_index) else {
            continue;
        };
        let kind: SymbolKind = if sig.imported {
            SymbolKind::Import
        } else if sig.exported {
            SymbolKind::Export
        } else {
            SymbolKind::Function
        };
        module.symbols.push(NirSymbol {
            address: function_address(function_index),
            name: sig.name.clone(),
            kind,
        });
    }
    Ok(())
}

fn lift_body(
    body: &FunctionBody<'_>,
    function_index: u32,
    signatures: &ModuleSignatures,
) -> Result<NirFunction> {
    let base: u64 = function_address(function_index);
    let sig: Option<&FunctionSig> = signatures.by_function_index(function_index);
    let name: String = sig.map_or_else(
        || format!("func_{function_index}"),
        |s: &FunctionSig| s.name.clone(),
    );
    let is_export: bool = sig.is_some_and(|s: &FunctionSig| s.exported);

    let operators: Vec<(Operator<'_>, usize)> = collect_operators(body)?;
    let control_targets: BTreeMap<usize, u64> = control_targets(&operators, base);
    let byte_arith: Vec<bool> = byte_arith_flags(&operators);

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(operators.len());
    for (ordinal, (op, _byte_offset)) in operators.iter().enumerate() {
        let address: u64 = base.saturating_add(ordinal as u64);
        let nir_op: NirOp = classify_op(op, control_targets.get(&ordinal).copied());
        let (reads_memory, writes_memory, mem_byte): (bool, bool, bool) = memory_facets(op);
        let is_byte_arith: bool = byte_arith.get(ordinal).is_some_and(|value: &bool| *value);
        let mut operand_list: Vec<String> = operands(op, signatures);
        if is_byte_arith {
            operand_list.push("byte stack".to_owned());
        }
        instructions.push(NirInstr {
            address,
            op: nir_op,
            mnemonic: mnemonic(op),
            operands: operand_list,
            reads_memory,
            writes_memory,
            byte_width: mem_byte || is_byte_arith,
            source: SourceRef::new(SourceLang::Wasm, address),
        });
    }

    let end: u64 = base.saturating_add(instructions.len() as u64);
    Ok(NirFunction {
        name,
        address: base,
        end,
        is_export,
        instructions,
        source: SourceRef::labelled(SourceLang::Wasm, base, format!("func_{function_index}")),
    })
}

fn collect_operators<'a>(body: &FunctionBody<'a>) -> Result<Vec<(Operator<'a>, usize)>> {
    let reader: wasmparser::OperatorsReader<'a> = body
        .get_operators_reader()
        .map_err(|e| LiftError::Source(format!("wasm operators: {e}")))?;
    let mut out: Vec<(Operator<'a>, usize)> = Vec::new();
    for item in reader.into_iter_with_offsets() {
        let pair: (Operator<'a>, usize) =
            item.map_err(|e| LiftError::Source(format!("wasm operator decode: {e}")))?;
        if out.len() >= MAX_WASM_OPERATORS_PER_FUNCTION {
            return Err(LiftError::Source(format!(
                "wasm function exceeds {MAX_WASM_OPERATORS_PER_FUNCTION} operators"
            )));
        }
        out.push(pair);
    }
    Ok(out)
}

const BYTE_ARITH_WINDOW: usize = 4;

fn byte_arith_flags(operators: &[(Operator<'_>, usize)]) -> Vec<bool> {
    let mut flags: Vec<bool> = vec![false; operators.len()];
    let mut byte_memory_seen_at: Option<usize> = None;
    for (ordinal, (op, _)) in operators.iter().enumerate() {
        if matches!(
            op,
            Operator::Block { .. }
                | Operator::Loop { .. }
                | Operator::If { .. }
                | Operator::Else
                | Operator::End
        ) {
            byte_memory_seen_at = None;
            continue;
        }
        if is_byte_width(op) {
            byte_memory_seen_at = Some(ordinal);
            continue;
        }
        if binary_op(op).is_some()
            && byte_memory_seen_at
                .is_some_and(|seen: usize| ordinal.saturating_sub(seen) <= BYTE_ARITH_WINDOW)
            && let Some(flag) = flags.get_mut(ordinal)
        {
            *flag = true;
        }
    }
    flags
}

struct ControlFrame {
    is_loop: bool,
    start: usize,
}

fn control_targets(operators: &[(Operator<'_>, usize)], base: u64) -> BTreeMap<usize, u64> {
    let mut open: Vec<usize> = Vec::new();
    let mut end_of: BTreeMap<usize, usize> = BTreeMap::new();
    let mut else_of: BTreeMap<usize, usize> = BTreeMap::new();
    for (ordinal, (op, _)) in operators.iter().enumerate() {
        match op {
            Operator::Block { .. }
            | Operator::Loop { .. }
            | Operator::If { .. }
            | Operator::TryTable { .. } => open.push(ordinal),
            Operator::Else => {
                if let Some(start) = open.last() {
                    else_of.insert(*start, ordinal);
                }
            }
            Operator::End => {
                if let Some(start) = open.pop() {
                    end_of.insert(start, ordinal);
                }
            }
            _ => {}
        }
    }
    let address = |ordinal: usize| -> u64 { base.saturating_add(ordinal as u64) };
    let mut frames: Vec<ControlFrame> = Vec::new();
    let mut targets: BTreeMap<usize, u64> = BTreeMap::new();
    for (ordinal, (op, _)) in operators.iter().enumerate() {
        let label = |relative_depth: u32, frames: &[ControlFrame]| -> Option<u64> {
            let index: usize = frames
                .len()
                .checked_sub(1)?
                .checked_sub(usize::try_from(relative_depth).ok()?)?;
            let frame: &ControlFrame = frames.get(index)?;
            if frame.is_loop {
                Some(address(frame.start))
            } else {
                end_of.get(&frame.start).map(|end: &usize| address(*end))
            }
        };
        match op {
            Operator::Loop { .. } => frames.push(ControlFrame {
                is_loop: true,
                start: ordinal,
            }),
            Operator::Block { .. } | Operator::TryTable { .. } => frames.push(ControlFrame {
                is_loop: false,
                start: ordinal,
            }),
            Operator::If { .. } => {
                let false_edge: Option<usize> = else_of
                    .get(&ordinal)
                    .map(|else_at: &usize| else_at.saturating_add(1))
                    .or_else(|| end_of.get(&ordinal).copied());
                if let Some(target) = false_edge {
                    targets.insert(ordinal, address(target));
                }
                frames.push(ControlFrame {
                    is_loop: false,
                    start: ordinal,
                });
            }
            Operator::Else => {
                if let Some(frame) = frames.last()
                    && let Some(end) = end_of.get(&frame.start)
                {
                    targets.insert(ordinal, address(*end));
                }
            }
            Operator::End => {
                frames.pop();
            }
            Operator::Br { relative_depth } | Operator::BrIf { relative_depth } => {
                if let Some(target) = label(*relative_depth, &frames) {
                    targets.insert(ordinal, target);
                }
            }
            Operator::BrTable { targets: table } => {
                if let Some(target) = label(table.default(), &frames) {
                    targets.insert(ordinal, target);
                }
            }
            _ => {}
        }
    }
    targets
}

fn classify_op(op: &Operator<'_>, control_target: Option<u64>) -> NirOp {
    match op {
        Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
            NirOp::Call {
                target: Some(function_address(*function_index)),
            }
        }
        Operator::CallIndirect { .. }
        | Operator::ReturnCallIndirect { .. }
        | Operator::CallRef { .. }
        | Operator::ReturnCallRef { .. } => NirOp::IndirectCall,
        Operator::Br { .. } | Operator::Else => NirOp::Branch {
            target: control_target,
        },
        Operator::BrIf { .. } | Operator::BrTable { .. } | Operator::If { .. } => {
            NirOp::CondBranch {
                target: control_target,
            }
        }
        Operator::Return => NirOp::Return,
        Operator::Unreachable => NirOp::Interrupt,
        Operator::I32Const { .. }
        | Operator::I64Const { .. }
        | Operator::F32Const { .. }
        | Operator::F64Const { .. } => NirOp::Const,
        _ => binary_op(op).map_or_else(
            || {
                if is_load(op) {
                    NirOp::Load
                } else if is_store(op) {
                    NirOp::Store
                } else {
                    NirOp::Nop
                }
            },
            |binary_op: BinaryOp| NirOp::BinOp { op: binary_op },
        ),
    }
}

const fn binary_op(op: &Operator<'_>) -> Option<BinaryOp> {
    Some(match op {
        Operator::I32Add | Operator::I64Add | Operator::F32Add | Operator::F64Add => BinaryOp::Add,
        Operator::I32Sub | Operator::I64Sub | Operator::F32Sub | Operator::F64Sub => BinaryOp::Sub,
        Operator::I32Mul | Operator::I64Mul | Operator::F32Mul | Operator::F64Mul => BinaryOp::Mul,
        Operator::I32DivS
        | Operator::I32DivU
        | Operator::I64DivS
        | Operator::I64DivU
        | Operator::F32Div
        | Operator::F64Div => BinaryOp::Div,
        Operator::I32RemS | Operator::I32RemU | Operator::I64RemS | Operator::I64RemU => {
            BinaryOp::Rem
        }
        Operator::I32And | Operator::I64And => BinaryOp::And,
        Operator::I32Or | Operator::I64Or => BinaryOp::Or,
        Operator::I32Xor | Operator::I64Xor => BinaryOp::Xor,
        Operator::I32Shl | Operator::I64Shl => BinaryOp::Shl,
        Operator::I32ShrS | Operator::I32ShrU | Operator::I64ShrS | Operator::I64ShrU => {
            BinaryOp::Shr
        }
        Operator::I32Rotl | Operator::I64Rotl => BinaryOp::Rol,
        Operator::I32Rotr | Operator::I64Rotr => BinaryOp::Ror,
        _ => return None,
    })
}

const fn is_load(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::I32Load { .. }
            | Operator::I64Load { .. }
            | Operator::F32Load { .. }
            | Operator::F64Load { .. }
            | Operator::I32Load8S { .. }
            | Operator::I32Load8U { .. }
            | Operator::I32Load16S { .. }
            | Operator::I32Load16U { .. }
            | Operator::I64Load8S { .. }
            | Operator::I64Load8U { .. }
            | Operator::I64Load16S { .. }
            | Operator::I64Load16U { .. }
            | Operator::I64Load32S { .. }
            | Operator::I64Load32U { .. }
    )
}

const fn is_store(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::I32Store { .. }
            | Operator::I64Store { .. }
            | Operator::F32Store { .. }
            | Operator::F64Store { .. }
            | Operator::I32Store8 { .. }
            | Operator::I32Store16 { .. }
            | Operator::I64Store8 { .. }
            | Operator::I64Store16 { .. }
            | Operator::I64Store32 { .. }
    )
}

const fn is_byte_width(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::I32Load8S { .. }
            | Operator::I32Load8U { .. }
            | Operator::I64Load8S { .. }
            | Operator::I64Load8U { .. }
            | Operator::I32Store8 { .. }
            | Operator::I64Store8 { .. }
    )
}

const fn memory_facets(op: &Operator<'_>) -> (bool, bool, bool) {
    (is_load(op), is_store(op), is_byte_width(op))
}

fn operands(op: &Operator<'_>, signatures: &ModuleSignatures) -> Vec<String> {
    match op {
        Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
            let name: String = signatures
                .by_function_index(*function_index)
                .map_or_else(|| format!("func_{function_index}"), |s| s.name.clone());
            vec![name]
        }
        Operator::LocalGet { local_index } | Operator::LocalSet { local_index } => {
            vec![format!("local{local_index}")]
        }
        Operator::GlobalGet { global_index } | Operator::GlobalSet { global_index } => {
            vec![format!("global{global_index}")]
        }
        Operator::I32Const { value } => vec![value.to_string()],
        Operator::I64Const { value } => vec![value.to_string()],
        Operator::F32Const { value } => vec![f32_operand(value.bits())],
        Operator::F64Const { value } => vec![f64_operand(value.bits())],
        Operator::I32Load8U { memarg }
        | Operator::I32Load8S { memarg }
        | Operator::I64Load8U { memarg }
        | Operator::I64Load8S { memarg }
        | Operator::I32Store8 { memarg }
        | Operator::I64Store8 { memarg } => {
            vec![format!("byte [mem+0x{:x}]", memarg.offset)]
        }
        Operator::I32Load { memarg }
        | Operator::I64Load { memarg }
        | Operator::I32Store { memarg }
        | Operator::I64Store { memarg } => {
            vec![format!("[mem+0x{:x}]", memarg.offset)]
        }
        _ => Vec::new(),
    }
}

fn mnemonic(op: &Operator<'_>) -> String {
    if let Some(explicit) = explicit_mnemonic(op) {
        return explicit.to_owned();
    }
    if let Some(binary_op) = binary_op(op) {
        return binary_op.mnemonic().to_owned();
    }
    let raw: String = format!("{op:?}");
    raw.split([' ', '(', '{'])
        .next()
        .map_or("op", |value: &str| value)
        .to_ascii_lowercase()
}

const fn explicit_mnemonic(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::Call { .. } => "call",
        Operator::ReturnCall { .. } => "return_call",
        Operator::CallIndirect { .. } => "call_indirect",
        Operator::ReturnCallIndirect { .. } => "return_call_indirect",
        Operator::CallRef { .. } => "call_ref",
        Operator::ReturnCallRef { .. } => "return_call_ref",
        Operator::Br { .. } => "br",
        Operator::BrIf { .. } => "br_if",
        Operator::BrTable { .. } => "br_table",
        Operator::Return => "return",
        Operator::Unreachable => "unreachable",
        Operator::Nop => "nop",
        Operator::Block { .. } => "block",
        Operator::Loop { .. } => "loop",
        Operator::If { .. } => "if",
        Operator::Else => "else",
        Operator::End => "end",
        Operator::Drop => "drop",
        Operator::Select => "select",
        Operator::LocalGet { .. } => "local.get",
        Operator::LocalSet { .. } => "local.set",
        Operator::LocalTee { .. } => "local.tee",
        Operator::GlobalGet { .. } => "global.get",
        Operator::GlobalSet { .. } => "global.set",
        Operator::I32Const { .. } => "i32.const",
        Operator::I64Const { .. } => "i64.const",
        Operator::F32Const { .. } => "f32.const",
        Operator::F64Const { .. } => "f64.const",
        Operator::I32Load8U { .. } => "i32.load8_u",
        Operator::I32Load8S { .. } => "i32.load8_s",
        Operator::I32Store8 { .. } => "i32.store8",
        _ => return None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        LiftError, MAX_WASM_OPERATORS_PER_FUNCTION, NirFunction, NirInstr, NirModule, NirOp,
        count_u32, function_address, lift_wasm_module,
    };

    fn ops_of(wat: &str) -> Vec<(String, NirOp, u64)> {
        let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble");
        let module: NirModule = lift_wasm_module(&bytes).expect("lift");
        module.functions[0]
            .instructions
            .iter()
            .map(|instr: &NirInstr| (instr.mnemonic.clone(), instr.op.clone(), instr.address))
            .collect()
    }

    #[test]
    fn a_branch_out_of_a_loop_targets_the_enclosing_block_end() {
        let ops: Vec<(String, NirOp, u64)> =
            ops_of("(module (func (param i32) block loop local.get 0 br_if 1 br 0 end end))");
        let end_of_block: u64 = ops.last().expect("final end").2 - 1;
        let loop_head: u64 = ops
            .iter()
            .find(|(mnemonic, _, _): &&(String, NirOp, u64)| mnemonic == "loop")
            .expect("loop")
            .2;
        let br_if: &NirOp = &ops
            .iter()
            .find(|(mnemonic, _, _): &&(String, NirOp, u64)| mnemonic == "br_if")
            .expect("br_if")
            .1;
        let br: &NirOp = &ops
            .iter()
            .find(|(mnemonic, _, _): &&(String, NirOp, u64)| mnemonic == "br")
            .expect("br")
            .1;
        assert_eq!(
            br_if,
            &NirOp::CondBranch {
                target: Some(end_of_block)
            }
        );
        assert_eq!(
            br,
            &NirOp::Branch {
                target: Some(loop_head)
            }
        );
    }

    #[test]
    fn if_and_else_carry_their_false_and_join_edges() {
        let ops: Vec<(String, NirOp, u64)> = ops_of(
            "(module (func (param i32) (result i32) local.get 0 if (result i32) i32.const 1 else i32.const 2 end))",
        );
        let address_of = |name: &str| -> u64 {
            ops.iter()
                .find(|(mnemonic, _, _): &&(String, NirOp, u64)| mnemonic == name)
                .expect(name)
                .2
        };
        let if_op: &NirOp = &ops
            .iter()
            .find(|(mnemonic, _, _): &&(String, NirOp, u64)| mnemonic == "if")
            .expect("if")
            .1;
        let else_op: &NirOp = &ops
            .iter()
            .find(|(mnemonic, _, _): &&(String, NirOp, u64)| mnemonic == "else")
            .expect("else")
            .1;
        let end_of_if: u64 = ops[ops.len() - 2].2;
        assert_eq!(
            if_op,
            &NirOp::CondBranch {
                target: Some(address_of("else") + 1)
            }
        );
        assert_eq!(
            else_op,
            &NirOp::Branch {
                target: Some(end_of_if)
            }
        );
    }

    fn leb_u32(mut value: u32) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let mut byte: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn leb_usize(value: usize) -> Vec<u8> {
        leb_u32(u32::try_from(value).map_or(u32::MAX, std::convert::identity))
    }

    fn push_section(module: &mut Vec<u8>, id: u8, content: &[u8]) {
        module.push(id);
        module.extend(leb_usize(content.len()));
        module.extend_from_slice(content);
    }

    fn oversized_function_module() -> Vec<u8> {
        let mut module: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();

        let mut types: Vec<u8> = Vec::new();
        types.extend(leb_u32(1));
        types.push(0x60);
        types.push(0);
        types.push(0);
        push_section(&mut module, 1, &types);

        let mut functions: Vec<u8> = Vec::new();
        functions.extend(leb_u32(1));
        functions.push(0);
        push_section(&mut module, 3, &functions);

        let body_size: usize = 1 + MAX_WASM_OPERATORS_PER_FUNCTION + 1;
        let mut code: Vec<u8> = Vec::with_capacity(1 + body_size);
        code.extend(leb_u32(1));
        code.extend(leb_usize(body_size));
        code.push(0);
        code.extend(std::iter::repeat_n(0x01, MAX_WASM_OPERATORS_PER_FUNCTION));
        code.push(0x0b);
        push_section(&mut module, 10, &code);

        module
    }

    #[test]
    fn oversized_wasm_function_is_rejected_before_unbounded_lift() {
        let bytes: Vec<u8> = oversized_function_module();
        let result: crate::Result<disrobe_nir::NirModule> = lift_wasm_module(&bytes);
        assert!(matches!(
            result,
            Err(LiftError::Source(message)) if message.contains("operator")
        ));
    }

    #[test]
    fn oversized_wasm_function_count_is_rejected() {
        let result: crate::Result<u32> = count_u32("function", usize::MAX);
        assert!(matches!(
            result,
            Err(LiftError::Source(message)) if message.contains("count exceeds u32")
        ));
    }

    fn single_function_module(body: &[u8]) -> Vec<u8> {
        let mut module: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();

        let mut types: Vec<u8> = Vec::new();
        types.extend(leb_u32(1));
        types.push(0x60);
        types.push(0);
        types.push(0);
        push_section(&mut module, 1, &types);

        let mut functions: Vec<u8> = Vec::new();
        functions.extend(leb_u32(1));
        functions.push(0);
        push_section(&mut module, 3, &functions);

        let mut function_body: Vec<u8> = Vec::new();
        function_body.extend(leb_u32(0));
        function_body.extend_from_slice(body);

        let mut code: Vec<u8> = Vec::new();
        code.extend(leb_u32(1));
        code.extend(leb_usize(function_body.len()));
        code.extend_from_slice(&function_body);
        push_section(&mut module, 10, &code);

        module
    }

    #[test]
    fn sequential_block_branch_resolves_to_last_matching_frame() {
        let body: [u8; 9] = [0x02, 0x40, 0x0b, 0x02, 0x40, 0x0c, 0x00, 0x0b, 0x0b];
        let bytes: Vec<u8> = single_function_module(&body);
        let module: NirModule = lift_wasm_module(&bytes).expect("small module must lift");
        let base: u64 = function_address(0);
        let function: &NirFunction = &module.functions[0];
        let branch: &NirInstr = function
            .instructions
            .iter()
            .find(|i: &&NirInstr| matches!(i.op, NirOp::Branch { .. }))
            .expect("a branch instruction");
        assert_eq!(
            branch.op,
            NirOp::Branch {
                target: Some(base + 4)
            },
            "br must resolve to the most recent frame recorded at its relative depth"
        );
    }

    #[test]
    fn branch_resolution_stays_linear_on_dense_blocks_and_branches() {
        let frames: usize = 40_000;
        let branches: usize = 40_000;
        let mut body: Vec<u8> = Vec::with_capacity(frames * 2 + branches * 6 + frames + 1);
        for _ in 0..frames {
            body.extend_from_slice(&[0x02, 0x40]);
        }
        for _ in 0..branches {
            body.extend_from_slice(&[0x0c, 0xff, 0xff, 0xff, 0xff, 0x0f]);
        }
        body.extend(std::iter::repeat_n(0x0b, frames + 1));
        let bytes: Vec<u8> = single_function_module(&body);
        let start: std::time::Instant = std::time::Instant::now();
        let module: NirModule =
            lift_wasm_module(&bytes).expect("dense block/branch function must lift bounded");
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "branch resolution must stay linear in blocks and branches, took {elapsed:?}"
        );
        let function: &NirFunction = &module.functions[0];
        let all_unresolved: bool = function
            .instructions
            .iter()
            .filter(|i: &&NirInstr| matches!(i.op, NirOp::Branch { .. }))
            .all(|i: &NirInstr| matches!(i.op, NirOp::Branch { target: None }));
        assert!(
            all_unresolved,
            "an out-of-range relative depth must resolve to no target"
        );
    }
}
