use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_wasm_deob::{FunctionSig, ModuleSignatures, extract_signatures};
use wasmparser::{FunctionBody, Operator, Parser, Payload};

use crate::error::{LiftError, Result};
use crate::operand::{f32_operand, f64_operand};
use crate::usize_to_u32_saturating;

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
    let depth_offsets: Vec<(u32, u64)> = control_stack_targets(&operators, base);
    let byte_arith: Vec<bool> = byte_arith_flags(&operators);

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(operators.len());
    for (ordinal, (op, _byte_offset)) in operators.iter().enumerate() {
        let address: u64 = base.saturating_add(ordinal as u64);
        let nir_op: NirOp = classify_op(op, &depth_offsets);
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

fn control_stack_targets(operators: &[(Operator<'_>, usize)], base: u64) -> Vec<(u32, u64)> {
    let mut stack: Vec<(bool, u64)> = Vec::new();
    let mut targets: Vec<(u32, u64)> = Vec::new();
    for (ordinal, (op, _)) in operators.iter().enumerate() {
        let address: u64 = base.saturating_add(ordinal as u64);
        match op {
            Operator::Loop { .. } => stack.push((true, address)),
            Operator::Block { .. } | Operator::If { .. } | Operator::TryTable { .. } => {
                stack.push((false, address));
            }
            Operator::End => {
                if let Some((is_loop, header)) = stack.pop() {
                    let target: u64 = if is_loop { header } else { address };
                    let depth: u32 = usize_to_u32_saturating(stack.len());
                    targets.push((depth, target));
                }
            }
            _ => {}
        }
    }
    targets
}

fn branch_target(relative_depth: u32, depth_offsets: &[(u32, u64)]) -> Option<u64> {
    depth_offsets
        .iter()
        .rev()
        .find(|(depth, _): &&(u32, u64)| *depth == relative_depth)
        .map(|(_, addr): &(u32, u64)| *addr)
}

fn classify_op(op: &Operator<'_>, depth_offsets: &[(u32, u64)]) -> NirOp {
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
        Operator::Br { relative_depth } => NirOp::Branch {
            target: branch_target(*relative_depth, depth_offsets),
        },
        Operator::BrIf { relative_depth } => NirOp::CondBranch {
            target: branch_target(*relative_depth, depth_offsets),
        },
        Operator::BrTable { targets } => NirOp::CondBranch {
            target: branch_target(targets.default(), depth_offsets),
        },
        Operator::If { .. } => NirOp::CondBranch { target: None },
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
mod tests {
    use super::{LiftError, MAX_WASM_OPERATORS_PER_FUNCTION, count_u32, lift_wasm_module};

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
}
