use wasmparser::Operator;

/// Stable, human-readable mnemonic for any WebAssembly operator.
#[must_use]
pub(crate) fn operator_mnemonic(op: &Operator<'_>) -> String {
    if let Some(name) = explicit_mnemonic(op) {
        return name.to_owned();
    }
    discriminant_name(op)
}

#[allow(clippy::too_many_lines)]
const fn explicit_mnemonic(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::Unreachable => "unreachable",
        Operator::Nop => "nop",
        Operator::Block { .. } => "block",
        Operator::Loop { .. } => "loop",
        Operator::If { .. } => "if",
        Operator::Else => "else",
        Operator::End => "end",
        Operator::Br { .. } => "br",
        Operator::BrIf { .. } => "br_if",
        Operator::BrTable { .. } => "br_table",
        Operator::Return => "return",
        Operator::Call { .. } => "call",
        Operator::CallIndirect { .. } => "call_indirect",
        Operator::ReturnCall { .. } => "return_call",
        Operator::ReturnCallIndirect { .. } => "return_call_indirect",
        Operator::Drop => "drop",
        Operator::Select => "select",
        Operator::TypedSelect { .. } => "select",
        Operator::LocalGet { .. } => "local.get",
        Operator::LocalSet { .. } => "local.set",
        Operator::LocalTee { .. } => "local.tee",
        Operator::GlobalGet { .. } => "global.get",
        Operator::GlobalSet { .. } => "global.set",
        Operator::I32Const { .. } => "i32.const",
        Operator::I64Const { .. } => "i64.const",
        Operator::F32Const { .. } => "f32.const",
        Operator::F64Const { .. } => "f64.const",
        Operator::MemorySize { .. } => "memory.size",
        Operator::MemoryGrow { .. } => "memory.grow",
        Operator::MemoryCopy { .. } => "memory.copy",
        Operator::MemoryFill { .. } => "memory.fill",
        Operator::MemoryInit { .. } => "memory.init",
        Operator::DataDrop { .. } => "data.drop",
        Operator::TableGet { .. } => "table.get",
        Operator::TableSet { .. } => "table.set",
        Operator::TableSize { .. } => "table.size",
        Operator::TableGrow { .. } => "table.grow",
        Operator::TableFill { .. } => "table.fill",
        Operator::TableCopy { .. } => "table.copy",
        Operator::TableInit { .. } => "table.init",
        Operator::ElemDrop { .. } => "elem.drop",
        Operator::RefNull { .. } => "ref.null",
        Operator::RefIsNull => "ref.is_null",
        Operator::RefFunc { .. } => "ref.func",
        _ => return None,
    })
}

fn discriminant_name(op: &Operator<'_>) -> String {
    let raw: String = format!("{op:?}");
    let head: &str = raw.split([' ', '(', '{']).next().unwrap_or("op");
    head.to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn names_known_ops_explicitly() {
        assert_eq!(operator_mnemonic(&Operator::Drop), "drop");
        assert_eq!(operator_mnemonic(&Operator::Return), "return");
        assert_eq!(operator_mnemonic(&Operator::RefIsNull), "ref.is_null");
        assert_eq!(
            operator_mnemonic(&Operator::MemoryFill { mem: 0 }),
            "memory.fill"
        );
    }

    #[test]
    fn falls_back_to_discriminant_for_unlisted() {
        let name: String = operator_mnemonic(&Operator::I32Add);
        assert_eq!(name, "I32Add");
    }
}
