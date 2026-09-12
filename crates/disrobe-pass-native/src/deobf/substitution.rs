use disrobe_mba::{Expr, Simplification, Width, simplify};
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

use super::mba_lift::lift_arith_value;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubstitutionResult {
    pub dest: String,
    pub original_expr: String,
    pub simplified_expr: String,
    pub original_nodes: u32,
    pub simplified_nodes: u32,
    pub proven: bool,
    pub changed: bool,
}

#[must_use]
pub fn simplify_sequence(bitness: u32, base: u64, bytes: &[u8]) -> Option<SubstitutionResult> {
    let insns: Vec<Instruction> = decode_all(bitness, base, bytes);
    if insns.is_empty() {
        return None;
    }
    let dest: Register = last_dest_register(&insns)?;
    let (expr, width): (Expr, Width) = lift_arith_value(&insns, dest)?;
    let result: Simplification = simplify(&expr, width);
    Some(SubstitutionResult {
        dest: format!("{dest:?}"),
        original_expr: result.original.to_string(),
        simplified_expr: result.simplified.to_string(),
        original_nodes: u32::try_from(result.original_nodes).unwrap_or(u32::MAX),
        simplified_nodes: u32::try_from(result.simplified_nodes).unwrap_or(u32::MAX),
        proven: result.verification.is_proven(),
        changed: result.changed(),
    })
}

fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

fn last_dest_register(insns: &[Instruction]) -> Option<Register> {
    use iced_x86::Mnemonic;
    insns
        .iter()
        .rev()
        .find(|i: &&Instruction| {
            i.op0_kind() == OpKind::Register
                && !matches!(
                    i.mnemonic(),
                    Mnemonic::Push
                        | Mnemonic::Pop
                        | Mnemonic::Ret
                        | Mnemonic::Cmp
                        | Mnemonic::Test
                        | Mnemonic::Lea
                )
        })
        .map(|i: &Instruction| i.op0_register())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
