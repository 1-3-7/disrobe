use disrobe_mba::{
    BinOp as MbaBinOp, Expr as MbaExpr, Simplification, UnOp as MbaUnOp, Verification, Width,
    simplify,
};

use super::EazVmMethod;
use super::lift::{LiftedBody, LiftedInstr, LiftedOperand};
use super::opcodes::CilOp;

const EAZVM_I4_TYPE_CODE: i32 = 0x101;
const MAX_METHODS_PER_IMAGE: usize = 1_024;
const MAX_INSTRUCTIONS_PER_METHOD: usize = 4_096;
const MAX_INSTRUCTIONS_PER_IMAGE: usize = 65_536;
const MAX_STACK_VALUES: usize = 1_024;
const MAX_EXPRESSION_NODES: usize = 256;
const MAX_EXPRESSION_DEPTH: usize = 32;
const MAX_EXPRESSION_VARS: usize = 6;
const MAX_ATTEMPTS_PER_IMAGE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageBudget {
    methods: usize,
    instructions: usize,
    attempts: usize,
}

impl ImageBudget {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            methods: 0,
            instructions: 0,
            attempts: 0,
        }
    }
}

impl Default for ImageBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RewriteOutcome {
    Rewritten(LiftedBody),
    Unchanged,
    Refused(&'static str),
}

#[derive(Debug, Clone)]
struct StackValue {
    expression: MbaExpr,
}

pub(crate) fn rewrite_method(method: &EazVmMethod, budget: &mut ImageBudget) -> RewriteOutcome {
    budget.methods = budget.methods.saturating_add(1);
    if budget.methods > MAX_METHODS_PER_IMAGE {
        return RewriteOutcome::Refused("method count exceeds cap");
    }
    let instruction_count: usize = method.lifted.instrs.len();
    if instruction_count > MAX_INSTRUCTIONS_PER_METHOD {
        return RewriteOutcome::Refused("method instruction count exceeds cap");
    }
    budget.instructions = budget.instructions.saturating_add(instruction_count);
    if budget.instructions > MAX_INSTRUCTIONS_PER_IMAGE {
        return RewriteOutcome::Refused("image instruction count exceeds cap");
    }
    if method.info.return_type_code != EAZVM_I4_TYPE_CODE
        || method
            .info
            .parameter_type_codes
            .iter()
            .any(|type_code: &i32| *type_code != EAZVM_I4_TYPE_CODE)
    {
        return RewriteOutcome::Refused("method signature is not entirely int32");
    }
    if !method.info.local_type_codes.is_empty() {
        return RewriteOutcome::Refused("method contains locals");
    }
    if method.info.exception_handler_count != 0 {
        return RewriteOutcome::Refused("method contains exception handlers");
    }
    if instruction_count < 2
        || method
            .lifted
            .instrs
            .last()
            .map(|instruction: &LiftedInstr| instruction.op)
            != Some(CilOp::Ret)
    {
        return RewriteOutcome::Refused("method is not a straight-line int32 return");
    }
    if budget.attempts >= MAX_ATTEMPTS_PER_IMAGE {
        return RewriteOutcome::Refused("image rewrite attempts exceed cap");
    }
    budget.attempts = budget.attempts.saturating_add(1);
    let original: &[LiftedInstr] = &method.lifted.instrs[..instruction_count - 1];
    let (expression, leaves): (MbaExpr, Vec<LiftedInstr>) =
        match lower_postfix(original, method.info.param_count) {
            Some(lowered) => lowered,
            None => {
                return RewriteOutcome::Refused(
                    "method contains an unsupported int32 stack operation",
                );
            }
        };
    if expression.node_count() > MAX_EXPRESSION_NODES || expression.depth() > MAX_EXPRESSION_DEPTH {
        return RewriteOutcome::Refused("expression complexity exceeds cap");
    }
    if leaves.is_empty() || leaves.len() > MAX_EXPRESSION_VARS {
        return RewriteOutcome::Refused("expression variable count is outside the supported range");
    }
    let simplification: Simplification = simplify(&expression, Width::W32);
    if !simplification.changed()
        || !proof_matches_w32(simplification.verification)
        || simplification.simplified_nodes >= simplification.original_nodes
    {
        return RewriteOutcome::Unchanged;
    }
    if simplification.simplified.depth() > MAX_EXPRESSION_DEPTH {
        return RewriteOutcome::Refused("simplified expression depth exceeds cap");
    }
    let mut rewritten: Vec<LiftedInstr> = Vec::new();
    if rewritten
        .try_reserve_exact(simplification.simplified_nodes.saturating_add(1))
        .is_err()
    {
        return RewriteOutcome::Refused("rewritten instruction allocation failed");
    }
    if emit_expression(&simplification.simplified, &leaves, &mut rewritten).is_none() {
        return RewriteOutcome::Refused("proven expression cannot be represented as supported CIL");
    }
    rewritten.push(LiftedInstr {
        op: CilOp::Ret,
        operand: LiftedOperand::None,
    });
    if rewritten.len() >= method.lifted.instrs.len() || !verify_straight_line(&rewritten) {
        return RewriteOutcome::Unchanged;
    }
    RewriteOutcome::Rewritten(LiftedBody { instrs: rewritten })
}

fn lower_postfix(
    instructions: &[LiftedInstr],
    parameter_count: u32,
) -> Option<(MbaExpr, Vec<LiftedInstr>)> {
    let mut stack: Vec<StackValue> = Vec::new();
    let mut leaves: Vec<LiftedInstr> = Vec::new();
    stack.try_reserve_exact(instructions.len()).ok()?;
    leaves.try_reserve_exact(MAX_EXPRESSION_VARS).ok()?;
    for instruction in instructions {
        let value: Option<MbaExpr> = match (&instruction.op, &instruction.operand) {
            (CilOp::LdargN(index), LiftedOperand::None) => {
                intern_argument(*index, instruction, parameter_count, &mut leaves)
            }
            (CilOp::LdargS, LiftedOperand::Var(index)) => {
                let index: u8 = u8::try_from(*index).ok()?;
                intern_argument(index, instruction, parameter_count, &mut leaves)
            }
            (CilOp::LdcI4M1, LiftedOperand::None) => Some(MbaExpr::konst(u64::from(u32::MAX))),
            (CilOp::LdcI4N(value), LiftedOperand::None) => Some(MbaExpr::konst(u64::from(*value))),
            (CilOp::LdcI4S | CilOp::LdcI4, LiftedOperand::I32(value)) => {
                Some(MbaExpr::konst(u64::from(value.cast_unsigned())))
            }
            _ => None,
        };
        if let Some(expression) = value {
            if stack.len() >= MAX_STACK_VALUES {
                return None;
            }
            stack.push(StackValue { expression });
            continue;
        }
        let operation: MbaBinOp = match instruction.op {
            CilOp::Add => MbaBinOp::Add,
            CilOp::Sub => MbaBinOp::Sub,
            CilOp::Mul => MbaBinOp::Mul,
            CilOp::And => MbaBinOp::And,
            CilOp::Or => MbaBinOp::Or,
            CilOp::Xor => MbaBinOp::Xor,
            _ => return None,
        };
        if instruction.operand != LiftedOperand::None {
            return None;
        }
        let right: StackValue = stack.pop()?;
        let left: StackValue = stack.pop()?;
        stack.push(StackValue {
            expression: MbaExpr::Binary(
                operation,
                Box::new(left.expression),
                Box::new(right.expression),
            ),
        });
    }
    if stack.len() != 1 {
        return None;
    }
    Some((stack.pop()?.expression, leaves))
}

fn intern_argument(
    index: u8,
    instruction: &LiftedInstr,
    parameter_count: u32,
    leaves: &mut Vec<LiftedInstr>,
) -> Option<MbaExpr> {
    if u32::from(index) >= parameter_count {
        return None;
    }
    let variable: u32 = if let Some(existing) = leaves.iter().position(|leaf: &LiftedInstr| {
        matches!(leaf.op, CilOp::LdargN(candidate) if candidate == index)
            || matches!(
                (&leaf.op, &leaf.operand),
                (CilOp::LdargS, LiftedOperand::Var(candidate)) if *candidate == u16::from(index)
            )
    }) {
        u32::try_from(existing).ok()?
    } else {
        if leaves.len() >= MAX_EXPRESSION_VARS {
            return None;
        }
        let next: u32 = u32::try_from(leaves.len()).ok()?;
        leaves.push(instruction.clone());
        next
    };
    Some(MbaExpr::var(variable))
}

const fn proof_matches_w32(verification: Verification) -> bool {
    matches!(
        verification,
        Verification::ExhaustiveAtWidth(Width::W32)
            | Verification::LinearColumnIdentity(Width::W32)
            | Verification::PolynomialIdentity(Width::W32)
    )
}

fn emit_expression(
    expression: &MbaExpr,
    leaves: &[LiftedInstr],
    output: &mut Vec<LiftedInstr>,
) -> Option<()> {
    if output.len() >= MAX_INSTRUCTIONS_PER_METHOD {
        return None;
    }
    match expression {
        MbaExpr::Const(value) => output.push(constant_instruction(*value)),
        MbaExpr::Var(index) => output.push(leaves.get(usize::try_from(*index).ok()?)?.clone()),
        MbaExpr::Unary(MbaUnOp::Neg, inner) => {
            output.push(constant_instruction(0));
            emit_expression(inner, leaves, output)?;
            output.push(no_operand(CilOp::Sub));
        }
        MbaExpr::Unary(MbaUnOp::Not, inner) => {
            emit_expression(inner, leaves, output)?;
            output.push(constant_instruction(u64::from(u32::MAX)));
            output.push(no_operand(CilOp::Xor));
        }
        MbaExpr::Binary(operation, left, right) => {
            emit_expression(left, leaves, output)?;
            emit_expression(right, leaves, output)?;
            let cil_operation: CilOp = match operation {
                MbaBinOp::Add => CilOp::Add,
                MbaBinOp::Sub => CilOp::Sub,
                MbaBinOp::Mul => CilOp::Mul,
                MbaBinOp::And => CilOp::And,
                MbaBinOp::Or => CilOp::Or,
                MbaBinOp::Xor => CilOp::Xor,
                MbaBinOp::Shl | MbaBinOp::Shr => return None,
            };
            output.push(no_operand(cil_operation));
        }
        MbaExpr::Ite(_, _, _)
        | MbaExpr::Slice(_, _, _)
        | MbaExpr::Compose(_, _, _)
        | MbaExpr::Mem(_, _) => return None,
    }
    Some(())
}

const fn constant_instruction(value: u64) -> LiftedInstr {
    let value: i32 = (value as u32).cast_signed();
    match value {
        -1 => no_operand(CilOp::LdcI4M1),
        0..=8 => no_operand(CilOp::LdcI4N(value as u8)),
        _ => LiftedInstr {
            op: CilOp::LdcI4,
            operand: LiftedOperand::I32(value),
        },
    }
}

const fn no_operand(op: CilOp) -> LiftedInstr {
    LiftedInstr {
        op,
        operand: LiftedOperand::None,
    }
}

fn verify_straight_line(instructions: &[LiftedInstr]) -> bool {
    let mut depth: usize = 0;
    for (index, instruction) in instructions.iter().enumerate() {
        match instruction.op {
            CilOp::LdargN(_)
            | CilOp::LdargS
            | CilOp::LdcI4M1
            | CilOp::LdcI4N(_)
            | CilOp::LdcI4S
            | CilOp::LdcI4 => depth = depth.saturating_add(1),
            CilOp::Add | CilOp::Sub | CilOp::Mul | CilOp::And | CilOp::Or | CilOp::Xor => {
                if depth < 2 {
                    return false;
                }
                depth -= 1;
            }
            CilOp::Ret if index + 1 == instructions.len() && depth == 1 => depth = 0,
            _ => return false,
        }
        if depth > MAX_STACK_VALUES {
            return false;
        }
    }
    depth == 0
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn mixed_method() -> EazVmMethod {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/eazvm/EazSample.eazvm.dll");
        let image: Vec<u8> = std::fs::read(path).expect("EazVM image");
        let recovery: super::super::EazVmRecovery =
            super::super::devirtualize(&image).expect("devirtualize");
        super::super::lookup_method(&recovery, "Mixed")
            .expect("Mixed recovery")
            .clone()
    }

    #[test]
    fn unsupported_and_oversized_bodies_preserve_the_original_lift() {
        let mixed: EazVmMethod = mixed_method();
        let mut unsupported: EazVmMethod = mixed.clone();
        unsupported.lifted.instrs[0] = LiftedInstr {
            op: CilOp::Call,
            operand: LiftedOperand::Member(1),
        };
        let unsupported_before: Vec<LiftedInstr> = unsupported.lifted.instrs.clone();
        let unsupported_outcome: RewriteOutcome =
            rewrite_method(&unsupported, &mut ImageBudget::new());
        assert!(matches!(unsupported_outcome, RewriteOutcome::Refused(_)));
        assert_eq!(unsupported.lifted.instrs, unsupported_before);

        let mut invalid_argument: EazVmMethod = mixed.clone();
        invalid_argument.lifted.instrs[0] = LiftedInstr {
            op: CilOp::LdargN(200),
            operand: LiftedOperand::None,
        };
        assert!(matches!(
            rewrite_method(&invalid_argument, &mut ImageBudget::new()),
            RewriteOutcome::Refused(_)
        ));

        let mut oversized: EazVmMethod = mixed;
        oversized.lifted.instrs = vec![
            LiftedInstr {
                op: CilOp::Nop,
                operand: LiftedOperand::None,
            };
            4_097
        ];
        let oversized_before: Vec<LiftedInstr> = oversized.lifted.instrs.clone();
        let oversized_outcome: RewriteOutcome = rewrite_method(&oversized, &mut ImageBudget::new());
        assert_eq!(
            oversized_outcome,
            RewriteOutcome::Refused("method instruction count exceeds cap")
        );
        assert_eq!(oversized.lifted.instrs, oversized_before);
    }

    #[test]
    fn exception_handlers_preserve_the_original_lift() {
        let mut method: EazVmMethod = mixed_method();
        method.info.exception_handler_count = 1;
        let original: Vec<LiftedInstr> = method.lifted.instrs.clone();

        let outcome: RewriteOutcome = rewrite_method(&method, &mut ImageBudget::new());

        assert_eq!(
            outcome,
            RewriteOutcome::Refused("method contains exception handlers")
        );
        assert_eq!(method.lifted.instrs, original);
    }
}
