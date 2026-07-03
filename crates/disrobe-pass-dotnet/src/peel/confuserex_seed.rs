//! Recovery of the ConfuserEx Constants/Resources xorshift key seed by evaluating the bootstrap method's seed-initialisation expression with the CIL emulator.

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, parse_method_body};
use crate::cil_emulator::{StubInput, StubOutput, emulate_stub};
use crate::pe::PeImage;
use crate::tables::MethodDefRow;

const MAX_SEED_RUN: usize = 64;

const MAX_METHODS_SCANNED: usize = 65_536;

#[must_use]
pub fn recover_seeds_by_emulation(
    image: &[u8],
    pe: &PeImage,
    methods: &[MethodDefRow],
) -> Vec<u32> {
    let mut seeds: Vec<u32> = Vec::new();
    let mut scanned: usize = 0;
    for method in methods {
        if scanned >= MAX_METHODS_SCANNED {
            break;
        }
        let Some(body): Option<MethodBody> = method_body(image, pe, method) else {
            continue;
        };
        scanned += 1;
        for seed in seeds_in_body(&body) {
            if !seeds.contains(&seed) {
                seeds.push(seed);
            }
        }
    }
    seeds
}

#[must_use]
pub fn seeds_in_body(body: &MethodBody) -> Vec<u32> {
    let ins: &[Instruction] = &body.instructions;
    let states: Vec<u32> = xorshift_state_locals(ins);
    let mut seeds: Vec<u32> = Vec::new();
    for state in states {
        for (i, instr) in ins.iter().enumerate() {
            if store_local_index(instr) != Some(state) {
                continue;
            }
            let Some(run): Option<&[Instruction]> = seed_run(ins, i) else {
                continue;
            };
            let Some(seed): Option<u32> = eval_run(run) else {
                continue;
            };
            if !seeds.contains(&seed) {
                seeds.push(seed);
            }
        }
    }
    seeds
}

fn xorshift_state_locals(ins: &[Instruction]) -> Vec<u32> {
    let mut states: Vec<u32> = Vec::new();
    for window in ins.windows(6) {
        let (Some(a), Some(b)): (Option<u32>, Option<u32>) =
            (load_local_index(&window[0]), load_local_index(&window[1]))
        else {
            continue;
        };
        let shift_op: &str = window[3].name.as_str();
        if a == b
            && window[2].name.starts_with("ldc.i4")
            && matches!(shift_op, "shr.un" | "shl" | "shr")
            && window[4].name == "xor"
            && store_local_index(&window[5]) == Some(a)
            && !states.contains(&a)
        {
            states.push(a);
        }
    }
    states
}

fn seed_run(ins: &[Instruction], store_index: usize) -> Option<&[Instruction]> {
    let mut start: usize = store_index;
    while start > 0 {
        let prev: &Instruction = &ins[start - 1];
        if is_pure_value_op(prev.name.as_str()) && load_local_index(prev).is_none() {
            start -= 1;
        } else {
            break;
        }
    }
    if start == store_index {
        return None;
    }
    let run: &[Instruction] = &ins[start..store_index];
    if run.len() > MAX_SEED_RUN {
        return None;
    }
    if run
        .iter()
        .any(|x: &Instruction| !is_pure_value_op(x.name.as_str()))
    {
        return None;
    }
    Some(run)
}

fn eval_run(run: &[Instruction]) -> Option<u32> {
    let mut instructions: Vec<Instruction> = run.to_vec();
    instructions.push(synthetic_ret());
    let body: MethodBody = MethodBody {
        max_stack: 16,
        code_size: 0,
        local_var_sig_tok: 0,
        init_locals: true,
        instructions,
        exception_clauses: Vec::new(),
    };
    match emulate_stub(&body, &StubInput::default()) {
        Ok(StubOutput::Int(v)) => Some((v as u64 & 0xFFFF_FFFF) as u32),
        _ => None,
    }
}

fn synthetic_ret() -> Instruction {
    Instruction {
        offset: u32::MAX,
        opcode: 0x2A,
        name: "ret".to_owned(),
        operand: OperandValue::None,
        flow: FlowControl::Return,
    }
}

fn is_pure_value_op(name: &str) -> bool {
    name.starts_with("ldc.i4")
        || name.starts_with("conv.")
        || matches!(
            name,
            "add" | "sub" | "mul" | "and" | "or" | "xor" | "shl" | "shr" | "shr.un" | "neg" | "not"
        )
}

fn load_local_index(ins: &Instruction) -> Option<u32> {
    local_index(ins.name.as_str(), "ldloc", &ins.operand)
}

fn store_local_index(ins: &Instruction) -> Option<u32> {
    local_index(ins.name.as_str(), "stloc", &ins.operand)
}

fn local_index(name: &str, prefix: &str, operand: &OperandValue) -> Option<u32> {
    let dotted: String = format!("{prefix}.");
    if let Some(rest) = name.strip_prefix(dotted.as_str()) {
        if rest == "s" {
            return match operand {
                OperandValue::U8(b) => Some(u32::from(*b)),
                _ => None,
            };
        }
        return rest.parse::<u32>().ok();
    }
    if name == prefix {
        return match operand {
            OperandValue::U16(v) => Some(u32::from(*v)),
            _ => None,
        };
    }
    None
}

fn method_body(image: &[u8], pe: &PeImage, method: &MethodDefRow) -> Option<MethodBody> {
    if method.rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(method.rva)?;
    if off >= image.len() {
        return None;
    }
    parse_method_body(&image[off..]).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 16,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    fn xorshift_loop_for(state_local: u8) -> Vec<u8> {
        let mut code: Vec<u8> = Vec::new();
        for shift in [(0x64u8, 12u8), (0x62, 25), (0x64, 27)] {
            code.push(0x11);
            code.push(state_local);
            code.push(0x11);
            code.push(state_local);
            code.push(0x1F);
            code.push(shift.1);
            code.push(shift.0);
            code.push(0x61);
            code.push(0x13);
            code.push(state_local);
        }
        code
    }

    #[test]
    fn recovers_literal_seed_before_xorshift() {
        let mut code: Vec<u8> = Vec::new();
        code.push(0x20);
        code.extend_from_slice(&0xF5F4_A2BFu32.to_le_bytes());
        code.push(0x13);
        code.push(3);
        code.extend_from_slice(&xorshift_loop_for(3));
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let seeds: Vec<u32> = seeds_in_body(&body);
        assert!(
            seeds.contains(&0xF5F4_A2BF),
            "literal seed must be recovered; got {seeds:?}"
        );
    }

    #[test]
    fn recovers_folded_xor_seed_that_literal_scan_would_miss() {
        let a: u32 = 0x21A3_E77D;
        let b: u32 = 0x3086_5247;
        let mut code: Vec<u8> = Vec::new();
        code.push(0x20);
        code.extend_from_slice(&a.to_le_bytes());
        code.push(0x20);
        code.extend_from_slice(&b.to_le_bytes());
        code.push(0x61);
        code.push(0x13);
        code.push(3);
        code.extend_from_slice(&xorshift_loop_for(3));
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let seeds: Vec<u32> = seeds_in_body(&body);
        assert!(
            seeds.contains(&(a ^ b)),
            "folded seed {:#010x} must be evaluated by emulation; got {seeds:?}",
            a ^ b
        );
    }

    #[test]
    fn ignores_body_without_xorshift_state() {
        let body: MethodBody = body_from(&[0x16, 0x0A, 0x06, 0x2A]);
        assert!(seeds_in_body(&body).is_empty());
    }

    #[test]
    fn folded_mul_add_seed_is_evaluated() {
        let a: u32 = 0x0000_1000;
        let mut code: Vec<u8> = Vec::new();
        code.push(0x20);
        code.extend_from_slice(&a.to_le_bytes());
        code.push(0x1F);
        code.push(7);
        code.push(0x5A);
        code.push(0x17);
        code.push(0x58);
        code.push(0x13);
        code.push(5);
        code.extend_from_slice(&xorshift_loop_for(5));
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let seeds: Vec<u32> = seeds_in_body(&body);
        let expected: u32 = a.wrapping_mul(7).wrapping_add(1);
        assert!(
            seeds.contains(&expected),
            "mul/add folded seed {expected:#010x} must be evaluated; got {seeds:?}"
        );
    }
}
