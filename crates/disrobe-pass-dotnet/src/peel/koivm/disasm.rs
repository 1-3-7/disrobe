use std::collections::BTreeMap;

use super::descriptors::KoiDescriptors;
use super::opcodes::{KoiOp, KoiOperand, KoiReg};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KoiInstr {
    pub offset: u32,
    pub op: KoiOp,
    pub operand: KoiInstrOperand,
    pub rel_target: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KoiInstrOperand {
    None,
    Register(KoiReg),
    ImmU32(u32),
    ImmU64(u64),
}

#[derive(Debug, Clone)]
pub struct KoiBlock {
    pub entry_offset: u32,
    pub entry_key: u8,
    pub instrs: Vec<KoiInstr>,
}

#[derive(Debug, Clone)]
pub struct KoiMethodDisasm {
    pub blocks: Vec<KoiBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmError {
    OutOfBounds(u32),
    UnknownOpcode(u8, u32),
    UnknownRegister(u8, u32),
    StreamEnd,
    TooManyBlocks,
}

const MAX_BLOCKS: usize = 512;
const MAX_INSTRS_PER_BLOCK: usize = 4096;

#[derive(Debug, Clone)]
struct StreamCipher {
    key: u8,
}

impl StreamCipher {
    const fn new(entry_key: u8) -> Self {
        Self { key: entry_key }
    }

    const fn decrypt(&mut self, cipher_byte: u8) -> u8 {
        let plain: u8 = cipher_byte ^ self.key;
        self.key = self.key.wrapping_mul(7).wrapping_add(plain);
        plain
    }
}

struct BlockDecode {
    instrs: Vec<KoiInstr>,
    exit_key: u8,
    successors: Vec<(u32, u8)>,
    end_pos: usize,
}

fn decode_block(
    koi: &[u8],
    entry_offset: u32,
    entry_key: u8,
    descriptors: &KoiDescriptors,
) -> Result<BlockDecode, DisasmError> {
    let mut instrs: Vec<KoiInstr> = Vec::new();
    let mut cipher: StreamCipher = StreamCipher::new(entry_key);
    let mut pos: usize = entry_offset as usize;
    let mut last_imm: Option<(usize, u32)> = None;

    for _ in 0..MAX_INSTRS_PER_BLOCK {
        if pos >= koi.len() {
            return Err(DisasmError::StreamEnd);
        }
        let instr_offset: u32 = u32::try_from(pos).unwrap_or(u32::MAX);

        let op_byte: u8 = cipher.decrypt(koi[pos]);
        pos += 1;
        let op: KoiOp = descriptors
            .decode_opcode(op_byte)
            .ok_or(DisasmError::UnknownOpcode(op_byte, instr_offset))?;

        if pos >= koi.len() {
            return Err(DisasmError::StreamEnd);
        }
        let _fixup: u8 = cipher.decrypt(koi[pos]);
        pos += 1;

        let operand: KoiInstrOperand = match op.operand() {
            KoiOperand::None => KoiInstrOperand::None,
            KoiOperand::Register => {
                if pos >= koi.len() {
                    return Err(DisasmError::StreamEnd);
                }
                let reg_byte: u8 = cipher.decrypt(koi[pos]);
                pos += 1;
                let reg: KoiReg = descriptors
                    .decode_register(reg_byte)
                    .ok_or(DisasmError::UnknownRegister(reg_byte, instr_offset))?;
                KoiInstrOperand::Register(reg)
            }
            KoiOperand::ImmDword => {
                let value: u32 = read_u32(koi, &mut pos, &mut cipher, instr_offset)?;
                last_imm = Some((pos_of_imm(instr_offset, op), value));
                KoiInstrOperand::ImmU32(value)
            }
            KoiOperand::ImmQword => {
                let lo: u32 = read_u32(koi, &mut pos, &mut cipher, instr_offset)?;
                let hi: u32 = read_u32(koi, &mut pos, &mut cipher, instr_offset)?;
                KoiInstrOperand::ImmU64((u64::from(hi) << 32) | u64::from(lo))
            }
        };

        let rel_target: Option<u32> = if op.is_terminator() {
            resolve_rel_target(last_imm)
        } else {
            None
        };

        instrs.push(KoiInstr {
            offset: instr_offset,
            op,
            operand,
            rel_target,
        });

        if op.is_terminator() {
            let exit_key: u8 = cipher.key;
            let successors: Vec<(u32, u8)> = match op {
                KoiOp::Jmp => rel_target
                    .map(|t: u32| vec![(t, exit_key)])
                    .unwrap_or_default(),
                KoiOp::Jz | KoiOp::Jnz => {
                    let mut succ: Vec<(u32, u8)> = Vec::new();
                    if let Some(t) = rel_target {
                        succ.push((t, exit_key));
                    }
                    let fallthrough: u32 = u32::try_from(pos).unwrap_or(u32::MAX);
                    succ.push((fallthrough, exit_key));
                    succ
                }
                _ => Vec::new(),
            };
            return Ok(BlockDecode {
                instrs,
                exit_key,
                successors,
                end_pos: pos,
            });
        }
    }
    Err(DisasmError::StreamEnd)
}

const fn pos_of_imm(instr_offset: u32, _op: KoiOp) -> usize {
    instr_offset as usize
}

fn resolve_rel_target(last_imm: Option<(usize, u32)>) -> Option<u32> {
    let (imm_instr_offset, rel): (usize, u32) = last_imm?;
    let rel_signed: i64 = i64::from(rel.cast_signed());
    let target: i64 = imm_instr_offset as i64 + rel_signed;
    u32::try_from(target).ok()
}

fn read_u32(
    koi: &[u8],
    pos: &mut usize,
    cipher: &mut StreamCipher,
    instr_offset: u32,
) -> Result<u32, DisasmError> {
    let mut bytes: [u8; 4] = [0u8; 4];
    for slot in &mut bytes {
        let cipher_byte: u8 = *koi
            .get(*pos)
            .ok_or(DisasmError::OutOfBounds(instr_offset))?;
        *slot = cipher.decrypt(cipher_byte);
        *pos += 1;
    }
    Ok(u32::from_le_bytes(bytes))
}

pub fn disassemble_method(
    koi: &[u8],
    entry_offset: u32,
    entry_key: u8,
    descriptors: &KoiDescriptors,
) -> Result<KoiMethodDisasm, DisasmError> {
    let mut blocks: BTreeMap<u32, KoiBlock> = BTreeMap::new();
    let mut worklist: Vec<(u32, u8)> = vec![(entry_offset, entry_key)];

    while let Some((offset, key)) = worklist.pop() {
        if blocks.contains_key(&offset) {
            continue;
        }
        if blocks.len() >= MAX_BLOCKS {
            return Err(DisasmError::TooManyBlocks);
        }
        let decoded: BlockDecode = decode_block(koi, offset, key, descriptors)?;
        for (succ_offset, succ_key) in &decoded.successors {
            if !blocks.contains_key(succ_offset) {
                worklist.push((*succ_offset, *succ_key));
            }
        }
        let _ = decoded.exit_key;
        let _ = decoded.end_pos;
        blocks.insert(
            offset,
            KoiBlock {
                entry_offset: offset,
                entry_key: key,
                instrs: decoded.instrs,
            },
        );
    }

    let ordered: Vec<KoiBlock> = blocks.into_values().collect();
    Ok(KoiMethodDisasm { blocks: ordered })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::koistream::{KoiSig, KoiStream, parse_koistream};
    use super::*;

    fn real_koistream() -> KoiStream {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.koistream.bin");
        let bytes: Vec<u8> = std::fs::read(path).unwrap();
        parse_koistream(&bytes).unwrap()
    }

    fn disasm_sig(id: u32) -> KoiMethodDisasm {
        let stream: KoiStream = real_koistream();
        let descriptors: KoiDescriptors = KoiDescriptors::from_seed(0);
        let sig: &KoiSig = stream.sig_by_id(id).unwrap();
        disassemble_method(&stream.raw, sig.entry_offset, sig.entry_key, &descriptors)
            .unwrap_or_else(|e| panic!("disasm id {id}: {e:?}"))
    }

    fn all_ops(d: &KoiMethodDisasm) -> Vec<KoiOp> {
        d.blocks
            .iter()
            .flat_map(|b: &KoiBlock| b.instrs.iter().map(|i: &KoiInstr| i.op))
            .collect()
    }

    #[test]
    fn add_method_full_cfg_disassembles() {
        let d: KoiMethodDisasm = disasm_sig(2);
        let ops: Vec<KoiOp> = all_ops(&d);
        assert!(
            ops.iter().any(|o: &KoiOp| matches!(o, KoiOp::AddDword)),
            "Add must contain ADD_DWORD"
        );
        assert!(
            ops.iter().any(|o: &KoiOp| matches!(o, KoiOp::Ret)),
            "Add must terminate in RET"
        );
        assert!(
            d.blocks.len() >= 2,
            "Add must have entry prologue + body block"
        );
    }

    #[test]
    fn square_uses_multiply() {
        let d: KoiMethodDisasm = disasm_sig(3);
        let ops: Vec<KoiOp> = all_ops(&d);
        assert!(
            ops.iter().any(|o: &KoiOp| matches!(o, KoiOp::MulDword)),
            "Square(x)=x*x must contain MUL_DWORD; got {ops:?}"
        );
    }

    #[test]
    fn sumto_loop_has_branch_and_add() {
        let d: KoiMethodDisasm = disasm_sig(4);
        let ops: Vec<KoiOp> = all_ops(&d);
        assert!(
            ops.iter()
                .any(|o: &KoiOp| matches!(o, KoiOp::Jz | KoiOp::Jnz)),
            "SumTo loop must contain a conditional jump; got {ops:?}"
        );
        assert!(ops.iter().any(|o: &KoiOp| matches!(o, KoiOp::AddDword)));
        assert!(
            d.blocks.len() >= 3,
            "a loop should produce at least 3 basic blocks; got {}",
            d.blocks.len()
        );
    }

    #[test]
    fn factorial_returns_qword_path() {
        let d: KoiMethodDisasm = disasm_sig(6);
        let ops: Vec<KoiOp> = all_ops(&d);
        assert!(
            ops.iter()
                .any(|o: &KoiOp| matches!(o, KoiOp::MulDword | KoiOp::MulQword)),
            "Factorial must contain a multiply; got {ops:?}"
        );
        assert!(ops.iter().any(|o: &KoiOp| matches!(o, KoiOp::Ret)));
    }

    #[test]
    fn all_six_methods_disassemble_without_error() {
        for id in 2u32..=7 {
            let d: KoiMethodDisasm = disasm_sig(id);
            assert!(!d.blocks.is_empty(), "id {id} produced no blocks");
            let ops: Vec<KoiOp> = all_ops(&d);
            assert!(
                ops.iter()
                    .any(|o: &KoiOp| matches!(o, KoiOp::Ret | KoiOp::Leave)),
                "id {id} must reach a return"
            );
        }
    }
}
