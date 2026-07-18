use iced_x86::{Decoder, DecoderOptions, Instruction};

pub const MAX_DECODE_INSNS: usize = 1 << 16;

#[must_use]
pub fn decode_all(bytes: &[u8], base: u64) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && out.len() < MAX_DECODE_INSNS {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}
