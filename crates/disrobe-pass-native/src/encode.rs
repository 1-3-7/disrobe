use iced_x86::{BlockEncoder, BlockEncoderOptions, Encoder, Instruction, InstructionBlock};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocatedBlock {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub instruction_offsets: Vec<u32>,
}

pub fn encode_instruction(bitness: u32, instruction: &Instruction) -> Result<Vec<u8>> {
    let mut encoder: Encoder = Encoder::new(bitness);
    encoder
        .encode(instruction, instruction.ip())
        .map_err(|e: iced_x86::IcedError| Error::Encode {
            stage: "encode-instruction",
            detail: e.to_string(),
        })?;
    Ok(encoder.take_buffer())
}

pub fn relocate_block(
    bitness: u32,
    instructions: &[Instruction],
    new_base: u64,
) -> Result<RelocatedBlock> {
    let block: InstructionBlock<'_> = InstructionBlock::new(instructions, new_base);
    let options: u32 = BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS;
    let result: iced_x86::BlockEncoderResult = BlockEncoder::encode(bitness, block, options)
        .map_err(|e: iced_x86::IcedError| Error::Encode {
            stage: "relocate-block",
            detail: e.to_string(),
        })?;
    Ok(RelocatedBlock {
        base: result.rip,
        bytes: result.code_buffer,
        instruction_offsets: result.new_instruction_offsets,
    })
}

pub fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: iced_x86::Decoder<'_> =
        iced_x86::Decoder::with_ip(bitness, bytes, base, iced_x86::DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions, Formatter as _, Mnemonic, NasmFormatter};
    use object::write::{Object as WriteObject, StandardSection};
    use object::{Architecture, BinaryFormat, Endianness};

    use super::*;

    fn semantic_key(insn: &Instruction) -> String {
        let mut formatter: NasmFormatter = NasmFormatter::new();
        let mut text: String = String::new();
        formatter.format(insn, &mut text);
        text
    }

    #[test]
    fn encode_single_instruction_round_trips() {
        let original: [u8; 7] = [0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00];
        let decoded: Vec<Instruction> = decode_all(64, 0x1000, &original);
        assert_eq!(decoded.len(), 1);
        let bytes: Vec<u8> = encode_instruction(64, &decoded[0]).expect("encode");
        let mut d: Decoder<'_> = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
        let mut re: Instruction = Instruction::default();
        d.decode_out(&mut re);
        assert_eq!(re.mnemonic(), Mnemonic::Mov);
        assert_eq!(re.immediate(1), 0x2A);
        assert_eq!(semantic_key(&re), semantic_key(&decoded[0]));
    }

    fn real_text_section() -> Vec<u8> {
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&[0x55]);
        code.extend_from_slice(&[0x48, 0x89, 0xE5]);
        code.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&[0x01, 0xD8]);
        code.extend_from_slice(&[0x83, 0xF8, 0x05]);
        code.extend_from_slice(&[0x74, 0x02]);
        code.extend_from_slice(&[0x31, 0xC0]);
        code.extend_from_slice(&[0x5D]);
        code.extend_from_slice(&[0xC3]);

        let mut obj: WriteObject<'_> =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let text: object::write::SectionId = obj.section_id(StandardSection::Text);
        let _ = obj.append_section_data(text, &code, 16);
        obj.write().expect("elf write")
    }

    fn text_bytes(elf: &[u8]) -> (u64, Vec<u8>) {
        use object::{Object as _, ObjectSection as _};
        let file: object::File<'_> = object::File::parse(elf).expect("parse elf");
        let section: object::Section<'_, '_> = file
            .sections()
            .find(|s: &object::Section<'_, '_>| {
                s.name().is_ok_and(|n: &str| n == ".text")
                    || matches!(s.kind(), object::SectionKind::Text)
            })
            .expect(".text present");
        (section.address(), section.data().expect("data").to_vec())
    }

    #[test]
    fn decode_encode_decode_is_semantically_equal_on_real_text() {
        let elf: Vec<u8> = real_text_section();
        let (base, text): (u64, Vec<u8>) = text_bytes(&elf);
        let original: Vec<Instruction> = decode_all(64, base, &text);
        assert!(
            original.len() >= 8,
            "decoded {} instructions",
            original.len()
        );

        let mut reencoded: Vec<u8> = Vec::new();
        for insn in &original {
            reencoded.extend_from_slice(&encode_instruction(64, insn).expect("re-encode"));
        }
        let round_tripped: Vec<Instruction> = decode_all(64, base, &reencoded);
        assert_eq!(
            round_tripped.len(),
            original.len(),
            "instruction count survives the round trip"
        );
        for (a, b) in original.iter().zip(round_tripped.iter()) {
            assert_eq!(
                semantic_key(a),
                semantic_key(b),
                "instruction {a} decoded back to {b} with different semantics"
            );
        }
    }

    #[test]
    fn relocate_block_fixes_relative_branch_targets() {
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&[0xEB, 0x01]);
        code.extend_from_slice(&[0x90]);
        code.extend_from_slice(&[0xC3]);
        let old_base: u64 = 0x1000;
        let new_base: u64 = 0x5_0000_0000;
        let insns: Vec<Instruction> = decode_all(64, old_base, &code);
        assert_eq!(insns.len(), 3);
        let jmp_target_old: u64 = insns[0].near_branch_target();
        assert_eq!(jmp_target_old, 0x1003, "the short jmp skips the nop");

        let relocated: RelocatedBlock = relocate_block(64, &insns, new_base).expect("relocate");
        assert_eq!(relocated.base, new_base);
        let moved: Vec<Instruction> = decode_all(64, new_base, &relocated.bytes);
        assert_eq!(moved.len(), 3, "relocated block decodes to same shape");
        assert_eq!(moved[0].mnemonic(), Mnemonic::Jmp);
        assert_eq!(
            moved[0].near_branch_target(),
            new_base + 3,
            "the branch target was rebased to follow the moved nop"
        );
        assert_eq!(moved[1].mnemonic(), Mnemonic::Nop);
        assert_eq!(moved[2].mnemonic(), Mnemonic::Ret);
    }

    #[test]
    fn encode_uses_requested_bitness() {
        let original: [u8; 2] = [0x01, 0xD8];
        let decoded: Vec<Instruction> = decode_all(32, 0x400, &original);
        assert_eq!(decoded.len(), 1);
        let bytes: Vec<u8> = encode_instruction(32, &decoded[0]).expect("encode 32");
        assert_eq!(
            bytes, original,
            "add eax,ebx re-encodes to its canonical bytes"
        );
    }
}
