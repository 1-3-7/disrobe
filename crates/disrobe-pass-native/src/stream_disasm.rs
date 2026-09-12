use std::fmt::Write as _;
use std::io::{self, Write};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDisasmStats {
    pub instruction_count: u64,
    pub function_count: u64,
    pub bytes_decoded: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct StreamDisasmLimits {
    pub max_text_bytes: usize,
    pub max_instructions: u64,
    pub max_output_bytes: u64,
}

impl Default for StreamDisasmLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 96 * 1024 * 1024,
            max_instructions: 8_000_000,
            max_output_bytes: 256 * 1024 * 1024,
        }
    }
}

pub fn stream_disasm_x86(
    sink: &mut dyn Write,
    text: &[u8],
    base: u64,
    bits: u32,
    limits: StreamDisasmLimits,
) -> io::Result<StreamDisasmStats> {
    let decode_len: usize = text.len().min(limits.max_text_bytes);
    let truncated_input: bool = decode_len < text.len();
    let window: &[u8] = &text[..decode_len];

    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, window, base, DecoderOptions::NONE);
    let mut formatter: NasmFormatter = NasmFormatter::new();
    let mut insn: Instruction = Instruction::default();
    let mut line: String = String::with_capacity(80);

    let mut instruction_count: u64 = 0;
    let mut function_count: u64 = 0;
    let mut output_bytes: u64 = 0;
    let mut at_function_start: bool = true;
    let mut limit_hit: bool = false;

    while decoder.can_decode() {
        if instruction_count >= limits.max_instructions || output_bytes >= limits.max_output_bytes {
            limit_hit = true;
            break;
        }
        decoder.decode_out(&mut insn);

        if at_function_start {
            function_count += 1;
            line.clear();
            let _ = write!(line, "\n; ==== sub_{:x} ====\n", insn.ip());
            sink.write_all(line.as_bytes())?;
            output_bytes += line.len() as u64;
            at_function_start = false;
        }

        line.clear();
        let _ = write!(line, "  {:08x}  ", insn.ip());
        formatter.format(&insn, &mut line);
        line.push('\n');
        sink.write_all(line.as_bytes())?;
        output_bytes += line.len() as u64;
        instruction_count += 1;

        if matches!(
            insn.flow_control(),
            FlowControl::Return | FlowControl::UnconditionalBranch
        ) {
            at_function_start = true;
        }
    }

    Ok(StreamDisasmStats {
        instruction_count,
        function_count,
        bytes_decoded: decode_len,
        truncated: truncated_input || limit_hit,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RipRef {
    pub instruction_offset: u64,
    pub target_va: u64,
    pub function_offset: u64,
}

const MAX_RIP_REFS: usize = 200_000;

#[must_use]
pub fn scan_rip_relative_refs(text: &[u8], base: u64, max_text_bytes: usize) -> Vec<RipRef> {
    let decode_len: usize = text.len().min(max_text_bytes);
    let window: &[u8] = &text[..decode_len];
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, window, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut out: Vec<RipRef> = Vec::new();
    let mut function_offset: u64 = base;
    let mut at_function_start: bool = true;

    while decoder.can_decode() {
        if out.len() >= MAX_RIP_REFS {
            break;
        }
        decoder.decode_out(&mut insn);
        if at_function_start {
            function_offset = insn.ip();
            at_function_start = false;
        }
        if matches!(
            insn.mnemonic(),
            iced_x86::Mnemonic::Lea | iced_x86::Mnemonic::Mov
        ) && insn.is_ip_rel_memory_operand()
        {
            out.push(RipRef {
                instruction_offset: insn.ip(),
                target_va: insn.ip_rel_memory_address(),
                function_offset,
            });
        }
        if matches!(
            insn.flow_control(),
            FlowControl::Return | FlowControl::UnconditionalBranch
        ) {
            at_function_start = true;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn streams_without_accumulating_and_counts_instructions() {
        let code: [u8; 8] = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let mut out: Vec<u8> = Vec::new();
        let stats: StreamDisasmStats =
            stream_disasm_x86(&mut out, &code, 0x1000, 64, StreamDisasmLimits::default())
                .expect("stream ok");
        assert_eq!(stats.instruction_count, 5, "push/mov/xor/pop/ret decoded");
        assert!(stats.function_count >= 1);
        assert!(!stats.truncated);
        let text: String = String::from_utf8(out).expect("utf8");
        assert!(text.contains("push"), "real mnemonic streamed: {text}");
        assert!(text.contains("ret"));
    }

    #[test]
    fn honors_text_byte_cap_and_reports_truncation() {
        let code: Vec<u8> = vec![0x90u8; 4096];
        let mut out: Vec<u8> = Vec::new();
        let limits: StreamDisasmLimits = StreamDisasmLimits {
            max_text_bytes: 16,
            max_instructions: 1_000_000,
            max_output_bytes: 1_000_000,
        };
        let stats: StreamDisasmStats =
            stream_disasm_x86(&mut out, &code, 0x1000, 64, limits).expect("stream ok");
        assert_eq!(stats.bytes_decoded, 16);
        assert_eq!(
            stats.instruction_count, 16,
            "16 single-byte nops in the window"
        );
        assert!(stats.truncated, "input larger than the cap is truncated");
    }

    #[test]
    fn honors_instruction_cap() {
        let code: Vec<u8> = vec![0x90u8; 4096];
        let mut out: Vec<u8> = Vec::new();
        let limits: StreamDisasmLimits = StreamDisasmLimits {
            max_text_bytes: 4096,
            max_instructions: 10,
            max_output_bytes: 1_000_000,
        };
        let stats: StreamDisasmStats =
            stream_disasm_x86(&mut out, &code, 0x1000, 64, limits).expect("stream ok");
        assert_eq!(stats.instruction_count, 10);
        assert!(stats.truncated);
    }
}
