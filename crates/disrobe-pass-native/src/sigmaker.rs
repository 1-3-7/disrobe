use core::fmt::Write as _;

use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, Instruction};
use object::{Object, ObjectSection};
use serde::Serialize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigmakerOptions {
    pub max_instructions: usize,
    pub minimize: bool,
}

impl Default for SigmakerOptions {
    fn default() -> Self {
        Self {
            max_instructions: 64,
            minimize: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureByte {
    pub value: u8,
    pub wildcard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signature {
    pub virtual_address: u64,
    pub file_offset: u64,
    pub instruction_count: usize,
    pub byte_length: usize,
    pub wildcard_count: usize,
    pub ida_pattern: String,
    pub byte_pattern: String,
    pub mask: String,
    pub unique: bool,
    pub match_count: usize,
    pub bytes: Vec<SignatureByte>,
}

impl Signature {
    #[must_use]
    pub fn literal_bytes(&self) -> Vec<u8> {
        self.bytes.iter().map(|b: &SignatureByte| b.value).collect()
    }

    #[must_use]
    pub fn emit_c_array(&self) -> String {
        let mut pattern: String = String::new();
        let mut mask: String = String::with_capacity(self.bytes.len());
        for (idx, byte) in self.bytes.iter().enumerate() {
            if idx != 0 {
                pattern.push(' ');
            }
            if byte.wildcard {
                pattern.push_str("0x00,");
                mask.push('?');
            } else {
                let _ = write!(pattern, "0x{:02X},", byte.value);
                mask.push('x');
            }
        }
        format!("unsigned char pattern[] = {{ {pattern} }};\nconst char *mask = \"{mask}\";\n")
    }

    #[must_use]
    pub fn emit_python_bytes(&self) -> String {
        let mut pattern: String = String::new();
        for byte in &self.bytes {
            if byte.wildcard {
                pattern.push_str("\\x00");
            } else {
                let _ = write!(pattern, "\\x{:02x}", byte.value);
            }
        }
        let mask: String = self
            .bytes
            .iter()
            .map(|b: &SignatureByte| if b.wildcard { '?' } else { 'x' })
            .collect();
        format!("pattern = b\"{pattern}\"\nmask = \"{mask}\"\n")
    }
}

#[derive(Debug, Clone, Copy)]
struct CodeSpan<'a> {
    address: u64,
    file_offset: u64,
    bytes: &'a [u8],
}

fn executable_spans<'a>(file: &'a object::File<'a>, bytes: &'a [u8]) -> Vec<CodeSpan<'a>> {
    const IMAGE_SCN_MEM_EXECUTE: u64 = 0x2000_0000;
    let mut spans: Vec<CodeSpan<'a>> = Vec::new();
    for section in file.sections() {
        let Some((off, size)): Option<(u64, u64)> = section.file_range() else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let executable: bool = match section.flags() {
            object::SectionFlags::Elf { sh_flags } => {
                sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0
            }
            object::SectionFlags::MachO { flags } => {
                flags & object::macho::S_ATTR_PURE_INSTRUCTIONS != 0
                    || flags & object::macho::S_ATTR_SOME_INSTRUCTIONS != 0
            }
            object::SectionFlags::Coff { characteristics } => {
                u64::from(characteristics) & IMAGE_SCN_MEM_EXECUTE != 0
            }
            _ => matches!(section.kind(), object::SectionKind::Text),
        };
        if !executable {
            continue;
        }
        let start: usize = off as usize;
        let end: usize = start.saturating_add(size as usize).min(bytes.len());
        if start >= end {
            continue;
        }
        spans.push(CodeSpan {
            address: section.address(),
            file_offset: off,
            bytes: &bytes[start..end],
        });
    }
    spans
}

fn bitness_of(file: &object::File<'_>) -> Result<u32> {
    match file.architecture() {
        object::Architecture::X86_64 | object::Architecture::X86_64_X32 => Ok(64),
        object::Architecture::I386 => Ok(32),
        other => Err(Error::UnsupportedArch(format!(
            "sigmaker decodes x86/x86-64 only; {other:?} is not supported"
        ))),
    }
}

fn span_for_va<'a>(spans: &[CodeSpan<'a>], va: u64) -> Option<CodeSpan<'a>> {
    spans
        .iter()
        .copied()
        .find(|s: &CodeSpan<'a>| va >= s.address && va < s.address + s.bytes.len() as u64)
}

fn decode_signature_bytes(
    span: &CodeSpan<'_>,
    va: u64,
    bitness: u32,
    max_instructions: usize,
) -> Result<(Vec<SignatureByte>, usize)> {
    let start: usize = (va - span.address) as usize;
    let code: &[u8] = &span.bytes[start..];
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, code, va, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut out: Vec<SignatureByte> = Vec::new();
    let mut instruction_count: usize = 0;
    while decoder.can_decode() && instruction_count < max_instructions {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        let offsets: ConstantOffsets = decoder.get_constant_offsets(&insn);
        let insn_start: usize = (insn.ip() - va) as usize;
        let insn_len: usize = insn.len();
        let Some(insn_bytes): Option<&[u8]> = code.get(insn_start..insn_start + insn_len) else {
            break;
        };
        let mut mask: Vec<bool> = vec![false; insn_len];
        mark_wildcards(offsets, &mut mask);
        for (i, &b) in insn_bytes.iter().enumerate() {
            out.push(SignatureByte {
                value: b,
                wildcard: mask.get(i).copied().unwrap_or(false),
            });
        }
        instruction_count += 1;
        if is_terminator(&insn) {
            break;
        }
    }
    if out.is_empty() {
        return Err(Error::Disasm {
            engine: "sigmaker",
            message: format!("no instruction decoded at {va:#x}"),
        });
    }
    Ok((out, instruction_count))
}

fn mark_wildcards(offsets: ConstantOffsets, mask: &mut [bool]) {
    let mark = |mask: &mut [bool], off: usize, size: usize| {
        for i in off..off + size {
            if let Some(slot) = mask.get_mut(i) {
                *slot = true;
            }
        }
    };
    if offsets.has_displacement() {
        mark(
            mask,
            offsets.displacement_offset(),
            offsets.displacement_size(),
        );
    }
    if offsets.has_immediate() {
        mark(mask, offsets.immediate_offset(), offsets.immediate_size());
    }
    if offsets.has_immediate2() {
        mark(mask, offsets.immediate_offset2(), offsets.immediate_size2());
    }
}

fn is_terminator(insn: &Instruction) -> bool {
    use iced_x86::FlowControl;
    matches!(
        insn.flow_control(),
        FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
    )
}

fn count_matches(spans: &[CodeSpan<'_>], bytes: &[SignatureByte]) -> usize {
    let mut total: usize = 0;
    for span in spans {
        total += count_matches_in(span.bytes, bytes);
        if total > 1 {
            return total;
        }
    }
    total
}

fn count_matches_in(haystack: &[u8], pattern: &[SignatureByte]) -> usize {
    if pattern.is_empty() || pattern.len() > haystack.len() {
        return 0;
    }
    let mut count: usize = 0;
    let last: usize = haystack.len() - pattern.len();
    for start in 0..=last {
        let window: &[u8] = &haystack[start..start + pattern.len()];
        if pattern_matches(window, pattern) {
            count += 1;
            if count > 1 {
                return count;
            }
        }
    }
    count
}

fn pattern_matches(window: &[u8], pattern: &[SignatureByte]) -> bool {
    for (i, sig) in pattern.iter().enumerate() {
        if sig.wildcard {
            continue;
        }
        if window[i] != sig.value {
            return false;
        }
    }
    true
}

fn minimize_to_unique(spans: &[CodeSpan<'_>], full: &[SignatureByte]) -> Vec<SignatureByte> {
    for len in 1..=full.len() {
        let prefix: &[SignatureByte] = &full[..len];
        if prefix.iter().all(|b: &SignatureByte| b.wildcard) {
            continue;
        }
        if count_matches(spans, prefix) == 1 {
            return prefix.to_vec();
        }
    }
    full.to_vec()
}

fn render_ida_pattern(bytes: &[SignatureByte]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 3);
    for (idx, b) in bytes.iter().enumerate() {
        if idx != 0 {
            out.push(' ');
        }
        if b.wildcard {
            out.push('?');
        } else {
            let _ = write!(out, "{:02X}", b.value);
        }
    }
    out
}

fn render_byte_and_mask(bytes: &[SignatureByte]) -> (String, String) {
    let mut pattern: String = String::with_capacity(bytes.len() * 4);
    let mut mask: String = String::with_capacity(bytes.len());
    for b in bytes {
        let _ = write!(pattern, "\\x{:02X}", b.value);
        mask.push(if b.wildcard { '?' } else { 'x' });
    }
    (pattern, mask)
}

pub fn make_signature(image: &[u8], va: u64, opts: SigmakerOptions) -> Result<Signature> {
    let file: object::File<'_> = object::File::parse(image).map_err(|e| Error::Export {
        stage: "sigmaker-parse",
        detail: e.to_string(),
    })?;
    let bitness: u32 = bitness_of(&file)?;
    let spans: Vec<CodeSpan<'_>> = executable_spans(&file, image);
    if spans.is_empty() {
        return Err(Error::Disasm {
            engine: "sigmaker",
            message: "image exposes no executable section to disassemble".to_owned(),
        });
    }
    let span: CodeSpan<'_> = span_for_va(&spans, va).ok_or_else(|| Error::Disasm {
        engine: "sigmaker",
        message: format!("{va:#x} is not inside any executable section"),
    })?;

    let (full, insn_count): (Vec<SignatureByte>, usize) =
        decode_signature_bytes(&span, va, bitness, opts.max_instructions)?;

    let chosen: Vec<SignatureByte> = if opts.minimize {
        minimize_to_unique(&spans, &full)
    } else {
        full
    };

    let match_count: usize = count_matches(&spans, &chosen);
    let file_offset: u64 = span.file_offset + (va - span.address);
    let wildcard_count: usize = chosen
        .iter()
        .filter(|b: &&SignatureByte| b.wildcard)
        .count();
    let ida_pattern: String = render_ida_pattern(&chosen);
    let (byte_pattern, mask): (String, String) = render_byte_and_mask(&chosen);

    Ok(Signature {
        virtual_address: va,
        file_offset,
        instruction_count: insn_count,
        byte_length: chosen.len(),
        wildcard_count,
        ida_pattern,
        byte_pattern,
        mask,
        unique: match_count == 1,
        match_count,
        bytes: chosen,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_support::{pe64_text_base, pe64_with_text};

    fn sample_text() -> Vec<u8> {
        let mut t: Vec<u8> = Vec::new();
        t.extend_from_slice(&[0x55]);
        t.extend_from_slice(&[0x48, 0x89, 0xE5]);
        t.extend_from_slice(&[0x48, 0xC7, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE]);
        t.extend_from_slice(&[0xE8, 0x11, 0x22, 0x33, 0x44]);
        t.extend_from_slice(&[0x5D]);
        t.extend_from_slice(&[0xC3]);
        t.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]);
        t
    }

    #[test]
    fn signature_matches_its_source_exactly_once() {
        let text: Vec<u8> = sample_text();
        let text_va: u32 = 0x1000;
        let image: Vec<u8> = pe64_with_text(&text, text_va);
        let func_va: u64 = pe64_text_base() + u64::from(text_va);

        let sig: Signature =
            make_signature(&image, func_va, SigmakerOptions::default()).expect("sig");

        assert!(
            sig.unique,
            "generated signature must be unique across the image, got {} matches",
            sig.match_count
        );
        assert_eq!(sig.match_count, 1);
        assert!(
            sig.wildcard_count >= 8,
            "the imm32 (0xDEADBEEF) and the call rel32 must be wildcarded: {}",
            sig.ida_pattern
        );
    }

    #[test]
    fn wildcards_land_on_immediate_and_branch_bytes() {
        let text: Vec<u8> = sample_text();
        let text_va: u32 = 0x1000;
        let image: Vec<u8> = pe64_with_text(&text, text_va);
        let func_va: u64 = pe64_text_base() + u64::from(text_va);
        let sig: Signature = make_signature(
            &image,
            func_va,
            SigmakerOptions {
                max_instructions: 64,
                minimize: false,
            },
        )
        .expect("sig");

        let literal: Vec<u8> = sig.literal_bytes();
        assert_eq!(
            &literal[..text.len() - 4],
            &text[..text.len() - 4],
            "literal bytes must reproduce the source function body"
        );

        let deadbeef_index: usize = 1 + 3 + 3;
        for i in deadbeef_index..deadbeef_index + 4 {
            assert!(
                sig.bytes[i].wildcard,
                "0xDEADBEEF immediate byte {i} must be a wildcard"
            );
        }
        let call_imm_index: usize = 1 + 3 + 7 + 1;
        for i in call_imm_index..call_imm_index + 4 {
            assert!(
                sig.bytes[i].wildcard,
                "call rel32 byte {i} must be a wildcard"
            );
        }
        assert!(
            !sig.bytes[0].wildcard,
            "the push rbp opcode must remain a literal anchor byte"
        );
    }

    #[test]
    fn c_array_decode_equals_source_bytes() {
        let text: Vec<u8> = sample_text();
        let text_va: u32 = 0x1000;
        let image: Vec<u8> = pe64_with_text(&text, text_va);
        let func_va: u64 = pe64_text_base() + u64::from(text_va);
        let sig: Signature = make_signature(
            &image,
            func_va,
            SigmakerOptions {
                max_instructions: 64,
                minimize: false,
            },
        )
        .expect("sig");

        let c_array: String = sig.emit_c_array();
        let parsed: Vec<u8> = parse_c_array_pattern(&c_array);
        let mask: Vec<bool> = parse_c_array_mask(&c_array);
        assert_eq!(parsed.len(), sig.bytes.len());
        for (i, sig_byte) in sig.bytes.iter().enumerate() {
            if !mask[i] {
                assert_eq!(
                    parsed[i], sig_byte.value,
                    "non-wildcard byte {i} in the emitted c-array must equal the source byte"
                );
            }
        }
        let non_wild_source: Vec<u8> = sig
            .bytes
            .iter()
            .enumerate()
            .filter(|(_, b): &(usize, &SignatureByte)| !b.wildcard)
            .map(|(_, b): (usize, &SignatureByte)| b.value)
            .collect();
        let non_wild_emitted: Vec<u8> = parsed
            .iter()
            .enumerate()
            .filter(|(i, _): &(usize, &u8)| !mask[*i])
            .map(|(_, b): (usize, &u8)| *b)
            .collect();
        assert_eq!(non_wild_source, non_wild_emitted);
    }

    #[test]
    fn python_bytes_emitter_is_well_formed() {
        let text: Vec<u8> = sample_text();
        let image: Vec<u8> = pe64_with_text(&text, 0x1000);
        let func_va: u64 = pe64_text_base() + 0x1000;
        let sig: Signature =
            make_signature(&image, func_va, SigmakerOptions::default()).expect("sig");
        let py: String = sig.emit_python_bytes();
        assert!(py.contains("pattern = b\""));
        assert!(py.contains("mask = \""));
        assert_eq!(py.matches("\\x").count(), sig.bytes.len());
    }

    #[test]
    fn va_outside_code_is_rejected() {
        let text: Vec<u8> = sample_text();
        let image: Vec<u8> = pe64_with_text(&text, 0x1000);
        let err: Error =
            make_signature(&image, 0xDEAD_0000, SigmakerOptions::default()).expect_err("reject");
        assert!(matches!(err, Error::Disasm { .. }));
    }

    fn parse_c_array_pattern(src: &str) -> Vec<u8> {
        let inner: &str = src
            .split_once('{')
            .and_then(|(_, rest): (&str, &str)| rest.split_once('}'))
            .map(|(body, _): (&str, &str)| body)
            .expect("braces");
        inner
            .split(',')
            .filter_map(|tok: &str| {
                let t: &str = tok.trim();
                t.strip_prefix("0x")
                    .and_then(|hex: &str| u8::from_str_radix(hex, 16).ok())
            })
            .collect()
    }

    fn parse_c_array_mask(src: &str) -> Vec<bool> {
        let mask_line: &str = src
            .lines()
            .find(|l: &&str| l.contains("mask"))
            .expect("mask line");
        let quoted: &str = mask_line
            .split_once('"')
            .and_then(|(_, rest): (&str, &str)| rest.split_once('"'))
            .map(|(m, _): (&str, &str)| m)
            .expect("quoted mask");
        quoted.chars().map(|c: char| c == '?').collect()
    }
}
