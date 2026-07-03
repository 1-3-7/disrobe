#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::arch::{Arch, DisasmInsn, Syntax, disassemble_x86};
use disrobe_pass_native::parse_nspack_layout;

const STUB_MAGIC: &[u8] = b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00";
const APLIB_BLOB_DELTA_FROM_STUB: usize = 0x3D1;

fn corpus(name: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push("nspack");
    p.push(name);
    fs::read(&p).ok()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

struct ApReader<'a> {
    src: &'a [u8],
    pos: usize,
    tag: u32,
    bits_left: u32,
}

impl<'a> ApReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        ApReader {
            src,
            pos: 0,
            tag: 0,
            bits_left: 0,
        }
    }

    fn next_byte(&mut self) -> u8 {
        let b: u8 = self.src.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    fn get_bit(&mut self) -> u32 {
        if self.bits_left == 0 {
            self.tag = u32::from(self.next_byte());
            self.bits_left = 8;
        }
        let bit: u32 = (self.tag >> 7) & 1;
        self.tag = (self.tag << 1) & 0xFF;
        self.bits_left -= 1;
        bit
    }

    fn get_gamma(&mut self) -> usize {
        let mut v: usize = 1;
        loop {
            v = (v << 1) + self.get_bit() as usize;
            if self.get_bit() == 0 {
                return v;
            }
        }
    }
}

fn copy_match(out: &mut Vec<u8>, off: usize, len: usize) {
    for _ in 0..len {
        let b: u8 = out.get(out.len().wrapping_sub(off)).copied().unwrap_or(0);
        out.push(b);
    }
}

fn aplib_depack_nspack(src: &[u8], cap: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    let mut r: ApReader<'_> = ApReader::new(src);
    let mut r0: usize = 0;
    out.push(r.next_byte());
    while out.len() < cap {
        if r.get_bit() == 0 {
            out.push(r.next_byte());
            continue;
        }
        if r.get_bit() == 0 {
            let gamma: usize = r.get_gamma();
            if gamma == 2 {
                let len: usize = r.get_gamma();
                copy_match(&mut out, r0, len);
                continue;
            }
            let high: usize = gamma - 3;
            let lo: usize = r.next_byte() as usize;
            let new_off: usize = (high << 8) | lo;
            let mut len: usize = r.get_gamma();
            if new_off >= 32_000 {
                len += 2;
            } else if new_off >= 1_280 {
                len += 1;
            } else if new_off < 128 {
                len += 2;
            }
            copy_match(&mut out, new_off, len);
            r0 = new_off;
            continue;
        }
        if r.get_bit() == 0 {
            let byte: usize = r.next_byte() as usize;
            if byte == 0 {
                break;
            }
            let short_off: usize = byte >> 1;
            let len: usize = 2 + (byte & 1);
            copy_match(&mut out, short_off, len);
            r0 = short_off;
            continue;
        }
        let mut off: usize = 0;
        for _ in 0..4 {
            off = (off << 1) | r.get_bit() as usize;
        }
        let b: u8 = if off == 0 {
            0
        } else {
            out.get(out.len().wrapping_sub(off)).copied().unwrap_or(0)
        };
        out.push(b);
    }
    out
}

fn recover_decoder_image(packed: &[u8]) -> Option<Vec<u8>> {
    parse_nspack_layout(packed).ok()?;
    let stub_off: usize = find_subsequence(packed, STUB_MAGIC)?;
    let blob_off: usize = stub_off.checked_add(APLIB_BLOB_DELTA_FROM_STUB)?;
    let blob: &[u8] = packed.get(blob_off..)?;
    let image: Vec<u8> = aplib_depack_nspack(blob, 0x700);
    let trailing_zeros: usize = image.iter().rev().take_while(|b: &&u8| **b == 0).count();
    let real_len: usize = image.len() - trailing_zeros;
    Some(image[..real_len].to_vec())
}

#[test]
fn nspack_stub_aplib_decompresses_to_valid_lzma_decoder() {
    let Some(packed): Option<Vec<u8>> = corpus("handle.packed.nspack.exe") else {
        eprintln!("skip: handle.packed.nspack.exe missing");
        return;
    };
    let image: Vec<u8> =
        recover_decoder_image(&packed).expect("aplib-depack of NSPack decompressor stub");

    assert!(
        image.len() > 0x600,
        "decoder image too small: {} bytes",
        image.len()
    );
    assert_eq!(
        &image[..6],
        &[0x8b, 0x11, 0x3b, 0x51, 0x04, 0x75],
        "decoder image must start with the range-reader prologue mov edx,[ecx]; cmp edx,[ecx+4]; jne"
    );

    let insns: Vec<DisasmInsn> =
        disassemble_x86(Arch::X86, 0, &image, Syntax::Nasm).expect("disassemble recovered decoder");
    assert!(
        insns.len() > 200,
        "expected a few hundred decoded instructions, got {}",
        insns.len()
    );
}

#[test]
fn nspack_decode_core_matches_disrobe_constants() {
    let Some(packed): Option<Vec<u8>> = corpus("handle.packed.nspack.exe") else {
        eprintln!("skip: handle.packed.nspack.exe missing");
        return;
    };
    let image: Vec<u8> =
        recover_decoder_image(&packed).expect("aplib-depack of NSPack decompressor stub");
    let insns: Vec<DisasmInsn> =
        disassemble_x86(Arch::X86, 0, &image, Syntax::Nasm).expect("disassemble recovered decoder");

    let mut text: String = String::new();
    for i in &insns {
        use std::fmt::Write as _;
        let _ = writeln!(text, "{:08x} {} {}", i.address, i.mnemonic, i.operands);
    }

    assert!(
        text.contains("1000000h"),
        "decode core must normalize the range against TOP_VALUE 0x1000000"
    );

    let shr11: bool = insns
        .iter()
        .any(|i: &DisasmInsn| i.mnemonic == "shr" && i.operands.replace(' ', "").contains(",0Bh"));
    assert!(
        shr11,
        "decode_bit must shift range right by 11 (NUM_BIT_MODEL_TOTAL_BITS)"
    );

    let move_bits5: bool = insns.iter().any(|i: &DisasmInsn| {
        (i.mnemonic == "sar" || i.mnemonic == "shr") && i.operands.replace(' ', "").contains(",5")
    });
    assert!(
        move_bits5,
        "decode_bit prob update must use MOVE_BITS shift of 5"
    );

    assert!(
        text.contains("800h"),
        "decode_bit must reference BIT_MODEL_TOTAL 0x800 (2048) in the prob update"
    );

    let probs_doubling: bool = insns
        .iter()
        .any(|i: &DisasmInsn| i.operands.contains("300h"));
    assert!(
        probs_doubling,
        "decode core must build the 0x300<<shift literal-probability table"
    );

    assert!(
        text.contains("736h") || text.contains("0E6Ch"),
        "table sizing must add 0x736 words (== 0xE6C bytes) for the non-literal probs"
    );
}
