#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

const SEC_TABLE_OFFSET: usize = 0x80 + 4 + 20 + 0xE0;
const FILE_ALIGN: u32 = 0x200;
const SECT_ALIGN: u32 = 0x1000;
const IMAGE_BASE: u32 = 0x0040_0000;

type RawSection = (Vec<u8>, u32, Vec<u8>);

#[derive(Debug, Clone)]
pub struct PackedImage {
    pub bytes: Vec<u8>,
    pub original: Vec<u8>,
    pub oep_rva: u32,
    pub stub_rva: u32,
    pub stub_section_name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SectionSpec<'a> {
    pub name: &'a [u8],
    pub rva: u32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum StubKind {
    LzDecompress,
    StreamDecrypt {
        key0: u8,
        key_step: u8,
    },
    StreamDecryptPoly {
        key0: u8,
        key_step: u8,
        seed: u8,
    },
    GuardedStreamDecrypt {
        key0: u8,
        key_step: u8,
        inverted: bool,
    },
}

pub const GUARDED_STUB_SIZE: usize = 0x500;
pub const GUARD_IMPORT_DIR: u32 = 0x300;
const GUARD_IMPORT_DIR_SIZE: u32 = 60;
pub const GUARD_K32_ILT: u32 = 0x340;
pub const GUARD_K32_IAT: u32 = 0x350;
const GUARD_NT_ILT: u32 = 0x360;
const GUARD_NT_IAT: u32 = 0x368;
const GUARD_NAME_IS_DEBUGGER_PRESENT: u32 = 0x380;
const GUARD_NAME_GET_TICK_COUNT: u32 = 0x3A0;
const GUARD_NAME_ADD_VEH: u32 = 0x3B0;
const GUARD_NAME_NT_QIP: u32 = 0x3D0;
const GUARD_NAME_KERNEL32: u32 = 0x3F0;
const GUARD_NAME_NTDLL: u32 = 0x400;
pub const GUARD_TLS_DIR: u32 = 0x410;
const GUARD_TLS_DIR_SIZE: u32 = 24;
pub const GUARD_TLS_CALLBACKS: u32 = 0x430;
const GUARD_TLS_RAW: u32 = 0x440;
const GUARD_TLS_INDEX: u32 = 0x444;
const GUARD_QIP_OUT: u32 = 0x448;
const GUARD_QIP_RETLEN: u32 = 0x44C;
pub const GUARD_TLS_MARKER: u32 = 0x450;
const GUARD_VEH_HANDLER: u32 = 0x460;
const GUARD_TLS_CALLBACK: u32 = 0x480;

pub const GUARDED_IMPORT_NAMES: [&str; 4] = [
    "IsDebuggerPresent",
    "GetTickCount",
    "AddVectoredExceptionHandler",
    "NtQueryInformationProcess",
];

fn align_up(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

fn lzss_compress(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    let window: usize = 4096;
    let min_match: usize = 3;
    let max_match: usize = 18;
    let mut flag_pos: usize = 0;
    let mut flag_bit: u8 = 0;
    while i < input.len() {
        if flag_bit == 0 {
            flag_pos = out.len();
            out.push(0);
            flag_bit = 1;
        }
        let lo: usize = i.saturating_sub(window);
        let mut best_len: usize = 0;
        let mut best_off: usize = 0;
        let mut j: usize = lo;
        while j < i {
            let mut l: usize = 0;
            while l < max_match
                && i + l < input.len()
                && input[j + l] == input[i + l]
                && j + l < i + max_match
            {
                l += 1;
            }
            if l > best_len {
                best_len = l;
                best_off = i - j;
            }
            j += 1;
        }
        if best_len >= min_match {
            let enc_len: u8 = (best_len - min_match) as u8;
            let off: u16 = best_off as u16;
            out.push((off & 0xFF) as u8);
            out.push((((off >> 8) & 0x0F) as u8) << 4 | enc_len);
            i += best_len;
        } else {
            out[flag_pos] |= flag_bit;
            out.push(input[i]);
            i += 1;
        }
        flag_bit = flag_bit.wrapping_shl(1);
    }
    out
}

fn stream_encrypt(input: &[u8], key0: u8, key_step: u8) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut key: u8 = key0;
    for (idx, b) in input.iter().enumerate() {
        out.push(b ^ key);
        key = key.wrapping_add(key_step).wrapping_add((idx & 0xFF) as u8);
    }
    out
}

struct Asm {
    code: Vec<u8>,
}

impl Asm {
    fn new() -> Self {
        Self { code: Vec::new() }
    }

    fn b(&mut self, byte: u8) {
        self.code.push(byte);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn imm32(&mut self, v: u32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn mov_esi_imm(&mut self, v: u32) {
        self.b(0xBE);
        self.imm32(v);
    }

    fn mov_edi_imm(&mut self, v: u32) {
        self.b(0xBF);
        self.imm32(v);
    }

    fn mov_ecx_imm(&mut self, v: u32) {
        self.b(0xB9);
        self.imm32(v);
    }

    fn mov_edx_imm(&mut self, v: u32) {
        self.b(0xBA);
        self.imm32(v);
    }

    fn mov_ebx_imm(&mut self, v: u32) {
        self.b(0xBB);
        self.imm32(v);
    }

    fn mov_eax_imm(&mut self, v: u32) {
        self.b(0xB8);
        self.imm32(v);
    }

    fn jmp_eax(&mut self) {
        self.bytes(&[0xFF, 0xE0]);
    }

    fn mov_r32_imm(&mut self, reg: u8, v: u32) {
        self.b(0xB8 + (reg & 7));
        self.imm32(v);
    }

    fn push_r32(&mut self, reg: u8) {
        self.b(0x50 + (reg & 7));
    }

    fn pop_r32(&mut self, reg: u8) {
        self.b(0x58 + (reg & 7));
    }

    fn nop(&mut self) {
        self.b(0x90);
    }

    fn mov_al_mem(&mut self, ptr: u8) {
        self.b(0x8A);
        self.b(ptr & 7);
    }

    fn mov_mem_al(&mut self, ptr: u8) {
        self.b(0x88);
        self.b(ptr & 7);
    }

    fn inc_r32(&mut self, reg: u8) {
        self.b(0x40 + (reg & 7));
    }

    fn dec_r32(&mut self, reg: u8) {
        self.b(0x48 + (reg & 7));
    }

    fn test_r32_self(&mut self, reg: u8) {
        self.b(0x85);
        self.b(0xC0 + (reg & 7) * 9);
    }

    fn xor_al_bl(&mut self) {
        self.bytes(&[0x30, 0xD8]);
    }

    fn add_bl_dl(&mut self) {
        self.bytes(&[0x00, 0xD3]);
    }

    fn add_bl_imm8(&mut self, v: u8) {
        self.bytes(&[0x80, 0xC3, v]);
    }

    fn inc_dl(&mut self) {
        self.bytes(&[0xFE, 0xC2]);
    }
}

const REG_ESI: u8 = 6;
const REG_EDI: u8 = 7;
const REG_ECX: u8 = 1;
const REG_EBP: u8 = 5;
const REG_EDX: u8 = 2;
const PTR_REGS: [u8; 2] = [REG_ESI, REG_EDI];
const CTR_REGS: [u8; 2] = [REG_ECX, REG_EBP];

fn emit_junk(a: &mut Asm, n: u8) {
    for i in 0..n {
        match i & 3 {
            0 => a.nop(),
            1 => {
                a.push_r32(REG_EDX);
                a.pop_r32(REG_EDX);
            }
            2 => {
                a.inc_r32(REG_EDI);
                a.dec_r32(REG_EDI);
            }
            _ => {
                a.push_r32(REG_ESI);
                a.pop_r32(REG_ESI);
            }
        }
    }
}

fn emit_stream_decrypt_stub_poly(
    enc_va: u32,
    enc_len: u32,
    key0: u8,
    key_step: u8,
    oep_va: u32,
    seed: u8,
) -> Vec<u8> {
    let ptr: u8 = PTR_REGS[(seed & 1) as usize];
    let ctr: u8 = CTR_REGS[((seed >> 1) & 1) as usize];
    let junk: u8 = 1 + (seed % 3);

    let mut a: Asm = Asm::new();
    emit_junk(&mut a, junk);
    a.mov_r32_imm(ptr, enc_va);
    a.mov_r32_imm(ctr, enc_len);
    a.bytes(&[0xB3, key0]);
    a.bytes(&[0x31, 0xD2]);
    emit_junk(&mut a, junk);

    let top: usize = a.code.len();
    a.test_r32_self(ctr);
    let jz_done_pos: usize = a.code.len() + 2;
    a.bytes(&[0x0F, 0x84]);
    a.imm32(0);

    a.mov_al_mem(ptr);
    a.xor_al_bl();
    a.mov_mem_al(ptr);
    a.inc_r32(ptr);

    a.add_bl_dl();
    a.add_bl_imm8(key_step);
    a.inc_dl();

    emit_junk(&mut a, junk);
    a.dec_r32(ctr);
    let jmp_top_pos: usize = a.code.len() + 1;
    a.b(0xE9);
    a.imm32(0);

    let done_label: usize = a.code.len();
    emit_junk(&mut a, junk);
    a.b(0x68);
    a.imm32(oep_va);
    a.b(0xC3);

    patch_rel32(&mut a.code, jz_done_pos, done_label);
    patch_rel32(&mut a.code, jmp_top_pos, top);
    a.code
}

fn emit_lz_decompress_stub(ops: &[(u32, u32, u32)], oep_va: u32) -> Vec<u8> {
    let mut a: Asm = Asm::new();
    for &(src_va, dest_va, out_len) in ops {
        emit_lz_decompress_block(&mut a, src_va, dest_va, out_len);
    }
    a.mov_eax_imm(oep_va);
    a.jmp_eax();
    a.code
}

fn emit_lz_decompress_block(a: &mut Asm, compressed_src_va: u32, dest_va: u32, out_len: u32) {
    a.mov_esi_imm(compressed_src_va);
    a.mov_edi_imm(dest_va);
    a.mov_edx_imm(dest_va + out_len);
    a.mov_ebx_imm(1);

    let next_bit: usize = a.code.len();
    a.bytes(&[0x39, 0xD7]);
    let jae_done_a: usize = a.code.len() + 2;
    a.bytes(&[0x0F, 0x83]);
    a.imm32(0);

    a.bytes(&[0x83, 0xFB, 0x01]);
    let jne_have_bits: usize = a.code.len() + 2;
    a.bytes(&[0x0F, 0x85]);
    a.imm32(0);

    a.bytes(&[0x0F, 0xB6, 0x1E]);
    a.bytes(&[0x46]);
    a.bytes(&[0x81, 0xCB, 0x00, 0x01, 0x00, 0x00]);

    let have_bits: usize = a.code.len();
    a.bytes(&[0xC1, 0xEB, 0x01]);
    let jnc_match: usize = a.code.len() + 2;
    a.bytes(&[0x0F, 0x83]);
    a.imm32(0);

    a.bytes(&[0xAC]);
    a.bytes(&[0xAA]);
    let jmp_next_a: usize = a.code.len() + 1;
    a.b(0xE9);
    a.imm32(0);

    let match_label: usize = a.code.len();
    a.bytes(&[0x53]);
    a.bytes(&[0x0F, 0xB6, 0x06]);
    a.bytes(&[0x89, 0xC5]);
    a.bytes(&[0x46]);
    a.bytes(&[0x0F, 0xB6, 0x0E]);
    a.bytes(&[0x46]);

    a.bytes(&[0x89, 0xC8]);
    a.bytes(&[0x83, 0xE0, 0x0F]);
    a.bytes(&[0x83, 0xC0, 0x03]);

    a.bytes(&[0xC1, 0xE9, 0x04]);
    a.bytes(&[0xC1, 0xE1, 0x08]);
    a.bytes(&[0x09, 0xE9]);

    a.bytes(&[0x56]);
    a.bytes(&[0x89, 0xFE]);
    a.bytes(&[0x29, 0xCE]);
    a.bytes(&[0x89, 0xC1]);
    a.bytes(&[0xF3, 0xA4]);
    a.bytes(&[0x5E]);

    a.bytes(&[0x5B]);
    let jmp_next_b: usize = a.code.len() + 1;
    a.b(0xE9);
    a.imm32(0);

    let done_label: usize = a.code.len();

    patch_rel32(&mut a.code, jne_have_bits, have_bits);
    patch_rel32(&mut a.code, jnc_match, match_label);
    patch_rel32(&mut a.code, jmp_next_a, next_bit);
    patch_rel32(&mut a.code, jmp_next_b, next_bit);
    patch_rel32(&mut a.code, jae_done_a, done_label);
}

fn emit_stream_decrypt_stub(
    enc_va: u32,
    enc_len: u32,
    key0: u8,
    key_step: u8,
    oep_va: u32,
) -> Vec<u8> {
    let mut a: Asm = Asm::new();
    a.mov_esi_imm(enc_va);
    a.mov_ecx_imm(enc_len);
    a.bytes(&[0xB3, key0]);
    a.bytes(&[0x31, 0xD2]);

    let top: usize = a.code.len();
    a.bytes(&[0x85, 0xC9]);
    let jz_done_pos: usize = a.code.len() + 2;
    a.bytes(&[0x0F, 0x84]);
    a.imm32(0);

    a.bytes(&[0x8A, 0x06]);
    a.bytes(&[0x30, 0xD8]);
    a.bytes(&[0x88, 0x06]);
    a.bytes(&[0x46]);

    a.bytes(&[0x00, 0xD3]);
    a.bytes(&[0x80, 0xC3, key_step]);
    a.bytes(&[0xFE, 0xC2]);

    a.bytes(&[0x49]);
    let jmp_top_pos: usize = a.code.len() + 1;
    a.b(0xE9);
    a.imm32(0);

    let done_label: usize = a.code.len();
    a.mov_eax_imm(oep_va);
    a.jmp_eax();

    patch_rel32(&mut a.code, jz_done_pos, done_label);
    patch_rel32(&mut a.code, jmp_top_pos, top);
    a.code
}

struct GuardAsm {
    a: Asm,
    bad_fixups: Vec<usize>,
    inverted: bool,
}

impl GuardAsm {
    fn jcc_bad(&mut self, cc: u8) {
        let opcode: u8 = if self.inverted { cc ^ 1 } else { cc };
        self.a.bytes(&[0x0F, opcode]);
        self.bad_fixups.push(self.a.code.len());
        self.a.imm32(0);
    }

    fn call_iat(&mut self, slot_va: u32) {
        self.a.bytes(&[0xFF, 0x15]);
        self.a.imm32(slot_va);
    }

    fn mov_eax_fs30(&mut self) {
        self.a.bytes(&[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]);
    }

    fn test_eax_eax(&mut self) {
        self.a.bytes(&[0x85, 0xC0]);
    }
}

const JCC_E: u8 = 0x84;
const JCC_NE: u8 = 0x85;
const JCC_A: u8 = 0x87;
const JCC_B: u8 = 0x82;

fn emit_guarded_stub(
    stub_va: u32,
    enc_va: u32,
    enc_len: u32,
    key0: u8,
    key_step: u8,
    oep_va: u32,
    inverted: bool,
) -> Vec<u8> {
    let va = |off: u32| -> u32 { stub_va + off };
    let mut g: GuardAsm = GuardAsm {
        a: Asm::new(),
        bad_fixups: Vec::new(),
        inverted,
    };

    g.a.bytes(&[0x80, 0x3D]);
    g.a.imm32(va(GUARD_TLS_MARKER));
    g.a.b(0x01);
    g.jcc_bad(JCC_NE);

    g.call_iat(va(GUARD_K32_IAT));
    g.test_eax_eax();
    g.jcc_bad(JCC_NE);

    g.mov_eax_fs30();
    g.a.bytes(&[0x0F, 0xB6, 0x40, 0x02]);
    g.test_eax_eax();
    g.jcc_bad(JCC_NE);

    g.mov_eax_fs30();
    g.a.bytes(&[0x8B, 0x40, 0x68]);
    g.a.bytes(&[0x83, 0xE0, 0x70]);
    g.jcc_bad(JCC_NE);

    g.mov_eax_fs30();
    g.a.bytes(&[0x8B, 0x40, 0x18]);
    g.a.bytes(&[0x8B, 0x48, 0x44]);
    g.a.bytes(&[0x85, 0xC9]);
    g.jcc_bad(JCC_NE);

    g.a.bytes(&[0x0F, 0x31, 0x89, 0xC3, 0x0F, 0x31, 0x29, 0xD8]);
    g.a.b(0x3D);
    g.a.imm32(0x0001_0000);
    g.jcc_bad(JCC_A);

    g.a.mov_eax_imm(1);
    g.a.bytes(&[0x0F, 0xA2, 0x0F, 0xBA, 0xE1, 0x1F]);
    g.jcc_bad(JCC_B);

    g.a.b(0x68);
    g.a.imm32(va(GUARD_QIP_RETLEN));
    g.a.bytes(&[0x6A, 0x04]);
    g.a.b(0x68);
    g.a.imm32(va(GUARD_QIP_OUT));
    g.a.bytes(&[0x6A, 0x07, 0x6A, 0xFF]);
    g.call_iat(va(GUARD_NT_IAT));
    g.test_eax_eax();
    g.jcc_bad(JCC_NE);
    g.a.b(0xA1);
    g.a.imm32(va(GUARD_QIP_OUT));
    g.test_eax_eax();
    g.jcc_bad(JCC_NE);

    g.call_iat(va(GUARD_K32_IAT + 4));
    g.a.bytes(&[0x89, 0xC3]);
    g.call_iat(va(GUARD_K32_IAT + 4));
    g.a.bytes(&[0x29, 0xD8]);
    g.a.b(0x3D);
    g.a.imm32(1000);
    g.jcc_bad(JCC_A);

    g.a.b(0x68);
    g.a.imm32(va(GUARD_VEH_HANDLER));
    g.a.bytes(&[0x6A, 0x01]);
    g.call_iat(va(GUARD_K32_IAT + 8));
    g.test_eax_eax();
    g.jcc_bad(JCC_E);
    g.a.bytes(&[0x31, 0xDB, 0xCD, 0x2D, 0x90, 0x83, 0xFB, 0x01]);
    g.jcc_bad(JCC_NE);

    let a: &mut Asm = &mut g.a;
    a.mov_esi_imm(enc_va);
    a.mov_ecx_imm(enc_len);
    a.bytes(&[0xB3, key0]);
    a.bytes(&[0x31, 0xD2]);
    let top: usize = a.code.len();
    a.bytes(&[0x85, 0xC9]);
    let jz_done_pos: usize = a.code.len() + 2;
    a.bytes(&[0x0F, 0x84]);
    a.imm32(0);
    a.bytes(&[0x8A, 0x06, 0x30, 0xD8, 0x88, 0x06, 0x46]);
    a.bytes(&[0x00, 0xD3]);
    a.bytes(&[0x80, 0xC3, key_step]);
    a.bytes(&[0xFE, 0xC2, 0x49]);
    let jmp_top_pos: usize = a.code.len() + 1;
    a.b(0xE9);
    a.imm32(0);
    let done_label: usize = a.code.len();
    a.mov_eax_imm(oep_va);
    a.jmp_eax();
    let bad_label: usize = a.code.len();
    a.bytes(&[0xEB, 0xFE]);
    patch_rel32(&mut a.code, jz_done_pos, done_label);
    patch_rel32(&mut a.code, jmp_top_pos, top);
    for pos in &g.bad_fixups {
        patch_rel32(&mut g.a.code, *pos, bad_label);
    }
    assert!(
        g.a.code.len() <= GUARD_IMPORT_DIR as usize,
        "guard code must stay below the import directory"
    );

    let mut section: Vec<u8> = g.a.code;
    section.resize(GUARD_IMPORT_DIR as usize, 0x90);
    section.resize(GUARDED_STUB_SIZE, 0);
    let put32 = |s: &mut Vec<u8>, off: u32, v: u32| {
        let o: usize = off as usize;
        s[o..o + 4].copy_from_slice(&v.to_le_bytes());
    };
    let put_bytes = |s: &mut Vec<u8>, off: u32, b: &[u8]| {
        let o: usize = off as usize;
        s[o..o + b.len()].copy_from_slice(b);
    };

    let descriptors: [(u32, u32, u32); 2] = [
        (GUARD_K32_ILT, GUARD_NAME_KERNEL32, GUARD_K32_IAT),
        (GUARD_NT_ILT, GUARD_NAME_NTDLL, GUARD_NT_IAT),
    ];
    for (i, (ilt, name, iat)) in descriptors.iter().enumerate() {
        let d: u32 = GUARD_IMPORT_DIR + i as u32 * 20;
        put32(&mut section, d, va_to_rva(va(*ilt)));
        put32(&mut section, d + 12, va_to_rva(va(*name)));
        put32(&mut section, d + 16, va_to_rva(va(*iat)));
    }
    let k32_names: [u32; 3] = [
        GUARD_NAME_IS_DEBUGGER_PRESENT,
        GUARD_NAME_GET_TICK_COUNT,
        GUARD_NAME_ADD_VEH,
    ];
    for (i, name_off) in k32_names.iter().enumerate() {
        let rva: u32 = va_to_rva(va(*name_off));
        put32(&mut section, GUARD_K32_ILT + i as u32 * 4, rva);
        put32(&mut section, GUARD_K32_IAT + i as u32 * 4, rva);
    }
    let nt_rva: u32 = va_to_rva(va(GUARD_NAME_NT_QIP));
    put32(&mut section, GUARD_NT_ILT, nt_rva);
    put32(&mut section, GUARD_NT_IAT, nt_rva);
    for (off, name) in [
        (GUARD_NAME_IS_DEBUGGER_PRESENT, GUARDED_IMPORT_NAMES[0]),
        (GUARD_NAME_GET_TICK_COUNT, GUARDED_IMPORT_NAMES[1]),
        (GUARD_NAME_ADD_VEH, GUARDED_IMPORT_NAMES[2]),
        (GUARD_NAME_NT_QIP, GUARDED_IMPORT_NAMES[3]),
    ] {
        put_bytes(&mut section, off, &[0, 0]);
        put_bytes(&mut section, off + 2, name.as_bytes());
    }
    put_bytes(&mut section, GUARD_NAME_KERNEL32, b"kernel32.dll\0");
    put_bytes(&mut section, GUARD_NAME_NTDLL, b"ntdll.dll\0");

    put32(&mut section, GUARD_TLS_DIR, va(GUARD_TLS_RAW));
    put32(&mut section, GUARD_TLS_DIR + 4, va(GUARD_TLS_RAW) + 4);
    put32(&mut section, GUARD_TLS_DIR + 8, va(GUARD_TLS_INDEX));
    put32(&mut section, GUARD_TLS_DIR + 12, va(GUARD_TLS_CALLBACKS));
    put32(&mut section, GUARD_TLS_DIR + 16, 0);
    put32(&mut section, GUARD_TLS_DIR + 20, 0);
    put32(&mut section, GUARD_TLS_CALLBACKS, va(GUARD_TLS_CALLBACK));
    put32(&mut section, GUARD_TLS_CALLBACKS + 4, 0);
    put32(&mut section, GUARD_TLS_RAW, 0);
    put32(&mut section, GUARD_TLS_INDEX, 0);
    put32(&mut section, GUARD_QIP_OUT, 0xDEAD_BEEF);
    put32(&mut section, GUARD_QIP_RETLEN, 0);
    section[GUARD_TLS_MARKER as usize] = 0;

    put_bytes(
        &mut section,
        GUARD_VEH_HANDLER,
        &[
            0x8B, 0x44, 0x24, 0x04, 0x8B, 0x40, 0x04, 0xC7, 0x80, 0xA4, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
        ],
    );
    let mut tls: Asm = Asm::new();
    tls.bytes(&[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]);
    tls.bytes(&[0x0F, 0xB6, 0x40, 0x02]);
    tls.bytes(&[0x85, 0xC0]);
    tls.bytes(&[0x75, 0x07]);
    tls.bytes(&[0xC6, 0x05]);
    tls.imm32(va(GUARD_TLS_MARKER));
    tls.b(0x01);
    tls.bytes(&[0xC2, 0x0C, 0x00]);
    put_bytes(&mut section, GUARD_TLS_CALLBACK, &tls.code);
    section
}

fn va_to_rva(target_va: u32) -> u32 {
    target_va - IMAGE_BASE
}

fn patch_rel32(code: &mut [u8], operand_pos: usize, target: usize) {
    let next_ip: i64 = (operand_pos + 4) as i64;
    let rel: i32 = (target as i64 - next_ip) as i32;
    code[operand_pos..operand_pos + 4].copy_from_slice(&rel.to_le_bytes());
}

pub fn build_packed(
    content: &[SectionSpec<'_>],
    oep_rva: u32,
    stub_name: &[u8],
    kind: StubKind,
) -> PackedImage {
    let original: Vec<u8> = build_original(content, oep_rva);

    let stub_rva: u32 = content
        .iter()
        .map(|s: &SectionSpec<'_>| align_up(s.rva + s.body.len() as u32, SECT_ALIGN))
        .max()
        .unwrap_or(SECT_ALIGN)
        .max(SECT_ALIGN);

    let oep_va: u32 = IMAGE_BASE + oep_rva;

    let (mut packed_sections, stub_code): (Vec<RawSection>, Vec<u8>) = match kind {
        StubKind::LzDecompress => {
            let mut sections: Vec<RawSection> = Vec::new();
            let mut payload: Vec<u8> = Vec::new();
            let mut decompress_ops: Vec<(u32, u32, u32)> = Vec::new();
            for s in content {
                let comp: Vec<u8> = lzss_compress(&s.body);
                let src_va: u32 = IMAGE_BASE + stub_rva + 0x400 + payload.len() as u32;
                decompress_ops.push((src_va, IMAGE_BASE + s.rva, s.body.len() as u32));
                payload.extend_from_slice(&comp);
                sections.push((s.name.to_vec(), s.rva, vec![0u8; s.body.len()]));
            }
            let mut code: Vec<u8> = emit_lz_decompress_stub(&decompress_ops, oep_va);
            let pad_to: usize = 0x400;
            if code.len() < pad_to {
                code.resize(pad_to, 0x90);
            }
            code.extend_from_slice(&payload);
            (sections, code)
        }
        StubKind::StreamDecrypt { key0, key_step } => {
            let mut sections: Vec<RawSection> = Vec::new();
            let s: &SectionSpec<'_> = &content[0];
            let enc: Vec<u8> = stream_encrypt(&s.body, key0, key_step);
            sections.push((s.name.to_vec(), s.rva, enc));
            for extra in &content[1..] {
                sections.push((extra.name.to_vec(), extra.rva, extra.body.clone()));
            }
            let code: Vec<u8> = emit_stream_decrypt_stub(
                IMAGE_BASE + s.rva,
                s.body.len() as u32,
                key0,
                key_step,
                oep_va,
            );
            (sections, code)
        }
        StubKind::StreamDecryptPoly {
            key0,
            key_step,
            seed,
        } => {
            let mut sections: Vec<RawSection> = Vec::new();
            let s: &SectionSpec<'_> = &content[0];
            let enc: Vec<u8> = stream_encrypt(&s.body, key0, key_step);
            sections.push((s.name.to_vec(), s.rva, enc));
            for extra in &content[1..] {
                sections.push((extra.name.to_vec(), extra.rva, extra.body.clone()));
            }
            let code: Vec<u8> = emit_stream_decrypt_stub_poly(
                IMAGE_BASE + s.rva,
                s.body.len() as u32,
                key0,
                key_step,
                oep_va,
                seed,
            );
            (sections, code)
        }
        StubKind::GuardedStreamDecrypt {
            key0,
            key_step,
            inverted,
        } => {
            let mut sections: Vec<RawSection> = Vec::new();
            let s: &SectionSpec<'_> = &content[0];
            let enc: Vec<u8> = stream_encrypt(&s.body, key0, key_step);
            sections.push((s.name.to_vec(), s.rva, enc));
            for extra in &content[1..] {
                sections.push((extra.name.to_vec(), extra.rva, extra.body.clone()));
            }
            let code: Vec<u8> = emit_guarded_stub(
                IMAGE_BASE + stub_rva,
                IMAGE_BASE + s.rva,
                s.body.len() as u32,
                key0,
                key_step,
                oep_va,
                inverted,
            );
            (sections, code)
        }
    };

    let directories: Vec<(usize, u32, u32)> = match kind {
        StubKind::GuardedStreamDecrypt { .. } => vec![
            (1, stub_rva + GUARD_IMPORT_DIR, GUARD_IMPORT_DIR_SIZE),
            (9, stub_rva + GUARD_TLS_DIR, GUARD_TLS_DIR_SIZE),
        ],
        StubKind::LzDecompress
        | StubKind::StreamDecrypt { .. }
        | StubKind::StreamDecryptPoly { .. } => Vec::new(),
    };
    packed_sections.push((stub_name.to_vec(), stub_rva, stub_code));
    let bytes: Vec<u8> = assemble_pe_with_dirs(&packed_sections, stub_rva, &directories);

    PackedImage {
        bytes,
        original,
        oep_rva,
        stub_rva,
        stub_section_name: stub_name.to_vec(),
    }
}

fn build_original(content: &[SectionSpec<'_>], oep_rva: u32) -> Vec<u8> {
    let secs: Vec<RawSection> = content
        .iter()
        .map(|s: &SectionSpec<'_>| (s.name.to_vec(), s.rva, s.body.clone()))
        .collect();
    assemble_pe(&secs, oep_rva)
}

fn assemble_pe(sections: &[RawSection], entry_rva: u32) -> Vec<u8> {
    assemble_pe_with_dirs(sections, entry_rva, &[])
}

fn assemble_pe_with_dirs(
    sections: &[RawSection],
    entry_rva: u32,
    directories: &[(usize, u32, u32)],
) -> Vec<u8> {
    let header_len: usize = 0x400;
    let mut buf: Vec<u8> = vec![0u8; header_len];
    buf[0] = b'M';
    buf[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe_off: usize = e_lfanew as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
    let coff: usize = pe_off + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
    buf[opt + 28..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&SECT_ALIGN.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&FILE_ALIGN.to_le_bytes());
    if !directories.is_empty() {
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    }
    for (index, rva, size) in directories {
        let entry: usize = opt + 96 + index * 8;
        buf[entry..entry + 4].copy_from_slice(&rva.to_le_bytes());
        buf[entry + 4..entry + 8].copy_from_slice(&size.to_le_bytes());
    }

    let max_end_rva: u32 = sections
        .iter()
        .map(|(_, rva, body): &(Vec<u8>, u32, Vec<u8>)| {
            align_up(rva + body.len() as u32, SECT_ALIGN)
        })
        .max()
        .unwrap_or(SECT_ALIGN);
    buf[opt + 56..opt + 60].copy_from_slice(&align_up(max_end_rva, SECT_ALIGN).to_le_bytes());

    let mut raw_cursor: u32 = header_len as u32;
    let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
    for (i, (name, rva, body)) in sections.iter().enumerate() {
        let off: usize = SEC_TABLE_OFFSET + i * 40;
        let mut name_buf: [u8; 8] = [0u8; 8];
        let nlen: usize = name.len().min(8);
        name_buf[..nlen].copy_from_slice(&name[..nlen]);
        buf[off..off + 8].copy_from_slice(&name_buf);
        let raw_size: u32 = align_up(body.len() as u32, FILE_ALIGN).max(FILE_ALIGN);
        buf[off + 8..off + 12].copy_from_slice(&(body.len() as u32).to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&rva.to_le_bytes());
        buf[off + 16..off + 20].copy_from_slice(&raw_size.to_le_bytes());
        buf[off + 20..off + 24].copy_from_slice(&raw_cursor.to_le_bytes());
        buf[off + 36..off + 40].copy_from_slice(&0xE000_0020u32.to_le_bytes());
        bodies.push((raw_cursor as usize, body.clone()));
        raw_cursor += raw_size;
    }
    buf.resize(raw_cursor as usize, 0);
    for (off, body) in bodies {
        buf[off..off + body.len()].copy_from_slice(&body);
    }
    buf
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn lzss_roundtrips_in_rust() {
        let input: Vec<u8> =
            b"the quick brown fox the quick brown fox jumps over the lazy dog dog dog".repeat(8);
        let comp: Vec<u8> = lzss_compress(&input);
        assert!(
            comp.len() < input.len(),
            "compressor must shrink repetitive input"
        );
        let dec: Vec<u8> = reference_lzss_decompress(&comp, input.len());
        assert_eq!(
            dec, input,
            "reference decompress must invert the compressor"
        );
    }

    #[test]
    fn poly_stub_encrypts_and_does_not_leak_plaintext_for_every_seed() {
        let body: Vec<u8> =
            b"polymorphic decrypt stub recovered by blind emulation across seeds. ".repeat(20);
        for seed in 0u8..4 {
            let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
                name: b".text",
                rva: 0x1000,
                body: body.clone(),
            }];
            let p: PackedImage = build_packed(
                &secs,
                0x1000,
                b".aspr",
                StubKind::StreamDecryptPoly {
                    key0: 0x44u8.wrapping_add(seed),
                    key_step: 0x29u8.wrapping_add(seed),
                    seed,
                },
            );
            let needle: &[u8] = b"polymorphic decrypt stub";
            let leaks: bool = p.bytes.windows(needle.len()).any(|w: &[u8]| w == needle);
            assert!(
                !leaks,
                "seed {seed}: encrypted packed image must not contain the plaintext",
            );
        }
    }

    #[test]
    fn stream_cipher_roundtrips() {
        let input: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let enc: Vec<u8> = stream_encrypt(&input, 0x5A, 0x13);
        let mut key: u8 = 0x5A;
        let dec: Vec<u8> = enc
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| {
                let p: u8 = b ^ key;
                key = key.wrapping_add(0x13).wrapping_add((i & 0xFF) as u8);
                p
            })
            .collect();
        assert_eq!(dec, input);
    }

    fn reference_lzss_decompress(comp: &[u8], out_len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(out_len);
        let mut i: usize = 0;
        while out.len() < out_len && i < comp.len() {
            let flags: u8 = comp[i];
            i += 1;
            for bit in 0..8 {
                if out.len() >= out_len {
                    break;
                }
                if (flags >> bit) & 1 == 1 {
                    out.push(comp[i]);
                    i += 1;
                } else {
                    let b0: u8 = comp[i];
                    let b1: u8 = comp[i + 1];
                    i += 2;
                    let off: usize = (b0 as usize) | (((b1 >> 4) as usize) << 8);
                    let len: usize = (b1 & 0x0F) as usize + 3;
                    let start: usize = out.len() - off;
                    for k in 0..len {
                        let byte: u8 = out[start + k];
                        out.push(byte);
                    }
                }
            }
        }
        out
    }
}
