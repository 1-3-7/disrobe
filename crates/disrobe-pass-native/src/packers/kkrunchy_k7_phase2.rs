#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal
)]

use crate::error::{Error, Result};
use crate::packers::kkrunchy_unpack::{KkrunchyHeaderInfo, parse_kkrunchy_header};
use crate::stub_emu::mem::MAX_MAP_BYTES;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const UNPACKED_IMAGE_BASE: u64 = 0x0040_0000;
const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;
const PE32_OPT_HEADER_SIZE: u16 = 0xe0;
const PE32_DATA_DIRECTORIES: u32 = 16;
const COFF_HEADER_LEN: usize = 20;
const IMPORT_DESCRIPTOR_SIZE: u32 = 0x14;

const EMU_STACK_BASE: u64 = 0x0012_0000;
const EMU_STACK_SIZE: u64 = 0x0004_0000;

const SYNTH_FN_BASE: u64 = 0x7000_0000;

const STEP_CAP_K7: u64 = 600_000_000;

const DEFAULT_STACK_RESERVE: u32 = 0x0010_0000;
const DEFAULT_STACK_COMMIT: u32 = 0x0000_1000;
const DEFAULT_HEAP_RESERVE: u32 = 0x0010_0000;
const DEFAULT_HEAP_COMMIT: u32 = 0x0000_1000;
const WIN32_CUI_SUBSYSTEM: u16 = 3;
const SCN_TEXT_CHARACTERISTICS: u32 = 0xe000_0020;

#[derive(Debug, Clone)]
pub struct KkrunchyK7Output {
    pub unpacked_image_base: u64,
    pub original_entry_rva: u32,
    pub recovered_memory_image: Vec<u8>,
    pub recovered_file_image: Vec<u8>,
    pub recovered_imports: Vec<(String, Vec<String>)>,
    pub oep_va: u64,
    pub steps: u64,
}

#[derive(Debug)]
struct K7Host {
    resolved: Vec<(String, Vec<String>)>,
    current_dll: Option<String>,
    next_fn: u64,
}

impl K7Host {
    fn new() -> Self {
        Self {
            resolved: Vec::new(),
            current_dll: None,
            next_fn: SYNTH_FN_BASE,
        }
    }

    fn read_cstr(mem: &Memory, addr: u64) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        let mut cur: u64 = addr;
        while bytes.len() < 256 {
            let Ok(b): Result<u8> = mem.read_u8(cur) else {
                break;
            };
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur += 1;
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl K7Host {
    fn record_function(&mut self, func_name: String) {
        let Some(dll): Option<String> = self.current_dll.clone() else {
            return;
        };
        if func_name.is_empty() {
            return;
        }
        for entry in &mut self.resolved {
            if entry.0 == dll {
                entry.1.push(func_name);
                return;
            }
        }
    }
}

impl HostCall for K7Host {
    fn dispatch(&mut self, _target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        let sp: u64 = regs.get(Reg::Rsp);
        let arg0: u64 = u64::from(mem.read_u32(sp).unwrap_or(0));
        let arg1: u64 = u64::from(mem.read_u32(sp.wrapping_add(4)).unwrap_or(0));

        let pointed: String = Self::read_cstr(mem, arg0);
        let looks_like_dll: bool = pointed.to_ascii_lowercase().ends_with(".dll");

        if looks_like_dll {
            if !self
                .resolved
                .iter()
                .any(|(d, _): &(String, Vec<String>)| *d == pointed)
            {
                self.resolved.push((pointed.clone(), Vec::new()));
            }
            self.current_dll = Some(pointed);
            regs.write_sized(Reg::Rax, UNPACKED_IMAGE_BASE, 32);
            regs.set(Reg::Rsp, sp.wrapping_add(4));
            return Ok(true);
        }

        let func_name: String = Self::read_cstr(mem, arg1);
        self.record_function(func_name);
        let v: u64 = self.next_fn;
        self.next_fn = self.next_fn.wrapping_add(0x10);
        regs.write_sized(Reg::Rax, v, 32);
        regs.set(Reg::Rsp, sp.wrapping_add(8));
        Ok(true)
    }
}

pub fn unpack_kkrunchy_k7_emulated(packed: &[u8]) -> Result<KkrunchyK7Output> {
    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(packed)?;
    let packed_base: u64 = u64::from(header.image_base);
    let image_span: u64 = u64::from(header.size_of_image)
        .max(u64::from(header.section_va) + u64::from(header.section_vsize))
        .min(MAX_MAP_BYTES);
    if image_span < 0x2000 {
        return Err(Error::SignatureDb(
            "kkrunchy k7: image span too small to host the depacker".to_owned(),
        ));
    }

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.mem.map(packed_base, image_span, Perm::RWX)?;
    cpu.mem.write(packed_base, packed)?;
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;

    cpu.regs.rip = packed_base + u64::from(header.entry_rva);
    cpu.regs
        .set(Reg::Rsp, EMU_STACK_BASE + EMU_STACK_SIZE - 0x100);
    for reg in [
        Reg::Rax,
        Reg::Rbx,
        Reg::Rcx,
        Reg::Rdx,
        Reg::Rsi,
        Reg::Rdi,
        Reg::Rbp,
    ] {
        cpu.regs.write_sized(reg, 0, 32);
    }

    let oep_lo: u64 = UNPACKED_IMAGE_BASE + u64::from(SECTION_ALIGNMENT);
    let oep_hi: u64 = UNPACKED_IMAGE_BASE + image_span.min(0x0010_0000);

    let mut host: K7Host = K7Host::new();
    let (oep_va, steps): (u64, u64) = run_to_oep(&mut cpu, &mut host, oep_lo, oep_hi)?;
    let original_entry_rva: u32 = (oep_va - UNPACKED_IMAGE_BASE) as u32;

    let unpacked_span: usize = image_span.min(0x0010_0000) as usize;
    let mut memory_image: Vec<u8> = cpu.mem.read_lossy(UNPACKED_IMAGE_BASE, unpacked_span);

    reconstruct_import_region(&mut memory_image, &cpu)?;

    let file_image: Vec<u8> =
        reconstruct_pe(&memory_image, original_entry_rva).ok_or_else(|| {
            Error::SignatureDb(
                "kkrunchy k7: OEP image lacked a usable .text region to rebuild".to_owned(),
            )
        })?;

    Ok(KkrunchyK7Output {
        unpacked_image_base: UNPACKED_IMAGE_BASE,
        original_entry_rva,
        recovered_memory_image: memory_image,
        recovered_file_image: file_image,
        recovered_imports: host.resolved,
        oep_va,
        steps,
    })
}

fn run_to_oep(cpu: &mut Cpu, host: &mut K7Host, oep_lo: u64, oep_hi: u64) -> Result<(u64, u64)> {
    let mut steps: u64 = 0;
    loop {
        if steps >= STEP_CAP_K7 {
            return Err(Error::SignatureDb(format!(
                "kkrunchy k7: depacker did not reach the OEP within {STEP_CAP_K7} steps"
            )));
        }
        steps += 1;
        let ip: u64 = cpu.regs.rip;
        if ip >= oep_lo && ip < oep_hi && cpu.mem.read_u8(ip).unwrap_or(0) != 0 {
            return Ok((ip, steps));
        }
        let exit: ExitReason = cpu.run(host, 1)?;
        match exit {
            ExitReason::StepCap(_) => {}
            ExitReason::JumpedOutOfRange { to, .. } if to >= oep_lo && to < oep_hi => {
                return Ok((to, steps));
            }
            other => {
                return Err(Error::SignatureDb(format!(
                    "kkrunchy k7: depacker stopped before the OEP ({other:?}) at step {steps}"
                )));
            }
        }
    }
}

fn reconstruct_import_region(memory_image: &mut [u8], cpu: &Cpu) -> Result<()> {
    let Some((desc_rva, oft_rva, name_dir_rva, iat_rva)): Option<(u32, u32, u32, u32)> =
        find_import_descriptor(memory_image)
    else {
        return Ok(());
    };
    let _ = (desc_rva, name_dir_rva);

    let Some((dll, funcs)): Option<(Vec<u8>, Vec<Vec<u8>>)> =
        locate_staging_import_list(cpu, iat_rva)
    else {
        return Ok(());
    };
    if funcs.is_empty() {
        return Ok(());
    }

    let thunk_terminator: u32 = iat_rva + (funcs.len() as u32 + 1) * 4;
    let mut cursor: u32 = thunk_terminator;
    let mut name_rvas: Vec<u32> = Vec::with_capacity(funcs.len());
    for func in &funcs {
        let off: usize = cursor as usize;
        if off + 2 + func.len() + 1 > memory_image.len() {
            return Ok(());
        }
        memory_image[off] = 0;
        memory_image[off + 1] = 0;
        memory_image[off + 2..off + 2 + func.len()].copy_from_slice(func);
        memory_image[off + 2 + func.len()] = 0;
        name_rvas.push(cursor);
        cursor += 2 + func.len() as u32 + 1;
    }
    let dll_off: usize = cursor as usize;
    if dll_off + dll.len() + 1 > memory_image.len() {
        return Ok(());
    }
    memory_image[dll_off..dll_off + dll.len()].copy_from_slice(&dll);
    memory_image[dll_off + dll.len()] = 0;

    write_thunks(memory_image, oft_rva, &name_rvas)?;
    write_thunks(memory_image, iat_rva, &name_rvas)?;
    Ok(())
}

fn find_import_descriptor(memory_image: &[u8]) -> Option<(u32, u32, u32, u32)> {
    let mut probe: usize = 0;
    let stride: usize = IMPORT_DESCRIPTOR_SIZE as usize;
    let hi: u32 = memory_image.len() as u32;
    while probe + stride <= memory_image.len() {
        let oft: u32 = u32::from_le_bytes(memory_image[probe..probe + 4].try_into().ok()?);
        let time: u32 = u32::from_le_bytes(memory_image[probe + 4..probe + 8].try_into().ok()?);
        let forward: u32 = u32::from_le_bytes(memory_image[probe + 8..probe + 12].try_into().ok()?);
        let name: u32 = u32::from_le_bytes(memory_image[probe + 12..probe + 16].try_into().ok()?);
        let iat: u32 = u32::from_le_bytes(memory_image[probe + 16..probe + 20].try_into().ok()?);
        let span: u32 = SECTION_ALIGNMENT;
        let plausible = |r: u32| -> bool { r >= span && r < hi };
        let valid: bool = oft != 0
            && name != 0
            && iat != 0
            && plausible(oft)
            && plausible(name)
            && plausible(iat)
            && oft != iat
            && oft != name
            && iat != name
            && time == 0
            && forward == 0;
        if valid {
            return Some((probe as u32, oft, name, iat));
        }
        probe += 1;
    }
    None
}

fn locate_staging_import_list(cpu: &Cpu, iat_rva: u32) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let want_thunk: u32 = UNPACKED_IMAGE_BASE as u32 + iat_rva;
    let scan_lo: u64 = UNPACKED_IMAGE_BASE;
    let scan_hi: u64 = UNPACKED_IMAGE_BASE + 0x0001_0000;
    let mut addr: u64 = scan_lo;
    while addr + 4 < scan_hi {
        let dword: u32 = cpu.mem.read_u32(addr).unwrap_or(0);
        if dword == want_thunk {
            let mut cur: u64 = addr + 4;
            let dll: Vec<u8> = read_cstr_bytes(cpu, cur)?;
            if dll.len() < 5 || !dll.eq_ignore_ascii_case_dll() {
                addr += 1;
                continue;
            }
            cur += dll.len() as u64 + 1;
            let mut funcs: Vec<Vec<u8>> = Vec::new();
            loop {
                let b: u8 = cpu.mem.read_u8(cur).unwrap_or(0);
                if b == 0 {
                    break;
                }
                let f: Vec<u8> = read_cstr_bytes(cpu, cur)?;
                if f.is_empty() || !f.iter().all(|c: &u8| c.is_ascii_graphic()) {
                    break;
                }
                cur += f.len() as u64 + 1;
                funcs.push(f);
            }
            if !funcs.is_empty() {
                return Some((dll, funcs));
            }
        }
        addr += 1;
    }
    None
}

trait DllSuffix {
    fn eq_ignore_ascii_case_dll(&self) -> bool;
}

impl DllSuffix for Vec<u8> {
    fn eq_ignore_ascii_case_dll(&self) -> bool {
        self.len() >= 4 && self[self.len() - 4..].eq_ignore_ascii_case(b".dll")
    }
}

fn read_cstr_bytes(cpu: &Cpu, addr: u64) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut cur: u64 = addr;
    while out.len() < 256 {
        let b: u8 = cpu.mem.read_u8(cur).ok()?;
        if b == 0 {
            return Some(out);
        }
        out.push(b);
        cur += 1;
    }
    None
}

fn write_thunks(memory_image: &mut [u8], table_rva: u32, name_rvas: &[u32]) -> Result<()> {
    let base: usize = table_rva as usize;
    for (i, rva) in name_rvas.iter().enumerate() {
        let off: usize = base + i * 4;
        if off + 4 > memory_image.len() {
            return Err(Error::SignatureDb(
                "kkrunchy k7: thunk table overruns recovered image".to_owned(),
            ));
        }
        memory_image[off..off + 4].copy_from_slice(&rva.to_le_bytes());
    }
    let term: usize = base + name_rvas.len() * 4;
    if term + 4 > memory_image.len() {
        return Err(Error::SignatureDb(
            "kkrunchy k7: thunk terminator overruns recovered image".to_owned(),
        ));
    }
    memory_image[term..term + 4].copy_from_slice(&0u32.to_le_bytes());
    Ok(())
}

fn reconstruct_pe(memory_image: &[u8], entry_rva: u32) -> Option<Vec<u8>> {
    let text_va: u32 = SECTION_ALIGNMENT;
    let text_off: usize = text_va as usize;
    if memory_image.len() < text_off + FILE_ALIGNMENT as usize {
        return None;
    }
    let region: &[u8] = &memory_image[text_off..];
    let content_end: usize = section_content_end(region);
    if content_end == 0 {
        return None;
    }
    let text_raw: u32 = align_up(
        u32::try_from(content_end).ok()?.max(FILE_ALIGNMENT),
        FILE_ALIGNMENT,
    );
    let text_capacity: usize = text_raw as usize;
    let avail: usize = region.len().min(text_capacity);
    let mut text: Vec<u8> = vec![0u8; text_capacity];
    text[..avail].copy_from_slice(&region[..avail]);

    let (import_rva, import_size, iat_rva, iat_size): (u32, u32, u32, u32) =
        import_directories(&text, text_va).unwrap_or((0, 0, 0, 0));

    let text_vsize: u32 = align_up(text_raw, SECTION_ALIGNMENT);
    let size_of_image: u32 = text_va + text_vsize;

    let e_lfanew: u32 = 0x40;
    let opt_off: usize = e_lfanew as usize + 4 + COFF_HEADER_LEN;
    let sec_off: usize = opt_off + PE32_OPT_HEADER_SIZE as usize;
    let headers_len: usize = FILE_ALIGNMENT as usize;
    let mut out: Vec<u8> = vec![0u8; headers_len + text_capacity];

    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    out[e_lfanew as usize..e_lfanew as usize + 4].copy_from_slice(b"PE\x00\x00");

    let coff: usize = e_lfanew as usize + 4;
    put_u16(&mut out, coff, 0x014c);
    put_u16(&mut out, coff + 2, 1);
    put_u16(&mut out, coff + 16, PE32_OPT_HEADER_SIZE);
    put_u16(&mut out, coff + 18, 0x0103);

    put_u16(&mut out, opt_off, 0x010b);
    put_u32(&mut out, opt_off + 4, text_raw);
    put_u32(&mut out, opt_off + 16, entry_rva);
    put_u32(&mut out, opt_off + 20, text_va);
    put_u32(&mut out, opt_off + 24, text_va);
    put_u32(&mut out, opt_off + 28, UNPACKED_IMAGE_BASE as u32);
    put_u32(&mut out, opt_off + 32, SECTION_ALIGNMENT);
    put_u32(&mut out, opt_off + 36, FILE_ALIGNMENT);
    put_u16(&mut out, opt_off + 40, 4);
    put_u16(&mut out, opt_off + 48, 4);
    put_u32(&mut out, opt_off + 56, size_of_image);
    put_u32(&mut out, opt_off + 60, FILE_ALIGNMENT);
    put_u16(&mut out, opt_off + 68, WIN32_CUI_SUBSYSTEM);
    put_u32(&mut out, opt_off + 72, DEFAULT_STACK_RESERVE);
    put_u32(&mut out, opt_off + 76, DEFAULT_STACK_COMMIT);
    put_u32(&mut out, opt_off + 80, DEFAULT_HEAP_RESERVE);
    put_u32(&mut out, opt_off + 84, DEFAULT_HEAP_COMMIT);
    put_u32(&mut out, opt_off + 92, PE32_DATA_DIRECTORIES);
    put_u32(&mut out, opt_off + 96 + 8, import_rva);
    put_u32(&mut out, opt_off + 96 + 12, import_size);
    put_u32(&mut out, opt_off + 96 + 96, iat_rva);
    put_u32(&mut out, opt_off + 96 + 100, iat_size);

    out[sec_off..sec_off + 5].copy_from_slice(b".text");
    put_u32(&mut out, sec_off + 8, text_vsize);
    put_u32(&mut out, sec_off + 12, text_va);
    put_u32(&mut out, sec_off + 16, text_raw);
    put_u32(&mut out, sec_off + 20, FILE_ALIGNMENT);
    put_u32(&mut out, sec_off + 36, SCN_TEXT_CHARACTERISTICS);

    out[headers_len..headers_len + text_capacity].copy_from_slice(&text);
    Some(out)
}

const SCRATCH_GAP_THRESHOLD: usize = 0x100;

fn section_content_end(region: &[u8]) -> usize {
    let mut content_end: usize = 0;
    let mut run_start: Option<usize> = None;
    for (i, byte) in region.iter().enumerate() {
        if *byte != 0 {
            if let Some(start) = run_start {
                let gap: usize = i - start;
                if gap >= SCRATCH_GAP_THRESHOLD && content_end != 0 {
                    return content_end;
                }
            }
            run_start = None;
            content_end = i + 1;
        } else if run_start.is_none() {
            run_start = Some(i);
        }
    }
    content_end
}

fn import_directories(text: &[u8], text_va: u32) -> Option<(u32, u32, u32, u32)> {
    let stride: usize = IMPORT_DESCRIPTOR_SIZE as usize;
    let hi: u32 = text_va + text.len() as u32;
    let mut probe: usize = 0;
    while probe + stride <= text.len() {
        let oft: u32 = u32::from_le_bytes(text[probe..probe + 4].try_into().ok()?);
        let name: u32 = u32::from_le_bytes(text[probe + 12..probe + 16].try_into().ok()?);
        let iat: u32 = u32::from_le_bytes(text[probe + 16..probe + 20].try_into().ok()?);
        let in_text = |r: u32| -> bool { r >= text_va && r < hi };
        if oft != 0 && name != 0 && iat != 0 && in_text(oft) && in_text(name) && in_text(iat) {
            let mut count: usize = 0;
            let mut cur: usize = probe;
            while cur + stride <= text.len() && text[cur..cur + stride].iter().any(|b: &u8| *b != 0)
            {
                count += 1;
                cur += stride;
            }
            let import_rva: u32 = text_va + probe as u32;
            let import_size: u32 = ((count + 1) * stride) as u32;
            let iat_size: u32 = iat_thunk_bytes(text, text_va, iat);
            return Some((import_rva, import_size, iat, iat_size));
        }
        probe += 1;
    }
    None
}

fn iat_thunk_bytes(text: &[u8], text_va: u32, iat_rva: u32) -> u32 {
    let Some(start): Option<usize> = iat_rva.checked_sub(text_va).map(|v: u32| v as usize) else {
        return 0;
    };
    let mut count: usize = 0;
    let mut cur: usize = start;
    while cur + 4 <= text.len() {
        let thunk: u32 =
            u32::from_le_bytes([text[cur], text[cur + 1], text[cur + 2], text[cur + 3]]);
        count += 1;
        if thunk == 0 {
            break;
        }
        cur += 4;
    }
    (count * 4) as u32
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        return value;
    }
    let mask: u32 = alignment - 1;
    value.wrapping_add(mask) & !mask
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const HELLO_PACKED_K7: &[u8] =
        include_bytes!("../../../../corpus/native/packers/kkrunchy/hello.packed.kkrunchy.exe");
    const HELLO_ORIGINAL: &[u8] =
        include_bytes!("../../../../corpus/native/packers/kkrunchy/hello.exe");

    #[test]
    fn k7_emulated_unpack_reconstructs_oep_image_byte_exact() {
        let out: KkrunchyK7Output =
            unpack_kkrunchy_k7_emulated(HELLO_PACKED_K7).expect("k7 emulated unpack");
        assert_eq!(out.original_entry_rva, 0x1000, "recovered OEP RVA");
        assert_eq!(
            out.recovered_file_image.len(),
            HELLO_ORIGINAL.len(),
            "reconstructed file length must match the pre-pack original",
        );
        let matching: usize = out
            .recovered_file_image
            .iter()
            .zip(HELLO_ORIGINAL.iter())
            .filter(|(a, b): &(&u8, &u8)| a == b)
            .count();
        assert_eq!(
            matching,
            HELLO_ORIGINAL.len(),
            "k7 OEP reconstruction must be byte-exact vs the pre-pack original \
             (got {matching}/{} matching)",
            HELLO_ORIGINAL.len(),
        );
        assert!(
            out.recovered_imports
                .iter()
                .any(
                    |(d, fns): &(String, Vec<String>)| d.eq_ignore_ascii_case("kernel32.dll")
                        && fns.iter().any(|f: &String| f == "GetStdHandle")
                ),
            "import bootstrap must recover kernel32.dll/GetStdHandle from the staging descriptor",
        );
    }
}
