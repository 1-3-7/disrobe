#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal,
    clippy::option_if_let_else,
    clippy::needless_type_cast
)]

use crate::error::{Error, Result};
use crate::stub_emu::mem::MAX_MAP_BYTES;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const FILE_HEADER_OFFSET_E_LFANEW: usize = 0x3C;
const PE_SIGNATURE_LEN: usize = 4;
const COFF_HEADER_LEN: usize = 20;
const SECTION_HEADER_LEN: usize = 40;

const MAX_FILE_IMAGE_BYTES: usize = 256 * 1024 * 1024;
const PHASE2_MAX_IMAGE_RATIO: usize = 4096;

const OEP_IMAGE_BASE: u64 = 0x0040_0000;
const OEP_REGION_SIZE: u64 = 0x0001_0000;

const EMU_STACK_BASE: u64 = 0x0012_0000;
const EMU_STACK_SIZE: u64 = 0x0004_0000;

const SYNTH_IAT_BASE: u64 = 0x7000_0000;
const SYNTH_GETPROC: u64 = 0x7000_FFF0;
const SYNTH_LOADLIB: u64 = 0x7000_FFE0;

const STEP_CAP_KKRUNCHY: u64 = 8_000_000;

const EMU_LAZY_PAGE_BUDGET: u32 = 16_384;

#[derive(Debug, Clone)]
pub struct KkrunchyPhaseTwoOutput {
    pub oep_image_base: u64,
    pub recovered_memory_image: Vec<u8>,
    pub recovered_file_image: Vec<u8>,
    pub oep_estimate: Option<u64>,
    pub exit_reason: String,
    pub host_calls: Vec<String>,
}

const SYNTH_RESOLVED_FN_BASE: u64 = SYNTH_IAT_BASE + 0x4000;

#[derive(Debug)]
struct KkrunchyHost {
    calls: Vec<String>,
    halted: bool,
    loadlib_slot: Option<u64>,
    getproc_slot: Option<u64>,
    next_synth_fn: u64,
}

impl KkrunchyHost {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            halted: false,
            loadlib_slot: None,
            getproc_slot: None,
            next_synth_fn: SYNTH_RESOLVED_FN_BASE,
        }
    }
}

impl HostCall for KkrunchyHost {
    fn dispatch(&mut self, target: u64, regs: &mut Regs, _mem: &mut Memory) -> Result<bool> {
        let sp: u64 = regs.get(Reg::Rsp);
        match target {
            SYNTH_GETPROC | SYNTH_LOADLIB => {
                let pops: u64 = if target == SYNTH_GETPROC { 2 } else { 1 };
                let fn_addr: u64 = self.next_synth_fn;
                self.next_synth_fn = self.next_synth_fn.wrapping_add(0x10);
                regs.write_sized(Reg::Rax, fn_addr, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(pops * 4));
                Ok(true)
            }
            _ if target < 0x0001_0000 => {
                if self.loadlib_slot.is_none() {
                    self.loadlib_slot = Some(target);
                } else if self.getproc_slot != Some(target) && Some(target) != self.loadlib_slot {
                    self.getproc_slot.get_or_insert(target);
                }
                let is_getproc: bool = self.getproc_slot == Some(target);
                let pops: u64 = if is_getproc { 2 } else { 1 };
                self.calls.push(if is_getproc {
                    "GetProcAddress".to_owned()
                } else {
                    "LoadLibraryA".to_owned()
                });
                let ret_val: u64 = if is_getproc {
                    let v: u64 = self.next_synth_fn;
                    self.next_synth_fn = self.next_synth_fn.wrapping_add(0x10);
                    v
                } else {
                    SYNTH_IAT_BASE
                };
                regs.write_sized(Reg::Rax, ret_val, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(pops * 4));
                Ok(true)
            }
            _ => {
                self.calls.push(format!("unknown@0x{target:08x}"));
                self.halted = true;
                Ok(false)
            }
        }
    }
}

pub fn unpack_kkrunchy_phase2_emulated(packed: &[u8]) -> Result<KkrunchyPhaseTwoOutput> {
    let pe_layout: PeLayout = parse_pe_layout(packed)?;
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);

    let packed_base: u64 = u64::from(pe_layout.image_base);
    let packed_capacity: u64 = u64::from(pe_layout.size_of_image)
        .max(u64::from(pe_layout.last_section_end_va))
        .min(MAX_MAP_BYTES);
    cpu.mem.map(packed_base, packed_capacity, Perm::RWX)?;
    cpu.mem
        .write(packed_base, &packed[..packed.len().min(packed.len())])?;

    cpu.mem.map(OEP_IMAGE_BASE, OEP_REGION_SIZE, Perm::RWX)?;
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);

    cpu.mem.map(SYNTH_IAT_BASE, 0x0001_0000, Perm::RX)?;

    let mut host: KkrunchyHost = KkrunchyHost::new();

    cpu.regs.rip = packed_base + u64::from(pe_layout.entry_point_rva);
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

    let oep_low: u64 = OEP_IMAGE_BASE + u64::from(pe_layout.entry_point_rva.max(0x1000));
    let oep_high: u64 = OEP_IMAGE_BASE + OEP_REGION_SIZE;
    let exit: ExitReason = run_until_oep(&mut cpu, &mut host, oep_low, oep_high)?;
    let final_rip: u64 = cpu.regs.rip;

    let recovered_memory_image: Vec<u8> =
        cpu.mem.read_lossy(OEP_IMAGE_BASE, OEP_REGION_SIZE as usize);

    let oep_estimate: Option<u64> = match &exit {
        ExitReason::JumpedOutOfRange { to, .. } => Some(*to),
        _ => None,
    };

    let recovered_file_image: Vec<u8> = reconstruct_classic_pe(&recovered_memory_image, &pe_layout)
        .or_else(|| match memory_to_file_image(&recovered_memory_image) {
            Some(f) if !f.is_empty() && f.starts_with(b"MZ") => Some(f),
            _ => None,
        })
        .unwrap_or_else(|| recovered_memory_image.clone());

    Ok(KkrunchyPhaseTwoOutput {
        oep_image_base: OEP_IMAGE_BASE,
        recovered_memory_image,
        recovered_file_image,
        oep_estimate,
        exit_reason: format!("{exit:?} final_rip=0x{final_rip:08x}"),
        host_calls: host.calls,
    })
}

fn run_until_oep(
    cpu: &mut Cpu,
    host: &mut KkrunchyHost,
    oep_low: u64,
    oep_high: u64,
) -> Result<ExitReason> {
    let mut steps: u64 = 0;
    loop {
        if steps >= STEP_CAP_KKRUNCHY {
            return Ok(ExitReason::StepCap(steps));
        }
        steps += 1;
        let ip: u64 = cpu.regs.rip;
        if ip >= oep_low && ip < oep_high {
            return Ok(ExitReason::JumpedOutOfRange { from: ip, to: ip });
        }
        let exit: ExitReason = cpu.run(host, 1)?;
        if host.halted {
            return Ok(exit);
        }
        match exit {
            ExitReason::StepCap(_) => {}
            other => return Ok(other),
        }
    }
}

const PE32_OPT_HEADER_SIZE: u16 = 0xe0;
const PE32_DATA_DIRECTORIES: u32 = 16;
const SECTION_FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const DEFAULT_STACK_RESERVE: u32 = 0x0010_0000;
const DEFAULT_STACK_COMMIT: u32 = 0x0000_1000;
const DEFAULT_HEAP_RESERVE: u32 = 0x0010_0000;
const DEFAULT_HEAP_COMMIT: u32 = 0x0000_1000;
const WIN32_GUI_CONSOLE_SUBSYSTEM: u16 = 3;

fn reconstruct_classic_pe(mem_image: &[u8], _pe: &PeLayout) -> Option<Vec<u8>> {
    let text_va: u32 = 0x1000;
    let text_rva_off: usize = text_va as usize;
    if mem_image.len() < text_rva_off + SECTION_FILE_ALIGNMENT as usize {
        return None;
    }
    let region: &[u8] = &mem_image[text_rva_off..];
    let content_end: usize = region
        .iter()
        .rposition(|b: &u8| *b != 0)
        .map_or(0, |i: usize| i + 1);
    if content_end == 0 {
        return None;
    }
    let text_raw_size: u32 = align_up_u32(
        u32::try_from(content_end).ok()?.max(SECTION_FILE_ALIGNMENT),
        SECTION_FILE_ALIGNMENT,
    );
    let text_capacity: usize = text_raw_size as usize;
    let avail: usize = region.len().min(text_capacity);

    let mut text_rebuilt: Vec<u8> = vec![0u8; text_capacity];
    text_rebuilt[..avail].copy_from_slice(&region[..avail]);
    let import_dirs: Option<(u32, u32, u32, u32)> =
        rebuild_import_table(&mut text_rebuilt, mem_image, text_va);
    let (import_dir_rva, import_dir_size, iat_dir_rva, iat_dir_size): (u32, u32, u32, u32) =
        import_dirs
            .or_else(|| locate_import_directories(&text_rebuilt, text_va))
            .unwrap_or((0, 0, 0, 0));

    let text_virtual_size: u32 = align_up_u32(text_raw_size, SECTION_ALIGNMENT);
    let size_of_image: u32 = text_va + text_virtual_size;

    let e_lfanew: u32 = 0x40;
    let opt_off: usize = e_lfanew as usize + 4 + COFF_HEADER_LEN;
    let sec_off: usize = opt_off + PE32_OPT_HEADER_SIZE as usize;
    let headers_len: usize = SECTION_FILE_ALIGNMENT as usize;
    let mut out: Vec<u8> = vec![0u8; headers_len + text_capacity];

    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    let pe_sig: usize = e_lfanew as usize;
    out[pe_sig..pe_sig + 4].copy_from_slice(b"PE\x00\x00");
    let coff: usize = pe_sig + 4;
    out[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
    out[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    out[coff + 16..coff + 18].copy_from_slice(&PE32_OPT_HEADER_SIZE.to_le_bytes());
    out[coff + 18..coff + 20].copy_from_slice(&0x0103u16.to_le_bytes());

    put_u16(&mut out, opt_off, 0x010b);
    put_u32(&mut out, opt_off + 4, text_raw_size);
    put_u32(&mut out, opt_off + 16, text_va);
    put_u32(&mut out, opt_off + 20, text_va);
    put_u32(&mut out, opt_off + 24, SECTION_ALIGNMENT);
    put_u32(&mut out, opt_off + 28, OEP_IMAGE_BASE as u32);
    put_u32(&mut out, opt_off + 32, SECTION_ALIGNMENT);
    put_u32(&mut out, opt_off + 36, SECTION_FILE_ALIGNMENT);
    put_u16(&mut out, opt_off + 40, 4);
    put_u16(&mut out, opt_off + 48, 4);
    put_u32(&mut out, opt_off + 56, size_of_image);
    put_u32(&mut out, opt_off + 60, SECTION_FILE_ALIGNMENT);
    put_u16(&mut out, opt_off + 68, WIN32_GUI_CONSOLE_SUBSYSTEM);
    put_u32(&mut out, opt_off + 72, DEFAULT_STACK_RESERVE);
    put_u32(&mut out, opt_off + 76, DEFAULT_STACK_COMMIT);
    put_u32(&mut out, opt_off + 80, DEFAULT_HEAP_RESERVE);
    put_u32(&mut out, opt_off + 84, DEFAULT_HEAP_COMMIT);
    put_u32(&mut out, opt_off + 92, PE32_DATA_DIRECTORIES);

    put_u32(&mut out, opt_off + 96 + 8, import_dir_rva);
    put_u32(&mut out, opt_off + 96 + 12, import_dir_size);
    put_u32(&mut out, opt_off + 96 + 96, iat_dir_rva);
    put_u32(&mut out, opt_off + 96 + 100, iat_dir_size);

    out[sec_off..sec_off + 5].copy_from_slice(b".text");
    put_u32(&mut out, sec_off + 8, text_virtual_size);
    put_u32(&mut out, sec_off + 12, text_va);
    put_u32(&mut out, sec_off + 16, text_raw_size);
    put_u32(&mut out, sec_off + 20, SECTION_FILE_ALIGNMENT);
    put_u32(&mut out, sec_off + 36, 0xe000_0020);

    out[headers_len..headers_len + text_capacity].copy_from_slice(&text_rebuilt);
    Some(out)
}

fn rebuild_import_table(
    text: &mut [u8],
    mem_image: &[u8],
    text_va: u32,
) -> Option<(u32, u32, u32, u32)> {
    let (dll_name, functions, bootstrap_iat_rva): (Vec<u8>, Vec<Vec<u8>>, u32) =
        read_bootstrap_imports(mem_image)?;
    if functions.is_empty() {
        return None;
    }

    let desc_off: usize = find_descriptor(text, text_va, bootstrap_iat_rva)?;
    let oft_rva: u32 = u32::from_le_bytes(text[desc_off..desc_off + 4].try_into().ok()?);
    let name_rva: u32 = u32::from_le_bytes(text[desc_off + 12..desc_off + 16].try_into().ok()?);
    let iat_rva: u32 = u32::from_le_bytes(text[desc_off + 16..desc_off + 20].try_into().ok()?);

    let thunk_table_end: u32 = iat_rva + (functions.len() as u32 + 1) * 4;
    let mut name_cursor: u32 = thunk_table_end;
    let mut name_rvas: Vec<u32> = Vec::with_capacity(functions.len());
    for func in &functions {
        let off: usize = name_cursor.checked_sub(text_va)? as usize;
        if off + 2 + func.len() + 1 > text.len() {
            return None;
        }
        text[off] = 0;
        text[off + 1] = 0;
        write_cstr(text, off + 2, func)?;
        name_rvas.push(name_cursor);
        let advance: u32 = 2 + func.len() as u32 + 1;
        name_cursor += advance;
    }

    let dll_off: usize = name_rva.checked_sub(text_va)? as usize;
    write_cstr(text, dll_off, &dll_name)?;

    write_thunks(text, text_va, oft_rva, &name_rvas)?;
    write_thunks(text, text_va, iat_rva, &name_rvas)?;

    let import_dir_rva: u32 = text_va + desc_off as u32;
    let import_dir_size: u32 = (2 * IMPORT_DESCRIPTOR_SIZE) as u32;
    let iat_dir_size: u32 = ((name_rvas.len() + 1) * 4) as u32;
    Some((import_dir_rva, import_dir_size, iat_rva, iat_dir_size))
}

fn find_descriptor(text: &[u8], text_va: u32, iat_rva: u32) -> Option<usize> {
    let stride: usize = IMPORT_DESCRIPTOR_SIZE;
    let hi: u32 = text_va + text.len() as u32;
    let mut probe: usize = 0;
    while probe + stride <= text.len() {
        let oft: u32 = u32::from_le_bytes(text[probe..probe + 4].try_into().ok()?);
        let name: u32 = u32::from_le_bytes(text[probe + 12..probe + 16].try_into().ok()?);
        let iat: u32 = u32::from_le_bytes(text[probe + 16..probe + 20].try_into().ok()?);
        let in_range = |r: u32| -> bool { r >= text_va && r < hi };
        if iat == iat_rva && in_range(oft) && in_range(name) && oft != name {
            return Some(probe);
        }
        probe += 1;
    }
    None
}

fn read_bootstrap_imports(mem_image: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>, u32)> {
    let dll_marker: &[u8] = b".dll";
    let mut scan: usize = 0;
    while scan + dll_marker.len() <= mem_image.len() {
        if mem_image[scan..scan + dll_marker.len()].eq_ignore_ascii_case(dll_marker) {
            let name_end: usize = scan + dll_marker.len();
            let mut name_start: usize = scan;
            while name_start > 0 {
                let c: u8 = mem_image[name_start - 1];
                if c == 0 || !c.is_ascii_graphic() {
                    break;
                }
                name_start -= 1;
            }
            let dll: Vec<u8> = mem_image[name_start..name_end].to_vec();
            if dll.len() < 5 || mem_image.get(name_end) != Some(&0) || name_start < 4 {
                scan += 1;
                continue;
            }
            let iat_va: u32 = u32::from_le_bytes([
                mem_image[name_start - 4],
                mem_image[name_start - 3],
                mem_image[name_start - 2],
                mem_image[name_start - 1],
            ]);
            let iat_rva: u32 = iat_va.wrapping_sub(OEP_IMAGE_BASE as u32);
            let mut functions: Vec<Vec<u8>> = Vec::new();
            let mut cur: usize = name_end + 1;
            while cur < mem_image.len() {
                if mem_image[cur] == 0 {
                    break;
                }
                let start: usize = cur;
                while cur < mem_image.len() && mem_image[cur] != 0 {
                    cur += 1;
                }
                let f: &[u8] = &mem_image[start..cur];
                if f.iter().all(|b: &u8| b.is_ascii_graphic()) {
                    functions.push(f.to_vec());
                } else {
                    break;
                }
                cur += 1;
            }
            if !functions.is_empty() {
                return Some((dll, functions, iat_rva));
            }
        }
        scan += 1;
    }
    None
}

fn write_thunks(text: &mut [u8], text_va: u32, table_rva: u32, name_rvas: &[u32]) -> Option<()> {
    let base: usize = table_rva.checked_sub(text_va)? as usize;
    for (i, rva) in name_rvas.iter().enumerate() {
        let off: usize = base + i * 4;
        if off + 4 > text.len() {
            return None;
        }
        text[off..off + 4].copy_from_slice(&rva.to_le_bytes());
    }
    let term: usize = base + name_rvas.len() * 4;
    if term + 4 > text.len() {
        return None;
    }
    text[term..term + 4].copy_from_slice(&0u32.to_le_bytes());
    Some(())
}

fn write_cstr(text: &mut [u8], off: usize, s: &[u8]) -> Option<()> {
    if off + s.len() + 1 > text.len() {
        return None;
    }
    text[off..off + s.len()].copy_from_slice(s);
    text[off + s.len()] = 0;
    Some(())
}

fn locate_import_directories(text: &[u8], text_va: u32) -> Option<(u32, u32, u32, u32)> {
    let stride: usize = IMPORT_DESCRIPTOR_SIZE;
    let mut probe: usize = 0;
    while probe + stride <= text.len() {
        let name_rva: u32 = u32::from_le_bytes(text[probe + 12..probe + 16].try_into().ok()?);
        let first_thunk: u32 = u32::from_le_bytes(text[probe + 16..probe + 20].try_into().ok()?);
        if name_rva >= text_va
            && first_thunk >= text_va
            && dll_name_at(text, text_va, name_rva).is_some()
        {
            let mut descriptors: usize = 0;
            let mut cur: usize = probe;
            loop {
                if cur + stride > text.len() {
                    break;
                }
                let all_zero: bool = text[cur..cur + stride].iter().all(|b: &u8| *b == 0);
                if all_zero {
                    break;
                }
                descriptors += 1;
                cur += stride;
            }
            let import_dir_rva: u32 = text_va + probe as u32;
            let import_dir_size: u32 = ((descriptors + 1) * stride) as u32;
            let iat_dir_rva: u32 = first_thunk;
            let iat_dir_size: u32 = iat_thunk_size(text, text_va, first_thunk);
            return Some((import_dir_rva, import_dir_size, iat_dir_rva, iat_dir_size));
        }
        probe += 1;
    }
    None
}

fn dll_name_at(text: &[u8], text_va: u32, name_rva: u32) -> Option<()> {
    let off: usize = name_rva.checked_sub(text_va)? as usize;
    if off >= text.len() {
        return None;
    }
    let end: usize = text[off..]
        .iter()
        .position(|b: &u8| *b == 0)
        .map(|p: usize| off + p)?;
    let name: &[u8] = &text[off..end];
    if name.len() < 4 || !name.iter().all(|b: &u8| b.is_ascii_graphic()) {
        return None;
    }
    let lower: Vec<u8> = name.iter().map(|b: &u8| b.to_ascii_lowercase()).collect();
    if lower.ends_with(b".dll") {
        Some(())
    } else {
        None
    }
}

fn iat_thunk_size(text: &[u8], text_va: u32, first_thunk: u32) -> u32 {
    let Some(start): Option<usize> = first_thunk.checked_sub(text_va).map(|v: u32| v as usize)
    else {
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

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn memory_to_file_image(mem_image: &[u8]) -> Option<Vec<u8>> {
    if mem_image.len() < 0x100 || !mem_image.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew: usize = u32::from_le_bytes(mem_image[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > mem_image.len() || &mem_image[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return None;
    }
    let coff: usize = e_lfanew + 4;
    let n_sec: u16 = u16::from_le_bytes(mem_image[coff + 2..coff + 4].try_into().ok()?);
    let opt_hdr_size: u16 = u16::from_le_bytes(mem_image[coff + 16..coff + 18].try_into().ok()?);
    let opt: usize = coff + 20;
    let file_alignment: u32 =
        u32::from_le_bytes(mem_image[opt + 36..opt + 40].try_into().ok()?).max(0x200);
    let sec_off: usize = opt + opt_hdr_size as usize;
    if sec_off + SECTION_HEADER_LEN * n_sec as usize > mem_image.len() {
        return None;
    }
    let headers_raw: u32 =
        u32::from_le_bytes(mem_image[opt + 60..opt + 64].try_into().ok()?).max(file_alignment);
    let mut sections: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(n_sec as usize);
    for i in 0..n_sec as usize {
        let s: usize = sec_off + i * SECTION_HEADER_LEN;
        let vs: u32 = u32::from_le_bytes(mem_image[s + 8..s + 12].try_into().ok()?);
        let va: u32 = u32::from_le_bytes(mem_image[s + 12..s + 16].try_into().ok()?);
        let raw_size: u32 = u32::from_le_bytes(mem_image[s + 16..s + 20].try_into().ok()?);
        let raw_ptr: u32 = u32::from_le_bytes(mem_image[s + 20..s + 24].try_into().ok()?);
        let effective_raw: u32 = if raw_size > 0 {
            raw_size
        } else {
            align_up_u32(vs, file_alignment)
        };
        sections.push((va, vs, effective_raw, raw_ptr));
    }
    let total_usize: usize = sections
        .iter()
        .map(|s: &(u32, u32, u32, u32)| (s.2 as usize).saturating_add(s.3 as usize))
        .max()
        .unwrap_or(headers_raw as usize)
        .max(headers_raw as usize);
    let image_ceiling: usize =
        MAX_FILE_IMAGE_BYTES.min(mem_image.len().saturating_mul(PHASE2_MAX_IMAGE_RATIO));
    if total_usize > image_ceiling {
        return None;
    }
    let mut out: Vec<u8> = vec![0u8; total_usize];
    let header_copy: usize = (headers_raw as usize).min(mem_image.len());
    out[..header_copy].copy_from_slice(&mem_image[..header_copy]);
    for sec_tuple in &sections {
        let (va, vs, eff_raw, raw_ptr): (u32, u32, u32, u32) = *sec_tuple;
        let src_lo: usize = va as usize;
        let src_hi: usize = src_lo
            .saturating_add(vs.max(eff_raw) as usize)
            .min(mem_image.len());
        let dst_lo: usize = raw_ptr as usize;
        let copy_len: usize = (src_hi.saturating_sub(src_lo)).min(eff_raw as usize);
        if dst_lo + copy_len <= out.len() && src_lo + copy_len <= mem_image.len() {
            out[dst_lo..dst_lo + copy_len].copy_from_slice(&mem_image[src_lo..src_lo + copy_len]);
        }
    }
    Some(out)
}

fn align_up_u32(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        return value;
    }
    let mask: u32 = alignment - 1;
    value.wrapping_add(mask) & !mask
}

#[derive(Debug, Clone)]
struct PeLayout {
    image_base: u32,
    entry_point_rva: u32,
    size_of_image: u32,
    last_section_end_va: u32,
}

fn parse_pe_layout(bytes: &[u8]) -> Result<PeLayout> {
    if bytes.len() < FILE_HEADER_OFFSET_E_LFANEW + 4 || !bytes.starts_with(b"MZ") {
        return Err(Error::UnknownFormat);
    }
    let e_lfanew: usize = read_u32_le(bytes, FILE_HEADER_OFFSET_E_LFANEW)? as usize;
    if e_lfanew + 4 > bytes.len() || &bytes[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return Err(Error::UnknownFormat);
    }
    let coff_off: usize = e_lfanew + PE_SIGNATURE_LEN;
    let num_sections: u16 = read_u16_le(bytes, coff_off + 2)?;
    let opt_hdr_size: u16 = read_u16_le(bytes, coff_off + 16)?;
    let opt_off: usize = coff_off + COFF_HEADER_LEN;
    let image_base: u32 = read_u32_le(bytes, opt_off + 28)?;
    let entry_point_rva: u32 = read_u32_le(bytes, opt_off + 16)?;
    let size_of_image: u32 = read_u32_le(bytes, opt_off + 56)?;
    let size_of_headers: u32 = read_u32_le(bytes, opt_off + 60)?;
    let sec_off: usize = opt_off + opt_hdr_size as usize;
    let mut last_end_va: u32 = size_of_headers;
    for i in 0..num_sections as usize {
        let s: usize = sec_off + i * SECTION_HEADER_LEN;
        if s + SECTION_HEADER_LEN > bytes.len() {
            break;
        }
        let virtual_size: u32 = read_u32_le(bytes, s + 8)?;
        let virtual_address: u32 = read_u32_le(bytes, s + 12)?;
        let size_of_raw_data: u32 = read_u32_le(bytes, s + 16)?;
        let end_va: u32 = virtual_address.saturating_add(virtual_size.max(size_of_raw_data));
        if end_va > last_end_va {
            last_end_va = end_va;
        }
    }
    Ok(PeLayout {
        image_base,
        entry_point_rva,
        size_of_image,
        last_section_end_va: last_end_va,
    })
}

fn read_u16_le(bytes: &[u8], off: usize) -> Result<u16> {
    if off + 2 > bytes.len() {
        return Err(Error::Truncated {
            needed: off + 2,
            had: bytes.len(),
        });
    }
    Ok(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32> {
    if off + 4 > bytes.len() {
        return Err(Error::Truncated {
            needed: off + 4,
            had: bytes.len(),
        });
    }
    Ok(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_layout_rejects_non_pe() {
        let r: Result<PeLayout> = parse_pe_layout(b"not a pe");
        assert!(r.is_err());
    }

    #[test]
    fn memory_to_file_image_rejects_non_mz() {
        let buf: Vec<u8> = vec![0u8; 0x200];
        assert!(memory_to_file_image(&buf).is_none());
    }
}
