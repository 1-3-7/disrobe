#![allow(
    clippy::doc_markdown,
    clippy::no_effect_underscore_binding,
    clippy::useless_let_if_seq,
    clippy::needless_pass_by_value,
    clippy::option_if_let_else,
    clippy::redundant_else,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::missing_errors_doc,
    clippy::trivially_copy_pass_by_ref,
    clippy::needless_type_cast,
    clippy::no_effect,
    clippy::needless_collect,
    clippy::manual_let_else,
    clippy::redundant_clone,
    clippy::useless_conversion,
    clippy::missing_panics_doc,
    clippy::missing_const_for_fn,
    clippy::comparison_chain,
    clippy::if_not_else,
    clippy::manual_range_contains,
    clippy::unreadable_literal,
    clippy::ptr_arg
)]

use disrobe_bytes::align_up_u32;

use crate::error::{Error, Result};
use crate::stub_emu::mem::MAX_MAP_BYTES;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const FILE_HEADER_OFFSET_E_LFANEW: usize = 0x3C;
const PE_SIGNATURE_LEN: usize = 4;
const COFF_HEADER_LEN: usize = 20;
const SECTION_HEADER_LEN: usize = 40;

const MAX_FILE_IMAGE_BYTES: usize = 256 * 1024 * 1024;

const PHASE2_MAX_IMAGE_RATIO: usize = 1024;

const EMU_HEAP_BASE: u64 = 0x2000_0000;
const EMU_HEAP_SIZE: u64 = 0x0800_0000;
const EMU_HEAP_ZERO_PAD: u64 = 0x0010_0000;
const EMU_STACK_BASE: u64 = 0x0080_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;

const SYNTH_IAT_BASE: u64 = 0xFE00_0000;
const STEP_CAP_DEFAULT: u64 = 100_000_000;

const EMU_LAZY_PAGE_BUDGET: u32 = 16_384;

#[derive(Debug, Clone)]
pub struct PhaseTwoEmulatedOutput {
    pub image_base: u64,
    pub size_of_image: u32,
    pub recovered_image: Vec<u8>,
    pub recovered_memory_image: Vec<u8>,
    pub pre_resolution_image: Vec<u8>,
    pub heap_snapshot: Vec<u8>,
    pub heap_base: u64,
    pub heap_used: u64,
    pub exit_reason: String,
    pub host_calls: Vec<String>,
    pub steps_executed: u64,
    pub oep_estimate: Option<u64>,
}

const SYNTH_MODULE_HANDLE: u64 = 0x7C80_0000;
const SYNTH_PROCESS_HEAP: u64 = 0x00A0_0000;

#[derive(Debug)]
struct PetiteHost {
    heap_brk: u64,
    heap_end: u64,
    calls: Vec<String>,
    halted: bool,
    iat_map: std::collections::BTreeMap<u64, &'static str>,
    snapshot_on_first_iat_resolution: bool,
    snapshot_taken_at: Option<u64>,
    image_base: u64,
    image_capacity: u64,
    image_snapshot: Option<Vec<u8>>,
    env: crate::stub_emu::SyntheticWindows,
    last_error: u32,
}

impl PetiteHost {
    fn new(
        heap_base: u64,
        heap_size: u64,
        image_base: u64,
        image_capacity: u64,
        env: crate::stub_emu::SyntheticWindows,
    ) -> Self {
        Self {
            heap_brk: heap_base,
            heap_end: heap_base.saturating_add(heap_size),
            calls: Vec::new(),
            halted: false,
            iat_map: std::collections::BTreeMap::new(),
            snapshot_on_first_iat_resolution: true,
            snapshot_taken_at: None,
            image_base,
            image_capacity,
            image_snapshot: None,
            env,
            last_error: 0,
        }
    }

    fn capture_pre_resolution_snapshot(&mut self, rip: u64, mem: &Memory) {
        if self.snapshot_taken_at.is_none() && self.snapshot_on_first_iat_resolution {
            self.snapshot_taken_at = Some(rip);
            self.image_snapshot =
                Some(mem.read_lossy(self.image_base, self.image_capacity as usize));
        }
    }

    fn heap_alloc(&mut self, mem: &mut Memory, size: u64) -> Result<u64> {
        let aligned: u64 = ((size + 0xFFF) & !0xFFFu64).max(0x1000);
        let alloc_at: u64 = (self.heap_brk + 0xFFF) & !0xFFFu64;
        let next_brk: u64 = alloc_at.saturating_add(aligned);
        if next_brk > self.heap_end {
            return Ok(0);
        }
        self.heap_brk = next_brk;
        let pad_lo: u64 = alloc_at.saturating_sub(EMU_HEAP_ZERO_PAD);
        mem.map(pad_lo, EMU_HEAP_ZERO_PAD, Perm::RW)?;
        mem.map(alloc_at, aligned, Perm::RWX)?;
        mem.map(next_brk, EMU_HEAP_ZERO_PAD, Perm::RW)?;
        Ok(alloc_at)
    }
}

impl HostCall for PetiteHost {
    fn dispatch(&mut self, target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        let symbol: &'static str = match self
            .iat_map
            .get(&target)
            .copied()
            .or_else(|| self.env.symbol_for(target))
        {
            Some(s) => s,
            None => {
                self.calls.push(format!("unknown@0x{target:016x}"));
                regs.write_sized(Reg::Rax, 0, 32);
                return Ok(true);
            }
        };
        self.calls.push(symbol.to_owned());
        let sp: u64 = regs.get(Reg::Rsp);
        let read_arg = |i: u32| -> Result<u32> { mem.read_u32(sp.wrapping_add(u64::from(i) * 4)) };
        let ret = |regs: &mut Regs, value: u64, argc: u64| -> Result<bool> {
            regs.write_sized(Reg::Rax, value, 32);
            regs.set(Reg::Rsp, sp.wrapping_add(argc * 4));
            Ok(true)
        };
        match symbol {
            "VirtualAlloc" => {
                let size: u64 = u64::from(read_arg(1)?);
                let addr: u64 = self.heap_alloc(mem, size)?;
                ret(regs, addr, 4)
            }
            "GlobalAlloc" | "LocalAlloc" => {
                let size: u64 = u64::from(read_arg(1)?);
                let addr: u64 = self.heap_alloc(mem, size)?;
                ret(regs, addr, 2)
            }
            "HeapAlloc" => {
                let size: u64 = u64::from(read_arg(2)?);
                let addr: u64 = self.heap_alloc(mem, size)?;
                ret(regs, addr, 3)
            }
            "GlobalReAlloc" | "HeapReAlloc" => {
                let (old_ptr, new_size, argc): (u64, u64, u64) = if symbol == "HeapReAlloc" {
                    (u64::from(read_arg(2)?), u64::from(read_arg(3)?), 4)
                } else {
                    (u64::from(read_arg(0)?), u64::from(read_arg(1)?), 3)
                };
                let addr: u64 = self.heap_alloc(mem, new_size)?;
                if addr != 0 && old_ptr != 0 {
                    let prior: Vec<u8> = mem.read_lossy(old_ptr, new_size as usize);
                    mem.write_unchecked(addr, &prior);
                }
                ret(regs, addr, argc)
            }
            "HeapCreate" => ret(regs, SYNTH_PROCESS_HEAP, 3),
            "GetProcessHeap" => ret(regs, SYNTH_PROCESS_HEAP, 0),
            "VirtualFree" | "GlobalFree" | "LocalFree" | "HeapFree" | "FreeLibrary"
            | "CloseHandle" => {
                let argc: u64 = match symbol {
                    "VirtualFree" => 3,
                    "HeapFree" => 3,
                    _ => 1,
                };
                ret(regs, 1, argc)
            }
            "VirtualProtect" => ret(regs, 1, 4),
            "VirtualQuery" => ret(regs, 0, 3),
            "GetModuleHandleA" | "GetModuleHandleW" => {
                self.capture_pre_resolution_snapshot(regs.rip, mem);
                ret(regs, SYNTH_MODULE_HANDLE, 1)
            }
            "LoadLibraryA" | "LoadLibraryW" => {
                self.capture_pre_resolution_snapshot(regs.rip, mem);
                ret(regs, SYNTH_MODULE_HANDLE, 1)
            }
            "GetProcAddress" => {
                self.capture_pre_resolution_snapshot(regs.rip, mem);
                let name_ptr: u64 = u64::from(read_arg(1)?);
                let resolved: u64 = if name_ptr <= 0xFFFF {
                    SYNTH_IAT_BASE + 0xFFF0
                } else {
                    self.env
                        .resolve_export_by_name_ptr(mem, name_ptr)
                        .unwrap_or(SYNTH_IAT_BASE + 0xFFF0)
                };
                ret(regs, resolved, 2)
            }
            "GetLastError" => ret(regs, u64::from(self.last_error), 0),
            "SetLastError" => {
                self.last_error = read_arg(0)?;
                ret(regs, 0, 1)
            }
            "GetCommandLineA" | "GetCommandLineW" => ret(regs, 0, 0),
            "IsBadReadPtr" => ret(regs, 0, 2),
            "Sleep" => ret(regs, 0, 1),
            "WriteFile" => ret(regs, 1, 5),
            "CreateFileA" | "CreateFileW" => ret(regs, 0xFFFF_FFFF, 7),
            "ExitProcess" => {
                self.halted = true;
                Ok(false)
            }
            "NtWriteFile" | "WaitOnAddress" | "MessageBoxA" | "wsprintfA" => {
                regs.write_sized(Reg::Rax, 0, 32);
                Ok(true)
            }
            _ => {
                regs.write_sized(Reg::Rax, 0, 32);
                Ok(true)
            }
        }
    }
}

pub fn unpack_petite_phase2_emulated(packed: &[u8]) -> Result<PhaseTwoEmulatedOutput> {
    let pe_layout: PeLayout = parse_pe_layout(packed)?;
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);

    let image_base: u64 = u64::from(pe_layout.image_base);
    let image_capacity: u64 = u64::from(pe_layout.size_of_image)
        .max(u64::from(pe_layout.last_section_end_va))
        .min(MAX_MAP_BYTES);
    cpu.mem.map(image_base, image_capacity, Perm::RWX)?;

    cpu.mem.write(
        image_base,
        &packed[..pe_layout.headers_raw_end.min(packed.len())],
    )?;

    for sec in &pe_layout.sections {
        let dst: u64 = image_base + u64::from(sec.virtual_address);
        let src: usize = sec.pointer_to_raw_data as usize;
        let raw: usize = sec.size_of_raw_data as usize;
        if src.saturating_add(raw) > packed.len() {
            continue;
        }
        cpu.mem.write_unchecked(dst, &packed[src..src + raw]);
    }

    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);

    let env: crate::stub_emu::SyntheticWindows =
        crate::stub_emu::install_synthetic_windows(&mut cpu)?;

    let mut host: PetiteHost = PetiteHost::new(
        EMU_HEAP_BASE,
        EMU_HEAP_SIZE,
        image_base,
        image_capacity,
        env.clone(),
    );
    cpu.mem.map(SYNTH_IAT_BASE, 0x0001_0000, Perm::RX)?;

    rewrite_iat(packed, &pe_layout, &mut cpu, &mut host, &env)?;

    cpu.regs.rip = u64::from(pe_layout.entry_point_rva) + image_base;
    cpu.regs
        .set(Reg::Rsp, EMU_STACK_BASE + EMU_STACK_SIZE - 0x100);
    cpu.regs.write_sized(Reg::Rax, 0, 32);
    cpu.regs.write_sized(Reg::Rbx, 0, 32);
    cpu.regs.write_sized(Reg::Rcx, 0, 32);
    cpu.regs.write_sized(Reg::Rdx, 0, 32);
    cpu.regs.write_sized(Reg::Rsi, 0, 32);
    cpu.regs.write_sized(Reg::Rdi, 0, 32);
    cpu.regs.write_sized(Reg::Rbp, 0, 32);

    let exit: ExitReason = cpu.run(&mut host, STEP_CAP_DEFAULT)?;
    let final_rip: u64 = cpu.regs.rip;

    let recovered_size: usize = (pe_layout.size_of_image.max(pe_layout.last_section_end_va)
        as usize)
        .min(MAX_MAP_BYTES as usize);
    let pre_resolution_image: Vec<u8> = match host.image_snapshot.take() {
        Some(mut snap) => {
            snap.resize(recovered_size, 0);
            snap
        }
        None => Vec::new(),
    };
    let mut post_emu_image: Vec<u8> = cpu.mem.read_lossy(image_base, recovered_size);
    restore_preserved_pe_headers(&mut post_emu_image, packed, &pe_layout);
    restore_iat_to_hint_name_rvas(&mut post_emu_image);
    let recovered_memory_image: Vec<u8> = post_emu_image.clone();
    let recovered_image: Vec<u8> = post_emu_image;

    let oep_estimate: Option<u64> = match &exit {
        ExitReason::JumpedOutOfRange { to, .. } => Some(*to),
        _ => None,
    };

    let heap_used: u64 = host.heap_brk.saturating_sub(EMU_HEAP_BASE);
    let heap_snapshot: Vec<u8> = if heap_used > 0 {
        cpu.mem.read_lossy(EMU_HEAP_BASE, heap_used as usize)
    } else {
        Vec::new()
    };

    let file_image: Vec<u8> = match memory_to_file_image(&recovered_image) {
        Some(f) if !f.is_empty() && f.starts_with(b"MZ") => f,
        _ => recovered_image.clone(),
    };

    Ok(PhaseTwoEmulatedOutput {
        image_base,
        size_of_image: pe_layout.size_of_image,
        recovered_image: file_image,
        recovered_memory_image,
        pre_resolution_image,
        heap_snapshot,
        heap_base: EMU_HEAP_BASE,
        heap_used,
        exit_reason: format!("{exit:?} final_rip=0x{final_rip:016x}"),
        host_calls: host.calls,
        steps_executed: 0,
        oep_estimate,
    })
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

fn restore_preserved_pe_headers(mem_image: &mut [u8], packed: &[u8], pe: &PeLayout) {
    if !packed.starts_with(b"MZ") {
        return;
    }
    if mem_image.starts_with(b"MZ") {
        return;
    }
    let header_len: usize = pe.headers_raw_end.min(packed.len()).min(mem_image.len());
    if header_len < 2 {
        return;
    }
    mem_image[..header_len].copy_from_slice(&packed[..header_len]);
}

fn restore_iat_to_hint_name_rvas(mem_image: &mut [u8]) {
    if mem_image.len() < 0x100 || !mem_image.starts_with(b"MZ") {
        return;
    }
    let Ok(e_lfanew_b): std::result::Result<[u8; 4], _> = mem_image[0x3c..0x40].try_into() else {
        return;
    };
    let e_lfanew: usize = u32::from_le_bytes(e_lfanew_b) as usize;
    if e_lfanew + 24 > mem_image.len() || &mem_image[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return;
    }
    let coff: usize = e_lfanew + 4;
    let opt: usize = coff + 20;
    if opt + 96 + 16 > mem_image.len() {
        return;
    }
    let Ok(imp_rva_b): std::result::Result<[u8; 4], _> =
        mem_image[opt + 96 + 8..opt + 96 + 12].try_into()
    else {
        return;
    };
    let imp_rva: u32 = u32::from_le_bytes(imp_rva_b);
    if imp_rva == 0 {
        return;
    }
    let imp_off: usize = imp_rva as usize;
    if imp_off + 20 > mem_image.len() {
        return;
    }
    let mut i: usize = 0;
    loop {
        let d: usize = imp_off + i * 20;
        if d + 20 > mem_image.len() {
            break;
        }
        let oft: u32 = u32::from_le_bytes(mem_image[d..d + 4].try_into().unwrap_or([0; 4]));
        let name: u32 = u32::from_le_bytes(mem_image[d + 12..d + 16].try_into().unwrap_or([0; 4]));
        let ft: u32 = u32::from_le_bytes(mem_image[d + 16..d + 20].try_into().unwrap_or([0; 4]));
        if oft == 0 && name == 0 && ft == 0 {
            break;
        }
        if oft != 0 && ft != 0 {
            let mut t: usize = 0;
            loop {
                let oft_off: usize = oft as usize + t * 4;
                let ft_off: usize = ft as usize + t * 4;
                if oft_off + 4 > mem_image.len() || ft_off + 4 > mem_image.len() {
                    break;
                }
                let oft_val: u32 = u32::from_le_bytes(
                    mem_image[oft_off..oft_off + 4].try_into().unwrap_or([0; 4]),
                );
                if oft_val == 0 {
                    let _ = (0u32).to_le_bytes();
                    mem_image[ft_off..ft_off + 4].copy_from_slice(&0u32.to_le_bytes());
                    break;
                }
                mem_image[ft_off..ft_off + 4].copy_from_slice(&oft_val.to_le_bytes());
                t += 1;
                if t > 0x1000 {
                    break;
                }
            }
        }
        i += 1;
        if i > 0x100 {
            break;
        }
    }
}

fn rewrite_iat(
    packed: &[u8],
    pe: &PeLayout,
    cpu: &mut Cpu,
    host: &mut PetiteHost,
    env: &crate::stub_emu::SyntheticWindows,
) -> Result<()> {
    let imp_rva: u32 = pe.import_dir_rva;
    if imp_rva == 0 {
        return Ok(());
    }
    let mut idx: u32 = 0;
    loop {
        let desc_rva: u32 = imp_rva + idx * 20;
        let desc_off: usize = match rva_to_file_off(pe, desc_rva) {
            Some(o) => o,
            None => break,
        };
        if desc_off + 20 > packed.len() {
            break;
        }
        let oft_rva: u32 = read_u32_le(packed, desc_off)?;
        let first_thunk_rva: u32 = read_u32_le(packed, desc_off + 16)?;
        let name_rva: u32 = read_u32_le(packed, desc_off + 12)?;
        if oft_rva == 0 && first_thunk_rva == 0 && name_rva == 0 {
            break;
        }
        let dll_name: String = match rva_to_file_off(pe, name_rva) {
            Some(off) => read_cstr(packed, off, 64).unwrap_or_default(),
            None => String::new(),
        };
        let thunk_table_rva: u32 = if oft_rva != 0 {
            oft_rva
        } else {
            first_thunk_rva
        };
        let mut t: u32 = 0;
        loop {
            let thunk_rva: u32 = thunk_table_rva + t * 4;
            let thunk_off: usize = match rva_to_file_off(pe, thunk_rva) {
                Some(o) => o,
                None => break,
            };
            if thunk_off + 4 > packed.len() {
                break;
            }
            let thunk: u32 = read_u32_le(packed, thunk_off)?;
            if thunk == 0 {
                break;
            }
            if thunk & 0x8000_0000 != 0 {
                t += 1;
                continue;
            }
            let func_off: usize = match rva_to_file_off(pe, thunk) {
                Some(o) => o,
                None => {
                    t += 1;
                    continue;
                }
            };
            let func_name: String = read_cstr(packed, func_off + 2, 96).unwrap_or_default();
            let iat_thunk_rva: u32 = first_thunk_rva + t * 4;
            let iat_addr: u64 = u64::from(pe.image_base) + u64::from(iat_thunk_rva);
            let resolved: u64 = match env.export_addr(&func_name) {
                Some(stub) => stub,
                None => {
                    let synth: u64 = pick_synth_addr(&func_name);
                    host.iat_map
                        .insert(synth, classify_iat(&dll_name, &func_name));
                    synth
                }
            };
            cpu.mem.write_u32(iat_addr, resolved as u32)?;
            t += 1;
        }
        idx += 1;
        if idx > 64 {
            break;
        }
    }
    Ok(())
}

fn pick_synth_addr(func: &str) -> u64 {
    let h: u64 = simple_hash(func);
    SYNTH_IAT_BASE + 0x2000 + (h & 0x0F_FFFF)
}

fn simple_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn classify_iat(_dll: &str, func: &str) -> &'static str {
    match func {
        "VirtualAlloc" => "VirtualAlloc",
        "VirtualFree" => "VirtualFree",
        "VirtualProtect" => "VirtualProtect",
        "GetModuleHandleA" => "GetModuleHandleA",
        "LoadLibraryA" => "LoadLibraryA",
        "GetProcAddress" => "GetProcAddress",
        "ExitProcess" => "ExitProcess",
        "NtWriteFile" => "NtWriteFile",
        "WaitOnAddress" => "WaitOnAddress",
        "MessageBoxA" => "MessageBoxA",
        "wsprintfA" => "wsprintfA",
        _ => "unknown",
    }
}

#[derive(Debug, Clone)]
struct PeLayout {
    image_base: u32,
    entry_point_rva: u32,
    size_of_image: u32,
    headers_raw_end: usize,
    import_dir_rva: u32,
    sections: Vec<SectionRecord>,
    last_section_end_va: u32,
}

#[derive(Debug, Clone, Copy)]
struct SectionRecord {
    virtual_address: u32,
    virtual_size: u32,
    pointer_to_raw_data: u32,
    size_of_raw_data: u32,
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
    let import_dir_rva: u32 = read_u32_le(bytes, opt_off + 96 + 8)?;
    let sec_off: usize = opt_off + opt_hdr_size as usize;
    let mut sections: Vec<SectionRecord> = Vec::with_capacity(num_sections as usize);
    let mut last_end_va: u32 = size_of_headers;
    for i in 0..num_sections as usize {
        let s: usize = sec_off + i * SECTION_HEADER_LEN;
        if s + SECTION_HEADER_LEN > bytes.len() {
            break;
        }
        let virtual_size: u32 = read_u32_le(bytes, s + 8)?;
        let virtual_address: u32 = read_u32_le(bytes, s + 12)?;
        let size_of_raw_data: u32 = read_u32_le(bytes, s + 16)?;
        let pointer_to_raw_data: u32 = read_u32_le(bytes, s + 20)?;
        let end_va: u32 = virtual_address.saturating_add(virtual_size.max(size_of_raw_data));
        if end_va > last_end_va {
            last_end_va = end_va;
        }
        sections.push(SectionRecord {
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
        });
    }
    Ok(PeLayout {
        image_base,
        entry_point_rva,
        size_of_image,
        headers_raw_end: size_of_headers as usize,
        import_dir_rva,
        sections,
        last_section_end_va: last_end_va,
    })
}

fn rva_to_file_off(pe: &PeLayout, rva: u32) -> Option<usize> {
    for sec in &pe.sections {
        if rva >= sec.virtual_address
            && rva
                < sec
                    .virtual_address
                    .saturating_add(sec.virtual_size.max(sec.size_of_raw_data))
        {
            let delta: u32 = rva - sec.virtual_address;
            return Some((sec.pointer_to_raw_data + delta) as usize);
        }
    }
    None
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

fn read_cstr(bytes: &[u8], off: usize, cap: usize) -> Option<String> {
    if off >= bytes.len() {
        return None;
    }
    let end: usize = (off + cap).min(bytes.len());
    let slice: &[u8] = &bytes[off..end];
    let nul: usize = slice
        .iter()
        .position(|b: &u8| *b == 0)
        .unwrap_or(slice.len());
    std::str::from_utf8(&slice[..nul]).ok().map(str::to_owned)
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
    fn memory_to_file_image_rejects_oversized_section_raw_size() {
        let e_lfanew: usize = 0x40;
        let opt_hdr_size: u16 = 0x60;
        let opt: usize = e_lfanew + 4 + 20;
        let sec_off: usize = opt + opt_hdr_size as usize;
        let mut mem_image: Vec<u8> = vec![0u8; (sec_off + SECTION_HEADER_LEN).max(0x100)];
        mem_image[0..2].copy_from_slice(b"MZ");
        mem_image[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        mem_image[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\x00\x00");
        let coff: usize = e_lfanew + 4;
        mem_image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        mem_image[coff + 16..coff + 18].copy_from_slice(&opt_hdr_size.to_le_bytes());
        mem_image[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        let s: usize = sec_off;
        mem_image[s + 16..s + 20].copy_from_slice(&0xFFFF_F000u32.to_le_bytes());
        mem_image[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        let start: std::time::Instant = std::time::Instant::now();
        let result: Option<Vec<u8>> = memory_to_file_image(&mem_image);
        assert!(
            result.is_none(),
            "crafted ~4 GiB section raw size must be rejected, not allocated"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "rejection must be immediate, never allocating gigabytes"
        );
    }
}
