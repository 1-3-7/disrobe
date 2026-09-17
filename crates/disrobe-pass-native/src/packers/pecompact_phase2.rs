#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::while_let_loop,
    clippy::too_long_first_doc_paragraph
)]

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, parse_pe_image};
use crate::packers::section_recovery::{
    IatReconstructionReport, SectionRecoveryReport, build_loaded_image, emulated_image_capacity,
    reconstruct_import_address_table, section_recovery_report,
};
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const EMU_HEAP_BASE: u64 = 0x2000_0000;
const EMU_HEAP_SIZE: u64 = 0x1000_0000;
const EMU_STACK_BASE: u64 = 0x0080_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const SYNTH_IAT_BASE: u64 = 0xFE00_0000;
const SYNTH_FN_BASE: u64 = 0xFE01_0000;
const EMU_TEB_BASE: u64 = 0x7EFD_E000;
const EMU_PEB_BASE: u64 = 0x7EFD_D000;
const EMU_LAZY_PAGE_BUDGET: u32 = 65_536;
const STEP_CAP_PECOMPACT: u64 = 120_000_000;

const LOADER_REBUILT_SECTIONS: &[&[u8]] = &[b".reloc", b".idata"];

const ORDINAL_NAME_PTR_CEILING: u64 = 0x1_0000;
const IMPORT_BY_ORDINAL_FLAG: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct PecompactPhaseTwoOutput {
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_point_rva: u32,
    pub recovered_memory_image: Vec<u8>,
    pub exit_reason: String,
    pub host_calls: Vec<String>,
    pub oep_estimate: Option<u64>,
    pub seh_dispatched: bool,

    pub content_recovery_pct: Option<f64>,
    pub whole_image_recovery_pct: Option<f64>,

    pub section_report: Option<SectionRecoveryReport>,
}

#[derive(Debug)]
struct PecompactHost {
    heap_brk: u64,
    heap_end: u64,
    image_base: u64,
    iat: BTreeMap<u64, &'static str>,
    resolved: BTreeMap<u64, String>,
    resolved_name_rva: BTreeMap<u32, u32>,
    next_synth_fn: u64,
    calls: Vec<String>,
    halted: bool,
}

impl PecompactHost {
    fn new(image_base: u64) -> Self {
        Self {
            heap_brk: EMU_HEAP_BASE,
            heap_end: EMU_HEAP_BASE.saturating_add(EMU_HEAP_SIZE),
            image_base,
            iat: BTreeMap::new(),
            resolved: BTreeMap::new(),
            resolved_name_rva: BTreeMap::new(),
            next_synth_fn: SYNTH_FN_BASE,
            calls: Vec::new(),
            halted: false,
        }
    }

    fn fresh_fn(&mut self) -> u64 {
        let v: u64 = self.next_synth_fn;
        self.next_synth_fn = self.next_synth_fn.wrapping_add(0x10);
        v
    }

    fn record_resolved_import(&mut self, synth: u64, name_ptr: u32, mem: &Memory) {
        if name_ptr == 0 {
            return;
        }
        if u64::from(name_ptr) < ORDINAL_NAME_PTR_CEILING {
            let original_iat: u32 = IMPORT_BY_ORDINAL_FLAG | name_ptr;
            self.resolved_name_rva.insert(synth as u32, original_iat);
            return;
        }
        if u64::from(name_ptr) < self.image_base.wrapping_add(2) {
            return;
        }
        let func_name: String = read_guest_cstr(mem, u64::from(name_ptr), 96);
        if func_name.is_empty() {
            return;
        }
        let name_entry_rva: u32 = (u64::from(name_ptr) - self.image_base - 2) as u32;
        self.resolved_name_rva.insert(synth as u32, name_entry_rva);
    }

    fn service(&mut self, name: &str, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        let sp: u64 = regs.get(Reg::Rsp);
        let arg = |i: u32| -> Result<u32> { mem.read_u32(sp.wrapping_add(u64::from(i) * 4)) };
        match name {
            "VirtualAlloc" => {
                let size: u32 = arg(1)?;
                let aligned: u64 = ((u64::from(size) + 0xFFF) & !0xFFFu64).max(0x1000);
                let at: u64 = (self.heap_brk + 0xFFF) & !0xFFFu64;
                if at.saturating_add(aligned) > self.heap_end {
                    regs.write_sized(Reg::Rax, 0, 32);
                } else {
                    self.heap_brk = at + aligned;
                    mem.map(at, aligned, Perm::RWX)?;
                    regs.write_sized(Reg::Rax, at, 32);
                }
                regs.set(Reg::Rsp, sp.wrapping_add(16));
                Ok(true)
            }
            "VirtualFree" => {
                regs.write_sized(Reg::Rax, 1, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(12));
                Ok(true)
            }
            "VirtualProtect" => {
                regs.write_sized(Reg::Rax, 1, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(16));
                Ok(true)
            }
            "GetProcAddress" => {
                let name_ptr: u32 = mem.read_u32(sp.wrapping_add(4))?;
                let fn_addr: u64 = self.fresh_fn();
                self.record_resolved_import(fn_addr, name_ptr, mem);
                regs.write_sized(Reg::Rax, fn_addr, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(8));
                Ok(true)
            }
            "GetModuleHandleA" | "LoadLibraryA" => {
                regs.write_sized(Reg::Rax, 0x7000_0000, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(4));
                Ok(true)
            }
            _ => {
                regs.write_sized(Reg::Rax, 0, 32);
                Ok(true)
            }
        }
    }
}

impl HostCall for PecompactHost {
    fn dispatch(&mut self, target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        if let Some(name) = self.resolved.get(&target).cloned() {
            self.calls.push(name.clone());
            return self.service(&name, regs, mem);
        }
        let symbol: &'static str = match self.iat.get(&target).copied() {
            Some(s) => s,
            None => {
                self.calls.push(format!("unknown@0x{target:08x}"));
                self.halted = true;
                return Ok(false);
            }
        };
        let sp: u64 = regs.get(Reg::Rsp);
        if symbol == "GetProcAddress" {
            let name_ptr: u32 = mem.read_u32(sp.wrapping_add(4))?;
            let func: String = read_guest_cstr(mem, u64::from(name_ptr), 96);
            self.calls.push(format!("GetProcAddress({func})"));
            let fn_addr: u64 = self.fresh_fn();
            self.record_resolved_import(fn_addr, name_ptr, mem);
            self.resolved.insert(fn_addr, func);
            regs.write_sized(Reg::Rax, fn_addr, 32);
            regs.set(Reg::Rsp, sp.wrapping_add(8));
            return Ok(true);
        }
        self.calls.push(symbol.to_owned());
        self.service(symbol, regs, mem)
    }
}

fn read_guest_cstr(mem: &Memory, addr: u64, cap: usize) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(cap);
    for i in 0..cap {
        let b: u8 = mem.read_u8(addr.wrapping_add(i as u64)).unwrap_or(0);
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn unpack_pecompact_phase2_emulated(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<PecompactPhaseTwoOutput> {
    let img: PeImage = parse_pe_image(packed)?;
    let image_base: u64 = img.image_base;
    let capacity: u64 = emulated_image_capacity(&img, packed.len());

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.enable_seh_dispatch();
    cpu.mem.map(image_base, capacity, Perm::RWX)?;
    map_image(&mut cpu, packed, &img, image_base)?;
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);
    map_synthetic_teb(&mut cpu)?;

    let mut host: PecompactHost = PecompactHost::new(image_base);
    rewrite_bootstrap_iat(packed, &img, &mut cpu, &mut host)?;

    cpu.regs.rip = image_base + u64::from(img.entry_point_rva);
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

    let ep_lo: u64 = image_base + u64::from(img.entry_point_rva);
    let exit: ExitReason = run_until_oep(&mut cpu, &mut host, image_base, ep_lo, capacity)?;
    let final_rip: u64 = cpu.regs.rip;
    let seh_dispatched: bool = host
        .calls
        .iter()
        .any(|c: &String| c.starts_with("GetProcAddress") || c == "VirtualAlloc");

    let mut recovered: Vec<u8> = cpu.mem.read_lossy(image_base, capacity as usize);
    let _: IatReconstructionReport =
        reconstruct_import_address_table(&mut recovered, &host.resolved_name_rva);
    let oep_estimate: Option<u64> = match &exit {
        ExitReason::JumpedOutOfRange { to, .. } => Some(*to),
        _ => None,
    };

    let (content_pct, whole_pct, report): (
        Option<f64>,
        Option<f64>,
        Option<SectionRecoveryReport>,
    ) = match original {
        Some(orig) => {
            let baseline: Vec<u8> = build_loaded_image(orig, capacity as usize)?;
            let content: f64 = content_recovery_pct(orig, &recovered, &baseline)?;
            let whole: f64 = whole_image_recovery_pct(&recovered, &baseline);
            let report: SectionRecoveryReport = section_recovery_report(orig, &recovered, &[])?;
            (Some(content), Some(whole), Some(report))
        }
        None => (None, None, None),
    };

    Ok(PecompactPhaseTwoOutput {
        image_base,
        size_of_image: img.size_of_image,
        entry_point_rva: img.entry_point_rva,
        recovered_memory_image: recovered,
        exit_reason: format!("{exit:?} final_rip=0x{final_rip:08x}"),
        host_calls: host.calls,
        oep_estimate,
        seh_dispatched,
        content_recovery_pct: content_pct,
        whole_image_recovery_pct: whole_pct,
        section_report: report,
    })
}

fn map_image(cpu: &mut Cpu, packed: &[u8], img: &PeImage, base: u64) -> Result<()> {
    let hdr: usize = 0x1000.min(packed.len());
    cpu.mem.write(base, &packed[..hdr])?;
    for sec in &img.sections {
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        if start >= end {
            continue;
        }
        cpu.mem
            .write_unchecked(base + u64::from(sec.virtual_address), &packed[start..end]);
    }
    Ok(())
}

fn map_synthetic_teb(cpu: &mut Cpu) -> Result<()> {
    cpu.mem.map(EMU_TEB_BASE, 0x2000, Perm::RW)?;
    cpu.mem.map(EMU_PEB_BASE, 0x1000, Perm::RW)?;
    cpu.mem.write_u32(EMU_TEB_BASE, 0xFFFF_FFFF)?;
    cpu.mem
        .write_u32(EMU_TEB_BASE + 0x18, EMU_TEB_BASE as u32)?;
    cpu.mem
        .write_u32(EMU_TEB_BASE + 0x30, EMU_PEB_BASE as u32)?;
    cpu.set_fs_base(EMU_TEB_BASE);
    Ok(())
}

fn rewrite_bootstrap_iat(
    packed: &[u8],
    img: &PeImage,
    cpu: &mut Cpu,
    host: &mut PecompactHost,
) -> Result<()> {
    let Some(imp): Option<&crate::packers::pe_sections::DataDirectory> =
        img.data_directories.get(1)
    else {
        return Ok(());
    };
    if imp.virtual_address == 0 {
        return Ok(());
    }
    let mut idx: usize = 0;
    loop {
        let desc_rva: u32 = imp.virtual_address + (idx * 20) as u32;
        let Some(desc_off): Option<usize> = rva_to_off(img, desc_rva) else {
            break;
        };
        if desc_off + 20 > packed.len() {
            break;
        }
        let oft: u32 = read_u32(packed, desc_off)?;
        let name_rva: u32 = read_u32(packed, desc_off + 12)?;
        let ft: u32 = read_u32(packed, desc_off + 16)?;
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let thunk_table: u32 = if oft != 0 { oft } else { ft };
        let mut t: u32 = 0;
        loop {
            let Some(thunk_off): Option<usize> = rva_to_off(img, thunk_table + t * 4) else {
                break;
            };
            if thunk_off + 4 > packed.len() {
                break;
            }
            let thunk: u32 = read_u32(packed, thunk_off)?;
            if thunk == 0 {
                break;
            }
            if thunk & 0x8000_0000 == 0 {
                let fn_off: Option<usize> = rva_to_off(img, thunk);
                if let Some(fn_off) = fn_off {
                    let func: String = read_cstr(packed, fn_off + 2, 64);
                    let classified: &'static str = classify(&func);
                    if classified != "Other" {
                        let synth: u64 = SYNTH_IAT_BASE + 0x100 + u64::from(t + idx as u32 * 0x40);
                        let iat_slot: u64 = img.image_base + u64::from(ft + t * 4);
                        cpu.mem.write_u32(iat_slot, synth as u32)?;
                        host.iat.insert(synth, classified);
                    }
                }
            }
            t += 1;
            if t > 256 {
                break;
            }
        }
        idx += 1;
        if idx > 64 {
            break;
        }
    }
    Ok(())
}

fn classify(func: &str) -> &'static str {
    match func {
        "GetProcAddress" => "GetProcAddress",
        "GetModuleHandleA" => "GetModuleHandleA",
        "LoadLibraryA" => "LoadLibraryA",
        "VirtualAlloc" => "VirtualAlloc",
        "VirtualFree" => "VirtualFree",
        "VirtualProtect" => "VirtualProtect",
        _ => "Other",
    }
}

fn run_until_oep(
    cpu: &mut Cpu,
    host: &mut PecompactHost,
    image_base: u64,
    ep_packed: u64,
    capacity: u64,
) -> Result<ExitReason> {
    let image_hi: u64 = image_base + capacity;
    let oep_lo: u64 = image_base + 0x1000;
    let mut steps: u64 = 0;
    let mut left_image: bool = false;
    loop {
        if steps >= STEP_CAP_PECOMPACT {
            return Ok(ExitReason::StepCap(steps));
        }
        steps += 1;
        let ip: u64 = cpu.regs.rip;
        let in_image: bool = ip >= image_base && ip < image_hi;
        if !in_image {
            left_image = true;
        } else if left_image && ip >= oep_lo && ip < ep_packed {
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

fn content_recovery_pct(original: &[u8], recovered: &[u8], baseline: &[u8]) -> Result<f64> {
    let img: PeImage = parse_pe_image(original)?;
    let compare_len: usize = recovered.len().min(baseline.len());
    let mut total: usize = 0;
    let mut matching: usize = 0;
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if LOADER_REBUILT_SECTIONS.contains(&name) {
            continue;
        }
        let off: usize = sec.virtual_address as usize;
        if off >= compare_len {
            continue;
        }
        let span_end: usize = (off + sec.virtual_size as usize).min(compare_len);
        for j in off..span_end {
            total += 1;
            if recovered[j] == baseline[j] {
                matching += 1;
            }
        }
    }
    if total == 0 {
        return Ok(0.0);
    }
    Ok(100.0 * matching as f64 / total as f64)
}

fn whole_image_recovery_pct(recovered: &[u8], baseline: &[u8]) -> f64 {
    let compare_len: usize = recovered.len().min(baseline.len());
    if compare_len == 0 {
        return 0.0;
    }
    let matching: usize = recovered
        .iter()
        .zip(baseline.iter())
        .take(compare_len)
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    let denom: usize = recovered.len().max(baseline.len());
    100.0 * matching as f64 / denom as f64
}

fn rva_to_off(img: &PeImage, rva: u32) -> Option<usize> {
    for sec in &img.sections {
        let span: u32 = sec.virtual_size.max(sec.raw_size);
        if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(span) {
            return Some((sec.raw_pointer + (rva - sec.virtual_address)) as usize);
        }
    }
    None
}

fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    if off + 4 > b.len() {
        return Err(Error::Truncated {
            needed: off + 4,
            had: b.len(),
        });
    }
    Ok(u32::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}

fn read_cstr(b: &[u8], off: usize, cap: usize) -> String {
    if off >= b.len() {
        return String::new();
    }
    let end: usize = (off + cap).min(b.len());
    let slice: &[u8] = &b[off..end];
    let nul: usize = slice
        .iter()
        .position(|c: &u8| *c == 0)
        .unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).into_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        let buf: Vec<u8> = vec![0u8; 0x80];
        assert!(unpack_pecompact_phase2_emulated(&buf, None).is_err());
    }

    #[test]
    fn whole_image_recovery_identical_is_100() {
        let a: Vec<u8> = vec![7, 7, 7, 7];
        assert!((whole_image_recovery_pct(&a, &a) - 100.0).abs() < f64::EPSILON);
    }
}
