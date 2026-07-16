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
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use crate::packers::section_recovery::{
    IatReconstructionReport, SectionRecoveryReport, build_loaded_image,
    reconstruct_import_address_table, section_recovery_report,
};
use crate::stub_emu::mem::MAX_MAP_BYTES;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const EMU_HEAP_BASE: u64 = 0x2000_0000;
const EMU_HEAP_SIZE: u64 = 0x0800_0000;
const EMU_STACK_BASE: u64 = 0x0080_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const SYNTH_IAT_BASE: u64 = 0xFE00_0000;
const SYNTH_FN_BASE: u64 = 0xFE01_0000;
const SYNTH_MODULE_BASE: u32 = 0x7000_0100;
const EMU_TEB_BASE: u64 = 0x7EFD_E000;
const EMU_PEB_BASE: u64 = 0x7EFD_D000;
const EMU_LAZY_PAGE_BUDGET: u32 = 16_384;
const STEP_CAP_ASPACK: u64 = 80_000_000;

const ASPACK_SECTION: &[u8] = b".aspack";
const ASPACK_ADATA_SECTION: &[u8] = b".adata";

const ORDINAL_NAME_PTR_CEILING: u64 = 0x1_0000;
const IMPORT_BY_ORDINAL_FLAG: u32 = 0x8000_0000;

const LOADER_REBUILT_SECTIONS: &[&[u8]] = &[b".reloc", b".idata"];
const IMPORT_DESCRIPTOR_BYTES: usize = 20;
const MAX_ASPACK_IMPORT_DESCRIPTORS: usize = 64;
const MAX_ASPACK_IMPORTS_PER_MODULE: usize = 256;
const MAX_ASPACK_MODULE_NAME_LEN: usize = 260;
const MAX_ASPACK_THUNK_CANDIDATES: usize = 1 << 20;
const PE_FILE_HEADER_LEN: usize = 24;
const PE32_DATA_DIRECTORY_OFFSET: usize = 96;
const IMPORT_DIRECTORY_INDEX: usize = 1;

#[derive(Debug, Clone)]
pub struct AspackPhaseTwoOutput {
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_point_rva: u32,
    pub stub_region_va: u32,
    pub recovered_memory_image: Vec<u8>,
    pub exit_reason: String,
    pub host_calls: Vec<String>,
    pub oep_estimate: Option<u64>,

    pub content_recovery_pct: Option<f64>,
    pub whole_image_recovery_pct: Option<f64>,

    pub section_report: Option<SectionRecoveryReport>,
}

#[derive(Debug, Clone, Copy)]
struct AspackResolvedImport {
    synth: u32,
    name_rva: u32,
}

#[derive(Debug)]
struct AspackImportModule {
    name_rva: u32,
    imports: Vec<AspackResolvedImport>,
    overflowed: bool,
}

#[derive(Debug)]
struct AspackImportCapture {
    name_rva: u32,
    synth_entries: Vec<u32>,
    name_entries: Vec<u32>,
}

#[derive(Debug)]
struct AspackImportLayout {
    name_rva: u32,
    iat_rva: u32,
    name_entries: Vec<u32>,
}

#[derive(Debug)]
struct AspackHost {
    heap_brk: u64,
    heap_end: u64,
    image_base: u64,
    iat: BTreeMap<u64, &'static str>,
    resolved: BTreeMap<u64, String>,
    resolved_name_rva: BTreeMap<u32, u32>,
    modules: BTreeMap<u32, AspackImportModule>,
    next_synth_fn: u64,
    next_synth_module: u32,
    calls: Vec<String>,
    halted: bool,
}

impl AspackHost {
    fn new(image_base: u64) -> Self {
        Self {
            heap_brk: EMU_HEAP_BASE,
            heap_end: EMU_HEAP_BASE.saturating_add(EMU_HEAP_SIZE),
            image_base,
            iat: BTreeMap::new(),
            resolved: BTreeMap::new(),
            resolved_name_rva: BTreeMap::new(),
            modules: BTreeMap::new(),
            next_synth_fn: SYNTH_FN_BASE,
            next_synth_module: SYNTH_MODULE_BASE,
            calls: Vec::new(),
            halted: false,
        }
    }

    fn fresh_fn(&mut self) -> u64 {
        let v: u64 = self.next_synth_fn;
        self.next_synth_fn = self.next_synth_fn.wrapping_add(0x10);
        v
    }

    fn fresh_module(&mut self) -> Option<u32> {
        let module: u32 = self.next_synth_module;
        self.next_synth_module = module.checked_add(0x10)?;
        Some(module)
    }

    fn resolved_import_name_rva(&self, name_ptr: u32, mem: &Memory) -> Option<u32> {
        if name_ptr == 0 {
            return None;
        }
        if u64::from(name_ptr) < ORDINAL_NAME_PTR_CEILING {
            let original_iat: u32 = IMPORT_BY_ORDINAL_FLAG | name_ptr;
            return Some(original_iat);
        }
        if u64::from(name_ptr) < self.image_base.wrapping_add(2) {
            return None;
        }
        let func_name: String = read_guest_cstr(mem, u64::from(name_ptr), 96);
        if func_name.is_empty() {
            return None;
        }
        let name_entry_rva: u64 = u64::from(name_ptr)
            .checked_sub(self.image_base)?
            .checked_sub(2)?;
        u32::try_from(name_entry_rva).ok()
    }

    fn record_resolved_import(&mut self, synth: u32, name_ptr: u32, mem: &Memory) -> Option<u32> {
        let name_rva: u32 = self.resolved_import_name_rva(name_ptr, mem)?;
        self.resolved_name_rva.insert(synth, name_rva);
        Some(name_rva)
    }

    fn module_name_rva(&self, name_ptr: u32, mem: &Memory) -> Option<u32> {
        if name_ptr == 0 {
            return None;
        }
        let name_rva: u64 = u64::from(name_ptr).checked_sub(self.image_base)?;
        let name: String = read_guest_cstr(mem, u64::from(name_ptr), MAX_ASPACK_MODULE_NAME_LEN);
        if name.is_empty() || !name.bytes().all(|byte: u8| byte.is_ascii_graphic()) {
            return None;
        }
        u32::try_from(name_rva).ok()
    }

    fn module_handle(&mut self, name_ptr: u32, mem: &Memory) -> Option<u32> {
        let name_rva: u32 = self.module_name_rva(name_ptr, mem)?;
        let handle: u32 = self.fresh_module()?;
        self.modules.insert(
            handle,
            AspackImportModule {
                name_rva,
                imports: Vec::new(),
                overflowed: false,
            },
        );
        Some(handle)
    }

    fn record_module_import(&mut self, module_handle: u32, synth: u32, name_rva: u32) {
        let Some(module): Option<&mut AspackImportModule> = self.modules.get_mut(&module_handle)
        else {
            return;
        };
        if module.imports.len() >= MAX_ASPACK_IMPORTS_PER_MODULE {
            module.overflowed = true;
            return;
        }
        module
            .imports
            .push(AspackResolvedImport { synth, name_rva });
    }

    fn service_win32(&mut self, name: &str, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
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
                let module_handle: u32 = mem.read_u32(sp)?;
                let name_ptr: u32 = mem.read_u32(sp.wrapping_add(4))?;
                let fn_addr: u64 = self.fresh_fn();
                let synth: u32 = u32::try_from(fn_addr).map_err(|_| {
                    Error::SignatureDb("ASPack: synthetic API address exceeds PE32".to_owned())
                })?;
                if let Some(name_rva) = self.record_resolved_import(synth, name_ptr, mem) {
                    self.record_module_import(module_handle, synth, name_rva);
                }
                regs.write_sized(Reg::Rax, fn_addr, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(8));
                Ok(true)
            }
            "GetModuleHandleA" | "LoadLibraryA" => {
                let name_ptr: u32 = mem.read_u32(sp)?;
                let module_handle: u32 = self
                    .module_handle(name_ptr, mem)
                    .map_or(0x7000_0000, |handle: u32| handle);
                regs.write_sized(Reg::Rax, u64::from(module_handle), 32);
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

impl HostCall for AspackHost {
    fn dispatch(&mut self, target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        if let Some(name) = self.resolved.get(&target).cloned() {
            self.calls.push(name.clone());
            return self.service_win32(&name, regs, mem);
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
            let module_handle: u32 = mem.read_u32(sp)?;
            let name_ptr: u32 = mem.read_u32(sp.wrapping_add(4))?;
            let func_name: String = read_guest_cstr(mem, u64::from(name_ptr), 96);
            self.calls.push(format!("GetProcAddress({func_name})"));
            let fn_addr: u64 = self.fresh_fn();
            let synth: u32 = u32::try_from(fn_addr).map_err(|_| {
                Error::SignatureDb("ASPack: synthetic API address exceeds PE32".to_owned())
            })?;
            if let Some(name_rva) = self.record_resolved_import(synth, name_ptr, mem) {
                self.record_module_import(module_handle, synth, name_rva);
            }
            self.resolved.insert(fn_addr, func_name);
            regs.write_sized(Reg::Rax, fn_addr, 32);
            regs.set(Reg::Rsp, sp.wrapping_add(8));
            return Ok(true);
        }
        self.calls.push(symbol.to_owned());
        self.service_win32(symbol, regs, mem)
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

pub fn unpack_aspack_phase2_emulated(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<AspackPhaseTwoOutput> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub_va: u32 = img
        .section_by_name(ASPACK_SECTION)
        .map(|s: &PeSection| s.virtual_address)
        .ok_or_else(|| Error::SignatureDb("ASPack: no .aspack stub section".to_owned()))?;

    let image_base: u64 = img.image_base;
    let capacity: u64 = u64::from(img.size_of_image)
        .max(last_section_end_va(&img))
        .min(MAX_MAP_BYTES);

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.mem.map(image_base, capacity, Perm::RWX)?;
    map_image(&mut cpu, packed, &img, image_base)?;
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);
    map_synthetic_teb(&mut cpu)?;

    let mut host: AspackHost = AspackHost::new(image_base);
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

    let stub_lo: u64 = image_base + u64::from(stub_va);
    let exit: ExitReason = run_until_oep(&mut cpu, &mut host, image_base, stub_lo, capacity)?;
    let final_rip: u64 = cpu.regs.rip;

    let mut recovered: Vec<u8> = cpu.mem.read_lossy(image_base, capacity as usize);
    let import_layouts: Vec<AspackImportLayout> =
        collect_aspack_import_layouts(&recovered, &host.modules);
    let _: IatReconstructionReport =
        reconstruct_import_address_table(&mut recovered, &host.resolved_name_rva);
    if let Some(import_directory) =
        reconstruct_aspack_import_descriptors(&mut recovered, image_base, &import_layouts)
    {
        rewrite_import_directory(&mut recovered, import_directory);
    }
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
            let report: SectionRecoveryReport =
                section_recovery_report(orig, &recovered, &[ASPACK_SECTION, ASPACK_ADATA_SECTION])?;
            (Some(content), Some(whole), Some(report))
        }
        None => (None, None, None),
    };

    Ok(AspackPhaseTwoOutput {
        image_base,
        size_of_image: img.size_of_image,
        entry_point_rva: img.entry_point_rva,
        stub_region_va: stub_va,
        recovered_memory_image: recovered,
        exit_reason: format!("{exit:?} final_rip=0x{final_rip:08x}"),
        host_calls: host.calls,
        oep_estimate,
        content_recovery_pct: content_pct,
        whole_image_recovery_pct: whole_pct,
        section_report: report,
    })
}

fn last_section_end_va(img: &PeImage) -> u64 {
    img.sections
        .iter()
        .map(|s: &PeSection| {
            u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size))
        })
        .max()
        .unwrap_or(0)
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
        let dst: u64 = base + u64::from(sec.virtual_address);
        cpu.mem.write_unchecked(dst, &packed[start..end]);
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
    host: &mut AspackHost,
) -> Result<()> {
    let imp_dir: Option<&crate::packers::pe_sections::DataDirectory> = img.data_directories.get(1);
    let Some(imp): Option<&crate::packers::pe_sections::DataDirectory> = imp_dir else {
        return Ok(());
    };
    if imp.virtual_address == 0 {
        return Ok(());
    }
    let mut idx: usize = 0;
    loop {
        let desc_rva: u32 = imp.virtual_address.saturating_add((idx * 20) as u32);
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
            let Some(thunk_off): Option<usize> =
                rva_to_off(img, thunk_table.saturating_add(t.saturating_mul(4)))
            else {
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
                        let iat_slot: u64 =
                            image_base_iat(img, ft.saturating_add(t.saturating_mul(4)));
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

fn image_base_iat(img: &PeImage, ft_rva: u32) -> u64 {
    img.image_base + u64::from(ft_rva)
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
    host: &mut AspackHost,
    image_base: u64,
    stub_lo: u64,
    capacity: u64,
) -> Result<ExitReason> {
    let image_hi: u64 = image_base + capacity;
    let mut steps: u64 = 0;
    let mut entered_stub: bool = false;
    loop {
        if steps >= STEP_CAP_ASPACK {
            return Ok(ExitReason::StepCap(steps));
        }
        steps += 1;
        let ip: u64 = cpu.regs.rip;
        let in_stub: bool = ip >= stub_lo && ip < image_hi;
        if in_stub {
            entered_stub = true;
        } else if entered_stub && ip >= image_base && ip < stub_lo {
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

#[derive(Debug, Clone, Copy)]
struct AspackImportDirectory {
    rva: u32,
    size: u32,
}

fn collect_aspack_import_layouts(
    recovered: &[u8],
    modules: &BTreeMap<u32, AspackImportModule>,
) -> Vec<AspackImportLayout> {
    let mut captures: Vec<AspackImportCapture> = Vec::with_capacity(modules.len());
    for module in modules.values() {
        if module.overflowed
            || module.imports.is_empty()
            || !is_valid_module_name(recovered, module.name_rva)
        {
            continue;
        }
        let synth_entries: Vec<u32> = module
            .imports
            .iter()
            .map(|import: &AspackResolvedImport| import.synth)
            .collect();
        let name_entries: Vec<u32> = module
            .imports
            .iter()
            .map(|import: &AspackResolvedImport| import.name_rva)
            .collect();
        if !name_entries
            .iter()
            .all(|entry: &u32| is_valid_import_entry(recovered, *entry))
        {
            continue;
        }
        captures.push(AspackImportCapture {
            name_rva: module.name_rva,
            synth_entries,
            name_entries,
        });
    }
    let tables: Vec<&[u32]> = captures
        .iter()
        .map(|capture: &AspackImportCapture| capture.synth_entries.as_slice())
        .collect();
    let excluded_rvas: Vec<Option<u32>> = vec![None; tables.len()];
    let Some(iat_rvas): Option<Vec<Option<u32>>> =
        find_unique_thunk_tables(recovered, &tables, &excluded_rvas)
    else {
        return Vec::new();
    };
    let mut layouts: Vec<AspackImportLayout> = Vec::with_capacity(captures.len());
    for (capture, iat_rva) in captures.into_iter().zip(iat_rvas) {
        let Some(iat_rva): Option<u32> = iat_rva else {
            continue;
        };
        layouts.push(AspackImportLayout {
            name_rva: capture.name_rva,
            iat_rva,
            name_entries: capture.name_entries,
        });
    }
    layouts
}

fn reconstruct_aspack_import_descriptors(
    recovered: &mut [u8],
    image_base: u64,
    layouts: &[AspackImportLayout],
) -> Option<AspackImportDirectory> {
    if layouts.is_empty() || layouts.len() > MAX_ASPACK_IMPORT_DESCRIPTORS {
        return None;
    }
    let directory: AspackImportDirectory =
        find_aspack_runtime_import_directory(recovered, image_base, layouts.len())?;
    let tables: Vec<&[u32]> = layouts
        .iter()
        .map(|layout: &AspackImportLayout| layout.name_entries.as_slice())
        .collect();
    let excluded_rvas: Vec<Option<u32>> = layouts
        .iter()
        .map(|layout: &AspackImportLayout| Some(layout.iat_rva))
        .collect();
    let ilt_rvas: Vec<Option<u32>> = find_unique_thunk_tables(recovered, &tables, &excluded_rvas)?;
    let mut descriptors: Vec<[u32; 5]> = Vec::with_capacity(layouts.len());
    for (layout, ilt_rva) in layouts.iter().zip(ilt_rvas) {
        if !is_valid_module_name(recovered, layout.name_rva) {
            return None;
        }
        let ilt_rva: u32 = ilt_rva?;
        descriptors.push([ilt_rva, 0, 0, layout.name_rva, layout.iat_rva]);
    }
    let descriptor_count: usize = descriptors.len().checked_add(1)?;
    let byte_count: usize = descriptor_count.checked_mul(IMPORT_DESCRIPTOR_BYTES)?;
    let directory_off: usize = usize::try_from(directory.rva).ok()?;
    let directory_end: usize = directory_off.checked_add(byte_count)?;
    if directory_end > recovered.len() {
        return None;
    }
    for (index, fields) in descriptors.iter().enumerate() {
        let descriptor_off: usize = directory_off.checked_add(index * IMPORT_DESCRIPTOR_BYTES)?;
        write_import_descriptor(recovered, descriptor_off, *fields)?;
    }
    recovered[directory_end - IMPORT_DESCRIPTOR_BYTES..directory_end].fill(0);
    Some(directory)
}

fn find_aspack_runtime_import_directory(
    recovered: &[u8],
    image_base: u64,
    expected_count: usize,
) -> Option<AspackImportDirectory> {
    if expected_count == 0 || expected_count > MAX_ASPACK_IMPORT_DESCRIPTORS {
        return None;
    }
    let image_base: u32 = u32::try_from(image_base).ok()?;
    let image_len: u32 = u32::try_from(recovered.len()).ok()?;
    let image_end: u32 = image_base.checked_add(image_len)?;
    if recovered.len() < IMPORT_DESCRIPTOR_BYTES {
        return None;
    }
    let scan_end: usize = recovered.len().saturating_sub(IMPORT_DESCRIPTOR_BYTES);
    let mut candidate: usize = 0;
    let mut found: Option<AspackImportDirectory> = None;
    while candidate <= scan_end {
        let first: u32 = read_u32(recovered, candidate).ok()?;
        if first == 0 {
            candidate = candidate.saturating_add(4);
            continue;
        }
        let first_fields: [u32; 5] = read_import_descriptor(recovered, candidate)?;
        if aspack_runtime_descriptor(first_fields, image_base, image_end).is_none() {
            candidate = candidate.saturating_add(4);
            continue;
        }
        let mut cursor: usize = candidate;
        let mut descriptor_count: usize = 0;
        loop {
            let Some(fields): Option<[u32; 5]> = read_import_descriptor(recovered, cursor) else {
                candidate = cursor.saturating_add(4);
                break;
            };
            if fields == [0; 5] {
                if descriptor_count == expected_count {
                    let rva: u32 = u32::try_from(candidate).ok()?;
                    let byte_count: usize = descriptor_count
                        .checked_add(1)?
                        .checked_mul(IMPORT_DESCRIPTOR_BYTES)?;
                    let size: u32 = u32::try_from(byte_count).ok()?;
                    let directory: AspackImportDirectory = AspackImportDirectory { rva, size };
                    if found.replace(directory).is_some() {
                        return None;
                    }
                }
                let next: usize = cursor.checked_add(IMPORT_DESCRIPTOR_BYTES)?;
                candidate = next;
                break;
            }
            if descriptor_count >= MAX_ASPACK_IMPORT_DESCRIPTORS {
                candidate = cursor.saturating_add(4);
                break;
            }
            if aspack_runtime_descriptor(fields, image_base, image_end).is_none() {
                candidate = cursor.saturating_add(4);
                break;
            }
            descriptor_count += 1;
            let next: usize = cursor.checked_add(IMPORT_DESCRIPTOR_BYTES)?;
            cursor = next;
        }
    }
    found
}

fn read_import_descriptor(recovered: &[u8], off: usize) -> Option<[u32; 5]> {
    let mut fields: [u32; 5] = [0; 5];
    for (index, field) in fields.iter_mut().enumerate() {
        let field_off: usize = off.checked_add(index.checked_mul(4)?)?;
        *field = read_u32(recovered, field_off).ok()?;
    }
    Some(fields)
}

fn aspack_runtime_descriptor(fields: [u32; 5], image_base: u32, image_end: u32) -> Option<()> {
    let runtime_table_va: u32 = fields[0];
    if runtime_table_va == 0
        || fields[1] != 0
        || fields[2] != 0
        || fields[3] != runtime_table_va
        || fields[4] != runtime_table_va
        || runtime_table_va < image_base
        || runtime_table_va >= image_end
    {
        return None;
    }
    let _: u32 = runtime_table_va.checked_sub(image_base)?;
    Some(())
}

fn find_unique_thunk_tables(
    recovered: &[u8],
    tables: &[&[u32]],
    excluded_rvas: &[Option<u32>],
) -> Option<Vec<Option<u32>>> {
    if tables.len() != excluded_rvas.len() || tables.is_empty() {
        return None;
    }
    let mut candidate_tables: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, entries) in tables.iter().enumerate() {
        if entries.is_empty() || entries.len() > MAX_ASPACK_IMPORTS_PER_MODULE {
            return None;
        }
        let key: u64 = thunk_table_key(entries)?;
        candidate_tables.entry(key).or_default().push(index);
    }
    let scan_end: usize = recovered.len().checked_sub(8)?;
    let mut found: Vec<Option<u32>> = vec![None; tables.len()];
    let mut candidate_checks: usize = 0;
    let mut off: usize = 0;
    while off <= scan_end {
        let first: u32 = read_u32(recovered, off).ok()?;
        let second: u32 = read_u32(recovered, off.checked_add(4)?).ok()?;
        let key: u64 = u64::from(first) | (u64::from(second) << 32);
        if let Some(indices) = candidate_tables.get(&key) {
            let rva: u32 = u32::try_from(off).ok()?;
            for index in indices {
                if excluded_rvas[*index] == Some(rva) {
                    continue;
                }
                candidate_checks = candidate_checks.checked_add(1)?;
                if candidate_checks > MAX_ASPACK_THUNK_CANDIDATES {
                    return None;
                }
                if thunk_table_matches(recovered, off, tables[*index]) {
                    if found[*index].is_some() || found.contains(&Some(rva)) {
                        return None;
                    }
                    found[*index] = Some(rva);
                }
            }
        }
        off = off.saturating_add(4);
    }
    Some(found)
}

fn thunk_table_key(entries: &[u32]) -> Option<u64> {
    let first: u32 = *entries.first()?;
    let second: u32 = entries.get(1).map_or(0, |value: &u32| *value);
    Some(u64::from(first) | (u64::from(second) << 32))
}

fn thunk_table_matches(recovered: &[u8], off: usize, entries: &[u32]) -> bool {
    for (index, entry) in entries.iter().enumerate() {
        let Some(entry_off): Option<usize> = off.checked_add(index * 4) else {
            return false;
        };
        let Ok(value) = read_u32(recovered, entry_off) else {
            return false;
        };
        if value != *entry {
            return false;
        }
    }
    let Some(terminator_off): Option<usize> = off.checked_add(entries.len() * 4) else {
        return false;
    };
    matches!(read_u32(recovered, terminator_off), Ok(0))
}

fn is_valid_import_entry(recovered: &[u8], entry: u32) -> bool {
    if entry & IMPORT_BY_ORDINAL_FLAG != 0 {
        return true;
    }
    let Some(name_off): Option<usize> = usize::try_from(entry)
        .ok()
        .and_then(|rva: usize| rva.checked_add(2))
    else {
        return false;
    };
    let Some(name): Option<&[u8]> = recovered.get(name_off..) else {
        return false;
    };
    let Some(len): Option<usize> = name.iter().position(|byte: &u8| *byte == 0) else {
        return false;
    };
    len > 0 && len <= 255 && name[..len].iter().all(u8::is_ascii_graphic)
}

fn is_valid_module_name(recovered: &[u8], name_rva: u32) -> bool {
    let Some(name_off): Option<usize> = usize::try_from(name_rva).ok() else {
        return false;
    };
    let Some(name): Option<&[u8]> = recovered.get(name_off..) else {
        return false;
    };
    let Some(len): Option<usize> = name.iter().position(|byte: &u8| *byte == 0) else {
        return false;
    };
    len > 0 && len <= MAX_ASPACK_MODULE_NAME_LEN && name[..len].iter().all(u8::is_ascii_graphic)
}

fn write_import_descriptor(recovered: &mut [u8], off: usize, fields: [u32; 5]) -> Option<()> {
    let end: usize = off.checked_add(IMPORT_DESCRIPTOR_BYTES)?;
    let descriptor: &mut [u8] = recovered.get_mut(off..end)?;
    for (index, field) in fields.iter().enumerate() {
        let field_off: usize = index.checked_mul(4)?;
        descriptor[field_off..field_off + 4].copy_from_slice(&field.to_le_bytes());
    }
    Some(())
}

fn rewrite_import_directory(recovered: &mut [u8], directory: AspackImportDirectory) {
    let Some(pe_off_u32): Option<u32> = read_u32(recovered, 0x3c).ok() else {
        return;
    };
    let Some(pe_off): Option<usize> = usize::try_from(pe_off_u32).ok() else {
        return;
    };
    let Some(optional_off): Option<usize> = pe_off.checked_add(PE_FILE_HEADER_LEN) else {
        return;
    };
    let Some(directory_off): Option<usize> = optional_off
        .checked_add(PE32_DATA_DIRECTORY_OFFSET)
        .and_then(|off: usize| off.checked_add(IMPORT_DIRECTORY_INDEX * 8))
    else {
        return;
    };
    let Some(directory_end): Option<usize> = directory_off.checked_add(8) else {
        return;
    };
    if directory_end > recovered.len() {
        return;
    }
    recovered[directory_off..directory_off + 4].copy_from_slice(&directory.rva.to_le_bytes());
    recovered[directory_off + 4..directory_end].copy_from_slice(&directory.size.to_le_bytes());
}

fn content_recovery_pct(original: &[u8], recovered: &[u8], baseline: &[u8]) -> Result<f64> {
    let img: PeImage = parse_pe_image(original)?;
    let compare_len: usize = recovered.len().min(baseline.len());
    let mut total: usize = 0;
    let mut matching: usize = 0;
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if LOADER_REBUILT_SECTIONS.contains(&name)
            || name == ASPACK_SECTION
            || name == ASPACK_ADATA_SECTION
        {
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
    fn rejects_non_aspack() {
        let mut buf: Vec<u8> = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let r: Result<AspackPhaseTwoOutput> = unpack_aspack_phase2_emulated(&buf, None);
        assert!(r.is_err());
    }

    #[test]
    fn whole_image_recovery_identical_is_100() {
        let a: Vec<u8> = vec![1, 2, 3, 4];
        assert!((whole_image_recovery_pct(&a, &a) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn whole_image_recovery_disjoint_is_low() {
        let a: Vec<u8> = vec![0, 0, 0, 0];
        let b: Vec<u8> = vec![9, 9, 9, 9];
        assert!(whole_image_recovery_pct(&a, &b) < 1.0);
    }
}
