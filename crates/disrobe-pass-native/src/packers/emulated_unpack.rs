#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::collections::BTreeMap;

use disrobe_core::neutralize::{Anchor, NeutralizedCheck, RuntimeCheck};

use crate::error::Result;
use crate::packers::pe_sections::{DataDirectory, PeImage};
use crate::packers::section_recovery::{
    SectionRecoveryReport, build_loaded_image, emulated_image_capacity, section_recovery_report,
};
use crate::stub_emu::win_env::read_cstr;
use crate::stub_emu::{
    ApiOutcome, ApiSandbox, Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs,
    SyntheticWindows, install_synthetic_windows_for_image,
};

const EMU_STACK_BASE: u64 = 0x0080_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const EMU_HEAP_BASE: u64 = 0x2000_0000;
const EMU_HEAP_SIZE: u64 = 0x0800_0000;
const EMU_LAZY_PAGE_BUDGET: u32 = 65_536;
const UNKNOWN_IMPORT_BASE: u64 = 0x7E00_0000;
const UNKNOWN_IMPORT_STRIDE: u64 = 0x10;
const TLS_RETURN_SENTINEL: u64 = 0x7FF3_0000;

pub const MAX_IMPORT_DESCRIPTORS: usize = 64;
pub const MAX_IMPORT_THUNKS: usize = 1024;
pub const MAX_TLS_CALLBACKS: usize = 16;
pub const TLS_CALLBACK_STEP_SHARE: u64 = 8;

const DIRECTORY_IMPORT: usize = 1;
const DIRECTORY_TLS: usize = 9;
const DLL_PROCESS_ATTACH: u64 = 1;

#[derive(Debug, Clone)]
pub struct EmulatedUnpack {
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_point_rva: u32,
    pub stub_section_rva: u32,
    pub recovered_memory_image: Vec<u8>,
    pub exit_reason: String,
    pub oep_rva: Option<u32>,
    pub content_bytes_mutated_by_stub: usize,
    pub steps_executed: u64,

    pub content_recovery_pct: Option<f64>,
    pub whole_image_recovery_pct: Option<f64>,
    pub section_report: Option<SectionRecoveryReport>,

    pub neutralized: Vec<NeutralizedCheck>,
    pub neutralized_dropped: u64,
    pub resolved_imports: usize,
    pub unresolved_imports: Vec<String>,
    pub tls_callbacks: Vec<TlsCallbackRun>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCallbackRun {
    pub callback_va: u64,
    pub steps: u64,
    pub outcome: String,
    pub returned: bool,
}

impl EmulatedUnpack {
    #[must_use]
    pub fn reached_oep(&self) -> bool {
        self.oep_rva.is_some() && self.content_bytes_mutated_by_stub > 0
    }

    #[must_use]
    pub fn neutralized_checks(&self) -> Vec<RuntimeCheck> {
        let mut checks: Vec<RuntimeCheck> = self
            .neutralized
            .iter()
            .map(|event: &NeutralizedCheck| event.check)
            .collect();
        checks.sort_unstable();
        checks.dedup();
        checks
    }
}

#[derive(Debug)]
struct StubHost {
    heap_brk: u64,
    heap_end: u64,
    halted: Option<String>,
    env: SyntheticWindows,
    api: ApiSandbox,
    unknown_imports: BTreeMap<u64, String>,
    mode: CpuMode,
}

impl StubHost {
    fn new(env: SyntheticWindows, unknown_imports: BTreeMap<u64, String>, mode: CpuMode) -> Self {
        Self {
            heap_brk: EMU_HEAP_BASE,
            heap_end: EMU_HEAP_BASE.saturating_add(EMU_HEAP_SIZE),
            halted: None,
            env,
            api: ApiSandbox::new(),
            unknown_imports,
            mode,
        }
    }

    fn legacy_alloc(&mut self, regs: &mut Regs, mem: &mut Memory) -> Result<()> {
        let sp: u64 = regs.get(Reg::Rsp);
        let size: u32 = mem.read_u32(sp.wrapping_add(8)).unwrap_or(0x1000);
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
        Ok(())
    }
}

impl HostCall for StubHost {
    fn dispatch(&mut self, target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        if let Some(name) = self.env.symbol_for(target) {
            return Ok(match self.api.dispatch(name, self.mode, regs, mem) {
                ApiOutcome::Handled => true,
                ApiOutcome::Unknown => {
                    self.halted = Some(format!(
                        "import {name} has no sandbox semantics in the generic stub emulator"
                    ));
                    false
                }
            });
        }
        if let Some(name) = self.unknown_imports.get(&target) {
            self.halted = Some(format!(
                "import {name} is not part of the synthetic windows environment"
            ));
            return Ok(false);
        }
        self.legacy_alloc(regs, mem)?;
        Ok(true)
    }

    fn take_vectored_registrations(&mut self) -> Vec<(bool, u64)> {
        self.api.take_veh_registrations()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EmulationConfig<'a> {
    pub stub_section_names: &'a [&'a [u8]],
    pub content_exclude: &'a [&'a [u8]],
    pub step_cap: u64,
}

pub fn emulate_unpack_stub(
    packed: &[u8],
    img: &PeImage,
    stub_rva: u32,
    original: Option<&[u8]>,
    config: &EmulationConfig<'_>,
) -> Result<EmulatedUnpack> {
    let image_base: u64 = img.image_base;
    let capacity: u64 = emulated_image_capacity(img, packed.len());
    let mode: CpuMode = if img.is_pe32_plus {
        CpuMode::Bits64
    } else {
        CpuMode::Bits32
    };

    let mut cpu: Cpu = Cpu::new(mode);
    cpu.mem.map(image_base, capacity, Perm::RWX)?;
    map_image(&mut cpu, packed, img, image_base);
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);
    let env: SyntheticWindows = install_synthetic_windows_for_image(&mut cpu, image_base)?;
    cpu.enable_seh_dispatch();
    let _ = cpu.mem.map(
        TLS_RETURN_SENTINEL,
        crate::stub_emu::PAGE_SIZE as u64,
        Perm::RX,
    );

    let imports: ImportResolution = resolve_imports(&mut cpu, img, image_base, &env);
    let mut host: StubHost = StubHost::new(env, imports.unknown_by_addr, mode);

    reset_registers(&mut cpu);
    let stub_lo: u64 = image_base + u64::from(stub_rva);
    let image_hi: u64 = image_base + capacity;
    let tls_budget: u64 = config.step_cap / TLS_CALLBACK_STEP_SHARE;
    let tls_callbacks: Vec<TlsCallbackRun> =
        run_tls_callbacks(&mut cpu, &mut host, img, image_base, image_hi, tls_budget);
    let tls_steps: u64 = tls_callbacks
        .iter()
        .map(|run: &TlsCallbackRun| run.steps)
        .sum();

    reset_registers(&mut cpu);
    cpu.regs.rip = image_base + u64::from(img.entry_point_rva);
    let main_cap: u64 = config.step_cap.saturating_sub(tls_steps);
    let (exit, steps): (ExitReason, u64) =
        run_until_oep(&mut cpu, &mut host, image_base, stub_lo, capacity, main_cap)?;
    let final_rip: u64 = cpu.regs.rip;

    let recovered: Vec<u8> = cpu.mem.read_lossy(image_base, capacity as usize);
    let content_mutated: usize =
        count_content_mutation(&recovered, packed, img, config.stub_section_names);

    let oep_rva: Option<u32> = match &exit {
        ExitReason::JumpedOutOfRange { to, .. }
            if *to >= image_base
                && *to < stub_lo
                && (*to - image_base) as u32 != img.entry_point_rva =>
        {
            Some((*to - image_base) as u32)
        }
        _ => None,
    };

    let (content_pct, whole_pct, report): (
        Option<f64>,
        Option<f64>,
        Option<SectionRecoveryReport>,
    ) = match original {
        Some(orig) => {
            let baseline: Vec<u8> = build_loaded_image(orig, capacity as usize)?;
            let content: f64 = content_recovery_pct(orig, &recovered, &baseline, config)?;
            let whole: f64 = whole_image_recovery_pct(&recovered, &baseline);
            let report: SectionRecoveryReport =
                section_recovery_report(orig, &recovered, config.stub_section_names)?;
            (Some(content), Some(whole), Some(report))
        }
        None => (None, None, None),
    };

    let exit_reason: String = host.halted.as_deref().map_or_else(
        || format!("{exit:?} final_rip=0x{final_rip:08x}"),
        |why: &str| format!("{exit:?} final_rip=0x{final_rip:08x} ({why})"),
    );

    let mut neutralized: Vec<NeutralizedCheck> = cpu.neutralized().to_vec();
    neutralized.extend_from_slice(host.api.events());
    for run in &tls_callbacks {
        neutralized.push(NeutralizedCheck {
            check: RuntimeCheck::TlsCallback,
            anchor: Anchor {
                address: run.callback_va,
                instruction: "tls callback".to_owned(),
                pattern: format!(
                    "IMAGE_TLS_DIRECTORY callback {:#x} executed before the entry point with DLL_PROCESS_ATTACH",
                    run.callback_va
                ),
            },
            outcome: run.outcome.clone(),
        });
    }
    neutralized.sort_by_key(|event: &NeutralizedCheck| (event.anchor.address, event.check));
    let neutralized_dropped: u64 = cpu
        .neutralized_dropped()
        .saturating_add(host.api.events_dropped());

    Ok(EmulatedUnpack {
        image_base,
        size_of_image: img.size_of_image,
        entry_point_rva: img.entry_point_rva,
        stub_section_rva: stub_rva,
        recovered_memory_image: recovered,
        exit_reason,
        oep_rva,
        content_bytes_mutated_by_stub: content_mutated,
        steps_executed: steps.saturating_add(tls_steps),
        content_recovery_pct: content_pct,
        whole_image_recovery_pct: whole_pct,
        section_report: report,
        neutralized,
        neutralized_dropped,
        resolved_imports: imports.resolved,
        unresolved_imports: imports.unresolved_names,
        tls_callbacks,
    })
}

fn reset_registers(cpu: &mut Cpu) {
    cpu.regs
        .set(Reg::Rsp, EMU_STACK_BASE + EMU_STACK_SIZE - 0x1000);
    for reg in [
        Reg::Rax,
        Reg::Rbx,
        Reg::Rcx,
        Reg::Rdx,
        Reg::Rsi,
        Reg::Rdi,
        Reg::Rbp,
        Reg::R8,
        Reg::R9,
        Reg::R10,
        Reg::R11,
        Reg::R12,
        Reg::R13,
        Reg::R14,
        Reg::R15,
    ] {
        cpu.regs.set(reg, 0);
    }
}

fn map_image(cpu: &mut Cpu, packed: &[u8], img: &PeImage, base: u64) {
    let hdr: usize = 0x1000.min(packed.len());
    cpu.mem.write_unchecked(base, &packed[..hdr]);
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
}

fn directory(img: &PeImage, index: usize) -> Option<DataDirectory> {
    let dir: DataDirectory = *img.data_directories.get(index)?;
    (dir.virtual_address != 0 && dir.size != 0).then_some(dir)
}

#[derive(Debug, Default)]
struct ImportResolution {
    resolved: usize,
    unresolved_names: Vec<String>,
    unknown_by_addr: BTreeMap<u64, String>,
}

fn read_va(mem: &Memory, mode: CpuMode, addr: u64) -> Option<u64> {
    match mode {
        CpuMode::Bits32 => mem.read_u32(addr).ok().map(u64::from),
        CpuMode::Bits64 => mem.read_u64(addr).ok(),
    }
}

fn write_va(mem: &mut Memory, mode: CpuMode, addr: u64, value: u64) -> bool {
    match mode {
        CpuMode::Bits32 => mem.write_u32(addr, value as u32).is_ok(),
        CpuMode::Bits64 => mem.write_u64(addr, value).is_ok(),
    }
}

fn resolve_imports(
    cpu: &mut Cpu,
    img: &PeImage,
    image_base: u64,
    env: &SyntheticWindows,
) -> ImportResolution {
    let mut out: ImportResolution = ImportResolution::default();
    let Some(dir): Option<DataDirectory> = directory(img, DIRECTORY_IMPORT) else {
        return out;
    };
    let mode: CpuMode = cpu.mode;
    let ptr: u64 = u64::from(mode.ptr_size());
    let ordinal_flag: u64 = match mode {
        CpuMode::Bits32 => 1 << 31,
        CpuMode::Bits64 => 1 << 63,
    };
    let mut next_unknown: u64 = UNKNOWN_IMPORT_BASE;
    let mut descriptor: u64 = image_base + u64::from(dir.virtual_address);
    for _ in 0..MAX_IMPORT_DESCRIPTORS {
        let Ok(original_first_thunk): Result<u32> = cpu.mem.read_u32(descriptor) else {
            break;
        };
        let Ok(name_rva): Result<u32> = cpu.mem.read_u32(descriptor + 12) else {
            break;
        };
        let Ok(first_thunk): Result<u32> = cpu.mem.read_u32(descriptor + 16) else {
            break;
        };
        if name_rva == 0 || first_thunk == 0 {
            break;
        }
        let dll: String = read_cstr(&cpu.mem, image_base + u64::from(name_rva), 64)
            .unwrap_or_else(|| "?".to_owned());
        let lookup_rva: u32 = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        for i in 0..MAX_IMPORT_THUNKS as u64 {
            let lookup: u64 = image_base + u64::from(lookup_rva) + i * ptr;
            let slot: u64 = image_base + u64::from(first_thunk) + i * ptr;
            let Some(entry): Option<u64> = read_va(&cpu.mem, mode, lookup) else {
                break;
            };
            if entry == 0 {
                break;
            }
            let label: String = if entry & ordinal_flag != 0 {
                format!("{dll}!#{}", entry & 0xFFFF)
            } else {
                let name: String = read_cstr(&cpu.mem, image_base + (entry & 0x7FFF_FFFF) + 2, 128)
                    .unwrap_or_else(|| "?".to_owned());
                format!("{dll}!{name}")
            };
            let bare: &str = label.rsplit('!').next().unwrap_or(label.as_str());
            match env.export_addr(bare) {
                Some(addr) => {
                    if write_va(&mut cpu.mem, mode, slot, addr) {
                        out.resolved += 1;
                    }
                }
                None => {
                    let addr: u64 = next_unknown;
                    next_unknown += UNKNOWN_IMPORT_STRIDE;
                    let _ = write_va(&mut cpu.mem, mode, slot, addr);
                    out.unknown_by_addr.insert(addr, label.clone());
                    out.unresolved_names.push(label);
                }
            }
        }
        descriptor += 20;
    }
    out
}

fn tls_callback_addresses(cpu: &Cpu, img: &PeImage, image_base: u64) -> Vec<u64> {
    let Some(dir): Option<DataDirectory> = directory(img, DIRECTORY_TLS) else {
        return Vec::new();
    };
    let mode: CpuMode = cpu.mode;
    let ptr: u64 = u64::from(mode.ptr_size());
    let tls_dir: u64 = image_base + u64::from(dir.virtual_address);
    let Some(callbacks): Option<u64> = read_va(&cpu.mem, mode, tls_dir + 3 * ptr) else {
        return Vec::new();
    };
    if callbacks == 0 {
        return Vec::new();
    }
    let mut out: Vec<u64> = Vec::new();
    for i in 0..MAX_TLS_CALLBACKS as u64 {
        let Some(callback): Option<u64> = read_va(&cpu.mem, mode, callbacks + i * ptr) else {
            break;
        };
        if callback == 0 {
            break;
        }
        out.push(callback);
    }
    out
}

fn run_tls_callbacks(
    cpu: &mut Cpu,
    host: &mut StubHost,
    img: &PeImage,
    image_base: u64,
    image_hi: u64,
    budget: u64,
) -> Vec<TlsCallbackRun> {
    let callbacks: Vec<u64> = tls_callback_addresses(cpu, img, image_base);
    if callbacks.is_empty() {
        return Vec::new();
    }
    let mode: CpuMode = cpu.mode;
    let per_callback: u64 = (budget / callbacks.len() as u64).max(1);
    let mut runs: Vec<TlsCallbackRun> = Vec::with_capacity(callbacks.len());
    for callback in callbacks {
        if callback < image_base || callback >= image_hi || !cpu.mem.is_mapped(callback) {
            runs.push(TlsCallbackRun {
                callback_va: callback,
                steps: 0,
                outcome: "callback address lies outside the mapped image; not executed".to_owned(),
                returned: false,
            });
            continue;
        }
        reset_registers(cpu);
        let mut sp: u64 = cpu.regs.get(Reg::Rsp);
        match mode {
            CpuMode::Bits32 => {
                for value in [0u64, DLL_PROCESS_ATTACH, image_base, TLS_RETURN_SENTINEL] {
                    sp = sp.wrapping_sub(4);
                    let _ = cpu.mem.write_u32(sp, value as u32);
                }
            }
            CpuMode::Bits64 => {
                cpu.regs.set(Reg::Rcx, image_base);
                cpu.regs.set(Reg::Rdx, DLL_PROCESS_ATTACH);
                cpu.regs.set(Reg::R8, 0);
                sp = sp.wrapping_sub(0x28);
                let _ = cpu.mem.write_u64(sp, TLS_RETURN_SENTINEL);
            }
        }
        cpu.regs.set(Reg::Rsp, sp);
        cpu.regs.rip = callback;
        let mut steps: u64 = 0;
        let mut returned: bool = false;
        let mut outcome: String = String::new();
        while steps < per_callback {
            if cpu.regs.rip == TLS_RETURN_SENTINEL {
                returned = true;
                break;
            }
            steps += 1;
            let exit: ExitReason = match cpu.run(host, 1) {
                Ok(exit) => exit,
                Err(e) => {
                    outcome = format!("emulator error: {e}");
                    break;
                }
            };
            if let Some(why) = host.halted.take() {
                outcome = format!("halted: {why}");
                break;
            }
            match exit {
                ExitReason::StepCap(_) => {}
                ExitReason::JumpedOutOfRange { to, .. } if to == TLS_RETURN_SENTINEL => {
                    returned = true;
                    break;
                }
                other => {
                    outcome = format!("{other:?}");
                    break;
                }
            }
        }
        if returned {
            outcome = format!("returned after {steps} steps");
        } else if outcome.is_empty() {
            outcome = format!("step budget {per_callback} exhausted");
        }
        runs.push(TlsCallbackRun {
            callback_va: callback,
            steps,
            outcome,
            returned,
        });
    }
    runs
}

fn run_until_oep(
    cpu: &mut Cpu,
    host: &mut StubHost,
    image_base: u64,
    stub_lo: u64,
    capacity: u64,
    step_cap: u64,
) -> Result<(ExitReason, u64)> {
    let image_hi: u64 = image_base + capacity;
    let mut steps: u64 = 0;
    let mut entered_stub: bool = false;
    loop {
        if steps >= step_cap {
            return Ok((ExitReason::StepCap(steps), steps));
        }
        steps += 1;
        let ip: u64 = cpu.regs.rip;
        let in_stub: bool = ip >= stub_lo && ip < image_hi;
        if in_stub {
            entered_stub = true;
        } else if entered_stub && ip >= image_base && ip < stub_lo {
            return Ok((ExitReason::JumpedOutOfRange { from: ip, to: ip }, steps));
        }
        let exit: ExitReason = cpu.run(host, 1)?;
        if host.halted.is_some() {
            return Ok((exit, steps));
        }
        match exit {
            ExitReason::StepCap(_) => {}
            other => return Ok((other, steps)),
        }
    }
}

fn count_content_mutation(
    recovered: &[u8],
    packed: &[u8],
    img: &PeImage,
    stub_names: &[&[u8]],
) -> usize {
    let mut mutated: usize = 0;
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if stub_names.contains(&name) {
            continue;
        }
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        if start >= end {
            continue;
        }
        let dst: usize = sec.virtual_address as usize;
        if dst >= recovered.len() {
            continue;
        }
        let span: usize = (end - start).min(recovered.len() - dst);
        mutated += recovered[dst..dst + span]
            .iter()
            .zip(packed[start..start + span].iter())
            .filter(|(a, b): &(&u8, &u8)| a != b)
            .count();
    }
    mutated
}

fn content_recovery_pct(
    original: &[u8],
    recovered: &[u8],
    baseline: &[u8],
    config: &EmulationConfig<'_>,
) -> Result<f64> {
    let img: PeImage = crate::packers::pe_sections::parse_pe_image(original)?;
    let compare_len: usize = recovered.len().min(baseline.len());
    let mut total: usize = 0;
    let mut matching: usize = 0;
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if config.stub_section_names.contains(&name)
            || config.content_exclude.contains(&name)
            || name == b".reloc"
            || name == b".idata"
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn whole_image_identical_is_100() {
        let a: Vec<u8> = vec![1, 2, 3, 4];
        assert!((whole_image_recovery_pct(&a, &a) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reached_oep_requires_mutation_and_oep() {
        let mut u: EmulatedUnpack = EmulatedUnpack {
            image_base: 0,
            size_of_image: 0,
            entry_point_rva: 0,
            stub_section_rva: 0,
            recovered_memory_image: vec![],
            exit_reason: String::new(),
            oep_rva: Some(0x1000),
            content_bytes_mutated_by_stub: 0,
            steps_executed: 0,
            content_recovery_pct: None,
            whole_image_recovery_pct: None,
            section_report: None,
            neutralized: Vec::new(),
            neutralized_dropped: 0,
            resolved_imports: 0,
            unresolved_imports: Vec::new(),
            tls_callbacks: Vec::new(),
        };
        assert!(
            !u.reached_oep(),
            "oep without mutation is not a real unpack"
        );
        u.content_bytes_mutated_by_stub = 10;
        assert!(u.reached_oep());
        u.oep_rva = None;
        assert!(
            !u.reached_oep(),
            "mutation without oep transfer is not done"
        );
    }
}
