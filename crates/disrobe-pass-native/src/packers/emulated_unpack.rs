#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

use crate::error::Result;
use crate::packers::pe_sections::PeImage;
use crate::packers::section_recovery::{
    SectionRecoveryReport, build_loaded_image, emulated_image_capacity, section_recovery_report,
};
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const EMU_STACK_BASE: u64 = 0x0080_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const EMU_HEAP_BASE: u64 = 0x2000_0000;
const EMU_HEAP_SIZE: u64 = 0x0800_0000;
const EMU_TEB_BASE: u64 = 0x7EFD_E000;
const EMU_PEB_BASE: u64 = 0x7EFD_D000;
const EMU_LAZY_PAGE_BUDGET: u32 = 65_536;

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
}

impl EmulatedUnpack {
    #[must_use]
    pub fn reached_oep(&self) -> bool {
        self.oep_rva.is_some() && self.content_bytes_mutated_by_stub > 0
    }
}

#[derive(Debug, Default)]
struct StubHost {
    heap_brk: u64,
    heap_end: u64,
    halted: bool,
}

impl StubHost {
    fn new() -> Self {
        Self {
            heap_brk: EMU_HEAP_BASE,
            heap_end: EMU_HEAP_BASE.saturating_add(EMU_HEAP_SIZE),
            halted: false,
        }
    }
}

impl HostCall for StubHost {
    fn dispatch(&mut self, _target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
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
        Ok(true)
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

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.mem.map(image_base, capacity, Perm::RWX)?;
    map_image(&mut cpu, packed, img, image_base);
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);
    map_synthetic_teb(&mut cpu)?;
    cpu.enable_seh_dispatch();

    cpu.regs.rip = image_base + u64::from(img.entry_point_rva);
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
    ] {
        cpu.regs.write_sized(reg, 0, 32);
    }

    let stub_lo: u64 = image_base + u64::from(stub_rva);
    let (exit, steps): (ExitReason, u64) =
        run_until_oep(&mut cpu, image_base, stub_lo, capacity, config.step_cap)?;
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

    Ok(EmulatedUnpack {
        image_base,
        size_of_image: img.size_of_image,
        entry_point_rva: img.entry_point_rva,
        stub_section_rva: stub_rva,
        recovered_memory_image: recovered,
        exit_reason: format!("{exit:?} final_rip=0x{final_rip:08x}"),
        oep_rva,
        content_bytes_mutated_by_stub: content_mutated,
        steps_executed: steps,
        content_recovery_pct: content_pct,
        whole_image_recovery_pct: whole_pct,
        section_report: report,
    })
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

fn run_until_oep(
    cpu: &mut Cpu,
    image_base: u64,
    stub_lo: u64,
    capacity: u64,
    step_cap: u64,
) -> Result<(ExitReason, u64)> {
    let image_hi: u64 = image_base + capacity;
    let mut steps: u64 = 0;
    let mut entered_stub: bool = false;
    let mut host: StubHost = StubHost::new();
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
        let exit: ExitReason = cpu.run(&mut host, 1)?;
        if host.halted {
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
