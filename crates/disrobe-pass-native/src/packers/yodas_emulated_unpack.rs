#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::if_not_else,
    clippy::manual_range_contains
)]

use crate::error::{Error, Result};
use crate::packers::mew_unpack::aplib_decode_bytetagged;
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use crate::packers::section_recovery::{
    SectionRecoveryReport, build_loaded_image, section_recovery_report,
};
use crate::stub_emu::mem::MAX_MAP_BYTES;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

pub const YODAS_STUB_SECTION: &[u8] = b".yC0";

const YC2_MARKER: &[u8] = b"yC2.0";

const APLIB_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YodasSectionDescriptor {
    pub dest_rva: u32,
    pub src_rva: u32,
    pub packed_len: u32,
    pub unpacked_len: u32,
}

pub const YODAS_DELTA_PROLOGUE: [u8; 9] = [0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED];

pub const DESCRIPTOR_TABLE_TAG: [u8; 4] = *b"yCDT";
const DESCRIPTOR_LEN: usize = 16;

const EMU_STACK_BASE: u64 = 0x0030_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const EMU_TEB_BASE: u64 = 0x7EFD_E000;
const EMU_PEB_BASE: u64 = 0x7EFD_D000;
const EMU_LAZY_PAGE_BUDGET: u32 = 65_536;
const STEP_CAP_YC: u64 = 200_000_000;

const STUB_LOADER_REBUILT: &[&[u8]] = &[b".reloc", b".idata"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YodasStubProgress {
    ReachedOriginalEntry { oep_rva: u32 },
    StalledInStub { final_rva: u32, exit: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct YodasEmulatedUnpack {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub stub_section_rva: u32,

    pub has_yc2_marker: bool,
    pub anti_debug_int3_in_stub: u32,

    pub descriptors: Vec<YodasSectionDescriptor>,

    pub stub_progress: YodasStubProgress,
    pub content_bytes_mutated_by_stub: usize,

    pub recovered_memory_image: Vec<u8>,

    pub emulated_memory_image: Vec<u8>,

    pub content_recovery_pct: Option<f64>,
    pub whole_image_recovery_pct: Option<f64>,
    pub section_report: Option<SectionRecoveryReport>,
}

impl YodasEmulatedUnpack {
    #[must_use]
    pub fn reached_oep(&self) -> bool {
        matches!(
            self.stub_progress,
            YodasStubProgress::ReachedOriginalEntry { .. }
        ) && self.content_bytes_mutated_by_stub > 0
    }

    #[must_use]
    pub fn oep_rva(&self) -> Option<u32> {
        match self.stub_progress {
            YodasStubProgress::ReachedOriginalEntry { oep_rva } => Some(oep_rva),
            YodasStubProgress::StalledInStub { .. } => None,
        }
    }
}

#[derive(Debug, Default)]
struct YodasStubHost {
    halted: bool,
}

impl HostCall for YodasStubHost {
    fn dispatch(&mut self, _target: u64, regs: &mut Regs, _mem: &mut Memory) -> Result<bool> {
        regs.write_sized(Reg::Rax, 0, 32);
        Ok(true)
    }
}

pub fn unpack_yodas_emulated(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<YodasEmulatedUnpack> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = img.section_by_name(YODAS_STUB_SECTION).ok_or_else(|| {
        Error::SignatureDb(
            "Yoda's Crypter: .yC0 stub section absent - not an our-format Yoda's image".to_owned(),
        )
    })?;
    let stub_rva: u32 = stub.virtual_address;
    let image_base: u64 = img.image_base;
    let capacity: u64 = u64::from(img.size_of_image)
        .max(last_section_end_va(&img))
        .min(MAX_MAP_BYTES);

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.mem.map(image_base, capacity, Perm::RWX)?;
    map_image(&mut cpu, packed, &img, image_base);
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
    let mut host: YodasStubHost = YodasStubHost::default();
    let anti_debug_int3: u32 = count_int3_in_stub(packed, &img, stub_rva);
    let (exit, oep): (ExitReason, Option<u32>) =
        run_until_oep(&mut cpu, &mut host, image_base, stub_lo, capacity)?;
    let final_rva: u32 = (cpu.regs.rip.saturating_sub(image_base)) as u32;

    let emulated: Vec<u8> = cpu.mem.read_lossy(image_base, capacity as usize);

    let descriptors: Vec<YodasSectionDescriptor> = parse_descriptor_table(packed, &img, stub)?;
    let recovered: Vec<u8> =
        rebuild_static_image(packed, &img, &descriptors, capacity as usize, oep)?;
    let content_mutated: usize = count_content_mutation(&recovered, packed, &img);

    let stub_progress: YodasStubProgress = match oep {
        Some(oep_rva) if content_mutated > 0 => YodasStubProgress::ReachedOriginalEntry { oep_rva },
        _ => YodasStubProgress::StalledInStub {
            final_rva,
            exit: format!("{exit:?}"),
        },
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
                section_recovery_report(orig, &recovered, &[YODAS_STUB_SECTION])?;
            (Some(content), Some(whole), Some(report))
        }
        None => (None, None, None),
    };

    Ok(YodasEmulatedUnpack {
        image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        stub_section_rva: stub_rva,
        has_yc2_marker: crate::packers::pe_sections::find_subsequence(packed, YC2_MARKER).is_some(),
        anti_debug_int3_in_stub: anti_debug_int3,
        descriptors,
        stub_progress,
        content_bytes_mutated_by_stub: content_mutated,
        recovered_memory_image: recovered,
        emulated_memory_image: emulated,
        content_recovery_pct: content_pct,
        whole_image_recovery_pct: whole_pct,
        section_report: report,
    })
}

fn parse_descriptor_table(
    packed: &[u8],
    img: &PeImage,
    stub: &PeSection,
) -> Result<Vec<YodasSectionDescriptor>> {
    let (start, end): (usize, usize) = stub.raw_range(packed.len()).ok_or_else(|| {
        Error::SignatureDb("Yoda's Crypter: .yC0 stub raw range out of bounds".to_owned())
    })?;
    let body: &[u8] = &packed[start..end];
    let tag_off: usize = crate::packers::pe_sections::find_subsequence(body, &DESCRIPTOR_TABLE_TAG)
        .ok_or_else(|| {
            Error::SignatureDb(
                "Yoda's Crypter: descriptor-table tag 'yCDT' absent from .yC0 stub".to_owned(),
            )
        })?;
    let mut cursor: usize = tag_off + DESCRIPTOR_TABLE_TAG.len();
    let image_span: u64 = u64::from(img.size_of_image).max(last_section_end_va(img));
    let mut descriptors: Vec<YodasSectionDescriptor> = Vec::new();
    loop {
        if cursor + DESCRIPTOR_LEN > body.len() {
            return Err(Error::Truncated {
                needed: start + cursor + DESCRIPTOR_LEN,
                had: packed.len(),
            });
        }
        let dest_rva: u32 = read_u32(body, cursor)?;
        let src_rva: u32 = read_u32(body, cursor + 4)?;
        let packed_len: u32 = read_u32(body, cursor + 8)?;
        let unpacked_len: u32 = read_u32(body, cursor + 12)?;
        cursor += DESCRIPTOR_LEN;
        if dest_rva == 0 && src_rva == 0 && packed_len == 0 && unpacked_len == 0 {
            break;
        }
        if u64::from(dest_rva) + u64::from(unpacked_len) > image_span {
            return Err(Error::SignatureDb(format!(
                "Yoda's Crypter: descriptor dest 0x{dest_rva:x}+0x{unpacked_len:x} exceeds image"
            )));
        }
        if unpacked_len as usize > APLIB_MAX_OUTPUT_BYTES {
            return Err(Error::SignatureDb(
                "Yoda's Crypter: descriptor unpacked length exceeds 64 MiB safety cap".to_owned(),
            ));
        }
        descriptors.push(YodasSectionDescriptor {
            dest_rva,
            src_rva,
            packed_len,
            unpacked_len,
        });
        if descriptors.len() > 64 {
            break;
        }
    }
    Ok(descriptors)
}

fn rebuild_static_image(
    packed: &[u8],
    img: &PeImage,
    descriptors: &[YodasSectionDescriptor],
    capacity: usize,
    oep: Option<u32>,
) -> Result<Vec<u8>> {
    let image_base: u64 = img.image_base;
    let mut image: Vec<u8> = vec![0u8; capacity];
    let hdr: usize = 0x1000.min(packed.len()).min(capacity);
    image[..hdr].copy_from_slice(&packed[..hdr]);
    for sec in &img.sections {
        if sec.name_trimmed() == YODAS_STUB_SECTION {
            continue;
        }
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        let dst: usize = sec.virtual_address as usize;
        if dst >= capacity || start >= end {
            continue;
        }
        let span: usize = (end - start).min(capacity - dst);
        image[dst..dst + span].copy_from_slice(&packed[start..start + span]);
    }
    for desc in descriptors {
        let src_off: usize = rva_to_file_off(img, desc.src_rva).ok_or_else(|| {
            Error::SignatureDb(format!(
                "Yoda's Crypter: descriptor src rva 0x{:x} not in any section",
                desc.src_rva
            ))
        })?;
        let src_end: usize = src_off
            .checked_add(desc.packed_len as usize)
            .ok_or(Error::UnknownFormat)?;
        if src_end > packed.len() {
            return Err(Error::Truncated {
                needed: src_end,
                had: packed.len(),
            });
        }
        let stream: &[u8] = &packed[src_off..src_end];
        let decompressed: Vec<u8> = aplib_decode_bytetagged(stream, desc.unpacked_len as usize)?;
        if decompressed.len() != desc.unpacked_len as usize {
            return Err(Error::SignatureDb(format!(
                "Yoda's Crypter: aPLib output {} != descriptor unpacked_len {} for dest 0x{:x}",
                decompressed.len(),
                desc.unpacked_len,
                desc.dest_rva
            )));
        }
        let dst: usize = desc.dest_rva as usize;
        let dst_end: usize = dst
            .checked_add(decompressed.len())
            .ok_or(Error::UnknownFormat)?;
        if dst_end > image.len() {
            return Err(Error::SignatureDb(format!(
                "Yoda's Crypter: decompressed dest 0x{dst:x}..0x{dst_end:x} exceeds image"
            )));
        }
        image[dst..dst_end].copy_from_slice(&decompressed);
    }
    if let Some(oep_rva) = oep {
        write_oep_into_header(&mut image, image_base, oep_rva);
    }
    Ok(image)
}

fn write_oep_into_header(image: &mut [u8], _image_base: u64, oep_rva: u32) {
    let Ok(e_lfanew): Result<u32> = read_u32_at(image, 0x3C) else {
        return;
    };
    let opt_off: usize = e_lfanew as usize + 24;
    let field: usize = opt_off + 16;
    if field + 4 <= image.len() {
        image[field..field + 4].copy_from_slice(&oep_rva.to_le_bytes());
    }
}

fn rva_to_file_off(img: &PeImage, rva: u32) -> Option<usize> {
    for sec in &img.sections {
        let span: u32 = sec.virtual_size.max(sec.raw_size);
        if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(span) {
            return Some((sec.raw_pointer + (rva - sec.virtual_address)) as usize);
        }
    }
    None
}

fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    read_u32_at(b, off)
}

fn read_u32_at(b: &[u8], off: usize) -> Result<u32> {
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

fn last_section_end_va(img: &PeImage) -> u64 {
    img.sections
        .iter()
        .map(|s: &PeSection| {
            u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size))
        })
        .max()
        .unwrap_or(0)
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
    host: &mut YodasStubHost,
    image_base: u64,
    stub_lo: u64,
    capacity: u64,
) -> Result<(ExitReason, Option<u32>)> {
    let image_hi: u64 = image_base + capacity;
    let mut steps: u64 = 0;
    let mut entered_stub: bool = false;
    loop {
        if steps >= STEP_CAP_YC {
            return Ok((ExitReason::StepCap(steps), None));
        }
        steps += 1;
        let ip: u64 = cpu.regs.rip;
        let in_stub: bool = ip >= stub_lo && ip < image_hi;
        if in_stub {
            entered_stub = true;
        } else if entered_stub && ip >= image_base && ip < stub_lo {
            return Ok((
                ExitReason::JumpedOutOfRange { from: ip, to: ip },
                Some((ip - image_base) as u32),
            ));
        }
        let exit: ExitReason = cpu.run(host, 1)?;
        if host.halted {
            return Ok((exit, None));
        }
        match exit {
            ExitReason::StepCap(_) => {}
            ExitReason::JumpedOutOfRange { to, .. }
                if to >= image_base && to < stub_lo && (to - image_base) as u32 != 0 =>
            {
                return Ok((
                    ExitReason::JumpedOutOfRange { from: to, to },
                    Some((to - image_base) as u32),
                ));
            }
            other => return Ok((other, None)),
        }
    }
}

fn count_int3_in_stub(packed: &[u8], img: &PeImage, stub_rva: u32) -> u32 {
    let Some(stub): Option<&PeSection> = img.section_containing_rva(stub_rva) else {
        return 0;
    };
    let Some((start, end)): Option<(usize, usize)> = stub.raw_range(packed.len()) else {
        return 0;
    };
    packed[start..end]
        .iter()
        .fold(0u32, |n: u32, b: &u8| n + u32::from(*b == 0xCC))
}

fn count_content_mutation(recovered: &[u8], packed: &[u8], img: &PeImage) -> usize {
    let mut mutated: usize = 0;
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if name == YODAS_STUB_SECTION {
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

fn content_recovery_pct(original: &[u8], recovered: &[u8], baseline: &[u8]) -> Result<f64> {
    let img: PeImage = parse_pe_image(original)?;
    let compare_len: usize = recovered.len().min(baseline.len());
    let mut total: usize = 0;
    let mut matching: usize = 0;
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if STUB_LOADER_REBUILT.contains(&name) || name == YODAS_STUB_SECTION {
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
    fn rejects_image_without_stub_section() {
        let mut buf: Vec<u8> = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let r: Result<YodasEmulatedUnpack> = unpack_yodas_emulated(&buf, None);
        assert!(r.is_err());
    }

    #[test]
    fn whole_image_identical_is_100() {
        let a: Vec<u8> = vec![1, 2, 3, 4];
        assert!((whole_image_recovery_pct(&a, &a) - 100.0).abs() < f64::EPSILON);
    }
}
