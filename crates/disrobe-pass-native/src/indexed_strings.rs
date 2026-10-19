use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::{BinaryFormat, Object as _, ObjectSection as _, SectionKind};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const MIN_DISTINCT_INDICES: usize = 8;
const MAX_CANDIDATES: usize = 16;
const MAX_SITES_PER_CANDIDATE: usize = 8192;
const MAX_COLLECTED_SITES: usize = 32_768;
const MAX_EXECUTABLE_SCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_MAPPED_IMAGE_BYTES: usize = 512 * 1024 * 1024;
const MAX_EMULATION_STEPS: u64 = 100_000;
const MAX_TOTAL_EMULATION_STEPS: u64 = 32_000_000;
const MAX_LITERAL_BYTES: usize = 4096;
const MAX_RECOVERED_LITERAL_BYTES: usize = 16 * 1024 * 1024;
const STACK_BASE: u64 = 0x1800_0000;
const STACK_SIZE: u64 = 0x0010_0000;
const RETURN_SENTINEL: u64 = 0x7fff_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedStringAnnotation {
    pub site: u64,
    pub accessor: u64,
    pub index: u32,
    pub literal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedStringRefusal {
    pub site: u64,
    pub accessor: u64,
    pub index: u32,
    pub kind: IndexedStringRefusalKind,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexedStringRefusalKind {
    CandidateSiteBound,
    CandidateBound,
    Mapping,
    EmulationFault,
    FuelExhausted,
    AggregateFuelExhausted,
    DidNotReturn,
    NullReturn,
    OutputRead,
    InvalidOutput,
    OutputBound,
    WriteLogBound,
}

impl IndexedStringRefusalKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CandidateSiteBound => "DR-NATIVE-0802",
            Self::CandidateBound => "DR-NATIVE-0810",
            Self::Mapping => "DR-NATIVE-0803",
            Self::EmulationFault => "DR-NATIVE-0804",
            Self::FuelExhausted => "DR-NATIVE-0805",
            Self::AggregateFuelExhausted => "DR-NATIVE-0816",
            Self::DidNotReturn => "DR-NATIVE-0806",
            Self::NullReturn => "DR-NATIVE-0807",
            Self::OutputRead => "DR-NATIVE-0808",
            Self::InvalidOutput => "DR-NATIVE-0809",
            Self::OutputBound => "DR-NATIVE-0815",
            Self::WriteLogBound => "DR-NATIVE-0812",
        }
    }
}

impl fmt::Display for IndexedStringRefusalKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedStringRecovery {
    pub annotations: Vec<IndexedStringAnnotation>,
    pub refusals: Vec<IndexedStringRefusal>,
}

#[derive(Debug, Clone)]
struct LoadedSection {
    address: u64,
    bytes: Vec<u8>,
    executable: bool,
    writable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CallSite {
    site: u64,
    accessor: u64,
    index: u32,
}

#[derive(Debug, Default)]
struct AccessorHost;

impl HostCall for AccessorHost {
    fn dispatch(&mut self, _target: u64, _regs: &mut Regs, _mem: &mut Memory) -> Result<bool> {
        Ok(false)
    }
}

pub fn recover_indexed_strings(bytes: &[u8]) -> Result<IndexedStringRecovery> {
    let file: object::File<'_> = object::File::parse(bytes)
        .map_err(|error: object::Error| Error::ObjectParse(error.to_string()))?;
    let Some(mode): Option<CpuMode> = cpu_mode(&file) else {
        return Ok(IndexedStringRecovery::default());
    };
    let sections: Vec<LoadedSection> = load_sections(&file)?;
    if sections.is_empty() {
        return Ok(IndexedStringRecovery::default());
    }
    let candidates: BTreeMap<u64, Vec<CallSite>> = collect_candidates(&sections, mode)?;
    let mut recovery: IndexedStringRecovery = IndexedStringRecovery::default();
    let mut remaining_literal_bytes: usize = MAX_RECOVERED_LITERAL_BYTES;
    let mut remaining_steps: u64 = MAX_TOTAL_EMULATION_STEPS;
    for (candidate_index, (accessor, sites)) in candidates.into_iter().enumerate() {
        if candidate_index < MAX_CANDIDATES {
            recover_candidate(
                &sections,
                mode,
                accessor,
                &sites,
                &mut remaining_literal_bytes,
                &mut remaining_steps,
                &mut recovery,
            );
        } else {
            for site in sites {
                recovery.refusals.push(refusal(
                    site,
                    IndexedStringRefusalKind::CandidateBound,
                    format!("indexed-string accessor exceeds {MAX_CANDIDATES}-candidate bound"),
                ));
            }
        }
    }
    recovery
        .annotations
        .sort_by_key(|annotation: &IndexedStringAnnotation| {
            (annotation.site, annotation.accessor, annotation.index)
        });
    recovery
        .refusals
        .sort_by_key(|refusal: &IndexedStringRefusal| {
            (
                refusal.site,
                refusal.accessor,
                refusal.index,
                refusal.kind.code(),
            )
        });
    Ok(recovery)
}

fn cpu_mode(file: &object::File<'_>) -> Option<CpuMode> {
    match (file.format(), file.architecture()) {
        (BinaryFormat::Pe, object::Architecture::X86_64) => Some(CpuMode::Bits64),
        _ => None,
    }
}

fn load_sections(file: &object::File<'_>) -> Result<Vec<LoadedSection>> {
    let mut total: usize = 0;
    let mut sections: Vec<LoadedSection> = Vec::new();
    for section in file.sections() {
        let address: u64 = section.address();
        let section_size: usize = usize::try_from(section.size()).map_err(|_| {
            Error::ObjectParse(
                "DR-NATIVE-0801: indexed-string section size exceeds address space".to_owned(),
            )
        })?;
        if address == 0 || section_size == 0 {
            continue;
        }
        let data: &[u8] = section.data().map_err(|error: object::Error| {
            Error::ObjectParse(format!(
                "DR-NATIVE-0811: indexed-string section at 0x{address:x} cannot be read: {error}"
            ))
        })?;
        let mapped_size: usize = section_size.max(data.len());
        total = total.checked_add(mapped_size).ok_or_else(|| {
            Error::ObjectParse(
                "DR-NATIVE-0801: indexed-string mapped image size overflow".to_owned(),
            )
        })?;
        if total > MAX_MAPPED_IMAGE_BYTES {
            return Err(Error::ObjectParse(format!(
                "DR-NATIVE-0801: indexed-string mapped image exceeds {MAX_MAPPED_IMAGE_BYTES} bytes"
            )));
        }
        let kind: SectionKind = section.kind();
        let executable: bool = matches!(kind, SectionKind::Text)
            || section
                .name()
                .is_ok_and(|name: &str| name == ".text" || name.starts_with(".text"));
        let writable: bool = matches!(kind, SectionKind::Data | SectionKind::UninitializedData);
        sections.push(LoadedSection {
            address,
            bytes: zero_extended(data, mapped_size),
            executable,
            writable,
        });
    }
    sections.sort_by_key(|section: &LoadedSection| section.address);
    Ok(sections)
}

fn zero_extended(data: &[u8], size: usize) -> Vec<u8> {
    let mut mapped: Vec<u8> = vec![0; size];
    mapped[..data.len()].copy_from_slice(data);
    mapped
}

fn collect_candidates(
    sections: &[LoadedSection],
    mode: CpuMode,
) -> Result<BTreeMap<u64, Vec<CallSite>>> {
    let mut groups: BTreeMap<u64, Vec<CallSite>> = BTreeMap::new();
    let mut scanned_bytes: usize = 0;
    let mut collected_sites: usize = 0;
    for section in sections
        .iter()
        .filter(|section: &&LoadedSection| section.executable)
    {
        scanned_bytes = scanned_bytes
            .checked_add(section.bytes.len())
            .ok_or_else(|| {
                Error::ObjectParse(
                    "DR-NATIVE-0814: indexed-string executable scan size overflow".to_owned(),
                )
            })?;
        if scanned_bytes > MAX_EXECUTABLE_SCAN_BYTES {
            return Err(Error::ObjectParse(format!(
                "DR-NATIVE-0814: indexed-string executable scan exceeds {MAX_EXECUTABLE_SCAN_BYTES} bytes"
            )));
        }
        let mut decoder: Decoder<'_> = Decoder::with_ip(
            mode.bits(),
            &section.bytes,
            section.address,
            DecoderOptions::NONE,
        );
        let mut previous: Option<Instruction> = None;
        while decoder.can_decode() {
            let instruction: Instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }
            if let (Some(previous_instruction), Some(accessor)) =
                (previous.as_ref(), direct_call_target(&instruction))
                && let Some(index) = immediate_ecx(previous_instruction)
            {
                collected_sites = collected_sites.checked_add(1).ok_or_else(|| {
                    Error::ObjectParse(
                        "DR-NATIVE-0813: indexed-string call-site count overflow".to_owned(),
                    )
                })?;
                if collected_sites > MAX_COLLECTED_SITES {
                    return Err(Error::ObjectParse(format!(
                        "DR-NATIVE-0813: indexed-string call-site scan exceeds {MAX_COLLECTED_SITES} sites"
                    )));
                }
                groups.entry(accessor).or_default().push(CallSite {
                    site: instruction.ip(),
                    accessor,
                    index,
                });
            }
            previous = Some(instruction);
        }
    }
    groups.retain(|_, sites: &mut Vec<CallSite>| {
        sites.sort();
        let indices: BTreeSet<u32> = sites.iter().map(|site: &CallSite| site.index).collect();
        indices.len() >= MIN_DISTINCT_INDICES
    });
    Ok(groups)
}

fn direct_call_target(instruction: &Instruction) -> Option<u64> {
    (instruction.flow_control() == FlowControl::Call
        && matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ))
    .then_some(instruction.near_branch_target())
}

fn immediate_ecx(instruction: &Instruction) -> Option<u32> {
    let register: Register = instruction.op0_register();
    if matches!(register, Register::ECX | Register::RCX) {
        if instruction.mnemonic() == Mnemonic::Mov
            && matches!(
                instruction.op1_kind(),
                OpKind::Immediate32 | OpKind::Immediate32to64
            )
        {
            return Some(instruction.immediate32());
        }
        if instruction.mnemonic() == Mnemonic::Xor && instruction.op1_register() == register {
            return Some(0);
        }
    }
    None
}

fn recover_candidate(
    sections: &[LoadedSection],
    mode: CpuMode,
    accessor: u64,
    sites: &[CallSite],
    remaining_literal_bytes: &mut usize,
    remaining_steps: &mut u64,
    recovery: &mut IndexedStringRecovery,
) {
    if *remaining_steps == 0 {
        refuse_aggregate_fuel(sites, recovery);
        return;
    }
    if *remaining_literal_bytes == 0 {
        refuse_output_bound(sites, recovery);
        return;
    }
    let mut cpu: Cpu = match prepare_cpu(sections, mode) {
        Ok(cpu) => cpu,
        Err(error) => {
            for site in sites {
                recovery.refusals.push(refusal(
                    *site,
                    IndexedStringRefusalKind::Mapping,
                    error.to_string(),
                ));
            }
            return;
        }
    };
    let bounded_site_count: usize = sites.len().min(MAX_SITES_PER_CANDIDATE);
    for (position, site) in sites.iter().take(bounded_site_count).enumerate() {
        if *remaining_steps == 0 {
            refuse_aggregate_fuel(&sites[position..], recovery);
            return;
        }
        let before: u64 = cpu.steps_executed();
        let step_cap: u64 = (*remaining_steps).min(MAX_EMULATION_STEPS);
        let result: core::result::Result<String, IndexedStringRefusal> =
            run_accessor(&mut cpu, sections, mode, *site, step_cap);
        *remaining_steps =
            remaining_steps.saturating_sub(cpu.steps_executed().saturating_sub(before));
        match result {
            Ok(literal) => {
                if literal.len() > *remaining_literal_bytes {
                    *remaining_literal_bytes = 0;
                    refuse_output_bound(&sites[position..], recovery);
                    return;
                }
                *remaining_literal_bytes -= literal.len();
                recovery.annotations.push(IndexedStringAnnotation {
                    site: site.site,
                    accessor,
                    index: site.index,
                    literal,
                });
            }
            Err(site_refusal) => {
                let kind: IndexedStringRefusalKind = site_refusal.kind;
                let contaminated: bool = matches!(
                    kind,
                    IndexedStringRefusalKind::WriteLogBound | IndexedStringRefusalKind::Mapping
                );
                recovery.refusals.push(site_refusal);
                if contaminated {
                    for remaining in sites.iter().skip(position + 1) {
                        recovery.refusals.push(refusal(
                            *remaining,
                            kind,
                            "a prior accessor execution left the emulator image untrusted"
                                .to_owned(),
                        ));
                    }
                    return;
                }
            }
        }
    }
    for site in sites.iter().skip(bounded_site_count) {
        recovery.refusals.push(refusal(
            *site,
            IndexedStringRefusalKind::CandidateSiteBound,
            format!("indexed-string site exceeds {MAX_SITES_PER_CANDIDATE}-site candidate bound"),
        ));
    }
}

fn refuse_aggregate_fuel(sites: &[CallSite], recovery: &mut IndexedStringRecovery) {
    for site in sites {
        recovery.refusals.push(refusal(
            *site,
            IndexedStringRefusalKind::AggregateFuelExhausted,
            format!("indexed-string recovery exhausted its {MAX_TOTAL_EMULATION_STEPS}-step aggregate fuel bound"),
        ));
    }
}

fn refuse_output_bound(sites: &[CallSite], recovery: &mut IndexedStringRecovery) {
    for site in sites {
        recovery.refusals.push(refusal(
            *site,
            IndexedStringRefusalKind::OutputBound,
            format!(
                "indexed-string output exceeds {MAX_RECOVERED_LITERAL_BYTES}-byte aggregate bound"
            ),
        ));
    }
}

fn prepare_cpu(sections: &[LoadedSection], mode: CpuMode) -> Result<Cpu> {
    let mut cpu: Cpu = Cpu::new(mode);
    for section in sections {
        if ranges_overlap(
            section.address,
            section.bytes.len() as u64,
            STACK_BASE,
            STACK_SIZE,
        ) || ranges_overlap(
            section.address,
            section.bytes.len() as u64,
            RETURN_SENTINEL,
            1,
        ) {
            return Err(Error::ObjectParse(
                "DR-NATIVE-0803: indexed-string input overlaps reserved emulator memory".to_owned(),
            ));
        }
        let perm: Perm = if section.executable {
            Perm::RX
        } else if section.writable {
            Perm::RW
        } else {
            Perm::R
        };
        cpu.mem
            .map(section.address, section.bytes.len() as u64, perm)?;
        cpu.mem.write_unchecked(section.address, &section.bytes);
    }
    cpu.mem.map(STACK_BASE, STACK_SIZE, Perm::RW)?;
    Ok(cpu)
}

fn ranges_overlap(left: u64, left_len: u64, right: u64, right_len: u64) -> bool {
    let Some(left_end): Option<u64> = left.checked_add(left_len) else {
        return true;
    };
    let Some(right_end): Option<u64> = right.checked_add(right_len) else {
        return true;
    };
    left < right_end && right < left_end
}

fn run_accessor(
    cpu: &mut Cpu,
    sections: &[LoadedSection],
    mode: CpuMode,
    site: CallSite,
    step_cap: u64,
) -> core::result::Result<String, IndexedStringRefusal> {
    cpu.regs = Regs::new(mode);
    let stack: u64 = STACK_BASE + STACK_SIZE - 0x1000;
    seed_call(cpu, mode, site.index, stack).map_err(|error: Error| {
        refusal(site, IndexedStringRefusalKind::Mapping, error.to_string())
    })?;
    cpu.regs.rip = site.accessor;
    cpu.mem.enable_write_log();
    let mut host: AccessorHost = AccessorHost;
    let run_result: Result<ExitReason> = cpu.run(&mut host, step_cap);
    let writes: Vec<(u64, u8)> = cpu.mem.write_log().to_vec();
    let log_truncated: bool = cpu.mem.write_log_truncated();
    let execution: core::result::Result<(), IndexedStringRefusal> = match run_result {
        Ok(ExitReason::JumpedOutOfRange { to, .. }) if to == RETURN_SENTINEL => Ok(()),
        Ok(ExitReason::StepCap(_)) => Err(refusal(
            site,
            if step_cap < MAX_EMULATION_STEPS {
                IndexedStringRefusalKind::AggregateFuelExhausted
            } else {
                IndexedStringRefusalKind::FuelExhausted
            },
            format!("accessor exceeded its {step_cap}-step fuel bound"),
        )),
        Ok(other) => Err(refusal(
            site,
            IndexedStringRefusalKind::DidNotReturn,
            format!("accessor did not return cleanly: {other:?}"),
        )),
        Err(error) => Err(refusal(
            site,
            IndexedStringRefusalKind::EmulationFault,
            error.to_string(),
        )),
    };
    let literal: core::result::Result<String, IndexedStringRefusal> = match execution {
        Ok(()) => read_literal(&cpu.mem, cpu.regs.get(Reg::Rax), site),
        Err(refusal) => Err(refusal),
    };
    restore_writes(cpu, sections, &writes, site)?;
    if log_truncated {
        return Err(refusal(
            site,
            IndexedStringRefusalKind::WriteLogBound,
            "accessor exceeded the emulator write-log bound".to_owned(),
        ));
    }
    literal
}

fn restore_writes(
    cpu: &mut Cpu,
    sections: &[LoadedSection],
    writes: &[(u64, u8)],
    site: CallSite,
) -> core::result::Result<(), IndexedStringRefusal> {
    let mut restored: BTreeSet<u64> = BTreeSet::new();
    for &(address, _) in writes.iter().rev() {
        if !restored.insert(address) {
            continue;
        }
        let Some(value): Option<u8> = baseline_byte(sections, address) else {
            return Err(refusal(
                site,
                IndexedStringRefusalKind::Mapping,
                format!("write at 0x{address:x} has no mapped baseline"),
            ));
        };
        cpu.mem.write_u8(address, value).map_err(|error: Error| {
            refusal(site, IndexedStringRefusalKind::Mapping, error.to_string())
        })?;
    }
    Ok(())
}

fn baseline_byte(sections: &[LoadedSection], address: u64) -> Option<u8> {
    if (STACK_BASE..STACK_BASE + STACK_SIZE).contains(&address) {
        return Some(0);
    }
    sections.iter().find_map(|section: &LoadedSection| {
        let offset: usize = usize::try_from(address.checked_sub(section.address)?).ok()?;
        section.bytes.get(offset).copied()
    })
}

fn seed_call(cpu: &mut Cpu, mode: CpuMode, index: u32, stack: u64) -> Result<()> {
    match mode {
        CpuMode::Bits64 => {
            let return_slot: u64 = stack - 0x28;
            cpu.regs.set(Reg::Rcx, u64::from(index));
            cpu.regs.set(Reg::Rsp, return_slot);
            cpu.mem.write_u64(return_slot, RETURN_SENTINEL)?;
        }
        CpuMode::Bits32 => {
            let return_slot: u64 = stack - 8;
            let argument_slot: u64 = stack - 4;
            cpu.regs.set(Reg::Rsp, return_slot);
            cpu.mem.write_u32(return_slot, RETURN_SENTINEL as u32)?;
            cpu.mem.write_u32(argument_slot, index)?;
        }
    }
    Ok(())
}

fn read_literal(
    memory: &Memory,
    address: u64,
    site: CallSite,
) -> core::result::Result<String, IndexedStringRefusal> {
    if address == 0 {
        return Err(refusal(
            site,
            IndexedStringRefusalKind::NullReturn,
            "accessor returned a null pointer".to_owned(),
        ));
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    for offset in 0..MAX_LITERAL_BYTES {
        let byte: u8 = memory
            .read_u8(address.wrapping_add(offset as u64))
            .map_err(|error: Error| {
                refusal(
                    site,
                    IndexedStringRefusalKind::OutputRead,
                    error.to_string(),
                )
            })?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|error: std::string::FromUtf8Error| {
                refusal(
                    site,
                    IndexedStringRefusalKind::InvalidOutput,
                    error.to_string(),
                )
            });
        }
        bytes.push(byte);
    }
    Err(refusal(
        site,
        IndexedStringRefusalKind::InvalidOutput,
        format!("accessor result has no NUL terminator within {MAX_LITERAL_BYTES} bytes"),
    ))
}

fn refusal(site: CallSite, kind: IndexedStringRefusalKind, reason: String) -> IndexedStringRefusal {
    IndexedStringRefusal {
        site: site.site,
        accessor: site.accessor,
        index: site.index,
        kind,
        reason: format!("{kind}: {reason}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_fuel_is_shared_across_sites_and_candidates() {
        let bytes: &[u8] =
            include_bytes!("../../../corpus/native/string-accessor/string-accessor-msvc-v1.dll");
        let file: object::File<'_> = object::File::parse(bytes).expect("compiler-built PE");
        let sections: Vec<LoadedSection> = load_sections(&file).expect("bounded sections");
        let candidates: BTreeMap<u64, Vec<CallSite>> =
            collect_candidates(&sections, CpuMode::Bits64).expect("accessor sites");
        let (&accessor, sites): (&u64, &Vec<CallSite>) =
            candidates.first_key_value().expect("compiled accessor");
        assert!(sites.len() >= 3);
        let mut cpu: Cpu = prepare_cpu(&sections, CpuMode::Bits64).expect("emulator image");
        let literal: String = run_accessor(
            &mut cpu,
            &sections,
            CpuMode::Bits64,
            sites[0],
            MAX_EMULATION_STEPS,
        )
        .expect("original accessor returns");
        let first_steps: u64 = cpu.steps_executed();
        assert!(first_steps > 1 && first_steps < MAX_EMULATION_STEPS);
        let mut remaining_steps: u64 = first_steps + 1;
        let mut remaining_bytes: usize = MAX_RECOVERED_LITERAL_BYTES;
        let mut recovery: IndexedStringRecovery = IndexedStringRecovery::default();
        recover_candidate(
            &sections,
            CpuMode::Bits64,
            accessor,
            sites,
            &mut remaining_bytes,
            &mut remaining_steps,
            &mut recovery,
        );
        assert_eq!(remaining_steps, 0);
        assert_eq!(recovery.annotations.len(), 1);
        assert_eq!(recovery.annotations[0].literal, literal);
        assert_eq!(remaining_bytes, MAX_RECOVERED_LITERAL_BYTES - literal.len());
        assert_eq!(recovery.refusals.len(), sites.len() - 1);
        assert!(
            recovery
                .refusals
                .iter()
                .all(|entry: &IndexedStringRefusal| entry.kind
                    == IndexedStringRefusalKind::AggregateFuelExhausted
                    && entry.reason.starts_with("DR-NATIVE-0816"))
        );
        recover_candidate(
            &sections,
            CpuMode::Bits64,
            accessor,
            sites,
            &mut remaining_bytes,
            &mut remaining_steps,
            &mut recovery,
        );
        assert_eq!(recovery.annotations.len(), 1);
        assert_eq!(recovery.refusals.len(), sites.len() * 2 - 1);
    }

    #[test]
    fn per_site_fuel_keeps_its_distinct_refusal() {
        let bytes: &[u8] =
            include_bytes!("../../../corpus/native/string-accessor/string-accessor-msvc-v1.dll");
        let file: object::File<'_> = object::File::parse(bytes).expect("compiler-built PE");
        let mut sections: Vec<LoadedSection> = load_sections(&file).expect("bounded sections");
        let candidates: BTreeMap<u64, Vec<CallSite>> =
            collect_candidates(&sections, CpuMode::Bits64).expect("accessor sites");
        let (&accessor, sites): (&u64, &Vec<CallSite>) =
            candidates.first_key_value().expect("compiled accessor");
        let mut mutations: usize = 0;
        for section in &mut sections {
            if let Some(offset) = accessor
                .checked_sub(section.address)
                .and_then(|offset: u64| usize::try_from(offset).ok())
                && let Some(entry) = section
                    .bytes
                    .get_mut(offset..)
                    .and_then(|tail: &mut [u8]| tail.get_mut(..2))
            {
                entry.copy_from_slice(&[0xeb, 0xfe]);
                mutations += 1;
            }
        }
        assert_eq!(mutations, 1);
        let mut cpu: Cpu = prepare_cpu(&sections, CpuMode::Bits64).expect("mutated image");
        let refused: IndexedStringRefusal = run_accessor(
            &mut cpu,
            &sections,
            CpuMode::Bits64,
            sites[0],
            MAX_EMULATION_STEPS,
        )
        .expect_err("loop exhausts per-site fuel");
        assert_eq!(refused.kind, IndexedStringRefusalKind::FuelExhausted);
        assert!(refused.reason.starts_with("DR-NATIVE-0805"));
        assert_eq!(cpu.steps_executed(), MAX_EMULATION_STEPS);
    }
}
