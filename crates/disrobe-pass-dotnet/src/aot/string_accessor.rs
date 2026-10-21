use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{AotCodeRange, AotMetadataAttribution, AotStackTraceMap};
use crate::pe::{PeBitness, PeImage};
use disrobe_pass_native::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};
use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

const AMD64_MACHINE: u16 = 0x8664;
const MAX_ACCESSOR_BODIES: usize = 65_536;
const MAX_ACCESSOR_BODY_BYTES: usize = 256 * 1024;
const MAX_ACCESSOR_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACCESSOR_CALL_SITES: usize = 16_384;
const MAX_ACCESSORS: usize = 256;
const MIN_ACCESSOR_CALL_SITES: usize = 2;
const MIN_ACCESSOR_TABLES: usize = 2;
const MAX_FROZEN_ARRAY_LENGTH: u32 = 16 * 1024 * 1024;
const METHOD_TABLE_HAS_COMPONENT_SIZE: u32 = 0x8000_0000;
const METHOD_TABLE_ELEMENT_TYPE_MASK: u32 = 0x7C00_0000;
const METHOD_TABLE_ELEMENT_TYPE_SHIFT: u32 = 26;
const METHOD_TABLE_KIND_MASK: u32 = 0x0003_0000;
const METHOD_TABLE_KIND_PARAMETERIZED: u32 = 0x0002_0000;
const METHOD_TABLE_ELEMENT_TYPE_SZ_ARRAY: u32 = 0x18;
const FROZEN_ARRAY_LENGTH_OFFSET: u32 = 8;
const FROZEN_ARRAY_DATA_OFFSET: u32 = 0x10;
const MAX_DECODE_STEPS: u64 = 2_000_000;
const MAX_DECODED_LITERALS: usize = 16_384;
const MAX_DECODED_BYTES: u64 = 1024 * 1024;
const MAX_ALLOCATIONS_PER_INDEX: usize = 8;
const MAX_IMAGE_MAP_BYTES: u64 = 512 * 1024 * 1024;
const EMU_STACK_BASE: u64 = 0x7000_0000_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const EMU_SCRATCH_BASE: u64 = 0x7100_0000_0000;
const EMU_SCRATCH_SIZE: u64 = 0x0100_0000;
const EMU_SENTINEL_RET: u64 = 0x7f00_dead_0000_beef;
const PAGE_MASK: u64 = 0xFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AotStringAccessorCallSite {
    pub call_rva: u32,
    pub caller_start_rva: u32,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AotFrozenArray {
    pub object_rva: u32,
    pub method_table_rva: u32,
    pub component_size: u16,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotStringLiteral {
    pub index: u32,
    pub value: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_rvas: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotStringDecodeRefusal {
    pub index: u32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotStringAccessor {
    pub accessor_rva: u32,
    pub end_rva: u32,
    pub tables: Vec<AotFrozenArray>,
    pub call_sites: Vec<AotStringAccessorCallSite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub literals: Vec<AotStringLiteral>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decode_refusals: Vec<AotStringDecodeRefusal>,
}

fn read_u32_rva(image: &[u8], pe: &PeImage, rva: u32) -> Option<u32> {
    let bytes: [u8; 4] = pe
        .slice_exact_file_backed_rva(image, rva, 4)?
        .try_into()
        .ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_rva(image: &[u8], pe: &PeImage, rva: u32) -> Option<u64> {
    let bytes: [u8; 8] = pe
        .slice_exact_file_backed_rva(image, rva, 8)?
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn frozen_array(
    image: &[u8],
    pe: &PeImage,
    region: Option<AotCodeRange>,
    object_rva: u32,
) -> Option<AotFrozenArray> {
    if let Some(region) = region
        && (object_rva < region.start_rva || object_rva >= region.end_rva)
    {
        return None;
    }
    let method_table_va: u64 = read_u64_rva(image, pe, object_rva)?;
    let method_table_rva: u32 = u32::try_from(method_table_va.checked_sub(pe.image_base)?).ok()?;
    let flags: u32 = read_u32_rva(image, pe, method_table_rva)?;
    let component_size: u16 = u16::try_from(flags & 0xFFFF).ok()?;
    if flags & METHOD_TABLE_HAS_COMPONENT_SIZE == 0
        || !matches!(component_size, 1 | 2 | 4 | 8)
        || (flags & METHOD_TABLE_ELEMENT_TYPE_MASK) >> METHOD_TABLE_ELEMENT_TYPE_SHIFT
            != METHOD_TABLE_ELEMENT_TYPE_SZ_ARRAY
        || flags & METHOD_TABLE_KIND_MASK != METHOD_TABLE_KIND_PARAMETERIZED
    {
        return None;
    }
    let length: u32 = read_u32_rva(
        image,
        pe,
        object_rva.checked_add(FROZEN_ARRAY_LENGTH_OFFSET)?,
    )?;
    if length > MAX_FROZEN_ARRAY_LENGTH {
        return None;
    }
    let data_bytes: u32 = length.checked_mul(u32::from(component_size))?;
    let data_rva: u32 = object_rva.checked_add(FROZEN_ARRAY_DATA_OFFSET)?;
    if let Some(region) = region
        && data_rva.checked_add(data_bytes)? > region.end_rva
    {
        return None;
    }
    if data_bytes > 0 {
        pe.slice_exact_file_backed_rva(image, data_rva, usize::try_from(data_bytes).ok()?)?;
    }
    Some(AotFrozenArray {
        object_rva,
        method_table_rva,
        component_size,
        length,
    })
}

fn rip_relative_lea(instruction: &DisasmInsn) -> Option<u32> {
    let rva: u32 = u32::try_from(instruction.address).ok()?;
    let bytes: &[u8] = instruction.bytes.as_slice();
    let (rex, rest): (u8, &[u8]) = match bytes {
        [rex @ 0x48..=0x4F, rest @ ..] => (*rex, rest),
        _ => return None,
    };
    let [0x8d, modrm, a, b, c, d] = rest else {
        return None;
    };
    if rex & 0x08 == 0 || modrm & 0xC7 != 0x05 {
        return None;
    }
    let length: u32 = u32::try_from(bytes.len()).ok()?;
    let target: i64 = i64::from(rva.checked_add(length)?)
        .checked_add(i64::from(i32::from_le_bytes([*a, *b, *c, *d])))?;
    u32::try_from(target).ok()
}

fn call_target(instruction: &DisasmInsn) -> Option<u32> {
    let rva: u32 = u32::try_from(instruction.address).ok()?;
    let [0xe8, a, b, c, d] = instruction.bytes.as_slice() else {
        return None;
    };
    let target: i64 = i64::from(rva.checked_add(5)?)
        .checked_add(i64::from(i32::from_le_bytes([*a, *b, *c, *d])))?;
    u32::try_from(target).ok()
}

fn ecx_immediate(instruction: &DisasmInsn) -> Option<u32> {
    match instruction.bytes.as_slice() {
        [0xb9, a, b, c, d] => Some(u32::from_le_bytes([*a, *b, *c, *d])),
        [0x31 | 0x33, 0xc9] => Some(0),
        _ => None,
    }
}

fn body_ranges(
    attribution: &AotMetadataAttribution,
    stack_trace_map: &AotStackTraceMap,
) -> BTreeSet<AotCodeRange> {
    attribution
        .methods
        .iter()
        .filter_map(|method| method.code_range)
        .chain(
            stack_trace_map
                .methods
                .iter()
                .filter_map(|method| method.code_range),
        )
        .filter(|range| range.start_rva < range.end_rva)
        .collect()
}

fn body_instructions(image: &[u8], pe: &PeImage, range: AotCodeRange) -> Option<Vec<DisasmInsn>> {
    let length: usize = usize::try_from(range.end_rva.checked_sub(range.start_rva)?).ok()?;
    if length == 0 || length > MAX_ACCESSOR_BODY_BYTES {
        return None;
    }
    let bytes: &[u8] = pe.slice_exact_file_backed_rva(image, range.start_rva, length)?;
    disassemble(Arch::X86_64, u64::from(range.start_rva), bytes).ok()
}

#[must_use]
pub fn recover_string_accessors(
    image: &[u8],
    attribution: &AotMetadataAttribution,
    stack_trace_map: &AotStackTraceMap,
    frozen_region: Option<AotCodeRange>,
) -> Vec<AotStringAccessor> {
    if !image.starts_with(b"MZ") {
        return Vec::new();
    }
    let Ok(pe) = crate::pe::parse(image) else {
        return Vec::new();
    };
    if pe.bitness != PeBitness::Pe32Plus || pe.machine != AMD64_MACHINE {
        return Vec::new();
    }
    let Ok(Some(ranges)): crate::error::Result<Option<Vec<AotCodeRange>>> =
        super::method_boundaries::read_ranges(image, &pe)
    else {
        return Vec::new();
    };
    let bodies: BTreeSet<AotCodeRange> = body_ranges(attribution, stack_trace_map);
    if bodies.len() > MAX_ACCESSOR_BODIES {
        return Vec::new();
    }
    let mut total: usize = 0;
    let mut sites: BTreeMap<u32, Vec<AotStringAccessorCallSite>> = BTreeMap::new();
    let mut site_count: usize = 0;
    for range in &bodies {
        let length: usize = usize::try_from(range.end_rva - range.start_rva).unwrap_or(usize::MAX);
        total = total.saturating_add(length);
        if total > MAX_ACCESSOR_TOTAL_BYTES {
            return Vec::new();
        }
        let Some(instructions) = body_instructions(image, &pe, *range) else {
            continue;
        };
        for pair in instructions.windows(2) {
            let [load, call] = pair else {
                continue;
            };
            let (Some(index), Some(target)) = (ecx_immediate(load), call_target(call)) else {
                continue;
            };
            let Ok(call_rva) = u32::try_from(call.address) else {
                continue;
            };
            site_count += 1;
            if site_count > MAX_ACCESSOR_CALL_SITES {
                return Vec::new();
            }
            sites
                .entry(target)
                .or_default()
                .push(AotStringAccessorCallSite {
                    call_rva,
                    caller_start_rva: range.start_rva,
                    index,
                });
        }
    }
    let mut accessors: Vec<AotStringAccessor> = Vec::new();
    for (target, mut call_sites) in sites {
        if call_sites.len() < MIN_ACCESSOR_CALL_SITES {
            continue;
        }
        let Ok(index) =
            ranges.binary_search_by_key(&target, |range: &AotCodeRange| range.start_rva)
        else {
            continue;
        };
        let Some(body) = ranges.get(index).copied() else {
            continue;
        };
        let Some(instructions) = body_instructions(image, &pe, body) else {
            continue;
        };
        let tables: BTreeSet<AotFrozenArray> = instructions
            .iter()
            .filter_map(rip_relative_lea)
            .filter_map(|object_rva| frozen_array(image, &pe, frozen_region, object_rva))
            .collect();
        if tables.len() < MIN_ACCESSOR_TABLES {
            continue;
        }
        if accessors.len() == MAX_ACCESSORS {
            return Vec::new();
        }
        call_sites.sort_unstable();
        call_sites.dedup();
        accessors.push(AotStringAccessor {
            accessor_rva: body.start_rva,
            end_rva: body.end_rva,
            tables: tables.into_iter().collect(),
            call_sites,
            literals: Vec::new(),
            decode_refusals: Vec::new(),
        });
    }
    accessors
}

struct Allocation {
    address: u64,
    component_size: u16,
    length: u32,
}

struct AccessorHost {
    image_base: u64,
    scratch_next: u64,
    allocations: Vec<Allocation>,
}

impl AccessorHost {
    fn array_method_table(mem: &Memory, method_table_va: u64) -> Option<u16> {
        let flags: u32 = mem.read_u32(method_table_va).ok()?;
        let component_size: u16 = u16::try_from(flags & 0xFFFF).ok()?;
        (flags & METHOD_TABLE_HAS_COMPONENT_SIZE != 0
            && matches!(component_size, 1 | 2 | 4 | 8)
            && (flags & METHOD_TABLE_ELEMENT_TYPE_MASK) >> METHOD_TABLE_ELEMENT_TYPE_SHIFT
                == METHOD_TABLE_ELEMENT_TYPE_SZ_ARRAY
            && flags & METHOD_TABLE_KIND_MASK == METHOD_TABLE_KIND_PARAMETERIZED)
            .then_some(component_size)
    }
}

impl HostCall for AccessorHost {
    fn dispatch(
        &mut self,
        _target: u64,
        regs: &mut Regs,
        mem: &mut Memory,
    ) -> disrobe_pass_native::error::Result<bool> {
        let method_table_va: u64 = regs.get(Reg::Rcx);
        if method_table_va < self.image_base {
            return Ok(false);
        }
        let Some(component_size) = Self::array_method_table(mem, method_table_va) else {
            return Ok(false);
        };
        let Ok(length) = u32::try_from(regs.get(Reg::Rdx)) else {
            return Ok(false);
        };
        if self.allocations.len() >= MAX_ALLOCATIONS_PER_INDEX {
            return Ok(false);
        }
        let data_bytes: u64 = u64::from(length).saturating_mul(u64::from(component_size));
        let total: u64 = data_bytes
            .saturating_add(u64::from(FROZEN_ARRAY_DATA_OFFSET))
            .saturating_add(0xF)
            & !0xF;
        if data_bytes > MAX_DECODED_BYTES
            || self.scratch_next.saturating_add(total) > EMU_SCRATCH_BASE + EMU_SCRATCH_SIZE
        {
            return Ok(false);
        }
        let address: u64 = self.scratch_next;
        mem.write_u64(address, method_table_va)?;
        mem.write_u32(address + u64::from(FROZEN_ARRAY_LENGTH_OFFSET), length)?;
        self.scratch_next += total;
        self.allocations.push(Allocation {
            address,
            component_size,
            length,
        });
        regs.set(Reg::Rax, address);
        Ok(true)
    }
}

fn map_image(cpu: &mut Cpu, image: &[u8], pe: &PeImage, body: (u64, u64)) -> Option<()> {
    let mut mapped: u64 = 0;
    for section in &pe.sections {
        let size: u64 = u64::from(section.virtual_size.max(section.raw_size));
        if size == 0 {
            continue;
        }
        let address: u64 = pe
            .image_base
            .checked_add(u64::from(section.virtual_address))?;
        let section_end: u64 = address.checked_add(size)?;
        let raw_start: usize = usize::try_from(section.raw_pointer).ok()?;
        let raw_len: usize = usize::try_from(u64::from(section.raw_size).min(size)).ok()?;
        let raw: &[u8] = image.get(raw_start..raw_start.checked_add(raw_len)?)?;
        let (map_at, map_len, perm): (u64, u64, Perm) = if body.0 >= address && body.0 < section_end
        {
            (
                body.0,
                body.1.min(section_end).checked_sub(body.0)?,
                Perm::RX,
            )
        } else {
            (address, size, Perm::R)
        };
        mapped = mapped.checked_add(map_len)?;
        if mapped > MAX_IMAGE_MAP_BYTES {
            return None;
        }
        cpu.mem.map(map_at, map_len, perm).ok()?;
        let skip: usize = usize::try_from(map_at.checked_sub(address)?).ok()?;
        let take: usize = usize::try_from(map_len).ok()?;
        if let Some(bytes) = raw.get(skip..raw.len().min(skip.checked_add(take)?)) {
            cpu.mem.write_unchecked(map_at, bytes);
        }
    }
    Some(())
}

fn decode_index(
    cpu: &mut Cpu,
    image_base: u64,
    accessor_va: u64,
    index: u32,
) -> Result<String, String> {
    cpu.regs = Regs::new(CpuMode::Bits64);
    let stack_top: u64 = EMU_STACK_BASE + EMU_STACK_SIZE - 0x1000;
    let shadow: u64 = stack_top - 0x20 - 8;
    cpu.mem
        .write_u64(shadow, EMU_SENTINEL_RET)
        .map_err(|error| error.to_string())?;
    cpu.regs.set(Reg::Rsp, shadow);
    cpu.regs.set(Reg::Rcx, u64::from(index));
    cpu.regs.rip = accessor_va;
    let mut host = AccessorHost {
        image_base,
        scratch_next: EMU_SCRATCH_BASE,
        allocations: Vec::new(),
    };
    let exit: ExitReason = cpu
        .run(&mut host, MAX_DECODE_STEPS)
        .map_err(|error| error.to_string())?;
    let ExitReason::HostHalt(_) = exit else {
        return Err(format!(
            "accessor did not reach a call the host declines: {exit:?} at rip 0x{:x} (mapped {}) after {} allocation(s); accessor 0x{accessor_va:x}",
            cpu.regs.rip,
            cpu.mem.is_mapped(cpu.regs.rip),
            host.allocations.len()
        ));
    };
    let mut byte_buffers = host
        .allocations
        .iter()
        .filter(|allocation| allocation.component_size == 1);
    let (Some(buffer), None) = (byte_buffers.next(), byte_buffers.next()) else {
        return Err("accessor did not allocate exactly one byte buffer".to_owned());
    };
    let length: usize = usize::try_from(buffer.length).map_err(|error| error.to_string())?;
    let data: Vec<u8> = cpu
        .mem
        .read(buffer.address + u64::from(FROZEN_ARRAY_DATA_OFFSET), length)
        .map_err(|error| error.to_string())?;
    String::from_utf8(data).map_err(|_| "decoded bytes are not UTF-8".to_owned())
}

pub fn decode_string_accessors(image: &[u8], accessors: &mut [AotStringAccessor]) {
    if accessors.is_empty() || !image.starts_with(b"MZ") {
        return;
    }
    let Ok(pe) = crate::pe::parse(image) else {
        return;
    };
    if pe.bitness != PeBitness::Pe32Plus || pe.machine != AMD64_MACHINE {
        return;
    }
    for accessor in accessors.iter_mut() {
        let body_start: u64 = (pe.image_base + u64::from(accessor.accessor_rva)) & !PAGE_MASK;
        let body_end: u64 = (pe.image_base + u64::from(accessor.end_rva) + PAGE_MASK) & !PAGE_MASK;
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
        if map_image(&mut cpu, image, &pe, (body_start, body_end)).is_none()
            || cpu
                .mem
                .map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)
                .is_err()
            || cpu
                .mem
                .map(EMU_SCRATCH_BASE, EMU_SCRATCH_SIZE, Perm::RW)
                .is_err()
        {
            return;
        }
        let accessor_va: u64 = pe.image_base + u64::from(accessor.accessor_rva);
        let mut indexes: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for site in &accessor.call_sites {
            indexes.entry(site.index).or_default().push(site.call_rva);
        }
        for (index, call_rvas) in indexes {
            if accessor.literals.len() == MAX_DECODED_LITERALS {
                break;
            }
            match decode_index(&mut cpu, pe.image_base, accessor_va, index) {
                Ok(value) => accessor.literals.push(AotStringLiteral {
                    index,
                    value,
                    call_rvas,
                }),
                Err(reason) => accessor
                    .decode_refusals
                    .push(AotStringDecodeRefusal { index, reason }),
            }
        }
    }
}
