use disrobe_bytes::ByteReader;

use super::{AotCodeRange, AotMethod};
use crate::pe::{DataDirectory, PeBitness, PeImage, SectionHeader};

const EXCEPTION_DIRECTORY_INDEX: usize = 3;
const AMD64_MACHINE: u16 = 0x8664;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const RUNTIME_FUNCTION_SIZE: usize = 12;
const MAX_EXCEPTION_DIRECTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUNTIME_FUNCTIONS: usize = 1_048_576;

fn invalid(at: usize, reason: &'static str) -> crate::error::Error {
    crate::error::Error::InvalidAotMethodBoundary {
        offset: u32::try_from(at).map_or(u32::MAX, |offset: u32| offset),
        reason,
    }
}

fn executable_file_backed_range(
    image: &[u8],
    pe: &PeImage,
    range: AotCodeRange,
) -> crate::error::Result<()> {
    let length_u32: u32 = range
        .end_rva
        .checked_sub(range.start_rva)
        .ok_or_else(|| invalid(0, "runtime-function range is reversed"))?;
    let length: usize = usize::try_from(length_u32)
        .map_err(|_: std::num::TryFromIntError| invalid(0, "code range size does not fit usize"))?;
    if length == 0 {
        return Err(invalid(0, "runtime-function range is empty"));
    }
    pe.slice_exact_file_backed_rva(image, range.start_rva, length)
        .ok_or_else(|| invalid(0, "runtime-function range is not entirely file backed"))?;
    let section: &SectionHeader = pe
        .sections
        .iter()
        .find(|section: &&SectionHeader| {
            let Some(raw_end): Option<u32> = section.virtual_address.checked_add(section.raw_size)
            else {
                return false;
            };
            range.start_rva >= section.virtual_address && range.end_rva <= raw_end
        })
        .ok_or_else(|| invalid(0, "runtime-function range has no owning PE section"))?;
    if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
        return Err(invalid(0, "runtime-function range is not executable"));
    }
    Ok(())
}

fn read_ranges(image: &[u8], pe: &PeImage) -> crate::error::Result<Option<Vec<AotCodeRange>>> {
    let Some(directory): Option<DataDirectory> =
        pe.data_directories.get(EXCEPTION_DIRECTORY_INDEX).copied()
    else {
        return Ok(None);
    };
    if directory.rva == 0 && directory.size == 0 {
        return Ok(None);
    }
    if directory.rva == 0 || directory.size == 0 {
        return Err(invalid(0, "exception directory has a partial location"));
    }
    let size: usize = usize::try_from(directory.size).map_err(|_: std::num::TryFromIntError| {
        invalid(0, "exception directory size does not fit usize")
    })?;
    if size > MAX_EXCEPTION_DIRECTORY_BYTES {
        return Err(invalid(0, "exception directory exceeds parser byte limit"));
    }
    if !size.is_multiple_of(RUNTIME_FUNCTION_SIZE) {
        return Err(invalid(
            size - size % RUNTIME_FUNCTION_SIZE,
            "exception directory has a partial runtime-function record",
        ));
    }
    let count: usize = size / RUNTIME_FUNCTION_SIZE;
    if count > MAX_RUNTIME_FUNCTIONS {
        return Err(invalid(0, "runtime-function count exceeds parser limit"));
    }
    let bytes: &[u8] = pe
        .slice_exact_file_backed_rva(image, directory.rva, size)
        .ok_or_else(|| invalid(0, "exception directory is not entirely file backed"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let mut ranges: Vec<AotCodeRange> = Vec::new();
    ranges
        .try_reserve_exact(count)
        .map_err(|_: std::collections::TryReserveError| {
            invalid(0, "runtime-function allocation failed")
        })?;
    let mut previous: Option<AotCodeRange> = None;
    for index in 0..count {
        let at: usize = index
            .checked_mul(RUNTIME_FUNCTION_SIZE)
            .ok_or_else(|| invalid(0, "runtime-function offset overflowed"))?;
        let start_rva: u32 = reader
            .read_u32_le()
            .map_err(|_: disrobe_bytes::ByteReadError| {
                invalid(at, "runtime-function start RVA is truncated")
            })?;
        let end_rva: u32 = reader
            .read_u32_le()
            .map_err(|_: disrobe_bytes::ByteReadError| {
                invalid(at, "runtime-function end RVA is truncated")
            })?;
        let unwind_rva: u32 = reader
            .read_u32_le()
            .map_err(|_: disrobe_bytes::ByteReadError| {
                invalid(at, "runtime-function unwind RVA is truncated")
            })?;
        pe.slice_exact_file_backed_rva(image, unwind_rva, 1)
            .ok_or_else(|| invalid(at, "runtime-function unwind data is not file backed"))?;
        let range: AotCodeRange = AotCodeRange { start_rva, end_rva };
        if start_rva >= end_rva {
            return Err(invalid(at, "runtime-function range is empty or reversed"));
        }
        if let Some(prior) = previous {
            if start_rva == prior.start_rva {
                return Err(invalid(at, "runtime-function begin RVA is duplicated"));
            }
            if start_rva < prior.start_rva {
                return Err(invalid(at, "runtime-function records are unsorted"));
            }
            if start_rva < prior.end_rva {
                return Err(invalid(at, "runtime-function ranges overlap"));
            }
        }
        executable_file_backed_range(image, pe, range).map_err(|error: crate::error::Error| {
            match error {
                crate::error::Error::InvalidAotMethodBoundary { reason, .. } => invalid(at, reason),
                other => other,
            }
        })?;
        ranges.push(range);
        previous = Some(range);
    }
    Ok(Some(ranges))
}

pub(super) fn attach_method_boundaries(
    image: &[u8],
    methods: &mut [AotMethod],
) -> crate::error::Result<Option<PeImage>> {
    if !image.starts_with(b"MZ") {
        return Ok(None);
    }
    let pe: PeImage = crate::pe::parse(image)?;
    if pe.bitness != PeBitness::Pe32Plus || pe.machine != AMD64_MACHINE {
        return Ok(None);
    }
    let Some(ranges): Option<Vec<AotCodeRange>> = read_ranges(image, &pe)? else {
        return Ok(Some(pe));
    };
    let mut assignments: Vec<(usize, AotCodeRange)> = Vec::new();
    assignments
        .try_reserve_exact(methods.len().min(ranges.len()))
        .map_err(|_: std::collections::TryReserveError| {
            invalid(0, "method-boundary assignment allocation failed")
        })?;
    for (method_index, method) in methods.iter().enumerate() {
        let Some(entrypoint_rva): Option<u32> = method.entrypoint_rva else {
            continue;
        };
        if let Ok(range_index) =
            ranges.binary_search_by_key(&entrypoint_rva, |range: &AotCodeRange| range.start_rva)
        {
            let range: AotCodeRange = *ranges
                .get(range_index)
                .ok_or_else(|| invalid(0, "method-boundary range index is absent"))?;
            assignments.push((method_index, range));
        }
    }
    for (method_index, range) in assignments {
        methods
            .get_mut(method_index)
            .ok_or_else(|| invalid(0, "method-boundary method index is absent"))?
            .code_range = Some(range);
    }
    Ok(Some(pe))
}
