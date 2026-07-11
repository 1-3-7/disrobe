use flate2::{Decompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};

use crate::peel::protector_resources::{
    MAX_RESOURCE_BYTES, RecoveredResource, is_complete_managed_assembly, map_embedded_resources,
};

const HEADER_MAGIC_MASK: u32 = 0x00FF_FFFF;
const HEADER_MAGIC: u32 = 0x007D_7A7B;
const STATIC_DEFLATE_MODE: u8 = 1;
const MAX_PARTS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryBudget {
    input_bytes: usize,
    output_bytes: usize,
    parts: usize,
}

impl RecoveryBudget {
    const fn standard() -> Self {
        Self {
            input_bytes: MAX_RESOURCE_BYTES,
            output_bytes: MAX_RESOURCE_BYTES,
            parts: MAX_PARTS,
        }
    }

    fn charge_input(&mut self, amount: usize) -> std::result::Result<(), String> {
        if amount > self.input_bytes {
            return Err(format!(
                "aggregate candidate input exceeds the {MAX_RESOURCE_BYTES}-byte limit"
            ));
        }
        self.input_bytes -= amount;
        Ok(())
    }

    fn charge_output(&mut self, amount: usize) -> std::result::Result<(), String> {
        if amount > self.output_bytes {
            return Err(format!(
                "aggregate declared output exceeds the {MAX_RESOURCE_BYTES}-byte limit"
            ));
        }
        self.output_bytes -= amount;
        Ok(())
    }

    fn charge_part(&mut self) -> std::result::Result<(), String> {
        if self.parts == 0 {
            return Err(format!(
                "aggregate part count exceeds the {MAX_PARTS}-part limit"
            ));
        }
        self.parts -= 1;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmartAssemblyResourceOutcome {
    Recovered(RecoveredResource),
    Unknown {
        resource_name: String,
        mode: u8,
    },
    Rejected {
        resource_name: String,
        reason: String,
    },
}

#[must_use]
pub fn recover_smartassembly_resources(image: &[u8]) -> Vec<SmartAssemblyResourceOutcome> {
    let mut budget: RecoveryBudget = RecoveryBudget::standard();
    let Some(outcomes): Option<Vec<SmartAssemblyResourceOutcome>> =
        map_embedded_resources(image, |resource_name, bytes| {
            recover_resource(resource_name, bytes, &mut budget)
        })
    else {
        return Vec::new();
    };
    outcomes
}

fn recover_resource(
    resource_name: &str,
    data: &[u8],
    budget: &mut RecoveryBudget,
) -> Option<SmartAssemblyResourceOutcome> {
    let header_bytes: [u8; 4] = data.get(..4)?.try_into().ok()?;
    let header: u32 = u32::from_le_bytes(header_bytes);
    if header & HEADER_MAGIC_MASK != HEADER_MAGIC {
        return None;
    }
    let mode: u8 = (header >> 24) as u8;
    if mode != STATIC_DEFLATE_MODE {
        return Some(SmartAssemblyResourceOutcome::Unknown {
            resource_name: resource_name.to_string(),
            mode,
        });
    }
    let resource_name: String = resource_name.to_string();
    let recovered: Vec<u8> = match decode_static_resource(data, budget) {
        Ok(bytes) => bytes,
        Err(reason) => {
            return Some(SmartAssemblyResourceOutcome::Rejected {
                resource_name,
                reason,
            });
        }
    };
    if !is_complete_managed_assembly(&recovered) {
        return Some(SmartAssemblyResourceOutcome::Rejected {
            resource_name,
            reason: "decoded bytes are not a bounded managed PE with an Assembly row".to_string(),
        });
    }
    Some(SmartAssemblyResourceOutcome::Recovered(RecoveredResource {
        name: resource_name,
        bytes: recovered,
    }))
}

fn decode_static_resource(
    data: &[u8],
    budget: &mut RecoveryBudget,
) -> std::result::Result<Vec<u8>, String> {
    budget.charge_input(data.len())?;
    let mut cursor: usize = 4;
    let total: usize = read_positive_i32(data, &mut cursor, "total inflated length")?;
    budget.charge_output(total)?;
    let reserve: usize = total
        .checked_add(1)
        .ok_or_else(|| "declared output length overflow".to_string())?;
    let mut output: Vec<u8> = Vec::new();
    output
        .try_reserve_exact(reserve)
        .map_err(|_error: std::collections::TryReserveError| {
            "declared output allocation failed".to_string()
        })?;
    let mut part_count: usize = 0;
    while output.len() < total {
        budget.charge_part()?;
        part_count += 1;
        let compressed_len: usize = read_positive_i32(data, &mut cursor, "compressed part length")?;
        let inflated_len: usize = read_positive_i32(data, &mut cursor, "inflated part length")?;
        let remaining_output: usize = total - output.len();
        if inflated_len > remaining_output {
            return Err(format!(
                "part {part_count} declares {inflated_len} output bytes with only {remaining_output} remaining"
            ));
        }
        let compressed_end: usize = cursor
            .checked_add(compressed_len)
            .ok_or_else(|| format!("part {part_count} compressed range overflow"))?;
        let compressed: &[u8] = data
            .get(cursor..compressed_end)
            .ok_or_else(|| format!("part {part_count} compressed bytes are truncated"))?;
        cursor = compressed_end;
        inflate_exact_part(compressed, inflated_len, part_count, &mut output)?;
    }
    if output.len() != total {
        return Err(format!(
            "aggregate output length {} does not match declared length {total}",
            output.len()
        ));
    }
    if cursor != data.len() {
        return Err(format!(
            "{} trailing byte(s) remain after the declared output",
            data.len() - cursor
        ));
    }
    Ok(output)
}

fn inflate_exact_part(
    compressed: &[u8],
    expected_len: usize,
    part_count: usize,
    output: &mut Vec<u8>,
) -> std::result::Result<(), String> {
    let output_start: usize = output.len();
    let output_window_len: usize = expected_len
        .checked_add(1)
        .ok_or_else(|| format!("part {part_count} output window overflow"))?;
    let expected_end: usize = output_start
        .checked_add(expected_len)
        .ok_or_else(|| format!("part {part_count} output range overflow"))?;
    let output_end: usize = output_start
        .checked_add(output_window_len)
        .ok_or_else(|| format!("part {part_count} output window range overflow"))?;
    output.resize(output_end, 0);
    let mut decoder: Decompress = Decompress::new(false);
    let status: Status = decoder
        .decompress(
            compressed,
            &mut output[output_start..output_end],
            FlushDecompress::Finish,
        )
        .map_err(|_error: flate2::DecompressError| {
            format!("part {part_count} raw DEFLATE stream is invalid")
        })?;
    let consumed: usize =
        usize::try_from(decoder.total_in()).map_err(|_error: std::num::TryFromIntError| {
            format!("part {part_count} consumed-byte count overflow")
        })?;
    let produced: usize =
        usize::try_from(decoder.total_out()).map_err(|_error: std::num::TryFromIntError| {
            format!("part {part_count} output-byte count overflow")
        })?;
    if status != Status::StreamEnd {
        return Err(format!(
            "part {part_count} raw DEFLATE stream did not reach its end"
        ));
    }
    if consumed != compressed.len() {
        return Err(format!(
            "part {part_count} consumed {consumed} of {} compressed bytes",
            compressed.len()
        ));
    }
    if produced != expected_len {
        return Err(format!(
            "part {part_count} produced {produced} bytes instead of {expected_len}"
        ));
    }
    output.truncate(expected_end);
    Ok(())
}

fn read_positive_i32(
    data: &[u8],
    cursor: &mut usize,
    label: &str,
) -> std::result::Result<usize, String> {
    let end: usize = cursor
        .checked_add(4)
        .ok_or_else(|| format!("{label} offset overflow"))?;
    let raw: [u8; 4] = data
        .get(*cursor..end)
        .and_then(|bytes: &[u8]| bytes.try_into().ok())
        .ok_or_else(|| format!("{label} is truncated"))?;
    *cursor = end;
    let value: i32 = i32::from_le_bytes(raw);
    if value <= 0 {
        return Err(format!("{label} must be positive, got {value}"));
    }
    usize::try_from(value)
        .map_err(|_error: std::num::TryFromIntError| format!("{label} does not fit usize"))
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::*;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

    fn test_failure(message: String) -> Box<dyn Error> {
        Box::new(std::io::Error::other(message))
    }

    fn decoded(result: std::result::Result<Vec<u8>, String>) -> TestResult<Vec<u8>> {
        result.map_err(test_failure)
    }

    fn rejected(result: std::result::Result<Vec<u8>, String>) -> TestResult<String> {
        match result {
            Ok(_) => Err(test_failure("decode unexpectedly succeeded".to_string())),
            Err(reason) => Ok(reason),
        }
    }

    fn container(payload: &[u8]) -> TestResult<Vec<u8>> {
        let mut encoder: DeflateEncoder<Vec<u8>> =
            DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload)?;
        let compressed: Vec<u8> = encoder.finish()?;
        let payload_len: i32 = i32::try_from(payload.len())?;
        let compressed_len: i32 = i32::try_from(compressed.len())?;
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0x017D_7A7Bu32.to_le_bytes());
        data.extend_from_slice(&payload_len.to_le_bytes());
        data.extend_from_slice(&compressed_len.to_le_bytes());
        data.extend_from_slice(&payload_len.to_le_bytes());
        data.extend_from_slice(&compressed);
        Ok(data)
    }

    const fn budget(input: usize, output: usize, parts: usize) -> RecoveryBudget {
        RecoveryBudget {
            input_bytes: input,
            output_bytes: output,
            parts,
        }
    }

    #[test]
    fn aggregate_output_budget_is_shared_across_resources() -> TestResult {
        let first: Vec<u8> = container(b"abc")?;
        let second: Vec<u8> = container(b"def")?;
        let mut shared: RecoveryBudget = budget(first.len() + second.len(), 5, 2);
        assert_eq!(
            decoded(decode_static_resource(&first, &mut shared))?,
            b"abc"
        );
        let error: String = rejected(decode_static_resource(&second, &mut shared))?;
        assert!(error.contains("aggregate declared output"));
        Ok(())
    }

    #[test]
    fn exact_budget_limits_are_inclusive() -> TestResult {
        let data: Vec<u8> = container(b"limit")?;
        let mut exact: RecoveryBudget = budget(data.len(), 5, 1);
        assert_eq!(
            decoded(decode_static_resource(&data, &mut exact))?,
            b"limit"
        );
        let mut short_input: RecoveryBudget = budget(data.len() - 1, 5, 1);
        assert!(decode_static_resource(&data, &mut short_input).is_err());
        let mut short_output: RecoveryBudget = budget(data.len(), 4, 1);
        assert!(decode_static_resource(&data, &mut short_output).is_err());
        let mut no_parts: RecoveryBudget = budget(data.len(), 5, 0);
        assert!(decode_static_resource(&data, &mut no_parts).is_err());
        Ok(())
    }

    #[test]
    fn exact_compressed_consumption_is_required() -> TestResult {
        let mut data: Vec<u8> = container(b"payload")?;
        let length_bytes: [u8; 4] = data
            .get(8..12)
            .ok_or_else(|| test_failure("compressed length missing".to_string()))?
            .try_into()?;
        let compressed_len: u32 = u32::from_le_bytes(length_bytes);
        data.get_mut(8..12)
            .ok_or_else(|| test_failure("compressed length missing".to_string()))?
            .copy_from_slice(&compressed_len.saturating_add(1).to_le_bytes());
        data.push(0);
        let mut limits: RecoveryBudget = RecoveryBudget::standard();
        let error: String = rejected(decode_static_resource(&data, &mut limits))?;
        assert!(error.contains("consumed"));
        Ok(())
    }

    #[test]
    fn exact_inflated_length_is_required() -> TestResult {
        let mut data: Vec<u8> = container(b"payload")?;
        data.get_mut(4..8)
            .ok_or_else(|| test_failure("total length missing".to_string()))?
            .copy_from_slice(&8i32.to_le_bytes());
        data.get_mut(12..16)
            .ok_or_else(|| test_failure("part length missing".to_string()))?
            .copy_from_slice(&8i32.to_le_bytes());
        let mut limits: RecoveryBudget = RecoveryBudget::standard();
        let error: String = rejected(decode_static_resource(&data, &mut limits))?;
        assert!(error.contains("produced 7 bytes instead of 8"));
        Ok(())
    }

    #[test]
    fn invalid_deflate_and_trailing_bytes_are_rejected() -> TestResult {
        let mut invalid: Vec<u8> = container(b"payload")?;
        invalid
            .get_mut(16..)
            .ok_or_else(|| test_failure("compressed bytes missing".to_string()))?
            .fill(0xFF);
        let mut invalid_limits: RecoveryBudget = RecoveryBudget::standard();
        assert!(decode_static_resource(&invalid, &mut invalid_limits).is_err());

        let mut trailing: Vec<u8> = container(b"payload")?;
        trailing.push(0);
        let mut trailing_limits: RecoveryBudget = RecoveryBudget::standard();
        let error: String = rejected(decode_static_resource(&trailing, &mut trailing_limits))?;
        assert!(error.contains("trailing byte"));
        Ok(())
    }

    #[test]
    fn nonpositive_lengths_are_rejected() -> TestResult {
        for total in [0i32, -1i32] {
            let mut data: Vec<u8> = container(b"payload")?;
            data.get_mut(4..8)
                .ok_or_else(|| test_failure("total length missing".to_string()))?
                .copy_from_slice(&total.to_le_bytes());
            let mut limits: RecoveryBudget = RecoveryBudget::standard();
            let error: String = rejected(decode_static_resource(&data, &mut limits))?;
            assert!(error.contains("must be positive"));
        }
        Ok(())
    }

    #[test]
    fn metadata_without_assembly_row_is_rejected() -> TestResult {
        let mut data: Vec<u8> =
            include_bytes!("../../tests/fixtures/smartassembly_resources/Payload.clean.dll")
                .to_vec();
        let pe: crate::pe::PeImage = crate::pe::parse(&data)?;
        let clr: crate::pe::ClrHeader = crate::pe::parse_clr_header(&data, &pe)?;
        let root: crate::metadata::MetadataRoot =
            crate::metadata::parse_metadata_root(&data, &pe, &clr)?;
        let tables = root
            .streams
            .get("#~")
            .ok_or_else(|| test_failure("table stream missing".to_string()))?;
        let metadata_offset: usize = pe
            .rva_to_offset(clr.metadata.rva)
            .ok_or_else(|| test_failure("metadata offset missing".to_string()))?;
        let table_offset: usize = usize::try_from(tables.offset)?;
        let valid_assembly_byte: usize = metadata_offset
            .checked_add(table_offset)
            .and_then(|offset: usize| offset.checked_add(12))
            .ok_or_else(|| test_failure("valid-mask offset overflow".to_string()))?;
        let valid_byte: &mut u8 = data
            .get_mut(valid_assembly_byte)
            .ok_or_else(|| test_failure("valid-mask byte missing".to_string()))?;
        *valid_byte &= !1;
        assert!(!is_complete_managed_assembly(&data));
        Ok(())
    }

    #[test]
    fn duplicate_assembly_rows_are_rejected() -> TestResult {
        let mut data: Vec<u8> =
            include_bytes!("../../tests/fixtures/smartassembly_resources/Payload.clean.dll")
                .to_vec();
        let pe: crate::pe::PeImage = crate::pe::parse(&data)?;
        let clr: crate::pe::ClrHeader = crate::pe::parse_clr_header(&data, &pe)?;
        let root: crate::metadata::MetadataRoot =
            crate::metadata::parse_metadata_root(&data, &pe, &clr)?;
        let tables = root
            .streams
            .get("#~")
            .ok_or_else(|| test_failure("table stream missing".to_string()))?;
        let metadata_offset: usize = pe
            .rva_to_offset(clr.metadata.rva)
            .ok_or_else(|| test_failure("metadata offset missing".to_string()))?;
        let table_offset: usize = usize::try_from(tables.offset)?;
        let stream_offset: usize = metadata_offset
            .checked_add(table_offset)
            .ok_or_else(|| test_failure("table stream offset overflow".to_string()))?;
        let valid_offset: usize = stream_offset
            .checked_add(8)
            .ok_or_else(|| test_failure("valid-mask offset overflow".to_string()))?;
        let valid_end: usize = valid_offset
            .checked_add(8)
            .ok_or_else(|| test_failure("valid-mask range overflow".to_string()))?;
        let valid_bytes: [u8; 8] = data
            .get(valid_offset..valid_end)
            .ok_or_else(|| test_failure("valid mask missing".to_string()))?
            .try_into()?;
        let valid: u64 = u64::from_le_bytes(valid_bytes);
        let lower_tables: usize = usize::try_from((valid & 0xFFFF_FFFF).count_ones())?;
        let count_offset: usize = stream_offset
            .checked_add(24)
            .and_then(|offset: usize| offset.checked_add(lower_tables.checked_mul(4)?))
            .ok_or_else(|| test_failure("Assembly row-count offset overflow".to_string()))?;
        let count_end: usize = count_offset
            .checked_add(4)
            .ok_or_else(|| test_failure("Assembly row-count range overflow".to_string()))?;
        data.get_mut(count_offset..count_end)
            .ok_or_else(|| test_failure("Assembly row count missing".to_string()))?
            .copy_from_slice(&2u32.to_le_bytes());
        assert!(!is_complete_managed_assembly(&data));
        Ok(())
    }

    #[test]
    fn empty_assembly_name_is_rejected() -> TestResult {
        let mut data: Vec<u8> =
            include_bytes!("../../tests/fixtures/smartassembly_resources/Payload.clean.dll")
                .to_vec();
        let pe: crate::pe::PeImage = crate::pe::parse(&data)?;
        let clr: crate::pe::ClrHeader = crate::pe::parse_clr_header(&data, &pe)?;
        let root: crate::metadata::MetadataRoot =
            crate::metadata::parse_metadata_root(&data, &pe, &clr)?;
        let metadata_size: usize = usize::try_from(clr.metadata.size)?;
        let metadata: &[u8] = pe.slice_at_rva(&data, clr.metadata.rva, metadata_size)?;
        let table_header = root
            .streams
            .get("#~")
            .ok_or_else(|| test_failure("table stream missing".to_string()))?;
        let tables: crate::tables::Tables = crate::tables::parse_tables(metadata, *table_header)?;
        let assembly: crate::tables::AssemblyRow = tables
            .assembly
            .ok_or_else(|| test_failure("Assembly row missing".to_string()))?;
        let strings = root
            .streams
            .get("#Strings")
            .ok_or_else(|| test_failure("strings heap missing".to_string()))?;
        let metadata_offset: usize = pe
            .rva_to_offset(clr.metadata.rva)
            .ok_or_else(|| test_failure("metadata offset missing".to_string()))?;
        let strings_offset: usize = usize::try_from(strings.offset)?;
        let name_offset: usize = usize::try_from(assembly.name)?;
        let absolute_name: usize = metadata_offset
            .checked_add(strings_offset)
            .and_then(|offset: usize| offset.checked_add(name_offset))
            .ok_or_else(|| test_failure("Assembly name offset overflow".to_string()))?;
        let name_byte: &mut u8 = data
            .get_mut(absolute_name)
            .ok_or_else(|| test_failure("Assembly name missing".to_string()))?;
        *name_byte = 0;
        assert!(!is_complete_managed_assembly(&data));
        Ok(())
    }
}
