use disrobe_sleigh::SleighError;
use disrobe_sleigh::syntax::{Endian, RegisterDef, SleighSpec, parse_spec};

use crate::error::{LiftError, Result};

use super::varnode::{MAX_VARNODE_BYTES, RegisterCell};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SpecRegisters {
    pub(super) cells: Vec<RegisterCell>,
    pub(super) big_endian: bool,
}

pub(super) fn canonical_registers(source: &str) -> Result<SpecRegisters> {
    let spec: SleighSpec = parse_spec(source).map_err(spec_error)?;
    let big_endian: bool = matches!(spec.endian, Some(Endian::Big));
    let mut definitions: Vec<(u64, u32, String)> = spec
        .registers
        .iter()
        .filter(|definition: &&RegisterDef| {
            definition.size_bytes > 0 && definition.size_bytes <= MAX_VARNODE_BYTES
        })
        .map(|definition: &RegisterDef| {
            (
                definition.offset,
                definition.size_bytes,
                canonical_name(&definition.name),
            )
        })
        .collect();
    definitions.sort_unstable();
    let mut cells: Vec<RegisterCell> = Vec::with_capacity(definitions.len());
    let mut next_free: u64 = 0;
    for (offset, size, name) in definitions {
        let end: u64 = offset
            .checked_add(u64::from(size))
            .ok_or_else(|| register_map_error("register definition range overflows"))?;
        if offset < next_free {
            continue;
        }
        cells.push(RegisterCell::new(offset, size, name, None));
        next_free = end;
    }
    if cells.is_empty() {
        return Err(register_map_error("spec defines no usable register"));
    }
    Ok(SpecRegisters { cells, big_endian })
}

fn canonical_name(name: &str) -> String {
    let mut canonical: String = String::with_capacity(name.len().saturating_add(2));
    for character in name.chars() {
        if character == '_' || character.is_ascii_alphanumeric() {
            canonical.push(character);
        } else {
            canonical.push('_');
        }
    }
    match canonical.chars().next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => canonical,
        _ => format!("reg_{canonical}"),
    }
}

fn spec_error(error: SleighError) -> LiftError {
    LiftError::InvalidPcode {
        address: 0,
        operation: "REGISTER_MAP".to_owned(),
        reason: format!("compiled spec did not parse: {error}"),
    }
}

fn register_map_error(reason: &str) -> LiftError {
    LiftError::InvalidPcode {
        address: 0,
        operation: "REGISTER_MAP".to_owned(),
        reason: reason.to_owned(),
    }
}
