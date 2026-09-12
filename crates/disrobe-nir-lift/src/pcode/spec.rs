use std::collections::BTreeSet;
use std::sync::OnceLock;

use disrobe_sleigh::SleighError;
use disrobe_sleigh::syntax::{Endian, RegisterDef, SleighSpec, parse_spec};
use disrobe_sleigh::vendor::{
    preprocessed_arm32_source, preprocessed_mips32be_source, preprocessed_mips32le_source,
};

use crate::error::{LiftError, Result};

use super::valid_identifier;
use super::varnode::{MAX_VARNODE_BYTES, RegisterCell};

const MAX_SPEC_REGISTERS: usize = 4096;
const MAX_SPEC_NAME_BYTES: usize = 128;
const UNUSED_SLOT_NAME: &str = "_";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SpecRegisters {
    pub(super) cells: Vec<RegisterCell>,
    pub(super) big_endian: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum SpecRegisterMap {
    Arm32,
    Mips32Be,
    Mips32Le,
}

impl SpecRegisterMap {
    pub(super) const fn mips32(endian: Endian) -> Self {
        match endian {
            Endian::Big => Self::Mips32Be,
            Endian::Little => Self::Mips32Le,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Arm32 => "arm32",
            Self::Mips32Be => "mips32be",
            Self::Mips32Le => "mips32le",
        }
    }

    fn preprocessed_source(self) -> core::result::Result<String, SleighError> {
        match self {
            Self::Arm32 => preprocessed_arm32_source(),
            Self::Mips32Be => preprocessed_mips32be_source(),
            Self::Mips32Le => preprocessed_mips32le_source(),
        }
    }

    fn slot(self) -> &'static OnceLock<core::result::Result<SpecRegisters, String>> {
        static ARM32: OnceLock<core::result::Result<SpecRegisters, String>> = OnceLock::new();
        static MIPS32_BE: OnceLock<core::result::Result<SpecRegisters, String>> = OnceLock::new();
        static MIPS32_LE: OnceLock<core::result::Result<SpecRegisters, String>> = OnceLock::new();
        match self {
            Self::Arm32 => &ARM32,
            Self::Mips32Be => &MIPS32_BE,
            Self::Mips32Le => &MIPS32_LE,
        }
    }
}

pub(super) fn registers(map: SpecRegisterMap) -> Result<SpecRegisters> {
    let built: &core::result::Result<SpecRegisters, String> = map.slot().get_or_init(|| {
        let text: String = map
            .preprocessed_source()
            .map_err(|error: SleighError| format!("compiled spec did not preprocess: {error}"))?;
        let spec: SleighSpec = parse_spec(&text)
            .map_err(|error: SleighError| format!("compiled spec did not parse: {error}"))?;
        let cells: Vec<RegisterCell> =
            canonical_cells(&spec.registers).map_err(|error: LiftError| error.to_string())?;
        Ok(SpecRegisters {
            cells,
            big_endian: matches!(spec.endian, Some(Endian::Big)),
        })
    });
    match built {
        Ok(value) => Ok(value.clone()),
        Err(reason) => Err(LiftError::InvalidPcode {
            address: 0,
            operation: "REGISTER_MAP".to_owned(),
            reason: format!("{} register map: {reason}", map.label()),
        }),
    }
}

pub(super) fn canonical_cells(definitions: &[RegisterDef]) -> Result<Vec<RegisterCell>> {
    if definitions.is_empty() {
        return Err(invalid("the compiled spec defines no registers"));
    }
    if definitions.len() > MAX_SPEC_REGISTERS {
        return Err(invalid("the compiled spec defines too many registers"));
    }
    let mut usable: Vec<(u64, u32, String)> = Vec::with_capacity(definitions.len());
    for definition in definitions {
        if definition.name == UNUSED_SLOT_NAME {
            continue;
        }
        if definition.size_bytes == 0 {
            return Err(invalid("the compiled spec defines a zero-width register"));
        }
        if definition.size_bytes > MAX_VARNODE_BYTES {
            return Err(invalid(
                "the compiled spec defines a register wider than any varnode",
            ));
        }
        definition
            .offset
            .checked_add(u64::from(definition.size_bytes))
            .ok_or_else(|| invalid("a spec register range overflows its address space"))?;
        usable.push((
            definition.offset,
            definition.size_bytes,
            identifier_from_spec_name(&definition.name)?,
        ));
    }
    if usable.is_empty() {
        return Err(invalid("the compiled spec defines no usable register"));
    }
    usable.sort_unstable();

    let mut cells: Vec<RegisterCell> = Vec::with_capacity(usable.len());
    let mut next_free: u64 = 0;
    for (offset, size, name) in usable {
        if offset < next_free {
            continue;
        }
        next_free = offset.saturating_add(u64::from(size));
        cells.push(RegisterCell::new(offset, size, name, None));
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cell in &cells {
        if !seen.insert(cell.name.to_ascii_lowercase()) {
            return Err(invalid(
                "the compiled spec reuses a canonical register name",
            ));
        }
    }
    Ok(cells)
}

pub(super) fn require_cells(cells: &[RegisterCell], names: &[&str], label: &str) -> Result<()> {
    for name in names {
        if !cells
            .iter()
            .any(|cell: &RegisterCell| cell.name.eq_ignore_ascii_case(name))
        {
            return Err(LiftError::InvalidPcode {
                address: 0,
                operation: "REGISTER_MAP".to_owned(),
                reason: format!("the {label} spec defines no whole register cell named {name}"),
            });
        }
    }
    Ok(())
}

fn identifier_from_spec_name(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > MAX_SPEC_NAME_BYTES {
        return Err(invalid("a spec register name has an unusable length"));
    }
    let normalized: String = name
        .chars()
        .map(|character: char| {
            if character == '_' || character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect();
    if !valid_identifier(&normalized) {
        return Err(invalid("the compiled spec names a register unusably"));
    }
    Ok(normalized)
}

fn invalid(reason: &str) -> LiftError {
    LiftError::InvalidPcode {
        address: 0,
        operation: "REGISTER_MAP".to_owned(),
        reason: reason.to_owned(),
    }
}
