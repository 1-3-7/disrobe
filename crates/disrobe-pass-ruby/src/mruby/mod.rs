pub mod decompile;
pub mod disasm;
pub mod irep;
pub mod lift;
pub mod ops;
pub mod reader;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::mruby::decompile::{MrubyDecompiled, decompile};
use crate::mruby::irep::{IrepTree, parse_irep};
use crate::mruby::reader::{RiteBinary, read_rite};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrubyAnalysis {
    pub binary: RiteBinary,
    pub irep: Option<IrepTree>,
    pub decompiled: MrubyDecompiled,
}

pub(crate) fn analyze(bytes: &[u8]) -> Result<MrubyAnalysis> {
    let binary: RiteBinary = read_rite(bytes)?;
    let irep: Option<IrepTree> = extract_irep(bytes, &binary);
    let decompiled: MrubyDecompiled = decompile(&binary, irep.as_ref());
    Ok(MrubyAnalysis {
        binary,
        irep,
        decompiled,
    })
}

fn extract_irep(bytes: &[u8], binary: &RiteBinary) -> Option<IrepTree> {
    let section: &reader::RiteSection =
        binary.sections.iter().find(|s| &s.identifier == b"IREP")?;
    let body_start: usize = (section.offset as usize).checked_add(8)?;
    let body_end: usize = body_start.checked_add(section.body_len as usize)?;
    let body: &[u8] = bytes.get(body_start..body_end.min(bytes.len()))?;
    parse_irep(body, binary.header.format_version).ok()
}
