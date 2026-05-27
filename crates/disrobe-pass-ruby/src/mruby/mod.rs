pub mod decompile;
pub mod reader;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::mruby::decompile::{MrubyDecompiled, decompile};
use crate::mruby::reader::{RiteBinary, read_rite};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrubyAnalysis {
    pub binary: RiteBinary,
    pub decompiled: MrubyDecompiled,
}

pub(crate) fn analyze(bytes: &[u8]) -> Result<MrubyAnalysis> {
    let binary: RiteBinary = read_rite(bytes)?;
    let decompiled: MrubyDecompiled = decompile(&binary);
    Ok(MrubyAnalysis { binary, decompiled })
}
