use disrobe_pass_py_disasm::{
    OpcodeRemap, RemapDetection, RemapVerdict, detect_opcode_remap, recover_opcode_remap,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, read_pyc};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::marshal::decompile_code_object_with_status;

#[derive(Debug, Clone, Serialize)]
pub struct RemappedRecovery {
    pub source: String,
    pub complete: bool,
    pub version_major: u8,
    pub version_minor: u8,
    pub covered_opcodes: usize,
    pub aligned_code_objects: usize,
    pub detection: RemapDetection,
}

fn pyc_code(bytes: &[u8], role: &str) -> Result<(CodeObject, PyVersion)> {
    let file: PycFile = read_pyc(bytes).map_err(|e| Error::Marshal(format!("{role}: {e}")))?;
    match file.code {
        Object::Code(code) => Ok((*code, file.header.version)),
        _ => Err(Error::Marshal(format!(
            "{role}: the pyc holds no code object"
        ))),
    }
}

pub(crate) fn remap_refusal(code: &CodeObject, version: PyVersion) -> Option<Error> {
    let detection: RemapDetection = detect_opcode_remap(code, version);
    (detection.verdict == RemapVerdict::Remapped).then(|| remapped_error(&detection, version))
}

fn remapped_error(detection: &RemapDetection, version: PyVersion) -> Error {
    Error::OpcodeRemap {
        major: version.major,
        minor: version.minor,
        entry_opcode: detection.entry_opcode.unwrap_or_default(),
        stock_resume_opcode: detection.stock_resume_opcode.unwrap_or_default(),
    }
}

pub fn recover_remapped_pyc(remapped: &[u8], reference: &[u8]) -> Result<RemappedRecovery> {
    let (code, version): (CodeObject, PyVersion) = pyc_code(remapped, "remapped input")?;
    let (stock, reference_version): (CodeObject, PyVersion) = pyc_code(reference, "reference")?;
    if reference_version != version {
        return Err(Error::Marshal(format!(
            "the reference was compiled by CPython {}.{} but the input by {}.{}; opcode tables only align within one version",
            reference_version.major, reference_version.minor, version.major, version.minor
        )));
    }
    let detection: RemapDetection = detect_opcode_remap(&code, version);
    let table: OpcodeRemap = recover_opcode_remap(&code, &stock, version)?;
    let restored: CodeObject = table.apply(&code)?;
    let (source, complete): (String, bool) = decompile_code_object_with_status(&restored, version)?;
    Ok(RemappedRecovery {
        source,
        complete,
        version_major: version.major,
        version_minor: version.minor,
        covered_opcodes: table.covered_opcodes(),
        aligned_code_objects: table.aligned_code_objects(),
        detection,
    })
}
