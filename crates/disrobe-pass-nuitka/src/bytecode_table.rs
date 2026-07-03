use disrobe_pass_pickle::{PickleValue, Session, disassemble};
use disrobe_py_marshal::{CodeObject, Object, PyVersion};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const BLOBDATA_MODULE: &str = "nuitka.Serialization";
const BLOBDATA_NAME: &str = "BlobData";
const NAME_PREFIX: &str = "bytecode of module '";
const NAME_SUFFIX: &str = "'";
const MAX_MODULES: usize = 1 << 20;

const PROBE_VERSIONS: [PyVersion; 12] = [
    PyVersion::PY314,
    PyVersion::PY313,
    PyVersion::PY312,
    PyVersion::PY311,
    PyVersion::PY310,
    PyVersion::PY39,
    PyVersion::PY38,
    PyVersion::PY37,
    PyVersion::PY36,
    PyVersion::PY315,
    PyVersion::PY27,
    PyVersion::PY35,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeModule {
    pub module_name: String,
    pub marshal_len: usize,
    pub disassembly: String,
    pub instruction_count: usize,
    pub source: String,
    pub recovered_directly: bool,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeTable {
    pub marshal_version: (u8, u8),
    pub modules: Vec<BytecodeModule>,
    pub notes: Vec<String>,
}

struct RawEntry {
    module_name: String,
    marshal: Vec<u8>,
}

pub fn decode_bytecode_table(
    const_bytes: &[u8],
    python_abi: Option<(u8, u8)>,
) -> Result<BytecodeTable> {
    let raw_entries: Vec<RawEntry> = parse_blob_entries(const_bytes)?;
    let mut notes: Vec<String> = Vec::new();

    if raw_entries.is_empty() {
        notes.push("__bytecode.const carried no frozen module code objects".to_owned());
        return Ok(BytecodeTable {
            marshal_version: python_abi.unwrap_or((0, 0)),
            modules: Vec::new(),
            notes,
        });
    }

    let version: PyVersion = resolve_marshal_version(&raw_entries, python_abi, &mut notes)?;
    let mut modules: Vec<BytecodeModule> = Vec::with_capacity(raw_entries.len());
    for entry in &raw_entries {
        modules.push(recover_module(entry, version));
    }

    Ok(BytecodeTable {
        marshal_version: (version.major, version.minor),
        modules,
        notes,
    })
}

pub(crate) fn recover_frozen_module(
    module_name: &str,
    marshal: &[u8],
    version: PyVersion,
) -> BytecodeModule {
    recover_module(
        &RawEntry {
            module_name: module_name.to_owned(),
            marshal: marshal.to_vec(),
        },
        version,
    )
}

fn recover_module(entry: &RawEntry, version: PyVersion) -> BytecodeModule {
    let code: CodeObject = match load_code(&entry.marshal, version) {
        Ok(code) => code,
        Err(e) => {
            return BytecodeModule {
                module_name: entry.module_name.clone(),
                marshal_len: entry.marshal.len(),
                disassembly: String::new(),
                instruction_count: 0,
                source: String::new(),
                recovered_directly: false,
                fallback_reason: Some(format!("marshal decode failed: {e}")),
            };
        }
    };

    let instructions: Vec<disrobe_pass_py_disasm::Instruction> =
        disrobe_pass_py_disasm::disassemble(&code, version);
    let disassembly: String = disrobe_pass_py_disasm::render_dis(&instructions);
    let (source, recovered_directly, fallback_reason): (String, bool, Option<String>) =
        recover_source(&code, version);

    BytecodeModule {
        module_name: entry.module_name.clone(),
        marshal_len: entry.marshal.len(),
        disassembly,
        instruction_count: instructions.len(),
        source,
        recovered_directly,
        fallback_reason,
    }
}

fn recover_source(code: &CodeObject, version: PyVersion) -> (String, bool, Option<String>) {
    let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
        match disrobe_pass_py_decompile::engine::marshal_to_decompile(version) {
            Ok(v) => v,
            Err(e) => {
                let reason: String = format!("{e}");
                let fallback: String = disrobe_pass_py_decompile::engine::disasm_fallback_source(
                    code,
                    &disrobe_pass_py_decompile::bytecode::version::PyVersion::V3_12,
                    &reason,
                );
                return (fallback, false, Some(reason));
            }
        };
    match disrobe_pass_py_decompile::engine::build_real_source(code, &decompile_version, version) {
        Ok(src) => (src, true, None),
        Err(e) => {
            let reason: String = format!("{e}");
            let fallback: String = disrobe_pass_py_decompile::engine::disasm_fallback_source(
                code,
                &decompile_version,
                &reason,
            );
            (fallback, false, Some(reason))
        }
    }
}

fn load_code(marshal: &[u8], version: PyVersion) -> Result<CodeObject> {
    let obj: Object = disrobe_py_marshal::load(marshal, version).map_err(Error::BytecodeMarshal)?;
    match obj {
        Object::Code(boxed) => Ok(*boxed),
        other => Err(Error::BytecodeNotCode(format!("{other:?}"))),
    }
}

fn resolve_marshal_version(
    entries: &[RawEntry],
    python_abi: Option<(u8, u8)>,
    notes: &mut Vec<String>,
) -> Result<PyVersion> {
    if let Some((major, minor)) = python_abi {
        let declared: PyVersion = PyVersion::new(major, minor);
        if entries
            .iter()
            .all(|e: &RawEntry| load_code(&e.marshal, declared).is_ok())
        {
            return Ok(declared);
        }
        notes.push(format!(
            "python ABI {major}.{minor} did not cleanly decode the bytecode table; probing marshal layout"
        ));
    }

    let probe: Option<PyVersion> = PROBE_VERSIONS.iter().copied().find(|v: &PyVersion| {
        entries
            .iter()
            .all(|e: &RawEntry| load_code(&e.marshal, *v).is_ok())
    });
    let Some(version): Option<PyVersion> = probe else {
        return Err(Error::BytecodeVersionUnknown);
    };
    notes.push(format!(
        "marshal layout matched python {}.{} by probe",
        version.major, version.minor
    ));
    Ok(version)
}

fn parse_blob_entries(const_bytes: &[u8]) -> Result<Vec<RawEntry>> {
    let mut session: Session = Session::new();
    let mut out: Vec<RawEntry> = Vec::new();
    let mut cursor: usize = 0usize;

    while cursor < const_bytes.len() {
        let rest: &[u8] = &const_bytes[cursor..];
        let dis: disrobe_pass_pickle::Disassembly = disassemble(rest)
            .map_err(|e: disrobe_pass_pickle::Error| Error::BytecodePickle(e.to_string()))?;
        let stop_off: usize = dis
            .stop_offset
            .ok_or(Error::ConstStreamNoStop { offset: cursor })?;
        let consumed: usize = stop_off + 1;
        let value: PickleValue = session
            .run(&dis)
            .map_err(|e: disrobe_pass_pickle::Error| Error::BytecodePickle(e.to_string()))?;

        if let Some(entry) = blob_entry_from_value(&value) {
            out.push(entry);
        }

        cursor = cursor
            .checked_add(consumed)
            .ok_or(Error::ConstTooManyStreams)?;
        if out.len() > MAX_MODULES {
            return Err(Error::ConstTooManyStreams);
        }
    }

    Ok(out)
}

fn blob_entry_from_value(value: &PickleValue) -> Option<RawEntry> {
    let PickleValue::Object { cls, state, .. } = value else {
        return None;
    };
    if !is_blobdata_class(cls) {
        return None;
    }
    let state: &PickleValue = state.as_deref()?;
    let mut data: Option<&Vec<u8>> = None;
    let mut name: Option<&str> = None;
    collect_blob_state(state, &mut data, &mut name);
    let marshal: Vec<u8> = data?.clone();
    let module_name: String = name.map_or_else(|| "<unknown>".to_owned(), strip_module_name);
    Some(RawEntry {
        module_name,
        marshal,
    })
}

fn collect_blob_state<'a>(
    state: &'a PickleValue,
    data: &mut Option<&'a Vec<u8>>,
    name: &mut Option<&'a str>,
) {
    match state {
        PickleValue::Dict(pairs) => {
            for (key, val) in pairs {
                let PickleValue::Str(field) = key else {
                    continue;
                };
                match (field.as_str(), val) {
                    ("data", PickleValue::Bytes(b)) => *data = Some(b),
                    ("name", PickleValue::Str(s)) => *name = Some(s),
                    _ => {}
                }
            }
        }
        PickleValue::Tuple(items) => {
            for item in items {
                collect_blob_state(item, data, name);
            }
        }
        _ => {}
    }
}

fn is_blobdata_class(cls: &PickleValue) -> bool {
    match cls {
        PickleValue::Global { module, name } => module == BLOBDATA_MODULE && name == BLOBDATA_NAME,
        PickleValue::Object { cls: inner, .. } => is_blobdata_class(inner),
        _ => false,
    }
}

fn strip_module_name(label: &str) -> String {
    label
        .strip_prefix(NAME_PREFIX)
        .and_then(|s: &str| s.strip_suffix(NAME_SUFFIX))
        .unwrap_or(label)
        .to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const BYTECODE_CONST: &[u8] =
        include_bytes!("../../../corpus/python/nuitka/bytecode-module/app.build/__bytecode.const");
    const SOURCE: &str =
        include_str!("../../../corpus/python/nuitka/bytecode-module/packaging.src.py");

    #[test]
    fn empty_table_yields_no_modules() {
        let table: BytecodeTable = decode_bytecode_table(&[], Some((3, 14))).expect("decode empty");
        assert!(table.modules.is_empty());
        assert!(table.notes.iter().any(|n: &String| n.contains("no frozen")));
    }

    #[test]
    fn recovers_single_frozen_module_code_object() {
        let table: BytecodeTable =
            decode_bytecode_table(BYTECODE_CONST, Some((3, 14))).expect("decode table");
        assert_eq!(table.marshal_version, (3, 14));
        assert_eq!(table.modules.len(), 1);
        let module: &BytecodeModule = &table.modules[0];
        assert_eq!(module.module_name, "packaging");
        assert!(module.instruction_count > 0);
        assert!(module.disassembly.contains("LOAD_CONST"));
    }

    #[test]
    fn recovered_source_names_match_known_module() {
        let table: BytecodeTable =
            decode_bytecode_table(BYTECODE_CONST, Some((3, 14))).expect("decode table");
        let module: &BytecodeModule = &table.modules[0];
        assert!(
            module.source.contains("describe"),
            "recovered source missing 'describe':\n{}",
            module.source
        );
        assert!(module.source.contains("total"));
        assert!(SOURCE.contains("def describe"));
    }

    #[test]
    fn version_probe_recovers_without_declared_abi() {
        let table: BytecodeTable =
            decode_bytecode_table(BYTECODE_CONST, None).expect("decode table");
        assert_eq!(table.modules.len(), 1);
        assert_eq!(table.marshal_version, (3, 14));
        assert!(table.notes.iter().any(|n: &String| n.contains("probe")));
    }

    #[test]
    fn strip_module_name_unwraps_nuitka_label() {
        assert_eq!(
            strip_module_name("bytecode of module 'packaging'"),
            "packaging"
        );
        assert_eq!(strip_module_name("packaging"), "packaging");
    }
}
