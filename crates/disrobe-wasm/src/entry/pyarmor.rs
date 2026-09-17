use std::collections::BTreeSet;

use disrobe_pass_pyarmor::{
    UnpackedModule, detect_from_wrapper, marshal_stream_start, unpack_module_bytes,
};
use disrobe_py_marshal::{
    CodeEra, CodeObject, Limits, Object, PyVersion, load_with_limits, pyversion_from_magic,
};
use serde::Serialize;

pub const MAX_WRAPPER_BYTES: usize = 1024 * 1024;
pub const MAX_RUNTIME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct ModuleOutput {
    pub metadata: Vec<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
struct Contents<'a> {
    code_objects: usize,
    names: BTreeSet<&'a str>,
    strings: BTreeSet<&'a str>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    ok: bool,
    format: &'static str,
    runtime_format: &'static str,
    python_version: String,
    runtime_arch: &'static str,
    marshal_offset: usize,
    code_objects: usize,
    names: BTreeSet<&'a str>,
    strings: BTreeSet<&'a str>,
}

fn text(object: &Object) -> Option<&str> {
    match object {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value),
        _ => None,
    }
}

fn collect<'a>(object: &'a Object, contents: &mut Contents<'a>) -> Result<(), String> {
    match object {
        Object::Code(code) => {
            validate_code_fields(code)?;
            contents.code_objects += 1;
            for name in core::iter::once(&code.name).chain(&code.names) {
                if let Some(name) = text(name) {
                    contents.names.insert(name);
                }
            }
            for item in &code.consts {
                collect(item, contents)?;
            }
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for item in items {
                collect(item, contents)?;
            }
        }
        Object::Dict(items) | Object::FrozenDict(items) => {
            for (key, value) in items {
                collect(key, contents)?;
                collect(value, contents)?;
            }
        }
        Object::Slice { lower, upper, step } => {
            for item in [lower, upper, step] {
                collect(item, contents)?;
            }
        }
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => {
            contents.strings.insert(value);
        }
        Object::Ref(_) | Object::Null => {
            return Err(
                "PyArmor module contains an unresolved marshal reference or null value".to_string(),
            );
        }
        Object::None
        | Object::StopIteration
        | Object::Ellipsis
        | Object::False
        | Object::True
        | Object::Int(_)
        | Object::Int64(_)
        | Object::Long(_)
        | Object::Float(_)
        | Object::Complex { .. }
        | Object::Bytes(_) => {}
    }
    Ok(())
}

fn validate_code_fields(code: &CodeObject) -> Result<(), String> {
    if [
        code.argcount,
        code.posonlyargcount,
        code.kwonlyargcount,
        code.nlocals,
        code.stacksize,
        code.flags,
        code.firstlineno,
    ]
    .into_iter()
    .any(|value| value < 0)
        || code.posonlyargcount > code.argcount
    {
        return Err("PyArmor code object contains invalid counts or flags".to_string());
    }
    let names_valid: bool = [&code.filename, &code.name]
        .into_iter()
        .chain(&code.names)
        .chain(&code.varnames)
        .chain(&code.freevars)
        .chain(&code.cellvars)
        .chain(&code.localsplusnames)
        .all(|name| text(name).is_some());
    if !names_valid {
        return Err("PyArmor code object contains a non-string name".to_string());
    }
    if code.era == CodeEra::Py311Plus
        && (text(&code.qualname).is_none()
            || code.localspluskinds.len() != code.localsplusnames.len())
    {
        return Err(
            "PyArmor code object contains invalid qualified-name or local-variable fields"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_module(bytes: &[u8], version: PyVersion) -> Result<(Object, usize), String> {
    let offset: usize =
        marshal_stream_start(bytes).map_err(|error| format!("PyArmor module header: {error}"))?;
    let stream: &[u8] = bytes
        .get(offset..)
        .ok_or_else(|| "PyArmor marshal offset exceeds module size".to_string())?;
    let limits: Limits = Limits {
        input_bytes: MAX_WRAPPER_BYTES,
        nodes: 65_536,
        depth: 64,
        collection_items: 16_384,
        dict_entries: 8_192,
        reference_bytes: 32 * 1024 * 1024,
    };
    let (object, consumed): (Object, usize) = load_with_limits(stream, version, limits)
        .map_err(|error| format!("PyArmor marshal validation: {error}"))?;
    if !matches!(object, Object::Code(_)) {
        return Err("PyArmor marshal root is not a code object".to_string());
    }
    if consumed != stream.len() {
        return Err("PyArmor module contains bytes after the marshal code object".to_string());
    }
    Ok((object, offset))
}

pub fn unpack(wrapper: &[u8], runtime: &[u8]) -> Result<ModuleOutput, String> {
    if wrapper.len() > MAX_WRAPPER_BYTES {
        return Err("PyArmor wrapper exceeds the 1 MiB browser limit".to_string());
    }
    if runtime.is_empty() {
        return Err("Choose the PyArmor runtime distributed with this wrapper".to_string());
    }
    if runtime.len() > MAX_RUNTIME_BYTES {
        return Err("PyArmor runtime exceeds the 16 MiB browser limit".to_string());
    }
    let source: &str = core::str::from_utf8(wrapper)
        .map_err(|_| "PyArmor wrapper must be UTF-8 text".to_string())?;
    let (_, payload): (_, Vec<u8>) =
        detect_from_wrapper(source).map_err(|error| format!("PyArmor wrapper: {error}"))?;
    if payload.len() > MAX_WRAPPER_BYTES {
        return Err("PyArmor payload exceeds the 1 MiB browser limit".to_string());
    }
    let module: UnpackedModule = unpack_module_bytes(&payload, runtime)
        .map_err(|error| format!("PyArmor module: {error}"))?;
    if module.bytes.len() > MAX_WRAPPER_BYTES {
        return Err("PyArmor module exceeds the 1 MiB browser limit".to_string());
    }
    let version: PyVersion = module
        .header
        .pyc_magic
        .and_then(|magic| pyversion_from_magic(0x0a0d_0000 | u32::from(magic)))
        .ok_or_else(|| "PyArmor module has an unsupported Python magic number".to_string())?;
    if module.header.python_major != Some(version.major)
        || module.header.python_minor != Some(version.minor)
    {
        return Err("PyArmor Python version does not match its magic number".to_string());
    }
    let (object, offset): (Object, usize) = validate_module(&module.bytes, version)?;
    let mut contents: Contents<'_> = Contents::default();
    collect(&object, &mut contents)?;
    let metadata: Metadata<'_> = Metadata {
        ok: true,
        format: "pyarmor-module",
        runtime_format: super::pyarmor_version_label(module.runtime_version),
        python_version: format!("{}.{}", version.major, version.minor),
        runtime_arch: module.runtime_arch.label(),
        marshal_offset: offset,
        code_objects: contents.code_objects,
        names: contents.names,
        strings: contents.strings,
    };
    let metadata: Vec<u8> =
        serde_json::to_vec(&metadata).map_err(|error| format!("PyArmor metadata: {error}"))?;
    if metadata.len() > MAX_METADATA_BYTES {
        return Err("PyArmor metadata exceeds the 8 MiB browser limit".to_string());
    }
    Ok(ModuleOutput {
        metadata,
        bytes: module.bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRAPPER: &[u8] = include_bytes!(
        "../../../../corpus/python/pyarmor/v9_latest_925/default/known_plaintext.py"
    );
    const RUNTIME: &[u8] = include_bytes!(
        "../../../../corpus/python/pyarmor/v9_latest_925/default/pyarmor_runtime_000000/pyarmor_runtime.pyd"
    );
    const V8_WRAPPER: &[u8] = include_bytes!(
        "../../../../corpus/python/pyarmor/v8/obfcode0/chunk_00_try_except_basic_try_except_else.py"
    );
    const V8_RUNTIME: &[u8] = include_bytes!(
        "../../../../corpus/python/pyarmor/v8/obfcode0/pyarmor_runtime_000000/pyarmor_runtime.pyd"
    );

    #[test]
    fn v9_module_matches_original_source_structure() -> Result<(), Box<dyn std::error::Error>> {
        let result: ModuleOutput = unpack(WRAPPER, RUNTIME)?;
        let metadata: serde_json::Value = serde_json::from_slice(&result.metadata)?;
        assert_eq!(metadata["runtime_format"], "9");
        assert_eq!(metadata["python_version"], "3.14");
        let names: Vec<String> = serde_json::from_value(metadata["names"].clone())?;
        for expected in [
            "add",
            "classify",
            "Counter",
            "__init__",
            "increment",
            "main",
            "value",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing source name {expected}"
            );
        }
        let strings: Vec<String> = serde_json::from_value(metadata["strings"].clone())?;
        for expected in ["disrobe-vmc-oracle-12345", "negative", "zero", "positive"] {
            assert!(
                strings.iter().any(|value| value == expected),
                "missing source string {expected}"
            );
        }
        assert!(metadata.get("aes_key").is_none());
        let mut trailing: Vec<u8> = result.bytes;
        trailing.push(0);
        assert!(validate_module(&trailing, PyVersion::PY314).is_err());
        Ok(())
    }

    #[test]
    fn v8_module_matches_reference_functions() -> Result<(), Box<dyn std::error::Error>> {
        let result: ModuleOutput = unpack(V8_WRAPPER, V8_RUNTIME)?;
        let metadata: serde_json::Value = serde_json::from_slice(&result.metadata)?;
        assert_eq!(metadata["runtime_format"], "8");
        assert_eq!(metadata["python_version"], "3.12");
        let names: Vec<String> = serde_json::from_value(metadata["names"].clone())?;
        for expected in [
            "try_except_basic",
            "try_except_else",
            "int",
            "ValueError",
            "KeyError",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing reference name {expected}"
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_wrong_and_oversized_inputs() -> Result<(), Box<dyn std::error::Error>> {
        assert!(unpack(WRAPPER, &[]).is_err());
        let mut wrong_runtime: Vec<u8> = RUNTIME.to_vec();
        let anchor: usize = wrong_runtime
            .windows(11)
            .position(|window| window == b"pyarmor-vax")
            .ok_or("missing runtime marker")?;
        wrong_runtime[anchor + 19] ^= 1;
        assert!(unpack(WRAPPER, &wrong_runtime).is_err());
        assert!(unpack(&vec![0; MAX_WRAPPER_BYTES + 1], RUNTIME).is_err());
        assert!(unpack(WRAPPER, &vec![0; MAX_RUNTIME_BYTES + 1]).is_err());
        assert!(unpack(b"print('plain Python')", RUNTIME).is_err());
        Ok(())
    }

    #[test]
    fn compatible_trial_runtimes_preserve_identical_module_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let v9: ModuleOutput = unpack(WRAPPER, RUNTIME)?;
        let v8: ModuleOutput = unpack(WRAPPER, V8_RUNTIME)?;
        assert_eq!(v8.bytes, v9.bytes);
        let metadata: serde_json::Value = serde_json::from_slice(&v8.metadata)?;
        assert_eq!(metadata["runtime_format"], "8");
        assert_eq!(metadata["python_version"], "3.14");
        Ok(())
    }

    #[test]
    fn rejects_noncode_and_invalid_header_offsets() {
        let mut bytes: Vec<u8> = vec![0; 8];
        bytes[0] = 8;
        bytes.push(b'N');
        assert!(validate_module(&bytes, PyVersion::PY314).is_err());
        bytes[..8].fill(255);
        assert!(validate_module(&bytes, PyVersion::PY314).is_err());
    }

    #[test]
    fn rejects_invalid_code_fields_after_structural_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let output: ModuleOutput = unpack(WRAPPER, RUNTIME)?;
        let (object, _): (Object, usize) = validate_module(&output.bytes, PyVersion::PY314)?;
        let Object::Code(mut code) = object else {
            return Err("expected code object".into());
        };
        validate_code_fields(&code)?;
        code.names.push(Object::Int(1));
        assert!(validate_code_fields(&code).is_err());
        code.names.pop();
        code.stacksize = -1;
        assert!(validate_code_fields(&code).is_err());
        Ok(())
    }
}
