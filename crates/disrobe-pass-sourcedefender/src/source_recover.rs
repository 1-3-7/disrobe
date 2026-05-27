use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_py_disasm::{Instruction, disassemble, render_dis};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};
use serde::Serialize;

use crate::envelope::{PyeCodePayload, PyeEnvelope};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRecoverOpts {
    pub marshal_version: PyVersion,
    pub invoke_pycdc: bool,
    pub recurse_nested: bool,
}

impl Default for SourceRecoverOpts {
    fn default() -> Self {
        Self {
            marshal_version: PyVersion::PY311,
            invoke_pycdc: false,
            recurse_nested: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRecoverOutput {
    pub original_filename: Option<String>,
    pub mtime: Option<i64>,
    pub marshal_size: usize,
    pub code_object_summary: Vec<CodeObjectSummary>,
    pub decompiled_source: Option<String>,
    pub disasm: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeObjectSummary {
    pub name: String,
    pub qualname: String,
    pub filename: String,
    pub argcount: i32,
    pub posonlyargcount: i32,
    pub kwonlyargcount: i32,
    pub stacksize: i32,
    pub flags: i32,
    pub firstlineno: i32,
    pub code_len: usize,
    pub consts_count: usize,
    pub names_count: usize,
    pub nested_index_path: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPyeArrayEnvelope {
    pub marshal_payload: Vec<u8>,
    pub original_filename: Option<String>,
    pub mtime: Option<i64>,
}

pub fn parse_array_envelope(bytes: &[u8]) -> Result<ParsedPyeArrayEnvelope> {
    let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let value: rmpv::Value = rmpv::decode::read_value(&mut cursor)
        .map_err(|e: rmpv::decode::Error| Error::Msgpack(format!("array decode failed: {e}")))?;
    let rmpv::Value::Array(items) = value else {
        return Err(Error::Msgpack("expected msgpack array envelope".to_owned()));
    };
    if items.is_empty() {
        return Err(Error::Msgpack("array envelope is empty".to_owned()));
    }
    let marshal_payload: Vec<u8> = match items.first() {
        Some(rmpv::Value::Binary(b)) => b.clone(),
        Some(rmpv::Value::String(s)) => s.clone().into_bytes(),
        _ => {
            return Err(Error::Msgpack(
                "first array element must be marshal bytes".to_owned(),
            ));
        }
    };
    let original_filename: Option<String> = match items.get(1) {
        Some(rmpv::Value::String(s)) => s.as_str().map(ToOwned::to_owned),
        Some(rmpv::Value::Binary(b)) => core::str::from_utf8(b).ok().map(ToOwned::to_owned),
        _ => None,
    };
    let mtime: Option<i64> = match items.get(2) {
        Some(rmpv::Value::Integer(i)) => i.as_i64(),
        _ => None,
    };
    Ok(ParsedPyeArrayEnvelope {
        marshal_payload,
        original_filename,
        mtime,
    })
}

pub fn decrypt_pye_to_source(
    bytes: &[u8],
    filename: &str,
    opts: SourceRecoverOpts,
) -> Result<SourceRecoverOutput> {
    let decrypted: crate::envelope::DecryptedPye = crate::envelope::decrypt_pye(bytes, filename)?;
    recover_from_plaintext(
        &decrypted.plaintext_msgpack,
        decrypted.envelope.as_ref(),
        opts,
    )
}

pub fn recover_from_plaintext(
    plaintext_msgpack: &[u8],
    map_envelope: Option<&PyeEnvelope>,
    opts: SourceRecoverOpts,
) -> Result<SourceRecoverOutput> {
    let (marshal_payload, original_filename, mtime): (Vec<u8>, Option<String>, Option<i64>) =
        extract_marshal_from_envelope(plaintext_msgpack, map_envelope)?;
    finalize_from_marshal(&marshal_payload, original_filename, mtime, opts)
}

pub fn recover_from_marshal_bytes(
    marshal_payload: &[u8],
    original_filename: Option<String>,
    mtime: Option<i64>,
    opts: SourceRecoverOpts,
) -> Result<SourceRecoverOutput> {
    finalize_from_marshal(marshal_payload, original_filename, mtime, opts)
}

fn extract_marshal_from_envelope(
    plaintext_msgpack: &[u8],
    map_envelope: Option<&PyeEnvelope>,
) -> Result<(Vec<u8>, Option<String>, Option<i64>)> {
    if let Some(envelope) = map_envelope {
        return match &envelope.original_code {
            PyeCodePayload::MarshalledBytes(b) => Ok((b.clone(), None, envelope.eol)),
            PyeCodePayload::Source(s) => Ok((s.as_bytes().to_vec(), None, envelope.eol)),
        };
    }
    let parsed: ParsedPyeArrayEnvelope = parse_array_envelope(plaintext_msgpack)?;
    Ok((
        parsed.marshal_payload,
        parsed.original_filename,
        parsed.mtime,
    ))
}

fn finalize_from_marshal(
    marshal_payload: &[u8],
    original_filename: Option<String>,
    mtime: Option<i64>,
    opts: SourceRecoverOpts,
) -> Result<SourceRecoverOutput> {
    let marshal_size: usize = marshal_payload.len();
    let root_obj: Object = marshal_load(marshal_payload, opts.marshal_version)
        .map_err(|e: disrobe_py_marshal::Error| Error::Msgpack(format!("marshal: {e}")))?;
    let mut summaries: Vec<CodeObjectSummary> = Vec::new();
    let mut top_code: Option<CodeObject> = None;
    if opts.recurse_nested {
        collect_code_objects(&root_obj, &mut Vec::new(), &mut summaries, &mut top_code, 0);
    } else if let Object::Code(co) = &root_obj {
        top_code = Some((**co).clone());
        summaries.push(summarize_code(co.as_ref(), &[]));
    }

    let disasm: String = top_code
        .as_ref()
        .map(|co: &CodeObject| render_dis(&disassemble(co, opts.marshal_version)))
        .unwrap_or_default();

    let decompiled_source: Option<String> = if opts.invoke_pycdc {
        try_invoke_pycdc(marshal_payload, opts.marshal_version)
    } else {
        None
    };

    Ok(SourceRecoverOutput {
        original_filename,
        mtime,
        marshal_size,
        code_object_summary: summaries,
        decompiled_source,
        disasm,
    })
}

const MAX_NESTED_CODE_DEPTH: usize = 32;

fn collect_code_objects(
    obj: &Object,
    path: &mut Vec<usize>,
    summaries: &mut Vec<CodeObjectSummary>,
    top: &mut Option<CodeObject>,
    depth: usize,
) {
    if depth > MAX_NESTED_CODE_DEPTH {
        return;
    }
    match obj {
        Object::Code(co) => {
            if top.is_none() {
                *top = Some((**co).clone());
            }
            summaries.push(summarize_code(co.as_ref(), path));
            for (idx, c) in co.consts.iter().enumerate() {
                path.push(idx);
                collect_code_objects(c, path, summaries, top, depth + 1);
                path.pop();
            }
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for (idx, c) in items.iter().enumerate() {
                path.push(idx);
                collect_code_objects(c, path, summaries, top, depth + 1);
                path.pop();
            }
        }
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (idx, (_, v)) in d.iter().enumerate() {
                path.push(idx);
                collect_code_objects(v, path, summaries, top, depth + 1);
                path.pop();
            }
        }
        _ => {}
    }
}

fn summarize_code(co: &CodeObject, path: &[usize]) -> CodeObjectSummary {
    CodeObjectSummary {
        name: object_to_string(&co.name),
        qualname: object_to_string(&co.qualname),
        filename: object_to_string(&co.filename),
        argcount: co.argcount,
        posonlyargcount: co.posonlyargcount,
        kwonlyargcount: co.kwonlyargcount,
        stacksize: co.stacksize,
        flags: co.flags,
        firstlineno: co.firstlineno,
        code_len: co.code.len(),
        consts_count: co.consts.len(),
        names_count: co.names.len(),
        nested_index_path: path.to_vec(),
    }
}

fn object_to_string(obj: &Object) -> String {
    match obj {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
        Object::None => String::new(),
        other => format!("{other:?}"),
    }
}

fn try_invoke_pycdc(marshal_payload: &[u8], py_version: PyVersion) -> Option<String> {
    let exe: PathBuf = which_pycdc()?;
    let tmp_dir: PathBuf = std::env::temp_dir();
    let pyc_path: PathBuf = tmp_dir.join(format!(
        "disrobe-pyc-{pid}-{nanos}.pyc",
        pid = std::process::id(),
        nanos = unique_nanos()
    ));
    let header: Vec<u8> = build_pyc_header(py_version);
    let mut blob: Vec<u8> = Vec::with_capacity(header.len() + marshal_payload.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(marshal_payload);
    if std::fs::write(&pyc_path, &blob).is_err() {
        return None;
    }
    let output: Option<std::process::Output> = Command::new(exe).arg(&pyc_path).output().ok();
    let _: std::io::Result<()> = std::fs::remove_file(&pyc_path);
    let captured: std::process::Output = output?;
    if !captured.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&captured.stdout).into_owned();
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}

fn which_pycdc() -> Option<PathBuf> {
    let candidate: &str = if cfg!(windows) { "pycdc.exe" } else { "pycdc" };
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full: PathBuf = dir.join(candidate);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

fn build_pyc_header(py_version: PyVersion) -> Vec<u8> {
    let magic: u16 = disrobe_py_marshal::magic_for(py_version).unwrap_or(3495);
    let trailing_u32_count: usize = if py_version.has_pep552_header() {
        3
    } else if py_version.has_source_size() {
        2
    } else {
        1
    };
    let mut header: Vec<u8> = Vec::with_capacity(4 + trailing_u32_count * 4);
    header.extend_from_slice(&magic.to_le_bytes());
    header.extend_from_slice(b"\r\n");
    for _ in 0..trailing_u32_count {
        header.extend_from_slice(&0u32.to_le_bytes());
    }
    header
}

fn unique_nanos() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0x1234_5678);
    u128::from(COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[allow(dead_code)]
fn _disasm_first_code_object(root: &Object, py_version: PyVersion) -> Option<Vec<Instruction>> {
    let mut top: Option<CodeObject> = None;
    let mut path: Vec<usize> = Vec::new();
    let mut summaries: Vec<CodeObjectSummary> = Vec::new();
    collect_code_objects(root, &mut path, &mut summaries, &mut top, 0);
    top.map(|co: CodeObject| disassemble(&co, py_version))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_py_marshal::{CodeEra, CodeObject, Object, dump as marshal_dump};

    use super::*;

    fn build_synthetic_code(name: &str, nested: Vec<CodeObject>) -> CodeObject {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.name = Object::ShortAscii {
            value: name.to_owned(),
            interned: false,
        };
        co.qualname = Object::ShortAscii {
            value: name.to_owned(),
            interned: false,
        };
        co.filename = Object::ShortAscii {
            value: format!("<{name}>"),
            interned: false,
        };
        co.firstlineno = 1;
        co.code = vec![0x97, 0x00, 0x64, 0x00, 0x53, 0x00];
        co.consts = nested
            .into_iter()
            .map(|c: CodeObject| Object::Code(Box::new(c)))
            .collect();
        co
    }

    fn build_pye_array_envelope(marshal_bytes: &[u8], filename: &str, mtime: i64) -> Vec<u8> {
        let value: rmpv::Value = rmpv::Value::Array(vec![
            rmpv::Value::Binary(marshal_bytes.to_vec()),
            rmpv::Value::String(filename.into()),
            rmpv::Value::Integer(mtime.into()),
        ]);
        let mut out: Vec<u8> = Vec::with_capacity(marshal_bytes.len() + filename.len() + 32);
        rmpv::encode::write_value(&mut out, &value).expect("encode");
        out
    }

    #[test]
    fn parse_array_envelope_extracts_three_fields() {
        let marshal_bytes: Vec<u8> = vec![1u8, 2, 3, 4, 5];
        let env_bytes: Vec<u8> =
            build_pye_array_envelope(&marshal_bytes, "module.py", 1_700_000_000);
        let parsed: ParsedPyeArrayEnvelope = parse_array_envelope(&env_bytes).expect("parse");
        assert_eq!(parsed.marshal_payload, marshal_bytes);
        assert_eq!(parsed.original_filename.as_deref(), Some("module.py"));
        assert_eq!(parsed.mtime, Some(1_700_000_000));
    }

    #[test]
    fn recover_from_marshal_bytes_disassembles_flat_code_object() {
        let co: CodeObject = build_synthetic_code("entry_flat", Vec::new());
        let marshal_bytes: Vec<u8> =
            marshal_dump(&Object::Code(Box::new(co)), PyVersion::PY311).expect("dump");
        let opts: SourceRecoverOpts = SourceRecoverOpts::default();
        let output: SourceRecoverOutput = recover_from_marshal_bytes(
            &marshal_bytes,
            Some("entry.py".to_owned()),
            Some(1_700_000_000),
            opts,
        )
        .expect("recover");
        assert_eq!(output.original_filename.as_deref(), Some("entry.py"));
        assert_eq!(output.mtime, Some(1_700_000_000));
        assert_eq!(output.marshal_size, marshal_bytes.len());
        assert_eq!(output.code_object_summary.len(), 1);
        assert_eq!(output.code_object_summary[0].name, "entry_flat");
        assert!(!output.disasm.is_empty());
        assert!(output.decompiled_source.is_none());
    }

    #[test]
    fn recover_from_plaintext_handles_array_envelope_and_walks_nested_code_objects() {
        let inner_a: CodeObject = build_synthetic_code("helper_a", Vec::new());
        let inner_b: CodeObject = build_synthetic_code("helper_b", Vec::new());
        let outer: CodeObject = build_synthetic_code("root_with_helpers", vec![inner_a, inner_b]);
        let marshal_bytes: Vec<u8> =
            marshal_dump(&Object::Code(Box::new(outer)), PyVersion::PY311).expect("dump");
        let env_bytes: Vec<u8> = build_pye_array_envelope(&marshal_bytes, "pkg/mod.py", 42);
        let opts: SourceRecoverOpts = SourceRecoverOpts::default();
        let output: SourceRecoverOutput =
            recover_from_plaintext(&env_bytes, None, opts).expect("recover plaintext");
        assert_eq!(output.original_filename.as_deref(), Some("pkg/mod.py"));
        let names: Vec<String> = output
            .code_object_summary
            .iter()
            .map(|s: &CodeObjectSummary| s.name.clone())
            .collect();
        assert!(names.iter().any(|n: &String| n == "root_with_helpers"));
        assert!(names.iter().any(|n: &String| n == "helper_a"));
        assert!(names.iter().any(|n: &String| n == "helper_b"));
    }

    #[test]
    fn recover_from_plaintext_uses_map_envelope_when_provided() {
        let co: CodeObject = build_synthetic_code("via_map", Vec::new());
        let marshal_bytes: Vec<u8> =
            marshal_dump(&Object::Code(Box::new(co)), PyVersion::PY311).expect("dump");
        let map_envelope: PyeEnvelope = PyeEnvelope {
            original_code: PyeCodePayload::MarshalledBytes(marshal_bytes.clone()),
            deadline: None,
            eol: Some(1234),
            other_fields: Vec::new(),
        };
        let opts: SourceRecoverOpts = SourceRecoverOpts::default();
        let output: SourceRecoverOutput =
            recover_from_plaintext(&[], Some(&map_envelope), opts).expect("recover map");
        assert_eq!(output.marshal_size, marshal_bytes.len());
        assert_eq!(output.mtime, Some(1234));
        assert_eq!(output.code_object_summary.len(), 1);
        assert_eq!(output.code_object_summary[0].name, "via_map");
    }

    #[test]
    fn parse_array_envelope_rejects_non_array_root() {
        let value: rmpv::Value =
            rmpv::Value::Map(vec![(rmpv::Value::String("k".into()), rmpv::Value::Nil)]);
        let mut out: Vec<u8> = Vec::new();
        rmpv::encode::write_value(&mut out, &value).expect("encode map");
        let err: Error = parse_array_envelope(&out).expect_err("non-array root must fail");
        assert!(matches!(err, Error::Msgpack(_)));
    }
}
