use disrobe_pass_py_decompile::bytecode::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_disasm::{Instruction, disassemble, render_dis};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};
use serde::Serialize;

use crate::debug::{dbg_enabled, dbg_kv, dbg_line};
use crate::envelope::{PyeCodePayload, PyeEnvelope};
use crate::error::{Error, Result};

const MAX_MARSHAL_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const MAX_NESTED_CODE_DEPTH: usize = 32;
const MAX_CODE_OBJECT_SUMMARIES: usize = 4096;
const MAX_MARSHAL_TRAVERSAL_OBJECTS: usize = 131_072;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRecoverOpts {
    pub marshal_version: PyVersion,
    pub recurse_nested: bool,
}

impl Default for SourceRecoverOpts {
    fn default() -> Self {
        Self {
            marshal_version: PyVersion::PY311,
            recurse_nested: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRecoverOutput {
    pub original_filename: Option<String>,
    pub mtime: Option<i64>,
    pub marshal_size: usize,
    pub recovered_source: Option<String>,
    pub code_object_summary: Vec<CodeObjectSummary>,
    pub disasm: String,
}

impl SourceRecoverOutput {
    #[must_use]
    pub const fn from_inline_source(
        source: String,
        original_filename: Option<String>,
        mtime: Option<i64>,
    ) -> Self {
        Self {
            original_filename,
            mtime,
            marshal_size: 0,
            recovered_source: Some(source),
            code_object_summary: Vec::new(),
            disasm: String::new(),
        }
    }
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
    crate::envelope::validate_msgpack_bounds(bytes)?;
    let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let value: rmpv::Value = rmpv::decode::read_value(&mut cursor)
        .map_err(|e: rmpv::decode::Error| Error::Msgpack(format!("array decode failed: {e}")))?;
    ensure_msgpack_consumed(cursor.position(), bytes.len())?;
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

fn ensure_msgpack_consumed(position: u64, input_len: usize) -> Result<()> {
    let expected: u64 = u64::try_from(input_len)
        .map_err(|_| Error::Msgpack("input length exceeds u64".to_owned()))?;
    if position != expected {
        return Err(Error::Msgpack(
            "trailing bytes after msgpack value".to_owned(),
        ));
    }
    Ok(())
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
    if let Some(envelope) = map_envelope
        && let PyeCodePayload::Source(s) = &envelope.original_code
    {
        ensure_marshal_payload_limit(s.len(), "inline source")?;
        dbg_kv("inline-source", || {
            format!("free-version source string, {} bytes", s.len())
        });
        return Ok(SourceRecoverOutput::from_inline_source(
            s.clone(),
            None,
            envelope.eol,
        ));
    }
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
            PyeCodePayload::MarshalledBytes(b) => {
                ensure_marshal_payload_limit(b.len(), "map marshal payload")?;
                Ok((b.clone(), None, envelope.eol))
            }
            PyeCodePayload::Source(_) => Err(Error::Msgpack(
                "inline source payload is not a marshal stream; recover it as source directly"
                    .to_owned(),
            )),
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
    ensure_marshal_payload_limit(marshal_payload.len(), "marshal payload")?;
    let marshal_size: usize = marshal_payload.len();
    dbg_kv("marshal-load", || {
        format!("{marshal_size} bytes, version {:?}", opts.marshal_version)
    });
    let root_obj: Object = marshal_load(marshal_payload, opts.marshal_version)
        .map_err(|e: disrobe_py_marshal::Error| Error::Msgpack(format!("marshal: {e}")))?;
    let mut summaries: Vec<CodeObjectSummary> = Vec::new();
    let mut top_code: Option<&CodeObject> = None;
    if opts.recurse_nested {
        let mut path: Vec<usize> = Vec::new();
        let mut traversal: MarshalTraversal = MarshalTraversal::default();
        collect_code_objects_with_budget(
            &root_obj,
            &mut path,
            &mut summaries,
            &mut top_code,
            0,
            &mut traversal,
        )?;
    } else if let Object::Code(co) = &root_obj {
        top_code = Some(co.as_ref());
        summaries.push(summarize_code(co.as_ref(), &[]));
    }
    dbg_kv("code-objects-recovered", || summaries.len().to_string());
    if dbg_enabled() {
        for summary in &summaries {
            dbg_line(|| {
                format!(
                    "code object {} ({} bytes, {} consts, {} names) at depth {}",
                    summary.qualname,
                    summary.code_len,
                    summary.consts_count,
                    summary.names_count,
                    summary.nested_index_path.len()
                )
            });
        }
    }

    let recovered_source: Option<String> =
        top_code.and_then(|co: &CodeObject| decompile_code_object(co, opts.marshal_version));
    dbg_kv("source-decompiled", || {
        recovered_source.as_ref().map_or_else(
            || "none".to_owned(),
            |s: &String| format!("{} bytes", s.len()),
        )
    });
    let disasm: String = top_code
        .map(|co: &CodeObject| render_dis(&disassemble(co, opts.marshal_version)))
        .unwrap_or_default();

    Ok(SourceRecoverOutput {
        original_filename,
        mtime,
        marshal_size,
        recovered_source,
        code_object_summary: summaries,
        disasm,
    })
}

const fn ensure_marshal_payload_limit(input_len: usize, surface: &'static str) -> Result<()> {
    if input_len > MAX_MARSHAL_PAYLOAD_BYTES {
        return Err(Error::InputLimit {
            surface,
            observed: input_len,
            limit: MAX_MARSHAL_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

fn decompile_code_object(code: &CodeObject, marshal_version: PyVersion) -> Option<String> {
    let decompile_version: DecompileVersion = marshal_to_decompile(marshal_version).ok()?;
    build_real_source(code, &decompile_version, marshal_version).ok()
}

#[derive(Debug, Default)]
struct MarshalTraversal {
    visited: usize,
}

impl MarshalTraversal {
    fn visit(&mut self) -> Result<()> {
        self.visited = self.visited.checked_add(1).ok_or(Error::InputLimit {
            surface: "marshal object traversal",
            observed: usize::MAX,
            limit: MAX_MARSHAL_TRAVERSAL_OBJECTS,
        })?;
        if self.visited > MAX_MARSHAL_TRAVERSAL_OBJECTS {
            return Err(Error::InputLimit {
                surface: "marshal object traversal",
                observed: self.visited,
                limit: MAX_MARSHAL_TRAVERSAL_OBJECTS,
            });
        }
        Ok(())
    }
}

fn collect_code_objects<'a>(
    obj: &'a Object,
    path: &mut Vec<usize>,
    summaries: &mut Vec<CodeObjectSummary>,
    top: &mut Option<&'a CodeObject>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_NESTED_CODE_DEPTH {
        return Err(Error::NestingLimit {
            surface: "marshal code objects",
            limit: MAX_NESTED_CODE_DEPTH,
        });
    }
    let mut traversal: MarshalTraversal = MarshalTraversal::default();
    collect_code_objects_with_budget(obj, path, summaries, top, depth, &mut traversal)
}

fn collect_code_objects_with_budget<'a>(
    obj: &'a Object,
    path: &mut Vec<usize>,
    summaries: &mut Vec<CodeObjectSummary>,
    top: &mut Option<&'a CodeObject>,
    depth: usize,
    traversal: &mut MarshalTraversal,
) -> Result<()> {
    if depth > MAX_NESTED_CODE_DEPTH {
        return Err(Error::NestingLimit {
            surface: "marshal code objects",
            limit: MAX_NESTED_CODE_DEPTH,
        });
    }
    traversal.visit()?;
    match obj {
        Object::Code(co) => {
            if top.is_none() {
                *top = Some(co.as_ref());
            }
            if summaries.len() >= MAX_CODE_OBJECT_SUMMARIES {
                return Err(Error::InputLimit {
                    surface: "marshal code summaries",
                    observed: summaries.len().saturating_add(1),
                    limit: MAX_CODE_OBJECT_SUMMARIES,
                });
            }
            summaries.push(summarize_code(co.as_ref(), path));
            for (idx, c) in co.consts.iter().enumerate() {
                collect_code_object_child(c, idx, path, summaries, top, depth, traversal)?;
            }
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for (idx, c) in items.iter().enumerate() {
                collect_code_object_child(c, idx, path, summaries, top, depth, traversal)?;
            }
        }
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (idx, (key, value)) in d.iter().enumerate() {
                let key_index: usize = idx
                    .checked_mul(2)
                    .ok_or_else(|| Error::Msgpack("marshal dictionary path overflow".to_owned()))?;
                let value_index: usize = key_index
                    .checked_add(1)
                    .ok_or_else(|| Error::Msgpack("marshal dictionary path overflow".to_owned()))?;
                collect_code_object_child(key, key_index, path, summaries, top, depth, traversal)?;
                collect_code_object_child(
                    value,
                    value_index,
                    path,
                    summaries,
                    top,
                    depth,
                    traversal,
                )?;
            }
        }
        Object::Slice { lower, upper, step } => {
            collect_code_object_child(lower, 0, path, summaries, top, depth, traversal)?;
            collect_code_object_child(upper, 1, path, summaries, top, depth, traversal)?;
            collect_code_object_child(step, 2, path, summaries, top, depth, traversal)?;
        }
        _ => {}
    }
    Ok(())
}

fn collect_code_object_child<'a>(
    child: &'a Object,
    index: usize,
    path: &mut Vec<usize>,
    summaries: &mut Vec<CodeObjectSummary>,
    top: &mut Option<&'a CodeObject>,
    depth: usize,
    traversal: &mut MarshalTraversal,
) -> Result<()> {
    let next_depth: usize = depth.checked_add(1).ok_or(Error::NestingLimit {
        surface: "marshal code objects",
        limit: MAX_NESTED_CODE_DEPTH,
    })?;
    path.push(index);
    let outcome: Result<()> =
        collect_code_objects_with_budget(child, path, summaries, top, next_depth, traversal);
    let _: Option<usize> = path.pop();
    outcome
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
        _ => "<non-string-code-field>".to_owned(),
    }
}

#[allow(dead_code)]
fn _disasm_first_code_object(root: &Object, py_version: PyVersion) -> Option<Vec<Instruction>> {
    let mut top: Option<&CodeObject> = None;
    let mut path: Vec<usize> = Vec::new();
    let mut summaries: Vec<CodeObjectSummary> = Vec::new();
    collect_code_objects(root, &mut path, &mut summaries, &mut top, 0).ok()?;
    top.map(|co: &CodeObject| disassemble(co, py_version))
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
    fn recover_from_marshal_bytes_walks_code_objects_in_slices() {
        let nested: CodeObject = build_synthetic_code("slice_nested", Vec::new());
        let root: Object = Object::Slice {
            lower: Box::new(Object::Code(Box::new(nested))),
            upper: Box::new(Object::None),
            step: Box::new(Object::None),
        };
        let marshal_bytes: Vec<u8> = marshal_dump(&root, PyVersion::PY311).expect("dump");
        let output: SourceRecoverOutput =
            recover_from_marshal_bytes(&marshal_bytes, None, None, SourceRecoverOpts::default())
                .expect("recover slice");
        assert!(
            output
                .code_object_summary
                .iter()
                .any(|summary: &CodeObjectSummary| summary.name == "slice_nested")
        );
    }

    #[test]
    fn recover_from_plaintext_emits_inline_source_without_marshal_load() {
        const FREE_SOURCE: &str = "def add(a, b):\n    return a + b\n\n\nprint(add(2, 3))\n";
        let map_envelope: PyeEnvelope = PyeEnvelope {
            original_code: PyeCodePayload::Source(FREE_SOURCE.to_owned()),
            deadline: None,
            eol: Some(99),
            other_fields: Vec::new(),
        };
        let opts: SourceRecoverOpts = SourceRecoverOpts::default();
        let output: SourceRecoverOutput =
            recover_from_plaintext(&[], Some(&map_envelope), opts).expect("inline source recover");
        assert_eq!(output.recovered_source.as_deref(), Some(FREE_SOURCE));
        assert_eq!(output.mtime, Some(99));
        assert_eq!(output.marshal_size, 0);
        assert!(output.code_object_summary.is_empty());
        assert!(output.disasm.is_empty());
    }

    #[test]
    fn inline_source_payload_is_never_routed_through_marshal_load() {
        let envelope: PyeEnvelope = PyeEnvelope {
            original_code: PyeCodePayload::Source("x = 1\n".to_owned()),
            deadline: None,
            eol: None,
            other_fields: Vec::new(),
        };
        let err: Error = extract_marshal_from_envelope(&[], Some(&envelope))
            .expect_err("source payload must not coerce to marshal bytes");
        assert!(matches!(err, Error::Msgpack(_)));
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

    #[test]
    fn parse_array_envelope_rejects_declared_binary_over_cap_before_decode() {
        let mut bytes: Vec<u8> = vec![0x91, 0xc6];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        let err: Error =
            parse_array_envelope(&bytes).expect_err("oversized binary declaration must fail");
        assert!(matches!(err, Error::Msgpack(msg) if msg.contains("binary length")));
    }
}
