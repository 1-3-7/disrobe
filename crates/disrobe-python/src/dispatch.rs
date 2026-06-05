use disrobe_pass_beam::{BeamFile, CodeChunk, Disassembly as BeamDisassembly};
use disrobe_pass_jvm::{ClassFile, DexFile, parse_classfile, parse_dex};
use disrobe_pass_mobile::hermes::{
    DisassemblyReport as HermesDisassemblyReport, HermesModule, disassemble as hermes_disassemble,
    parse as parse_hermes_bundle,
};
use disrobe_pass_py_decompile::engine::{NativeDecompile, decompile_pyc};
use disrobe_pass_py_disasm::{Instruction as PyDisasmInstruction, disassemble as py_disassemble};
use disrobe_pass_wasm_deob::{ModuleSummary, analyze_module};
use disrobe_py_marshal::PyVersion as MarshalVersion;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule};

use crate::convert::to_py;
use crate::err::{DisrobeError, unsupported_language};

const PYTHON_LANGS: &[&str] = &["python", "py", "python3"];

/// Disassemble source or bytes in the given language.
#[pyfunction]
#[pyo3(signature = (language, source))]
#[pyo3(text_signature = "(language, source)")]
fn disasm(py: Python<'_>, language: &str, source: PyObject) -> PyResult<String> {
    let lang: String = language.to_ascii_lowercase();
    if PYTHON_LANGS.contains(&lang.as_str()) {
        let src: String = extract_str(py, &source, language)?;
        return python_disasm_via_host(py, &src);
    }
    match lang.as_str() {
        "python-bytecode" | "pyc" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            python_pyc_disasm_text(&bytes)
        }
        "jvm-class" | "class" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let cf: ClassFile =
                parse_classfile(&bytes).map_err(crate::err::map("jvm classfile"))?;
            Ok(jvm_classfile_text(&cf))
        }
        "dex" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let dex: DexFile = parse_dex(&bytes).map_err(crate::err::map("dex"))?;
            Ok(dex_text(&dex))
        }
        "beam" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let beam: BeamFile = BeamFile::parse(&bytes).map_err(crate::err::map("beam"))?;
            let code: &CodeChunk =
                beam.chunks.code.as_ref().ok_or_else(|| {
                    DisrobeError::new_err("beam file has no Code chunk".to_owned())
                })?;
            let dis: BeamDisassembly = disrobe_pass_beam::disassemble(code)
                .map_err(crate::err::map("beam disassemble"))?;
            Ok(beam_text(&dis))
        }
        "hermes" | "hermes-bundle" | "hbc" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let module: HermesModule =
                parse_hermes_bundle(&bytes).map_err(crate::err::map("hermes"))?;
            let report: HermesDisassemblyReport = hermes_disassemble(&module);
            Ok(hermes_text(&report))
        }
        "wasm" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let summary: ModuleSummary = analyze_module(&bytes).map_err(crate::err::map("wasm"))?;
            Ok(wasm_text(&summary))
        }
        "lua" => Err(unsupported_language(
            language,
            "compile to .luac via `luac -o` then call `disrobe.disasm('lua-bytecode', bytes)` \
             (lua bytecode pass lands in v0.10)",
        )),
        "ruby" => Err(unsupported_language(
            language,
            "use `RubyVM::InstructionSequence.compile(src).disasm` via the host ruby; \
             ruby bytecode pass lands in v0.10",
        )),
        "php" | "php-bytecode" => Err(unsupported_language(
            language,
            "use the `disrobe-pass-php` CLI subcommand or the upcoming Python binding in v0.10",
        )),
        other => Err(unsupported_language(
            other,
            "no backing disasm implementation",
        )),
    }
}

/// Parse source or bytes into the language's structured IR, returning a dict.
#[pyfunction]
#[pyo3(signature = (language, source))]
#[pyo3(text_signature = "(language, source)")]
fn parse<'py>(py: Python<'py>, language: &str, source: PyObject) -> PyResult<Bound<'py, PyAny>> {
    let lang: String = language.to_ascii_lowercase();
    if PYTHON_LANGS.contains(&lang.as_str()) {
        let src: String = extract_str(py, &source, language)?;
        return python_parse_via_host(py, &src);
    }
    match lang.as_str() {
        "python-bytecode" | "pyc" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let result: NativeDecompile =
                decompile_pyc(&bytes).map_err(crate::err::map("py.parse"))?;
            let marshal: MarshalVersion = result.marshal_version;
            let ins: Vec<PyDisasmInstruction> = py_disassemble(&result.code, marshal);
            let payload: serde_json::Value = serde_json::json!({
                "kind": "pyc",
                "source": result.source,
                "marshal_version": format!("{}.{}", marshal.major, marshal.minor),
                "instructions": ins.iter().map(|i: &PyDisasmInstruction| {
                    serde_json::json!({
                        "offset": i.offset,
                        "opname": i.opname,
                        "arg": i.arg,
                        "argrepr": i.argrepr,
                    })
                }).collect::<Vec<_>>(),
            });
            to_py(py, &payload)
        }
        "jvm-class" | "class" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let cf: ClassFile =
                parse_classfile(&bytes).map_err(crate::err::map("jvm classfile"))?;
            to_py(py, &cf)
        }
        "dex" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let dex: DexFile = parse_dex(&bytes).map_err(crate::err::map("dex"))?;
            to_py(py, &dex)
        }
        "wasm" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let summary: ModuleSummary = analyze_module(&bytes).map_err(crate::err::map("wasm"))?;
            to_py(py, &summary)
        }
        "hermes" | "hermes-bundle" | "hbc" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let module: HermesModule =
                parse_hermes_bundle(&bytes).map_err(crate::err::map("hermes"))?;
            let report: HermesDisassemblyReport = hermes_disassemble(&module);
            to_py(py, &report)
        }
        "beam" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let beam: BeamFile = BeamFile::parse(&bytes).map_err(crate::err::map("beam"))?;
            let code: &CodeChunk =
                beam.chunks.code.as_ref().ok_or_else(|| {
                    DisrobeError::new_err("beam file has no Code chunk".to_owned())
                })?;
            let dis: BeamDisassembly = disrobe_pass_beam::disassemble(code)
                .map_err(crate::err::map("beam disassemble"))?;
            to_py(py, &dis)
        }
        "javascript" | "js" | "typescript" | "ts" => Err(unsupported_language(
            language,
            "no structural JS/TS parser shipped yet; use `disrobe.js_unminify` for surface analysis",
        )),
        "go" | "swift" | "kotlin" | "ruby" | "lua" | "php" => Err(unsupported_language(
            language,
            "source-level parser for this language lands in v0.10; \
             use the equivalent CLI subcommand for now",
        )),
        other => Err(unsupported_language(
            other,
            "no backing parse implementation",
        )),
    }
}

/// Compile source in the given language to bytecode bytes.
#[pyfunction]
#[pyo3(signature = (language, source, *, version = None))]
#[pyo3(text_signature = "(language, source, *, version=None)")]
fn compile<'py>(
    py: Python<'py>,
    language: &str,
    source: &str,
    version: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _: Option<&str> = version;
    let lang: String = language.to_ascii_lowercase();
    if PYTHON_LANGS.contains(&lang.as_str()) {
        return python_compile_via_host(py, source);
    }
    match lang.as_str() {
        "lua" => Err(unsupported_language(
            language,
            "spawn `luac -o -` if `luac` is on PATH; lua bytecode pass lands in v0.10",
        )),
        "ruby" => Err(unsupported_language(
            language,
            "use `RubyVM::InstructionSequence.compile(src).to_binary` via the host ruby",
        )),
        other => Err(unsupported_language(
            other,
            "compile is implemented for python only; use the language's native toolchain",
        )),
    }
}

fn python_disasm_via_host<'py>(py: Python<'py>, source: &str) -> PyResult<String> {
    let dis: Bound<'py, PyModule> = PyModule::import(py, "dis")?;
    let builtins: Bound<'py, PyModule> = PyModule::import(py, "builtins")?;
    let compile_fn: Bound<'py, PyAny> = builtins.getattr("compile")?;
    let code: Bound<'py, PyAny> = compile_fn.call1((source, "<disrobe>", "exec"))?;
    let io: Bound<'py, PyModule> = PyModule::import(py, "io")?;
    let buf: Bound<'py, PyAny> = io.getattr("StringIO")?.call0()?;
    let kwargs: Bound<'py, pyo3::types::PyDict> = pyo3::types::PyDict::new(py);
    kwargs.set_item("file", buf.clone())?;
    dis.getattr("dis")?.call((code,), Some(&kwargs))?;
    let text: String = buf.call_method0("getvalue")?.extract()?;
    Ok(text)
}

fn python_pyc_disasm_text(bytes: &[u8]) -> PyResult<String> {
    let result: NativeDecompile = decompile_pyc(bytes).map_err(crate::err::map("py.disasm"))?;
    let marshal: MarshalVersion = result.marshal_version;
    let ins: Vec<PyDisasmInstruction> = py_disassemble(&result.code, marshal);
    Ok(disrobe_pass_py_disasm::render_dis(&ins))
}

fn python_parse_via_host<'py>(py: Python<'py>, source: &str) -> PyResult<Bound<'py, PyAny>> {
    let ast: Bound<'py, PyModule> = PyModule::import(py, "ast")?;
    let tree: Bound<'py, PyAny> = ast.getattr("parse")?.call1((source,))?;
    let dump: Bound<'py, PyAny> = ast.getattr("dump")?.call1((tree.clone(),))?;
    let kwargs: Bound<'py, pyo3::types::PyDict> = pyo3::types::PyDict::new(py);
    kwargs.set_item("type", "Module")?;
    kwargs.set_item("kind", "module")?;
    kwargs.set_item("dump", dump)?;
    Ok(kwargs.into_any())
}

fn python_compile_via_host<'py>(py: Python<'py>, source: &str) -> PyResult<Bound<'py, PyBytes>> {
    let builtins: Bound<'py, PyModule> = PyModule::import(py, "builtins")?;
    let compile_fn: Bound<'py, PyAny> = builtins.getattr("compile")?;
    let code: Bound<'py, PyAny> = compile_fn.call1((source, "<disrobe>", "exec"))?;
    let marshal: Bound<'py, PyModule> = PyModule::import(py, "marshal")?;
    let dumped: Bound<'py, PyAny> = marshal.getattr("dumps")?.call1((code,))?;
    let bytes: Bound<'py, PyBytes> = dumped
        .downcast_into::<PyBytes>()
        .map_err(|e| DisrobeError::new_err(format!("marshal.dumps returned non-bytes: {e}")))?;
    Ok(bytes)
}

fn extract_str(py: Python<'_>, source: &PyObject, language: &str) -> PyResult<String> {
    let bound: Bound<'_, PyAny> = source.bind(py).clone();
    bound.extract::<String>().map_err(|_| {
        DisrobeError::new_err(format!(
            "language `{language}` expects str source, got {}",
            bound
                .get_type()
                .name()
                .map_or_else(|_| "?".to_owned(), |n| n.to_string())
        ))
    })
}

fn extract_bytes(py: Python<'_>, source: &PyObject, language: &str) -> PyResult<Vec<u8>> {
    let bound: Bound<'_, PyAny> = source.bind(py).clone();
    if let Ok(b) = bound.downcast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(v) = bound.extract::<Vec<u8>>() {
        return Ok(v);
    }
    Err(DisrobeError::new_err(format!(
        "language `{language}` expects bytes source, got {}",
        bound
            .get_type()
            .name()
            .map_or_else(|_| "?".to_owned(), |n| n.to_string())
    )))
}

fn jvm_classfile_text(cf: &ClassFile) -> String {
    let mut s: String = String::with_capacity(256);
    let class_name: String = cf
        .this_class_name()
        .map_or_else(|_| format!("#{}", cf.this_class), str::to_owned);
    s.push_str(&format!(
        "// class {class_name} (minor {}, major {})\n",
        cf.minor_version, cf.major_version
    ));
    for (i, m) in cf.methods.iter().enumerate() {
        let name: &str = cf.utf8_at(m.name_index).unwrap_or("?");
        let desc: &str = cf.utf8_at(m.descriptor_index).unwrap_or("?");
        s.push_str(&format!("method[{i}] {name} {desc}\n"));
    }
    for (i, f) in cf.fields.iter().enumerate() {
        let name: &str = cf.utf8_at(f.name_index).unwrap_or("?");
        let desc: &str = cf.utf8_at(f.descriptor_index).unwrap_or("?");
        s.push_str(&format!("field[{i}] {name} {desc}\n"));
    }
    s
}

fn dex_text(dex: &DexFile) -> String {
    let mut s: String = String::with_capacity(256);
    s.push_str(&format!("// dex header version {:?}\n", dex.header.version));
    s.push_str(&format!("strings:   {}\n", dex.strings.len()));
    s.push_str(&format!("types:     {}\n", dex.type_names.len()));
    s.push_str(&format!("classes:   {}\n", dex.class_descriptors.len()));
    s
}

fn beam_text(dis: &BeamDisassembly) -> String {
    let mut s: String = String::with_capacity(dis.instructions.len() * 32);
    for (i, ins) in dis.instructions.iter().enumerate() {
        s.push_str(&format!("{i:5} {}\n", ins.name));
    }
    s
}

fn hermes_text(report: &HermesDisassemblyReport) -> String {
    let mut s: String = String::with_capacity(256);
    s.push_str(&format!(
        "// hermes bundle: {} functions, {} identifiers, {} strings\n",
        report.function_count, report.identifier_count, report.string_count
    ));
    for f in &report.functions {
        s.push_str(&format!(
            "func[{}] {} params={} frame={} bytes={}\n",
            f.index, f.function_name, f.param_count, f.frame_size, f.bytecode_size_bytes
        ));
    }
    s
}

fn wasm_text(summary: &ModuleSummary) -> String {
    serde_json::to_string_pretty(summary).unwrap_or_else(|_| String::from("// wasm summary"))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(disasm, m)?)?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    Ok(())
}
