use disrobe_pass_beam::{BeamFile, CodeChunk, Disassembly as BeamDisassembly};
use disrobe_pass_go::{GoAnalysis, analyze as go_analyze};
use disrobe_pass_js_deob::{UnminifyStats, unminify};
use disrobe_pass_jvm::{
    ClassFile, DecompiledClass, DexFile, KotlinMetadata, decompile_class, parse_classfile,
    parse_dex, recover_kotlin_metadata,
};
use disrobe_pass_lua::{DecompiledChunk, Fidelity as LuaFidelity, decompile_auto};
use disrobe_pass_mobile::hermes::{
    DisassemblyReport as HermesDisassemblyReport, HermesModule, disassemble as hermes_disassemble,
    parse as parse_hermes_bundle,
};
use disrobe_pass_php::{
    Decompilation as PhpDecompilation, OpArray as PhpOpArray, PeelOptions as PhpPeelOptions,
    PeelReport as PhpPeelReport, decompile_oparray as php_decompile_oparray,
    opcode_name as php_opcode_name, parse_oparray as php_parse_oparray,
    peel_eval_chain as php_peel_eval_chain,
};
use disrobe_pass_py_decompile::engine::{NativeDecompile, decompile_pyc};
use disrobe_pass_py_disasm::{Instruction as PyDisasmInstruction, disassemble as py_disassemble};
use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes as ruby_analyze_bytes};
use disrobe_pass_swift_objc::{SwiftObjcReport, analyze as swift_analyze};
use disrobe_pass_wasm_deob::{ModuleSummary, analyze_module};
use disrobe_py_marshal::PyVersion as MarshalVersion;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule};

use crate::convert::to_py;
use crate::err::{DisrobeError, unsupported_language};
use crate::llm::null_bundled_value;
use crate::typed::{
    CanonicalSource, GoAnalysis as PyGoAnalysis, JsUnminify, JvmClass, LuaDecompilation, PhpDecode,
    RubyAnalysis as PyRubyAnalysis, SwiftReport,
};

#[derive(Debug, serde::Serialize)]
struct CanonicalSourceView {
    source: String,
    language: String,
    produced_by: String,
    confidence: f64,
}

#[derive(Debug, serde::Serialize)]
struct JsUnminifyView {
    source: String,
    stats: UnminifyStats,
}

#[derive(Debug, serde::Serialize)]
struct PhpDecodeView {
    source: String,
    layers: Vec<disrobe_pass_php::PeelTrace>,
    residual_eval: bool,
}

const PYTHON_LANGS: &[&str] = &["python", "py", "python3"];

fn canonical_source(
    source: String,
    language: &str,
    produced_by: &str,
    confidence: f64,
) -> PyResult<CanonicalSource> {
    let view: CanonicalSourceView = CanonicalSourceView {
        source,
        language: language.to_owned(),
        produced_by: produced_by.to_owned(),
        confidence,
    };
    CanonicalSource::from_serialize(&view)
}

const fn lua_confidence(fidelity: LuaFidelity) -> f64 {
    match fidelity {
        LuaFidelity::Lossless => 1.0,
        LuaFidelity::Lossy => 0.7,
        LuaFidelity::BestEffort => 0.4,
    }
}

fn jvm_confidence(decompiled: &DecompiledClass) -> f64 {
    let total: usize = decompiled.method_count;
    if total == 0 {
        return 1.0;
    }
    let lifted: f64 = decompiled.fully_lifted_methods as f64;
    lifted / (total as f64)
}

#[pyfunction]
#[pyo3(signature = (language, source))]
#[pyo3(text_signature = "(language, source)")]
fn disasm(py: Python<'_>, language: &str, source: Py<PyAny>) -> PyResult<String> {
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
        "ruby" | "ruby-bytecode" | "yarv" | "mruby" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            ruby_disasm_text(&bytes)
        }
        "php" | "php-bytecode" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            php_disasm_text(&bytes)
        }
        "lua" => Err(unsupported_language(
            language,
            "lua recovery is lifter-based: call `disrobe.decompile('lua', bytecode)` for source \
             or `disrobe.parse('lua', bytecode)` for the structural chunk",
        )),
        other => Err(unsupported_language(
            other,
            "no backing disasm implementation",
        )),
    }
}

#[pyfunction]
#[pyo3(signature = (language, source))]
#[pyo3(text_signature = "(language, source)")]
fn parse<'py>(py: Python<'py>, language: &str, source: Py<PyAny>) -> PyResult<Bound<'py, PyAny>> {
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
        "javascript" | "js" | "typescript" | "ts" => {
            let src: String = extract_str(py, &source, language)?;
            let (out, stats): (String, UnminifyStats) = unminify(&src);
            let report: JsUnminifyView = JsUnminifyView { source: out, stats };
            let typed: JsUnminify = JsUnminify::from_value(null_bundled_value(&report)?);
            Bound::new(py, typed).map(Bound::into_any)
        }
        "go" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let analysis: GoAnalysis = go_analyze(&bytes).map_err(crate::err::map("go"))?;
            let typed: PyGoAnalysis = PyGoAnalysis::from_value(null_bundled_value(&analysis)?);
            Bound::new(py, typed).map(Bound::into_any)
        }
        "swift" | "objc" | "objective-c" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let report: SwiftObjcReport =
                swift_analyze(&bytes).map_err(crate::err::map("swift"))?;
            let typed: SwiftReport = SwiftReport::from_value(null_bundled_value(&report)?);
            Bound::new(py, typed).map(Bound::into_any)
        }
        "kotlin" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let cf: ClassFile = parse_classfile(&bytes).map_err(crate::err::map("kotlin"))?;
            let typed: JvmClass = JvmClass::from_value(null_bundled_value(&cf)?);
            Bound::new(py, typed).map(Bound::into_any)
        }
        "ruby" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let analysis: RubyAnalysis =
                ruby_analyze_bytes(&bytes, "<ruby>").map_err(crate::err::map("ruby"))?;
            let typed: PyRubyAnalysis = PyRubyAnalysis::from_value(null_bundled_value(&analysis)?);
            Bound::new(py, typed).map(Bound::into_any)
        }
        "lua" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let chunk: DecompiledChunk = decompile_auto(&bytes).map_err(crate::err::map("lua"))?;
            let typed: LuaDecompilation = LuaDecompilation::from_value(null_bundled_value(&chunk)?);
            Bound::new(py, typed).map(Bound::into_any)
        }
        "php" => {
            let bytes: Vec<u8> = extract_str_or_bytes(py, &source, language)?;
            let report: PhpPeelReport = php_peel_eval_chain(&bytes, PhpPeelOptions::default())
                .map_err(crate::err::map("php"))?;
            let view: PhpDecodeView = PhpDecodeView {
                source: String::from_utf8_lossy(&report.final_source).into_owned(),
                layers: report.layers,
                residual_eval: report.residual_eval,
            };
            let typed: PhpDecode = PhpDecode::from_value(null_bundled_value(&view)?);
            Bound::new(py, typed).map(Bound::into_any)
        }
        other => Err(unsupported_language(
            other,
            "no backing parse implementation",
        )),
    }
}

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
            "compile needs a source-to-bytecode compiler, which disrobe does not embed; \
             run `luac -o -` from the lua toolchain, then analyze the bytecode with \
             `disrobe.parse('lua', ...)` or `disrobe.decompile('lua', ...)`",
        )),
        "ruby" => Err(unsupported_language(
            language,
            "compile needs a source-to-bytecode compiler, which disrobe does not embed; \
             run `RubyVM::InstructionSequence.compile(src).to_binary` from the ruby \
             toolchain, then analyze it with `disrobe.parse('ruby', ...)`",
        )),
        other => Err(unsupported_language(
            other,
            "compile is implemented for python only; use the language's native toolchain",
        )),
    }
}

#[pyfunction]
#[pyo3(signature = (language, source))]
#[pyo3(text_signature = "(language, source)")]
fn decompile(py: Python<'_>, language: &str, source: Py<PyAny>) -> PyResult<CanonicalSource> {
    let lang: String = language.to_ascii_lowercase();
    match lang.as_str() {
        "python-bytecode" | "pyc" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let result: NativeDecompile =
                decompile_pyc(&bytes).map_err(crate::err::map("decompile pyc"))?;
            canonical_source(result.source, "python", "disrobe-pass-py-decompile", 1.0)
        }
        "jvm-class" | "class" | "java" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let cf: ClassFile =
                parse_classfile(&bytes).map_err(crate::err::map("jvm classfile"))?;
            let decompiled: DecompiledClass = decompile_class(&cf);
            let confidence: f64 = jvm_confidence(&decompiled);
            canonical_source(decompiled.source, "java", "disrobe-pass-jvm", confidence)
        }
        "kotlin" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let cf: ClassFile = parse_classfile(&bytes).map_err(crate::err::map("kotlin"))?;
            let metadata: Option<KotlinMetadata> =
                recover_kotlin_metadata(&cf).map_err(crate::err::map("kotlin metadata"))?;
            let decompiled: DecompiledClass = decompile_class(&cf);
            let confidence: f64 = jvm_confidence(&decompiled);
            let language_label: &str = if metadata.is_some() { "kotlin" } else { "java" };
            canonical_source(
                decompiled.source,
                language_label,
                "disrobe-pass-jvm",
                confidence,
            )
        }
        "lua" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let chunk: DecompiledChunk = decompile_auto(&bytes).map_err(crate::err::map("lua"))?;
            canonical_source(
                chunk.source,
                "lua",
                "disrobe-pass-lua",
                lua_confidence(chunk.fidelity),
            )
        }
        "ruby" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let analysis: RubyAnalysis =
                ruby_analyze_bytes(&bytes, "<ruby>").map_err(crate::err::map("ruby"))?;
            let (text, confidence): (String, f64) = ruby_recovered_source(&analysis)?;
            canonical_source(text, "ruby", "disrobe-pass-ruby", confidence)
        }
        "php" => {
            let bytes: Vec<u8> = extract_str_or_bytes(py, &source, language)?;
            let report: PhpPeelReport = php_peel_eval_chain(&bytes, PhpPeelOptions::default())
                .map_err(crate::err::map("php"))?;
            let confidence: f64 = if report.residual_eval { 0.5 } else { 1.0 };
            canonical_source(
                String::from_utf8_lossy(&report.final_source).into_owned(),
                "php",
                "disrobe-pass-php",
                confidence,
            )
        }
        "php-bytecode" => {
            let bytes: Vec<u8> = extract_bytes(py, &source, language)?;
            let oparray: PhpOpArray =
                php_parse_oparray(&bytes).map_err(crate::err::map("php oparray"))?;
            let decompiled: PhpDecompilation = php_decompile_oparray(&oparray);
            canonical_source(decompiled.php_skeleton, "php", "disrobe-pass-php", 0.5)
        }
        "javascript" | "js" | "typescript" | "ts" => {
            let src: String = extract_str(py, &source, language)?;
            let (out, _): (String, UnminifyStats) = unminify(&src);
            canonical_source(out, "javascript", "disrobe-pass-js-deob", 1.0)
        }
        other => Err(unsupported_language(
            other,
            "decompile is wired for python/pyc, jvm/java, kotlin, lua, ruby, php, and javascript; \
             use the language-specific binding (go_analyze, swift_analyze, wasm_analyze, ...) \
             for binary-analysis targets",
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
        .cast_into::<PyBytes>()
        .map_err(|e| DisrobeError::new_err(format!("marshal.dumps returned non-bytes: {e}")))?;
    Ok(bytes)
}

fn extract_str(py: Python<'_>, source: &Py<PyAny>, language: &str) -> PyResult<String> {
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

fn extract_bytes(py: Python<'_>, source: &Py<PyAny>, language: &str) -> PyResult<Vec<u8>> {
    let bound: Bound<'_, PyAny> = source.bind(py).clone();
    if let Ok(b) = bound.cast::<PyBytes>() {
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

fn extract_str_or_bytes(py: Python<'_>, source: &Py<PyAny>, language: &str) -> PyResult<Vec<u8>> {
    let bound: Bound<'_, PyAny> = source.bind(py).clone();
    if let Ok(s) = bound.extract::<String>() {
        return Ok(s.into_bytes());
    }
    if let Ok(b) = bound.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(v) = bound.extract::<Vec<u8>>() {
        return Ok(v);
    }
    Err(DisrobeError::new_err(format!(
        "language `{language}` expects str or bytes source, got {}",
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
        let name: &str = cf.utf8_at(m.name_index).map_or("?", |value: &str| value);
        let desc: &str = cf
            .utf8_at(m.descriptor_index)
            .map_or("?", |value: &str| value);
        s.push_str(&format!("method[{i}] {name} {desc}\n"));
    }
    for (i, f) in cf.fields.iter().enumerate() {
        let name: &str = cf.utf8_at(f.name_index).map_or("?", |value: &str| value);
        let desc: &str = cf
            .utf8_at(f.descriptor_index)
            .map_or("?", |value: &str| value);
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

fn ruby_disasm_text(bytes: &[u8]) -> PyResult<String> {
    let analysis: RubyAnalysis =
        ruby_analyze_bytes(bytes, "<ruby>").map_err(crate::err::map("ruby disasm"))?;
    if let Some(yarv) = analysis.yarv.as_ref()
        && !yarv.disasm_text.is_empty()
    {
        return Ok(yarv.disasm_text.clone());
    }
    if let Some(mruby) = analysis.mruby.as_ref() {
        return Ok(mruby_irep_text(mruby));
    }
    Err(DisrobeError::new_err(format!(
        "ruby input is `{flavor:?}`, which carries no bytecode to disassemble; \
         use `disrobe.parse('ruby', bytes)` for the structural analysis",
        flavor = analysis.flavor
    )))
}

fn mruby_irep_text(mruby: &disrobe_pass_ruby::MrubyAnalysis) -> String {
    use disrobe_pass_ruby::{IrepRecord, IrepTree};
    let Some(irep): Option<&IrepTree> = mruby.irep.as_ref() else {
        return String::from("// mruby image has no decodable irep tree\n");
    };
    let mut s: String = String::with_capacity(256);
    s.push_str(&format!(
        "// mruby RITE image: {} irep records, {} instruction bytes\n",
        irep.records.len(),
        irep.total_insn_bytes
    ));
    for record in &irep.records {
        let record: &IrepRecord = record;
        s.push_str(&format!(
            "irep[{}] depth={} nlocals={} nregs={} insn_bytes={} symbols={} pool={}\n",
            record.index,
            record.depth,
            record.nlocals,
            record.nregs,
            record.insn_len,
            record.symbols.len(),
            record.pool.len()
        ));
    }
    s
}

fn php_disasm_text(bytes: &[u8]) -> PyResult<String> {
    let oparray: PhpOpArray = php_parse_oparray(bytes).map_err(crate::err::map("php disasm"))?;
    let mut s: String = String::with_capacity(256);
    render_php_oparray(&oparray, 0, &mut s);
    Ok(s)
}

fn render_php_oparray(oparray: &PhpOpArray, depth: usize, out: &mut String) {
    let indent: String = "  ".repeat(depth);
    let label: &str = oparray
        .name
        .as_deref()
        .map_or("{main}", |value: &str| value);
    out.push_str(&format!(
        "{indent}// op_array {label} args={} literals={} ops={}\n",
        oparray.num_args,
        oparray.literals.len(),
        oparray.ops.len()
    ));
    for (i, op) in oparray.ops.iter().enumerate() {
        out.push_str(&format!("{indent}{i:5} {}\n", php_opcode_name(op.opcode)));
    }
    for child in &oparray.children {
        render_php_oparray(child, depth + 1, out);
    }
}

fn ruby_recovered_source(analysis: &RubyAnalysis) -> PyResult<(String, f64)> {
    if let Some(yarv) = analysis.yarv.as_ref() {
        let confidence: f64 = ruby_fidelity_confidence(yarv.decompiled.fidelity);
        return Ok((yarv.decompiled.source.clone(), confidence));
    }
    if let Some(mruby) = analysis.mruby.as_ref() {
        let confidence: f64 = if mruby.decompiled.has_body { 0.7 } else { 0.3 };
        return Ok((mruby.decompiled.source.clone(), confidence));
    }
    Err(DisrobeError::new_err(format!(
        "ruby input is `{flavor:?}`, which carries no bytecode body to decompile; \
         MRI source is already text. Use `disrobe.parse('ruby', bytes)` for the \
         structural analysis",
        flavor = analysis.flavor
    )))
}

const fn ruby_fidelity_confidence(fidelity: disrobe_pass_ruby::Fidelity) -> f64 {
    use disrobe_pass_ruby::Fidelity;
    match fidelity {
        Fidelity::LiteralPoolOnly => 0.7,
        Fidelity::StructuralOnly => 0.5,
        Fidelity::Lossy => 0.4,
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(disasm, m)?)?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_function(wrap_pyfunction!(decompile, m)?)?;
    Ok(())
}
