use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use disrobe_llm_metadata::{LlmMetadataEmitter, MetadataSelection};

use super::super::llm::{self as llm_cli, LlmFlags};
use super::py_obj_label;

pub(super) fn disasm(
    input: PathBuf,
    out: Option<PathBuf>,
    emit_kinds: Vec<String>,
    llm_flags: &LlmFlags,
) -> miette::Result<()> {
    let _: Option<MetadataSelection> = llm_flags.to_selection()?;
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0050: cannot read input: {e}"))?;
    let pyc: disrobe_py_marshal::PycFile = disrobe_py_marshal::read_pyc(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0051: not a valid .pyc: {e}"))?;
    let code_obj: disrobe_py_marshal::CodeObject = match &pyc.code {
        disrobe_py_marshal::Object::Code(co) => co.as_ref().clone(),
        _ => {
            return Err(miette::miette!(
                "DR-CLI-0052: .pyc body is not a code object"
            ));
        }
    };
    let instructions: Vec<disrobe_pass_py_disasm::Instruction> =
        disrobe_pass_py_disasm::disassemble(&code_obj, pyc.header.version);
    let rendered: String = disrobe_pass_py_disasm::render_dis(&instructions);

    let out_path: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("disasm");
        PathBuf::from(format!("./out/{stem}.dis.txt"))
    });
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0053: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, &rendered)
        .map_err(|e| miette::miette!("DR-CLI-0054: cannot write disasm: {e}"))?;
    let json_path: PathBuf = out_path.with_extension("dis.json");
    let json_bytes: Vec<u8> = serde_json::to_vec_pretty(&instructions)
        .map_err(|e| miette::miette!("DR-CLI-0056: serialize disasm json: {e}"))?;
    std::fs::write(&json_path, json_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0055: cannot write disasm json: {e}"))?;

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("py-disasm")
        .to_owned();
    let stub_dir: &Path = out_path.parent().unwrap_or_else(|| Path::new("."));
    super::super::emit::apply_not_applicable_stubs(
        &emit_kinds,
        stub_dir,
        &stem,
        "py-disasm",
        "not implemented for the py pass in this build",
    )?;

    let llm_out: Option<llm_cli::LlmOutputs> = maybe_emit_llm_disasm(
        llm_flags,
        &input,
        &bytes,
        &out_path,
        &instructions,
        &code_obj,
        pyc.header.version,
    )?;

    println!("py disasm: OK");
    println!("  input:        {}", input.display());
    println!(
        "  python:       {}.{}",
        pyc.header.version.major, pyc.header.version.minor
    );
    println!(
        "  pyc magic:    0x{:08x} ({})",
        pyc.header.magic, pyc.header.magic
    );
    println!("  instructions: {}", instructions.len());
    println!("  wrote:        {}", out_path.display());
    println!("  json:         {}", json_path.display());
    if let Some(o) = llm_out.as_ref() {
        println!("  llm bundle:   {}", o.bundle.display());
        if let Some(a) = o.agents_md.as_ref() {
            println!("  agents.md:    {}", a.display());
        }
        if let Some(s) = o.skill_md.as_ref() {
            println!("  skill.md:     {}", s.display());
        }
    }
    Ok(())
}

fn maybe_emit_llm_disasm(
    llm_flags: &LlmFlags,
    input: &Path,
    bytes: &[u8],
    out_path: &Path,
    instructions: &[disrobe_pass_py_disasm::Instruction],
    code: &disrobe_py_marshal::CodeObject,
    version: disrobe_py_marshal::PyVersion,
) -> miette::Result<Option<llm_cli::LlmOutputs>> {
    let Some(selection): Option<MetadataSelection> = llm_flags.to_selection()? else {
        return Ok(None);
    };
    let started: std::time::Instant = std::time::Instant::now();
    let names: Vec<String> = code.names.iter().map(py_obj_label).collect();
    let varnames: Vec<String> = code.varnames.iter().map(py_obj_label).collect();
    let consts: Vec<String> = code.consts.iter().map(py_obj_label).collect();
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let emitter: disrobe_pass_py_disasm::PyDisasmLlmInput =
        disrobe_pass_py_disasm::PyDisasmLlmInput {
            bytecode_version: format!("python.{}.{}", version.major, version.minor),
            instructions: instructions.to_vec(),
            names,
            varnames,
            consts,
            duration_ms,
        };
    let envelope_map: serde_json::Value = emitter.emit_metadata(&selection);
    let step: disrobe_llm_metadata::PipelineStep = llm_cli::make_step(
        "disrobe-pass-py-disasm",
        disrobe_pass_py_disasm::VERSION,
        "raw",
        "disasm",
        duration_ms,
    );
    let mut passes: Vec<(disrobe_llm_metadata::PipelineStep, serde_json::Value)> =
        vec![(step, envelope_map)];
    passes.extend(crate::cli::ir_metadata::pass_for_bytes(
        &selection, input, bytes,
    ));
    let outputs: llm_cli::LlmOutputs =
        llm_cli::write_llm_bundle(llm_flags, &selection, input, bytes, out_path, passes)?;
    Ok(Some(outputs))
}
