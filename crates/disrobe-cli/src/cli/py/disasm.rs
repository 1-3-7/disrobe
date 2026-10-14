use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use disrobe_llm_metadata::{LlmMetadataEmitter, MetadataSelection};

use super::super::llm::{self as llm_cli, LlmFlags};
use super::py_obj_label;

pub(super) fn disasm(
    input: PathBuf,
    out: Option<PathBuf>,
    opcode_reference: Option<PathBuf>,
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
    let (code_obj, opcode_table): (disrobe_py_marshal::CodeObject, String) =
        resolve_opcode_table(code_obj, pyc.header.version, opcode_reference.as_deref())?;
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
    println!("  opcode table: {opcode_table}");
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

fn resolve_opcode_table(
    code: disrobe_py_marshal::CodeObject,
    version: disrobe_py_marshal::PyVersion,
    reference: Option<&Path>,
) -> miette::Result<(disrobe_py_marshal::CodeObject, String)> {
    let detection: disrobe_pass_py_disasm::RemapDetection =
        disrobe_pass_py_disasm::detect_opcode_remap(&code, version);
    let Some(reference) = reference else {
        if detection.verdict == disrobe_pass_py_disasm::RemapVerdict::Remapped {
            eprintln!(
                "py disasm: {}: the opcodes are permuted, so this listing uses the wrong names; pass --opcode-reference with a stock-CPython .pyc of a module in the file",
                disrobe_pass_py_disasm::RemapDetection::NAME
            );
            return Ok((
                code,
                format!(
                    "permuted ({})",
                    disrobe_pass_py_disasm::RemapDetection::NAME
                ),
            ));
        }
        return Ok((code, "stock".to_owned()));
    };
    let bytes: Vec<u8> = std::fs::read(reference)
        .map_err(|e| miette::miette!("DR-CLI-0050: cannot read the opcode reference: {e}"))?;
    let stock: disrobe_py_marshal::PycFile = disrobe_py_marshal::read_pyc(&bytes).map_err(|e| {
        miette::miette!("DR-CLI-0051: the opcode reference is not a valid .pyc: {e}")
    })?;
    if stock.header.version != version {
        return Err(miette::miette!(
            "DR-CLI-0051: the opcode reference was compiled by CPython {}.{}, the input by {}.{}",
            stock.header.version.major,
            stock.header.version.minor,
            version.major,
            version.minor
        ));
    }
    let disrobe_py_marshal::Object::Code(stock_code) = &stock.code else {
        return Err(miette::miette!(
            "DR-CLI-0052: the opcode reference body is not a code object"
        ));
    };
    let table: disrobe_pass_py_disasm::OpcodeRemap =
        disrobe_pass_py_disasm::recover_opcode_remap(&code, stock_code, version)
            .map_err(|e| miette::miette!("{e}"))?;
    let restored: disrobe_py_marshal::CodeObject =
        table.apply(&code).map_err(|e| miette::miette!("{e}"))?;
    Ok((
        restored,
        format!(
            "recovered from the reference ({} opcodes, {} aligned code objects)",
            table.covered_opcodes(),
            table.aligned_code_objects()
        ),
    ))
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
    let names: Vec<String> = code.names.iter().map(py_obj_label).collect();
    let varnames: Vec<String> = code.varnames.iter().map(py_obj_label).collect();
    let consts: Vec<String> = code.consts.iter().map(py_obj_label).collect();
    let emitter: disrobe_pass_py_disasm::PyDisasmLlmInput =
        disrobe_pass_py_disasm::PyDisasmLlmInput {
            bytecode_version: format!("python.{}.{}", version.major, version.minor),
            instructions: instructions.to_vec(),
            names,
            varnames,
            consts,
        };
    let envelope_map: serde_json::Value = emitter.emit_metadata(&selection);
    let step: disrobe_llm_metadata::PipelineStep = llm_cli::make_step(
        "disrobe-pass-py-disasm",
        disrobe_pass_py_disasm::VERSION,
        "raw",
        "disasm",
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
