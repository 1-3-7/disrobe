#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_mobile::{
    DecompileReport, DisassemblyReport, HERMES_LIFTED_VERSIONS, HermesModule,
    decompile_hermes_module, disassemble_hermes, hermes_disasm_function, parse_hermes_module,
};

use super::emit::EmitSpec;
use super::globals;
use super::output::{self, OutputFormat};

#[derive(Subcommand, Debug)]
pub(crate) enum HermesCmd {
    #[command(
        about = "lift a React Native Hermes bundle (.hbc / index.android.bundle) back to a JavaScript surface"
    )]
    Decompile {
        #[arg(help = "input Hermes bundle (.hbc / index.android.bundle)")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-hermes)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "disassemble a Hermes bundle into a per-function summary (no JS surface)")]
    Disasm {
        #[arg(help = "input Hermes bundle")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the disasm JSON (default: ./out/<stem>-hermes.disasm.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_name = "INDEX_OR_NAME",
            allow_hyphen_values = true,
            help = "print one function by its zero-based index or exact name instead of writing the whole-bundle summary"
        )]
        function: Option<String>,
    },
    #[command(
        about = "parse the Hermes header and report version, function count, string/identifier counts"
    )]
    Info {
        #[arg(help = "input Hermes bundle")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: HermesCmd, format: OutputFormat) -> miette::Result<()> {
    match action {
        HermesCmd::Decompile { input, out, emit } => decompile(input, out, emit),
        HermesCmd::Disasm {
            input,
            out,
            function,
        } => disasm(input, out, function, format),
        HermesCmd::Info { input } => info(input),
    }
}

fn decompile(input: PathBuf, out: Option<PathBuf>, emit_kinds: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0450: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("hermes-decompile")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-hermes")));
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("hermes decompile: DRY-RUN");
        println!("  input:        {}", input.display());
        return Ok(());
    }
    let module: HermesModule = parse_hermes_module(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0451: hermes parse: {e}"))?;
    let report: DecompileReport = decompile_hermes_module(&module);

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0452: cannot create out dir: {e}"))?;
    let source_path: PathBuf = out_dir.join(format!("{stem}.js"));
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let source: String = render_decompiled_source(&module, &report);
    std::fs::write(&source_path, source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0453: cannot write lifted source: {e}"))?;

    let if_funcs: usize = report.functions.iter().filter(|f| f.has_if).count();
    let loop_funcs: usize = report.functions.iter().filter(|f| f.has_loop).count();
    let try_funcs: usize = report.functions.iter().filter(|f| f.has_try_catch).count();
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.hermes.decompile/v1",
        "input": input.display().to_string(),
        "hermes_version": module.header.version,
        "function_count": module.functions.len(),
        "functions_with_body": report.functions_with_body,
        "identifier_count": module.identifiers.len(),
        "string_count": module.strings.len(),
        "reconstructed_ops": report.total_reconstructed_ops,
        "fallback_ops": report.total_fallback_ops,
        "functions_with_if": if_funcs,
        "functions_with_loop": loop_funcs,
        "functions_with_try_catch": try_funcs,
        "raw_bytecode_size": module.raw_bytecode_size,
        "source_path": source_path.display().to_string(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0455: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0454: cannot write manifest: {e}"))?;

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "hermes-decompile")?;

    let total_ops: usize = report.total_reconstructed_ops + report.total_fallback_ops;
    let coverage: f64 = if total_ops == 0 {
        0.0
    } else {
        (report.total_reconstructed_ops as f64 / total_ops as f64) * 100.0
    };
    println!("hermes decompile: OK");
    println!("  input:        {}", input.display());
    println!("  hermes ver:   {}", module.header.version);
    println!("  functions:    {}", module.functions.len());
    println!("  with body:    {}", report.functions_with_body);
    println!("  identifiers:  {}", module.identifiers.len());
    println!("  strings:      {}", module.strings.len());
    println!(
        "  opcode cov:   {:.1}% ({} reconstructed / {} fallback)",
        coverage, report.total_reconstructed_ops, report.total_fallback_ops
    );
    println!("  if/loop/try:  {if_funcs}/{loop_funcs}/{try_funcs}");
    println!("  source:       {}", source_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn disasm(
    input: PathBuf,
    out: Option<PathBuf>,
    function: Option<String>,
    format: OutputFormat,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0460: cannot read input: {e}"))?;
    let module: HermesModule = parse_hermes_module(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0461: hermes parse: {e}"))?;
    if let Some(selector) = function {
        let index: usize = resolve_function_index(&module, &selector)?;
        return disasm_one_function(&input, &module, index, format);
    }
    let report: DisassemblyReport = disassemble_hermes(&module);
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("hermes-disasm")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-hermes.disasm.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0462: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-CLI-0463: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0464: cannot write output: {e}"))?;
    println!("hermes disasm: OK");
    println!("  input:        {}", input.display());
    println!("  functions:    {}", report.function_count);
    println!("  identifiers:  {}", report.identifier_count);
    println!("  strings:      {}", report.string_count);
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn resolve_function_index(module: &HermesModule, selector: &str) -> miette::Result<usize> {
    if !selector.is_empty() && selector.bytes().all(|byte: u8| byte.is_ascii_digit()) {
        let index: usize = selector.parse::<usize>().map_err(|_: std::num::ParseIntError| {
            miette::miette!(
                "DR-CLI-0875: Hermes function index {selector} exceeds the supported index range"
            )
        })?;
        validate_function_index(index, module.functions.len())?;
        return Ok(index);
    }
    if selector.starts_with('-')
        && selector.len() > 1
        && selector[1..].bytes().all(|byte: u8| byte.is_ascii_digit())
    {
        return Err(miette::miette!(
            "DR-CLI-0875: Hermes function index {selector} is negative; indexes are zero-based"
        ));
    }
    let mut first_match: usize = 0;
    let mut match_count: usize = 0;
    for (index, header) in module.functions.iter().enumerate() {
        let is_match: bool = module
            .string_by_global_id(header.function_name_id)
            .is_some_and(|name: &str| name == selector);
        if is_match {
            if match_count == 0 {
                first_match = index;
            }
            match_count += 1;
        }
    }
    match match_count {
        0 => Err(miette::miette!(
            "DR-CLI-0875: no Hermes function has the exact name {selector:?}"
        )),
        1 => Ok(first_match),
        count => Err(miette::miette!(
            "DR-CLI-0875: Hermes function name {selector:?} is ambiguous across {} entries; select a zero-based index",
            count
        )),
    }
}

fn disasm_one_function(
    input: &std::path::Path,
    module: &HermesModule,
    index: usize,
    format: OutputFormat,
) -> miette::Result<()> {
    if !HERMES_LIFTED_VERSIONS.contains(&module.header.version) {
        return Err(miette::miette!(
            "DR-CLI-0876: Hermes bytecode version {} has no opcode table; per-function disassembly supports versions {:?}",
            module.header.version,
            HERMES_LIFTED_VERSIONS
        ));
    }
    let total: usize = module.functions.len();
    validate_function_index(index, total)?;
    let function_name: Option<String> = module
        .functions
        .get(index)
        .and_then(|header: &disrobe_pass_mobile::SmallFunctionHeader| {
            module.string_by_global_id(header.function_name_id)
        })
        .filter(|name: &&str| !name.is_empty())
        .map(str::to_owned);
    let report: HermesFunctionDisassembly = HermesFunctionDisassembly {
        schema: "disrobe.hermes.function-disassembly/v1",
        input: input.display().to_string(),
        bytecode_version: module.header.version,
        function_index: index,
        function_count: total,
        function_name,
        instructions: hermes_disasm_function(module, index),
    };
    output::emit(format, &report, || {
        println!("hermes disasm: {}", input.display());
        println!(
            "  bytecode version: {}  function {index} of {total}",
            module.header.version
        );
        if let Some(name) = &report.function_name {
            println!("  function name: {name}");
        }
        for line in &report.instructions {
            println!("  {line}");
        }
        if report.instructions.is_empty() {
            println!("  this function declares no instruction bytes");
        }
    })
}

fn validate_function_index(index: usize, total: usize) -> miette::Result<()> {
    if index < total {
        return Ok(());
    }
    if total == 0 {
        return Err(miette::miette!(
            "DR-CLI-0875: function index {index} is invalid because this bundle declares 0 functions"
        ));
    }
    Err(miette::miette!(
        "DR-CLI-0875: function index {index} is past the end of this bundle, which declares {total} function(s) numbered 0 to {}",
        total - 1
    ))
}

#[derive(Debug, serde::Serialize)]
struct HermesFunctionDisassembly {
    schema: &'static str,
    input: String,
    bytecode_version: u32,
    function_index: usize,
    function_count: usize,
    function_name: Option<String>,
    instructions: Vec<String>,
}

fn info(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0470: cannot read input: {e}"))?;
    let module: HermesModule = parse_hermes_module(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0471: hermes parse: {e}"))?;
    println!("hermes info: OK");
    println!("  input:           {}", input.display());
    println!("  hermes ver:      {}", module.header.version);
    println!("  function count:  {}", module.header.function_count);
    println!("  string count:    {}", module.header.string_count);
    println!("  identifier ct:   {}", module.header.identifier_count);
    println!("  bytecode size:   {} bytes", module.raw_bytecode_size);
    println!("  file length:     {}", module.header.file_length);
    Ok(())
}

fn render_decompiled_source(module: &HermesModule, report: &DecompileReport) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::with_capacity(report.functions.len() * 160 + 256);
    out.push_str("// disrobe hermes decompile: reconstructed pseudo-JavaScript.\n");
    out.push_str(
        "// register-VM lifting; unreconstructed opcodes shown in <Opcode>(args) disasm form.\n",
    );
    let _ = writeln!(
        out,
        "// hermes_version={}, functions={}, identifiers={}, strings={}\n",
        module.header.version,
        module.functions.len(),
        module.identifiers.len(),
        module.strings.len()
    );
    for f in &report.functions {
        let _ = writeln!(
            out,
            "// fn #{} blocks={} ops={}r/{}f{}{}{}",
            f.index,
            f.block_count,
            f.reconstructed_ops,
            f.fallback_ops,
            if f.has_if { " if" } else { "" },
            if f.has_loop { " loop" } else { "" },
            if f.has_try_catch { " try" } else { "" },
        );
        out.push_str(&f.source);
        out.push_str("\n\n");
    }
    out
}

fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    pass: &'static str,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    if spec.is_empty() {
        return Ok(());
    }
    for kind in spec.iter() {
        let _: PathBuf = super::emit::write_not_applicable_stub(
            out_dir,
            stem,
            pass,
            kind,
            "not implemented for the hermes pass in this build",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{resolve_function_index, validate_function_index};
    use disrobe_pass_mobile::{HermesHeader, HermesModule, HermesStringKind, SmallFunctionHeader};

    #[test]
    fn an_empty_function_table_has_no_valid_index() {
        let result: Result<(), String> =
            validate_function_index(0, 0).map_err(|error: miette::Report| error.to_string());
        assert_eq!(
            result,
            Err(
                "DR-CLI-0875: function index 0 is invalid because this bundle declares 0 functions"
                    .to_owned()
            )
        );
    }

    #[test]
    fn duplicate_function_names_require_an_index() {
        let header: SmallFunctionHeader = SmallFunctionHeader {
            offset: 0,
            param_count: 0,
            bytecode_size_bytes: 0,
            function_name_id: 0,
            info_offset: 0,
            frame_size: 0,
            env_size: 0,
            highest_read_cache_index: 0,
            highest_write_cache_index: 0,
            prohibit_invoke: 0,
            strict_mode: false,
            has_exception_handler: false,
            has_debug_info: false,
            overflowed: false,
        };
        let module: HermesModule = HermesModule {
            header: HermesHeader {
                version: 96,
                source_hash: [0u8; 20],
                file_length: 0,
                global_code_index: 0,
                function_count: 2,
                string_kind_count: 0,
                identifier_count: 1,
                string_count: 0,
                overflow_string_count: 0,
                string_storage_size: 0,
                big_int_count: 0,
                big_int_storage_size: 0,
                reg_exp_count: 0,
                reg_exp_storage_size: 0,
                array_buffer_size: 0,
                obj_key_buffer_size: 0,
                obj_value_buffer_size: 0,
                segment_id: 0,
                cjs_module_count: 0,
                function_source_count: 0,
                debug_info_offset: 0,
                flags: 0,
            },
            functions: vec![header, header],
            identifiers: vec!["duplicate".to_owned()],
            strings: Vec::new(),
            string_kinds: vec![HermesStringKind::Identifier],
            overflow_resolved: 0,
            utf16_strings: 0,
            raw_bytecode_size: 0,
            array_buffer: Vec::new(),
            obj_key_buffer: Vec::new(),
            obj_value_buffer: Vec::new(),
            big_int_table: Vec::new(),
            big_int_storage: Vec::new(),
            reg_exp_table: Vec::new(),
            reg_exp_storage: Vec::new(),
            raw_image: Vec::new(),
        };
        let result: Result<usize, String> = resolve_function_index(&module, "duplicate")
            .map_err(|error: miette::Report| error.to_string());
        assert_eq!(
            result,
            Err(
                "DR-CLI-0875: Hermes function name \"duplicate\" is ambiguous across 2 entries; select a zero-based index"
                    .to_owned()
            )
        );
    }
}
