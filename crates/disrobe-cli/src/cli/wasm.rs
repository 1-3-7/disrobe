#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::{Subcommand, ValueEnum};
use wasmparser::{Parser, Payload};

use disrobe_pass_wasm_deob::{
    ComponentManifest, FunctionCfg, GcTypeGraph, LiftResult, LiftTarget, ModuleSummary,
    SsaFunction, StructuredFunction, analyze_module, build_function_cfg, build_ssa,
    parse_component_manifest, recover_gc_types, reloop_inverse,
};

use super::emit::{EmitKind, EmitSpec, write_applicable_payload, write_not_applicable_stub};

#[derive(Subcommand, Debug)]
pub(crate) enum WasmCmd {
    #[command(
        about = "decompile a WebAssembly module to JSON summary, Rust, TypeScript, WAT, or C pseudo-source"
    )]
    Decompile {
        #[arg(help = ".wasm input module")]
        input: PathBuf,
        #[arg(short, long, help = "output path")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = WasmTarget::Json,
            help = "JSON (default) emits the analyzer summary; rust / ts / wat / c lift each function via SSA + structured reloop and concatenate"
        )]
        target: WasmTarget,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report (non-applicable kinds are written as stubs)"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "deobfuscate a WebAssembly module (wasm-name-obfuscator, Jscrambler-WASM, Wobfuscator, Tigress -> Emscripten, Wasmixer)"
    )]
    Deob {
        #[arg(help = ".wasm input module")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the analysis JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "parse a WebAssembly Component Model envelope and emit its world / adapter manifest"
    )]
    Component {
        #[arg(help = ".wasm component input")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the component manifest JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "recover the WebAssembly GC type graph (struct / array / ref types) from a module"
    )]
    Types {
        #[arg(help = ".wasm input module")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the GC type graph JSON")]
        out: Option<PathBuf>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WasmTarget {
    Json,
    Rust,
    Ts,
    Wat,
    C,
}

pub(crate) fn run(action: WasmCmd) -> miette::Result<()> {
    match action {
        WasmCmd::Decompile {
            input,
            out,
            target,
            emit,
        } => decompile(input, out, target, emit),
        WasmCmd::Deob { input, out } => analyze(input, out),
        WasmCmd::Component { input, out } => emit_component(input, out),
        WasmCmd::Types { input, out } => emit_types(input, out),
    }
}

fn decompile(
    input: PathBuf,
    out: Option<PathBuf>,
    target: WasmTarget,
    emit: Vec<String>,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(&emit);
    match target {
        WasmTarget::Json => {
            let path: PathBuf = analyze_to(input.as_path(), out.as_deref())?;
            apply_emit_stubs(
                &spec,
                &input,
                path.parent().unwrap_or_else(|| Path::new(".")),
            )?;
        }
        WasmTarget::Rust => lift_module(input.as_path(), out, LiftTarget::Rust, "rs", &spec)?,
        WasmTarget::Ts => lift_module(input.as_path(), out, LiftTarget::TypeScript, "ts", &spec)?,
        WasmTarget::Wat => lift_module(input.as_path(), out, LiftTarget::Wat, "wat", &spec)?,
        WasmTarget::C => lift_module(input.as_path(), out, LiftTarget::C, "c", &spec)?,
    }
    Ok(())
}

fn analyze_to(input: &Path, out: Option<&Path>) -> miette::Result<PathBuf> {
    let bytes: Vec<u8> = read_input(input)?;
    let summary: ModuleSummary = analyze_module(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let stem: String = input_stem(input);
    let out_path: PathBuf = out.map_or_else(
        || PathBuf::from(format!("./out/{stem}.summary.json")),
        Path::to_path_buf,
    );
    write_json(&out_path, &summary)?;
    println!("wasm decompile: OK (target=json)");
    println!("  types:        {}", summary.type_count);
    println!("  functions:    {}", summary.func_count);
    println!("  imports:      {}", summary.imports.len());
    println!("  exports:      {}", summary.exports.len());
    println!("  code bytes:   {}", summary.code_size_bytes);
    println!("  wrote:        {}", out_path.display());
    Ok(out_path)
}

fn analyze(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let summary: ModuleSummary = analyze_module(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let stem: String = input_stem(&input);
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.summary.json")));
    write_json(&out_path, &summary)?;
    println!("wasm deob: OK");
    println!("  types:        {}", summary.type_count);
    println!("  functions:    {}", summary.func_count);
    println!("  imports:      {}", summary.imports.len());
    println!("  exports:      {}", summary.exports.len());
    println!("  code bytes:   {}", summary.code_size_bytes);
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn lift_module(
    input: &Path,
    out: Option<PathBuf>,
    target: LiftTarget,
    ext: &str,
    spec: &EmitSpec,
) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(input)?;
    let stem: String = input_stem(input);
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.lifted.{ext}")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0041: cannot create dir: {e}"))?;
    }
    let bodies: Vec<LiftedBody> = lift_all_bodies(&bytes, target)?;
    let banner: &'static str = match target {
        LiftTarget::Rust => "// disrobe wasm lift target=rust",
        LiftTarget::TypeScript => "// disrobe wasm lift target=typescript",
        LiftTarget::Wat => ";; disrobe wasm lift target=wat",
        LiftTarget::C => "/* disrobe wasm lift target=c */",
    };
    let mut combined: String = String::with_capacity(banner.len() + bodies.len() * 256);
    let _: std::fmt::Result = writeln!(combined, "{banner}");
    let _: std::fmt::Result = writeln!(combined, "{banner} functions={}", bodies.len());
    for body in &bodies {
        let _: std::fmt::Result = writeln!(combined);
        let _: std::fmt::Result = writeln!(
            combined,
            "{banner} fn_index={} blocks_emitted={}",
            body.fn_index, body.result.blocks_emitted
        );
        combined.push_str(&body.result.pseudo_source);
        if !body.result.pseudo_source.ends_with('\n') {
            combined.push('\n');
        }
    }
    std::fs::write(&out_path, combined.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0042: cannot write lifted output: {e}"))?;

    println!("wasm decompile: OK (target={ext})");
    println!("  functions:    {}", bodies.len());
    println!("  wrote:        {}", out_path.display());

    let stub_dir: &Path = out_path.parent().unwrap_or_else(|| Path::new("."));
    apply_emit_stubs(spec, input, stub_dir)?;
    Ok(())
}

#[derive(Debug)]
struct LiftedBody {
    fn_index: u32,
    result: LiftResult,
}

fn lift_all_bodies(bytes: &[u8], target: LiftTarget) -> miette::Result<Vec<LiftedBody>> {
    let mut bodies: Vec<LiftedBody> = Vec::new();
    let mut fn_index: u32 = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> =
            payload.map_err(|e| miette::miette!("DR-WASMDEOB-0001: parse: {e}"))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let cfg: FunctionCfg = build_function_cfg(&body)
                .map_err(|e| miette::miette!("DR-WASMDEOB-0001: cfg build fn {fn_index}: {e}"))?;
            let ssa: SsaFunction = build_ssa(&cfg, &body, &[])
                .map_err(|e| miette::miette!("DR-WASMDEOB-0001: ssa build fn {fn_index}: {e}"))?;
            let structured: StructuredFunction = reloop_inverse(&cfg);
            let result: LiftResult =
                disrobe_pass_wasm_deob::lift_with_ssa(&structured, &ssa, target);
            bodies.push(LiftedBody { fn_index, result });
            fn_index = fn_index.saturating_add(1);
        }
    }
    Ok(bodies)
}

fn apply_emit_stubs(spec: &EmitSpec, input: &Path, out_dir: &Path) -> miette::Result<()> {
    if spec.is_empty() {
        return Ok(());
    }
    let stem: String = input_stem(input);
    for kind in spec.iter() {
        match kind {
            EmitKind::Ir | EmitKind::Source | EmitKind::Disasm => {
                let _: PathBuf = write_not_applicable_stub(
                    out_dir,
                    &stem,
                    "wasm-decompile",
                    kind,
                    "wasm decompile emits the lifted pseudo-source directly; --emit kind is redundant with --target",
                )?;
            }
            EmitKind::Cfg => {
                let cfgs: Vec<serde_json::Value> = collect_cfgs(input)?;
                let _: PathBuf = write_applicable_payload(
                    out_dir,
                    &stem,
                    EmitKind::Cfg,
                    &serde_json::json!({ "schema": "disrobe.wasm.cfg/v0", "functions": cfgs }),
                )?;
            }
            EmitKind::Symbols | EmitKind::Imports | EmitKind::Strings => {
                let summary: ModuleSummary =
                    analyze_module(&std::fs::read(input).map_err(|e| miette::miette!("{e}"))?)
                        .map_err(|e| miette::miette!("{e}"))?;
                let payload: serde_json::Value = match kind {
                    EmitKind::Symbols => serde_json::json!({
                        "schema": "disrobe.wasm.symbols/v0",
                        "exports": summary.exports,
                        "function_names": summary.names.function_names,
                    }),
                    EmitKind::Imports => serde_json::json!({
                        "schema": "disrobe.wasm.imports/v0",
                        "imports": summary.imports,
                    }),
                    _ => serde_json::json!({
                        "schema": "disrobe.wasm.strings/v0",
                        "applicable": false,
                        "reason": "wasm has no string section per se; use disrobe wasm types for value-type analysis",
                    }),
                };
                let _: PathBuf = write_applicable_payload(out_dir, &stem, kind, &payload)?;
            }
            EmitKind::Report => {
                let summary: ModuleSummary =
                    analyze_module(&std::fs::read(input).map_err(|e| miette::miette!("{e}"))?)
                        .map_err(|e| miette::miette!("{e}"))?;
                let _: PathBuf = write_applicable_payload(out_dir, &stem, kind, &summary)?;
            }
            EmitKind::Ast | EmitKind::Manifest | EmitKind::Sourcemap | EmitKind::Signatures => {
                let _: PathBuf = write_not_applicable_stub(
                    out_dir,
                    &stem,
                    "wasm-decompile",
                    kind,
                    "not implemented for the wasm pass in this build",
                )?;
            }
        }
    }
    Ok(())
}

fn collect_cfgs(input: &Path) -> miette::Result<Vec<serde_json::Value>> {
    let bytes: Vec<u8> = read_input(input)?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut fn_index: u32 = 0;
    for payload in Parser::new(0).parse_all(&bytes) {
        let payload: Payload<'_> =
            payload.map_err(|e| miette::miette!("DR-WASMDEOB-0001: parse: {e}"))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let cfg: FunctionCfg = build_function_cfg(&body)
                .map_err(|e| miette::miette!("DR-WASMDEOB-0001: cfg fn {fn_index}: {e}"))?;
            out.push(serde_json::json!({
                "fn_index": fn_index,
                "blocks": cfg.blocks.len(),
                "entry": cfg.entry.0,
            }));
            fn_index = fn_index.saturating_add(1);
        }
    }
    Ok(out)
}

fn emit_component(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let manifest: ComponentManifest =
        parse_component_manifest(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let stem: String = input_stem(&input);
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.component.json")));
    write_json(&out_path, &manifest)?;
    println!("wasm component: OK");
    println!("  classification:    {:?}", manifest.classification);
    println!("  world imports:     {}", manifest.world_imports.len());
    println!("  world exports:     {}", manifest.world_exports.len());
    println!("  type decls:        {}", manifest.type_decl_count);
    println!("  core type decls:   {}", manifest.core_type_decl_count);
    println!("  embedded modules:  {}", manifest.embedded_modules.len());
    println!(
        "  embedded comps:    {}",
        manifest.embedded_components.len()
    );
    println!("  adapter funcs:     {}", manifest.adapter_funcs.len());
    println!("  wrote:             {}", out_path.display());
    Ok(())
}

fn emit_types(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let graph: GcTypeGraph = recover_gc_types(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let stem: String = input_stem(&input);
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.gc-types.json")));
    write_json(&out_path, &graph)?;
    println!("wasm types: OK");
    println!("  struct types:      {}", graph.struct_count());
    println!("  array types:       {}", graph.array_count());
    println!("  observed refs:     {}", graph.observed_ref_kinds.len());
    println!("  used struct ops:   {}", graph.used_struct_types.len());
    println!("  used array ops:    {}", graph.used_array_types.len());
    println!("  wrote:             {}", out_path.display());
    Ok(())
}

fn read_input(input: &Path) -> miette::Result<Vec<u8>> {
    std::fs::read(input).map_err(|e| miette::miette!("DR-CLI-0040: cannot read input: {e}"))
}

fn input_stem(input: &Path) -> String {
    input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wasm")
        .to_owned()
}

fn write_json<T: serde::Serialize>(out_path: &Path, value: &T) -> miette::Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0041: cannot create dir: {e}"))?;
    }
    let bytes: Vec<u8> = serde_json::to_vec_pretty(value)
        .map_err(|e| miette::miette!("DR-CLI-0043: serialize: {e}"))?;
    std::fs::write(out_path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0042: cannot write output: {e}"))?;
    Ok(())
}
