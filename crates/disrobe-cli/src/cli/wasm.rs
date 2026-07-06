#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::path::{Path, PathBuf};

use wasmparser::{Parser, Payload};

use disrobe_pass_wasm_deob::{
    CalleeNames, ComponentManifest, FunctionCfg, FunctionSig, GcHirModule, GcTypeGraph, LiftResult,
    LiftTarget, ModuleSignatures, ModuleSummary, RecoveredModule, RecoveryReport, analyze_module,
    build_function_cfg, c_runtime_prelude, extract_signatures, lift_function_body, lift_gc_module,
    lift_module_to_wat, parse_component_manifest, recover_gc_types, recover_module,
    rust_runtime_prelude, typescript_runtime_prelude,
};

use super::emit::{EmitKind, EmitSpec, write_applicable_payload, write_not_applicable_stub};

use super::wasm_cmd::{WasmCmd, WasmTarget};

pub(crate) fn run(action: WasmCmd) -> miette::Result<()> {
    match action {
        WasmCmd::Decompile {
            input,
            out,
            target,
            emit,
        } => decompile(input, out, target, emit),
        WasmCmd::Deob {
            input,
            out,
            emit_wasm,
            list,
        } => deob(input, out, emit_wasm, list),
        WasmCmd::Component { input, out } => emit_component(input, out),
        WasmCmd::Types { input, out } => emit_types(input, out),
        WasmCmd::LiftGc { input, out, json } => lift_gc(input, out, json),
    }
}

fn lift_gc(input: PathBuf, out: Option<PathBuf>, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let graph: GcTypeGraph = recover_gc_types(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let hir: GcHirModule = lift_gc_module(&graph);
    if json {
        let text: String = serde_json::to_string_pretty(&hir)
            .map_err(|e| miette::miette!("DR-CLI-0047: gc-hir serialize: {e}"))?;
        println!("{text}");
        return Ok(());
    }
    let stem: String = input_stem(&input);
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-gc-hir")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0048: cannot create out dir: {e}"))?;
    let json_path: PathBuf = out_dir.join(format!("{stem}.gc-hir.json"));
    write_json(&json_path, &hir)?;
    let rust_path: PathBuf = out_dir.join(format!("{stem}.gc-types.rs"));
    std::fs::write(&rust_path, hir.rust_source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0049: cannot write gc rust source: {e}"))?;
    let ts_path: PathBuf = out_dir.join(format!("{stem}.gc-types.ts"));
    std::fs::write(&ts_path, hir.ts_source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0050: cannot write gc ts source: {e}"))?;
    println!("wasm lift-gc: OK");
    println!("  struct types: {}", hir.structs.len());
    println!("  array types:  {}", hir.arrays.len());
    println!("  abstract refs:{}", hir.abstract_refs.len());
    for s in hir.structs.values() {
        println!(
            "    struct {} (#{}, {} field(s), final={})",
            s.rust_name,
            s.type_index,
            s.fields.len(),
            s.is_final
        );
    }
    for a in hir.arrays.values() {
        println!(
            "    array  {} (#{}, mutable-elem={}, final={})",
            a.rust_name, a.type_index, a.element_mutable, a.is_final
        );
    }
    println!("  rust source:  {}", rust_path.display());
    println!("  ts source:    {}", ts_path.display());
    println!("  gc-hir json:  {}", json_path.display());
    Ok(())
}

fn decompile(
    input: PathBuf,
    out: Option<PathBuf>,
    target: WasmTarget,
    emit: Vec<String>,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(&emit)?;
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

fn deob(
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    emit_wasm: Option<PathBuf>,
    list: bool,
) -> miette::Result<()> {
    if list {
        crate::cli::emit::print_obfuscator_catalog(
            &disrobe_pass_wasm_deob::chain_detector::WasmDetectorImpl,
            "disrobe wasm deob <input.wasm> --out <output.wat>",
        );
        return Ok(());
    }
    let Some(input): Option<PathBuf> = input else {
        return Err(miette::miette!(
            "DR-CLI-0046: wasm deob needs an input file (or `--list` to show supported obfuscators)"
        ));
    };
    let bytes: Vec<u8> = read_input(input.as_path())?;
    let recovered: RecoveredModule = recover_module(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let report: RecoveryReport = recovered.report.clone();
    let clean_bytes: Vec<u8> = recovered.bytes;
    let summary: ModuleSummary =
        analyze_module(&clean_bytes).map_err(|e| miette::miette!("{e}"))?;
    let sigs: ModuleSignatures =
        extract_signatures(&clean_bytes).map_err(|e| miette::miette!("DR-WASMDEOB-0001: {e}"))?;
    let wat: String = assemble_wat(&clean_bytes, &sigs)?;
    let func_count: usize = sigs.defined().len();

    let stem: String = input_stem(&input);
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.deob.wat")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0041: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, wat.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0042: cannot write deobfuscated wat: {e}"))?;

    let summary_path: PathBuf = out_path.with_extension("summary.json");
    write_json(&summary_path, &summary)?;
    let report_path: PathBuf = out_path.with_extension("recovery.json");
    write_json(&report_path, &report)?;

    let emitted_wasm: Option<PathBuf> = match emit_wasm {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| miette::miette!("DR-CLI-0041: cannot create dir: {e}"))?;
            }
            std::fs::write(&path, &clean_bytes)
                .map_err(|e| miette::miette!("DR-CLI-0043: cannot write recovered wasm: {e}"))?;
            Some(path)
        }
        None => None,
    };

    println!("wasm deob: OK");
    println!("  functions:    {func_count}");
    println!("  imports:      {}", summary.imports.len());
    println!("  exports:      {}", summary.exports.len());
    println!("  code bytes:   {}", summary.code_size_bytes);
    println!("  mba folded:   {}", report.mba_expressions_folded);
    println!("  opaque preds: {}", report.opaque_predicates_removed);
    println!("  collatz preds:{}", report.collatz_predicates_removed);
    println!("  call_indirect:{}", report.call_indirect_resolved);
    println!(
        "  cff funcs:    {}",
        report.flattened_functions_restructured
    );
    println!("  decrypt bytes:{}", report.decrypt_stub_bytes_recovered);
    println!("  wat source:   {}", out_path.display());
    println!("  summary:      {}", summary_path.display());
    println!("  recovery:     {}", report_path.display());
    if let Some(path) = emitted_wasm {
        println!("  recovered wasm: {}", path.display());
    }
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

    let sigs: ModuleSignatures =
        extract_signatures(&bytes).map_err(|e| miette::miette!("DR-WASMDEOB-0001: {e}"))?;
    let combined: String = match target {
        LiftTarget::Wat => assemble_wat(&bytes, &sigs)?,
        LiftTarget::Rust | LiftTarget::TypeScript | LiftTarget::C => {
            assemble_high_level(&bytes, &sigs, target)?
        }
    };
    let func_count: usize = sigs.defined().len();

    std::fs::write(&out_path, combined.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0042: cannot write lifted output: {e}"))?;

    println!("wasm decompile: OK (target={ext})");
    println!("  functions:    {func_count}");
    println!("  wrote:        {}", out_path.display());

    let stub_dir: &Path = out_path.parent().unwrap_or_else(|| Path::new("."));
    apply_emit_stubs(spec, input, stub_dir)?;
    Ok(())
}

fn callee_resolver(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn assemble_high_level(
    bytes: &[u8],
    sigs: &ModuleSignatures,
    target: LiftTarget,
) -> miette::Result<String> {
    let callees: CalleeNames = callee_resolver(sigs);
    let defined: &[FunctionSig] = sigs.defined();
    let mut combined: String = match target {
        LiftTarget::Rust => rust_runtime_prelude().to_owned(),
        LiftTarget::TypeScript => typescript_runtime_prelude().to_owned(),
        LiftTarget::C => c_runtime_prelude().to_owned(),
        LiftTarget::Wat => String::new(),
    };
    let mut idx: usize = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> =
            payload.map_err(|e| miette::miette!("DR-WASMDEOB-0001: parse: {e}"))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let sig: FunctionSig = defined
                .get(idx)
                .cloned()
                .unwrap_or_else(|| FunctionSig::placeholder(u32::try_from(idx).unwrap_or(0)));
            let result: LiftResult = lift_function_body(&body, &sig, &callees, target);
            combined.push('\n');
            combined.push_str(&result.pseudo_source);
            if !result.pseudo_source.ends_with('\n') {
                combined.push('\n');
            }
            idx += 1;
        }
    }
    Ok(combined)
}

fn assemble_wat(bytes: &[u8], sigs: &ModuleSignatures) -> miette::Result<String> {
    let defined: &[FunctionSig] = sigs.defined();
    let mut pairs: Vec<(wasmparser::FunctionBody<'_>, FunctionSig)> = Vec::new();
    let mut idx: usize = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> =
            payload.map_err(|e| miette::miette!("DR-WASMDEOB-0001: parse: {e}"))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let sig: FunctionSig = defined
                .get(idx)
                .cloned()
                .unwrap_or_else(|| FunctionSig::placeholder(u32::try_from(idx).unwrap_or(0)));
            pairs.push((body, sig));
            idx += 1;
        }
    }
    let offset: u32 = u32::try_from(sigs.imported_function_count()).unwrap_or(0);
    let mut out: String = String::from(";; disrobe wasm lift target=wat\n");
    out.push_str(&lift_module_to_wat(&pairs, offset));
    Ok(out)
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
            EmitKind::Ast
            | EmitKind::Manifest
            | EmitKind::Sourcemap
            | EmitKind::Signatures
            | EmitKind::Fingerprints
            | EmitKind::Recovery
            | EmitKind::Provenancemap => {
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
    let out_dir: &Path = out_path.parent().unwrap_or_else(|| Path::new("."));
    let carved_modules: Vec<PathBuf> =
        carve_embedded(&bytes, &manifest.embedded_modules, out_dir, &stem, "module")?;
    let carved_components: Vec<PathBuf> = carve_embedded(
        &bytes,
        &manifest.embedded_components,
        out_dir,
        &stem,
        "component",
    )?;
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
    for path in carved_modules.iter().chain(carved_components.iter()) {
        println!("  carved:            {}", path.display());
    }
    Ok(())
}

fn carve_embedded(
    bytes: &[u8],
    members: &[disrobe_pass_wasm_deob::EmbeddedModule],
    out_dir: &Path,
    stem: &str,
    kind: &str,
) -> miette::Result<Vec<PathBuf>> {
    let mut written: Vec<PathBuf> = Vec::with_capacity(members.len());
    for (idx, member) in members.iter().enumerate() {
        let Some(slice): Option<&[u8]> = bytes.get(member.start..member.end) else {
            return Err(miette::miette!(
                "DR-CLI-0044: embedded {kind} byte range {}..{} is out of bounds (file is {} bytes)",
                member.start,
                member.end,
                bytes.len()
            ));
        };
        if slice.is_empty() {
            continue;
        }
        let path: PathBuf = out_dir.join(format!("{stem}.{kind}-{idx:03}.wasm"));
        std::fs::write(&path, slice)
            .map_err(|e| miette::miette!("DR-CLI-0045: cannot write {}: {e}", path.display()))?;
        written.push(path);
    }
    Ok(written)
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const MINIMAL_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
    ];

    fn scratch(name: &str) -> PathBuf {
        let base: PathBuf = std::env::current_dir().expect("cwd").join("tmp").join(name);
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("mk base");
        base
    }

    #[test]
    fn decompile_default_target_writes_real_wat_source() {
        let base: PathBuf = scratch("wasm-decompile-wat-test");
        let in_path: PathBuf = base.join("mod.wasm");
        std::fs::write(&in_path, MINIMAL_WASM).expect("write wasm");
        let out_path: PathBuf = base.join("mod.wat");

        decompile(in_path, Some(out_path.clone()), WasmTarget::Wat, Vec::new())
            .expect("decompile wat ok");

        let wat: String = std::fs::read_to_string(&out_path).expect("read wat");
        assert!(
            wat.contains("(func"),
            "lifted wat must contain a function: {wat}"
        );
        assert!(
            wat.contains("i32.const 42"),
            "lifted wat must contain the real recovered constant: {wat}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn deob_writes_real_lifted_source_not_only_json() {
        let base: PathBuf = scratch("wasm-deob-test");
        let in_path: PathBuf = base.join("mod.wasm");
        std::fs::write(&in_path, MINIMAL_WASM).expect("write wasm");
        let out_path: PathBuf = base.join("mod.deob.wat");

        let recovered_path: PathBuf = base.join("mod.recovered.wasm");
        deob(
            Some(in_path),
            Some(out_path.clone()),
            Some(recovered_path.clone()),
            false,
        )
        .expect("deob ok");

        let wat: String = std::fs::read_to_string(&out_path).expect("read deob wat");
        assert!(
            wat.contains("i32.const 42"),
            "deob must lift real source, not only emit a summary: {wat}"
        );
        let summary_path: PathBuf = out_path.with_extension("summary.json");
        assert!(summary_path.is_file(), "summary sidecar must also land");
        let report_path: PathBuf = out_path.with_extension("recovery.json");
        assert!(report_path.is_file(), "recovery report sidecar must land");
        assert!(recovered_path.is_file(), "recovered wasm must be emitted");
        let recovered_bytes: Vec<u8> = std::fs::read(&recovered_path).expect("read recovered wasm");
        assert!(
            wasmparser::validate(&recovered_bytes).is_ok(),
            "recovered wasm must validate"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    const COMPONENT_WITH_NESTED_MODULE: &str = r#"
        (component
          (core module $m
            (func (export "add") (param i32 i32) (result i32)
              local.get 0
              local.get 1
              i32.add))
          (core instance $i (instantiate $m))
          (alias core export $i "add" (core func $add))
          (func $lifted (param "x" u32) (param "y" u32) (result u32)
            (canon lift (core func $add)))
          (export "add" (func $lifted)))
    "#;

    #[test]
    fn component_carves_embedded_modules_as_standalone_wasm() {
        let base: PathBuf = scratch("wasm-component-carve-test");
        let comp_bytes: Vec<u8> =
            wat::parse_str(COMPONENT_WITH_NESTED_MODULE).expect("encode component");
        let in_path: PathBuf = base.join("comp.wasm");
        std::fs::write(&in_path, &comp_bytes).expect("write component");
        let out_path: PathBuf = base.join("comp.component.json");

        emit_component(in_path, Some(out_path)).expect("component ok");

        let carved: PathBuf = base.join("comp.module-000.wasm");
        assert!(
            carved.is_file(),
            "an embedded core module must be carved to a standalone .wasm"
        );
        let carved_bytes: Vec<u8> = std::fs::read(&carved).expect("read carved module");
        assert!(
            wasmparser::validate(&carved_bytes).is_ok(),
            "carved embedded module must validate as a standalone wasm module"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
