#![allow(clippy::needless_pass_by_value)]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use clap::Subcommand;
use disrobe_core::subprocess::{CapturedOutput, wait_with_output_timeout};

use crate::cli::progress_ui::StageSpinner;

const CPYTHON_PROBE_TIMEOUT_SECS: u64 = 5;
const CAPTURE_CAP_BYTES: usize = 1024 * 1024;

#[derive(Subcommand, Debug)]
pub(crate) enum NuitkaCmd {
    #[command(
        about = "detect a Nuitka build flavor (--onefile, --standalone, --module, signed-PE, wheel) & report the Python version"
    )]
    Detect {
        #[arg(help = "Nuitka-built executable to inspect")]
        input: PathBuf,
    },
    #[command(
        about = "extract a Nuitka --onefile payload (kax / kay + zstd) to its embedded files"
    )]
    Extract {
        #[arg(help = "Nuitka --onefile executable to extract")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-extracted)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "scan a Nuitka --standalone binary's symbol table for impl_* & module-init functions"
    )]
    Symbols {
        #[arg(help = "Nuitka binary to scan")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the symbol graph JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "decompile recoverable Nuitka constants (literals, identifiers, annotations) from a build dir or binary, plus version + module map"
    )]
    Decompile {
        #[arg(help = "Nuitka binary or its <name>.build directory")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the decompilation JSON (default: ./out/<stem>.nuitka-constants.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "also emit the recovered Python surface skeleton to this path"
        )]
        python: Option<PathBuf>,
    },
    #[command(
        about = "decode a single Nuitka .const file (concatenated pickle streams) to its constant pool"
    )]
    Constants {
        #[arg(help = "path to a *.const file (e.g. module.hello.const)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "blob_name from __constant.txt (\"\" global pool, else module name)",
            default_value = ""
        )]
        blob_name: String,
        #[arg(short, long, help = "output path for the constant pool JSON")]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: NuitkaCmd) -> miette::Result<()> {
    match action {
        NuitkaCmd::Detect { input } => detect(input),
        NuitkaCmd::Extract { input, out } => extract(input, out),
        NuitkaCmd::Symbols { input, out } => symbols(input, out),
        NuitkaCmd::Decompile { input, out, python } => decompile(input, out, python),
        NuitkaCmd::Constants {
            input,
            blob_name,
            out,
        } => constants(input, blob_name, out),
    }
}

fn detect(input: PathBuf) -> miette::Result<()> {
    let det: disrobe_pass_nuitka::Detection =
        disrobe_pass_nuitka::detect_in_file(&input).map_err(|e| miette::miette!("{e}"))?;
    println!("nuitka detect: OK");
    println!("  flavor:       {:?}", det.flavor);
    println!("  signatures:   {:?}", det.hits);
    if let (Some(maj), Some(min)) = (det.version.python_major, det.version.python_minor) {
        println!("  python:       {maj}.{min}");
    }
    if let Some(off) = det.onefile_payload_offset {
        println!("  onefile payload @ offset {off}");
    }
    Ok(())
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let label: String = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("nuitka")
        .to_owned();
    let spinner: StageSpinner = StageSpinner::start(&label, "detecting nuitka onefile payload");
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0016: cannot read input: {e}"))?;
    let det: disrobe_pass_nuitka::Detection =
        disrobe_pass_nuitka::detect_in_bytes(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let Some(offset): Option<usize> = det.onefile_payload_offset else {
        return Err(miette::miette!(
            "DR-CLI-0017: input is not a Nuitka --onefile build (no KA[XY] payload detected); use `nuitka symbols` for --standalone builds"
        ));
    };
    spinner.set_message(&format!("extracting payload at offset {offset}"));
    let payload: disrobe_pass_nuitka::OnefilePayload =
        disrobe_pass_nuitka::extract_onefile(&bytes, offset).map_err(|e| miette::miette!("{e}"))?;
    spinner.finish(&format!("{} entries", payload.entries.len()));
    let out_dir: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("nuitka-out");
        PathBuf::from(format!("./out/{stem}-extracted"))
    });
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0018: cannot create out dir: {e}"))?;
    let mut written: usize = 0usize;
    for entry in &payload.entries {
        if entry.symlink_target.is_some() {
            continue;
        }
        let Some(target): Option<PathBuf> = safe_join(&out_dir, &entry.filename) else {
            return Err(miette::miette!(
                "DR-CLI-0023: refusing unsafe payload path '{}' (traversal)",
                entry.filename
            ));
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0018: cannot create out dir: {e}"))?;
        }
        std::fs::write(&target, &entry.data)
            .map_err(|e| miette::miette!("DR-CLI-0019: cannot write {}: {e}", target.display()))?;
        written += 1;
    }
    println!("nuitka extract: OK");
    println!("  flavor:        {:?}", det.flavor);
    println!("  encoding:      {:?}", payload.encoding);
    println!("  checksums:     {}", payload.has_checksums);
    println!("  entries:       {}", payload.entries.len());
    println!("  files written: {written}");
    println!("  payload bytes: {}", payload.payload_size);
    println!("  out dir:       {}", out_dir.display());
    for entry in &payload.entries {
        println!("    - {} ({} bytes)", entry.filename, entry.size);
    }
    Ok(())
}

fn safe_join(root: &std::path::Path, filename: &str) -> Option<PathBuf> {
    let mut result: PathBuf = root.to_path_buf();
    let mut components: usize = 0usize;
    for raw in filename.split(['/', '\\']) {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw == ".." || raw.contains(':') {
            return None;
        }
        result.push(raw);
        components += 1;
    }
    if components == 0 {
        return None;
    }
    Some(result)
}

fn symbols(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0020: cannot read input: {e}"))?;
    let graph: disrobe_pass_nuitka::SymbolGraph =
        disrobe_pass_nuitka::scan_symbols(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let target: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("nuitka-symbols");
        PathBuf::from(format!("./out/{stem}.symbols.json"))
    });
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0021: cannot create dir: {e}"))?;
    }
    let graph_bytes: Vec<u8> = serde_json::to_vec_pretty(&graph)
        .map_err(|e| miette::miette!("DR-CLI-0024: serialize symbols: {e}"))?;
    std::fs::write(&target, graph_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0022: cannot write symbols: {e}"))?;
    println!("nuitka symbols: OK");
    println!("  impl_functions:   {}", graph.impl_functions.len());
    println!("  module_inits:     {}", graph.module_inits.len());
    println!("  make_func_count:  {}", graph.make_function_count);
    println!("  interesting strs: {}", graph.strings.len());
    println!("  wrote:            {}", target.display());
    Ok(())
}

fn decompile(input: PathBuf, out: Option<PathBuf>, python: Option<PathBuf>) -> miette::Result<()> {
    let label: String = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("nuitka")
        .to_owned();
    let spinner: StageSpinner = StageSpinner::start(&label, "decompiling nuitka constants");
    let mut result: disrobe_pass_nuitka::NuitkaDecompilation = if input.is_dir() {
        disrobe_pass_nuitka::decompile_build_dir(&input).map_err(|e| miette::miette!("{e}"))?
    } else {
        disrobe_pass_nuitka::decompile_binary(&input).map_err(|e| miette::miette!("{e}"))?
    };
    measure_frozen_recompile(&mut result);
    spinner.finish(&format!("{:?}", result.source_kind));

    let stem: String = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("nuitka")
        .to_owned();
    let target: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.nuitka-constants.json")));
    let out_dir: PathBuf = target
        .parent()
        .filter(|p: &&std::path::Path| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0026: cannot create dir: {e}"))?;
    let json: Vec<u8> = serde_json::to_vec_pretty(&result)
        .map_err(|e| miette::miette!("DR-CLI-0027: cannot serialize decompilation: {e}"))?;
    std::fs::write(&target, &json)
        .map_err(|e| miette::miette!("DR-CLI-0028: cannot write decompilation: {e}"))?;

    let module_emits: Vec<ModuleEmit> = emit_bytecode_modules(result.bytecode.as_ref(), &out_dir)?;
    let default_surface_path: Option<PathBuf> =
        emit_surface_skeleton(result.surface.as_ref(), &out_dir, &stem)?;
    let skeleton_emits: Vec<ModuleEmit> =
        emit_skeleton_modules(result.skeleton.as_ref(), &out_dir, Some(stem.as_str()))?;
    let frozen_emits: usize = emit_frozen_modules(result.frozen_modules.as_ref(), &out_dir)?;
    let disasm_image: Option<Vec<u8>> = disasm_image_for(&input, &result);
    let native_emit: Option<PathBuf> = emit_native_disasm(
        result.native_disasm.as_ref(),
        disasm_image.as_deref(),
        &out_dir,
    )?;
    let name_map_emit: Option<PathBuf> = emit_name_map(result.name_map.as_ref(), &out_dir)?;
    let carved: CarveCounts = carve_onefile_data(&input, &result, &out_dir)?;
    write_recovery_manifest(
        &out_dir,
        &result,
        frozen_emits,
        skeleton_emits.len(),
        &carved,
    )?;

    let distinct_strings: usize = result.constants.all_strings.len();
    let distinct_ints: usize = result.constants.all_ints.len();
    let stream_total: usize = result
        .constants
        .pools
        .values()
        .map(|p: &disrobe_pass_nuitka::ConstantsPool| p.stream_count)
        .sum();

    println!("nuitka decompile: OK");
    println!("  source kind:      {:?}", result.source_kind);
    print_version(&result.version);
    print_skeleton(result.skeleton.as_ref());
    print_frozen(result.frozen_modules.as_ref());
    print_data_files(&result.data_files);
    if !result.constants.pools.is_empty() {
        println!("  const files:      {}", result.constants.pools.len());
        println!("  pickle streams:   {stream_total}");
        println!("  distinct strings: {distinct_strings}");
        println!("  distinct ints:    {distinct_ints}");
        for (name, pool) in &result.constants.pools {
            println!(
                "    - {name}: {} streams, {} strings, {} ints",
                pool.stream_count,
                pool.strings.len(),
                pool.ints.len()
            );
        }
    }
    if let Some(surface) = &result.surface {
        println!(
            "  surface:          {} ({} functions, fidelity {:?})",
            surface.module_name,
            surface.functions.len(),
            surface.fidelity
        );
    }
    if let Some(table) = &result.bytecode {
        let recovered: usize = table
            .modules
            .iter()
            .filter(|m: &&disrobe_pass_nuitka::BytecodeModule| m.recovered_directly)
            .count();
        println!(
            "  bytecode table:   {} frozen module(s), python {}.{} ({recovered} to source)",
            table.modules.len(),
            table.marshal_version.0,
            table.marshal_version.1
        );
        for module in &table.modules {
            println!(
                "    - {}: {} instructions{}",
                module.module_name,
                module.instruction_count,
                if module.recovered_directly {
                    " (source recovered)"
                } else {
                    " (disasm only)"
                }
            );
        }
    }
    for note in &result.notes {
        println!("  note: {note}");
    }
    println!("  wrote:            {}", target.display());
    for emit in &module_emits {
        println!(
            "  module:           {} -> {}",
            emit.module_name,
            emit.path.display()
        );
    }
    if let Some(path) = &default_surface_path {
        println!("  surface skeleton: {}", path.display());
    }
    for emit in &skeleton_emits {
        println!(
            "  skeleton:         {} -> {}",
            emit.module_name,
            emit.path.display()
        );
    }
    if frozen_emits > 0 {
        println!(
            "  frozen source:    {frozen_emits} module(s) -> {}",
            out_dir.join("frozen").display()
        );
    }
    if let Some(disasm) = result.native_disasm.as_ref() {
        println!(
            "  native disasm:    {} instructions, {} functions{} -> {}",
            disasm.instruction_count,
            disasm.function_count,
            if disasm.truncated { " (truncated)" } else { "" },
            native_emit
                .as_ref()
                .map_or_else(String::new, |p: &PathBuf| p.display().to_string())
        );
    }
    if let Some(map) = result.name_map.as_ref()
        && !map.is_empty()
    {
        println!(
            "  native name map:  {} identifier(s) -> {} function(s){}",
            map.entries.len(),
            map.mapped_functions,
            name_map_emit
                .as_ref()
                .map_or_else(String::new, |p: &PathBuf| format!(" -> {}", p.display()))
        );
    }
    if carved.data_files > 0 {
        println!(
            "  data files:       {} carved -> {}",
            carved.data_files,
            out_dir.join("data").display()
        );
    }
    if carved.native_extensions > 0 {
        println!(
            "  native libs:      {} carved + disasm/capabilities/recon -> {}",
            carved.native_extensions,
            out_dir.join("extracted").join("libs").display()
        );
    }

    if let Some(python_path) = python {
        let source: String = if let Some(surface) = result.surface.as_ref() {
            surface.python_source.clone()
        } else if let Some(skeleton) = result.skeleton.as_ref() {
            join_skeleton_source(skeleton)
        } else {
            return Err(miette::miette!(
                "DR-CLI-0030: --python requested but no surface or skeleton was recovered"
            ));
        };
        if let Some(parent) = python_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0031: cannot create dir: {e}"))?;
        }
        std::fs::write(&python_path, source.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0032: cannot write python skeleton: {e}"))?;
        println!("  wrote python skeleton: {}", python_path.display());
    }

    Ok(())
}

fn print_skeleton(skeleton: Option<&disrobe_pass_nuitka::NuitkaSkeleton>) {
    let Some(skeleton): Option<&disrobe_pass_nuitka::NuitkaSkeleton> = skeleton else {
        return;
    };
    if skeleton.modules.is_empty() {
        return;
    }
    let total_functions: usize = skeleton.function_count();
    let typed: usize = skeleton
        .modules
        .iter()
        .flat_map(|m: &disrobe_pass_nuitka::SkeletonModule| m.functions.iter())
        .filter(|f: &&disrobe_pass_nuitka::SkeletonFunction| {
            f.from_annotations && !f.name.starts_with("_typed_function_")
        })
        .count();
    println!(
        "  skeleton:         {} modules, {total_functions} functions ({typed} with recovered type annotations; param kinds/defaults/order approximate)",
        skeleton.modules.len()
    );
    for module in &skeleton.modules {
        println!(
            "    - {} ({} functions{})",
            module.name,
            module.functions.len(),
            module
                .filename
                .as_deref()
                .map_or_else(String::new, |f: &str| format!(", {f}"))
        );
        for func in &module.functions {
            let params: String = func
                .params
                .iter()
                .map(|p: &disrobe_pass_nuitka::SkeletonParam| {
                    p.annotation
                        .as_ref()
                        .map_or_else(|| p.name.clone(), |a: &String| format!("{}: {a}", p.name))
                })
                .collect::<Vec<String>>()
                .join(", ");
            let ret: String = func
                .return_annotation
                .as_ref()
                .map_or_else(String::new, |r: &String| format!(" -> {r}"));
            println!("        def {}({params}){ret}", func.name);
        }
    }
}

fn measure_frozen_recompile(result: &mut disrobe_pass_nuitka::NuitkaDecompilation) {
    let Some(frozen): Option<&disrobe_pass_nuitka::FrozenModules> = result.frozen_modules.as_ref()
    else {
        return;
    };
    if frozen.recompile.is_some() || frozen.decompiled_count() == 0 {
        return;
    }
    let (major, minor): (u8, u8) = frozen.marshal_version;
    let Some(python): Option<PathBuf> = locate_cpython(major, minor) else {
        return;
    };
    let report: disrobe_pass_nuitka::RecompileReport =
        disrobe_pass_nuitka::verify_recompile(frozen, &python);
    if let Some(frozen_mut) = result.frozen_modules.as_mut() {
        frozen_mut.recompile = Some(report);
    }
}

fn locate_cpython(major: u8, minor: u8) -> Option<PathBuf> {
    let exact: String = format!("python{major}.{minor}");
    for name in [exact.as_str(), "python3", "python"] {
        let spawned: Result<std::process::Child, std::io::Error> = Command::new(name)
            .arg("-c")
            .arg("import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let Ok(child): Result<std::process::Child, std::io::Error> = spawned else {
            continue;
        };
        let Some(captured): Option<CapturedOutput> = wait_with_output_timeout(
            child,
            Duration::from_secs(CPYTHON_PROBE_TIMEOUT_SECS),
            CAPTURE_CAP_BYTES,
        ) else {
            continue;
        };
        if captured.exit_code != Some(0) {
            continue;
        }
        let reported: String = String::from_utf8_lossy(&captured.stdout).trim().to_owned();
        if reported == format!("{major}.{minor}") {
            return Some(PathBuf::from(name));
        }
    }
    None
}

fn print_frozen(frozen: Option<&disrobe_pass_nuitka::FrozenModules>) {
    let Some(frozen): Option<&disrobe_pass_nuitka::FrozenModules> = frozen else {
        return;
    };
    if frozen.modules.is_empty() {
        return;
    }
    let decompiled: usize = frozen.decompiled_count();
    let empty: usize = frozen.empty_count();
    let failed: usize = frozen.failed_count();
    match &frozen.recompile {
        Some(report) => println!(
            "  frozen bytecode:  {} module(s) from .bytecode stream, python {}.{}: {decompiled} decompiled, {empty} empty/comment-only, {failed} failed; {}/{} recompile-clean on {}",
            frozen.modules.len(),
            frozen.marshal_version.0,
            frozen.marshal_version.1,
            report.clean,
            report.checked,
            report.interpreter,
        ),
        None => println!(
            "  frozen bytecode:  {} module(s) from .bytecode stream, python {}.{}: {decompiled} decompiled (recompile unverified), {empty} empty/comment-only, {failed} failed",
            frozen.modules.len(),
            frozen.marshal_version.0,
            frozen.marshal_version.1,
        ),
    }
    for module in frozen.modules.iter().take(40) {
        let label: &str = match disrobe_pass_nuitka::frozen_status(module) {
            disrobe_pass_nuitka::FrozenStatus::Decompiled => " (decompiled source)",
            disrobe_pass_nuitka::FrozenStatus::Empty => " (empty/comment-only)",
            disrobe_pass_nuitka::FrozenStatus::Failed => " (disasm only)",
        };
        println!("    - {}{label}", module.module_name);
    }
    if frozen.modules.len() > 40 {
        println!("    ... and {} more", frozen.modules.len() - 40);
    }
}

fn write_recovery_manifest(
    out_dir: &std::path::Path,
    result: &disrobe_pass_nuitka::NuitkaDecompilation,
    frozen: usize,
    skeleton: usize,
    carved: &CarveCounts,
) -> miette::Result<()> {
    let native: (u64, u64) = result
        .native_disasm
        .as_ref()
        .map_or((0, 0), |d: &disrobe_pass_nuitka::NativeDisasm| {
            (d.instruction_count, d.function_count)
        });
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.nuitka.recovery-manifest/v1",
        "outputs": {
            "frozen/": {
                "what": "REAL Python source recovered from frozen bytecode in the binary",
                "fidelity": "decompiled-from-bytecode",
                "count": frozen
            },
            "skeleton/app/, skeleton/libs/": {
                "what": "typed signatures of native-compiled modules (no bytecode); app/ is the user's package, libs/ is bundled stdlib and third-party",
                "fidelity": "signatures-only-native-compiled",
                "count": skeleton
            },
            "native/": {
                "what": "x86 disassembly of the compiled image .text (Nuitka emits machine code; no source .c exists)",
                "fidelity": "native-asm",
                "instructions": native.0,
                "functions": native.1
            },
            "native/name-map.json": {
                "what": "recovered python identifiers correlated to the .text functions that reference their string constants (static, no debug symbols)",
                "fidelity": "native-to-name-correlation",
                "identifiers": result.name_map.as_ref().map_or(0, |m: &disrobe_pass_nuitka::NativeNameMap| m.entries.len()),
                "mapped_functions": result.name_map.as_ref().map_or(0, |m: &disrobe_pass_nuitka::NativeNameMap| m.mapped_functions)
            },
            "extracted/libs/": {
                "what": "bundled DLLs and .pyd/.so extension modules carved from the payload, each with a sibling .asm disassembly, .capabilities.json, and .recon.json",
                "count": carved.native_extensions
            },
            "data/": {
                "what": "bundled non-code data files carved from the payload (assets, models, resources)",
                "count": carved.data_files
            }
        }
    });
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0045: recovery-manifest serialize: {e}"))?;
    std::fs::write(out_dir.join("recovery-manifest.json"), bytes)
        .map_err(|e| miette::miette!("DR-CLI-0046: cannot write recovery-manifest: {e}"))?;
    Ok(())
}

fn emit_name_map(
    name_map: Option<&disrobe_pass_nuitka::NativeNameMap>,
    out_dir: &std::path::Path,
) -> miette::Result<Option<PathBuf>> {
    let Some(map): Option<&disrobe_pass_nuitka::NativeNameMap> = name_map else {
        return Ok(None);
    };
    if map.is_empty() {
        return Ok(None);
    }
    let dir: PathBuf = out_dir.join("native");
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("DR-CLI-0047: cannot create native dir: {e}"))?;
    let json: Vec<u8> = serde_json::to_vec_pretty(map)
        .map_err(|e| miette::miette!("DR-CLI-0048: serialize name map: {e}"))?;
    std::fs::write(dir.join("name-map.json"), json)
        .map_err(|e| miette::miette!("DR-CLI-0049: cannot write name-map.json: {e}"))?;

    let mut text: String = String::with_capacity(map.entries.len() * 48);
    text.push_str(
        "; recovered python identifier -> address of its string constant -> .text functions that reference it\n",
    );
    text.push_str("; (static correlation; no debug symbols required)\n\n");
    for entry in &map.entries {
        let _ = std::fmt::Write::write_fmt(
            &mut text,
            format_args!("{} @ {:#x}\n", entry.name, entry.string_address),
        );
        for r in &entry.references {
            match r.function_address {
                Some(addr) => {
                    let _ = std::fmt::Write::write_fmt(
                        &mut text,
                        format_args!(
                            "    ref @ {:#x}  in function {:#x}\n",
                            r.instruction_offset, addr
                        ),
                    );
                }
                None => {
                    let _ = std::fmt::Write::write_fmt(
                        &mut text,
                        format_args!("    ref @ {:#x}\n", r.instruction_offset),
                    );
                }
            }
        }
    }
    let path: PathBuf = dir.join("name-map.txt");
    std::fs::write(&path, text.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0050: cannot write name-map.txt: {e}"))?;
    Ok(Some(path))
}

fn disasm_image_for(
    input: &std::path::Path,
    result: &disrobe_pass_nuitka::NuitkaDecompilation,
) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = std::fs::read(input).ok()?;
    if !matches!(
        result.source_kind,
        disrobe_pass_nuitka::DecompSourceKind::OnefilePayload
    ) {
        return Some(bytes);
    }
    let det: disrobe_pass_nuitka::Detection = disrobe_pass_nuitka::detect_in_bytes(&bytes).ok()?;
    let offset: usize = det.onefile_payload_offset?;
    let mut main_dll: Option<Vec<u8>> = None;
    let _ = disrobe_pass_nuitka::extract_onefile_streaming(
        &bytes,
        offset,
        &mut |entry: &disrobe_pass_nuitka::StreamedEntry<'_>| {
            if main_dll.is_none()
                && entry.symlink_target.is_none()
                && std::path::Path::new(&entry.filename)
                    .extension()
                    .is_some_and(|x: &std::ffi::OsStr| x.eq_ignore_ascii_case("dll"))
                && !is_runtime_native_lib(&entry.filename)
            {
                main_dll = Some(entry.data.to_vec());
            }
            Ok(())
        },
    );
    main_dll
}

fn emit_native_disasm(
    disasm: Option<&disrobe_pass_nuitka::NativeDisasm>,
    image: Option<&[u8]>,
    out_dir: &std::path::Path,
) -> miette::Result<Option<PathBuf>> {
    let Some(disasm): Option<&disrobe_pass_nuitka::NativeDisasm> = disasm else {
        return Ok(None);
    };
    if disasm.is_empty() {
        return Ok(None);
    }
    let Some(image): Option<&[u8]> = image else {
        return Ok(None);
    };
    let native_dir: PathBuf = out_dir.join("native");
    std::fs::create_dir_all(&native_dir)
        .map_err(|e| miette::miette!("DR-CLI-0043: cannot create native dir: {e}"))?;
    let safe: String = sanitize_module_name(&disasm.module_name);
    let path: PathBuf = native_dir.join(format!("{safe}.asm"));
    let written: Option<disrobe_pass_nuitka::NativeDisasm> =
        disrobe_pass_nuitka::disassemble_module_to_file(&disasm.module_name, image, &path);
    Ok(written.map(|_| path))
}

fn emit_frozen_modules(
    frozen: Option<&disrobe_pass_nuitka::FrozenModules>,
    out_dir: &std::path::Path,
) -> miette::Result<usize> {
    let Some(frozen): Option<&disrobe_pass_nuitka::FrozenModules> = frozen else {
        return Ok(0);
    };
    let frozen_dir: PathBuf = out_dir.join("frozen");
    let mut written: usize = 0usize;
    for module in &frozen.modules {
        let (suffix, content): (&str, &str) = match disrobe_pass_nuitka::frozen_status(module) {
            disrobe_pass_nuitka::FrozenStatus::Decompiled => ("py", module.source.as_str()),
            disrobe_pass_nuitka::FrozenStatus::Failed if !module.disassembly.is_empty() => {
                ("dis.txt", module.disassembly.as_str())
            }
            _ => continue,
        };
        if written == 0 {
            std::fs::create_dir_all(&frozen_dir)
                .map_err(|e| miette::miette!("DR-CLI-0041: cannot create frozen dir: {e}"))?;
        }
        let safe: String = sanitize_module_name(&module.module_name);
        let path: PathBuf = frozen_dir.join(format!("{safe}.{suffix}"));
        std::fs::write(&path, content.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0042: cannot write {}: {e}", path.display()))?;
        written += 1;
    }
    Ok(written)
}

fn print_data_files(data_files: &[disrobe_pass_nuitka::DataFileEntry]) {
    if data_files.is_empty() {
        return;
    }
    let total_bytes: u64 = data_files
        .iter()
        .map(|d: &disrobe_pass_nuitka::DataFileEntry| d.size)
        .sum();
    println!(
        "  bundled files:    {} ({total_bytes} bytes total)",
        data_files.len()
    );
    for entry in data_files {
        println!(
            "    - {} ({} bytes, {:?})",
            entry.filename, entry.size, entry.kind
        );
    }
}

#[derive(Debug, Default)]
struct CarveCounts {
    data_files: usize,
    native_extensions: usize,
}

fn is_native_extension(filename: &str) -> bool {
    std::path::Path::new(filename)
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .is_some_and(|ext: &str| {
            ext.eq_ignore_ascii_case("dll")
                || ext.eq_ignore_ascii_case("pyd")
                || ext.eq_ignore_ascii_case("so")
        })
}

fn carve_onefile_data(
    input: &std::path::Path,
    result: &disrobe_pass_nuitka::NuitkaDecompilation,
    out_dir: &std::path::Path,
) -> miette::Result<CarveCounts> {
    if !matches!(
        result.source_kind,
        disrobe_pass_nuitka::DecompSourceKind::OnefilePayload
    ) {
        return Ok(CarveCounts::default());
    }
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0037: cannot re-read input for carving: {e}"))?;
    let det: disrobe_pass_nuitka::Detection =
        disrobe_pass_nuitka::detect_in_bytes(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let Some(offset): Option<usize> = det.onefile_payload_offset else {
        return Ok(CarveCounts::default());
    };
    let data_dir: PathBuf = out_dir.join("data");
    let libs_dir: PathBuf = out_dir.join("extracted").join("libs");
    let mut counts: CarveCounts = CarveCounts::default();
    let mut carve_err: Option<miette::Report> = None;
    let walk: Result<disrobe_pass_nuitka::StreamedPayload, _> =
        disrobe_pass_nuitka::extract_onefile_streaming(
            &bytes,
            offset,
            &mut |entry: &disrobe_pass_nuitka::StreamedEntry<'_>| {
                if entry.symlink_target.is_some() {
                    return Ok(());
                }
                carve_one_entry(entry, &data_dir, &libs_dir, &mut counts).map_err(|e| {
                    let msg: String = format!("{e}");
                    carve_err = Some(e);
                    std::io::Error::other(msg)
                })
            },
        );
    if let Some(e) = carve_err {
        return Err(e);
    }
    walk.map_err(|e| miette::miette!("{e}"))?;
    Ok(counts)
}

fn carve_one_entry(
    entry: &disrobe_pass_nuitka::StreamedEntry<'_>,
    data_dir: &std::path::Path,
    libs_dir: &std::path::Path,
    counts: &mut CarveCounts,
) -> miette::Result<()> {
    let native: bool = is_native_extension(&entry.filename);
    let root: &std::path::Path = if native { libs_dir } else { data_dir };
    let Some(target): Option<PathBuf> = safe_join(root, &entry.filename) else {
        return Err(miette::miette!(
            "DR-CLI-0038: refusing unsafe bundled path '{}' (traversal)",
            entry.filename
        ));
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0039: cannot create carve dir: {e}"))?;
    }
    std::fs::write(&target, entry.data)
        .map_err(|e| miette::miette!("DR-CLI-0040: cannot write {}: {e}", target.display()))?;
    if native {
        analyze_native_extension(&target, &entry.filename, entry.data)?;
        counts.native_extensions += 1;
    } else {
        counts.data_files += 1;
    }
    Ok(())
}

const MAX_DEEP_ANALYZE_LIB_BYTES: usize = 16 * 1024 * 1024;

fn is_runtime_native_lib(filename: &str) -> bool {
    let lower: String = filename.to_ascii_lowercase();
    [
        "python",
        "vcruntime",
        "libcrypto",
        "libssl",
        "libffi",
        "api-ms",
        "msvcp",
        "ucrtbase",
    ]
    .iter()
    .any(|p: &&str| lower.starts_with(p))
}

fn analyze_native_extension(
    written_path: &std::path::Path,
    filename: &str,
    data: &[u8],
) -> miette::Result<()> {
    let stem: &std::path::Path = written_path;
    let deep: bool = data.len() <= MAX_DEEP_ANALYZE_LIB_BYTES && !is_runtime_native_lib(filename);
    if deep {
        let asm_path: PathBuf = stem.with_extension("asm");
        let _: Option<disrobe_pass_nuitka::NativeDisasm> =
            disrobe_pass_nuitka::disassemble_module_to_file(filename, data, &asm_path);
    }
    if deep && let Ok(report) = disrobe_capabilities::analyze(data) {
        let cap_path: PathBuf = stem.with_extension("capabilities.json");
        let json: Vec<u8> = serde_json::to_vec_pretty(&report)
            .map_err(|e| miette::miette!("DR-CLI-0042: serialize capabilities: {e}"))?;
        std::fs::write(&cap_path, json).map_err(|e| {
            miette::miette!("DR-CLI-0043: cannot write {}: {e}", cap_path.display())
        })?;
    }
    let config: disrobe_core::recon::ReconConfig = disrobe_core::recon::ReconConfig::default();
    let report: disrobe_core::recon::ReconReport =
        disrobe_core::recon::report_bytes(data, Some(filename), &config);
    if !report.findings.is_empty() {
        let recon_path: PathBuf = stem.with_extension("recon.json");
        let json: Vec<u8> = serde_json::to_vec_pretty(&report)
            .map_err(|e| miette::miette!("DR-CLI-0044: serialize recon: {e}"))?;
        std::fs::write(&recon_path, json).map_err(|e| {
            miette::miette!("DR-CLI-0051: cannot write {}: {e}", recon_path.display())
        })?;
    }
    Ok(())
}

fn join_skeleton_source(skeleton: &disrobe_pass_nuitka::NuitkaSkeleton) -> String {
    skeleton
        .modules
        .iter()
        .map(|m: &disrobe_pass_nuitka::SkeletonModule| m.python.clone())
        .collect::<Vec<String>>()
        .join("\n\n")
}

fn emit_skeleton_modules(
    skeleton: Option<&disrobe_pass_nuitka::NuitkaSkeleton>,
    out_dir: &std::path::Path,
    entry_stem: Option<&str>,
) -> miette::Result<Vec<ModuleEmit>> {
    let Some(skeleton): Option<&disrobe_pass_nuitka::NuitkaSkeleton> = skeleton else {
        return Ok(Vec::new());
    };
    let names: Vec<String> = skeleton
        .modules
        .iter()
        .map(|m: &disrobe_pass_nuitka::SkeletonModule| m.name.clone())
        .collect();
    let app_packages: Vec<String> = disrobe_pass_nuitka::infer_app_packages(entry_stem, &names);
    let skel_dir: PathBuf = out_dir.join("skeleton");
    let mut emits: Vec<ModuleEmit> = Vec::with_capacity(skeleton.modules.len());
    for module in &skeleton.modules {
        if module.python.is_empty() {
            continue;
        }
        let origin: disrobe_pass_nuitka::ModuleOrigin = disrobe_pass_nuitka::classify_with_filename(
            &module.name,
            module.filename.as_deref(),
            &app_packages,
        );
        let dir: PathBuf = skel_dir.join(origin.dir());
        std::fs::create_dir_all(&dir)
            .map_err(|e| miette::miette!("DR-CLI-0035: cannot create skeleton dir: {e}"))?;
        let safe: String = sanitize_module_name(&module.name);
        let path: PathBuf = dir.join(format!("{safe}.py"));
        std::fs::write(&path, module.python.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0036: cannot write {}: {e}", path.display()))?;
        emits.push(ModuleEmit {
            module_name: module.name.clone(),
            path,
        });
    }
    Ok(emits)
}

#[derive(Debug)]
struct ModuleEmit {
    module_name: String,
    path: PathBuf,
}

fn emit_bytecode_modules(
    table: Option<&disrobe_pass_nuitka::BytecodeTable>,
    out_dir: &std::path::Path,
) -> miette::Result<Vec<ModuleEmit>> {
    let Some(table): Option<&disrobe_pass_nuitka::BytecodeTable> = table else {
        return Ok(Vec::new());
    };
    let mut emits: Vec<ModuleEmit> = Vec::with_capacity(table.modules.len());
    for module in &table.modules {
        let safe: String = sanitize_module_name(&module.module_name);
        if module.recovered_directly && !module.source.is_empty() {
            let path: PathBuf = out_dir.join(format!("{safe}.py"));
            std::fs::write(&path, module.source.as_bytes()).map_err(|e| {
                miette::miette!("DR-CLI-0033: cannot write {}: {e}", path.display())
            })?;
            emits.push(ModuleEmit {
                module_name: module.module_name.clone(),
                path,
            });
        } else if !module.disassembly.is_empty() {
            let path: PathBuf = out_dir.join(format!("{safe}.dis.txt"));
            std::fs::write(&path, module.disassembly.as_bytes()).map_err(|e| {
                miette::miette!("DR-CLI-0033: cannot write {}: {e}", path.display())
            })?;
            emits.push(ModuleEmit {
                module_name: module.module_name.clone(),
                path,
            });
        }
    }
    Ok(emits)
}

fn emit_surface_skeleton(
    surface: Option<&disrobe_pass_nuitka::SurfaceModule>,
    out_dir: &std::path::Path,
    stem: &str,
) -> miette::Result<Option<PathBuf>> {
    let Some(surface): Option<&disrobe_pass_nuitka::SurfaceModule> = surface else {
        return Ok(None);
    };
    if surface.python_source.is_empty() {
        return Ok(None);
    }
    let path: PathBuf = out_dir.join(format!("{stem}.surface.py"));
    std::fs::write(&path, surface.python_source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0034: cannot write surface skeleton: {e}"))?;
    Ok(Some(path))
}

fn sanitize_module_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed: &str = cleaned.trim_matches(['.', '/', '\\', ' ']);
    if trimmed.is_empty() {
        "module".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn constants(input: PathBuf, blob_name: String, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0029: cannot read .const file: {e}"))?;
    let source_file: String = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("input.const")
        .to_owned();
    let pool: disrobe_pass_nuitka::ConstantsPool =
        disrobe_pass_nuitka::decompile_const_bytes(&bytes, &source_file, &blob_name)
            .map_err(|e| miette::miette!("{e}"))?;

    if let Some(target) = out {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0026: cannot create dir: {e}"))?;
        }
        let json: Vec<u8> = serde_json::to_vec_pretty(&pool)
            .map_err(|e| miette::miette!("DR-CLI-0027: cannot serialize pool: {e}"))?;
        std::fs::write(&target, &json)
            .map_err(|e| miette::miette!("DR-CLI-0028: cannot write pool: {e}"))?;
        println!("  wrote:            {}", target.display());
    }

    println!("nuitka constants: OK");
    println!("  source file:      {source_file}");
    println!("  blob name:        {blob_name:?}");
    println!("  bytes consumed:   {}", pool.bytes_consumed);
    println!("  pickle streams:   {}", pool.stream_count);
    println!("  distinct strings: {}", pool.strings.len());
    println!("  distinct ints:    {}", pool.ints.len());
    println!("  globals:          {}", pool.globals.len());
    println!("  strings:          {:?}", pool.strings);
    println!("  ints:             {:?}", pool.ints);
    Ok(())
}

fn print_version(version: &disrobe_pass_nuitka::NuitkaVersionReport) {
    if let Some(exact) = &version.exact {
        println!(
            "  version:          {}.{}.{} {} ({:?})",
            exact.major, exact.minor, exact.micro, exact.release_level, version.confidence
        );
    } else {
        let era: &str = version.era_label.as_deref().unwrap_or("unknown");
        println!("  version:          {era} ({:?})", version.confidence);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn nuitka_build_dir(name: &str) -> Option<PathBuf> {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("nuitka")
            .join(name);
        if path.is_dir() { Some(path) } else { None }
    }

    #[test]
    fn decompile_writes_recovered_directly_module_as_py() {
        let Some(build_dir): Option<PathBuf> = nuitka_build_dir("bytecode-module/app.build") else {
            return;
        };
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("nuitka-decompile-bytecode-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let out_json: PathBuf = scratch.join("app.nuitka-constants.json");

        decompile(build_dir, Some(out_json.clone()), None).expect("decompile ok");

        assert!(out_json.is_file(), "constants json must land");
        let recovered_py: PathBuf = scratch.join("packaging.py");
        assert!(
            recovered_py.is_file(),
            "a recovered_directly module must be written as <name>.py"
        );
        let py: String = std::fs::read_to_string(&recovered_py).expect("read recovered py");
        assert!(
            py.contains("def describe"),
            "recovered .py must be the real decompiled source, not a placeholder: {py}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    fn real_corpus_exe(name: &str) -> Option<PathBuf> {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("nuitka")
            .join("real")
            .join(name);
        if path.is_file() { Some(path) } else { None }
    }

    #[test]
    fn decompile_binary_surfaces_skeleton_and_emits_py() {
        let Some(exe): Option<PathBuf> = real_corpus_exe("sample_app-standalone.exe") else {
            return;
        };
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("nuitka-cli-skeleton-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let out_json: PathBuf = scratch.join("x.json");

        decompile(exe, Some(out_json.clone()), None).expect("decompile ok");

        let json: String = std::fs::read_to_string(&out_json).expect("read json");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse json");
        assert!(
            parsed
                .get("skeleton")
                .is_some_and(|s: &serde_json::Value| !s.is_null()),
            "CLI-facing JSON must carry the skeleton"
        );
        assert!(
            parsed
                .get("module_constants")
                .is_some_and(|s: &serde_json::Value| !s.is_null()),
            "CLI-facing JSON must carry module_constants"
        );
        let core_py: PathBuf = scratch
            .join("skeleton")
            .join("app")
            .join("sample_app.core.py");
        assert!(
            core_py.is_file(),
            "per-module app skeleton .py must be emitted under skeleton/app/"
        );
        let core: String = std::fs::read_to_string(&core_py).expect("read core skeleton");
        assert!(
            core.contains("def compute_checksum(data: bytes) -> int"),
            "skeleton .py must carry the typed signature: {core}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn decompile_emits_surface_skeleton_by_default() {
        let Some(build_dir): Option<PathBuf> = nuitka_build_dir("module/hello.build") else {
            return;
        };
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("nuitka-decompile-surface-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let out_json: PathBuf = scratch.join("hello.nuitka-constants.json");

        decompile(build_dir, Some(out_json), None).expect("decompile ok");

        let surface_py: PathBuf = scratch.join("hello.surface.py");
        assert!(
            surface_py.is_file(),
            "the surface C-skeleton must be emitted by default as <stem>.surface.py without --python"
        );
        let surface: String = std::fs::read_to_string(&surface_py).expect("read surface");
        assert!(
            surface.contains("def "),
            "surface skeleton must carry the real recovered Python surface: {surface}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
