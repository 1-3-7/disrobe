#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use disrobe_core::progress::Progress as _;

use super::globals;
use super::progress_ui;

const NWJS_ZIP_ENTRY_COUNT_CAP: usize = 65_535;
const NWJS_ZIP_ENTRY_BYTES_CAP: u64 = 512 * 1024 * 1024;
const NWJS_ZIP_TOTAL_BYTES_CAP: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Subcommand, Debug)]
pub(crate) enum JsCmd {
    #[command(
        about = "inspect a V8 cached-data (.jsc), Node SEA blob, nexe-built exe, nw.js zip suffix, or Electron .asar; recovers and disassembles BytecodeArrays from a node-24 .jsc"
    )]
    V8 {
        #[arg(
            help = "input artifact: .jsc / sea-prep.blob / nexe-built exe / nw.js binary / app.asar"
        )]
        input: PathBuf,
        #[arg(
            long = "json-out",
            help = "write a JSON report alongside the human-readable summary (collides with global --json bool; use --json-out)"
        )]
        json_out: Option<PathBuf>,
        #[arg(
            short,
            long,
            help = "carve each container member (asar / nexe / nw.js / SEA) to this directory and write any recovered .jsc disassembly as <stem>.jsc.txt"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            default_value_t = 4usize,
            help = "minimum ASCII run length for snapshot string-pool scrape (default 4)"
        )]
        scrape_min: usize,
    },
    #[command(
        about = "deobfuscate a JavaScript / TypeScript source file (obfuscator.io, JS-Confuser, Jscrambler, jsfuck, JJEncode, AAEncode, Dean Edwards Packer, ...)"
    )]
    Deob {
        #[arg(help = "obfuscated JavaScript / TypeScript source file")]
        input: Option<PathBuf>,
        #[arg(short, long, help = "output path for the deobfuscated source")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "list the obfuscators/protectors disrobe can detect for this pass, then exit"
        )]
        list: bool,
        #[arg(
            long,
            help = "run unminify peepholes (!0 / !1, void 0, !!x, 'a' + 'b' merge) after string-array recovery"
        )]
        unminify: bool,
        #[arg(
            long,
            help = "run hex-ident rename (_0xabcd -> var_1, var_2, ...) for human-readable output"
        )]
        rename: bool,
        #[arg(
            long,
            help = "run scope-aware rename via oxc_semantic (skips obj._0xabc member props, conflict-checked)"
        )]
        rename_scope_aware: bool,
        #[arg(
            long,
            value_enum,
            help = "target a specific legacy or hard-to-detect obfuscator family"
        )]
        legacy: Option<LegacyFamily>,
        #[arg(
            long,
            help = "run the full obfuscator.io reversal pipeline (string-array decode, control-flow unflattening, opaque-predicate folding, packing expansion, dead-code & debug-protection strip) iterated to a fixpoint"
        )]
        full: bool,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
        #[arg(
            long = "recover-sources",
            value_name = "OUTDIR",
            help = "reconstruct the whole original source tree of a deployed/minified/obfuscated frontend (a .js carrying an inline or external source map) into OUTDIR; falls back to an unminify pass when no map is present"
        )]
        recover_sources: Option<PathBuf>,
        #[arg(
            long,
            help = "with --recover-sources, do not write skeleton stubs for sources whose sourcesContent is absent"
        )]
        no_stubs: bool,
    },
    #[command(
        about = "reconstruct the original source tree from a JavaScript source map (.js.map, an inline data: map, or the //# sourceMappingURL comment in a .js file); writes the original files when sourcesContent is present, else a skeleton from sources[]/names[]"
    )]
    Sourcemap {
        #[arg(
            help = "input: a .js.map, a .js file carrying a //# sourceMappingURL comment, or a file containing a data: source map url"
        )]
        input: PathBuf,
        #[arg(short, long, help = "output directory for the recovered source tree")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "do not write skeleton stubs for sources whose sourcesContent is absent"
        )]
        no_stubs: bool,
        #[arg(
            long,
            help = "print the recovery report as JSON to stdout instead of writing files"
        )]
        report: bool,
    },
    #[command(
        about = "split a bundled JavaScript file back into per-module sources (Webpack 4 / 5, Vite, Rollup, esbuild, Turbopack, Bun, Parcel 2, Browserify, SystemJS / RequireJS / AMD, Rolldown)"
    )]
    Unbundle {
        #[arg(help = "bundled JavaScript file to split")]
        input: PathBuf,
        #[arg(short, long, help = "output directory")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = UnbundleTarget::Auto,
            help = "force a specific bundler runtime; default auto-detects from runtime markers"
        )]
        target: UnbundleTarget,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds; sourcemap synthesizes per-chunk v3 source maps and decodes embedded data-url maps"
        )]
        emit: Vec<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnbundleTarget {
    Auto,
    Webpack,
    Webpack4,
    Webpack5,
    Vite,
    Rollup,
    Esbuild,
    Turbopack,
    Bun,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyFamily {
    Jsobfu,
    JscramblerFree,
    Auto,
}

pub(crate) fn run(action: JsCmd) -> miette::Result<()> {
    match action {
        JsCmd::V8 {
            input,
            json_out,
            out,
            scrape_min,
        } => v8_inspect(input, json_out, out, scrape_min),
        JsCmd::Deob {
            input,
            out,
            list,
            unminify,
            rename,
            rename_scope_aware,
            legacy,
            full,
            emit,
            recover_sources,
            no_stubs,
        } => {
            if let Some(out_dir) = recover_sources {
                let Some(input): Option<PathBuf> = input else {
                    return Err(miette::miette!(
                        "DR-CLI-0100: js --recover-sources needs an input .js file"
                    ));
                };
                return recover_deployed(input, out_dir, no_stubs);
            }
            deob(
                input,
                out,
                list,
                unminify,
                rename,
                rename_scope_aware,
                legacy,
                full,
                emit,
            )
        }
        JsCmd::Sourcemap {
            input,
            out,
            no_stubs,
            report,
        } => sourcemap_recover(input, out, no_stubs, report),
        JsCmd::Unbundle {
            input,
            out,
            target,
            emit,
        } => unbundle(input, out, target, emit),
    }
}

fn load_source_map_json(input: &std::path::Path, bytes: &[u8]) -> miette::Result<String> {
    let text: &str = std::str::from_utf8(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0090: input is not UTF-8: {e}"))?;
    if let Some(info) = disrobe_pass_js_deob::find_source_map(text) {
        if info.inline {
            return disrobe_pass_js_deob::decode_data_url_json(&info.url)
                .map_err(|e| miette::miette!("DR-CLI-0091: decode inline source map: {e}"));
        }
        let referenced: PathBuf = input
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(&info.url);
        if referenced.exists() {
            return std::fs::read_to_string(&referenced).map_err(|e| {
                miette::miette!(
                    "DR-CLI-0092: cannot read referenced map {}: {e}",
                    referenced.display()
                )
            });
        }
        return Err(miette::miette!(
            "DR-CLI-0093: input references external map `{}` which was not found next to {}; fetch it and pass the .map directly",
            info.url,
            input.display()
        ));
    }
    if text.trim_start().starts_with("data:") {
        return disrobe_pass_js_deob::decode_data_url_json(text.trim())
            .map_err(|e| miette::miette!("DR-CLI-0094: decode data: source map: {e}"));
    }
    Ok(text.to_owned())
}

fn sourcemap_recover(
    input: PathBuf,
    out: Option<PathBuf>,
    no_stubs: bool,
    report_only: bool,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0095: cannot read input: {e}"))?;
    let raw_json: String = load_source_map_json(&input, &bytes)?;
    let options: disrobe_pass_js_deob::RecoverOptions = disrobe_pass_js_deob::RecoverOptions {
        emit_stubs: !no_stubs,
    };
    let report: disrobe_pass_js_deob::RecoveryReport =
        disrobe_pass_js_deob::recover_source_map_json(&raw_json, options)
            .map_err(|e| miette::miette!("DR-CLI-0096: source map recovery failed: {e}"))?;

    if report_only {
        let json: String = serde_json::to_string_pretty(&report)
            .map_err(|e| miette::miette!("DR-CLI-0097: serialize report: {e}"))?;
        println!("{json}");
        return Ok(());
    }

    let g: globals::Globals = globals::current();
    let out_root: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("js-sourcemap");
        PathBuf::from(format!("./out/{stem}.sources"))
    });
    if g.dry_run {
        println!("js sourcemap: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  out dir:      {}", out_root.display());
        println!("  sources:      {}", report.total_sources);
        println!("  with content: {}", report.with_content);
        println!("  stubs:        {}", report.reconstructed_stubs);
        return Ok(());
    }
    if out_root.exists() && !g.force {
        let has_entries: bool =
            std::fs::read_dir(&out_root).is_ok_and(|mut it| it.next().is_some());
        if has_entries {
            return Err(miette::miette!(
                "DR-CLI-0098: out dir {} already exists; pass --force to overwrite",
                out_root.display()
            ));
        }
    }
    let written: std::collections::BTreeMap<String, PathBuf> =
        disrobe_pass_js_deob::write_recovered_sources(&out_root, &report)
            .map_err(|e| miette::miette!("DR-CLI-0099: cannot write recovered sources: {e}"))?;

    println!("js sourcemap: OK");
    println!(
        "  file:         {}",
        report.file.as_deref().unwrap_or("(none)")
    );
    println!(
        "  source root:  {}",
        report.source_root.as_deref().unwrap_or("(none)")
    );
    println!("  sources:      {}", report.total_sources);
    println!("  with content: {}", report.with_content);
    println!("  stubs:        {}", report.reconstructed_stubs);
    println!("  out dir:      {}", out_root.display());
    for (rel, path) in &written {
        println!("    - {rel}: {}", path.display());
    }
    Ok(())
}

fn recover_deployed(input: PathBuf, out_dir: PathBuf, no_stubs: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0101: cannot read input: {e}"))?;
    let source_text: &str = std::str::from_utf8(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0102: input is not UTF-8: {e}"))?;
    let options: disrobe_pass_js_deob::RecoverOptions = disrobe_pass_js_deob::RecoverOptions {
        emit_stubs: !no_stubs,
    };
    let input_dir: PathBuf = input
        .parent()
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
    let recovery: disrobe_pass_js_deob::DeployedRecovery =
        disrobe_pass_js_deob::recover_deployed_source(source_text, options, |url: &str| {
            std::fs::read_to_string(input_dir.join(url)).ok()
        })
        .map_err(|e| miette::miette!("DR-CLI-0103: deployed-source recovery failed: {e}"))?;

    let g: globals::Globals = globals::current();
    if out_dir.exists() && !g.force {
        let has_entries: bool = std::fs::read_dir(&out_dir).is_ok_and(|mut it| it.next().is_some());
        if has_entries {
            return Err(miette::miette!(
                "DR-CLI-0104: out dir {} already exists; pass --force to overwrite",
                out_dir.display()
            ));
        }
    }

    println!("js recover-sources: OK");
    println!("  input:        {}", input.display());
    match &recovery.location {
        disrobe_pass_js_deob::SourceMapLocation::Inline => {
            println!("  source map:   inline (data: url in //# sourceMappingURL)");
        }
        disrobe_pass_js_deob::SourceMapLocation::External { url } => {
            println!("  source map:   external -> {url}");
        }
        disrobe_pass_js_deob::SourceMapLocation::Absent => {
            println!("  source map:   absent");
        }
    }

    if let Some(report) = recovery.report.as_ref() {
        let written: std::collections::BTreeMap<String, PathBuf> =
            disrobe_pass_js_deob::write_recovered_sources(&out_dir, report)
                .map_err(|e| miette::miette!("DR-CLI-0105: cannot write recovered tree: {e}"))?;
        println!("  out dir:      {}", out_dir.display());
        println!("  sources:      {}", report.total_sources);
        println!(
            "  byte-identical (sourcesContent present): {}",
            report.with_content
        );
        println!(
            "  honest stubs (sourcesContent absent):    {}",
            report.reconstructed_stubs
        );
        println!(
            "  ignored (build tooling):                 {}",
            report.ignored_sources
        );
        println!(
            "  mapped segments:                         {}",
            report.mapped_segments
        );
        if let Some(id) = report.debug_id.as_ref() {
            println!("  debug id:     {id}");
        }
        if report.hermes {
            println!("  hermes:       yes (react-native metro map)");
        }
        for file in &report.files {
            let tag: &str = if file.reconstructed { "stub" } else { "orig" };
            let path: Option<&PathBuf> = written.get(&file.relative_path);
            match path {
                Some(p) => println!(
                    "    [{tag}] {} ({} bytes) -> {}",
                    file.relative_path,
                    file.bytes.len(),
                    p.display()
                ),
                None => println!(
                    "    [{tag}] {} ({} bytes)",
                    file.relative_path,
                    file.bytes.len()
                ),
            }
        }
        return Ok(());
    }

    match recovery.fallback.as_ref() {
        Some(disrobe_pass_js_deob::NoMapFallback::Deobfuscated { source }) => {
            std::fs::create_dir_all(&out_dir).map_err(|e: std::io::Error| {
                miette::miette!("DR-CLI-0106: cannot create out dir: {e}")
            })?;
            let stem: &str = input
                .file_stem()
                .and_then(|s: &std::ffi::OsStr| s.to_str())
                .unwrap_or("deployed");
            let dest: PathBuf = out_dir.join(format!("{stem}.unminified.js"));
            std::fs::write(&dest, source.as_bytes()).map_err(|e: std::io::Error| {
                miette::miette!("DR-CLI-0107: cannot write unminified source: {e}")
            })?;
            println!(
                "  no source map: ran an unminify pass instead (no original tree is recoverable)"
            );
            println!("  wrote:        {}", dest.display());
        }
        Some(disrobe_pass_js_deob::NoMapFallback::OriginalUnchanged) | None => {
            println!("  no source map and the unminify pass produced no change; nothing to write");
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct RecoveredFunction {
    bytecode_file_offset: usize,
    frame_size: i32,
    parameter_count: u16,
    bytecode_length: usize,
    instruction_count: usize,
    disassembly: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
enum V8Report {
    Bytenode {
        path: String,
        magic: String,
        node_version: disrobe_pass_js_deob::v8::NodeVersion,
        header_layout: disrobe_pass_js_deob::v8::HeaderLayout,
        header_size: usize,
        payload_offset: usize,
        payload_length: usize,
        snapshot_status: disrobe_pass_js_deob::v8::SnapshotDeserializeStatus,
        scraped_strings: Vec<String>,
        structural: disrobe_pass_js_deob::v8::StructuralRecovery,
        bytecode_functions: Vec<RecoveredFunction>,
        bytecode_recovery_note: Option<String>,
    },
    NodeSea {
        path: String,
        magic: String,
        magic_offset: u64,
        flags_raw: u32,
        flags: disrobe_pass_js_deob::v8::SeaFlags,
        code_path: String,
        main_code_len: u64,
    },
    Nexe {
        path: String,
        payload_offset: u64,
        payload_size: u64,
        footer_offset: u64,
    },
    NwjsZipSuffix {
        path: String,
        eocd_offset: u64,
        central_dir_offset: u64,
        central_dir_size: u64,
    },
    Asar {
        path: String,
        data_offset: u64,
        entry_count: usize,
        entries: Vec<disrobe_pass_js_deob::v8::AsarListingEntry>,
    },
    Unrecognized {
        path: String,
        len: usize,
    },
}

fn v8_inspect(
    input: PathBuf,
    json_out: Option<PathBuf>,
    out: Option<PathBuf>,
    scrape_min: usize,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0060: cannot read input: {e}"))?;
    let report: V8Report = classify_v8_artifact(&input, &bytes, scrape_min);
    match &report {
        V8Report::Bytenode {
            magic,
            node_version,
            header_layout,
            header_size,
            payload_offset,
            payload_length,
            snapshot_status,
            scraped_strings,
            structural,
            bytecode_functions,
            bytecode_recovery_note,
            ..
        } => {
            println!("v8 bytenode (.jsc / V8 SerializedCodeData):");
            println!("  magic:             {magic}");
            println!("  node version:      {}", node_version.label());
            println!("  header layout:     {header_layout:?}");
            println!("  header size:       {header_size} bytes");
            println!("  payload offset:    {payload_offset}");
            println!("  payload length:    {payload_length} bytes");
            if !bytecode_functions.is_empty() {
                println!(
                    "  recovered functions ({}) via CodeSerializer object-graph parse:",
                    bytecode_functions.len()
                );
                for (i, func) in bytecode_functions.iter().enumerate() {
                    println!(
                        "    [{i}] @0x{:X}  params={}  frame={}  bytecode={}B  instrs={}",
                        func.bytecode_file_offset,
                        func.parameter_count,
                        func.frame_size,
                        func.bytecode_length,
                        func.instruction_count
                    );
                    for line in func.disassembly.lines() {
                        println!("        {line}");
                    }
                }
            } else if let Some(note) = bytecode_recovery_note {
                match snapshot_status {
                    disrobe_pass_js_deob::v8::SnapshotDeserializeStatus::UnknownV8Marker {
                        magic_low,
                    } => {
                        println!(
                            "  bytecode recovery: skipped (UnknownV8Marker low16=0x{magic_low:04X})"
                        );
                    }
                    disrobe_pass_js_deob::v8::SnapshotDeserializeStatus::KnownV8Version {
                        ..
                    } => {
                        println!("  bytecode recovery: {note}");
                    }
                }
            }
            println!("  structural recovery (deterministic, self-contained, offline):");
            println!(
                "    SFI markers:       {}",
                structural.shared_function_info_markers
            );
            let names: Vec<&str> = structural.function_name_candidates();
            println!("    function/binding names ({}):", names.len());
            for n in names.iter().take(20usize) {
                println!("      - {n:?}");
            }
            let literals: Vec<&str> = structural.string_literal_candidates();
            println!("    inline string literals ({}):", literals.len());
            for s in literals.iter().take(20usize) {
                println!("      - {s:?}");
            }
            println!(
                "    recovered string bytes: {}",
                structural.recovered_byte_total
            );
            println!("  lossy limits (honest):");
            for note in &structural.lossy_notes {
                println!("    - {note}");
            }
            println!(
                "  raw printable-run scrape ({} unique, superset incl. binary-adjacent noise):",
                scraped_strings.len()
            );
            for s in scraped_strings.iter().take(10usize) {
                println!("    - {s:?}");
            }
            if scraped_strings.len() > 10usize {
                println!("    ... ({} more)", scraped_strings.len() - 10usize);
            }
        }
        V8Report::NodeSea {
            magic,
            magic_offset,
            flags,
            code_path,
            main_code_len,
            ..
        } => {
            println!("node sea blob:");
            println!("  magic:             {magic}");
            println!("  magic offset:      {magic_offset}");
            println!(
                "  flags:             use_snapshot={} use_code_cache={} include_assets={} include_exec_argv={}",
                flags.use_snapshot,
                flags.use_code_cache,
                flags.include_assets,
                flags.include_exec_argv
            );
            println!("  code path:         {code_path:?}");
            println!("  main code length:  {main_code_len} bytes");
        }
        V8Report::Nexe {
            payload_offset,
            payload_size,
            footer_offset,
            ..
        } => {
            println!("nexe (last-N-byte footer):");
            println!("  footer offset:     {footer_offset}");
            println!("  payload offset:    {payload_offset}");
            println!("  payload size:      {payload_size} bytes");
        }
        V8Report::NwjsZipSuffix {
            eocd_offset,
            central_dir_offset,
            central_dir_size,
            ..
        } => {
            println!("nw.js (ZIP EOCD appended to host binary):");
            println!("  eocd offset:       {eocd_offset}");
            println!("  central dir off:   {central_dir_offset}");
            println!("  central dir size:  {central_dir_size}");
        }
        V8Report::Asar {
            data_offset,
            entry_count,
            entries,
            ..
        } => {
            println!("electron asar archive:");
            println!("  data offset:       {data_offset}");
            println!("  entries:           {entry_count}");
            for e in entries.iter().take(20usize) {
                println!("    - {} (offset={}, size={})", e.path, e.offset, e.size);
            }
            if entries.len() > 20usize {
                println!("    ... ({} more)", entries.len() - 20usize);
            }
        }
        V8Report::Unrecognized { len, .. } => {
            println!("v8 inspect: no known artifact signature");
            println!("  input length:      {len} bytes");
            println!("  tried: .jsc / SEA / nexe / nw.js / asar");
        }
    }
    if let Some(out_dir) = out {
        carve_v8_members(&input, &bytes, &report, &out_dir)?;
    }
    if let Some(out) = json_out {
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e: std::io::Error| {
                miette::miette!("DR-CLI-0061: cannot create json dir: {e}")
            })?;
        }
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&report).map_err(|e: serde_json::Error| {
                miette::miette!("DR-CLI-0062: serialize v8 report: {e}")
            })?;
        std::fs::write(&out, &payload).map_err(|e: std::io::Error| {
            miette::miette!("DR-CLI-0063: cannot write v8 report json: {e}")
        })?;
        println!("  json report:       {}", out.display());
    }
    Ok(())
}

fn carve_v8_members(
    input: &std::path::Path,
    bytes: &[u8],
    report: &V8Report,
    out_dir: &std::path::Path,
) -> miette::Result<()> {
    std::fs::create_dir_all(out_dir).map_err(|e: std::io::Error| {
        miette::miette!(
            "DR-CLI-0064: cannot create carve dir {}: {e}",
            out_dir.display()
        )
    })?;
    let stem: &str = input
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .unwrap_or("v8");
    match report {
        V8Report::Asar { entries, .. } => {
            let listing: disrobe_pass_js_deob::v8::AsarListing =
                disrobe_pass_js_deob::v8::list_asar(bytes)
                    .map_err(|e| miette::miette!("DR-CLI-0065: re-parse asar for carve: {e}"))?;
            for entry in entries {
                let member: &[u8] =
                    disrobe_pass_js_deob::v8::carve_asar_entry(bytes, &listing, entry)
                        .map_err(|e| miette::miette!("DR-CLI-0066: carve asar entry: {e}"))?;
                let dest: PathBuf = join_member_path(out_dir, &entry.path)?;
                write_member(&dest, member)?;
                println!(
                    "  carved:            {} ({} bytes)",
                    dest.display(),
                    member.len()
                );
            }
        }
        V8Report::Nexe { .. } => {
            let loc: disrobe_pass_js_deob::v8::NexeLocation =
                disrobe_pass_js_deob::v8::detect_nexe_suffix(bytes).ok_or_else(|| {
                    miette::miette!("DR-CLI-0067: nexe footer vanished on re-parse")
                })?;
            let payload: &[u8] = disrobe_pass_js_deob::v8::carve_nexe_payload(bytes, &loc)
                .map_err(|e| miette::miette!("DR-CLI-0068: carve nexe payload: {e}"))?;
            let dest: PathBuf = out_dir.join("nexe-payload.bin");
            write_member(&dest, payload)?;
            println!(
                "  carved:            {} ({} bytes)",
                dest.display(),
                payload.len()
            );
        }
        V8Report::NwjsZipSuffix { .. } => {
            let written: usize = carve_nwjs_zip(bytes, out_dir)?;
            println!(
                "  carved:            {written} nw.js zip member(s) -> {}",
                out_dir.display()
            );
        }
        V8Report::NodeSea { code_path, .. } => {
            let blob: disrobe_pass_js_deob::v8::SeaBlob =
                disrobe_pass_js_deob::v8::parse_sea_blob(bytes)
                    .map_err(|e| miette::miette!("DR-CLI-0069: re-parse sea for carve: {e}"))?;
            let main: Vec<u8> = disrobe_pass_js_deob::v8::carve_sea_main_code(bytes, &blob)
                .map_err(|e| miette::miette!("DR-CLI-0070: carve sea main code: {e}"))?;
            let name: String = sea_member_name(code_path);
            let dest: PathBuf = out_dir.join(&name);
            write_member(&dest, &main)?;
            println!(
                "  carved:            {} ({} bytes)",
                dest.display(),
                main.len()
            );
        }
        V8Report::Bytenode {
            bytecode_functions, ..
        } => {
            if bytecode_functions.is_empty() {
                println!("  carve:             no .jsc disassembly recovered (nothing to write)");
            } else {
                use std::fmt::Write as _;
                let mut text: String = String::new();
                for (i, func) in bytecode_functions.iter().enumerate() {
                    let _: core::fmt::Result = writeln!(
                        text,
                        "; function [{i}] @0x{:X} params={} frame={} bytecode={}B instrs={}",
                        func.bytecode_file_offset,
                        func.parameter_count,
                        func.frame_size,
                        func.bytecode_length,
                        func.instruction_count
                    );
                    text.push_str(&func.disassembly);
                    if !func.disassembly.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push('\n');
                }
                let dest: PathBuf = out_dir.join(format!("{stem}.jsc.txt"));
                std::fs::write(&dest, text.as_bytes()).map_err(|e: std::io::Error| {
                    miette::miette!("DR-CLI-0071: cannot write jsc disassembly: {e}")
                })?;
                println!(
                    "  carved:            {} ({} functions)",
                    dest.display(),
                    bytecode_functions.len()
                );
            }
        }
        V8Report::Unrecognized { .. } => {
            println!("  carve:             unrecognized artifact, nothing to carve");
        }
    }
    Ok(())
}

fn join_member_path(out_dir: &std::path::Path, member: &str) -> miette::Result<PathBuf> {
    let rel: PathBuf = PathBuf::from(member);
    let safe: bool = rel
        .components()
        .all(|c: std::path::Component<'_>| matches!(c, std::path::Component::Normal(_)));
    if !safe {
        return Err(miette::miette!(
            "DR-CLI-0072: refusing to carve member with traversal/absolute path: {member}"
        ));
    }
    Ok(out_dir.join(rel))
}

fn write_member(dest: &std::path::Path, body: &[u8]) -> miette::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e: std::io::Error| {
            miette::miette!("DR-CLI-0073: cannot create dir {}: {e}", parent.display())
        })?;
    }
    std::fs::write(dest, body).map_err(|e: std::io::Error| {
        miette::miette!("DR-CLI-0074: cannot write {}: {e}", dest.display())
    })
}

fn sea_member_name(code_path: &str) -> String {
    let base: Option<&str> = std::path::Path::new(code_path)
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str());
    match base {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => "sea-main.js".to_owned(),
    }
}

fn carve_nwjs_zip(bytes: &[u8], out_dir: &std::path::Path) -> miette::Result<usize> {
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> = zip::ZipArchive::new(cursor)
        .map_err(|e: zip::result::ZipError| miette::miette!("DR-CLI-0075: nw.js zip open: {e}"))?;
    let entry_count: usize = archive.len();
    if entry_count > NWJS_ZIP_ENTRY_COUNT_CAP {
        return Err(miette::miette!(
            "DR-CLI-0081: nw.js zip entry count {entry_count} exceeds cap {NWJS_ZIP_ENTRY_COUNT_CAP}"
        ));
    }
    let mut written: usize = 0usize;
    let mut total_written: u64 = 0u64;
    for i in 0..entry_count {
        let mut entry: zip::read::ZipFile<'_> =
            archive.by_index(i).map_err(|e: zip::result::ZipError| {
                miette::miette!("DR-CLI-0076: zip entry {i}: {e}")
            })?;
        let Some(rel): Option<PathBuf> = entry.enclosed_name() else {
            continue;
        };
        let dest: PathBuf = out_dir.join(&rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest).map_err(|e: std::io::Error| {
                miette::miette!("DR-CLI-0077: mkdir {}: {e}", dest.display())
            })?;
            continue;
        }
        let declared: u64 = entry.size();
        let remaining: u64 = NWJS_ZIP_TOTAL_BYTES_CAP
            .checked_sub(total_written)
            .ok_or_else(|| {
                miette::miette!(
                    "DR-CLI-0082: nw.js zip output exceeds total cap {NWJS_ZIP_TOTAL_BYTES_CAP}"
                )
            })?;
        let read_cap: u64 = NWJS_ZIP_ENTRY_BYTES_CAP.min(remaining);
        if declared > read_cap {
            return Err(miette::miette!(
                "DR-CLI-0083: nw.js zip entry {} declared size {declared} exceeds cap {read_cap}",
                rel.display()
            ));
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e: std::io::Error| {
                miette::miette!("DR-CLI-0078: mkdir parent {}: {e}", parent.display())
            })?;
        }
        let mut file: std::fs::File =
            std::fs::File::create(&dest).map_err(|e: std::io::Error| {
                miette::miette!("DR-CLI-0079: create {}: {e}", dest.display())
            })?;
        let copy_limit: u64 = read_cap.checked_add(1).ok_or_else(|| {
            miette::miette!(
                "DR-CLI-0084: nw.js zip copy cap overflow for {}",
                rel.display()
            )
        })?;
        let mut limited: std::io::Take<&mut zip::read::ZipFile<'_>> =
            std::io::Read::take(&mut entry, copy_limit);
        let copied: u64 = std::io::copy(&mut limited, &mut file).map_err(|e: std::io::Error| {
            miette::miette!("DR-CLI-0080: write {}: {e}", dest.display())
        })?;
        if copied > read_cap {
            let _: std::io::Result<()> = std::fs::remove_file(&dest);
            return Err(miette::miette!(
                "DR-CLI-0085: nw.js zip entry {} exceeds cap {read_cap}",
                rel.display()
            ));
        }
        total_written = total_written.checked_add(copied).ok_or_else(|| {
            miette::miette!("DR-CLI-0086: nw.js zip output byte counter overflow")
        })?;
        written = written.saturating_add(1usize);
    }
    Ok(written)
}

fn recover_bytecode_functions(
    body: &disrobe_pass_js_deob::v8::BytenodeCacheBody,
) -> (Vec<RecoveredFunction>, Option<String>) {
    match disrobe_pass_js_deob::v8::parse_code_serializer_graph(body) {
        Ok(graph) => {
            let node: disrobe_pass_js_deob::v8::NodeVersion = graph.node_version;
            let functions: Vec<RecoveredFunction> = graph
                .bytecode_arrays
                .iter()
                .map(|bc: &disrobe_pass_js_deob::v8::RecoveredBytecodeArray| {
                    let disasm: disrobe_pass_js_deob::v8::Disassembly =
                        disrobe_pass_js_deob::v8::disassemble(&bc.bytecode, node);
                    RecoveredFunction {
                        bytecode_file_offset: bc.bytecode_file_offset,
                        frame_size: bc.frame_size,
                        parameter_count: bc.parameter_count,
                        bytecode_length: bc.bytecode.len(),
                        instruction_count: disasm.instructions.len(),
                        disassembly: disasm.render_text(),
                    }
                })
                .collect();
            (functions, None)
        }
        Err(e) => (Vec::new(), Some(format!("{e}"))),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn synth_stored_zip(name: &str, body: &[u8]) -> Vec<u8> {
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file(name, opts).expect("start");
        writer.write_all(body).expect("write");
        writer.finish().expect("finish").into_inner()
    }

    fn patch_first_u32(bytes: &mut [u8], signature: &[u8], field_offset: usize, value: u32) {
        let start: usize = bytes
            .windows(signature.len())
            .position(|window: &[u8]| window == signature)
            .expect("signature");
        let at: usize = start + field_offset;
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn carve_nwjs_zip_rejects_forged_entry_size() {
        let mut bytes: Vec<u8> = synth_stored_zip("app.js", b"console.log(1)");
        patch_first_u32(&mut bytes, b"PK\x03\x04", 22, u32::MAX);
        patch_first_u32(&mut bytes, b"PK\x01\x02", 24, u32::MAX);
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-cli-nwjs-forged")
                .expect("create scratch directory");
        let out: PathBuf = scratch.path().join("out");
        let err: miette::Report =
            carve_nwjs_zip(&bytes, &out).expect_err("forged size must reject");
        assert!(format!("{err}").contains("declared size"));
    }
}

fn classify_v8_artifact(input: &std::path::Path, bytes: &[u8], scrape_min: usize) -> V8Report {
    let path_str: String = input.display().to_string();
    if let Ok(body) = disrobe_pass_js_deob::v8::parse_bytenode_full(bytes) {
        let status: disrobe_pass_js_deob::v8::SnapshotDeserializeStatus =
            disrobe_pass_js_deob::v8::snapshot_deserialize_status(&body.header);
        let scraped: disrobe_pass_js_deob::v8::ScrapedConstantPool =
            disrobe_pass_js_deob::v8::scrape_payload_strings(&body.payload, scrape_min);
        let structural: disrobe_pass_js_deob::v8::StructuralRecovery =
            disrobe_pass_js_deob::v8::recover_structure(
                &body.payload,
                body.header.version_hash.node,
            );
        let (bytecode_functions, bytecode_recovery_note): (Vec<RecoveredFunction>, Option<String>) =
            recover_bytecode_functions(&body);
        return V8Report::Bytenode {
            path: path_str,
            magic: format!("0x{:08X}", body.header.magic_number),
            node_version: body.header.version_hash.node,
            header_layout: body.header.layout,
            header_size: body.header.header_size,
            payload_offset: body.payload_offset,
            payload_length: body.payload_length,
            snapshot_status: status,
            scraped_strings: scraped.strings,
            structural,
            bytecode_functions,
            bytecode_recovery_note,
        };
    }
    if let Ok(blob) = disrobe_pass_js_deob::v8::parse_sea_blob(bytes) {
        return V8Report::NodeSea {
            path: path_str,
            magic: format!("0x{:08X}", blob.magic),
            magic_offset: blob.magic_offset,
            flags_raw: blob.flags.raw,
            flags: blob.flags,
            code_path: blob.code_path,
            main_code_len: blob.main_code_len,
        };
    }
    if let Some(loc) = disrobe_pass_js_deob::v8::detect_nexe_suffix(bytes) {
        return V8Report::Nexe {
            path: path_str,
            payload_offset: loc.payload_offset,
            payload_size: loc.payload_size,
            footer_offset: loc.footer_offset,
        };
    }
    if let Some(loc) = disrobe_pass_js_deob::v8::detect_nwjs_zip_suffix(bytes) {
        return V8Report::NwjsZipSuffix {
            path: path_str,
            eocd_offset: loc.eocd_offset,
            central_dir_offset: loc.central_dir_offset,
            central_dir_size: loc.central_dir_size,
        };
    }
    if let Ok(asar) = disrobe_pass_js_deob::v8::list_asar(bytes) {
        let entry_count: usize = asar.entries.len();
        return V8Report::Asar {
            path: path_str,
            data_offset: asar.data_offset,
            entry_count,
            entries: asar.entries,
        };
    }
    V8Report::Unrecognized {
        path: path_str,
        len: bytes.len(),
    }
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn deob(
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    list: bool,
    unminify: bool,
    rename: bool,
    rename_scope_aware: bool,
    legacy: Option<LegacyFamily>,
    full: bool,
    emit: Vec<String>,
) -> miette::Result<()> {
    if list {
        crate::cli::emit::print_obfuscator_catalog(
            &disrobe_pass_js_deob::chain_detector::JsObfDetector,
            "disrobe js deob <input.js> --out <output.js>",
        );
        return Ok(());
    }
    let Some(input): Option<PathBuf> = input else {
        return Err(miette::miette!(
            "DR-CLI-0037b: js deob needs an input file (or `--list` to show supported obfuscators)"
        ));
    };
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0037: cannot read input: {e}"))?;
    let detection: disrobe_pass_js_deob::Detection = disrobe_pass_js_deob::detect(&bytes);
    let source_text: &str = std::str::from_utf8(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0042: input is not UTF-8: {e}"))?;

    if full {
        return deob_full(
            &input,
            out,
            source_text,
            &detection,
            rename,
            rename_scope_aware,
            emit,
        );
    }

    let recovery: Option<disrobe_pass_js_deob::StringArrayRecovery> =
        disrobe_pass_js_deob::recover_string_array(source_text)
            .map_err(|e| miette::miette!("{e}"))?;

    let stem_owned: String = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("js-deob")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem_owned}.deobfuscated.js")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0038: cannot create dir: {e}"))?;
    }
    let detection_path: PathBuf = out_path.with_extension("detection.json");
    let detection_bytes: Vec<u8> =
        serde_json::to_vec_pretty(&detection).map_err(|e: serde_json::Error| {
            miette::miette!("DR-CLI-0039b: serialize detection: {e}")
        })?;
    std::fs::write(&detection_path, &detection_bytes)
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0039: cannot write detection: {e}"))?;

    let mid_source: String = recovery
        .as_ref()
        .map_or_else(|| source_text.to_owned(), |r| r.rewritten_source.clone());

    let (after_legacy, jsobfu_stats, jscrambler_stats): (
        String,
        Option<disrobe_pass_js_deob::JsObfuRewriteStats>,
        Option<disrobe_pass_js_deob::IntegrityStripStats>,
    ) = apply_legacy(&mid_source, legacy);

    let (after_unminify, unminify_stats, ast_unminify_stats): (
        String,
        Option<disrobe_pass_js_deob::UnminifyStats>,
        Option<disrobe_pass_js_deob::AstUnminifyStats>,
    ) = if unminify {
        let (peephole_out, peephole_stats): (String, disrobe_pass_js_deob::UnminifyStats) =
            disrobe_pass_js_deob::unminify(&after_legacy);
        let (ast_out, ast_stats): (String, disrobe_pass_js_deob::AstUnminifyStats) =
            disrobe_pass_js_deob::unminify_ast(&peephole_out);
        (ast_out, Some(peephole_stats), Some(ast_stats))
    } else {
        (after_legacy, None, None)
    };
    let (after_rename, rename_stats): (String, Option<disrobe_pass_js_deob::RenameStats>) =
        if rename {
            let (out, stats): (String, disrobe_pass_js_deob::RenameStats) =
                disrobe_pass_js_deob::rename_hex_idents(&after_unminify);
            (out, Some(stats))
        } else {
            (after_unminify, None)
        };
    let (rewritten, scope_rename_stats): (String, Option<disrobe_pass_js_deob::ScopeAwareStats>) =
        if rename_scope_aware {
            let (out, stats): (String, disrobe_pass_js_deob::ScopeAwareStats) =
                disrobe_pass_js_deob::rename_scope_aware(&after_rename)
                    .map_err(|e| miette::miette!("{e}"))?;
            (out, Some(stats))
        } else {
            (after_rename, None)
        };
    std::fs::write(&out_path, rewritten.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0043: cannot write deobfuscated source: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    crate::cli::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem_owned,
        "js-deob",
        "not implemented for the js pass in this build",
    )?;

    if let Some(ref r) = recovery {
        let recovery_path: PathBuf = out_path.with_extension("recovery.json");
        let recovery_bytes: Vec<u8> =
            serde_json::to_vec_pretty(r).map_err(|e: serde_json::Error| {
                miette::miette!("DR-CLI-0044b: serialize recovery: {e}")
            })?;
        std::fs::write(&recovery_path, &recovery_bytes).map_err(|e: std::io::Error| {
            miette::miette!("DR-CLI-0044: cannot write recovery: {e}")
        })?;
    }

    println!("js deob: OK");
    println!("  family:       {:?}", detection.family);
    println!("  confidence:   {:.2}", detection.confidence);
    println!("  markers:      {:?}", detection.markers);
    if let Some(r) = &recovery {
        println!("  string array:");
        println!("    id:                  {}", r.array_id);
        println!("    original strings:    {}", r.original_strings.len());
        println!("    rotation count:      {}", r.rotation_count);
        println!("    rotator removed:     {}", r.rotator_removed);
        if let Some(ref dec) = r.decoder_name {
            println!("    decoder name:        {dec}");
        }
        println!("    call sites total:    {}", r.call_sites_total);
        println!("    call sites inlined:  {}", r.call_sites_inlined);
    } else {
        println!("  string array:       (not detected)");
    }
    if let Some(stats) = &jsobfu_stats {
        println!("  jsobfu rewrite:");
        println!(
            "    bracket->dot rewrites: {}",
            stats.bracket_to_dot_rewrites
        );
        println!("    array.join folded:     {}", stats.array_join_folded);
    }
    if let Some(stats) = &jscrambler_stats {
        println!("  jscrambler integrity:");
        println!("    iifes stripped:        {}", stats.iifes_stripped);
        println!("    bare loops stripped:   {}", stats.bare_loops_stripped);
        println!("    bytes removed:         {}", stats.bytes_removed);
    }
    if let Some(stats) = &unminify_stats {
        println!("  unminify:");
        println!(
            "    !0/!1 reversed:        {}",
            stats.bool_shorthand_reversed
        );
        println!(
            "    void 0 reversed:       {}",
            stats.void_undefined_reversed
        );
        println!("    !!x reduced:           {}", stats.double_not_reversed);
        println!("    string concat merged:  {}", stats.merged_string_concat);
        println!("    arithmetic folded:     {}", stats.arithmetic_folded);
        println!(
            "    f.call reversed:       {}",
            stats.function_call_reversed
        );
        println!("    globals call sites:    {}", stats.globals_call_sites);
        println!("    globals evaluated:     {}", stats.globals_evaluated);
        println!("    globals failed:        {}", stats.globals_failed);
        println!("    if(true) inlined:      {}", stats.if_true_inlined);
        println!("    if(false) eliminated:  {}", stats.if_false_eliminated);
        println!(
            "    setInterval watchdog:  {}",
            stats.set_interval_watchdogs_removed
        );
        println!(
            "    Function(debugger):    {}",
            stats.function_debugger_removed
        );
        println!(
            "    debugger IIFE:         {}",
            stats.debugger_loops_removed
        );
        println!(
            "    self-defending IIFE:   {}",
            stats.self_defending_iifes_removed
        );
        println!(
            "    self-defending check:  {}",
            stats.self_defending_checkers_removed
        );
        println!(
            "    self-defending wrap:   {}",
            stats.self_defending_wrappers_removed
        );
        println!(
            "    debug-protect ratchet: {}",
            stats.debug_protection_ratchets_removed
        );
        println!("    member access dotted:  {}", stats.member_access_dotted);
        println!(
            "    cf-flatten blocks:     {}",
            stats.control_flow_blocks_unflattened
        );
        println!(
            "    cf-flatten cases:      {}",
            stats.control_flow_cases_inlined
        );
    }
    if let Some(stats) = &ast_unminify_stats {
        println!("  unminify (ast):");
        println!(
            "    indirect calls:        {}",
            stats.indirect_calls_simplified
        );
        println!(
            "    bracket -> dot:        {}",
            stats.bracket_accesses_dotted
        );
        println!(
            "    optional chains:       {}",
            stats.optional_chains_rebuilt
        );
        println!(
            "    nullish coalescing:    {}",
            stats.nullish_coalesces_rebuilt
        );
        println!(
            "    ternary -> if/else:    {}",
            stats.ternary_statements_expanded
        );
        println!(
            "    sequence splits:       {}",
            stats.sequence_statement_splits
        );
        println!(
            "    var decls split:       {}",
            stats.var_declarations_split
        );
        println!("    classes reconstructed: {}", stats.classes_reconstructed);
        println!("    jsx (classic):         {}", stats.jsx_elements_restored);
        println!(
            "    jsx (automatic):       {}",
            stats.jsx_automatic_elements_restored
        );
        println!("    for -> while:          {}", stats.for_loops_to_while);
        println!(
            "    bodies blocked:        {}",
            stats.statement_bodies_blocked
        );
    }
    if let Some(stats) = &rename_stats {
        println!("  rename:");
        println!("    hex idents renamed:    {}", stats.idents_renamed);
        println!("    references rewritten:  {}", stats.references_rewritten);
    }
    if let Some(stats) = &scope_rename_stats {
        println!("  scope-aware rename:");
        println!("    idents renamed:        {}", stats.idents_renamed);
        println!("    references rewritten:  {}", stats.references_rewritten);
    }
    println!("  wrote:        {}", out_path.display());
    println!("  detection:    {}", detection_path.display());
    Ok(())
}

fn deob_full(
    input: &std::path::Path,
    out: Option<PathBuf>,
    source_text: &str,
    detection: &disrobe_pass_js_deob::Detection,
    rename: bool,
    rename_scope_aware: bool,
    emit: Vec<String>,
) -> miette::Result<()> {
    if matches!(
        detection.family,
        disrobe_pass_js_deob::JsObfuscator::JsConfuser
    ) {
        return deob_full_jsconfuser(
            input,
            out,
            source_text,
            detection,
            rename,
            rename_scope_aware,
            emit,
        );
    }
    deob_full_obfuscator_io(
        input,
        out,
        source_text,
        detection,
        rename,
        rename_scope_aware,
        emit,
    )
}

fn apply_full_renames(
    mut current: String,
    rename: bool,
    rename_scope_aware: bool,
) -> miette::Result<(
    String,
    Option<disrobe_pass_js_deob::RenameStats>,
    Option<disrobe_pass_js_deob::ScopeAwareStats>,
)> {
    let rename_stats: Option<disrobe_pass_js_deob::RenameStats> = if rename {
        let (next, stats): (String, disrobe_pass_js_deob::RenameStats) =
            disrobe_pass_js_deob::rename_hex_idents(&current);
        current = next;
        Some(stats)
    } else {
        None
    };
    let scope_rename_stats: Option<disrobe_pass_js_deob::ScopeAwareStats> = if rename_scope_aware {
        let (next, stats): (String, disrobe_pass_js_deob::ScopeAwareStats) =
            disrobe_pass_js_deob::rename_scope_aware(&current)
                .map_err(|e| miette::miette!("{e}"))?;
        current = next;
        Some(stats)
    } else {
        None
    };
    Ok((current, rename_stats, scope_rename_stats))
}

fn deob_full_obfuscator_io(
    input: &std::path::Path,
    out: Option<PathBuf>,
    source_text: &str,
    detection: &disrobe_pass_js_deob::Detection,
    rename: bool,
    rename_scope_aware: bool,
    emit: Vec<String>,
) -> miette::Result<()> {
    let opts: disrobe_pass_js_deob::ObfuscatorIoOptions =
        disrobe_pass_js_deob::ObfuscatorIoOptions::all();
    let output: disrobe_pass_js_deob::ObfuscatorIoOutput =
        disrobe_pass_js_deob::obfuscator_io_deobfuscate(source_text, &opts)
            .map_err(|e| miette::miette!("{e}"))?;

    let (current, rename_stats, scope_rename_stats): (
        String,
        Option<disrobe_pass_js_deob::RenameStats>,
        Option<disrobe_pass_js_deob::ScopeAwareStats>,
    ) = apply_full_renames(output.source.clone(), rename, rename_scope_aware)?;

    let stem_owned: String = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("js-deob")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem_owned}.deobfuscated.js")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0045: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, current.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0046: cannot write deobfuscated source: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    crate::cli::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem_owned,
        "js-deob",
        "not implemented for the js pass in this build",
    )?;

    let pipeline_path: PathBuf = out_path.with_extension("pipeline.json");
    let pipeline_bytes: Vec<u8> = serde_json::to_vec_pretty(&output)
        .map_err(|e: serde_json::Error| miette::miette!("DR-CLI-0047: serialize pipeline: {e}"))?;
    std::fs::write(&pipeline_path, &pipeline_bytes)
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0048: cannot write pipeline: {e}"))?;

    println!("js deob (full pipeline): OK");
    println!("  family:                    {:?}", detection.family);
    println!("  passes run:                {}", output.passes_run);
    println!("  controls applied:          {:?}", output.controls_applied);
    println!(
        "  string-array sites inlined:{}",
        output.string_array_call_sites_inlined
    );
    println!(
        "  cf-flatten collapsed:      {}",
        output.flatten_dispatches_collapsed
    );
    println!(
        "  dispatcher sites inlined:  {}",
        output.dispatcher_call_sites_inlined
    );
    println!(
        "  opaque predicates folded:  {}",
        output.opaque_predicates_folded
    );
    println!(
        "  packed blocks expanded:    {}",
        output.packed_blocks_expanded
    );
    println!(
        "  bracket accesses rewritten:{}",
        output.bracket_accesses_rewritten
    );
    println!("  hex idents renamed:        {}", output.idents_renamed);
    if let Some(stats) = &rename_stats {
        println!("  post-rename hex idents:    {}", stats.idents_renamed);
    }
    if let Some(stats) = &scope_rename_stats {
        println!("  scope-aware renamed:       {}", stats.idents_renamed);
    }
    println!(
        "  bytes:                     {} -> {}",
        source_text.len(),
        current.len()
    );
    println!("  wrote:                     {}", out_path.display());
    println!("  pipeline stats:            {}", pipeline_path.display());
    Ok(())
}

fn deob_full_jsconfuser(
    input: &std::path::Path,
    out: Option<PathBuf>,
    source_text: &str,
    detection: &disrobe_pass_js_deob::Detection,
    rename: bool,
    rename_scope_aware: bool,
    emit: Vec<String>,
) -> miette::Result<()> {
    let opts: disrobe_pass_js_deob::DeobOptions = disrobe_pass_js_deob::DeobOptions::all();
    let output: disrobe_pass_js_deob::DeobOutput =
        disrobe_pass_js_deob::deobfuscate_all(source_text, &opts);
    let (current, rename_stats, scope_rename_stats): (
        String,
        Option<disrobe_pass_js_deob::RenameStats>,
        Option<disrobe_pass_js_deob::ScopeAwareStats>,
    ) = apply_full_renames(output.source.clone(), rename, rename_scope_aware)?;

    let stem_owned: String = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("js-deob")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem_owned}.deobfuscated.js")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0045: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, current.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0046: cannot write deobfuscated source: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    crate::cli::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem_owned,
        "js-deob",
        "not implemented for the js pass in this build",
    )?;

    let pipeline_path: PathBuf = out_path.with_extension("pipeline.json");
    let pipeline_bytes: Vec<u8> = serde_json::to_vec_pretty(&output)
        .map_err(|e: serde_json::Error| miette::miette!("DR-CLI-0047: serialize pipeline: {e}"))?;
    std::fs::write(&pipeline_path, &pipeline_bytes)
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0048: cannot write pipeline: {e}"))?;

    println!("js deob (full pipeline): OK");
    println!("  family:                    {:?}", detection.family);
    println!(
        "  dispatcher calls inlined:  {}",
        output.dispatcher_calls_inlined
    );
    println!(
        "  calculator calls inlined:  {}",
        output.calculator_calls_inlined
    );
    println!("  rgf calls inlined:         {}", output.rgf_calls_inlined);
    println!(
        "  rgf eval wrappers inlined: {}",
        output.rgf_eval_wrappers_inlined
    );
    println!(
        "  rgf eval runtime walls:    {}",
        output.rgf_eval_runtime_walls
    );
    println!(
        "  opaque predicates folded:  {}",
        output.opaque_predicates_folded
    );
    println!(
        "  cf-flatten collapsed:      {}",
        output.flatten_dispatches_collapsed
    );
    println!(
        "  state-sum machines:        {}",
        output.state_sum_machines_linearized
    );
    println!(
        "  state-sum blocks:          {}",
        output.state_sum_blocks_recovered
    );
    println!(
        "  string literals decoded:   {}",
        output.string_literals_decoded
    );
    println!(
        "  string compression blocks: {}",
        output.string_compression_blocks_reversed
    );
    println!(
        "  string conceal call sites: {}",
        output.string_conceal_call_sites_decoded
    );
    println!(
        "  variable masks removed:    {}",
        output.variable_masking_proxies_eliminated
    );
    println!(
        "  packed blocks expanded:    {}",
        output.packed_blocks_expanded
    );
    println!(
        "  lock guards stripped:      {}",
        output.lock_guards_stripped
    );
    println!(
        "  integrity loops stripped:  {}",
        output.integrity_loops_stripped
    );
    println!(
        "  dead branches removed:     {}",
        output.dead_code_branches_removed
    );
    println!(
        "  integrity self-checks:     {}",
        output.integrity_self_checks_unwrapped
    );
    if let Some(stats) = &rename_stats {
        println!("  post-rename hex idents:    {}", stats.idents_renamed);
    }
    if let Some(stats) = &scope_rename_stats {
        println!("  scope-aware renamed:       {}", stats.idents_renamed);
    }
    println!(
        "  bytes:                     {} -> {}",
        source_text.len(),
        current.len()
    );
    println!("  wrote:                     {}", out_path.display());
    println!("  pipeline stats:            {}", pipeline_path.display());
    Ok(())
}

fn apply_legacy(
    source: &str,
    legacy: Option<LegacyFamily>,
) -> (
    String,
    Option<disrobe_pass_js_deob::JsObfuRewriteStats>,
    Option<disrobe_pass_js_deob::IntegrityStripStats>,
) {
    match legacy {
        None => (source.to_owned(), None, None),
        Some(LegacyFamily::Jsobfu) => {
            let (out, stats): (String, disrobe_pass_js_deob::JsObfuRewriteStats) =
                disrobe_pass_js_deob::rewrite_bracket_access(source);
            (out, Some(stats), None)
        }
        Some(LegacyFamily::JscramblerFree) => {
            let (out, stats): (String, disrobe_pass_js_deob::IntegrityStripStats) =
                disrobe_pass_js_deob::strip_integrity_loops(source);
            (out, None, Some(stats))
        }
        Some(LegacyFamily::Auto) => {
            let jsobfu_det: disrobe_pass_js_deob::JsObfuDetection =
                disrobe_pass_js_deob::detect_jsobfu(source);
            let jscrambler_det: disrobe_pass_js_deob::JscramblerDetection =
                disrobe_pass_js_deob::detect_free_tier(source);
            if jsobfu_det.matched && jsobfu_det.confidence >= jscrambler_det.confidence {
                let (out, stats): (String, disrobe_pass_js_deob::JsObfuRewriteStats) =
                    disrobe_pass_js_deob::rewrite_bracket_access(source);
                (out, Some(stats), None)
            } else if jscrambler_det.matched {
                let (out, stats): (String, disrobe_pass_js_deob::IntegrityStripStats) =
                    disrobe_pass_js_deob::strip_integrity_loops(source);
                (out, None, Some(stats))
            } else {
                (source.to_owned(), None, None)
            }
        }
    }
}

fn unbundle(
    input: PathBuf,
    out: Option<PathBuf>,
    target: UnbundleTarget,
    emit: Vec<String>,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0045: cannot read input: {e}"))?;
    let source_text: &str = std::str::from_utf8(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0046: input is not UTF-8: {e}"))?;
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("js unbundle: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  target:       {target:?}");
        return Ok(());
    }
    let out_root: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("js-unbundle");
        PathBuf::from(format!("./out/{stem}"))
    });
    if out_root.exists() && !g.force {
        let has_entries: bool =
            std::fs::read_dir(&out_root).is_ok_and(|mut it| it.next().is_some());
        if has_entries {
            return Err(miette::miette!(
                "DR-CLI-0032: out dir {} already exists; pass --force to overwrite",
                out_root.display()
            ));
        }
    }
    std::fs::create_dir_all(&out_root)
        .map_err(|e| miette::miette!("DR-CLI-0047: cannot create out dir: {e}"))?;

    let result: disrobe_pass_js_deob::UnbundleResult = match target {
        UnbundleTarget::Auto => disrobe_pass_js_deob::auto_unbundle(source_text)
            .map_err(|e| miette::miette!("DR-CLI-0048: auto-unbundle failed: {e}"))?,
        UnbundleTarget::Webpack | UnbundleTarget::Webpack4 => {
            disrobe_pass_js_deob::unbundle(disrobe_pass_js_deob::BundlerKind::Webpack4, source_text)
                .map_err(|e| miette::miette!("DR-CLI-0049: webpack4 unbundle failed: {e}"))?
        }
        UnbundleTarget::Webpack5 => {
            disrobe_pass_js_deob::unbundle(disrobe_pass_js_deob::BundlerKind::Webpack5, source_text)
                .map_err(|e| miette::miette!("DR-CLI-0050: webpack5 unbundle failed: {e}"))?
        }
        UnbundleTarget::Vite => {
            disrobe_pass_js_deob::unbundle(disrobe_pass_js_deob::BundlerKind::Vite, source_text)
                .map_err(|e| miette::miette!("DR-CLI-0051: vite unbundle failed: {e}"))?
        }
        UnbundleTarget::Rollup => {
            disrobe_pass_js_deob::unbundle(disrobe_pass_js_deob::BundlerKind::Rollup, source_text)
                .map_err(|e| miette::miette!("DR-CLI-0052: rollup unbundle failed: {e}"))?
        }
        UnbundleTarget::Esbuild => {
            disrobe_pass_js_deob::unbundle(disrobe_pass_js_deob::BundlerKind::Esbuild, source_text)
                .map_err(|e| miette::miette!("DR-CLI-0053: esbuild unbundle failed: {e}"))?
        }
        UnbundleTarget::Turbopack => disrobe_pass_js_deob::unbundle(
            disrobe_pass_js_deob::BundlerKind::Turbopack,
            source_text,
        )
        .map_err(|e| miette::miette!("DR-CLI-0054: turbopack unbundle failed: {e}"))?,
        UnbundleTarget::Bun => {
            disrobe_pass_js_deob::unbundle(disrobe_pass_js_deob::BundlerKind::Bun, source_text)
                .map_err(|e| miette::miette!("DR-CLI-0055: bun unbundle failed: {e}"))?
        }
    };

    let bar: progress_ui::ActiveProgress = progress_ui::make_progress("js unbundle");
    let total: u64 = u64::try_from(result.modules.len()).unwrap_or(u64::MAX);
    bar.set_total(total);
    bar.set_message("writing chunks");
    for _ in &result.modules {
        bar.tick();
    }
    bar.finish("done");
    let written: std::collections::BTreeMap<String, PathBuf> =
        disrobe_pass_js_deob::write_modules(&out_root, &result)
            .map_err(|e| miette::miette!("DR-CLI-0056: cannot write modules: {e}"))?;
    let manifest_path: PathBuf = out_root.join("manifest.json");
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&result)
        .map_err(|e: serde_json::Error| miette::miette!("DR-CLI-0057b: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, &manifest_bytes)
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0057: cannot write manifest: {e}"))?;

    let stem: String = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("js-unbundle")
        .to_owned();
    let sourcemaps: Option<SourcemapEmitSummary> =
        emit_sourcemaps_if_requested(&emit, source_text, result.kind, &out_root, &stem)?;

    println!("js unbundle: OK");
    println!("  bundler:      {}", result.kind.as_str());
    println!("  matched:      {}", result.detection.matched);
    println!("  confidence:   {:.2}", result.detection.confidence);
    println!("  markers:      {:?}", result.detection.markers);
    println!("  modules:      {}", result.modules.len());
    println!("  out dir:      {}", out_root.display());
    println!("  manifest:     {}", manifest_path.display());
    for (id, path) in &written {
        println!("    - {id}: {}", path.display());
    }
    if let Some(maps) = &sourcemaps {
        println!(
            "  sourcemaps:   {} synthesized, {} embedded -> {}",
            maps.synthesized,
            maps.embedded,
            maps.dir.display()
        );
        for (chunk, path) in &maps.written {
            println!("    - {chunk}: {}", path.display());
        }
    }
    Ok(())
}

#[derive(Debug)]
struct SourcemapEmitSummary {
    synthesized: usize,
    embedded: usize,
    dir: PathBuf,
    written: std::collections::BTreeMap<String, PathBuf>,
}

fn emit_sourcemaps_if_requested(
    emit: &[String],
    source_text: &str,
    kind: disrobe_pass_js_deob::BundlerKind,
    out_root: &std::path::Path,
    stem: &str,
) -> miette::Result<Option<SourcemapEmitSummary>> {
    let spec: crate::cli::emit::EmitSpec = crate::cli::emit::EmitSpec::parse(emit)?;
    if spec.is_empty() {
        return Ok(None);
    }
    let non_sourcemap: Vec<String> = spec
        .iter()
        .filter(|k: &crate::cli::emit::EmitKind| *k != crate::cli::emit::EmitKind::Sourcemap)
        .map(|k: crate::cli::emit::EmitKind| k.label().to_owned())
        .collect();
    crate::cli::emit::apply_not_applicable_stubs(
        &non_sourcemap,
        out_root,
        stem,
        "js-unbundle",
        "not implemented for the js unbundle pass in this build",
    )?;
    if !spec.contains(crate::cli::emit::EmitKind::Sourcemap) {
        return Ok(None);
    }
    let (_, emitted): (
        disrobe_pass_js_deob::UnbundleGraphResult,
        disrobe_pass_js_deob::SourceMapEmit,
    ) = disrobe_pass_js_deob::unbundle_with_sourcemaps(kind, source_text)
        .map_err(|e| miette::miette!("DR-CLI-0058: js --emit sourcemap synthesis failed: {e}"))?;
    let written: std::collections::BTreeMap<String, PathBuf> =
        disrobe_pass_js_deob::write_sourcemaps(out_root, &emitted)
            .map_err(|e| miette::miette!("DR-CLI-0059: cannot write js sourcemaps: {e}"))?;
    Ok(Some(SourcemapEmitSummary {
        synthesized: emitted.per_chunk.len(),
        embedded: emitted.embedded.len(),
        dir: out_root.join("sourcemaps"),
        written,
    }))
}
