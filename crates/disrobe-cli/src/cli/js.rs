#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use disrobe_core::progress::Progress as _;

use super::globals;
use super::progress_ui;

#[derive(Subcommand, Debug)]
pub(crate) enum JsCmd {
    #[command(
        about = "inspect a V8 cached-data (.jsc), Node SEA blob, nexe-built exe, nw.js zip suffix, or Electron .asar; prints REAL detection + honest snapshot-deserialize wall"
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
        input: PathBuf,
        #[arg(short, long, help = "output path for the deobfuscated source")]
        out: Option<PathBuf>,
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
            scrape_min,
        } => v8_inspect(input, json_out, scrape_min),
        JsCmd::Deob {
            input,
            out,
            unminify,
            rename,
            rename_scope_aware,
            legacy,
            full,
        } => deob(
            input,
            out,
            unminify,
            rename,
            rename_scope_aware,
            legacy,
            full,
        ),
        JsCmd::Unbundle { input, out, target } => unbundle(input, out, target),
    }
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

fn v8_inspect(input: PathBuf, json_out: Option<PathBuf>, scrape_min: usize) -> miette::Result<()> {
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
            ..
        } => {
            println!("v8 bytenode (.jsc / V8 SerializedCodeData):");
            println!("  magic:             {magic}");
            println!("  node version:      {}", node_version.label());
            println!("  header layout:     {header_layout:?}");
            println!("  header size:       {header_size} bytes");
            println!("  payload offset:    {payload_offset}");
            println!("  payload length:    {payload_length} bytes");
            match snapshot_status {
                disrobe_pass_js_deob::v8::SnapshotDeserializeStatus::SnapshotDeserializeWall {
                    v8_version_label,
                    reason,
                    ..
                } => {
                    println!("  snapshot status:   SnapshotDeserializeWall ({v8_version_label})");
                    println!("    reason: {reason}");
                }
                disrobe_pass_js_deob::v8::SnapshotDeserializeStatus::UnknownV8Marker {
                    magic_low,
                } => {
                    println!("  snapshot status:   UnknownV8Marker (low16=0x{magic_low:04X})");
                }
            }
            println!("  scraped strings:   {} unique", scraped_strings.len());
            for s in scraped_strings.iter().take(20usize) {
                println!("    - {s:?}");
            }
            if scraped_strings.len() > 20usize {
                println!("    ... ({} more)", scraped_strings.len() - 20usize);
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

fn classify_v8_artifact(input: &std::path::Path, bytes: &[u8], scrape_min: usize) -> V8Report {
    let path_str: String = input.display().to_string();
    if let Ok(body) = disrobe_pass_js_deob::v8::parse_bytenode_full(bytes) {
        let status: disrobe_pass_js_deob::v8::SnapshotDeserializeStatus =
            disrobe_pass_js_deob::v8::snapshot_deserialize_status(&body.header);
        let scraped: disrobe_pass_js_deob::v8::ScrapedConstantPool =
            disrobe_pass_js_deob::v8::scrape_payload_strings(&body.payload, scrape_min);
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

#[allow(clippy::fn_params_excessive_bools)]
fn deob(
    input: PathBuf,
    out: Option<PathBuf>,
    unminify: bool,
    rename: bool,
    rename_scope_aware: bool,
    legacy: Option<LegacyFamily>,
    full: bool,
) -> miette::Result<()> {
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
        );
    }

    let recovery: Option<disrobe_pass_js_deob::StringArrayRecovery> =
        disrobe_pass_js_deob::recover_string_array(source_text)
            .map_err(|e| miette::miette!("{e}"))?;

    let out_path: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("js-deob");
        PathBuf::from(format!("./out/{stem}.deobfuscated.js"))
    });
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

    let (after_unminify, unminify_stats): (String, Option<disrobe_pass_js_deob::UnminifyStats>) =
        if unminify {
            let (out, stats): (String, disrobe_pass_js_deob::UnminifyStats) =
                disrobe_pass_js_deob::unminify(&after_legacy);
            (out, Some(stats))
        } else {
            (after_legacy, None)
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
            "    cf-flatten blocks:     {}",
            stats.control_flow_blocks_unflattened
        );
        println!(
            "    cf-flatten cases:      {}",
            stats.control_flow_cases_inlined
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
) -> miette::Result<()> {
    let opts: disrobe_pass_js_deob::ObfuscatorIoOptions =
        disrobe_pass_js_deob::ObfuscatorIoOptions::all();
    let output: disrobe_pass_js_deob::ObfuscatorIoOutput =
        disrobe_pass_js_deob::obfuscator_io_deobfuscate(source_text, &opts)
            .map_err(|e| miette::miette!("{e}"))?;

    let mut current: String = output.source.clone();
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

    let out_path: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("js-deob");
        PathBuf::from(format!("./out/{stem}.deobfuscated.js"))
    });
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0045: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, current.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0046: cannot write deobfuscated source: {e}"))?;

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

fn unbundle(input: PathBuf, out: Option<PathBuf>, target: UnbundleTarget) -> miette::Result<()> {
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
    Ok(())
}
