#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use disrobe_core::progress::Progress as _;

use super::globals;
use super::progress_ui;

#[derive(Subcommand, Debug)]
pub(crate) enum JsCmd {
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
        JsCmd::Deob {
            input,
            out,
            unminify,
            rename,
            rename_scope_aware,
            legacy,
        } => deob(input, out, unminify, rename, rename_scope_aware, legacy),
        JsCmd::Unbundle { input, out, target } => unbundle(input, out, target),
    }
}

fn deob(
    input: PathBuf,
    out: Option<PathBuf>,
    unminify: bool,
    rename: bool,
    rename_scope_aware: bool,
    legacy: Option<LegacyFamily>,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0037: cannot read input: {e}"))?;
    let detection: disrobe_pass_js_deob::Detection = disrobe_pass_js_deob::detect(&bytes);
    let source_text: &str = std::str::from_utf8(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0042: input is not UTF-8: {e}"))?;
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
