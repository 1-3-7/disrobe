#![allow(clippy::needless_pass_by_value)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_go::{
    EmbedFile, GoAnalysis, GoBuildInfo, GoFunc, GoModule, analyze as analyze_go,
};

const RECOVERED_NAME_PREVIEW: usize = 40;
const RECOVERED_STRING_PREVIEW: usize = 40;
const EMBED_FILE_PREVIEW: usize = 40;

#[derive(Subcommand, Debug)]
pub(crate) enum GoCmd {
    #[command(
        about = "recover symbols, pclntab, moduledata, garble obfuscation report, & embed.FS contents from a Go PE / ELF / Mach-O"
    )]
    Recover {
        #[arg(help = "input Go binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the analysis JSON (default: ./out/<stem>-go.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "report Go build version, pclntab version, & stripped/garble fingerprint")]
    Info {
        #[arg(help = "input Go binary")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: GoCmd) -> miette::Result<()> {
    match action {
        GoCmd::Recover { input, out, emit } => recover(input, out, emit),
        GoCmd::Info { input } => info(input),
    }
}

fn recover(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0650: cannot read input: {e}"))?;
    let analysis: GoAnalysis =
        analyze_go(&bytes).map_err(|e| miette::miette!("DR-CLI-0651: go analyze: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("go-recover")
        .to_owned();
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-go.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0652: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&analysis)
        .map_err(|e| miette::miette!("DR-CLI-0653: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0654: cannot write output: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    crate::cli::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem,
        "go-recover",
        "not implemented for the go pass in this build",
    )?;
    let carved: Vec<PathBuf> = carve_embed_files(&analysis, stub_dir, &stem)?;
    println!("go recover: OK");
    println!("  input:        {}", input.display());
    println!("  image kind:   {}", analysis.image_kind);
    println!("  ptr size:     {}", analysis.ptr_size);
    println!("  pclntab ver:  {}", analysis.pclntab_version);
    if let Some(v) = analysis.buildversion.as_ref() {
        println!("  buildversion: {v}");
    }
    println!("  funcs:        {}", analysis.symbols.funcs.len());
    println!("  packages:     {}", analysis.symbols.package_set.len());
    println!("  garble:       {:?}", analysis.garble.quality);
    println!(
        "  embed.FS:     used={} directives={}",
        analysis.embed.uses_embed_fs,
        analysis.embed.directives.len()
    );
    render_build_info(analysis.moduledata.build_info.as_ref());
    render_recovered(&analysis);
    if !carved.is_empty() {
        println!("  carved {} embed.FS file(s):", carved.len());
        for path in &carved {
            println!("    {}", path.display());
        }
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn carve_embed_files(
    analysis: &GoAnalysis,
    out_dir: &std::path::Path,
    stem: &str,
) -> miette::Result<Vec<PathBuf>> {
    let carvable: bool = analysis
        .embed
        .files
        .iter()
        .any(|f: &EmbedFile| !f.is_dir && f.data.len() as u64 == f.size);
    if !carvable {
        return Ok(Vec::new());
    }
    let root: PathBuf = out_dir.join(format!("{stem}-embed"));
    let mut written: Vec<PathBuf> = Vec::new();
    for file in &analysis.embed.files {
        if file.is_dir || file.data.len() as u64 != file.size {
            continue;
        }
        let Some(dest): Option<PathBuf> = safe_join_relpath(&root, &file.name) else {
            return Err(miette::miette!(
                "DR-CLI-0655: refusing unsafe embed path '{}' (traversal)",
                file.name
            ));
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0656: cannot create embed dir: {e}"))?;
        }
        std::fs::write(&dest, &file.data)
            .map_err(|e| miette::miette!("DR-CLI-0657: cannot write {}: {e}", dest.display()))?;
        written.push(dest);
    }
    Ok(written)
}

fn safe_join_relpath(root: &std::path::Path, name: &str) -> Option<PathBuf> {
    let mut result: PathBuf = root.to_path_buf();
    let mut components: usize = 0usize;
    for raw in name.split(['/', '\\']) {
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

fn render_recovered(analysis: &GoAnalysis) {
    render_recovered_symbols(&analysis.symbols.funcs);
    render_recovered_packages(&analysis.symbols.package_set);
    render_recovered_strings(&analysis.garble.recovered_strings);
    render_surviving_stdlib(&analysis.garble.surviving_stdlib_names);
    render_embed_files(&analysis.embed.files);
}

fn render_recovered_symbols(funcs: &[GoFunc]) {
    if funcs.is_empty() {
        return;
    }
    let shown: usize = funcs.len().min(RECOVERED_NAME_PREVIEW);
    println!("  recovered funcs:");
    for f in &funcs[..shown] {
        println!("    {:#018x}  {}", f.entry, f.name);
    }
    if funcs.len() > shown {
        println!(
            "    ... {} more (see the analysis JSON)",
            funcs.len() - shown
        );
    }
}

fn render_recovered_packages(packages: &[String]) {
    if packages.is_empty() {
        return;
    }
    let shown: usize = packages.len().min(RECOVERED_NAME_PREVIEW);
    println!("  packages:");
    for p in &packages[..shown] {
        println!("    {p}");
    }
    if packages.len() > shown {
        println!(
            "    ... {} more (see the analysis JSON)",
            packages.len() - shown
        );
    }
}

fn render_recovered_strings(strings: &[String]) {
    if strings.is_empty() {
        return;
    }
    let shown: usize = strings.len().min(RECOVERED_STRING_PREVIEW);
    println!("  garble strings recovered: {}", strings.len());
    for s in &strings[..shown] {
        println!("    {s:?}");
    }
    if strings.len() > shown {
        println!(
            "    ... {} more (see the analysis JSON)",
            strings.len() - shown
        );
    }
}

fn render_surviving_stdlib(names: &std::collections::BTreeSet<String>) {
    if names.is_empty() {
        return;
    }
    println!("  surviving stdlib symbols: {}", names.len());
    for n in names {
        println!("    {n}");
    }
}

fn render_embed_files(files: &[EmbedFile]) {
    if files.is_empty() {
        return;
    }
    let shown: usize = files.len().min(EMBED_FILE_PREVIEW);
    println!("  embed.FS files: {}", files.len());
    for f in &files[..shown] {
        let kind: &str = if f.is_dir { "dir " } else { "file" };
        let integrity: &str = if f.is_dir {
            ""
        } else if f.digest_verified {
            " digest verified"
        } else {
            " digest unverified"
        };
        println!("    [{kind}] {} ({} bytes){integrity}", f.name, f.size);
    }
    if files.len() > shown {
        println!(
            "    ... {} more (see the analysis JSON)",
            files.len() - shown
        );
    }
}

fn info(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0660: cannot read input: {e}"))?;
    let analysis: GoAnalysis =
        analyze_go(&bytes).map_err(|e| miette::miette!("DR-CLI-0661: go analyze: {e}"))?;
    println!("go info: OK");
    println!("  input:        {}", input.display());
    println!("  image kind:   {}", analysis.image_kind);
    println!("  ptr size:     {}", analysis.ptr_size);
    println!("  pclntab ver:  {}", analysis.pclntab_version);
    if let Some(v) = analysis.buildversion.as_ref() {
        println!("  buildversion: {v}");
    }
    println!("  garble:       {:?}", analysis.garble.quality);
    println!(
        "  stripped:     stripped={} recovered_funcs={} stdlib_ratio={:.2}",
        analysis.stripped.stripped,
        analysis.stripped.recovered_funcs,
        analysis.stripped.stdlib_ratio
    );
    render_build_info(analysis.moduledata.build_info.as_ref());
    Ok(())
}

fn render_build_info(build_info: Option<&GoBuildInfo>) {
    let Some(bi) = build_info else {
        println!("  build info:   (no embedded runtime/debug.BuildInfo block)");
        return;
    };
    println!("  build info (runtime/debug.BuildInfo):");
    if let Some(v) = bi.go_version.as_deref() {
        println!("    go version: {v}");
    }
    if let Some(p) = bi.path.as_deref() {
        println!("    path:       {p}");
    }
    if let Some(main) = bi.main.as_ref() {
        println!("    main:       {}", format_go_module(main));
    }
    if bi.deps.is_empty() {
        println!("    deps:       (none)");
    } else {
        println!("    deps:       {}", bi.deps.len());
        for dep in &bi.deps {
            println!("      {}", format_go_module(dep));
            if let Some(replacement) = dep.replace.as_deref() {
                println!("        => {}", format_go_module(replacement));
            }
        }
    }
    if bi.settings.is_empty() {
        println!("    settings:   (none)");
    } else {
        println!("    settings:");
        for (k, v) in &bi.settings {
            println!("      {k}={v}");
        }
    }
}

fn format_go_module(module: &GoModule) -> String {
    let mut line: String = module.path.clone();
    if !module.version.is_empty() {
        line.push(' ');
        line.push_str(&module.version);
    }
    if !module.sum.is_empty() {
        line.push(' ');
        line.push_str(&module.sum);
    }
    line
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn hello_embed_fixture() -> Option<PathBuf> {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("disrobe-pass-go")
            .join("tests")
            .join("fixtures")
            .join("hello_embed.exe");
        if path.is_file() { Some(path) } else { None }
    }

    #[test]
    fn recover_carves_embed_files_with_full_bytes() {
        let Some(input): Option<PathBuf> = hello_embed_fixture() else {
            return;
        };
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("go-embed-carve-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let out_json: PathBuf = scratch.join("hello_embed-go.json");

        recover(input, Some(out_json), Vec::new()).expect("recover ok");

        let note: PathBuf = scratch
            .join("hello_embed-embed")
            .join("assets")
            .join("note.txt");
        assert!(
            note.is_file(),
            "embed.FS member must be carved to disk with its real path"
        );
        let carved: Vec<u8> = std::fs::read(&note).expect("read carved note");
        assert_eq!(
            carved, b"disrobe embed fixture payload alpha\n",
            "carved member must be the full byte-exact content, not a 64-byte preview"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
