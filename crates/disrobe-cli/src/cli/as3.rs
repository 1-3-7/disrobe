#![allow(clippy::needless_pass_by_value)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_as3::abc::{disasm as disasm_abc, parse as parse_abc};
use disrobe_pass_as3::decompile::render_program;
use disrobe_pass_as3::swf::{
    DoAbc, Swf, SwfTag, TagCode, parse as parse_swf, parse_do_abc, parse_do_abc_legacy,
};
use disrobe_pass_as3::{AbcFile, DisasmLine};

#[derive(Subcommand, Debug)]
pub(crate) enum As3Cmd {
    #[command(about = "disassemble every DoABC tag in a .swf into per-instruction AS3 bytecode")]
    Disasm {
        #[arg(help = "input .swf file")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-as3-disasm)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "list every tag in a .swf (TagCode, offset, payload size)")]
    Tags {
        #[arg(help = "input .swf file")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: As3Cmd) -> miette::Result<()> {
    match action {
        As3Cmd::Disasm { input, out, emit } => disasm(input, out, emit),
        As3Cmd::Tags { input } => tags(input),
    }
}

fn disasm(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0730: cannot read input: {e}"))?;
    let swf: Swf = parse_swf(&bytes).map_err(|e| miette::miette!("DR-CLI-0731: swf parse: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("as3-disasm")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-as3-disasm")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0732: cannot create out dir: {e}"))?;
    let mut abc_blocks: Vec<(String, DoAbc)> = Vec::new();
    for (idx, tag) in swf.tags.iter().enumerate() {
        if tag.code == TagCode::DO_ABC {
            let block: DoAbc =
                parse_do_abc(tag).map_err(|e| miette::miette!("DR-CLI-0733: doabc parse: {e}"))?;
            abc_blocks.push((format!("doabc-{idx:03}"), block));
        } else if tag.code == TagCode::DO_ABC_DEFINE {
            let block: DoAbc = parse_do_abc_legacy(tag)
                .map_err(|e| miette::miette!("DR-CLI-0734: doabcdefine parse: {e}"))?;
            abc_blocks.push((format!("doabcdefine-{idx:03}"), block));
        }
    }
    if abc_blocks.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0735: .swf has no DoABC / DoABCDefine tags (no AS3 to disassemble)"
        ));
    }
    let emit_source: bool = emit
        .iter()
        .flat_map(|raw: &String| raw.split(','))
        .any(|piece: &str| piece.trim().eq_ignore_ascii_case("source"));
    let mut total_instructions: usize = 0;
    let mut total_methods: usize = 0;
    let mut total_classes: usize = 0;
    let mut source_files: usize = 0;
    for (label, block) in &abc_blocks {
        let abc: AbcFile = parse_abc(&block.abc_bytes)
            .map_err(|e| miette::miette!("DR-CLI-0736: abc parse {label}: {e}"))?;
        let mut per_method: Vec<serde_json::Value> = Vec::with_capacity(abc.method_bodies.len());
        for (mi, body) in abc.method_bodies.iter().enumerate() {
            let lines: Vec<DisasmLine> = disasm_abc(&body.code)
                .map_err(|e| miette::miette!("DR-CLI-0737: abc disasm {label} m{mi}: {e}"))?;
            total_instructions += lines.len();
            per_method.push(serde_json::json!({
                "method_index": mi,
                "max_stack": body.max_stack,
                "local_count": body.local_count,
                "code_len": body.code.len(),
                "lines": lines,
            }));
        }
        total_methods += abc.method_bodies.len();
        total_classes += abc.instances.len();
        let block_path: PathBuf = out_dir.join(format!("{label}.json"));
        let payload: serde_json::Value = serde_json::json!({
            "schema": "disrobe.as3.disasm/v0",
            "abc_name": block.name,
            "abc_flags": block.flags,
            "method_count": abc.methods.len(),
            "instance_count": abc.instances.len(),
            "method_bodies": per_method,
        });
        std::fs::write(
            &block_path,
            serde_json::to_vec_pretty(&payload).unwrap_or_default(),
        )
        .map_err(|e| miette::miette!("DR-CLI-0738: cannot write {label}: {e}"))?;

        if emit_source && !abc.instances.is_empty() {
            let source: String = render_program(&abc)
                .map_err(|e| miette::miette!("DR-CLI-0742: as3 decompile {label}: {e}"))?;
            let source_path: PathBuf = out_dir.join(format!("{label}.source.as3"));
            std::fs::write(&source_path, source.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0743: cannot write {label} source: {e}"))?;
            source_files += 1;
        }
    }
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.as3.disasm/v0",
        "input": input.display().to_string(),
        "swf_version": swf.header.version,
        "compression": format!("{:?}", swf.header.compression),
        "abc_blocks": abc_blocks.len(),
        "classes": total_classes,
        "methods": total_methods,
        "instructions": total_instructions,
        "source_files": source_files,
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0739: cannot write manifest: {e}"))?;
    let stub_kinds: Vec<String> = emit
        .iter()
        .flat_map(|raw: &String| raw.split(','))
        .map(|piece: &str| piece.trim().to_owned())
        .filter(|piece: &String| !piece.is_empty() && !piece.eq_ignore_ascii_case("source"))
        .collect();
    crate::cli::emit::apply_not_applicable_stubs(
        &stub_kinds,
        &out_dir,
        &stem,
        "as3-disasm",
        "not implemented for the as3 pass in this build",
    )?;
    println!("as3 disasm: OK");
    println!("  input:        {}", input.display());
    println!("  swf version:  {}", swf.header.version);
    println!("  abc blocks:   {}", abc_blocks.len());
    println!("  classes:      {total_classes}");
    println!("  methods:      {total_methods}");
    println!("  instructions: {total_instructions}");
    if emit_source {
        println!("  source files: {source_files}");
    }
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn tags(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0740: cannot read input: {e}"))?;
    let swf: Swf = parse_swf(&bytes).map_err(|e| miette::miette!("DR-CLI-0741: swf parse: {e}"))?;
    println!("as3 tags: OK");
    println!("  input:        {}", input.display());
    println!("  swf version:  {}", swf.header.version);
    println!("  compression:  {:?}", swf.header.compression);
    println!("  tag count:    {}", swf.tags.len());
    for tag in &swf.tags {
        let SwfTag {
            code,
            offset,
            payload,
        } = tag;
        println!(
            "    [offset=0x{offset:08x}] tag={} payload={} bytes",
            code.0,
            payload.len()
        );
    }
    Ok(())
}
