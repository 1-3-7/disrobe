#![allow(clippy::needless_pass_by_value)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_as3::abc::MethodBody;
use disrobe_pass_as3::abc::{disasm as disasm_abc, parse as parse_abc};
use disrobe_pass_as3::decompile::render_program;
use disrobe_pass_as3::swf::{
    DoAbc, Swf, SwfTag, TagCode, parse as parse_swf, parse_do_abc, parse_do_abc_legacy,
};
use disrobe_pass_as3::{AbcFile, DisasmLine};

use super::util::push_format;

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
    let mut total_instructions: usize = 0;
    let mut total_methods: usize = 0;
    let mut total_classes: usize = 0;
    let mut source_files: usize = 0;
    let mut disasm_files: usize = 0;
    for (label, block) in &abc_blocks {
        let abc: AbcFile = parse_abc(&block.abc_bytes)
            .map_err(|e| miette::miette!("DR-CLI-0736: abc parse {label}: {e}"))?;
        let mut per_method: Vec<serde_json::Value> = Vec::with_capacity(abc.method_bodies.len());
        let mut flat_disasm: String = String::new();
        for (mi, body) in abc.method_bodies.iter().enumerate() {
            let lines: Vec<DisasmLine> = disasm_abc(&body.code)
                .map_err(|e| miette::miette!("DR-CLI-0737: abc disasm {label} m{mi}: {e}"))?;
            total_instructions += lines.len();
            append_method_disasm(&mut flat_disasm, mi, body, &lines);
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
        let block_bytes: Vec<u8> = serde_json::to_vec_pretty(&payload)
            .map_err(|e| miette::miette!("DR-CLI-0744: serialize {label}: {e}"))?;
        std::fs::write(&block_path, block_bytes)
            .map_err(|e| miette::miette!("DR-CLI-0738: cannot write {label}: {e}"))?;

        if !flat_disasm.is_empty() {
            let disasm_path: PathBuf = out_dir.join(format!("{label}.disasm.txt"));
            std::fs::write(&disasm_path, flat_disasm.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0746: cannot write {label} disasm: {e}"))?;
            disasm_files += 1;
        }

        if !abc.instances.is_empty() {
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
        "disasm_files": disasm_files,
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0745: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
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
    println!("  source files: {source_files}");
    println!("  disasm files: {disasm_files}");
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn append_method_disasm(
    out: &mut String,
    method_index: usize,
    body: &MethodBody,
    lines: &[DisasmLine],
) {
    push_format(
        out,
        format_args!(
            "; method {method_index}  max_stack={} locals={} code_len={}\n",
            body.max_stack,
            body.local_count,
            body.code.len()
        ),
    );
    for line in lines {
        let DisasmLine {
            offset,
            opcode,
            mnemonic,
            operands,
        }: &DisasmLine = line;
        if operands.is_empty() {
            push_format(
                out,
                format_args!("  {offset:08x}: {mnemonic:<20} ; op=0x{opcode:02x}\n"),
            );
        } else {
            let rendered: Vec<String> = operands.iter().map(|o: &i64| o.to_string()).collect();
            push_format(
                out,
                format_args!(
                    "  {offset:08x}: {mnemonic:<20} {} ; op=0x{opcode:02x}\n",
                    rendered.join(", ")
                ),
            );
        }
    }
    out.push('\n');
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
        }: &SwfTag = tag;
        println!(
            "    [offset=0x{offset:08x}] tag={} payload={} bytes",
            code.0,
            payload.len()
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn disasm_emits_real_as3_source_by_default() {
        let input: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("disrobe-pass-scriptlang")
            .join("tests")
            .join("fixtures")
            .join("haxe_main.swf");
        if !input.is_file() {
            return;
        }
        let out_dir: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("as3-disasm-test");
        let _ = std::fs::remove_dir_all(&out_dir);

        disasm(input, Some(out_dir.clone()), Vec::new()).expect("disasm ok");

        let source: PathBuf = std::fs::read_dir(&out_dir)
            .expect("read out dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p: &PathBuf| p.to_string_lossy().ends_with(".source.as3"))
            .expect("a .source.as3 file must be written by default");
        let text: String = std::fs::read_to_string(&source).expect("read as3 source");
        assert!(
            text.contains("class ") && text.contains("function "),
            "as3 source must contain real class/function declarations: {text}"
        );

        let disasm: PathBuf = std::fs::read_dir(&out_dir)
            .expect("read out dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p: &PathBuf| p.to_string_lossy().ends_with(".disasm.txt"))
            .expect("a .disasm.txt file must be written next to the json");
        let listing: String = std::fs::read_to_string(&disasm).expect("read as3 disasm");
        assert!(
            listing.contains("; method 0") && listing.contains("op=0x"),
            "flat disasm must contain per-method instruction lines: {listing}"
        );

        let _ = std::fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn disasm_flat_text_lands_for_synthetic_block() {
        let out_dir: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("as3-disasm-flat-test");
        let _ = std::fs::remove_dir_all(&out_dir);
        let swf_path: PathBuf = out_dir.join("synthetic.swf");
        std::fs::create_dir_all(&out_dir).expect("mk out dir");
        std::fs::write(&swf_path, super::tests_support::build_swf()).expect("write swf");

        disasm(swf_path, Some(out_dir.clone()), Vec::new()).expect("disasm ok");

        let disasm_path: PathBuf = std::fs::read_dir(&out_dir)
            .expect("read out dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p: &PathBuf| p.to_string_lossy().ends_with(".disasm.txt"))
            .expect("a .disasm.txt must be emitted for the synthetic abc block");
        let listing: String = std::fs::read_to_string(&disasm_path).expect("read disasm");
        assert!(
            !listing.trim().is_empty() && listing.contains("op=0x"),
            "synthetic block disasm must contain real instruction lines: {listing}"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests_support {
    fn u30(mut value: u32, out: &mut Vec<u8>) {
        loop {
            let mut byte: u8 = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn emit_method_info(b: &mut Vec<u8>) {
        u30(0, b);
        u30(0, b);
        u30(0, b);
        b.push(0x00);
    }

    fn build_abc() -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&16u16.to_le_bytes());
        b.extend_from_slice(&46u16.to_le_bytes());
        u30(1, &mut b);
        u30(1, &mut b);
        u30(1, &mut b);
        let strings: [&str; 6] = ["", "Greeter", "Object", "trace", "greet", "hi"];
        u30(strings.len() as u32, &mut b);
        for s in &strings[1..] {
            u30(s.len() as u32, &mut b);
            b.extend_from_slice(s.as_bytes());
        }
        u30(2, &mut b);
        b.push(0x16);
        u30(0, &mut b);
        u30(1, &mut b);
        u30(5, &mut b);
        for name in [1u32, 2, 3, 4] {
            b.push(0x07);
            u30(1, &mut b);
            u30(name, &mut b);
        }
        u30(2, &mut b);
        emit_method_info(&mut b);
        emit_method_info(&mut b);
        u30(0, &mut b);
        u30(1, &mut b);
        u30(1, &mut b);
        u30(2, &mut b);
        b.push(0x00);
        u30(0, &mut b);
        u30(0, &mut b);
        u30(1, &mut b);
        u30(4, &mut b);
        b.push(0x01);
        u30(0, &mut b);
        u30(1, &mut b);
        u30(0, &mut b);
        u30(0, &mut b);
        u30(1, &mut b);
        u30(0, &mut b);
        u30(0, &mut b);
        let mut code: Vec<u8> = Vec::new();
        code.push(0xD0);
        code.push(0x30);
        code.push(0x5D);
        u30(3, &mut code);
        code.push(0x2C);
        u30(5, &mut code);
        code.push(0x4F);
        u30(3, &mut code);
        u30(1, &mut code);
        code.push(0x47);
        u30(1, &mut b);
        u30(1, &mut b);
        u30(2, &mut b);
        u30(1, &mut b);
        u30(1, &mut b);
        u30(2, &mut b);
        u30(code.len() as u32, &mut b);
        b.extend_from_slice(&code);
        u30(0, &mut b);
        u30(0, &mut b);
        b
    }

    fn pack_tag(code: u16, payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        if payload.len() < 0x3F {
            let header: u16 = (code << 6) | (payload.len() as u16 & 0x3F);
            out.extend_from_slice(&header.to_le_bytes());
        } else {
            let header: u16 = (code << 6) | 0x3F;
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    pub(super) fn build_swf() -> Vec<u8> {
        let abc: Vec<u8> = build_abc();
        let mut do_abc_payload: Vec<u8> = Vec::new();
        do_abc_payload.extend_from_slice(&0u32.to_le_bytes());
        do_abc_payload.extend_from_slice(b"Script");
        do_abc_payload.push(0);
        do_abc_payload.extend_from_slice(&abc);
        let mut body: Vec<u8> = Vec::new();
        body.push(0x00);
        body.extend_from_slice(&24u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&pack_tag(82, &do_abc_payload));
        body.extend_from_slice(&pack_tag(0, &[]));
        let mut swf: Vec<u8> = Vec::new();
        swf.extend_from_slice(b"FWS");
        swf.push(10);
        let file_length: u32 = (8 + body.len()) as u32;
        swf.extend_from_slice(&file_length.to_le_bytes());
        swf.extend_from_slice(&body);
        swf
    }
}
