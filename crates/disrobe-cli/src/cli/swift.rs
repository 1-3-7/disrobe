#![allow(clippy::needless_pass_by_value)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_swift_objc::{
    MachoKind, ParsedSlice, SwiftClassDump, SwiftShieldUndoMap, XorBlobDecodeResult, detect_magic,
    parse_slice, swift_class_dump, swiftshield_undo_from_dsym_text, xor_decode_printable_strings,
};

use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum SwiftCmd {
    #[command(
        about = "Swift / ObjC class-dump from a Mach-O / .ipa (best-effort, single slice; use `disrobe macho classdump` for fat binaries)"
    )]
    Classdump {
        #[arg(help = "input Mach-O / .ipa")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the dump JSON (default: ./out/<stem>-swift.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "reverse a SwiftShield obfuscation map from a .dSYM symbol-mapping text file"
    )]
    ShieldUndo {
        #[arg(help = "input .dSYM mapping text (one `obf ==> original` pair per line)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the undo map JSON (default: ./out/<stem>-swiftshield.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(about = "decode printable strings from a single-byte XOR blob with an explicit key")]
    XorDecrypt {
        #[arg(help = "input XOR-encrypted blob")]
        input: PathBuf,
        #[arg(
            long,
            value_parser = crate::parse_u8_auto,
            help = "required single-byte XOR key (decimal or 0xHH)"
        )]
        key: u8,
        #[arg(
            short,
            long,
            help = "output path for the decoded strings JSON (default: ./out/<stem>-xor.json)"
        )]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: SwiftCmd) -> miette::Result<()> {
    match action {
        SwiftCmd::Classdump { input, out } => classdump(input, out),
        SwiftCmd::ShieldUndo { input, out } => shield_undo(input, out),
        SwiftCmd::XorDecrypt { input, key, out } => xor_decrypt(input, key, out),
    }
}

fn classdump(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0700: cannot read input: {e}"))?;
    let kind: MachoKind = detect_magic(&bytes)
        .ok_or_else(|| miette::miette!("DR-CLI-0701: input is not a Mach-O binary"))?;
    if matches!(kind, MachoKind::Fat32 | MachoKind::Fat64) {
        return Err(miette::miette!(
            "DR-CLI-0702: input is a fat Mach-O; use `disrobe macho classdump` for fat binaries"
        ));
    }
    let parsed: ParsedSlice =
        parse_slice(&bytes).map_err(|e| miette::miette!("DR-CLI-0703: parse slice: {e}"))?;
    let dump: SwiftClassDump = swift_class_dump(&bytes, &parsed);
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("swift-classdump")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-swift.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0704: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&dump)
        .map_err(|e| miette::miette!("DR-CLI-0705: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0706: cannot write output: {e}"))?;
    let swift_source: String = render_swift_source(&dump);
    let source_path: PathBuf = out_path.with_extension("swift");
    if !swift_source.is_empty() {
        std::fs::write(&source_path, swift_source.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0707: cannot write swift source: {e}"))?;
    }
    println!("swift classdump: OK");
    println!("  input:        {}", input.display());
    println!(
        "  cpu/bits:     {} / {:?}",
        parsed.header.cpu.label(),
        parsed.header.bitness
    );
    println!(
        "  swift types:  {}",
        dump.types_section.as_ref().map_or(0, |s| s.pointer_count)
    );
    println!("  reflected:    {}", dump.reflected_types.len());
    println!("  mangled syms: {}", dump.mangled_symbols.len());
    println!("  demangled:    {}", dump.demangled.len());
    if swift_source.is_empty() {
        println!("  swift source: none (no reflection metadata recovered)");
    } else {
        println!("  swift source: {}", source_path.display());
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn render_swift_source(dump: &SwiftClassDump) -> String {
    if !dump.type_dump.is_empty() {
        let mut out: String =
            String::from("// disrobe swift class-dump (recovered reflection metadata)\n\n");
        out.push_str(&dump.type_dump.render());
        return out;
    }
    if dump.reflected_types.is_empty() {
        return String::new();
    }
    let mut out: String =
        String::from("// disrobe swift class-dump (recovered reflection metadata)\n\n");
    for ty in &dump.reflected_types {
        out.push_str(&ty.render());
        out.push('\n');
    }
    out
}

fn shield_undo(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let text: String = std::fs::read_to_string(&input)
        .map_err(|e| miette::miette!("DR-CLI-0710: cannot read input: {e}"))?;
    let map: SwiftShieldUndoMap = swiftshield_undo_from_dsym_text(&text);
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("swiftshield")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-swiftshield.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0711: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&map)
        .map_err(|e| miette::miette!("DR-CLI-0712: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0713: cannot write output: {e}"))?;
    println!("swift shield-undo: OK");
    println!("  input:        {}", input.display());
    println!("  mappings:     {}", map.mappings.len());
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn xor_decrypt(input: PathBuf, key: u8, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0720: cannot read input: {e}"))?;
    let g: globals::Globals = globals::current();
    let result: XorBlobDecodeResult = xor_decode_printable_strings(&bytes, key);
    if g.dry_run {
        println!("swift xor-decrypt: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  key:          0x{key:02x}");
        return Ok(());
    }
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("swift-xor")
        .to_owned();
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-xor.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0721: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&result)
        .map_err(|e| miette::miette!("DR-CLI-0722: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0723: cannot write output: {e}"))?;
    println!("swift xor-decrypt: OK");
    println!("  input:        {}", input.display());
    println!("  key:          0x{key:02x}");
    println!("  recovered:    {} string(s)", result.recovered.len());
    println!("  scanned:      {} bytes", result.bytes_scanned);
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn classdump_writes_real_swift_source() {
        let input: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("mobile")
            .join("macho-mac")
            .join("SwiftHello.original");
        if !input.is_file() {
            return;
        }
        let out_dir: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("swift-classdump-test");
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir).expect("mk out dir");
        let out_path: PathBuf = out_dir.join("hello.json");

        classdump(input, Some(out_path.clone())).expect("classdump ok");

        let source_path: PathBuf = out_path.with_extension("swift");
        let text: String = std::fs::read_to_string(&source_path).expect("read swift source");
        assert!(
            text.contains("class ")
                || text.contains("struct ")
                || text.contains("enum ")
                || text.contains("protocol "),
            "swift source must contain recovered type declarations: {text}"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
}
