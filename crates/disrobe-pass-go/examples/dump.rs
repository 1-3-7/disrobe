use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, analyze};

fn dump(name: &str) {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    let bytes: Vec<u8> = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) => {
            println!("{name}: MISSING ({e})");
            return;
        }
    };
    let a: GoAnalysis = match analyze(&bytes) {
        Ok(a) => a,
        Err(e) => {
            println!("{name}: ERR {e}");
            return;
        }
    };
    println!("=== {name} ({} bytes) ===", bytes.len());
    println!("  image_kind={} ptr_size={}", a.image_kind, a.ptr_size);
    println!("  pclntab_version={}", a.pclntab_version);
    println!("  buildversion={:?}", a.buildversion);
    println!("  funcs={}", a.symbols.funcs.len());
    println!("  source_files={}", a.symbols.source_files.len());
    println!("  packages={}", a.symbols.package_set.len());
    println!(
        "  moduledata.via={:?} types_va={:#x} typelinks_va={:#x} len={} itablinks_va={:#x} len={}",
        a.moduledata.via,
        a.moduledata.types_va,
        a.moduledata.typelinks_va,
        a.moduledata.typelinks_len,
        a.moduledata.itablinks_va,
        a.moduledata.itablinks_len
    );
    println!(
        "  typemeta types={} itabs={} strings={}",
        a.typemeta.types.len(),
        a.typemeta.itabs.len(),
        a.typemeta.strings.len()
    );
    let named: usize = a.typemeta.types.iter().filter(|t| t.name.is_some()).count();
    println!("  typemeta named_types={named}");
    for t in a.typemeta.types.iter().take(12) {
        println!(
            "    type va={:#x} kind={:?} name={:?}",
            t.va, t.kind, t.name
        );
    }
    let main_like: Vec<&str> = a
        .typemeta
        .types
        .iter()
        .filter_map(|t| t.name.as_deref())
        .filter(|n| n.contains("main.") || n.contains("buildInfo"))
        .collect();
    println!(
        "  main-related type names ({}): {:?}",
        main_like.len(),
        main_like
    );
    let categories: [(&str, &str); 5] = [
        ("runtime.", "runtime"),
        ("sync.", "sync"),
        ("embed.", "embed"),
        ("reflect.", "reflect"),
        ("internal/", "internal/*"),
    ];
    for (needle, label) in categories {
        let n: usize = a
            .typemeta
            .types
            .iter()
            .filter_map(|t| t.name.as_deref())
            .filter(|s| s.contains(needle))
            .count();
        println!("  type names containing '{label}' = {n}");
    }
    for (i, t) in a.typemeta.itabs.iter().enumerate().take(8) {
        println!(
            "    itab[{}] va={:#x} interface={:?} concrete={:?}",
            i, t.va, t.interface_name, t.concrete_name
        );
    }
    println!(
        "  stripped={} recovered_funcs={} stdlib_ratio={:.3} buildid={:?}",
        a.stripped.stripped,
        a.stripped.recovered_funcs,
        a.stripped.stdlib_ratio,
        a.stripped.buildid
    );
    println!(
        "  garble quality={:?} score={} stdlib_fp={} seed={:?} wall={}",
        a.garble.quality,
        a.garble.detection_score,
        a.garble.stdlib_fingerprints_present,
        a.garble.seed_hash,
        a.garble.name_recovery_wall.is_some()
    );
    println!(
        "  embed uses_fs={} directives={} files={}",
        a.embed.uses_embed_fs,
        a.embed.directives.len(),
        a.embed.files.len()
    );
    for f in &a.embed.files {
        println!(
            "    embed: {} size={} dir={} preview={:?}",
            f.name, f.size, f.is_dir, f.preview
        );
    }
    let mains: Vec<&str> = a
        .symbols
        .funcs
        .iter()
        .filter(|f| f.name.starts_with("main."))
        .map(|f| f.name.as_str())
        .collect();
    println!("  main.* funcs ({}): {:?}", mains.len(), mains);
}

fn main() {
    dump("hello_normal.exe");
    dump("hello_stripped.exe");
    dump("hello_garble.exe");
    dump("hello_embed.exe");
}
