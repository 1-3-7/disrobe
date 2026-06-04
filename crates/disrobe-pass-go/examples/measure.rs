use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, analyze};

#[derive(Debug, Clone, Copy, Default)]
struct Metrics {
    funcs: usize,
    types_total: usize,
    types_named: usize,
    itabs_total: usize,
    itabs_full: usize,
    generic_funcs: usize,
    generic_types: usize,
}

fn metrics(a: &GoAnalysis) -> Metrics {
    let types_named: usize = a.typemeta.types.iter().filter(|t| t.name.is_some()).count();
    let itabs_full: usize = a
        .typemeta
        .itabs
        .iter()
        .filter(|i| i.interface_name.is_some() && i.concrete_name.is_some())
        .count();
    let generic_funcs: usize = a
        .symbols
        .funcs
        .iter()
        .filter(|f| f.name.contains('[') && f.name.contains(']'))
        .count();
    let generic_types: usize = a
        .typemeta
        .types
        .iter()
        .filter_map(|t| t.name.as_deref())
        .filter(|n| {
            n.contains('[') && n.contains(']') && !n.starts_with("[]") && !n.starts_with('[')
        })
        .count();
    Metrics {
        funcs: a.symbols.funcs.len(),
        types_total: a.typemeta.types.len(),
        types_named,
        itabs_total: a.typemeta.itabs.len(),
        itabs_full,
        generic_funcs,
        generic_types,
    }
}

fn run(name: &str) {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&p) else {
        println!("{name:32} MISSING");
        return;
    };
    let a: GoAnalysis = match analyze(&bytes) {
        Ok(a) => a,
        Err(e) => {
            println!("{name:32} ERR {e}");
            return;
        }
    };
    let m: Metrics = metrics(&a);
    let name_ratio: f64 = if m.types_total == 0 {
        0.0
    } else {
        m.types_named as f64 / m.types_total as f64
    };
    let itab_ratio: f64 = if m.itabs_total == 0 {
        0.0
    } else {
        m.itabs_full as f64 / m.itabs_total as f64
    };
    println!(
        "{name:32} pcln={:14} md.via={:30} funcs={:5} types={:4} named={:4} ({:5.1}%) itabs={:3} full={:3} ({:5.1}%) gfn={:3} gty={:3}",
        a.pclntab_version,
        format!("{:?}", a.moduledata.via),
        m.funcs,
        m.types_total,
        m.types_named,
        name_ratio * 100.0,
        m.itabs_total,
        m.itabs_full,
        itab_ratio * 100.0,
        m.generic_funcs,
        m.generic_types,
    );
    println!(
        "        structured-generics={} (from-fn={}, shape-args={})",
        a.typemeta.generics.len(),
        a.typemeta
            .generics
            .iter()
            .filter(|g| g.from_function)
            .count(),
        a.typemeta.generics.iter().filter(|g| g.shape_args).count(),
    );
    if name == "hello_generics.exe" {
        let main_generics: BTreeSet<&str> = a
            .typemeta
            .generics
            .iter()
            .filter(|g| g.base.starts_with("main."))
            .map(|g| g.full.as_str())
            .collect();
        for g in main_generics {
            println!("        main-generic: {g}");
        }
    }
}

fn main() {
    for f in [
        "hello_normal.exe",
        "hello_stripped.exe",
        "hello_garble.exe",
        "hello_embed.exe",
        "hello_generics.exe",
        "hello_generics_stripped.exe",
        "hello_magic_stomped.exe",
        "hello_md_wiped.exe",
    ] {
        run(f);
    }
}
