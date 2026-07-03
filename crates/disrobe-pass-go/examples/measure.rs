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
    types_with_methods: usize,
    methods_total: usize,
    methods_named: usize,
    methods_linked: usize,
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
    let types_with_methods: usize = a
        .typemeta
        .types
        .iter()
        .filter(|t| !t.methods.is_empty())
        .count();
    let methods_total: usize = a.typemeta.types.iter().map(|t| t.methods.len()).sum();
    let methods_named: usize = a
        .typemeta
        .types
        .iter()
        .flat_map(|t| t.methods.iter())
        .filter(|m| m.name.is_some())
        .count();
    let methods_linked: usize = a
        .typemeta
        .types
        .iter()
        .flat_map(|t| t.methods.iter())
        .filter(|m| m.linker_name.is_some())
        .count();
    Metrics {
        funcs: a.symbols.funcs.len(),
        types_total: a.typemeta.types.len(),
        types_named,
        itabs_total: a.typemeta.itabs.len(),
        itabs_full,
        generic_funcs,
        generic_types,
        types_with_methods,
        methods_total,
        methods_named,
        methods_linked,
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
    let method_link_ratio: f64 = if m.methods_total == 0 {
        0.0
    } else {
        m.methods_linked as f64 / m.methods_total as f64
    };
    println!(
        "        methods: types-with={:3} total={:4} named={:4} linked={:4} ({:5.1}%)",
        m.types_with_methods,
        m.methods_total,
        m.methods_named,
        m.methods_linked,
        method_link_ratio * 100.0,
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
    let dwarf_detailed: usize = a
        .dwarf
        .functions
        .iter()
        .filter(|f| !f.params.is_empty() || !f.locals.is_empty() || !f.type_params.is_empty())
        .count();
    println!(
        "        dwarf present={} compressed={} v{:?} CUs={} funcs={} named-detail={} types={}",
        a.dwarf.present,
        a.dwarf.compressed,
        a.dwarf.dwarf_version,
        a.dwarf.compile_units,
        a.dwarf.functions.len(),
        dwarf_detailed,
        a.dwarf.type_names.len(),
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
    ] {
        run(f);
    }
}
