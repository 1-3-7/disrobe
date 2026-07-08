#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::containers::cython::{
    CythonFunction, CythonModule, RecoverySource, detect_cython, recover_cython,
};

const FORMAT_DIR: &str = "cython";

fn find<'m>(module: &'m CythonModule, name: &str) -> Option<&'m CythonFunction> {
    module
        .functions
        .iter()
        .find(|f: &&CythonFunction| f.name == name)
}

fn doc_of(module: &CythonModule, name: &str) -> String {
    find(module, name)
        .and_then(|f: &CythonFunction| f.doc.clone())
        .unwrap_or_default()
}

#[test]
fn unstripped_recovers_full_python_surface() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, "mod.unstripped.pyd")
    else {
        eprintln!("skip: missing corpus/binfmt/cython/mod.unstripped.pyd");
        return;
    };

    let identity = detect_cython(&bytes).expect("cython module detected");
    assert_eq!(identity.module_name, "mod");
    assert_eq!(identity.init_symbol, "PyInit_mod");
    assert!(identity.pyx_symbols_present);

    let module: CythonModule = recover_cython(&bytes).expect("recover cython");
    assert_eq!(module.module_name, "mod");
    assert!(module.pyx_symbols_present);

    for name in ["greet", "add", "scale", "accumulate", "reset"] {
        assert!(
            find(&module, name).is_some(),
            "function `{name}` not recovered"
        );
    }

    assert_eq!(
        doc_of(&module, "greet"),
        "greet(str name, int count=1)\n\ngreet(name, count=1) -> str\n\nReturn a greeting repeated count times."
    );
    assert_eq!(
        doc_of(&module, "add"),
        "add(int a, int b) -> int\n\nadd(a, b) -> int\n\nAdd two integers."
    );
    assert_eq!(
        doc_of(&module, "scale"),
        "scale(double value, double factor=2.0) -> double\n\nScale a value by a factor."
    );

    let greet: &CythonFunction = find(&module, "greet").unwrap();
    assert_eq!(
        greet.signature.as_deref(),
        Some("greet(str name, int count=1)")
    );
    assert_eq!(greet.recovered_via, RecoverySource::Symbol);
    assert!(
        greet
            .impl_symbol
            .as_deref()
            .is_some_and(|s: &str| s.contains("greet"))
    );

    let accumulate: &CythonFunction = find(&module, "accumulate").unwrap();
    assert_eq!(
        accumulate.qualname.as_deref(),
        Some("Accumulator.accumulate")
    );

    let class = module
        .classes
        .iter()
        .find(|c| c.name == "Accumulator")
        .expect("Accumulator class recovered");
    assert_eq!(
        class.doc.as_deref(),
        Some("Accumulator(long start=0)\n\nA simple accumulator cdef class.")
    );
    assert!(class.methods.iter().any(|m: &String| m == "reset"));

    assert!(module.source_files.iter().any(|s: &String| s == "mod.pyx"));
    assert!(module.has_debug_line);
}

#[test]
fn stripped_recovers_surface_structurally() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, "mod.stripped.pyd") else {
        eprintln!("skip: missing corpus/binfmt/cython/mod.stripped.pyd");
        return;
    };

    let identity = detect_cython(&bytes).expect("cython detected via markers");
    assert_eq!(identity.module_name, "mod");
    assert!(!identity.pyx_symbols_present);
    assert!(identity.marker_strings_present);

    let module: CythonModule = recover_cython(&bytes).expect("recover stripped cython");
    assert!(!module.pyx_symbols_present);

    for name in ["greet", "add", "scale", "accumulate", "reset"] {
        let func: &CythonFunction = find(&module, name)
            .unwrap_or_else(|| panic!("function `{name}` not recovered from stripped module"));
        assert_eq!(func.recovered_via, RecoverySource::Structural);
    }

    assert_eq!(
        doc_of(&module, "add"),
        "add(int a, int b) -> int\n\nadd(a, b) -> int\n\nAdd two integers."
    );
    assert_eq!(
        doc_of(&module, "greet"),
        "greet(str name, int count=1)\n\ngreet(name, count=1) -> str\n\nReturn a greeting repeated count times."
    );

    assert!(module.source_files.iter().any(|s: &String| s == "mod.pyx"));
    assert!(!module.has_debug_line);
}

#[test]
fn truncated_module_does_not_panic() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, "mod.stripped.pyd") else {
        return;
    };
    for cut in (0..bytes.len()).step_by(1024) {
        let _ = detect_cython(&bytes[..cut]);
        let _ = recover_cython(&bytes[..cut]);
    }
}
