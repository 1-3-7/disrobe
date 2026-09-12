#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::containers::cython::{
    CythonFunction, CythonModule, RecoverySource, detect_cython, recover_cython,
};

use common::requirement::required_fixture;

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
    let bytes: Vec<u8> = required_fixture(FORMAT_DIR, "mod.unstripped.pyd");

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
    let bytes: Vec<u8> = required_fixture(FORMAT_DIR, "mod.stripped.pyd");

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
fn linked_elf_resolves_pointers_through_dynamic_relocations() {
    let bytes: Vec<u8> = required_fixture(FORMAT_DIR, "cymod.linux.so");

    let identity = detect_cython(&bytes).expect("linked cython so detected");
    assert_eq!(identity.module_name, "cymod");
    assert_eq!(identity.init_symbol, "PyInit_cymod");

    let module: CythonModule = recover_cython(&bytes).expect("recover linked cython so");
    assert_eq!(module.module_name, "cymod");

    for name in ["foo", "bar"] {
        assert!(
            find(&module, name).is_some(),
            "function `{name}` not recovered from linked so; dynamic relocations unresolved"
        );
    }
    assert_eq!(doc_of(&module, "foo"), "foo(x, y) -> int\n\nCompute foo.");
    assert_eq!(doc_of(&module, "bar"), "bar(a) -> int\n\nCompute bar.");
    assert_eq!(
        find(&module, "foo").and_then(|f: &CythonFunction| f.signature.clone()),
        Some("foo(x, y) -> int".to_owned())
    );
}

#[test]
fn truncated_module_does_not_panic() {
    let bytes: Vec<u8> = required_fixture(FORMAT_DIR, "mod.stripped.pyd");
    for cut in (0..bytes.len()).step_by(1024) {
        let _ = detect_cython(&bytes[..cut]);
        let _ = recover_cython(&bytes[..cut]);
    }
}
