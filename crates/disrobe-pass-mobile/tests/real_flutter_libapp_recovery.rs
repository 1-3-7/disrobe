#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    CidTableMatch, DartLibAppRecovery, decompile_libapp_so_recovery, predefined_count,
};

fn sample_so() -> Vec<u8> {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let path: PathBuf = Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join("disrobe_sample")
        .join("libapp_arm64.so");
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "real AOT sample must be committed: {} ({e})",
            path.display()
        )
    })
}

#[test]
fn recovers_app_class_names_from_real_aot() {
    let bytes: Vec<u8> = sample_so();
    let recovery: DartLibAppRecovery =
        decompile_libapp_so_recovery(&bytes).expect("recover from real libapp.so");

    assert_eq!(
        recovery.version_hash, "ace654289f5abc240509fc941453ebc5",
        "the committed sample is built with the pinned Dart 3.12.2 snapshot version"
    );
    assert_eq!(
        recovery.cid_table_match,
        CidTableMatch::Pinned,
        "the embedded cid table must match the sample's snapshot version"
    );

    let classes: &Vec<String> = &recovery.string_pool.class_names;
    for expected in ["InventoryItem", "WarehouseLedger"] {
        assert!(
            classes.iter().any(|c: &String| c == expected),
            "object-pool string recovery must surface app class {expected}; sample classes: {:?}",
            &classes.iter().take(30).collect::<Vec<&String>>()
        );
    }
}

#[test]
fn recovers_app_method_selectors_from_real_aot() {
    let bytes: Vec<u8> = sample_so();
    let recovery: DartLibAppRecovery =
        decompile_libapp_so_recovery(&bytes).expect("recover from real libapp.so");

    let methods: &Vec<String> = &recovery.string_pool.method_or_field_names;
    for expected in [
        "totalCarryingValue",
        "countBackordered",
        "mostValuable",
        "fibonacciStep",
    ] {
        assert!(
            methods.iter().any(|m: &String| m == expected),
            "method/selector recovery must surface {expected} from the real snapshot string table"
        );
    }

    for inlined in [
        "classifyMagnitude",
        "extendedValue",
        "isBackordered",
        "withRestock",
    ] {
        assert!(
            !methods.contains(&inlined.to_owned()),
            "honest boundary: {inlined} is a small leaf the AOT compiler inlined and tree-shook, so its name is absent from the object pool; recovery must not invent it"
        );
    }

    let getters: &Vec<String> = &recovery.string_pool.getter_selectors;
    assert!(
        !getters.is_empty(),
        "a real Dart AOT image has get: selectors in its object pool"
    );
    assert!(
        recovery.string_pool.setter_selectors.iter().any(|_| true)
            || recovery.string_pool.init_selectors.iter().any(|_| true)
            || !getters.is_empty(),
        "selector recovery must yield at least one get:/set:/init: selector"
    );
}

#[test]
fn recovers_string_literals_from_real_aot() {
    let bytes: Vec<u8> = sample_so();
    let recovery: DartLibAppRecovery =
        decompile_libapp_so_recovery(&bytes).expect("recover from real libapp.so");

    let literals: &Vec<String> = &recovery.string_pool.literals;
    for expected in [
        "widget-alpha",
        "gadget-bravo",
        "sprocket-charlie",
        "flange-delta",
        "enterprise-tier",
        "mid-market-tier",
        "starter-tier",
    ] {
        assert!(
            literals.iter().any(|s: &String| s == expected),
            "string-object recovery must surface the app literal {expected}"
        );
    }
}

#[test]
fn recovers_library_uris_from_real_aot() {
    let bytes: Vec<u8> = sample_so();
    let recovery: DartLibAppRecovery = decompile_libapp_so_recovery(&bytes).expect("recover");
    let libs: &Vec<String> = &recovery.string_pool.library_uris;
    assert!(
        libs.iter().any(|u: &String| u.starts_with("dart:")),
        "the snapshot string pool carries dart: core library uris"
    );
    assert!(
        libs.len() > 20,
        "a real Flutter AOT pulls in dozens of dart: libraries, got {}",
        libs.len()
    );
}

#[test]
fn recovers_object_pool_and_dispatch_from_real_aot() {
    let bytes: Vec<u8> = sample_so();
    let recovery: DartLibAppRecovery = decompile_libapp_so_recovery(&bytes).expect("recover");
    let pool = &recovery.object_pool;

    assert!(
        pool.distinct_slots > 1000,
        "a real AOT image references thousands of object-pool slots via ldr [x27], got {}",
        pool.distinct_slots
    );
    assert!(
        pool.total_load_sites > pool.distinct_slots,
        "pool slots are loaded from many sites; total {} should exceed distinct {}",
        pool.total_load_sites,
        pool.distinct_slots
    );
    assert!(
        pool.direct_call_count > 1000,
        "real AOT code is dense with bl direct calls, got {}",
        pool.direct_call_count
    );
    assert!(
        pool.indirect_call_count > 100,
        "dynamic dispatch uses blr indirect calls, got {}",
        pool.indirect_call_count
    );
    assert!(
        pool.distinct_dispatch_slots > 50,
        "a real app dispatches through dozens of distinct pool slots, got {}",
        pool.distinct_dispatch_slots
    );

    eprintln!(
        "real libapp recovery: cid_table_match={:?} predefined_cids={} classes={} methods={} get/set/init={} libraries={} pool_slots={} load_sites={} bl={} blr={} dispatch_slots={}",
        recovery.cid_table_match,
        predefined_count(),
        recovery.string_pool.class_names.len(),
        recovery.string_pool.method_or_field_names.len(),
        recovery.recovered_selector_count,
        recovery.string_pool.library_uris.len(),
        pool.distinct_slots,
        pool.total_load_sites,
        pool.direct_call_count,
        pool.indirect_call_count,
        pool.distinct_dispatch_slots
    );
}

#[test]
fn honest_boundary_is_stated_not_source() {
    let bytes: Vec<u8> = sample_so();
    let recovery: DartLibAppRecovery = decompile_libapp_so_recovery(&bytes).expect("recover");
    assert!(
        recovery.source_boundary.contains("machine code")
            && recovery.source_boundary.contains(".dill"),
        "the recovery must state the honest boundary: bodies stay machine code, source lives in the kernel"
    );
}
