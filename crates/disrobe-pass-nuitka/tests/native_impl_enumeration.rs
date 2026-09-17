#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_nuitka::{
    NameBinding, NativeBodyRecovery, NativeFunctionBody, NuitkaConstants, parse_constants,
};

const STANDALONE: &str = "sample_app-standalone.exe";
const ONEFILE: &str = "sample_app-onefile.exe";

const LOCATED_IMPLS: usize = 29;
const HOST_FUNCTIONS: usize = 11;
const CONSTRUCTORS: usize = 2;
const LARGEST_HOST_SHARE: usize = 7;
const MIN_IMPLS_CALLING_CPYTHON: usize = 22;

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/python/nuitka/real")
        .join(name)
}

fn read_committed(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus(name);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "the committed real Nuitka artifact {} must be readable, this gate does not skip: {e}",
            path.display()
        )
    })
}

fn lift(name: &str) -> Option<NativeBodyRecovery> {
    let image: Vec<u8> = read_committed(name);
    let constants: NuitkaConstants = parse_constants(&image);
    disrobe_pass_nuitka::lift_native_bodies(&image, Some(&constants))
}

fn is_cpython_api(symbol: &str) -> bool {
    symbol.starts_with("Py") || symbol.starts_with("_Py")
}

#[test]
fn every_constructing_function_contributes_its_impls_not_only_the_largest() {
    let recovery: NativeBodyRecovery =
        lift(STANDALONE).expect("native body lift on the committed real standalone build");

    assert_eq!(
        recovery.located_impls, LOCATED_IMPLS,
        "the constructor cross-reference must report every impl passed to a Nuitka function \
         constructor anywhere in the image"
    );
    assert_eq!(
        recovery.functions.len(),
        recovery.located_impls,
        "every located impl must yield exactly one function record, so none is silently omitted"
    );
    assert_eq!(
        recovery.host_functions, HOST_FUNCTIONS,
        "the impls must be attributed across every constructing function, not one"
    );
    assert_eq!(
        recovery.constructors.len(),
        CONSTRUCTORS,
        "constructors are the callees that receive at least two distinct function pointers"
    );

    let mut per_host: BTreeMap<u64, usize> = BTreeMap::new();
    for function in &recovery.functions {
        *per_host.entry(function.constructed_in).or_insert(0) += 1;
    }
    let largest_host_share: usize = per_host.values().copied().max().unwrap_or(0);
    assert_eq!(
        largest_host_share, LARGEST_HOST_SHARE,
        "the largest constructing function on this build contributes this many impls"
    );
    assert!(
        largest_host_share < recovery.located_impls,
        "selecting only the largest constructing function would report {largest_host_share} of \
         {} impls that satisfy the identical constructor evidence",
        recovery.located_impls
    );
}

#[test]
fn located_impls_are_distinct_and_attributed_to_a_real_constructor() {
    let recovery: NativeBodyRecovery =
        lift(STANDALONE).expect("native body lift on the committed real standalone build");
    let constructors: BTreeSet<u64> = recovery.constructors.iter().copied().collect();
    let mut addresses: BTreeSet<u64> = BTreeSet::new();

    for function in &recovery.functions {
        assert!(
            addresses.insert(function.impl_address),
            "impl address {:#x} was reported twice",
            function.impl_address
        );
        assert!(
            constructors.contains(&function.constructor),
            "impl {:#x} names constructor {:#x}, which is not in the discovered constructor set",
            function.impl_address,
            function.constructor
        );
        assert_ne!(
            function.impl_address, function.constructor,
            "a constructor must never be reported as one of its own arguments"
        );
        assert!(
            function.instruction_count > 0,
            "impl {} at {:#x} decoded no instructions",
            function.name,
            function.impl_address
        );
        assert!(
            function.code_size > 0,
            "impl {:#x} carries a zero-length code range",
            function.impl_address
        );
    }

    let hosts: BTreeSet<u64> = recovery
        .functions
        .iter()
        .map(|f: &NativeFunctionBody| f.constructed_in)
        .collect();
    assert_eq!(
        hosts.len(),
        recovery.host_functions,
        "the per-function host attribution must agree with the reported host count"
    );
}

#[test]
fn located_impls_call_the_real_cpython_c_api() {
    let recovery: NativeBodyRecovery =
        lift(STANDALONE).expect("native body lift on the committed real standalone build");
    let calling: Vec<&NativeFunctionBody> = recovery
        .functions
        .iter()
        .filter(|f: &&NativeFunctionBody| f.api_calls.iter().any(|c: &String| is_cpython_api(c)))
        .collect();

    eprintln!(
        "NUITKA IMPL CENSUS: {}/{} located impl(s) call at least one CPython C-API symbol \
         resolved through the image import table, across {} constructing function(s)",
        calling.len(),
        recovery.functions.len(),
        recovery.host_functions
    );

    assert!(
        calling.len() >= MIN_IMPLS_CALLING_CPYTHON,
        "only {}/{} located impl(s) call the CPython C-API; a set that admitted arbitrary \
         functions would fall below this floor",
        calling.len(),
        recovery.functions.len()
    );

    let vocabulary: BTreeSet<&str> = recovery
        .functions
        .iter()
        .flat_map(|f: &NativeFunctionBody| f.api_calls.iter())
        .map(String::as_str)
        .filter(|c: &&str| is_cpython_api(c))
        .collect();
    assert!(
        vocabulary.len() >= 20,
        "the resolved C-API vocabulary across located impls is implausibly small: {vocabulary:?}"
    );
    for symbol in &vocabulary {
        assert!(
            !symbol.is_empty() && symbol.is_ascii(),
            "import names come from the real import table and must be plain ascii: {symbol:?}"
        );
    }
}

#[test]
fn every_function_carries_one_explicit_name_binding_state() {
    let recovery: NativeBodyRecovery =
        lift(STANDALONE).expect("native body lift on the committed real standalone build");
    let bound: usize = recovery
        .functions
        .iter()
        .filter(|f: &&NativeFunctionBody| matches!(f.name_binding, NameBinding::CodeObject))
        .count();
    let positional: usize = recovery
        .functions
        .iter()
        .filter(|f: &&NativeFunctionBody| matches!(f.name_binding, NameBinding::Positional))
        .count();

    assert_eq!(
        bound + positional,
        recovery.functions.len(),
        "the binding state partitions the located impls"
    );
    assert_eq!(
        bound, recovery.bound_functions,
        "the reported bound count must be derived from the per-function binding state"
    );
    for function in &recovery.functions {
        match function.name_binding {
            NameBinding::Positional => assert!(
                function.name.starts_with("native_impl_"),
                "a positional record must carry a synthetic name, got {}",
                function.name
            ),
            NameBinding::CodeObject => assert!(
                !function.name.is_empty(),
                "a code-object-bound record must carry the recovered name"
            ),
        }
    }
    let reconstructed: usize = recovery
        .functions
        .iter()
        .filter(|f: &&NativeFunctionBody| f.is_body_recovered())
        .count();
    assert_eq!(
        reconstructed, recovery.reconstructed_bodies,
        "the reported reconstructed-body count must equal the number of records that carry one"
    );
}

#[test]
fn enumeration_is_deterministic_across_runs() {
    let first: NativeBodyRecovery = lift(STANDALONE).expect("first lift");
    let second: NativeBodyRecovery = lift(STANDALONE).expect("second lift");
    let left: Vec<u8> = serde_json::to_vec(&first).expect("serialize first");
    let right: Vec<u8> = serde_json::to_vec(&second).expect("serialize second");
    assert_eq!(
        left, right,
        "two lifts of the same image must produce byte-identical output"
    );
    let ordered: bool = first
        .functions
        .windows(2)
        .all(|pair: &[NativeFunctionBody]| pair[0].constructed_in <= pair[1].constructed_in);
    assert!(
        ordered,
        "records must be emitted in constructing-function order so the output is stable"
    );
}

#[test]
fn a_non_python_image_without_constants_is_refused() {
    let image: Vec<u8> = read_committed(ONEFILE);
    let constants: NuitkaConstants = parse_constants(&image);
    assert!(
        constants.is_empty(),
        "the onefile bootstrap stub carries no plaintext constants chunk; its payload does"
    );
    assert!(
        disrobe_pass_nuitka::lift_native_bodies(&image, None).is_none(),
        "the onefile bootstrap stub links no CPython C-API, so its functions must never be \
         reported as compiled Python function bodies"
    );
}

#[test]
fn a_compiled_python_image_lifts_without_a_constants_chunk() {
    let image: Vec<u8> = read_committed(STANDALONE);
    let without: NativeBodyRecovery = disrobe_pass_nuitka::lift_native_bodies(&image, None)
        .expect("a compiled-Python image must carve impls with no constants chunk available");
    let with: NativeBodyRecovery = lift(STANDALONE).expect("lift with constants");

    assert_eq!(
        without.located_impls, with.located_impls,
        "impl carving reads machine code only, so the constants chunk must not change the count"
    );
    assert_eq!(
        without.bound_functions, 0,
        "with no constants chunk there is no code-object metadata to bind a name to"
    );
    assert!(
        without
            .functions
            .iter()
            .all(|f: &NativeFunctionBody| matches!(f.name_binding, NameBinding::Positional)),
        "every record must declare itself positionally named when nothing could bind it"
    );
}
