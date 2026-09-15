#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;

use disrobe_binfmt::structural::validate_wasm;
use disrobe_fuzz::over_input_budget;
use disrobe_nir_lift::lift_wasm_module;
use disrobe_pass_wasm_deob::dwarf::{has_dwarf, recover_source_map};
use disrobe_pass_wasm_deob::{
    analyze_module, detect, fingerprint_module, parse_component_manifest, recover_gc_types,
    scan_custom_page_sizes, scan_function_refs, scan_gc_extern, scan_js_string_builtins,
    scan_memories, scan_module_eh as scan_module, strip_name_section,
};

fn drive_section_scanners(data: &[u8]) {
    let _ = black_box(scan_custom_page_sizes(data));
    let _ = black_box(scan_function_refs(data));
    let _ = black_box(scan_gc_extern(data));
    let _ = black_box(scan_js_string_builtins(data));
    let _ = black_box(scan_memories(data));
    let _ = black_box(scan_module(data));
    let _ = black_box(recover_gc_types(data));
    let _ = black_box(has_dwarf(data));
    let _ = black_box(recover_source_map(data));
}

fn stripping_names_keeps_the_module_parseable(data: &[u8]) {
    if analyze_module(data).is_err() {
        return;
    }
    let Ok(stripped): disrobe_pass_wasm_deob::Result<Vec<u8>> = strip_name_section(data) else {
        return;
    };
    assert!(
        stripped.len() <= data.len(),
        "stripping the name section produced a larger module than it was given"
    );
    let _ = black_box(analyze_module(&stripped));
}

fuzz_target!(|data: &[u8]| {
    if over_input_budget(data) {
        return;
    }
    let _ = black_box(validate_wasm(data));
    let _ = black_box(detect(data));
    let _ = black_box(analyze_module(data));
    let _ = black_box(parse_component_manifest(data));
    let _ = black_box(fingerprint_module(data));
    drive_section_scanners(data);
    stripping_names_keeps_the_module_parseable(data);
    let _ = black_box(lift_wasm_module(data));
});
