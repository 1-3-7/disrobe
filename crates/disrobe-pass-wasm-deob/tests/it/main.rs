#![allow(clippy::duplicate_mod)]

#[cfg(feature = "sandbox")]
#[path = "../common/bounded_wasmtime.rs"]
mod bounded_wasmtime;
#[path = "../common/build_records.rs"]
mod build_records;
#[path = "../common/div_cases.rs"]
mod div_cases;
#[cfg(feature = "sandbox")]
#[path = "../common/eh_exec.rs"]
mod eh_exec;
#[cfg(feature = "sandbox")]
#[path = "../common/exec_diff.rs"]
mod exec_diff;
#[path = "../common/published.rs"]
mod published;
#[path = "../common/wat_corpus.rs"]
mod wat_corpus;

#[path = "../adversarial_resilience.rs"]
mod adversarial_resilience;
#[path = "../atomic_fence_lift.rs"]
mod atomic_fence_lift;
#[path = "../boundary_links.rs"]
mod boundary_links;
#[path = "../boundary_name_propagation.rs"]
mod boundary_name_propagation;
#[path = "../cff_conditional_reloop.rs"]
mod cff_conditional_reloop;
#[path = "../compile_lifted.rs"]
mod compile_lifted;
#[path = "../cryptic_bytes_wasm.rs"]
mod cryptic_bytes_wasm;
#[path = "../debug_framework.rs"]
mod debug_framework;
#[path = "../dwarf_recovery.rs"]
mod dwarf_recovery;
#[path = "../eh_scan.rs"]
mod eh_scan;
#[path = "../external_op_denominator.rs"]
mod external_op_denominator;
#[path = "../fuzz_decode_never_panics.rs"]
mod fuzz_decode_never_panics;
#[path = "../gc_types_corpus.rs"]
mod gc_types_corpus;
#[path = "../hostile_local_names.rs"]
mod hostile_local_names;
#[path = "../jscrambler_integrity.rs"]
mod jscrambler_integrity;
#[path = "../jscrambler_opaque.rs"]
mod jscrambler_opaque;
#[path = "../lift_e2e_pipeline.rs"]
mod lift_e2e_pipeline;
#[path = "../lift_targets.rs"]
mod lift_targets;
#[cfg(feature = "sandbox")]
#[path = "../linear_memory_local_offset.rs"]
mod linear_memory_local_offset;
#[path = "../mba_ssa_oracle.rs"]
mod mba_ssa_oracle;
#[path = "../module_source.rs"]
mod module_source;
#[path = "../name_recovery_e2e.rs"]
mod name_recovery_e2e;
#[path = "../obfuscators_e2e.rs"]
mod obfuscators_e2e;
#[path = "../published_wasm_reverser_roster.rs"]
mod published_wasm_reverser_roster;
#[path = "../recover_differential.rs"]
mod recover_differential;
#[path = "../recovered_type_declarations.rs"]
mod recovered_type_declarations;
#[path = "../reverse_oracle.rs"]
mod reverse_oracle;
#[path = "../rust_execution_differential.rs"]
mod rust_execution_differential;
#[path = "../semantic_differential.rs"]
mod semantic_differential;
#[path = "../semantic_recovery_corpus.rs"]
mod semantic_recovery_corpus;
#[path = "../shared_memory_atomics_runtime.rs"]
mod shared_memory_atomics_runtime;
#[path = "../signature_defeat.rs"]
mod signature_defeat;
#[path = "../stage2_integration.rs"]
mod stage2_integration;
#[path = "../tigress_unflatten.rs"]
mod tigress_unflatten;
#[path = "../typescript_atomic_runtime.rs"]
mod typescript_atomic_runtime;
#[path = "../wasm_br_table_result_values.rs"]
mod wasm_br_table_result_values;
#[path = "../wasm_component_lift.rs"]
mod wasm_component_lift;
#[path = "../wasm_component_lift_kinds.rs"]
mod wasm_component_lift_kinds;
#[path = "../wasm_custom_page_sizes.rs"]
mod wasm_custom_page_sizes;
#[path = "../wasm_div_sign_roundtrip.rs"]
mod wasm_div_sign_roundtrip;
#[path = "../wasm_eh_faithful_differential.rs"]
mod wasm_eh_faithful_differential;
#[path = "../wasm_eh_wholemodule_differential.rs"]
mod wasm_eh_wholemodule_differential;
#[path = "../wasm_family_recovery.rs"]
mod wasm_family_recovery;
#[path = "../wasm_float_const_nan_bits.rs"]
mod wasm_float_const_nan_bits;
#[path = "../wasm_function_refs.rs"]
mod wasm_function_refs;
#[path = "../wasm_gc_desc_ops.rs"]
mod wasm_gc_desc_ops;
#[path = "../wasm_gc_extern.rs"]
mod wasm_gc_extern;
#[path = "../wasm_gc_faithful_differential.rs"]
mod wasm_gc_faithful_differential;
#[path = "../wasm_gc_lift.rs"]
mod wasm_gc_lift;
#[path = "../wasm_gc_wholemodule_differential.rs"]
mod wasm_gc_wholemodule_differential;
#[path = "../wasm_js_string_builtins.rs"]
mod wasm_js_string_builtins;
#[path = "../wasm_lift_execution_differential.rs"]
mod wasm_lift_execution_differential;
#[path = "../wasm_memory64.rs"]
mod wasm_memory64;
#[path = "../wasm_module_parser_resilience.rs"]
mod wasm_module_parser_resilience;
#[path = "../wasm_multi_memory.rs"]
mod wasm_multi_memory;
#[path = "../wasm_multi_memory_faithful_differential.rs"]
mod wasm_multi_memory_faithful_differential;
#[path = "../wasm_name_obf_gauntlet.rs"]
mod wasm_name_obf_gauntlet;
#[path = "../wasm_name_obfuscator_runner_outputs.rs"]
mod wasm_name_obfuscator_runner_outputs;
#[path = "../wasm_no_placeholders.rs"]
mod wasm_no_placeholders;
#[path = "../wasm_relaxed_simd.rs"]
mod wasm_relaxed_simd;
#[path = "../wasm_signedness_recovery.rs"]
mod wasm_signedness_recovery;
#[path = "../wasm_simd128_lift.rs"]
mod wasm_simd128_lift;
#[path = "../wasm_simd_differential.rs"]
mod wasm_simd_differential;
#[path = "../wasm_stack_switching.rs"]
mod wasm_stack_switching;
#[path = "../wasm_stack_switching_wholemodule_differential.rs"]
mod wasm_stack_switching_wholemodule_differential;
#[path = "../wasm_stdlib_fingerprint.rs"]
mod wasm_stdlib_fingerprint;
#[path = "../wasm_structured_features.rs"]
mod wasm_structured_features;
#[path = "../wasm_tail_call.rs"]
mod wasm_tail_call;
#[path = "../wasm_threads_parse.rs"]
mod wasm_threads_parse;
#[path = "../wasm_trunc_sat.rs"]
mod wasm_trunc_sat;
#[path = "../wasmixer_defrag.rs"]
mod wasmixer_defrag;
#[path = "../wasmixer_sandbox_unwrap.rs"]
mod wasmixer_sandbox_unwrap;
#[path = "../wasmixer_stub_detect.rs"]
mod wasmixer_stub_detect;
#[path = "../wat_const_bit_pattern_roundtrip.rs"]
mod wat_const_bit_pattern_roundtrip;
#[path = "../wat_export_aliases.rs"]
mod wat_export_aliases;
#[path = "../wholemodule_behavioral_oracle.rs"]
mod wholemodule_behavioral_oracle;
#[path = "../wobfuscator_optable.rs"]
mod wobfuscator_optable;
