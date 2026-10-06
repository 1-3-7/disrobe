#![allow(clippy::duplicate_mod)]

#[path = "../arxan_js.rs"]
mod arxan_js;

#[path = "../arxan_node_reference.rs"]
mod arxan_node_reference;

#[path = "../ast_alias_inline_oracle.rs"]
mod ast_alias_inline_oracle;

#[path = "../ast_amd_param_oracle.rs"]
mod ast_amd_param_oracle;

#[path = "../ast_arg_rest_oracle.rs"]
mod ast_arg_rest_oracle;

#[path = "../ast_argument_spread_oracle.rs"]
mod ast_argument_spread_oracle;

#[path = "../ast_async_restore_oracle.rs"]
mod ast_async_restore_oracle;

#[path = "../ast_builtin_prototype_oracle.rs"]
mod ast_builtin_prototype_oracle;

#[path = "../ast_chained_assign_oracle.rs"]
mod ast_chained_assign_oracle;

#[path = "../ast_conditional_statement_oracle.rs"]
mod ast_conditional_statement_oracle;

#[path = "../ast_de_morgan_oracle.rs"]
mod ast_de_morgan_oracle;

#[path = "../ast_dead_code_oracle.rs"]
mod ast_dead_code_oracle;

#[path = "../ast_default_param_oracle.rs"]
mod ast_default_param_oracle;

#[path = "../ast_es6_class_oracle.rs"]
mod ast_es6_class_oracle;

#[path = "../ast_exponent_oracle.rs"]
mod ast_exponent_oracle;

#[path = "../ast_export_rename_oracle.rs"]
mod ast_export_rename_oracle;

#[path = "../ast_for_of_destructure_oracle.rs"]
mod ast_for_of_destructure_oracle;

#[path = "../ast_for_of_direct_oracle.rs"]
mod ast_for_of_direct_oracle;

#[path = "../ast_for_of_helper_oracle.rs"]
mod ast_for_of_helper_oracle;

#[path = "../ast_for_of_hoisted_snapshot_oracle.rs"]
mod ast_for_of_hoisted_snapshot_oracle;

#[path = "../ast_for_of_loose_oracle.rs"]
mod ast_for_of_loose_oracle;

#[path = "../ast_for_of_oracle.rs"]
mod ast_for_of_oracle;

#[path = "../ast_for_of_spread_snapshot_oracle.rs"]
mod ast_for_of_spread_snapshot_oracle;

#[path = "../ast_for_of_string_oracle.rs"]
mod ast_for_of_string_oracle;

#[path = "../ast_for_of_values_oracle.rs"]
mod ast_for_of_values_oracle;

#[path = "../ast_iife_param_oracle.rs"]
mod ast_iife_param_oracle;

#[path = "../ast_import_rename_oracle.rs"]
mod ast_import_rename_oracle;

#[path = "../ast_indirect_call_oracle.rs"]
mod ast_indirect_call_oracle;

#[path = "../ast_interop_unwrap_oracle.rs"]
mod ast_interop_unwrap_oracle;

#[path = "../ast_jsx_restore_oracle.rs"]
mod ast_jsx_restore_oracle;

#[path = "../ast_literal_length_oracle.rs"]
mod ast_literal_length_oracle;

#[path = "../ast_literal_logic_oracle.rs"]
mod ast_literal_logic_oracle;

#[path = "../ast_literal_normalize_oracle.rs"]
mod ast_literal_normalize_oracle;

#[path = "../ast_loop_comma_body_oracle.rs"]
mod ast_loop_comma_body_oracle;

#[path = "../ast_mba_simplify_oracle.rs"]
mod ast_mba_simplify_oracle;

#[path = "../ast_merge_else_if_oracle.rs"]
mod ast_merge_else_if_oracle;

#[path = "../ast_numeric_literal_oracle.rs"]
mod ast_numeric_literal_oracle;

#[path = "../ast_object_param_oracle.rs"]
mod ast_object_param_oracle;

#[path = "../ast_object_shorthand_oracle.rs"]
mod ast_object_shorthand_oracle;

#[path = "../ast_parity_transforms_oracle.rs"]
mod ast_parity_transforms_oracle;

#[path = "../ast_regenerator_restore_oracle.rs"]
mod ast_regenerator_restore_oracle;

#[path = "../ast_registry_param_oracle.rs"]
mod ast_registry_param_oracle;

#[path = "../ast_require_alias_oracle.rs"]
mod ast_require_alias_oracle;

#[path = "../ast_require_destructure_oracle.rs"]
mod ast_require_destructure_oracle;

#[path = "../ast_require_member_oracle.rs"]
mod ast_require_member_oracle;

#[path = "../ast_sequence_split_oracle.rs"]
mod ast_sequence_split_oracle;

#[path = "../ast_split_var_oracle.rs"]
mod ast_split_var_oracle;

#[path = "../ast_spread_clone_oracle.rs"]
mod ast_spread_clone_oracle;

#[path = "../ast_spread_rebuild_oracle.rs"]
mod ast_spread_rebuild_oracle;

#[path = "../ast_structural_parity_oracle.rs"]
mod ast_structural_parity_oracle;

#[path = "../ast_system_register_param_oracle.rs"]
mod ast_system_register_param_oracle;

#[path = "../ast_template_literal_oracle.rs"]
mod ast_template_literal_oracle;

#[path = "../ast_then_catch_oracle.rs"]
mod ast_then_catch_oracle;

#[path = "../ast_type_constructor_oracle.rs"]
mod ast_type_constructor_oracle;

#[path = "../ast_umd_param_oracle.rs"]
mod ast_umd_param_oracle;

#[path = "../ast_undefined_init_oracle.rs"]
mod ast_undefined_init_oracle;

#[path = "../ast_var_to_block_oracle.rs"]
mod ast_var_to_block_oracle;

#[path = "../bundle_graph.rs"]
mod bundle_graph;

#[path = "../bundle_unbundle.rs"]
mod bundle_unbundle;

#[path = "../bundler_amd.rs"]
mod bundler_amd;

#[path = "../bundler_browserify.rs"]
mod bundler_browserify;

#[path = "../bundler_bun_full.rs"]
mod bundler_bun_full;

#[path = "../bundler_chunk_annotations.rs"]
mod bundler_chunk_annotations;

#[path = "../bundler_esbuild_full.rs"]
mod bundler_esbuild_full;

#[path = "../bundler_parcel.rs"]
mod bundler_parcel;

#[path = "../bundler_rolldown.rs"]
mod bundler_rolldown;

#[path = "../bundler_rollup_full.rs"]
mod bundler_rollup_full;

#[path = "../bundler_sourcemap_roundtrip.rs"]
mod bundler_sourcemap_roundtrip;

#[path = "../bundler_sourcemap_synth.rs"]
mod bundler_sourcemap_synth;

#[path = "../bundler_systemjs.rs"]
mod bundler_systemjs;

#[path = "../bundler_turbopack_full.rs"]
mod bundler_turbopack_full;

#[path = "../bundler_vite_manifest.rs"]
mod bundler_vite_manifest;

#[path = "../bundler_webpack_full_graph.rs"]
mod bundler_webpack_full_graph;

#[path = "../bytenode_lift.rs"]
mod bytenode_lift;

#[path = "../bytenode_node_18_through_24.rs"]
mod bytenode_node_18_through_24;

#[path = "../bytenode_real_fixtures.rs"]
mod bytenode_real_fixtures;

#[path = "../chain_recovery_real.rs"]
mod chain_recovery_real;

#[path = "../chain_routing_real.rs"]
mod chain_routing_real;

#[path = "../debug_framework.rs"]
mod debug_framework;

#[path = "../electron_nwjs.rs"]
mod electron_nwjs;

#[path = "../emit_sourcemap.rs"]
mod emit_sourcemap;

#[path = "../esoteric_aaencode.rs"]
mod esoteric_aaencode;

#[path = "../esoteric_atob_indirection.rs"]
mod esoteric_atob_indirection;

#[path = "../esoteric_eval_indirection.rs"]
mod esoteric_eval_indirection;

#[path = "../esoteric_jjencode.rs"]
mod esoteric_jjencode;

#[path = "../esoteric_jsfiretruck.rs"]
mod esoteric_jsfiretruck;

#[path = "../esoteric_jsfuck.rs"]
mod esoteric_jsfuck;

#[path = "../esoteric_packer.rs"]
mod esoteric_packer;

#[path = "../esoteric_packer_recursive_oracle.rs"]
mod esoteric_packer_recursive_oracle;

#[path = "../esoteric_recovery_graded.rs"]
mod esoteric_recovery_graded;

#[path = "../full_pipeline.rs"]
mod full_pipeline;

#[path = "../gauntlet_javascript_obfuscator.rs"]
mod gauntlet_javascript_obfuscator;

#[path = "../hotspots_sonarjs_oracle.rs"]
mod hotspots_sonarjs_oracle;

#[path = "../js_literal_surrogate_reexec.rs"]
mod js_literal_surrogate_reexec;

#[path = "../jsconfuser_all.rs"]
mod jsconfuser_all;

#[path = "../jsconfuser_ast_scrambler.rs"]
mod jsconfuser_ast_scrambler;

#[path = "../jsconfuser_calculator.rs"]
mod jsconfuser_calculator;

#[path = "../jsconfuser_dispatcher.rs"]
mod jsconfuser_dispatcher;

#[path = "../jsconfuser_flatten.rs"]
mod jsconfuser_flatten;

#[path = "../jsconfuser_gauntlet.rs"]
mod jsconfuser_gauntlet;

#[path = "../jsconfuser_integrity.rs"]
mod jsconfuser_integrity;

#[path = "../jsconfuser_lock.rs"]
mod jsconfuser_lock;

#[path = "../jsconfuser_moved_decls.rs"]
mod jsconfuser_moved_decls;

#[path = "../jsconfuser_node_oracle.rs"]
mod jsconfuser_node_oracle;

#[path = "../jsconfuser_opaque.rs"]
mod jsconfuser_opaque;

#[path = "../jsconfuser_packing.rs"]
mod jsconfuser_packing;

#[path = "../jsconfuser_rgf.rs"]
mod jsconfuser_rgf;

#[path = "../jsconfuser_shuffle.rs"]
mod jsconfuser_shuffle;

#[path = "../jsconfuser_string_compression.rs"]
mod jsconfuser_string_compression;

#[path = "../jsconfuser_string_encoding.rs"]
mod jsconfuser_string_encoding;

#[path = "../jsconfuser_variable_masking.rs"]
mod jsconfuser_variable_masking;

#[path = "../jscrambler_19_reversers.rs"]
mod jscrambler_19_reversers;

#[path = "../jscrambler_48_transforms.rs"]
mod jscrambler_48_transforms;

#[path = "../jscrambler_lock_all.rs"]
mod jscrambler_lock_all;

#[path = "../jscrambler_opt_all.rs"]
mod jscrambler_opt_all;

#[path = "../jscrambler_pipeline.rs"]
mod jscrambler_pipeline;

#[path = "../jscrambler_rasp_all.rs"]
mod jscrambler_rasp_all;

#[path = "../jscrambler_template_all.rs"]
mod jscrambler_template_all;

#[path = "../jsdefender_deobf.rs"]
mod jsdefender_deobf;

#[path = "../jsobfu_pipeline.rs"]
mod jsobfu_pipeline;

#[path = "../mangled_name_sources.rs"]
mod mangled_name_sources;

#[path = "../mangled_usage_context_oracle.rs"]
mod mangled_usage_context_oracle;

#[path = "../name_inference_funnel.rs"]
mod name_inference_funnel;

#[path = "../name_inference_precision.rs"]
mod name_inference_precision;

#[path = "../node_sea_pkg_nexe.rs"]
mod node_sea_pkg_nexe;

#[path = "../obfuscator_io_cfo_dead_decl.rs"]
mod obfuscator_io_cfo_dead_decl;

#[path = "../obfuscator_io_controls.rs"]
mod obfuscator_io_controls;

#[path = "../obfuscator_io_detection_precision.rs"]
mod obfuscator_io_detection_precision;

#[path = "../obfuscator_io_differential_oracle.rs"]
mod obfuscator_io_differential_oracle;

#[path = "../obfuscator_io_e2e.rs"]
mod obfuscator_io_e2e;

#[path = "../obfuscator_io_modern_string_array.rs"]
mod obfuscator_io_modern_string_array;

#[path = "../obfuscator_io_presets.rs"]
mod obfuscator_io_presets;

#[path = "../obfuscator_io_reparse_gate.rs"]
mod obfuscator_io_reparse_gate;

#[path = "../pace_js.rs"]
mod pace_js;

#[path = "../protectors_chain.rs"]
mod protectors_chain;

#[path = "../published_bundler_roster.rs"]
mod published_bundler_roster;

#[path = "../real_bundlers.rs"]
mod real_bundlers;

#[path = "../real_esoterics.rs"]
mod real_esoterics;

#[path = "../real_javascript_obfuscator.rs"]
mod real_javascript_obfuscator;

#[path = "../real_jsconfuser.rs"]
mod real_jsconfuser;

#[path = "../real_jsobfu.rs"]
mod real_jsobfu;

#[path = "../real_jsobfu_recovery_oracle.rs"]
mod real_jsobfu_recovery_oracle;

#[path = "../real_megafile_smoke.rs"]
mod real_megafile_smoke;

#[path = "../real_minified_unminify.rs"]
mod real_minified_unminify;

#[path = "../real_node_packagers.rs"]
mod real_node_packagers;

#[path = "../real_obfuscator_io_recovery.rs"]
mod real_obfuscator_io_recovery;

#[path = "../real_typescript_toolchain.rs"]
mod real_typescript_toolchain;

#[path = "../real_webpack_concat_unbundle.rs"]
mod real_webpack_concat_unbundle;

#[path = "../reeval_corpus_oracle.rs"]
mod reeval_corpus_oracle;

#[path = "../reeval_oracle.rs"]
mod reeval_oracle;

#[path = "../sandbox_overflow_resilience.rs"]
mod sandbox_overflow_resilience;

#[path = "../source_map_limits.rs"]
mod source_map_limits;

#[path = "../sourcemap_hostile_corpus.rs"]
mod sourcemap_hostile_corpus;

#[path = "../sourcemap_recover_real.rs"]
mod sourcemap_recover_real;

#[path = "../sourcemap_stub_escaping.rs"]
mod sourcemap_stub_escaping;

#[path = "../sourcemap_tree_corpus.rs"]
mod sourcemap_tree_corpus;

#[path = "../string_array_end_to_end.rs"]
mod string_array_end_to_end;

#[path = "../tauri_classify.rs"]
mod tauri_classify;

#[path = "../terser_restore.rs"]
mod terser_restore;

#[path = "../text_pipeline_reparse_gate.rs"]
mod text_pipeline_reparse_gate;

#[path = "../top_level_iife_scope.rs"]
mod top_level_iife_scope;

#[path = "../ts_helpers_oracle.rs"]
mod ts_helpers_oracle;

#[path = "../ts_preset_env_undo.rs"]
mod ts_preset_env_undo;

#[path = "../unbundle_limits.rs"]
mod unbundle_limits;

#[path = "../unminify_generated_differential.rs"]
mod unminify_generated_differential;

#[path = "../unminify_node_battery.rs"]
mod unminify_node_battery;

#[path = "../unminify_radix_decimalize.rs"]
mod unminify_radix_decimalize;

#[path = "../unminify_string_split.rs"]
mod unminify_string_split;

#[path = "../v8_bytecode_disasm.rs"]
mod v8_bytecode_disasm;

#[path = "../v8_bytenode.rs"]
mod v8_bytenode;

#[path = "../v8_codeserializer_real.rs"]
mod v8_codeserializer_real;

#[path = "../v8_recovery_ceiling.rs"]
mod v8_recovery_ceiling;

#[path = "../v8_structural_recovery.rs"]
mod v8_structural_recovery;

#[path = "../webpack_unbundle_gauntlet.rs"]
mod webpack_unbundle_gauntlet;
