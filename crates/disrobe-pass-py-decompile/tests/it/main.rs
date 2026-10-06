#![allow(clippy::duplicate_mod)]

#[path = "../common/mod.rs"]
mod common;

#[path = "../alt_runtime_decompile.rs"]
mod alt_runtime_decompile;
#[path = "../arbitrary_recompile_gate.rs"]
mod arbitrary_recompile_gate;
#[path = "../arbitrary_recompile_gate_310.rs"]
mod arbitrary_recompile_gate_310;
#[path = "../arbitrary_recompile_gate_311.rs"]
mod arbitrary_recompile_gate_311;
#[path = "../arbitrary_recompile_gate_312.rs"]
mod arbitrary_recompile_gate_312;
#[path = "../arbitrary_recompile_gate_313.rs"]
mod arbitrary_recompile_gate_313;
#[path = "../arbitrary_recompile_gate_315.rs"]
mod arbitrary_recompile_gate_315;
#[path = "../arbitrary_recompile_gate_38.rs"]
mod arbitrary_recompile_gate_38;
#[path = "../arbitrary_recompile_gate_39.rs"]
mod arbitrary_recompile_gate_39;
#[path = "../ast_builder_smoke.rs"]
mod ast_builder_smoke;
#[path = "../ast_node_construct.rs"]
mod ast_node_construct;
#[path = "../ast_visitor_walk.rs"]
mod ast_visitor_walk;
#[path = "../band_auto_route.rs"]
mod band_auto_route;
#[path = "../band_interpreter_pin.rs"]
mod band_interpreter_pin;
#[path = "../band_publish_value.rs"]
mod band_publish_value;
#[path = "../boolean_guard_chain_recompile.rs"]
mod boolean_guard_chain_recompile;
#[path = "../byte_identical_tier_measure.rs"]
mod byte_identical_tier_measure;
#[path = "../chain_disasm_fallback_tier.rs"]
mod chain_disasm_fallback_tier;
#[path = "../chained_compare_condition_recompile.rs"]
mod chained_compare_condition_recompile;
#[path = "../ci_003_py312_regression.rs"]
mod ci_003_py312_regression;
#[path = "../class_subpattern_recompile.rs"]
mod class_subpattern_recompile;
#[path = "../codegen_2x_syntax.rs"]
mod codegen_2x_syntax;
#[path = "../codegen_assert.rs"]
mod codegen_assert;
#[path = "../codegen_chained_assign.rs"]
mod codegen_chained_assign;
#[path = "../codegen_class_def.rs"]
mod codegen_class_def;
#[path = "../codegen_comprehensions.rs"]
mod codegen_comprehensions;
#[path = "../codegen_dict_double_unpack.rs"]
mod codegen_dict_double_unpack;
#[path = "../codegen_function_def.rs"]
mod codegen_function_def;
#[path = "../codegen_if_chain.rs"]
mod codegen_if_chain;
#[path = "../codegen_loops.rs"]
mod codegen_loops;
#[path = "../codegen_nested_ternary_precedence.rs"]
mod codegen_nested_ternary_precedence;
#[path = "../codegen_operator_precedence.rs"]
mod codegen_operator_precedence;
#[path = "../codegen_short_circuit.rs"]
mod codegen_short_circuit;
#[path = "../codegen_ternary.rs"]
mod codegen_ternary;
#[path = "../codegen_try.rs"]
mod codegen_try;
#[path = "../codegen_with.rs"]
mod codegen_with;
#[path = "../codegen_yield_from.rs"]
mod codegen_yield_from;
#[path = "../cold_sibling_guard_else_recompile.rs"]
mod cold_sibling_guard_else_recompile;
#[path = "../construct_roundtrip.rs"]
mod construct_roundtrip;
#[path = "../determinism.rs"]
mod determinism;
#[path = "../dos_extended_arg_build_tuple.rs"]
mod dos_extended_arg_build_tuple;
#[path = "../dos_extended_arg_jump_past_end.rs"]
mod dos_extended_arg_jump_past_end;
#[path = "../dos_extended_arg_unpack.rs"]
mod dos_extended_arg_unpack;
#[path = "../dup_consumer_ternary_recompile.rs"]
mod dup_consumer_ternary_recompile;
#[path = "../edge_case_recompile.rs"]
mod edge_case_recompile;
#[path = "../elif_after_guarded_cold_try_recompile.rs"]
mod elif_after_guarded_cold_try_recompile;
#[path = "../emit_blank_line_preservation.rs"]
mod emit_blank_line_preservation;
#[path = "../emit_simple_module.rs"]
mod emit_simple_module;
#[path = "../exception_table_hostile_entries.rs"]
mod exception_table_hostile_entries;
#[path = "../failure_families_310.rs"]
mod failure_families_310;
#[path = "../finally_tail_return_recompile.rs"]
mod finally_tail_return_recompile;
#[path = "../for_body_comprehension_recompile.rs"]
mod for_body_comprehension_recompile;
#[path = "../for_break_return_tail.rs"]
mod for_break_return_tail;
#[path = "../frame_tree_nested_try_finally.rs"]
mod frame_tree_nested_try_finally;
#[path = "../frame_tree_post311_exception_table.rs"]
mod frame_tree_post311_exception_table;
#[path = "../frame_tree_pre311_block_ops.rs"]
mod frame_tree_pre311_block_ops;
#[path = "../frame_tree_try_inside_if_chain.rs"]
mod frame_tree_try_inside_if_chain;
#[path = "../frame_tree_validator.rs"]
mod frame_tree_validator;
#[path = "../frame_tree_with_multiple_items.rs"]
mod frame_tree_with_multiple_items;
#[path = "../full_stdlib_recompile_gate.rs"]
mod full_stdlib_recompile_gate;
#[path = "../fuzz_decode_never_panics.rs"]
mod fuzz_decode_never_panics;
#[path = "../generated_differential.rs"]
mod generated_differential;
#[path = "../guarded_with_region_recompile.rs"]
mod guarded_with_region_recompile;
#[path = "../infinite_loop_finally_guarded_break_auto.rs"]
mod infinite_loop_finally_guarded_break_auto;
#[path = "../infinite_loop_finally_guarded_continue_auto.rs"]
mod infinite_loop_finally_guarded_continue_auto;
#[path = "../infinite_loop_finally_guarded_nonconstant_return_auto.rs"]
mod infinite_loop_finally_guarded_nonconstant_return_auto;
#[path = "../infinite_loop_finally_guarded_raise_auto.rs"]
mod infinite_loop_finally_guarded_raise_auto;
#[path = "../infinite_loop_finally_guarded_return_auto.rs"]
mod infinite_loop_finally_guarded_return_auto;
#[path = "../infinite_loop_try_finally_auto.rs"]
mod infinite_loop_try_finally_auto;
#[path = "../inlined_break_tail_recompile.rs"]
mod inlined_break_tail_recompile;
#[path = "../lambda_body_control_flow_recompile.rs"]
mod lambda_body_control_flow_recompile;
#[path = "../legacy_async_with_recompile.rs"]
mod legacy_async_with_recompile;
#[path = "../legacy_with_head_recompile.rs"]
mod legacy_with_head_recompile;
#[path = "../linecache_explicit_none_tail_recompile.rs"]
mod linecache_explicit_none_tail_recompile;
#[path = "../literal_printing_recompile.rs"]
mod literal_printing_recompile;
#[path = "../loop_continue_before_try_recompile.rs"]
mod loop_continue_before_try_recompile;
#[path = "../loop_handler_flow_recompile.rs"]
mod loop_handler_flow_recompile;
#[path = "../loop_tail_else_arm_recompile.rs"]
mod loop_tail_else_arm_recompile;
#[path = "../loop_try_body_input_space.rs"]
mod loop_try_body_input_space;
#[path = "../loop_try_body_recompile.rs"]
mod loop_try_body_recompile;
#[path = "../marker_never_reaches_recovered_source.rs"]
mod marker_never_reaches_recovered_source;
#[path = "../marquee_tiny_3_14.rs"]
mod marquee_tiny_3_14;
#[path = "../megafile_roundtrip.rs"]
mod megafile_roundtrip;
#[path = "../modern_async.rs"]
mod modern_async;
#[path = "../modern_finally_continuation.rs"]
mod modern_finally_continuation;
#[path = "../modern_fstring.rs"]
mod modern_fstring;
#[path = "../modern_fstring_nested.rs"]
mod modern_fstring_nested;
#[path = "../modern_inlined_comprehension.rs"]
mod modern_inlined_comprehension;
#[path = "../modern_match_class.rs"]
mod modern_match_class;
#[path = "../modern_match_literal.rs"]
mod modern_match_literal;
#[path = "../modern_match_mapping.rs"]
mod modern_match_mapping;
#[path = "../modern_match_or_guard.rs"]
mod modern_match_or_guard;
#[path = "../modern_match_sequence.rs"]
mod modern_match_sequence;
#[path = "../modern_pep654_eg_chain.rs"]
mod modern_pep654_eg_chain;
#[path = "../modern_request_handler_roundtrip.rs"]
mod modern_request_handler_roundtrip;
#[path = "../modern_try_star.rs"]
mod modern_try_star;
#[path = "../modern_tstring.rs"]
mod modern_tstring;
#[path = "../modern_tstring_roundtrip.rs"]
mod modern_tstring_roundtrip;
#[path = "../modern_type_params.rs"]
mod modern_type_params;
#[path = "../modern_walrus.rs"]
mod modern_walrus;
#[path = "../nested_for_try_recompile.rs"]
mod nested_for_try_recompile;
#[path = "../opcode_dispatch.rs"]
mod opcode_dispatch;
#[path = "../per_code_object_fallback.rs"]
mod per_code_object_fallback;
#[path = "../playground_known_open.rs"]
mod playground_known_open;
#[path = "../playground_strict.rs"]
mod playground_strict;
#[path = "../pre311_except_handler_continuation_recompile.rs"]
mod pre311_except_handler_continuation_recompile;
#[path = "../pre311_guarded_finally_recompile.rs"]
mod pre311_guarded_finally_recompile;
#[path = "../pre311_if_else_loop_recompile.rs"]
mod pre311_if_else_loop_recompile;
#[path = "../pre311_loop_try_recompile.rs"]
mod pre311_loop_try_recompile;
#[path = "../pre311_sibling_guard_before_try_recompile.rs"]
mod pre311_sibling_guard_before_try_recompile;
#[path = "../pre311_terminating_guard_with_recompile.rs"]
mod pre311_terminating_guard_with_recompile;
#[path = "../published_whole_module_figure.rs"]
mod published_whole_module_figure;
#[path = "../py313_base_events_guarded_loop.rs"]
mod py313_base_events_guarded_loop;
#[path = "../py313_codec_none_ternary.rs"]
mod py313_codec_none_ternary;
#[path = "../py_decompile_311.rs"]
mod py_decompile_311;
#[path = "../py_decompile_314.rs"]
mod py_decompile_314;
#[path = "../py_decompile_38.rs"]
mod py_decompile_38;
#[path = "../pypy_compat.rs"]
mod pypy_compat;
#[path = "../register_standard_browsers.rs"]
mod register_standard_browsers;
#[path = "../rotated_while_try_handler_break_auto.rs"]
mod rotated_while_try_handler_break_auto;
#[path = "../roundtrip_adversarial.rs"]
mod roundtrip_adversarial;
#[path = "../roundtrip_codediff_handler_swap.rs"]
mod roundtrip_codediff_handler_swap;
#[path = "../roundtrip_const_pool_reorder.rs"]
mod roundtrip_const_pool_reorder;
#[path = "../roundtrip_metric.rs"]
mod roundtrip_metric;
#[path = "../roundtrip_perfect.rs"]
mod roundtrip_perfect;
#[path = "../roundtrip_recurses_nested.rs"]
mod roundtrip_recurses_nested;
#[path = "../roundtrip_semantic_arg.rs"]
mod roundtrip_semantic_arg;
#[path = "../roundtrip_semantic_nop_padding.rs"]
mod roundtrip_semantic_nop_padding;
#[path = "../roundtrip_semantic_super_instr.rs"]
mod roundtrip_semantic_super_instr;
#[path = "../sequential_loops_recompile.rs"]
mod sequential_loops_recompile;
#[path = "../shared_exit_loop_try_recompile.rs"]
mod shared_exit_loop_try_recompile;
#[path = "../store_target_recovery.rs"]
mod store_target_recovery;
#[path = "../strict_tier_differential.rs"]
mod strict_tier_differential;
#[path = "../structuring_behaviour_strict.rs"]
mod structuring_behaviour_strict;
#[path = "../trailing_guard_recompile.rs"]
mod trailing_guard_recompile;
#[path = "../try_else_tail_recompile.rs"]
mod try_else_tail_recompile;
#[path = "../try_region_forward_jump_recompile.rs"]
mod try_region_forward_jump_recompile;
#[path = "../tstring_decode_proof.rs"]
mod tstring_decode_proof;
#[path = "../tstring_leading_literal_controlflow.rs"]
mod tstring_leading_literal_controlflow;
#[path = "../version_matrix.rs"]
mod version_matrix;
#[path = "../while_true_multi_exit.rs"]
mod while_true_multi_exit;
#[path = "../with_body_try_region_recompile.rs"]
mod with_body_try_region_recompile;
#[path = "../with_recompile.rs"]
mod with_recompile;
#[path = "../with_region_input_space.rs"]
mod with_region_input_space;
