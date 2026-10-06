#![allow(clippy::duplicate_mod)]

#[path = "../common/mod.rs"]
mod common;

#[path = "../adversarial_resilience.rs"]
mod adversarial_resilience;
#[path = "../agile_net.rs"]
mod agile_net;
#[path = "../aot_native_containers.rs"]
mod aot_native_containers;
#[path = "../armdot.rs"]
mod armdot;
#[path = "../array_literal_rendering.rs"]
mod array_literal_rendering;
#[path = "../async_state_machine_recovery.rs"]
mod async_state_machine_recovery;
#[path = "../await_foreach_movenext_recovery.rs"]
mod await_foreach_movenext_recovery;
#[path = "../babel_dotnet.rs"]
mod babel_dotnet;
#[path = "../backing_field_rendering.rs"]
mod backing_field_rendering;
#[path = "../bitmono_gauntlet.rs"]
mod bitmono_gauntlet;
#[path = "../bitmono_string_recovery.rs"]
mod bitmono_string_recovery;
#[path = "../bool_return_rendering.rs"]
mod bool_return_rendering;
#[path = "../cast_width_sign_oracle.rs"]
mod cast_width_sign_oracle;
#[path = "../cff_deflatten.rs"]
mod cff_deflatten;
#[path = "../cfg_empty_body_regression.rs"]
mod cfg_empty_body_regression;
#[path = "../cha_devirtualization.rs"]
mod cha_devirtualization;
#[path = "../cil_disasm.rs"]
mod cil_disasm;
#[path = "../cil_integer_reference.rs"]
mod cil_integer_reference;
#[path = "../cil_pe_parse.rs"]
mod cil_pe_parse;
#[path = "../cil_to_csharp.rs"]
mod cil_to_csharp;
#[path = "../cil_to_fsharp.rs"]
mod cil_to_fsharp;
#[path = "../cil_to_vbnet.rs"]
mod cil_to_vbnet;
#[path = "../confuserex2_full.rs"]
mod confuserex2_full;
#[path = "../confuserex2_gauntlet.rs"]
mod confuserex2_gauntlet;
#[path = "../crypto_obfuscator.rs"]
mod crypto_obfuscator;
#[path = "../csharp_behaviour_strict.rs"]
mod csharp_behaviour_strict;
#[path = "../debug_framework.rs"]
mod debug_framework;
#[path = "../deepsea.rs"]
mod deepsea;
#[path = "../default_feature_boundary.rs"]
mod default_feature_boundary;
#[path = "../devirt.rs"]
mod devirt;
#[path = "../devirt_byte_stack.rs"]
mod devirt_byte_stack;
#[path = "../devirt_cil_handler.rs"]
mod devirt_cil_handler;
#[path = "../devirt_emit.rs"]
mod devirt_emit;
#[path = "../devirt_model_ref.rs"]
mod devirt_model_ref;
#[path = "../devirt_oracle.rs"]
mod devirt_oracle;
#[path = "../devirt_real_corpus.rs"]
mod devirt_real_corpus;
#[path = "../devirt_structure.rs"]
mod devirt_structure;
#[path = "../dotfuscator.rs"]
mod dotfuscator;
#[path = "../dotfuscator_ce.rs"]
mod dotfuscator_ce;
#[path = "../dotnet_de4dot.rs"]
mod dotnet_de4dot;
#[path = "../dotnet_dnspy.rs"]
mod dotnet_dnspy;
#[path = "../dotnet_ilspy.rs"]
mod dotnet_ilspy;
#[path = "../dotnet_native_aot.rs"]
mod dotnet_native_aot;
#[path = "../dotnet_patcher_netcryptor.rs"]
mod dotnet_patcher_netcryptor;
#[path = "../dotnet_reactor.rs"]
mod dotnet_reactor;
#[path = "../dotnet_reactor_strings.rs"]
mod dotnet_reactor_strings;
#[path = "../dotnet_versions.rs"]
mod dotnet_versions;
#[path = "../eazfuscator.rs"]
mod eazfuscator;
#[path = "../eazfuscator_string_emu.rs"]
mod eazfuscator_string_emu;
#[path = "../edgecases_syntax_regressions.rs"]
mod edgecases_syntax_regressions;
#[path = "../fuzz_decode_never_panics.rs"]
mod fuzz_decode_never_panics;
#[path = "../fuzz_subparsers.rs"]
mod fuzz_subparsers;
#[path = "../generated_differential.rs"]
mod generated_differential;
#[path = "../generic_type_recompile_oracle.rs"]
mod generic_type_recompile_oracle;
#[path = "../goliath_dotnet.rs"]
mod goliath_dotnet;
#[path = "../hostile_metadata_names.rs"]
mod hostile_metadata_names;
#[path = "../ilprotector_resource_emu.rs"]
mod ilprotector_resource_emu;
#[path = "../iterator_stub_rendering.rs"]
mod iterator_stub_rendering;
#[path = "../keyword_param_oracle.rs"]
mod keyword_param_oracle;
#[path = "../lambda_rendering.rs"]
mod lambda_rendering;
#[path = "../linq_chain_rendering.rs"]
mod linq_chain_rendering;
#[path = "../linq_syntax_regressions.rs"]
mod linq_syntax_regressions;
#[path = "../maxtocode_section_emu.rs"]
mod maxtocode_section_emu;
#[path = "../methodimpl_shapes.rs"]
mod methodimpl_shapes;
#[path = "../movenext_recompile_oracle.rs"]
mod movenext_recompile_oracle;
#[path = "../native_aot_chain.rs"]
mod native_aot_chain;
#[path = "../native_aot_invoke_map.rs"]
mod native_aot_invoke_map;
#[path = "../native_aot_managed_abi.rs"]
mod native_aot_managed_abi;
#[path = "../native_aot_method_boundaries.rs"]
mod native_aot_method_boundaries;
#[path = "../native_aot_names_coverage.rs"]
mod native_aot_names_coverage;
#[path = "../native_aot_net10.rs"]
mod native_aot_net10;
#[path = "../native_aot_net7.rs"]
mod native_aot_net7;
#[path = "../native_aot_param.rs"]
mod native_aot_param;
#[path = "../native_aot_real_image.rs"]
mod native_aot_real_image;
#[path = "../native_aot_sret.rs"]
mod native_aot_sret;
#[path = "../native_not_applicable_corpus.rs"]
mod native_not_applicable_corpus;
#[path = "../native_stub_surface.rs"]
mod native_stub_surface;
#[path = "../null_conditional_direct_instance_call.rs"]
mod null_conditional_direct_instance_call;
#[path = "../null_conditional_early_return.rs"]
mod null_conditional_early_return;
#[path = "../obfuscar.rs"]
mod obfuscar;
#[path = "../obfuscar_gauntlet.rs"]
mod obfuscar_gauntlet;
#[path = "../operator_special_names.rs"]
mod operator_special_names;
#[path = "../param_indirection.rs"]
mod param_indirection;
#[path = "../pe_parse_resilience.rs"]
mod pe_parse_resilience;
#[path = "../property_and_typeof_rendering.rs"]
mod property_and_typeof_rendering;
#[path = "../real_baseline.rs"]
mod real_baseline;
#[path = "../real_confuserex2.rs"]
mod real_confuserex2;
#[path = "../real_confuserex2_resources.rs"]
mod real_confuserex2_resources;
#[path = "../real_eazvm.rs"]
mod real_eazvm;
#[path = "../real_koivm.rs"]
mod real_koivm;
#[path = "../real_native_aot.rs"]
mod real_native_aot;
#[path = "../real_obfuscar.rs"]
mod real_obfuscar;
#[path = "../real_peel.rs"]
mod real_peel;
#[path = "../real_r2r.rs"]
mod real_r2r;
#[path = "../recompile_oracle.rs"]
mod recompile_oracle;
#[path = "../record_struct_recovery.rs"]
mod record_struct_recovery;
#[path = "../retained_value_type_isinst.rs"]
mod retained_value_type_isinst;
#[cfg(feature = "semantic-reach")]
#[path = "../seed_reach.rs"]
mod seed_reach;
#[path = "../skater_net.rs"]
mod skater_net;
#[path = "../skater_strings.rs"]
mod skater_strings;
#[path = "../smartassembly.rs"]
mod smartassembly;
#[path = "../smartassembly_resources.rs"]
mod smartassembly_resources;
#[path = "../smartassembly_strings.rs"]
mod smartassembly_strings;
#[path = "../spices_net.rs"]
mod spices_net;
#[path = "../spices_recovery.rs"]
mod spices_recovery;
#[path = "../stack_spill_before_store.rs"]
mod stack_spill_before_store;
#[path = "../state_machine_loop_recovery.rs"]
mod state_machine_loop_recovery;
#[path = "../state_machine_reweave_loop_body.rs"]
mod state_machine_reweave_loop_body;
#[path = "../stock_control_no_false_positive.rs"]
mod stock_control_no_false_positive;
#[path = "../string_evidence_roster.rs"]
mod string_evidence_roster;
#[path = "../support_label_evidence.rs"]
mod support_label_evidence;
#[path = "../themida_dotnet.rs"]
mod themida_dotnet;
#[path = "../tuple_literal_rendering.rs"]
mod tuple_literal_rendering;
#[path = "../type_fidelity.rs"]
mod type_fidelity;
#[path = "../unsigned_overflow_fixture.rs"]
mod unsigned_overflow_fixture;
#[path = "../value_type_isinst_rendering.rs"]
mod value_type_isinst_rendering;
#[path = "../value_type_override_rendering.rs"]
mod value_type_override_rendering;
#[path = "../whole_type_il_equivalence_oracle.rs"]
mod whole_type_il_equivalence_oracle;
