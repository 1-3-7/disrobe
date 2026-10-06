#![allow(clippy::duplicate_mod)]

#[path = "../apk_e2e.rs"]
mod apk_e2e;

#[path = "../arm_decode_boundary_reference.rs"]
mod arm_decode_boundary_reference;

#[path = "../as3_source_emit.rs"]
mod as3_source_emit;

#[path = "../auto_anti_analysis.rs"]
mod auto_anti_analysis;

#[path = "../auto_apk_dex.rs"]
mod auto_apk_dex;

#[path = "../auto_appimage_type1.rs"]
mod auto_appimage_type1;

#[path = "../auto_arc_dynamic_lzw.rs"]
mod auto_arc_dynamic_lzw;

#[path = "../auto_arc_fixed_lzw.rs"]
mod auto_arc_fixed_lzw;

#[path = "../auto_arj.rs"]
mod auto_arj;

#[path = "../auto_batch_dir.rs"]
mod auto_batch_dir;

#[path = "../auto_chain_routing.rs"]
mod auto_chain_routing;

#[path = "../auto_confuser_dotnet.rs"]
mod auto_confuser_dotnet;

#[path = "../auto_d8_captured_lambda.rs"]
mod auto_d8_captured_lambda;

#[path = "../auto_d8_constructor_delegate.rs"]
mod auto_d8_constructor_delegate;

#[path = "../auto_d8_core_library.rs"]
mod auto_d8_core_library;

#[path = "../auto_dalvik_feature_gate.rs"]
mod auto_dalvik_feature_gate;

#[path = "../auto_dalvik_symbol_export.rs"]
mod auto_dalvik_symbol_export;

#[path = "../auto_default_tree.rs"]
mod auto_default_tree;

#[path = "../auto_dotnet_refused_method.rs"]
mod auto_dotnet_refused_method;

#[path = "../auto_electron_js.rs"]
mod auto_electron_js;

#[path = "../auto_enigma.rs"]
mod auto_enigma;

#[path = "../auto_erofs.rs"]
mod auto_erofs;

#[path = "../auto_flutter_aot_routing.rs"]
mod auto_flutter_aot_routing;

#[path = "../auto_flutter_symbol_export.rs"]
mod auto_flutter_symbol_export;

#[path = "../auto_flutter_symbol_literal.rs"]
mod auto_flutter_symbol_literal;

#[path = "../auto_full_python_chain.rs"]
mod auto_full_python_chain;

#[path = "../auto_innosetup.rs"]
mod auto_innosetup;

#[path = "../auto_installshield.rs"]
mod auto_installshield;

#[path = "../auto_js_commonjs_param.rs"]
mod auto_js_commonjs_param;

#[path = "../auto_js_iife_param.rs"]
mod auto_js_iife_param;

#[path = "../auto_js_system_register_param.rs"]
mod auto_js_system_register_param;

#[path = "../auto_jvm_kotlin_finally.rs"]
mod auto_jvm_kotlin_finally;

#[path = "../auto_lzh_level3.rs"]
mod auto_lzh_level3;

#[path = "../auto_native_instruction_coverage.rs"]
mod auto_native_instruction_coverage;

#[path = "../auto_native_trap_guard.rs"]
mod auto_native_trap_guard;

#[path = "../auto_node_sea_bytenode.rs"]
mod auto_node_sea_bytenode;

#[path = "../auto_out_dir_ownership.rs"]
mod auto_out_dir_ownership;

#[path = "../auto_pe_upx_rust.rs"]
mod auto_pe_upx_rust;

#[path = "../auto_plain_native_image.rs"]
mod auto_plain_native_image;

#[path = "../auto_python_loop_try.rs"]
mod auto_python_loop_try;

#[path = "../auto_rar.rs"]
mod auto_rar;

#[path = "../auto_rn_hermes.rs"]
mod auto_rn_hermes;

#[path = "../auto_rpm.rs"]
mod auto_rpm;

#[path = "../auto_shell_walls.rs"]
mod auto_shell_walls;

#[path = "../auto_stuffit_method13.rs"]
mod auto_stuffit_method13;

#[path = "../auto_stuffit_method5.rs"]
mod auto_stuffit_method5;

#[path = "../auto_stuffit_method8.rs"]
mod auto_stuffit_method8;

#[path = "../auto_stuffit5.rs"]
mod auto_stuffit5;

#[path = "../auto_uefi_fv.rs"]
mod auto_uefi_fv;

#[path = "../auto_windows_script_routing.rs"]
mod auto_windows_script_routing;

#[path = "../behavior_effects.rs"]
mod behavior_effects;

#[path = "../benign_attribution_gate.rs"]
mod benign_attribution_gate;

#[path = "../binary_resolution_is_target_dir_agnostic.rs"]
mod binary_resolution_is_target_dir_agnostic;

#[cfg(feature = "full")]
#[path = "../chain_goldens.rs"]
mod chain_goldens;

#[path = "../chain_integration.rs"]
mod chain_integration;

#[cfg(feature = "full")]
#[path = "../chain_real_extractors.rs"]
mod chain_real_extractors;

#[path = "../cli_dry_run_global.rs"]
mod cli_dry_run_global;

#[cfg(feature = "full")]
#[path = "../cli_e2e.rs"]
mod cli_e2e;

#[path = "../cli_emit_universal.rs"]
mod cli_emit_universal;

#[path = "../cli_force.rs"]
mod cli_force;

#[path = "../cli_in_place.rs"]
mod cli_in_place;

#[path = "../cli_llm_e2e.rs"]
mod cli_llm_e2e;

#[path = "../cli_luau_opcode_map.rs"]
mod cli_luau_opcode_map;

#[path = "../cli_no_cache.rs"]
mod cli_no_cache;

#[path = "../cli_out_final_symlink.rs"]
mod cli_out_final_symlink;

#[path = "../cli_progress.rs"]
mod cli_progress;

#[path = "../cli_threads.rs"]
mod cli_threads;

#[cfg(feature = "wasm")]
#[path = "../cli_wasm_boundary_links.rs"]
mod cli_wasm_boundary_links;

#[cfg(feature = "wasm")]
#[path = "../cli_wasm_target_c.rs"]
mod cli_wasm_target_c;

#[cfg(feature = "wasm")]
#[path = "../cli_wasm_target_rust.rs"]
mod cli_wasm_target_rust;

#[cfg(feature = "wasm")]
#[path = "../cli_wasm_target_ts.rs"]
mod cli_wasm_target_ts;

#[cfg(feature = "wasm")]
#[path = "../cli_wasm_target_wat.rs"]
mod cli_wasm_target_wat;

#[path = "../cli_webview_carve.rs"]
mod cli_webview_carve;

#[path = "../config_cli_e2e.rs"]
mod config_cli_e2e;

#[path = "../container_breadth.rs"]
mod container_breadth;

#[cfg(feature = "native")]
#[path = "../cyclonedx_emit.rs"]
mod cyclonedx_emit;

#[path = "../determinism_cross_platform.rs"]
mod determinism_cross_platform;

#[cfg(feature = "mobile")]
#[path = "../discord_e2e.rs"]
mod discord_e2e;

#[path = "../disrobe_diff.rs"]
mod disrobe_diff;

#[path = "../disrobe_guard_deny.rs"]
mod disrobe_guard_deny;

#[path = "../dotnet_decompile_deobfuscate.rs"]
mod dotnet_decompile_deobfuscate;

#[path = "../dotnet_native_aot_cli.rs"]
mod dotnet_native_aot_cli;

#[path = "../dotnet_single_file.rs"]
mod dotnet_single_file;

#[path = "../envelope_cli_e2e.rs"]
mod envelope_cli_e2e;

#[path = "../flutter_decompile_aot.rs"]
mod flutter_decompile_aot;

#[path = "../flutter_engine_fallback_identity.rs"]
mod flutter_engine_fallback_identity;

#[path = "../flutter_symbol_export.rs"]
mod flutter_symbol_export;

#[path = "../frisk_redact.rs"]
mod frisk_redact;

#[path = "../github_meta_yaml.rs"]
mod github_meta_yaml;

#[cfg(feature = "server")]
#[path = "../grpc_e2e.rs"]
mod grpc_e2e;

#[path = "../helper_subcommands_e2e.rs"]
mod helper_subcommands_e2e;

#[path = "../hermes_function_disasm.rs"]
mod hermes_function_disasm;

#[path = "../identify_byte_coverage.rs"]
mod identify_byte_coverage;

#[path = "../identify_wasm_byte_coverage.rs"]
mod identify_wasm_byte_coverage;

#[path = "../js_sourcemap_path_containment.rs"]
mod js_sourcemap_path_containment;

#[path = "../js_unbundle_sourcemap_emit.rs"]
mod js_unbundle_sourcemap_emit;

#[path = "../js_v8_carve.rs"]
mod js_v8_carve;

#[path = "../jvm_dalvik_symbol_export.rs"]
mod jvm_dalvik_symbol_export;

#[path = "../jvm_dex_native_decompile.rs"]
mod jvm_dex_native_decompile;

#[path = "../jvm_dex2jar.rs"]
mod jvm_dex2jar;

#[path = "../jvm_jar_native_decompile.rs"]
mod jvm_jar_native_decompile;

#[path = "../jvm_jni_link.rs"]
mod jvm_jni_link;

#[path = "../jvm_mapping_restore.rs"]
mod jvm_mapping_restore;

#[path = "../jvm_protector_peel.rs"]
mod jvm_protector_peel;

#[path = "../llm_agents_md.rs"]
mod llm_agents_md;

#[path = "../llm_claude_settings.rs"]
mod llm_claude_settings;

#[path = "../llm_recovery_json.rs"]
mod llm_recovery_json;

#[path = "../llm_skill_packs.rs"]
mod llm_skill_packs;

#[path = "../llm_slash_commands.rs"]
mod llm_slash_commands;

#[path = "../luks1_extract.rs"]
mod luks1_extract;

#[path = "../native_aarch64_dense_switch.rs"]
mod native_aarch64_dense_switch;

#[path = "../native_aarch64_scalar_fp.rs"]
mod native_aarch64_scalar_fp;

#[path = "../native_aarch64_simd_memory.rs"]
mod native_aarch64_simd_memory;

#[path = "../native_arch_routing.rs"]
mod native_arch_routing;

#[path = "../native_decode_coverage.rs"]
mod native_decode_coverage;

#[cfg(feature = "native")]
#[path = "../native_delphi.rs"]
mod native_delphi;

#[path = "../native_diff_e2e.rs"]
mod native_diff_e2e;

#[path = "../native_export_ghidra.rs"]
mod native_export_ghidra;

#[path = "../native_match_e2e.rs"]
mod native_match_e2e;

#[path = "../native_pdb_cxx_headers.rs"]
mod native_pdb_cxx_headers;

#[path = "../native_pdb_provenance.rs"]
mod native_pdb_provenance;

#[path = "../native_perfunction_coverage.rs"]
mod native_perfunction_coverage;

#[path = "../native_unbind_report.rs"]
mod native_unbind_report;

#[path = "../native_unpack_chain_notice.rs"]
mod native_unpack_chain_notice;

#[path = "../out_stage_mirror.rs"]
mod out_stage_mirror;

#[path = "../playground_gate.rs"]
mod playground_gate;

#[cfg(feature = "plugin")]
#[path = "../plugin_e2e.rs"]
mod plugin_e2e;

#[path = "../py_auto_deob_e2e.rs"]
mod py_auto_deob_e2e;

#[path = "../py_decompile_headline.rs"]
mod py_decompile_headline;

#[path = "../py_decompile_native.rs"]
mod py_decompile_native;

#[cfg(feature = "py")]
#[path = "../pyarmor_bcc_cli_surface.rs"]
mod pyarmor_bcc_cli_surface;

#[path = "../pyarmor_bcc_static.rs"]
mod pyarmor_bcc_static;

#[path = "../query_cli_e2e.rs"]
mod query_cli_e2e;

#[path = "../query_jvm_implementors.rs"]
mod query_jvm_implementors;

#[path = "../recon_redact_e2e.rs"]
mod recon_redact_e2e;

#[path = "../report_cli_e2e.rs"]
mod report_cli_e2e;

#[path = "../report_forensic_e2e.rs"]
mod report_forensic_e2e;

#[path = "../sarif_emit.rs"]
mod sarif_emit;

#[path = "../scan_full_value_surfaces.rs"]
mod scan_full_value_surfaces;

#[path = "../self_update_check_only.rs"]
mod self_refresh_check_only;

#[path = "../semdiff_e2e.rs"]
mod semdiff_e2e;

#[cfg(feature = "server")]
#[path = "../serve_http_e2e.rs"]
mod serve_http_e2e;

#[cfg(feature = "server")]
#[path = "../serve_stdio_protocol_e2e.rs"]
mod serve_stdio_protocol_e2e;

#[path = "../sig_native_crypto.rs"]
mod sig_native_crypto;

#[path = "../slim_network_bail.rs"]
mod slim_network_bail;

#[path = "../slim_wasm_bail.rs"]
mod slim_wasm_bail;

#[path = "../spdx_openvex_emit.rs"]
mod spdx_openvex_emit;

#[path = "../vulnmatch_cli_e2e.rs"]
mod vulnmatch_cli_e2e;

#[path = "../yara_loader.rs"]
mod yara_loader;
