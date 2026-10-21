#![allow(clippy::duplicate_mod)]

#[path = "../common/mod.rs"]
mod common;

#[path = "../support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

#[path = "../bcompiler_read.rs"]
mod bcompiler_read;
#[path = "../blackbird_detect.rs"]
mod blackbird_detect;
#[path = "../debug_framework.rs"]
mod debug_framework;
#[path = "../decompile_oparray.rs"]
mod decompile_oparray;
#[path = "../deflatten_behavioral.rs"]
mod deflatten_behavioral;
#[path = "../fopo_peel.rs"]
mod fopo_peel;
#[path = "../fuzz_resilience.rs"]
mod fuzz_resilience;
#[path = "../generated_differential.rs"]
mod generated_differential;
#[path = "../ioncube_decode.rs"]
mod ioncube_decode;
#[path = "../ioncube_detect.rs"]
mod ioncube_detect;
#[path = "../ioncube_synthetic_envelope_detect.rs"]
mod ioncube_synthetic_envelope_detect;
#[path = "../key_extractor.rs"]
mod key_extractor;
#[path = "../loader_behavioral.rs"]
mod loader_behavioral;
#[path = "../obfuscation_info_php.rs"]
mod obfuscation_info_php;
#[path = "../oparray_behavioral.rs"]
mod oparray_behavioral;
#[path = "../oparray_chain.rs"]
mod oparray_chain;
#[path = "../opcache_file_reader.rs"]
mod opcache_file_reader;
#[path = "../peel_lossless_families.rs"]
mod peel_lossless_families;
#[path = "../phar_archive_quota.rs"]
mod phar_archive_quota;
#[path = "../phar_decompression_bomb.rs"]
mod phar_decompression_bomb;
#[path = "../phar_extract.rs"]
mod phar_extract;
#[path = "../php_array_and_foreach_differential.rs"]
mod php_array_and_foreach_differential;
#[path = "../php_behaviour_strict.rs"]
mod php_behaviour_strict;
#[path = "../php_cipher_wrapper_differential.rs"]
mod php_cipher_wrapper_differential;
#[path = "../php_decode_loop_differential.rs"]
mod php_decode_loop_differential;
#[path = "../php_encoder_online.rs"]
mod php_encoder_online;
#[path = "../php_eval_chain_peel.rs"]
mod php_eval_chain_peel;
#[path = "../php_list_destructuring_differential.rs"]
mod php_list_destructuring_differential;
#[path = "../php_loop_jump_differential.rs"]
mod php_loop_jump_differential;
#[path = "../php_octal_charcode_recovery.rs"]
mod php_octal_charcode_recovery;
#[path = "../php_precedence_eval.rs"]
mod php_precedence_eval;
#[path = "../php_real_chain_recovery.rs"]
mod php_real_chain_recovery;
#[path = "../php_real_chain_recovery_ext.rs"]
mod php_real_chain_recovery_ext;
#[path = "../php_recursive_helper_differential.rs"]
mod php_recursive_helper_differential;
#[path = "../php_runtime_differential.rs"]
mod php_runtime_differential;
#[path = "../php_source_detect.rs"]
mod php_source_detect;
#[path = "../php_str_indirect.rs"]
mod php_str_indirect;
#[path = "../php_token_parse.rs"]
mod php_token_parse;
#[path = "../php_try_catch_differential.rs"]
mod php_try_catch_differential;
#[path = "../php_variadic_differential.rs"]
mod php_variadic_differential;
#[path = "../php_webshell_sigs.rs"]
mod php_webshell_sigs;
#[path = "../pipeline_recover.rs"]
mod pipeline_recover;
#[path = "../protector_container_lift.rs"]
mod protector_container_lift;
#[path = "../real_better_php_obf.rs"]
mod real_better_php_obf;
#[path = "../real_phar.rs"]
mod real_phar;
#[path = "../restructure_behavioral.rs"]
mod restructure_behavioral;
#[path = "../smuggler_detect.rs"]
mod smuggler_detect;
#[path = "../sourceguardian_decode.rs"]
mod sourceguardian_decode;
#[path = "../sourceguardian_detect.rs"]
mod sourceguardian_detect;
#[path = "../sourceguardian_synthetic_envelope_detect.rs"]
mod sourceguardian_synthetic_envelope_detect;
#[path = "../zend_guard_decode.rs"]
mod zend_guard_decode;
#[path = "../zend_guard_detect.rs"]
mod zend_guard_detect;
#[path = "../zend_guard_synthetic_envelope_detect.rs"]
mod zend_guard_synthetic_envelope_detect;
