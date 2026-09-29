#[path = "../common/mod.rs"]
mod common;
#[path = "../support/compiler_toolchain.rs"]
#[allow(clippy::panic, clippy::redundant_pub_crate)]
mod compiler_toolchain;
#[path = "../support/object_symbol.rs"]
#[allow(clippy::redundant_pub_crate)]
mod object_symbol;
#[path = "../support/prerequisite.rs"]
#[allow(clippy::panic, clippy::redundant_pub_crate, dead_code)]
mod prerequisite;
#[path = "../support/vm_layout_generator.rs"]
mod vm_layout_generator;

mod aarch64_const_division_oracle;
mod abi_inference_oracle;
mod api_hash_oracle;
mod copyprop_oracle;
mod ebpf_oracle;
mod emu_strings_memdelta_oracle;
mod ignored_tests_are_classified;
mod native_recompile_matrix;
mod native_typed_locals_oracle;
mod pseudo_c_const_division_oracle;
mod pseudo_c_effect_spill_grade;
mod pseudo_c_leaf_oracle;
mod pseudo_c_operand_registers;
mod pseudo_c_wholeprog_oracle;
mod pseudo_rust_leaf_oracle;
mod pseudo_rust_wholeprog_oracle;
mod return_channel_corpus;
mod setcc_registers;
mod simd_devirt_oracle;
mod stack_string_oracle;
mod vm_devirt_oracle;
mod vm_layout_generator_grade;
