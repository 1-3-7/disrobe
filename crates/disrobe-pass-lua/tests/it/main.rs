#![allow(clippy::duplicate_mod)]

#[path = "../common/mod.rs"]
mod common;

#[path = "../support/dvm1_reference.rs"]
#[allow(
    dead_code,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_pub_crate,
    clippy::unwrap_used
)]
mod dvm1_reference;

#[path = "../support/lua_toolchain.rs"]
#[allow(
    dead_code,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_pub_crate,
    clippy::unwrap_used
)]
mod lua_toolchain;

#[path = "../support/prometheus_residue.rs"]
#[allow(
    dead_code,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_pub_crate,
    clippy::unwrap_used
)]
mod prometheus_residue;

#[path = "../aztup_brew.rs"]
mod aztup_brew;
#[path = "../bool_chain_reexec_oracle.rs"]
mod bool_chain_reexec_oracle;
#[path = "../boronide.rs"]
mod boronide;
#[path = "../darksec.rs"]
mod darksec;
#[path = "../debug_framework.rs"]
mod debug_framework;
#[path = "../decompile_fidelity_metric.rs"]
mod decompile_fidelity_metric;
#[path = "../dialect_operand_reexec_oracle.rs"]
mod dialect_operand_reexec_oracle;
#[path = "../division_modulo_reexec_oracle.rs"]
mod division_modulo_reexec_oracle;
#[path = "../float_type_recovery.rs"]
mod float_type_recovery;
#[path = "../fuzz_decode_never_panics.rs"]
mod fuzz_decode_never_panics;
#[path = "../generated_differential.rs"]
mod generated_differential;
#[path = "../glua_quirks.rs"]
mod glua_quirks;
#[path = "../hercules_gauntlet.rs"]
mod hercules_gauntlet;
#[path = "../hercules_real.rs"]
mod hercules_real;
#[path = "../ironbrew2.rs"]
mod ironbrew2;
#[path = "../ironbrew2_lzw_bomb.rs"]
mod ironbrew2_lzw_bomb;
#[path = "../ironbrew2_real_oracle.rs"]
mod ironbrew2_real_oracle;
#[path = "../ironbrew_literal_reexec.rs"]
mod ironbrew_literal_reexec;
#[path = "../lift_work_budget.rs"]
mod lift_work_budget;
#[path = "../lua_51_decompile.rs"]
mod lua_51_decompile;
#[path = "../lua_51_reader.rs"]
mod lua_51_reader;
#[path = "../lua_52_reader.rs"]
mod lua_52_reader;
#[path = "../lua_53_reader.rs"]
mod lua_53_reader;
#[path = "../lua_54_reader.rs"]
mod lua_54_reader;
#[path = "../lua_55_reader.rs"]
mod lua_55_reader;
#[path = "../luajit_decompile_oracle.rs"]
mod luajit_decompile_oracle;
#[path = "../luajit_lift_real.rs"]
mod luajit_lift_real;
#[path = "../luajit_reader.rs"]
mod luajit_reader;
#[path = "../luaobfuscator_com.rs"]
mod luaobfuscator_com;
#[path = "../luaobfuscator_com_real.rs"]
mod luaobfuscator_com_real;
#[path = "../luau_behaviour_reexec.rs"]
mod luau_behaviour_reexec;
#[path = "../luau_debug_break.rs"]
mod luau_debug_break;
#[path = "../luau_decompile_oracle.rs"]
mod luau_decompile_oracle;
#[path = "../luau_opcode_map.rs"]
mod luau_opcode_map;
#[path = "../luau_reader.rs"]
mod luau_reader;
#[path = "../luau_shared_dag_bomb.rs"]
mod luau_shared_dag_bomb;
#[path = "../luau_template_refusal.rs"]
mod luau_template_refusal;
#[path = "../luraph.rs"]
mod luraph;
#[path = "../luvit_extract.rs"]
mod luvit_extract;
#[path = "../moonsec_v1.rs"]
mod moonsec_v1;
#[path = "../moonsec_v1_loader.rs"]
mod moonsec_v1_loader;
#[path = "../moonsec_v2.rs"]
mod moonsec_v2;
#[path = "../moonsec_v3.rs"]
mod moonsec_v3;
#[path = "../negative_corpus.rs"]
mod negative_corpus;
#[path = "../precedence_reexec_oracle.rs"]
mod precedence_reexec_oracle;
#[path = "../prometheus_gauntlet.rs"]
mod prometheus_gauntlet;
#[path = "../prometheus_lua.rs"]
mod prometheus_lua;
#[path = "../prometheus_runner_presets.rs"]
mod prometheus_runner_presets;
#[path = "../prometheus_vmlift_oracle.rs"]
mod prometheus_vmlift_oracle;
#[path = "../psu.rs"]
mod psu;
#[path = "../published_lua_vm_devirt_legs.rs"]
mod published_lua_vm_devirt_legs;
#[path = "../published_luau_opcode_roster.rs"]
mod published_luau_opcode_roster;
#[path = "../real_dead_upstream_stubs.rs"]
mod real_dead_upstream_stubs;
#[path = "../real_decompile_5x_megafile.rs"]
mod real_decompile_5x_megafile;
#[path = "../real_decompile_megafile.rs"]
mod real_decompile_megafile;
#[path = "../real_luac_hello.rs"]
mod real_luac_hello;
#[path = "../real_luac_megafile.rs"]
mod real_luac_megafile;
#[path = "../real_luajit_megafile.rs"]
mod real_luajit_megafile;
#[path = "../real_luau_decompile.rs"]
mod real_luau_decompile;
#[path = "../real_luau_megafile.rs"]
mod real_luau_megafile;
#[path = "../real_prometheus_megafile.rs"]
mod real_prometheus_megafile;
#[path = "../recompile_oracle.rs"]
mod recompile_oracle;
#[path = "../reexec_diff_oracle.rs"]
mod reexec_diff_oracle;
#[path = "../reserved_field_access.rs"]
mod reserved_field_access;
#[path = "../resilience.rs"]
mod resilience;
#[path = "../string_escape_roundtrip.rs"]
mod string_escape_roundtrip;
#[path = "../structuring_floor_oracle.rs"]
mod structuring_floor_oracle;
#[path = "../unity_slua_roundtrip.rs"]
mod unity_slua_roundtrip;
#[path = "../vm_devirt_ironbrew.rs"]
mod vm_devirt_ironbrew;
#[path = "../vm_families_devirt.rs"]
mod vm_families_devirt;
#[path = "../wearedevs_luau.rs"]
mod wearedevs_luau;
#[path = "../wearedevs_luau_real.rs"]
mod wearedevs_luau_real;
