#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/dvm1_reference.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dvm1_reference;

use std::fmt::Write as _;

use disrobe_pass_lua::decompile::lift::{LiftedProto, lift_proto_dialect};
use disrobe_pass_lua::obfuscator::vm_devirt::{
    BootstrapKeys, DevirtReport, Devirtualized, VM_KIND_IRONBREW2, devirtualize,
};
use disrobe_pass_lua::reader::common::{LuaDialect, LuaProto};
use dvm1_reference::{
    CANONICAL_HANDLERS, PermRecipe, VmModule, assert_no_answer_key_in_bootstrap,
    build_permutation_program, encode_module, encoded_for_vop, known_module, reference_encoded,
    render_bootstrap, solved_permutation, to_hex, to_lua_byte_table, to_lua_decimal_escape,
    vop_for_index,
};

#[test]
fn devirt_recovers_handlers_and_constants() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x1357_2468,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("recipe sets the xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let dv: Devirtualized = devirtualize(&payload, &bootstrap).expect("devirtualize");
    let report: &DevirtReport = &dv.report;

    assert_eq!(report.kind, VM_KIND_IRONBREW2);
    assert_eq!(report.xor_key, xor_key);
    assert_eq!(
        report.handlers_recovered, report.handlers_total,
        "every distinct VM opcode handler must be mapped to a canonical op"
    );
    assert_eq!(
        report.opcodes_lifted, report.opcodes_total,
        "every VM instruction must lift to a Lua 5.1 instruction"
    );
    assert_eq!(report.constants_decoded, 3);
}

#[test]
fn devirt_recovers_exact_lua51_code_stream() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x0042_0042,
        step: 7,
        base: 0x50,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("recipe sets the xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let dv: Devirtualized = devirtualize(&payload, &bootstrap).expect("devirtualize");
    let proto: &LuaProto = &dv.proto;

    assert_eq!(proto.num_params, module.num_params);
    assert_eq!(proto.is_vararg, module.is_vararg);
    assert_eq!(proto.constants, module.constants);
    assert_eq!(proto.code.len(), module.code.len());

    let getglobal: u32 = proto.code[0];
    assert_eq!(getglobal & 0x3F, 5, "first op must be GETGLOBAL (5)");
    let call: u32 = proto.code[4];
    assert_eq!(call & 0x3F, 28, "fifth op must be CALL (28)");
    let ret: u32 = proto.code[5];
    assert_eq!(ret & 0x3F, 30, "sixth op must be RETURN (30)");
}

#[test]
fn recovered_permutation_is_a_real_permutation_not_identity() {
    let recipe: PermRecipe = PermRecipe {
        seed: 0x1357_2468,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    assert_eq!(
        keys.opmap.len(),
        CANONICAL_HANDLERS.len(),
        "emulation must derive a distinct encoded slot per handler"
    );
    let mut permuted: usize = 0;
    for (idx, canon) in CANONICAL_HANDLERS.iter().enumerate() {
        let encoded: u8 = encoded_for_vop(&keys.opmap, *canon);
        assert_eq!(
            encoded,
            reference_encoded(idx as u32, &recipe),
            "the emulator must reproduce the arithmetic recipe exactly"
        );
        if u32::from(encoded) != u32::from(vop_for_index(idx)) {
            permuted += 1;
        }
    }
    assert!(
        permuted >= 4,
        "the runtime-derived table must genuinely permute the opcodes, not be the identity"
    );
}

#[test]
fn changing_the_seed_changes_what_recovery_yields() {
    let module: VmModule = known_module();
    let base: PermRecipe = PermRecipe {
        seed: 0x1111_2222,
        step: 9,
        base: 0x30,
        key_mask: 0xFF,
    };
    let base_keys: BootstrapKeys = solved_permutation(&base);
    let base_xor: u8 = base_keys.xor_key.expect("xor key");
    let base_payload: Vec<u8> = encode_module(&module, &base_keys.opmap, base_xor);
    let base_boot: String = render_bootstrap(&base, "-- IronBrew2\nIRONBREW_VM");

    let altered: PermRecipe = PermRecipe {
        seed: 0x3333_4444,
        ..base
    };
    let altered_keys: BootstrapKeys = solved_permutation(&altered);
    let altered_boot: String = render_bootstrap(&altered, "-- IronBrew2\nIRONBREW_VM");

    assert_ne!(
        base_keys.opmap, altered_keys.opmap,
        "a different runtime seed must produce a different opcode permutation"
    );

    let with_base_boot: Devirtualized =
        devirtualize(&base_payload, &base_boot).expect("matching seed devirtualizes cleanly");
    assert_eq!(
        with_base_boot.proto.code[0] & 0x3F,
        5,
        "with the correct seed the first op resolves to GETGLOBAL"
    );

    let wrong_seed_result: Result<Devirtualized, _> = devirtualize(&base_payload, &altered_boot);
    match wrong_seed_result {
        Err(_) => {}
        Ok(wrong) => {
            assert_ne!(
                with_base_boot.proto.code, wrong.proto.code,
                "decoding under a table derived from the wrong seed must diverge from the correct decode, proving the seed is load-bearing"
            );
        }
    }
}

#[test]
fn devirt_lifts_to_readable_lua_print_and_arithmetic() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x7F7F_7F7F,
        step: 13,
        base: 0x60,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let dv: Devirtualized = devirtualize(&payload, &bootstrap).expect("devirtualize");
    let lifted: LiftedProto = lift_proto_dialect(&dv.proto, LuaDialect::Lua51, 0);

    assert!(
        lifted.source.contains("print"),
        "recovered lua must call print:\n{}",
        lifted.source
    );
    assert!(
        lifted.source.contains('+'),
        "recovered lua must contain the 40 + 2 addition:\n{}",
        lifted.source
    );
}

#[test]
fn devirt_rejects_payload_without_magic() {
    let recipe: PermRecipe = PermRecipe {
        seed: 1,
        step: 3,
        base: 5,
        key_mask: 0xFF,
    };
    let bogus: Vec<u8> = vec![0u8; 32];
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert!(devirtualize(&bogus, &bootstrap).is_err());
}

#[test]
fn devirt_fails_when_init_program_absent() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x2222_3333,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap_without_recipe: &str = "-- IronBrew2\nIRONBREW_VM\nSEED=999\n";
    assert!(
        devirtualize(&payload, bootstrap_without_recipe).is_err(),
        "without the bootstrap init program there is no answer key to read, so devirt must fail rather than guess"
    );
}

#[test]
fn ironbrew2_peel_devirtualizes_embedded_payload() {
    use disrobe_pass_lua::ironbrew2;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x4242_4242,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let mut bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);
    let _ = writeln!(bootstrap, "VMPAYLOAD={} ", to_hex(&payload));

    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = ironbrew2::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        result.fully_recovered,
        "ironbrew2 peel must fully devirtualize the embedded vm payload; markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(recovered.contains("print"), "recovered:\n{recovered}");
    assert!(
        result
            .recovered_strings
            .iter()
            .any(|s: &String| s == "print")
    );
}

#[test]
fn moonsec_v3_peel_devirtualizes_embedded_payload() {
    use disrobe_pass_lua::moonsec_v3;
    use disrobe_pass_lua::obfuscator::vm_devirt::VM_KIND_MOONSEC;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let _ = VM_KIND_MOONSEC;
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x6B6B_6B6B,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let mut bootstrap: String = render_bootstrap(&recipe, "-- MoonSec v3\nMS_VM_ENTRY");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);
    let _ = writeln!(bootstrap, "VMPAYLOAD={} ", to_hex(&payload));

    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = moonsec_v3::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        result.fully_recovered,
        "moonsec v3 peel must fully devirtualize a statically embedded vm payload; markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(recovered.contains("print"), "recovered:\n{recovered}");
}

#[test]
fn moonsec_v3_peel_devirtualizes_lua_table_wrapper() {
    use disrobe_pass_lua::moonsec_v3;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x3C3C_4444,
        step: 13,
        base: 0x50,
        key_mask: 0xFF,
    };
    let program: Vec<u8> = build_permutation_program(&recipe);
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = format!(
        "-- MoonSec v3\nMS_VM_ENTRY()\nlocal MS_VM_SEED = 0x{:08X}\nlocal MS_VM_BUILDER = {{{}}}\nlocal MS_VM_PAYLOAD = \"{}\"\n",
        recipe.seed,
        to_lua_byte_table(&program),
        to_lua_decimal_escape(&payload)
    );
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = moonsec_v3::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        result.fully_recovered,
        "moonsec v3 lua table wrapper must fully devirtualize; markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(recovered.contains("print"), "recovered:\n{recovered}");
}

#[test]
fn ironbrew2_peel_without_payload_is_honest_passthrough() {
    use disrobe_pass_lua::ironbrew2;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let recipe: PermRecipe = PermRecipe {
        seed: 0x1010_1010,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = ironbrew2::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        !result.fully_recovered,
        "no embedded payload means no honest full recovery"
    );
    assert!(!result.residual_markers.is_empty());
}
