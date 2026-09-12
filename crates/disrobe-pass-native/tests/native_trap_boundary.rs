use disrobe_pass_native::{
    Error, LeafRecovery, PseudoAbi, Result, recover_leaf_function_abi,
    recover_leaf_function_in_object, recover_leaf_function_switch_abi,
    recover_vectorized_reduction,
};

const BOUNDARY: u64 = 0x0040_1000;

#[test]
fn declared_int3_boundary_is_refused_with_its_byte_and_address() -> Result<()> {
    let code: [u8; 4] = [0xcc, 0x04, 0x11, 0xc3];
    let result: Result<LeafRecovery> = recover_leaf_function_abi(&code, BOUNDARY, PseudoAbi::MsX64);
    assert_declared_boundary_trap(result)
}

#[test]
fn every_public_x86_leaf_recovery_route_refuses_a_leading_int3() -> Result<()> {
    let code: [u8; 4] = [0xcc, 0x04, 0x11, 0xc3];

    assert_declared_boundary_trap(recover_vectorized_reduction(
        &code,
        BOUNDARY,
        PseudoAbi::MsX64,
    ))?;
    assert_declared_boundary_trap(recover_leaf_function_switch_abi(
        &code,
        BOUNDARY,
        PseudoAbi::MsX64,
        &[],
    ))?;
    assert_declared_boundary_trap(recover_leaf_function_in_object(
        &[],
        &code,
        BOUNDARY,
        PseudoAbi::MsX64,
        &[],
    ))
}

#[test]
fn invalid_abi_precedes_declared_boundary_classification() -> Result<()> {
    let code: [u8; 4] = [0xcc, 0x04, 0x11, 0xc3];
    let result: Result<LeafRecovery> =
        recover_leaf_function_abi(&code, BOUNDARY, PseudoAbi::Aapcs64);

    match result {
        Err(Error::LlvmIr(message))
            if message == "aapcs64 requires the aarch64 recovery entry point" =>
        {
            Ok(())
        }
        Err(error) => Err(Error::LlvmIr(format!(
            "invalid ABI must precede boundary classification: {error}"
        ))),
        Ok(recovery) => Err(Error::LlvmIr(format!(
            "invalid ABI unexpectedly recovered a leaf: {recovery:?}"
        ))),
    }
}

#[test]
fn interior_padding_and_trailing_int3_remain_liftable() {
    let interior: [u8; 8] = [0x48, 0x89, 0xc8, 0x90, 0x48, 0x01, 0xd0, 0xc3];
    let trailing: [u8; 5] = [0x48, 0x89, 0xc8, 0xc3, 0xcc];

    let interior_recovery: Result<LeafRecovery> =
        recover_leaf_function_abi(&interior, BOUNDARY, PseudoAbi::MsX64);
    let trailing_recovery: Result<LeafRecovery> =
        recover_leaf_function_abi(&trailing, BOUNDARY, PseudoAbi::MsX64);

    assert!(interior_recovery.is_ok(), "{interior_recovery:?}");
    assert!(trailing_recovery.is_ok(), "{trailing_recovery:?}");
}

fn assert_declared_boundary_trap(result: Result<LeafRecovery>) -> Result<()> {
    let error: Error = match result {
        Err(error) => error,
        Ok(recovery) => {
            return Err(Error::LlvmIr(format!(
                "an int3 at the declared method boundary was recovered: {recovery:?}"
            )));
        }
    };
    assert_eq!(
        error.to_string(),
        "DR-NATIVE-0029: declared function boundary 0x0000000000401000 starts with trap byte 0xCC"
    );
    assert!(matches!(
        error,
        Error::DeclaredFunctionBoundaryTrap {
            boundary: BOUNDARY,
            observed: 0xcc
        }
    ));
    Ok(())
}
