use disrobe_pass_native::{Error, LeafRecovery, PseudoAbi, Result, recover_leaf_function_abi};

const BOUNDARY: u64 = 0x0040_1000;

#[test]
fn declared_int3_boundary_is_refused_with_its_byte_and_address() -> Result<()> {
    let code: [u8; 4] = [0xcc, 0x04, 0x11, 0xc3];
    let result: Result<LeafRecovery> = recover_leaf_function_abi(&code, BOUNDARY, PseudoAbi::MsX64);
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
