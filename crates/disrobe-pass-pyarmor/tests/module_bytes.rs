use disrobe_pass_pyarmor::{
    Error, PyarmorVersion, UnpackedModule, detect_from_wrapper, unpack_module_bytes,
};

const WRAPPER: &str =
    include_str!("../../../corpus/python/pyarmor/v9_latest_925/default/known_plaintext.py");
const RUNTIME: &[u8] = include_bytes!(
    "../../../corpus/python/pyarmor/v9_latest_925/default/pyarmor_runtime_000000/pyarmor_runtime.pyd"
);

#[test]
fn only_standard_protection_reaches_runtime_processing() -> Result<(), Box<dyn std::error::Error>> {
    let (_, mut payload): (_, Vec<u8>) = detect_from_wrapper(WRAPPER)?;
    for protection in [0_u32, 1, 0x108, u32::MAX] {
        payload[20..24].copy_from_slice(&protection.to_le_bytes());
        assert!(
            matches!(unpack_module_bytes(&payload, &[]), Err(Error::ModuleProtectionUnsupported(value)) if value == protection)
        );
    }
    payload[20..24].copy_from_slice(&9_u32.to_le_bytes());
    assert!(matches!(
        unpack_module_bytes(&payload, &[]),
        Err(Error::BccPartialOnly)
    ));
    payload[20..24].copy_from_slice(&8_u32.to_le_bytes());
    assert!(matches!(
        unpack_module_bytes(&payload, &[]),
        Err(Error::KeyExtraction(_))
    ));
    Ok(())
}

#[test]
fn runtime_serial_and_explicit_version_must_match() -> Result<(), Box<dyn std::error::Error>> {
    let (_, mut payload): (_, Vec<u8>) = detect_from_wrapper(WRAPPER)?;
    payload[2..8].copy_from_slice(b"008000");
    assert!(
        matches!(unpack_module_bytes(&payload, RUNTIME), Err(Error::ModuleRuntimeMismatch { payload, runtime }) if payload == "008000" && runtime == "000000")
    );
    let mut runtime: Vec<u8> = RUNTIME.to_vec();
    let anchor: usize = runtime
        .windows(11)
        .position(|window| window == b"pyarmor-vax")
        .ok_or("missing runtime marker")?;
    runtime[anchor + 12..anchor + 18].copy_from_slice(b"008000");
    assert!(matches!(
        unpack_module_bytes(&payload, &runtime),
        Err(Error::ModuleVersionMismatch {
            payload: 8,
            runtime: 9
        })
    ));
    runtime[anchor - 8..anchor - 4].copy_from_slice(&99_u32.to_le_bytes());
    assert!(matches!(
        unpack_module_bytes(&payload, &runtime),
        Err(Error::ModuleRuntimeUnsupported)
    ));
    Ok(())
}

#[test]
fn trial_serial_uses_the_runtime_descriptor() -> Result<(), Box<dyn std::error::Error>> {
    let (_, payload): (_, Vec<u8>) = detect_from_wrapper(WRAPPER)?;
    let module: UnpackedModule = unpack_module_bytes(&payload, RUNTIME)?;
    assert_eq!(module.runtime_version, PyarmorVersion::V9);
    assert_eq!(module.header.serial.as_deref(), Some("000000"));
    assert_eq!(module.header.python_major, Some(3));
    assert_eq!(module.header.python_minor, Some(14));
    assert_eq!(module.header.pyc_magic, Some(0x0e2b));
    assert!(!module.bytes.is_empty());
    Ok(())
}
