#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_dotnet::{DecompiledAssembly, StructuredMethod, decompile_assembly};

const EDGECASES_DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const MONEY_EQUALS_VALUE: u32 = 0x0600_00E8;
const MONEY_EQUALS_OBJECT: u32 = 0x0600_00E9;
const MONEY_GET_HASH_CODE: u32 = 0x0600_00EA;
const MONEY_TO_STRING: u32 = 0x0600_00EB;

fn edgecases() -> DecompiledAssembly {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(EDGECASES_DLL);
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read fixture: {error}"));
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn money_header(assembly: &DecompiledAssembly, token: u32) -> &str {
    let method: &StructuredMethod = assembly
        .methods
        .iter()
        .find(|method: &&StructuredMethod| method.token == token)
        .unwrap_or_else(|| panic!("Money MethodDef 0x{token:08X} not found"));
    let mut lines: std::str::Lines<'_> = method.signature.lines();
    let declaring_type: &str = lines
        .next()
        .unwrap_or_else(|| panic!("Money MethodDef 0x{token:08X} has no declaring type"));
    assert_eq!(
        declaring_type, "// EdgeCases.Money",
        "MethodDef 0x{token:08X} moved away from EdgeCases.Money"
    );
    let header: &str = lines
        .next()
        .unwrap_or_else(|| panic!("Money MethodDef 0x{token:08X} has no C# header"));
    assert!(
        lines.next().is_none(),
        "Money MethodDef 0x{token:08X} has a malformed signature: {}",
        method.signature
    );
    header
}

#[test]
fn money_headers_follow_value_type_slot_metadata() {
    let assembly: DecompiledAssembly = edgecases();
    let equals_object: &str = money_header(&assembly, MONEY_EQUALS_OBJECT);
    let get_hash_code: &str = money_header(&assembly, MONEY_GET_HASH_CODE);
    let to_string: &str = money_header(&assembly, MONEY_TO_STRING);
    let equals_value: &str = money_header(&assembly, MONEY_EQUALS_VALUE);

    assert_eq!(equals_object, "public override bool Equals(object obj)");
    assert_eq!(get_hash_code, "public override int GetHashCode()");
    assert_eq!(to_string, "public override string ToString()");
    assert_eq!(equals_value, "public bool Equals(EdgeCases.Money other)");
    assert!(
        !equals_value.contains("override") && !equals_value.contains("sealed"),
        "the final new-slot interface implementation must remain a plain method: {equals_value}"
    );
}
