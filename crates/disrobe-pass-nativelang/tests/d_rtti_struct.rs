#![cfg(feature = "chain")]

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_nativelang::chain_detector::{NATIVELANG_PASS, PASS_ID};
use object::{Object, ObjectSymbol};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

const STRIPPED: &[u8] = include_bytes!("fixtures/d_rtti_struct/rtti_families.stripped.exe");
const REFERENCE_OBJECT: &[u8] = include_bytes!("fixtures/d_rtti_struct/rtti_families.obj");
const PACKET_TYPEINFO: &str = "_D32TypeInfo_S13rtti_families6Packet6__initZ";

fn recovered_names(payload: &[u8]) -> Result<Vec<String>, Box<dyn Error>> {
    let report: serde_json::Value = serde_json::from_slice(payload)?;
    let symbols: &Vec<serde_json::Value> = report["demangled_symbols"]
        .as_array()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing demangled symbol array"))?;
    Ok(symbols
        .iter()
        .filter_map(|symbol: &serde_json::Value| symbol["demangled"].as_str().map(str::to_owned))
        .collect())
}

#[test]
fn registered_pass_recovers_dmd_struct_rtti_from_a_stripped_pe() -> Result<(), Box<dyn Error>> {
    assert_eq!(PASS_ID, "nativelang.classify");
    let reference: object::File<'_> = object::File::parse(REFERENCE_OBJECT)?;
    assert!(
        reference
            .symbols()
            .any(|symbol: object::Symbol<'_, '_>| { symbol.name().ok() == Some(PACKET_TYPEINFO) })
    );
    let stripped: object::File<'_> = object::File::parse(STRIPPED)?;
    assert_eq!(stripped.architecture(), object::Architecture::X86_64);
    assert!(
        !stripped
            .symbols()
            .any(|symbol: object::Symbol<'_, '_>| { symbol.name().ok() == Some(PACKET_TYPEINFO) })
    );

    let input: Artifact = Artifact::new(Rung::Raw, STRIPPED.to_vec(), [0_u8; 32]);
    let first: Artifact = NATIVELANG_PASS.run(&input)?;
    let second: Artifact = NATIVELANG_PASS.run(&input)?;
    assert_eq!(first.rung, Rung::Surface);
    assert_eq!(first.envelope, second.envelope);

    let names: Vec<String> = recovered_names(&first.envelope)?;
    assert!(
        names
            .iter()
            .any(|name: &String| name == "rtti_families.Holder")
    );
    assert!(
        names
            .iter()
            .any(|name: &String| name == "rtti_families.Packet")
    );
    Ok(())
}
