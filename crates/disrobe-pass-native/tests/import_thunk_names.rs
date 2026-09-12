#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items
)]

use disrobe_pass_native::backend_export::{
    render_ghidra_postscript, render_idapython, render_symbol_map_json,
};
use disrobe_pass_native::lang::{
    FunctionNameConfidence, FunctionNameEvidenceSource, InputByteRange, sanitize_function_name,
};
use disrobe_pass_native::pseudo_c::{
    Abi, NamedRecoveredProgram, ProgramFunction, RecoveredProgram, recover_program,
    recover_program_with_naming,
};
use disrobe_pass_native::sig_engine::{FunctionNameSubject, resolved_import_thunk_names};

const PE: &[u8] = include_bytes!("../../../corpus/native/formats/hello.pe64.exe");
const NAMED_THUNK_ADDRESS: u64 = 0x1_4000_3200;
const NAMED_THUNK_FILE_START: usize = 0x2600;
const NAMED_THUNK_FILE_END: usize = 0x2606;
const FORWARDER_ADDRESS: u64 = 0x1_4000_16be;
const FORWARDER_FILE_START: usize = 0xabe;
const FORWARDER_FILE_END: usize = 0xac5;
const IMPORT_STUB_ADDRESS: u64 = 0x1_4000_3208;
const IMPORT_STUB_FILE_START: usize = 0x2608;
const IMPORT_STUB_FILE_END: usize = 0x260e;
const LOCAL_JUMP_ADDRESS: u64 = 0x1_4000_1041;
const LOCAL_JUMP_FILE_START: usize = 0x441;
const LOCAL_JUMP_FILE_END: usize = 0x443;

fn subject(name: &str, address: u64, range: core::ops::Range<usize>) -> ProgramFunction {
    ProgramFunction {
        name: name.to_owned(),
        address,
        code: PE[range].to_vec(),
    }
}

#[test]
fn native_caller_recovers_the_resolved_import_thunk_name_and_exports_it() {
    assert_eq!(
        &PE[NAMED_THUNK_FILE_START..NAMED_THUNK_FILE_END],
        &[0xff, 0x25, 0xc2, 0x80, 0x00, 0x00]
    );
    let functions: [ProgramFunction; 1] = [subject(
        "sub_140003200",
        NAMED_THUNK_ADDRESS,
        NAMED_THUNK_FILE_START..NAMED_THUNK_FILE_END,
    )];

    let first: NamedRecoveredProgram = recover_program_with_naming(PE, &functions, Abi::MsX64);
    let second: NamedRecoveredProgram = recover_program_with_naming(PE, &functions, Abi::MsX64);
    let existing_caller: RecoveredProgram = recover_program(PE, &functions, Abi::MsX64);

    assert_eq!(first, second);
    assert_eq!(existing_caller, first.program);
    assert_eq!(first.names.len(), 1);
    let recovered_name = &first.names[0];
    assert_eq!(recovered_name.function_address, NAMED_THUNK_ADDRESS);
    assert_eq!(recovered_name.name, "GetLastError");
    assert_eq!(
        recovered_name.evidence.confidence,
        FunctionNameConfidence::High
    );
    assert_eq!(
        recovered_name.evidence.source,
        FunctionNameEvidenceSource::ImportThunk
    );
    assert_eq!(
        recovered_name.evidence.input_bytes,
        InputByteRange {
            start: NAMED_THUNK_FILE_START as u64,
            end: NAMED_THUNK_FILE_END as u64,
        }
    );
    assert_eq!(recovered_name.evidence.target_address, 0x1_4000_b2c8);
    assert!(recovered_name.evidence.target_is_indirect);
    let function = first
        .program
        .recovered
        .iter()
        .find(|function| function.address == NAMED_THUNK_ADDRESS)
        .unwrap_or_else(|| {
            panic!(
                "resolved thunk must reach recovered pseudo-C: {:?}",
                first.program.unrecovered
            )
        });
    assert_eq!(function.name, "GetLastError");
    assert!(function.source.contains(" GetLastError("));
    assert!(function.source.contains("0x14000b2c8ULL"));
    assert_eq!(function.return_width_bits, 32);
    assert!(function.signature.parameter_bindings().is_empty());

    assert_eq!(
        function.name_evidence.as_ref(),
        Some(&recovered_name.evidence)
    );
    let json: String = render_symbol_map_json(&existing_caller).expect("render JSON export");
    let ghidra: String = render_ghidra_postscript(&existing_caller).expect("render Ghidra export");
    let ida: String = render_idapython(&existing_caller).expect("render IDA export");
    assert!(json.contains("\"name\": \"GetLastError\""));
    assert!(json.contains("\"kind\": \"function-name-evidence\""));
    assert!(json.contains("high"));
    assert!(json.contains("import-thunk"));
    assert!(ghidra.contains("GetLastError"));
    assert!(ida.contains("GetLastError"));
}

#[test]
fn duplicate_import_identity_abstains_for_every_colliding_function() {
    assert_eq!(
        &PE[IMPORT_STUB_FILE_START..IMPORT_STUB_FILE_END],
        &[0xff, 0x25, 0xb2, 0x80, 0x00, 0x00]
    );
    let functions: [ProgramFunction; 2] = [
        subject(
            "sub_1400016be",
            FORWARDER_ADDRESS,
            FORWARDER_FILE_START..FORWARDER_FILE_END,
        ),
        subject(
            "sub_140003208",
            IMPORT_STUB_ADDRESS,
            IMPORT_STUB_FILE_START..IMPORT_STUB_FILE_END,
        ),
    ];
    let subjects: Vec<FunctionNameSubject<'_>> =
        functions.iter().map(FunctionNameSubject::from).collect();

    assert!(resolved_import_thunk_names(PE, &subjects).is_empty());
}

#[test]
fn unresolved_jump_abstains() {
    assert_eq!(
        &PE[LOCAL_JUMP_FILE_START..LOCAL_JUMP_FILE_END],
        &[0xeb, 0x0a]
    );
    let unresolved: ProgramFunction = subject(
        "sub_140001041",
        LOCAL_JUMP_ADDRESS,
        LOCAL_JUMP_FILE_START..LOCAL_JUMP_FILE_END,
    );
    let unresolved_subject: FunctionNameSubject<'_> = FunctionNameSubject::from(&unresolved);
    assert!(resolved_import_thunk_names(PE, &[unresolved_subject]).is_empty());
}

#[test]
fn real_exported_symbol_is_not_replaced_by_the_import_identity() {
    let mut exported_thunk: Vec<u8> = PE.to_vec();
    exported_thunk[0x4428..0x442c].copy_from_slice(&0x3200_u32.to_le_bytes());
    let real: ProgramFunction = ProgramFunction {
        name: "disrobe_compute".to_owned(),
        address: NAMED_THUNK_ADDRESS,
        code: exported_thunk[NAMED_THUNK_FILE_START..NAMED_THUNK_FILE_END].to_vec(),
    };
    let real_subject: FunctionNameSubject<'_> = FunctionNameSubject::from(&real);
    assert!(resolved_import_thunk_names(&exported_thunk, &[real_subject]).is_empty());

    let recovered: NamedRecoveredProgram =
        recover_program_with_naming(&exported_thunk, &[real], Abi::MsX64);
    assert!(recovered.names.is_empty());
    assert!(recovered.program.unrecovered.iter().any(|function| {
        function.address == NAMED_THUNK_ADDRESS && function.name == "disrobe_compute"
    }));
}

#[test]
fn ordinary_real_function_has_no_import_thunk_name() {
    let real: ProgramFunction = subject("disrobe_compute", 0x1_4000_16d0, 0xad0..0xad4);
    let real_subject: FunctionNameSubject<'_> = FunctionNameSubject::from(&real);
    assert!(resolved_import_thunk_names(PE, &[real_subject]).is_empty());
}

#[test]
fn import_identifier_sanitization_is_stable_and_valid() {
    assert_eq!(
        sanitize_function_name("9puts@@GLIBC_2.2.5"),
        Some("_9puts_GLIBC_2_2_5".to_owned())
    );
    assert_eq!(sanitize_function_name("///"), None);
}
