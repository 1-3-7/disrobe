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
    FunctionNameConfidence, FunctionNameEvidenceSource, InputByteRange,
};
use disrobe_pass_native::pseudo_c::{
    Abi, NamedRecoveredProgram, ProgramFunction, RecoveredProgram, recover_program,
    recover_program_with_naming,
};
use disrobe_pass_native::sig_engine::{FunctionNameSubject, exported_function_names};
use object::{Object, ObjectSymbol};

const PE: &[u8] = include_bytes!("../../../corpus/native/formats/hello.pe64.exe");
const FUNCTION_ADDRESS: u64 = 0x1_4000_16d0;
const FUNCTION_FILE_START: usize = 0xad0;
const FUNCTION_FILE_END: usize = 0xadc;
const EXPORT_NAME_START: usize = 0x4441;
const EXPORT_NAME_END: usize = 0x4450;
const ELF_STRIPPED: &[u8] =
    include_bytes!("../../disrobe-typerec/tests/fixtures/heap_corpus.stripped.so");
const ELF_UNSTRIPPED: &[u8] =
    include_bytes!("../../disrobe-typerec/tests/fixtures/heap_corpus.unstripped.so");
const ELF_FILL_ADDRESS: u64 = 0x13d0;
const ELF_FILL_FILE_START: usize = 0x3d0;
const ELF_FILL_FILE_END: usize = 0x43a;
const ELF_FILL_NAME_START: usize = 0x335;
const ELF_FILL_NAME_END: usize = 0x339;

fn subject(name: &str) -> ProgramFunction {
    ProgramFunction {
        name: name.to_owned(),
        address: FUNCTION_ADDRESS,
        code: PE[FUNCTION_FILE_START..FUNCTION_FILE_END].to_vec(),
    }
}

fn subject_at(image: &[u8], name: &str, address: u64, file_offset: usize) -> ProgramFunction {
    ProgramFunction {
        name: name.to_owned(),
        address,
        code: image[file_offset..=file_offset].to_vec(),
    }
}

fn write_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn replace_export_name(raw_name: &[u8]) -> Vec<u8> {
    assert!(raw_name.len() < EXPORT_NAME_END - EXPORT_NAME_START);
    let mut image: Vec<u8> = PE.to_vec();
    image[EXPORT_NAME_START..=EXPORT_NAME_END].fill(0);
    image[EXPORT_NAME_START..EXPORT_NAME_START + raw_name.len()].copy_from_slice(raw_name);
    image
}

fn two_export_image(
    first_address_rva: u32,
    second_address_rva: u32,
    first_name: &[u8],
    second_name: &[u8],
) -> Vec<u8> {
    const TABLE_START: usize = 0x4460;
    const NAME_POINTERS_START: usize = 0x4468;
    const ORDINALS_START: usize = 0x4470;
    const FIRST_NAME_START: usize = 0x4480;
    let second_name_start: usize = FIRST_NAME_START + first_name.len() + 1;
    let mut image: Vec<u8> = PE.to_vec();
    write_u32(&mut image, 0x4414, 2);
    write_u32(&mut image, 0x4418, 2);
    write_u32(&mut image, 0x441c, 0xa060);
    write_u32(&mut image, 0x4420, 0xa068);
    write_u32(&mut image, 0x4424, 0xa070);
    write_u32(&mut image, TABLE_START, first_address_rva);
    write_u32(&mut image, TABLE_START + 4, second_address_rva);
    write_u32(&mut image, NAME_POINTERS_START, 0xa080);
    write_u32(
        &mut image,
        NAME_POINTERS_START + 4,
        0xa000 + u32::try_from(second_name_start - 0x4400).expect("fixture RVA fits"),
    );
    image[ORDINALS_START..ORDINALS_START + 2].copy_from_slice(&0_u16.to_le_bytes());
    image[ORDINALS_START + 2..ORDINALS_START + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[FIRST_NAME_START..FIRST_NAME_START + first_name.len()].copy_from_slice(first_name);
    image[second_name_start..second_name_start + second_name.len()].copy_from_slice(second_name);
    image
}

#[test]
fn native_caller_recovers_exported_function_name_with_typed_evidence() {
    assert_eq!(&PE[EXPORT_NAME_START..EXPORT_NAME_END], b"disrobe_compute");
    let functions: [ProgramFunction; 1] = [subject("sub_1400016d0")];

    let first: NamedRecoveredProgram = recover_program_with_naming(PE, &functions, Abi::MsX64);
    let second: NamedRecoveredProgram = recover_program_with_naming(PE, &functions, Abi::MsX64);
    let existing_caller: RecoveredProgram = recover_program(PE, &functions, Abi::MsX64);

    assert_eq!(first, second);
    assert_eq!(existing_caller, first.program);
    assert_eq!(first.names.len(), 1);
    let recovered_name = &first.names[0];
    assert_eq!(recovered_name.function_address, FUNCTION_ADDRESS);
    assert_eq!(recovered_name.name, "disrobe_compute");
    assert_eq!(
        recovered_name.evidence.confidence,
        FunctionNameConfidence::High
    );
    assert_eq!(
        recovered_name.evidence.source,
        FunctionNameEvidenceSource::ExportedName
    );
    assert_eq!(
        recovered_name.evidence.input_bytes,
        InputByteRange {
            start: EXPORT_NAME_START as u64,
            end: EXPORT_NAME_END as u64,
        }
    );
    assert_eq!(recovered_name.evidence.identity, "disrobe_compute");
    assert_eq!(recovered_name.evidence.target_address, FUNCTION_ADDRESS);
    assert!(!recovered_name.evidence.target_is_indirect);

    let recovered_function = first
        .program
        .recovered
        .iter()
        .find(|function| function.address == FUNCTION_ADDRESS)
        .unwrap_or_else(|| panic!("exported function must recover: {first:?}"));
    assert_eq!(recovered_function.name, "disrobe_compute");
    assert!(recovered_function.source.contains(" disrobe_compute("));
    assert_eq!(
        recovered_function.name_evidence.as_ref(),
        Some(&recovered_name.evidence)
    );

    let json: String = render_symbol_map_json(&existing_caller).expect("render JSON export");
    let repeated_json: String =
        render_symbol_map_json(&second).expect("render repeated JSON export");
    let ghidra: String = render_ghidra_postscript(&existing_caller).expect("render Ghidra export");
    let ida: String = render_idapython(&existing_caller).expect("render IDA export");
    assert!(json.contains("\"name\": \"disrobe_compute\""));
    assert!(json.contains("exported-name"));
    assert_eq!(json.as_bytes(), repeated_json.as_bytes());
    assert!(ghidra.contains("disrobe_compute"));
    assert!(ida.contains("disrobe_compute"));
}

#[test]
fn exported_identifier_is_sanitized_before_reaching_the_caller() {
    let image: Vec<u8> = replace_export_name(b"9bad-name");
    let function: ProgramFunction = subject_at(&image, "sub_1400016d0", FUNCTION_ADDRESS, 0xad0);
    let recovered: NamedRecoveredProgram =
        recover_program_with_naming(&image, &[function], Abi::MsX64);

    assert_eq!(recovered.names.len(), 1);
    assert_eq!(recovered.names[0].name, "_9bad_name");
    assert_eq!(recovered.names[0].evidence.identity, "9bad-name");
    assert_eq!(
        recovered.names[0].evidence.input_bytes,
        InputByteRange {
            start: EXPORT_NAME_START as u64,
            end: (EXPORT_NAME_START + 9) as u64,
        }
    );
}

#[test]
fn exported_api_name_does_not_turn_the_function_into_an_import_thunk() {
    let image: Vec<u8> = replace_export_name(b"GetLastError");
    let function: ProgramFunction = subject("sub_1400016d0");
    let recovered: NamedRecoveredProgram =
        recover_program_with_naming(&image, &[function], Abi::MsX64);
    let recovered_function = recovered
        .program
        .recovered
        .iter()
        .find(|candidate| candidate.address == FUNCTION_ADDRESS)
        .unwrap_or_else(|| panic!("exported function must recover: {recovered:?}"));

    assert_eq!(recovered_function.name, "GetLastError");
    assert!(
        !recovered_function
            .source
            .contains("disrobe_import_target_t")
    );
    assert!(recovered_function.source.contains(" GetLastError("));
}

#[test]
fn existing_function_name_wins_over_export_evidence() {
    let functions: [ProgramFunction; 1] = [subject("ground_truth_name")];
    let recovered: NamedRecoveredProgram = recover_program_with_naming(PE, &functions, Abi::MsX64);

    assert!(recovered.names.is_empty());
    assert!(
        recovered
            .program
            .recovered
            .iter()
            .any(|function| function.name == "ground_truth_name")
    );
}

#[test]
fn duplicate_export_address_and_sanitized_name_abstain() {
    let duplicate_address: Vec<u8> =
        two_export_image(0x16d0, 0x16d0, b"first_name", b"second_name");
    let one_function: [ProgramFunction; 1] = [subject_at(
        &duplicate_address,
        "sub_1400016d0",
        FUNCTION_ADDRESS,
        0xad0,
    )];
    let one_subject: Vec<FunctionNameSubject<'_>> =
        one_function.iter().map(FunctionNameSubject::from).collect();
    assert!(exported_function_names(&duplicate_address, &one_subject).is_empty());

    let duplicate_name: Vec<u8> = two_export_image(0x16d0, 0x16e0, b"shared-name", b"shared_name");
    let two_functions: [ProgramFunction; 2] = [
        subject_at(&duplicate_name, "sub_1400016d0", FUNCTION_ADDRESS, 0xad0),
        subject_at(&duplicate_name, "sub_1400016e0", 0x1_4000_16e0, 0xae0),
    ];
    let two_subjects: Vec<FunctionNameSubject<'_>> = two_functions
        .iter()
        .map(FunctionNameSubject::from)
        .collect();
    assert!(exported_function_names(&duplicate_name, &two_subjects).is_empty());
}

#[test]
fn invalid_export_evidence_abstains() {
    let mut non_text: Vec<u8> = PE.to_vec();
    write_u32(&mut non_text, 0x4428, 0x4000);
    let non_text_function: [ProgramFunction; 1] = [subject_at(
        &non_text,
        "sub_140004000",
        0x1_4000_4000,
        0x2800,
    )];
    let non_text_subject: Vec<FunctionNameSubject<'_>> = non_text_function
        .iter()
        .map(FunctionNameSubject::from)
        .collect();
    assert!(exported_function_names(&non_text, &non_text_subject).is_empty());

    let mut malformed: Vec<u8> = PE.to_vec();
    write_u32(&mut malformed, 0x442c, u32::MAX);
    let malformed_function: [ProgramFunction; 1] = [subject_at(
        &malformed,
        "sub_1400016d0",
        FUNCTION_ADDRESS,
        0xad0,
    )];
    let malformed_subject: Vec<FunctionNameSubject<'_>> = malformed_function
        .iter()
        .map(FunctionNameSubject::from)
        .collect();
    assert!(exported_function_names(&malformed, &malformed_subject).is_empty());

    let empty_name: Vec<u8> = replace_export_name(b"");
    let empty_function: [ProgramFunction; 1] = [subject_at(
        &empty_name,
        "sub_1400016d0",
        FUNCTION_ADDRESS,
        0xad0,
    )];
    let empty_subject: Vec<FunctionNameSubject<'_>> = empty_function
        .iter()
        .map(FunctionNameSubject::from)
        .collect();
    assert!(exported_function_names(&empty_name, &empty_subject).is_empty());

    let mut addressless: Vec<u8> = PE.to_vec();
    write_u32(&mut addressless, 0x4428, 0);
    let addressless_function: [ProgramFunction; 1] = [subject_at(
        &addressless,
        "sub_140000000",
        0x1_4000_0000,
        0x400,
    )];
    let addressless_subject: Vec<FunctionNameSubject<'_>> = addressless_function
        .iter()
        .map(FunctionNameSubject::from)
        .collect();
    assert!(exported_function_names(&addressless, &addressless_subject).is_empty());
}

#[test]
fn stripped_elf_dynamic_export_recovers_the_unstripped_function_name() {
    assert_eq!(&ELF_STRIPPED[..6], b"\x7fELF\x02\x01");
    assert_eq!(&ELF_STRIPPED[18..20], &[0x3e, 0x00]);
    assert_eq!(
        &ELF_STRIPPED[ELF_FILL_NAME_START..ELF_FILL_NAME_END],
        b"fill"
    );
    assert_eq!(
        &ELF_STRIPPED[ELF_FILL_FILE_START..ELF_FILL_FILE_START + 16],
        &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x89, 0x7d, 0xf8, 0xbf, 0x10, 0x00,
            0x00, 0x00,
        ]
    );

    let stripped_file: object::File<'_> =
        object::File::parse(ELF_STRIPPED).expect("tracked stripped ELF must parse");
    let unstripped_file: object::File<'_> =
        object::File::parse(ELF_UNSTRIPPED).expect("tracked unstripped ELF must parse");
    assert_eq!(stripped_file.format(), object::BinaryFormat::Elf);
    assert_eq!(stripped_file.architecture(), object::Architecture::X86_64);
    assert!(stripped_file.is_little_endian());
    assert!(stripped_file.section_by_name(".dynsym").is_some());
    assert!(stripped_file.section_by_name(".dynstr").is_some());
    assert!(stripped_file.section_by_name(".symtab").is_none());
    assert!(unstripped_file.section_by_name(".symtab").is_some());
    let unstripped_fill: object::Symbol<'_, '_> = unstripped_file
        .symbols()
        .find(|symbol: &object::Symbol<'_, '_>| {
            symbol.name().is_ok_and(|name: &str| name == "fill")
        })
        .expect("unstripped ground truth must contain fill");
    assert_eq!(unstripped_fill.address(), ELF_FILL_ADDRESS);
    assert_eq!(unstripped_fill.size(), 106);
    assert_eq!(unstripped_fill.kind(), object::SymbolKind::Text);

    let stripped_function: ProgramFunction = ProgramFunction {
        name: "sub_13d0".to_owned(),
        address: ELF_FILL_ADDRESS,
        code: ELF_STRIPPED[ELF_FILL_FILE_START..ELF_FILL_FILE_END].to_vec(),
    };
    let first: NamedRecoveredProgram = recover_program_with_naming(
        ELF_STRIPPED,
        core::slice::from_ref(&stripped_function),
        Abi::SysV,
    );
    let second: NamedRecoveredProgram =
        recover_program_with_naming(ELF_STRIPPED, &[stripped_function], Abi::SysV);
    assert_eq!(first, second);
    assert_eq!(first.names.len(), 1);
    let recovered_name = &first.names[0];
    assert_eq!(recovered_name.function_address, ELF_FILL_ADDRESS);
    assert_eq!(recovered_name.name, "fill");
    assert_eq!(
        recovered_name.evidence.confidence,
        FunctionNameConfidence::High
    );
    assert_eq!(
        recovered_name.evidence.source,
        FunctionNameEvidenceSource::ExportedName
    );
    assert_eq!(
        recovered_name.evidence.input_bytes,
        InputByteRange {
            start: ELF_FILL_NAME_START as u64,
            end: ELF_FILL_NAME_END as u64,
        }
    );
    assert_eq!(
        &ELF_STRIPPED[usize::try_from(recovered_name.evidence.input_bytes.start)
            .expect("evidence start fits")
            ..usize::try_from(recovered_name.evidence.input_bytes.end).expect("evidence end fits")],
        recovered_name.evidence.identity.as_bytes()
    );
    assert_eq!(recovered_name.evidence.identity, "fill");
    assert_eq!(recovered_name.evidence.target_address, ELF_FILL_ADDRESS);
    assert!(!recovered_name.evidence.target_is_indirect);
    assert_eq!(
        serde_json::to_vec(&first.names).expect("first result must serialize"),
        serde_json::to_vec(&second.names).expect("second result must serialize")
    );

    let unstripped_function: ProgramFunction = ProgramFunction {
        name: "sub_13d0".to_owned(),
        address: ELF_FILL_ADDRESS,
        code: ELF_UNSTRIPPED[ELF_FILL_FILE_START..ELF_FILL_FILE_END].to_vec(),
    };
    let unstripped_subject: FunctionNameSubject<'_> =
        FunctionNameSubject::from(&unstripped_function);
    assert!(exported_function_names(ELF_UNSTRIPPED, &[unstripped_subject]).is_empty());

    let duplicate_subjects: [FunctionNameSubject<'_>; 2] = [
        FunctionNameSubject::from(&unstripped_function),
        FunctionNameSubject::from(&unstripped_function),
    ];
    assert!(exported_function_names(ELF_STRIPPED, &duplicate_subjects).is_empty());
}
