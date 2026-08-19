#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use std::path::PathBuf;

use disrobe_binfmt::{StructuralFormat, identify_by_structure};

const EM_ARM: u16 = 0x0028;
const EM_AVR: u16 = 0x0053;

const ELF32_FIXTURES: [(&str, u16); 4] = [
    ("native/arch/thumb_forms.elf", EM_ARM),
    ("native/arch/arm32_forms.elf", EM_ARM),
    ("native/arch/arm32_mixed_modes.elf", EM_ARM),
    ("native/formats/avr_firmware.elf", EM_AVR),
];

const ELF64_FIXTURES: [&str; 2] = [
    "native/discovery/disc.unstripped.elf",
    "native/nim/hello.nim.elf",
];

fn corpus_bytes(relative: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(relative);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the graded corpus fixture {} must be readable: {error}",
            path.display()
        )
    })
}

fn elf_class(bytes: &[u8]) -> u8 {
    *bytes.get(4).expect("an ELF fixture carries EI_CLASS")
}

fn elf_machine(bytes: &[u8]) -> u16 {
    let raw: [u8; 2] = bytes
        .get(18..20)
        .and_then(|slice: &[u8]| <[u8; 2]>::try_from(slice).ok())
        .expect("an ELF fixture carries e_machine");
    u16::from_le_bytes(raw)
}

#[test]
fn a_thirty_two_bit_elf_is_structurally_identified() {
    let mut machines: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    for (relative, expected_machine) in ELF32_FIXTURES {
        let bytes: Vec<u8> = corpus_bytes(relative);
        assert_eq!(
            elf_class(&bytes),
            1,
            "{relative} must be a 32-bit ELF for this case to test the 32-bit path"
        );
        assert_eq!(
            elf_machine(&bytes),
            expected_machine,
            "{relative} must stay on the architecture this case records, otherwise the spread \
             below claims coverage it does not have"
        );
        machines.insert(expected_machine);
        assert_eq!(
            identify_by_structure(&bytes),
            Some(StructuralFormat::Elf),
            "{relative} is a conforming 32-bit ELF, so structural identification must name it; \
             a 32-bit program header table starts at offset 52, not 64"
        );
    }
    assert!(
        machines.len() >= 2,
        "the 32-bit case must span more than one architecture, otherwise it reads as an ARM \
         defect rather than an ELF-class one: {machines:?}"
    );
}

#[test]
fn a_sixty_four_bit_elf_stays_structurally_identified() {
    for relative in ELF64_FIXTURES {
        let bytes: Vec<u8> = corpus_bytes(relative);
        assert_eq!(
            elf_class(&bytes),
            2,
            "{relative} must be a 64-bit ELF for this case to guard the 64-bit path"
        );
        assert_eq!(
            identify_by_structure(&bytes),
            Some(StructuralFormat::Elf),
            "{relative} must stay identified when the 32-bit floor is corrected"
        );
    }
}

#[test]
fn a_thirty_two_bit_elf_with_a_table_inside_its_own_header_is_refused() {
    let baseline: Vec<u8> = corpus_bytes(ELF32_FIXTURES[0].0);
    assert_eq!(
        identify_by_structure(&baseline),
        Some(StructuralFormat::Elf),
        "the unmutated fixture must identify, otherwise the mutations below prove nothing"
    );
    for offset in [0u32, 1, 51] {
        let mut mutated: Vec<u8> = baseline.clone();
        mutated[28..32].copy_from_slice(&offset.to_le_bytes());
        assert_eq!(
            identify_by_structure(&mutated),
            None,
            "a 32-bit program header table declared at {offset}, inside the 52-byte ELF header, \
             is not something a linker emits, so it must be refused"
        );
    }
}

#[test]
fn a_thirty_two_bit_elf_whose_tables_run_past_the_end_is_refused() {
    let baseline: Vec<u8> = corpus_bytes(ELF32_FIXTURES[0].0);
    let mut past_phoff: Vec<u8> = baseline.clone();
    past_phoff[28..32].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert_eq!(
        identify_by_structure(&past_phoff),
        None,
        "a 32-bit program header table past the end of the file must be refused"
    );
    let mut past_shoff: Vec<u8> = baseline;
    past_shoff[32..36].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert_eq!(
        identify_by_structure(&past_shoff),
        None,
        "a 32-bit section header table past the end of the file must be refused"
    );
}

#[test]
fn a_thirty_two_bit_elf_with_a_wrong_entry_size_is_refused() {
    let baseline: Vec<u8> = corpus_bytes(ELF32_FIXTURES[0].0);
    let mut wrong_ph: Vec<u8> = baseline.clone();
    wrong_ph[42..44].copy_from_slice(&56u16.to_le_bytes());
    assert_eq!(
        identify_by_structure(&wrong_ph),
        None,
        "a 32-bit ELF declaring the 64-bit program entry size is inconsistent and must be refused"
    );
    let mut wrong_sh: Vec<u8> = baseline;
    wrong_sh[46..48].copy_from_slice(&64u16.to_le_bytes());
    assert_eq!(
        identify_by_structure(&wrong_sh),
        None,
        "a 32-bit ELF declaring the 64-bit section entry size is inconsistent and must be refused"
    );
}
