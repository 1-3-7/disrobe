use disrobe_pass_dotnet::Error;
use disrobe_pass_dotnet::aot::{
    AotLayoutProfile, AotMetadataStatus, AotReport, ReadyToRunHeader, ReadyToRunInspection, detect,
    inspect_ready_to_run_header,
};
use object::Object as _;
use object::ObjectSection as _;

const ELF_IMAGE: &[u8] = include_bytes!("fixtures/native_aot/aot_elf_x86_64.elf");
const MACHO_IMAGE: &[u8] = include_bytes!("fixtures/native_aot/aot_macho_x86_64.macho");

fn write_u16(image: &mut [u8], at: usize, value: u16) -> bool {
    let Some(end): Option<usize> = at.checked_add(2) else {
        return false;
    };
    let Some(target): Option<&mut [u8]> = image.get_mut(at..end) else {
        return false;
    };
    target.copy_from_slice(&value.to_le_bytes());
    true
}

fn write_i32(image: &mut [u8], at: usize, value: i32) -> bool {
    let Some(end): Option<usize> = at.checked_add(4) else {
        return false;
    };
    let Some(target): Option<&mut [u8]> = image.get_mut(at..end) else {
        return false;
    };
    target.copy_from_slice(&value.to_le_bytes());
    true
}

fn write_u64(image: &mut [u8], at: usize, value: u64) -> bool {
    let Some(end): Option<usize> = at.checked_add(8) else {
        return false;
    };
    let Some(target): Option<&mut [u8]> = image.get_mut(at..end) else {
        return false;
    };
    target.copy_from_slice(&value.to_le_bytes());
    true
}

fn erase_ready_to_run_signatures(image: &[u8]) -> Vec<u8> {
    let mut copy: Vec<u8> = image.to_vec();
    let needle: [u8; 4] = disrobe_pass_dotnet::aot::READY_TO_RUN_SIGNATURE.to_le_bytes();
    let mut cursor: usize = 0;
    while cursor < copy.len() {
        let Some(remaining): Option<&[u8]> = copy.get(cursor..) else {
            break;
        };
        let Some(relative): Option<usize> = remaining
            .windows(needle.len())
            .position(|window: &[u8]| window == needle)
        else {
            break;
        };
        let Some(found): Option<usize> = cursor.checked_add(relative) else {
            break;
        };
        let Some(first): Option<&mut u8> = copy.get_mut(found) else {
            break;
        };
        *first = first.wrapping_add(1);
        let Some(next): Option<usize> = found.checked_add(1) else {
            break;
        };
        cursor = next;
    }
    copy
}

fn assert_names_are_present(image: &[u8], names: &[String]) {
    for name in names {
        let present: bool = image
            .windows(name.len())
            .any(|window: &[u8]| window == name.as_bytes());
        assert!(
            present,
            "recovered name is absent from container bytes: {name}"
        );
    }
}

fn inspect(image: &[u8]) -> Result<ReadyToRunInspection, &'static str> {
    let inspection: Option<ReadyToRunInspection> =
        inspect_ready_to_run_header(image).map_err(|_: Error| "container inspection failed")?;
    inspection.ok_or("container has no ahead-of-time header")
}

fn header_offset(image: &[u8]) -> Result<usize, &'static str> {
    let report: AotReport = detect(image);
    let header: &ReadyToRunHeader = report
        .ready_to_run
        .as_ref()
        .ok_or("container must carry a valid header")?;
    usize::try_from(header.file_offset)
        .map_err(|_: std::num::TryFromIntError| "fixture header offset must fit usize")
}

fn first_elf64_rela_addend_offset(image: &[u8]) -> Result<usize, &'static str> {
    let file: object::File<'_, &[u8]> =
        object::File::parse(image).map_err(|_: object::Error| "ELF parse failed")?;
    let Some((file_start, file_size)): Option<(u64, u64)> = file
        .section_by_name(".rela.dyn")
        .and_then(|section| section.file_range())
    else {
        return Err("ELF relocation section is absent");
    };
    if file_size < 24 {
        return Err("ELF relocation section is too small");
    }
    let addend_offset: u64 = file_start
        .checked_add(16)
        .ok_or("ELF relocation addend offset must fit u64")?;
    usize::try_from(addend_offset)
        .map_err(|_: std::num::TryFromIntError| "ELF relocation addend offset must fit usize")
}

#[test]
fn linked_elf_recovers_pointer_pair_metadata_names() -> Result<(), &'static str> {
    let report: AotReport = detect(ELF_IMAGE);
    let inspection: ReadyToRunInspection = inspect(ELF_IMAGE)?;
    assert!(report.is_native_aot);
    assert_eq!(
        inspection.profile_selection.selected,
        AotLayoutProfile::PointerPair
    );
    assert_eq!(
        inspection.profile_selection.declared,
        Some(AotLayoutProfile::PointerPair)
    );
    assert!(!inspection.profile_selection.disagreement);
    assert_eq!(inspection.profile_selection.self_consistent_rows, 2);
    assert_eq!(inspection.profile_selection.mapped_rows, 2);
    assert_eq!(report.recovered_names, ["ElfFixtureType", "SharedMetadata"]);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::NotPresent
    );
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
    assert_names_are_present(ELF_IMAGE, &report.recovered_names);
    Ok(())
}

#[test]
fn linked_macho_recovers_length_and_pointer_metadata_names() -> Result<(), &'static str> {
    let report: AotReport = detect(MACHO_IMAGE);
    let inspection: ReadyToRunInspection = inspect(MACHO_IMAGE)?;
    assert!(report.is_native_aot);
    assert_eq!(
        inspection.profile_selection.selected,
        AotLayoutProfile::LengthAndPointer
    );
    assert_eq!(
        inspection.profile_selection.declared,
        Some(AotLayoutProfile::LengthAndPointer)
    );
    assert!(!inspection.profile_selection.disagreement);
    assert_eq!(inspection.profile_selection.self_consistent_rows, 2);
    assert_eq!(inspection.profile_selection.mapped_rows, 2);
    assert_eq!(
        report.recovered_names,
        ["MachOFixtureType", "SharedMetadata"]
    );
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::NotPresent
    );
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
    assert_names_are_present(MACHO_IMAGE, &report.recovered_names);
    Ok(())
}

#[test]
fn structural_score_overrides_a_forged_declared_version() -> Result<(), &'static str> {
    let header_offset: usize = header_offset(MACHO_IMAGE)?;
    let major_offset: usize = header_offset
        .checked_add(4)
        .ok_or("fixture header version offset must fit usize")?;
    let mut altered: Vec<u8> = MACHO_IMAGE.to_vec();
    assert!(write_u16(&mut altered, major_offset, 10));
    let report: AotReport = detect(&altered);
    let inspection: ReadyToRunInspection = inspect(&altered)?;
    assert_eq!(
        inspection.profile_selection.selected,
        AotLayoutProfile::LengthAndPointer
    );
    assert_eq!(
        inspection.profile_selection.declared,
        Some(AotLayoutProfile::PointerPair)
    );
    assert!(inspection.profile_selection.disagreement);
    assert_eq!(
        report.recovered_names,
        ["MachOFixtureType", "SharedMetadata"]
    );
    Ok(())
}

#[test]
fn valid_container_without_a_header_is_distinct_from_an_unreadable_image() {
    let without_header: Vec<u8> = erase_ready_to_run_signatures(ELF_IMAGE);
    let valid_result: disrobe_pass_dotnet::Result<Option<ReadyToRunInspection>> =
        inspect_ready_to_run_header(&without_header);
    assert!(matches!(valid_result, Ok(None)));
    let invalid_result: disrobe_pass_dotnet::Result<Option<ReadyToRunInspection>> =
        inspect_ready_to_run_header(b"not native");
    assert!(matches!(invalid_result, Err(Error::AotContainerRead(_))));
}

#[test]
fn hostile_declared_section_count_is_refused_without_allocation() -> Result<(), &'static str> {
    let header_offset: usize = header_offset(ELF_IMAGE)?;
    let count_offset: usize = header_offset
        .checked_add(12)
        .ok_or("fixture section count offset must fit usize")?;
    let mut altered: Vec<u8> = ELF_IMAGE.to_vec();
    assert!(write_u16(&mut altered, count_offset, u16::MAX));
    let result: disrobe_pass_dotnet::Result<Option<ReadyToRunInspection>> =
        inspect_ready_to_run_header(&altered);
    assert!(matches!(result, Ok(None)));
    let report: AotReport = detect(&altered);
    assert!(!report.is_native_aot);
    assert!(report.ready_to_run.is_none());
    assert!(report.recovered_names.is_empty());
    Ok(())
}

#[test]
fn invalid_relocation_addend_and_negative_length_are_refused() -> Result<(), &'static str> {
    let elf_addend: usize = first_elf64_rela_addend_offset(ELF_IMAGE)?;
    let mut invalid_elf: Vec<u8> = ELF_IMAGE.to_vec();
    assert!(write_u64(&mut invalid_elf, elf_addend, u64::MAX));
    let elf_result: disrobe_pass_dotnet::Result<Option<ReadyToRunInspection>> =
        inspect_ready_to_run_header(&invalid_elf);
    assert!(matches!(elf_result, Ok(None)));

    let macho_header: usize = header_offset(MACHO_IMAGE)?;
    let macho_length: usize = macho_header
        .checked_add(20)
        .ok_or("Mach-O row length offset must fit usize")?;
    let mut invalid_macho: Vec<u8> = MACHO_IMAGE.to_vec();
    assert!(write_i32(&mut invalid_macho, macho_length, -1));
    let macho_result: disrobe_pass_dotnet::Result<Option<ReadyToRunInspection>> =
        inspect_ready_to_run_header(&invalid_macho);
    assert!(matches!(macho_result, Ok(None)));
    Ok(())
}
