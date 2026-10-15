#![allow(clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use disrobe_pass_native::hardening::{
    Check, Evidence, HARDENING_SCHEMA, HardeningError, HardeningReport, ImageFormat,
    ImageHardening, Property, Status, analyze,
};
use object::Endianness;
use object::read::elf::{FileHeader as _, ProgramHeader as _};
use object::read::macho::MachHeader as _;
use sha2::{Digest as _, Sha256};

const CORPUS: &str = "corpus/native/hardening";
const FAT_ALIGN_LOG2: u32 = 14;
const FLIP_ROUNDS: usize = 192;

#[derive(Debug, Clone)]
struct Case {
    name: String,
    path: PathBuf,
    sha256: String,
    format: String,
    complete: bool,
    expect: BTreeMap<String, String>,
    reference: BTreeMap<String, String>,
    fortify: Option<(usize, usize)>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn text_field(table: &toml::Table, key: &str, context: &str) -> String {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{context}: the manifest entry needs a string `{key}`"))
        .to_owned()
}

fn string_map(table: &toml::Table, key: &str, context: &str) -> BTreeMap<String, String> {
    let Some(value): Option<&toml::Value> = table.get(key) else {
        return BTreeMap::new();
    };
    let inner: &toml::Table = value
        .as_table()
        .unwrap_or_else(|| panic!("{context}: `{key}` must be a table"));
    inner
        .iter()
        .map(|(name, value): (&String, &toml::Value)| {
            let text: &str = value
                .as_str()
                .unwrap_or_else(|| panic!("{context}: `{key}.{name}` must be a string"));
            (name.clone(), text.to_owned())
        })
        .collect()
}

fn count_field(table: &toml::Table, key: &str) -> Option<usize> {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value: i64| usize::try_from(value).ok())
}

fn cases() -> Vec<Case> {
    let manifest: PathBuf = repo_root().join(CORPUS).join("MANIFEST.toml");
    let text: String =
        std::fs::read_to_string(&manifest).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "the hardening matrix manifest is required at {}: {error}",
                manifest.display()
            )
        });
    let table: toml::Table =
        text.parse::<toml::Table>()
            .unwrap_or_else(|error: toml::de::Error| {
                panic!("the hardening manifest must be TOML: {error}")
            });
    let mut cases: Vec<Case> = Vec::new();
    for (section, base, complete) in [
        ("fixture", repo_root().join(CORPUS), true),
        ("reference", repo_root(), false),
    ] {
        let entries: &[toml::Value] = table
            .get(section)
            .and_then(toml::Value::as_array)
            .map_or(&[], Vec::as_slice);
        for entry in entries {
            let entry: &toml::Table = entry
                .as_table()
                .unwrap_or_else(|| panic!("every [[{section}]] entry must be a table"));
            let name: String = text_field(entry, "name", section);
            let fortify: Option<(usize, usize)> =
                count_field(entry, "fortified").zip(count_field(entry, "fortifiable"));
            cases.push(Case {
                path: base.join(text_field(entry, "path", &name)),
                sha256: text_field(entry, "sha256", &name),
                format: text_field(entry, "format", &name),
                expect: string_map(entry, "expect", &name),
                reference: string_map(entry, "reference", &name),
                complete,
                fortify,
                name,
            });
        }
    }
    assert!(
        cases.len() >= 24,
        "the hardening manifest lists {} images; the matrix holds at least 24",
        cases.len()
    );
    cases
}

fn read_case(case: &Case) -> Vec<u8> {
    let bytes: Vec<u8> = std::fs::read(&case.path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{}: the committed fixture is required at {}: {error}",
            case.name,
            case.path.display()
        )
    });
    let digest: String =
        Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut text: String, byte: &u8| {
                let _: std::fmt::Result = write!(text, "{byte:02x}");
                text
            });
    assert_eq!(
        digest, case.sha256,
        "{}: the fixture bytes differ from the build the manifest records",
        case.name
    );
    bytes
}

fn named<'cases>(cases: &'cases [Case], name: &str) -> &'cases Case {
    cases
        .iter()
        .find(|case: &&Case| case.name == name)
        .unwrap_or_else(|| panic!("the matrix holds {name}"))
}

fn analyze_case(case: &Case, bytes: &[u8]) -> HardeningReport {
    analyze(bytes).unwrap_or_else(|error: HardeningError| {
        panic!(
            "{}: a built image must be read, not refused: {error}",
            case.name
        )
    })
}

const fn format_name(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Elf => "elf",
        ImageFormat::Pe => "pe",
        ImageFormat::MachO => "macho",
    }
}

fn evidence_value<'report>(check: &'report Check, field_suffix: &str) -> Option<&'report str> {
    check
        .evidence
        .iter()
        .find(|evidence: &&Evidence| evidence.field.ends_with(field_suffix))
        .map(|evidence: &Evidence| evidence.value.as_str())
}

fn grade_reference(case: &Case, image: &ImageHardening, misses: &mut Vec<String>) {
    for (key, expected) in &case.reference {
        let (property, field, exact): (Property, &str, bool) = match key.as_str() {
            "security_cookie" => (Property::Gs, "SecurityCookie", true),
            "guard_flags" => (Property::Cfg, "GuardFlags", true),
            "se_handler_count" => (Property::SafeSeh, "SEHandlerCount", true),
            "rpath" => (Property::Rpath, "DT_RPATH", true),
            "runpath" => (Property::Runpath, "DT_RUNPATH", true),
            "cryptid" => (Property::Encrypted, "cryptid", false),
            other => {
                misses.push(format!("{}: unknown reference value `{other}`", case.name));
                continue;
            }
        };
        let observed: Option<&str> = image
            .check(property)
            .and_then(|check: &Check| evidence_value(check, field));
        let agrees: bool = observed.is_some_and(|value: &str| {
            if exact {
                value == expected
            } else {
                value.split_whitespace().next() == Some(expected.as_str())
            }
        });
        if !agrees {
            misses.push(format!(
                "{}: {property} cites {field} as {observed:?}, the reference reader reports {expected}",
                case.name
            ));
        }
    }
}

fn grade(case: &Case, report: &HardeningReport) -> Vec<String> {
    let mut misses: Vec<String> = Vec::new();
    let [image]: &[ImageHardening] = report.images.as_slice() else {
        misses.push(format!(
            "{}: one image expected, {} reported",
            case.name,
            report.images.len()
        ));
        return misses;
    };
    if format_name(image.format) != case.format {
        misses.push(format!(
            "{}: read as {}, built as {}",
            case.name, image.format, case.format
        ));
    }
    for (property, expected) in &case.expect {
        let Some(check): Option<&Check> = image
            .checks
            .iter()
            .find(|check: &&Check| check.property.as_str() == property)
        else {
            misses.push(format!("{}: no {property} verdict", case.name));
            continue;
        };
        if check.status.as_str() != expected {
            misses.push(format!(
                "{}: {property} is {}, the build and the reference readers say {expected}",
                case.name, check.status
            ));
        }
    }
    for check in &image.checks {
        if check.evidence.is_empty() {
            misses.push(format!(
                "{}: {} cites no evidence",
                case.name, check.property
            ));
        }
        if case.complete && !case.expect.contains_key(check.property.as_str()) {
            misses.push(format!(
                "{}: {} has no expectation in the manifest",
                case.name, check.property
            ));
        }
    }
    if let Some((fortified, fortifiable)) = case.fortify {
        match &image.fortify {
            Some(counts) if counts.fortified == fortified && counts.fortifiable == fortifiable => {}
            other => misses.push(format!(
                "{}: FORTIFY counts {other:?}, the build imports {fortified} fortified of {fortifiable} fortifiable",
                case.name
            )),
        }
    }
    grade_reference(case, image, &mut misses);
    misses
}

#[test]
fn matrix_verdicts_match_the_build_flags_and_the_reference_readers() {
    let cases: Vec<Case> = cases();
    let mut graded: usize = 0;
    let mut misses: Vec<String> = Vec::new();
    for case in &cases {
        let bytes: Vec<u8> = read_case(case);
        let report: HardeningReport = analyze_case(case, &bytes);
        assert_eq!(report.schema, HARDENING_SCHEMA);
        graded += case.expect.len() + case.reference.len();
        misses.extend(grade(case, &report));
    }
    println!(
        "HARDENING MATRIX: {}/{graded} verdicts and cited values agree across {} images",
        graded.saturating_sub(misses.len()),
        cases.len()
    );
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

fn flipped(status: &str) -> &'static str {
    if status == "present" {
        "absent"
    } else {
        "present"
    }
}

#[test]
fn every_flipped_expectation_turns_the_grade_red() {
    let mut controls: usize = 0;
    for case in &cases() {
        let bytes: Vec<u8> = read_case(case);
        let report: HardeningReport = analyze_case(case, &bytes);
        assert!(
            grade(case, &report).is_empty(),
            "{}: the unmutated grade must be green",
            case.name
        );
        for (property, expected) in &case.expect {
            let mut mutant: Case = case.clone();
            mutant
                .expect
                .insert(property.clone(), flipped(expected).to_owned());
            let misses: Vec<String> = grade(&mutant, &report);
            assert!(
                misses
                    .iter()
                    .any(|miss: &String| miss.contains(property.as_str())),
                "{}: flipping the {property} expectation left the grade green",
                case.name
            );
            controls += 1;
        }
        for key in case.reference.keys() {
            let mut mutant: Case = case.clone();
            mutant.reference.insert(key.clone(), "0x7".to_owned());
            assert!(
                !grade(&mutant, &report).is_empty(),
                "{}: a wrong {key} reference value left the grade green",
                case.name
            );
            controls += 1;
        }
        if let Some((fortified, fortifiable)) = case.fortify {
            let mut mutant: Case = case.clone();
            mutant.fortify = Some((fortified + 1, fortifiable));
            assert!(
                !grade(&mutant, &report).is_empty(),
                "{}: a wrong FORTIFY count left the grade green",
                case.name
            );
            controls += 1;
        }
    }
    println!("HARDENING MUTATION CONTROLS: {controls} flipped expectations all turned red");
}

fn program_header_offset(bytes: &[u8], kind: u32) -> usize {
    let header: &object::elf::FileHeader64<Endianness> =
        object::elf::FileHeader64::<Endianness>::parse(bytes)
            .unwrap_or_else(|error: object::Error| panic!("the ELF header must parse: {error}"));
    let endian: Endianness = header
        .endian()
        .unwrap_or_else(|error: object::Error| panic!("the ELF endianness must parse: {error}"));
    let headers: &[object::elf::ProgramHeader64<Endianness>] = header
        .program_headers(endian, bytes)
        .unwrap_or_else(|error: object::Error| panic!("the program headers must parse: {error}"));
    let index: usize = headers
        .iter()
        .position(|segment: &object::elf::ProgramHeader64<Endianness>| {
            segment.p_type(endian) == kind
        })
        .unwrap_or_else(|| panic!("the fixture carries a program header of type {kind:#x}"));
    let table: usize = usize::try_from(header.e_phoff.get(endian))
        .unwrap_or_else(|error: std::num::TryFromIntError| panic!("e_phoff fits: {error}"));
    table + index * usize::from(header.e_phentsize.get(endian))
}

#[test]
fn a_flipped_header_bit_changes_the_verdict_it_decides() {
    let cases: Vec<Case> = cases();
    let case: &Case = named(&cases, "elf-x86_64-full");
    let mut bytes: Vec<u8> = read_case(case);
    let offset: usize = program_header_offset(&bytes, object::elf::PT_GNU_STACK) + 4;
    bytes[offset] |= 1;
    let report: HardeningReport = analyze_case(case, &bytes);
    let misses: Vec<String> = grade(case, &report);
    assert_eq!(
        misses.len(),
        1,
        "setting PF_X on PT_GNU_STACK must change exactly the nx verdict: {misses:?}"
    );
    assert!(misses[0].contains("nx"), "{misses:?}");
}

#[test]
fn a_dynamic_table_past_its_bound_is_refused() {
    let cases: Vec<Case> = cases();
    let mut bytes: Vec<u8> = read_case(named(&cases, "elf-x86_64-full"));
    let header: usize = program_header_offset(&bytes, object::elf::PT_DYNAMIC);
    let start: u64 = u64::try_from(bytes.len())
        .unwrap_or_else(|error: std::num::TryFromIntError| panic!("length fits: {error}"));
    let entries: u64 = 65_537;
    for _ in 0..entries {
        bytes.extend_from_slice(&u64::from(object::elf::DT_DEBUG).to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
    }
    bytes[header + 8..header + 16].copy_from_slice(&start.to_le_bytes());
    bytes[header + 32..header + 40].copy_from_slice(&(entries * 16).to_le_bytes());
    assert!(matches!(
        analyze(&bytes),
        Err(HardeningError::Malformed {
            format: ImageFormat::Elf,
            ..
        })
    ));
}

fn code_signature_offset(bytes: &[u8]) -> usize {
    let header: &object::macho::MachHeader64<Endianness> =
        object::macho::MachHeader64::<Endianness>::parse(bytes, 0)
            .unwrap_or_else(|error: object::Error| panic!("the Mach-O header must parse: {error}"));
    let endian: Endianness = header
        .endian()
        .unwrap_or_else(|error: object::Error| panic!("the Mach-O endianness must parse: {error}"));
    let mut commands: object::read::macho::LoadCommandIterator<'_, Endianness> = header
        .load_commands(endian, bytes, 0)
        .unwrap_or_else(|error: object::Error| panic!("the load commands must parse: {error}"));
    while let Some(command) = commands
        .next()
        .unwrap_or_else(|error: object::Error| panic!("a load command must parse: {error}"))
    {
        if command.cmd() == object::macho::LC_CODE_SIGNATURE {
            let linkedit: &object::macho::LinkeditDataCommand<Endianness> =
                command.data().unwrap_or_else(|error: object::Error| {
                    panic!("LC_CODE_SIGNATURE must parse: {error}")
                });
            return usize::try_from(linkedit.dataoff.get(endian)).unwrap_or_else(
                |error: std::num::TryFromIntError| panic!("dataoff fits: {error}"),
            );
        }
    }
    panic!("the fixture carries LC_CODE_SIGNATURE")
}

#[test]
fn a_signature_index_past_its_bound_leaves_the_runtime_flag_undetermined() {
    let cases: Vec<Case> = cases();
    let mut bytes: Vec<u8> = read_case(named(&cases, "macho-x86_64-objc-arc"));
    let blob: usize = code_signature_offset(&bytes);
    bytes[blob + 8..blob + 12].copy_from_slice(&65_u32.to_be_bytes());
    let report: HardeningReport = analyze(&bytes)
        .unwrap_or_else(|error: HardeningError| panic!("the image stays readable: {error}"));
    let image: &ImageHardening = &report.images[0];
    let signature: Option<Status> = image
        .check(Property::CodeSignature)
        .map(|check: &Check| check.status);
    let runtime: Option<Status> = image
        .check(Property::HardenedRuntime)
        .map(|check: &Check| check.status);
    assert_eq!(signature, Some(Status::Present));
    assert_eq!(runtime, Some(Status::Undetermined));
}

fn fat_binary(slices: &[(&[u8], u32, u32)]) -> Vec<u8> {
    let align: usize = 1 << FAT_ALIGN_LOG2;
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    let count: u32 = u32::try_from(slices.len())
        .unwrap_or_else(|error: std::num::TryFromIntError| panic!("slice count fits: {error}"));
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut offset: usize = align;
    let mut placements: Vec<usize> = Vec::new();
    for (slice, cputype, cpusubtype) in slices {
        let start: u32 = u32::try_from(offset)
            .unwrap_or_else(|error: std::num::TryFromIntError| panic!("offset fits: {error}"));
        let size: u32 = u32::try_from(slice.len())
            .unwrap_or_else(|error: std::num::TryFromIntError| panic!("size fits: {error}"));
        for word in [*cputype, *cpusubtype, start, size, FAT_ALIGN_LOG2] {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        placements.push(offset);
        offset = (offset + slice.len()).next_multiple_of(align);
    }
    for ((slice, _, _), start) in slices.iter().zip(placements) {
        bytes.resize(start, 0);
        bytes.extend_from_slice(slice);
    }
    bytes
}

#[test]
fn a_universal_binary_reports_every_slice_like_the_thin_image() {
    let cases: Vec<Case> = cases();
    let thin: Vec<(Vec<u8>, HardeningReport)> = ["macho-x86_64-full", "macho-arm64-full"]
        .iter()
        .map(|name: &&str| {
            let case: &Case = named(&cases, name);
            let bytes: Vec<u8> = read_case(case);
            let report: HardeningReport = analyze_case(case, &bytes);
            (bytes, report)
        })
        .collect();
    let fat: Vec<u8> = fat_binary(&[
        (&thin[0].0, object::macho::CPU_TYPE_X86_64, 3),
        (&thin[1].0, object::macho::CPU_TYPE_ARM64, 0),
    ]);
    let report: HardeningReport = analyze(&fat)
        .unwrap_or_else(|error: HardeningError| panic!("a universal binary must be read: {error}"));
    assert_eq!(report.images.len(), 2);
    let offsets: Vec<Option<u64>> = report
        .images
        .iter()
        .map(|image: &ImageHardening| image.slice_offset)
        .collect();
    assert_eq!(offsets, vec![Some(0x4000), Some(0x8000)]);
    for (slice, (_, thin_report)) in report.images.iter().zip(&thin) {
        assert_eq!(slice.machine, thin_report.images[0].machine);
        assert_eq!(slice.checks, thin_report.images[0].checks);
    }
}

#[test]
fn unreadable_inputs_are_typed_refusals() {
    assert!(matches!(
        analyze(&[]),
        Err(HardeningError::UnknownFormat { .. })
    ));
    assert!(matches!(
        analyze(b"plain text is no executable image"),
        Err(HardeningError::UnknownFormat { .. })
    ));
    let cases: Vec<Case> = cases();
    let elf: Vec<u8> = read_case(named(&cases, "elf-x86_64-full"));
    assert!(matches!(
        analyze(&elf[..40]),
        Err(HardeningError::Malformed {
            format: ImageFormat::Elf,
            ..
        })
    ));
    let mut relocatable: Vec<u8> = elf.clone();
    relocatable[16] = 1;
    relocatable[17] = 0;
    assert!(matches!(
        analyze(&relocatable),
        Err(HardeningError::NotLinkedImage {
            format: ImageFormat::Elf,
            ..
        })
    ));
    let mut far_headers: Vec<u8> = elf;
    far_headers[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        analyze(&far_headers),
        Err(HardeningError::Malformed {
            format: ImageFormat::Elf,
            ..
        })
    ));
    let mut macho: Vec<u8> = read_case(named(&cases, "macho-x86_64-full"));
    macho[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        analyze(&macho),
        Err(HardeningError::Malformed {
            format: ImageFormat::MachO,
            ..
        })
    ));
    let mut crowded: Vec<u8> = Vec::new();
    crowded.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    crowded.extend_from_slice(&65_u32.to_be_bytes());
    crowded.resize(8 + 65 * 20, 0);
    assert!(matches!(
        analyze(&crowded),
        Err(HardeningError::TooManySlices { count: 65, .. })
    ));
    let pe: Vec<u8> = read_case(named(&cases, "pe-x64-clang-nocrt.exe"));
    for length in [0x120, 0x200] {
        assert!(matches!(
            analyze(&pe[..length]),
            Err(HardeningError::Malformed {
                format: ImageFormat::Pe,
                ..
            })
        ));
    }
}

const fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn assert_verdict_or_refusal(name: &str, bytes: &[u8]) {
    if let Ok(report) = analyze(bytes) {
        for image in &report.images {
            for check in &image.checks {
                assert!(
                    !check.evidence.is_empty(),
                    "{name}: {} carries a verdict without evidence",
                    check.property
                );
            }
        }
    }
}

#[test]
fn truncations_and_byte_flips_yield_a_verdict_or_a_typed_refusal() {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for case in &cases() {
        let bytes: Vec<u8> = read_case(case);
        let step: usize = (bytes.len() / 97).max(1);
        for length in (0..bytes.len()).step_by(step) {
            assert_verdict_or_refusal(&case.name, &bytes[..length]);
        }
        let mut mutant: Vec<u8> = bytes.clone();
        for _ in 0..FLIP_ROUNDS {
            let position: usize = usize::try_from(next_random(&mut state) % 4096)
                .unwrap_or_else(|error: std::num::TryFromIntError| panic!("fits: {error}"))
                % mutant.len();
            mutant[position] ^= 1 << (next_random(&mut state) % 8);
            assert_verdict_or_refusal(&case.name, &mutant);
        }
    }
}

#[test]
fn the_json_shape_names_every_property_and_status_as_documented() {
    for case in &cases() {
        let bytes: Vec<u8> = read_case(case);
        let report: HardeningReport = analyze_case(case, &bytes);
        let value: serde_json::Value =
            serde_json::to_value(&report).unwrap_or_else(|error: serde_json::Error| {
                panic!("the report must serialize: {error}")
            });
        assert_eq!(value["schema"], HARDENING_SCHEMA);
        let images: &[serde_json::Value] = value["images"].as_array().map_or(&[], Vec::as_slice);
        for (image, json) in report.images.iter().zip(images) {
            assert_eq!(json["format"], format_name(image.format));
            let checks: &[serde_json::Value] = json["checks"].as_array().map_or(&[], Vec::as_slice);
            assert_eq!(checks.len(), image.checks.len());
            for (check, json) in image.checks.iter().zip(checks) {
                assert_eq!(json["property"], check.property.as_str());
                assert_eq!(json["status"], check.status.as_str());
                assert_eq!(check.property.to_string(), check.property.as_str());
                assert_eq!(check.status.to_string(), check.status.as_str());
            }
        }
        let back: HardeningReport =
            serde_json::from_value(value).unwrap_or_else(|error: serde_json::Error| {
                panic!("the report must round-trip: {error}")
            });
        assert_eq!(back, report, "{}", case.name);
    }
}

#[test]
fn verdicts_cover_each_status_in_the_matrix() {
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for case in &cases() {
        for (property, status) in &case.expect {
            seen.entry(property.clone())
                .or_default()
                .push(status.clone());
        }
    }
    let one_sided: Vec<&String> = seen
        .iter()
        .filter(|(_, statuses): &(&String, &Vec<String>)| {
            !(statuses
                .iter()
                .any(|status: &String| status == Status::Present.as_str())
                && statuses
                    .iter()
                    .any(|status: &String| status == Status::Absent.as_str()))
        })
        .map(|(property, _): (&String, &Vec<String>)| property)
        .collect();
    assert!(
        one_sided.is_empty(),
        "every property needs a present and an absent fixture so a constant verdict cannot pass: {one_sided:?}"
    );
}
