#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::flutter::{DartCallingConvention, DartCodeNameRole};
use disrobe_pass_mobile::{
    AotLiftReport, DartCodeName, DartCodeNameTable, DartGraphObfuscationHint,
    DartGraphRecoveryOptions, DartGraphRecoveryReport, DartLiftedFunction, lift_libapp_aot,
    recover_dart_pinned_elf,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const ISOLATE_INSTRUCTIONS_SYMBOL: &str = "_kDartIsolateSnapshotInstructions";

const FUNCTION_CODE_PREFIX: &str = "[Optimized] ";

const ALLOCATION_STUB_PREFIX: &str = "[Stub] Allocate ";

const DW_TAG_SUBPROGRAM: u64 = 0x2e;

const DW_AT_NAME: u64 = 0x03;

const DW_AT_LOW_PC: u64 = 0x11;

const DW_AT_HIGH_PC: u64 = 0x12;

const DW_AT_ABSTRACT_ORIGIN: u64 = 0x31;

const STACK_ARGUMENTS_NOTE: &str = "passes every Dart argument on the stack";

const DROPPED_PARENT_PREFIX: &str = "<optimized out>.";

#[derive(Debug, Clone, Deserialize)]
struct LedgerOracle {
    source: String,
    application_library: String,
    application_code: Vec<String>,
    literals: Vec<LedgerLiteral>,
    register_argument_calls: Vec<ArgumentCall>,
    releases: Vec<LedgerRelease>,
}

#[derive(Debug, Clone, Deserialize)]
struct LedgerLiteral {
    function: String,
    source: String,
    rendered: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ArgumentCall {
    function: String,
    callee: String,
    arguments: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LedgerRelease {
    dart_version: String,
    snapshot_compatibility_hash: String,
    calling_convention: DartCallingConvention,
    artifact: String,
    sha256: String,
    features: String,
    instruction_sizes: String,
    instruction_sizes_sha256: String,
    debugging_info: String,
    debugging_info_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
struct VersionsOracle {
    releases: Vec<VersionsRelease>,
}

#[derive(Debug, Clone, Deserialize)]
struct VersionsRelease {
    dart_version: String,
    builds: Vec<VersionsBuild>,
}

#[derive(Debug, Clone, Deserialize)]
struct VersionsBuild {
    name: String,
    artifact: String,
    sha256: String,
    instruction_sizes: String,
    instruction_sizes_sha256: String,
    debugging_info: String,
    debugging_info_sha256: String,
    obfuscation_map: Option<String>,
    obfuscation_map_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct InstructionSize {
    l: Option<String>,
    c: Option<String>,
    n: String,
    s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DwarfFunction {
    name: String,
    size: u64,
}

#[derive(Debug, Clone, Default)]
struct DwarfFunctions {
    by_offset: BTreeMap<u64, Vec<DwarfFunction>>,
    symbols: BTreeMap<u64, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct CodeNameGrade {
    code_objects: usize,
    function_code_objects: usize,
    allocation_stub_code_objects: usize,
    owners: usize,
    owners_with_dropped_parent: usize,
    allocation_stubs: usize,
    aliases: usize,
}

struct GradedBuild<'build> {
    label: String,
    report: &'build DartGraphRecoveryReport,
    sizes: &'build [InstructionSize],
    dwarf: &'build DwarfFunctions,
    reverse_obfuscation: Option<&'build BTreeMap<String, String>>,
}

fn flutter_corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
}

fn read_tracked(set: &str, name: &str) -> Vec<u8> {
    let path: PathBuf = flutter_corpus().join(set).join(name);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "corpus/mobile/flutter/{set}/{name} is tracked and graded here; it cannot be read at {} \
             ({error}); restore it with `git checkout -- corpus/mobile/flutter/{set}` or rebuild it \
             with corpus/mobile/flutter/{set}/build.sh",
            path.display()
        )
    });
    assert!(
        !bytes.is_empty(),
        "corpus/mobile/flutter/{set}/{name} read back empty"
    );
    bytes
}

fn read_verified(set: &str, name: &str, sha256: &str) -> Vec<u8> {
    let bytes: Vec<u8> = read_tracked(set, name);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        sha256,
        "corpus/mobile/flutter/{set}/{name} is not the file its build record describes"
    );
    bytes
}

fn ledger_oracle() -> LedgerOracle {
    let oracle: LedgerOracle = serde_json::from_slice(&read_tracked("ledger", "oracle.json"))
        .expect("ledger/oracle.json parses");
    assert_eq!(
        oracle.releases.len(),
        10,
        "the ledger set pins one patch release of each Dart minor from 3.3 to 3.12"
    );
    oracle
}

fn versions_oracle() -> VersionsOracle {
    let oracle: VersionsOracle = serde_json::from_slice(&read_tracked("versions", "oracle.json"))
        .expect("versions/oracle.json parses");
    assert_eq!(oracle.releases.len(), 9);
    oracle
}

fn instruction_sizes(set: &str, name: &str, sha256: &str) -> Vec<InstructionSize> {
    serde_json::from_slice(&read_verified(set, name, sha256))
        .unwrap_or_else(|error: serde_json::Error| panic!("{set}/{name} does not parse: {error}"))
}

fn reverse_obfuscation_map(set: &str, name: &str, sha256: &str) -> BTreeMap<String, String> {
    let pairs: Vec<String> = serde_json::from_slice(&read_verified(set, name, sha256))
        .unwrap_or_else(|error: serde_json::Error| panic!("{set}/{name} does not parse: {error}"));
    assert!(
        pairs.len().is_multiple_of(2),
        "{set}/{name} must hold original and obfuscated names in pairs"
    );
    pairs
        .chunks_exact(2)
        .filter(|pair: &&[String]| pair[0] != pair[1])
        .map(|pair: &[String]| (pair[1].clone(), pair[0].clone()))
        .collect::<BTreeMap<String, String>>()
}

const fn is_obfuscation_key(byte: u8) -> bool {
    byte == b'_' || byte == b'@' || byte.is_ascii_alphanumeric()
}

fn deobfuscate(name: &str, reverse: &BTreeMap<String, String>) -> String {
    let bytes: &[u8] = name.as_bytes();
    let mut text: String = String::with_capacity(name.len());
    let mut index: usize = 0;
    while index < bytes.len() {
        if !is_obfuscation_key(bytes[index]) {
            let character: char = name[index..].chars().next().expect("a character remains");
            text.push(character);
            index += character.len_utf8();
            continue;
        }
        let start: usize = index;
        while index < bytes.len() && is_obfuscation_key(bytes[index]) {
            index += 1;
        }
        let token: &str = &name[start..index];
        text.push_str(reverse.get(token).map_or(token, String::as_str));
    }
    text
}

fn uleb(bytes: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte: u8 = *bytes
            .get(*at)
            .ok_or_else(|| format!("LEB128 runs past offset {at}"))?;
        *at += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 70 {
            return Err(format!("LEB128 at {at} is longer than ten bytes"));
        }
    }
}

fn fixed(bytes: &[u8], at: &mut usize, width: usize) -> Result<u64, String> {
    let slice: &[u8] = bytes
        .get(*at..*at + width)
        .ok_or_else(|| format!("a {width}-byte value runs past offset {at}"))?;
    *at += width;
    let mut value: u64 = 0;
    for (shift, byte) in slice.iter().enumerate() {
        value |= u64::from(*byte) << (8 * shift);
    }
    Ok(value)
}

#[derive(Debug, Clone)]
enum AttributeValue {
    Number(u64),
    Text(String),
}

fn read_form(
    bytes: &[u8],
    at: &mut usize,
    form: u64,
    address_size: usize,
) -> Result<AttributeValue, String> {
    let value: AttributeValue = match form {
        0x01 => AttributeValue::Number(fixed(bytes, at, address_size)?),
        0x05 => AttributeValue::Number(fixed(bytes, at, 2)?),
        0x06 | 0x0e | 0x13 | 0x17 => AttributeValue::Number(fixed(bytes, at, 4)?),
        0x07 => AttributeValue::Number(fixed(bytes, at, 8)?),
        0x0b | 0x0c => AttributeValue::Number(fixed(bytes, at, 1)?),
        0x0d | 0x0f => AttributeValue::Number(uleb(bytes, at)?),
        0x19 => AttributeValue::Number(1),
        0x08 => {
            let end: usize = bytes
                .get(*at..)
                .and_then(|rest: &[u8]| rest.iter().position(|byte: &u8| *byte == 0))
                .ok_or_else(|| format!("an inline DWARF string at {at} is not terminated"))?;
            let text: String = String::from_utf8(bytes[*at..*at + end].to_vec())
                .map_err(|error: std::string::FromUtf8Error| error.to_string())?;
            *at += end + 1;
            AttributeValue::Text(text)
        }
        other => {
            return Err(format!(
                "DWARF form {other:#x} is outside what gen_snapshot writes"
            ));
        }
    };
    Ok(value)
}

type Abbreviations = BTreeMap<u64, (u64, Vec<(u64, u64)>)>;

fn abbreviations(bytes: &[u8]) -> Result<Abbreviations, String> {
    let mut table: Abbreviations = BTreeMap::new();
    let mut at: usize = 0;
    loop {
        let code: u64 = uleb(bytes, &mut at)?;
        if code == 0 {
            return Ok(table);
        }
        let tag: u64 = uleb(bytes, &mut at)?;
        at += 1;
        let mut attributes: Vec<(u64, u64)> = Vec::new();
        loop {
            let attribute: u64 = uleb(bytes, &mut at)?;
            let form: u64 = uleb(bytes, &mut at)?;
            if attribute == 0 && form == 0 {
                break;
            }
            attributes.push((attribute, form));
        }
        table.insert(code, (tag, attributes));
    }
}

fn dwarf_functions(elf: &[u8]) -> Result<DwarfFunctions, String> {
    let file: object::File<'_> = object::File::parse(elf).map_err(|error| error.to_string())?;
    let base: u64 = file
        .dynamic_symbols()
        .find(|symbol| symbol.name() == Ok(ISOLATE_INSTRUCTIONS_SYMBOL))
        .map(|symbol| symbol.address())
        .ok_or("the ELF names no isolate instructions symbol")?;
    let section = |name: &str| -> Result<Vec<u8>, String> {
        file.section_by_name(name)
            .ok_or_else(|| format!("the ELF carries no {name} section"))?
            .data()
            .map(<[u8]>::to_vec)
            .map_err(|error| error.to_string())
    };
    let info: Vec<u8> = section(".debug_info")?;
    let abbreviation_table: Abbreviations = abbreviations(&section(".debug_abbrev")?)?;
    let mut abstract_names: BTreeMap<u64, String> = BTreeMap::new();
    let mut concrete: Vec<(u64, u64, u64)> = Vec::new();
    let mut unit: usize = 0;
    while unit < info.len() {
        let mut at: usize = unit;
        let length: u64 = fixed(&info, &mut at, 4)?;
        if length >= 0xffff_fff0 {
            return Err("64-bit DWARF is outside what gen_snapshot writes".to_owned());
        }
        let end: usize = at + usize::try_from(length).map_err(|error| error.to_string())?;
        let version: u64 = fixed(&info, &mut at, 2)?;
        if !(2..=4).contains(&version) {
            return Err(format!(
                "DWARF version {version} is outside what gen_snapshot writes"
            ));
        }
        let _abbreviation_offset: u64 = fixed(&info, &mut at, 4)?;
        let address_size: usize =
            usize::try_from(fixed(&info, &mut at, 1)?).map_err(|error| error.to_string())?;
        while at < end {
            let offset: u64 = u64::try_from(at - unit).map_err(|error| error.to_string())?;
            let code: u64 = uleb(&info, &mut at)?;
            if code == 0 {
                continue;
            }
            let (tag, attributes): &(u64, Vec<(u64, u64)>) = abbreviation_table
                .get(&code)
                .ok_or_else(|| format!("DWARF abbreviation {code} is not declared"))?;
            let mut name: Option<String> = None;
            let mut origin: Option<u64> = None;
            let mut low: Option<u64> = None;
            let mut high: Option<u64> = None;
            for (attribute, form) in attributes {
                let value: AttributeValue = read_form(&info, &mut at, *form, address_size)?;
                match (*attribute, value) {
                    (DW_AT_NAME, AttributeValue::Text(text)) => name = Some(text),
                    (DW_AT_ABSTRACT_ORIGIN, AttributeValue::Number(number)) => {
                        origin = Some(number);
                    }
                    (DW_AT_LOW_PC, AttributeValue::Number(number)) => low = Some(number),
                    (DW_AT_HIGH_PC, AttributeValue::Number(number)) => high = Some(number),
                    _ => {}
                }
            }
            if *tag != DW_TAG_SUBPROGRAM {
                continue;
            }
            if let Some(text) = name {
                abstract_names.insert(offset, text);
            }
            if let (Some(origin), Some(low), Some(high)) = (origin, low, high) {
                concrete.push((origin, low, high));
            }
        }
        unit = end;
    }
    let mut functions: DwarfFunctions = DwarfFunctions::default();
    for symbol in file.symbols() {
        if symbol.kind() != object::SymbolKind::Text {
            continue;
        }
        let Some(offset) = symbol.address().checked_sub(base) else {
            continue;
        };
        let name: &str = symbol.name().map_err(|error| error.to_string())?;
        functions
            .symbols
            .entry(offset)
            .or_default()
            .push(name.to_owned());
    }
    for (origin, low, high) in concrete {
        let name: String = abstract_names
            .get(&origin)
            .cloned()
            .ok_or_else(|| format!("concrete subprogram names unknown origin {origin:#x}"))?;
        let offset: u64 = low
            .checked_sub(base)
            .ok_or("a subprogram starts before the isolate instructions")?;
        functions
            .by_offset
            .entry(offset)
            .or_default()
            .push(DwarfFunction {
                name,
                size: high.saturating_sub(low),
            });
    }
    Ok(functions)
}

fn display_name(name: &str, reverse: Option<&BTreeMap<String, String>>) -> String {
    reverse.map_or_else(|| name.to_owned(), |map| deobfuscate(name, map))
}

fn grade_code_names(build: &GradedBuild<'_>) -> Result<CodeNameGrade, String> {
    let label: &str = &build.label;
    let names: &DartCodeNameTable = &build.report.code_names;
    if !names.reason.is_empty() {
        return Err(format!("{label}: no code names: {}", names.reason));
    }
    if names.table_entry_count != build.sizes.len() || names.boundaries.len() != build.sizes.len() {
        return Err(format!(
            "{label}: the instructions table holds {} entries ({} boundaries), gen_snapshot listed {} code objects",
            names.table_entry_count,
            names.boundaries.len(),
            build.sizes.len()
        ));
    }
    let mut function_code_objects: usize = 0;
    let mut allocation_stub_code_objects: usize = 0;
    for (index, (boundary, size)) in names.boundaries.iter().zip(build.sizes).enumerate() {
        allocation_stub_code_objects += usize::from(size.n.starts_with(ALLOCATION_STUB_PREFIX));
        if boundary.payload_length != size.s {
            return Err(format!(
                "{label}: code object {index} spans {} bytes, gen_snapshot sized {} at {}",
                boundary.payload_length, size.s, size.n
            ));
        }
        let dwarf: Option<&Vec<DwarfFunction>> =
            build.dwarf.by_offset.get(&boundary.instructions_offset);
        let is_function: bool = size.n.starts_with(FUNCTION_CODE_PREFIX);
        if is_function != dwarf.is_some() {
            return Err(format!(
                "{label}: code object {index} ({}) at {:#x} {} a DWARF subprogram",
                size.n,
                boundary.instructions_offset,
                if dwarf.is_some() { "has" } else { "lacks" }
            ));
        }
        if let Some(functions) = dwarf
            && functions
                .iter()
                .any(|function: &DwarfFunction| function.size != size.s)
        {
            return Err(format!(
                "{label}: DWARF sizes code object {index} differently from gen_snapshot"
            ));
        }
        function_code_objects += usize::from(is_function);
    }
    let mut owners: usize = 0;
    let mut owners_with_dropped_parent: usize = 0;
    let mut allocation_stubs: usize = 0;
    let mut aliases: usize = 0;
    let mut owned_offsets: BTreeSet<u64> = BTreeSet::new();
    for entry in &names.entries {
        let index: usize = usize::try_from(entry.code_index)
            .ok()
            .and_then(|code_index: usize| code_index.checked_sub(1))
            .ok_or_else(|| format!("{label}: {} has code index 0", entry.qualified_name))?;
        let size: &InstructionSize = build.sizes.get(index).ok_or_else(|| {
            format!(
                "{label}: {} names code index {} past the table",
                entry.qualified_name, entry.code_index
            )
        })?;
        if entry.role == DartCodeNameRole::AllocationStub {
            allocation_stubs += 1;
            grade_allocation_stub(build, entry, size)?;
            continue;
        }
        let dwarf: &Vec<DwarfFunction> = build
            .dwarf
            .by_offset
            .get(&entry.instructions_offset)
            .ok_or_else(|| {
                format!(
                    "{label}: {} at {:#x} is not where DWARF starts a function",
                    entry.qualified_name, entry.instructions_offset
                )
            })?;
        if entry.role != DartCodeNameRole::CodeOwner {
            aliases += 1;
            continue;
        }
        owners += 1;
        if !owned_offsets.insert(entry.instructions_offset) {
            return Err(format!(
                "{label}: two code owners claim {:#x}",
                entry.instructions_offset
            ));
        }
        let expected: String = display_name(&entry.qualified_name, build.reverse_obfuscation);
        let dropped_parent: Option<&str> = expected.strip_prefix(DROPPED_PARENT_PREFIX);
        owners_with_dropped_parent += usize::from(dropped_parent.is_some());
        let matches: bool = dropped_parent.map_or_else(
            || {
                dwarf
                    .iter()
                    .any(|function: &DwarfFunction| function.name == expected)
            },
            |closure: &str| {
                let suffix: String = format!(".{closure}");
                dwarf
                    .iter()
                    .any(|function: &DwarfFunction| function.name.ends_with(&suffix))
            },
        );
        if !matches {
            return Err(format!(
                "{label}: the code object at {:#x} is {:?} in DWARF, disrobe names it {expected}",
                entry.instructions_offset,
                dwarf
                    .iter()
                    .map(|function: &DwarfFunction| function.name.as_str())
                    .collect::<Vec<&str>>()
            ));
        }
        if size.c.as_deref().unwrap_or_default() != entry.class_name.as_deref().unwrap_or_default()
            || size.l != entry.library_url
        {
            return Err(format!(
                "{label}: gen_snapshot owns code object {index} by {:?} in {:?}, disrobe by {:?} in {:?}",
                size.c, size.l, entry.class_name, entry.library_url
            ));
        }
    }
    Ok(CodeNameGrade {
        code_objects: build.sizes.len(),
        function_code_objects,
        allocation_stub_code_objects,
        owners,
        owners_with_dropped_parent,
        allocation_stubs,
        aliases,
    })
}

fn grade_allocation_stub(
    build: &GradedBuild<'_>,
    entry: &DartCodeName,
    size: &InstructionSize,
) -> Result<(), String> {
    let label: &str = &build.label;
    let class: &str = entry.class_name.as_deref().unwrap_or_default();
    if size.n != format!("{ALLOCATION_STUB_PREFIX}{class}")
        || size.c.as_deref() != Some(class)
        || size.l != entry.library_url
    {
        return Err(format!(
            "{label}: gen_snapshot lists code object {} as {} of {:?} in {:?}, disrobe as the allocation stub of {class} in {:?}",
            entry.code_index, size.n, size.c, size.l, entry.library_url
        ));
    }
    let expected: String = display_name(&entry.qualified_name, build.reverse_obfuscation);
    let symbols: &[String] = build
        .dwarf
        .symbols
        .get(&entry.instructions_offset)
        .map_or(&[], Vec::as_slice);
    if !symbols.contains(&expected) {
        return Err(format!(
            "{label}: the ELF symbol at {:#x} is {symbols:?}, disrobe names the allocation stub {expected}",
            entry.instructions_offset
        ));
    }
    Ok(())
}

fn recover(bytes: &[u8], label: &str) -> DartGraphRecoveryReport {
    recover_dart_pinned_elf(
        bytes,
        &DartGraphRecoveryOptions {
            obfuscation_hint: DartGraphObfuscationHint::SourceNames,
            ..DartGraphRecoveryOptions::default()
        },
    )
    .unwrap_or_else(|error| panic!("{label} does not recover: {error}"))
}

fn retarget(
    names: &mut DartCodeNameTable,
    role: DartCodeNameRole,
    mutate: impl Fn(&mut DartCodeName),
) {
    let owner: &mut DartCodeName = names
        .entries
        .iter_mut()
        .rev()
        .find(|entry: &&mut DartCodeName| entry.role == role)
        .expect("a graded build names at least one code owner and one allocation stub");
    mutate(owner);
}

fn assert_mutations_turn_red(build: &GradedBuild<'_>) {
    let renamed: DartGraphRecoveryReport = {
        let mut report: DartGraphRecoveryReport = build.report.clone();
        retarget(
            &mut report.code_names,
            DartCodeNameRole::CodeOwner,
            |entry: &mut DartCodeName| {
                entry.qualified_name.push_str("Renamed");
            },
        );
        report
    };
    let renamed_stub: DartGraphRecoveryReport = {
        let mut report: DartGraphRecoveryReport = build.report.clone();
        retarget(
            &mut report.code_names,
            DartCodeNameRole::AllocationStub,
            |entry: &mut DartCodeName| {
                entry.qualified_name.push_str("Renamed");
            },
        );
        report
    };
    let reowned: DartGraphRecoveryReport = {
        let mut report: DartGraphRecoveryReport = build.report.clone();
        retarget(
            &mut report.code_names,
            DartCodeNameRole::CodeOwner,
            |entry: &mut DartCodeName| {
                entry.class_name = Some("ForeignOwner".to_owned());
            },
        );
        report
    };
    let shifted: DartGraphRecoveryReport = {
        let mut report: DartGraphRecoveryReport = build.report.clone();
        retarget(
            &mut report.code_names,
            DartCodeNameRole::CodeOwner,
            |entry: &mut DartCodeName| {
                entry.instructions_offset += 4;
            },
        );
        report
    };
    let resized: DartGraphRecoveryReport = {
        let mut report: DartGraphRecoveryReport = build.report.clone();
        if let Some(boundary) = report.code_names.boundaries.last_mut() {
            boundary.payload_length += 4;
        }
        report
    };
    for (mutation, report) in [
        ("a renamed code owner", &renamed),
        ("a renamed allocation stub", &renamed_stub),
        ("a code owner moved to another class", &reowned),
        ("a code owner moved four bytes", &shifted),
        ("a code object resized", &resized),
    ] {
        let mutated: GradedBuild<'_> = GradedBuild {
            label: build.label.clone(),
            report,
            sizes: build.sizes,
            dwarf: build.dwarf,
            reverse_obfuscation: build.reverse_obfuscation,
        };
        assert!(
            grade_code_names(&mutated).is_err(),
            "{}: {mutation} must fail the code-name grade",
            build.label
        );
    }
}

#[test]
fn code_names_match_gen_snapshot_dwarf_and_instruction_sizes_on_every_release_build() {
    let oracle: VersionsOracle = versions_oracle();
    for release in &oracle.releases {
        for build in &release.builds {
            let label: String = format!("Dart {} {}", release.dart_version, build.name);
            let bytes: Vec<u8> = read_verified("versions", &build.artifact, &build.sha256);
            let report: DartGraphRecoveryReport = recover(&bytes, &label);
            let sizes: Vec<InstructionSize> = instruction_sizes(
                "versions",
                &build.instruction_sizes,
                &build.instruction_sizes_sha256,
            );
            let debug: Vec<u8> = read_verified(
                "versions",
                &build.debugging_info,
                &build.debugging_info_sha256,
            );
            let dwarf: DwarfFunctions = dwarf_functions(&debug)
                .unwrap_or_else(|error: String| panic!("{label}: DWARF does not read: {error}"));
            let reverse: Option<BTreeMap<String, String>> = build
                .obfuscation_map
                .as_deref()
                .zip(build.obfuscation_map_sha256.as_deref())
                .map(|(name, sha256): (&str, &str)| {
                    reverse_obfuscation_map("versions", name, sha256)
                });
            let graded: GradedBuild<'_> = GradedBuild {
                label: label.clone(),
                report: &report,
                sizes: &sizes,
                dwarf: &dwarf,
                reverse_obfuscation: reverse.as_ref(),
            };
            let grade: CodeNameGrade =
                grade_code_names(&graded).unwrap_or_else(|failure: String| panic!("{failure}"));
            eprintln!(
                "{label}: {} code objects, {} Dart functions in DWARF, {} named by their code owner ({} closures whose parent the snapshot dropped), {} of {} allocation stubs named, {} more functions sharing or pointing at that code",
                grade.code_objects,
                grade.function_code_objects,
                grade.owners,
                grade.owners_with_dropped_parent,
                grade.allocation_stubs,
                grade.allocation_stub_code_objects,
                grade.aliases
            );
            if build.name == "source" {
                assert_eq!(
                    grade.owners, grade.function_code_objects,
                    "{label}: every Dart function code object keeps its owner when DWARF stack traces are off, so every one must be named"
                );
                assert_eq!(grade.owners_with_dropped_parent, 0);
                assert_eq!(
                    grade.allocation_stubs, grade.allocation_stub_code_objects,
                    "{label}: every allocation stub keeps its class when DWARF stack traces are off"
                );
            } else {
                assert!(
                    report.code_names.discarded_entry_count > 0,
                    "{label}: a --dwarf-stack-traces build discards code objects"
                );
            }
            assert_mutations_turn_red(&graded);
        }
    }
}

#[test]
fn code_names_match_gen_snapshot_dwarf_on_the_stripped_ledger_builds() {
    let oracle: LedgerOracle = ledger_oracle();
    for release in &oracle.releases {
        let label: String = format!("ledger Dart {}", release.dart_version);
        let bytes: Vec<u8> = read_verified("ledger", &release.artifact, &release.sha256);
        let report: DartGraphRecoveryReport = recover(&bytes, &label);
        assert_eq!(
            report.snapshot_compatibility_hash,
            release.snapshot_compatibility_hash
        );
        assert_eq!(report.features, release.features);
        let sizes: Vec<InstructionSize> = instruction_sizes(
            "ledger",
            &release.instruction_sizes,
            &release.instruction_sizes_sha256,
        );
        let debug: Vec<u8> = read_verified(
            "ledger",
            &release.debugging_info,
            &release.debugging_info_sha256,
        );
        let dwarf: DwarfFunctions = dwarf_functions(&debug)
            .unwrap_or_else(|error: String| panic!("{label}: DWARF does not read: {error}"));
        let graded: GradedBuild<'_> = GradedBuild {
            label: label.clone(),
            report: &report,
            sizes: &sizes,
            dwarf: &dwarf,
            reverse_obfuscation: None,
        };
        let grade: CodeNameGrade =
            grade_code_names(&graded).unwrap_or_else(|failure: String| panic!("{failure}"));
        assert_eq!(
            grade.owners, grade.function_code_objects,
            "{label}: a stripped build without DWARF stack traces keeps every code owner"
        );
        assert_eq!(grade.owners_with_dropped_parent, 0);
        assert_eq!(
            grade.allocation_stubs, grade.allocation_stub_code_objects,
            "{label}: every allocation stub keeps its class in a stripped build"
        );
        let named: BTreeSet<&str> = report
            .code_names
            .entries
            .iter()
            .filter(|entry: &&DartCodeName| {
                entry.role == DartCodeNameRole::CodeOwner
                    && entry.library_url.as_deref() == Some(oracle.application_library.as_str())
            })
            .map(|entry: &DartCodeName| entry.qualified_name.as_str())
            .collect::<BTreeSet<&str>>();
        let expected: BTreeSet<&str> = oracle
            .application_code
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<&str>>();
        assert!(
            expected.is_subset(&named),
            "{label}: the application code objects {expected:?} must all be named, got {named:?}"
        );
        assert_mutations_turn_red(&graded);
    }
}

fn resolved_literals<'report>(
    report: &'report AotLiftReport,
    function: &str,
) -> BTreeSet<&'report str> {
    report
        .functions
        .iter()
        .filter(|lifted: &&DartLiftedFunction| lifted.name.as_deref() == Some(function))
        .flat_map(|lifted: &DartLiftedFunction| lifted.pool_refs.iter())
        .filter_map(|pool_ref| pool_ref.resolved_content.as_deref())
        .collect::<BTreeSet<&str>>()
}

fn grade_literals(
    report: &AotLiftReport,
    literals: &[LedgerLiteral],
    source: &str,
) -> Result<usize, String> {
    for literal in literals {
        if !source.contains(&literal.source) {
            return Err(format!(
                "the ledger source does not write {}; the literal grade reads the source",
                literal.source
            ));
        }
        if !resolved_literals(report, &literal.function).contains(literal.rendered.as_str()) {
            return Err(format!(
                "{} loads no pool slot that renders {} (source {})",
                literal.function, literal.rendered, literal.source
            ));
        }
    }
    Ok(literals.len())
}

fn call_lines<'body>(body: &'body str, callee: &str) -> Vec<&'body str> {
    body.lines()
        .map(str::trim)
        .filter(|line: &&str| line.contains(&format!("{callee}(")))
        .collect::<Vec<&str>>()
}

fn grade_calling_convention(
    report: &AotLiftReport,
    expected: DartCallingConvention,
    calls: &[ArgumentCall],
) -> Result<(), String> {
    if report.calling_convention != Some(expected) {
        return Err(format!(
            "the lift uses {:?}, the release passes arguments by {expected:?}",
            report.calling_convention
        ));
    }
    let stack_note: bool = report
        .notes
        .iter()
        .any(|note: &String| note.contains(STACK_ARGUMENTS_NOTE));
    match expected {
        DartCallingConvention::StackArguments => {
            if report.structured_function_count != 0 || !stack_note {
                return Err(format!(
                    "a stack-argument release must structure no body and say why; {} bodies structured, note present {stack_note}",
                    report.structured_function_count
                ));
            }
            for call in calls {
                let calls_callee: bool = report
                    .functions
                    .iter()
                    .filter(|lifted: &&DartLiftedFunction| {
                        lifted.name.as_deref() == Some(call.function.as_str())
                    })
                    .any(|lifted: &DartLiftedFunction| {
                        lifted.static_call_names().contains(&call.callee.as_str())
                    });
                if !calls_callee {
                    return Err(format!(
                        "{} must still record its static call to {}",
                        call.function, call.callee
                    ));
                }
            }
        }
        DartCallingConvention::RegisterArguments => {
            if stack_note {
                return Err("a register-argument release must not carry the stack note".to_owned());
            }
            let bodies: Vec<String> = report
                .functions
                .iter()
                .filter(|lifted: &&DartLiftedFunction| lifted.is_structured())
                .map(DartLiftedFunction::best_pseudo_dart)
                .collect::<Vec<String>>();
            for call in calls {
                let carried: bool = bodies.iter().any(|body: &String| {
                    body.starts_with(&format!("{}(", call.function))
                        && call_lines(body, &call.callee).iter().any(|line: &&str| {
                            call.arguments
                                .iter()
                                .all(|argument: &String| line.contains(argument.as_str()))
                        })
                });
                if !carried {
                    return Err(format!(
                        "{} must call {} with {:?} recovered from its argument registers",
                        call.function, call.callee, call.arguments
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn source_literals_and_call_arguments_resolve_through_each_release_abi() {
    let oracle: LedgerOracle = ledger_oracle();
    let source: String = String::from_utf8(read_tracked("ledger", &oracle.source))
        .expect("the ledger source is UTF-8");
    assert!(
        oracle.literals.len() >= 20,
        "the literal grade covers strings, doubles, integers, lists, symbols and type arguments"
    );
    for release in &oracle.releases {
        let label: String = format!("ledger Dart {}", release.dart_version);
        let bytes: Vec<u8> = read_verified("ledger", &release.artifact, &release.sha256);
        let report: AotLiftReport = lift_libapp_aot(&bytes)
            .unwrap_or_else(|error| panic!("{label} does not lift: {error}"));
        assert!(report.abi_resolved, "{label}: the release ABI is pinned");
        assert_eq!(report.version_hash, release.snapshot_compatibility_hash);
        let graded: usize = grade_literals(&report, &oracle.literals, &source)
            .unwrap_or_else(|failure: String| panic!("{label}: {failure}"));
        eprintln!("{label}: {graded} source literals resolved from the object pool");
        grade_calling_convention(
            &report,
            release.calling_convention,
            &oracle.register_argument_calls,
        )
        .unwrap_or_else(|failure: String| panic!("{label}: {failure}"));

        let mut renamed: Vec<LedgerLiteral> = oracle.literals.clone();
        renamed[1].rendered = "\"opening-balances\"".to_owned();
        assert!(
            grade_literals(&report, &renamed, &source).is_err(),
            "{label}: one changed expected string must fail the literal grade"
        );
        let mut renumbered: Vec<LedgerLiteral> = oracle.literals.clone();
        renumbered[2].rendered = "19.96".to_owned();
        assert!(
            grade_literals(&report, &renumbered, &source).is_err(),
            "{label}: one changed expected double must fail the literal grade"
        );
        let flipped: DartCallingConvention = match release.calling_convention {
            DartCallingConvention::StackArguments => DartCallingConvention::RegisterArguments,
            DartCallingConvention::RegisterArguments => DartCallingConvention::StackArguments,
        };
        assert!(
            grade_calling_convention(&report, flipped, &oracle.register_argument_calls).is_err(),
            "{label}: the other calling convention must fail the ABI grade"
        );
        let mut moved: Vec<ArgumentCall> = oracle.register_argument_calls.clone();
        moved[0].arguments[1] = "19.96".to_owned();
        if release.calling_convention == DartCallingConvention::RegisterArguments {
            assert!(
                grade_calling_convention(&report, release.calling_convention, &moved).is_err(),
                "{label}: one changed expected argument must fail the ABI grade"
            );
        }
    }
}

#[test]
fn deobfuscation_follows_the_sdk_token_rule() {
    let reverse: BTreeMap<String, String> = [
        ("Zn".to_owned(), "asUint8List".to_owned()),
        ("_If".to_owned(), "_UnmodifiableByteBufferView".to_owned()),
    ]
    .into_iter()
    .collect::<BTreeMap<String, String>>();
    assert_eq!(
        deobfuscate("_If.Zn", &reverse),
        "_UnmodifiableByteBufferView.asUint8List"
    );
    assert_eq!(
        deobfuscate("new _If", &reverse),
        "new _UnmodifiableByteBufferView"
    );
    assert_eq!(deobfuscate("Zna.Zn=", &reverse), "Zna.asUint8List=");
}
