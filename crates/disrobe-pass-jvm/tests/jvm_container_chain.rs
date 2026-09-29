#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    ChildArtifact, DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER, Pass,
};
use disrobe_core::error::CoreError;
use disrobe_core::scratch::ScratchDir;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_jvm::chain_detector::{JVM_PASS, JvmDetector};
use disrobe_pass_jvm::{JIMAGE_MAGIC, JimageHeader, parse_jimage_header};
use sha2::{Digest, Sha256};

pub mod common;

const JMOD: &[u8] = include_bytes!("fixtures/jmod_probe/probe.jmod");
const JMOD_SHA256: &str = "e975f6c6758f1eb4699541060667dee5cea51bdf2703468ee7f71358264f643c";
const JMOD_PROVENANCE: &str = include_str!("fixtures/jmod_probe/provenance.toml");

const D8_DEX: &[u8] =
    include_bytes!("fixtures/compound_loop_condition/CompoundLoops-release-min21.dex");
const D8_DEX_SHA256: &str = "cfe7c8207627b0bcedcc8c0649c58b59f85a10911e433208c13866f434f335ea";
const D8_PROVENANCE: &str = include_str!("fixtures/compound_loop_condition/provenance.toml");

const MANIFEST: &str = "jvm-container.json";
const TAG_CLASSFILE: &str = "jvm-classfile";
const TAG_DEX: &str = "android-dex";

const OAT_HEADER_FIXED_SIZE: u32 = 56;
const OAT_DEX_LOCATION: &str = "/data/app/probe/base.apk";

const JIMAGE_ATTRIBUTE_MODULE: u8 = 1;
const JIMAGE_ATTRIBUTE_PARENT: u8 = 2;
const JIMAGE_ATTRIBUTE_BASE: u8 = 3;
const JIMAGE_ATTRIBUTE_EXTENSION: u8 = 4;
const JIMAGE_ATTRIBUTE_OFFSET: u8 = 5;
const JIMAGE_ATTRIBUTE_COMPRESSED: u8 = 6;
const JIMAGE_ATTRIBUTE_UNCOMPRESSED: u8 = 7;

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn detect(bytes: &[u8]) -> Option<DetectVerdict> {
    let ctx: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    Detector::detect(&JvmDetector, &ctx)
}

fn extract(bytes: &[u8]) -> Result<Vec<ChildArtifact>, CoreError> {
    JVM_PASS.extract_children(&Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]))
}

fn refusals(bytes: &[u8]) -> Vec<String> {
    JVM_PASS
        .chain_refusals(&Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]))
        .expect("chain refusals")
}

fn assert_container(bytes: &[u8], tag: &str) {
    let verdict: DetectVerdict = detect(bytes).unwrap_or_else(|| panic!("{tag} not detected"));
    assert_eq!(verdict.format_tag, tag);
    assert_eq!(verdict.family, FAMILY_CONTAINER);
    let surfaced: Artifact = JVM_PASS
        .run(&Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]))
        .expect("the container pass run surfaces its manifest");
    let manifest: serde_json::Value =
        serde_json::from_slice(&surfaced.envelope).expect("run output is the JSON manifest");
    assert_eq!(manifest["format"], tag);
}

fn members(children: Vec<ChildArtifact>) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for child in children {
        if child.handle.relative_path == MANIFEST {
            assert_eq!(child.handle.hint.as_deref(), Some(TERMINAL_HINT));
            continue;
        }
        assert!(
            !child.handle.is_terminal(),
            "member {} must be re-chained so the dex and class passes take it",
            child.handle.relative_path
        );
        let name: String = child.handle.relative_path;
        assert!(!out.contains_key(&name), "member {name} emitted twice");
        out.insert(name, child.bytes);
    }
    out
}

fn manifest(children: &[ChildArtifact]) -> serde_json::Value {
    let child: &ChildArtifact = children
        .last()
        .expect("container children end with the manifest");
    assert_eq!(child.handle.relative_path, MANIFEST);
    serde_json::from_slice(&child.bytes).expect("manifest is JSON")
}

fn assert_dense_and_sorted(children: &[ChildArtifact]) {
    for (index, child) in children.iter().enumerate() {
        assert_eq!(child.handle.artifact_index as usize, index);
    }
    let names: Vec<&str> = children[..children.len() - 1]
        .iter()
        .map(|c: &ChildArtifact| c.handle.relative_path.as_str())
        .collect();
    let mut sorted: Vec<&str> = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "member children must be emitted in name order"
    );
}

fn mismatches(
    emitted: &BTreeMap<String, Vec<u8>>,
    reference: &BTreeMap<String, Vec<u8>>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (name, bytes) in reference {
        match emitted.get(name) {
            None => out.push(format!("missing {name}")),
            Some(got) if got != bytes => out.push(format!("differs {name}")),
            Some(_) => {}
        }
    }
    for name in emitted.keys() {
        if !reference.contains_key(name) {
            out.push(format!("extra {name}"));
        }
    }
    out
}

fn assert_grade_and_mutation_control(
    emitted: &mut BTreeMap<String, Vec<u8>>,
    reference: &BTreeMap<String, Vec<u8>>,
) {
    assert!(!reference.is_empty(), "the reference holds no members");
    let found: Vec<String> = mismatches(emitted, reference);
    assert!(
        found.is_empty(),
        "{} of {} member(s) disagree with the reference: {:?}",
        found.len(),
        reference.len(),
        found.iter().take(20).collect::<Vec<&String>>()
    );
    let name: String = emitted
        .iter()
        .find(|(_, bytes): &(&String, &Vec<u8>)| !bytes.is_empty())
        .map(|(name, _): (&String, &Vec<u8>)| name.clone())
        .expect("a non-empty member to mutate");
    flip_first_byte(emitted, &name);
    assert_eq!(
        mismatches(emitted, reference),
        vec![format!("differs {name}")],
        "the mutation control must turn the grade red"
    );
    flip_first_byte(emitted, &name);
}

fn flip_first_byte(emitted: &mut BTreeMap<String, Vec<u8>>, name: &str) {
    let bytes: &mut Vec<u8> = emitted.get_mut(name).expect("member to mutate");
    bytes[0] ^= 0x01;
}

fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read reference directory") {
            let path: PathBuf = entry.expect("reference directory entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative: String = path
                .strip_prefix(root)
                .expect("reference file under the root")
                .components()
                .map(|c: std::path::Component<'_>| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<String>>()
                .join("/");
            out.insert(relative, std::fs::read(&path).expect("read reference file"));
        }
    }
    out
}

fn run_tool(tool: &Path, args: &[&std::ffi::OsStr]) {
    let output: Output = Command::new(tool)
        .args(args)
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("{} did not start: {e}", tool.display()));
    assert!(
        output.status.success(),
        "{} failed: {}",
        tool.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn jmod_members_match_the_jdk_jmod_extract_tree() {
    assert_eq!(sha256_hex(JMOD), JMOD_SHA256);
    assert!(JMOD_PROVENANCE.contains(JMOD_SHA256));
    assert_container(JMOD, "jmod");

    let children: Vec<ChildArtifact> = extract(JMOD).expect("jmod members");
    assert_dense_and_sorted(&children);
    let summary: serde_json::Value = manifest(&children);
    let mut emitted: BTreeMap<String, Vec<u8>> = members(children);

    let jmod: PathBuf = common::grader_jdk_tool("jmod");
    let scratch: ScratchDir = ScratchDir::create("jmod-reference").expect("scratch dir");
    let input: PathBuf = scratch.path().join("probe.jmod");
    std::fs::write(&input, JMOD).expect("write jmod");
    let tree: PathBuf = scratch.path().join("tree");
    run_tool(
        &jmod,
        &[
            "extract".as_ref(),
            "--dir".as_ref(),
            tree.as_os_str(),
            input.as_os_str(),
        ],
    );
    let reference: BTreeMap<String, Vec<u8>> = read_tree(&tree);
    assert_eq!(reference.len(), 5, "the probe jmod records five entries");
    assert_grade_and_mutation_control(&mut emitted, &reference);

    let probe: &Vec<u8> = &emitted["classes/disrobe/probe/Probe.class"];
    assert_eq!(
        detect(probe).map(|v: DetectVerdict| v.format_tag),
        Some(TAG_CLASSFILE),
        "the emitted class member must route to the classfile pass"
    );
    assert_eq!(summary["sections"]["classes"], 3);
    assert_eq!(summary["sections"]["config"], 1);
    assert_eq!(summary["sections"]["headers"], 1);
}

#[test]
fn jimage_members_match_the_jdk_jimage_extract_tree() {
    let jimage: PathBuf = common::grader_jdk_tool("jimage");
    let modules: PathBuf = jimage
        .parent()
        .and_then(Path::parent)
        .expect("the JDK home above bin")
        .join("lib")
        .join("modules");
    let bytes: Vec<u8> = std::fs::read(&modules)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", modules.display()));
    let header: JimageHeader = parse_jimage_header(&bytes).expect("the JDK image header");
    assert_eq!(
        (header.version_major, header.version_minor),
        (1, 0),
        "the JDK writes jimage version 1.0 as one 32-bit word, major in the high half"
    );
    assert_container(&bytes, "jimage");

    let children: Vec<ChildArtifact> = extract(&bytes).expect("jimage members");
    assert_dense_and_sorted(&children);
    let summary: serde_json::Value = manifest(&children);
    let mut emitted: BTreeMap<String, Vec<u8>> = members(children);
    assert!(
        refusals(&bytes).is_empty(),
        "the JDK image stores every resource uncompressed"
    );
    assert_eq!(summary["compressed_not_emitted"], 0);

    let scratch: ScratchDir = ScratchDir::create("jimage-reference").expect("scratch dir");
    let tree: PathBuf = scratch.path().join("tree");
    let dir_arg: std::ffi::OsString = {
        let mut arg: std::ffi::OsString = std::ffi::OsString::from("--dir=");
        arg.push(tree.as_os_str());
        arg
    };
    run_tool(
        &jimage,
        &["extract".as_ref(), dir_arg.as_os_str(), modules.as_os_str()],
    );
    let reference: BTreeMap<String, Vec<u8>> = read_tree(&tree);
    assert!(
        reference.len() > 10_000,
        "jimage extract wrote only {} files",
        reference.len()
    );
    assert_grade_and_mutation_control(&mut emitted, &reference);
    assert_eq!(
        detect(&emitted["java.base/java/lang/Object.class"]).map(|v: DetectVerdict| v.format_tag),
        Some(TAG_CLASSFILE)
    );
}

struct JimageResourceSpec<'a> {
    module: &'a str,
    parent: &'a str,
    base: &'a str,
    extension: &'a str,
    content: &'a [u8],
    compressed: bool,
}

fn intern(strings: &mut Vec<u8>, value: &str) -> u64 {
    let offset: u64 = strings.len() as u64;
    strings.extend_from_slice(value.as_bytes());
    strings.push(0);
    offset
}

fn push_attribute(locations: &mut Vec<u8>, kind: u8, value: u64) {
    let bytes: [u8; 8] = value.to_be_bytes();
    let skip: usize = bytes.iter().take(7).take_while(|b: &&u8| **b == 0).count();
    let significant: &[u8] = &bytes[skip..];
    locations.push((kind << 3) | (significant.len() as u8 - 1));
    locations.extend_from_slice(significant);
}

fn build_jimage(resources: &[JimageResourceSpec<'_>]) -> Vec<u8> {
    let mut strings: Vec<u8> = vec![0];
    let mut locations: Vec<u8> = vec![0];
    let mut offsets: Vec<u32> = Vec::new();
    let mut content: Vec<u8> = Vec::new();
    for resource in resources {
        let module: u64 = intern(&mut strings, resource.module);
        let parent: u64 = intern(&mut strings, resource.parent);
        let base: u64 = intern(&mut strings, resource.base);
        let extension: u64 = intern(&mut strings, resource.extension);
        offsets.push(locations.len() as u32);
        push_attribute(&mut locations, JIMAGE_ATTRIBUTE_MODULE, module);
        push_attribute(&mut locations, JIMAGE_ATTRIBUTE_PARENT, parent);
        push_attribute(&mut locations, JIMAGE_ATTRIBUTE_BASE, base);
        push_attribute(&mut locations, JIMAGE_ATTRIBUTE_EXTENSION, extension);
        push_attribute(
            &mut locations,
            JIMAGE_ATTRIBUTE_OFFSET,
            content.len() as u64,
        );
        if resource.compressed {
            push_attribute(
                &mut locations,
                JIMAGE_ATTRIBUTE_COMPRESSED,
                resource.content.len() as u64,
            );
            push_attribute(
                &mut locations,
                JIMAGE_ATTRIBUTE_UNCOMPRESSED,
                resource.content.len() as u64 * 4,
            );
        } else {
            push_attribute(
                &mut locations,
                JIMAGE_ATTRIBUTE_UNCOMPRESSED,
                resource.content.len() as u64,
            );
        }
        locations.push(0);
        content.extend_from_slice(resource.content);
    }
    let mut image: Vec<u8> = Vec::new();
    image.extend_from_slice(&JIMAGE_MAGIC.to_le_bytes());
    image.extend_from_slice(&(1u32 << 16).to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes());
    image.extend_from_slice(&(resources.len() as u32).to_le_bytes());
    image.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
    image.extend_from_slice(&(locations.len() as u32).to_le_bytes());
    image.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    for _ in &offsets {
        image.extend_from_slice(&0i32.to_le_bytes());
    }
    for offset in &offsets {
        image.extend_from_slice(&offset.to_le_bytes());
    }
    image.extend_from_slice(&locations);
    image.extend_from_slice(&strings);
    image.extend_from_slice(&content);
    image
}

const PROBE_CLASS: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 69, 0, 1];
const PROBE_TEXT: &[u8] = b"a stored resource the image carries verbatim\n";
const PACKED: &[u8] = b"zip-compressed payload the pass refuses";
const PACKAGE_NODE: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 1];

fn synthetic_jimage_resources() -> Vec<JimageResourceSpec<'static>> {
    vec![
        JimageResourceSpec {
            module: "probe.mod",
            parent: "disrobe/probe",
            base: "Probe",
            extension: "class",
            content: PROBE_CLASS,
            compressed: false,
        },
        JimageResourceSpec {
            module: "",
            parent: "",
            base: "packages",
            extension: "",
            content: b"",
            compressed: false,
        },
        JimageResourceSpec {
            module: "packages",
            parent: "disrobe.probe",
            base: "probe.mod",
            extension: "",
            content: PACKAGE_NODE,
            compressed: false,
        },
        JimageResourceSpec {
            module: "probe.mod",
            parent: "disrobe/probe",
            base: "Packed",
            extension: "class",
            content: PACKED,
            compressed: true,
        },
        JimageResourceSpec {
            module: "probe.mod",
            parent: "",
            base: "notes",
            extension: "txt",
            content: PROBE_TEXT,
            compressed: false,
        },
    ]
}

#[test]
fn synthetic_jimage_emits_stored_members_and_refuses_compressed_ones() {
    let image: Vec<u8> = build_jimage(&synthetic_jimage_resources());
    assert_container(&image, "jimage");
    let children: Vec<ChildArtifact> = extract(&image).expect("jimage members");
    assert_dense_and_sorted(&children);
    let summary: serde_json::Value = manifest(&children);
    let mut emitted: BTreeMap<String, Vec<u8>> = members(children);
    let reference: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        (
            "probe.mod/disrobe/probe/Probe.class".to_owned(),
            PROBE_CLASS.to_vec(),
        ),
        ("probe.mod/notes.txt".to_owned(), PROBE_TEXT.to_vec()),
    ]);
    assert_grade_and_mutation_control(&mut emitted, &reference);
    let refused: Vec<String> = refusals(&image);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].contains("probe.mod/disrobe/probe/Packed.class"));
    assert_eq!(summary["compressed_not_emitted"], 1);
}

#[test]
fn hostile_jimage_ranges_and_duplicates_are_typed_errors() {
    let mut past_end: Vec<u8> = build_jimage(&synthetic_jimage_resources());
    past_end.truncate(past_end.len() - PROBE_TEXT.len() / 2);
    assert_eq!(
        detect(&past_end).map(|v: DetectVerdict| v.format_tag),
        Some("jimage")
    );
    let error: String = extract(&past_end)
        .expect_err("a member past the end of the image")
        .to_string();
    assert!(
        error.contains("DR-JVM-0912") && error.contains("DR-JVM-0026"),
        "{error}"
    );

    let duplicate: Vec<u8> = build_jimage(&[
        JimageResourceSpec {
            module: "m",
            parent: "",
            base: "a",
            extension: "txt",
            content: b"one",
            compressed: false,
        },
        JimageResourceSpec {
            module: "m",
            parent: "",
            base: "a",
            extension: "txt",
            content: b"two",
            compressed: false,
        },
    ]);
    let error: String = extract(&duplicate)
        .expect_err("a name listed twice")
        .to_string();
    assert!(error.contains("DR-JVM-0098"), "{error}");
}

fn build_odex(dex: &[u8]) -> Vec<u8> {
    let dex_offset: u32 = 40;
    let mut odex: Vec<u8> = Vec::new();
    odex.extend_from_slice(b"dey\n036\0");
    odex.extend_from_slice(&dex_offset.to_le_bytes());
    odex.extend_from_slice(&(dex.len() as u32).to_le_bytes());
    for _ in 0..6 {
        odex.extend_from_slice(&0u32.to_le_bytes());
    }
    odex.extend_from_slice(dex);
    odex
}

fn assert_d8_dex_member(bytes: &[u8], tag: &str) -> serde_json::Value {
    assert_eq!(sha256_hex(D8_DEX), D8_DEX_SHA256);
    assert!(D8_PROVENANCE.contains(D8_DEX_SHA256));
    assert_container(bytes, tag);
    let children: Vec<ChildArtifact> = extract(bytes).expect("container members");
    assert_dense_and_sorted(&children);
    let summary: serde_json::Value = manifest(&children);
    let mut emitted: BTreeMap<String, Vec<u8>> = members(children);
    let reference: BTreeMap<String, Vec<u8>> =
        BTreeMap::from([("classes.dex".to_owned(), D8_DEX.to_vec())]);
    assert_grade_and_mutation_control(&mut emitted, &reference);
    assert_eq!(
        sha256_hex(&emitted["classes.dex"]),
        D8_DEX_SHA256,
        "the embedded dex must hash to the D8 build record"
    );
    assert_eq!(
        detect(&emitted["classes.dex"]).map(|v: DetectVerdict| v.format_tag),
        Some(TAG_DEX),
        "the embedded dex must route to the dex pass"
    );
    summary
}

#[test]
fn odex_embedded_dex_matches_the_d8_build_record() {
    let odex: Vec<u8> = build_odex(D8_DEX);
    let summary: serde_json::Value = assert_d8_dex_member(&odex, "android-odex");
    assert_eq!(summary["dexopt_version"], "036");
    assert_eq!(summary["dex_offset"], 40);
}

#[test]
fn odex_whose_dex_overruns_the_file_is_not_claimed() {
    let mut odex: Vec<u8> = build_odex(D8_DEX);
    odex.truncate(odex.len() - 1);
    assert!(detect(&odex).is_none());
}

fn oat_rodata(dex: &[u8], dex_file_offset_delta: u32) -> Vec<u8> {
    let key_values: &[u8] = b"compiler-filter\0verify\0";
    let oat_dex_files_offset: u32 = OAT_HEADER_FIXED_SIZE + key_values.len() as u32;
    let mut entry: Vec<u8> = Vec::new();
    entry.extend_from_slice(&(OAT_DEX_LOCATION.len() as u32).to_le_bytes());
    entry.extend_from_slice(OAT_DEX_LOCATION.as_bytes());
    entry.extend_from_slice(&0x1357_9BDFu32.to_le_bytes());
    let dex_file_offset: u32 = oat_dex_files_offset + entry.len() as u32 + 4;
    entry.extend_from_slice(&(dex_file_offset + dex_file_offset_delta).to_le_bytes());

    let mut rodata: Vec<u8> = Vec::new();
    rodata.extend_from_slice(b"oat\n");
    rodata.extend_from_slice(b"183\0");
    rodata.extend_from_slice(&0u32.to_le_bytes());
    rodata.extend_from_slice(&2i32.to_le_bytes());
    rodata.extend_from_slice(&0u32.to_le_bytes());
    rodata.extend_from_slice(&1u32.to_le_bytes());
    rodata.extend_from_slice(&oat_dex_files_offset.to_le_bytes());
    for _ in 0..6 {
        rodata.extend_from_slice(&0u32.to_le_bytes());
    }
    rodata.extend_from_slice(&(key_values.len() as u32).to_le_bytes());
    rodata.extend_from_slice(key_values);
    rodata.extend_from_slice(&entry);
    rodata.extend_from_slice(dex);
    rodata
}

fn build_oat_elf(rodata: &[u8]) -> Vec<u8> {
    use object::write::{Object, StandardSection, Symbol, SymbolFlags, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolKind, SymbolScope};
    let mut obj: Object<'_> =
        Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let text: object::write::SectionId = obj.section_id(StandardSection::Text);
    obj.append_section_data(text, &[0x1F, 0x20, 0x03, 0xD5], 4);
    let rodata_id: object::write::SectionId = obj.section_id(StandardSection::ReadOnlyData);
    obj.append_section_data(rodata_id, b"oat\nnot the header, a decoy", 16);
    let offset: u64 = obj.append_section_data(rodata_id, rodata, 16);
    obj.add_symbol(Symbol {
        name: b"oatdata".to_vec(),
        value: offset,
        size: rodata.len() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(rodata_id),
        flags: SymbolFlags::None,
    });
    obj.write().expect("write oat elf")
}

#[test]
fn oat_embedded_dex_matches_the_d8_build_record() {
    let oat: Vec<u8> = build_oat_elf(&oat_rodata(D8_DEX, 0));
    let summary: serde_json::Value = assert_d8_dex_member(&oat, "android-oat");
    assert_eq!(summary["oat_version"], 183);
    assert_eq!(summary["instruction_set"], "arm64");
    assert_eq!(summary["dex_locations"][0], OAT_DEX_LOCATION);
    assert_eq!(summary["key_value_store"]["compiler-filter"], "verify");
    assert!(refusals(&oat).is_empty());
}

#[test]
fn oat_whose_dex_offset_misses_the_dex_is_refused_not_guessed() {
    let oat: Vec<u8> = build_oat_elf(&oat_rodata(D8_DEX, 4));
    assert_container(&oat, "android-oat");
    let children: Vec<ChildArtifact> = extract(&oat).expect("the header still surfaces");
    assert_eq!(children.len(), 1, "only the manifest, no guessed dex");
    let refused: Vec<String> = refusals(&oat);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].contains("DR-JVM-0030"), "{refused:?}");
    assert_eq!(manifest(&children)["refusals"][0], refused[0].as_str());
}

#[test]
fn plain_elf_without_oatdata_is_not_claimed() {
    use object::write::{Object, StandardSection};
    use object::{Architecture, BinaryFormat, Endianness};
    let mut obj: Object<'_> =
        Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let rodata: object::write::SectionId = obj.section_id(StandardSection::ReadOnlyData);
    obj.append_section_data(rodata, &oat_rodata(D8_DEX, 0), 16);
    let elf: Vec<u8> = obj.write().expect("write elf");
    assert!(detect(&elf).is_none());
}

#[test]
fn corrupt_jmod_is_a_typed_error() {
    let mut broken: Vec<u8> = JMOD.to_vec();
    let end: usize = broken.len();
    broken[end - 22..].fill(0);
    assert_eq!(
        detect(&broken).map(|v: DetectVerdict| v.format_tag),
        Some("jmod")
    );
    let error: String = extract(&broken)
        .expect_err("a jmod without its end record")
        .to_string();
    assert!(error.contains("DR-JVM-0912"), "{error}");
}

#[test]
fn every_truncation_of_every_container_is_handled_without_panic() {
    let samples: Vec<Vec<u8>> = vec![
        JMOD.to_vec(),
        build_jimage(&synthetic_jimage_resources()),
        build_odex(D8_DEX),
        build_oat_elf(&oat_rodata(D8_DEX, 0)),
    ];
    let mut outcomes: BTreeSet<&'static str> = BTreeSet::new();
    for sample in &samples {
        for len in 0..=sample.len() {
            let prefix: &[u8] = &sample[..len];
            let claimed: bool = detect(prefix).is_some();
            match extract(prefix) {
                Ok(_) => {
                    outcomes.insert(if claimed { "claimed-ok" } else { "unclaimed" });
                }
                Err(error) => {
                    assert!(
                        error.to_string().contains("DR-JVM-09"),
                        "untyped failure: {error}"
                    );
                    outcomes.insert("typed-error");
                }
            }
        }
    }
    assert!(outcomes.contains("typed-error") && outcomes.contains("claimed-ok"));
}
