#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_native::{
    FileIdReport, Finding, IdentityKind, StructClass, StructFamily, StructFinding, identify_file,
    native_struct_findings,
};

fn corpus_bytes(rel: &str) -> Option<Vec<u8>> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(rel);
    std::fs::read(path).ok()
}

fn struct_hit(findings: &[StructFinding], family: StructFamily) -> Option<&StructFinding> {
    findings
        .iter()
        .find(|f: &&StructFinding| f.family == family)
}

#[test]
fn aspack_real_sample_ep_anchored_version_matches_ground_truth() {
    let cases: &[&str] = &[
        "native/packers/aspack/AccessEnum.packed.aspack.exe",
        "native/packers/aspack/Clockres.packed.aspack.exe",
    ];
    let mut present: usize = 0;
    for rel in cases {
        let Some(bytes): Option<Vec<u8>> = corpus_bytes(rel) else {
            continue;
        };
        present += 1;
        let findings: Vec<StructFinding> = native_struct_findings(&bytes);
        let hit: &StructFinding = struct_hit(&findings, StructFamily::Aspack)
            .unwrap_or_else(|| panic!("aspack EP stub not matched in {rel}: {findings:?}"));
        assert_eq!(hit.class, StructClass::Packer);
        let version: &str = hit.version.as_deref().expect("aspack EP version label");
        assert_eq!(
            version, "2.12-2.42",
            "real ASPack EP stub must pin the 2.12-2.42 variant, got {version} in {rel}"
        );
    }
    if present == 0 {
        eprintln!("skip: aspack corpus absent");
    }
}

#[test]
fn pecompact_real_sample_reloc_field_pins_family() {
    let cases: &[&str] = &[
        "native/packers/pecompact/AccessEnum.packed.pecompact.exe",
        "native/packers/pecompact/Clockres.packed.pecompact.exe",
    ];
    let mut present: usize = 0;
    for rel in cases {
        let Some(bytes): Option<Vec<u8>> = corpus_bytes(rel) else {
            continue;
        };
        present += 1;
        let findings: Vec<StructFinding> = native_struct_findings(&bytes);
        let hit: &StructFinding =
            struct_hit(&findings, StructFamily::Pecompact).unwrap_or_else(|| {
                panic!("pecompact PEC2 reloc field not read in {rel}: {findings:?}")
            });
        assert_eq!(hit.class, StructClass::Packer);
        assert!(
            hit.locus.contains("PointerToRelocations"),
            "pecompact must be pinned by the structured reloc field, locus={}",
            hit.locus
        );
    }
    if present == 0 {
        eprintln!("skip: pecompact corpus absent");
    }
}

#[test]
fn msvc_rich_header_yields_exact_toolset_build() {
    let Some(bytes): Option<Vec<u8>> = corpus_bytes("native/packers/upx/hello.original.exe") else {
        eprintln!("skip: rust/msvc original absent");
        return;
    };
    let findings: Vec<StructFinding> = native_struct_findings(&bytes);
    let hit: &StructFinding = struct_hit(&findings, StructFamily::Msvc)
        .unwrap_or_else(|| panic!("rich header not decoded: {findings:?}"));
    let version: &str = hit.version.as_deref().expect("rich exact build");
    assert!(
        version.contains("14.0.35721") && version.contains("VS2015"),
        "rich header must decode the exact MSVC toolset build, got {version}"
    );
}

#[test]
fn go_real_binary_buildinfo_version_matches_toolchain() {
    let Some(bytes): Option<Vec<u8>> = corpus_bytes("native/compilers/go/hello.go.exe") else {
        eprintln!("skip: go compiler sample absent");
        return;
    };
    let findings: Vec<StructFinding> = native_struct_findings(&bytes);
    let hit: &StructFinding = struct_hit(&findings, StructFamily::Go)
        .unwrap_or_else(|| panic!("go buildinfo not decoded: {findings:?}"));
    let version: &str = hit.version.as_deref().expect("go buildinfo version");
    assert_eq!(
        version, "go1.26.3",
        "go buildinfo must decode the exact toolchain version from the manifest oracle (go1.26.3)"
    );
}

#[test]
fn clean_originals_carry_no_false_ep_or_struct_packer_flag() {
    let originals: &[&str] = &[
        "native/packers/aspack/AccessEnum.original.exe",
        "native/packers/aspack/Clockres.original.exe",
        "native/packers/pecompact/AccessEnum.original.exe",
        "native/packers/upx/hello.original.exe",
    ];
    let mut checked: usize = 0;
    for rel in originals {
        let Some(bytes): Option<Vec<u8>> = corpus_bytes(rel) else {
            continue;
        };
        checked += 1;
        let findings: Vec<StructFinding> = native_struct_findings(&bytes);
        let false_packer: bool = findings.iter().any(|f: &StructFinding| {
            matches!(f.class, StructClass::Packer | StructClass::Protector)
        });
        assert!(
            !false_packer,
            "clean original {rel} falsely flagged by EP/struct matcher: {findings:?}"
        );
    }
    if checked == 0 {
        eprintln!("skip: clean originals absent");
    }
}

#[test]
fn identify_file_surfaces_aspack_version_through_cli_report() {
    let Some(bytes): Option<Vec<u8>> =
        corpus_bytes("native/packers/aspack/AccessEnum.packed.aspack.exe")
    else {
        eprintln!("skip: aspack sample absent");
        return;
    };
    let report: FileIdReport = identify_file(&bytes);
    let aspack: &Finding = report
        .of_kind(IdentityKind::Packer)
        .find(|f: &&Finding| f.family == "aspack")
        .expect("aspack reaches the CLI report");
    assert_eq!(aspack.version.as_deref(), Some("2.12-2.42"));
}

#[test]
fn identify_file_surfaces_msvc_exact_build_through_cli_report() {
    let Some(bytes): Option<Vec<u8>> = corpus_bytes("native/packers/upx/hello.original.exe") else {
        eprintln!("skip: msvc original absent");
        return;
    };
    let report: FileIdReport = identify_file(&bytes);
    let msvc: &Finding = report
        .of_kind(IdentityKind::Compiler)
        .find(|f: &&Finding| f.family == "msvc")
        .expect("msvc reaches the CLI report");
    let version: &str = msvc.version.as_deref().expect("msvc version in CLI report");
    assert!(
        version.contains("14.0.35721"),
        "the CLI identify report must carry the exact MSVC build, got {version}"
    );
}

#[test]
fn identify_file_surfaces_go_version_through_cli_report() {
    let Some(bytes): Option<Vec<u8>> = corpus_bytes("native/compilers/go/hello.go.exe") else {
        eprintln!("skip: go sample absent");
        return;
    };
    let report: FileIdReport = identify_file(&bytes);
    let go: &Finding = report
        .of_kind(IdentityKind::Compiler)
        .find(|f: &&Finding| f.family == "go")
        .expect("go reaches the CLI report");
    assert_eq!(go.version.as_deref(), Some("go1.26.3"));
}
