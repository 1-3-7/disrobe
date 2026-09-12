#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]
use std::fs;
use std::io::Read as _;
use std::path::PathBuf;

use disrobe_pass_jvm::protectors::unflatten::{self, CffReport};
use disrobe_pass_jvm::{
    Attribute, CffUndoStats, ClassFile, ConstantPoolEntry, MethodInfo, parse_classfile,
    undo_control_flow,
};

fn r8_jar() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    p.push("r8");
    p.push("EdgeCases-r8.jar");
    p
}

#[test]
fn real_r8_jar_unflattens_without_leaving_a_dispatcher_switch() {
    let Ok(f): Result<fs::File, _> = fs::File::open(r8_jar()) else {
        eprintln!("skip: r8 fixture absent at {}", r8_jar().display());
        return;
    };
    let mut z: zip::ZipArchive<fs::File> = zip::ZipArchive::new(f).expect("zip");
    let mut methods_scanned: u32 = 0;
    let mut residual: u32 = 0;
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if !entry.name().ends_with(".class") {
            continue;
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes).expect("read");
        let Ok(cf): Result<ClassFile, _> = parse_classfile(&bytes) else {
            continue;
        };
        let report: CffReport = unflatten::unflatten_class(&cf);
        methods_scanned += report.methods_scanned;
        residual += report.residual_switch_regions;
    }
    assert!(methods_scanned >= 1, "r8 jar must hold real method bodies");
    assert_eq!(
        residual, 0,
        "the real engine must structure every touched method to a switch-free reducible CFG"
    );
}

#[test]
fn goto_dense_body_without_state_dispatcher_is_not_flagged_flattened() {
    let mut cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("Code".into()),
        ],
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let mut code_body: Vec<u8> = Vec::new();
    for _ in 0..12 {
        code_body.push(0xA7);
        code_body.extend_from_slice(&[0x00, 0x03]);
    }
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
    info.extend_from_slice(&code_body);
    info.extend_from_slice(&0u16.to_be_bytes());
    cf.methods.push(MethodInfo {
        access_flags: 0,
        name_index: 0,
        descriptor_index: 0,
        attributes: vec![Attribute {
            name_index: 1,
            info,
        }],
    });
    let stats: CffUndoStats = undo_control_flow(&cf);
    assert_eq!(
        stats.flattened_methods, 0,
        "counting gotos is not deflattening; only a switch-on-state dispatcher counts"
    );
}
