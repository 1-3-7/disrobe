#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, parse_classfile};

const CONVERSIONS: &[(u8, &str, &str, &str)] = &[
    (0x81, "Ci2l", "I", "J"),
    (0x82, "Ci2f", "I", "F"),
    (0x83, "Ci2d", "I", "D"),
    (0x84, "Cl2i", "J", "I"),
    (0x85, "Cl2f", "J", "F"),
    (0x86, "Cl2d", "J", "D"),
    (0x87, "Cf2i", "F", "I"),
    (0x88, "Cf2l", "F", "J"),
    (0x89, "Cf2d", "F", "D"),
    (0x8A, "Cd2i", "D", "I"),
    (0x8B, "Cd2l", "D", "J"),
    (0x8C, "Cd2f", "D", "F"),
    (0x8D, "Ci2b", "I", "I"),
    (0x8E, "Ci2c", "I", "I"),
    (0x8F, "Ci2s", "I", "I"),
];

fn is_wide_desc(desc: &str) -> bool {
    desc == "J" || desc == "D"
}

fn object_init() -> MethodRef {
    MethodRef {
        class: "Ljava/lang/Object;".to_owned(),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: Vec::new(),
        },
        name: "<init>".to_owned(),
    }
}

fn conv_ctor(class: &str) -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt35c_one(0x70, 0, 0));
    relocs.push(Reloc::MethodIndex {
        unit: 1,
        method: object_init(),
    });
    units.extend(insn::fmt10x(0x0E));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: format!("L{class};"),
            proto: ProtoRef {
                return_type: "V".to_owned(),
                params: Vec::new(),
            },
            name: "<init>".to_owned(),
        },
        access_flags: 0x1,
        is_direct: true,
        registers_size: 1,
        ins_size: 1,
        outs_size: 1,
        insns: units,
        relocations: relocs,
    }
}

fn conv_method(op: u8, class: &str, src: &str, ret: &str) -> EncodedMethod {
    let src_width: u16 = if is_wide_desc(src) { 2 } else { 1 };
    let dest_width: u16 = if is_wide_desc(ret) { 2 } else { 1 };
    let ins_size: u16 = src_width + 1;
    let registers_size: u16 = dest_width + ins_size;
    let src_reg: u8 = u8::try_from(dest_width).unwrap();
    let cond_reg: u8 = u8::try_from(dest_width + src_width).unwrap();

    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(op, 0, src_reg));
    units.push(0x38 | (u16::from(cond_reg) << 8));
    units.push(3);
    units.extend(insn::fmt10x(0x00));
    let ret_op: u8 = if is_wide_desc(ret) { 0x10 } else { 0x0F };
    units.extend(insn::fmt11x(ret_op, 0));

    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: format!("L{class};"),
            proto: ProtoRef {
                return_type: ret.to_owned(),
                params: vec![src.to_owned(), "I".to_owned()],
            },
            name: "conv".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn conv_class(op: u8, class: &str, src: &str, ret: &str) -> ClassDef {
    ClassDef {
        class: format!("L{class};"),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![conv_ctor(class), conv_method(op, class, src, ret)],
        virtual_methods: Vec::new(),
    }
}

fn make_conversion_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    for (op, class, src, ret) in CONVERSIONS {
        builder.add_class(conv_class(*op, class, src, ret));
    }
    builder.build()
}

fn cp_utf8(cf: &ClassFile, idx: u16) -> Option<&str> {
    match cf.constant_pool.get(usize::from(idx)) {
        Some(ConstantPoolEntry::Utf8(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn stack_map_local_tags(cf: &ClassFile) -> Vec<u8> {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some("conv"))
        .expect("conv method present");
    let code = method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .expect("conv has Code");
    let info: &[u8] = &code.info;
    let code_len: usize = u32::from_be_bytes([info[4], info[5], info[6], info[7]]) as usize;
    let mut o: usize = 8 + code_len;
    let exc_len: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2 + exc_len * 8;
    let attr_count: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2;
    let mut body: Option<&[u8]> = None;
    for _ in 0..attr_count {
        let name_idx: u16 = u16::from_be_bytes([info[o], info[o + 1]]);
        let len: usize =
            u32::from_be_bytes([info[o + 2], info[o + 3], info[o + 4], info[o + 5]]) as usize;
        let start: usize = o + 6;
        if cp_utf8(cf, name_idx) == Some("StackMapTable") {
            body = Some(&info[start..start + len]);
            break;
        }
        o = start + len;
    }
    let body: &[u8] = body.expect("conv has a StackMapTable attribute");
    let mut tags: Vec<u8> = Vec::new();
    let mut p: usize = 0;
    let entries: usize = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    for _ in 0..entries {
        assert_eq!(body[p], 255, "lifter emits full_frame frames only");
        p += 1 + 2;
        let num_locals: usize = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        for _ in 0..num_locals {
            let tag: u8 = body[p];
            tags.push(tag);
            p += 1;
            if tag == 7 || tag == 8 {
                p += 2;
            }
        }
        let num_stack: usize = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        for _ in 0..num_stack {
            let tag: u8 = body[p];
            p += 1;
            if tag == 7 || tag == 8 {
                p += 2;
            }
        }
    }
    tags
}

fn tag_for_desc(desc: &str) -> u8 {
    match desc {
        "J" => 4,
        "F" => 2,
        "D" => 3,
        _ => 1,
    }
}

fn nonzero_tag_multiset(tags: &[u8]) -> BTreeMap<u8, usize> {
    let mut out: BTreeMap<u8, usize> = BTreeMap::new();
    for &t in tags {
        if t != 0 {
            *out.entry(t).or_insert(0) += 1;
        }
    }
    out
}

#[test]
fn conversion_merge_frames_type_the_result_register_per_jvm_semantics() {
    let result: Dex2JarResult =
        translate_dex_bytes(&make_conversion_dex()).expect("translate crafted conversion dex");
    for (_op, class, src, ret) in CONVERSIONS {
        let entry: &Vec<u8> = result
            .jar_entries
            .get(&format!("{class}.class"))
            .unwrap_or_else(|| panic!("{class}.class present in translation"));
        let cf: ClassFile = parse_classfile(entry).expect("parse conversion class");
        let tags: Vec<u8> = stack_map_local_tags(&cf);
        let actual: BTreeMap<u8, usize> = nonzero_tag_multiset(&tags);
        let mut expected: BTreeMap<u8, usize> = BTreeMap::new();
        *expected.entry(tag_for_desc(src)).or_insert(0) += 1;
        *expected.entry(tag_for_desc(ret)).or_insert(0) += 1;
        *expected.entry(1).or_insert(0) += 1;
        assert_eq!(
            actual, expected,
            "{class} ({src}->{ret}): the merge frame local types {tags:?} do not match the \
             expected multiset (source {src}, the branch-condition int, and the converted result \
             {ret}); a mis-typed numeric-conversion result in the shipped dalvik typestate makes \
             the StackMapTable disagree with the emitted store instruction"
        );
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn class_names() -> String {
    CONVERSIONS
        .iter()
        .map(|(_op, class, _src, _ret): &(u8, &str, &str, &str)| format!("\"{class}\""))
        .collect::<Vec<String>>()
        .join(", ")
}

#[test]
fn every_numeric_conversion_class_passes_xverify_all() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP conversion -Xverify:all gate: java not on PATH");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP conversion -Xverify:all gate: javac not on PATH");
        return;
    };

    let result: Dex2JarResult =
        translate_dex_bytes(&make_conversion_dex()).expect("translate crafted conversion dex");

    let purpose: String = format!("disrobe_conv_frame_verifier_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();

    for (_op, class, _src, _ret) in CONVERSIONS {
        let entry: &Vec<u8> = result
            .jar_entries
            .get(&format!("{class}.class"))
            .unwrap_or_else(|| panic!("{class}.class present in translation"));
        std::fs::write(dir.join(format!("{class}.class")), entry).expect("write class");
    }

    let probe_src: String = PROBE_SRC.replace("__NAMES__", &class_names());
    let probe_path: PathBuf = dir.join("Probe.java");
    std::fs::write(&probe_path, &probe_src).expect("write probe");
    let compiled: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&dir)
        .arg(&probe_path)
        .output()
        .expect("javac probe");
    assert!(
        compiled.status.success(),
        "conversion probe did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let run: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(&dir)
        .arg("Probe")
        .output()
        .expect("run java probe");
    let out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    let err: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stderr);
    eprintln!(
        "CONVERSION VERIFY: status={} stdout={} stderr={}",
        run.status,
        out.trim(),
        err.trim()
    );

    let clean: usize = out
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("conv_clean="))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(0);
    let fail: usize = out
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("conv_fail="))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let other: usize = out
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("conv_other="))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(usize::MAX);

    assert!(
        run.status.success() && out.contains("conv_clean="),
        "the conversion probe did not run to completion under -Xverify:all"
    );
    assert_eq!(
        fail,
        0,
        "at least one lifted numeric-conversion class was rejected by the real JVM verifier; \
         the shipped dalvik typestate mis-types a conversion result so the StackMapTable frame \
         disagrees with the emitted conversion+store. per-class: {}",
        out.trim()
    );
    assert_eq!(
        other,
        0,
        "a conversion class failed to load for a non-verify reason: {}",
        out.trim()
    );
    assert_eq!(
        clean,
        CONVERSIONS.len(),
        "expected all {} numeric-conversion classes to pass -Xverify:all: {}",
        CONVERSIONS.len(),
        out.trim()
    );
}

const PROBE_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        String[] names = { __NAMES__ };
        int clean = 0, fail = 0, other = 0;
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            try {
                Class<?> c = Class.forName(n, true, Probe.class.getClassLoader());
                c.getDeclaredMethods();
                c.getDeclaredConstructors();
                clean++;
                sb.append(n).append("=clean ");
            } catch (VerifyError ve) {
                fail++;
                String m = String.valueOf(ve.getMessage()).replace('\n', ' ');
                sb.append(n).append("=FAIL(").append(m.substring(0, Math.min(120, m.length()))).append(") ");
            } catch (Throwable t) {
                other++;
                sb.append(n).append("=OTHER(").append(t.getClass().getSimpleName()).append(") ");
            }
        }
        System.out.println("conv_clean=" + clean + " conv_fail=" + fail + " conv_other=" + other);
        System.out.println(sb.toString().trim());
    }
}
"#;
