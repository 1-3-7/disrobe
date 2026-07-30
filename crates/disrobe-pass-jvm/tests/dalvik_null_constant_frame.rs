#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, parse_classfile};

const ITEM_INTEGER: u8 = 1;
const ITEM_NULL: u8 = 5;
const ITEM_OBJECT: u8 = 7;

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

fn sample_ctor() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt35c_one(0x70, 0, 0));
    relocs.push(Reloc::MethodIndex {
        unit: 1,
        method: object_init(),
    });
    units.extend(insn::fmt10x(0x0E));
    EncodedMethod {
        method: MethodRef {
            class: "LSample;".to_owned(),
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

fn pick_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 0));
    units.push(0x38 | (2u16 << 8));
    units.push(5);
    units.extend(insn::fmt21c(0x1A, 0, 0));
    relocs.push(Reloc::StringIndex {
        unit: 4,
        value: "picked".to_owned(),
    });
    units.push(0x28 | (2u16 << 8));
    units.extend(insn::fmt11n(0x12, 1, 1));
    units.extend(insn::fmt11x(0x11, 0));
    EncodedMethod {
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "Ljava/lang/String;".to_owned(),
                params: vec!["I".to_owned()],
            },
            name: "pick".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 3,
        ins_size: 1,
        outs_size: 0,
        insns: units,
        relocations: relocs,
    }
}

fn count_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 0));
    units.push(0x38 | (2u16 << 8));
    units.push(4);
    units.extend(insn::fmt11n(0x12, 0, 7));
    units.push(0x28 | (2u16 << 8));
    units.extend(insn::fmt11n(0x12, 1, 1));
    units.extend(insn::fmt11x(0x0F, 0));
    EncodedMethod {
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "I".to_owned(),
                params: vec!["I".to_owned()],
            },
            name: "count".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 3,
        ins_size: 1,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn make_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LSample;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![sample_ctor(), pick_method(), count_method()],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn cp_utf8(cf: &ClassFile, idx: u16) -> Option<&str> {
    match cf.constant_pool.get(usize::from(idx)) {
        Some(ConstantPoolEntry::Utf8(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn stack_map_body(cf: &ClassFile, method_name: &str) -> Vec<u8> {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some(method_name))
        .unwrap_or_else(|| panic!("{method_name} present"));
    let code = method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .unwrap_or_else(|| panic!("{method_name} has Code"));
    let info: &[u8] = &code.info;
    let code_len: usize = u32::from_be_bytes([info[4], info[5], info[6], info[7]]) as usize;
    let mut o: usize = 8 + code_len;
    let exc_len: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2 + exc_len * 8;
    let attr_count: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2;
    for _ in 0..attr_count {
        let name_idx: u16 = u16::from_be_bytes([info[o], info[o + 1]]);
        let len: usize =
            u32::from_be_bytes([info[o + 2], info[o + 3], info[o + 4], info[o + 5]]) as usize;
        let body_start: usize = o + 6;
        if cp_utf8(cf, name_idx) == Some("StackMapTable") {
            return info[body_start..body_start + len].to_vec();
        }
        o = body_start + len;
    }
    panic!("{method_name} has no StackMapTable attribute");
}

fn local_tags(body: &[u8]) -> Vec<Vec<u8>> {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut o: usize = 0;
    let entries: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2;
    for _ in 0..entries {
        let frame_type: u8 = body[o];
        o += 1;
        assert_eq!(frame_type, 255, "the lifter emits full_frame frames only");
        o += 2;
        let num_locals: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        let mut tags: Vec<u8> = Vec::with_capacity(num_locals);
        for _ in 0..num_locals {
            let tag: u8 = body[o];
            o += 1;
            tags.push(tag);
            if tag == ITEM_OBJECT || tag == 8 {
                o += 2;
            }
        }
        frames.push(tags);
        let num_stack: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_stack {
            let tag: u8 = body[o];
            o += 1;
            if tag == ITEM_OBJECT || tag == 8 {
                o += 2;
            }
        }
    }
    frames
}

fn sample_class() -> ClassFile {
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate crafted dex");
    let sample: &Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present in translation");
    parse_classfile(sample).expect("parse Sample.class")
}

#[test]
fn a_zero_constant_that_joins_a_reference_two_blocks_later_is_framed_as_a_reference() {
    let cf: ClassFile = sample_class();
    let frames: Vec<Vec<u8>> = local_tags(&stack_map_body(&cf, "pick"));
    assert!(
        !frames.is_empty(),
        "pick() branches, so it must carry frames"
    );
    for tags in &frames {
        let slot: u8 = *tags
            .get(1)
            .expect("local 1 carries the register the zero constant defines");
        assert!(
            matches!(slot, ITEM_NULL | ITEM_OBJECT),
            "pick() writes a dalvik zero constant into a register whose only other definition is a \
             String, and the two meet two blocks downstream at the return. The frame declares tag \
             {slot} for that local, which is integer, so the lift stored an int there while the \
             frame at the join describes the merged reference. Deciding the constant's java type \
             from the next instruction alone cannot see a join that far away; the decision has to \
             be made over the whole chain of program points the constant reaches"
        );
    }
}

#[test]
fn a_zero_constant_that_joins_an_int_two_blocks_later_stays_an_int() {
    let cf: ClassFile = sample_class();
    let frames: Vec<Vec<u8>> = local_tags(&stack_map_body(&cf, "count"));
    assert!(
        !frames.is_empty(),
        "count() branches, so it must carry frames"
    );
    for tags in &frames {
        let slot: u8 = *tags
            .get(1)
            .expect("local 1 carries the register the zero constant defines");
        assert_eq!(
            slot, ITEM_INTEGER,
            "count() returns the register the zero constant defines and nothing reaching it is a \
             reference, so the frame has to keep it integer. A resolver that answers `reference` \
             whenever it is unsure would turn every dalvik zero into a null and break every int \
             that starts at zero"
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

const PROBE_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        Class<?> c = Class.forName("Sample", true, Probe.class.getClassLoader());
        c.getDeclaredMethods();
        java.lang.reflect.Method pick = c.getMethod("pick", int.class);
        java.lang.reflect.Method count = c.getMethod("count", int.class);
        System.out.println("verify_ok=1 pick0=" + pick.invoke(null, 0)
            + " pick1=" + pick.invoke(null, 1)
            + " count0=" + count.invoke(null, 0)
            + " count1=" + count.invoke(null, 1));
    }
}
"#;

#[test]
fn the_recovered_class_passes_the_real_jvm_verifier_and_runs() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP -Xverify:all gate: java not on PATH");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP -Xverify:all gate: javac not on PATH");
        return;
    };
    let dir: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        &format!("disrobe_dalvik_null_constant_frame_{}", std::process::id()),
    )
    .expect("scratch dir");
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate crafted dex");
    let sample: &Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present");
    std::fs::write(dir.path().join("Sample.class"), sample).expect("write Sample.class");
    let src: PathBuf = dir.path().join("Probe.java");
    std::fs::write(&src, PROBE_SRC).expect("write Probe.java");
    let compiled: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(dir.path())
        .arg(&src)
        .output()
        .expect("compile Probe");
    assert!(
        compiled.status.success(),
        "compile Probe: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(dir.path())
        .arg("Probe")
        .output()
        .expect("run Probe");
    let stdout: String = String::from_utf8_lossy(&run.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&run.stderr).into_owned();
    assert!(
        run.status.success() && stdout.contains("verify_ok=1"),
        "the recovered Sample did not link and run under -Xverify:all.\nstdout: {stdout}\nstderr: \
         {stderr}"
    );
    assert!(
        stdout.contains("pick0=null") && stdout.contains("pick1=picked"),
        "pick() takes the branch that leaves the zero constant in place when its argument is zero \
         and the branch that assigns the string otherwise, so the recovered method is checked for \
         behaviour and not only for a frame the verifier accepts: {stdout}"
    );
    assert!(
        stdout.contains("count0=0") && stdout.contains("count1=7"),
        "count() must return 0 on the branch that leaves the zero constant in place and 7 on the \
         branch that assigns it: {stdout}"
    );
}
