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
    ClassDef, DexBuilder, EncodedField, EncodedMethod, FieldRef, MethodRef, ProtoRef, Reloc, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, parse_classfile};

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

fn foo_init() -> MethodRef {
    MethodRef {
        class: "LFoo;".to_owned(),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: vec!["I".to_owned()],
        },
        name: "<init>".to_owned(),
    }
}

fn make_dex() -> Vec<u8> {
    let mut foo_init_units: Vec<u16> = Vec::new();
    let mut foo_init_relocs: Vec<Reloc> = Vec::new();
    let base: usize = foo_init_units.len();
    foo_init_units.extend(insn::fmt35c_one(0x70, 0, 0));
    foo_init_relocs.push(Reloc::MethodIndex {
        unit: base + 1,
        method: object_init(),
    });
    foo_init_units.extend(insn::fmt10x(0x0E));

    let foo_ctor: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
        method: foo_init(),
        access_flags: 0x1,
        is_direct: true,
        registers_size: 2,
        ins_size: 2,
        outs_size: 1,
        insns: foo_init_units,
        relocations: foo_init_relocs,
    };

    let mut sample_init_units: Vec<u16> = Vec::new();
    let mut sample_init_relocs: Vec<Reloc> = Vec::new();
    let sbase: usize = sample_init_units.len();
    sample_init_units.extend(insn::fmt35c_one(0x70, 0, 0));
    sample_init_relocs.push(Reloc::MethodIndex {
        unit: sbase + 1,
        method: object_init(),
    });
    sample_init_units.extend(insn::fmt10x(0x0E));
    let sample_ctor: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
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
        insns: sample_init_units,
        relocations: sample_init_relocs,
    };

    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    let new_pos: usize = units.len();
    units.extend(insn::fmt21c(0x22, 0, 0));
    relocs.push(Reloc::TypeIndex {
        unit: new_pos + 1,
        descriptor: "LFoo;".to_owned(),
    });
    units.push(0x38 | (2u16 << 8));
    units.push(4);
    units.extend(insn::fmt11n(0x12, 1, 1));
    units.push(0x28 | (2u16 << 8));
    units.extend(insn::fmt11n(0x12, 1, 2));
    let invoke_pos: usize = units.len();
    units.extend(insn::fmt35c_two(0x70, 0, 1, 0));
    relocs.push(Reloc::MethodIndex {
        unit: invoke_pos + 1,
        method: foo_init(),
    });
    units.extend(insn::fmt11x(0x11, 0));

    let make_method: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "LFoo;".to_owned(),
                params: vec!["Z".to_owned()],
            },
            name: "make".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 3,
        ins_size: 1,
        outs_size: 2,
        insns: units,
        relocations: relocs,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LFoo;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![foo_ctor],
        virtual_methods: Vec::new(),
    });
    builder.add_class(ClassDef {
        class: "LSample;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![sample_ctor, make_method],
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

fn stack_map_body(cf: &ClassFile) -> Vec<u8> {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some("make"))
        .expect("make method present");
    let code = method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .expect("make has Code");
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
    panic!("make has no StackMapTable attribute");
}

fn tag8_body_offsets(body: &[u8]) -> Vec<usize> {
    let mut found: Vec<usize> = Vec::new();
    let mut o: usize = 0;
    let entries: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2;
    for _ in 0..entries {
        let frame_type: u8 = body[o];
        o += 1;
        assert_eq!(frame_type, 255, "lifter emits full_frame frames only");
        o += 2;
        let num_locals: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_locals {
            let tag: u8 = body[o];
            o += 1;
            if tag == 8 {
                found.push(o);
                o += 2;
            } else if tag == 7 {
                o += 2;
            }
        }
        let num_stack: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_stack {
            let tag: u8 = body[o];
            o += 1;
            if tag == 7 || tag == 8 {
                o += 2;
            }
        }
    }
    found
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("StackMapTable body must occur in the class bytes")
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

fn translate() -> Dex2JarResult {
    translate_dex_bytes(&make_dex()).expect("translate crafted dex")
}

#[test]
fn cross_block_new_instance_emits_uninitialized_offset_frame() {
    let result: Dex2JarResult = translate();
    let sample: &Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present in translation");
    let cf: ClassFile = parse_classfile(sample).expect("parse Sample.class");
    let body: Vec<u8> = stack_map_body(&cf);
    let offsets: Vec<usize> = tag8_body_offsets(&body);
    assert!(
        !offsets.is_empty(),
        "make() must carry an Uninitialized(offset) verification type for the not-yet-<init>ed \
         Foo reference that is live across the argument branch; none was emitted, so the lift fell \
         back to a strategy that does not exercise tag 8"
    );
    for &rel in &offsets {
        let target: u16 = u16::from_be_bytes([body[rel], body[rel + 1]]);
        assert_eq!(
            target, 0,
            "the Uninitialized entry must point at the `new` bytecode (offset 0 in make())"
        );
    }
}

fn verify_dir(java: &PathBuf, dir: &std::path::Path) -> std::process::Output {
    Command::new(java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(dir)
        .arg("Probe")
        .output()
        .expect("run java probe")
}

const PROBE_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        Class<?> c = Class.forName("Sample", true, Probe.class.getClassLoader());
        c.getDeclaredMethods();
        java.lang.reflect.Method m = c.getMethod("make", boolean.class);
        Object t = m.invoke(null, true);
        Object f = m.invoke(null, false);
        System.out.println("verify_ok=1 " + t.getClass().getName() + " " + f.getClass().getName());
    }
}
"#;

#[test]
fn recovered_class_verifies_and_wrong_offset_is_rejected() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP -Xverify:all gate: java not on PATH");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP -Xverify:all gate: javac not on PATH");
        return;
    };

    let result: Dex2JarResult = translate();
    let sample: Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present")
        .clone();
    let foo: Vec<u8> = result
        .jar_entries
        .get("Foo.class")
        .expect("Foo.class present")
        .clone();

    let purpose: String = format!("disrobe_uninit_frame_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let ok_dir: PathBuf = root.join("ok");
    let bad_dir: PathBuf = root.join("bad");
    std::fs::create_dir_all(&ok_dir).expect("mkdir ok");
    std::fs::create_dir_all(&bad_dir).expect("mkdir bad");

    let probe_src: PathBuf = ok_dir.join("Probe.java");
    std::fs::write(&probe_src, PROBE_SRC).expect("write probe");
    let compiled: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&ok_dir)
        .arg(&probe_src)
        .output()
        .expect("javac probe");
    assert!(
        compiled.status.success(),
        "probe did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    std::fs::copy(ok_dir.join("Probe.class"), bad_dir.join("Probe.class")).expect("copy probe");

    std::fs::write(ok_dir.join("Foo.class"), &foo).expect("write foo ok");
    std::fs::write(ok_dir.join("Sample.class"), &sample).expect("write sample ok");
    std::fs::write(bad_dir.join("Foo.class"), &foo).expect("write foo bad");

    let cf: ClassFile = parse_classfile(&sample).expect("parse Sample.class");
    let body: Vec<u8> = stack_map_body(&cf);
    let body_abs: usize = find_subslice(&sample, &body);
    let rel: usize = *tag8_body_offsets(&body)
        .first()
        .expect("a tag-8 offset exists");
    let mut corrupt: Vec<u8> = sample;
    corrupt[body_abs + rel] = 0xFF;
    corrupt[body_abs + rel + 1] = 0xFF;
    std::fs::write(bad_dir.join("Sample.class"), &corrupt).expect("write sample bad");

    let ok: std::process::Output = verify_dir(&java, &ok_dir);
    let ok_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&ok.stdout);
    eprintln!(
        "POSITIVE (correct Uninitialized(0) frame): status={} stdout={} stderr={}",
        ok.status,
        ok_out.trim(),
        String::from_utf8_lossy(&ok.stderr).trim()
    );
    assert!(
        ok.status.success() && ok_out.contains("verify_ok=1") && ok_out.contains("Foo Foo"),
        "the recovered Sample.class with a correct Uninitialized(offset) frame must pass \
         -Xverify:all and construct a Foo on both arms"
    );

    let bad: std::process::Output = verify_dir(&java, &bad_dir);
    let bad_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad.stdout);
    let bad_err: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad.stderr);
    eprintln!(
        "NEGATIVE (Uninitialized offset corrupted to 0xFFFF): status={} stdout={} stderr={}",
        bad.status,
        bad_out.trim(),
        bad_err.trim()
    );
    assert!(
        !bad.status.success() && !bad_out.contains("verify_ok=1"),
        "the corrupted-offset class must not pass; the verifier accepted a wrong Uninitialized \
         frame, so the positive result is vacuous"
    );
    assert!(
        bad_err.contains("Uninitialized")
            || bad_err.contains("StackMapTable")
            || bad_err.contains("VerifyError")
            || bad_err.contains("ClassFormatError"),
        "the corrupted-offset class must be rejected by the JVM for the bad Uninitialized offset; \
         stderr was:\n{bad_err}"
    );
}

fn make_alias_dex() -> Vec<u8> {
    let mut foo_init_units: Vec<u16> = Vec::new();
    let mut foo_init_relocs: Vec<Reloc> = Vec::new();
    foo_init_units.extend(insn::fmt35c_one(0x70, 0, 0));
    foo_init_relocs.push(Reloc::MethodIndex {
        unit: 1,
        method: object_init(),
    });
    foo_init_units.extend(insn::fmt10x(0x0E));
    let foo_ctor: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
        method: foo_init(),
        access_flags: 0x1,
        is_direct: true,
        registers_size: 2,
        ins_size: 2,
        outs_size: 1,
        insns: foo_init_units,
        relocations: foo_init_relocs,
    };

    let mut sample_init_units: Vec<u16> = Vec::new();
    let mut sample_init_relocs: Vec<Reloc> = Vec::new();
    sample_init_units.extend(insn::fmt35c_one(0x70, 0, 0));
    sample_init_relocs.push(Reloc::MethodIndex {
        unit: 1,
        method: object_init(),
    });
    sample_init_units.extend(insn::fmt10x(0x0E));
    let sample_ctor: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
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
        insns: sample_init_units,
        relocations: sample_init_relocs,
    };

    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt21c(0x22, 0, 0));
    relocs.push(Reloc::TypeIndex {
        unit: 1,
        descriptor: "LFoo;".to_owned(),
    });
    units.extend(insn::fmt12x(0x07, 1, 0));
    units.extend(insn::fmt11n(0x12, 2, 1));
    units.push(0x38 | (3u16 << 8));
    units.push(4);
    units.extend(insn::fmt11n(0x12, 2, 7));
    units.push(0x28 | (2u16 << 8));
    units.extend(insn::fmt11n(0x12, 2, 9));
    let invoke_pos: usize = units.len();
    units.extend(insn::fmt35c_two(0x70, 1, 2, 0));
    relocs.push(Reloc::MethodIndex {
        unit: invoke_pos + 1,
        method: foo_init(),
    });
    units.push(0x38 | (4u16 << 8));
    units.push(3);
    units.extend(insn::fmt11n(0x12, 2, 3));
    units.extend(insn::fmt11x(0x11, 0));

    let make_method: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "LFoo;".to_owned(),
                params: vec!["Z".to_owned(), "Z".to_owned()],
            },
            name: "make".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 5,
        ins_size: 2,
        outs_size: 2,
        insns: units,
        relocations: relocs,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LFoo;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![foo_ctor],
        virtual_methods: Vec::new(),
    });
    builder.add_class(ClassDef {
        class: "LSample;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![sample_ctor, make_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn translate_alias() -> Dex2JarResult {
    translate_dex_bytes(&make_alias_dex()).expect("translate crafted alias dex")
}

fn first_local_tag7_pos(body: &[u8]) -> Option<usize> {
    let mut o: usize = 0;
    let entries: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2;
    for _ in 0..entries {
        let frame_type: u8 = body[o];
        o += 1;
        assert_eq!(frame_type, 255, "lifter emits full_frame frames only");
        o += 2;
        let num_locals: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_locals {
            let tag: u8 = body[o];
            if tag == 7 {
                return Some(o);
            }
            o += 1;
            if tag == 8 {
                o += 2;
            }
        }
        let num_stack: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_stack {
            let tag: u8 = body[o];
            o += 1;
            if tag == 7 || tag == 8 {
                o += 2;
            }
        }
    }
    None
}

#[test]
fn alias_move_of_uninitialized_ref_emits_shared_offset_frames() {
    let result: Dex2JarResult = translate_alias();
    let sample: &Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present in alias translation");
    let cf: ClassFile = parse_classfile(sample).expect("parse alias Sample.class");
    let body: Vec<u8> = stack_map_body(&cf);
    let offsets: Vec<usize> = tag8_body_offsets(&body);
    assert!(
        offsets.len() >= 2,
        "make() aliases the not-yet-<init>ed Foo across a branch via move-object, so both the \
         original and the alias register must carry an Uninitialized(0) verification type; the \
         lifter emitted only {} tag-8 entries, so the move-object alias fell back",
        offsets.len()
    );
    for &rel in &offsets {
        let target: u16 = u16::from_be_bytes([body[rel], body[rel + 1]]);
        assert_eq!(
            target, 0,
            "every Uninitialized alias entry must point at the shared `new` bytecode (offset 0)"
        );
    }
    assert!(
        first_local_tag7_pos(&body).is_some(),
        "after the <init> on the alias, a later merge frame must report the aliases as the \
         initialized Foo (tag 7); none was found, so the <init> did not propagate to all aliases"
    );
}

const PROBE_ALIAS_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        Class<?> c = Class.forName("Sample", true, Probe.class.getClassLoader());
        c.getDeclaredMethods();
        java.lang.reflect.Method m = c.getMethod("make", boolean.class, boolean.class);
        String all = "";
        boolean[] bs = { true, false };
        for (boolean x : bs) for (boolean y : bs) {
            Object r = m.invoke(null, x, y);
            all += r.getClass().getName() + ",";
        }
        System.out.println("verify_ok=1 " + all);
    }
}
"#;

#[test]
fn aliased_uninitialized_ref_verifies_and_partial_init_is_rejected() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP alias -Xverify:all gate: java not on PATH");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP alias -Xverify:all gate: javac not on PATH");
        return;
    };

    let result: Dex2JarResult = translate_alias();
    let sample: Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present")
        .clone();
    let foo: Vec<u8> = result
        .jar_entries
        .get("Foo.class")
        .expect("Foo.class present")
        .clone();

    let purpose: String = format!("disrobe_uninit_alias_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let ok_dir: PathBuf = root.join("ok");
    let bad_off_dir: PathBuf = root.join("bad_off");
    let bad_partial_dir: PathBuf = root.join("bad_partial");
    for d in [&ok_dir, &bad_off_dir, &bad_partial_dir] {
        std::fs::create_dir_all(d).expect("mkdir alias dir");
    }

    let probe_src: PathBuf = ok_dir.join("Probe.java");
    std::fs::write(&probe_src, PROBE_ALIAS_SRC).expect("write alias probe");
    let compiled: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&ok_dir)
        .arg(&probe_src)
        .output()
        .expect("javac alias probe");
    assert!(
        compiled.status.success(),
        "alias probe did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    std::fs::copy(ok_dir.join("Probe.class"), bad_off_dir.join("Probe.class")).expect("copy probe");
    std::fs::copy(
        ok_dir.join("Probe.class"),
        bad_partial_dir.join("Probe.class"),
    )
    .expect("copy probe");

    std::fs::write(ok_dir.join("Foo.class"), &foo).expect("write foo ok");
    std::fs::write(ok_dir.join("Sample.class"), &sample).expect("write sample ok");
    std::fs::write(bad_off_dir.join("Foo.class"), &foo).expect("write foo bad_off");
    std::fs::write(bad_partial_dir.join("Foo.class"), &foo).expect("write foo bad_partial");

    let cf: ClassFile = parse_classfile(&sample).expect("parse alias Sample.class");
    let body: Vec<u8> = stack_map_body(&cf);
    let body_abs: usize = find_subslice(&sample, &body);

    let off_rel: usize = *tag8_body_offsets(&body)
        .first()
        .expect("a tag-8 alias offset exists");
    let mut corrupt_off: Vec<u8> = sample.clone();
    corrupt_off[body_abs + off_rel] = 0xFF;
    corrupt_off[body_abs + off_rel + 1] = 0xFF;
    std::fs::write(bad_off_dir.join("Sample.class"), &corrupt_off).expect("write sample bad_off");

    let tag7_rel: usize =
        first_local_tag7_pos(&body).expect("a post-init tag-7 alias entry exists");
    let mut corrupt_partial: Vec<u8> = sample;
    corrupt_partial[body_abs + tag7_rel] = 8;
    corrupt_partial[body_abs + tag7_rel + 1] = 0;
    corrupt_partial[body_abs + tag7_rel + 2] = 0;
    std::fs::write(bad_partial_dir.join("Sample.class"), &corrupt_partial)
        .expect("write sample bad_partial");

    let ok: std::process::Output = verify_dir(&java, &ok_dir);
    let ok_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&ok.stdout);
    eprintln!(
        "ALIAS POSITIVE (shared Uninitialized(0) on original and alias): status={} stdout={} stderr={}",
        ok.status,
        ok_out.trim(),
        String::from_utf8_lossy(&ok.stderr).trim()
    );
    assert!(
        ok.status.success()
            && ok_out.contains("verify_ok=1")
            && ok_out.contains("Foo,Foo,Foo,Foo,"),
        "the recovered Sample.class must pass -Xverify:all and return a constructed Foo on all four \
         boolean paths, proving the <init> on the alias initialized the original register too"
    );

    let bad_off: std::process::Output = verify_dir(&java, &bad_off_dir);
    let bad_off_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad_off.stdout);
    let bad_off_err: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad_off.stderr);
    eprintln!(
        "ALIAS NEGATIVE A (alias Uninitialized offset -> 0xFFFF): status={} stdout={} stderr={}",
        bad_off.status,
        bad_off_out.trim(),
        bad_off_err.trim()
    );
    assert!(
        !bad_off.status.success() && !bad_off_out.contains("verify_ok=1"),
        "the corrupted-offset alias class must not pass; the tag-8 frames are not being verified"
    );

    let bad_partial: std::process::Output = verify_dir(&java, &bad_partial_dir);
    let bad_partial_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad_partial.stdout);
    let bad_partial_err: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad_partial.stderr);
    eprintln!(
        "ALIAS NEGATIVE B (post-init alias forced back to Uninitialized, i.e. only one alias \
         initialized): status={} stdout={} stderr={}",
        bad_partial.status,
        bad_partial_out.trim(),
        bad_partial_err.trim()
    );
    assert!(
        !bad_partial.status.success() && !bad_partial_out.contains("verify_ok=1"),
        "declaring a post-init alias as still Uninitialized (only one alias initialized) must be \
         rejected; the positive result would be vacuous if the verifier accepted a partial init"
    );
    assert!(
        bad_partial_err.contains("Uninitialized")
            || bad_partial_err.contains("StackMapTable")
            || bad_partial_err.contains("VerifyError")
            || bad_partial_err.contains("ClassFormatError")
            || bad_partial_err.contains("bad type"),
        "the partial-init class must be rejected by the JVM verifier; stderr was:\n{bad_partial_err}"
    );
}

fn foo_last_field() -> FieldRef {
    FieldRef {
        class: "LFoo;".to_owned(),
        type_desc: "I".to_owned(),
        name: "last".to_owned(),
    }
}

fn foo_class_with_last() -> ClassDef {
    let mut u: Vec<u16> = Vec::new();
    let mut r: Vec<Reloc> = Vec::new();
    u.extend(insn::fmt21c(0x67, 1, 0));
    r.push(Reloc::FieldIndex {
        unit: 1,
        field: foo_last_field(),
    });
    u.extend(insn::fmt35c_one(0x70, 0, 0));
    r.push(Reloc::MethodIndex {
        unit: 3,
        method: object_init(),
    });
    u.extend(insn::fmt10x(0x0E));
    let ctor: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
        method: foo_init(),
        access_flags: 0x1,
        is_direct: true,
        registers_size: 2,
        ins_size: 2,
        outs_size: 1,
        insns: u,
        relocations: r,
    };
    ClassDef {
        class: "LFoo;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: vec![EncodedField {
            field: foo_last_field(),
            access_flags: 0x9,
        }],
        static_values: Vec::new(),
        direct_methods: vec![ctor],
        virtual_methods: Vec::new(),
    }
}

fn make_twonews_dex() -> Vec<u8> {
    let mut sample_init_units: Vec<u16> = Vec::new();
    let mut sample_init_relocs: Vec<Reloc> = Vec::new();
    sample_init_units.extend(insn::fmt35c_one(0x70, 0, 0));
    sample_init_relocs.push(Reloc::MethodIndex {
        unit: 1,
        method: object_init(),
    });
    sample_init_units.extend(insn::fmt10x(0x0E));
    let sample_ctor: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
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
        insns: sample_init_units,
        relocations: sample_init_relocs,
    };

    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.push(0x38 | (2u16 << 8));
    units.push(6);
    let new_a: usize = units.len();
    units.extend(insn::fmt21c(0x22, 0, 0));
    relocs.push(Reloc::TypeIndex {
        unit: new_a + 1,
        descriptor: "LFoo;".to_owned(),
    });
    units.extend(insn::fmt11n(0x12, 1, 1));
    units.push(0x28 | (4u16 << 8));
    let new_b: usize = units.len();
    units.extend(insn::fmt21c(0x22, 0, 0));
    relocs.push(Reloc::TypeIndex {
        unit: new_b + 1,
        descriptor: "LFoo;".to_owned(),
    });
    units.extend(insn::fmt11n(0x12, 1, 2));
    let invoke_pos: usize = units.len();
    units.extend(insn::fmt35c_two(0x70, 0, 1, 0));
    relocs.push(Reloc::MethodIndex {
        unit: invoke_pos + 1,
        method: foo_init(),
    });
    units.extend(insn::fmt11x(0x11, 0));

    let make2: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "LFoo;".to_owned(),
                params: vec!["Z".to_owned()],
            },
            name: "make2".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 3,
        ins_size: 1,
        outs_size: 2,
        insns: units,
        relocations: relocs,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(foo_class_with_last());
    builder.add_class(ClassDef {
        class: "LSample;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![sample_ctor, make2],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn translate_twonews() -> Dex2JarResult {
    translate_dex_bytes(&make_twonews_dex()).expect("translate crafted twonews dex")
}

fn method_code_info<'a>(cf: &'a ClassFile, name: &str) -> &'a [u8] {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some(name))
        .expect("method present");
    let code = method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .expect("method has Code");
    &code.info
}

fn method_bytecode(cf: &ClassFile, name: &str) -> Vec<u8> {
    let info: &[u8] = method_code_info(cf, name);
    let code_len: usize = u32::from_be_bytes([info[4], info[5], info[6], info[7]]) as usize;
    info[8..8 + code_len].to_vec()
}

fn stack_map_body_of(cf: &ClassFile, name: &str) -> Vec<u8> {
    let info: &[u8] = method_code_info(cf, name);
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
    panic!("{name} has no StackMapTable attribute");
}

fn last_frame_last_local_tag_pos(body: &[u8]) -> usize {
    let mut o: usize = 0;
    let entries: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2;
    let mut last: usize = 0;
    for _ in 0..entries {
        assert_eq!(body[o], 255, "lifter emits full_frame frames only");
        o += 1;
        o += 2;
        let num_locals: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_locals {
            last = o;
            let tag: u8 = body[o];
            o += 1;
            if tag == 7 || tag == 8 {
                o += 2;
            }
        }
        let num_stack: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_stack {
            let tag: u8 = body[o];
            o += 1;
            if tag == 7 || tag == 8 {
                o += 2;
            }
        }
    }
    last
}

fn class_names_contain(cf: &ClassFile, needle: &str) -> bool {
    cf.constant_pool
        .iter()
        .any(|e: &ConstantPoolEntry| matches!(e, ConstantPoolEntry::Utf8(s) if s == needle))
}

#[test]
fn nondominated_merge_new_recovers_instead_of_stub() {
    let result: Dex2JarResult = translate_twonews();
    let sample: &Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present in twonews translation");
    let cf: ClassFile = parse_classfile(sample).expect("parse twonews Sample.class");
    assert!(
        !class_names_contain(&cf, "java/lang/UnsupportedOperationException"),
        "make2() reaches Foo.<init> from two forward new-instance predecessors that do not all \
         pass through one `new` (the dominance check fails); the method must be recovered, not \
         emitted as a throwing stub, but the class references UnsupportedOperationException"
    );
    let code: Vec<u8> = method_bytecode(&cf, "make2");
    assert!(
        code.contains(&0xBB) && code.contains(&0xB7) && code.contains(&0xB0),
        "the recovered make2() must collapse the two uninitialized allocations into a single \
         new/invokespecial/areturn at the merge; got bytecode {code:02x?}"
    );
    let body: Vec<u8> = stack_map_body_of(&cf, "make2");
    let entries: usize = u16::from_be_bytes([body[0], body[1]]) as usize;
    assert!(
        entries >= 2,
        "make2()'s recovered branch/merge structure must carry the merge and else-arm frames; \
         only {entries} StackMapTable entries were emitted"
    );
}

const TWONEWS_PROBE_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        Class<?> c = Class.forName("Sample", true, Probe.class.getClassLoader());
        Class<?> foo = Class.forName("Foo", true, Probe.class.getClassLoader());
        c.getDeclaredMethods();
        java.lang.reflect.Method m = c.getMethod("make2", boolean.class);
        Object t = m.invoke(null, true);
        int at = foo.getField("last").getInt(null);
        Object f = m.invoke(null, false);
        int af = foo.getField("last").getInt(null);
        System.out.println(
            "verify_ok=1 " + t.getClass().getName() + " " + at + " "
            + f.getClass().getName() + " " + af);
    }
}
"#;

#[test]
fn nondominated_merge_verifies_and_wrong_frame_is_rejected() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP twonews -Xverify:all gate: java not on PATH");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP twonews -Xverify:all gate: javac not on PATH");
        return;
    };

    let result: Dex2JarResult = translate_twonews();
    let sample: Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present")
        .clone();
    let foo: Vec<u8> = result
        .jar_entries
        .get("Foo.class")
        .expect("Foo.class present")
        .clone();

    let purpose: String = format!("disrobe_twonews_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let ok_dir: PathBuf = root.join("ok");
    let bad_dir: PathBuf = root.join("bad");
    std::fs::create_dir_all(&ok_dir).expect("mkdir ok");
    std::fs::create_dir_all(&bad_dir).expect("mkdir bad");

    let probe_src: PathBuf = ok_dir.join("Probe.java");
    std::fs::write(&probe_src, TWONEWS_PROBE_SRC).expect("write probe");
    let compiled: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&ok_dir)
        .arg(&probe_src)
        .output()
        .expect("javac probe");
    assert!(
        compiled.status.success(),
        "twonews probe did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    std::fs::copy(ok_dir.join("Probe.class"), bad_dir.join("Probe.class")).expect("copy probe");
    std::fs::write(ok_dir.join("Foo.class"), &foo).expect("write foo ok");
    std::fs::write(ok_dir.join("Sample.class"), &sample).expect("write sample ok");
    std::fs::write(bad_dir.join("Foo.class"), &foo).expect("write foo bad");

    let ok: std::process::Output = verify_dir(&java, &ok_dir);
    let ok_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&ok.stdout);
    eprintln!(
        "TWONEWS POSITIVE (two forward new-instance predecessors collapsed to one merge new): \
         status={} stdout={} stderr={}",
        ok.status,
        ok_out.trim(),
        String::from_utf8_lossy(&ok.stderr).trim()
    );
    assert!(
        ok.status.success() && ok_out.contains("verify_ok=1") && ok_out.contains("Foo 1 Foo 2"),
        "the recovered Sample.class must pass -Xverify:all and construct a Foo on both arms with \
         the branch-selected constructor argument (1 on the true arm, 2 on the false arm), \
         proving the two-predecessor merge collapses to one correct allocation"
    );

    let cf: ClassFile = parse_classfile(&sample).expect("parse twonews Sample.class");
    let body: Vec<u8> = stack_map_body_of(&cf, "make2");
    let body_abs: usize = find_subslice(&sample, &body);
    let tag_pos: usize = last_frame_last_local_tag_pos(&body);
    assert_eq!(
        body[tag_pos], 1,
        "the merge frame's last local (the constructor-argument register) must be an Integer"
    );
    let mut corrupt: Vec<u8> = sample;
    corrupt[body_abs + tag_pos] = 2;
    std::fs::write(bad_dir.join("Sample.class"), &corrupt).expect("write sample bad");

    let bad: std::process::Output = verify_dir(&java, &bad_dir);
    let bad_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad.stdout);
    let bad_err: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad.stderr);
    eprintln!(
        "TWONEWS NEGATIVE (merge frame argument type Integer -> Float): status={} stdout={} stderr={}",
        bad.status,
        bad_out.trim(),
        bad_err.trim()
    );
    assert!(
        !bad.status.success() && !bad_out.contains("verify_ok=1"),
        "a merge frame that misdescribes the constructor-argument local must be rejected; the \
         verifier accepted a wrong merge frame, so the positive result is vacuous"
    );
    assert!(
        bad_err.contains("VerifyError")
            || bad_err.contains("StackMapTable")
            || bad_err.contains("ClassFormatError")
            || bad_err.contains("stackmap"),
        "the corrupted merge frame must be rejected by the JVM verifier; stderr was:\n{bad_err}"
    );
}
