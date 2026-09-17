#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};

const OP_CONST_4: u8 = 0x12;
const OP_CONST_HIGH16: u8 = 0x15;
const OP_SUB_FLOAT_2ADDR: u8 = 0xC7;
const ONE_FLOAT_HIGH16: i16 = 0x3F80;
const OP_RETURN: u8 = 0x0F;
const OP_RETURN_VOID: u8 = 0x0E;
const OP_CMPG_FLOAT: u8 = 0x2E;
const OP_IF_EQZ: u8 = 0x38;
const OP_IF_NEZ: u8 = 0x39;
const OP_GOTO: u8 = 0x28;
const OP_INVOKE_DIRECT: u8 = 0x70;

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

fn split_ctor() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt35c_one(OP_INVOKE_DIRECT, 0, 0));
    relocs.push(Reloc::MethodIndex {
        unit: 1,
        method: object_init(),
    });
    units.extend(insn::fmt10x(OP_RETURN_VOID));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSplit;".to_owned(),
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
    units.extend(insn::fmt11n(OP_CONST_4, 0, 0));
    units.extend(insn::fmt23x(OP_CMPG_FLOAT, 0, 2, 0));
    units.extend(insn::fmt21s(OP_IF_NEZ, 0, 4));
    units.extend(insn::fmt11n(OP_CONST_4, 0, 1));
    units.push(u16::from(OP_GOTO) | (2u16 << 8));
    units.extend(insn::fmt11n(OP_CONST_4, 0, 0));
    units.extend(insn::fmt21s(OP_IF_EQZ, 0, 3));
    units.extend(insn::fmt11x(OP_RETURN, 2));
    units.extend(insn::fmt11x(OP_RETURN, 3));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSplit;".to_owned(),
            proto: ProtoRef {
                return_type: "F".to_owned(),
                params: vec!["F".to_owned(), "F".to_owned()],
            },
            name: "pick".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 4,
        ins_size: 2,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn zero_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt11n(OP_CONST_4, 0, 0));
    units.extend(insn::fmt11x(OP_RETURN, 0));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSplit;".to_owned(),
            proto: ProtoRef {
                return_type: "F".to_owned(),
                params: Vec::new(),
            },
            name: "zero".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 1,
        ins_size: 0,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn scale_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt21s(OP_CONST_HIGH16, 0, ONE_FLOAT_HIGH16));
    units.extend(insn::fmt12x(OP_SUB_FLOAT_2ADDR, 0, 1));
    units.extend(insn::fmt11x(OP_RETURN, 0));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSplit;".to_owned(),
            proto: ProtoRef {
                return_type: "F".to_owned(),
                params: vec!["F".to_owned()],
            },
            name: "inverse".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 2,
        ins_size: 1,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn make_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LSplit;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![split_ctor(), pick_method(), zero_method(), scale_method()],
        virtual_methods: Vec::new(),
    });
    builder.build()
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
        Class<?> c = Class.forName("Split", true, Probe.class.getClassLoader());
        c.getDeclaredMethods();
        java.lang.reflect.Method pick = c.getMethod("pick", float.class, float.class);
        java.lang.reflect.Method zero = c.getMethod("zero");
        java.lang.reflect.Method inverse = c.getMethod("inverse", float.class);
        System.out.println("verify_ok=1"
            + " nonzero=" + pick.invoke(null, 3.0f, 5.0f)
            + " atzero=" + pick.invoke(null, 0.0f, 5.0f)
            + " zero=" + zero.invoke(null)
            + " inverse=" + inverse.invoke(null, 0.25f));
    }
}
"#;

#[test]
fn a_register_that_is_a_float_at_one_constant_and_a_branch_flag_at_another_lifts_and_runs() {
    let java: PathBuf = find_on_path("java").expect(
        "a JDK must be on PATH: this gate grades the recovered class against the real jvm \
         verifier, and a reference outside disrobe cannot be stood in for",
    );
    let javac: PathBuf = find_on_path("javac").expect(
        "a JDK must be on PATH: this gate compiles a probe that calls the recovered method, and a \
         reference outside disrobe cannot be stood in for",
    );
    let dir: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        &format!("disrobe_dalvik_const_split_{}", std::process::id()),
    )
    .expect("scratch dir");
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate crafted dex");
    let recovered: &Vec<u8> = result.jar_entries.get("Split.class").expect(
        "Split.class present in the translation, so the lifter reached the crafted method shape",
    );
    assert_eq!(
        result.bodies_recovered, 4,
        "the crafted class declares four bodies and every one is inside the declared dalvik \
         surface, so a stub here means the shape was refused rather than lowered: recovered {} of \
         {}",
        result.bodies_recovered, result.method_total
    );
    std::fs::write(dir.path().join("Split.class"), recovered).expect("write Split.class");
    let src: PathBuf = dir.path().join("Probe.java");
    std::fs::write(&src, PROBE_SRC).expect("write Probe.java");
    let compiled: Output = Command::new(&javac)
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
    let run: Output = Command::new(&java)
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
        "pick() writes register v0 twice: once as the second operand of cmpg-float, where it is a \
         float, and once as the flag a later if-eqz reads, where it is an int. Typing that register \
         float for the whole method loads a float into an int-only branch and the real jvm verifier \
         rejects the body. The java type of a dalvik constant belongs to the definition, not to the \
         register.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("nonzero=5.0") && stdout.contains("atzero=0.0"),
        "pick() returns its second argument when the first is not zero and its first argument when \
         it is, so the recovered method is graded for behavior and not only for a frame the \
         verifier accepts: {stdout}"
    );
    assert!(
        stdout.contains("zero=0.0"),
        "zero() returns a dalvik zero constant whose only use is a float return, so narrowing the \
         float decision to the definition must not turn that constant back into an int: {stdout}"
    );
    assert!(
        stdout.contains("inverse=0.75"),
        "inverse() feeds its constant to sub-float/2addr, where the constant's register is the \
         first operand as well as the destination. A reader that only inspects the second operand \
         of a two-address float op sees no float use at all and demotes the constant to an int, \
         which is how a real apk method built from 1f minus a ratio stops verifying: {stdout}"
    );
}
