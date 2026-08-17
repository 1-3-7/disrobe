#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::bytecode::{CodeAttribute, Instruction, disassemble, parse_code_attribute};
use disrobe_pass_jvm::classfile::{Attribute, ClassFile, MethodInfo};
use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{assemble_jar, parse_classfile};

const CLASS: &str = "Lcom/disrobe/Fill;";
const INTERNAL: &str = "com/disrobe/Fill";

fn build_fill_method(
    name: &str,
    ret: &str,
    elem_type: &str,
    element_width: u16,
    data: &[u8],
    count: u8,
) -> EncodedMethod {
    let mut insns: Vec<u16> = Vec::new();
    insns.push(0x0012 | (u16::from(count) << 12));
    insns.push(0x0023);
    insns.push(0x0000);
    let fill_pc: i32 = insns.len() as i32;
    insns.push(0x0026);
    let rel_lo_pos: usize = insns.len();
    insns.push(0x0000);
    insns.push(0x0000);
    insns.push(0x0011);
    if !insns.len().is_multiple_of(2) {
        insns.push(0x0000);
    }
    let payload_pc: i32 = insns.len() as i32;
    insns.push(0x0300);
    insns.push(element_width);
    insns.push(u16::from(count));
    insns.push(0x0000);
    let mut padded: Vec<u8> = data.to_vec();
    if !padded.len().is_multiple_of(2) {
        padded.push(0);
    }
    for pair in padded.chunks(2) {
        insns.push(u16::from(pair[0]) | (u16::from(pair[1]) << 8));
    }
    let rel: u32 = (payload_pc - fill_pc) as u32;
    insns[rel_lo_pos] = (rel & 0xFFFF) as u16;
    insns[rel_lo_pos + 1] = ((rel >> 16) & 0xFFFF) as u16;

    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: CLASS.to_owned(),
            proto: ProtoRef {
                return_type: ret.to_owned(),
                params: Vec::new(),
            },
            name: name.to_owned(),
        },
        access_flags: 0x0009,
        is_direct: true,
        registers_size: 1,
        ins_size: 0,
        outs_size: 0,
        insns,
        relocations: vec![Reloc::TypeIndex {
            unit: 2,
            descriptor: elem_type.to_owned(),
        }],
    }
}

struct Case {
    name: &'static str,
    ret: &'static str,
    elem_type: &'static str,
    element_width: u16,
    data: Vec<u8>,
    count: u8,
    store_mnemonic: &'static str,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "fB",
            ret: "[B",
            elem_type: "[B",
            element_width: 1,
            data: vec![0x0A, 0x14, 0xFF],
            count: 3,
            store_mnemonic: "bastore",
        },
        Case {
            name: "fI",
            ret: "[I",
            elem_type: "[I",
            element_width: 4,
            data: vec![0x07, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
            count: 2,
            store_mnemonic: "iastore",
        },
        Case {
            name: "fJ",
            ret: "[J",
            elem_type: "[J",
            element_width: 8,
            data: vec![
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
            ],
            count: 2,
            store_mnemonic: "lastore",
        },
        Case {
            name: "fC",
            ret: "[C",
            elem_type: "[C",
            element_width: 2,
            data: vec![72, 0, 105, 0, 33, 0],
            count: 3,
            store_mnemonic: "castore",
        },
        Case {
            name: "fS",
            ret: "[S",
            elem_type: "[S",
            element_width: 2,
            data: vec![0xFF, 0xFF, 0xE8, 0x03, 0xFF, 0x7F],
            count: 3,
            store_mnemonic: "sastore",
        },
        Case {
            name: "fF",
            ret: "[F",
            elem_type: "[F",
            element_width: 4,
            data: 1.5f32
                .to_le_bytes()
                .into_iter()
                .chain((-2.0f32).to_le_bytes())
                .collect(),
            count: 2,
            store_mnemonic: "fastore",
        },
        Case {
            name: "fD",
            ret: "[D",
            elem_type: "[D",
            element_width: 8,
            data: 3.25f64
                .to_le_bytes()
                .into_iter()
                .chain((-0.5f64).to_le_bytes())
                .collect(),
            count: 2,
            store_mnemonic: "dastore",
        },
    ]
}

fn build_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    let methods: Vec<EncodedMethod> = cases()
        .iter()
        .map(|c: &Case| {
            build_fill_method(
                c.name,
                c.ret,
                c.elem_type,
                c.element_width,
                &c.data,
                c.count,
            )
        })
        .collect();
    builder.add_class(ClassDef {
        class: CLASS.to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: methods,
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn build_parameter_reuse_dex() -> Vec<u8> {
    let mut insns: Vec<u16> = vec![
        0x0138, 0x0003, 0x0012, 0x2112, 0x1123, 0x0000, 0x0126, 0x0000, 0x0000, 0x0111, 0x0300,
        0x0004, 0x0002, 0x0000, 0x0007, 0x0000, 0xFFFF, 0xFFFF,
    ];
    let fill_pc: i32 = 6;
    let payload_pc: i32 = 10;
    let offset: u32 = (payload_pc - fill_pc) as u32;
    insns[7] = (offset & 0xFFFF) as u16;
    insns[8] = (offset >> 16) as u16;

    let method: EncodedMethod = EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: CLASS.to_owned(),
            proto: ProtoRef {
                return_type: "[I".to_owned(),
                params: vec!["Z".to_owned()],
            },
            name: "branchFill".to_owned(),
        },
        access_flags: 0x0009,
        is_direct: true,
        registers_size: 2,
        ins_size: 1,
        outs_size: 0,
        insns,
        relocations: vec![Reloc::TypeIndex {
            unit: 5,
            descriptor: "[I".to_owned(),
        }],
    };
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: CLASS.to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn method_codes(class_bytes: &[u8]) -> BTreeMap<String, CodeAttribute> {
    let cf: ClassFile = parse_classfile(class_bytes).expect("parse class");
    let mut out: BTreeMap<String, CodeAttribute> = BTreeMap::new();
    for m in &cf.methods {
        let m: &MethodInfo = m;
        let name: String = cf.utf8_at(m.name_index).expect("name").to_string();
        for attr in &m.attributes {
            let attr: &Attribute = attr;
            if cf.utf8_at(attr.name_index).ok() == Some("Code") {
                out.insert(
                    name.clone(),
                    parse_code_attribute(&attr.info).expect("code"),
                );
            }
        }
    }
    out
}

#[test]
fn fill_array_data_recovers_every_element_type() {
    let dex: Vec<u8> = build_dex();
    let result: Dex2JarResult = translate_dex_bytes(&dex).expect("translate");
    let class_bytes: &Vec<u8> = result
        .jar_entries
        .get(&format!("{INTERNAL}.class"))
        .expect("class entry");
    let codes: BTreeMap<String, CodeAttribute> = method_codes(class_bytes);

    for c in cases() {
        let code: &CodeAttribute = codes.get(c.name).unwrap_or_else(|| panic!("{}", c.name));
        let insns: Vec<Instruction> = disassemble(&code.code).expect("disassemble");
        let mnemonics: Vec<&str> = insns.iter().map(|i: &Instruction| i.mnemonic).collect();

        assert!(
            !mnemonics.contains(&"athrow"),
            "{} still stubbed: {mnemonics:?}",
            c.name
        );
        let newarrays: usize = mnemonics
            .iter()
            .filter(|m: &&&str| **m == "newarray")
            .count();
        assert_eq!(newarrays, 1, "{} newarray count: {mnemonics:?}", c.name);
        let stores: usize = mnemonics
            .iter()
            .filter(|m: &&&str| **m == c.store_mnemonic)
            .count();
        assert_eq!(
            stores,
            usize::from(c.count),
            "{} expected {} {} ops: {mnemonics:?}",
            c.name,
            c.count,
            c.store_mnemonic
        );
        assert!(
            mnemonics.last() == Some(&"areturn"),
            "{} must end areturn: {mnemonics:?}",
            c.name
        );
    }

    verify_with_jvm(&result);
}

#[test]
fn char_short_fill_round_trips_runtime_values() {
    let dex: Vec<u8> = build_dex();
    let result: Dex2JarResult = translate_dex_bytes(&dex).expect("translate");

    let Some(java): Option<PathBuf> = find_java() else {
        eprintln!("skip jvm verify: no java");
        return;
    };
    let javac: PathBuf = java.with_file_name(if cfg!(windows) { "javac.exe" } else { "javac" });
    if !javac.is_file() {
        eprintln!("skip jvm verify: no javac");
        return;
    }

    let jar: Vec<u8> = assemble_jar(&result).expect("jar");
    let purpose: String = format!("disrobe_fill_cs_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let jar_path: PathBuf = dir.join("fill.jar");
    let mut f: std::fs::File = std::fs::File::create(&jar_path).expect("create jar");
    f.write_all(&jar).expect("write jar");
    drop(f);

    let driver: &str = "public class W { public static void main(String[] a) throws Exception { \
        Class<?> c = Class.forName(\"com.disrobe.Fill\"); \
        java.lang.reflect.Method mc = c.getDeclaredMethod(\"fC\"); mc.setAccessible(true); \
        char[] cs = (char[]) mc.invoke(null); \
        if (!new String(cs).equals(\"Hi!\")) throw new IllegalStateException(\"char mismatch: \" + new String(cs)); \
        java.lang.reflect.Method ms = c.getDeclaredMethod(\"fS\"); ms.setAccessible(true); \
        short[] ss = (short[]) ms.invoke(null); \
        if (!(ss.length == 3 && ss[0] == -1 && ss[1] == 1000 && ss[2] == 32767)) \
            throw new IllegalStateException(\"short mismatch: \" + java.util.Arrays.toString(ss)); \
        System.out.println(\"VALUES_OK\"); } }";
    let src: PathBuf = dir.join("W.java");
    std::fs::write(&src, driver).expect("write driver");

    let compile: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&dir)
        .arg(&src)
        .output()
        .expect("javac");
    assert!(
        compile.status.success(),
        "driver compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let cp: String = format!("{}{}{}", dir.display(), classpath_sep(), jar_path.display());
    let run: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(&cp)
        .arg("W")
        .output()
        .expect("java run");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && stdout.contains("VALUES_OK"),
        "jvm value check failed: stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn fill_array_data_survives_parameter_register_reuse_after_branch() {
    let dex: Vec<u8> = build_parameter_reuse_dex();
    let result: Dex2JarResult = translate_dex_bytes(&dex).expect("translate");
    let class_bytes: &Vec<u8> = result
        .jar_entries
        .get(&format!("{INTERNAL}.class"))
        .expect("class entry");
    let codes: BTreeMap<String, CodeAttribute> = method_codes(class_bytes);
    let code: &CodeAttribute = codes.get("branchFill").expect("branchFill code");
    let insns: Vec<Instruction> = disassemble(&code.code).expect("disassemble");
    let mnemonics: Vec<&str> = insns.iter().map(|i: &Instruction| i.mnemonic).collect();
    assert!(!mnemonics.contains(&"athrow"), "stubbed: {mnemonics:?}");
    assert_eq!(
        mnemonics
            .iter()
            .filter(|mnemonic: &&&str| **mnemonic == "iastore")
            .count(),
        2,
        "payload stores missing: {mnemonics:?}"
    );

    let Some(java): Option<PathBuf> = find_java() else {
        eprintln!("skip jvm verify: no java");
        return;
    };
    let javac: PathBuf = java.with_file_name(if cfg!(windows) { "javac.exe" } else { "javac" });
    if !javac.is_file() {
        eprintln!("skip jvm verify: no javac");
        return;
    }
    let jar: Vec<u8> = assemble_jar(&result).expect("jar");
    let purpose: String = format!("disrobe_fill_branch_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let jar_path: PathBuf = dir.join("fill.jar");
    let mut jar_file: std::fs::File = std::fs::File::create(&jar_path).expect("create jar");
    jar_file.write_all(&jar).expect("write jar");
    drop(jar_file);
    let driver: &str = "public class B { public static void main(String[] a) throws Exception { \
        Class<?> c = Class.forName(\"com.disrobe.Fill\"); \
        java.lang.reflect.Method m = c.getDeclaredMethod(\"branchFill\", boolean.class); \
        for (boolean v : new boolean[]{false, true}) { \
            int[] values = (int[]) m.invoke(null, v); \
            if (!java.util.Arrays.equals(values, new int[]{7, -1})) \
                throw new IllegalStateException(java.util.Arrays.toString(values)); } \
        System.out.println(\"BRANCH_FILL_OK\"); } }";
    let src: PathBuf = dir.join("B.java");
    std::fs::write(&src, driver).expect("write driver");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&dir)
        .arg(&src)
        .output()
        .expect("javac");
    assert!(
        compile.status.success(),
        "driver compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let cp: String = format!("{}{}{}", dir.display(), classpath_sep(), jar_path.display());
    let run: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(&cp)
        .arg("B")
        .output()
        .expect("java run");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && stdout.contains("BRANCH_FILL_OK"),
        "jvm value check failed: stdout={stdout} stderr={stderr}"
    );
}

fn find_java() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("JAVA_HOME") {
        let exe: PathBuf = if cfg!(windows) {
            PathBuf::from(&home).join("bin").join("java.exe")
        } else {
            PathBuf::from(&home).join("bin").join("java")
        };
        if exe.is_file() {
            return Some(exe);
        }
    }
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &[".exe", ""] } else { &[""] };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let cand: PathBuf = dir.join(format!("java{ext}"));
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

fn verify_with_jvm(result: &Dex2JarResult) {
    let Some(java): Option<PathBuf> = find_java() else {
        eprintln!("skip jvm verify: no java");
        return;
    };
    let jar: Vec<u8> = assemble_jar(result).expect("jar");
    let purpose: String = format!("disrobe_fill_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let jar_path: PathBuf = dir.join("fill.jar");
    let mut f: std::fs::File = std::fs::File::create(&jar_path).expect("create jar");
    f.write_all(&jar).expect("write jar");
    drop(f);

    let driver: &str = "public class V { public static void main(String[] a) throws Exception { \
        Class<?> c = Class.forName(\"com.disrobe.Fill\"); \
        for (java.lang.reflect.Method m : c.getDeclaredMethods()) { m.setAccessible(true); m.invoke(null); } \
        System.out.println(\"VERIFY_OK\"); } }";
    let src: PathBuf = dir.join("V.java");
    std::fs::write(&src, driver).expect("write driver");

    let javac: PathBuf = java.with_file_name(if cfg!(windows) { "javac.exe" } else { "javac" });
    if !javac.is_file() {
        eprintln!("skip jvm verify: no javac");
        return;
    }
    let compile: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&dir)
        .arg(&src)
        .output()
        .expect("javac");
    assert!(
        compile.status.success(),
        "driver compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let cp: String = format!("{}{}{}", dir.display(), classpath_sep(), jar_path.display());
    let run: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(&cp)
        .arg("V")
        .output()
        .expect("java run");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && stdout.contains("VERIFY_OK"),
        "jvm verify failed: stdout={stdout} stderr={stderr}"
    );
}

const fn classpath_sep() -> &'static str {
    if cfg!(windows) { ";" } else { ":" }
}
