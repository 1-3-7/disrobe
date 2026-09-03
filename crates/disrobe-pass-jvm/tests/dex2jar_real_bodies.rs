#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_jvm::bytecode::{CodeAttribute, Instruction, disassemble, parse_code_attribute};
use disrobe_pass_jvm::classfile::{Attribute, ClassFile, MethodInfo};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};

const ALOAD_0: u8 = 0x2A;
const GETFIELD: u8 = 0xB4;
const DSTORE_1: u8 = 0x48;
const DLOAD_1: u8 = 0x27;
const DMUL: u8 = 0x6B;
const DRETURN: u8 = 0xAF;
use disrobe_pass_jvm::parse_classfile;

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for part in parts {
        p.push(part);
    }
    p
}

fn baseline_classes() -> BTreeMap<String, Vec<u8>> {
    let bytes: Vec<u8> =
        std::fs::read(corpus(&["jvm", "megafile", "EdgeCases-baseline.jar"])).expect("read jar");
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(bytes);
    let mut zip: zip::ZipArchive<std::io::Cursor<Vec<u8>>> =
        zip::ZipArchive::new(cursor).expect("open jar");
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..zip.len() {
        let mut f: zip::read::ZipFile<'_> = zip.by_index(i).expect("entry");
        let name: String = f.name().to_string();
        if name.ends_with(".class") {
            let mut buf: Vec<u8> = Vec::new();
            f.read_to_end(&mut buf).expect("read class");
            out.insert(name[..name.len() - 6].to_string(), buf);
        }
    }
    out
}

fn find_code(cf: &ClassFile, method: &MethodInfo) -> Option<CodeAttribute> {
    for attr in &method.attributes {
        let attr: &Attribute = attr;
        if cf.utf8_at(attr.name_index).ok()? == "Code" {
            return parse_code_attribute(&attr.info).ok();
        }
    }
    None
}

fn method_code(cf: &ClassFile, name: &str, descriptor: &str) -> Option<CodeAttribute> {
    for m in &cf.methods {
        let m: &MethodInfo = m;
        let mname: &str = cf.utf8_at(m.name_index).ok()?;
        let mdesc: &str = cf.utf8_at(m.descriptor_index).ok()?;
        if mname == name && mdesc == descriptor {
            return find_code(cf, m);
        }
    }
    None
}

fn is_register_shuffle(mnemonic: &str) -> bool {
    mnemonic.ends_with("load")
        || mnemonic.contains("load_")
        || mnemonic.ends_with("store")
        || mnemonic.contains("store_")
        || matches!(
            mnemonic,
            "nop"
                | "dup"
                | "dup_x1"
                | "dup_x2"
                | "dup2"
                | "dup2_x1"
                | "dup2_x2"
                | "swap"
                | "pop"
                | "pop2"
        )
}

fn semantic_skeleton(code: &CodeAttribute) -> Vec<&'static str> {
    let insns: Vec<Instruction> = disassemble(&code.code).expect("disassemble code");
    insns
        .into_iter()
        .map(|i: Instruction| i.mnemonic)
        .filter(|m: &&'static str| !is_register_shuffle(m))
        .collect()
}

fn is_const(mnemonic: &str) -> bool {
    mnemonic.starts_with("iconst")
        || mnemonic.starts_with("lconst")
        || mnemonic.starts_with("fconst")
        || mnemonic.starts_with("dconst")
        || mnemonic.starts_with("aconst")
        || matches!(mnemonic, "bipush" | "sipush" | "ldc" | "ldc_w" | "ldc2_w")
}

fn normalize(skel: Vec<&'static str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(skel.len());
    for m in skel {
        let token: String = if is_const(m) {
            "const".to_string()
        } else {
            m.to_string()
        };
        if out.last() != Some(&token) {
            out.push(token);
        }
    }
    out
}

fn matches_baseline(translated: &CodeAttribute, baseline: &CodeAttribute) -> bool {
    normalize(semantic_skeleton(translated)) == normalize(semantic_skeleton(baseline))
}

fn constructor_skeleton(code: &CodeAttribute) -> Vec<String> {
    let instructions: Vec<Instruction> = disassemble(&code.code).expect("disassemble code");
    let mnemonics: Vec<&'static str> = instructions
        .iter()
        .map(|instruction: &Instruction| instruction.mnemonic)
        .collect();
    constructor_skeleton_from_mnemonics(&mnemonics)
}

fn constructor_skeleton_from_mnemonics(mnemonics: &[&'static str]) -> Vec<String> {
    let mut skeleton: Vec<&'static str> = Vec::with_capacity(mnemonics.len());
    for (index, mnemonic) in mnemonics.iter().copied().enumerate() {
        if mnemonic == "checkcast" && mnemonics.get(index + 1).copied() == Some("areturn") {
            continue;
        }
        if !is_register_shuffle(mnemonic) {
            skeleton.push(mnemonic);
        }
    }
    normalize(skeleton)
}

fn constructor_matches_baseline(translated: &CodeAttribute, baseline: &CodeAttribute) -> bool {
    constructor_skeleton(translated) == constructor_skeleton(baseline)
}

#[test]
fn constructor_skeleton_only_excludes_an_adjacent_return_cast() {
    let skeleton: Vec<String> = constructor_skeleton_from_mnemonics(&[
        "checkcast",
        "astore_1",
        "aload_1",
        "areturn",
        "iconst_0",
        "checkcast",
        "areturn",
    ]);
    assert_eq!(skeleton, ["checkcast", "areturn", "const", "areturn"]);
}

struct Leaf {
    class: &'static str,
    name: &'static str,
    descriptor: &'static str,
}

const LEAF_METHODS: &[Leaf] = &[
    Leaf {
        class: "EdgeCases$Vector2D",
        name: "dot",
        descriptor: "(LEdgeCases$Vector2D;)D",
    },
    Leaf {
        class: "EdgeCases$Vector2D",
        name: "magnitude",
        descriptor: "()D",
    },
    Leaf {
        class: "EdgeCases$Square",
        name: "area",
        descriptor: "()D",
    },
    Leaf {
        class: "EdgeCases$Square",
        name: "side",
        descriptor: "()D",
    },
    Leaf {
        class: "EdgeCases$Circle",
        name: "radius",
        descriptor: "()D",
    },
    Leaf {
        class: "EdgeCases$Triangle",
        name: "area",
        descriptor: "()D",
    },
    Leaf {
        class: "EdgeCases$Triangle",
        name: "base",
        descriptor: "()D",
    },
    Leaf {
        class: "EdgeCases$Triangle",
        name: "height",
        descriptor: "()D",
    },
];

fn translated_classes() -> BTreeMap<String, Vec<u8>> {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");
    result
        .jar_entries
        .into_iter()
        .filter(|(name, _)| name.ends_with(".class"))
        .map(|(name, bytes)| (name[..name.len() - 6].to_string(), bytes))
        .collect()
}

#[test]
fn recovered_leaf_bodies_structural_match_baseline() {
    let translated: BTreeMap<String, Vec<u8>> = translated_classes();
    let baseline: BTreeMap<String, Vec<u8>> = baseline_classes();

    let mut matched: usize = 0;
    let mut total: usize = 0;
    let mut report: Vec<String> = Vec::new();

    for leaf in LEAF_METHODS {
        let (Some(tbytes), Some(bbytes)): (Option<&Vec<u8>>, Option<&Vec<u8>>) =
            (translated.get(leaf.class), baseline.get(leaf.class))
        else {
            continue;
        };
        let tcf: ClassFile = parse_classfile(tbytes).expect("parse translated class");
        let bcf: ClassFile = parse_classfile(bbytes).expect("parse baseline class");
        let (Some(tcode), Some(bcode)): (Option<CodeAttribute>, Option<CodeAttribute>) = (
            method_code(&tcf, leaf.name, leaf.descriptor),
            method_code(&bcf, leaf.name, leaf.descriptor),
        ) else {
            continue;
        };
        total += 1;
        let ok: bool = matches_baseline(&tcode, &bcode);
        if ok {
            matched += 1;
        } else {
            report.push(format!(
                "MISMATCH {}.{}{}: translated={:?} baseline={:?}",
                leaf.class,
                leaf.name,
                leaf.descriptor,
                semantic_skeleton(&tcode),
                semantic_skeleton(&bcode)
            ));
        }
    }

    assert!(
        total >= 6,
        "expected at least 6 curated leaf methods, got {total}"
    );
    let pct: f64 = (matched as f64) * 100.0 / (total as f64);
    eprintln!("leaf-method body structural-match: {matched}/{total} ({pct:.1}%)");
    assert!(
        matched == total,
        "all curated leaf bodies must structurally match the javac baseline: {matched}/{total}\n{}",
        report.join("\n")
    );
}

const CONSTRUCTOR_ON_STACK_METHODS: &[Leaf] = &[
    Leaf {
        class: "EdgeCases$Vector2D",
        name: "add",
        descriptor: "(LEdgeCases$Vector2D;)LEdgeCases$Vector2D;",
    },
    Leaf {
        class: "EdgeCases$Pair",
        name: "mapFirst",
        descriptor: "(Ljava/util/function/Function;)LEdgeCases$Pair;",
    },
    Leaf {
        class: "EdgeCases$Pair",
        name: "mapSecond",
        descriptor: "(Ljava/util/function/Function;)LEdgeCases$Pair;",
    },
    Leaf {
        class: "EdgeCases",
        name: "safeVarargs",
        descriptor: "([Ljava/lang/Object;)Ljava/util/List;",
    },
    Leaf {
        class: "EdgeCases",
        name: "mapAll",
        descriptor: "(Ljava/util/List;Ljava/util/function/Function;)Ljava/util/List;",
    },
];

#[test]
fn new_instance_constructed_on_stack_matches_baseline() {
    let translated: BTreeMap<String, Vec<u8>> = translated_classes();
    let baseline: BTreeMap<String, Vec<u8>> = baseline_classes();

    let mut matched: usize = 0;
    let mut total: usize = 0;
    let mut report: Vec<String> = Vec::new();

    for leaf in CONSTRUCTOR_ON_STACK_METHODS {
        let (Some(tbytes), Some(bbytes)): (Option<&Vec<u8>>, Option<&Vec<u8>>) =
            (translated.get(leaf.class), baseline.get(leaf.class))
        else {
            continue;
        };
        let tcf: ClassFile = parse_classfile(tbytes).expect("parse translated class");
        let bcf: ClassFile = parse_classfile(bbytes).expect("parse baseline class");
        let (Some(tcode), Some(bcode)): (Option<CodeAttribute>, Option<CodeAttribute>) = (
            method_code(&tcf, leaf.name, leaf.descriptor),
            method_code(&bcf, leaf.name, leaf.descriptor),
        ) else {
            continue;
        };
        total += 1;
        if constructor_matches_baseline(&tcode, &bcode) {
            matched += 1;
        } else {
            report.push(format!(
                "MISMATCH {}.{}{}: translated={:?} baseline={:?}",
                leaf.class,
                leaf.name,
                leaf.descriptor,
                semantic_skeleton(&tcode),
                semantic_skeleton(&bcode)
            ));
        }
    }

    assert!(
        total >= 5,
        "expected the curated constructor-on-stack methods to be present, got {total}"
    );
    assert!(
        matched == total,
        "eager new;dup lowering must place the allocation at the new-instance site so the body \
         structurally matches the javac baseline: {matched}/{total}\n{}",
        report.join("\n")
    );
}

fn translated_kt_classes() -> BTreeMap<String, Vec<u8>> {
    let dex_bytes: Vec<u8> =
        std::fs::read(corpus(&["jvm", "dex", "EdgeCasesKt.dex"])).expect("kt dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate kt");
    result
        .jar_entries
        .into_iter()
        .filter(|(name, _)| name.ends_with(".class"))
        .map(|(name, bytes)| (name[..name.len() - 6].to_string(), bytes))
        .collect()
}

#[test]
fn whenmappings_clinit_recovers_empty_catch_dispatch() {
    let classes: BTreeMap<String, Vec<u8>> = translated_kt_classes();
    let bytes: &Vec<u8> = classes
        .get("Direction$WhenMappings")
        .expect("Direction$WhenMappings present in kotlin translation");
    let cf: ClassFile = parse_classfile(bytes).expect("parse WhenMappings");
    let code: CodeAttribute =
        method_code(&cf, "<clinit>", "()V").expect("WhenMappings.<clinit> has a Code attribute");

    let mnemonics: Vec<&'static str> = disassemble(&code.code)
        .expect("disassemble clinit")
        .into_iter()
        .map(|i: Instruction| i.mnemonic)
        .collect();
    for probe in ["newarray", "iastore", "putstatic"] {
        assert!(
            mnemonics.contains(&probe),
            "recovered when-map <clinit> must build the ordinal->case int[] (real body, not a stub); {probe} missing: {mnemonics:?}"
        );
    }
    assert_eq!(
        code.exception_table.len(),
        4,
        "each `catch (NoSuchFieldError) {{}}` guard must lower to its own bounds-checked JVM handler entry: {:?}",
        code.exception_table
    );
    assert_eq!(
        code.dropped_exception_entries, 0,
        "every synthesized empty-catch dispatch handler must point at an in-bounds offset"
    );
}

#[test]
fn square_area_code_bytes_are_exact() {
    let translated: BTreeMap<String, Vec<u8>> = translated_classes();
    let bytes: &Vec<u8> = translated
        .get("EdgeCases$Square")
        .expect("Square present in translation");
    let cf: ClassFile = parse_classfile(bytes).expect("parse Square");
    let code: CodeAttribute = method_code(&cf, "area", "()D").expect("Square.area has Code");

    let getfield_idx: u16 = {
        let insns: Vec<Instruction> = disassemble(&code.code).expect("disassemble");
        let gf: &Instruction = insns
            .iter()
            .find(|i: &&Instruction| i.mnemonic == "getfield")
            .expect("area must read a field");
        u16::try_from(operand_u16(&code.code, gf.pc as usize)).expect("u16 index")
    };
    let hi: u8 = (getfield_idx >> 8) as u8;
    let lo: u8 = (getfield_idx & 0xFF) as u8;

    let expected: Vec<u8> = vec![
        ALOAD_0, GETFIELD, hi, lo, DSTORE_1, DLOAD_1, DLOAD_1, DMUL, DSTORE_1, DLOAD_1, DRETURN,
    ];
    assert_eq!(
        code.code, expected,
        "Square.area() recovered Code bytes must equal the pinned register->stack lowering"
    );
}

fn operand_u16(code: &[u8], pc: usize) -> usize {
    usize::from(u16::from_be_bytes([code[pc + 1], code[pc + 2]]))
}

struct VerifierOutcome {
    linked: usize,
    verify_failures: usize,
    methods_verified: usize,
    bodies_recovered: usize,
    method_total: usize,
}

fn run_jvm_verifier(
    java: &PathBuf,
    helper_dir: &PathBuf,
    dex_name: &str,
    tag: &str,
) -> VerifierOutcome {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", dex_name])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");
    let jar: Vec<u8> = disrobe_pass_jvm::assemble_jar(&result).expect("assemble jar");
    let jar_path: PathBuf = helper_dir.join(format!("{tag}.jar"));
    std::fs::write(&jar_path, &jar).expect("write jar");

    let run: std::process::Output = std::process::Command::new(java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(helper_dir)
        .arg("V")
        .arg(&jar_path)
        .output()
        .expect("run verifier");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "verifier helper crashed on {dex_name}: {}\n{}",
        String::from_utf8_lossy(&run.stderr),
        stdout
    );
    eprintln!("verifier [{dex_name}]: {}", stdout.trim());
    assert!(
        stdout.contains("verify_failures=0"),
        "translated classes from {dex_name} must pass the JVM verifier with zero failures: {stdout}"
    );
    let body_pct: f64 = result.bodies_recovered as f64 * 100.0 / result.method_total.max(1) as f64;
    eprintln!(
        "real bodies recovered [{dex_name}]: {}/{} ({body_pct:.1}% of all methods)",
        result.bodies_recovered, result.method_total
    );
    VerifierOutcome {
        linked: parse_metric(&stdout, "classes_linked_ok="),
        verify_failures: parse_metric(&stdout, "verify_failures="),
        methods_verified: parse_metric(&stdout, "methods_verified="),
        bodies_recovered: result.bodies_recovered,
        method_total: result.method_total,
    }
}

#[test]
fn translated_classes_pass_jvm_verifier() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP: java (JDK) not on PATH - JVM verifier check unavailable");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac (JDK) not on PATH - cannot build verifier helper");
        return;
    };

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_dex2jar_verify")
            .expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("V.java");
    std::fs::write(&src_path, VERIFIER_SRC).expect("write helper");

    let compiled: std::process::Output = std::process::Command::new(&javac)
        .arg("-d")
        .arg(&dir)
        .arg(&src_path)
        .output()
        .expect("run javac");
    if !compiled.status.success() {
        eprintln!(
            "SKIP translated_classes_pass_jvm_verifier: the verifier helper needs a JDK exposing the java.lang.classfile API (JDK 24+); this toolchain could not compile it: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        return;
    }

    let java_out: VerifierOutcome = run_jvm_verifier(&java, &dir, "EdgeCases.dex", "java");
    assert_eq!(
        java_out.verify_failures, 0,
        "EdgeCases.dex recovered bodies must verify"
    );
    assert!(
        java_out.linked >= 30,
        "expected the synthetic-supertype loader to link most classes, got {}",
        java_out.linked
    );
    assert!(
        java_out.methods_verified >= 250,
        "expected the JVM to actually verify the recovered bodies, got {}",
        java_out.methods_verified
    );
    assert!(
        java_out.bodies_recovered >= 354,
        "switch/try/array, empty-catch dispatch, and synthetic-class CFG lowering must hold its \
         recovered-body floor on EdgeCases.dex ({} of {}); a drop means a real-body regression",
        java_out.bodies_recovered,
        java_out.method_total
    );

    let kt_out: VerifierOutcome = run_jvm_verifier(&java, &dir, "EdgeCasesKt.dex", "kotlin");
    assert_eq!(
        kt_out.verify_failures, 0,
        "EdgeCasesKt.dex recovered bodies (Kotlin coroutine state machines included) must verify"
    );
    assert!(
        kt_out.bodies_recovered >= 435,
        "Kotlin synthetic/coroutine bodies (WhenMappings empty-catch dispatch included) must hold \
         their recovered-body floor ({} of {})",
        kt_out.bodies_recovered,
        kt_out.method_total
    );
}

const VERIFIER_SRC: &str = r#"
import java.io.*;
import java.lang.classfile.*;
import java.lang.constant.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.zip.*;

public class V {
    static class L extends ClassLoader {
        Map<String,byte[]> pool;
        L(Map<String,byte[]> p){ super(V.class.getClassLoader()); pool = p; }
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] b = pool.get(name);
            if (b != null) return defineClass(name, b, 0, b.length);
            try { return super.findClass(name); }
            catch (ClassNotFoundException e) { return defineStub(name); }
        }
        Class<?> defineStub(String name) {
            ClassDesc cd = ClassDesc.of(name);
            boolean throwable = name.endsWith("Exception") || name.endsWith("Error")
                || name.endsWith("Throwable");
            byte[] b = throwable
                ? ClassFile.of().build(cd, cb -> cb
                    .withFlags(ClassFile.ACC_PUBLIC | ClassFile.ACC_SUPER)
                    .withSuperclass(ClassDesc.of("java.lang.Throwable")))
                : ClassFile.of().build(cd, cb -> cb
                    .withFlags(ClassFile.ACC_PUBLIC | ClassFile.ACC_INTERFACE | ClassFile.ACC_ABSTRACT)
                    .withSuperclass(ConstantDescs.CD_Object));
            return defineClass(name, b, 0, b.length);
        }
        void link(Class<?> c){ resolveClass(c); }
    }
    public static void main(String[] a) throws Exception {
        Map<String,byte[]> pool = new HashMap<>();
        try (ZipInputStream z = new ZipInputStream(new FileInputStream(a[0]))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (!e.getName().endsWith(".class")) continue;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192]; int n;
                while ((n = z.read(buf)) > 0) bos.write(buf, 0, n);
                String cn = e.getName().substring(0, e.getName().length()-6).replace('/', '.');
                pool.put(cn, bos.toByteArray());
            }
        }
        L l = new L(pool);
        int ok=0, vf=0, methods=0;
        List<String> errs = new ArrayList<>();
        for (String cn : pool.keySet()) {
            try {
                Class<?> c = l.findClass(cn);
                l.link(c);
                // getDeclaredMethods forces full method-body verification of the class.
                Method[] ms = c.getDeclaredMethods();
                methods += ms.length;
                ok++;
            } catch (VerifyError ve) {
                vf++; errs.add("VERIFY "+cn+": "+ve.getMessage());
            } catch (Throwable t) { /* missing deps unrelated to our bytecode shape */ }
        }
        System.out.println("classes_linked_ok="+ok+" verify_failures="+vf+" methods_verified="+methods);
        for (String s : errs) System.out.println(s);
    }
}
"#;

fn parse_metric(stdout: &str, key: &str) -> usize {
    stdout
        .split_whitespace()
        .find_map(|tok: &str| tok.strip_prefix(key))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(0)
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat"]
    } else {
        &[""]
    };
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
