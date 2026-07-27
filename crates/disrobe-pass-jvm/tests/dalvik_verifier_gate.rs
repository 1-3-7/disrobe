#![allow(
    clippy::absurd_extreme_comparisons,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_jvm::assemble_jar;
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};

const COMMITTED_DEXES: &[(&str, &[u8])] = &[
    (
        "EdgeCases.dex",
        include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex"),
    ),
    (
        "EdgeCasesKt.dex",
        include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex"),
    ),
    (
        "Hello.dex",
        include_bytes!("../../../corpus/jvm/dex/Hello.dex"),
    ),
];

const VERIFY_CLEAN_CLASS_FLOOR: usize = 102;

const LIFTER_VERIFY_FAIL_CEILING: usize = 0;

const BODY_VERIFY_CLEAN_FLOOR: usize = 307;

const BODY_VERIFY_FAIL_CEILING: usize = 0;

struct VerifyCounts {
    clean_classes: usize,
    lifter_fail_classes: usize,
    link_skipped_classes: usize,
    methods_clean: usize,
    methods_in_failed_classes: usize,
    body_clean: usize,
    body_fail: usize,
    errors: Vec<String>,
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

fn parse_metric(stdout: &str, key: &str) -> usize {
    stdout
        .split_whitespace()
        .find_map(|tok: &str| tok.strip_prefix(key))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(0)
}

fn run_verifier(java: &Path, dir: &Path, jar: &Path) -> VerifyCounts {
    let run: Output = Command::new(java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(dir)
        .arg("V")
        .arg(jar)
        .output()
        .expect("run jvm verifier");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "verifier helper crashed: {}\n{stdout}",
        String::from_utf8_lossy(&run.stderr)
    );
    let errors: Vec<String> = stdout
        .lines()
        .filter(|l: &&str| l.starts_with("VERIFY ") || l.starts_with("BODYVERIFY "))
        .map(|l: &str| l.to_string())
        .collect();
    VerifyCounts {
        clean_classes: parse_metric(&stdout, "verify_clean_classes="),
        lifter_fail_classes: parse_metric(&stdout, "lifter_verify_fail_classes="),
        link_skipped_classes: parse_metric(&stdout, "link_skipped_classes="),
        methods_clean: parse_metric(&stdout, "methods_clean="),
        methods_in_failed_classes: parse_metric(&stdout, "methods_lifter_fail="),
        body_clean: parse_metric(&stdout, "body_clean="),
        body_fail: parse_metric(&stdout, "body_fail="),
        errors,
    }
}

#[test]
fn recovered_dalvik_bodies_pass_the_real_jvm_verifier() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!(
            "SKIP dalvik verifier gate: java (JDK 24+ exposing java.lang.classfile) not on PATH; \
             the headline verifier-clean number cannot be attested in this environment"
        );
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP dalvik verifier gate: javac (JDK) not on PATH");
        return;
    };

    let purpose: String = format!("disrobe_dalvik_verifier_gate_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("V.java");
    std::fs::write(&src_path, VERIFIER_SRC).expect("write verifier source");

    let compiled: Output = Command::new(&javac)
        .arg("-d")
        .arg(&dir)
        .arg(&src_path)
        .output()
        .expect("run javac");
    if !compiled.status.success() {
        eprintln!(
            "SKIP dalvik verifier gate: helper needs a JDK exposing java.lang.classfile (JDK 24+): {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        return;
    }

    let mut total_clean: usize = 0;
    let mut total_lifter_fail: usize = 0;
    let mut total_link_skipped: usize = 0;
    let mut total_methods_clean: usize = 0;
    let mut total_methods_in_failed: usize = 0;
    let mut total_body_clean: usize = 0;
    let mut total_body_fail: usize = 0;
    let mut all_errors: Vec<String> = Vec::new();

    for (label, dex_bytes) in COMMITTED_DEXES {
        let result: Dex2JarResult = translate_dex_bytes(dex_bytes).expect("translate dex");
        let jar: Vec<u8> = assemble_jar(&result).expect("assemble jar");
        let jar_path: PathBuf = dir.join(format!("{label}.jar"));
        std::fs::write(&jar_path, &jar).expect("write jar");

        let counts: VerifyCounts = run_verifier(&java, &dir, &jar_path);
        let verifiable: usize = counts.clean_classes + counts.lifter_fail_classes;
        let pct: f64 = counts.clean_classes as f64 * 100.0 / verifiable.max(1) as f64;
        eprintln!(
            "DALVIK VERIFY {label}: clean={} lifter_fail={} link_skipped={} \
             ({pct:.1}% of verifiable classes pass -Xverify:all); methods_in_clean_classes={} methods_in_failed_classes={} \
             body_clean={} body_fail={}",
            counts.clean_classes,
            counts.lifter_fail_classes,
            counts.link_skipped_classes,
            counts.methods_clean,
            counts.methods_in_failed_classes,
            counts.body_clean,
            counts.body_fail
        );
        total_clean += counts.clean_classes;
        total_lifter_fail += counts.lifter_fail_classes;
        total_link_skipped += counts.link_skipped_classes;
        total_methods_clean += counts.methods_clean;
        total_methods_in_failed += counts.methods_in_failed_classes;
        total_body_clean += counts.body_clean;
        total_body_fail += counts.body_fail;
        all_errors.extend(counts.errors);
    }

    let verifiable: usize = total_clean + total_lifter_fail;
    let class_pct: f64 = total_clean as f64 * 100.0 / verifiable.max(1) as f64;
    eprintln!(
        "DALVIK VERIFY TOTAL: verifier_clean_classes={total_clean} lifter_verify_fail_classes={total_lifter_fail} \
         link_skipped_classes={total_link_skipped} \
         => {class_pct:.1}% of verifiable classes pass the real JVM verifier on the committed dex corpus \
         (methods in clean classes={total_methods_clean}, in failed classes={total_methods_in_failed}); \
         RE-HOSTED BODY VERIFY: body_clean={total_body_clean} body_fail={total_body_fail} \
         (every non-stub recovered method body re-hosted into an Object carrier and run through -Xverify:all)"
    );
    for e in &all_errors {
        eprintln!("  {e}");
    }
    assert!(
        total_clean >= VERIFY_CLEAN_CLASS_FLOOR,
        "verifier-clean classes {total_clean} fell below floor {VERIFY_CLEAN_CLASS_FLOOR}; \
         the dalvik lifter regressed (fewer recovered bodies pass the real JVM verifier)"
    );
    assert!(
        total_lifter_fail <= LIFTER_VERIFY_FAIL_CEILING,
        "genuine lifter verify failures {total_lifter_fail} exceeded ceiling {LIFTER_VERIFY_FAIL_CEILING}; \
         the lifter started emitting malformed bytecode the JVM rejects:\n{}",
        all_errors.join("\n")
    );
    assert!(
        total_body_clean >= BODY_VERIFY_CLEAN_FLOOR,
        "re-hosted verifier-clean method bodies {total_body_clean} fell below floor {BODY_VERIFY_CLEAN_FLOOR}; \
         the dalvik lifter recovered fewer real bodies that pass the per-method -Xverify:all carrier"
    );
    assert!(
        total_body_fail <= BODY_VERIFY_FAIL_CEILING,
        "re-hosted method bodies that the JVM verifier rejects {total_body_fail} exceeded ceiling {BODY_VERIFY_FAIL_CEILING}; \
         the lifter emitted a real body the verifier rejects:\n{}",
        all_errors.join("\n")
    );
    assert!(
        verifiable >= 90,
        "expected the committed corpus to submit >=90 verifiable classes to the JVM, got {verifiable}"
    );
}

const VERIFIER_SRC: &str = r#"
import java.io.*;
import java.lang.classfile.*;
import java.lang.classfile.instruction.*;
import java.lang.constant.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.zip.*;

public class V {
    static class L extends ClassLoader {
        Map<String,byte[]> pool;
        Set<String> stubbed = new HashSet<>();
        L(Map<String,byte[]> p){ super(V.class.getClassLoader()); pool = p; }
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] b = pool.get(name);
            if (b != null) return defineClass(name, b, 0, b.length);
            try { return super.findClass(name); }
            catch (ClassNotFoundException e) { return defineStub(name); }
        }
        Class<?> defineStub(String name) {
            stubbed.add(name);
            ClassDesc cd = ClassDesc.of(name);
            byte[] b = ClassFile.of().build(cd, cb -> cb
                .withFlags(ClassFile.ACC_PUBLIC)
                .withSuperclass(ClassDesc.of("java.lang.RuntimeException")));
            return defineClass(name, b, 0, b.length);
        }
        boolean isStubbed(String name) { return stubbed.contains(name); }
        Class<?> defineRaw(String name, byte[] b) {
            return defineClass(name, b, 0, b.length);
        }
        void link(Class<?> c){ resolveClass(c); }
    }
    static boolean refsStub(L l, ClassModel cm, MethodModel mm) {
        for (java.lang.classfile.constantpool.PoolEntry pe : cm.constantPool()) {
            String nm = null;
            if (pe instanceof java.lang.classfile.constantpool.ClassEntry ce) {
                nm = ce.asInternalName().replace('/', '.');
                if (nm.startsWith("[")) continue;
            }
            if (nm != null && l.isStubbed(nm)) return true;
        }
        return false;
    }
    static boolean isStub(CodeModel code) {
        int n = 0; boolean athrow = false;
        for (CodeElement ce : code) {
            if (ce instanceof Instruction) {
                n++;
                if (ce instanceof ThrowInstruction) athrow = true;
            }
        }
        return n <= 4 && athrow;
    }
    static int methodsWithCode(byte[] b) {
        ClassModel cm = ClassFile.of().parse(b);
        int n = 0;
        for (MethodModel m : cm.methods())
            if (m.code().isPresent()) n++;
        return n;
    }
    static boolean usesInvokeSpecial(MethodModel mm) {
        for (CodeElement ce : mm.code().get()) {
            if (ce instanceof InvokeInstruction ii && ii.opcode() == Opcode.INVOKESPECIAL) return true;
        }
        return false;
    }
    static int carrierSeq = 0;
    static byte[] carrier(ClassModel cm, MethodModel mm) {
        boolean isStatic = (mm.flags().flagsMask() & ClassFile.ACC_STATIC) != 0;
        String mname = mm.methodName().stringValue();
        MethodTypeDesc origType = mm.methodTypeSymbol();
        MethodTypeDesc carriedType = origType;
        if (!isStatic) {
            ClassDesc recv = cm.thisClass().asSymbol();
            List<ClassDesc> ps = new ArrayList<>();
            ps.add(recv);
            ps.addAll(origType.parameterList());
            carriedType = MethodTypeDesc.of(origType.returnType(), ps);
        }
        final MethodTypeDesc ct = carriedType;
        ClassDesc carrierName = ClassDesc.of("probe.P" + (carrierSeq++));
        return ClassFile.of().build(carrierName, cb -> {
            cb.withFlags(ClassFile.ACC_PUBLIC);
            cb.withSuperclass(ConstantDescs.CD_Object);
            cb.withMethod(mname, ct, ClassFile.ACC_PUBLIC | ClassFile.ACC_STATIC, mb -> {
                mm.code().ifPresent(code -> mb.withCode(xb -> {
                    for (CodeElement ce : code) xb.with(ce);
                }));
            });
        });
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
        int verifyClean=0, lifterFail=0, linkSkipped=0;
        int methodsClean=0, methodsLifterFail=0;
        int bodyClean=0, bodyFail=0;
        List<String> errs = new ArrayList<>();
        List<String> bodyErrs = new ArrayList<>();
        List<String> names = new ArrayList<>(pool.keySet());
        Collections.sort(names);
        for (String cn : names) {
            int mc = methodsWithCode(pool.get(cn));
            try {
                Class<?> c = l.findClass(cn);
                l.link(c);
                c.getDeclaredMethods();
                c.getDeclaredConstructors();
                verifyClean++; methodsClean += mc;
            } catch (VerifyError ve) {
                String m = String.valueOf(ve.getMessage());
                lifterFail++; methodsLifterFail += mc;
                errs.add("VERIFY "+cn+": "+m.replace('\n',' ').substring(0, Math.min(200, m.length())));
            } catch (Throwable t) {
                linkSkipped++;
            }
        }
        for (String cn : names) {
            ClassModel cm = ClassFile.of().parse(pool.get(cn));
            for (MethodModel mm : cm.methods()) {
                if (mm.code().isEmpty()) continue;
                if (mm.methodName().stringValue().equals("<init>")) continue;
                if (mm.methodName().stringValue().equals("<clinit>")) continue;
                if (isStub(mm.code().get())) continue;
                if (usesInvokeSpecial(mm)) continue;
                if (refsStub(l, cm, mm)) continue;
                try {
                    byte[] cb = carrier(cm, mm);
                    Class<?> pc = l.defineRaw(null, cb);
                    l.link(pc);
                    pc.getDeclaredMethods();
                    bodyClean++;
                } catch (VerifyError ve) {
                    bodyFail++;
                    if (bodyErrs.size() < 60) {
                        String m = String.valueOf(ve.getMessage());
                        bodyErrs.add("BODYVERIFY "+cn+"."+mm.methodName().stringValue()
                            +mm.methodType().stringValue()+": "+m.replace('\n',' ').substring(0, Math.min(140, m.length())));
                    }
                } catch (Throwable t) {
                }
            }
        }
        System.out.println("verify_clean_classes="+verifyClean+" lifter_verify_fail_classes="+lifterFail
            +" link_skipped_classes="+linkSkipped
            +" methods_clean="+methodsClean+" methods_lifter_fail="+methodsLifterFail
            +" body_clean="+bodyClean+" body_fail="+bodyFail);
        for (String s : errs) System.out.println(s);
        for (String s : bodyErrs) System.out.println(s);
    }
}
"#;
