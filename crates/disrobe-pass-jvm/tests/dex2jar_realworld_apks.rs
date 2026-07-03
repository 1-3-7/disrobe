#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::path::PathBuf;

use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ApkExtract, extract_apk};

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

struct RealApk {
    file: &'static str,
    min_bodies_pct: f64,
    min_method_total: usize,
}

const REAL_APKS: &[RealApk] = &[
    RealApk {
        file: "transmissionic-ionic.apk",
        min_bodies_pct: 93.7,
        min_method_total: 20_000,
    },
    RealApk {
        file: "rustdesk-flutter.apk",
        min_bodies_pct: 89.8,
        min_method_total: 20_000,
    },
    RealApk {
        file: "enrecipes-nativescript.apk",
        min_bodies_pct: 92.1,
        min_method_total: 20_000,
    },
];

#[test]
fn realworld_apk_bodies_recovered_above_floor() {
    if std::env::var_os("DISROBE_RUN_REAL_APK_TESTS").is_none() {
        eprintln!("SKIP: set DISROBE_RUN_REAL_APK_TESTS=1 to run local real apk corpus checks");
        return;
    }
    let mut measured: usize = 0;
    for apk in REAL_APKS {
        let path: PathBuf = corpus(&["mobile", "apk", "inbox", apk.file]);
        if !path.is_file() {
            eprintln!(
                "skipping {} (local-only fixture not present at {})",
                apk.file,
                path.display()
            );
            continue;
        }
        measured += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read apk");
        let extract: ApkExtract = extract_apk(&bytes).expect("extract apk");

        let mut method_total: usize = 0;
        let mut bodies_recovered: usize = 0;
        let mut dex_count: usize = 0;
        for (name, dex_bytes) in &extract.dex_files {
            if !name.ends_with(".dex") {
                continue;
            }
            dex_count += 1;
            let result: Dex2JarResult =
                translate_dex_bytes(dex_bytes).expect("translate classes.dex");
            method_total += result.method_total;
            bodies_recovered += result.bodies_recovered;
        }

        assert!(
            dex_count >= 1,
            "{}: apk must contain at least one classes.dex",
            apk.file
        );
        assert!(
            method_total >= apk.min_method_total,
            "{}: expected >= {} defined methods, got {method_total}",
            apk.file,
            apk.min_method_total
        );
        let pct: f64 = bodies_recovered as f64 * 100.0 / method_total.max(1) as f64;
        eprintln!(
            "REALWORLD {}: dex_files={dex_count} method_total={method_total} \
             bodies_recovered={bodies_recovered} ({pct:.1}%)",
            apk.file
        );
        assert!(
            pct >= apk.min_bodies_pct,
            "{}: honest body-recovery {pct:.1}% fell below floor {:.1}% (lifter regression)",
            apk.file,
            apk.min_bodies_pct
        );
    }
    if measured == 0 {
        eprintln!("realworld apk measurement skipped: no local fixtures present (expected in CI)");
    }
}

#[test]
fn realworld_apk_translated_classes_verify() {
    if std::env::var_os("DISROBE_RUN_REAL_APK_TESTS").is_none() {
        eprintln!("SKIP: set DISROBE_RUN_REAL_APK_TESTS=1 to run local real apk verification");
        return;
    }
    let path: PathBuf = corpus(&["mobile", "apk", "inbox", "transmissionic-ionic.apk"]);
    if !path.is_file() {
        eprintln!("SKIP: local apk fixture not present at {}", path.display());
        return;
    }
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP: java (JDK) not on PATH");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac (JDK) not on PATH");
        return;
    };

    let bytes: Vec<u8> = std::fs::read(&path).expect("read apk");
    let extract: ApkExtract = extract_apk(&bytes).expect("extract apk");
    let dex: &Vec<u8> = extract
        .dex_files
        .get("classes.dex")
        .expect("transmissionic classes.dex");
    let result: Dex2JarResult = translate_dex_bytes(dex).expect("translate");
    let jar: Vec<u8> = disrobe_pass_jvm::assemble_jar(&result).expect("assemble jar");

    let dir: PathBuf = std::env::temp_dir().join("disrobe_realworld_verify");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let jar_path: PathBuf = dir.join("translated.jar");
    std::fs::write(&jar_path, &jar).expect("write jar");
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
            "SKIP realworld verify: helper needs a JDK exposing java.lang.classfile (JDK 24+): {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        return;
    }

    let run: std::process::Output = std::process::Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(&dir)
        .arg("V")
        .arg(&jar_path)
        .output()
        .expect("run verifier");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "verifier helper crashed: {}\n{}",
        String::from_utf8_lossy(&run.stderr),
        stdout
    );
    let linked: usize = parse_metric(&stdout, "classes_linked_ok=");
    let verify_failures: usize = parse_metric(&stdout, "verify_failures=");
    let methods: usize = parse_metric(&stdout, "methods_verified=");
    eprintln!(
        "REALWORLD VERIFY transmissionic: classes_linked_ok={linked} verify_failures={verify_failures} methods_verified={methods}"
    );
    for line in stdout
        .lines()
        .filter(|l: &&str| l.starts_with("VERIFY "))
        .take(20)
    {
        eprintln!("{line}");
    }
    assert!(
        linked >= 200,
        "expected the synthetic-supertype loader to link a real subset, got {linked}\n{stdout}"
    );
    assert!(
        methods >= 1000,
        "expected the JVM to actually verify a real subset of recovered bodies, got {methods}"
    );

    let catch_stub_failures: usize = stdout
        .lines()
        .filter(|l: &&str| l.contains("is not a subclass of Throwable"))
        .count();
    let lifter_failures: usize = verify_failures.saturating_sub(catch_stub_failures);
    let fail_rate_pct: f64 = lifter_failures as f64 * 100.0 / methods.max(1) as f64;
    eprintln!(
        "real-world verify failures: total={verify_failures} catch-stub-artifacts={catch_stub_failures} \
         lifter={lifter_failures} rate={fail_rate_pct:.2}% of {methods} verified"
    );
    assert!(
        fail_rate_pct <= MAX_VERIFY_FAIL_RATE_PCT,
        "real-world lifter JVM verify failure rate {fail_rate_pct:.2}% exceeded ceiling \
         {MAX_VERIFY_FAIL_RATE_PCT}%; the branch-mode lifter regressed"
    );
}

const MAX_VERIFY_FAIL_RATE_PCT: f64 = 9.0;

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
            byte[] b = ClassFile.of().build(cd, cb -> cb
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
        List<String> names = new ArrayList<>(pool.keySet());
        Collections.sort(names);
        for (String cn : names) {
            try {
                Class<?> c = l.findClass(cn);
                l.link(c);
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
