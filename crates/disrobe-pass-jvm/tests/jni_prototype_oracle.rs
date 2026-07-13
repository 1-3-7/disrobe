#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_jvm::{
    ClassFile, JniPrototype, NativeMethod, emit_jni_prototypes, native_methods_from_class,
    parse_classfile,
};

const FIXTURE_SRC: &str = include_str!("fixtures/jni/NativeSurface.java");

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
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

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c: &char| !c.is_whitespace()).collect()
}

fn header_prototypes(header: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest: &str = header;
    while let Some(pos) = rest.find("JNIEXPORT") {
        let after: &str = &rest[pos..];
        let Some(semi): Option<usize> = after.find(';') else {
            break;
        };
        out.push(strip_ws(&after[..=semi]));
        rest = &after[semi + 1..];
    }
    out
}

const fn platform_include_dir() -> &'static str {
    if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

#[test]
fn emitted_prototypes_match_javac_h_and_compile_against_jni_h() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP jni prototype oracle: javac (JDK) not on PATH");
        return;
    };

    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_jni_proto_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let classes: PathBuf = dir.join("classes");
    let headers: PathBuf = dir.join("headers");
    std::fs::create_dir_all(&classes).expect("mkdir classes");
    std::fs::create_dir_all(&headers).expect("mkdir headers");
    let src: PathBuf = dir.join("NativeSurface.java");
    std::fs::write(&src, FIXTURE_SRC).expect("write fixture");

    let compiled: Output = Command::new(&javac)
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-h")
        .arg(&headers)
        .arg("-d")
        .arg(&classes)
        .arg(&src)
        .output()
        .expect("run javac -h");
    assert!(
        compiled.status.success(),
        "javac -h failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let header_path: PathBuf = headers.join("com_example_jni_NativeSurface.h");
    let header: String = std::fs::read_to_string(&header_path).expect("read generated header");
    let mut truth: Vec<String> = header_prototypes(&header);
    truth.sort();
    assert!(
        !truth.is_empty(),
        "no JNIEXPORT prototypes found in the generated header"
    );

    let class_path: PathBuf = classes.join("com/example/jni/NativeSurface.class");
    let class_bytes: Vec<u8> = std::fs::read(&class_path).expect("read compiled class");
    let class: ClassFile = parse_classfile(&class_bytes).expect("parse class");
    let methods: Vec<NativeMethod> = native_methods_from_class(&class);
    let protos: Vec<JniPrototype> = emit_jni_prototypes(&methods);
    let mut emitted: Vec<String> = protos
        .iter()
        .map(|p: &JniPrototype| strip_ws(&p.declaration))
        .collect();
    emitted.sort();

    assert_eq!(
        emitted, truth,
        "emitted prototypes diverge from javac -h ground truth\nemitted={emitted:#?}\ntruth={truth:#?}"
    );
    eprintln!(
        "javac -h equality: {}/{} prototypes match",
        emitted.len(),
        truth.len()
    );

    let Some(cc): Option<PathBuf> = find_on_path("clang").or_else(|| find_on_path("gcc")) else {
        eprintln!(
            "SKIP jni.h syntax check: no clang/gcc on PATH; javac -h equality already attested"
        );
        return;
    };
    let Some(java_home): Option<std::ffi::OsString> = std::env::var_os("JAVA_HOME") else {
        eprintln!("SKIP jni.h syntax check: JAVA_HOME unset; javac -h equality already attested");
        return;
    };
    let include: PathBuf = PathBuf::from(&java_home).join("include");
    let include_platform: PathBuf = include.join(platform_include_dir());
    let mut c_source: String = String::from("#include <jni.h>\n");
    for proto in &protos {
        c_source.push_str(&proto.declaration);
        c_source.push('\n');
    }
    let c_path: PathBuf = dir.join("prototypes.c");
    std::fs::write(&c_path, &c_source).expect("write prototypes.c");
    let syntax: Output = Command::new(&cc)
        .arg("-fsyntax-only")
        .arg("-I")
        .arg(&include)
        .arg("-I")
        .arg(&include_platform)
        .arg(&c_path)
        .output()
        .expect("run C compiler");
    assert!(
        syntax.status.success(),
        "emitted prototypes failed to compile against real jni.h:\n{}\n{}",
        String::from_utf8_lossy(&syntax.stdout),
        String::from_utf8_lossy(&syntax.stderr)
    );
    eprintln!(
        "clang -fsyntax-only against real jni.h: exit 0 ({} prototypes)",
        protos.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
