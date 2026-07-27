#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};

const ICONST_3: u8 = 0x06;
const LDC2_W: u8 = 0x14;
const LADD: u8 = 0x61;
const LSHL: u8 = 0x79;
const LXOR: u8 = 0x83;
const GETSTATIC: u8 = 0xB2;
const INVOKEVIRTUAL: u8 = 0xB6;
const RETURN: u8 = 0xB1;

struct ClassEmit {
    pool: Vec<Vec<u8>>,
}

impl ClassEmit {
    const fn new() -> Self {
        Self { pool: Vec::new() }
    }

    fn add(&mut self, entry: Vec<u8>) -> u16 {
        self.pool.push(entry);
        u16::try_from(self.pool.len()).expect("pool index fits u16")
    }

    fn utf8(&mut self, s: &str) -> u16 {
        let mut e: Vec<u8> = vec![1];
        e.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
        e.extend_from_slice(s.as_bytes());
        self.add(e)
    }

    fn long(&mut self, value: i64) -> u16 {
        let mut e: Vec<u8> = vec![5];
        e.extend_from_slice(&value.to_be_bytes());
        let idx: u16 = self.add(e);
        self.pool.push(Vec::new());
        idx
    }

    fn class(&mut self, name: &str) -> u16 {
        let n: u16 = self.utf8(name);
        let mut e: Vec<u8> = vec![7];
        e.extend_from_slice(&n.to_be_bytes());
        self.add(e)
    }

    fn name_and_type(&mut self, name: &str, desc: &str) -> u16 {
        let n: u16 = self.utf8(name);
        let d: u16 = self.utf8(desc);
        let mut e: Vec<u8> = vec![12];
        e.extend_from_slice(&n.to_be_bytes());
        e.extend_from_slice(&d.to_be_bytes());
        self.add(e)
    }

    fn fieldref(&mut self, owner: &str, name: &str, desc: &str) -> u16 {
        let c: u16 = self.class(owner);
        let nt: u16 = self.name_and_type(name, desc);
        let mut e: Vec<u8> = vec![9];
        e.extend_from_slice(&c.to_be_bytes());
        e.extend_from_slice(&nt.to_be_bytes());
        self.add(e)
    }

    fn methodref(&mut self, owner: &str, name: &str, desc: &str) -> u16 {
        let c: u16 = self.class(owner);
        let nt: u16 = self.name_and_type(name, desc);
        let mut e: Vec<u8> = vec![10];
        e.extend_from_slice(&c.to_be_bytes());
        e.extend_from_slice(&nt.to_be_bytes());
        self.add(e)
    }

    fn into_bytes(self, this_class: u16, super_class: u16, methods: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&52u16.to_be_bytes());
        let count: u16 = u16::try_from(self.pool.len() + 1).unwrap();
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.pool {
            out.extend_from_slice(entry);
        }
        out.extend_from_slice(&0x0021u16.to_be_bytes());
        out.extend_from_slice(&this_class.to_be_bytes());
        out.extend_from_slice(&super_class.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&u16::try_from(methods.len()).unwrap().to_be_bytes());
        for m in methods {
            out.extend_from_slice(m);
        }
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }
}

fn ldc2(idx: u16) -> Vec<u8> {
    let mut v: Vec<u8> = vec![LDC2_W];
    v.extend_from_slice(&idx.to_be_bytes());
    v
}

fn build_obfuscated_class() -> (Vec<u8>, i64) {
    let a: i64 = 0x1122_3344_5566_7788;
    let b: i64 = 0x0F0F_0F0F_0F0F_0F0F;
    let c: i64 = 0x0000_0000_0000_0100;
    let shift: i64 = 3;
    let expected: i64 = ((a ^ b).wrapping_add(c)) << (shift & 0x3F);

    let mut e: ClassEmit = ClassEmit::new();
    let code_utf8: u16 = e.utf8("Code");
    let main_name: u16 = e.utf8("main");
    let main_desc: u16 = e.utf8("([Ljava/lang/String;)V");
    let la: u16 = e.long(a);
    let lb: u16 = e.long(b);
    let lc: u16 = e.long(c);
    let sysout: u16 = e.fieldref("java/lang/System", "out", "Ljava/io/PrintStream;");
    let println: u16 = e.methodref("java/io/PrintStream", "println", "(J)V");
    let object: u16 = e.class("java/lang/Object");
    let this_class: u16 = e.class("NumberObf");

    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&ldc2(la));
    code.extend_from_slice(&ldc2(lb));
    code.push(LXOR);
    code.extend_from_slice(&ldc2(lc));
    code.push(LADD);
    code.push(ICONST_3);
    code.push(LSHL);
    let mut store: Vec<u8> = Vec::new();
    store.extend_from_slice(&[GETSTATIC]);
    store.extend_from_slice(&sysout.to_be_bytes());
    let mut after: Vec<u8> = Vec::new();
    after.extend_from_slice(&[INVOKEVIRTUAL]);
    after.extend_from_slice(&println.to_be_bytes());
    after.push(RETURN);

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&store);
    body.extend_from_slice(&code);
    body.extend_from_slice(&after);

    let mut code_attr: Vec<u8> = Vec::new();
    code_attr.extend_from_slice(&6u16.to_be_bytes());
    code_attr.extend_from_slice(&1u16.to_be_bytes());
    code_attr.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    code_attr.extend_from_slice(&body);
    code_attr.extend_from_slice(&0u16.to_be_bytes());
    code_attr.extend_from_slice(&0u16.to_be_bytes());

    let mut method: Vec<u8> = Vec::new();
    method.extend_from_slice(&0x0009u16.to_be_bytes());
    method.extend_from_slice(&main_name.to_be_bytes());
    method.extend_from_slice(&main_desc.to_be_bytes());
    method.extend_from_slice(&1u16.to_be_bytes());
    method.extend_from_slice(&code_utf8.to_be_bytes());
    method.extend_from_slice(&u32::try_from(code_attr.len()).unwrap().to_be_bytes());
    method.extend_from_slice(&code_attr);

    let _ = object;
    let bytes: Vec<u8> = e.into_bytes(this_class, object, &[method]);
    (bytes, expected)
}

fn java_tool(tool: &str) -> Option<PathBuf> {
    let home: String = std::env::var("JAVA_HOME").ok()?;
    let exe: PathBuf = Path::new(&home).join("bin").join(if cfg!(windows) {
        format!("{tool}.exe")
    } else {
        tool.to_owned()
    });
    exe.exists().then_some(exe)
}

fn which(tool: &str) -> Option<PathBuf> {
    if let Some(p) = java_tool(tool) {
        return Some(p);
    }
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let out: std::process::Output = Command::new(probe).arg(tool).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let line: &str = std::str::from_utf8(&out.stdout).ok()?.lines().next()?;
    let p: PathBuf = PathBuf::from(line.trim());
    p.exists().then_some(p)
}

fn run_class(java: &Path, dir: &Path, main: &str) -> Option<String> {
    let out: std::process::Output = Command::new(java)
        .arg("-cp")
        .arg(dir)
        .arg(main)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!("java run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[test]
fn long_number_obfuscation_folds_and_recompiles_to_same_jvm_output() {
    let (Some(java), Some(javac)): (Option<PathBuf>, Option<PathBuf>) =
        (which("java"), which("javac"))
    else {
        eprintln!("skip: no JDK on PATH/JAVA_HOME; cannot run the real-JVM oracle");
        return;
    };

    let (obf_bytes, expected): (Vec<u8>, i64) = build_obfuscated_class();
    let purpose: String = format!("disrobe_numfold_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let tmp: PathBuf = scratch.path().to_path_buf();
    let obf_class: PathBuf = tmp.join("NumberObf.class");
    std::fs::write(&obf_class, &obf_bytes).expect("write obf class");

    let oracle_stdout: String =
        run_class(&java, &tmp, "NumberObf").expect("obfuscated class runs under the JVM");
    assert_eq!(
        oracle_stdout,
        expected.to_string(),
        "JVM oracle must print the computed long value"
    );

    let decompiled: DecompiledClass =
        decompile_classfile_bytes(&obf_bytes).expect("disrobe decompiles the obfuscated class");
    let src: String = decompiled.source;

    assert!(
        src.contains(&format!("{expected}L")),
        "the long arithmetic chain must fold to the single literal {expected}L; got:\n{src}"
    );
    assert!(
        !src.contains('^') && !src.contains("<<"),
        "no residual XOR/shift chain should remain after folding; got:\n{src}"
    );

    let recovered_src: String = src.replace("class NumberObf", "class Recovered");
    let recovered_java: PathBuf = tmp.join("Recovered.java");
    std::fs::write(&recovered_java, &recovered_src).expect("write recovered source");

    let compile: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&tmp)
        .arg(&recovered_java)
        .output()
        .expect("javac runs");
    assert!(
        compile.status.success(),
        "recovered source must recompile under javac:\n{}\nsource:\n{recovered_src}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let recovered_stdout: String =
        run_class(&java, &tmp, "Recovered").expect("recovered class runs under the JVM");
    assert_eq!(
        recovered_stdout, oracle_stdout,
        "recovered program's JVM stdout must match the obfuscated original's JVM stdout"
    );
}
