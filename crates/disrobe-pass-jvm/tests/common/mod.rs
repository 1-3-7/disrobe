#![allow(
    dead_code,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::print_stderr
)]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use sha2::{Digest, Sha256};

pub const VERIFIER_SRC: &str = include_str!("V.java");

pub fn find_on_path(name: &str) -> Option<PathBuf> {
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

pub fn parse_metric(stdout: &str, key: &str) -> usize {
    stdout
        .split_whitespace()
        .find_map(|tok: &str| tok.strip_prefix(key))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(0)
}

pub fn assert_permille(stdout: &str, expected: u32) {
    let seen: Option<u32> = stdout
        .split_whitespace()
        .find_map(|tok: &str| tok.strip_prefix("permille="))
        .and_then(|value: &str| value.parse::<u32>().ok());
    assert_eq!(
        seen,
        Some(expected),
        "the jvm helper reported a body sample of {seen:?} permille but this gate's pinned counts \
         were recorded at {expected}; a caller that changes the sample rate changes the population \
         behind every figure the gate asserts"
    );
}

#[derive(Debug)]
pub struct RealApk {
    pub file: &'static str,
    pub sha256: &'static str,
    pub short: &'static str,
    pub golden: &'static str,
    pub method_total: usize,
    pub code_item_methods_pinned: usize,
    pub self_reported_bodies_pinned: usize,
    pub candidate_bodies_pinned: usize,
    pub sampled_bodies_pinned: usize,
    pub presented_bodies: usize,
    pub attested_clean_pinned: usize,
    pub attested_rejected_pinned: usize,
}

pub const REAL_APKS: &[RealApk] = &[
    RealApk {
        file: "transmissionic-ionic.apk",
        sha256: "941d6781ed72f9e819347431d2ff36406b032b12a72a62fbac50d06f9b2a0b4f",
        short: "transmissionic",
        golden: "transmissionic-ionic.txt",
        method_total: 27_805,
        code_item_methods_pinned: 26_416,
        self_reported_bodies_pinned: 26_360,
        candidate_bodies_pinned: 26_360,
        sampled_bodies_pinned: 2_688,
        presented_bodies: 989,
        attested_clean_pinned: 988,
        attested_rejected_pinned: 1,
    },
    RealApk {
        file: "rustdesk-flutter.apk",
        sha256: "56996f058b23635c33d29c6d9f2e31091da45ce5021ce8f5e614970446bc669a",
        short: "rustdesk",
        golden: "rustdesk-flutter.txt",
        method_total: 32_410,
        code_item_methods_pinned: 29_983,
        self_reported_bodies_pinned: 29_841,
        candidate_bodies_pinned: 29_810,
        sampled_bodies_pinned: 2_892,
        presented_bodies: 1223,
        attested_clean_pinned: 1217,
        attested_rejected_pinned: 6,
    },
    RealApk {
        file: "enrecipes-nativescript.apk",
        sha256: "5992f51701ec7f3c06cb353f10ce0c0cb875718775d66b6ed5aa370a0c94934b",
        short: "enrecipes",
        golden: "enrecipes-nativescript.txt",
        method_total: 29_301,
        code_item_methods_pinned: 27_544,
        self_reported_bodies_pinned: 27_461,
        candidate_bodies_pinned: 27_460,
        sampled_bodies_pinned: 2_839,
        presented_bodies: 786,
        attested_clean_pinned: 783,
        attested_rejected_pinned: 3,
    },
];

pub fn real_apk_inbox() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("mobile");
    path.push("apk");
    path.push("inbox");
    path
}

pub fn real_apk_path(file: &str) -> PathBuf {
    real_apk_inbox().join(file)
}

pub fn read_real_apk(file: &str) -> Vec<u8> {
    const MAX_BYTES: usize = 64 * 1024 * 1024;

    let path: PathBuf = real_apk_path(file);
    let apk: &RealApk = REAL_APKS
        .iter()
        .find(|apk: &&RealApk| apk.file == file)
        .unwrap_or_else(|| panic!("{} has no pinned SHA-256 identity", path.display()));
    let input: File =
        File::open(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let mut reader: std::io::Take<File> =
        input.take(u64::try_from(MAX_BYTES + 1).expect("byte limit fits u64"));
    let mut bytes: Vec<u8> = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        bytes.len() <= MAX_BYTES,
        "{} exceeds the 64 MiB real-apk identity limit",
        path.display()
    );
    let actual: String = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        actual,
        apk.sha256,
        "{} has the wrong SHA-256 identity: expected {}, actual {}",
        path.display(),
        apk.sha256,
        actual
    );
    bytes
}

pub fn real_apks_absent() -> Vec<&'static str> {
    REAL_APKS
        .iter()
        .filter(|apk: &&RealApk| {
            if real_apk_path(apk.file).is_file() {
                drop(read_real_apk(apk.file));
                false
            } else {
                true
            }
        })
        .map(|apk: &RealApk| apk.file)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyScope {
    Classes { permille: u32 },
    Bodies { permille: u32 },
}

#[derive(Debug)]
pub struct JvmVerifier {
    java: PathBuf,
    scratch: ScratchDir,
}

impl JvmVerifier {
    pub fn prepare(purpose: &str) -> Result<Self, String> {
        let java: PathBuf =
            find_on_path("java").ok_or_else(|| "java (JDK 24+) not on PATH".to_string())?;
        let javac: PathBuf =
            find_on_path("javac").ok_or_else(|| "javac (JDK 24+) not on PATH".to_string())?;
        let scratch: ScratchDir = ScratchDir::create(purpose).map_err(|e| e.to_string())?;
        let dir: &Path = scratch.path();
        let src: PathBuf = dir.join("V.java");
        std::fs::write(&src, VERIFIER_SRC).map_err(|e| e.to_string())?;
        let compiled: Output = Command::new(&javac)
            .arg("-d")
            .arg(dir)
            .arg(&src)
            .output()
            .map_err(|e| e.to_string())?;
        if !compiled.status.success() {
            return Err(format!(
                "helper needs a JDK exposing java.lang.classfile (JDK 24+): {}",
                String::from_utf8_lossy(&compiled.stderr)
            ));
        }
        Ok(Self { java, scratch })
    }

    pub fn dir(&self) -> &Path {
        self.scratch.path()
    }

    pub fn write_jar(&self, label: &str, jar: &[u8]) -> PathBuf {
        let path: PathBuf = self.dir().join(format!("{label}.jar"));
        std::fs::write(&path, jar).expect("write jar for the jvm verifier");
        path
    }

    pub fn run(&self, scope: VerifyScope, jar: &Path) -> String {
        let mut cmd: Command = Command::new(&self.java);
        cmd.arg("-Xverify:all").arg("-cp").arg(self.dir()).arg("V");
        match scope {
            VerifyScope::Classes { permille } => {
                cmd.arg("classes").arg(permille.to_string()).arg(jar);
            }
            VerifyScope::Bodies { permille } => {
                cmd.arg("bodies").arg(permille.to_string()).arg(jar);
            }
        }
        let run: Output = cmd.output().expect("run the jvm bytecode verifier");
        let stdout: String = String::from_utf8_lossy(&run.stdout).into_owned();
        assert!(
            run.status.success(),
            "jvm verifier helper crashed: {}\n{stdout}",
            String::from_utf8_lossy(&run.stderr)
        );
        stdout
    }
}

pub fn lines_with_prefix(stdout: &str, prefix: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l: &&str| l.starts_with(prefix))
        .map(|l: &str| l.to_string())
        .collect()
}
