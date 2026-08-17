#![allow(
    dead_code,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;

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
    pub short: &'static str,
    pub golden: &'static str,
    pub method_total: usize,
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
        short: "transmissionic",
        golden: "transmissionic-ionic.txt",
        method_total: 27_805,
        self_reported_bodies_pinned: 26_224,
        candidate_bodies_pinned: 26_224,
        sampled_bodies_pinned: 2_677,
        presented_bodies: 990,
        attested_clean_pinned: 987,
        attested_rejected_pinned: 3,
    },
    RealApk {
        file: "rustdesk-flutter.apk",
        short: "rustdesk",
        golden: "rustdesk-flutter.txt",
        method_total: 32_410,
        self_reported_bodies_pinned: 29_423,
        candidate_bodies_pinned: 29_392,
        sampled_bodies_pinned: 2_856,
        presented_bodies: 1218,
        attested_clean_pinned: 1211,
        attested_rejected_pinned: 7,
    },
    RealApk {
        file: "enrecipes-nativescript.apk",
        short: "enrecipes",
        golden: "enrecipes-nativescript.txt",
        method_total: 29_301,
        self_reported_bodies_pinned: 27_276,
        candidate_bodies_pinned: 27_275,
        sampled_bodies_pinned: 2_824,
        presented_bodies: 782,
        attested_clean_pinned: 778,
        attested_rejected_pinned: 4,
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

pub fn real_apks_absent() -> Vec<&'static str> {
    REAL_APKS
        .iter()
        .filter(|apk: &&RealApk| !real_apk_path(apk.file).is_file())
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
