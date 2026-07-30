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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyScope {
    Classes,
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
            VerifyScope::Classes => {
                cmd.arg("classes").arg(jar);
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
