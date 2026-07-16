#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

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

const SOURCE: &str = "public class NanConst {\n\
    public static void main(String[] args) {\n\
    \tSystem.out.println(Float.floatToRawIntBits(Float.intBitsToFloat(0x7f800001)) & 0xFFFFFFFFL);\n\
    \tSystem.out.println(Float.floatToRawIntBits(Float.NaN) & 0xFFFFFFFFL);\n\
    \tSystem.out.println(Long.toUnsignedString(Double.doubleToRawLongBits(Double.longBitsToDouble(0xfff8000000000001L))));\n\
    \tSystem.out.println(Long.toUnsignedString(Double.doubleToRawLongBits(Double.NaN)));\n\
    }\n\
}\n";

#[test]
fn noncanonical_nan_literal_round_trips_while_named_constant_does_not() {
    let Some(javac_path): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "SKIP: javac not on PATH; non-canonical NaN constant recompile fidelity NOT enforced."
        );
        return;
    };
    let Some(java_path): Option<PathBuf> = find_on_path("java") else {
        eprintln!(
            "SKIP: java not on PATH; non-canonical NaN constant recompile fidelity NOT enforced."
        );
        return;
    };

    let root: PathBuf =
        std::env::temp_dir().join(format!("disrobe_nan_const_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("mkdir root");
    let src_path: PathBuf = root.join("NanConst.java");
    std::fs::write(&src_path, SOURCE.as_bytes()).expect("write source");

    let compile: std::process::Output = Command::new(&javac_path)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(&root)
        .arg(&src_path)
        .output()
        .expect("run javac");
    assert!(
        compile.status.success(),
        "NaN reconstruction expression did not compile under real javac: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run: std::process::Output = Command::new(&java_path)
        .arg("-cp")
        .arg(&root)
        .arg("NanConst")
        .output()
        .expect("run java");
    assert!(
        run.status.success(),
        "NanConst did not run: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let stdout: String = String::from_utf8(run.stdout).expect("stdout utf8");
    let lines: Vec<&str> = stdout
        .split('\n')
        .map(|l: &str| l.trim_end_matches('\r'))
        .filter(|l: &&str| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 4, "unexpected output:\n{stdout}");

    assert_eq!(
        lines[0], "2139095041",
        "Float.intBitsToFloat(0x7f800001) must recompile to the exact original raw bits"
    );
    assert_eq!(
        lines[1], "2143289344",
        "Float.NaN recompiles to the canonical raw bits, distinct from the planted constant"
    );
    assert_ne!(
        lines[0], lines[1],
        "emitting Float.NaN for a non-canonical NaN constant changes the observable value"
    );

    assert_eq!(
        lines[2], "18444492273895866369",
        "Double.longBitsToDouble(0xfff8000000000001L) must recompile to the exact original raw bits"
    );
    assert_eq!(
        lines[3], "9221120237041090560",
        "Double.NaN recompiles to the canonical raw bits, distinct from the planted constant"
    );
    assert_ne!(
        lines[2], lines[3],
        "emitting Double.NaN for a non-canonical NaN constant changes the observable value"
    );

    let _ = std::fs::remove_dir_all(&root);
}
