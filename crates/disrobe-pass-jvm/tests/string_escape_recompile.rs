#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::escape_java_string;

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

fn trap_battery() -> Vec<String> {
    vec![
        "hello world".to_string(),
        String::new(),
        "\u{0000}\u{0001}\u{0007}\u{0008}\u{0009}\u{000B}\u{000C}\u{001B}\u{001F}\u{007F}"
            .to_string(),
        "line1\nline2".to_string(),
        "carriage\rreturn".to_string(),
        "crlf\r\n end".to_string(),
        "quote\"and'apos".to_string(),
        "back\\slash".to_string(),
        "lit\\u000Aunit".to_string(),
        "\\u0041".to_string(),
        "accent\u{00E9}euro\u{20AC}cjk\u{4E2D}nbsp\u{00A0}".to_string(),
        "sep\u{2028}para\u{2029}end".to_string(),
        "emoji\u{1F600}math\u{1D54F}".to_string(),
        "mixed\ttab\u{2028}\u{1F680}\"q\\b\u{0007}end".to_string(),
    ]
}

fn expected_line(value: &str) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    let mut line: String = units.len().to_string();
    for u in &units {
        let _ = write!(line, ":{u}");
    }
    line
}

fn emit_source(inputs: &[String]) -> String {
    let mut lits: Vec<String> = Vec::with_capacity(inputs.len());
    for s in inputs {
        lits.push(escape_java_string(s));
    }
    let array_body: String = lits.join(",\n        ");
    let mut src: String = String::new();
    src.push_str("public class EscRoundTrip {\n");
    src.push_str("    static final String[] V = {\n        ");
    src.push_str(&array_body);
    src.push_str("\n    };\n");
    src.push_str("    public static void main(String[] args) {\n");
    src.push_str("        StringBuilder sb = new StringBuilder();\n");
    src.push_str("        for (int k = 0; k < V.length; k++) {\n");
    src.push_str("            String s = V[k];\n");
    src.push_str("            sb.append(s.length());\n");
    src.push_str("            for (int i = 0; i < s.length(); i++) {\n");
    src.push_str("                sb.append(':').append((int) s.charAt(i));\n");
    src.push_str("            }\n");
    src.push_str("            sb.append('\\n');\n");
    src.push_str("        }\n");
    src.push_str("        System.out.print(sb.toString());\n");
    src.push_str("    }\n");
    src.push_str("}\n");
    src
}

#[test]
fn escaped_string_literals_recompile_and_round_trip_under_real_jvm() {
    let Some(javac_path): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "SKIP: javac not on PATH; Java-source string escaping recompile round-trip NOT \
             enforced."
        );
        return;
    };
    let Some(java_path): Option<PathBuf> = find_on_path("java") else {
        eprintln!(
            "SKIP: java not on PATH; Java-source string escaping recompile round-trip NOT enforced."
        );
        return;
    };

    let inputs: Vec<String> = trap_battery();
    let source: String = emit_source(&inputs);

    let root: PathBuf =
        std::env::temp_dir().join(format!("disrobe_str_escape_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("mkdir root");
    let src_path: PathBuf = root.join("EscRoundTrip.java");
    std::fs::write(&src_path, source.as_bytes()).expect("write source");

    let compile: std::process::Output = Command::new(&javac_path)
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(&root)
        .arg(&src_path)
        .output()
        .expect("run javac");
    assert!(
        compile.status.success(),
        "escaped literals did not compile under real javac: {}\nsource:\n{source}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run: std::process::Output = Command::new(&java_path)
        .arg("-cp")
        .arg(&root)
        .arg("EscRoundTrip")
        .output()
        .expect("run java");
    assert!(
        run.status.success(),
        "EscRoundTrip did not run: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let stdout: String = String::from_utf8(run.stdout).expect("stdout utf8");
    let actual: Vec<&str> = stdout
        .split('\n')
        .map(|l: &str| l.trim_end_matches('\r'))
        .filter(|l: &&str| !l.is_empty())
        .collect();
    assert_eq!(
        actual.len(),
        inputs.len(),
        "line count mismatch; jvm printed {} lines for {} inputs\nstdout:\n{stdout}",
        actual.len(),
        inputs.len()
    );

    for (idx, value) in inputs.iter().enumerate() {
        let want: String = expected_line(value);
        assert_eq!(
            actual[idx],
            want,
            "string #{idx} did not round-trip through real javac/java; \
             the recovered constant would recompile to a different value.\n\
             input bytes: {:?}\nemitted literal: {}\nexpected units: {want}\nactual units: {}",
            value.as_bytes(),
            escape_java_string(value),
            actual[idx]
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}
