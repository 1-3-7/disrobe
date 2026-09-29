#![cfg(windows)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use disrobe_pass_shell::batch::engine::{BatchDeobReport, deobfuscate_batch};

const PROGRAMS: [(&str, &str); 9] = [
    (
        "substring_index",
        "@echo off\r\nset \"x=abcdefghijklmnopqrstuvwxyz\"\r\necho %x:~7,1%%x:~4,1%%x:~11,1%%x:~11,1%%x:~14,1%\r\n",
    ),
    ("caret_escapes", "@echo off\r\ne^c^h^o h^i t^h^ere\r\n"),
    (
        "arithmetic",
        "@echo off\r\nset /a n=3*4+2\r\nset /a m=n %% 5\r\necho %n% %m%\r\n",
    ),
    (
        "substitution",
        "@echo off\r\nset \"s=hXllo wXrld\"\r\necho %s:X=e%\r\necho %s:X=o%\r\n",
    ),
    (
        "command_in_variable",
        "@echo off\r\nset \"p=ec\"\r\nset \"q=ho\"\r\n%p%%q% built from parts\r\n",
    ),
    (
        "delayed_expansion",
        "@echo off\r\nsetlocal enabledelayedexpansion\r\nset v=1\r\nfor /l %%i in (1,1,3) do set /a v+=%%i\r\necho !v!\r\n",
    ),
    (
        "for_tokens",
        "@echo off\r\nfor /f \"tokens=2 delims=,\" %%a in (\"x,yes,z\") do echo %%a\r\n",
    ),
    (
        "computed_branch",
        "@echo off\r\nset /a k=7*6\r\nif %k%==42 (echo answer) else (echo other)\r\nif not %k%==42 echo never\r\n",
    ),
    (
        "negative_substring",
        "@echo off\r\nset \"w=obfuscated\"\r\necho %w:~-5% %w:~0,-5% %w:~2%\r\n",
    ),
];

fn run_cmd(dir: &Path, name: &str, script: &str) -> String {
    let path: PathBuf = dir.join(format!("{name}.bat"));
    std::fs::write(&path, script).expect("write the batch script");
    let output: std::process::Output = std::process::Command::new("cmd")
        .args(["/d", "/c"])
        .arg(&path)
        .current_dir(dir)
        .output()
        .expect("cmd runs the authored script");
    assert!(output.status.success(), "{name}: cmd failed: {output:?}");
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

fn to_crlf(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

#[test]
fn deobfuscated_batch_programs_print_what_the_originals_print() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_batch_behaviour").expect("scratch");
    let dir: &Path = scratch.path();
    let mut failures: Vec<String> = Vec::new();
    for (name, program) in PROGRAMS {
        let expected: String = run_cmd(dir, &format!("{name}.orig"), program);
        assert!(
            !expected.trim().is_empty(),
            "{name}: the original prints something"
        );
        let report: BatchDeobReport = deobfuscate_batch(program, &[]);
        let recovered: String = to_crlf(&report.output);
        let actual: String = run_cmd(dir, &format!("{name}.dec"), &recovered);
        if actual != expected {
            failures.push(format!(
                "{name}\n--- expected ---\n{expected}--- actual ---\n{actual}--- recovered ---\n{}",
                report.output
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n=====\n"));
}

#[test]
fn a_recovery_that_changes_one_character_is_caught() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_batch_behaviour_mutation")
            .expect("scratch");
    let dir: &Path = scratch.path();
    let (name, program): (&str, &str) = PROGRAMS[0];
    let expected: String = run_cmd(dir, &format!("{name}.orig"), program);
    let report: BatchDeobReport = deobfuscate_batch(program, &[]);
    let mutated: String = to_crlf(&report.output)
        .replacen("x:~7,1", "x:~8,1", 1)
        .replacen("hello", "hellp", 1);
    assert_ne!(
        mutated,
        to_crlf(&report.output),
        "the mutation must change the recovery"
    );
    assert_ne!(run_cmd(dir, &format!("{name}.mut"), &mutated), expected);
}
