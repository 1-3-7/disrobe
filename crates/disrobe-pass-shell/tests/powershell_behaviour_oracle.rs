#![cfg(windows)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use disrobe_pass_shell::chain_detector::{ShellRefusal, recover_detected};
use disrobe_pass_shell::{Detection, detect};

const PROGRAMS: [(&str, &str); 7] = [
    (
        "format_reorder",
        "$a = ('{2}{0}{1}' -f 'ell','o','H')\nWrite-Output $a\nWrite-Output ('{1}-{0}' -f 'two','one')\n",
    ),
    (
        "char_casts_and_concatenation",
        "$w = [char]87 + [char]0x6F + 'rld'\nWrite-Output ('Hello, ' + $w)\n",
    ),
    (
        "backticks_and_case",
        "wR`I`TE-oU`TpUt 'ticks'\nWr`i`te-Out`put ('ca' + 'se')\nWrite-Output \"t`tab\"\nW`rite-Output 'escape'\n",
    ),
    (
        "reversal_and_join",
        "$r = -join ('desrever'[-1..-8])\nWrite-Output $r\nWrite-Output (-join [char[]](72,105))\n",
    ),
    (
        "replace_and_split",
        "Write-Output ('aXbXc' -replace 'X','-')\nWrite-Output (('p,q,r' -split ',') -join '+')\n",
    ),
    (
        "invoke_expression_of_a_literal",
        "Invoke-Expression ('Write-Output ' + \"'from iex'\")\n& ('Write-' + 'Output') 'from call'\n",
    ),
    (
        "call_operator_and_format",
        "& ('Wr' + 'ite-Output') ('{0} and {1}' -f (6 * 7), 40)\n",
    ),
];

const REFUSED: [(&str, &str, &str); 1] = [(
    "subexpressions_in_strings",
    "Write-Output \"Wr$('ite')-$('x' + 'y')\"\n",
    "DR-SHELL-0928",
)];

fn run_powershell(dir: &Path, name: &str, script: &str) -> String {
    let path: PathBuf = dir.join(format!("{name}.ps1"));
    std::fs::write(&path, script).expect("write the script");
    let output: std::process::Output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&path)
        .current_dir(dir)
        .output()
        .expect("Windows PowerShell runs the authored script");
    assert!(
        output.status.success(),
        "{name}: powershell failed: {output:?}"
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

fn recover(program: &str) -> Result<String, ShellRefusal> {
    let detection: Detection = detect(program.as_bytes());
    recover_detected(&detection, program.as_bytes())
}

#[test]
fn deobfuscated_powershell_programs_print_what_the_originals_print() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_ps_behaviour").expect("scratch");
    let dir: &Path = scratch.path();
    let mut failures: Vec<String> = Vec::new();
    for (name, program) in PROGRAMS {
        let expected: String = run_powershell(dir, &format!("{name}.orig"), program);
        assert!(
            !expected.trim().is_empty(),
            "{name}: the original prints something"
        );
        match recover(program) {
            Ok(recovered) => {
                let actual: String = run_powershell(dir, &format!("{name}.dec"), &recovered);
                if actual != expected {
                    failures.push(format!(
                        "{name}\n--- expected ---\n{expected}--- actual ---\n{actual}--- recovered ---\n{recovered}"
                    ));
                }
            }
            Err(refusal) => failures.push(format!("{name}: refused: {}", refusal.into_error())),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n=====\n"));
}

#[test]
fn a_recovery_that_changes_one_character_is_caught() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_ps_behaviour_mutation")
            .expect("scratch");
    let dir: &Path = scratch.path();
    let (name, program): (&str, &str) = PROGRAMS[0];
    let expected: String = run_powershell(dir, &format!("{name}.orig"), program);
    let recovered: String = recover(program).expect("the first program recovers");
    let mutated: String = recovered
        .replacen("Hello", "Hellp", 1)
        .replacen("'H'", "'J'", 1);
    assert_ne!(mutated, recovered, "the mutation must change the recovery");
    assert_ne!(
        run_powershell(dir, &format!("{name}.mut"), &mutated),
        expected
    );
}

#[test]
fn shapes_the_detector_does_not_claim_are_refused_by_name() {
    for (name, program, code) in REFUSED {
        match recover(program) {
            Ok(recovered) => panic!("{name}: now recovered, move it to PROGRAMS:\n{recovered}"),
            Err(refusal) => {
                let message: String = refusal.into_error().to_string();
                assert!(message.contains(code), "{name}: {message}");
            }
        }
    }
}
