use std::time::Duration;

use disrobe_pass_shell::{
    render_bash_with_header, render_batch_with_header, render_powershell_with_header,
    render_vba_with_header,
};

#[test]
fn powershell_emits_two_line_ps_header() {
    let out: String =
        render_powershell_with_header("Write-Host x\n", Duration::from_millis(5), "5.1");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Deobfuscated in 5ms with Disrobe"));
    assert_eq!(lines[1], "# PowerShell 5.1");
}

#[test]
fn bash_emits_two_line_bash_header() {
    let out: String = render_bash_with_header("echo x\n", Duration::from_millis(15), "5.2");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Deobfuscated in 15ms with Disrobe"));
    assert_eq!(lines[1], "# Bash 5.2");
}

#[test]
fn batch_emits_two_line_batch_header() {
    let out: String = render_batch_with_header("@echo off\n", Duration::from_millis(3), "Win11");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Deobfuscated in 3ms with Disrobe"));
    assert_eq!(lines[1], "# Batch Win11");
}

#[test]
fn vba_emits_two_line_vba_header() {
    let out: String = render_vba_with_header("Sub X\nEnd Sub\n", Duration::from_millis(7), "7.1");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Deobfuscated in 7ms with Disrobe"));
    assert_eq!(lines[1], "# VBA 7.1");
}
