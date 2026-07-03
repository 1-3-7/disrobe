#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_ruby::analyze_bytes;

fn ruby_available() -> bool {
    let Ok(out): Result<std::process::Output, std::io::Error> =
        Command::new("ruby").arg("--version").output()
    else {
        return false;
    };
    out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ruby 3.4")
}

fn compile_to_yarb(source: &str, tag: &str) -> Option<Vec<u8>> {
    let mut script_path: PathBuf = std::env::temp_dir();
    script_path.push(format!("disrobe_rescue_gen_{tag}.rb"));
    let mut out_path: PathBuf = std::env::temp_dir();
    out_path.push(format!("disrobe_rescue_{tag}.yarvc"));

    let script: String = format!(
        "src = {source:?}\nFile.binwrite(ARGV.fetch(0), RubyVM::InstructionSequence.compile(src).to_binary)\n"
    );
    std::fs::write(&script_path, script).ok()?;
    let status = Command::new("ruby")
        .arg(&script_path)
        .arg(&out_path)
        .status()
        .ok()?;
    let _ = std::fs::remove_file(&script_path);
    if !status.success() {
        return None;
    }
    let bytes: Vec<u8> = std::fs::read(&out_path).ok()?;
    let _ = std::fs::remove_file(&out_path);
    Some(bytes)
}

fn recover(source: &str, tag: &str) -> Option<String> {
    let bytes: Vec<u8> = compile_to_yarb(source, tag)?;
    assert_eq!(&bytes[..4], b"YARB", "compiled blob must carry YARB magic");
    let analysis = analyze_bytes(&bytes, tag).ok()?;
    let yarv = analysis.yarv?;
    Some(yarv.decompiled.source)
}

#[test]
fn rescue_recovers_exception_class_and_bound_variable_from_real_yarv() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the rescue oracle");
        return;
    }
    let source: &str = "def risky(a, b)\n  begin\n    a / b\n  rescue ZeroDivisionError => e\n    puts e.message\n  rescue TypeError\n    puts \"type\"\n  end\nend\n";
    let Some(src): Option<String> = recover(source, "classvar") else {
        eprintln!("skip: ruby could not compile the rescue source");
        return;
    };
    assert!(
        src.contains("rescue ZeroDivisionError => e"),
        "expected the discriminated class plus bound variable, got:\n{src}"
    );
    assert!(
        src.contains("e.message"),
        "expected the rescue body to reference the bound `e`, not the raw `$!`, got:\n{src}"
    );
    assert!(
        src.contains("rescue TypeError"),
        "expected the second class-only clause, got:\n{src}"
    );
    let code: String = src
        .lines()
        .take_while(|l| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !code.contains("$!.message"),
        "the raw implicit exception global must not leak where a named var was bound:\n{code}"
    );
}

#[test]
fn rescue_multiple_classes_in_one_clause_from_real_yarv() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the rescue oracle");
        return;
    }
    let source: &str = "def h(x)\n  begin\n    Integer(x)\n  rescue ArgumentError, TypeError => e\n    puts e.message\n  end\nend\n";
    let Some(src): Option<String> = recover(source, "multiclass") else {
        eprintln!("skip: ruby could not compile the rescue source");
        return;
    };
    assert!(
        src.contains("rescue ArgumentError, TypeError => e"),
        "expected the short-circuit class list plus bound var recovered as one clause, got:\n{src}"
    );
    let code: String = src
        .lines()
        .take_while(|l| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !code.contains("unless ArgumentError") && !code.contains("$!"),
        "the branchif short-circuit chain must not degrade into an `unless` test or leak `$!`:\n{code}"
    );
}

#[test]
fn rescue_bare_class_without_binding_omits_arrow_from_real_yarv() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the rescue oracle");
        return;
    }
    let source: &str = "def f\n  begin\n    raise \"boom\"\n  rescue RuntimeError\n    puts \"caught\"\n  end\nend\n";
    let Some(src): Option<String> = recover(source, "bare") else {
        eprintln!("skip: ruby could not compile the rescue source");
        return;
    };
    assert!(
        src.contains("rescue RuntimeError"),
        "expected the recovered class, got:\n{src}"
    );
    let code: String = src
        .lines()
        .take_while(|l| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !code.contains("rescue RuntimeError =>"),
        "a class-only clause must not invent a bound variable:\n{code}"
    );
}
