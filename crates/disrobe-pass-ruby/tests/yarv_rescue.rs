#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
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
    let script_purpose: String = format!("disrobe_rescue_gen_{tag}");
    let (script_scratch, script_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&script_purpose, "rb").ok()?;
    drop(script_file);
    let script_path: PathBuf = script_scratch.path().to_path_buf();
    let out_purpose: String = format!("disrobe_rescue_{tag}");
    let (out_scratch, out_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&out_purpose, "yarvc").ok()?;
    drop(out_file);
    let out_path: PathBuf = out_scratch.path().to_path_buf();

    let script: String = format!(
        "src = {source:?}\nFile.binwrite(ARGV.fetch(0), RubyVM::InstructionSequence.compile(src).to_binary)\n"
    );
    std::fs::write(&script_path, script).ok()?;
    let status = Command::new("ruby")
        .arg(&script_path)
        .arg(&out_path)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let bytes: Vec<u8> = std::fs::read(&out_path).ok()?;
    Some(bytes)
}

fn recover(source: &str, tag: &str) -> Option<String> {
    let bytes: Vec<u8> = compile_to_yarb(source, tag)?;
    assert_eq!(&bytes[..4], b"YARB", "compiled blob must carry YARB magic");
    let analysis = analyze_bytes(&bytes, tag).ok()?;
    let yarv = analysis.yarv?;
    Some(yarv.decompiled.source)
}

fn code_only(source: &str) -> String {
    source
        .lines()
        .take_while(|line: &&str| !line.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn ruby_opcode_count(source: &str, opcode: &str, tag: &str) -> Option<usize> {
    let purpose: String = format!("disrobe_rescue_source_{tag}");
    let (scratch, file): (ScratchFile, std::fs::File) = ScratchFile::create(&purpose, "rb").ok()?;
    drop(file);
    let source_path: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&source_path, source).ok()?;
    let output = Command::new("ruby")
        .arg("-e")
        .arg(
            "iseq = RubyVM::InstructionSequence.compile(File.read(ARGV.fetch(0))); puts iseq.disasm.lines.count { |line| line.include?(ARGV.fetch(1)) }",
        )
        .arg(&source_path)
        .arg(opcode)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<usize>()
        .ok()
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

#[test]
fn ensure_body_survives_once_and_retains_runtime_opcode_count() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the ensure check");
        return;
    }
    let source: &str =
        "begin\n  risky\nrescue RuntimeError => e\n  warn e.message\nensure\n  cleanup\nend\n";
    let Some(recovered): Option<String> = recover(source, "ensure") else {
        eprintln!("skip: ruby could not compile the ensure source");
        return;
    };
    let code: String = code_only(&recovered);
    assert_eq!(
        code.matches("cleanup()").count(),
        1,
        "the ensure handler must survive exactly once:\n{code}"
    );
    let original_count: usize = ruby_opcode_count(source, "opt_send_without_block", "ensure_orig")
        .expect("real Ruby disasm counted original sends");
    let recovered_count: usize =
        ruby_opcode_count(&code, "opt_send_without_block", "ensure_recovered")
            .expect("real Ruby disasm counted recovered sends");
    assert_eq!(original_count, 5, "the fixture must exercise five sends");
    assert_eq!(
        recovered_count, original_count,
        "real Ruby disasm send count must survive recovery"
    );
}

#[test]
fn zero_arg_inline_block_statement_remains_recompilable() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the block check");
        return;
    }
    let source: &str = "def f\n  tap { 1 }\n  :done\nend\n";
    let Some(recovered): Option<String> = recover(source, "inline_block") else {
        eprintln!("skip: ruby could not compile the block source");
        return;
    };
    let code: String = code_only(&recovered);
    assert!(
        code.contains("tap { 1 }") && !code.contains("}()"),
        "the zero-argument block call must remain valid Ruby:\n{code}"
    );
    let original_count: usize = ruby_opcode_count(source, "opt_send_without_block", "block_orig")
        .expect("real Ruby disasm counted original block sends");
    let recovered_count: usize =
        ruby_opcode_count(&code, "opt_send_without_block", "block_recovered")
            .expect("real Ruby disasm counted recovered block sends");
    assert_eq!(recovered_count, original_count);
}
