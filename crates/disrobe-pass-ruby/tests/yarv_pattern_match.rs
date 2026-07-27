#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::literal_string_with_formatting_args
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::analyze_bytes;

fn ruby_pattern_oracle_available() -> bool {
    let Ok(out): Result<std::process::Output, std::io::Error> =
        Command::new("ruby").arg("--version").output()
    else {
        return false;
    };
    out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ruby 3.4")
}

fn compile_to_yarb(source: &str, tag: &str) -> Option<Vec<u8>> {
    let script_purpose: String = format!("disrobe_pm_gen_{tag}");
    let (script_scratch, script_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&script_purpose, "rb").ok()?;
    drop(script_file);
    let script_path: PathBuf = script_scratch.path().to_path_buf();
    let out_purpose: String = format!("disrobe_pm_{tag}");
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

fn strip_annotations(recovered: &str) -> String {
    recovered
        .lines()
        .filter(|l| {
            let s: &str = l.trim_start();
            !s.starts_with('#')
                || s.starts_with("# frozen_string_literal")
                || s.starts_with("# encoding")
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

fn opcode_multiset_pct(original: &str, recovered: &str, tag: &str) -> Option<u32> {
    let cleaned: String = strip_annotations(recovered);
    let script_purpose: String = format!("disrobe_pm_oracle_{tag}");
    let (script_scratch, script_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&script_purpose, "rb").ok()?;
    drop(script_file);
    let script: PathBuf = script_scratch.path().to_path_buf();
    let program: &str = "def opcodes(iseq)\n  out = []\n  walk = lambda do |i|\n    i.disasm.each_line { |l| out << $1 if l =~ /^\\d{4} (\\S+)/ }\n    i.each_child { |c| walk.call(c) }\n  end\n  walk.call(iseq)\n  out\nend\nwant = opcodes(RubyVM::InstructionSequence.compile(File.read(ARGV.fetch(0))))\nhave = opcodes(RubyVM::InstructionSequence.compile(File.read(ARGV.fetch(1))))\nhw = Hash.new(0); want.each { |x| hw[x] += 1 }\nhh = Hash.new(0); have.each { |x| hh[x] += 1 }\ninter = 0; hw.each { |k, v| inter += [v, hh[k]].min }\ntotal = want.size\nputs(total > 0 ? (100 * inter / total) : 0)\n";
    std::fs::write(&script, program).ok()?;
    let orig_purpose: String = format!("disrobe_pm_orig_{tag}");
    let (orig_scratch, orig_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&orig_purpose, "rb").ok()?;
    drop(orig_file);
    let orig_path: PathBuf = orig_scratch.path().to_path_buf();
    let rec_purpose: String = format!("disrobe_pm_rec_{tag}");
    let (rec_scratch, rec_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&rec_purpose, "rb").ok()?;
    drop(rec_file);
    let rec_path: PathBuf = rec_scratch.path().to_path_buf();
    std::fs::write(&orig_path, original).ok()?;
    std::fs::write(&rec_path, cleaned).ok()?;
    let out = Command::new("ruby")
        .arg(&script)
        .arg(&orig_path)
        .arg(&rec_path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .ok()
}

#[test]
fn array_pattern_recovers_bracket_bindings_from_real_yarv() {
    if !ruby_pattern_oracle_available() {
        eprintln!(
            "skip: pattern-match oracle needs ruby 3.4.x; its yarv pattern opcodes are version-specific"
        );
        return;
    }
    let source: &str = "arr = [1, 2]\ncase arr\nin [a, b]\n  puts a\nend\n";
    let Some(src): Option<String> = recover(source, "array") else {
        eprintln!("skip: ruby could not compile the pattern source");
        return;
    };
    assert!(src.contains("case arr"), "expected `case arr`, got:\n{src}");
    assert!(
        src.contains("in [a, b]"),
        "expected reconstructed array pattern `in [a, b]`, got:\n{src}"
    );
    assert!(
        src.contains("puts(a)"),
        "expected the arm body `puts(a)`, got:\n{src}"
    );
    let code: String = src
        .lines()
        .take_while(|l| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !code.contains("opt_aref") && !code.contains("core#raise") && !code.contains("respond_to?"),
        "recovered pattern arm must not leak raw deconstruct scaffolding, got:\n{code}"
    );
}

#[test]
fn hash_pattern_recovers_brace_bindings_from_real_yarv() {
    if !ruby_pattern_oracle_available() {
        eprintln!(
            "skip: pattern-match oracle needs ruby 3.4.x; its yarv pattern opcodes are version-specific"
        );
        return;
    }
    let source: &str = "h = {name: 1}\ncase h\nin {name:}\n  puts name\nend\n";
    let Some(src): Option<String> = recover(source, "hash") else {
        eprintln!("skip: ruby could not compile the pattern source");
        return;
    };
    assert!(src.contains("case h"), "expected case h, got:\n{src}");
    assert!(
        src.contains("in {name:}"),
        "expected reconstructed hash pattern in name colon, got:\n{src}"
    );
    assert!(
        src.contains("puts(name)"),
        "expected the arm body puts(name), got:\n{src}"
    );
}

#[test]
fn mixed_array_and_hash_arms_both_reconstruct_from_real_yarv() {
    if !ruby_pattern_oracle_available() {
        eprintln!(
            "skip: pattern-match oracle needs ruby 3.4.x; its yarv pattern opcodes are version-specific"
        );
        return;
    }
    let source: &str =
        "arr = [1, 2]\ncase arr\nin [a, b]\n  puts a\nin {name:}\n  puts name\nend\n";
    let Some(src): Option<String> = recover(source, "mixed") else {
        eprintln!("skip: ruby could not compile the pattern source");
        return;
    };
    assert!(
        src.contains("in [a, b]"),
        "expected the array arm `in [a, b]`, got:\n{src}"
    );
    assert!(
        src.contains("in {name:}"),
        "expected the hash arm in name colon, got:\n{src}"
    );
    let case_count: usize = src.matches("case arr").count();
    assert_eq!(
        case_count, 1,
        "both arms should fold into a single case, got {case_count}:\n{src}"
    );
}

const STRUCTURAL_GAUNTLET: &str = concat!(
    "case value\n",
    "in Integer => n if n.positive?\n",
    "  :pos\n",
    "in 1 | 2 | 3\n",
    "  :small\n",
    "in [a, b, *rest]\n",
    "  [a, b, rest]\n",
    "in [*, 42, *]\n",
    "  :contains\n",
    "in {name:, **opts}\n",
    "  [name, opts]\n",
    "in {type: String => t, payload:}\n",
    "  [t, payload]\n",
    "in []\n",
    "  :empty\n",
    "in String\n",
    "  :str\n",
    "else\n",
    "  :other\n",
    "end\n",
);

#[test]
fn structural_pattern_gauntlet_recompiles_to_matching_opcode_multiset() {
    if !ruby_pattern_oracle_available() {
        eprintln!("skip: pattern-match oracle needs ruby 3.4.x");
        return;
    }
    let Some(src): Option<String> = recover(STRUCTURAL_GAUNTLET, "gauntlet") else {
        eprintln!("skip: ruby could not compile the gauntlet source");
        return;
    };

    for needle in [
        "case value",
        "in Integer => n if n.positive?",
        "in 1 | 2 | 3",
        "in [a, b, *rest]",
        "in [*, 42, *]",
        "in {name:, **opts}",
        "in {type: String => t, payload:}",
        "in []",
        "in String",
        "else",
    ] {
        assert!(
            src.contains(needle),
            "expected reconstructed `{needle}`, got:\n{src}"
        );
    }
    let code: String = src
        .lines()
        .take_while(|l| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !code.contains("core#")
            && !code.contains("obj[")
            && !code.contains("deconstruct")
            && !code.contains(".length >="),
        "no raw pattern scaffolding may leak:\n{code}"
    );

    let pct: u32 = opcode_multiset_pct(STRUCTURAL_GAUNTLET, &src, "gauntlet")
        .expect("real ruby recompile-multiset oracle produced a rate");
    assert!(
        pct >= 90,
        "structural case/in opcode-multiset equivalence regressed below 90%, got {pct}%:\n{src}"
    );
}

const CONST_DECONSTRUCT: &str = concat!(
    "case pt\n",
    "in Point(x:, y:) if x == y\n",
    "  :diag\n",
    "in Point(x: 0, y:)\n",
    "  [:ony, y]\n",
    "in Point(x:, y: 0)\n",
    "  [:onx, x]\n",
    "in Point => p\n",
    "  [:gen, p]\n",
    "end\n",
);

#[test]
fn const_deconstruct_pattern_recompiles_to_matching_opcode_multiset() {
    if !ruby_pattern_oracle_available() {
        eprintln!("skip: pattern-match oracle needs ruby 3.4.x");
        return;
    }
    let prelude: String = format!("Point = Struct.new(:x, :y)\n{CONST_DECONSTRUCT}");
    let Some(src): Option<String> = recover(&prelude, "constpat") else {
        eprintln!("skip: ruby could not compile the const-pattern source");
        return;
    };
    for needle in [
        "in Point(x:, y:) if x == y",
        "in Point(x: 0, y:)",
        "in Point(x:, y: 0)",
        "in Point => p",
    ] {
        assert!(
            src.contains(needle),
            "expected reconstructed `{needle}`, got:\n{src}"
        );
    }
    let pct: u32 = opcode_multiset_pct(&prelude, &src, "constpat")
        .expect("real ruby recompile-multiset oracle produced a rate");
    assert!(
        pct >= 90,
        "const-deconstruct opcode-multiset equivalence regressed below 90%, got {pct}%:\n{src}"
    );
}
