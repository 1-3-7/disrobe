#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::analyze_bytes;
use ruby_toolchain::require_mri_measured_series;

fn compile_to_yarb(source: &str, tag: &str) -> Option<Vec<u8>> {
    let script_purpose: String = format!("disrobe_la_gen_{tag}");
    let (script_scratch, script_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&script_purpose, "rb").ok()?;
    drop(script_file);
    let script_path: PathBuf = script_scratch.path().to_path_buf();
    let out_purpose: String = format!("disrobe_la_{tag}");
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
    let analysis = analyze_bytes(&bytes, tag).ok()?;
    let yarv = analysis.yarv?;
    Some(yarv.decompiled.source)
}

fn code_only(src: &str) -> String {
    src.lines()
        .take_while(|l| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn recompile_pct(original: &str, recovered_code: &str, tag: &str) -> Option<u32> {
    let orig_purpose: String = format!("disrobe_la_orig_{tag}");
    let (orig_scratch, orig_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&orig_purpose, "rb").ok()?;
    drop(orig_file);
    let orig_path: PathBuf = orig_scratch.path().to_path_buf();
    let rec_purpose: String = format!("disrobe_la_rec_{tag}");
    let (rec_scratch, rec_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&rec_purpose, "rb").ok()?;
    drop(rec_file);
    let rec_path: PathBuf = rec_scratch.path().to_path_buf();
    std::fs::write(&orig_path, original).ok()?;
    std::fs::write(&rec_path, recovered_code).ok()?;

    let script: &str = concat!(
        "def ops(i); o=[]; w=->(x){x.disasm.each_line{|l| o<<$1 if l=~/^\\d{4} (\\S+)/}; ",
        "x.each_child{|c| w.call(c)}}; w.call(i); o; end\n",
        "def mm(a,b); ha=Hash.new(0); a.each{|x| ha[x]+=1}; hb=Hash.new(0); b.each{|x| hb[x]+=1}; ",
        "n=0; ha.each{|k,v| n+=[v,hb[k]].min}; n; end\n",
        "w=ops(RubyVM::InstructionSequence.compile(File.read(ARGV[0])))\n",
        "h=ops(RubyVM::InstructionSequence.compile(File.read(ARGV[1])))\n",
        "puts(w.empty? ? 0 : (100*mm(w,h)/w.size))\n"
    );
    let script_purpose: String = format!("disrobe_la_oracle_{tag}");
    let (script_scratch, script_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&script_purpose, "rb").ok()?;
    drop(script_file);
    let script_path: PathBuf = script_scratch.path().to_path_buf();
    std::fs::write(&script_path, script).ok()?;

    let output = Command::new("ruby")
        .arg(&script_path)
        .arg(&orig_path)
        .arg(&rec_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()
}

fn assert_recovers(source: &str, tag: &str, needle: &str, min_pct: u32) {
    if require_mri_measured_series(&format!("the {tag} loop-assignment recovery")).is_none() {
        return;
    }
    let src: String = recover(source, tag).unwrap_or_else(|| {
        panic!(
            "ruby is usable here but could not compile the {tag} source into a yarv image, so this \
             case compared nothing; an interpreter that is present and then fails to build the \
             input is a defect, never a skip"
        )
    });
    let code: String = code_only(&src);
    assert!(
        code.contains(needle),
        "[{tag}] expected `{needle}` in recovered code:\n{code}"
    );
    let pct: u32 = recompile_pct(source, &code, tag)
        .unwrap_or_else(|| panic!("[{tag}] oracle did not produce a rate for:\n{code}"));
    assert!(
        pct >= min_pct,
        "[{tag}] recompile-equivalence {pct}% below floor {min_pct}% for:\n{code}"
    );
}

#[test]
fn until_pre_tested_loop_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(n)\n  i = 0\n  until i >= n\n    i += 1\n  end\n  i\nend\n",
        "until_pre",
        "until i >= n",
        95,
    );
}

#[test]
fn begin_while_post_tested_loop_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(n)\n  i = 0\n  begin\n    i += 1\n  end while i < n\n  i\nend\n",
        "begin_while",
        "end while i < n",
        95,
    );
}

#[test]
fn begin_until_post_tested_loop_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(n)\n  i = 0\n  begin\n    i += 1\n  end until i >= n\n  i\nend\n",
        "begin_until",
        "end until i >= n",
        95,
    );
}

#[test]
fn while_modifier_loop_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(arr)\n  arr.pop while arr.size > 2\n  arr\nend\n",
        "while_mod",
        "while",
        95,
    );
}

#[test]
fn aref_or_assign_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(h)\n  h[:cache] ||= {}\n  h\nend\n",
        "aref_oreq",
        "] ||= {}",
        85,
    );
}

#[test]
fn aref_and_assign_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(a, i)\n  a[i] &&= 7\n  a\nend\n",
        "aref_andeq",
        "&&= 7",
        85,
    );
}

#[test]
fn nested_aref_or_assign_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(t, on, from, to)\n  (t[on] ||= {})[from] = to\n  t\nend\n",
        "nested_oreq",
        "||= {})[from] = to",
        90,
    );
}

#[test]
fn retry_in_rescue_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(max)\n  tries = 0\n  begin\n    tries += 1\n    raise 'boom'\n  rescue StandardError\n    retry if tries < max\n    :gave_up\n  end\nend\n",
        "retry",
        "retry",
        90,
    );
}

#[test]
fn value_break_in_block_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(arr)\n  arr.each do |x|\n    break x * 2 if x > 9\n    x\n  end\nend\n",
        "break_value",
        "break x * 2",
        90,
    );
}

#[test]
fn explicit_return_in_block_reconstructs_from_real_yarv() {
    assert_recovers(
        "def f(arr)\n  arr.each do |x|\n    return x if x > 9\n  end\n  nil\nend\n",
        "return_blk",
        "return",
        78,
    );
}
