#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::mruby::lift::{MrubyLowering, lowering};
use disrobe_pass_ruby::mruby::ops::{MrubyOpcode, opcode_count, opcode_spec};
use disrobe_pass_ruby::{
    IrepRecord, IrepTree, MrubyAnalysis, MrubyInstruction, RubyAnalysis, analyze_bytes,
    disassemble_iseq,
};
use ruby_toolchain::{
    MRBC, MRUBY_MEASURED_SERIES, ToolchainBanner, ToolchainRequirement, require_measured_series,
};

const GRADED: &str =
    "the mruby instruction-set coverage ledger graded against the installed mruby ops.h";

const INCLUDE_OVERRIDE: &str = "DISROBE_MRUBY_INCLUDE";

const VERSION_RENAMES: &[(&str, &str, &str)] = &[(
    "LOADI8",
    "LOADI",
    "mruby renamed opcode 3 from LOADI to LOADI8 in the 3.4.0 release without changing its number \
     or its BB operand shape; disrobe keeps the name the RITE0300 series was measured under",
)];

const DUMPER_ALIASES: &[(&str, &str, &str)] = &[(
    "ARRAY",
    "ARRAY2",
    "mruby's own instruction dumper prints OP_ARRAY2 under the OP_ARRAY name with a third operand \
     column; the two are separated by encoded length, three bytes against four",
)];

const WIDTH_PREFIXES: &[&str] = &["EXT1", "EXT2", "EXT3"];

const WIDE_LOCALS: u32 = 240;

const WIDE_SYMBOLS: u32 = 300;

const MEASURED_OPCODE_FLOOR: usize = 98;

const SNIPPETS: &[(&str, &str)] = &[
    (
        "load_small",
        "a = -1\nb = 0\nc = 7\nd = 200\ne = 30000\nf = 2000000\ng = -5\nputs a, b, c, d, e, f, g\n",
    ),
    (
        "load_kinds",
        "s = \"hi\"\nsym = :foo\nfl = 1.5\nt = true\nu = false\nv = nil\nputs s, sym, fl, t, u, \
         v.inspect\n",
    ),
    (
        "globals",
        "$g = 1\nputs $g\nObject::X = 2\nputs Object::X\nh = {a: 1}\nputs h[:a]\n",
    ),
    (
        "ivars",
        "class K\n  def set\n    @i = 1\n    @@c = 2\n  end\n  def get\n    [@i, @@c]\n  end\nend\nk \
         = K.new\nk.set\np k.get\n",
    ),
    (
        "consts",
        "X = 1\nmodule M\n  Y = 2\nend\nputs X\nputs M::Y\nM::Z = 3\nputs M::Z\n",
    ),
    ("upvar", "n = 0\n[1, 2].each { |i| n = n + i }\nputs n\n"),
    (
        "index",
        "h = {}\nh[:a] = 1\nputs h[:a]\nar = [0]\nar[0] = 9\nputs ar[0]\n",
    ),
    (
        "arith",
        "a = 1 + 2\nb = a - 1\nc = b * 3\nd = c / 2\ne = a + 100\nf = a - 100\ng = a - b\nputs a, \
         b, c, d, e, f, g\n",
    ),
    (
        "compare",
        "a = 1\nputs(a == 1)\nputs(a < 2)\nputs(a <= 2)\nputs(a > 0)\nputs(a >= 0)\n",
    ),
    (
        "arrays",
        "a = [1, 2]\nb = [*a, 3]\nc = a + b\nx, *y, z = b\na.push(4)\nputs b.inspect, c.inspect, \
         x, y.inspect, z\n",
    ),
    (
        "hashes",
        "h = {a: 1}\ng = {b: 2}\nm = {**h, **g}\nn = {**h, c: 3, d: 4}\nm[:c] = 3\np m, n\n",
    ),
    (
        "strings",
        "n = 1\ns = \"a#{n}b\"\nsym = :\"dyn#{n}\"\nputs s, sym\n",
    ),
    ("ranges", "a = (1..3).to_a\nb = (1...3).to_a\np a, b\n"),
    (
        "classdef",
        "class A\n  def m; 1; end\nend\nclass B < A\n  def m; super + 1; end\n  def n(*a); a; \
         end\nend\nputs B.new.m\np B.new.n(1, 2)\n",
    ),
    (
        "sclass",
        "class C\n  class << self\n    def s; 5; end\n  end\nend\nputs C.s\n",
    ),
    (
        "aliasundef",
        "class D\n  def a; 1; end\n  alias b a\n  def c; 2; end\n  undef c\nend\nputs D.new.b\n",
    ),
    (
        "blocks",
        "def y1\n  yield 1\nend\nputs(y1 { |v| v + 1 })\nl = ->(v) { v * 2 }\nputs l.call(3)\npr = \
         proc { |v| v }\nputs pr.call(4)\n",
    ),
    (
        "control",
        "i = 0\nwhile i < 3\n  i += 1\n  next if i == 1\n  break if i == 3\nend\nputs i\nputs(i > \
         1 ? \"y\" : \"n\")\nunless i.nil?\n  puts \"set\"\nend\n",
    ),
    (
        "exceptions",
        "begin\n  raise \"x\"\nrescue RuntimeError => e\n  puts e.message\nelse\n  puts \
         \"no\"\nensure\n  puts \"fin\"\nend\n",
    ),
    (
        "kwargs",
        "def kw(a:, b: 2, **rest, &blk)\n  [a, b, rest]\nend\np kw(a: 1, c: 3)\n",
    ),
    (
        "optargs",
        "def op(a, b = 2, *c, d, e: 5)\n  [a, b, c, d, e]\nend\np op(1, 2, 3, 4)\n",
    ),
    (
        "retry_redo",
        "t = 0\nbegin\n  t += 1\n  raise \"r\" if t < 2\nrescue\n  retry\nend\nputs t\nk = 0\n[1].each \
         do |v|\n  k += 1\n  redo if k < 2\nend\nputs k\n",
    ),
    ("safe_nav", "x = nil\nputs x&.size.inspect\n"),
    (
        "case_when",
        "v = 2\ncase v\nwhen 1 then puts \"one\"\nwhen 2 then puts \"two\"\nelse puts \
         \"other\"\nend\n",
    ),
    (
        "return_blk",
        "def rb\n  [1, 2].each { |v| return v }\n  0\nend\nputs rb\n",
    ),
    (
        "block_break",
        "r = [1, 2, 3].each { |v| break v * 2 }\nputs r\n",
    ),
    (
        "super_bare",
        "class E\n  def m(a, b); a + b; end\nend\nclass F < E\n  def m(a, b); super; \
         end\nend\nputs F.new.m(1, 2)\n",
    ),
    (
        "module_ex",
        "module N\n  def self.s; 1; end\n  def i; 2; end\nend\nclass G\n  include N\nend\nputs \
         N.s\nputs G.new.i\n",
    ),
    (
        "tclass",
        "class H\n  def self.q; 1; end\n  def r; self.class; end\nend\nputs H.q\np H.new.r\n",
    ),
    ("strcat", "a = \"x\"\nb = \"#{a}y#{a}z\"\nputs b\n"),
    ("local_jump", "def f\n  break\nend\nputs 1\n"),
    (
        "wide_operands",
        "def big\n  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] * 40\nend\nputs big.size\n",
    ),
    (
        "top_level_const",
        "::TOP = 1\nputs ::TOP\nclass Q\n  ::INNER = 2\nend\nputs ::INNER\n",
    ),
    (
        "nested_array_arg",
        "def f(a, b)\n  [a, b]\nend\nx = [1, 2]\np f(*x)\ny = [[1, 2], [3, 4]]\np y\n",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct IsaOpcode {
    index: usize,
    mnemonic: String,
    format: String,
}

#[derive(Debug, Clone)]
struct MrubyReference {
    include_dir: PathBuf,
    version: String,
    isa: Vec<IsaOpcode>,
}

#[derive(Debug, Clone)]
struct Measurement {
    name: String,
    compiler_present: BTreeSet<String>,
    disrobe_present: BTreeSet<String>,
    unmodeled: BTreeSet<String>,
}

fn path_candidates() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(explicit) = std::env::var_os(INCLUDE_OVERRIDE) {
        candidates.push(PathBuf::from(explicit));
    }
    if let Some(raw) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&raw) {
            for exe in ["mrbc", "mrbc.exe"] {
                let program: PathBuf = entry.join(exe);
                if !program.is_file() {
                    continue;
                }
                let Some(prefix): Option<&Path> = entry.parent() else {
                    continue;
                };
                let include: PathBuf = prefix.join("include").join("mruby");
                if !candidates.contains(&include) {
                    candidates.push(include);
                }
            }
        }
    }
    candidates
}

fn locate_reference() -> MrubyReference {
    let candidates: Vec<PathBuf> = path_candidates();
    for candidate in &candidates {
        let ops: PathBuf = candidate.join("ops.h");
        let version: PathBuf = candidate.join("version.h");
        if !ops.is_file() || !version.is_file() {
            continue;
        }
        let ops_text: String = std::fs::read_to_string(&ops)
            .unwrap_or_else(|error| panic!("read {}: {error}", ops.display()));
        let version_text: String = std::fs::read_to_string(&version)
            .unwrap_or_else(|error| panic!("read {}: {error}", version.display()));
        return MrubyReference {
            include_dir: candidate.clone(),
            version: parse_version(&version_text, &version),
            isa: parse_ops_header(&ops_text, &ops),
        };
    }
    let searched: String = if candidates.is_empty() {
        "nothing; no mrbc was found on PATH".to_owned()
    } else {
        candidates
            .iter()
            .map(|path: &PathBuf| path.display().to_string())
            .collect::<Vec<String>>()
            .join(", ")
    };
    panic!(
        "{GRADED} cannot be measured because the mruby headers that carry the opcode table were \
         not found. Searched: {searched}. This case must not report success without them, because \
         grading disrobe's opcode table against disrobe's own opcode table proves nothing. Install \
         the mruby development headers, or set {INCLUDE_OVERRIDE} to the directory holding ops.h \
         and version.h."
    );
}

fn parse_version(text: &str, source: &Path) -> String {
    let mut parts: BTreeMap<&str, String> = BTreeMap::new();
    for line in text.lines() {
        let trimmed: &str = line.trim();
        let Some(rest): Option<&str> = trimmed.strip_prefix("#define MRUBY_RELEASE_") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let (Some(name), Some(value)): (Option<&str>, Option<&str>) =
            (fields.next(), fields.next())
        else {
            continue;
        };
        for wanted in ["MAJOR", "MINOR", "TEENY"] {
            if name == wanted {
                parts.insert(wanted, value.to_owned());
            }
        }
    }
    let (Some(major), Some(minor), Some(teeny)): (
        Option<&String>,
        Option<&String>,
        Option<&String>,
    ) = (parts.get("MAJOR"), parts.get("MINOR"), parts.get("TEENY")) else {
        panic!(
            "{} does not declare MRUBY_RELEASE_MAJOR, MINOR and TEENY, so the version the opcode \
             table belongs to cannot be stated and the measurement must not report success",
            source.display()
        );
    };
    format!("{major}.{minor}.{teeny}")
}

fn parse_ops_header(text: &str, source: &Path) -> Vec<IsaOpcode> {
    let mut parsed: Vec<IsaOpcode> = Vec::new();
    for line in text.lines() {
        let Some(rest): Option<&str> = line.strip_prefix("OPCODE(") else {
            continue;
        };
        let Some((mnemonic, tail)): Option<(&str, &str)> = rest.split_once(',') else {
            panic!(
                "{}: OPCODE entry `{line}` has no operand field",
                source.display()
            );
        };
        let Some((format, _)): Option<(&str, &str)> = tail.split_once(')') else {
            panic!("{}: OPCODE entry `{line}` is not closed", source.display());
        };
        parsed.push(IsaOpcode {
            index: parsed.len(),
            mnemonic: mnemonic.trim().to_owned(),
            format: format.trim().to_owned(),
        });
    }
    assert!(
        !parsed.is_empty(),
        "{} yielded no OPCODE entries; the reference parser is reading the wrong file or the \
         header layout changed, and an empty reference would let every comparison below pass \
         without comparing anything",
        source.display()
    );
    parsed
}

fn expected_disrobe_mnemonic(isa_mnemonic: &str) -> &str {
    VERSION_RENAMES
        .iter()
        .find(|(upstream, _, _)| *upstream == isa_mnemonic)
        .map_or(isa_mnemonic, |(_, disrobe, _)| *disrobe)
}

#[allow(clippy::match_same_arms)]
fn isa_operand_width(format: &str, mnemonic: &str) -> usize {
    match format {
        "Z" => 0,
        "B" => 1,
        "BB" => 2,
        "BBB" => 3,
        "BS" => 3,
        "BSS" => 5,
        "S" => 2,
        "W" => 3,
        other => panic!(
            "mruby declares operand shape `{other}` for {mnemonic}, which this reference parser \
             cannot size. A new operand shape must be sized deliberately against the header, never \
             guessed, because every length below depends on it"
        ),
    }
}

fn encoded_lengths(isa: &[IsaOpcode]) -> BTreeMap<String, usize> {
    isa.iter()
        .map(|entry: &IsaOpcode| {
            (
                entry.mnemonic.clone(),
                1 + isa_operand_width(&entry.format, &entry.mnemonic),
            )
        })
        .collect()
}

fn resolve_printed(
    printed: &str,
    observed_length: Option<u32>,
    lengths: &BTreeMap<String, usize>,
) -> String {
    for (dumper, actual, _) in DUMPER_ALIASES {
        if *dumper != printed {
            continue;
        }
        let (Some(printed_len), Some(actual_len), Some(observed)): (
            Option<&usize>,
            Option<&usize>,
            Option<u32>,
        ) = (lengths.get(*dumper), lengths.get(*actual), observed_length) else {
            continue;
        };
        if printed_len != actual_len && usize::try_from(observed).unwrap_or(0) == *actual_len {
            return expected_disrobe_mnemonic(actual).to_owned();
        }
    }
    expected_disrobe_mnemonic(printed).to_owned()
}

fn require_mrbc() -> ToolchainBanner {
    require_measured_series(
        &MRBC,
        MRUBY_MEASURED_SERIES,
        GRADED,
        ToolchainRequirement::Mandatory,
    )
    .expect("the mandatory mrbc probe must succeed")
}

fn compile(name: &str, source: &str) -> (ScratchFile, ScratchFile, PathBuf, String) {
    let (rb_scratch, rb_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&format!("disrobe_mruby_isa_{name}"), "rb")
            .expect("create snippet scratch file");
    drop(rb_file);
    let rb_path: PathBuf = rb_scratch.path().to_path_buf();
    std::fs::write(&rb_path, source).expect("write snippet source");

    let (mrb_scratch, mrb_file): (ScratchFile, std::fs::File) =
        ScratchFile::create(&format!("disrobe_mruby_isa_{name}"), "mrb")
            .expect("create snippet output file");
    drop(mrb_file);
    let mrb_path: PathBuf = mrb_scratch.path().to_path_buf();

    let output: Output = Command::new("mrbc")
        .arg("-v")
        .arg("-o")
        .arg(&mrb_path)
        .arg(&rb_path)
        .output()
        .expect("run mrbc");
    assert!(
        output.status.success(),
        "mrbc rejected the `{name}` snippet, so it measures nothing. A snippet that stops \
         compiling must be repaired or removed, never left to shrink the measured set silently. \
         mrbc said: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing: String = String::from_utf8_lossy(&output.stdout).into_owned();
    (rb_scratch, mrb_scratch, mrb_path, listing)
}

fn compiler_instructions(
    listing: &str,
    lengths: &BTreeMap<String, usize>,
) -> Vec<Vec<(u32, String)>> {
    compiler_printed(listing)
        .into_iter()
        .map(|irep: Vec<(u32, String)>| {
            let pcs: Vec<u32> = irep.iter().map(|(pc, _): &(u32, String)| *pc).collect();
            let mut folded: Vec<(u32, String)> = Vec::with_capacity(irep.len());
            let mut prefix_pc: Option<u32> = None;
            for (index, (pc, printed)) in irep.into_iter().enumerate() {
                if WIDTH_PREFIXES.contains(&printed.as_str()) {
                    prefix_pc = prefix_pc.or(Some(pc));
                    continue;
                }
                let widened: Option<u32> = prefix_pc.take();
                let resolved: String = if widened.is_some() {
                    expected_disrobe_mnemonic(&printed).to_owned()
                } else {
                    let observed: Option<u32> = pcs
                        .get(index + 1)
                        .and_then(|next: &u32| next.checked_sub(pc));
                    resolve_printed(&printed, observed, lengths)
                };
                folded.push((widened.unwrap_or(pc), resolved));
            }
            folded
        })
        .collect()
}

fn compiler_prefixes(listing: &str) -> BTreeSet<String> {
    compiler_printed(listing)
        .into_iter()
        .flatten()
        .map(|(_, printed): (u32, String)| printed)
        .filter(|printed: &String| WIDTH_PREFIXES.contains(&printed.as_str()))
        .collect()
}

fn wide_local_program() -> String {
    let mut source: String = String::new();
    for index in 0..WIDE_LOCALS {
        writeln!(source, "v{index} = {index}").expect("format into a string");
    }
    source.push_str("puts [");
    for index in 0..WIDE_LOCALS {
        if index > 0 {
            source.push_str(", ");
        }
        write!(source, "v{index}").expect("format into a string");
    }
    source.push_str("].size\n");
    source
}

fn wide_symbol_program() -> String {
    let mut source: String = String::from("h = {}\n");
    for index in 0..WIDE_SYMBOLS {
        writeln!(source, "h[:s{index}] = {index}").expect("format into a string");
    }
    source.push_str("puts h.size\n");
    source
}

fn wide_both_program() -> String {
    let mut source: String = String::new();
    for index in 0..WIDE_LOCALS {
        writeln!(source, "v{index} = :a{index}").expect("format into a string");
    }
    source.push_str("h = {}\n");
    for index in 0..WIDE_SYMBOLS {
        writeln!(source, "h[:b{index}] = {index}").expect("format into a string");
    }
    let last_local: u32 = WIDE_LOCALS - 1;
    let last_symbol: u32 = WIDE_SYMBOLS - 1;
    writeln!(source, "v{last_local} = :b{last_symbol}").expect("format into a string");
    writeln!(source, "puts h.size, v{last_local}").expect("format into a string");
    source
}

fn all_snippets() -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = SNIPPETS
        .iter()
        .map(|(name, source): &(&str, &str)| ((*name).to_owned(), (*source).to_owned()))
        .collect();
    all.push(("wide_registers".to_owned(), wide_local_program()));
    all.push(("wide_symbols".to_owned(), wide_symbol_program()));
    all.push(("wide_both".to_owned(), wide_both_program()));
    all
}

fn compiler_printed(listing: &str) -> Vec<Vec<(u32, String)>> {
    let mut ireps: Vec<Vec<(u32, String)>> = Vec::new();
    let mut inside: bool = false;
    for line in listing.lines() {
        if line.starts_with("irep ") {
            ireps.push(Vec::new());
            inside = false;
            continue;
        }
        if line.starts_with("file:") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(_line_no), Some(pc), Some(mnemonic)): (Option<&str>, Option<&str>, Option<&str>) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(pc): Result<u32, _> = pc.parse::<u32>() else {
            continue;
        };
        if !mnemonic
            .bytes()
            .all(|b: u8| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            continue;
        }
        let Some(current): Option<&mut Vec<(u32, String)>> = ireps.last_mut() else {
            continue;
        };
        current.push((pc, mnemonic.to_owned()));
    }
    ireps
}

fn disrobe_ireps(bytes: &[u8], name: &str) -> Vec<Vec<(u32, String)>> {
    let analysis: RubyAnalysis =
        analyze_bytes(bytes, &format!("{name}.mrb")).expect("analyze the mrbc output");
    let mruby: MrubyAnalysis = analysis.mruby.expect("mruby analysis present");
    let tree: IrepTree = mruby.irep.expect("irep tree parsed from real mrbc output");
    tree.records
        .iter()
        .map(|record: &IrepRecord| {
            let instructions: Vec<MrubyInstruction> =
                disassemble_iseq(&record.iseq).expect("disassemble real mrbc iseq");
            instructions
                .into_iter()
                .map(|instruction: MrubyInstruction| (instruction.pc, instruction.mnemonic))
                .collect::<Vec<(u32, String)>>()
        })
        .collect()
}

fn measure(name: &str, source: &str, lengths: &BTreeMap<String, usize>) -> Measurement {
    let (_rb_scratch, _mrb_scratch, mrb_path, listing): (
        ScratchFile,
        ScratchFile,
        PathBuf,
        String,
    ) = compile(name, source);
    let bytes: Vec<u8> = std::fs::read(&mrb_path).expect("read the mrbc output");
    assert_eq!(
        bytes.get(..4),
        Some(&b"RITE"[..]),
        "{name}: mrbc did not produce a RITE container"
    );
    let mut compiler_present: BTreeSet<String> = compiler_instructions(&listing, lengths)
        .into_iter()
        .flatten()
        .map(|(_, mnemonic): (u32, String)| mnemonic)
        .collect();
    compiler_present.extend(compiler_prefixes(&listing));
    let disrobe_present: BTreeSet<String> = disrobe_ireps(&bytes, name)
        .into_iter()
        .flatten()
        .map(|(_, mnemonic): (u32, String)| mnemonic)
        .collect();
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, &format!("{name}.mrb")).expect("analyze the mrbc output");
    let unmodeled: BTreeSet<String> = analysis
        .mruby
        .expect("mruby analysis present")
        .decompiled
        .unmodeled_mnemonics
        .into_iter()
        .collect();
    Measurement {
        name: name.to_owned(),
        compiler_present,
        disrobe_present,
        unmodeled,
    }
}

fn measure_all(lengths: &BTreeMap<String, usize>) -> Vec<Measurement> {
    all_snippets()
        .iter()
        .map(|(name, source): &(String, String)| measure(name, source, lengths))
        .collect()
}

#[test]
fn disrobe_opcode_table_matches_the_installed_mruby_ops_header() {
    let reference: MrubyReference = locate_reference();
    println!(
        "reference: {} (mruby {}), {} opcodes",
        reference.include_dir.display(),
        reference.version,
        reference.isa.len()
    );
    assert_eq!(
        opcode_count(),
        reference.isa.len(),
        "disrobe declares {} opcodes but mruby {} declares {} in {}; a table of the wrong length \
         decodes every instruction after the divergence at the wrong offset",
        opcode_count(),
        reference.version,
        reference.isa.len(),
        reference.include_dir.join("ops.h").display()
    );
    for entry in &reference.isa {
        let index: u8 = u8::try_from(entry.index).expect("an mruby opcode number fits in a byte");
        let spec: &MrubyOpcode = opcode_spec(index).unwrap_or_else(|| {
            panic!(
                "disrobe has no opcode at number {index}, where mruby {} declares {}",
                reference.version, entry.mnemonic
            )
        });
        let expected: &str = expected_disrobe_mnemonic(&entry.mnemonic);
        assert_eq!(
            spec.mnemonic, expected,
            "opcode {index} is `{}` in mruby {} but `{}` in disrobe; an instruction reported under \
             a mnemonic the instruction set does not use cannot be looked up by anyone reading the \
             output",
            entry.mnemonic, reference.version, spec.mnemonic
        );
        assert_eq!(
            spec.format.spec_name(),
            entry.format,
            "opcode {index} ({}) takes operands `{}` in mruby {} but `{}` in disrobe; a wrong \
             operand width desynchronises every instruction that follows it",
            entry.mnemonic,
            entry.format,
            reference.version,
            spec.format.spec_name()
        );
        assert_eq!(
            spec.format.base_width(),
            isa_operand_width(&entry.format, &entry.mnemonic),
            "opcode {index} ({}) encodes {} operand bytes in mruby {} but disrobe advances {}",
            entry.mnemonic,
            isa_operand_width(&entry.format, &entry.mnemonic),
            reference.version,
            spec.format.base_width()
        );
    }
    for (upstream, disrobe, reason) in VERSION_RENAMES {
        assert!(
            reference
                .isa
                .iter()
                .any(|entry: &IsaOpcode| entry.mnemonic == *upstream || entry.mnemonic == *disrobe),
            "the recorded rename `{upstream}` -> `{disrobe}` ({reason}) names no opcode in mruby \
             {}, so the entry is stale and would silently excuse a real mnemonic mismatch",
            reference.version
        );
    }
}

#[test]
fn every_isa_opcode_is_lowered_or_reported_dropped_under_its_real_mnemonic() {
    let reference: MrubyReference = locate_reference();
    let banner: ToolchainBanner = require_mrbc();
    let lengths: BTreeMap<String, usize> = encoded_lengths(&reference.isa);
    let measurements: Vec<Measurement> = measure_all(&lengths);

    let mut seen_anywhere: BTreeSet<String> = BTreeSet::new();
    let mut dropped_anywhere: BTreeSet<String> = BTreeSet::new();
    for measurement in &measurements {
        seen_anywhere.extend(measurement.compiler_present.iter().cloned());
        dropped_anywhere.extend(measurement.unmodeled.iter().cloned());
    }
    for reported in &dropped_anywhere {
        assert!(
            reference
                .isa
                .iter()
                .any(|entry: &IsaOpcode| expected_disrobe_mnemonic(&entry.mnemonic) == reported),
            "a program reported `{reported}` dropped, but mruby {} declares no such opcode; a \
             dropped instruction must surface under a mnemonic the instruction set actually uses",
            reference.version
        );
    }

    let mut lowered_measured: Vec<String> = Vec::new();
    let mut dropped_measured: Vec<String> = Vec::new();
    let mut decoder_measured: Vec<String> = Vec::new();
    let mut declared_only: Vec<String> = Vec::new();

    for entry in &reference.isa {
        let index: u8 = u8::try_from(entry.index).expect("an mruby opcode number fits in a byte");
        let spec: &MrubyOpcode = opcode_spec(index).expect("the table comparison covers presence");
        let status: MrubyLowering = lowering(spec.op);
        let exercised: bool = seen_anywhere.contains(spec.mnemonic);
        let reported: bool = dropped_anywhere.contains(spec.mnemonic);

        if !status.reaches_the_lifter() {
            for measurement in &measurements {
                assert!(
                    !measurement.disrobe_present.contains(spec.mnemonic),
                    "{}: disrobe's decoder emitted {} as an instruction, but it is declared a \
                     width prefix the decoder consumes into the instruction it widens",
                    measurement.name,
                    spec.mnemonic
                );
            }
            if exercised {
                decoder_measured.push(entry.mnemonic.clone());
            } else {
                declared_only.push(format!(
                    "{} (decoder prefix, not reached by any snippet)",
                    entry.mnemonic
                ));
            }
            continue;
        }

        if !status.can_report_itself_dropped() {
            for measurement in &measurements {
                assert!(
                    !measurement.unmodeled.contains(spec.mnemonic),
                    "{}: {} is declared to lower with semantics on every input, but this program \
                     reported it dropped. Either the lowering is conditional and the declaration \
                     must say so with a reason, or the lowering regressed",
                    measurement.name,
                    spec.mnemonic
                );
            }
            if exercised {
                lowered_measured.push(entry.mnemonic.clone());
            } else {
                declared_only.push(format!(
                    "{} (lowers, not reached by any snippet)",
                    entry.mnemonic
                ));
            }
            continue;
        }

        if let MrubyLowering::Dropped(_) = status
            && exercised
        {
            assert!(
                reported,
                "{} is declared always reported under its own mnemonic, and a snippet emits it, \
                 but no program reported it; a dropped opcode that never surfaces is a silent skip",
                entry.mnemonic
            );
        }

        if exercised && reported {
            dropped_measured.push(entry.mnemonic.clone());
        } else if exercised {
            lowered_measured.push(entry.mnemonic.clone());
        } else {
            let shape: &str = match status {
                MrubyLowering::Dropped(_) => "always reported",
                _ => "conditional",
            };
            declared_only.push(format!(
                "{} ({shape}, not reached by any snippet)",
                entry.mnemonic
            ));
        }
    }

    let total: usize = reference.isa.len();
    let measured: usize = lowered_measured.len() + dropped_measured.len() + decoder_measured.len();
    println!(
        "mruby {} instruction set, {} opcodes, compiler {}",
        reference.version, total, banner.banner
    );
    println!("  measured against real mrbc output: {measured}/{total}");
    println!(
        "    lowered with semantics: {}/{total} {:?}",
        lowered_measured.len(),
        lowered_measured
    );
    println!(
        "    reported dropped under their own mnemonic: {}/{total} {:?}",
        dropped_measured.len(),
        dropped_measured
    );
    println!(
        "    consumed by the decoder into the instruction they widen: {}/{total} {:?}",
        decoder_measured.len(),
        decoder_measured
    );
    println!(
        "  declared only, no reachable mrbc input: {}/{total} {:?}",
        declared_only.len(),
        declared_only
    );

    assert_eq!(
        measured + declared_only.len(),
        total,
        "every opcode in the instruction set must land in exactly one column of the ledger"
    );
    assert!(
        measured >= MEASURED_OPCODE_FLOOR,
        "only {measured}/{total} opcodes were measured against real mrbc output, below the \
         recorded floor of {MEASURED_OPCODE_FLOOR}. The snippet corpus stopped reaching opcodes it \
         used to reach, so the ledger is now asserting less than it claims"
    );

    for entry in &reference.isa {
        let index: u8 = u8::try_from(entry.index).expect("an mruby opcode number fits in a byte");
        let spec: &MrubyOpcode = opcode_spec(index).expect("the table comparison covers presence");
        if let MrubyLowering::Conditional(reason) | MrubyLowering::Dropped(reason) =
            lowering(spec.op)
        {
            assert!(
                reason.len() > 40,
                "{} may withhold a lowering, so it must carry a reason a reader can act on, got \
                 {reason:?}",
                entry.mnemonic
            );
        }
    }
}

#[test]
fn disrobe_disassembly_agrees_with_the_mrbc_listing_instruction_for_instruction() {
    let reference: MrubyReference = locate_reference();
    let banner: ToolchainBanner = require_mrbc();
    let lengths: BTreeMap<String, usize> = encoded_lengths(&reference.isa);
    let mut compared: usize = 0;

    let programs: Vec<(String, String)> = all_snippets();
    for (name, source) in &programs {
        let (_rb_scratch, _mrb_scratch, mrb_path, listing): (
            ScratchFile,
            ScratchFile,
            PathBuf,
            String,
        ) = compile(name, source);
        let bytes: Vec<u8> = std::fs::read(&mrb_path).expect("read the mrbc output");
        let expected: Vec<Vec<(u32, String)>> = compiler_instructions(&listing, &lengths);
        let actual: Vec<Vec<(u32, String)>> = disrobe_ireps(&bytes, name);
        assert_eq!(
            actual.len(),
            expected.len(),
            "{name}: mrbc printed {} ireps and disrobe parsed {}",
            expected.len(),
            actual.len()
        );
        for (index, (want, have)) in expected.iter().zip(actual.iter()).enumerate() {
            let want_named: &Vec<(u32, String)> = want;
            assert_eq!(
                have, want_named,
                "{name}: irep {index} disassembles differently from the mrbc {} listing; a \
                 divergence here is an operand-width or opcode-number defect, not a rendering \
                 preference",
                reference.version
            );
            compared += want_named.len();
        }
    }

    println!(
        "compared {compared} instructions against the {} listing across {} programs",
        banner.banner,
        programs.len()
    );
    assert!(
        compared > 500,
        "only {compared} instructions were compared against the compiler listing; a comparison \
         this small is not evidence the decoder agrees with mruby"
    );
}
