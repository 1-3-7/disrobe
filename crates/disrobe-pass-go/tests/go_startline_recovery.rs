#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, GoFunc, analyze};

const STARTLINE_SRC: &str = "package main\n\
\n\
import \"fmt\"\n\
\n\
//go:noinline\n\
func Alpha() int {\n\
\treturn len(\"alpha\")\n\
}\n\
\n\
//go:noinline\n\
func Beta(n int) int {\n\
\treturn Alpha() + n\n\
}\n\
\n\
//go:noinline\n\
func Gamma(a int, b int) int {\n\
\treturn Beta(a) * b\n\
}\n\
\n\
//go:noinline\n\
func Delta() string {\n\
\treturn fmt.Sprintf(\"%d\", Gamma(2, 3))\n\
}\n\
\n\
func main() {\n\
\tfmt.Println(Alpha(), Beta(1), Gamma(1, 2), Delta())\n\
}\n";

fn expected_start_lines(src: &str) -> BTreeMap<String, i32> {
    let mut out: BTreeMap<String, i32> = BTreeMap::new();
    for (idx, line) in src.lines().enumerate() {
        let Some(rest): Option<&str> = line.strip_prefix("func ") else {
            continue;
        };
        if rest.starts_with('(') {
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let line_no: i32 = i32::try_from(idx + 1).expect("source line fits in i32");
        out.insert(format!("main.{name}"), line_no);
    }
    out
}

fn find_func<'a>(analysis: &'a GoAnalysis, name: &str) -> Option<&'a GoFunc> {
    analysis
        .symbols
        .funcs
        .iter()
        .find(|f: &&GoFunc| f.name == name)
}

#[test]
fn expected_map_reads_source_lines() {
    let expected: BTreeMap<String, i32> = expected_start_lines(STARTLINE_SRC);
    assert_eq!(expected.get("main.Alpha"), Some(&6));
    assert_eq!(expected.get("main.Beta"), Some(&11));
    assert_eq!(expected.get("main.Gamma"), Some(&16));
    assert_eq!(expected.get("main.Delta"), Some(&21));
    assert_eq!(expected.get("main.main"), Some(&25));
}

#[test]
fn stripped_binary_recovers_per_function_start_line_from_source() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("startline");
    common::write_module(&scratch, "startlinemod", STARTLINE_SRC);

    let Some(normal): Option<PathBuf> = common::go_build(&scratch, "app_normal.exe", &[]) else {
        panic!("normal go build failed");
    };
    let Some(stripped): Option<PathBuf> =
        common::go_build(&scratch, "app_stripped.exe", &["-ldflags", "-s -w"])
    else {
        panic!("stripped go build failed");
    };

    let normal_bytes: Vec<u8> = std::fs::read(&normal).expect("read normal build");
    let stripped_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped build");
    let normal_analysis: GoAnalysis = analyze(&normal_bytes).expect("analyze normal build");
    let stripped_analysis: GoAnalysis = analyze(&stripped_bytes).expect("analyze stripped build");

    assert!(
        stripped_analysis.stripped.stripped,
        "the -s -w build must classify as stripped"
    );
    assert_eq!(
        stripped_analysis.pclntab_version, "go1.20..go1.25",
        "go1.26 emits the 0xfffffff1 pclntab whose _func carries startLine"
    );

    let expected: BTreeMap<String, i32> = expected_start_lines(STARTLINE_SRC);
    let mut matched: usize = 0;
    for (name, want) in &expected {
        let func: &GoFunc = find_func(&stripped_analysis, name)
            .unwrap_or_else(|| panic!("stripped recovery dropped function {name}"));
        assert_eq!(
            func.start_line,
            Some(*want),
            "startLine for {name} must equal its source `func` line {want}, got {:?}",
            func.start_line
        );
        matched += 1;

        let normal_func: &GoFunc = find_func(&normal_analysis, name)
            .unwrap_or_else(|| panic!("normal recovery dropped function {name}"));
        assert_eq!(
            normal_func.start_line,
            Some(*want),
            "the unstripped build must recover the same startLine for {name}"
        );
    }
    assert_eq!(
        matched,
        expected.len(),
        "every declared main.* function must recover its source start line"
    );

    let with_line: usize = stripped_analysis
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.start_line.is_some())
        .count();
    assert!(
        with_line >= expected.len(),
        "the whole binary's go1.20+ funcs carry startLine; expected at least {} recovered, got {with_line}",
        expected.len()
    );
}

#[test]
fn start_line_offset_is_fixed_width_on_32bit_image() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_386);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze 386 fixture");
    assert_eq!(analysis.ptr_size, 4, "expected a 32-bit image");
    assert_eq!(
        analysis.pclntab_version, "go1.20..go1.25",
        "the 32-bit fixture is a go1.20+ build carrying startLine"
    );

    let total: usize = analysis.symbols.funcs.len();
    let with_line: usize = analysis
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.start_line.is_some())
        .count();
    assert!(
        total > 100,
        "the 386 fixture exposes hundreds of funcs (got {total})"
    );
    let ratio: f64 = with_line as f64 / total.max(1) as f64;
    assert!(
        ratio >= 0.9,
        "the _func struct is fixed-width, so startLine sits at +36 on 32-bit images too: \
         expected >= 90% of funcs to carry a plausible line, got {with_line}/{total} = {ratio:.3}"
    );

    let runtime_main: &GoFunc =
        find_func(&analysis, "runtime.main").expect("runtime.main must be recovered");
    assert!(
        runtime_main.start_line.is_some_and(|l: i32| l > 0),
        "runtime.main has a real source line in proc.go, got {:?}",
        runtime_main.start_line
    );
}
