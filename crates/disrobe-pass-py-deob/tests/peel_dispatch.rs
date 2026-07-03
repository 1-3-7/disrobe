#![allow(clippy::expect_used, clippy::panic)]

use disrobe_pass_py_deob::obfuscators::{manglify, obfuxtreme, wodx};
use disrobe_pass_py_deob::{Obfuscator, ObfuscatorQuality, PeelResult, peel};

fn run(obf: &str) -> PeelResult {
    peel(obf.as_bytes()).unwrap_or_else(|e| panic!("peel failed: {e:?}"))
}

#[test]
fn wodx_wrapper_dispatches_and_recovers() {
    let original: &str = "def greet(name):\n    return f'hi {name}'\n";
    let obf: String = wodx::bake(original);
    let result: PeelResult = run(&obf);
    assert!(result.recovered, "wodx must report recovered");
    assert_eq!(result.final_source, original);
    assert_ne!(result.final_source.as_bytes(), obf.as_bytes());
    let summary = result.obfuscator.expect("wodx summary present");
    assert_eq!(summary.obfuscator, Obfuscator::Wodx);
    assert_eq!(summary.quality, ObfuscatorQuality::Full);
}

#[test]
fn manglify_wrapper_dispatches_and_restores_idents() {
    let original: &str =
        "def calculate(x):\n    return x * 2\n\ndef double(y):\n    return calculate(y)\n";
    let obf: String = manglify::bake(original);
    let result: PeelResult = run(&obf);
    assert!(result.recovered, "manglify must report recovered");
    assert_ne!(result.final_source.as_bytes(), obf.as_bytes());
    assert!(
        result.final_source.contains("def calculate"),
        "expected restored identifier in {}",
        result.final_source
    );
    assert!(result.final_source.contains("def double"));
    let summary = result.obfuscator.expect("manglify summary present");
    assert_eq!(summary.obfuscator, Obfuscator::Manglify);
}

#[test]
fn obfuxtreme_wrapper_dispatches_and_recovers() {
    let original: &str =
        "match x:\n    case 1:\n        print('one')\n    case _:\n        print('?')\n";
    let obf: String = obfuxtreme::bake(original);
    let result: PeelResult = run(&obf);
    assert!(result.recovered, "obfuxtreme must report recovered");
    assert_eq!(result.final_source, original);
    assert_ne!(result.final_source.as_bytes(), obf.as_bytes());
    let summary = result.obfuscator.expect("obfuxtreme summary present");
    assert_eq!(summary.obfuscator, Obfuscator::ObfuXtreme);
}

#[test]
fn plain_source_reports_no_detection() {
    let plain: &str = "def main():\n    return 42\n";
    let result: PeelResult = run(plain);
    assert!(
        !result.recovered,
        "plain source must not be reported recovered"
    );
    assert!(result.obfuscator.is_none());
    assert!(result.steps.is_empty());
    assert_eq!(result.final_source, plain);
}
