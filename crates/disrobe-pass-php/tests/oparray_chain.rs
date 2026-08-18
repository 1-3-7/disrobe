#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::too_many_arguments)]

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, Pass};
use disrobe_core::error::CoreError;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_php::chain_detector::{PHP_PASS, PhpDetectorImpl};
use disrobe_pass_php::decompile::op;
use disrobe_pass_php::{Error, PhpKind, detect_php, parse_oparray};
use php_toolchain::{PHP_OPCACHE, PhpRuntime, require_php, unmeasured};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HELLO_DZOA: &[u8] = include_bytes!("fixtures/protector_oparray/hello.dzoa");
const GENERATOR_DZOA: &[u8] = include_bytes!("fixtures/oparray_generator/generators.dzoa");

const T_UNUSED: u8 = 0;
const T_CONST: u8 = 1;
const T_TMP: u8 = 2;
const T_CV: u8 = 8;

enum TableKey<'a> {
    Long(i64),
    String(&'a str),
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_op(
    out: &mut Vec<u8>,
    opcode: u8,
    op1_type: u8,
    op2_type: u8,
    result_type: u8,
    op1: u32,
    op2: u32,
    result: u32,
    extended_value: u32,
    lineno: u32,
) {
    out.extend_from_slice(&[opcode, op1_type, op2_type, result_type]);
    for value in [op1, op2, result, extended_value, lineno] {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn optimized_switch_oparray(subject: TableKey<'_>, string_table: bool) -> Vec<u8> {
    let mut literals: Vec<u8> = Vec::new();
    let subject_literal: u32 = 0;
    match subject {
        TableKey::Long(value) => {
            literals.push(2);
            literals.extend_from_slice(&value.to_le_bytes());
        }
        TableKey::String(value) => {
            literals.push(4);
            push_string(&mut literals, value);
        }
    }
    let labels: [&str; 6] = ["a", "b", "c", "d", "e", "default"];
    for label in labels {
        literals.push(4);
        push_string(&mut literals, label);
    }
    let table_literal: u32 = 7;
    literals.push(if string_table { 7 } else { 6 });
    literals.extend_from_slice(&6u32.to_le_bytes());
    let targets: [u32; 6] = [2, 2, 4, 6, 8, 10];
    if string_table {
        for (key, target) in ["one", "two", "four", "seven", "nine", "twelve"]
            .into_iter()
            .zip(targets)
        {
            push_string(&mut literals, key);
            literals.extend_from_slice(&target.to_le_bytes());
        }
    } else {
        for (key, target) in [1i64, 2, 4, 7, 9, -12].into_iter().zip(targets) {
            literals.extend_from_slice(&key.to_le_bytes());
            literals.extend_from_slice(&target.to_le_bytes());
        }
    }

    let mut ops: Vec<u8> = Vec::new();
    push_op(
        &mut ops,
        op::ASSIGN,
        T_CV,
        T_CONST,
        T_UNUSED,
        0,
        subject_literal,
        0,
        0,
        1,
    );
    push_op(
        &mut ops,
        if string_table {
            op::SWITCH_STRING
        } else {
            op::SWITCH_LONG
        },
        T_CV,
        T_CONST,
        T_UNUSED,
        0,
        table_literal,
        0,
        12,
        2,
    );
    for (target, literal) in [(2u32, 1u32), (4, 2), (6, 3), (8, 4), (10, 5)] {
        assert_eq!(ops.len() / 24, target as usize);
        push_op(
            &mut ops,
            op::ECHO,
            T_CONST,
            T_UNUSED,
            T_UNUSED,
            literal,
            0,
            0,
            0,
            target,
        );
        push_op(
            &mut ops,
            op::JMP,
            T_UNUSED,
            T_UNUSED,
            T_UNUSED,
            14,
            0,
            0,
            0,
            target,
        );
    }
    push_op(
        &mut ops,
        op::ECHO,
        T_CONST,
        T_UNUSED,
        T_UNUSED,
        6,
        0,
        0,
        0,
        12,
    );
    push_op(
        &mut ops,
        op::JMP,
        T_UNUSED,
        T_UNUSED,
        T_UNUSED,
        14,
        0,
        0,
        0,
        12,
    );
    push_op(
        &mut ops,
        op::RETURN,
        T_CONST,
        T_UNUSED,
        T_UNUSED,
        subject_literal,
        0,
        0,
        0,
        13,
    );

    let mut wire: Vec<u8> = b"DZOA\x03".to_vec();
    wire.extend_from_slice(&[0, 0, 0]);
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire.extend_from_slice(&1u32.to_le_bytes());
    wire.push(1);
    push_string(&mut wire, "value");
    wire.extend_from_slice(&8u32.to_le_bytes());
    wire.extend_from_slice(&literals);
    wire.extend_from_slice(&15u32.to_le_bytes());
    wire.extend_from_slice(&ops);
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire
}

fn optimized_match_oparray(subject: i64) -> Vec<u8> {
    let mut literals: Vec<u8> = Vec::new();
    literals.push(2);
    literals.extend_from_slice(&subject.to_le_bytes());
    for value in ["low", "seven", "nine", "other"] {
        literals.push(4);
        push_string(&mut literals, value);
    }
    literals.push(6);
    literals.extend_from_slice(&4u32.to_le_bytes());
    for (key, target) in [(1i64, 2u32), (2, 2), (7, 4), (9, 6)] {
        literals.extend_from_slice(&key.to_le_bytes());
        literals.extend_from_slice(&target.to_le_bytes());
    }

    let mut ops: Vec<u8> = Vec::new();
    push_op(&mut ops, op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, 0, 0, 0, 1);
    push_op(&mut ops, op::MATCH, T_CV, T_CONST, T_UNUSED, 0, 5, 0, 8, 2);
    for (target, literal) in [(2u32, 1u32), (4, 2), (6, 3), (8, 4)] {
        assert_eq!(ops.len() / 24, target as usize);
        push_op(
            &mut ops,
            op::QM_ASSIGN,
            T_CONST,
            T_UNUSED,
            T_TMP,
            literal,
            0,
            0,
            0,
            target,
        );
        push_op(
            &mut ops,
            op::JMP,
            T_UNUSED,
            T_UNUSED,
            T_UNUSED,
            10,
            0,
            0,
            0,
            target,
        );
    }
    push_op(
        &mut ops,
        op::ECHO,
        T_TMP,
        T_UNUSED,
        T_UNUSED,
        0,
        0,
        0,
        0,
        10,
    );
    push_op(
        &mut ops,
        op::RETURN,
        T_CONST,
        T_UNUSED,
        T_UNUSED,
        0,
        0,
        0,
        0,
        11,
    );

    let mut wire: Vec<u8> = b"DZOA\x03".to_vec();
    wire.extend_from_slice(&[0, 0, 0]);
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire.extend_from_slice(&1u32.to_le_bytes());
    wire.push(1);
    push_string(&mut wire, "value");
    wire.extend_from_slice(&6u32.to_le_bytes());
    wire.extend_from_slice(&literals);
    wire.extend_from_slice(&12u32.to_le_bytes());
    wire.extend_from_slice(&ops);
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire
}

fn rewrite_nth_match_arm_result(mut wire: Vec<u8>, nth: usize, result: u32) -> Vec<u8> {
    let marker: [u8; 4] = [op::QM_ASSIGN, T_CONST, T_UNUSED, T_TMP];
    let positions: Vec<usize> = wire
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, candidate): (usize, &[u8])| (candidate == marker).then_some(index))
        .collect();
    assert_eq!(positions.len(), 4);
    let start: usize = positions[nth] + 12;
    let end: usize = start + size_of::<u32>();
    wire[start..end].copy_from_slice(&result.to_le_bytes());
    wire
}

fn rewrite_nth_match_jump_target(mut wire: Vec<u8>, nth: usize, target: u32) -> Vec<u8> {
    let marker: [u8; 4] = [op::JMP, T_UNUSED, T_UNUSED, T_UNUSED];
    let positions: Vec<usize> = wire
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, candidate): (usize, &[u8])| (candidate == marker).then_some(index))
        .collect();
    assert_eq!(positions.len(), 4);
    let start: usize = positions[nth] + 4;
    let end: usize = start + size_of::<u32>();
    wire[start..end].copy_from_slice(&target.to_le_bytes());
    wire
}

fn rewrite_nth_match_arm_operand_type(mut wire: Vec<u8>, nth: usize, operand_type: u8) -> Vec<u8> {
    let marker: [u8; 4] = [op::QM_ASSIGN, T_CONST, T_UNUSED, T_TMP];
    let positions: Vec<usize> = wire
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, candidate): (usize, &[u8])| (candidate == marker).then_some(index))
        .collect();
    assert_eq!(positions.len(), 4);
    wire[positions[nth] + 1] = operand_type;
    wire
}

fn opcache_dll(php: &PhpRuntime) -> Option<PathBuf> {
    let configured: Option<std::ffi::OsString> = std::env::var_os("DZOA_OPCACHE_DLL");
    if let Some(configured) = configured {
        let path: PathBuf = PathBuf::from(configured);
        return path.is_file().then_some(path);
    }
    let resolved: PathBuf = if php.binary == Path::new("php") {
        let output: Output = Command::new(&php.binary)
            .args(["-r", "echo PHP_BINARY;"])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))?
    } else {
        php.binary.clone()
    };
    let directory: &Path = resolved.parent()?;
    ["ext/php_opcache.dll", "php_opcache.dll", "ext/opcache.so"]
        .into_iter()
        .map(|relative: &str| directory.join(relative))
        .find(|candidate: &PathBuf| candidate.is_file())
}

fn compiler_dump(php: &PhpRuntime, source: &str) -> Option<String> {
    let graded: &str = "PHP 8.4 optimized switch compiler dispatch fields";
    let Some(dll): Option<PathBuf> = opcache_dll(php) else {
        unmeasured(
            &PHP_OPCACHE,
            graded,
            "the opcache extension was not found beside the PHP 8.4 binary",
        );
        return None;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_switch_dump")
            .expect("create compiler dump scratch directory");
    let source_path: PathBuf = scratch.path().join("switch.php");
    let dzoa_path: PathBuf = scratch.path().join("switch.dzoa");
    let dump_path: PathBuf = scratch.path().join("switch.dump");
    let mut source_file: std::fs::File =
        std::fs::File::create(&source_path).expect("create compiler source");
    source_file
        .write_all(source.as_bytes())
        .expect("write compiler source");
    drop(source_file);
    let emitter: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("php")
        .join("oparray")
        .join("emit_dzoa.php");
    let output: Output = Command::new(&php.binary)
        .env("DZOA_OPCACHE_DLL", &dll)
        .arg(&emitter)
        .arg(&source_path)
        .arg(&dzoa_path)
        .arg(&dump_path)
        .output()
        .expect("run PHP 8.4 opcache emitter");
    if !output.status.success() {
        unmeasured(
            &PHP_OPCACHE,
            graded,
            &format!(
                "the PHP 8.4 opcache extension emitted no opcode dump: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        );
        return None;
    }
    Some(std::fs::read_to_string(dump_path).expect("read PHP 8.4 compiler dump"))
}

fn retarget_long(mut wire: Vec<u8>, key: i64, old_target: u32, new_target: u32) -> Vec<u8> {
    let mut entry: Vec<u8> = key.to_le_bytes().to_vec();
    entry.extend_from_slice(&old_target.to_le_bytes());
    let positions: Vec<usize> = wire
        .windows(entry.len())
        .enumerate()
        .filter_map(|(index, candidate): (usize, &[u8])| (candidate == entry).then_some(index))
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "the independently serialized key must be unique"
    );
    let start: usize = positions[0] + size_of::<i64>();
    let end: usize = start + size_of::<u32>();
    wire[start..end].copy_from_slice(&new_target.to_le_bytes());
    wire
}

fn retarget_switch_default(mut wire: Vec<u8>, opcode: u8, new_target: u32) -> Vec<u8> {
    let marker: [u8; 4] = [opcode, T_CV, T_CONST, T_UNUSED];
    let positions: Vec<usize> = wire
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, candidate): (usize, &[u8])| (candidate == marker).then_some(index))
        .collect();
    assert_eq!(positions.len(), 1, "the switch opcode must be unique");
    let start: usize = positions[0] + 4 * size_of::<u32>();
    let end: usize = start + size_of::<u32>();
    wire[start..end].copy_from_slice(&new_target.to_le_bytes());
    wire
}

fn overwrite_long_table_count(mut wire: Vec<u8>, count: u32) -> Vec<u8> {
    let marker: [u8; 5] = [6, 6, 0, 0, 0];
    let positions: Vec<usize> = wire
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, candidate): (usize, &[u8])| (candidate == marker).then_some(index))
        .collect();
    assert_eq!(positions.len(), 1, "the long table marker must be unique");
    let start: usize = positions[0] + 1;
    let end: usize = start + size_of::<u32>();
    wire[start..end].copy_from_slice(&count.to_le_bytes());
    wire
}

const fn context(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    }
}

#[test]
fn registered_pass_recovers_committed_oparray_to_php_source() {
    assert_eq!(detect_php(HELLO_DZOA).kind, PhpKind::Unknown);
    let verdict: DetectVerdict = Detector::detect(&PhpDetectorImpl, &context(HELLO_DZOA))
        .expect("the registered PHP detector must recognize DZOA input");
    assert_eq!(verdict.pass_id, "php.peel");
    assert_eq!(verdict.format_tag, "php-oparray");

    let input: Artifact = Artifact::new(Rung::Raw, HELLO_DZOA.to_vec(), [0x5a; 32]);
    let output: Artifact = PHP_PASS
        .run(&input)
        .expect("the registered pass must recover DZOA");

    assert_eq!(output.rung, Rung::Surface);
    assert_eq!(output.root_hash, input.root_hash);
    assert_eq!(
        std::str::from_utf8(&output.envelope).expect("recovered source must be UTF-8"),
        "<?php\necho 'hello from ioncube container';\nreturn 1;\n"
    );
}

fn assert_runtime_equivalent(
    php: &PhpRuntime,
    wire: Vec<u8>,
    original: &str,
    expected: &[u8],
) -> String {
    let input: Artifact = Artifact::new(Rung::Raw, wire, [0xa5; 32]);
    let output: Artifact = PHP_PASS
        .run(&input)
        .expect("the registered pass must recover the optimized switch");
    let source: String =
        String::from_utf8(output.envelope).expect("the registered pass must emit UTF-8 PHP source");
    let original_stdout: Vec<u8> = php.stdout_of("optimized switch original", original.as_bytes());
    let recovered_stdout: Vec<u8> = php.stdout_of("optimized switch recovered", source.as_bytes());
    assert_eq!(original_stdout, expected);
    assert_eq!(recovered_stdout, original_stdout, "{source}");
    assert!(source.contains("switch ($value)"), "{source}");
    assert!(!source.contains("unrecovered ZEND_SWITCH"), "{source}");
    source
}

#[test]
fn registered_pass_recovers_php_84_long_and_string_switch_tables() {
    let Some(php): Option<PhpRuntime> = require_php(
        "PHP 8.4 optimized SWITCH_LONG and SWITCH_STRING registered-pass runtime equivalence",
    ) else {
        return;
    };
    assert!(php.banner.starts_with("PHP 8.4."), "{}", php.banner);

    let long_original: &str = "<?php $value=4; switch($value){case 1:case 2:echo'a';break;case 4:echo'b';break;case 7:echo'c';break;case 9:echo'd';break;case -12:echo'e';break;default:echo'default';}";
    let long_source: String = assert_runtime_equivalent(
        &php,
        optimized_switch_oparray(TableKey::Long(4), false),
        long_original,
        b"b",
    );
    assert!(
        long_source.contains("case 1:\n    case 2:"),
        "{long_source}"
    );
    assert!(long_source.contains("case 4:"), "{long_source}");
    let retargeted_source: String = assert_runtime_equivalent(
        &php,
        retarget_long(optimized_switch_oparray(TableKey::Long(4), false), 4, 4, 6),
        "<?php $value=4; switch($value){case 1:case 2:echo'a';break;case 4:echo'c';break;case 7:echo'c';break;case 9:echo'd';break;case -12:echo'e';break;default:echo'default';}",
        b"c",
    );
    assert_ne!(retargeted_source, long_source);

    let string_original: &str = "<?php $value='seven'; switch($value){case'one':case'two':echo'a';break;case'four':echo'b';break;case'seven':echo'c';break;case'nine':echo'd';break;case'twelve':echo'e';break;default:echo'default';}";
    let string_source: String = assert_runtime_equivalent(
        &php,
        optimized_switch_oparray(TableKey::String("seven"), true),
        string_original,
        b"c",
    );
    assert!(string_source.contains("case 'seven':"), "{string_source}");
    assert!(string_source.contains("default:"), "{string_source}");

    let default_original: &str = "<?php $value=3; switch($value){case 1:case 2:echo'a';break;case 4:echo'b';break;case 7:echo'c';break;case 9:echo'd';break;case -12:echo'e';break;default:echo'default';}";
    assert_runtime_equivalent(
        &php,
        optimized_switch_oparray(TableKey::Long(3), false),
        default_original,
        b"default",
    );
    let negative_original: &str = "<?php $value=-12; switch($value){case 1:case 2:echo'a';break;case 4:echo'b';break;case 7:echo'c';break;case 9:echo'd';break;case -12:echo'e';break;default:echo'default';}";
    assert_runtime_equivalent(
        &php,
        optimized_switch_oparray(TableKey::Long(-12), false),
        negative_original,
        b"e",
    );

    let compiler_source: &str = "<?php function long_table($value){switch($value){case 1:case 2:echo'a';break;case 4:echo'b';break;case 7:echo'c';break;case 9:echo'd';break;case -12:echo'e';break;default:echo'default';}} function string_table($value){switch($value){case'one':case'two':echo'a';break;case'four':echo'b';break;case'seven':echo'c';break;case'nine':echo'd';break;case'twelve':echo'e';break;default:echo'default';}}";
    if let Some(dump) = compiler_dump(&php, compiler_source) {
        let long_dispatch: &str = dump
            .lines()
            .find(|line: &&str| line.contains("SWITCH_LONG"))
            .expect("PHP 8.4 must compile six integer cases to SWITCH_LONG");
        for field in ["1:", "2:", "4:", "7:", "9:", "-12:", "default:"] {
            assert!(long_dispatch.contains(field), "{long_dispatch}\n{dump}");
        }
        let string_dispatch: &str = dump
            .lines()
            .find(|line: &&str| line.contains("SWITCH_STRING"))
            .expect("PHP 8.4 must compile six string cases to SWITCH_STRING");
        for field in [
            "\"one\":",
            "\"two\":",
            "\"four\":",
            "\"seven\":",
            "\"nine\":",
            "\"twelve\":",
            "default:",
        ] {
            assert!(string_dispatch.contains(field), "{string_dispatch}\n{dump}");
        }
    }
}

#[test]
fn registered_pass_recovers_case_and_default_at_the_same_target() {
    let Some(php): Option<PhpRuntime> = require_php(
        "PHP 8.4 optimized SWITCH_LONG shared case and default target runtime equivalence",
    ) else {
        return;
    };
    assert!(php.banner.starts_with("PHP 8.4."), "{}", php.banner);

    let original: &str = "<?php $value=3; switch($value){case 1:case 2:default:echo'a';break;case 4:echo'b';break;case 7:echo'c';break;case 9:echo'd';break;case -12:echo'e';break;}";
    let source: String = assert_runtime_equivalent(
        &php,
        retarget_switch_default(
            optimized_switch_oparray(TableKey::Long(3), false),
            op::SWITCH_LONG,
            2,
        ),
        original,
        b"a",
    );
    assert!(
        source.contains("case 1:\n    case 2:\n    default:"),
        "{source}"
    );
}

#[test]
fn registered_pass_recovers_php_84_optimized_match_expression() {
    let Some(php): Option<PhpRuntime> =
        require_php("PHP 8.4 optimized MATCH registered-pass runtime equivalence")
    else {
        return;
    };
    assert!(php.banner.starts_with("PHP 8.4."), "{}", php.banner);

    let input: Artifact = Artifact::new(Rung::Raw, optimized_match_oparray(7), [0x37; 32]);
    let output: Artifact = PHP_PASS
        .run(&input)
        .expect("the registered pass must recover the optimized match");
    let source: String =
        String::from_utf8(output.envelope).expect("the registered pass must emit UTF-8 PHP source");
    let original: &str =
        "<?php $value=7;echo match($value){1,2=>'low',7=>'seven',9=>'nine',default=>'other'};";
    let original_stdout: Vec<u8> = php.stdout_of("optimized match original", original.as_bytes());
    let recovered_stdout: Vec<u8> = php.stdout_of("optimized match recovered", source.as_bytes());
    assert_eq!(original_stdout, b"seven");
    assert_eq!(recovered_stdout, original_stdout, "{source}");
    assert!(source.contains("match ($value)"), "{source}");
    assert!(source.contains("1, 2 => 'low'"), "{source}");
    assert!(source.contains("default => 'other'"), "{source}");
    assert!(!source.contains("unrecovered ZEND_MATCH"), "{source}");

    let mutated_input: Artifact = Artifact::new(Rung::Raw, optimized_match_oparray(9), [0x38; 32]);
    let mutated_output: Artifact = PHP_PASS
        .run(&mutated_input)
        .expect("the registered pass must recover the mutated optimized match");
    let mutated_source: String = String::from_utf8(mutated_output.envelope)
        .expect("the mutated registered pass output must be UTF-8");
    let mutated_stdout: Vec<u8> = php.stdout_of(
        "mutated optimized match recovered",
        mutated_source.as_bytes(),
    );
    assert_eq!(mutated_stdout, b"nine");
    assert_ne!(mutated_source, source);
}

#[test]
fn real_php_emitter_reaches_registered_pass_for_optimized_match() {
    let graded: &str = "PHP 8.4 optimized MATCH emitter to registered-pass runtime equivalence";
    let Some(php): Option<PhpRuntime> = require_php(graded) else {
        return;
    };
    let Some(dll): Option<PathBuf> = opcache_dll(&php) else {
        unmeasured(
            &PHP_OPCACHE,
            graded,
            "the opcache extension was not found beside the PHP 8.4 binary",
        );
        return;
    };
    let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let source_path: PathBuf = root
        .join("corpus")
        .join("php")
        .join("oparray")
        .join("src")
        .join("match_optimized.php");
    let emitter: PathBuf = root
        .join("corpus")
        .join("php")
        .join("oparray")
        .join("emit_dzoa.php");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_match_registered")
            .expect("create registered match scratch directory");
    let dzoa_path: PathBuf = scratch.path().join("match.dzoa");
    let dump_path: PathBuf = scratch.path().join("match.dump");
    let emitted: Output = Command::new(&php.binary)
        .env("DZOA_OPCACHE_DLL", &dll)
        .arg(&emitter)
        .arg(&source_path)
        .arg(&dzoa_path)
        .arg(&dump_path)
        .output()
        .expect("run PHP 8.4 MATCH emitter");
    assert!(
        emitted.status.success(),
        "{}",
        String::from_utf8_lossy(&emitted.stderr)
    );
    let wire: Vec<u8> = std::fs::read(&dzoa_path).expect("read compiler-produced MATCH DZOA");
    let dump: String = std::fs::read_to_string(&dump_path).expect("read MATCH compiler dump");
    assert!(dump.contains("MATCH CV0($value) 1:"), "{dump}");
    assert!(dump.contains("MATCH CV0($value) \"red\":"), "{dump}");
    let input: Artifact = Artifact::new(Rung::Raw, wire, [0x3a; 32]);
    let output: Artifact = PHP_PASS
        .run(&input)
        .expect("the registered pass must recover compiler-produced MATCH DZOA");
    let recovered: String =
        String::from_utf8(output.envelope).expect("registered MATCH output must be UTF-8");
    let original: Vec<u8> =
        std::fs::read(&source_path).expect("read the tracked optimized MATCH source");
    assert_eq!(
        php.stdout_of("compiler MATCH original", &original),
        php.stdout_of("compiler MATCH recovered", recovered.as_bytes()),
        "{recovered}"
    );
    assert!(recovered.matches("match (").count() >= 2, "{recovered}");
    assert!(!recovered.contains("unrecovered ZEND_MATCH"), "{recovered}");
}

#[test]
fn registered_pass_refuses_ambiguous_optimized_match_results_and_joins() {
    for (index, wire) in [
        rewrite_nth_match_arm_result(optimized_match_oparray(7), 1, 1),
        rewrite_nth_match_jump_target(optimized_match_oparray(7), 2, 3),
        rewrite_nth_match_arm_operand_type(optimized_match_oparray(7), 0, T_TMP),
    ]
    .into_iter()
    .enumerate()
    {
        let input: Artifact = Artifact::new(Rung::Raw, wire, [0x39; 32]);
        let output: Artifact = PHP_PASS
            .run(&input)
            .expect("an ambiguous optimized match must produce marked partial source");
        let source: &str =
            std::str::from_utf8(&output.envelope).expect("partial source must remain UTF-8");
        assert!(
            source.contains("unrecovered ZEND_MATCH at op 1"),
            "{source}"
        );
        assert!(
            source.contains("result region is structurally ambiguous"),
            "{source}"
        );
        assert!(!source.contains("match ($value)"), "{source}");
        assert!(
            !source.contains("echo 'seven'"),
            "mutation {index}\n{source}"
        );
        assert!(
            !source.contains("echo 'other'"),
            "mutation {index}\n{source}"
        );
    }
}

#[test]
fn registered_pass_refuses_ambiguous_optimized_switch_targets() {
    let wire: Vec<u8> = retarget_long(optimized_switch_oparray(TableKey::Long(4), false), 4, 4, 1);
    let input: Artifact = Artifact::new(Rung::Raw, wire, [0x5c; 32]);
    let output: Artifact = PHP_PASS
        .run(&input)
        .expect("a structurally ambiguous table must produce marked partial source");
    let source: &str =
        std::str::from_utf8(&output.envelope).expect("partial source must remain UTF-8");
    assert!(
        source.contains("unrecovered ZEND_SWITCH_LONG at op 1"),
        "{source}"
    );
    assert!(source.contains("structurally ambiguous"), "{source}");
    assert!(!source.contains("switch ($value)"), "{source}");
}

#[test]
fn v3_switch_table_count_is_bounded_before_entry_allocation() {
    let wire: Vec<u8> =
        overwrite_long_table_count(optimized_switch_oparray(TableKey::Long(4), false), 65_537);
    let error: Error = parse_oparray(&wire).expect_err("an oversized table must fail parsing");
    assert!(
        matches!(
            error,
            Error::OpArrayFieldOversize {
                field: "switch_table",
                value: 65_537,
                cap: 65_536
            }
        ),
        "{error}"
    );
}

#[test]
fn registered_pass_rejects_a_truncated_oparray_with_the_parser_code() {
    let bytes: &[u8] = b"DZOA\x02";
    Detector::detect(&PhpDetectorImpl, &context(bytes))
        .expect("the detector must route a truncated DZOA container to its bounded parser");
    let input: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0x3c; 32]);
    let error: CoreError = PHP_PASS
        .run(&input)
        .expect_err("a truncated DZOA container must be refused");

    assert!(
        error.to_string().contains("DR-PHP-0092"),
        "unexpected error: {error}"
    );
}

#[test]
fn registered_pass_recovers_generator_yield_and_delegation() {
    let verdict: DetectVerdict = Detector::detect(&PhpDetectorImpl, &context(GENERATOR_DZOA))
        .expect("the registered PHP detector must recognize the generator op array");
    assert_eq!(verdict.pass_id, "php.peel");
    assert_eq!(verdict.format_tag, "php-oparray");

    let input: Artifact = Artifact::new(Rung::Raw, GENERATOR_DZOA.to_vec(), [0x73; 32]);
    let output: Artifact = PHP_PASS
        .run(&input)
        .expect("the registered pass must recover the generator op array");
    let source: &str =
        std::str::from_utf8(&output.envelope).expect("recovered source must be UTF-8");

    assert_eq!(output.rung, Rung::Surface);
    assert!(source.contains("yield 'first';"), "{source}");
    assert!(source.contains("yield 'label' => 'keyed';"), "{source}");
    assert!(source.contains("yield from $items;"), "{source}");
}

#[test]
fn chain_detector_requires_exact_leading_magic_and_keeps_container_precedence() {
    let near_miss: DetectVerdict = Detector::detect(&PhpDetectorImpl, &context(b"DZOX<?php"))
        .expect("the embedded PHP source remains detectable");
    assert_eq!(near_miss.format_tag, "php-source");
    let verdict: DetectVerdict = Detector::detect(&PhpDetectorImpl, &context(b"DZOA<?php"))
        .expect("leading DZOA must take precedence over an embedded PHP tag");
    assert_eq!(verdict.format_tag, "php-oparray");
    assert!(Detector::detect(&PhpDetectorImpl, &context(b"DZOX payload")).is_none());
}
