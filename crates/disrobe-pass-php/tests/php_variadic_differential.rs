#![allow(clippy::expect_used, clippy::panic)]

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use disrobe_pass_php::decompile::op;
use disrobe_pass_php::{
    Decompilation, Literal, Op, OpArray, OperandType, RecoveryReport, RecoveryStage,
    decompile_oparray, parse_oparray, recover_php,
};
use php_toolchain::{PHP, PhpRun, ToolchainRequirement, require_with_requirement};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const VARIADIC_DZOA: &[u8] = include_bytes!("fixtures/oparray_variadic/variadic.dzoa");
const VARIADIC_SOURCE: &[u8] = include_bytes!("fixtures/oparray_variadic/variadic.php");
const RECV_VARIADIC: u8 = 164;
const SEND_UNPACK: u8 = 165;
const CHECK_UNDEF_ARGS: u8 = 199;

fn opcache_dll(php: &php_toolchain::PhpRuntime) -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("DZOA_OPCACHE_DLL") {
        let path: PathBuf = PathBuf::from(configured);
        return path.is_file().then_some(path);
    }
    let resolved: PathBuf = if php
        .binary
        .parent()
        .is_some_and(|parent: &Path| !parent.as_os_str().is_empty())
    {
        php.binary.clone()
    } else {
        let output: Output = bounded_command_output(
            Command::new(&php.binary).args(["-r", "echo PHP_BINARY;"]),
            "resolve the PHP 8.4 executable",
        );
        if !output.status.success() {
            return None;
        }
        PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let directory: &Path = resolved.parent()?;
    ["ext/php_opcache.dll", "php_opcache.dll", "ext/opcache.so"]
        .into_iter()
        .map(|relative: &str| directory.join(relative))
        .find(|candidate: &PathBuf| candidate.is_file())
}

fn bounded_command_output(command: &mut Command, label: &str) -> Output {
    let mut child: Child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    let deadline: Instant = Instant::now() + Duration::from_secs(45);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().expect("collect emitter output"),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                child.kill().expect("terminate a timed-out emitter");
                let output: Output = child.wait_with_output().expect("collect timed-out output");
                panic!(
                    "{label} exceeded 45 seconds: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(error) => panic!("wait for the tracked PHP op array emitter: {error}"),
        }
    }
}

#[test]
fn tracked_variadic_op_array_reproduces_from_php_84() {
    let runtime = require_with_requirement(
        &PHP,
        "the tracked variadic op array against PHP 8.4",
        ToolchainRequirement::Mandatory,
    )
    .expect("PHP 8.4 is required to regenerate the tracked variadic op array");
    assert!(
        runtime.banner.starts_with("PHP 8.4."),
        "the reference must be PHP 8.4, found {}",
        runtime.banner
    );
    let dll: PathBuf = opcache_dll(&runtime)
        .expect("the PHP 8.4 opcache extension is required to regenerate the tracked op array");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_variadic_reemit")
            .expect("create the variadic re-emission directory");
    let produced: PathBuf = scratch.path().join("variadic.dzoa");
    let repository: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let emitter: PathBuf = repository
        .join("corpus")
        .join("php")
        .join("oparray")
        .join("emit_dzoa.php");
    let source: PathBuf = repository
        .join("crates")
        .join("disrobe-pass-php")
        .join("tests")
        .join("fixtures")
        .join("oparray_variadic")
        .join("variadic.php");
    let output: Output = bounded_command_output(
        Command::new(&runtime.binary)
            .env("DZOA_OPCACHE_DLL", &dll)
            .arg(emitter)
            .arg(source)
            .arg(&produced),
        "regenerate the tracked PHP variadic op array",
    );
    assert!(
        output.status.success(),
        "the tracked emitter failed under {}: {}",
        runtime.banner,
        String::from_utf8_lossy(&output.stderr)
    );
    let fresh: Vec<u8> = std::fs::read(produced).expect("read the regenerated variadic op array");
    assert_eq!(
        fresh, VARIADIC_DZOA,
        "the tracked variadic op array no longer reproduces from its PHP 8.4 source"
    );
}

fn opcode_sites(node: &OpArray, container: &str) -> Vec<String> {
    let mut sites: Vec<String> = node
        .ops
        .iter()
        .enumerate()
        .filter(|(_, op): &(usize, &Op)| {
            matches!(op.opcode, RECV_VARIADIC | SEND_UNPACK | CHECK_UNDEF_ARGS)
        })
        .map(|(index, op): (usize, &Op)| format!("{container}#{index}:{}", op.opcode))
        .collect();
    for child in &node.children {
        let label: &str = child.name.as_deref().unwrap_or("{closure}");
        sites.extend(opcode_sites(child, label));
    }
    sites
}

#[test]
fn malformed_variadic_container_shapes_are_named_refusals() {
    let parsed: OpArray = parse_oparray(VARIADIC_DZOA).expect("parse tracked PHP 8.4 DZOA");

    let mut bad_receive: OpArray = parsed.clone();
    let receive: &mut Op = bad_receive
        .children
        .iter_mut()
        .flat_map(|child: &mut OpArray| child.ops.iter_mut())
        .find(|op: &&mut Op| op.opcode == RECV_VARIADIC)
        .expect("tracked fixture must carry RECV_VARIADIC");
    receive.op1 = 0;
    let receive_result: Decompilation = decompile_oparray(&bad_receive);
    assert!(receive_result.unrecovered.iter().any(|entry| {
        entry.opcode == RECV_VARIADIC
            && entry.reason
                == "the variadic receive does not name the cv immediately after the fixed parameters"
    }));

    let mut overflow_receive: OpArray = parsed.clone();
    overflow_receive.children[0].num_args = u32::MAX;
    let overflow_result: Decompilation = decompile_oparray(&overflow_receive);
    assert!(overflow_result.unrecovered.iter().any(|entry| {
        entry.opcode == RECV_VARIADIC
            && entry.reason
                == "the variadic receive does not name the cv immediately after the fixed parameters"
    }));

    let mut bad_unpack: OpArray = parsed.clone();
    let unpack: &mut Op = bad_unpack
        .ops
        .iter_mut()
        .find(|op: &&mut Op| op.opcode == SEND_UNPACK)
        .expect("tracked fixture must carry SEND_UNPACK");
    unpack.op2 = 1;
    let unpack_result: Decompilation = decompile_oparray(&bad_unpack);
    assert!(unpack_result.unrecovered.iter().any(|entry| {
        entry.opcode == SEND_UNPACK
            && entry.reason
                == "the call argument order, container evidence, or bounded render shape is invalid"
    }));

    let mut bad_position: OpArray = parsed;
    let positional: &mut Op = bad_position
        .ops
        .iter_mut()
        .find(|op: &&mut Op| op.opcode == op::SEND_VAL && op.op2_type == OperandType::Unused)
        .expect("tracked fixture must carry a positional SEND_VAL");
    positional.op2 = 99;
    let position_result: Decompilation = decompile_oparray(&bad_position);
    assert!(position_result.unrecovered.iter().any(|entry| {
        entry.opcode == op::SEND_VAL
            && entry.reason
                == "the call argument order, container evidence, or bounded render shape is invalid"
    }));

    let mut bad_name: OpArray = parse_oparray(VARIADIC_DZOA).expect("parse tracked PHP 8.4 DZOA");
    let non_string: u32 = bad_name
        .literals
        .iter()
        .position(|literal: &Literal| matches!(literal, Literal::Long(_)))
        .and_then(|index: usize| u32::try_from(index).ok())
        .expect("tracked fixture must carry an integer literal");
    let named: &mut Op = bad_name
        .ops
        .iter_mut()
        .find(|op: &&mut Op| op.opcode == op::SEND_VAR && op.op2_type == OperandType::Const)
        .expect("tracked fixture must carry a named SEND_VAR");
    named.op2 = non_string;
    let name_result: Decompilation = decompile_oparray(&bad_name);
    assert!(name_result.unrecovered.iter().any(|entry| {
        entry.opcode == op::SEND_VAR
            && entry.reason
                == "the named call argument has no literal php identifier in this op array"
    }));
}

#[test]
fn php_84_variadic_calls_reach_the_registered_recovery_route() {
    let parsed: OpArray = parse_oparray(VARIADIC_DZOA).expect("parse tracked PHP 8.4 DZOA");
    let sites: Vec<String> = opcode_sites(&parsed, "$_main");
    assert_eq!(
        sites,
        [
            "$_main#4:199",
            "$_main#8:165",
            "$_main#9:199",
            "$_main#24:199",
            "collect_args#1:164",
        ]
    );

    let report: RecoveryReport =
        recover_php(VARIADIC_DZOA, None).expect("recover tracked PHP 8.4 DZOA");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    assert!(
        report
            .output
            .contains("function collect_args($first, ...$rest)"),
        "recovered output: {}",
        report.output
    );
    assert!(
        report.output.contains("collect_args(...$spread)"),
        "recovered output: {}",
        report.output
    );
    assert!(
        report
            .output
            .contains("collect_args(bonus: mark('B', 'named'), first: mark('F', 'zero'))"),
        "recovered output: {}",
        report.output
    );
    let decompilation: &Decompilation = report
        .decompilation
        .as_ref()
        .expect("the registered route must retain its decompilation report");
    assert!(
        decompilation
            .unrecovered
            .iter()
            .all(|entry| !matches!(entry.opcode, RECV_VARIADIC | SEND_UNPACK | CHECK_UNDEF_ARGS)),
        "variadic opcodes were refused: {:?}",
        decompilation.unrecovered
    );
    assert!(decompilation.limitations.iter().any(|entry| {
        entry.opcode == RECV_VARIADIC
            && entry.note
                == "the op array does not carry parameter metadata, so a by-value variadic parameter and a by-reference variadic parameter are indistinguishable"
    }));
}

#[test]
fn recovered_variadic_calls_match_php_84_and_fail_the_perturbation() {
    let runtime = require_with_requirement(
        &PHP,
        "PHP 8.4 variadic call recovery",
        ToolchainRequirement::Mandatory,
    )
    .expect("PHP 8.4 is a required reference for the variadic behavioral grade");
    assert!(
        runtime.banner.starts_with("PHP 8.4."),
        "the reference must be PHP 8.4, found {}",
        runtime.banner
    );
    let original: PhpRun = runtime.run("original PHP 8.4 variadic source", VARIADIC_SOURCE);
    assert!(
        original.exited_clean,
        "original stderr: {}",
        original.stderr
    );
    assert_eq!(
        original.stdout,
        b"[\"one\",{\"bonus\":\"three\"}]\nBF[\"zero\",{\"bonus\":\"named\"}]\n"
    );

    let recovered: RecoveryReport =
        recover_php(VARIADIC_DZOA, None).expect("recover tracked PHP 8.4 DZOA");
    let measured: PhpRun = runtime.run(
        "recovered PHP 8.4 variadic source",
        recovered.output.as_bytes(),
    );
    assert!(
        measured.exited_clean,
        "recovered stderr: {}",
        measured.stderr
    );
    assert_eq!(
        measured.stdout, original.stdout,
        "behavioral grade: 0/2 calls"
    );

    let mutants: [(&str, String); 4] = [
        (
            "unpacked call",
            recovered.output.replacen("...$spread", "$spread", 1),
        ),
        (
            "variadic declaration",
            recovered.output.replacen("...$rest", "$rest", 1),
        ),
        (
            "named argument identity",
            recovered.output.replacen("bonus: mark", "other: mark", 1),
        ),
        (
            "named argument order",
            recovered.output.replacen(
                "bonus: mark('B', 'named'), first: mark('F', 'zero')",
                "first: mark('F', 'zero'), bonus: mark('B', 'named')",
                1,
            ),
        ),
    ];
    for (label, mutant) in mutants {
        assert_ne!(mutant, recovered.output, "{label} mutant did not apply");
        let perturbed: PhpRun = runtime.run(label, mutant.as_bytes());
        assert!(
            !perturbed.exited_clean || perturbed.stdout != original.stdout,
            "{label} mutant must fail the behavioral grade"
        );
    }
}
