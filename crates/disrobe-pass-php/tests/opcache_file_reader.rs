#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::redundant_pub_crate,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

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
    Error, Literal, Op, OpArray, OpArrayKind, OperandType, parse_oparray, parse_opcache_file,
};
use disrobe_testkit::authorized_authored_source;
use php_toolchain::{
    PHP_OPCACHE, PhpRuntime, compile_opcache_image, corpus_path, opcache_extension, require_php,
    unmeasured, write_opcache_source,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SAMPLES: [&str; 25] = [
    "arithmetic",
    "closure_bodies",
    "closures",
    "control_flow",
    "do_while",
    "dynamic_members",
    "functions",
    "generators",
    "goto_forward",
    "goto_shapes",
    "interpolation",
    "keyed_foreach",
    "match_optimized",
    "members",
    "nullsafe",
    "nullsafe_calls",
    "objects",
    "references",
    "spaceship",
    "switch_linear",
    "switch_optimized",
    "type_checks",
    "unset_cv",
    "variable_variable",
    "versioned",
];

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

struct Toolchain {
    php: PhpRuntime,
    opcache: PathBuf,
}

fn toolchain(graded: &str) -> Option<Toolchain> {
    let php: PhpRuntime = require_php(graded)?;
    let Some(opcache): Option<PathBuf> = opcache_extension(&php) else {
        unmeasured(
            &PHP_OPCACHE,
            graded,
            "the opcache extension was not found beside the php binary",
        );
        return None;
    };
    Some(Toolchain { php, opcache })
}

fn emit_dzoa(toolchain: &Toolchain, source: &Path, out: &Path) -> OpArray {
    let emitter: PathBuf =
        authorized_authored_source(&workspace_root(), "corpus/php/oparray/emit_dzoa.php")
            .expect("authorize the tracked PHP opcache emitter");
    let output: Output = Command::new(&toolchain.php.binary)
        .env("DZOA_OPCACHE_DLL", &toolchain.opcache)
        .env("DZOA_AFTER_OPTIMIZER", "1")
        .arg(&emitter)
        .arg(source)
        .arg(out)
        .output()
        .expect("start the opcache dump emitter");
    assert!(
        output.status.success(),
        "the opcache dump emitter failed on {}: {}",
        source.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_oparray(&std::fs::read(out).expect("read the emitted op array"))
        .expect("parse the emitted op array")
}

fn same_literal(dump: &Literal, image: &Literal) -> bool {
    match (dump, image) {
        (Literal::Double(printed), Literal::Double(exact)) => {
            let scale: f64 = exact.abs().max(printed.abs()).max(f64::MIN_POSITIVE);
            (printed - exact).abs() <= scale * 1e-5
        }
        (Literal::Array(_), Literal::Values(_)) => true,
        (Literal::SwitchLong(entries), Literal::MatchTable(table)) => {
            entries.len() == table.len()
                && entries
                    .iter()
                    .zip(table)
                    .all(|((key, target), (image_key, image_target))| {
                        *image_key == Literal::Long(*key) && target == image_target
                    })
        }
        (Literal::SwitchString(entries), Literal::MatchTable(table)) => {
            entries.len() == table.len()
                && entries
                    .iter()
                    .zip(table)
                    .all(|((key, target), (image_key, image_target))| {
                        *image_key == Literal::Str(key.clone()) && target == image_target
                    })
        }
        (Literal::Str(printed), Literal::Str(exact)) => {
            printed == exact || *printed == exact.replace("\r\n", "\n")
        }
        _ => dump == image,
    }
}

fn operand_matches(
    dump: &OpArray,
    image: &OpArray,
    ty: OperandType,
    dump_value: u32,
    image_value: u32,
) -> bool {
    if ty != OperandType::Const {
        return dump_value == image_value;
    }
    match (
        dump.literals.get(dump_value as usize),
        image.literals.get(image_value as usize),
    ) {
        (Some(left), Some(right)) => same_literal(left, right),
        _ => false,
    }
}

fn extended_value_matches(dump: &Op, image: &Op) -> bool {
    if dump.extended_value == image.extended_value {
        return true;
    }
    match dump.opcode {
        op::RETURN => dump.extended_value == 0 && image.extended_value == u32::MAX,
        op::BIND_LEXICAL => dump.extended_value == 0 && image.extended_value == 2,
        _ => false,
    }
}

fn compare_op_array(label: &str, dump: &OpArray, image: &OpArray, failures: &mut Vec<String>) {
    if dump.num_args != image.num_args {
        failures.push(format!(
            "{label}: num_args {} from the dump, {} from the image",
            dump.num_args, image.num_args
        ));
    }
    if dump.try_catch != image.try_catch {
        failures.push(format!(
            "{label}: try/catch table {:?} from the dump, {:?} from the image",
            dump.try_catch, image.try_catch
        ));
    }
    for (slot, name) in dump.var_names.iter().enumerate() {
        if name.is_some() && image.var_names.get(slot) != Some(name) {
            failures.push(format!(
                "{label}: CV{slot} is {name:?} in the dump, {:?} in the image",
                image.var_names.get(slot)
            ));
        }
    }
    if dump.ops.len() != image.ops.len() {
        failures.push(format!(
            "{label}: {} ops from the dump, {} from the image",
            dump.ops.len(),
            image.ops.len()
        ));
        return;
    }
    for (index, (left, right)) in dump.ops.iter().zip(&image.ops).enumerate() {
        if left.opcode == op::BIND_STATIC && right.opcode == op::NOP && left.extended_value == 0 {
            continue;
        }
        let declared_key: bool =
            matches!(left.opcode, op::DECLARE_CLASS | op::DECLARE_CLASS_DELAYED)
                && right.op1_type == OperandType::Const
                && operand_matches(
                    dump,
                    image,
                    OperandType::Const,
                    left.op1,
                    right.op1.wrapping_sub(1),
                );
        let moved_constant: bool = left.opcode == op::FETCH_CONSTANT
            && left.op1_type == OperandType::Const
            && right.op1_type == OperandType::Unused
            && right.op2_type == OperandType::Const
            && operand_matches(dump, image, OperandType::Const, left.op1, right.op2);
        if declared_key || moved_constant {
            continue;
        }
        let same: bool = left.opcode == right.opcode
            && left.op1_type == right.op1_type
            && left.op2_type == right.op2_type
            && left.result_type == right.result_type
            && operand_matches(dump, image, left.op1_type, left.op1, right.op1)
            && operand_matches(dump, image, left.op2_type, left.op2, right.op2)
            && left.result == right.result
            && extended_value_matches(left, right);
        if !same {
            failures.push(format!(
                "{label} op {index}: dump {left:?} image {right:?} (dump op1 {:?} op2 {:?}, image op1 {:?} op2 {:?})",
                (left.op1_type == OperandType::Const)
                    .then(|| dump.literals.get(left.op1 as usize))
                    .flatten(),
                (left.op2_type == OperandType::Const)
                    .then(|| dump.literals.get(left.op2 as usize))
                    .flatten(),
                (right.op1_type == OperandType::Const)
                    .then(|| image.literals.get(right.op1 as usize))
                    .flatten(),
                (right.op2_type == OperandType::Const)
                    .then(|| image.literals.get(right.op2 as usize))
                    .flatten(),
            ));
        }
    }
    let dump_closures: Vec<&OpArray> = dump
        .children
        .iter()
        .filter(|child: &&OpArray| child.kind == OpArrayKind::Closure)
        .collect();
    let image_closures: Vec<&OpArray> = image
        .children
        .iter()
        .filter(|child: &&OpArray| child.kind == OpArrayKind::Closure)
        .collect();
    if dump_closures.len() != image_closures.len() {
        failures.push(format!(
            "{label}: {} closures in the dump, {} in the image",
            dump_closures.len(),
            image_closures.len()
        ));
        return;
    }
    for (ordinal, (left, right)) in dump_closures.iter().zip(&image_closures).enumerate() {
        compare_op_array(&format!("{label} closure {ordinal}"), left, right, failures);
    }
}

fn compare_script(sample: &str, dump: &OpArray, image: &OpArray) -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    compare_op_array(&format!("{sample} main"), dump, image, &mut failures);
    for child in &dump.children {
        let label: String = format!(
            "{sample} {}::{}",
            child.class_name.as_deref().unwrap_or(""),
            child.name.as_deref().unwrap_or("")
        );
        let counterpart: Option<&OpArray> = match child.kind {
            OpArrayKind::Function => image.children.iter().find(|candidate: &&OpArray| {
                candidate.kind == OpArrayKind::Function && candidate.name == child.name
            }),
            OpArrayKind::Method => image
                .classes
                .iter()
                .filter(|class| Some(&class.name) == child.class_name.as_ref())
                .flat_map(|class| class.methods.iter())
                .find(|method: &&OpArray| method.name == child.name),
            OpArrayKind::Closure | OpArrayKind::Main => continue,
        };
        match counterpart {
            Some(counterpart) => compare_op_array(&label, child, counterpart, &mut failures),
            None => failures.push(format!("{label}: absent from the image")),
        }
    }
    failures
}

#[test]
fn the_file_cache_reader_agrees_with_the_opcache_dump_on_every_oparray_sample() {
    let graded: &str = "the opcache file-cache reader against the opcache opcode dump";
    let Some(toolchain): Option<Toolchain> = toolchain(graded) else {
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_opcache_reader")
            .expect("create the reader scratch directory");
    let mut failures: Vec<String> = Vec::new();
    for sample in SAMPLES {
        let source: Vec<u8> = std::fs::read(corpus_path(&format!("oparray/src/{sample}.php")))
            .expect("read the tracked op array sample");
        let staged: PathBuf = scratch.path().join(format!("{sample}.php"));
        write_opcache_source(&staged, &source).expect("stage the sample");
        let dump: OpArray = emit_dzoa(
            &toolchain,
            &staged,
            &scratch.path().join(format!("{sample}.dzoa")),
        );
        let bytes: Vec<u8> = compile_opcache_image(
            &toolchain.php,
            &toolchain.opcache,
            &source,
            scratch.path(),
            sample,
        )
        .unwrap_or_else(|defect: String| panic!("{sample}: {defect}"));
        let image: OpArray = parse_opcache_file(&bytes).unwrap_or_else(|error: Error| {
            panic!("{sample}: the file-cache image did not parse: {error}")
        });
        failures.extend(compare_script(sample, &dump, &image));
    }
    assert!(
        failures.is_empty(),
        "the file-cache reader disagrees with the opcache dump in {} places:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn reseal(image: &mut [u8]) {
    let mem_size: usize = u64::from_le_bytes(image[40..48].try_into().unwrap()) as usize;
    let str_size: usize = u64::from_le_bytes(image[48..56].try_into().unwrap()) as usize;
    let mut body: Vec<u8> = image[80..80 + mem_size].to_vec();
    body.extend_from_slice(&image[80 + mem_size..80 + mem_size + str_size]);
    let checksum: u32 = adler32(&body);
    image[72..76].copy_from_slice(&checksum.to_le_bytes());
}

#[test]
fn a_mutated_file_cache_image_is_a_typed_error_or_a_bounded_parse() {
    let graded: &str = "the opcache file-cache reader against mutated real images";
    let Some(toolchain): Option<Toolchain> = toolchain(graded) else {
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_opcache_mutation")
            .expect("create the mutation scratch directory");
    let source: Vec<u8> = std::fs::read(corpus_path("oparray/src/closure_bodies.php"))
        .expect("read the tracked op array sample");
    let pristine: Vec<u8> = compile_opcache_image(
        &toolchain.php,
        &toolchain.opcache,
        &source,
        scratch.path(),
        "closure_bodies",
    )
    .unwrap_or_else(|defect: String| panic!("{defect}"));
    parse_opcache_file(&pristine).expect("the pristine image parses");
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rejected: usize = 0;
    for _ in 0..4096 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut image: Vec<u8> = pristine.clone();
        let position: usize = 80 + (state >> 33) as usize % (image.len() - 80);
        image[position] ^= 1 << ((state >> 29) % 8);
        reseal(&mut image);
        if parse_opcache_file(&image).is_err() {
            rejected += 1;
        }
    }
    assert!(
        rejected > 0,
        "no single-bit mutation of a real image was rejected, so the reader validates nothing"
    );
    for cut in [0, 7, 79, 80, pristine.len() / 2, pristine.len() - 1] {
        assert!(
            parse_opcache_file(&pristine[..cut]).is_err(),
            "an image truncated to {cut} bytes must be a typed error"
        );
    }
    let mut unsealed: Vec<u8> = pristine.clone();
    let last: usize = unsealed.len() - 1;
    unsealed[last] ^= 0x40;
    assert!(
        matches!(
            parse_opcache_file(&unsealed),
            Err(Error::OpcacheChecksum { .. })
        ),
        "a byte changed without resealing must fail the checksum"
    );
}
