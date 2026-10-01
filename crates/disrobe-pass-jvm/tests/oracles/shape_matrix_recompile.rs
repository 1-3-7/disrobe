#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};

const OP_JSR: u8 = 0xA8;
const UNRESOLVED_INDY: &str = "/* unresolved invokedynamic via ";
const INCOMPLETE_MARKER: &str = "// <decompile: incomplete: ";

#[derive(Clone, Copy, Debug)]
enum Compiler {
    Javac,
    Ecj16,
    Ecj14,
}

struct Shape {
    probe: (&'static str, &'static str),
    driver: (&'static str, &'static str),
}

const FOLD: Shape = Shape {
    probe: (
        "FoldProbe.java",
        include_str!("../fixtures/shape_matrix/FoldProbe.java"),
    ),
    driver: (
        "FoldDriver.java",
        include_str!("../fixtures/shape_matrix/FoldDriver.java"),
    ),
};

const FALL_THROUGH: Shape = Shape {
    probe: (
        "FallThroughProbe.java",
        include_str!("../fixtures/shape_matrix/FallThroughProbe.java"),
    ),
    driver: (
        "FallThroughDriver.java",
        include_str!("../fixtures/shape_matrix/FallThroughDriver.java"),
    ),
};

const STATE_MACHINE: Shape = Shape {
    probe: (
        "StateMachineProbe.java",
        include_str!("../fixtures/shape_matrix/StateMachineProbe.java"),
    ),
    driver: (
        "StateMachineDriver.java",
        include_str!("../fixtures/shape_matrix/StateMachineDriver.java"),
    ),
};

const DISPATCH: Shape = Shape {
    probe: (
        "DispatchProbe.java",
        include_str!("../fixtures/shape_matrix/DispatchProbe.java"),
    ),
    driver: (
        "DispatchDriver.java",
        include_str!("../fixtures/shape_matrix/DispatchDriver.java"),
    ),
};

const RELAY: Shape = Shape {
    probe: (
        "RelayProbe.java",
        include_str!("../fixtures/shape_matrix/RelayProbe.java"),
    ),
    driver: (
        "RelayDriver.java",
        include_str!("../fixtures/shape_matrix/RelayDriver.java"),
    ),
};

const LONG_COMPARE: Shape = Shape {
    probe: (
        "LongCompareProbe.java",
        include_str!("../fixtures/shape_matrix/LongCompareProbe.java"),
    ),
    driver: (
        "LongCompareDriver.java",
        include_str!("../fixtures/shape_matrix/LongCompareDriver.java"),
    ),
};

const NAN_COMPARE: Shape = Shape {
    probe: (
        "NanCompareProbe.java",
        include_str!("../fixtures/shape_matrix/NanCompareProbe.java"),
    ),
    driver: (
        "NanCompareDriver.java",
        include_str!("../fixtures/shape_matrix/NanCompareDriver.java"),
    ),
};

const RECORD: Shape = Shape {
    probe: (
        "RecordProbe.java",
        include_str!("../fixtures/shape_matrix/RecordProbe.java"),
    ),
    driver: (
        "RecordDriver.java",
        include_str!("../fixtures/shape_matrix/RecordDriver.java"),
    ),
};

const TYPE_SWITCH: Shape = Shape {
    probe: (
        "TypeSwitchProbe.java",
        include_str!("../fixtures/shape_matrix/TypeSwitchProbe.java"),
    ),
    driver: (
        "TypeSwitchDriver.java",
        include_str!("../fixtures/shape_matrix/TypeSwitchDriver.java"),
    ),
};

const LOOP_HEADER: Shape = Shape {
    probe: (
        "LoopHeaderProbe.java",
        include_str!("../fixtures/loop_coverage/LoopHeaderProbe.java"),
    ),
    driver: (
        "LoopHeaderDriver.java",
        include_str!("../fixtures/loop_coverage/LoopHeaderDriver.java"),
    ),
};

const SYNC_LOOP: Shape = Shape {
    probe: (
        "SyncLoopProbe.java",
        include_str!("../fixtures/loop_coverage/SyncLoopProbe.java"),
    ),
    driver: (
        "SyncLoopDriver.java",
        include_str!("../fixtures/loop_coverage/SyncLoopDriver.java"),
    ),
};

const JSR_FINALLY: Shape = Shape {
    probe: (
        "FinallyProbe.java",
        include_str!("../fixtures/ecj_jsr/FinallyProbe.java"),
    ),
    driver: (
        "FinallyDriver.java",
        include_str!("../fixtures/shape_matrix/FinallyDriver.java"),
    ),
};

const TERNARY: Shape = Shape {
    probe: (
        "TernaryProbe.java",
        include_str!("../fixtures/shape_matrix/TernaryProbe.java"),
    ),
    driver: (
        "TernaryDriver.java",
        include_str!("../fixtures/shape_matrix/TernaryDriver.java"),
    ),
};

const SWITCH_EXIT: Shape = Shape {
    probe: (
        "SwitchExitProbe.java",
        include_str!("../fixtures/shape_matrix/SwitchExitProbe.java"),
    ),
    driver: (
        "SwitchExitDriver.java",
        include_str!("../fixtures/shape_matrix/SwitchExitDriver.java"),
    ),
};

const INCREMENT: Shape = Shape {
    probe: (
        "IncrementProbe.java",
        include_str!("../fixtures/shape_matrix/IncrementProbe.java"),
    ),
    driver: (
        "IncrementDriver.java",
        include_str!("../fixtures/shape_matrix/IncrementDriver.java"),
    ),
};

const TYPE_SWITCH_BLOCK: Shape = Shape {
    probe: (
        "TypeSwitchBlockProbe.java",
        include_str!("../fixtures/shape_matrix/TypeSwitchBlockProbe.java"),
    ),
    driver: (
        "TypeSwitchBlockDriver.java",
        include_str!("../fixtures/shape_matrix/TypeSwitchBlockDriver.java"),
    ),
};

const JSR_SHAPES: Shape = Shape {
    probe: (
        "JsrShapesProbe.java",
        include_str!("../fixtures/shape_matrix/JsrShapesProbe.java"),
    ),
    driver: (
        "JsrShapesDriver.java",
        include_str!("../fixtures/shape_matrix/JsrShapesDriver.java"),
    ),
};

const FINALLY_JOIN: Shape = Shape {
    probe: (
        "FinallyJoinProbe.java",
        include_str!("../fixtures/shape_matrix/FinallyJoinProbe.java"),
    ),
    driver: (
        "FinallyJoinDriver.java",
        include_str!("../fixtures/shape_matrix/FinallyJoinDriver.java"),
    ),
};

const FINALLY_EXIT: Shape = Shape {
    probe: (
        "FinallyExitProbe.java",
        include_str!("../fixtures/shape_matrix/FinallyExitProbe.java"),
    ),
    driver: (
        "FinallyExitDriver.java",
        include_str!("../fixtures/shape_matrix/FinallyExitDriver.java"),
    ),
};

const COMPOUND_TERNARY: Shape = Shape {
    probe: (
        "CompoundTernaryProbe.java",
        include_str!("../fixtures/shape_matrix/CompoundTernaryProbe.java"),
    ),
    driver: (
        "CompoundTernaryDriver.java",
        include_str!("../fixtures/shape_matrix/CompoundTernaryDriver.java"),
    ),
};

const FLAG_VALUE: Shape = Shape {
    probe: (
        "FlagValueProbe.java",
        include_str!("../fixtures/shape_matrix/FlagValueProbe.java"),
    ),
    driver: (
        "FlagValueDriver.java",
        include_str!("../fixtures/shape_matrix/FlagValueDriver.java"),
    ),
};

const NULL_LOCAL: Shape = Shape {
    probe: (
        "NullLocalProbe.java",
        include_str!("../fixtures/shape_matrix/NullLocalProbe.java"),
    ),
    driver: (
        "NullLocalDriver.java",
        include_str!("../fixtures/shape_matrix/NullLocalDriver.java"),
    ),
};

const FINALLY_BRANCH_EXIT: Shape = Shape {
    probe: (
        "FinallyBranchExitProbe.java",
        include_str!("../fixtures/shape_matrix/FinallyBranchExitProbe.java"),
    ),
    driver: (
        "FinallyBranchExitDriver.java",
        include_str!("../fixtures/shape_matrix/FinallyBranchExitDriver.java"),
    ),
};

const SLOT_REUSE: Shape = Shape {
    probe: (
        "SlotReuseProbe.java",
        include_str!("../fixtures/shape_matrix/SlotReuseProbe.java"),
    ),
    driver: (
        "SlotReuseDriver.java",
        include_str!("../fixtures/shape_matrix/SlotReuseDriver.java"),
    ),
};

fn find_on_path(name: &str) -> PathBuf {
    let path_var: std::ffi::OsString = std::env::var_os("PATH").expect("PATH is set");
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    std::env::split_paths(&path_var)
        .flat_map(|dir: PathBuf| {
            exts.iter()
                .map(move |ext: &&str| dir.join(format!("{name}{ext}")))
        })
        .find(|candidate: &PathBuf| candidate.is_file())
        .unwrap_or_else(|| {
            panic!("the JDK is on PATH in every CI job that runs these tests: {name} not on PATH")
        })
}

fn ecj_jar() -> PathBuf {
    let jar: PathBuf = std::env::var_os("DISROBE_ECJ_JAR").map_or_else(
        || {
            panic!(
                "DISROBE_ECJ_JAR must name the Eclipse compiler jar (ecj-3.26.0.jar, \
                 https://repo1.maven.org/maven2/org/eclipse/jdt/ecj/3.26.0/ecj-3.26.0.jar)"
            )
        },
        PathBuf::from,
    );
    assert!(
        jar.is_file(),
        "DISROBE_ECJ_JAR names {}, which is not a file",
        jar.display()
    );
    jar
}

fn ecj(level: &[&str]) -> Command {
    let mut command: Command = Command::new(find_on_path("java"));
    command.arg("-jar").arg(ecj_jar()).args(level);
    command
}

fn compile(compiler: Compiler, dir: &Path, sources: &[(&str, &str)]) -> Result<(), String> {
    let mut cmd: Command = match compiler {
        Compiler::Javac => Command::new(find_on_path("javac")),
        Compiler::Ecj16 => ecj(&["-16"]),
        Compiler::Ecj14 => ecj(&["-source", "1.4", "-target", "1.4"]),
    };
    cmd.arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(dir)
        .arg("-d")
        .arg(dir);
    for (name, source) in sources {
        let path: PathBuf = dir.join(name);
        std::fs::write(&path, source).expect("write source");
        cmd.arg(&path);
    }
    let out: Output = cmd.output().expect("start the compiler");
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{compiler:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn run(dir: &Path, main_class: &str) -> Result<String, String> {
    let out: Output = Command::new(find_on_path("java"))
        .env_remove("FORCE_COLOR")
        .arg("-cp")
        .arg(dir)
        .arg(main_class)
        .output()
        .expect("java");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(format!(
            "running {main_class} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

struct Recovery {
    original_class: Vec<u8>,
    original_output: String,
    recompiled_output: Result<String, String>,
    decompiled: DecompiledClass,
}

fn recover(compiler: Compiler, tag: &str, shape: &Shape) -> Recovery {
    let original: ScratchDir =
        ScratchDir::create(&format!("disrobe_jvm_shape_{tag}_orig")).expect("scratch dir");
    compile(compiler, original.path(), &[shape.probe, shape.driver])
        .unwrap_or_else(|err: String| panic!("the authored program must compile: {err}"));
    let class_name: &str = shape.probe.0.trim_end_matches(".java");
    let driver_name: &str = shape.driver.0.trim_end_matches(".java");
    let original_class: Vec<u8> =
        std::fs::read(original.path().join(format!("{class_name}.class"))).expect("read class");
    let decompiled: DecompiledClass =
        decompile_classfile_bytes(&original_class).expect("decompile");
    let recompiled_dir: ScratchDir =
        ScratchDir::create(&format!("disrobe_jvm_shape_{tag}_dec")).expect("scratch dir");
    let recompiled_output: Result<String, String> = compile(
        Compiler::Javac,
        recompiled_dir.path(),
        &[(shape.probe.0, decompiled.source.as_str()), shape.driver],
    )
    .and_then(|()| run(recompiled_dir.path(), driver_name));
    Recovery {
        original_class,
        original_output: run(original.path(), driver_name)
            .unwrap_or_else(|err: String| panic!("the authored program must run: {err}")),
        recompiled_output,
        decompiled,
    }
}

fn assert_recovered(compiler: Compiler, tag: &str, shape: &Shape, expected: &str) -> Recovery {
    let recovered: Recovery = recover(compiler, tag, shape);
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, expected,
        "the authored program's own output changed under {compiler:?}"
    );
    match &recovered.recompiled_output {
        Ok(output) => assert_eq!(
            output, &recovered.original_output,
            "the recovered {tag} source must run like the {compiler:?} build; recovered source:\n{source}"
        ),
        Err(err) => panic!(
            "the recovered {tag} source from the {compiler:?} build must recompile and run: {err}\nrecovered source:\n{source}"
        ),
    }
    assert_eq!(
        recovered.decompiled.fully_lifted_methods, recovered.decompiled.method_count,
        "every {tag} method must be fully lifted; recovered source:\n{source}"
    );
    recovered
}

const FOLD_OUTPUT: &str = "20,22,6,3004,21021;1020,1022,1010,4005,21024;2020,2022,2014,3004,21027;3020,3022,3018,4005,21030;";

#[test]
fn a_fold_across_iinc_recompiles_from_javac() {
    assert_recovered(Compiler::Javac, "fold_javac", &FOLD, FOLD_OUTPUT);
}

#[test]
fn a_fold_across_iinc_recompiles_from_ecj() {
    assert_recovered(Compiler::Ecj16, "fold_ecj", &FOLD, FOLD_OUTPUT);
}

const FALL_THROUGH_OUTPUT: &str = "0,-1751820221,-1934434749,1731976771,0,-1751820221,-1934434749,1731976771,de,ab,b,de,de,de,cde,de,de,de,e,de,";

#[test]
fn case_fall_through_recompiles_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "fall_through_javac",
        &FALL_THROUGH,
        FALL_THROUGH_OUTPUT,
    );
}

#[test]
fn case_fall_through_recompiles_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "fall_through_ecj",
        &FALL_THROUGH,
        FALL_THROUGH_OUTPUT,
    );
}

const STATE_MACHINE_OUTPUT: &str = "ac0dac0d:4,-786089020;a1c2da1c2d:4,2404;a1c4da1c4d:4,2804;ac6dac6d:4,3004;a1da1d:4,2804;a1da1d:4,3604;ac12dac12d:4,4604;";

#[test]
fn a_state_machine_reading_its_state_recompiles_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "state_machine_javac",
        &STATE_MACHINE,
        STATE_MACHINE_OUTPUT,
    );
}

#[test]
fn a_state_machine_reading_its_state_recompiles_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "state_machine_ecj",
        &STATE_MACHINE,
        STATE_MACHINE_OUTPUT,
    );
}

const DISPATCH_OUTPUT: &str = "-786089020;2404;2804;3004;2804;3604;4604;";

#[test]
fn a_returning_dispatcher_reading_its_state_recompiles_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "dispatch_javac",
        &DISPATCH,
        DISPATCH_OUTPUT,
    );
}

#[test]
fn a_returning_dispatcher_reading_its_state_recompiles_from_ecj() {
    assert_recovered(Compiler::Ecj16, "dispatch_ecj", &DISPATCH, DISPATCH_OUTPUT);
}

const RELAY_OUTPUT: &str = "-1291;-291;709;1709;2709;3709;4709;";

#[test]
fn a_constant_dispatcher_reading_its_state_recompiles_from_javac() {
    assert_recovered(Compiler::Javac, "relay_javac", &RELAY, RELAY_OUTPUT);
}

#[test]
fn a_constant_dispatcher_reading_its_state_recompiles_from_ecj() {
    assert_recovered(Compiler::Ecj16, "relay_ecj", &RELAY, RELAY_OUTPUT);
}

const SWITCH_EXIT_OUTPUT: &str = "0,21,17,7,100,55,11,17,29,18,55,31,1828";

#[test]
fn switch_arms_that_return_keep_the_join_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "switch_exit_javac",
        &SWITCH_EXIT,
        SWITCH_EXIT_OUTPUT,
    );
}

#[test]
fn switch_arms_that_return_keep_the_join_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "switch_exit_ecj",
        &SWITCH_EXIT,
        SWITCH_EXIT_OUTPUT,
    );
}

const TERNARY_OUTPUT: &str = "Tefalse-4,20;Fotrue-9,30;Fetrue-14,45;Fotrue19,60;Fetrue24,75;25";

fn assert_no_empty_branch(tag: &str, source: &str) {
    let squashed: String = source.split_whitespace().collect::<Vec<&str>>().join(" ");
    assert!(
        !squashed.contains(") { } else { }"),
        "the recovered {tag} source keeps an empty if/else before a value-only ternary:\n{source}"
    );
}

#[test]
fn a_value_only_ternary_evaluates_its_condition_once_from_javac() {
    let recovered: Recovery =
        assert_recovered(Compiler::Javac, "ternary_javac", &TERNARY, TERNARY_OUTPUT);
    assert_no_empty_branch("ternary_javac", &recovered.decompiled.source);
}

#[test]
fn a_value_only_ternary_evaluates_its_condition_once_from_ecj() {
    let recovered: Recovery =
        assert_recovered(Compiler::Ecj16, "ternary_ecj", &TERNARY, TERNARY_OUTPUT);
    assert_no_empty_branch("ternary_ecj", &recovered.decompiled.source);
}

const COMPOUND_TERNARY_OUTPUT: &str = "4,2,none,2,-22;3,2,none,2,39;2,2,none,2,-60;1,2,none,2,-79;0,2,s2,1,102;-1,2,s3,1,133;-2,2,s4,1,-156;16";

#[test]
fn compound_conditions_choosing_a_value_recompile_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "compound_ternary_javac",
        &COMPOUND_TERNARY,
        COMPOUND_TERNARY_OUTPUT,
    );
}

#[test]
fn compound_conditions_choosing_a_value_recompile_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "compound_ternary_ecj",
        &COMPOUND_TERNARY,
        COMPOUND_TERNARY_OUTPUT,
    );
}

const FLAG_VALUE_OUTPUT: &str = "10,5,50,false,true,0,8;10,5,50,false,true,0,8;10,5,50,false,false,0,8;10,5,50,false,false,0,8;10,5,50,false,false,0,9;10,5,50,true,false,0,9;10,5,50,true,true,1,9;10,5,50,false,false,1,9;11,9,50,false,false,1,9;11,9,60,false,false,1,9;11,9,70,false,false,2,9;11,9,80,false,false,2,9;";

#[test]
fn conditional_flags_and_nested_boolean_values_recompile_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "flag_value_javac",
        &FLAG_VALUE,
        FLAG_VALUE_OUTPUT,
    );
}

#[test]
fn conditional_flags_and_nested_boolean_values_recompile_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "flag_value_ecj",
        &FLAG_VALUE,
        FLAG_VALUE_OUTPUT,
    );
}

const NULL_LOCAL_OUTPUT: &str = "null,even0;null,null;null,even2;k3,null;k4,even4;k5,null;";

#[test]
fn a_local_holding_null_or_a_string_recompiles_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "null_local_javac",
        &NULL_LOCAL,
        NULL_LOCAL_OUTPUT,
    );
}

#[test]
fn a_local_holding_null_or_a_string_recompiles_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "null_local_ecj",
        &NULL_LOCAL,
        NULL_LOCAL_OUTPUT,
    );
}

const SLOT_REUSE_OUTPUT: &str =
    "0 1 2[],4,a0,c:x:99cx;1 2 3[0],4,b2,c:y:99cy;2 3 4[0, 1],4,c4,c:z:99cz;";

#[test]
fn a_slot_reused_with_another_reference_type_recompiles_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "slot_reuse_javac",
        &SLOT_REUSE,
        SLOT_REUSE_OUTPUT,
    );
}

#[test]
fn a_slot_reused_with_another_reference_type_recompiles_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "slot_reuse_ecj",
        &SLOT_REUSE,
        SLOT_REUSE_OUTPUT,
    );
}

const FINALLY_BRANCH_EXIT_OUTPUT: &str =
    "-1 22 1;0 88 1;289 289 1;895 895 2;2716 2716 2;8182 8182 2;24583 24583 3;";

const UNFOLDED_BRANCH_COPY_REFUSAL: &str = "// <decompile: not recovered: a branch leaves the try into a copy of the finally that was not folded";

fn assert_finally_branch_exit_runs_equal_or_is_refused(compiler: Compiler, tag: &str) {
    let recovered: Recovery = recover(compiler, tag, &FINALLY_BRANCH_EXIT);
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, FINALLY_BRANCH_EXIT_OUTPUT,
        "the authored program's own output changed under {compiler:?}"
    );
    if recovered.recompiled_output.as_ref() == Ok(&recovered.original_output) {
        assert_eq!(
            recovered.decompiled.fully_lifted_methods, recovered.decompiled.method_count,
            "a recovered source that runs like the {compiler:?} build is fully lifted:\n{source}"
        );
        return;
    }
    assert!(
        method_body(source, "static void voidExits(").contains(UNFOLDED_BRANCH_COPY_REFUSAL),
        "a finally copy the structurer left inside the try must be refused by name:\n{source}"
    );
    assert!(
        recovered.decompiled.fully_lifted_methods < recovered.decompiled.method_count,
        "a refused method is not fully lifted:\n{source}"
    );
}

#[test]
fn a_branch_into_a_finally_copy_runs_the_finally_once_or_is_refused_from_javac() {
    assert_finally_branch_exit_runs_equal_or_is_refused(
        Compiler::Javac,
        "finally_branch_exit_javac",
    );
}

#[test]
fn a_branch_into_a_finally_copy_runs_the_finally_once_or_is_refused_from_ecj() {
    assert_finally_branch_exit_runs_equal_or_is_refused(Compiler::Ecj16, "finally_branch_exit_ecj");
}

const INCREMENT_OUTPUT: &str =
    "0,2,7,0,2,5,0,0,0,2,22;7,9,14,5,7,10,1,1,0,2,36;7,9,14,10,12,15,2,2,0,2,36;";

#[test]
fn increments_used_as_values_recompile_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "increment_javac",
        &INCREMENT,
        INCREMENT_OUTPUT,
    );
}

#[test]
fn increments_used_as_values_recompile_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "increment_ecj",
        &INCREMENT,
        INCREMENT_OUTPUT,
    );
}

const LONG_COMPARE_OUTPUT: &str = "0y000 -1n-1-1-1 -1n-1-1-1 -1n-1-1-1 -1n-1-1-1 -1n-1-1-1 1;1y111 0y000 -1n-1-1-1 -1n-1-1-1 -1n-1-1-1 -1n-1-1-1 2;1y111 1y111 0y000 -1n-1-1-1 -1n-1-1-1 -1n-1-1-1 3;1y111 1y111 1y111 0y000 -1n-1-1-1 -1n-1-1-1 4;1y111 1y111 1y111 1y111 0y000 -1n-1-1-1 5;1y111 1y111 1y111 1y111 1y111 0y000 6;";

#[test]
fn long_compares_recompile_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "long_compare_javac",
        &LONG_COMPARE,
        LONG_COMPARE_OUTPUT,
    );
}

#[test]
fn long_compares_recompile_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "long_compare_ecj",
        &LONG_COMPARE,
        LONG_COMPARE_OUTPUT,
    );
}

const NAN_COMPARE_OUTPUT: &str = "FFFFFT!? FFFF!? ny,FFFFFT!? FFFF!? ny,FFFFFT!? FFFF!? ny,FFFFFT!? FFFF!? ny,FFFFFT!? FFFF!? ny,5;FFFFFT!? FFFF!? ny,FTFTTF! FTFT! nn,TTFFFT? TTFF! yy,TTFFFT? TTFF! yy,TTFFFT? TTFF! yy,0;FFFFFT!? FFFF!? ny,FFTTFT! FFTT? nn,FTFTTF! FTFT! nn,TTFFFT? TTFF! yy,TTFFFT? TTFF! yy,0;FFFFFT!? FFFF!? ny,FFTTFT! FFTT? nn,FFTTFT! FFTT? nn,FTFTTF! FTFT! nn,TTFFFT? TTFF! yy,2;FFFFFT!? FFFF!? ny,FFTTFT! FFTT? nn,FFTTFT! FFTT? nn,FFTTFT! FFTT? nn,FTFTTF! FTFT! nn,5;";

#[test]
fn nan_compares_recompile_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "nan_compare_javac",
        &NAN_COMPARE,
        NAN_COMPARE_OUTPUT,
    );
}

#[test]
fn nan_compares_recompile_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "nan_compare_ecj",
        &NAN_COMPARE,
        NAN_COMPARE_OUTPUT,
    );
}

const LOOP_HEADER_OUTPUT: &str = "0,4,0,12,8,12,20,28,44,";

#[test]
fn a_loop_header_branch_without_an_exit_recompiles_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "loop_header_javac",
        &LOOP_HEADER,
        LOOP_HEADER_OUTPUT,
    );
}

#[test]
fn a_loop_header_branch_without_an_exit_recompiles_from_ecj() {
    assert_recovered(
        Compiler::Ecj16,
        "loop_header_ecj",
        &LOOP_HEADER,
        LOOP_HEADER_OUTPUT,
    );
}

#[test]
fn a_synchronized_block_in_a_loop_recompiles_from_ecj() {
    let recovered: Recovery =
        assert_recovered(Compiler::Ecj16, "sync_loop_ecj", &SYNC_LOOP, "10,3");
    assert_eq!(
        recovered
            .decompiled
            .source
            .matches("synchronized (")
            .count(),
        2,
        "both synchronized blocks keep their lock; recovered source:\n{}",
        recovered.decompiled.source
    );
}

fn assert_named_indy_refusal(compiler: Compiler, tag: &str, shape: &Shape, expected: &str) {
    let recovered: Recovery = recover(compiler, tag, shape);
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, expected,
        "the authored program's own output changed under {compiler:?}"
    );
    if let Ok(output) = &recovered.recompiled_output {
        assert_eq!(
            output, &recovered.original_output,
            "a recovered {tag} source that recompiles must run like the {compiler:?} build; recovered source:\n{source}"
        );
        assert!(
            !source.contains(UNRESOLVED_INDY),
            "a recovered {tag} source that runs like the {compiler:?} build names no unresolved invokedynamic:\n{source}"
        );
        assert_eq!(
            recovered.decompiled.fully_lifted_methods, recovered.decompiled.method_count,
            "a recovered {tag} source that runs like the {compiler:?} build is fully lifted:\n{source}"
        );
        return;
    }
    assert!(
        source.contains(UNRESOLVED_INDY) || source.contains(INCOMPLETE_MARKER),
        "a non-concat invokedynamic the decompiler cannot lower must be named in the source:\n{source}"
    );
    assert!(
        recovered.decompiled.fully_lifted_methods < recovered.decompiled.method_count,
        "a method holding an unresolved invokedynamic is not fully lifted; recovered source:\n{source}"
    );
}

const RECORD_OUTPUT: &str = "RecordProbe[a=3, b=x],RecordProbe[a=4, b=null],true,false,true";

#[test]
fn a_record_object_methods_invokedynamic_from_javac_is_recovered_or_named() {
    assert_named_indy_refusal(Compiler::Javac, "record_javac", &RECORD, RECORD_OUTPUT);
}

#[test]
fn a_record_object_methods_invokedynamic_from_ecj_is_recovered_or_named() {
    assert_named_indy_refusal(Compiler::Ecj16, "record_ecj", &RECORD, RECORD_OUTPUT);
}

#[test]
fn a_type_switch_expression_from_javac_recompiles() {
    let recovered: Recovery = assert_recovered(
        Compiler::Javac,
        "type_switch_javac",
        &TYPE_SWITCH,
        "int5,big12,str3,null,other,",
    );
    assert!(
        !recovered.decompiled.source.contains(UNRESOLVED_INDY),
        "the typeSwitch bootstrap is lowered to a pattern switch:\n{}",
        recovered.decompiled.source
    );
}

const UNRENDERED_BLOCK_MARKER: &str =
    "// <decompile: incomplete: a reachable block has no rendered statement>";

fn method_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start: usize = source
        .find(signature)
        .unwrap_or_else(|| panic!("{signature} is missing from the recovered source:\n{source}"));
    let body: &str = &source[start..];
    &body[..body.find("\n    }").unwrap_or(body.len())]
}

#[test]
fn a_type_switch_statement_from_javac_is_recovered_or_named() {
    let recovered: Recovery = recover(
        Compiler::Javac,
        "type_switch_block_javac",
        &TYPE_SWITCH_BLOCK,
    );
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, "int,big,str3,null,other,big,48",
        "the authored program's own output changed under javac"
    );
    if recovered.recompiled_output.as_ref() == Ok(&recovered.original_output)
        && recovered.decompiled.fully_lifted_methods == recovered.decompiled.method_count
    {
        return;
    }
    assert!(
        method_body(source, "public static String describe(").contains(UNRENDERED_BLOCK_MARKER),
        "a type switch statement whose restart loop is not lowered must carry the coverage \
         marker in its own method:\n{source}"
    );
    assert_eq!(
        recovered.decompiled.fully_lifted_methods + 1,
        recovered.decompiled.method_count,
        "exactly the type switch method is degraded:\n{source}"
    );
}

#[test]
fn an_ecj_14_try_finally_with_jsr_recompiles_and_runs_like_the_original() {
    let recovered: Recovery = recover(Compiler::Ecj14, "jsr_finally_ecj14", &JSR_FINALLY);
    let source: &str = &recovered.decompiled.source;
    assert!(
        recovered.original_class.contains(&OP_JSR),
        "the ecj 1.4 build must carry jsr subroutines"
    );
    assert_eq!(
        recovered.original_output,
        "0 10 0;0 11 1;1 4 34;3 6 1060;6 10 32866;10 11 1018857;15 4 31584584;21 6 979122128;-21 10 288014875;-21 11 338526513;",
        "the authored program's own output changed under ecj 1.4"
    );
    match &recovered.recompiled_output {
        Ok(output) => assert_eq!(
            output, &recovered.original_output,
            "the recovered try/finally must run like the ecj 1.4 build; recovered source:\n{source}"
        ),
        Err(err) => panic!(
            "the recovered try/finally from the ecj 1.4 build must recompile and run: {err}\nrecovered source:\n{source}"
        ),
    }
    assert_eq!(
        recovered.decompiled.fully_lifted_methods, recovered.decompiled.method_count,
        "every jsr method must be fully lifted; recovered source:\n{source}"
    );
}

const JSR_SHAPES_OUTPUT: &str = "-99 -1 116 116;-99 0 415 415;0 1 1290 1290;7 2 3845 3845;14 3 -11645 -11645;21 4 -34860 -34860;28 5 -104527 -104527;35 6 -313598 -313598;42 7 -940662 -940662;49 8 -2821903 -2821903;56 9 -8465648 -8465648;";

#[test]
fn ecj_14_subroutines_with_branches_handlers_and_nesting_recompile() {
    let recovered: Recovery = assert_recovered(
        Compiler::Ecj14,
        "jsr_shapes_ecj14",
        &JSR_SHAPES,
        JSR_SHAPES_OUTPUT,
    );
    assert!(
        recovered.original_class.contains(&OP_JSR),
        "the ecj 1.4 build must carry jsr subroutines"
    );
}

const FINALLY_EXIT_OUTPUT: &str = "-1 -1 -6 -6 0 -6 -7 -7 -1 -7 5;5 5 1 1 0 1 1 1 6 2 9;10 10 7 7 0 7 8 8 -1 8 20;44 44 88 88 1 88 243 243 -1 243 250;33 500 33 999 3 999 3006 3006 -1 3006 3018;6044 6044 12095 12095 6 12101 36315 36315 6 36317 36312;72634 72634 145277 145277 6 145289 50 435867 -1 435867 435867;871746 871746 1743503 1743503 6 1743515 5230563 5230563 -1 5230563 5230558;10461130 10461130 20922273 20922273 6 20922285 62766876 62766876 -1 62766876 62766876;125533768 125533768 251067551 251067551 6 251067563 753202713 753202713 0 753202715 753202710;";

#[test]
fn branching_finally_bodies_run_once_on_early_exits_from_javac() {
    assert_recovered(
        Compiler::Javac,
        "finally_exit_javac",
        &FINALLY_EXIT,
        FINALLY_EXIT_OUTPUT,
    );
}

const FINALLY_JOIN_OUTPUT: &str = "0 0;0 0;0 0;1 0;3 0;3 3;7 7;12 15;12 11;19 28;";

#[test]
fn a_continue_that_leaves_a_branching_finally_from_javac_runs_equal_or_is_refused() {
    let recovered: Recovery = recover(Compiler::Javac, "finally_join_javac", &FINALLY_JOIN);
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, FINALLY_JOIN_OUTPUT,
        "the authored program's own output changed under javac"
    );
    if recovered.recompiled_output.as_ref() == Ok(&recovered.original_output) {
        assert_eq!(
            recovered.decompiled.fully_lifted_methods, recovered.decompiled.method_count,
            "a recovered source that runs like the javac build is fully lifted:\n{source}"
        );
        return;
    }
    assert!(
        source.contains("// <decompile: not recovered: "),
        "a recovered continue that does not run like the javac build must name its refusal:\n{source}"
    );
    assert!(
        recovered.decompiled.fully_lifted_methods < recovered.decompiled.method_count,
        "a refused method is not fully lifted:\n{source}"
    );
}

const JSR_REFUSED_PROBE: (&str, &str) = (
    "JsrRefusedProbe.java",
    include_str!("../fixtures/shape_matrix/JsrRefusedProbe.java"),
);

const REFUSAL_MARKERS: [&str; 3] = [
    "// <decompile: not recovered: ",
    INCOMPLETE_MARKER,
    "__unresolved__",
];

#[test]
fn ecj_14_subroutines_the_structurer_cannot_fold_are_refused_by_name() {
    let dir: ScratchDir = ScratchDir::create("disrobe_jvm_shape_jsr_refused").expect("scratch dir");
    compile(Compiler::Ecj14, dir.path(), &[JSR_REFUSED_PROBE])
        .unwrap_or_else(|err: String| panic!("the authored program must compile: {err}"));
    let class: Vec<u8> =
        std::fs::read(dir.path().join("JsrRefusedProbe.class")).expect("read class");
    assert!(
        class.contains(&OP_JSR),
        "the ecj 1.4 build must carry jsr subroutines"
    );
    let decompiled: DecompiledClass = decompile_classfile_bytes(&class).expect("decompile");
    let source: &str = &decompiled.source;
    for method in [
        "static int branchy(",
        "static int looping(",
        "static int nested(",
    ] {
        let start: usize = source.find(method).unwrap_or_else(|| {
            panic!(
                "{method} is missing from the recovered source:
{source}"
            )
        });
        let body: &str = &source[start..];
        let body: &str = &body[..body
            .find(
                "
    }",
            )
            .unwrap_or(body.len())];
        assert!(
            REFUSAL_MARKERS
                .iter()
                .any(|marker: &&str| body.contains(marker)),
            "{method} is not recovered soundly yet, so its body must name the refusal:
{source}"
        );
    }
    assert_eq!(
        decompiled.fully_lifted_methods + 3,
        decompiled.method_count,
        "exactly the three refused methods are not fully lifted:
{source}"
    );
}

const CMP_VALUE_DRIVER: (&str, &str) = (
    "CmpValueDriver.java",
    include_str!("../fixtures/shape_matrix/CmpValueDriver.java"),
);

const CMP_VALUE_OUTPUT: &str = "01 -10 -10 -10 -10 12 01 -10 -10 -10 12 12 01 -10 -10 12 12 12 01 -10 12 12 12 12 01 |-1,1,-1,1 -1,1,-1,1 -1,1,-1,1 -1,1,-1,1 -1,1,-1,1 -1,1,-1,1 0,0,0,0 -1,-1,-1,-1 -1,-1,-1,-1 -1,-1,-1,-1 -1,1,-1,1 1,1,1,1 0,0,0,0 0,0,0,0 -1,-1,-1,-1 -1,1,-1,1 1,1,1,1 0,0,0,0 0,0,0,0 -1,-1,-1,-1 -1,1,-1,1 1,1,1,1 1,1,1,1 1,1,1,1 0,0,0,0";

struct ConstantPool {
    entries: Vec<Vec<u8>>,
}

impl ConstantPool {
    fn add(&mut self, entry: Vec<u8>) -> u16 {
        self.entries.push(entry);
        u16::try_from(self.entries.len()).expect("pool index fits u16")
    }

    fn utf8(&mut self, text: &str) -> u16 {
        let mut entry: Vec<u8> = vec![1];
        entry.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(text.as_bytes());
        self.add(entry)
    }

    fn class(&mut self, name: &str) -> u16 {
        let name_index: u16 = self.utf8(name);
        let mut entry: Vec<u8> = vec![7];
        entry.extend_from_slice(&name_index.to_be_bytes());
        self.add(entry)
    }
}

fn assemble_cmp_value_class() -> Vec<u8> {
    const LLOAD_0: u8 = 0x1E;
    const LLOAD_2: u8 = 0x20;
    const FLOAD_0: u8 = 0x22;
    const FLOAD_1: u8 = 0x23;
    const DLOAD_0: u8 = 0x26;
    const DLOAD_2: u8 = 0x28;
    const ICONST_1: u8 = 0x04;
    const IADD: u8 = 0x60;
    const LCMP: u8 = 0x94;
    const FCMPL: u8 = 0x95;
    const FCMPG: u8 = 0x96;
    const DCMPL: u8 = 0x97;
    const DCMPG: u8 = 0x98;
    const IRETURN: u8 = 0xAC;
    let methods: [(&str, &str, u16, Vec<u8>); 6] = [
        (
            "longOrder",
            "(JJ)I",
            4,
            vec![LLOAD_0, LLOAD_2, LCMP, IRETURN],
        ),
        (
            "longOrderPlusOne",
            "(JJ)I",
            4,
            vec![LLOAD_0, LLOAD_2, LCMP, ICONST_1, IADD, IRETURN],
        ),
        (
            "floatLow",
            "(FF)I",
            2,
            vec![FLOAD_0, FLOAD_1, FCMPL, IRETURN],
        ),
        (
            "floatHigh",
            "(FF)I",
            2,
            vec![FLOAD_0, FLOAD_1, FCMPG, IRETURN],
        ),
        (
            "doubleLow",
            "(DD)I",
            4,
            vec![DLOAD_0, DLOAD_2, DCMPL, IRETURN],
        ),
        (
            "doubleHigh",
            "(DD)I",
            4,
            vec![DLOAD_0, DLOAD_2, DCMPG, IRETURN],
        ),
    ];
    let mut pool: ConstantPool = ConstantPool {
        entries: Vec::new(),
    };
    let code_name: u16 = pool.utf8("Code");
    let this_class: u16 = pool.class("CmpValueProbe");
    let super_class: u16 = pool.class("java/lang/Object");
    let method_count: u16 = u16::try_from(methods.len()).unwrap();
    let mut method_bytes: Vec<u8> = Vec::new();
    for (name, descriptor, locals, code) in methods {
        let name_index: u16 = pool.utf8(name);
        let descriptor_index: u16 = pool.utf8(descriptor);
        let mut attribute: Vec<u8> = Vec::new();
        attribute.extend_from_slice(&4u16.to_be_bytes());
        attribute.extend_from_slice(&locals.to_be_bytes());
        attribute.extend_from_slice(&u32::try_from(code.len()).unwrap().to_be_bytes());
        attribute.extend_from_slice(&code);
        attribute.extend_from_slice(&0u16.to_be_bytes());
        attribute.extend_from_slice(&0u16.to_be_bytes());
        method_bytes.extend_from_slice(&0x0009u16.to_be_bytes());
        method_bytes.extend_from_slice(&name_index.to_be_bytes());
        method_bytes.extend_from_slice(&descriptor_index.to_be_bytes());
        method_bytes.extend_from_slice(&1u16.to_be_bytes());
        method_bytes.extend_from_slice(&code_name.to_be_bytes());
        method_bytes.extend_from_slice(&u32::try_from(attribute.len()).unwrap().to_be_bytes());
        method_bytes.extend_from_slice(&attribute);
    }
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&52u16.to_be_bytes());
    out.extend_from_slice(&u16::try_from(pool.entries.len() + 1).unwrap().to_be_bytes());
    for entry in &pool.entries {
        out.extend_from_slice(entry);
    }
    out.extend_from_slice(&0x0021u16.to_be_bytes());
    out.extend_from_slice(&this_class.to_be_bytes());
    out.extend_from_slice(&super_class.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&method_count.to_be_bytes());
    out.extend_from_slice(&method_bytes);
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

#[test]
fn compare_results_used_as_values_recompile_with_their_nan_bias() {
    let class_bytes: Vec<u8> = assemble_cmp_value_class();
    let original: ScratchDir =
        ScratchDir::create("disrobe_jvm_shape_cmp_value_orig").expect("scratch dir");
    std::fs::write(original.path().join("CmpValueProbe.class"), &class_bytes)
        .expect("write the assembled class");
    compile(Compiler::Javac, original.path(), &[CMP_VALUE_DRIVER])
        .unwrap_or_else(|err: String| panic!("the driver must compile: {err}"));
    let original_output: String = run(original.path(), "CmpValueDriver")
        .unwrap_or_else(|err: String| panic!("the assembled class must run: {err}"));
    assert_eq!(
        original_output, CMP_VALUE_OUTPUT,
        "the JVM's own lcmp, fcmpl, fcmpg, dcmpl and dcmpg results changed"
    );
    let decompiled: DecompiledClass =
        decompile_classfile_bytes(&class_bytes).expect("decompile the assembled class");
    let source: &str = &decompiled.source;
    let recompiled: ScratchDir =
        ScratchDir::create("disrobe_jvm_shape_cmp_value_dec").expect("scratch dir");
    let recompiled_output: Result<String, String> = compile(
        Compiler::Javac,
        recompiled.path(),
        &[("CmpValueProbe.java", source), CMP_VALUE_DRIVER],
    )
    .and_then(|()| run(recompiled.path(), "CmpValueDriver"));
    match recompiled_output {
        Ok(output) => assert_eq!(
            output, original_output,
            "lcmp, fcmpl, fcmpg, dcmpl and dcmpg values must keep their order and NaN bias; recovered source:\n{source}"
        ),
        Err(err) => panic!(
            "the recovered compare values must recompile and run: {err}\nrecovered source:\n{source}"
        ),
    }
    assert_eq!(
        decompiled.fully_lifted_methods, decompiled.method_count,
        "every compare method must be fully lifted; recovered source:\n{source}"
    );
}

const KOTLIN_PROVENANCE: &str = include_str!("../fixtures/shape_matrix/kotlin/PROVENANCE.txt");
const KOTLIN_STDLIB_SHA256: &str =
    "4ec0293bc3751423b203f1d8493251c57c42e73eb6377a6b8560d0974ff0a6df";
const JETBRAINS_ANNOTATIONS_SHA256: &str =
    "ace2a10dc8e2d5fd34925ecac03e4988b2c0f851650c94b8cef49ba1bd111478";

struct KotlinShape {
    name: &'static str,
    class: &'static [u8],
    driver: &'static str,
    output: &'static str,
}

const KT_FOLD: KotlinShape = KotlinShape {
    name: "KtFold",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtFold.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtFoldDriver.java"),
    output: "22,2002,6,3004,21021;1022,4003,1010,4005,29027;2022,6004,2014,3004,40033;3022,8005,3018,4005,54039;4022,10006,4022,3004,71045;",
};

const KT_COUNT_LOOP: KotlinShape = KotlinShape {
    name: "KtCountLoop",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtCountLoop.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtCountLoopDriver.java"),
    output: "4208,1,4127;3208,202,3127;2202,103,191;3247,204,3127;3208,205,3159;3252,101,191;6223,2,3111;1202,203,2127;2229,204,143;5208,305,3159;3247,1,2175;2234,202,191;",
};

const KT_WHEN: KotlinShape = KotlinShape {
    name: "KtWhen",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtWhen.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtWhenDriver.java"),
    output: "-1100,other,3,1,4;-201,other,3,0,4;-105,other,4,0,4;10,other,1,0,1;10,low,1,0,1;40,low,1,0,1;60,mid,1,0,1;80,mid,2,0,4;-5,mid,2,0,4;-94,other,2,0,4;49,other,2,2,4;-92,other,2,0,4;81,other,2,0,4;-90,ten,4,0,4;-89,other,4,0,4;-80,other,2,0,4;-30,other,4,2,4;1,other,3,0,4;600,other,3,2,4;900,other,3,1,4;",
};

const KT_WHEN_STRING: KotlinShape = KotlinShape {
    name: "KtWhenString",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtWhenString.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtWhenStringDriver.java"),
    output: "1,3,3,3,1,2,1,3,1,2,1,3,",
};

const KT_STATE_MACHINE: KotlinShape = KotlinShape {
    name: "KtStateMachine",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtStateMachine.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtStateMachineDriver.java"),
    output: "ac0dac0d:6,1287;a1c2da1c2d:8,-2;a1c4da1c4d:8,1357;ac6dac6d:6,2169;a1da1d:6,1287;a1da1d:6,1483;ac12dac12d:6,3345;a1da1d:6,1455;a1da1d:6,1651;ac18dac18d:6,601;",
};

const KT_SYNC_LOOP: KotlinShape = KotlinShape {
    name: "KtSyncLoop",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtSyncLoop.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtSyncLoopDriver.java"),
    output: "0,0,0;0,0,1;1,2,3;3,6,8;6,6,18;10,6,35;15,6,61;21,6,98;",
};

const KT_SYNC_CONTINUE: KotlinShape = KotlinShape {
    name: "KtSyncContinue",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtSyncContinue.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtSyncContinueDriver.java"),
    output: "0,0,2,8,8,24,58,58,",
};

const KT_LONG_COMPARE: KotlinShape = KotlinShape {
    name: "KtLongCompare",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtLongCompare.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtLongCompareDriver.java"),
    output: "0 0 110 0,-1 -9 10010 0,-1 -9 10010 1,-1 -9 10010 0,-1 -9 10010 -1,-1 -9 10010 0,-1 -9 10010 1,;1 10 11001 0,0 0 110 0,-1 -9 10010 1,-1 -9 10010 0,-1 -9 10010 -1,-1 -9 10010 0,-1 -9 10010 1,;1 10 11001 -1,1 10 11001 -1,0 0 110 0,-1 -9 10010 -1,-1 -9 10010 -1,-1 -9 10010 -1,-1 -9 10010 0,;1 10 11001 0,1 10 11001 0,1 10 11001 1,0 0 110 0,-1 -9 10010 -1,-1 -9 10010 0,-1 -9 10010 1,;1 10 11001 1,1 10 11001 1,1 10 11001 1,1 10 11001 1,0 0 110 0,-1 -9 10010 1,-1 -9 10010 1,;1 10 11001 0,1 10 11001 0,1 10 11001 1,1 10 11001 0,1 10 11001 -1,0 0 110 0,-1 -9 10010 1,;1 10 11001 -1,1 10 11001 -1,1 10 11001 0,1 10 11001 -1,1 10 11001 -1,1 10 11001 -1,0 0 110 0,;",
};

const KT_NAN_COMPARE: KotlinShape = KotlinShape {
    name: "KtNanCompare",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtNanCompare.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtNanCompareDriver.java"),
    output: "224 224 n 0 NaN,224 224 n 1 -Infinity,224 224 n 1 -1.5,224 224 n 1 -0.0,224 224 n 1 0.0,224 224 n 1 2.25,224 224 n 1 Infinity,;224 224 n -1 NaN,90 90 n 0 -Infinity,163 99 y -1 -Infinity,163 99 y -1 -Infinity,163 99 y -1 -Infinity,163 99 y -1 -Infinity,163 99 y -1 -Infinity,;224 224 n -1 NaN,108 172 n 1 -Infinity,90 90 n 0 -1.5,163 99 y -1 -1.5,163 99 y -1 -1.5,163 99 y -1 -1.5,163 99 y -1 -1.5,;224 224 n -1 NaN,108 172 n 1 -Infinity,108 172 n 1 -1.5,90 90 n 0 -0.0,90 90 n -1 0.0,163 99 y -1 -0.0,163 99 y -1 -0.0,;224 224 n -1 NaN,108 172 n 1 -Infinity,108 172 n 1 -1.5,90 90 n 1 -0.0,90 90 n 0 0.0,163 99 y -1 0.0,163 99 y -1 0.0,;224 224 n -1 NaN,108 172 n 1 -Infinity,108 172 n 1 -1.5,108 172 n 1 -0.0,108 172 n 1 0.0,90 90 n 0 2.25,163 99 y -1 2.25,;224 224 n -1 NaN,108 172 n 1 -Infinity,108 172 n 1 -1.5,108 172 n 1 -0.0,108 172 n 1 0.0,108 172 n 1 2.25,90 90 n 0 Infinity,;",
};

const KT_TEMPLATE: KotlinShape = KotlinShape {
    name: "KtTemplate",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtTemplate.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtTemplateDriver.java"),
    output: "a=-1 b=-4999999999 c=-0.25 d=o f=false [-2]|<-1><-1>|4|v=null|;a=0 b=1 c=0.0 d=p f=true [0]|<0><0>|3|v=null|;a=1 b=5000000001 c=0.25 d=q f=false [2]|<1><1>|3|v=p1|0,;a=2 b=10000000001 c=0.5 d=r f=true [4]|<2><2>|3|v=p2|0,1,;a=3 b=15000000001 c=0.75 d=s f=false [6]|<3><3>|3|v=p3|0,1,2,;",
};

const KT_FINALLY: KotlinShape = KotlinShape {
    name: "KtFinally",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtFinally.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtFinallyDriver.java"),
    output: "-100,11,-1099,-20,12;div,23,div,-2,24;100,35,1101,20,36;50,47,551,10,48;33,59,367,6,60;25,71,276,4,72;20,83,221,4,84;16,95,183,2,96;",
};

const KT_FINALLY_LOOP: KotlinShape = KotlinShape {
    name: "KtFinallyLoop",
    class: include_bytes!("../fixtures/shape_matrix/kotlin/KtFinallyLoop.class"),
    driver: include_str!("../fixtures/shape_matrix/kotlin/KtFinallyLoopDriver.java"),
    output: "0,100,201,301,404,508,608,608,",
};

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: sha2::digest::Output<sha2::Sha256> = <sha2::Sha256 as sha2::Digest>::digest(bytes);
    format!("{digest:x}")
}

fn kotlinc_lib_dir() -> PathBuf {
    let path_var: std::ffi::OsString = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path_var)
        .find(|dir: &PathBuf| dir.join("kotlinc").is_file())
        .and_then(|bin: PathBuf| bin.parent().map(|home: &Path| home.join("lib")))
        .unwrap_or_else(|| {
            panic!(
                "the Kotlin shape tests run the committed classes against kotlin-stdlib 2.4.10 and \
                 annotations 13.0: set DISROBE_KOTLIN_STDLIB_JAR and DISROBE_JETBRAINS_ANNOTATIONS_JAR \
                 (Maven Central, see tests/fixtures/shape_matrix/kotlin/PROVENANCE.txt) or put kotlinc \
                 2.4.10 on PATH"
            )
        })
}

fn kotlin_library(variable: &str, file_name: &str, sha256: &str) -> PathBuf {
    let path: PathBuf =
        std::env::var_os(variable).map_or_else(|| kotlinc_lib_dir().join(file_name), PathBuf::from);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "{variable} or kotlinc 2.4.10 must provide {file_name} at {}: {err}",
            path.display()
        )
    });
    assert_eq!(
        sha256_hex(&bytes),
        sha256,
        "{} is not the pinned {file_name}",
        path.display()
    );
    path
}

fn kotlin_runtime() -> Vec<PathBuf> {
    vec![
        kotlin_library(
            "DISROBE_KOTLIN_STDLIB_JAR",
            "kotlin-stdlib.jar",
            KOTLIN_STDLIB_SHA256,
        ),
        kotlin_library(
            "DISROBE_JETBRAINS_ANNOTATIONS_JAR",
            "annotations-13.0.jar",
            JETBRAINS_ANNOTATIONS_SHA256,
        ),
    ]
}

fn kotlin_classpath(dir: &Path, libraries: &[PathBuf]) -> std::ffi::OsString {
    std::env::join_paths(std::iter::once(dir.to_path_buf()).chain(libraries.iter().cloned()))
        .expect("classpath entries hold no separator")
}

fn javac_against_kotlin(
    dir: &Path,
    libraries: &[PathBuf],
    sources: &[(&str, &str)],
) -> Result<(), String> {
    let mut command: Command = Command::new(find_on_path("javac"));
    command
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(kotlin_classpath(dir, libraries))
        .arg("-d")
        .arg(dir);
    for (name, source) in sources {
        let path: PathBuf = dir.join(name);
        std::fs::write(&path, source).expect("write source");
        command.arg(&path);
    }
    let out: Output = command.output().expect("start javac");
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "javac failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn run_against_kotlin(
    dir: &Path,
    libraries: &[PathBuf],
    main_class: &str,
) -> Result<String, String> {
    let out: Output = Command::new(find_on_path("java"))
        .env_remove("FORCE_COLOR")
        .arg("-cp")
        .arg(kotlin_classpath(dir, libraries))
        .arg(main_class)
        .output()
        .expect("java");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(format!(
            "running {main_class} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

struct KotlinRecovery {
    libraries: Vec<PathBuf>,
    original_output: String,
    recompiled_output: Result<String, String>,
    decompiled: DecompiledClass,
}

fn rerun_recovered_kotlin(
    shape: &KotlinShape,
    libraries: &[PathBuf],
    source: &str,
    tag: &str,
) -> Result<String, String> {
    let dir: ScratchDir = ScratchDir::create(&format!("disrobe_jvm_kotlin_{}_{tag}", shape.name))
        .expect("scratch dir");
    let driver_name: String = format!("{}Driver", shape.name);
    javac_against_kotlin(
        dir.path(),
        libraries,
        &[
            (&format!("{}.java", shape.name), source),
            (&format!("{driver_name}.java"), shape.driver),
        ],
    )
    .and_then(|()| run_against_kotlin(dir.path(), libraries, &driver_name))
}

fn recover_kotlin(shape: &KotlinShape) -> KotlinRecovery {
    let class_line: String = format!("Class: out/{}.class", shape.name);
    let recorded: Option<&str> = KOTLIN_PROVENANCE
        .lines()
        .skip_while(|line: &&str| *line != class_line)
        .nth(1)
        .and_then(|line: &str| line.strip_prefix("Class SHA-256: "));
    assert_eq!(
        recorded,
        Some(sha256_hex(shape.class).as_str()),
        "{}.class is not the kotlinc 2.4.10 build its PROVENANCE record names",
        shape.name
    );
    let libraries: Vec<PathBuf> = kotlin_runtime();
    let driver_name: String = format!("{}Driver", shape.name);
    let original: ScratchDir =
        ScratchDir::create(&format!("disrobe_jvm_kotlin_{}_orig", shape.name))
            .expect("scratch dir");
    std::fs::write(
        original.path().join(format!("{}.class", shape.name)),
        shape.class,
    )
    .expect("write the kotlinc class");
    javac_against_kotlin(
        original.path(),
        &libraries,
        &[(&format!("{driver_name}.java"), shape.driver)],
    )
    .unwrap_or_else(|err: String| {
        panic!("the driver must compile against the kotlinc class: {err}")
    });
    let original_output: String = run_against_kotlin(original.path(), &libraries, &driver_name)
        .unwrap_or_else(|err: String| panic!("the kotlinc class must run: {err}"));
    let decompiled: DecompiledClass = decompile_classfile_bytes(shape.class).expect("decompile");
    let recompiled_output: Result<String, String> =
        rerun_recovered_kotlin(shape, &libraries, &decompiled.source, "dec");
    KotlinRecovery {
        libraries,
        original_output,
        recompiled_output,
        decompiled,
    }
}

fn assert_kotlin_recovered(shape: &KotlinShape, mutation: (&str, &str)) {
    let recovery: KotlinRecovery = recover_kotlin(shape);
    let source: &str = &recovery.decompiled.source;
    assert_eq!(
        recovery.original_output, shape.output,
        "the kotlinc 2.4.10 build of {} no longer prints its recorded output",
        shape.name
    );
    match &recovery.recompiled_output {
        Ok(output) => assert_eq!(
            output, &recovery.original_output,
            "the recovered {} source must run like the kotlinc build; recovered source:\n{source}",
            shape.name
        ),
        Err(err) => panic!(
            "the recovered {} source must recompile and run: {err}\nrecovered source:\n{source}",
            shape.name
        ),
    }
    assert_eq!(
        recovery.decompiled.fully_lifted_methods, recovery.decompiled.method_count,
        "every {} method must be fully lifted; recovered source:\n{source}",
        shape.name
    );
    let (from, to): (&str, &str) = mutation;
    assert_eq!(
        source.matches(from).count(),
        1,
        "the {} mutation site {from:?} must occur once in the recovered source:\n{source}",
        shape.name
    );
    let mutated_output: String = rerun_recovered_kotlin(
        shape,
        &recovery.libraries,
        &source.replacen(from, to, 1),
        "mut",
    )
    .unwrap_or_else(|err: String| {
        panic!(
            "the mutated {} source must still recompile and run: {err}",
            shape.name
        )
    });
    assert_ne!(
        mutated_output, shape.output,
        "replacing {from:?} with {to:?} left the {} output unchanged, so this grade cannot fail",
        shape.name
    );
}

fn names_a_refusal(source: &str) -> bool {
    REFUSAL_MARKERS
        .iter()
        .any(|marker: &&str| source.contains(marker))
}

fn assert_kotlin_recovered_or_refused(shape: &KotlinShape) {
    let recovery: KotlinRecovery = recover_kotlin(shape);
    let source: &str = &recovery.decompiled.source;
    assert_eq!(
        recovery.original_output, shape.output,
        "the kotlinc 2.4.10 build of {} no longer prints its recorded output",
        shape.name
    );
    if recovery.recompiled_output.as_ref() == Ok(&recovery.original_output)
        && recovery.decompiled.fully_lifted_methods == recovery.decompiled.method_count
    {
        return;
    }
    assert!(
        names_a_refusal(source),
        "a recovered {} source that does not run like the kotlinc build must name its refusal:\n{source}",
        shape.name
    );
    assert!(
        recovery.decompiled.fully_lifted_methods < recovery.decompiled.method_count,
        "a refused {} method is not fully lifted:\n{source}",
        shape.name
    );
    let unmarked: String = source
        .lines()
        .filter(|line: &&str| !names_a_refusal(line))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !names_a_refusal(&unmarked),
        "the {} refusal check must fail once the markers are gone",
        shape.name
    );
}

#[test]
fn a_kotlin_fold_across_an_increment_recompiles_and_runs_like_kotlinc() {
    assert_kotlin_recovered(
        &KT_FOLD,
        ("var3 = (var3 + var1++);", "var3 = (var3 + ++var1);"),
    );
}

#[test]
fn kotlin_counting_loops_left_by_return_break_or_throw_recompile() {
    assert_kotlin_recovered(
        &KT_COUNT_LOOP,
        ("if ((var2 & 1) == 1) {", "if ((var2 & 1) == 0) {"),
    );
}

#[test]
fn a_kotlin_when_with_shared_branches_and_ranges_recompiles() {
    assert_kotlin_recovered(&KT_WHEN, ("return 2;", "return 3;"));
}

#[test]
fn a_kotlin_state_machine_reading_its_state_recompiles() {
    assert_kotlin_recovered(&KT_STATE_MACHINE, ("var2 = 3;", "var2 = 1;"));
}

#[test]
fn kotlin_synchronized_blocks_in_loops_recompile() {
    assert_kotlin_recovered(
        &KT_SYNC_LOOP,
        ("var2 = (var2 + (var3 * 2));", "var2 = (var2 + (var3 * 3));"),
    );
}

#[test]
fn kotlin_long_compare_to_recompiles() {
    assert_kotlin_recovered(
        &KT_LONG_COMPARE,
        (
            "kotlin.jvm.internal.Intrinsics.compare(arg1, arg0) == 0",
            "kotlin.jvm.internal.Intrinsics.compare(arg1, arg0) >= 0",
        ),
    );
}

#[test]
fn kotlin_nan_compares_recompile_with_their_bias() {
    assert_kotlin_recovered(
        &KT_NAN_COMPARE,
        ("if (!(arg0 < arg1)) {", "if ((arg0 >= arg1)) {"),
    );
}

#[test]
fn kotlin_string_templates_recompile() {
    assert_kotlin_recovered(
        &KT_TEMPLATE,
        ("\" b=\" + (arg1 + 1L)", "\" b=\" + (arg1 + 2L)"),
    );
}

#[test]
fn a_kotlin_finally_runs_once_on_every_exit() {
    assert_kotlin_recovered(
        &KT_FINALLY,
        (
            "        var1 = var2;\n",
            "        counter = (KtFinally.counter + 1);\n        var1 = var2;\n",
        ),
    );
}

#[test]
fn a_kotlin_string_when_is_recovered_or_refused_by_name() {
    assert_kotlin_recovered_or_refused(&KT_WHEN_STRING);
}

#[test]
fn a_kotlin_continue_out_of_synchronized_is_recovered_or_refused_by_name() {
    assert_kotlin_recovered_or_refused(&KT_SYNC_CONTINUE);
}

#[test]
fn a_kotlin_continue_out_of_try_finally_is_recovered_or_refused_by_name() {
    assert_kotlin_recovered_or_refused(&KT_FINALLY_LOOP);
}
