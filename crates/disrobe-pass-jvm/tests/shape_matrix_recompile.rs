#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};

const OP_JSR: u8 = 0xA8;
const UNRESOLVED_INDY: &str = "/* unresolved invokedynamic via ";

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
        include_str!("fixtures/shape_matrix/FoldProbe.java"),
    ),
    driver: (
        "FoldDriver.java",
        include_str!("fixtures/shape_matrix/FoldDriver.java"),
    ),
};

const FALL_THROUGH: Shape = Shape {
    probe: (
        "FallThroughProbe.java",
        include_str!("fixtures/shape_matrix/FallThroughProbe.java"),
    ),
    driver: (
        "FallThroughDriver.java",
        include_str!("fixtures/shape_matrix/FallThroughDriver.java"),
    ),
};

const STATE_MACHINE: Shape = Shape {
    probe: (
        "StateMachineProbe.java",
        include_str!("fixtures/shape_matrix/StateMachineProbe.java"),
    ),
    driver: (
        "StateMachineDriver.java",
        include_str!("fixtures/shape_matrix/StateMachineDriver.java"),
    ),
};

const DISPATCH: Shape = Shape {
    probe: (
        "DispatchProbe.java",
        include_str!("fixtures/shape_matrix/DispatchProbe.java"),
    ),
    driver: (
        "DispatchDriver.java",
        include_str!("fixtures/shape_matrix/DispatchDriver.java"),
    ),
};

const RELAY: Shape = Shape {
    probe: (
        "RelayProbe.java",
        include_str!("fixtures/shape_matrix/RelayProbe.java"),
    ),
    driver: (
        "RelayDriver.java",
        include_str!("fixtures/shape_matrix/RelayDriver.java"),
    ),
};

const LONG_COMPARE: Shape = Shape {
    probe: (
        "LongCompareProbe.java",
        include_str!("fixtures/shape_matrix/LongCompareProbe.java"),
    ),
    driver: (
        "LongCompareDriver.java",
        include_str!("fixtures/shape_matrix/LongCompareDriver.java"),
    ),
};

const NAN_COMPARE: Shape = Shape {
    probe: (
        "NanCompareProbe.java",
        include_str!("fixtures/shape_matrix/NanCompareProbe.java"),
    ),
    driver: (
        "NanCompareDriver.java",
        include_str!("fixtures/shape_matrix/NanCompareDriver.java"),
    ),
};

const RECORD: Shape = Shape {
    probe: (
        "RecordProbe.java",
        include_str!("fixtures/shape_matrix/RecordProbe.java"),
    ),
    driver: (
        "RecordDriver.java",
        include_str!("fixtures/shape_matrix/RecordDriver.java"),
    ),
};

const TYPE_SWITCH: Shape = Shape {
    probe: (
        "TypeSwitchProbe.java",
        include_str!("fixtures/shape_matrix/TypeSwitchProbe.java"),
    ),
    driver: (
        "TypeSwitchDriver.java",
        include_str!("fixtures/shape_matrix/TypeSwitchDriver.java"),
    ),
};

const LOOP_HEADER: Shape = Shape {
    probe: (
        "LoopHeaderProbe.java",
        include_str!("fixtures/loop_coverage/LoopHeaderProbe.java"),
    ),
    driver: (
        "LoopHeaderDriver.java",
        include_str!("fixtures/loop_coverage/LoopHeaderDriver.java"),
    ),
};

const SYNC_LOOP: Shape = Shape {
    probe: (
        "SyncLoopProbe.java",
        include_str!("fixtures/loop_coverage/SyncLoopProbe.java"),
    ),
    driver: (
        "SyncLoopDriver.java",
        include_str!("fixtures/loop_coverage/SyncLoopDriver.java"),
    ),
};

const JSR_FINALLY: Shape = Shape {
    probe: (
        "FinallyProbe.java",
        include_str!("fixtures/ecj_jsr/FinallyProbe.java"),
    ),
    driver: (
        "FinallyDriver.java",
        include_str!("fixtures/shape_matrix/FinallyDriver.java"),
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

const INCOMPLETE_MARKER: &str =
    "// <decompile: incomplete: a reachable block has no rendered statement>";

fn assert_recovered_or_incomplete(compiler: Compiler, tag: &str, shape: &Shape, expected: &str) {
    let recovered: Recovery = recover(compiler, tag, shape);
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, expected,
        "the authored program's own output changed under {compiler:?}"
    );
    let refused: bool = source.contains(INCOMPLETE_MARKER)
        && recovered.decompiled.fully_lifted_methods < recovered.decompiled.method_count;
    match &recovered.recompiled_output {
        Ok(output) if output == &recovered.original_output => {}
        Ok(output) => panic!(
            "the recovered {tag} source runs differently from the {compiler:?} build ({output}); recovered source:\n{source}"
        ),
        Err(err) => assert!(
            refused,
            "the recovered {tag} source fails ({err}) without naming the incomplete method; recovered source:\n{source}"
        ),
    }
}

const DISPATCH_OUTPUT: &str = "-786089020;2404;2804;3004;2804;3604;4604;";

#[test]
fn a_returning_dispatcher_reading_its_state_is_recovered_or_marked_from_javac() {
    assert_recovered_or_incomplete(
        Compiler::Javac,
        "dispatch_javac",
        &DISPATCH,
        DISPATCH_OUTPUT,
    );
}

#[test]
fn a_returning_dispatcher_reading_its_state_is_recovered_or_marked_from_ecj() {
    assert_recovered_or_incomplete(Compiler::Ecj16, "dispatch_ecj", &DISPATCH, DISPATCH_OUTPUT);
}

const RELAY_OUTPUT: &str = "-1291;-291;709;1709;2709;3709;4709;";

#[test]
fn a_constant_dispatcher_reading_its_state_is_recovered_or_marked_from_javac() {
    assert_recovered_or_incomplete(Compiler::Javac, "relay_javac", &RELAY, RELAY_OUTPUT);
}

#[test]
fn a_constant_dispatcher_reading_its_state_is_recovered_or_marked_from_ecj() {
    assert_recovered_or_incomplete(Compiler::Ecj16, "relay_ecj", &RELAY, RELAY_OUTPUT);
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
        return;
    }
    assert!(
        source.contains(UNRESOLVED_INDY),
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
fn a_type_switch_invokedynamic_from_javac_is_recovered_or_named() {
    assert_named_indy_refusal(
        Compiler::Javac,
        "type_switch_javac",
        &TYPE_SWITCH,
        "int5,big12,str3,null,other,",
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

const CMP_VALUE_DRIVER: (&str, &str) = (
    "CmpValueDriver.java",
    include_str!("fixtures/shape_matrix/CmpValueDriver.java"),
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
