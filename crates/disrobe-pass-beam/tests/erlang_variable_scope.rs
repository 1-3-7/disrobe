#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::erlang_scope::{UnboundReference, clause_count, unbound_references};
use common::erlang_toolchain::{Erlang, require_erlang, run_bounded};
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::body_lift::comprehension::resugar_module;
use disrobe_pass_beam::body_lift::expr::{BinSegment, CaseArm, CatchArm, Expr, FnClause, Stmt};
use disrobe_pass_beam::body_lift::{LiftedBody, lift_function};
use disrobe_pass_beam::core_erlang::{CoreClause, CoreFunction, CoreModule};
use disrobe_pass_beam::{AtomTable, BeamFile, Chunks, Instruction, Operand, lift};

fn tracked_beam_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
}

const TRACKED_BEAMS: [(&str, &str, usize); 6] = [
    ("erlang", "hello.beam", 1),
    ("disasm_oracle", "probe.beam", 5),
    ("disasm_oracle", "probe2.beam", 12),
    ("megafile", "edge_cases.beam", 60),
    ("megafile", "Elixir.EdgeCases.MyServer.beam", 6),
    ("elixir", "Elixir.Hello.beam", 2),
];

const TOTAL_CLAUSE_FLOOR: usize = 110;

fn core_lift_of(directory: &str, file: &str) -> CoreModule {
    let path: PathBuf = tracked_beam_dir().join(directory).join(file);
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read tracked {}: {e}", path.display()));
    let beam: BeamFile =
        BeamFile::parse(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    let mut core: CoreModule =
        lift(&beam).unwrap_or_else(|e| panic!("core lift {}: {e}", path.display()));
    resugar_module(&mut core);
    core
}

#[test]
fn core_lifted_bodies_bind_every_variable_they_read() {
    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    println!("\n=== VARIABLE SCOPE OF THE BYTECODE CORE LIFT (no erlang toolchain involved) ===");
    for (directory, file, clause_floor) in TRACKED_BEAMS {
        let core: CoreModule = core_lift_of(directory, file);
        let clauses: usize = clause_count(&core);
        assert!(
            clauses >= clause_floor,
            "{file} lifted {clauses} clauses, below the {clause_floor} this fixture carries, so \
             the scope property would grade almost nothing"
        );
        let found: Vec<UnboundReference> = unbound_references(&core);
        checked += clauses;
        println!(
            "  {:<40} clauses {clauses:<4} unbound reads {}",
            file,
            found.len()
        );
        for reference in &found {
            println!("       {reference}");
            failures.push(format!("{file}: {reference}"));
        }
    }
    println!("clauses checked: {checked}\n");
    assert!(
        checked >= TOTAL_CLAUSE_FLOOR,
        "the tracked beam fixtures now yield {checked} clauses, below the {TOTAL_CLAUSE_FLOOR} \
         floor, so this property covers less than it did"
    );
    assert!(
        failures.is_empty(),
        "the core lift emits {} variable reads that nothing binds, which erlc rejects as unbound \
         variables:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

const GRADED: &str = "variable scope of the bytecode core lift over the erlang recompile corpus";

const CORPUS_CLAUSE_FLOOR: usize = 140;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
        .join("recompile_oracle")
}

fn compile_module(erlc: &Path, src: &Path, out_dir: &Path) -> Result<(), String> {
    let mut cmd: Command = Command::new(erlc);
    cmd.arg("-o").arg(out_dir).arg(src);
    match run_bounded(cmd) {
        Some((true, _, _)) => Ok(()),
        Some((false, so, se)) => Err(format!("stdout:\n{so}\nstderr:\n{se}")),
        None => Err("erlc timed out".to_owned()),
    }
}

#[test]
fn core_lifted_corpus_bodies_bind_every_variable_they_read() {
    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let mut modules: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .expect("read corpus dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path: &PathBuf| path.extension().is_some_and(|ext| ext == "erl"))
        .collect();
    modules.sort();
    assert!(
        modules.len() >= 19,
        "the recompile corpus regressed to {} modules",
        modules.len()
    );

    let scratch: ScratchDir =
        ScratchDir::create("disrobe_beam_scope_corpus").expect("create scratch directory");
    let out_dir: &Path = scratch.path();
    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    println!(
        "\n=== VARIABLE SCOPE OF THE BYTECODE CORE LIFT (erlc from OTP {}) ===",
        erlang.release
    );
    for src in &modules {
        let name: String = src
            .file_stem()
            .expect("module stem")
            .to_string_lossy()
            .into_owned();
        if let Err(detail) = compile_module(&erlang.erlc, src, out_dir) {
            panic!("corpus module {name} must compile:\n{detail}");
        }
        let bytes: Vec<u8> =
            std::fs::read(out_dir.join(format!("{name}.beam"))).expect("read compiled beam");
        let beam: BeamFile = BeamFile::parse(&bytes).expect("parse compiled beam");
        let mut core: CoreModule = lift(&beam).expect("core lift");
        resugar_module(&mut core);
        let clauses: usize = clause_count(&core);
        let found: Vec<UnboundReference> = unbound_references(&core);
        checked += clauses;
        println!(
            "  {name:<18} clauses {clauses:<4} unbound reads {}",
            found.len()
        );
        for reference in &found {
            println!("       {reference}");
            failures.push(format!("{name}: {reference}"));
        }
    }
    println!("clauses checked: {checked}\n");
    assert!(
        checked >= CORPUS_CLAUSE_FLOOR,
        "the corpus now yields {checked} clauses, below the {CORPUS_CLAUSE_FLOOR} floor, so this \
         property covers less than it did"
    );
    assert!(
        failures.is_empty(),
        "the core lift emits {} variable reads that nothing binds, which erlc rejects as unbound \
         variables:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

const MATCH_DIRECTIVES: [&str; 11] = [
    "ensure_at_least",
    "ensure_exactly",
    "integer",
    "binary",
    "float",
    "utf8",
    "skip",
    "get_tail",
    "=:=",
    "test_tail",
    "nil",
];

fn directive_chunks() -> Chunks {
    Chunks {
        atoms: AtomTable {
            atoms: MATCH_DIRECTIVES
                .iter()
                .map(|name: &&str| (*name).to_owned())
                .collect(),
        },
        code: None,
        strings: None,
        attributes: None,
        compile_info: None,
        dbgi: None,
        docs: None,
        exports: Vec::new(),
        imports: Vec::new(),
        locals: Vec::new(),
        literals: None,
        line: None,
        funs: Vec::new(),
        other: BTreeMap::new(),
    }
}

fn directive(name: &str) -> Operand {
    let index: usize = MATCH_DIRECTIVES
        .iter()
        .position(|known: &&str| *known == name)
        .expect("directive is in the match atom table");
    Operand::Atom(u32::try_from(index).expect("index fits") + 1)
}

fn value_command(kind: &str, size: u64, destination: u32) -> Vec<Operand> {
    vec![
        directive(kind),
        Operand::Literal(3),
        Operand::Literal(0b100),
        Operand::Literal(size),
        Operand::Literal(1),
        Operand::XReg(destination),
    ]
}

fn instruction(name: &'static str, operands: Vec<Operand>) -> Instruction {
    Instruction {
        offset: 0,
        opcode: 0,
        name,
        operands,
    }
}

#[test]
fn an_exactly_sized_binary_match_lifts_a_head_that_binds_what_its_body_reads() {
    let mut commands: Vec<Operand> = vec![directive("ensure_exactly"), Operand::Literal(24)];
    commands.extend(value_command("integer", 8, 1));
    commands.extend(value_command("integer", 16, 2));
    let instrs: Vec<Instruction> = vec![
        instruction("label", vec![Operand::Literal(1)]),
        instruction(
            "bs_start_match3",
            vec![
                Operand::Label(0),
                Operand::XReg(0),
                Operand::Literal(1),
                Operand::XReg(0),
            ],
        ),
        instruction(
            "bs_match",
            vec![Operand::Label(0), Operand::XReg(0), Operand::List(commands)],
        ),
        instruction(
            "put_tuple2",
            vec![
                Operand::XReg(0),
                Operand::List(vec![Operand::XReg(1), Operand::XReg(2)]),
            ],
        ),
        instruction("return", Vec::new()),
    ];

    let (clauses, complete): (Vec<FnClause>, bool) =
        lift_function(&instrs, 1, &directive_chunks(), &BTreeMap::new());
    assert!(complete, "an exactly sized match is a complete lift");
    assert_eq!(clauses.len(), 1);
    assert_eq!(
        clauses[0].patterns.len(),
        1,
        "the match belongs in the clause head, not the body"
    );
    let core: CoreModule = module_of(
        "signed",
        1,
        clauses
            .into_iter()
            .map(|lifted: FnClause| CoreClause {
                params: Vec::new(),
                patterns: lifted.patterns,
                guard: lifted.guard,
                instructions: Vec::new(),
                body: LiftedBody {
                    stmts: lifted.body,
                    lift_complete: true,
                },
            })
            .collect(),
    );
    assert_eq!(unbound_references(&core), Vec::new());
}

fn clause(patterns: Vec<Expr>, stmts: Vec<Stmt>) -> CoreClause {
    CoreClause {
        params: Vec::new(),
        patterns,
        guard: None,
        instructions: Vec::new(),
        body: LiftedBody {
            stmts,
            lift_complete: true,
        },
    }
}

fn module_of(name: &str, arity: u32, clauses: Vec<CoreClause>) -> CoreModule {
    CoreModule {
        module: "probe".to_owned(),
        exports: vec![(name.to_owned(), arity)],
        imports: Vec::new(),
        functions: vec![CoreFunction {
            name: name.to_owned(),
            arity,
            label: 1,
            exported: true,
            clauses,
        }],
    }
}

fn var(name: &str) -> Expr {
    Expr::Var(name.to_owned())
}

fn segment(
    value: Expr,
    size: Option<Expr>,
    kind: &str,
    flags: Vec<String>,
    unit: u32,
) -> BinSegment {
    BinSegment {
        value: Box::new(value),
        size: size.map(Box::new),
        unit,
        kind: kind.to_owned(),
        flags,
    }
}

fn signed_pair_pattern() -> Expr {
    Expr::BinaryConstruct(vec![
        segment(
            var("B0"),
            Some(Expr::Int(16)),
            "integer",
            vec!["signed".to_owned()],
            1,
        ),
        segment(var("B1"), None, "binary", Vec::new(), 8),
    ])
}

fn names_of(found: &[UnboundReference]) -> Vec<String> {
    found
        .iter()
        .map(|r: &UnboundReference| r.variable.clone())
        .collect()
}

#[test]
fn a_body_reading_names_its_binary_pattern_never_bound_is_reported() {
    let core: CoreModule = module_of(
        "signed",
        1,
        vec![clause(
            vec![signed_pair_pattern()],
            vec![Stmt::Return(Expr::Tuple(vec![var("X2"), var("X0")]))],
        )],
    );
    let found: Vec<UnboundReference> = unbound_references(&core);
    assert_eq!(names_of(&found), vec!["X2".to_owned(), "X0".to_owned()]);
    assert_eq!(found[0].function, "signed");
    assert_eq!(found[0].arity, 1);
}

#[test]
fn a_body_reading_the_names_its_binary_pattern_bound_is_accepted() {
    let core: CoreModule = module_of(
        "signed",
        1,
        vec![clause(
            vec![signed_pair_pattern()],
            vec![Stmt::Return(Expr::Tuple(vec![var("B0"), var("B1")]))],
        )],
    );
    assert_eq!(unbound_references(&core), Vec::new());
}

#[test]
fn a_head_the_emitter_replaces_with_synthetic_parameters_binds_those_names() {
    let arity_mismatch: CoreModule = module_of(
        "signed",
        2,
        vec![clause(
            vec![signed_pair_pattern()],
            vec![Stmt::Return(Expr::Tuple(vec![var("X0"), var("X1")]))],
        )],
    );
    assert_eq!(unbound_references(&arity_mismatch), Vec::new());

    let reads_the_dropped_names: CoreModule = module_of(
        "signed",
        2,
        vec![clause(
            vec![signed_pair_pattern()],
            vec![Stmt::Return(Expr::Tuple(vec![var("B0"), var("B1")]))],
        )],
    );
    assert_eq!(
        names_of(&unbound_references(&reads_the_dropped_names)),
        vec!["B0".to_owned(), "B1".to_owned()]
    );
}

#[test]
fn a_binary_pattern_sized_by_an_earlier_segment_is_accepted() {
    let dynamic_size: Expr = Expr::BinaryConstruct(vec![
        segment(var("B0"), Some(Expr::Int(8)), "integer", Vec::new(), 1),
        segment(var("B1"), Some(var("B0")), "binary", Vec::new(), 8),
    ]);
    let core: CoreModule = module_of(
        "dynsize",
        1,
        vec![clause(
            vec![dynamic_size],
            vec![Stmt::Return(Expr::Tuple(vec![var("B0"), var("B1")]))],
        )],
    );
    assert_eq!(unbound_references(&core), Vec::new());
}

fn case_binding_arms(second_arm_binds: bool) -> Expr {
    Expr::Case {
        subject: Box::new(var("X0")),
        arms: vec![
            CaseArm {
                pattern: Expr::Atom("a".to_owned()),
                guard: None,
                body: vec![Stmt::Bind {
                    pattern: var("T0"),
                    value: Expr::Int(1),
                }],
            },
            CaseArm {
                pattern: Expr::Atom("b".to_owned()),
                guard: None,
                body: vec![if second_arm_binds {
                    Stmt::Bind {
                        pattern: var("T0"),
                        value: Expr::Int(2),
                    }
                } else {
                    Stmt::Expr(Expr::Int(2))
                }],
            },
        ],
    }
}

#[test]
fn a_variable_every_case_arm_binds_is_readable_after_the_case() {
    let core: CoreModule = module_of(
        "pick",
        1,
        vec![clause(
            vec![var("X0")],
            vec![Stmt::Expr(case_binding_arms(true)), Stmt::Return(var("T0"))],
        )],
    );
    assert_eq!(unbound_references(&core), Vec::new());
}

#[test]
fn a_variable_only_one_case_arm_binds_does_not_escape_the_case() {
    let core: CoreModule = module_of(
        "pick",
        1,
        vec![clause(
            vec![var("X0")],
            vec![
                Stmt::Expr(case_binding_arms(false)),
                Stmt::Return(var("T0")),
            ],
        )],
    );
    assert_eq!(names_of(&unbound_references(&core)), vec!["T0".to_owned()]);
}

#[test]
fn a_catch_class_variable_binds_for_its_arm_body() {
    let with_class_variable: Expr = Expr::Try {
        body: vec![Stmt::Return(Expr::Atom("ok".to_owned()))],
        of_arms: Vec::new(),
        catch_arms: vec![CatchArm {
            class: "Class".to_owned(),
            pattern: var("Reason"),
            stacktrace: Some("Stack".to_owned()),
            body: vec![Stmt::Return(Expr::Tuple(vec![
                var("Class"),
                var("Reason"),
                var("Stack"),
            ]))],
        }],
        after: Vec::new(),
    };
    let core: CoreModule = module_of(
        "classify",
        0,
        vec![clause(Vec::new(), vec![Stmt::Return(with_class_variable)])],
    );
    assert_eq!(unbound_references(&core), Vec::new());

    let atom_class: Expr = Expr::Try {
        body: vec![Stmt::Return(Expr::Atom("ok".to_owned()))],
        of_arms: Vec::new(),
        catch_arms: vec![CatchArm {
            class: "error".to_owned(),
            pattern: var("Reason"),
            stacktrace: None,
            body: vec![Stmt::Return(Expr::Tuple(vec![var("Class"), var("Reason")]))],
        }],
        after: Vec::new(),
    };
    let reads_a_class_it_never_named: CoreModule = module_of(
        "classify",
        0,
        vec![clause(Vec::new(), vec![Stmt::Return(atom_class)])],
    );
    assert_eq!(
        names_of(&unbound_references(&reads_a_class_it_never_named)),
        vec!["Class".to_owned()]
    );
}

#[test]
fn a_resugared_comprehension_binds_its_generator_patterns() {
    let fragment: &str = "[{T0, T1} || {T0, T1} <- X0, is_atom(T0), T1 >= 1]";
    let over_a_bound_source: CoreModule = module_of(
        "filtered",
        1,
        vec![clause(
            vec![var("X0")],
            vec![Stmt::Return(Expr::Raw(fragment.to_owned()))],
        )],
    );
    assert_eq!(unbound_references(&over_a_bound_source), Vec::new());

    let over_an_unbound_source: CoreModule = module_of(
        "filtered",
        1,
        vec![clause(
            vec![var("X1")],
            vec![Stmt::Return(Expr::Raw(fragment.to_owned()))],
        )],
    );
    assert_eq!(
        names_of(&unbound_references(&over_an_unbound_source)),
        vec!["X0".to_owned()]
    );
}
