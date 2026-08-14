use super::super::{BinOp, LoopCond, MemRmwOp, UnOp};
use super::*;

fn r64(reg: Reg) -> RegRef {
    RegRef {
        reg,
        width: Width::W64,
    }
}

fn mem(base: Reg, disp: i64) -> MemRef {
    MemRef {
        base: Some(base),
        index: None,
        disp,
        width: Width::W64,
    }
}

fn assign(dest: Reg, src: Source) -> Node {
    Node::Stmt(Stmt::Assign {
        dest: r64(dest),
        src,
    })
}

fn bin(dest: Reg, op: BinOp, src: Source) -> Node {
    Node::Stmt(Stmt::BinAssign {
        dest: r64(dest),
        op,
        src,
    })
}

fn store(addr: MemRef, src: Source) -> Node {
    Node::Stmt(Stmt::Store { addr, src })
}

fn call(args: Vec<Reg>) -> Node {
    Node::Stmt(Stmt::Call {
        target: 0x1000,
        args,
        name: Some("callee".to_owned()),
    })
}

fn reg_src(reg: Reg) -> Source {
    Source::Reg(r64(reg))
}

fn plan(body: &Block) -> SpillOutcome {
    let mut copy: Block = body.clone();
    inline_single_use_definitions(&mut copy, &[])
}

fn run(body: &[Node]) -> (Block, SpillOutcome) {
    let mut block: Block = body.to_vec();
    let outcome: SpillOutcome = inline_single_use_definitions(&mut block, &[]);
    (block, outcome)
}

fn reason_for(outcome: &SpillOutcome, dest: Reg) -> Option<SpillReason> {
    outcome
        .decisions
        .iter()
        .find(|decision: &&SpillDecision| decision.dest == dest)
        .and_then(|decision: &SpillDecision| decision.facts.reason)
}

#[test]
fn a_single_use_register_copy_is_inlined_into_its_use() {
    let (block, outcome): (Block, SpillOutcome) = run(&[
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ]);
    assert_eq!(outcome.inlined, 1);
    assert_eq!(block.len(), 1);
    assert_eq!(block[0], bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rsi)));
}

#[test]
fn a_single_use_load_is_inlined_when_nothing_intervenes() {
    let (block, outcome): (Block, SpillOutcome) = run(&[
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 8))),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ]);
    assert_eq!(outcome.inlined, 1);
    assert_eq!(
        block,
        vec![bin(Reg::Rdi, BinOp::Add, Source::Mem(mem(Reg::Rsi, 8)))]
    );
}

#[test]
fn a_value_read_twice_keeps_its_named_temporary() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 0))),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
        bin(Reg::R8, BinOp::Xor, reg_src(Reg::Rbx)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(
        reason_for(&outcome, Reg::Rbx),
        Some(SpillReason::MultipleUses)
    );
    let facts: UseFacts = plan(&body)
        .decisions
        .iter()
        .find(|decision: &&SpillDecision| decision.dest == Reg::Rbx)
        .map(|decision: &SpillDecision| decision.facts.uses)
        .expect("the twice-read value is classified");
    assert_eq!(facts.textual, 2);
}

#[test]
fn an_operand_written_between_the_definition_and_the_use_is_never_inlined() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        assign(Reg::Rsi, Source::Imm(5)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(
        reason_for(&outcome, Reg::Rbx),
        Some(SpillReason::Crosses(InlineBarrier::OperandWrite))
    );
}

#[test]
fn a_load_never_moves_past_an_aliasing_store() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 0))),
        store(mem(Reg::Rsi, 0), Source::Imm(7)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(
        reason_for(&outcome, Reg::Rbx),
        Some(SpillReason::Crosses(InlineBarrier::Store))
    );
}

#[test]
fn a_load_moves_past_a_store_that_cannot_alias() {
    let (block, outcome): (Block, SpillOutcome) = run(&[
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 0))),
        store(mem(Reg::Rsi, 64), Source::Imm(7)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ]);
    assert_eq!(outcome.inlined, 1);
    assert_eq!(block.len(), 2);
}

#[test]
fn a_load_never_moves_past_a_call() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 0))),
        call(vec![Reg::Rcx]),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(
        reason_for(&outcome, Reg::Rbx),
        Some(SpillReason::Crosses(InlineBarrier::Call))
    );
}

#[test]
fn a_load_never_moves_past_an_aliasing_read_modify_write() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 0))),
        Node::Stmt(Stmt::MemRmw {
            addr: mem(Reg::Rsi, 0),
            op: MemRmwOp::Un(UnOp::Not),
        }),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(
        reason_for(&outcome, Reg::Rbx),
        Some(SpillReason::Crosses(InlineBarrier::Atomic))
    );
}

#[test]
fn a_definition_whose_only_use_sits_inside_a_loop_is_not_sunk_into_it() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 0))),
        Node::While {
            body: vec![bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx))],
            cond: None,
        },
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(reason_for(&outcome, Reg::Rbx), Some(SpillReason::LoopDepth));
    let facts: UseFacts = plan(&body)
        .decisions
        .iter()
        .find(|decision: &&SpillDecision| decision.dest == Reg::Rbx)
        .map(|decision: &SpillDecision| decision.facts.uses)
        .expect("the loop-sunk value is classified");
    assert_eq!(facts.textual, 1);
    assert!(facts.loop_weighted > facts.textual);
}

#[test]
fn a_definition_read_after_a_control_flow_join_is_not_inlined() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        Node::Label(1),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(
        reason_for(&outcome, Reg::Rbx),
        Some(SpillReason::LiveAfterUse)
    );
}

#[test]
fn a_call_argument_accepts_a_register_rename_but_refuses_a_load() {
    let (renamed, rename_outcome): (Block, SpillOutcome) =
        run(&[assign(Reg::Rcx, reg_src(Reg::Rbx)), call(vec![Reg::Rcx])]);
    assert_eq!(rename_outcome.inlined, 1);
    assert_eq!(renamed, vec![call(vec![Reg::Rbx])]);

    let loaded: Vec<Node> = vec![
        assign(Reg::Rcx, Source::Mem(mem(Reg::Rbx, 0))),
        call(vec![Reg::Rcx]),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&loaded);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, loaded);
    assert_eq!(
        reason_for(&outcome, Reg::Rcx),
        Some(SpillReason::NoSubstitutableUse)
    );
}

#[test]
fn a_live_out_register_definition_is_never_removed() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let mut block: Block = body.clone();
    let outcome: SpillOutcome = inline_single_use_definitions(&mut block, &[Reg::Rbx]);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
}

#[test]
fn the_return_register_is_never_inlined_away() {
    let body: Vec<Node> = vec![
        assign(Reg::Rax, reg_src(Reg::Rsi)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rax)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
}

#[test]
fn an_unstructured_goto_blocks_a_definition_with_an_earlier_read() {
    let body: Vec<Node> = vec![
        Node::Stmt(Stmt::Store {
            addr: mem(Reg::R9, 0),
            src: reg_src(Reg::Rbx),
        }),
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        bin(Reg::R8, BinOp::Xor, reg_src(Reg::Rbx)),
        Node::Goto(1),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
}

#[test]
fn a_loop_carried_read_before_the_definition_blocks_the_rewrite() {
    let body: Vec<Node> = vec![Node::While {
        body: vec![
            bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
            assign(Reg::Rbx, reg_src(Reg::Rsi)),
            bin(Reg::R8, BinOp::Xor, reg_src(Reg::Rbx)),
        ],
        cond: None,
    }];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
}

#[test]
fn a_loop_body_definition_with_no_earlier_read_is_still_inlined() {
    let (block, outcome): (Block, SpillOutcome) = run(&[Node::While {
        body: vec![
            assign(Reg::Rbx, reg_src(Reg::Rsi)),
            bin(Reg::R8, BinOp::Xor, reg_src(Reg::Rbx)),
        ],
        cond: None,
    }]);
    assert_eq!(outcome.inlined, 1);
    assert_eq!(
        block,
        vec![Node::While {
            body: vec![bin(Reg::R8, BinOp::Xor, reg_src(Reg::Rsi))],
            cond: None,
        }]
    );
}

#[test]
fn a_flag_operand_read_is_never_substituted() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        Node::Stmt(Stmt::FlagSnapshot {
            var: 0,
            kind: CondKind::E,
            flags: Flags::Cmp {
                lhs: r64(Reg::Rbx),
                rhs: Source::Imm(0),
            },
        }),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
    assert_eq!(
        reason_for(&outcome, Reg::Rbx),
        Some(SpillReason::NoSubstitutableUse)
    );
}

#[test]
fn a_loop_condition_read_keeps_the_definition() {
    let body: Vec<Node> = vec![Node::DoWhile {
        body: vec![assign(Reg::Rbx, reg_src(Reg::Rsi))],
        cond: LoopCond::Direct {
            cond: CondKind::Ne,
            flags: Flags::Cmp {
                lhs: r64(Reg::Rbx),
                rhs: Source::Imm(0),
            },
        },
    }];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
}

#[test]
fn chained_single_use_copies_collapse_to_one_statement() {
    let (block, outcome): (Block, SpillOutcome) = run(&[
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        assign(Reg::R8, reg_src(Reg::Rbx)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::R8)),
    ]);
    assert_eq!(outcome.inlined, 2);
    assert_eq!(block, vec![bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rsi))]);
}

#[test]
fn a_round_trip_through_a_scratch_register_collapses_without_a_self_assignment() {
    let (block, outcome): (Block, SpillOutcome) = run(&[
        assign(Reg::Rbx, reg_src(Reg::Rsi)),
        assign(Reg::R8, reg_src(Reg::Rbx)),
        assign(Reg::Rbx, reg_src(Reg::R8)),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ]);
    assert!(outcome.inlined >= 1);
    assert!(
        !block.iter().any(|node: &Node| matches!(
            node,
            Node::Stmt(Stmt::Assign {
                dest,
                src: Source::Reg(source)
            }) if dest.reg == source.reg
        )),
        "{block:?}"
    );
    assert_eq!(block, vec![bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rsi))]);
}

#[test]
fn the_rewrite_is_byte_identical_across_repeated_runs() {
    let body: Vec<Node> = vec![
        assign(Reg::Rbx, Source::Mem(mem(Reg::Rsi, 0))),
        assign(Reg::R8, reg_src(Reg::Rdi)),
        store(mem(Reg::R9, 32), reg_src(Reg::R8)),
        bin(Reg::R10, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let (first, first_outcome): (Block, SpillOutcome) = run(&body);
    let (second, second_outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(first, second);
    assert_eq!(first_outcome.inlined, second_outcome.inlined);
    assert_eq!(
        format!("{:?}", first_outcome.decisions),
        format!("{:?}", second_outcome.decisions)
    );
}

#[test]
fn a_narrow_definition_is_left_alone() {
    let body: Vec<Node> = vec![
        Node::Stmt(Stmt::Assign {
            dest: RegRef {
                reg: Reg::Rbx,
                width: Width::W32,
            },
            src: reg_src(Reg::Rsi),
        }),
        bin(Reg::Rdi, BinOp::Add, reg_src(Reg::Rbx)),
    ];
    let (block, outcome): (Block, SpillOutcome) = run(&body);
    assert_eq!(outcome.inlined, 0);
    assert_eq!(block, body);
}

#[test]
fn spill_facts_report_inlinability_from_one_struct() {
    let facts: SpillFacts = SpillFacts {
        uses: UseFacts {
            textual: 1,
            loop_weighted: 1,
        },
        reason: None,
    };
    assert!(facts.inlinable());
    let blocked: SpillFacts = SpillFacts {
        uses: facts.uses,
        reason: Some(SpillReason::Crosses(InlineBarrier::Call)),
    };
    assert!(!blocked.inlinable());
}
