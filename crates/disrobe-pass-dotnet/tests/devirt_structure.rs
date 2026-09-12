use disrobe_pass_dotnet::devirt::{
    BasicBlock, BinOp, Budget, DvIr, IrInstruction, Terminator, ValueId,
    emit::emit_structured_pseudo_csharp,
    structure::{StructuredAst, structure},
};

fn if_diamond_ir() -> DvIr {
    DvIr::new(
        1,
        1,
        vec![
            BasicBlock::new(
                0,
                vec![IrInstruction::LoadArgument {
                    destination: ValueId::new(0),
                    index: 0,
                }],
                Terminator::CondBr {
                    condition: ValueId::new(0),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(2),
                },
            ),
            BasicBlock::new(
                1,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(1),
                        value: 7,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(1),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(3)),
            ),
            BasicBlock::new(
                2,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(2),
                        value: 9,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(2),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(3)),
            ),
            BasicBlock::new(
                3,
                vec![IrInstruction::LoadLocal {
                    destination: ValueId::new(3),
                    index: 0,
                }],
                Terminator::Ret(Some(ValueId::new(3))),
            ),
        ],
    )
}

fn counted_loop_ir() -> DvIr {
    DvIr::new(
        0,
        1,
        vec![
            BasicBlock::new(
                0,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(0),
                        value: 0,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(0),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                1,
                vec![
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(1),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(2),
                        value: 3,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(3),
                        op: BinOp::Clt,
                        left: ValueId::new(1),
                        right: ValueId::new(2),
                    },
                ],
                Terminator::CondBr {
                    condition: ValueId::new(3),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(2),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(3),
                },
            ),
            BasicBlock::new(
                2,
                vec![
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(4),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(5),
                        value: 1,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(6),
                        op: BinOp::Add,
                        left: ValueId::new(4),
                        right: ValueId::new(5),
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(6),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                3,
                vec![IrInstruction::LoadLocal {
                    destination: ValueId::new(7),
                    index: 0,
                }],
                Terminator::Ret(Some(ValueId::new(7))),
            ),
        ],
    )
}

fn nested_if_loop_ir() -> DvIr {
    DvIr::new(
        1,
        1,
        vec![
            BasicBlock::new(
                0,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(0),
                        value: 0,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(0),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                1,
                vec![
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(1),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(2),
                        value: 2,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(3),
                        op: BinOp::Clt,
                        left: ValueId::new(1),
                        right: ValueId::new(2),
                    },
                ],
                Terminator::CondBr {
                    condition: ValueId::new(3),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(2),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(6),
                },
            ),
            BasicBlock::new(
                2,
                vec![IrInstruction::LoadArgument {
                    destination: ValueId::new(4),
                    index: 0,
                }],
                Terminator::CondBr {
                    condition: ValueId::new(4),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(3),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(4),
                },
            ),
            BasicBlock::new(
                3,
                vec![IrInstruction::Const {
                    destination: ValueId::new(5),
                    value: 10,
                }],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(5)),
            ),
            BasicBlock::new(
                4,
                vec![IrInstruction::Const {
                    destination: ValueId::new(6),
                    value: 20,
                }],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(5)),
            ),
            BasicBlock::new(
                5,
                vec![
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(7),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(8),
                        value: 1,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(9),
                        op: BinOp::Add,
                        left: ValueId::new(7),
                        right: ValueId::new(8),
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(9),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                6,
                vec![IrInstruction::LoadLocal {
                    destination: ValueId::new(10),
                    index: 0,
                }],
                Terminator::Ret(Some(ValueId::new(10))),
            ),
        ],
    )
}

fn irreducible_ir() -> DvIr {
    DvIr::new(
        1,
        0,
        vec![
            BasicBlock::new(
                0,
                vec![IrInstruction::LoadArgument {
                    destination: ValueId::new(0),
                    index: 0,
                }],
                Terminator::CondBr {
                    condition: ValueId::new(0),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(2),
                },
            ),
            BasicBlock::new(
                1,
                Vec::new(),
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(3)),
            ),
            BasicBlock::new(
                2,
                Vec::new(),
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(3)),
            ),
            BasicBlock::new(
                3,
                Vec::new(),
                Terminator::CondBr {
                    condition: ValueId::new(0),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(4),
                },
            ),
            BasicBlock::new(4, Vec::new(), Terminator::Ret(Some(ValueId::new(0)))),
        ],
    )
}

fn straight_line_ir() -> DvIr {
    DvIr::new(
        0,
        0,
        vec![BasicBlock::new(
            0,
            vec![IrInstruction::Const {
                destination: ValueId::new(0),
                value: 7,
            }],
            Terminator::Ret(Some(ValueId::new(0))),
        )],
    )
}

fn loop_escape_ir(continue_on_true: bool) -> DvIr {
    let true_target: u32 = if continue_on_true { 1 } else { 4 };
    DvIr::new(
        1,
        1,
        vec![
            BasicBlock::new(
                0,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(0),
                        value: 0,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(0),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                1,
                vec![
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(1),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(2),
                        value: 4,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(3),
                        op: BinOp::Clt,
                        left: ValueId::new(1),
                        right: ValueId::new(2),
                    },
                ],
                Terminator::CondBr {
                    condition: ValueId::new(3),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(2),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(4),
                },
            ),
            BasicBlock::new(
                2,
                vec![IrInstruction::LoadArgument {
                    destination: ValueId::new(4),
                    index: 0,
                }],
                Terminator::CondBr {
                    condition: ValueId::new(4),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(true_target),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(3),
                },
            ),
            BasicBlock::new(
                3,
                vec![
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(5),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(6),
                        value: 1,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(7),
                        op: BinOp::Add,
                        left: ValueId::new(5),
                        right: ValueId::new(6),
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(7),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                4,
                vec![IrInstruction::LoadLocal {
                    destination: ValueId::new(8),
                    index: 0,
                }],
                Terminator::Ret(Some(ValueId::new(8))),
            ),
        ],
    )
}

fn pathological_ir() -> DvIr {
    let mut blocks: Vec<BasicBlock> = Vec::new();
    for id in 0_u32..256_u32 {
        let block: BasicBlock = if id == 255 {
            BasicBlock::new(
                id,
                vec![IrInstruction::Const {
                    destination: ValueId::new(0),
                    value: 0,
                }],
                Terminator::Ret(Some(ValueId::new(0))),
            )
        } else {
            BasicBlock::new(
                id,
                Vec::new(),
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(
                    id.saturating_add(1),
                )),
            )
        };
        blocks.push(block);
    }
    DvIr::new(0, 0, blocks)
}

fn do_while_ir() -> DvIr {
    DvIr::new(
        0,
        1,
        vec![
            BasicBlock::new(
                0,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(0),
                        value: 0,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(0),
                    },
                ],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                1,
                Vec::new(),
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(2)),
            ),
            BasicBlock::new(
                2,
                vec![
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(1),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(2),
                        value: 1,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(3),
                        op: BinOp::Add,
                        left: ValueId::new(1),
                        right: ValueId::new(2),
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(3),
                    },
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(4),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(5),
                        value: 3,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(6),
                        op: BinOp::Clt,
                        left: ValueId::new(4),
                        right: ValueId::new(5),
                    },
                ],
                Terminator::CondBr {
                    condition: ValueId::new(6),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(3),
                },
            ),
            BasicBlock::new(
                3,
                vec![IrInstruction::LoadLocal {
                    destination: ValueId::new(7),
                    index: 0,
                }],
                Terminator::Ret(Some(ValueId::new(7))),
            ),
        ],
    )
}

fn non_dominating_value_ir() -> DvIr {
    DvIr::new(
        1,
        1,
        vec![
            BasicBlock::new(
                0,
                vec![IrInstruction::LoadArgument {
                    destination: ValueId::new(0),
                    index: 0,
                }],
                Terminator::CondBr {
                    condition: ValueId::new(0),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(2),
                },
            ),
            BasicBlock::new(
                1,
                vec![IrInstruction::Const {
                    destination: ValueId::new(1),
                    value: 1,
                }],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(3)),
            ),
            BasicBlock::new(
                2,
                vec![IrInstruction::Const {
                    destination: ValueId::new(2),
                    value: 2,
                }],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(3)),
            ),
            BasicBlock::new(
                3,
                vec![
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(1),
                    },
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(3),
                        index: 0,
                    },
                ],
                Terminator::Ret(Some(ValueId::new(3))),
            ),
        ],
    )
}

fn do_while_header_value_escapes_scope_ir() -> DvIr {
    DvIr::new(
        0,
        0,
        vec![
            BasicBlock::new(
                0,
                Vec::new(),
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(1)),
            ),
            BasicBlock::new(
                1,
                vec![IrInstruction::Const {
                    destination: ValueId::new(0),
                    value: 7,
                }],
                Terminator::Br(disrobe_pass_dotnet::devirt::BlockId::new(2)),
            ),
            BasicBlock::new(
                2,
                vec![IrInstruction::Const {
                    destination: ValueId::new(1),
                    value: 0,
                }],
                Terminator::CondBr {
                    condition: ValueId::new(1),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(3),
                },
            ),
            BasicBlock::new(3, Vec::new(), Terminator::Ret(Some(ValueId::new(0)))),
        ],
    )
}

#[test]
fn structures_if_diamond_with_exact_pseudo_csharp() {
    let ir: DvIr = if_diamond_ir();
    let mut structure_budget: Budget = Budget::new(1_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(1_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(ast.fallback_reason().is_none());
    assert_eq!(
        rendered,
        concat!(
            "long recovered(long arg0)\n",
            "{\n",
            "    long local0 = 0L;\n",
            "\n",
            "    long v0 = arg0;\n",
            "    if (v0 != 0)\n",
            "    {\n",
            "        long v1 = 7L;\n",
            "        local0 = v1;\n",
            "    }\n",
            "    else\n",
            "    {\n",
            "        long v2 = 9L;\n",
            "        local0 = v2;\n",
            "    }\n",
            "    long v3 = local0;\n",
            "    return v3;\n",
            "}\n",
        )
    );
}

#[test]
fn structures_counted_loop_with_exact_pseudo_csharp() {
    let ir: DvIr = counted_loop_ir();
    let mut structure_budget: Budget = Budget::new(1_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(1_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(ast.fallback_reason().is_none());
    assert_eq!(
        rendered,
        concat!(
            "long recovered()\n",
            "{\n",
            "    long local0 = 0L;\n",
            "\n",
            "    long v0 = 0L;\n",
            "    local0 = v0;\n",
            "    long v1 = local0;\n",
            "    long v2 = 3L;\n",
            "    int v3 = (v1 < v2) ? 1 : 0;\n",
            "    while (v3 != 0)\n",
            "    {\n",
            "        long v4 = local0;\n",
            "        long v5 = 1L;\n",
            "        long v6 = v4 + v5;\n",
            "        local0 = v6;\n",
            "        v1 = local0;\n",
            "        v2 = 3L;\n",
            "        v3 = (v1 < v2) ? 1 : 0;\n",
            "    }\n",
            "    long v7 = local0;\n",
            "    return v7;\n",
            "}\n",
        )
    );
}

#[test]
fn structures_if_inside_loop_with_nested_control() {
    let ir: DvIr = nested_if_loop_ir();
    let mut structure_budget: Budget = Budget::new(2_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(2_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(ast.fallback_reason().is_none());
    assert_eq!(
        rendered,
        concat!(
            "long recovered(long arg0)\n",
            "{\n",
            "    long local0 = 0L;\n",
            "\n",
            "    long v0 = 0L;\n",
            "    local0 = v0;\n",
            "    long v1 = local0;\n",
            "    long v2 = 2L;\n",
            "    int v3 = (v1 < v2) ? 1 : 0;\n",
            "    while (v3 != 0)\n",
            "    {\n",
            "        long v4 = arg0;\n",
            "        if (v4 != 0)\n",
            "        {\n",
            "            long v5 = 10L;\n",
            "        }\n",
            "        else\n",
            "        {\n",
            "            long v6 = 20L;\n",
            "        }\n",
            "        long v7 = local0;\n",
            "        long v8 = 1L;\n",
            "        long v9 = v7 + v8;\n",
            "        local0 = v9;\n",
            "        v1 = local0;\n",
            "        v2 = 2L;\n",
            "        v3 = (v1 < v2) ? 1 : 0;\n",
            "    }\n",
            "    long v10 = local0;\n",
            "    return v10;\n",
            "}\n",
        )
    );
}

#[test]
fn irreducible_control_flow_uses_labeled_fallback_marker() {
    let ir: DvIr = irreducible_ir();
    let mut structure_budget: Budget = Budget::new(1_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(1_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert_eq!(ast.fallback_reason(), Some("irreducible control flow"));
    assert_eq!(
        rendered,
        concat!(
            "structured fallback: irreducible control flow\n",
            "long recovered(long arg0)\n",
            "{\n",
            "L0:\n",
            "    long v0 = arg0;\n",
            "    if (v0 != 0) goto L1;\n",
            "    goto L2;\n",
            "L1:\n",
            "    goto L3;\n",
            "L2:\n",
            "    goto L3;\n",
            "L3:\n",
            "    if (v0 != 0) goto L1;\n",
            "    goto L4;\n",
            "L4:\n",
            "    return v0;\n",
            "}\n",
        )
    );
}

#[test]
fn structures_straight_line_without_control_keywords() {
    let ir: DvIr = straight_line_ir();
    let mut structure_budget: Budget = Budget::new(100);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(100);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(ast.fallback_reason().is_none());
    assert!(!rendered.contains("if ("));
    assert!(!rendered.contains("while ("));
    assert!(!rendered.contains("goto "));
    assert_eq!(
        rendered,
        concat!(
            "long recovered()\n",
            "{\n",
            "    long v0 = 7L;\n",
            "    return v0;\n",
            "}\n",
        )
    );
}

#[test]
fn non_dominating_value_use_falls_back_without_invalid_scope() {
    let ir: DvIr = non_dominating_value_ir();
    let mut structure_budget: Budget = Budget::new(1_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(1_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(
        ast.fallback_reason()
            .is_some_and(|reason: &str| reason.contains("dominate"))
    );
    assert!(rendered.starts_with("structured fallback:"));
    assert!(rendered.contains("goto L"));
}

#[test]
fn do_while_header_value_that_escapes_lexical_scope_falls_back() {
    let ir: DvIr = do_while_header_value_escapes_scope_ir();
    let mut structure_budget: Budget = Budget::new(1_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(1_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(
        ast.fallback_reason()
            .is_some_and(|reason: &str| reason.contains("lexical scope"))
    );
    assert!(rendered.starts_with("structured fallback:"));
    assert!(rendered.contains("goto L"));
}

#[test]
fn structure_and_rendering_are_deterministic() {
    let ir: DvIr = nested_if_loop_ir();
    let mut first_structure_budget: Budget = Budget::new(2_000);
    let first_ast: StructuredAst = structure(&ir, &mut first_structure_budget);
    let mut second_structure_budget: Budget = Budget::new(2_000);
    let second_ast: StructuredAst = structure(&ir, &mut second_structure_budget);
    let mut first_render_budget: Budget = Budget::new(2_000);
    let first_rendered: String = emit_structured_pseudo_csharp(&ir, &mut first_render_budget);
    let mut second_render_budget: Budget = Budget::new(2_000);
    let second_rendered: String = emit_structured_pseudo_csharp(&ir, &mut second_render_budget);

    assert_eq!(first_ast, second_ast);
    assert_eq!(first_rendered, second_rendered);
}

#[test]
fn exhausted_budget_falls_back_without_unbounded_structuring() {
    let ir: DvIr = pathological_ir();
    let mut budget: Budget = Budget::new(1);
    let ast: StructuredAst = structure(&ir, &mut budget);

    assert!(
        ast.fallback_reason()
            .is_some_and(|reason: &str| reason.contains("budget"))
    );
}

#[test]
fn structures_reducible_loop_break_without_labeled_fallback() {
    let ir: DvIr = loop_escape_ir(false);
    let mut structure_budget: Budget = Budget::new(2_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(2_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(ast.fallback_reason().is_none());
    assert!(!rendered.contains("structured fallback:"));
    assert!(!rendered.contains("goto "));
    assert!(rendered.contains("if (v4 != 0)\n        {\n        }\n        else"));
    assert!(rendered.contains("continue;\n        }\n        break;"));
}

#[test]
fn recomputes_loop_predicate_after_non_tail_back_edge() {
    let ir: DvIr = loop_escape_ir(true);
    let mut structure_budget: Budget = Budget::new(2_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(2_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(ast.fallback_reason().is_none());
    assert!(!rendered.contains("structured fallback:"));
    assert_eq!(rendered.matches("v1 = local0;").count(), 2);
    assert_eq!(rendered.matches("v3 = (v1 < v2) ? 1 : 0;").count(), 2);
    assert!(rendered.contains(
        "local0 = v7;\n        }\n        v1 = local0;\n        v2 = 4L;\n        v3 = (v1 < v2) ? 1 : 0;"
    ));
}

#[test]
fn structures_do_while_with_exact_pseudo_csharp() {
    let ir: DvIr = do_while_ir();
    let mut structure_budget: Budget = Budget::new(1_000);
    let ast: StructuredAst = structure(&ir, &mut structure_budget);
    let mut render_budget: Budget = Budget::new(1_000);
    let rendered: String = emit_structured_pseudo_csharp(&ir, &mut render_budget);

    assert!(ast.fallback_reason().is_none());
    assert_eq!(
        rendered,
        concat!(
            "long recovered()\n",
            "{\n",
            "    long local0 = 0L;\n",
            "\n",
            "    long v0 = 0L;\n",
            "    local0 = v0;\n",
            "    int v6;\n",
            "    do\n",
            "    {\n",
            "        long v1 = local0;\n",
            "        long v2 = 1L;\n",
            "        long v3 = v1 + v2;\n",
            "        local0 = v3;\n",
            "        long v4 = local0;\n",
            "        long v5 = 3L;\n",
            "        v6 = (v4 < v5) ? 1 : 0;\n",
            "    } while (v6 != 0);\n",
            "    long v7 = local0;\n",
            "    return v7;\n",
            "}\n",
        )
    );
}
