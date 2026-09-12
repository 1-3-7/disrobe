use disrobe_pass_dotnet::devirt::{
    BasicBlock, BinOp, DvIr, IrInstruction, Terminator, ValueId,
    emit::{emit_normalized_cil, emit_pseudo_csharp},
};

fn recovered_ir() -> DvIr {
    DvIr::new(
        2,
        0,
        vec![BasicBlock::new(
            0,
            vec![
                IrInstruction::LoadArgument {
                    destination: ValueId::new(0),
                    index: 0,
                },
                IrInstruction::LoadArgument {
                    destination: ValueId::new(1),
                    index: 1,
                },
                IrInstruction::Binary {
                    destination: ValueId::new(2),
                    op: BinOp::Add,
                    left: ValueId::new(0),
                    right: ValueId::new(1),
                },
                IrInstruction::Const {
                    destination: ValueId::new(3),
                    value: 0x5a,
                },
                IrInstruction::Binary {
                    destination: ValueId::new(4),
                    op: BinOp::Xor,
                    left: ValueId::new(2),
                    right: ValueId::new(3),
                },
            ],
            Terminator::Ret(Some(ValueId::new(4))),
        )],
    )
}

fn control_flow_ir() -> DvIr {
    DvIr::new(
        1,
        1,
        vec![
            BasicBlock::new(
                0,
                vec![
                    IrInstruction::LoadArgument {
                        destination: ValueId::new(0),
                        index: 0,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(0),
                    },
                    IrInstruction::LoadLocal {
                        destination: ValueId::new(1),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(2),
                        value: 0,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(3),
                        op: BinOp::Ceq,
                        left: ValueId::new(1),
                        right: ValueId::new(2),
                    },
                ],
                Terminator::CondBr {
                    condition: ValueId::new(3),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(2),
                },
            ),
            BasicBlock::new(
                1,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(4),
                        value: 1,
                    },
                    IrInstruction::StoreArgument {
                        index: 0,
                        value: ValueId::new(4),
                    },
                ],
                Terminator::Ret(Some(ValueId::new(4))),
            ),
            BasicBlock::new(
                2,
                vec![
                    IrInstruction::Const {
                        destination: ValueId::new(5),
                        value: 2,
                    },
                    IrInstruction::StoreLocal {
                        index: 0,
                        value: ValueId::new(5),
                    },
                ],
                Terminator::Ret(Some(ValueId::new(5))),
            ),
        ],
    )
}

#[test]
fn recovered_arithmetic_has_exact_deterministic_renderings() {
    let ir: DvIr = recovered_ir();
    let pseudo: String = emit_pseudo_csharp(&ir);
    let cil: String = emit_normalized_cil(&ir);

    assert_eq!(
        pseudo,
        concat!(
            "long recovered(long arg0, long arg1)\n",
            "{\n",
            "L0:\n",
            "    long v0 = arg0;\n",
            "    long v1 = arg1;\n",
            "    long v2 = v0 + v1;\n",
            "    long v3 = 90L;\n",
            "    long v4 = v2 ^ v3;\n",
            "    return v4;\n",
            "}\n",
        )
    );
    assert_eq!(
        cil,
        concat!(
            ".method int64 recovered(int64 arg0, int64 arg1)\n",
            "{\n",
            "L0:\n",
            "    ldarg 0 -> v0\n",
            "    ldarg 1 -> v1\n",
            "    add v0, v1 -> v2\n",
            "    ldc.i8 90 -> v3\n",
            "    xor v2, v3 -> v4\n",
            "    ret v4\n",
            "}\n",
        )
    );
    assert_eq!(pseudo, emit_pseudo_csharp(&ir));
    assert_eq!(cil, emit_normalized_cil(&ir));
}

#[test]
fn empty_method_has_local_declaration_and_void_return() {
    let ir: DvIr = DvIr::new(
        0,
        1,
        vec![BasicBlock::new(0, Vec::new(), Terminator::Ret(None))],
    );

    assert_eq!(
        emit_pseudo_csharp(&ir),
        concat!(
            "void recovered()\n",
            "{\n",
            "    long local0 = 0L;\n",
            "\n",
            "L0:\n",
            "    return;\n",
            "}\n",
        )
    );
    assert_eq!(
        emit_normalized_cil(&ir),
        concat!(
            ".method void recovered()\n",
            "{\n",
            "    .locals init ([0] int64 local0)\n",
            "L0:\n",
            "    ret\n",
            "}\n",
        )
    );
}

#[test]
fn single_value_return_has_exact_renderings() {
    let ir: DvIr = DvIr::new(
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
    );

    assert_eq!(
        emit_pseudo_csharp(&ir),
        concat!(
            "long recovered()\n",
            "{\n",
            "L0:\n",
            "    long v0 = 7L;\n",
            "    return v0;\n",
            "}\n",
        )
    );
    assert_eq!(
        emit_normalized_cil(&ir),
        concat!(
            ".method int64 recovered()\n",
            "{\n",
            "L0:\n",
            "    ldc.i8 7 -> v0\n",
            "    ret v0\n",
            "}\n",
        )
    );
}

#[test]
fn branches_and_slot_mutations_remain_explicit() {
    let ir: DvIr = control_flow_ir();

    assert_eq!(
        emit_pseudo_csharp(&ir),
        concat!(
            "long recovered(long arg0)\n",
            "{\n",
            "    long local0 = 0L;\n",
            "\n",
            "L0:\n",
            "    long v0 = arg0;\n",
            "    local0 = v0;\n",
            "    long v1 = local0;\n",
            "    long v2 = 0L;\n",
            "    int v3 = (v1 == v2) ? 1 : 0;\n",
            "    if (v3 != 0) goto L1;\n",
            "    goto L2;\n",
            "L1:\n",
            "    long v4 = 1L;\n",
            "    arg0 = v4;\n",
            "    return v4;\n",
            "L2:\n",
            "    long v5 = 2L;\n",
            "    local0 = v5;\n",
            "    return v5;\n",
            "}\n",
        )
    );
    assert_eq!(
        emit_normalized_cil(&ir),
        concat!(
            ".method int64 recovered(int64 arg0)\n",
            "{\n",
            "    .locals init ([0] int64 local0)\n",
            "L0:\n",
            "    ldarg 0 -> v0\n",
            "    stloc 0, v0\n",
            "    ldloc 0 -> v1\n",
            "    ldc.i8 0 -> v2\n",
            "    ceq v1, v2 -> v3\n",
            "    brtrue v3, L1, L2\n",
            "L1:\n",
            "    ldc.i8 1 -> v4\n",
            "    starg 0, v4\n",
            "    ret v4\n",
            "L2:\n",
            "    ldc.i8 2 -> v5\n",
            "    stloc 0, v5\n",
            "    ret v5\n",
            "}\n",
        )
    );
}

#[test]
fn invalid_ir_is_marked_unrecovered() {
    let ir: DvIr = DvIr::new(
        0,
        0,
        vec![BasicBlock::new(
            0,
            vec![IrInstruction::Binary {
                destination: ValueId::new(0),
                op: BinOp::Add,
                left: ValueId::new(1),
                right: ValueId::new(2),
            }],
            Terminator::Ret(Some(ValueId::new(0))),
        )],
    );

    assert_eq!(
        emit_pseudo_csharp(&ir),
        "/* unrecovered: invalid DvIr: IR use precedes its definition */\n"
    );
    assert_eq!(
        emit_normalized_cil(&ir),
        "/* unrecovered: invalid DvIr: IR use precedes its definition */\n"
    );
}
