use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use super::decompile::{Instruction, OperandValue};
use super::literals::{BufferKind, LiteralFormat, LiteralValue, decode_literals_in};
use super::{HERMES_SHAPE_TABLE_VERSION, HermesModule, ObjectShape};

const MAX_SHAPE_PROPERTIES: usize = 1 << 16;

#[must_use]
pub(crate) fn uses_modern_instructions(version: u32) -> bool {
    version >= HERMES_SHAPE_TABLE_VERSION
}

#[must_use]
pub(crate) fn shape_keys(module: &HermesModule, shape: u64) -> Option<Vec<LiteralValue>> {
    let entry: &ObjectShape = module.obj_shape_table.get(usize::try_from(shape).ok()?)?;
    let count: usize = usize::try_from(entry.property_count).ok()?;
    if count > MAX_SHAPE_PROPERTIES {
        return None;
    }
    let keys: Vec<LiteralValue> = decode_literals_in(
        LiteralFormat::for_version(module.header.version),
        &module.obj_key_buffer,
        usize::try_from(entry.key_buffer_offset).ok()?,
        count,
        BufferKind::Key,
    );
    (keys.len() == count).then_some(keys)
}

fn renamed(inst: &mut Instruction, name: &'static str) {
    inst.name = Cow::Borrowed(name);
}

fn keep_operands(inst: &mut Instruction, keep: &[usize]) {
    let operands: Vec<OperandValue> = keep
        .iter()
        .filter_map(|index: &usize| inst.operands.get(*index).copied())
        .collect();
    inst.operands = operands;
}

fn register(inst: &Instruction, index: usize) -> Option<u32> {
    match inst.operands.get(index) {
        Some(OperandValue::Reg(reg)) => Some(*reg),
        _ => None,
    }
}

fn unsigned(inst: &Instruction, index: usize) -> Option<u64> {
    match inst.operands.get(index) {
        Some(OperandValue::UInt(value)) => Some(*value),
        _ => None,
    }
}

fn written_register(inst: &Instruction) -> Option<u32> {
    let name: &str = &inst.name;
    if name.starts_with("Put")
        || name.starts_with("Store")
        || name.starts_with("Define")
        || name.starts_with('J')
        || matches!(
            name,
            "CacheNewObject" | "Ret" | "Throw" | "ThrowIfThisInitialized"
        )
    {
        return None;
    }
    register(inst, 0)
}

fn clobbers_several(inst: &Instruction) -> bool {
    matches!(
        &*inst.name,
        "IteratorBegin" | "IteratorNext" | "GetPNameList" | "GetNextPName"
    ) || inst.name.starts_with("CreateBaseClass")
        || inst.name.starts_with("CreateDerivedClass")
}

fn block_starts(
    instructions: &[Instruction],
    handler_targets: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let mut starts: BTreeSet<usize> = handler_targets.clone();
    for (position, inst) in instructions.iter().enumerate() {
        for operand in &inst.operands {
            if let OperandValue::Target(target) = operand {
                starts.insert(*target);
                if let Some(next) = instructions.get(position + 1) {
                    starts.insert(next.offset);
                }
            }
        }
    }
    starts
}

fn slot_key(
    shapes: &BTreeMap<u32, Vec<LiteralValue>>,
    inst: &Instruction,
    object_at: usize,
    slot_at: usize,
) -> Option<LiteralValue> {
    let object: u32 = register(inst, object_at)?;
    let slot: usize = usize::try_from(unsigned(inst, slot_at)?).ok()?;
    shapes.get(&object)?.get(slot).cloned()
}

fn rewrite_slot_store(inst: &mut Instruction, key: LiteralValue) {
    match key {
        LiteralValue::StringId(id) => {
            renamed(inst, "PutNewOwnByIdLong");
            keep_operands(inst, &[0, 1]);
            inst.operands.push(OperandValue::StringId(id));
        }
        LiteralValue::Integer(index) if index >= 0 => {
            renamed(inst, "PutOwnByIndexL");
            keep_operands(inst, &[0, 1]);
            inst.operands
                .push(OperandValue::UInt(index.unsigned_abs().into()));
        }
        _ => {}
    }
}

fn rewrite_slot_load(inst: &mut Instruction, key: LiteralValue) {
    if let LiteralValue::StringId(id) = key {
        renamed(inst, "GetByIdLong");
        keep_operands(inst, &[0, 1]);
        inst.operands.push(OperandValue::UInt(0));
        inst.operands.push(OperandValue::StringId(id));
    }
}

#[must_use]
pub(crate) fn normalize(
    module: &HermesModule,
    handler_targets: &BTreeSet<usize>,
    mut instructions: Vec<Instruction>,
) -> Vec<Instruction> {
    let starts: BTreeSet<usize> = block_starts(&instructions, handler_targets);
    let mut shapes: BTreeMap<u32, Vec<LiteralValue>> = BTreeMap::new();
    for inst in &mut instructions {
        if starts.contains(&inst.offset) {
            shapes.clear();
        }
        let created_shape: Option<(u32, Vec<LiteralValue>)> = match &*inst.name {
            "NewObjectWithBuffer" | "NewObjectWithBufferLong" => register(inst, 0)
                .zip(unsigned(inst, 1).and_then(|shape: u64| shape_keys(module, shape))),
            "NewObjectWithBufferAndParent" => register(inst, 0)
                .zip(unsigned(inst, 2).and_then(|shape: u64| shape_keys(module, shape))),
            _ => None,
        };
        match &*inst.name {
            "PutByIdLoose" | "PutByIdStrict" => renamed(inst, "PutById"),
            "PutByIdLooseLong" | "PutByIdStrictLong" => renamed(inst, "PutByIdLong"),
            "TryPutByIdLoose" | "TryPutByIdStrict" => renamed(inst, "TryPutById"),
            "TryPutByIdLooseLong" | "TryPutByIdStrictLong" => renamed(inst, "TryPutByIdLong"),
            "DefineOwnById" => {
                renamed(inst, "PutNewOwnById");
                keep_operands(inst, &[0, 1, 3]);
            }
            "DefineOwnByIdLong" => {
                renamed(inst, "PutNewOwnByIdLong");
                keep_operands(inst, &[0, 1, 3]);
            }
            "DefineOwnByIndex" | "DefineOwnInDenseArray" => renamed(inst, "PutOwnByIndex"),
            "DefineOwnByIndexL" | "DefineOwnInDenseArrayL" => renamed(inst, "PutOwnByIndexL"),
            "DefineOwnByVal" => renamed(inst, "PutOwnByVal"),
            "DefineOwnGetterSetterByVal" => renamed(inst, "PutOwnGetterSetterByVal"),
            "PutByValLoose" | "PutByValStrict" => renamed(inst, "PutByVal"),
            "DelByVal" => keep_operands(inst, &[0, 1, 2]),
            "AddS" => renamed(inst, "Add"),
            "ReifyArgumentsLoose" | "ReifyArgumentsStrict" => renamed(inst, "ReifyArguments"),
            "GetArgumentsPropByValLoose" | "GetArgumentsPropByValStrict" => {
                renamed(inst, "GetArgumentsPropByVal");
            }
            "UIntSwitchImm" => renamed(inst, "SwitchImm"),
            "CreateFunctionEnvironment" | "CreateTopLevelEnvironment" => {
                renamed(inst, "CreateEnvironment");
            }
            "GetParentEnvironment" => renamed(inst, "GetEnvironment"),
            "CreateEnvironment" => renamed(inst, "CreateInnerEnvironment"),
            "GetEnvironment" => renamed(inst, "GetEnvironmentFrom"),
            "CreateThisForNew" => {
                renamed(inst, "CreateThis");
                keep_operands(inst, &[0, 1, 1]);
            }
            "CreateThisForSuper" => {
                renamed(inst, "CreateThis");
                keep_operands(inst, &[0, 1, 1]);
            }
            "CallWithNewTarget" => {
                renamed(inst, "ConstructWithNewTarget");
                keep_operands(inst, &[0, 1, 3, 2]);
            }
            "CreateGenerator" => renamed(inst, "CreateGeneratorObject"),
            "CreateGeneratorLongIndex" => renamed(inst, "CreateGeneratorObjectLongIndex"),
            "NewObjectWithBuffer" | "NewObjectWithBufferLong" => {
                renamed(inst, "NewObjectWithShape");
            }
            "NewObjectWithBufferAndParent" => renamed(inst, "NewObjectWithShapeAndParent"),
            "PutOwnBySlotIdx" | "PutOwnBySlotIdxLong" => {
                if let Some(key) = slot_key(&shapes, inst, 0, 2) {
                    rewrite_slot_store(inst, key);
                }
            }
            "GetOwnBySlotIdx" | "GetOwnBySlotIdxLong" => {
                if let Some(key) = slot_key(&shapes, inst, 1, 2) {
                    rewrite_slot_load(inst, key);
                }
            }
            _ => {}
        }
        if clobbers_several(inst) {
            shapes.clear();
        } else if let Some(written) = written_register(inst) {
            shapes.remove(&written);
        }
        if let Some((object, keys)) = created_shape {
            shapes.insert(object, keys);
        }
        if inst.name.starts_with('J') || matches!(&*inst.name, "Ret" | "Throw") {
            shapes.clear();
        }
    }
    instructions
}
