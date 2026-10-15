use std::collections::BTreeMap;

use super::HermesModule;
use super::decompile::{Instruction, OperandValue, decode_for_lift, lift_specs};
use super::lift::{call_frame_size, metro_registrations};
use super::literals::{BufferKind, LiteralFormat, LiteralValue, decode_literals_in};
use super::opcodes::OpcodeSpec;
use crate::react_native::assets::{
    AssetSite, Known, MAX_ASSET_LITERAL_KEYS, MAX_SCALES, PACKAGER_MARKER, RnAsset,
    asset_from_fields,
};

struct Scanner<'a> {
    module: &'a HermesModule,
    format: LiteralFormat,
}

impl Scanner<'_> {
    fn text(&self, id: u32) -> Option<String> {
        self.module.string_by_global_id(id).map(str::to_owned)
    }

    fn literal(&self, value: &LiteralValue) -> Option<Known> {
        match value {
            LiteralValue::StringId(id) => self.text(*id).map(Known::Text),
            LiteralValue::Integer(i) => Some(Known::Number(f64::from(*i))),
            LiteralValue::Number(n) => Some(Known::Number(*n)),
            LiteralValue::Bool(b) => Some(Known::Bool(*b)),
            LiteralValue::Null | LiteralValue::Undefined | LiteralValue::PrivateName => None,
        }
    }

    fn keys_and_values(
        &self,
        inst: &Instruction,
    ) -> Option<(Vec<LiteralValue>, Vec<LiteralValue>)> {
        let uint = |index: usize| -> Option<u64> {
            match inst.operands.get(index) {
                Some(OperandValue::UInt(value)) => Some(*value),
                _ => None,
            }
        };
        match &*inst.name {
            "NewObjectWithShape" | "NewObjectWithShapeAndParent" => {
                let (shape_at, values_at): (usize, usize) = if inst.name == "NewObjectWithShape" {
                    (1, 2)
                } else {
                    (2, 3)
                };
                let keys: Vec<LiteralValue> =
                    super::modern::shape_keys(self.module, uint(shape_at)?)?;
                if keys.len() > MAX_ASSET_LITERAL_KEYS {
                    return None;
                }
                let values: Vec<LiteralValue> = decode_literals_in(
                    self.format,
                    &self.module.array_buffer,
                    usize::try_from(uint(values_at)?).ok()?,
                    keys.len(),
                    BufferKind::Value,
                );
                Some((keys, values))
            }
            "NewObjectWithBuffer" | "NewObjectWithBufferLong" => {
                let count: usize = usize::try_from(uint(2)?).ok()?;
                if count > MAX_ASSET_LITERAL_KEYS {
                    return None;
                }
                let keys: Vec<LiteralValue> = decode_literals_in(
                    self.format,
                    &self.module.obj_key_buffer,
                    usize::try_from(uint(3)?).ok()?,
                    count,
                    BufferKind::Key,
                );
                let values: Vec<LiteralValue> = decode_literals_in(
                    self.format,
                    &self.module.obj_value_buffer,
                    usize::try_from(uint(4)?).ok()?,
                    count,
                    BufferKind::Value,
                );
                Some((keys, values))
            }
            _ => None,
        }
    }

    fn array(&self, inst: &Instruction) -> Option<Known> {
        let uint = |index: usize| -> Option<u64> {
            match inst.operands.get(index) {
                Some(OperandValue::UInt(value)) => Some(*value),
                _ => None,
            }
        };
        let count: usize = usize::try_from(uint(2)?).ok()?;
        if count > MAX_SCALES {
            return None;
        }
        let values: Vec<LiteralValue> = decode_literals_in(
            self.format,
            &self.module.array_buffer,
            usize::try_from(uint(3)?).ok()?,
            count,
            BufferKind::Value,
        );
        values
            .iter()
            .map(|value: &LiteralValue| match self.literal(value) {
                Some(Known::Number(n)) => Some(n),
                _ => None,
            })
            .collect::<Option<Vec<f64>>>()
            .map(Known::Numbers)
    }

    fn constant(&self, inst: &Instruction) -> Option<Known> {
        let operand = inst.operands.get(1);
        match (&*inst.name, operand) {
            ("LoadConstString" | "LoadConstStringLongIndex", Some(OperandValue::StringId(id))) => {
                self.text(*id).map(Known::Text)
            }
            ("LoadConstUInt8", Some(OperandValue::UInt(value))) => {
                Some(Known::Number(*value as f64))
            }
            ("LoadConstInt", Some(OperandValue::Imm(value))) => Some(Known::Number(*value as f64)),
            ("LoadConstDouble", Some(OperandValue::Float(bits))) => {
                Some(Known::Number(f64::from_bits(*bits)))
            }
            ("LoadConstZero", _) => Some(Known::Number(0.0)),
            ("LoadConstTrue", _) => Some(Known::Bool(true)),
            ("LoadConstFalse", _) => Some(Known::Bool(false)),
            ("NewArrayWithBuffer" | "NewArrayWithBufferLong", _) => self.array(inst),
            _ => None,
        }
    }

    fn scan(&self, instructions: &[Instruction]) -> Vec<BTreeMap<String, Known>> {
        let mut registers: BTreeMap<u32, Known> = BTreeMap::new();
        let mut objects: BTreeMap<u32, usize> = BTreeMap::new();
        let mut found: Vec<BTreeMap<String, Known>> = Vec::new();
        for inst in instructions {
            let reg = |index: usize| -> Option<u32> {
                match inst.operands.get(index) {
                    Some(OperandValue::Reg(reg)) => Some(*reg),
                    _ => None,
                }
            };
            let name: &str = &inst.name;
            if name.starts_with('J') || matches!(name, "Ret" | "Throw" | "Catch") {
                registers.clear();
                objects.clear();
            }
            if let Some((keys, values)) = self.keys_and_values(inst)
                && let Some(dest) = reg(0)
            {
                let mut fields: BTreeMap<String, Known> = BTreeMap::new();
                for (key, value) in keys.iter().zip(values.iter()) {
                    if let Some(Known::Text(key)) = self.literal(key)
                        && let Some(value) = self.literal(value)
                    {
                        fields.insert(key, value);
                    }
                }
                registers.remove(&dest);
                objects.remove(&dest);
                if fields.contains_key(PACKAGER_MARKER) {
                    objects.insert(dest, found.len());
                    found.push(fields);
                }
                continue;
            }
            let store: Option<(u32, u32, u32)> = match name {
                "PutNewOwnById" | "PutNewOwnByIdShort" | "PutNewOwnByIdLong" => {
                    match inst.operands.get(2) {
                        Some(OperandValue::StringId(id)) => {
                            reg(0).zip(reg(1)).map(|(o, v)| (o, v, *id))
                        }
                        _ => None,
                    }
                }
                "PutById" | "PutByIdLong" => match inst.operands.get(3) {
                    Some(OperandValue::StringId(id)) => {
                        reg(0).zip(reg(1)).map(|(o, v)| (o, v, *id))
                    }
                    _ => None,
                },
                _ => None,
            };
            if let Some((object, value, key)) = store {
                if let Some(slot) = objects.get(&object).copied()
                    && let Some(key) = self.text(key)
                    && let Some(known) = registers.get(&value).cloned()
                    && let Some(fields) = found.get_mut(slot)
                {
                    fields.insert(key, known);
                }
                continue;
            }
            if let Some(dest) = reg(0)
                && !name.starts_with("Put")
                && !name.starts_with("Store")
                && !name.starts_with('J')
            {
                objects.remove(&dest);
                match self.constant(inst) {
                    Some(known) => {
                        registers.insert(dest, known);
                    }
                    None => {
                        if matches!(name, "Mov" | "MovLong")
                            && let Some(source) = reg(1)
                            && let Some(known) = registers.get(&source).cloned()
                        {
                            registers.insert(dest, known);
                        } else {
                            registers.remove(&dest);
                        }
                    }
                }
            }
        }
        found
    }
}

#[must_use]
pub fn react_native_assets(module: &HermesModule) -> Vec<RnAsset> {
    let Some(specs): Option<&'static [OpcodeSpec]> = lift_specs(module.header.version) else {
        return Vec::new();
    };
    let scanner: Scanner<'_> = Scanner {
        module,
        format: LiteralFormat::for_version(module.header.version),
    };
    let global: usize = module.header.global_code_index as usize;
    let factories: BTreeMap<u32, u64> = module
        .functions
        .get(global)
        .map(|header| {
            let instructions: Vec<Instruction> = decode_for_lift(module, global, specs);
            metro_registrations(module, &instructions, call_frame_size(module, header))
                .into_iter()
                .map(|registration| (registration.factory, registration.id))
                .collect()
        })
        .unwrap_or_default();
    let mut out: Vec<RnAsset> = Vec::new();
    for function in 0..module.functions.len() {
        let instructions: Vec<Instruction> = decode_for_lift(module, function, specs);
        for fields in scanner.scan(&instructions) {
            let site: AssetSite = AssetSite {
                hermes_function: Some(function),
                source_offset: None,
                metro_module: u32::try_from(function)
                    .ok()
                    .and_then(|fid: u32| factories.get(&fid).copied()),
            };
            if let Some(asset) = asset_from_fields(&fields, site) {
                out.push(asset);
            }
        }
    }
    out
}
