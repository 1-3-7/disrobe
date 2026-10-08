use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{Instruction, MethodBody, OperandValue};
use crate::model::{AssemblyModel, MethodModel, TypeModel};
use crate::peel::obfuscar_strings::{ObfuscarStringRecovery, recover_obfuscar_strings};
use crate::peel::string_emu::RecoveredString;
use crate::tables::NestedClassRow;

use super::body::replace_in_place;
use super::{Literals, Residual};

pub(crate) const LAYER_HIDE_STRINGS: &str = "Obfuscar HideStrings";

#[derive(Debug)]
pub(crate) struct ObfuscarLayer {
    accessors: BTreeMap<u32, String>,
    pub(crate) runtime_methods: BTreeSet<u32>,
    pub(crate) runtime_types: BTreeSet<u32>,
    pub(crate) carrier_count: u32,
    pub(crate) string_sites: u32,
}

impl ObfuscarLayer {
    pub(crate) fn build(
        image: &[u8],
        model: &AssemblyModel,
        nested: &[NestedClassRow],
        residuals: &mut Vec<Residual>,
    ) -> Self {
        let recovery: ObfuscarStringRecovery = recover_obfuscar_strings(image);
        if let Some(reason) = &recovery.unknown_reason {
            residuals.push(Residual {
                layer: LAYER_HIDE_STRINGS.to_owned(),
                method_token: None,
                reason: reason.clone(),
            });
        }
        let mut accessors: BTreeMap<u32, String> = BTreeMap::new();
        for entry in recovery.recovered {
            let RecoveredString {
                method_token, text, ..
            } = entry;
            accessors.insert(method_token, text);
        }
        let mut runtime_methods: BTreeSet<u32> = accessors.keys().copied().collect();
        let mut runtime_types: BTreeSet<u32> = BTreeSet::new();
        for ty in &model.types {
            let owns_accessor: bool = ty
                .methods
                .iter()
                .any(|m: &MethodModel| accessors.contains_key(&m.token));
            if owns_accessor {
                runtime_types.insert(ty.token);
                for m in &ty.methods {
                    runtime_methods.insert(m.token);
                }
            }
        }
        for row in nested {
            let enclosing: u32 = 0x0200_0000 | row.enclosing_class;
            if runtime_types.contains(&enclosing) {
                let nested_token: u32 = 0x0200_0000 | row.nested_class;
                runtime_types.insert(nested_token);
                if let Some(ty) = model
                    .types
                    .iter()
                    .find(|t: &&TypeModel| t.token == nested_token)
                {
                    for m in &ty.methods {
                        runtime_methods.insert(m.token);
                    }
                }
            }
        }
        Self {
            accessors,
            runtime_methods,
            runtime_types,
            carrier_count: recovery.carrier_count,
            string_sites: 0,
        }
    }

    #[must_use]
    pub(crate) fn present(&self) -> bool {
        !self.accessors.is_empty()
    }

    pub(crate) fn rewrite(
        &mut self,
        method_token: u32,
        body: &mut MethodBody,
        literals: &mut Literals,
        residuals: &mut Vec<Residual>,
    ) -> bool {
        if self.accessors.is_empty() {
            return false;
        }
        let mut changed: bool = false;
        for index in 0..body.instructions.len() {
            let ins: &Instruction = &body.instructions[index];
            if ins.name != "call" {
                continue;
            }
            let OperandValue::Token(token) = ins.operand else {
                continue;
            };
            let Some(text): Option<&String> = self.accessors.get(&token) else {
                continue;
            };
            let Some(synthetic): Option<u32> = literals.intern(text.encode_utf16().collect())
            else {
                residuals.push(Residual {
                    layer: LAYER_HIDE_STRINGS.to_owned(),
                    method_token: Some(method_token),
                    reason: "the synthetic string table is full".to_owned(),
                });
                return changed;
            };
            if replace_in_place(
                &mut body.instructions[index],
                "ldstr",
                OperandValue::Token(synthetic),
            ) {
                self.string_sites = self.string_sites.saturating_add(1);
                changed = true;
            }
        }
        changed
    }
}
