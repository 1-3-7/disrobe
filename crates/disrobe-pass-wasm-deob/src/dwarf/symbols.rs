use std::collections::BTreeMap;

use serde::Serialize;

use crate::dwarf::unit::{RawParameter, RawSubprogram, RawVariable, UnitBundle};

pub type FunctionId = u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParameterInfo {
    pub name: Option<String>,
    pub type_id: Option<TypeRef>,
    pub decl_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VariableInfo {
    pub name: Option<String>,
    pub type_id: Option<TypeRef>,
    pub decl_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionInfo {
    pub id: FunctionId,
    pub name: Option<String>,
    pub linkage_name: Option<String>,
    pub source_file: Option<String>,
    pub decl_line: Option<u32>,
    pub low_pc: Option<u64>,
    pub high_pc: Option<u64>,
    pub return_type: Option<TypeRef>,
    pub parameters: Vec<ParameterInfo>,
    pub variables: Vec<VariableInfo>,
    pub unit_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct TypeRef(pub u64);

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolTable {
    pub functions: BTreeMap<FunctionId, FunctionInfo>,
}

impl SymbolTable {
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    #[must_use]
    pub fn lookup_by_pc(&self, pc: u64) -> Option<&FunctionInfo> {
        self.functions
            .values()
            .find(|f| match (f.low_pc, f.high_pc) {
                (Some(low), Some(high)) => pc >= low && pc < high,
                _ => false,
            })
    }
}

pub fn build(
    bundles: &[UnitBundle],
    file_for_index: &dyn Fn(u64, u64) -> Option<String>,
) -> SymbolTable {
    let mut functions: BTreeMap<FunctionId, FunctionInfo> = BTreeMap::new();
    for bundle in bundles {
        for sub in &bundle.subprograms {
            let id: FunctionId = sub.die_offset;
            let source_file: Option<String> = sub
                .decl_file_index
                .and_then(|idx: u64| file_for_index(bundle.compile_unit.unit_offset, idx));
            functions.insert(id, lower_subprogram(sub, source_file));
        }
    }
    SymbolTable { functions }
}

fn lower_subprogram(sub: &RawSubprogram, source_file: Option<String>) -> FunctionInfo {
    let parameters: Vec<ParameterInfo> = sub
        .parameters
        .iter()
        .map(lower_parameter)
        .collect::<Vec<_>>();
    let variables: Vec<VariableInfo> = sub.variables.iter().map(lower_variable).collect::<Vec<_>>();
    FunctionInfo {
        id: sub.die_offset,
        name: sub.name.clone(),
        linkage_name: sub.linkage_name.clone(),
        source_file,
        decl_line: sub.decl_line,
        low_pc: sub.low_pc,
        high_pc: sub.high_pc,
        return_type: sub.return_type_offset.map(TypeRef),
        parameters,
        variables,
        unit_offset: sub.unit_offset,
    }
}

#[inline]
fn lower_parameter(p: &RawParameter) -> ParameterInfo {
    ParameterInfo {
        name: p.name.clone(),
        type_id: p.type_offset.map(TypeRef),
        decl_line: p.decl_line,
    }
}

#[inline]
fn lower_variable(v: &RawVariable) -> VariableInfo {
    VariableInfo {
        name: v.name.clone(),
        type_id: v.type_offset.map(TypeRef),
        decl_line: v.decl_line,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_fn(id: u64, low: Option<u64>, high: Option<u64>) -> FunctionInfo {
        FunctionInfo {
            id,
            name: Some(format!("fn_{id}")),
            linkage_name: None,
            source_file: None,
            decl_line: None,
            low_pc: low,
            high_pc: high,
            return_type: None,
            parameters: Vec::new(),
            variables: Vec::new(),
            unit_offset: 0,
        }
    }

    #[test]
    fn lookup_by_pc_matches_range() {
        let mut table: SymbolTable = SymbolTable::default();
        table
            .functions
            .insert(1, make_fn(1, Some(0x100), Some(0x200)));
        table
            .functions
            .insert(2, make_fn(2, Some(0x200), Some(0x300)));
        assert_eq!(table.lookup_by_pc(0x150).map(|f| f.id), Some(1));
        assert_eq!(table.lookup_by_pc(0x200).map(|f| f.id), Some(2));
        assert!(table.lookup_by_pc(0x500).is_none());
    }

    #[test]
    fn empty_table_lookup_returns_none() {
        let table: SymbolTable = SymbolTable::default();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(table.lookup_by_pc(0).is_none());
    }
}
