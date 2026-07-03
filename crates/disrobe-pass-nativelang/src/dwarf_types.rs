use disrobe_pass_native::{
    CoverageScore, ReconstructedType, SplitDwarfInfo, TypeKind, TypeMember, TypeReconstruction,
    reconstruct_dwarf_types,
};
use serde::{Deserialize, Serialize};

use crate::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceGrade {
    None,
    SymbolsOnly,
    TypesAndLines,
}

impl SourceGrade {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SymbolsOnly => "symbols-only",
            Self::TypesAndLines => "types-and-lines",
        }
    }

    #[must_use]
    pub const fn recoverable(self) -> bool {
        matches!(self, Self::TypesAndLines)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructedMember {
    pub name: String,
    pub type_name: String,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructedTypeReport {
    pub name: String,
    pub kind: String,
    pub byte_size: Option<u64>,
    pub members: Vec<ReconstructedMember>,
    pub template_params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeReport {
    pub present: bool,
    pub types: Vec<ReconstructedTypeReport>,
    pub named_type_count: u32,
    pub text_size: u64,
    pub line_covered_bytes: u64,
    pub line_coverage_pct: f64,
    pub grade: SourceGrade,
    pub has_skeleton_units: bool,
    pub dwo_names: Vec<String>,
}

impl TypeReport {
    #[must_use]
    pub const fn absent(has_symbol_table: bool) -> Self {
        Self {
            present: false,
            types: Vec::new(),
            named_type_count: 0,
            text_size: 0,
            line_covered_bytes: 0,
            line_coverage_pct: 0.0,
            grade: if has_symbol_table {
                SourceGrade::SymbolsOnly
            } else {
                SourceGrade::None
            },
            has_skeleton_units: false,
            dwo_names: Vec::new(),
        }
    }
}

const LINE_COVERAGE_GRADE_FLOOR: f64 = 50.0;
const MAX_REPORTED_TYPES: usize = 1 << 16;

#[must_use]
pub fn recover_types(bytes: &[u8], has_symbol_table: bool) -> TypeReport {
    debug::dbg_section("dwarf-types");
    let Ok(rec): Result<TypeReconstruction, _> = reconstruct_dwarf_types(bytes) else {
        debug::dbg_line(|| {
            "dwarf-types wall: object carries no .debug_info; falling back to symbol grade"
                .to_owned()
        });
        return TypeReport::absent(has_symbol_table);
    };
    let coverage: CoverageScore = rec.coverage;
    let line_coverage_pct: f64 = coverage.pct();
    let named_type_count: u32 = u32::try_from(rec.named_type_count()).unwrap_or(u32::MAX);
    let grade: SourceGrade = grade_for(named_type_count, line_coverage_pct, has_symbol_table);
    debug::dbg_kv("dwarf-types-recovered", || rec.types.len().to_string());
    debug::dbg_kv("dwarf-types-named", || named_type_count.to_string());
    debug::dbg_kv("dwarf-line-coverage", || format!("{line_coverage_pct:.1}%"));
    debug::dbg_kv("dwarf-source-grade", || grade.label().to_owned());
    let split: SplitDwarfInfo = rec.split_dwarf;
    let types: Vec<ReconstructedTypeReport> = rec
        .types
        .into_iter()
        .take(MAX_REPORTED_TYPES)
        .map(render_type)
        .collect();
    TypeReport {
        present: true,
        types,
        named_type_count,
        text_size: coverage.text_size,
        line_covered_bytes: coverage.covered_bytes,
        line_coverage_pct,
        grade,
        has_skeleton_units: split.has_skeleton_units,
        dwo_names: split.dwo_names,
    }
}

fn grade_for(named_type_count: u32, line_coverage_pct: f64, has_symbol_table: bool) -> SourceGrade {
    if named_type_count > 0 && line_coverage_pct >= LINE_COVERAGE_GRADE_FLOOR {
        SourceGrade::TypesAndLines
    } else if has_symbol_table || named_type_count > 0 {
        SourceGrade::SymbolsOnly
    } else {
        SourceGrade::None
    }
}

fn render_type(t: ReconstructedType) -> ReconstructedTypeReport {
    ReconstructedTypeReport {
        name: t.name,
        kind: kind_label(t.kind).to_owned(),
        byte_size: t.byte_size,
        members: t.members.into_iter().map(render_member).collect(),
        template_params: t.template_params,
    }
}

fn render_member(m: TypeMember) -> ReconstructedMember {
    ReconstructedMember {
        name: m.name,
        type_name: m.type_name,
        offset: m.offset,
    }
}

const fn kind_label(kind: TypeKind) -> &'static str {
    match kind {
        TypeKind::Base => "base",
        TypeKind::Pointer => "pointer",
        TypeKind::Reference => "reference",
        TypeKind::Structure => "structure",
        TypeKind::Class => "class",
        TypeKind::Union => "union",
        TypeKind::Enumeration => "enumeration",
        TypeKind::Array => "array",
        TypeKind::Typedef => "typedef",
        TypeKind::Const => "const",
        TypeKind::Volatile => "volatile",
        TypeKind::Subroutine => "subroutine",
        TypeKind::Unspecified => "unspecified",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn grade_promotes_only_with_types_and_line_coverage() {
        assert_eq!(grade_for(12, 92.0, true), SourceGrade::TypesAndLines);
        assert_eq!(grade_for(12, 92.0, false), SourceGrade::TypesAndLines);
        assert_eq!(grade_for(0, 92.0, true), SourceGrade::SymbolsOnly);
        assert_eq!(grade_for(5, 10.0, true), SourceGrade::SymbolsOnly);
        assert_eq!(grade_for(0, 0.0, true), SourceGrade::SymbolsOnly);
        assert_eq!(grade_for(0, 0.0, false), SourceGrade::None);
    }

    #[test]
    fn absent_report_grades_by_symbol_table() {
        let with_syms: TypeReport = TypeReport::absent(true);
        assert!(!with_syms.present);
        assert_eq!(with_syms.grade, SourceGrade::SymbolsOnly);
        assert!(!with_syms.grade.recoverable());
        let stripped: TypeReport = TypeReport::absent(false);
        assert_eq!(stripped.grade, SourceGrade::None);
    }

    #[test]
    fn recoverable_only_on_types_and_lines() {
        assert!(SourceGrade::TypesAndLines.recoverable());
        assert!(!SourceGrade::SymbolsOnly.recoverable());
        assert!(!SourceGrade::None.recoverable());
    }

    #[test]
    fn recover_types_on_non_object_is_absent() {
        let report: TypeReport = recover_types(b"not an object at all, just text", false);
        assert!(!report.present);
        assert_eq!(report.grade, SourceGrade::None);
    }
}
