use serde::{Deserialize, Serialize};

use super::demangler::{DartNameKind, DemangledName};
use super::snapshot::DartStaticRecovery;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartFunctionSkeleton {
    pub name: String,
    pub kind: DartNameKind,
    pub is_private: bool,
    pub offset: usize,
    pub arg_count: u8,
    pub has_frame: bool,
    pub body: String,
}

impl DartFunctionSkeleton {
    /// Renders the skeleton as Dart-like source. Bodies are intentionally a
    /// single honest marker because AOT register-allocates locals away and lowers
    /// control flow, so statement-level bodies are not statically recoverable.
    #[must_use]
    pub fn to_dart_source(&self) -> String {
        let params: String = (0..self.arg_count)
            .map(|i: u8| format!("arg{i}"))
            .collect::<Vec<String>>()
            .join(", ");
        let modifier: &str = match self.kind {
            DartNameKind::Getter => "get ",
            DartNameKind::Setter => "set ",
            _ => "",
        };
        format!("{modifier}{}({params}) {{ {} }}", self.name, self.body)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DartProgramSkeleton {
    pub function_count: usize,
    pub named_function_count: usize,
    pub functions: Vec<DartFunctionSkeleton>,
    pub class_names: Vec<String>,
    pub library_uris: Vec<String>,
}

/// Body marker placed in every reconstructed Dart function, making the static
/// ceiling explicit in the output.
const SKELETON_BODY: &str = "/* AOT body: register-allocated, not statically recoverable */";

/// Builds a program skeleton by pairing scanned function boundaries with the
/// demangled names recovered from the data snapshot.
///
/// Boundaries and names come from independent sources (the instructions image
/// vs the data snapshot's string clusters), so this association is positional:
/// the i-th recovered method name labels the i-th boundary. Unpaired boundaries
/// keep a synthetic `sub_<offset>` name; unpaired names are dropped. Bodies are
/// always skeleton markers — the honest AOT static ceiling.
#[must_use]
pub fn build_program_skeleton(recovery: &DartStaticRecovery) -> DartProgramSkeleton {
    let mut functions: Vec<DartFunctionSkeleton> =
        Vec::with_capacity(recovery.function_boundaries.len());
    let mut named: usize = 0;
    for (i, boundary) in recovery.function_boundaries.iter().enumerate() {
        let named_entry: Option<&DemangledName> = recovery.method_names.get(i);
        let (name, kind, is_private): (String, DartNameKind, bool) = match named_entry {
            Some(n) => {
                named += 1;
                (n.scrubbed.clone(), n.kind, n.is_private)
            }
            None => (
                format!("sub_{:#010x}", boundary.offset),
                DartNameKind::Method,
                false,
            ),
        };
        functions.push(DartFunctionSkeleton {
            name,
            kind,
            is_private,
            offset: boundary.offset,
            arg_count: boundary.inferred_arg_registers,
            has_frame: boundary.has_frame,
            body: SKELETON_BODY.to_owned(),
        });
    }
    DartProgramSkeleton {
        function_count: functions.len(),
        named_function_count: named,
        functions,
        class_names: recovery.class_names.clone(),
        library_uris: recovery.library_uris.clone(),
    }
}

/// Fraction of static structure recovered, used for honest before/after
/// reporting.
///
/// The share of function boundaries that received a real demangled name plus the
/// presence of class/library structure. Capped at the documented 45-55% AOT body
/// ceiling because bodies are never statically recovered.
#[must_use]
pub fn static_recovery_fraction(skeleton: &DartProgramSkeleton) -> f64 {
    if skeleton.function_count == 0 {
        return 0.0;
    }
    let named_share: f64 = skeleton.named_function_count as f64 / skeleton.function_count as f64;
    let structure_bonus: f64 = if skeleton.class_names.is_empty() {
        0.0
    } else {
        0.1
    };
    named_share.mul_add(0.45, structure_bonus).min(0.55)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::snapshot::DartFunctionBoundary;
    use super::*;

    fn boundary(offset: usize, args: u8) -> DartFunctionBoundary {
        DartFunctionBoundary {
            offset,
            inferred_arg_registers: args,
            has_frame: true,
        }
    }

    fn method(name: &str, kind: DartNameKind) -> DemangledName {
        DemangledName {
            scrubbed: name.to_owned(),
            kind,
            is_private: name.starts_with('_'),
        }
    }

    fn recovery(
        boundaries: Vec<DartFunctionBoundary>,
        methods: Vec<DemangledName>,
        classes: Vec<String>,
    ) -> DartStaticRecovery {
        DartStaticRecovery {
            function_boundary_count: boundaries.len(),
            function_boundaries: boundaries,
            class_names: classes,
            method_names: methods,
            library_uris: Vec::new(),
            recovered_name_count: 0,
        }
    }

    #[test]
    fn pairs_boundaries_with_names() {
        let rec: DartStaticRecovery = recovery(
            vec![boundary(0x100, 2), boundary(0x200, 1)],
            vec![
                method("build", DartNameKind::Method),
                method("createState", DartNameKind::Method),
            ],
            vec!["HomePage".to_owned()],
        );
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        assert_eq!(skel.function_count, 2);
        assert_eq!(skel.named_function_count, 2);
        assert_eq!(skel.functions[0].name, "build");
        assert_eq!(skel.functions[0].arg_count, 2);
        assert!(
            skel.functions[0]
                .body
                .contains("not statically recoverable")
        );
    }

    #[test]
    fn unnamed_boundary_gets_synthetic_name() {
        let rec: DartStaticRecovery = recovery(vec![boundary(0x140, 0)], Vec::new(), Vec::new());
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        assert_eq!(skel.named_function_count, 0);
        assert!(skel.functions[0].name.starts_with("sub_"));
    }

    #[test]
    fn getter_renders_with_modifier() {
        let rec: DartStaticRecovery = recovery(
            vec![boundary(0x10, 0)],
            vec![method("length", DartNameKind::Getter)],
            Vec::new(),
        );
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        let src: String = skel.functions[0].to_dart_source();
        assert!(src.starts_with("get length("), "src: {src}");
    }

    #[test]
    fn recovery_fraction_respects_ceiling() {
        let rec: DartStaticRecovery = recovery(
            vec![boundary(0x10, 1), boundary(0x20, 1)],
            vec![
                method("a", DartNameKind::Method),
                method("b", DartNameKind::Method),
            ],
            vec!["C".to_owned()],
        );
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        let frac: f64 = static_recovery_fraction(&skel);
        assert!(frac > 0.4 && frac <= 0.55, "fraction {frac}");
    }

    #[test]
    fn empty_program_is_zero() {
        let rec: DartStaticRecovery = recovery(Vec::new(), Vec::new(), Vec::new());
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        assert!(static_recovery_fraction(&skel).abs() < f64::EPSILON);
    }
}
