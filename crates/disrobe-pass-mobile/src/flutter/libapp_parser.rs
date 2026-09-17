use serde::{Deserialize, Serialize};

use super::cid_table::{DartCidTable, cid_table, matches_version, predefined_count};
use super::demangler::DartNameKind;
use super::object_pool::{ObjectPoolReferenceMap, recover_object_pool_references};
use super::snapshot::DartStaticRecovery;
use super::string_pool::{DartStringPool, recover_string_pool};
use crate::debug::{dbg_enabled, dbg_kv, dbg_kv_guarded, dbg_line, dbg_section};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartFunctionSkeleton {
    pub name: String,
    pub name_resolved: bool,
    pub kind: DartNameKind,
    pub is_private: bool,
    pub offset: usize,
    pub arg_count: u8,
    pub has_frame: bool,
    pub body: String,
}

impl DartFunctionSkeleton {
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

const SKELETON_BODY: &str = "AOT body: ARM64 machine code (register-allocated, inlined); disassembled, not decompiled to source";

#[must_use]
pub fn build_program_skeleton(recovery: &DartStaticRecovery) -> DartProgramSkeleton {
    let mut functions: Vec<DartFunctionSkeleton> =
        Vec::with_capacity(recovery.function_boundaries.len());
    for boundary in &recovery.function_boundaries {
        functions.push(DartFunctionSkeleton {
            name: format!("sub_{:#010x}", boundary.offset),
            name_resolved: false,
            kind: DartNameKind::Method,
            is_private: false,
            offset: boundary.offset,
            arg_count: boundary.inferred_arg_registers,
            has_frame: boundary.has_frame,
            body: SKELETON_BODY.to_owned(),
        });
    }
    let named_function_count: usize = functions
        .iter()
        .filter(|f: &&DartFunctionSkeleton| f.name_resolved)
        .count();
    DartProgramSkeleton {
        function_count: functions.len(),
        named_function_count,
        functions,
        class_names: recovery.class_names.clone(),
        library_uris: recovery.library_uris.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartRecoveryCounts {
    pub function_boundaries: usize,
    pub named_functions: usize,
    pub class_names: usize,
    pub library_uris: usize,
    pub bodies_recovered: usize,
}

#[must_use]
pub fn recovery_counts(skeleton: &DartProgramSkeleton) -> DartRecoveryCounts {
    DartRecoveryCounts {
        function_boundaries: skeleton.function_count,
        named_functions: skeleton.named_function_count,
        class_names: skeleton.class_names.len(),
        library_uris: skeleton.library_uris.len(),
        bodies_recovered: 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CidTableMatch {
    Pinned,
    UnknownVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartLibAppRecovery {
    pub version_hash: String,
    pub cid_table: DartCidTable,
    pub cid_table_match: CidTableMatch,
    pub predefined_class_count: u16,
    pub string_pool: DartStringPool,
    pub object_pool: ObjectPoolReferenceMap,
    pub function_count: usize,
    pub recovered_class_count: usize,
    pub recovered_selector_count: usize,
    pub recovered_library_count: usize,
    pub source_boundary: String,
}

const SOURCE_BOUNDARY: &str = "function bodies are compiled ARM64 machine code; this recovery surfaces the object pool, class/string/selector inventory, and dispatch sites, not Dart source. the byte-exact source path is the .dill kernel.";

#[must_use]
pub fn recover_libapp(
    version_hash: &str,
    isolate_data: &[u8],
    instructions_base: u64,
    isolate_instructions: &[u8],
    static_recovery: &DartStaticRecovery,
) -> DartLibAppRecovery {
    dbg_section("dart.libapp-recovery");
    dbg_kv_guarded("version_hash", || {
        if version_hash.is_empty() {
            "<none>".to_owned()
        } else {
            version_hash.to_owned()
        }
    });
    let string_pool: DartStringPool = recover_string_pool(isolate_data);
    let object_pool: ObjectPoolReferenceMap =
        recover_object_pool_references(instructions_base, isolate_instructions);
    let cid_table_match: CidTableMatch = if matches_version(version_hash) {
        dbg_line(|| format!("cid-table = pinned to Dart version {version_hash}"));
        CidTableMatch::Pinned
    } else {
        dbg_line(|| {
            format!(
                "cid-table = unknown version {version_hash}; using built-in cid layout as best-effort"
            )
        });
        CidTableMatch::UnknownVersion
    };
    if dbg_enabled() {
        dbg_kv("recovered_class_names", || {
            string_pool.class_names.len().to_string()
        });
        dbg_kv("recovered_library_uris", || {
            string_pool.library_uris.len().to_string()
        });
    }
    let recovered_selector_count: usize = string_pool.getter_selectors.len()
        + string_pool.setter_selectors.len()
        + string_pool.init_selectors.len();
    DartLibAppRecovery {
        version_hash: version_hash.to_owned(),
        cid_table: cid_table(),
        cid_table_match,
        predefined_class_count: predefined_count(),
        recovered_class_count: string_pool.class_names.len(),
        recovered_selector_count,
        recovered_library_count: string_pool.library_uris.len(),
        function_count: static_recovery.function_boundaries.len(),
        string_pool,
        object_pool,
        source_boundary: SOURCE_BOUNDARY.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::cid_table::DART_3_12_VERSION_HASH;
    use super::super::demangler::DemangledName;
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

    fn smi_len(char_count: usize) -> Vec<u8> {
        let mut value: u64 = (char_count as u64) << 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let low: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(low | 0x80);
                return out;
            }
            out.push(low);
        }
    }

    fn string_object(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = smi_len(text.len());
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn ldr_pool(dst: u32, byte_offset: u32) -> u32 {
        let imm12: u32 = byte_offset / 8;
        0xF940_0000 | (imm12 << 10) | 27u32 << 5 | dst
    }

    #[test]
    fn boundaries_are_not_named_by_string_pool_index() {
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
        assert_eq!(
            skel.named_function_count, 0,
            "string-pool names carry no offset correspondence; nothing may be confidently named"
        );
        for f in &skel.functions {
            assert!(
                !f.name_resolved,
                "no boundary has a structurally resolved name"
            );
            assert!(
                f.name.starts_with("sub_"),
                "an unresolved boundary keeps its address-derived label, not a guessed Dart name, got {}",
                f.name
            );
            assert_ne!(
                f.name, "build",
                "the alphabetically-first string-pool name must never be zipped onto the offset-first boundary"
            );
        }
        assert_eq!(skel.functions[0].arg_count, 2);
        assert!(skel.functions[0].body.contains("not decompiled to source"));
    }

    #[test]
    fn unnamed_boundary_gets_synthetic_name() {
        let rec: DartStaticRecovery = recovery(vec![boundary(0x140, 0)], Vec::new(), Vec::new());
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        assert_eq!(skel.named_function_count, 0);
        assert!(skel.functions[0].name.starts_with("sub_"));
        assert!(!skel.functions[0].name_resolved);
    }

    #[test]
    fn getter_renders_with_modifier() {
        let skel: DartFunctionSkeleton = DartFunctionSkeleton {
            name: "length".to_owned(),
            name_resolved: true,
            kind: DartNameKind::Getter,
            is_private: false,
            offset: 0x10,
            arg_count: 0,
            has_frame: true,
            body: SKELETON_BODY.to_owned(),
        };
        let src: String = skel.to_dart_source();
        assert!(src.starts_with("get length("), "src: {src}");
    }

    #[test]
    fn recovery_counts_are_raw_integers() {
        let rec: DartStaticRecovery = recovery(
            vec![boundary(0x10, 1), boundary(0x20, 1)],
            vec![
                method("a", DartNameKind::Method),
                method("b", DartNameKind::Method),
            ],
            vec!["C".to_owned()],
        );
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        let counts: DartRecoveryCounts = recovery_counts(&skel);
        assert_eq!(counts.function_boundaries, 2);
        assert_eq!(
            counts.named_functions, 0,
            "boundaries have no recoverable name from the stripped AOT instruction scan"
        );
        assert_eq!(counts.class_names, 1);
        assert_eq!(counts.bodies_recovered, 0);
    }

    #[test]
    fn empty_program_counts_zero() {
        let rec: DartStaticRecovery = recovery(Vec::new(), Vec::new(), Vec::new());
        let skel: DartProgramSkeleton = build_program_skeleton(&rec);
        let counts: DartRecoveryCounts = recovery_counts(&skel);
        assert_eq!(counts.function_boundaries, 0);
        assert_eq!(counts.named_functions, 0);
        assert_eq!(counts.bodies_recovered, 0);
    }

    #[test]
    fn libapp_recovery_ties_strings_pool_and_cid_table() {
        let mut data: Vec<u8> = vec![0u8];
        for tok in [
            "InventoryItem",
            "get:isBackordered",
            "package:app/main.dart",
            "widget-alpha",
        ] {
            data.extend_from_slice(&string_object(tok));
            data.push(0u8);
        }
        let instructions: Vec<u8> = {
            let mut v: Vec<u8> = Vec::new();
            for w in [ldr_pool(0, 16), ldr_pool(1, 24)] {
                v.extend_from_slice(&w.to_le_bytes());
            }
            v
        };
        let rec: DartStaticRecovery = recovery(vec![boundary(0x40, 1)], Vec::new(), Vec::new());
        let out: DartLibAppRecovery =
            recover_libapp(DART_3_12_VERSION_HASH, &data, 0, &instructions, &rec);
        assert_eq!(out.cid_table_match, CidTableMatch::Pinned);
        assert!(out.predefined_class_count > 150);
        assert!(
            out.string_pool
                .class_names
                .iter()
                .any(|c: &String| c == "InventoryItem")
        );
        assert!(
            out.string_pool
                .getter_selectors
                .iter()
                .any(|s: &String| s == "isBackordered")
        );
        assert_eq!(out.object_pool.distinct_slots, 2);
        assert_eq!(out.recovered_class_count, 1);
        assert_eq!(out.recovered_selector_count, 1);
        assert!(out.source_boundary.contains("machine code"));
    }

    #[test]
    fn unknown_version_is_flagged_not_silently_wrong() {
        let rec: DartStaticRecovery = recovery(Vec::new(), Vec::new(), Vec::new());
        let out: DartLibAppRecovery = recover_libapp("0000feed", &[], 0, &[], &rec);
        assert_eq!(out.cid_table_match, CidTableMatch::UnknownVersion);
    }
}
