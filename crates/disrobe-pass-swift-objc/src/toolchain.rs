use serde::{Deserialize, Serialize};

use crate::macho::{DylibReference, DysymtabInfo, ParsedSlice, PlatformVersion, SymtabInfo};

const SWIFT_RUNTIME_PREFIX: &str = "/usr/lib/swift/libswift";
const OBJC_RUNTIME: &str = "/usr/lib/libobjc.A.dylib";
const SWIFT_TOOLCHAIN_MARKER: &str = "/usr/lib/swift-";
const MAX_TOOLCHAIN_HINTS: usize = 16;

const MH_EXECUTE: u32 = 0x2;
const MH_DYLIB: u32 = 0x6;
const MH_BUNDLE: u32 = 0x8;
const MH_OBJECT: u32 = 0x1;
const MH_DYLINKER: u32 = 0x7;
const MH_PRELOAD: u32 = 0x5;
const MH_CORE: u32 = 0x4;
const MH_DSYM: u32 = 0xA;
const MH_KEXT_BUNDLE: u32 = 0xB;
const MH_FILESET: u32 = 0xC;

const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolState {
    LocalSymbolsPresent,
    LocalSymbolsStripped,
    NoSymbolTable,
}

impl SymbolState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalSymbolsPresent => "local-symbols-present",
            Self::LocalSymbolsStripped => "local-symbols-stripped",
            Self::NoSymbolTable => "no-symbol-table",
        }
    }

    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::LocalSymbolsPresent => {
                "the symbol table still carries local symbols, so function names inside this image are readable without inference"
            }
            Self::LocalSymbolsStripped => {
                "the symbol table carries no local symbols, so only exported and imported names are readable and internal function names must come from metadata rather than from symbols"
            }
            Self::NoSymbolTable => {
                "the image declares no symbol table at all, so every name must come from metadata or from inference"
            }
        }
    }
}

#[must_use]
pub const fn file_type_label(filetype: u32) -> &'static str {
    match filetype {
        MH_OBJECT => "object",
        MH_EXECUTE => "executable",
        MH_CORE => "core",
        MH_PRELOAD => "preload",
        MH_DYLIB => "dylib",
        MH_DYLINKER => "dylinker",
        MH_BUNDLE => "bundle",
        MH_DSYM => "dsym-companion",
        MH_KEXT_BUNDLE => "kext-bundle",
        MH_FILESET => "fileset",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainReport {
    pub file_type: String,
    pub platform: Option<String>,
    pub min_os_version: Option<String>,
    pub sdk_version: Option<String>,
    pub position_independent: bool,
    pub allows_stack_execution: bool,
    pub forbids_heap_execution: bool,
    pub links_swift_runtime: bool,
    pub links_objc_runtime: bool,
    pub swift_runtime_dylibs: Vec<String>,
    pub swift_toolchain_rpath_hints: Vec<String>,
    pub symbol_state: SymbolState,
    pub symbol_state_note: String,
    pub local_symbol_count: u32,
    pub total_symbol_count: u32,
    pub dylib_count: usize,
    pub has_uuid: bool,
    pub has_chained_fixups: bool,
    pub has_exports_trie: bool,
}

#[must_use]
pub fn report(parsed: &ParsedSlice) -> ToolchainReport {
    let symbol_state: SymbolState = symbol_state_for(parsed);
    let swift_runtime_dylibs: Vec<String> = parsed
        .dylibs
        .iter()
        .filter(|d: &&DylibReference| d.name.starts_with(SWIFT_RUNTIME_PREFIX))
        .map(|d: &DylibReference| d.name.clone())
        .collect();
    let swift_toolchain_rpath_hints: Vec<String> = parsed
        .rpaths
        .iter()
        .filter_map(|path: &String| toolchain_hint(path))
        .take(MAX_TOOLCHAIN_HINTS)
        .collect();
    let platform: Option<PlatformVersion> = parsed.platform_version;

    ToolchainReport {
        file_type: file_type_label(parsed.header.filetype).to_owned(),
        platform: platform.map(|p: PlatformVersion| p.platform_label().to_owned()),
        min_os_version: platform.map(|p: PlatformVersion| p.min_os.to_string()),
        sdk_version: platform.map(|p: PlatformVersion| p.sdk.to_string()),
        position_independent: parsed.header.flags & MH_PIE != 0,
        allows_stack_execution: parsed.header.flags & MH_ALLOW_STACK_EXECUTION != 0,
        forbids_heap_execution: parsed.header.flags & MH_NO_HEAP_EXECUTION != 0,
        links_swift_runtime: !swift_runtime_dylibs.is_empty(),
        links_objc_runtime: parsed
            .dylibs
            .iter()
            .any(|d: &DylibReference| d.name == OBJC_RUNTIME),
        swift_runtime_dylibs,
        swift_toolchain_rpath_hints,
        symbol_state,
        symbol_state_note: symbol_state.note().to_owned(),
        local_symbol_count: parsed
            .dysymtab
            .map_or(0, |d: DysymtabInfo| d.local_sym_count),
        total_symbol_count: parsed.symtab.map_or(0, |s: SymtabInfo| s.num_syms),
        dylib_count: parsed.dylibs.len(),
        has_uuid: parsed.uuid.is_some(),
        has_chained_fixups: parsed.chained_fixups.is_some(),
        has_exports_trie: parsed.exports_trie.is_some(),
    }
}

const fn symbol_state_for(parsed: &ParsedSlice) -> SymbolState {
    let Some(symtab): Option<SymtabInfo> = parsed.symtab else {
        return SymbolState::NoSymbolTable;
    };
    if symtab.num_syms == 0 {
        return SymbolState::NoSymbolTable;
    }
    match parsed.dysymtab {
        Some(dysymtab) if dysymtab.local_sym_count == 0 => SymbolState::LocalSymbolsStripped,
        _ => SymbolState::LocalSymbolsPresent,
    }
}

fn toolchain_hint(rpath: &str) -> Option<String> {
    let start: usize = rpath.find(SWIFT_TOOLCHAIN_MARKER)?;
    let tail: &str = rpath.get(start + SWIFT_TOOLCHAIN_MARKER.len()..)?;
    let version: &str = tail.split('/').next().unwrap_or(tail);
    if version.is_empty() {
        return None;
    }
    Some(format!("swift-{version}"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::macho::{DylibKind, SymtabInfo};

    fn symtab(num_syms: u32) -> SymtabInfo {
        SymtabInfo {
            sym_off: 0,
            num_syms,
            str_off: 0,
            str_size: 0,
        }
    }

    fn dysymtab(local_sym_count: u32) -> DysymtabInfo {
        DysymtabInfo {
            local_sym_index: 0,
            local_sym_count,
            extdef_sym_index: 0,
            extdef_sym_count: 0,
            undef_sym_index: 0,
            undef_sym_count: 0,
            indirect_sym_off: 0,
            indirect_sym_count: 0,
        }
    }

    #[test]
    fn no_symbol_table_is_distinct_from_stripped_locals() {
        let empty: ParsedSlice = ParsedSlice::default();
        assert_eq!(symbol_state_for(&empty), SymbolState::NoSymbolTable);

        let declared_but_empty: ParsedSlice = ParsedSlice {
            symtab: Some(symtab(0)),
            ..ParsedSlice::default()
        };
        assert_eq!(
            symbol_state_for(&declared_but_empty),
            SymbolState::NoSymbolTable,
            "a symbol table declaring zero symbols carries no names either"
        );

        let stripped: ParsedSlice = ParsedSlice {
            symtab: Some(symtab(40)),
            dysymtab: Some(dysymtab(0)),
            ..ParsedSlice::default()
        };
        assert_eq!(
            symbol_state_for(&stripped),
            SymbolState::LocalSymbolsStripped,
            "symbols present with zero locals is a stripped image, not an unsymbolized one"
        );

        let present: ParsedSlice = ParsedSlice {
            symtab: Some(symtab(227)),
            dysymtab: Some(dysymtab(186)),
            ..ParsedSlice::default()
        };
        assert_eq!(symbol_state_for(&present), SymbolState::LocalSymbolsPresent);
    }

    #[test]
    fn each_symbol_state_states_what_it_costs_the_analyst() {
        assert!(
            SymbolState::LocalSymbolsStripped
                .note()
                .contains("only exported and imported")
        );
        assert!(
            SymbolState::NoSymbolTable
                .note()
                .contains("no symbol table at all")
        );
        assert_ne!(
            SymbolState::LocalSymbolsPresent.note(),
            SymbolState::LocalSymbolsStripped.note()
        );
    }

    #[test]
    fn toolchain_hint_reads_the_swift_version_out_of_an_rpath() {
        assert_eq!(
            toolchain_hint("/Library/Developer/CommandLineTools/usr/lib/swift-6.2/macosx")
                .as_deref(),
            Some("swift-6.2")
        );
        assert_eq!(
            toolchain_hint("/Library/Developer/CommandLineTools/usr/lib/swift-5.5/macosx")
                .as_deref(),
            Some("swift-5.5")
        );
        assert_eq!(toolchain_hint("/usr/lib/swift").as_deref(), None);
        assert_eq!(toolchain_hint("@loader_path").as_deref(), None);
    }

    #[test]
    fn runtime_linkage_is_read_from_the_dylib_list() {
        let parsed: ParsedSlice = ParsedSlice {
            dylibs: vec![
                DylibReference {
                    kind: DylibKind::Load,
                    name: "/usr/lib/swift/libswiftCore.dylib".to_owned(),
                    current_version: "0.0.0".to_owned(),
                    compatibility_version: "0.0.0".to_owned(),
                },
                DylibReference {
                    kind: DylibKind::Load,
                    name: OBJC_RUNTIME.to_owned(),
                    current_version: "228.0.0".to_owned(),
                    compatibility_version: "1.0.0".to_owned(),
                },
            ],
            ..ParsedSlice::default()
        };
        let report: ToolchainReport = report(&parsed);
        assert!(report.links_swift_runtime);
        assert!(report.links_objc_runtime);
        assert_eq!(report.swift_runtime_dylibs.len(), 1);
        assert_eq!(report.dylib_count, 2);
    }

    #[test]
    fn file_type_labels_cover_the_kinds_an_analyst_meets() {
        assert_eq!(file_type_label(MH_EXECUTE), "executable");
        assert_eq!(file_type_label(MH_DYLIB), "dylib");
        assert_eq!(file_type_label(MH_OBJECT), "object");
        assert_eq!(file_type_label(MH_BUNDLE), "bundle");
        assert_eq!(file_type_label(0xFF), "unknown");
    }
}
