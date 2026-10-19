#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_go::{
    GoAnalysis, GoFunc, GoImage, GoItab, GoTypeRef, ModuledataSource, Section, analyze,
};

const USER_TYPES: [&str; 2] = ["Parcel", "Ledger"];
const KIND_MASK: u8 = 0x1f;
const KIND_ARRAY: u8 = 17;
const KIND_STRUCT: u8 = 25;
const SHT_SYMTAB: u32 = 2;
const ELF_SECTION_HEADER_LEN: usize = 64;
const ELF_MAX_SECTIONS: usize = 1 << 12;

const PUBLISHED_HEADING: &str = "Go type-name recovery";
const PUBLISHED_BAR: &str = "type names";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    functions: usize,
    methods: usize,
    user_methods: usize,
    itabs: usize,
    types: usize,
    fields: usize,
}

struct MatrixRow {
    binary: &'static str,
    version: &'static str,
    target: &'static str,
    elided_function_names: bool,
    counts: Counts,
}

const GO117_AMD64: Counts = Counts {
    functions: 15,
    methods: 301,
    user_methods: 3,
    itabs: 11,
    types: 57,
    fields: 2,
};

const GO117_ARM64: Counts = Counts {
    functions: 15,
    methods: 300,
    user_methods: 3,
    itabs: 11,
    types: 56,
    fields: 2,
};

const GO118: Counts = Counts {
    functions: 15,
    methods: 313,
    user_methods: 3,
    itabs: 11,
    types: 57,
    fields: 2,
};

const GO120: Counts = Counts {
    functions: 15,
    methods: 369,
    user_methods: 3,
    itabs: 11,
    types: 69,
    fields: 2,
};

const GO126: Counts = Counts {
    functions: 15,
    methods: 604,
    user_methods: 3,
    itabs: 17,
    types: 115,
    fields: 2,
};

const GO117_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go117_linux_amd64",
        version: "go1.17.13",
        target: "linux/amd64",
        elided_function_names: false,
        counts: GO117_AMD64,
    },
    MatrixRow {
        binary: "go117_linux_amd64_pie",
        version: "go1.17.13",
        target: "linux/amd64 PIE",
        elided_function_names: false,
        counts: GO117_AMD64,
    },
    MatrixRow {
        binary: "go117_linux_arm64",
        version: "go1.17.13",
        target: "linux/arm64",
        elided_function_names: false,
        counts: GO117_ARM64,
    },
];

const GO118_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go118_linux_amd64",
        version: "go1.18.10",
        target: "linux/amd64",
        elided_function_names: true,
        counts: GO118,
    },
    MatrixRow {
        binary: "go118_linux_amd64_pie",
        version: "go1.18.10",
        target: "linux/amd64 PIE",
        elided_function_names: true,
        counts: GO118,
    },
    MatrixRow {
        binary: "go118_linux_arm64",
        version: "go1.18.10",
        target: "linux/arm64",
        elided_function_names: true,
        counts: GO118,
    },
];

const GO120_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go120_linux_amd64",
        version: "go1.20.14",
        target: "linux/amd64",
        elided_function_names: true,
        counts: GO120,
    },
    MatrixRow {
        binary: "go120_linux_amd64_pie",
        version: "go1.20.14",
        target: "linux/amd64 PIE",
        elided_function_names: true,
        counts: GO120,
    },
    MatrixRow {
        binary: "go120_linux_arm64",
        version: "go1.20.14",
        target: "linux/arm64",
        elided_function_names: true,
        counts: GO120,
    },
];

const GO126_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go126_linux_amd64",
        version: "go1.26.3",
        target: "linux/amd64",
        elided_function_names: false,
        counts: GO126,
    },
    MatrixRow {
        binary: "go126_linux_amd64_pie",
        version: "go1.26.3",
        target: "linux/amd64 PIE",
        elided_function_names: false,
        counts: GO126,
    },
    MatrixRow {
        binary: "go126_linux_arm64",
        version: "go1.26.3",
        target: "linux/arm64",
        elided_function_names: false,
        counts: GO126,
    },
];

#[derive(Clone)]
struct NmReference {
    text: BTreeMap<u64, BTreeSet<String>>,
    symbols: BTreeMap<String, u64>,
    itabs: BTreeMap<u64, String>,
    equality: BTreeMap<u64, String>,
}

impl NmReference {
    fn parse(text: &str) -> Self {
        let mut reference: Self = Self {
            text: BTreeMap::new(),
            symbols: BTreeMap::new(),
            itabs: BTreeMap::new(),
            equality: BTreeMap::new(),
        };
        for line in text.lines() {
            let Some((address, rest)): Option<(&str, &str)> = line.trim_start().split_once(' ')
            else {
                continue;
            };
            let Ok(address): Result<u64, _> = u64::from_str_radix(address, 16) else {
                continue;
            };
            let Some((kind, name)): Option<(&str, &str)> = rest.split_once(' ') else {
                continue;
            };
            reference.symbols.insert(name.to_owned(), address);
            if matches!(kind, "T" | "t") {
                reference
                    .text
                    .entry(address)
                    .or_default()
                    .insert(name.to_owned());
                if let Some(type_name) = name
                    .strip_prefix("type:.eq.")
                    .or_else(|| name.strip_prefix("type..eq."))
                {
                    reference.equality.insert(address, type_name.to_owned());
                }
            } else if let Some(pair) = name
                .strip_prefix("go:itab.")
                .or_else(|| name.strip_prefix("go.itab."))
            {
                reference.itabs.insert(address, pair.to_owned());
            }
        }
        reference
    }

    fn address(&self, name: &str) -> u64 {
        *self
            .symbols
            .get(name)
            .unwrap_or_else(|| panic!("go tool nm reference must name {name}"))
    }

    fn rename_text(&mut self, from: &str, to: &str) {
        for names in self.text.values_mut() {
            if names.remove(from) {
                names.insert(to.to_owned());
            }
        }
    }
}

fn renamed_references(
    loaded: &LoadedRow,
    from: &str,
    to: &str,
) -> (NmReference, BTreeMap<String, u64>) {
    let mut nm: NmReference = loaded.nm.clone();
    nm.rename_text(from, to);
    let mut objdump: BTreeMap<String, u64> = loaded.objdump.clone();
    let address: u64 = objdump
        .remove(from)
        .unwrap_or_else(|| panic!("go tool objdump names {from}"));
    objdump.insert(to.to_owned(), address);
    (nm, objdump)
}

fn objdump_functions(text: &str) -> BTreeMap<String, u64> {
    let mut functions: BTreeMap<String, u64> = BTreeMap::new();
    let mut pending: Option<String> = None;
    for line in text.lines() {
        if let Some(header) = line.strip_prefix("TEXT ") {
            let (name, _): (&str, &str) = header
                .split_once("(SB)")
                .unwrap_or_else(|| panic!("go tool objdump header without (SB): {line:?}"));
            pending = Some(name.to_owned());
            continue;
        }
        let Some(name): Option<String> = pending.take() else {
            continue;
        };
        let address: u64 = line
            .split_whitespace()
            .find_map(|token: &str| token.strip_prefix("0x"))
            .and_then(|hex: &str| u64::from_str_radix(hex, 16).ok())
            .unwrap_or_else(|| panic!("go tool objdump body of {name} names no address: {line:?}"));
        functions.insert(name, address);
    }
    functions
}

fn pclntab_spelling(name: &str, elided: bool) -> String {
    if !elided {
        return name.to_owned();
    }
    match (name.find('['), name.rfind(']')) {
        (Some(open), Some(close)) if close > open => {
            format!("{}[...]{}", &name[..open], &name[close + 1..])
        }
        _ => name.to_owned(),
    }
}

fn is_name_char(ch: char) -> bool {
    ch.is_alphanumeric() || matches!(ch, '_' | '.' | '/' | '-' | '~' | '·')
}

fn runtime_token(token: &str) -> &str {
    let short: &str = token
        .rsplit_once('/')
        .map_or(token, |(_, tail): (&str, &str)| tail);
    match short.rsplit_once(['.', '·']) {
        Some((head, local))
            if head.contains('.')
                && !local.is_empty()
                && local.bytes().all(|byte: u8| byte.is_ascii_digit()) =>
        {
            head
        }
        _ => short,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Nest {
    TypeArguments,
    Brackets,
    Struct,
    Other,
}

fn runtime_spelling(linker: &str) -> String {
    let chars: Vec<char> = linker.chars().collect();
    let mut spelled: String = String::with_capacity(linker.len());
    let mut stack: Vec<Nest> = Vec::new();
    let mut field_start: bool = false;
    let mut index: usize = 0;
    while index < chars.len() {
        let ch: char = chars[index];
        let verbatim: bool = stack.contains(&Nest::TypeArguments);
        if is_name_char(ch) {
            let start: usize = index;
            while index < chars.len() && is_name_char(chars[index]) {
                index += 1;
            }
            let token: String = chars[start..index].iter().collect();
            if verbatim {
                spelled.push_str(&token);
                field_start = false;
                continue;
            }
            let named_field: bool = field_start
                && stack.last() == Some(&Nest::Struct)
                && chars.get(index) == Some(&' ')
                && chars
                    .get(index + 1)
                    .is_some_and(|next: &char| !matches!(next, '}' | '"'));
            let token: &str = if named_field {
                token
                    .rsplit_once('.')
                    .map_or(token.as_str(), |(_, field): (&str, &str)| field)
            } else {
                runtime_token(&token)
            };
            if token == "struct"
                && chars.get(index) == Some(&' ')
                && chars.get(index + 1) == Some(&'{')
            {
                spelled.push_str("struct {");
                stack.push(Nest::Struct);
                field_start = true;
                index += 2;
                continue;
            }
            spelled.push_str(token);
            field_start = false;
            continue;
        }
        match ch {
            '[' => {
                let name_start: usize = chars[..index]
                    .iter()
                    .rposition(|prior: &char| !is_name_char(*prior))
                    .map_or(0, |boundary: usize| boundary + 1);
                let previous: String = chars[name_start..index].iter().collect();
                stack.push(if !previous.is_empty() && previous != "map" {
                    Nest::TypeArguments
                } else {
                    Nest::Brackets
                });
            }
            '(' | '{' => stack.push(Nest::Other),
            ']' | ')' | '}' => {
                stack.pop();
            }
            _ => {}
        }
        spelled.push(ch);
        if ch == ';' {
            field_start = stack.last() == Some(&Nest::Struct);
        } else if ch != ' ' {
            field_start = false;
        }
        index += 1;
    }
    spelled
}

fn split_itab_pair(pair: &str) -> (String, String) {
    let mut depth: usize = 0;
    for (index, ch) in pair.char_indices() {
        match ch {
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                return (
                    runtime_spelling(&pair[..index]),
                    runtime_spelling(&pair[index + 1..]),
                );
            }
            _ => {}
        }
    }
    panic!("go tool nm itab symbol without a concrete,interface pair: {pair:?}")
}

fn method_symbol(receiver: &str, method: &str) -> Option<String> {
    let (pointer, named): (bool, &str) = receiver
        .strip_prefix('*')
        .map_or((false, receiver), |rest: &str| (true, rest));
    let (package, type_name): (&str, &str) = named.split_once('.')?;
    if package.is_empty()
        || !package
            .chars()
            .all(|ch: char| ch.is_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(if pointer {
        format!("{package}.(*{type_name}).{method}")
    } else {
        format!("{package}.{type_name}.{method}")
    })
}

#[derive(Debug, Default)]
struct Grade {
    total: usize,
    mismatches: Vec<String>,
}

impl Grade {
    const fn matched(&self) -> usize {
        self.total - self.mismatches.len()
    }

    fn check(&mut self, matched: bool, describe: impl FnOnce() -> String) {
        self.total += 1;
        if !matched {
            self.mismatches.push(describe());
        }
    }
}

fn types_by_address(analysis: &GoAnalysis) -> BTreeMap<u64, &GoTypeRef> {
    analysis
        .typemeta
        .types
        .iter()
        .map(|ty: &GoTypeRef| (ty.va, ty))
        .collect()
}

fn grade_functions(
    analysis: &GoAnalysis,
    nm: &NmReference,
    objdump: &BTreeMap<String, u64>,
    elided: bool,
) -> Grade {
    let mut grade: Grade = Grade::default();
    for (name, address) in objdump {
        let nm_names: Option<&BTreeSet<String>> = nm.text.get(address);
        assert!(
            nm_names.is_some_and(|names: &BTreeSet<String>| names.contains(name)),
            "go tool objdump places {name} at {address:#x}, go tool nm names {nm_names:?} there"
        );
        let expected: String = pclntab_spelling(name, elided);
        let recovered: Vec<&GoFunc> = analysis
            .symbols
            .funcs
            .iter()
            .filter(|func: &&GoFunc| func.va == Some(*address))
            .collect();
        grade.check(
            recovered.iter().any(|func: &&GoFunc| func.name == expected),
            || {
                let names: Vec<&str> = recovered
                    .iter()
                    .map(|func: &&GoFunc| func.name.as_str())
                    .collect();
                format!("function {expected} at {address:#x} recovered as {names:?}")
            },
        );
    }
    grade
}

fn grade_methods(analysis: &GoAnalysis, nm: &NmReference) -> Grade {
    let mut grade: Grade = Grade::default();
    for ty in &analysis.typemeta.types {
        let Some(receiver): Option<&str> = ty.name.as_deref() else {
            continue;
        };
        for method in &ty.methods {
            let Some(name): Option<&str> = method.name.as_deref() else {
                continue;
            };
            if method.func_va == 0 {
                continue;
            }
            let Some(expected): Option<String> = method_symbol(receiver, name) else {
                continue;
            };
            let nm_names: Vec<String> = nm
                .text
                .get(&method.func_va)
                .map(|names: &BTreeSet<String>| {
                    names
                        .iter()
                        .map(|symbol: &String| runtime_spelling(symbol))
                        .collect()
                })
                .unwrap_or_default();
            grade.check(nm_names.contains(&expected), || {
                format!(
                    "method {expected} at {:#x}: go tool nm names {nm_names:?}",
                    method.func_va
                )
            });
        }
    }
    grade
}

fn user_method_symbols(nm: &NmReference) -> BTreeMap<u64, String> {
    let prefixes: Vec<String> = USER_TYPES
        .iter()
        .flat_map(|user: &&str| [format!("main.{user}."), format!("main.(*{user}).")])
        .collect();
    nm.text
        .iter()
        .flat_map(|(address, names): (&u64, &BTreeSet<String>)| {
            names.iter().map(move |name: &String| (*address, name))
        })
        .filter(|(_, name): &(u64, &String)| {
            prefixes.iter().any(|prefix: &String| {
                name.strip_prefix(prefix.as_str())
                    .is_some_and(|method: &str| !method.is_empty() && !method.contains('.'))
            })
        })
        .map(|(address, name): (u64, &String)| (address, name.clone()))
        .collect()
}

fn grade_user_method_coverage(analysis: &GoAnalysis, nm: &NmReference) -> Grade {
    let mut grade: Grade = Grade::default();
    for (address, symbol) in user_method_symbols(nm) {
        let covered: bool = analysis.typemeta.types.iter().any(|ty: &GoTypeRef| {
            ty.name.as_deref().is_some_and(|receiver: &str| {
                ty.methods.iter().any(|method| {
                    method.func_va == address
                        && method
                            .name
                            .as_deref()
                            .and_then(|name: &str| method_symbol(receiver, name))
                            .as_deref()
                            == Some(symbol.as_str())
                })
            })
        });
        grade.check(covered, || {
            format!("go tool nm method {symbol} at {address:#x} is in no recovered method table")
        });
    }
    grade
}

fn grade_itabs(analysis: &GoAnalysis, nm: &NmReference) -> Grade {
    let recovered: BTreeMap<u64, &GoItab> = analysis
        .typemeta
        .itabs
        .iter()
        .map(|itab: &GoItab| (itab.va, itab))
        .collect();
    let mut grade: Grade = Grade::default();
    for (address, pair) in &nm.itabs {
        let (concrete, interface): (String, String) = split_itab_pair(pair);
        let found: Option<(Option<&str>, Option<&str>)> =
            recovered.get(address).map(|itab: &&GoItab| {
                (
                    itab.concrete_name.as_deref(),
                    itab.interface_name.as_deref(),
                )
            });
        grade.check(
            found == Some((Some(concrete.as_str()), Some(interface.as_str()))),
            || format!("itab {concrete},{interface} at {address:#x} recovered as {found:?}"),
        );
    }
    grade
}

fn named_descriptors(image: &GoImage<'_>, nm: &NmReference) -> BTreeMap<u64, String> {
    let ptr_size: u64 = u64::from(image.ptr_size());
    let equal_offset: u64 = ptr_size * 2 + 8;
    let kind_offset: u64 = ptr_size * 2 + 7;
    let start: u64 = nm.address("runtime.types");
    let end: u64 = nm.address("runtime.etypes");
    assert!(start < end, "runtime.types must precede runtime.etypes");
    let mut descriptors: BTreeMap<u64, String> = BTreeMap::new();
    let mut insert = |descriptor: u64, name: String| {
        if let Some(previous) = descriptors.insert(descriptor, name.clone()) {
            assert_eq!(
                previous, name,
                "go tool nm names the descriptor at {descriptor:#x} twice"
            );
        }
    };
    let mut word: u64 = start.next_multiple_of(ptr_size);
    while word + ptr_size <= end {
        let code: Option<u64> = image
            .read_ptr(word)
            .filter(|funcval: &u64| *funcval != 0)
            .and_then(|funcval: u64| image.read_ptr(funcval));
        if let Some(type_name) = code.and_then(|code: u64| nm.equality.get(&code))
            && let Some(descriptor) = word.checked_sub(equal_offset)
            && descriptor >= start
            && image
                .data_at_va(descriptor + kind_offset, 1)
                .is_some_and(|kind: &[u8]| matches!(kind[0] & KIND_MASK, KIND_ARRAY | KIND_STRUCT))
        {
            insert(descriptor, runtime_spelling(type_name));
        }
        word += ptr_size;
    }
    for (address, pair) in &nm.itabs {
        let (concrete, interface): (String, String) = split_itab_pair(pair);
        let interface_descriptor: u64 = image
            .read_ptr(*address)
            .unwrap_or_else(|| panic!("itab at {address:#x} must name its interface"));
        let concrete_descriptor: u64 = image
            .read_ptr(*address + ptr_size)
            .unwrap_or_else(|| panic!("itab at {address:#x} must name its concrete type"));
        insert(interface_descriptor, interface);
        insert(concrete_descriptor, concrete);
    }
    descriptors
}

fn grade_type_names(analysis: &GoAnalysis, descriptors: &BTreeMap<u64, String>) -> Grade {
    let recovered: BTreeMap<u64, &GoTypeRef> = types_by_address(analysis);
    let mut grade: Grade = Grade::default();
    for (address, expected) in descriptors {
        let found: Option<&str> = recovered
            .get(address)
            .and_then(|ty: &&GoTypeRef| ty.name.as_deref());
        grade.check(found == Some(expected.as_str()), || {
            format!("type {expected} at {address:#x} recovered as {found:?}")
        });
    }
    grade
}

fn field_markers(nm: &NmReference, user: &str) -> BTreeSet<String> {
    let prefix: String = format!("main.{user}");
    nm.text
        .values()
        .flatten()
        .filter_map(|symbol: &String| symbol.strip_prefix(prefix.as_str()))
        .filter(|field: &&str| {
            field
                .chars()
                .next()
                .is_some_and(|first: char| first.is_ascii_uppercase())
                && !field.contains('.')
        })
        .map(str::to_owned)
        .collect()
}

fn grade_user_fields(
    analysis: &GoAnalysis,
    nm: &NmReference,
    descriptors: &BTreeMap<u64, String>,
) -> Grade {
    let recovered: BTreeMap<u64, &GoTypeRef> = types_by_address(analysis);
    let mut grade: Grade = Grade::default();
    for user in USER_TYPES {
        let qualified: String = format!("main.{user}");
        let address: u64 = descriptors
            .iter()
            .find(|(_, name): &(&u64, &String)| **name == qualified)
            .map_or_else(
                || panic!("go tool nm must name the {qualified} descriptor"),
                |(address, _): (&u64, &String)| *address,
            );
        let expected: BTreeSet<String> = field_markers(nm, user);
        assert!(
            !expected.is_empty(),
            "go tool nm must carry field markers for {qualified}"
        );
        let found: Option<BTreeSet<String>> = recovered
            .get(&address)
            .map(|ty: &&GoTypeRef| ty.fields.iter().map(|field| field.name.clone()).collect());
        grade.check(found.as_ref() == Some(&expected), || {
            format!(
                "{qualified} at {address:#x}: fields {found:?}, go tool nm markers {expected:?}"
            )
        });
    }
    grade
}

fn without_symbols_or_debug_info(bytes: &[u8]) -> Vec<u8> {
    let read = |offset: usize, len: usize| -> u64 {
        let raw: &[u8] = offset
            .checked_add(len)
            .and_then(|end: usize| bytes.get(offset..end))
            .unwrap_or_else(|| panic!("ELF field at {offset:#x} lies outside the file"));
        raw.iter().rev().fold(0u64, |value: u64, byte: &u8| {
            (value << 8) | u64::from(*byte)
        })
    };
    let to_usize = |value: u64| -> usize { usize::try_from(value).expect("ELF field fits usize") };
    assert_eq!(bytes.get(..4), Some(b"\x7fELF".as_slice()), "rows are ELF");
    assert_eq!(
        bytes.get(4..6),
        Some([2u8, 1u8].as_slice()),
        "rows are ELF64 little-endian"
    );
    let table: usize = to_usize(read(0x28, 8));
    let entry_len: usize = to_usize(read(0x3a, 2));
    let count: usize = to_usize(read(0x3c, 2));
    let names_index: usize = to_usize(read(0x3e, 2));
    assert_eq!(entry_len, ELF_SECTION_HEADER_LEN, "ELF64 section headers");
    assert!(
        count <= ELF_MAX_SECTIONS && names_index < count,
        "the section table is bounded"
    );
    let header = |index: usize| -> usize { table + index * ELF_SECTION_HEADER_LEN };
    let names_offset: usize = to_usize(read(header(names_index) + 0x18, 8));
    let mut stripped: Vec<u8> = bytes.to_vec();
    for index in 0..count {
        let at: usize = header(index);
        let name_start: usize = names_offset + to_usize(read(at, 4));
        let name_len: usize = bytes[name_start..]
            .iter()
            .position(|byte: &u8| *byte == 0)
            .expect("section names are NUL-terminated");
        let name: &[u8] = &bytes[name_start..name_start + name_len];
        let neutralize: bool = read(at + 4, 4) == u64::from(SHT_SYMTAB)
            || name == b".strtab"
            || name.starts_with(b".debug_")
            || name.starts_with(b".zdebug_");
        if !neutralize {
            continue;
        }
        let offset: usize = to_usize(read(at + 0x18, 8));
        let size: usize = to_usize(read(at + 0x20, 8));
        stripped[offset..offset + size].fill(0);
        stripped[at..at + 8].fill(0);
        stripped[at + 0x18..at + 0x28].fill(0);
    }
    stripped
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("go")
        .join("versions")
}

struct LoadedRow {
    bytes: Vec<u8>,
    nm: NmReference,
    objdump: BTreeMap<String, u64>,
}

fn load_row(row: &MatrixRow) -> LoadedRow {
    let root: PathBuf = corpus_root();
    let read_text = |path: PathBuf| -> String {
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()))
    };
    let binary: PathBuf = root.join(row.binary);
    let bytes: Vec<u8> = std::fs::read(&binary)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", binary.display()));
    let nm: NmReference =
        NmReference::parse(&read_text(root.join(format!("{}.nm.txt", row.binary))));
    let objdump: BTreeMap<String, u64> =
        objdump_functions(&read_text(root.join(format!("{}.objdump.txt", row.binary))));
    LoadedRow { bytes, nm, objdump }
}

struct RowGrades {
    functions: Grade,
    methods: Grade,
    user_methods: Grade,
    itabs: Grade,
    types: Grade,
    fields: Grade,
}

impl RowGrades {
    const fn classes(&self) -> [(&'static str, &Grade); 6] {
        [
            ("functions", &self.functions),
            ("methods", &self.methods),
            ("user methods", &self.user_methods),
            ("itabs", &self.itabs),
            ("type names", &self.types),
            ("field names", &self.fields),
        ]
    }

    const fn totals(&self) -> Counts {
        Counts {
            functions: self.functions.total,
            methods: self.methods.total,
            user_methods: self.user_methods.total,
            itabs: self.itabs.total,
            types: self.types.total,
            fields: self.fields.total,
        }
    }
}

struct GradedInput {
    analysis: GoAnalysis,
    descriptors: BTreeMap<u64, String>,
}

fn graded_input(bytes: &[u8], nm: &NmReference) -> GradedInput {
    let analysis: GoAnalysis = analyze(bytes).unwrap_or_else(|error| panic!("analyze: {error}"));
    let image: GoImage<'_> = GoImage::parse(bytes).expect("parse image");
    let descriptors: BTreeMap<u64, String> = named_descriptors(&image, nm);
    GradedInput {
        analysis,
        descriptors,
    }
}

fn grade_row(
    input: &GradedInput,
    nm: &NmReference,
    objdump: &BTreeMap<String, u64>,
    elided: bool,
) -> RowGrades {
    RowGrades {
        functions: grade_functions(&input.analysis, nm, objdump, elided),
        methods: grade_methods(&input.analysis, nm),
        user_methods: grade_user_method_coverage(&input.analysis, nm),
        itabs: grade_itabs(&input.analysis, nm),
        types: grade_type_names(&input.analysis, &input.descriptors),
        fields: grade_user_fields(&input.analysis, nm, &input.descriptors),
    }
}

fn assert_symbols_removed(stripped: &[u8], row: &MatrixRow) {
    let image: GoImage<'_> = GoImage::parse(stripped).expect("parse stripped image");
    assert!(
        image.symbol_addrs().is_empty(),
        "{} {}: the stripped copy still carries a symbol table",
        row.version,
        row.target
    );
    assert!(
        !image.sections().iter().any(|section: &Section<'_>| {
            section.name.starts_with(".debug_") || section.name.starts_with(".zdebug_")
        }),
        "{} {}: the stripped copy still carries DWARF",
        row.version,
        row.target
    );
}

fn assert_row(row: &MatrixRow) {
    let loaded: LoadedRow = load_row(row);
    let stripped: Vec<u8> = without_symbols_or_debug_info(&loaded.bytes);
    assert_symbols_removed(&stripped, row);
    let mut failures: Vec<String> = Vec::new();
    for (input, bytes) in [("unstripped", &loaded.bytes), ("stripped", &stripped)] {
        let graded: GradedInput = graded_input(bytes, &loaded.nm);
        if input == "stripped" {
            assert_eq!(
                graded.analysis.moduledata.via,
                ModuledataSource::PclntabBacksearch,
                "{} {} stripped: moduledata must be recovered from its pclntab relationship",
                row.version,
                row.target
            );
        }
        let grades: RowGrades = grade_row(
            &graded,
            &loaded.nm,
            &loaded.objdump,
            row.elided_function_names,
        );
        let summary: Vec<String> = grades
            .classes()
            .iter()
            .map(|(class, grade): &(&str, &Grade)| {
                format!("{class} {}/{}", grade.matched(), grade.total)
            })
            .collect();
        eprintln!(
            "{} {} {input}: {}",
            row.version,
            row.target,
            summary.join(", ")
        );
        if grades.totals() != row.counts {
            failures.push(format!(
                "{} {} {input}: graded populations {:?} differ from the pinned {:?}",
                row.version,
                row.target,
                grades.totals(),
                row.counts
            ));
        }
        for (class, grade) in grades.classes() {
            for mismatch in &grade.mismatches {
                failures.push(format!(
                    "{} {} {input} {class}: {mismatch}",
                    row.version, row.target
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "recovered names differ from go tool nm and go tool objdump of the unstripped build:\n{}",
        failures.join("\n")
    );
}

fn assert_version(rows: &[MatrixRow]) {
    for row in rows {
        assert_row(row);
    }
}

#[test]
fn go117_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO117_ROWS);
}

#[test]
fn go118_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO118_ROWS);
}

#[test]
fn go120_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO120_ROWS);
}

#[test]
fn current_go_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO126_ROWS);
}

#[test]
fn runtime_spelling_follows_the_compiler_type_strings() {
    let cases: [(&str, &str); 8] = [
        ("*internal/bisect.parseError", "*bisect.parseError"),
        ("[2]runtime.Frame", "[2]runtime.Frame"),
        (
            "struct { runtime.gList; runtime.n int32 }",
            "struct { runtime.gList; n int32 }",
        ),
        ("runtime.untracedG.7", "runtime.untracedG"),
        (
            "sync/atomic.Pointer[internal/sync.node[interface {},interface {}]]",
            "atomic.Pointer[internal/sync.node[interface {},interface {}]]",
        ),
        (
            "[16]sync/atomic.Pointer[go.shape.struct { internal/sync.isEntry bool }]",
            "[16]atomic.Pointer[go.shape.struct { internal/sync.isEntry bool }]",
        ),
        ("map[string]*internal/abi.Type", "map[string]*abi.Type"),
        (
            "sync/atomic.(*Pointer[os.dirInfo]).Load",
            "atomic.(*Pointer[os.dirInfo]).Load",
        ),
    ];
    for (linker, runtime) in cases {
        assert_eq!(runtime_spelling(linker), runtime, "spelling of {linker}");
    }
    assert_eq!(
        pclntab_spelling("type:.eq.[1]main.Parcel", true),
        "type:.eq.[...]main.Parcel"
    );
    assert_eq!(
        pclntab_spelling("type:.eq.[1]main.Parcel", false),
        "type:.eq.[1]main.Parcel"
    );
}

#[test]
fn matrix_grades_turn_red_on_mutated_references() {
    let row: &MatrixRow = &GO126_ROWS[0];
    let loaded: LoadedRow = load_row(row);
    let graded: GradedInput = graded_input(&loaded.bytes, &loaded.nm);
    let baseline: RowGrades = grade_row(&graded, &loaded.nm, &loaded.objdump, false);
    for (class, grade) in baseline.classes() {
        assert!(
            grade.total > 0 && grade.mismatches.is_empty(),
            "{class} must grade clean before mutation: {:?}",
            grade.mismatches
        );
    }

    let (renamed, objdump): (NmReference, BTreeMap<String, u64>) =
        renamed_references(&loaded, "main.ParcelPriority", "main.ParcelPriorityMutated");
    let grades: RowGrades = grade_row(&graded, &renamed, &objdump, false);
    assert_eq!(
        grades.functions.mismatches.len(),
        1,
        "a renamed objdump function must turn the function grade red"
    );
    assert_eq!(
        grades.fields.mismatches.len(),
        1,
        "a renamed field marker must turn the field grade red"
    );

    let (renamed, objdump): (NmReference, BTreeMap<String, u64>) =
        renamed_references(&loaded, "main.(*Ledger).Add", "main.(*Ledger).Append");
    let grades: RowGrades = grade_row(&graded, &renamed, &objdump, false);
    assert_eq!(
        grades.methods.mismatches.len(),
        1,
        "a renamed method symbol must turn the method grade red"
    );
    assert_eq!(
        grades.user_methods.mismatches.len(),
        1,
        "a renamed user method must turn the coverage grade red"
    );

    let mut renamed: NmReference = loaded.nm.clone();
    let itab: &mut String = renamed
        .itabs
        .values_mut()
        .find(|pair: &&mut String| pair.ends_with(",error"))
        .expect("an itab binds error");
    *itab = itab.replace(",error", ",fmt.Stringer");
    let grades: RowGrades = grade_row(&graded, &renamed, &loaded.objdump, false);
    assert_eq!(
        grades.itabs.mismatches.len(),
        1,
        "a mutated itab symbol must turn the itab grade red"
    );

    let mut descriptors: BTreeMap<u64, String> = graded.descriptors.clone();
    let parcel: &mut String = descriptors
        .values_mut()
        .find(|name: &&mut String| name.as_str() == "main.Parcel")
        .expect("the descriptor oracle names main.Parcel");
    "main.Parcels".clone_into(parcel);
    assert_eq!(
        grade_type_names(&graded.analysis, &descriptors)
            .mismatches
            .len(),
        1,
        "a mutated descriptor name must turn the type-name grade red"
    );
    let mut shifted: BTreeMap<u64, String> = graded.descriptors.clone();
    let (address, name): (u64, String) = shifted
        .pop_first()
        .expect("the descriptor oracle is non-empty");
    shifted.insert(address + 1, name);
    assert_eq!(
        grade_type_names(&graded.analysis, &shifted)
            .mismatches
            .len(),
        1,
        "a shifted descriptor address must turn the type-name grade red"
    );
}

#[test]
fn published_go_type_name_bar_is_the_nm_graded_stripped_build() {
    let row: &MatrixRow = &GO126_ROWS[0];
    let loaded: LoadedRow = load_row(row);
    let stripped: Vec<u8> = without_symbols_or_debug_info(&loaded.bytes);
    assert_symbols_removed(&stripped, row);
    let graded: GradedInput = graded_input(&stripped, &loaded.nm);
    let grade: Grade = grade_type_names(&graded.analysis, &graded.descriptors);
    eprintln!(
        "{} {} stripped: type names {}/{}",
        row.version,
        row.target,
        grade.matched(),
        grade.total
    );
    let bar: serde_json::Value = common::published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let num: u64 = bar["num"].as_u64().expect("the type names bar carries num");
    let den: u64 = bar["den"].as_u64().expect("the type names bar carries den");
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the type names bar carries value");
    let floor_pct: f64 = bar["floor_pct"]
        .as_f64()
        .expect("the type names bar carries floor_pct");
    assert_eq!(
        (num, den),
        (
            u64::try_from(grade.matched()).expect("count fits u64"),
            u64::try_from(grade.total).expect("count fits u64")
        ),
        "xtask/data/recovery.json must publish this measurement; mismatches {:?}",
        grade.mismatches
    );
    assert!(
        (100.0 * num as f64 / den as f64 - value).abs() < 0.005,
        "the published value must equal {num}/{den}"
    );
    assert!(
        (floor_pct - 100.0).abs() < f64::EPSILON && grade.mismatches.is_empty(),
        "the matrix gate requires every nm-named descriptor to match, so the published floor is \
         100%; mismatches {:?}",
        grade.mismatches
    );
}
