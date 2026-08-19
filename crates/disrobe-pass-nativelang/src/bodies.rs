use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction as NativeRecoveredFunction, RecoveredProgram,
    UnrecoveredFunction, recover_program,
};
use serde::{Deserialize, Serialize};

use crate::debug;
use crate::detect::NativeLang;
use crate::disasm::{MAX_LISTED_FUNCTIONS, map_arch};
use crate::functions::{
    BoundaryConfidence, FunctionExtent, FunctionOrigin, RecoveredFunction, boundary_confidence,
    carve_function, function_extent, sorted_function_starts,
};
use crate::image::{CodeArch, ImageKind, NativeImage};

const MAX_BODY_FUNCTIONS: usize = MAX_LISTED_FUNCTIONS;
const MAX_BODY_CODE_BYTES: u64 = 64 * 1024;
const MAX_RETAINED_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EMITTED_NAME_CHARS: usize = 120;
const MAX_GATE_TOKENS: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodyAbi {
    MsX64,
    SysV,
}

impl BodyAbi {
    const fn to_native(self) -> PseudoAbi {
        match self {
            Self::MsX64 => PseudoAbi::MsX64,
            Self::SysV => PseudoAbi::SysV,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeRole {
    UserCode,
    LanguageRuntime,
    CompilerGenerated,
    Unclassified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodySkip {
    UnsupportedArchitecture,
    NoAssignedAddress,
    UnboundedExtent,
    LowBoundaryConfidence,
    OversizedBody,
    UncarvableRange,
    FunctionBudgetExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "detail")]
pub enum BodyRejection {
    Decompiler(String),
    UnboundIdentifier(String),
    GateBudgetExhausted,
    EmptySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "source")]
pub enum RustBody {
    Emitted(String),
    NotEmitted,
    Rejected(BodyRejection),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum BodyStatus {
    Recovered {
        pseudo_c: String,
        pseudo_rust: RustBody,
    },
    RecoveredElided {
        pseudo_c_bytes: u64,
        pseudo_rust_bytes: u64,
    },
    Rejected {
        reason: BodyRejection,
    },
    NotAttempted {
        reason: BodySkip,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionBody {
    pub name: String,
    pub emitted_name: String,
    pub start: u64,
    pub end: u64,
    pub byte_len: u64,
    pub origin: FunctionOrigin,
    pub boundary_confidence: BoundaryConfidence,
    pub role: RuntimeRole,
    pub status: BodyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyRecovery {
    pub arch_supported: bool,
    pub abi: Option<BodyAbi>,
    pub function_count: u32,
    pub recovered: u32,
    pub recovered_elided: u32,
    pub rejected: u32,
    pub not_attempted: u32,
    pub rust_bodies: u32,
    pub retained_source_bytes: u64,
    pub bodies: Vec<FunctionBody>,
}

impl BodyRecovery {
    #[must_use]
    pub const fn unsupported(function_count: u32) -> Self {
        Self {
            arch_supported: false,
            abi: None,
            function_count,
            recovered: 0,
            recovered_elided: 0,
            rejected: 0,
            not_attempted: function_count,
            rust_bodies: 0,
            retained_source_bytes: 0,
            bodies: Vec::new(),
        }
    }
}

#[must_use]
pub fn recover_bodies(
    image: &NativeImage<'_>,
    lang: NativeLang,
    functions: &[RecoveredFunction],
) -> BodyRecovery {
    recover_bodies_within(image, lang, functions, MAX_RETAINED_SOURCE_BYTES)
}

#[must_use]
pub(crate) fn recover_bodies_within(
    image: &NativeImage<'_>,
    lang: NativeLang,
    functions: &[RecoveredFunction],
    source_budget: u64,
) -> BodyRecovery {
    debug::dbg_section("bodies");
    let count: u32 = u32::try_from(functions.len()).unwrap_or(u32::MAX);
    let Some(abi): Option<BodyAbi> = body_abi(image) else {
        debug::dbg_line(|| {
            format!(
                "body lift skipped: arch {:?} kind {:?} has no supported decompiler ABI",
                image.arch, image.kind
            )
        });
        return BodyRecovery::unsupported(count);
    };
    let sorted_starts: Vec<u64> = sorted_function_starts(functions);
    let mut ordered: Vec<&RecoveredFunction> = functions.iter().collect();
    ordered.sort_by(|left: &&RecoveredFunction, right: &&RecoveredFunction| {
        left.start.cmp(&right.start).then_with(|| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.end.cmp(&right.end))
        })
    });

    let mut used_names: BTreeSet<String> = BTreeSet::new();
    let mut pending: Vec<PendingBody> = Vec::new();
    let mut skipped: Vec<FunctionBody> = Vec::new();
    let mut program: Vec<ProgramFunction> = Vec::new();

    for func in ordered {
        let extent: Option<FunctionExtent> = function_extent(image, func, &sorted_starts);
        let confidence: BoundaryConfidence = extent
            .map_or(BoundaryConfidence::Low, |e: FunctionExtent| {
                boundary_confidence(func, e)
            });
        let role: RuntimeRole = classify_role(lang, func);
        let emitted_name: String = emitted_identifier(&func.name, func.start, &mut used_names);
        let skip: Option<BodySkip> = if !func.address_assigned {
            Some(BodySkip::NoAssignedAddress)
        } else if extent.is_none() {
            Some(BodySkip::UnboundedExtent)
        } else if confidence == BoundaryConfidence::Low {
            Some(BodySkip::LowBoundaryConfidence)
        } else if program.len() >= MAX_BODY_FUNCTIONS {
            Some(BodySkip::FunctionBudgetExhausted)
        } else {
            None
        };
        let end: u64 = extent.map_or(func.start, |e: FunctionExtent| e.end);
        if let Some(reason) = skip {
            skipped.push(FunctionBody {
                name: func.name.clone(),
                emitted_name,
                start: func.start,
                end,
                byte_len: end.saturating_sub(func.start),
                origin: func.origin,
                boundary_confidence: confidence,
                role,
                status: BodyStatus::NotAttempted { reason },
            });
            continue;
        }
        let byte_len: u64 = end.saturating_sub(func.start);
        if byte_len > MAX_BODY_CODE_BYTES {
            skipped.push(FunctionBody {
                name: func.name.clone(),
                emitted_name,
                start: func.start,
                end,
                byte_len,
                origin: func.origin,
                boundary_confidence: confidence,
                role,
                status: BodyStatus::NotAttempted {
                    reason: BodySkip::OversizedBody,
                },
            });
            continue;
        }
        let Some(code): Option<&[u8]> = carve_function(image, func.start, end) else {
            skipped.push(FunctionBody {
                name: func.name.clone(),
                emitted_name,
                start: func.start,
                end,
                byte_len,
                origin: func.origin,
                boundary_confidence: confidence,
                role,
                status: BodyStatus::NotAttempted {
                    reason: BodySkip::UncarvableRange,
                },
            });
            continue;
        };
        program.push(ProgramFunction {
            name: emitted_name.clone(),
            address: func.start,
            code: code.to_vec(),
        });
        pending.push(PendingBody {
            name: func.name.clone(),
            emitted_name,
            start: func.start,
            end,
            byte_len,
            origin: func.origin,
            confidence,
            role,
        });
    }

    debug::dbg_kv("body-attempts", || program.len().to_string());
    let program_result: RecoveredProgram = recover_program(image.raw, &program, abi.to_native());
    let recovered_by_address: BTreeMap<u64, &NativeRecoveredFunction> = program_result
        .recovered
        .iter()
        .map(|f: &NativeRecoveredFunction| (f.address, f))
        .collect();
    let rejected_by_address: BTreeMap<u64, &UnrecoveredFunction> = program_result
        .unrecovered
        .iter()
        .map(|f: &UnrecoveredFunction| (f.address, f))
        .collect();

    let mut bodies: Vec<FunctionBody> = Vec::with_capacity(pending.len() + skipped.len());
    let mut retained_source_bytes: u64 = 0;
    for slot in pending {
        let status: BodyStatus = if let Some(found) = recovered_by_address.get(&slot.start) {
            body_status(found, &mut retained_source_bytes, source_budget)
        } else if let Some(missed) = rejected_by_address.get(&slot.start) {
            BodyStatus::Rejected {
                reason: BodyRejection::Decompiler(missed.reason.clone()),
            }
        } else {
            BodyStatus::Rejected {
                reason: BodyRejection::EmptySource,
            }
        };
        bodies.push(FunctionBody {
            name: slot.name,
            emitted_name: slot.emitted_name,
            start: slot.start,
            end: slot.end,
            byte_len: slot.byte_len,
            origin: slot.origin,
            boundary_confidence: slot.confidence,
            role: slot.role,
            status,
        });
    }
    bodies.extend(skipped);
    bodies.sort_by(|left: &FunctionBody, right: &FunctionBody| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.emitted_name.cmp(&right.emitted_name))
    });

    let mut recovered: u32 = 0;
    let mut recovered_elided: u32 = 0;
    let mut rejected: u32 = 0;
    let mut not_attempted: u32 = 0;
    let mut rust_bodies: u32 = 0;
    for body in &bodies {
        match body.status {
            BodyStatus::Recovered {
                pseudo_rust: RustBody::Emitted(_),
                ..
            } => {
                recovered = recovered.saturating_add(1);
                rust_bodies = rust_bodies.saturating_add(1);
            }
            BodyStatus::Recovered { .. } => recovered = recovered.saturating_add(1),
            BodyStatus::RecoveredElided { .. } => {
                recovered_elided = recovered_elided.saturating_add(1);
            }
            BodyStatus::Rejected { .. } => rejected = rejected.saturating_add(1),
            BodyStatus::NotAttempted { .. } => not_attempted = not_attempted.saturating_add(1),
        }
    }
    debug::dbg_kv("body-outcomes", || {
        format!(
            "recovered={recovered} elided={recovered_elided} rejected={rejected} \
             not-attempted={not_attempted}"
        )
    });

    BodyRecovery {
        arch_supported: true,
        abi: Some(abi),
        function_count: count,
        recovered,
        recovered_elided,
        rejected,
        not_attempted,
        rust_bodies,
        retained_source_bytes,
        bodies,
    }
}

struct PendingBody {
    name: String,
    emitted_name: String,
    start: u64,
    end: u64,
    byte_len: u64,
    origin: FunctionOrigin,
    confidence: BoundaryConfidence,
    role: RuntimeRole,
}

fn body_status(found: &NativeRecoveredFunction, retained: &mut u64, budget: u64) -> BodyStatus {
    if found.source.trim().is_empty() {
        return BodyStatus::Rejected {
            reason: BodyRejection::EmptySource,
        };
    }
    if let Some(reason) = first_unbound_identifier(&found.source) {
        return BodyStatus::Rejected { reason };
    }
    let rust: RustBody = match found.rust_source.as_ref() {
        None => RustBody::NotEmitted,
        Some(source) if source.trim().is_empty() => RustBody::Rejected(BodyRejection::EmptySource),
        Some(source) => match complete_rust_declarations(source) {
            Err(rejection) => RustBody::Rejected(rejection),
            Ok(completed) => first_undeclared_rust_call(&completed)
                .map_or(RustBody::Emitted(completed), RustBody::Rejected),
        },
    };
    let c_bytes: u64 = found.source.len() as u64;
    let rust_bytes: u64 = match &rust {
        RustBody::Emitted(source) => source.len() as u64,
        RustBody::NotEmitted | RustBody::Rejected(_) => 0,
    };
    let total: u64 = c_bytes.saturating_add(rust_bytes);
    if retained.saturating_add(total) > budget {
        return BodyStatus::RecoveredElided {
            pseudo_c_bytes: c_bytes,
            pseudo_rust_bytes: rust_bytes,
        };
    }
    *retained = retained.saturating_add(total);
    BodyStatus::Recovered {
        pseudo_c: found.source.clone(),
        pseudo_rust: rust,
    }
}

const fn body_abi(image: &NativeImage<'_>) -> Option<BodyAbi> {
    if map_arch(image.arch).is_none() {
        return None;
    }
    match image.arch {
        CodeArch::X86_64 => match image.kind {
            ImageKind::Pe => Some(BodyAbi::MsX64),
            ImageKind::Elf | ImageKind::MachO => Some(BodyAbi::SysV),
        },
        CodeArch::X86 | CodeArch::Aarch64 | CodeArch::Other => None,
    }
}

const C_KEYWORDS: &[&str] = &[
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "__attribute__",
    "__int128",
    "__restrict",
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "int16_t",
    "int32_t",
    "int64_t",
    "int8_t",
    "intptr_t",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "size_t",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uint8_t",
    "uintptr_t",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
];

const C_COMPILER_BUILTINS: &[&str] = &[
    "__builtin_bswap16",
    "__builtin_bswap32",
    "__builtin_bswap64",
    "__builtin_clz",
    "__builtin_clzll",
    "__builtin_fabs",
    "__builtin_fabsf",
    "__builtin_fabsf16",
    "__builtin_offsetof",
    "__builtin_sqrt",
    "__builtin_sqrtf",
    "__builtin_trap",
];

const C_TYPE_TOKENS: &[&str] = &[
    "_Bool",
    "__int128",
    "bool",
    "char",
    "double",
    "float",
    "int",
    "int16_t",
    "int32_t",
    "int64_t",
    "int8_t",
    "intptr_t",
    "long",
    "short",
    "signed",
    "size_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uint8_t",
    "uintptr_t",
    "unsigned",
    "void",
];

const STRING_H_NAMES: &[&str] = &[
    "memchr", "memcmp", "memcpy", "memmove", "memset", "strcat", "strchr", "strcmp", "strcpy",
    "strcspn", "strlen", "strncat", "strncmp", "strncpy", "strpbrk", "strrchr", "strspn", "strstr",
    "strtok",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum CToken {
    Ident(String),
    Punct(char),
    Literal,
}

#[derive(Debug)]
struct CTokens {
    tokens: Vec<CToken>,
    provided: BTreeSet<String>,
    truncated: bool,
}

fn tokenize_c(source: &str) -> CTokens {
    let mut tokens: Vec<CToken> = Vec::new();
    let mut provided: BTreeSet<String> = BTreeSet::new();
    for line in source.lines() {
        let trimmed: &str = line.trim_start();
        if let Some(directive) = trimmed.strip_prefix('#') {
            if directive.trim_start().starts_with("include") && directive.contains("<string.h>") {
                for name in STRING_H_NAMES {
                    provided.insert((*name).to_owned());
                }
            }
            continue;
        }
        let bytes: &[u8] = line.as_bytes();
        let mut index: usize = 0;
        while index < bytes.len() && tokens.len() < MAX_GATE_TOKENS {
            let byte: u8 = bytes[index];
            if byte == b'_' || byte.is_ascii_alphabetic() {
                let start: usize = index;
                while index < bytes.len()
                    && (bytes[index] == b'_' || bytes[index].is_ascii_alphanumeric())
                {
                    index = index.saturating_add(1);
                }
                match line.get(start..index) {
                    Some(text) => tokens.push(CToken::Ident(text.to_owned())),
                    None => tokens.push(CToken::Literal),
                }
            } else if byte.is_ascii_digit() {
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'.')
                {
                    index = index.saturating_add(1);
                }
                tokens.push(CToken::Literal);
            } else if byte == b'"' || byte == b'\'' {
                let quote: u8 = byte;
                index = index.saturating_add(1);
                while index < bytes.len() && bytes[index] != quote {
                    if bytes[index] == b'\\' {
                        index = index.saturating_add(1);
                    }
                    index = index.saturating_add(1);
                }
                index = index.saturating_add(1);
                tokens.push(CToken::Literal);
            } else if byte.is_ascii_whitespace() {
                index = index.saturating_add(1);
            } else {
                tokens.push(CToken::Punct(byte as char));
                index = index.saturating_add(1);
            }
        }
        if tokens.len() >= MAX_GATE_TOKENS {
            return CTokens {
                tokens,
                provided,
                truncated: true,
            };
        }
    }
    CTokens {
        tokens,
        provided,
        truncated: false,
    }
}

fn strip_attribute_groups(tokens: Vec<CToken>) -> Vec<CToken> {
    let mut out: Vec<CToken> = Vec::with_capacity(tokens.len());
    let mut index: usize = 0;
    while index < tokens.len() {
        let is_attribute: bool = matches!(
            tokens.get(index),
            Some(CToken::Ident(name)) if name == "__attribute__"
        );
        if !is_attribute {
            if let Some(token) = tokens.get(index) {
                out.push(token.clone());
            }
            index = index.saturating_add(1);
            continue;
        }
        index = index.saturating_add(1);
        if !matches!(tokens.get(index), Some(CToken::Punct('('))) {
            continue;
        }
        let mut depth: usize = 0;
        while index < tokens.len() {
            match tokens.get(index) {
                Some(CToken::Punct('(')) => depth = depth.saturating_add(1),
                Some(CToken::Punct(')')) => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        index = index.saturating_add(1);
                        break;
                    }
                }
                _ => {}
            }
            index = index.saturating_add(1);
        }
    }
    out
}

fn first_unbound_identifier(source: &str) -> Option<BodyRejection> {
    let scan: CTokens = tokenize_c(source);
    if scan.truncated {
        return Some(BodyRejection::GateBudgetExhausted);
    }
    let provided: BTreeSet<String> = scan.provided;
    let tokens: Vec<CToken> = strip_attribute_groups(scan.tokens);
    let mut type_names: BTreeSet<String> = BTreeSet::new();
    let mut typedef_depth: Option<usize> = None;
    let mut brace_depth: usize = 0;
    let mut last_ident: Option<&str> = None;
    for token in &tokens {
        match token {
            CToken::Punct('{') => brace_depth = brace_depth.saturating_add(1),
            CToken::Punct('}') => brace_depth = brace_depth.saturating_sub(1),
            CToken::Ident(name) if name == "typedef" => {
                typedef_depth = Some(brace_depth);
                last_ident = None;
            }
            CToken::Ident(name) if typedef_depth == Some(brace_depth) => {
                last_ident = Some(name.as_str());
            }
            CToken::Punct(';') if typedef_depth == Some(brace_depth) => {
                if let Some(name) = last_ident {
                    type_names.insert(name.to_owned());
                }
                typedef_depth = None;
                last_ident = None;
            }
            CToken::Punct(_) if typedef_depth == Some(brace_depth) => last_ident = None,
            CToken::Ident(_) | CToken::Punct(_) | CToken::Literal => {}
        }
    }

    let mut bound: BTreeSet<String> = provided;
    bound.extend(type_names.iter().cloned());
    let mut used: Vec<&str> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let CToken::Ident(name) = token else { continue };
        if C_KEYWORDS.contains(&name.as_str()) || C_COMPILER_BUILTINS.contains(&name.as_str()) {
            continue;
        }
        if matches!(
            tokens.get(index.saturating_add(1)),
            Some(CToken::Punct(':'))
        ) && matches!(
            index
                .checked_sub(1)
                .and_then(|prev: usize| tokens.get(prev)),
            None | Some(CToken::Punct(';' | '{' | '}'))
        ) {
            bound.insert(name.clone());
            continue;
        }
        let mut back: usize = index;
        while let Some(prev) = back.checked_sub(1) {
            back = prev;
            match tokens.get(prev) {
                Some(CToken::Punct('*')) => {}
                Some(CToken::Ident(previous))
                    if C_TYPE_TOKENS.contains(&previous.as_str())
                        || type_names.contains(previous.as_str()) =>
                {
                    bound.insert(name.clone());
                    break;
                }
                _ => break,
            }
        }
        used.push(name.as_str());
    }
    used.into_iter()
        .find(|name: &&str| !bound.contains(*name))
        .map(|name: &str| BodyRejection::UnboundIdentifier(name.to_owned()))
}

const RUST_CALL_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "extern", "fn", "for", "if", "in", "let", "loop",
    "match", "move", "mut", "pub", "return", "static", "unsafe", "while",
];

fn first_undeclared_rust_call(source: &str) -> Option<BodyRejection> {
    match undeclared_rust_calls(source) {
        Err(rejection) => Some(rejection),
        Ok(calls) => calls
            .into_iter()
            .next()
            .map(|call: SiblingCall| BodyRejection::UnboundIdentifier(call.name)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SiblingCall {
    name: String,
    arity: usize,
}

fn undeclared_rust_calls(source: &str) -> Result<Vec<SiblingCall>, BodyRejection> {
    let scan: CTokens = tokenize_c(source);
    if scan.truncated {
        return Err(BodyRejection::GateBudgetExhausted);
    }
    let tokens: Vec<CToken> = scan.tokens;
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token, CToken::Ident(name) if name == "fn")
            && let Some(CToken::Ident(name)) = tokens.get(index.saturating_add(1))
        {
            declared.insert(name.clone());
        }
    }
    let mut order: Vec<SiblingCall> = Vec::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (index, token) in tokens.iter().enumerate() {
        let CToken::Ident(name) = token else { continue };
        if RUST_CALL_KEYWORDS.contains(&name.as_str()) || declared.contains(name.as_str()) {
            continue;
        }
        if !matches!(
            tokens.get(index.saturating_add(1)),
            Some(CToken::Punct('('))
        ) {
            continue;
        }
        let qualified: bool = matches!(
            index
                .checked_sub(1)
                .and_then(|prev: usize| tokens.get(prev)),
            Some(CToken::Punct('.' | ':' | '!'))
        );
        if qualified {
            continue;
        }
        let Some(arity): Option<usize> = call_arity(&tokens, index.saturating_add(1)) else {
            return Err(BodyRejection::UnboundIdentifier(name.clone()));
        };
        match seen.get(name.as_str()) {
            Some(previous) if *previous != arity => {
                return Err(BodyRejection::UnboundIdentifier(name.clone()));
            }
            Some(_) => {}
            None => {
                seen.insert(name.clone(), arity);
                order.push(SiblingCall {
                    name: name.clone(),
                    arity,
                });
            }
        }
    }
    Ok(order)
}

fn call_arity(tokens: &[CToken], open_paren: usize) -> Option<usize> {
    let mut depth: usize = 0;
    let mut commas: usize = 0;
    let mut empty: bool = true;
    let mut index: usize = open_paren;
    while let Some(token) = tokens.get(index) {
        match token {
            CToken::Punct('(' | '[' | '{') => depth = depth.saturating_add(1),
            CToken::Punct(')' | ']' | '}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(if empty { 0 } else { commas.saturating_add(1) });
                }
                empty = false;
            }
            CToken::Punct(',') if depth == 1 => {
                commas = commas.saturating_add(1);
                empty = false;
            }
            CToken::Ident(_) | CToken::Literal | CToken::Punct(_) => empty = false,
        }
        index = index.saturating_add(1);
    }
    None
}

fn complete_rust_declarations(source: &str) -> Result<String, BodyRejection> {
    let calls: Vec<SiblingCall> = undeclared_rust_calls(source)?;
    if calls.is_empty() {
        return Ok(source.to_owned());
    }
    let mut block: String = String::from("extern \"C\" {\n");
    for call in &calls {
        let params: String = (0..call.arity)
            .map(|index: usize| format!("a{index}: u64"))
            .collect::<Vec<String>>()
            .join(", ");
        block.push_str("    fn ");
        block.push_str(&call.name);
        block.push('(');
        block.push_str(&params);
        block.push_str(") -> u64;\n");
    }
    block.push_str("}\n");
    block.push_str(source);
    Ok(block)
}

fn emitted_identifier(name: &str, address: u64, used: &mut BTreeSet<String>) -> String {
    let mut candidate: String = String::with_capacity(name.len().min(MAX_EMITTED_NAME_CHARS));
    for ch in name.chars().take(MAX_EMITTED_NAME_CHARS) {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            candidate.push(ch);
        } else {
            candidate.push('_');
        }
    }
    let repaired: bool =
        if candidate.is_empty() || candidate.starts_with(|c: char| c.is_ascii_digit()) {
            candidate.insert(0, 'f');
            true
        } else {
            candidate != name
        };
    if repaired
        || C_KEYWORDS.contains(&candidate.as_str())
        || C_COMPILER_BUILTINS.contains(&candidate.as_str())
        || used.contains(&candidate)
    {
        candidate = format!("{candidate}_{address:x}");
    }
    while used.contains(&candidate) {
        candidate.push('_');
    }
    used.insert(candidate.clone());
    candidate
}

const NIM_COMPILER_GENERATED: &[&str] = &[
    "NimMain",
    "NimMainInner",
    "NimMainModule",
    "PreMain",
    "PreMainInner",
    "systemDatInit",
    "systemInit",
];

const NIM_RUNTIME_MODULES: &[&str] = &[
    "alloc",
    "assertions",
    "avltree",
    "bitmasks",
    "cellseqs_v2",
    "cellsets",
    "chcks",
    "digitsutils",
    "dollars",
    "dragonbox",
    "exitprocs",
    "formatfloat",
    "gc",
    "io",
    "iterators",
    "memory",
    "mm",
    "schubfach",
    "seqs_v2",
    "strs_v2",
    "syncio",
    "system",
    "widestrs",
];

const ZIG_RUNTIME_MODULES: &[&str] = &[
    "Allocator",
    "Io",
    "Progress",
    "Random",
    "Reader",
    "Thread",
    "Writer",
    "array_list",
    "ascii",
    "atomic",
    "builtin",
    "coff",
    "compress",
    "crypto",
    "debug",
    "dwarf",
    "elf",
    "fmt",
    "fs",
    "hash",
    "hash_map",
    "heap",
    "io",
    "json",
    "leb128",
    "linked_list",
    "log",
    "macho",
    "math",
    "mem",
    "meta",
    "os",
    "pdb",
    "posix",
    "process",
    "sort",
    "std",
    "target",
    "time",
    "unicode",
];

const CRYSTAL_RUNTIME_MODULES: &[&str] = &[
    "Crystal",
    "Exception",
    "Fiber",
    "GC",
    "Pointer",
    "Reference",
    "Slice",
    "String",
    "Thread",
];

const D_RUNTIME_MODULES: &[&str] = &["core", "etc", "gc", "object", "rt", "std"];

const RUNTIME_SOURCE_MARKERS: &[&str] = &[
    "/druntime/",
    "/lib/crystal/",
    "/lib/std/",
    "/phobos/",
    "/share/crystal/src/",
    "\\druntime\\",
    "\\lib\\std\\",
    "\\phobos\\",
];

fn classify_role(lang: NativeLang, func: &RecoveredFunction) -> RuntimeRole {
    let name: &str = func.name.as_str();
    if compiler_generated(lang, name) {
        return RuntimeRole::CompilerGenerated;
    }
    if let Some(lines) = func.source_lines.as_ref()
        && let Some(file) = lines.file.as_deref()
    {
        let lowered: String = file.to_ascii_lowercase();
        if RUNTIME_SOURCE_MARKERS
            .iter()
            .any(|marker: &&str| lowered.contains(marker))
        {
            return RuntimeRole::LanguageRuntime;
        }
    }
    let modules: &[&str] = match lang {
        NativeLang::Nim => NIM_RUNTIME_MODULES,
        NativeLang::Zig => ZIG_RUNTIME_MODULES,
        NativeLang::Crystal => CRYSTAL_RUNTIME_MODULES,
        NativeLang::D => D_RUNTIME_MODULES,
    };
    let separator: char = if lang == NativeLang::Crystal {
        ':'
    } else {
        '.'
    };
    if let Some(prefix) = name.split(separator).next()
        && modules.contains(&prefix)
    {
        return RuntimeRole::LanguageRuntime;
    }
    if func.demangled.is_none() && name.starts_with("sub_") {
        return RuntimeRole::Unclassified;
    }
    RuntimeRole::UserCode
}

fn compiler_generated(lang: NativeLang, name: &str) -> bool {
    match lang {
        NativeLang::Nim => {
            NIM_COMPILER_GENERATED.contains(&name)
                || name.starts_with("nim")
                || name.starts_with("Nim")
        }
        NativeLang::Zig => name.starts_with("__") || name.starts_with("start."),
        NativeLang::Crystal => name.starts_with("__crystal") || name.starts_with("_crystal"),
        NativeLang::D => name.starts_with("_d_") || name.starts_with("rt."),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::functions::LineRange;
    use crate::image::Section;
    use object::SectionKind;

    fn func(name: &str, start: u64, end: Option<u64>) -> RecoveredFunction {
        RecoveredFunction {
            name: name.to_owned(),
            demangled: None,
            signature: None,
            start,
            end,
            source_lines: None,
            params: Vec::new(),
            origin: FunctionOrigin::SymbolTable,
            address_assigned: true,
        }
    }

    fn image_with_text(
        kind: ImageKind,
        arch: CodeArch,
        addr: u64,
        data: &'static [u8],
    ) -> NativeImage<'static> {
        NativeImage {
            kind,
            relocatable: false,
            arch,
            ptr_size: 8,
            entry: addr,
            raw: &[],
            sections: vec![Section {
                name: ".text".to_owned(),
                address: addr,
                kind: SectionKind::Text,
                data,
            }],
            symbols: Vec::new(),
            func_symbols: Vec::new(),
        }
    }

    #[test]
    fn dotted_names_become_valid_c_identifiers() {
        let mut used: BTreeSet<String> = BTreeSet::new();
        let first: String = emitted_identifier("io.Writer.print", 0x0103_5190, &mut used);
        assert_eq!(first, "io_Writer_print_1035190");
        let second: String = emitted_identifier("system.-%", 0x0100_8140, &mut used);
        assert_eq!(second, "system____1008140");
        let plain: String = emitted_identifier("sub_1400012a0", 0x0001_4000_12a0, &mut used);
        assert_eq!(plain, "sub_1400012a0");
    }

    #[test]
    fn colliding_names_get_distinct_identifiers() {
        let mut used: BTreeSet<String> = BTreeSet::new();
        let first: String = emitted_identifier("dup", 0x1000, &mut used);
        let second: String = emitted_identifier("dup", 0x1000, &mut used);
        assert_eq!(first, "dup");
        assert_eq!(second, "dup_1000");
        let third: String = emitted_identifier("dup_1000", 0x2000, &mut used);
        assert_eq!(third, "dup_1000_2000");
        let fourth: String = emitted_identifier("dup", 0x1000, &mut used);
        assert_eq!(fourth, "dup_1000_");
    }

    #[test]
    fn leading_digit_and_keyword_names_are_repaired() {
        let mut used: BTreeSet<String> = BTreeSet::new();
        assert_eq!(emitted_identifier("9lives", 0x30, &mut used), "f9lives_30");
        assert_eq!(emitted_identifier("while", 0x40, &mut used), "while_40");
    }

    #[test]
    fn gate_accepts_a_self_contained_translation_unit() {
        let source: &str = "#include <stdint.h>\nextern uint64_t sub_10(uint64_t);\nuint64_t \
                            f(uint64_t a0) {\n    uint64_t r_rax = a0;\n    r_rax = \
                            sub_10(r_rax);\n    return r_rax;\n}\n";
        assert_eq!(first_unbound_identifier(source), None);
    }

    #[test]
    fn gate_rejects_an_undeclared_temporary() {
        let source: &str = "#include <stdint.h>\nuint64_t f(uint64_t a0) {\n    uint64_t r_rax = \
                            a0;\n    if (sel_cc_0 == 0) { return r_rax; }\n    return 0;\n}\n";
        assert_eq!(
            first_unbound_identifier(source),
            Some(BodyRejection::UnboundIdentifier("sel_cc_0".to_owned()))
        );
    }

    #[test]
    fn gate_binds_typedefs_labels_and_declared_headers() {
        let source: &str = "#include <stdint.h>\n#include <string.h>\nuint64_t f(uint64_t a0) {\n \
                            typedef struct __attribute__((packed, may_alias)) {\n        uint64_t \
                            field_0;\n    } recovered_struct_0_t;\n    recovered_struct_0_t \
                            *view = (recovered_struct_0_t *)(uintptr_t)a0;\n    memcpy(&a0, \
                            &view->field_0, 8);\n    goto recover_L6;\n    recover_L6: ;\n    \
                            return a0;\n}\n";
        assert_eq!(first_unbound_identifier(source), None);
    }

    #[test]
    fn compiler_builtins_need_no_declaration_in_a_recovered_body() {
        let source: &str = "#include <stdint.h>\nuint64_t f(uint64_t a0) {\n    if (a0 == 0) { \
                            __builtin_trap(); }\n    return (uint64_t)__builtin_clzll(a0);\n}\n";
        assert_eq!(first_unbound_identifier(source), None);
    }

    #[test]
    fn an_unknown_double_underscore_name_is_still_unbound() {
        let source: &str = "#include <stdint.h>\nuint64_t f(uint64_t a0) {\n    return \
                            __builtin_not_a_real_builtin(a0);\n}\n";
        assert_eq!(
            first_unbound_identifier(source),
            Some(BodyRejection::UnboundIdentifier(
                "__builtin_not_a_real_builtin".to_owned()
            ))
        );
    }

    fn rust_sources_under(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries: std::fs::ReadDir = std::fs::read_dir(root).unwrap_or_else(|error| {
            panic!(
                "the builtin allowlist is graded against {}, which must be readable: {error}",
                root.display()
            )
        });
        for entry in entries {
            let path: std::path::PathBuf = entry.expect("read a directory entry").path();
            if path.is_dir() {
                rust_sources_under(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn the_builtin_allowlist_covers_every_builtin_the_decompiler_can_emit() {
        let root: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("disrobe-pass-native")
            .join("src");
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        rust_sources_under(&root, &mut files);
        assert!(
            files.len() > 10,
            "the decompiler crate must expose its sources for the builtin drift grade, found {}",
            files.len()
        );
        files.sort();
        let mut found: BTreeSet<String> = BTreeSet::new();
        for file in &files {
            let text: String = std::fs::read_to_string(file)
                .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
            let bytes: &[u8] = text.as_bytes();
            let needle: &[u8] = b"__builtin_";
            let mut index: usize = 0;
            while let Some(offset) = bytes
                .get(index..)
                .and_then(|rest: &[u8]| rest.windows(needle.len()).position(|w| w == needle))
            {
                let start: usize = index + offset;
                let mut end: usize = start + needle.len();
                while bytes
                    .get(end)
                    .is_some_and(|b: &u8| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    end += 1;
                }
                if let Some(name) = text.get(start..end) {
                    found.insert(name.to_owned());
                }
                index = end;
            }
        }
        assert!(
            found.len() >= 8,
            "the drift grade must see the builtins the decompiler emits, saw {found:?}"
        );
        for name in &found {
            assert!(
                C_COMPILER_BUILTINS
                    .iter()
                    .any(|known: &&str| known.starts_with(name.as_str())),
                "{name} is emitted by the decompiler but the gate would report it unbound; add it \
                 to C_COMPILER_BUILTINS"
            );
        }
    }

    #[test]
    fn dropped_sibling_declarations_are_restored_before_the_rust_gate() {
        let source: &str = "#[allow(dead_code)]\npub fn caller(a0: u64) -> u64 {\n    let mut \
                            r_rax: u64 = a0;\n    r_rax = unsafe { nimCopyMem(r_rax, a0, a0, a0, \
                            a0) };\n    r_rax = unsafe { nimZeroMem(r_rax, a0) };\n    r_rax = \
                            unsafe { nimCopyMem(r_rax, a0, a0, a0, a0) };\n    r_rax\n}\n";
        let completed: String =
            complete_rust_declarations(source).expect("the sibling arities agree");
        assert!(
            completed.starts_with(
                "extern \"C\" {\n    fn nimCopyMem(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) \
                 -> u64;\n    fn nimZeroMem(a0: u64, a1: u64) -> u64;\n}\n"
            ),
            "{completed}"
        );
        assert!(completed.ends_with(source), "{completed}");
        assert_eq!(first_undeclared_rust_call(&completed), None);
    }

    #[test]
    fn a_sibling_called_at_two_arities_is_refused_rather_than_guessed() {
        let source: &str = "pub fn caller(a0: u64) -> u64 {\n    let mut r_rax: u64 = unsafe { \
                            helper(a0) };\n    r_rax = unsafe { helper(a0, r_rax) };\n    \
                            r_rax\n}\n";
        assert_eq!(
            complete_rust_declarations(source),
            Err(BodyRejection::UnboundIdentifier("helper".to_owned()))
        );
    }

    #[test]
    fn nested_call_arguments_do_not_inflate_the_restored_arity() {
        let source: &str = "pub fn caller(a0: u64) -> u64 {\n    unsafe { outer(inner(a0, a0), \
                            a0) }\n}\n";
        let completed: String = complete_rust_declarations(source).expect("arities are consistent");
        assert!(
            completed.contains("fn outer(a0: u64, a1: u64) -> u64;"),
            "{completed}"
        );
        assert!(
            completed.contains("fn inner(a0: u64, a1: u64) -> u64;"),
            "{completed}"
        );
    }

    #[test]
    fn a_body_with_no_undeclared_call_is_left_byte_identical() {
        let source: &str = "extern \"C\" {\n    fn sub_10(a0: u64) -> u64;\n}\npub fn caller(a0: \
                            u64) -> u64 {\n    unsafe { sub_10(a0) }\n}\n";
        assert_eq!(
            complete_rust_declarations(source).as_deref(),
            Ok(source),
            "an already self-contained body must not be rewritten"
        );
    }

    #[test]
    fn rust_gate_rejects_an_undeclared_sibling_call() {
        let source: &str = "pub fn caller(a0: u64) -> u64 {\n    let mut r_rax: u64 = a0;\n    \
                            r_rax = unsafe { system_osTryAllocPages_1009d50(r_rax) };\n    \
                            r_rax\n}\n";
        assert_eq!(
            first_undeclared_rust_call(source),
            Some(BodyRejection::UnboundIdentifier(
                "system_osTryAllocPages_1009d50".to_owned()
            ))
        );
    }

    #[test]
    fn rust_gate_accepts_declared_externs_and_method_calls() {
        let source: &str = "extern \"C\" {\n    fn sub_10(a0: u64) -> u64;\n}\npub fn caller(a0: \
                            u64) -> u64 {\n    let mut frame: [u8; 8] = [0u8; 8];\n    let base: \
                            u64 = frame.as_mut_ptr() as usize as u64;\n    let got: u64 = unsafe \
                            { sub_10(a0) };\n    \
                            got.wrapping_add(base).wrapping_add(u64::from(1u32))\n}\n";
        assert_eq!(first_undeclared_rust_call(source), None);
    }

    #[test]
    fn gate_rejects_an_undeclared_call_without_its_header() {
        let source: &str = "#include <stdint.h>\nuint64_t f(uint64_t a0) {\n    memcpy(&a0, &a0, \
                            8);\n    return a0;\n}\n";
        assert_eq!(
            first_unbound_identifier(source),
            Some(BodyRejection::UnboundIdentifier("memcpy".to_owned()))
        );
    }

    #[test]
    fn a_token_flood_exhausts_the_gate_budget_instead_of_passing_unchecked() {
        let mut source: String = String::from("#include <stdint.h>\nuint64_t f(void) {\n");
        for index in 0..(MAX_GATE_TOKENS / 4) {
            source.push_str("    a");
            source.push_str(&index.to_string());
            source.push_str(" = 0;\n");
        }
        source.push_str("    return 0;\n}\n");
        assert_eq!(
            first_unbound_identifier(&source),
            Some(BodyRejection::GateBudgetExhausted)
        );
        assert_eq!(
            first_undeclared_rust_call(&source),
            Some(BodyRejection::GateBudgetExhausted)
        );
    }

    #[test]
    fn unsupported_architecture_reports_every_function_as_not_attempted() {
        let image: NativeImage<'static> =
            image_with_text(ImageKind::Elf, CodeArch::Other, 0x1000, &[0xc3]);
        let recovery: BodyRecovery =
            recover_bodies(&image, NativeLang::Zig, &[func("f", 0x1000, Some(0x1001))]);
        assert!(!recovery.arch_supported);
        assert_eq!(recovery.abi, None);
        assert_eq!(recovery.not_attempted, 1);
        assert_eq!(recovery.recovered, 0);
    }

    #[test]
    fn section_end_bounded_carve_is_low_confidence_and_not_attempted() {
        let code: &'static [u8] = &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let image: NativeImage<'static> =
            image_with_text(ImageKind::Elf, CodeArch::X86_64, 0x1000, code);
        let recovery: BodyRecovery =
            recover_bodies(&image, NativeLang::Zig, &[func("only", 0x1000, None)]);
        assert_eq!(recovery.bodies.len(), 1);
        assert_eq!(
            recovery.bodies[0].boundary_confidence,
            BoundaryConfidence::Low
        );
        assert_eq!(
            recovery.bodies[0].status,
            BodyStatus::NotAttempted {
                reason: BodySkip::LowBoundaryConfidence
            }
        );
    }

    #[test]
    fn counts_partition_the_function_set() {
        let code: &'static [u8] = &[0x48, 0x89, 0xf8, 0xc3, 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let image: NativeImage<'static> =
            image_with_text(ImageKind::Elf, CodeArch::X86_64, 0x1000, code);
        let mut unassigned: RecoveredFunction = func("reloc", 0x2000, Some(0x2004));
        unassigned.address_assigned = false;
        let recovery: BodyRecovery = recover_bodies(
            &image,
            NativeLang::Zig,
            &[
                func("identity", 0x1000, Some(0x1004)),
                func("frame", 0x1004, Some(0x100a)),
                unassigned,
            ],
        );
        assert_eq!(recovery.function_count, 3);
        let total: u32 = recovery.recovered
            + recovery.recovered_elided
            + recovery.rejected
            + recovery.not_attempted;
        assert_eq!(total, recovery.function_count);
        assert_eq!(u32::try_from(recovery.bodies.len()).unwrap(), total);
    }

    #[test]
    fn identity_leaf_recovers_a_pseudo_c_body() {
        let code: &'static [u8] = &[0x48, 0x89, 0xf8, 0xc3];
        let image: NativeImage<'static> =
            image_with_text(ImageKind::Elf, CodeArch::X86_64, 0x1000, code);
        let recovery: BodyRecovery = recover_bodies(
            &image,
            NativeLang::Zig,
            &[func("identity", 0x1000, Some(0x1004))],
        );
        assert_eq!(recovery.abi, Some(BodyAbi::SysV));
        let BodyStatus::Recovered {
            ref pseudo_c,
            ref pseudo_rust,
        } = recovery.bodies[0].status
        else {
            panic!("expected a recovered body, got {:?}", recovery.bodies[0]);
        };
        assert!(pseudo_c.contains("uint64_t identity("), "{pseudo_c}");
        let RustBody::Emitted(ref rust) = *pseudo_rust else {
            panic!("expected pseudo-Rust, got {pseudo_rust:?}");
        };
        assert!(rust.contains("fn identity("), "{rust}");
        assert_eq!(recovery.rust_bodies, 1);
        assert_eq!(
            recovery.retained_source_bytes,
            (pseudo_c.len() + rust.len()) as u64
        );
    }

    #[test]
    fn a_source_budget_elides_later_bodies_without_losing_their_outcome() {
        let code: &'static [u8] = &[0x48, 0x89, 0xf8, 0xc3, 0x48, 0x89, 0xf0, 0xc3];
        let image: NativeImage<'static> =
            image_with_text(ImageKind::Elf, CodeArch::X86_64, 0x1000, code);
        let functions: [RecoveredFunction; 2] = [
            func("first", 0x1000, Some(0x1004)),
            func("second", 0x1004, Some(0x1008)),
        ];
        let full: BodyRecovery =
            recover_bodies_within(&image, NativeLang::Zig, &functions, 1 << 20);
        assert_eq!(full.recovered, 2);
        assert_eq!(full.recovered_elided, 0);
        let first_bytes: u64 = match &full.bodies[0].status {
            BodyStatus::Recovered {
                pseudo_c,
                pseudo_rust: RustBody::Emitted(rust),
            } => (pseudo_c.len() + rust.len()) as u64,
            other => panic!("expected a recovered first body, got {other:?}"),
        };
        let squeezed: BodyRecovery =
            recover_bodies_within(&image, NativeLang::Zig, &functions, first_bytes);
        assert_eq!(squeezed.recovered, 1);
        assert_eq!(squeezed.recovered_elided, 1);
        assert_eq!(squeezed.retained_source_bytes, first_bytes);
        let BodyStatus::RecoveredElided {
            pseudo_c_bytes,
            pseudo_rust_bytes,
        } = squeezed.bodies[1].status
        else {
            panic!(
                "expected the second body to be elided, got {:?}",
                squeezed.bodies[1]
            );
        };
        assert!(pseudo_c_bytes > 0);
        assert!(pseudo_rust_bytes > 0);
        assert_eq!(
            squeezed.recovered
                + squeezed.recovered_elided
                + squeezed.rejected
                + squeezed.not_attempted,
            squeezed.function_count
        );
    }

    #[test]
    fn pe_images_select_the_microsoft_abi() {
        let code: &'static [u8] = &[0x48, 0x89, 0xc8, 0xc3];
        let image: NativeImage<'static> =
            image_with_text(ImageKind::Pe, CodeArch::X86_64, 0x1000, code);
        let recovery: BodyRecovery = recover_bodies(
            &image,
            NativeLang::D,
            &[func("identity", 0x1000, Some(0x1004))],
        );
        assert_eq!(recovery.abi, Some(BodyAbi::MsX64));
    }

    #[test]
    fn roles_separate_runtime_compiler_and_user_functions() {
        let mut user: RecoveredFunction = func("main.greet", 0x1000, Some(0x1004));
        user.demangled = Some("main.greet".to_owned());
        assert_eq!(classify_role(NativeLang::Zig, &user), RuntimeRole::UserCode);
        assert_eq!(
            classify_role(NativeLang::Zig, &func("io.Writer.print", 0x1000, None)),
            RuntimeRole::LanguageRuntime
        );
        assert_eq!(
            classify_role(NativeLang::Zig, &func("__truncdfsf2", 0x1000, None)),
            RuntimeRole::CompilerGenerated
        );
        assert_eq!(
            classify_role(NativeLang::Nim, &func("NimMainModule", 0x1000, None)),
            RuntimeRole::CompilerGenerated
        );
        assert_eq!(
            classify_role(NativeLang::Nim, &func("digitsutils.addInt", 0x1000, None)),
            RuntimeRole::LanguageRuntime
        );
        assert_eq!(
            classify_role(NativeLang::Crystal, &func("sub_140002d30", 0x1000, None)),
            RuntimeRole::Unclassified
        );
        let mut runtime_by_path: RecoveredFunction = func("Foo_bar", 0x1000, None);
        runtime_by_path.source_lines = Some(LineRange {
            file: Some("/usr/lib/crystal/src/string.cr".to_owned()),
            lo: 1,
            hi: 9,
        });
        assert_eq!(
            classify_role(NativeLang::Crystal, &runtime_by_path),
            RuntimeRole::LanguageRuntime
        );
    }
}
