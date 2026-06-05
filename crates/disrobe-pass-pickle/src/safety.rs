use serde::{Deserialize, Serialize};

use crate::vm::{GlobalRef, PickleValue, VmTrace};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Benign,
    Suspicious,
    OvertlyMalicious,
}

/// How the verdict for a [`Finding`] was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    SignatureCertain,
    PatternInferred,
    ContextDependent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub confidence: ConfidenceTier,
    pub category: String,
    pub detail: String,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyReport {
    pub severity: Severity,
    pub findings: Vec<Finding>,
    pub imports: Vec<String>,
    pub reduce_count: usize,
    pub unused_memo_count: usize,
}

/// Tunables for [`analyze_with_options`].
#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    pub policy: Policy,
    pub deep: bool,
}

const OVERTLY_MALICIOUS: &[(&str, &str)] = &[
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "spawnl"),
    ("os", "spawnv"),
    ("posix", "system"),
    ("nt", "system"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
    ("__builtin__", "compile"),
    ("__builtin__", "__import__"),
    ("pty", "spawn"),
    ("code", "interact"),
    ("platform", "popen"),
    ("commands", "getoutput"),
    ("commands", "getstatusoutput"),
    ("runpy", "_run_code"),
    ("runpy", "run_path"),
    ("runpy", "run_module"),
];

const SUSPICIOUS_MODULES: &[&str] = &[
    "socket",
    "asyncio",
    "ctypes",
    "importlib",
    "imp",
    "marshal",
    "shutil",
    "tempfile",
    "webbrowser",
    "requests",
    "urllib",
    "urllib2",
    "httplib",
    "ftplib",
    "telnetlib",
    "smtplib",
    "multiprocessing",
    "concurrent",
    "threading",
    "signal",
    "pickle",
    "dill",
    "base64",
    "zlib",
    "bz2",
    "lzma",
    "codecs",
];

const SUSPICIOUS_PAIRS: &[(&str, &str)] = &[
    ("builtins", "getattr"),
    ("builtins", "setattr"),
    ("builtins", "globals"),
    ("builtins", "vars"),
    ("builtins", "open"),
    ("builtins", "input"),
    ("builtins", "memoryview"),
    ("__builtin__", "getattr"),
    ("__builtin__", "setattr"),
    ("__builtin__", "apply"),
    ("__builtin__", "open"),
    ("operator", "attrgetter"),
    ("operator", "methodcaller"),
    ("functools", "partial"),
    ("importlib", "import_module"),
    ("os", "environ"),
    ("os", "getcwd"),
    ("sys", "modules"),
    ("copyreg", "__newobj__"),
];

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub allow_globals: Vec<String>,
    pub deny_globals: Vec<String>,
}

impl Policy {
    #[must_use]
    pub fn classify(&self, module: &str, name: &str) -> Option<Severity> {
        let fqn: String = format!("{module}.{name}");
        if self
            .deny_globals
            .iter()
            .any(|d: &String| d == &fqn || d == module)
        {
            return Some(Severity::OvertlyMalicious);
        }
        if self
            .allow_globals
            .iter()
            .any(|a: &String| a == &fqn || a == module)
        {
            return Some(Severity::Benign);
        }
        None
    }
}

#[must_use]
pub fn analyze(trace: &VmTrace) -> SafetyReport {
    analyze_with_policy(trace, &Policy::default())
}

#[must_use]
pub fn analyze_with_policy(trace: &VmTrace, policy: &Policy) -> SafetyReport {
    analyze_with_options(
        trace,
        &AnalysisOptions {
            policy: policy.clone(),
            deep: false,
        },
    )
}

/// Signature path plus gadget-chain reconstruction.
#[must_use]
pub fn analyze_deep(trace: &VmTrace) -> SafetyReport {
    analyze_with_options(
        trace,
        &AnalysisOptions {
            policy: Policy::default(),
            deep: true,
        },
    )
}

#[must_use]
pub fn analyze_with_options(trace: &VmTrace, opts: &AnalysisOptions) -> SafetyReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut imports: Vec<String> = Vec::new();

    for gref in &trace.global_refs {
        let GlobalRef {
            module,
            name,
            offset,
        }: &GlobalRef = gref;
        imports.push(format!("{module}.{name}"));
        if let Some(sev) = opts.policy.classify(module, name) {
            findings.push(Finding {
                severity: sev,
                confidence: ConfidenceTier::SignatureCertain,
                category: if sev == Severity::OvertlyMalicious {
                    "policy.deny".to_string()
                } else {
                    "policy.allow".to_string()
                },
                detail: format!("policy verdict for {module}.{name}"),
                offset: Some(*offset),
            });
            if sev == Severity::Benign {
                continue;
            }
        }
        classify_global(module, name, *offset, &mut findings);
    }

    imports.sort_unstable();
    imports.dedup();

    let reduce_under_dangerous: bool = trace
        .global_refs
        .iter()
        .any(|g: &GlobalRef| is_overtly_malicious(&g.module, &g.name))
        && trace.reduce_count > 0;
    if reduce_under_dangerous {
        findings.push(Finding {
            severity: Severity::OvertlyMalicious,
            confidence: ConfidenceTier::SignatureCertain,
            category: "reduce.dangerous_callable".to_string(),
            detail: format!(
                "{} REDUCE/INST/OBJ invocations resolve a dangerous callable at unpickle time",
                trace.reduce_count
            ),
            offset: None,
        });
    }

    scan_value(&trace.result, &mut findings);

    if opts.deep {
        gadget_chain_patterns::scan(&trace.result, &mut findings);
    }

    if !trace.unused_memos.is_empty() {
        findings.push(Finding {
            severity: Severity::Suspicious,
            confidence: ConfidenceTier::SignatureCertain,
            category: "memo.unused".to_string(),
            detail: format!(
                "{} memoized object(s) are never referenced - possible dead-stack injection or evasion",
                trace.unused_memos.len()
            ),
            offset: None,
        });
    }

    let severity: Severity = findings
        .iter()
        .map(|f: &Finding| f.severity)
        .max()
        .unwrap_or(Severity::Benign);

    SafetyReport {
        severity,
        findings,
        imports,
        reduce_count: trace.reduce_count,
        unused_memo_count: trace.unused_memos.len(),
    }
}

fn classify_global(module: &str, name: &str, offset: usize, findings: &mut Vec<Finding>) {
    if is_overtly_malicious(module, name) {
        findings.push(Finding {
            severity: Severity::OvertlyMalicious,
            confidence: ConfidenceTier::SignatureCertain,
            category: "global.dangerous_callable".to_string(),
            detail: format!("imports {module}.{name} - code/command execution primitive"),
            offset: Some(offset),
        });
        return;
    }
    if SUSPICIOUS_PAIRS.contains(&(module, name)) {
        findings.push(Finding {
            severity: Severity::Suspicious,
            confidence: ConfidenceTier::SignatureCertain,
            category: "global.suspicious_callable".to_string(),
            detail: format!(
                "imports {module}.{name} - attribute/network/dynamic-dispatch primitive"
            ),
            offset: Some(offset),
        });
        return;
    }
    if SUSPICIOUS_MODULES.contains(&module) {
        findings.push(Finding {
            severity: Severity::Suspicious,
            confidence: ConfidenceTier::SignatureCertain,
            category: "global.suspicious_module".to_string(),
            detail: format!("imports from {module} - networking/serialization/system module"),
            offset: Some(offset),
        });
    }
}

#[inline]
fn is_overtly_malicious(module: &str, name: &str) -> bool {
    OVERTLY_MALICIOUS.contains(&(module, name))
}

fn scan_value(value: &PickleValue, findings: &mut Vec<Finding>) {
    match value {
        PickleValue::Reduce { callable, args } => {
            if let PickleValue::Global { module, name } = callable.as_ref()
                && is_overtly_malicious(module, name)
            {
                findings.push(Finding {
                    severity: Severity::OvertlyMalicious,
                    confidence: ConfidenceTier::SignatureCertain,
                    category: "reduce.payload".to_string(),
                    detail: format!(
                        "{module}.{name}() executed on load with args {}",
                        crate::decompile::to_python(args)
                    ),
                    offset: None,
                });
            }
            scan_value(callable, findings);
            scan_value(args, findings);
        }
        PickleValue::Object { cls, args, state } => {
            scan_value(cls, findings);
            scan_value(args, findings);
            if let Some(s) = state {
                scan_value(s, findings);
            }
        }
        PickleValue::List(items)
        | PickleValue::Tuple(items)
        | PickleValue::Set(items)
        | PickleValue::FrozenSet(items) => {
            for it in items {
                scan_value(it, findings);
            }
        }
        PickleValue::Dict(pairs) => {
            for (k, v) in pairs {
                scan_value(k, findings);
                scan_value(v, findings);
            }
        }
        PickleValue::PersId { id } => scan_value(id, findings),
        _ => {}
    }
}

/// Gadget-chain reconstruction over the resolved symbolic object graph.
pub mod gadget_chain_patterns {
    use super::{ConfidenceTier, Finding, OVERTLY_MALICIOUS, Severity, is_overtly_malicious};
    use crate::vm::PickleValue;

    const GETATTR_LIKE: &[(&str, &str)] = &[("builtins", "getattr"), ("__builtin__", "getattr")];

    const ATTR_WRAPPERS: &[(&str, &str)] = &[
        ("operator", "attrgetter"),
        ("operator", "methodcaller"),
        ("_operator", "attrgetter"),
        ("_operator", "methodcaller"),
    ];

    const PARTIAL_LIKE: &[(&str, &str)] = &[
        ("functools", "partial"),
        ("__builtin__", "apply"),
        ("builtins", "apply"),
    ];

    const IMPORT_LIKE: &[(&str, &str)] = &[
        ("builtins", "__import__"),
        ("__builtin__", "__import__"),
        ("importlib", "import_module"),
    ];

    const EVAL_LIKE: &[(&str, &str)] = &[
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "compile"),
        ("builtins", "__import__"),
        ("__builtin__", "eval"),
        ("__builtin__", "exec"),
        ("__builtin__", "compile"),
        ("__builtin__", "__import__"),
    ];

    /// A callable resolved through any indirection wrappers that hid it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ResolvedCallable {
        /// A `module.name` global reached directly or after unwrapping.
        Named { module: String, name: String },
        /// `getattr(obj, attr)` where `obj` resolved to a global named `base`.
        Attr { base: String, attr: String },
        /// A callable whose identity could not be statically resolved.
        Opaque,
    }

    impl ResolvedCallable {
        fn fqn(&self) -> Option<String> {
            match self {
                Self::Named { module, name } => Some(format!("{module}.{name}")),
                Self::Attr { base, attr } => Some(format!("{base}.{attr}")),
                Self::Opaque => None,
            }
        }
    }

    /// A resolved callable plus whether any indirection wrapper had to be peeled to reach it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Resolution {
        callable: ResolvedCallable,
        via_wrapper: bool,
    }

    impl Resolution {
        fn direct(callable: ResolvedCallable) -> Self {
            Self {
                callable,
                via_wrapper: false,
            }
        }

        fn wrapped(callable: ResolvedCallable) -> Self {
            Self {
                callable,
                via_wrapper: true,
            }
        }

        const OPAQUE: Self = Self {
            callable: ResolvedCallable::Opaque,
            via_wrapper: false,
        };
    }

    /// Walk the whole graph, flagging every invocation whose callable resolves to a dangerous primitive.
    pub(super) fn scan(value: &PickleValue, findings: &mut Vec<Finding>) {
        walk(value, findings, 0);
    }

    fn walk(value: &PickleValue, findings: &mut Vec<Finding>, depth: usize) {
        if depth > 512 {
            return;
        }
        match value {
            PickleValue::Reduce { callable, args } => {
                let resolved: Resolution = resolve_callable(callable, 0);
                emit_invocation(&resolved, args, "reduce", findings);
                walk(callable, findings, depth + 1);
                walk(args, findings, depth + 1);
            }
            PickleValue::Object { cls, args, state } => {
                let resolved: Resolution = resolve_callable(cls, 0);
                emit_invocation(&resolved, args, "construct", findings);
                if let Some(s) = state {
                    emit_setstate(&resolved, s, findings);
                    walk(s, findings, depth + 1);
                }
                walk(cls, findings, depth + 1);
                walk(args, findings, depth + 1);
            }
            PickleValue::List(items)
            | PickleValue::Tuple(items)
            | PickleValue::Set(items)
            | PickleValue::FrozenSet(items) => {
                for it in items {
                    walk(it, findings, depth + 1);
                }
            }
            PickleValue::Dict(pairs) => {
                for (k, v) in pairs {
                    walk(k, findings, depth + 1);
                    walk(v, findings, depth + 1);
                }
            }
            PickleValue::PersId { id } => walk(id, findings, depth + 1),
            _ => {}
        }
    }

    /// Resolve a value in callable position to its underlying callable, peeling indirection wrappers.
    fn resolve_callable(value: &PickleValue, depth: usize) -> Resolution {
        if depth > 64 {
            return Resolution::OPAQUE;
        }
        match value {
            PickleValue::Global { module, name } => Resolution::direct(ResolvedCallable::Named {
                module: module.clone(),
                name: name.clone(),
            }),
            PickleValue::Reduce { callable, args } => {
                resolve_reduce_callable(callable, args, depth)
            }
            PickleValue::Object { cls, .. } => resolve_callable(cls, depth + 1),
            _ => Resolution::OPAQUE,
        }
    }

    /// Decode the common wrapper gadgets when an outer callable is itself an inner `Reduce`.
    fn resolve_reduce_callable(
        inner_callable: &PickleValue,
        inner_args: &PickleValue,
        depth: usize,
    ) -> Resolution {
        let wrapper: Resolution = resolve_callable(inner_callable, depth + 1);
        let Some((wmod, wname)): Option<(String, String)> = named_pair(&wrapper.callable) else {
            return Resolution::OPAQUE;
        };
        let positional: &[PickleValue] = tuple_items(inner_args);

        if GETATTR_LIKE.contains(&(wmod.as_str(), wname.as_str())) {
            return Resolution::wrapped(resolve_getattr(positional, depth));
        }
        if IMPORT_LIKE.contains(&(wmod.as_str(), wname.as_str())) {
            if let Some(PickleValue::Str(module)) = positional.first() {
                return Resolution::wrapped(ResolvedCallable::Named {
                    module: module.clone(),
                    name: String::new(),
                });
            }
            return Resolution::OPAQUE;
        }
        if PARTIAL_LIKE.contains(&(wmod.as_str(), wname.as_str())) {
            if let Some(first) = positional.first() {
                return Resolution::wrapped(resolve_callable(first, depth + 1).callable);
            }
            return Resolution::OPAQUE;
        }
        if ATTR_WRAPPERS.contains(&(wmod.as_str(), wname.as_str())) {
            if let Some(PickleValue::Str(attr)) = positional.first() {
                return Resolution::wrapped(ResolvedCallable::Attr {
                    base: "<attrgetter>".to_string(),
                    attr: attr.clone(),
                });
            }
            return Resolution::OPAQUE;
        }
        Resolution::OPAQUE
    }

    /// `getattr(obj, "attr")` where `obj` is itself a resolved callable/global.
    fn resolve_getattr(positional: &[PickleValue], depth: usize) -> ResolvedCallable {
        let (Some(obj), Some(PickleValue::Str(attr))): (
            Option<&PickleValue>,
            Option<&PickleValue>,
        ) = (positional.first(), positional.get(1)) else {
            return ResolvedCallable::Opaque;
        };
        match resolve_callable(obj, depth + 1).callable {
            ResolvedCallable::Named { module, name } if name.is_empty() => {
                ResolvedCallable::Named {
                    module,
                    name: attr.clone(),
                }
            }
            ResolvedCallable::Named { module, name } => ResolvedCallable::Attr {
                base: format!("{module}.{name}"),
                attr: attr.clone(),
            },
            ResolvedCallable::Attr { base, attr: inner } => ResolvedCallable::Attr {
                base: format!("{base}.{inner}"),
                attr: attr.clone(),
            },
            ResolvedCallable::Opaque => ResolvedCallable::Opaque,
        }
    }

    fn emit_invocation(
        resolved: &Resolution,
        args: &PickleValue,
        site: &str,
        findings: &mut Vec<Finding>,
    ) {
        let Some((severity, tier, reason)): Option<(Severity, ConfidenceTier, &'static str)> =
            classify_resolved(resolved)
        else {
            return;
        };
        let Some(fqn): Option<String> = resolved.callable.fqn() else {
            return;
        };
        findings.push(Finding {
            severity,
            confidence: tier,
            category: format!("gadget.{site}_chain"),
            detail: format!(
                "{fqn}(...) reached via gadget chain ({reason}); args {}",
                crate::decompile::to_python(args)
            ),
            offset: None,
        });
    }

    /// Flag an `Object` carrying state whose class resolves to a dangerous callable (BUILD trigger).
    fn emit_setstate(cls: &Resolution, state: &PickleValue, findings: &mut Vec<Finding>) {
        if let Some((severity, tier, _)) = classify_resolved(cls)
            && let Some(fqn) = cls.callable.fqn()
        {
            findings.push(Finding {
                severity,
                confidence: tier,
                category: "gadget.setstate_trigger".to_string(),
                detail: format!(
                    "{fqn}.__setstate__/__dict__.update runs on load with state {}",
                    crate::decompile::to_python(state)
                ),
                offset: None,
            });
        }
    }

    /// Map a resolved callable to a severity and confidence tier.
    fn classify_resolved(
        resolved: &Resolution,
    ) -> Option<(Severity, ConfidenceTier, &'static str)> {
        let (module, name): (&str, &str) = match &resolved.callable {
            ResolvedCallable::Named { module, name } => (module.as_str(), name.as_str()),
            ResolvedCallable::Attr { base, attr } => (base.as_str(), attr.as_str()),
            ResolvedCallable::Opaque => return None,
        };

        if is_overtly_malicious(module, name) {
            let direct: bool = !resolved.via_wrapper
                && matches!(resolved.callable, ResolvedCallable::Named { .. })
                && OVERTLY_MALICIOUS.contains(&(module, name));
            let tier: ConfidenceTier = if direct {
                ConfidenceTier::SignatureCertain
            } else {
                ConfidenceTier::PatternInferred
            };
            return Some((Severity::OvertlyMalicious, tier, "execution primitive"));
        }
        if EVAL_LIKE.contains(&(module, name)) {
            let tier: ConfidenceTier = if resolved.via_wrapper {
                ConfidenceTier::PatternInferred
            } else {
                ConfidenceTier::SignatureCertain
            };
            return Some((Severity::OvertlyMalicious, tier, "dynamic eval/exec/import"));
        }
        if let ResolvedCallable::Attr { base, attr } = &resolved.callable
            && attr_resolves_to_danger(base, attr)
        {
            return Some((
                Severity::OvertlyMalicious,
                ConfidenceTier::PatternInferred,
                "attribute chain to execution primitive",
            ));
        }
        None
    }

    /// Check a reconstructed `module.name` from a `getattr` base/attr pair against the danger list.
    fn attr_resolves_to_danger(base: &str, attr: &str) -> bool {
        if is_overtly_malicious(base, attr) {
            return true;
        }
        if let Some((module, name)) = base.rsplit_once('.')
            && is_overtly_malicious(module, name)
        {
            return true;
        }
        OVERTLY_MALICIOUS
            .iter()
            .any(|(m, n): &(&str, &str)| *m == base && *n == attr)
    }

    fn named_pair(resolved: &ResolvedCallable) -> Option<(String, String)> {
        match resolved {
            ResolvedCallable::Named { module, name } => Some((module.clone(), name.clone())),
            _ => None,
        }
    }

    fn tuple_items(value: &PickleValue) -> &[PickleValue] {
        match value {
            PickleValue::Tuple(items) | PickleValue::List(items) => items,
            _ => std::slice::from_ref(value),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::disasm::disassemble;
    use crate::vm::execute;

    fn report(bytes: &[u8]) -> SafetyReport {
        analyze(&execute(&disassemble(bytes).expect("disasm")).expect("vm"))
    }

    fn deep_report(bytes: &[u8]) -> SafetyReport {
        analyze_deep(&execute(&disassemble(bytes).expect("disasm")).expect("vm"))
    }

    /// `SHORT_BINUNICODE`: `\x8c <len> <bytes>`.
    fn su(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0x8c, s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    /// `GLOBAL module \n name \n` via the proto-0 `c` opcode (`0x63`).
    fn global(module: &str, name: &str) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0x63];
        v.extend_from_slice(module.as_bytes());
        v.push(b'\n');
        v.extend_from_slice(name.as_bytes());
        v.push(b'\n');
        v
    }

    #[test]
    fn benign_int_is_benign() {
        assert_eq!(report(b"\x80\x02K\x01.").severity, Severity::Benign);
    }

    #[test]
    fn os_system_reduce_is_malicious() {
        let bytes: &[u8] = b"\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x94\x8c\x02id\x85\x94R\x94.";
        let r: SafetyReport = report(bytes);
        assert_eq!(r.severity, Severity::OvertlyMalicious);
        assert!(r.findings.iter().any(|f| f.category == "reduce.payload"));
    }

    #[test]
    fn deny_policy_flags() {
        let trace: VmTrace = execute(
            &disassemble(
                b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x06pandas\x8c\x04read\x93\x94.",
            )
            .unwrap(),
        )
        .unwrap();
        let pol: Policy = Policy {
            allow_globals: vec![],
            deny_globals: vec!["pandas".to_string()],
        };
        assert_eq!(
            analyze_with_policy(&trace, &pol).severity,
            Severity::OvertlyMalicious
        );
    }

    /// Direct `os.system("id")` REDUCE stays `SignatureCertain` on both paths.
    #[test]
    fn deep_keeps_direct_signature_tier() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02];
        bytes.extend(global("os", "system"));
        bytes.extend(su("id"));
        bytes.push(0x85);
        bytes.push(0x52);
        bytes.push(b'.');
        let r: SafetyReport = deep_report(&bytes);
        assert_eq!(r.severity, Severity::OvertlyMalicious);
        assert!(
            r.findings
                .iter()
                .any(|f| f.confidence == ConfidenceTier::SignatureCertain
                    && f.severity == Severity::OvertlyMalicious)
        );
    }

    /// Indirect `functools.partial(os.system, "id")()`: only the deep path reconstructs the chain.
    #[test]
    fn deep_catches_partial_wrapped_os_system() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02];
        bytes.extend(global("functools", "partial"));
        bytes.extend(global("os", "system"));
        bytes.extend(su("id"));
        bytes.push(0x86);
        bytes.push(0x52);
        bytes.push(0x29);
        bytes.push(0x52);
        bytes.push(b'.');
        let deep: SafetyReport = deep_report(&bytes);
        assert_eq!(deep.severity, Severity::OvertlyMalicious);
        assert!(
            deep.findings
                .iter()
                .any(|f| f.category.starts_with("gadget.")
                    && f.confidence == ConfidenceTier::PatternInferred),
            "deep must reconstruct partial-wrapped os.system, got {:?}",
            deep.findings
        );
    }

    /// `getattr(__import__("os"), "system")("id")`: evasion chain never naming `os.system` directly.
    #[test]
    fn deep_catches_getattr_import_chain() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02];
        bytes.extend(global("builtins", "getattr"));
        bytes.extend(global("builtins", "__import__"));
        bytes.extend(su("os"));
        bytes.push(0x85);
        bytes.push(0x52);
        bytes.extend(su("system"));
        bytes.push(0x86);
        bytes.push(0x52);
        bytes.extend(su("id"));
        bytes.push(0x85);
        bytes.push(0x52);
        bytes.push(b'.');
        let deep: SafetyReport = deep_report(&bytes);
        assert_eq!(deep.severity, Severity::OvertlyMalicious);
        assert!(
            deep.findings.iter().any(|f| f.detail.contains("os.system")
                && f.confidence == ConfidenceTier::PatternInferred),
            "deep must resolve getattr(__import__(os), system), got {:?}",
            deep.findings
        );
    }

    /// `builtins.eval("...")` reached as an invocation, not just an import.
    #[test]
    fn deep_flags_eval_invocation() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02];
        bytes.extend(global("builtins", "eval"));
        bytes.extend(su("__import__('os').system('id')"));
        bytes.push(0x85);
        bytes.push(0x52);
        bytes.push(b'.');
        let deep: SafetyReport = deep_report(&bytes);
        assert_eq!(deep.severity, Severity::OvertlyMalicious);
        assert!(
            deep.findings
                .iter()
                .any(|f| f.category.starts_with("gadget.") && f.detail.contains("eval"))
        );
    }

    /// A benign object graph produces no gadget findings under the deep path.
    #[test]
    fn deep_no_false_positive_on_benign_list() {
        let r: SafetyReport = deep_report(b"\x80\x02](K\x01K\x02e.");
        assert_ne!(r.severity, Severity::OvertlyMalicious);
        assert!(!r.findings.iter().any(|f| f.category.starts_with("gadget.")));
    }

    /// Constructing a stdlib data class via NEWOBJ with no dangerous callable is not flagged.
    #[test]
    fn deep_no_false_positive_on_benign_newobj() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02];
        bytes.extend(global("collections", "OrderedDict"));
        bytes.push(0x29);
        bytes.push(0x81);
        bytes.push(b'.');
        let r: SafetyReport = deep_report(&bytes);
        assert!(
            !r.findings
                .iter()
                .any(|f| f.category.starts_with("gadget.")
                    && f.severity == Severity::OvertlyMalicious),
            "benign NEWOBJ must not raise a gadget finding, got {:?}",
            r.findings
        );
    }

    /// BUILD trigger: an Object whose class is a dangerous callable and which carries state.
    #[test]
    fn deep_catches_setstate_build_trigger() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02];
        bytes.extend(global("os", "system"));
        bytes.push(0x29);
        bytes.push(0x81);
        bytes.extend(su("payload"));
        bytes.push(0x62);
        bytes.push(b'.');
        let deep: SafetyReport = deep_report(&bytes);
        assert_eq!(deep.severity, Severity::OvertlyMalicious);
        assert!(
            deep.findings
                .iter()
                .any(|f| f.category == "gadget.setstate_trigger"
                    || f.category == "gadget.construct_chain"),
            "BUILD/setstate gadget must be flagged, got {:?}",
            deep.findings
        );
    }
}
