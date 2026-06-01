use serde::{Deserialize, Serialize};

use crate::vm::{GlobalRef, PickleValue, VmTrace};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Benign,
    Suspicious,
    OvertlyMalicious,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
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
    let mut findings: Vec<Finding> = Vec::new();
    let mut imports: Vec<String> = Vec::new();

    for gref in &trace.global_refs {
        let GlobalRef {
            module,
            name,
            offset,
        } = gref;
        imports.push(format!("{module}.{name}"));
        if let Some(sev) = policy.classify(module, name) {
            findings.push(Finding {
                severity: sev,
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
            category: "reduce.dangerous_callable".to_string(),
            detail: format!(
                "{} REDUCE/INST/OBJ invocations resolve a dangerous callable at unpickle time",
                trace.reduce_count
            ),
            offset: None,
        });
    }

    scan_value(&trace.result, &mut findings);

    if !trace.unused_memos.is_empty() {
        findings.push(Finding {
            severity: Severity::Suspicious,
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
            category: "global.dangerous_callable".to_string(),
            detail: format!("imports {module}.{name} - code/command execution primitive"),
            offset: Some(offset),
        });
        return;
    }
    if SUSPICIOUS_PAIRS.contains(&(module, name)) {
        findings.push(Finding {
            severity: Severity::Suspicious,
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::disasm::disassemble;
    use crate::vm::execute;

    fn report(bytes: &[u8]) -> SafetyReport {
        analyze(&execute(&disassemble(bytes).expect("disasm")).expect("vm"))
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
        let trace = execute(
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
}
