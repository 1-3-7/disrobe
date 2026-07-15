use super::dispatch::DispatchEntry;
use super::model::{
    BccLinkMap, BodyStatus, EvidenceSource, FunctionKind, FunctionRecord, LinkConfidence,
    LinkSummary, NameStatus, NativeRef, Signature, SourceIdentity,
};
use super::residual::{NodeKind, ResidualModule, ResidualNode};
use super::stub::StubInfo;
use crate::v8v9::BccArch;

struct FunctionNode {
    qualname: String,
    firstlineno: i32,
    kind: FunctionKind,
    class: Option<String>,
    signature: Signature,
}

pub(crate) fn link(
    residual: &ResidualModule,
    dispatch: &[DispatchEntry],
    stub: &StubInfo,
    python_version: String,
) -> BccLinkMap {
    let module: Option<String> = residual.module_name.clone().or_else(|| stub.module.clone());
    let py_path: Option<String> = stub
        .py_path
        .clone()
        .or_else(|| residual.py_path_hint.clone())
        .or_else(|| module.as_deref().map(module_to_path));
    let module_cross_validated: bool =
        match (residual.module_name.as_deref(), stub.module.as_deref()) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        };

    let mut functions: Vec<FunctionNode> = Vec::new();
    collect_functions(&residual.root, &mut functions);
    functions.sort_by(|a: &FunctionNode, b: &FunctionNode| {
        a.firstlineno
            .cmp(&b.firstlineno)
            .then_with(|| a.qualname.cmp(&b.qualname))
    });

    let bindings: Vec<Option<usize>> = assign_dispatch(&functions, dispatch);
    let mut function_bound: Vec<Option<usize>> = vec![None; functions.len()];
    for (dispatch_idx, bound) in bindings.iter().enumerate() {
        if let Some(fn_idx) = *bound
            && function_bound[fn_idx].is_none()
        {
            function_bound[fn_idx] = Some(dispatch_idx);
        }
    }

    let mut records: Vec<FunctionRecord> = Vec::with_capacity(functions.len());
    for (fn_idx, node) in functions.iter().enumerate() {
        let native: Option<NativeRef> = function_bound[fn_idx]
            .and_then(|d: usize| dispatch.get(d))
            .map(native_ref);
        records.push(build_record(
            node,
            native,
            module.as_deref(),
            py_path.as_deref(),
            module_cross_validated,
            stub,
        ));
    }

    for (dispatch_idx, entry) in dispatch.iter().enumerate() {
        let already: bool = bindings.get(dispatch_idx).copied().flatten().is_some();
        if already {
            continue;
        }
        records.push(unlinked_native_record(
            entry,
            module.as_deref(),
            py_path.as_deref(),
        ));
    }

    let summary: LinkSummary = summarize(&records, dispatch.len());
    let notes: Vec<String> = build_notes(&records, &functions, module_cross_validated);

    BccLinkMap {
        module,
        py_path,
        python_version,
        records,
        summary,
        notes,
    }
}

fn collect_functions(node: &ResidualNode, out: &mut Vec<FunctionNode>) {
    if let NodeKind::Function {
        kind,
        class,
        signature,
    } = &node.kind
    {
        out.push(FunctionNode {
            qualname: node.qualname.clone(),
            firstlineno: node.firstlineno,
            kind: *kind,
            class: class.clone(),
            signature: signature.clone(),
        });
    }
    for child in &node.children {
        collect_functions(child, out);
    }
}

fn assign_dispatch(functions: &[FunctionNode], dispatch: &[DispatchEntry]) -> Vec<Option<usize>> {
    let mut ordered: Vec<usize> = (0..functions.len()).collect();
    ordered.sort_by_key(|i: &usize| functions[*i].firstlineno);

    let any_line: bool = dispatch
        .iter()
        .any(|entry: &DispatchEntry| entry.dispatch_line.is_some());
    let mut result: Vec<Option<usize>> = vec![None; dispatch.len()];

    if any_line {
        for (d, entry) in dispatch.iter().enumerate() {
            let Some(line): Option<i32> = entry.dispatch_line else {
                continue;
            };
            let mut chosen: Option<usize> = None;
            for i in &ordered {
                if functions[*i].firstlineno <= line {
                    chosen = Some(*i);
                } else {
                    break;
                }
            }
            result[d] = chosen;
        }
        return result;
    }

    if dispatch.len() == functions.len() {
        let mut dispatch_order: Vec<usize> = (0..dispatch.len()).collect();
        dispatch_order.sort_by_key(|d: &usize| dispatch[*d].code_offset);
        for (rank, d) in dispatch_order.iter().enumerate() {
            result[*d] = ordered.get(rank).copied();
        }
    }
    result
}

fn native_ref(entry: &DispatchEntry) -> NativeRef {
    NativeRef {
        offset: entry.code_offset,
        size: entry.size,
        arch: arch_label(entry.arch).to_owned(),
        container: format!(
            "bcc-image[{}] {}",
            entry.container_index,
            arch_label(entry.arch)
        ),
        dispatch_name: Some(entry.name.clone()),
    }
}

fn build_record(
    node: &FunctionNode,
    native: Option<NativeRef>,
    module: Option<&str>,
    py_path: Option<&str>,
    module_cross_validated: bool,
    stub: &StubInfo,
) -> FunctionRecord {
    let mut evidence: Vec<EvidenceSource> = vec![EvidenceSource::ResidualCodeObject];
    if native.is_some() {
        evidence.push(EvidenceSource::DispatchTable);
        if native
            .as_ref()
            .and_then(|n: &NativeRef| n.dispatch_name.as_ref())
            .is_some_and(|name: &String| name.starts_with("bcc"))
        {
            evidence.push(EvidenceSource::NativeNameTable);
        }
    }
    if stub.has_pyarmor_call || stub.has_assert_armored {
        evidence.push(EvidenceSource::WrapperStub);
    }
    if module_cross_validated {
        evidence.push(EvidenceSource::PackageLayout);
    }

    let body_status: BodyStatus = if native.is_some() {
        BodyStatus::NativeWall
    } else {
        BodyStatus::BytecodeRetained
    };
    let confidence: LinkConfidence = if evidence.len() >= 2 {
        LinkConfidence::Confirmed
    } else {
        LinkConfidence::Probable
    };
    let name: &str = node
        .qualname
        .rsplit('.')
        .next()
        .unwrap_or(node.qualname.as_str());
    let name_status: NameStatus = if name.is_empty() || name.starts_with('<') && name != "<lambda>"
    {
        NameStatus::Stripped
    } else {
        NameStatus::Recovered
    };

    FunctionRecord {
        native,
        source: SourceIdentity {
            py_path: py_path.map(str::to_owned),
            module: module.map(str::to_owned),
            qualname: node.qualname.clone(),
            class: node.class.clone(),
            kind: node.kind,
            firstlineno: node.firstlineno,
        },
        signature: node.signature.clone(),
        body_status,
        confidence,
        name_status,
        evidence,
    }
}

fn unlinked_native_record(
    entry: &DispatchEntry,
    module: Option<&str>,
    py_path: Option<&str>,
) -> FunctionRecord {
    let qualname: String = format!("<native@{:#x}>", entry.code_offset);
    FunctionRecord {
        native: Some(native_ref(entry)),
        source: SourceIdentity {
            py_path: py_path.map(str::to_owned),
            module: module.map(str::to_owned),
            qualname,
            class: None,
            kind: FunctionKind::Function,
            firstlineno: entry.dispatch_line.unwrap_or(0),
        },
        signature: Signature {
            argcount: 0,
            posonlyargcount: 0,
            kwonlyargcount: 0,
            has_varargs: false,
            has_varkeywords: false,
            is_async: false,
            is_generator: false,
            param_names_recovered: false,
            parameters: Vec::new(),
            rendered: "(...)".to_owned(),
        },
        body_status: BodyStatus::NativeWall,
        confidence: LinkConfidence::Synthetic,
        name_status: NameStatus::Stripped,
        evidence: vec![
            EvidenceSource::DispatchTable,
            EvidenceSource::NativeNameTable,
        ],
    }
}

fn summarize(records: &[FunctionRecord], dispatch_len: usize) -> LinkSummary {
    let mut summary: LinkSummary = LinkSummary {
        total_functions: records.len(),
        dispatch_entries: dispatch_len,
        ..LinkSummary::default()
    };
    for record in records {
        if record.native.is_some() {
            summary.native_functions += 1;
        }
        if matches!(record.body_status, BodyStatus::BytecodeRetained) {
            summary.bytecode_retained += 1;
        }
        match record.confidence {
            LinkConfidence::Confirmed => summary.confirmed += 1,
            LinkConfidence::Probable => summary.probable += 1,
            LinkConfidence::Synthetic => summary.synthetic += 1,
        }
    }
    summary.unlinked_dispatch_entries = records
        .iter()
        .filter(|record: &&FunctionRecord| {
            record.native.is_some() && matches!(record.confidence, LinkConfidence::Synthetic)
        })
        .count();
    summary
}

fn build_notes(
    records: &[FunctionRecord],
    functions: &[FunctionNode],
    module_cross_validated: bool,
) -> Vec<String> {
    let mut notes: Vec<String> = Vec::new();
    let native: usize = records
        .iter()
        .filter(|r: &&FunctionRecord| r.native.is_some())
        .count();
    let retained: usize = records
        .iter()
        .filter(|r: &&FunctionRecord| matches!(r.body_status, BodyStatus::BytecodeRetained))
        .count();
    notes.push(format!(
        "{native} function(s) linked to BCC-compiled native code; {retained} function(s) kept as bytecode and stay decompilable by the standard pass"
    ));
    let param_stripped: bool = functions.iter().any(|node: &FunctionNode| {
        !node.signature.param_names_recovered && node.signature.argcount > 0
    });
    if param_stripped {
        notes.push(
            "parameter names are stripped from the BCC residual; arity and parameter kinds are exact, parameter names are placeholders".to_owned(),
        );
    }
    if !module_cross_validated {
        notes.push(
            "module identity rests on a single source; residual filename and wrapper layout did not both resolve".to_owned(),
        );
    }
    notes.push(
        "native bodies are marked as a native wall; body recovery is the separate Mir-tier layer"
            .to_owned(),
    );
    notes
}

const fn arch_label(arch: BccArch) -> &'static str {
    match arch {
        BccArch::WinX64 => "win-x64",
        BccArch::LinuxX64 => "linux-x64",
        BccArch::DarwinArm64 => "darwin-arm64",
        BccArch::Other(_) => "other",
    }
}

fn module_to_path(module: &str) -> String {
    format!("{}.py", module.replace('.', "/"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn empty_signature() -> Signature {
        Signature {
            argcount: 0,
            posonlyargcount: 0,
            kwonlyargcount: 0,
            has_varargs: false,
            has_varkeywords: false,
            is_async: false,
            is_generator: false,
            param_names_recovered: false,
            parameters: Vec::new(),
            rendered: "()".to_owned(),
        }
    }

    fn node(qual: &str, line: i32) -> FunctionNode {
        FunctionNode {
            qualname: qual.to_owned(),
            firstlineno: line,
            kind: FunctionKind::Function,
            class: None,
            signature: empty_signature(),
        }
    }

    fn entry(line: i32, offset: u64) -> DispatchEntry {
        DispatchEntry {
            name: format!("bcc_{line}"),
            dispatch_line: Some(line),
            code_offset: offset,
            size: 0x10,
            arch: BccArch::WinX64,
            container_index: 0,
        }
    }

    #[test]
    fn decorator_offset_binds_to_containing_function() {
        let functions: Vec<FunctionNode> = vec![
            node("add", 4),
            node("area", 22),
            node("make", 25),
            node("deep", 30),
        ];
        let dispatch: Vec<DispatchEntry> =
            vec![entry(4, 0x100), entry(22, 0x200), entry(26, 0x300)];
        let bindings: Vec<Option<usize>> = assign_dispatch(&functions, &dispatch);
        assert_eq!(bindings[0], Some(0));
        assert_eq!(bindings[1], Some(1));
        assert_eq!(bindings[2], Some(2), "def-line 26 binds to make at 25");
    }

    #[test]
    fn line_below_all_functions_is_unbound() {
        let functions: Vec<FunctionNode> = vec![node("a", 10), node("b", 20)];
        let dispatch: Vec<DispatchEntry> = vec![entry(5, 0x100)];
        let bindings: Vec<Option<usize>> = assign_dispatch(&functions, &dispatch);
        assert_eq!(bindings[0], None);
    }

    #[test]
    fn positional_fallback_when_no_lines() {
        let functions: Vec<FunctionNode> = vec![node("a", 10), node("b", 20)];
        let mut dispatch: Vec<DispatchEntry> = vec![entry(0, 0x300), entry(0, 0x100)];
        for item in &mut dispatch {
            item.dispatch_line = None;
            item.name = "sub".to_owned();
        }
        let bindings: Vec<Option<usize>> = assign_dispatch(&functions, &dispatch);
        assert_eq!(bindings[1], Some(0), "lowest offset binds first function");
        assert_eq!(bindings[0], Some(1));
    }
}
