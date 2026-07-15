use std::collections::BTreeMap;

use super::model::{BccLinkMap, BodyStatus};
use super::residual::{NodeKind, ResidualModule, ResidualNode};

pub(crate) fn render(residual: &ResidualModule, map: &BccLinkMap) -> String {
    let statuses: BTreeMap<&str, BodyStatus> = map
        .records
        .iter()
        .map(|record| (record.source.qualname.as_str(), record.body_status))
        .collect();

    let mut out: String = String::new();
    push_header(&mut out, map);
    for child in &residual.root.children {
        render_node(child, 0, &statuses, &mut out);
    }
    out
}

fn push_header(out: &mut String, map: &BccLinkMap) {
    let module: &str = map.module.as_deref().unwrap_or("<unknown>");
    let path: &str = map.py_path.as_deref().unwrap_or("<unknown>");
    out.push_str("\"\"\"disrobe BCC skeleton for module ");
    out.push_str(module);
    out.push_str(" (source ");
    out.push_str(path);
    out.push_str(").\n");
    out.push_str(
        "native_wall bodies are BCC-compiled native functions listed in the function map; bytecode_retained bodies stay standard Python bytecode.\n",
    );
    out.push_str("Parameter names are placeholders where the residual stripped them; arity is exact.\"\"\"\n\n");
}

fn render_node(
    node: &ResidualNode,
    depth: usize,
    statuses: &BTreeMap<&str, BodyStatus>,
    out: &mut String,
) {
    match &node.kind {
        NodeKind::Module | NodeKind::Internal => {
            for child in &node.children {
                render_node(child, depth, statuses, out);
            }
        }
        NodeKind::Class => render_class(node, depth, statuses, out),
        NodeKind::Function {
            kind, signature, ..
        } => {
            let indent: String = "    ".repeat(depth);
            let status: BodyStatus = statuses
                .get(node.qualname.as_str())
                .copied()
                .unwrap_or(BodyStatus::BytecodeRetained);
            let marker: &str = match status {
                BodyStatus::NativeWall => "native_wall",
                BodyStatus::BytecodeRetained => "bytecode_retained",
            };
            out.push_str(&indent);
            out.push('@');
            out.push_str(marker);
            out.push('\n');
            out.push_str(&indent);
            out.push_str(kind.keyword());
            out.push(' ');
            out.push_str(&node.name);
            out.push_str(&signature.rendered);
            out.push_str(":\n");
            out.push_str(&indent);
            out.push_str("    ...\n\n");
        }
    }
}

fn render_class(
    node: &ResidualNode,
    depth: usize,
    statuses: &BTreeMap<&str, BodyStatus>,
    out: &mut String,
) {
    let indent: String = "    ".repeat(depth);
    out.push_str(&indent);
    out.push_str("class ");
    out.push_str(&node.name);
    out.push_str(":\n");
    if node.children.is_empty() {
        out.push_str(&indent);
        out.push_str("    ...\n\n");
        return;
    }
    for child in &node.children {
        render_node(child, depth + 1, statuses, out);
    }
    out.push('\n');
}
