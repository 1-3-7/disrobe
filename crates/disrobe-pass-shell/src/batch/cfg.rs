use std::collections::BTreeMap;
use std::sync::LazyLock;

use disrobe_ir::{DisasmSymbol, DisasmSymbolKind};
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum EdgeKind {
    FallThrough,
    Goto,
    ConditionalGoto,
    Call,
    CallReturn,
    ExitProcedure,
    ExitScript,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgEdge {
    pub kind: EdgeKind,
    pub target_label: Option<String>,
    pub target_block: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BasicBlock {
    pub index: usize,
    pub label: Option<String>,
    pub start_line: usize,
    pub statements: Vec<String>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchCfg {
    pub blocks: Vec<BasicBlock>,
    pub labels: BTreeMap<String, usize>,
    pub call_targets: Vec<String>,
    pub goto_targets: Vec<String>,
    pub unresolved_targets: Vec<String>,
}

#[derive(Debug, Clone)]
struct Statement {
    line: usize,
    text: String,
    label: Option<String>,
    transfers: Vec<Transfer>,
}

#[derive(Debug, Clone)]
struct Transfer {
    kind: EdgeKind,
    target: Option<String>,
}

static LABEL_DEF: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"^\s*:([A-Za-z_][A-Za-z0-9_\.]*)\s*$"));

static GOTO: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"(?i)\bgoto\s+:?([A-Za-z_%][A-Za-z0-9_\.%]*|:eof)")
});

static CALL_LABEL: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)\bcall\s+:([A-Za-z_%][A-Za-z0-9_\.%]*)"));

static EXIT_B: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)\bexit\s*/b\b"));

static EXIT_SCRIPT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)\bexit\b(?!\s*/b)"));

static IF_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)^\s*if\b"));

fn normalise_target(raw: &str) -> Option<String> {
    let trimmed: &str = raw.trim().trim_start_matches(':');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

fn parse_statement(line: usize, text: &str) -> Statement {
    let trimmed: &str = text.trim();
    if let Some(cap) = LABEL_DEF.captures(trimmed) {
        let label: Option<String> = cap
            .get(1)
            .map(|m: regex::Match<'_>| m.as_str().to_ascii_uppercase());
        return Statement {
            line,
            text: text.to_owned(),
            label,
            transfers: Vec::new(),
        };
    }
    let mut transfers: Vec<Transfer> = Vec::new();
    let conditional: bool = IF_PREFIX.is_match(trimmed);
    for cap in CALL_LABEL.captures_iter(trimmed) {
        let target: Option<String> = cap
            .get(1)
            .and_then(|m: regex::Match<'_>| normalise_target(m.as_str()));
        transfers.push(Transfer {
            kind: EdgeKind::Call,
            target,
        });
    }
    for cap in GOTO.captures_iter(trimmed) {
        let raw: &str = cap
            .get(1)
            .map(|m: regex::Match<'_>| m.as_str())
            .unwrap_or("");
        let target: Option<String> =
            if raw.eq_ignore_ascii_case(":eof") || raw.eq_ignore_ascii_case("eof") {
                None
            } else {
                normalise_target(raw)
            };
        let kind: EdgeKind = if raw.eq_ignore_ascii_case(":eof") || raw.eq_ignore_ascii_case("eof")
        {
            EdgeKind::ExitProcedure
        } else if conditional {
            EdgeKind::ConditionalGoto
        } else {
            EdgeKind::Goto
        };
        transfers.push(Transfer { kind, target });
    }
    if EXIT_B.is_match(trimmed) {
        transfers.push(Transfer {
            kind: EdgeKind::ExitProcedure,
            target: None,
        });
    } else if EXIT_SCRIPT.is_match(trimmed) {
        transfers.push(Transfer {
            kind: EdgeKind::ExitScript,
            target: None,
        });
    }
    Statement {
        line,
        text: text.to_owned(),
        label: None,
        transfers,
    }
}

#[must_use]
fn is_terminator(kind: &EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Goto | EdgeKind::ExitProcedure | EdgeKind::ExitScript
    )
}

#[must_use]
pub fn resolve_cfg(input: &str) -> BatchCfg {
    let statements: Vec<Statement> = input
        .lines()
        .enumerate()
        .filter_map(|(i, raw): (usize, &str)| {
            let trimmed: &str = raw.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("::")
                || trimmed.eq_ignore_ascii_case("rem")
            {
                return None;
            }
            Some(parse_statement(i, raw))
        })
        .collect();

    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut labels: BTreeMap<String, usize> = BTreeMap::new();
    let mut current: Option<BasicBlock> = None;

    for stmt in &statements {
        if let Some(ref label) = stmt.label {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            let index: usize = blocks.len();
            labels.entry(label.clone()).or_insert(index);
            current = Some(BasicBlock {
                index,
                label: Some(label.clone()),
                start_line: stmt.line,
                statements: Vec::new(),
                edges: Vec::new(),
            });
            continue;
        }
        let block: &mut BasicBlock = current.get_or_insert_with(|| BasicBlock {
            index: blocks.len(),
            label: None,
            start_line: stmt.line,
            statements: Vec::new(),
            edges: Vec::new(),
        });
        block.statements.push(stmt.text.trim().to_owned());
        let mut ends_block: bool = false;
        for transfer in &stmt.transfers {
            block.edges.push(CfgEdge {
                kind: transfer.kind.clone(),
                target_label: transfer.target.clone(),
                target_block: None,
            });
            if transfer.kind == EdgeKind::Call {
                block.edges.push(CfgEdge {
                    kind: EdgeKind::CallReturn,
                    target_label: None,
                    target_block: None,
                });
            }
            if is_terminator(&transfer.kind) {
                ends_block = true;
            }
        }
        if ends_block && let Some(finished) = current.take() {
            blocks.push(finished);
        }
    }
    if let Some(block) = current.take() {
        blocks.push(block);
    }

    resolve_edges(&mut blocks, &labels);

    let mut call_targets: Vec<String> = Vec::new();
    let mut goto_targets: Vec<String> = Vec::new();
    let mut unresolved_targets: Vec<String> = Vec::new();
    for block in &blocks {
        for edge in &block.edges {
            let Some(ref target) = edge.target_label else {
                continue;
            };
            match edge.kind {
                EdgeKind::Call => push_unique(&mut call_targets, target),
                EdgeKind::Goto | EdgeKind::ConditionalGoto => {
                    push_unique(&mut goto_targets, target);
                }
                _ => {}
            }
            if edge.target_block.is_none() && !labels.contains_key(target) {
                push_unique(&mut unresolved_targets, target);
            }
        }
    }

    BatchCfg {
        blocks,
        labels,
        call_targets,
        goto_targets,
        unresolved_targets,
    }
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|v: &String| v == value) {
        list.push(value.to_owned());
    }
}

fn resolve_edges(blocks: &mut [BasicBlock], labels: &BTreeMap<String, usize>) {
    let block_count: usize = blocks.len();
    for (i, block) in blocks.iter_mut().enumerate() {
        let next_block: Option<usize> = (i + 1 < block_count).then_some(i + 1);
        let mut needs_fallthrough: bool = true;
        for edge in &mut block.edges {
            if let Some(target) = edge.target_label.clone() {
                edge.target_block = labels.get(&target).copied();
                if edge.target_block.is_none()
                    && matches!(
                        edge.kind,
                        EdgeKind::Goto | EdgeKind::ConditionalGoto | EdgeKind::Call
                    )
                {
                    edge.kind = EdgeKind::Unresolved;
                }
            }
            if edge.kind == EdgeKind::CallReturn {
                edge.target_block = next_block;
            }
            if matches!(
                edge.kind,
                EdgeKind::Goto | EdgeKind::ExitProcedure | EdgeKind::ExitScript
            ) {
                needs_fallthrough = false;
            }
        }
        if needs_fallthrough && let Some(next) = next_block {
            block.edges.push(CfgEdge {
                kind: EdgeKind::FallThrough,
                target_label: None,
                target_block: Some(next),
            });
        }
    }
}

impl BatchCfg {
    #[must_use]
    pub fn to_ir_symbols(&self) -> Vec<DisasmSymbol> {
        let mut symbols: Vec<DisasmSymbol> = Vec::with_capacity(self.labels.len());
        for (name, block_index) in &self.labels {
            let is_callable: bool = self.call_targets.iter().any(|t: &String| t == name);
            let kind: DisasmSymbolKind = if is_callable {
                DisasmSymbolKind::Function
            } else {
                DisasmSymbolKind::Label
            };
            let address: u64 = self
                .blocks
                .get(*block_index)
                .map_or(0, |b: &BasicBlock| b.start_line as u64);
            symbols.push(DisasmSymbol {
                address,
                name: name.clone(),
                kind,
            });
        }
        symbols.sort_by_key(|s: &DisasmSymbol| s.address);
        symbols
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn resolves_goto_label_jump() {
        let src: &str = "@echo off\ngoto :TARGET\necho skipped\n:TARGET\necho hit\n";
        let cfg: BatchCfg = resolve_cfg(src);
        assert!(cfg.labels.contains_key("TARGET"));
        let goto_block: &BasicBlock = cfg
            .blocks
            .iter()
            .find(|b: &&BasicBlock| b.edges.iter().any(|e: &CfgEdge| e.kind == EdgeKind::Goto))
            .expect("goto block");
        let edge: &CfgEdge = goto_block
            .edges
            .iter()
            .find(|e: &&CfgEdge| e.kind == EdgeKind::Goto)
            .expect("goto edge");
        assert_eq!(edge.target_label.as_deref(), Some("TARGET"));
        assert_eq!(edge.target_block, cfg.labels.get("TARGET").copied());
    }

    #[test]
    fn call_creates_call_and_return_edges() {
        let src: &str = "@echo off\ncall :SUB arg1\necho after\ngoto :END\n:SUB\necho in-sub\nexit /b 0\n:END\nexit /b 0\n";
        let cfg: BatchCfg = resolve_cfg(src);
        assert!(cfg.call_targets.iter().any(|t: &String| t == "SUB"));
        let call_block: &BasicBlock = cfg
            .blocks
            .iter()
            .find(|b: &&BasicBlock| b.edges.iter().any(|e: &CfgEdge| e.kind == EdgeKind::Call))
            .expect("call block");
        assert!(
            call_block
                .edges
                .iter()
                .any(|e: &CfgEdge| e.kind == EdgeKind::CallReturn)
        );
        let sub_symbol: bool = cfg
            .to_ir_symbols()
            .iter()
            .any(|s: &DisasmSymbol| s.name == "SUB" && s.kind == DisasmSymbolKind::Function);
        assert!(sub_symbol, "SUB must lower to an IR Function symbol");
    }

    #[test]
    fn conditional_goto_keeps_fallthrough() {
        let src: &str = "@echo off\nif \"%X%\"==\"1\" goto :YES\necho no-branch\n:YES\necho yes\n";
        let cfg: BatchCfg = resolve_cfg(src);
        let cond_block: &BasicBlock = cfg
            .blocks
            .iter()
            .find(|b: &&BasicBlock| {
                b.edges
                    .iter()
                    .any(|e: &CfgEdge| e.kind == EdgeKind::ConditionalGoto)
            })
            .expect("conditional block");
        assert!(
            cond_block
                .edges
                .iter()
                .any(|e: &CfgEdge| e.kind == EdgeKind::FallThrough),
            "conditional goto must retain a fall-through edge"
        );
    }

    #[test]
    fn computed_call_target_is_unresolved_not_dropped() {
        let src: &str = "@echo off\ncall :SWITCH_%FRUIT%\nexit /b 0\n";
        let cfg: BatchCfg = resolve_cfg(src);
        assert!(
            cfg.unresolved_targets
                .iter()
                .any(|t: &String| t.contains('%')),
            "computed call target must be surfaced as unresolved; got {:?}",
            cfg.unresolved_targets
        );
    }

    #[test]
    fn exit_b_terminates_block_without_fallthrough_into_next_label() {
        let src: &str = "@echo off\n:A\necho a\nexit /b 0\n:B\necho b\nexit /b 0\n";
        let cfg: BatchCfg = resolve_cfg(src);
        let block_a: &BasicBlock = cfg
            .blocks
            .iter()
            .find(|b: &&BasicBlock| b.label.as_deref() == Some("A"))
            .expect("block A");
        assert!(
            block_a
                .edges
                .iter()
                .any(|e: &CfgEdge| e.kind == EdgeKind::ExitProcedure)
        );
        assert!(
            !block_a
                .edges
                .iter()
                .any(|e: &CfgEdge| e.kind == EdgeKind::FallThrough),
            "exit /b must not fall through into the next label"
        );
    }

    #[test]
    fn goto_eof_is_exit_procedure() {
        let src: &str = "@echo off\ngoto :eof\n";
        let cfg: BatchCfg = resolve_cfg(src);
        assert!(
            cfg.blocks
                .iter()
                .flat_map(|b: &BasicBlock| &b.edges)
                .any(|e: &CfgEdge| e.kind == EdgeKind::ExitProcedure)
        );
    }
}
