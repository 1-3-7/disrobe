use serde::Serialize;

use super::lexer::{Lexer, Token, TokenKind};

#[derive(Debug, Clone, Serialize)]
pub enum AstNode {
    Script {
        children: Vec<AstNode>,
    },
    Statement {
        text: String,
        children: Vec<AstNode>,
    },
    Assignment {
        lhs: String,
        rhs: Box<AstNode>,
    },
    Pipeline {
        stages: Vec<AstNode>,
    },
    Call {
        command: String,
        args: Vec<AstNode>,
    },
    StringLiteral {
        value: String,
        quoted: char,
    },
    Number {
        value: i64,
    },
    Variable {
        name: String,
    },
    ScriptBlock {
        body: Box<AstNode>,
    },
    Raw {
        text: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct Ast {
    pub root: AstNode,
    pub statement_count: usize,
}

#[must_use]
pub fn parse_ast(src: &[u8]) -> Ast {
    let tokens: Vec<Token> = Lexer::new(src).tokenize();
    let mut parser: Parser<'_> = Parser::new(&tokens);
    let root: AstNode = parser.parse_script();
    let statement_count: usize = match &root {
        AstNode::Script { children } => children.len(),
        _ => 0,
    };
    Ast {
        root,
        statement_count,
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn parse_script(&mut self) -> AstNode {
        let mut stmts: Vec<AstNode> = Vec::new();
        while self.pos < self.tokens.len() {
            let tok: &Token = &self.tokens[self.pos];
            if matches!(tok.kind, TokenKind::Eof) {
                break;
            }
            if matches!(
                tok.kind,
                TokenKind::Whitespace | TokenKind::Newline | TokenKind::Comment
            ) {
                self.pos += 1;
                continue;
            }
            let Some(stmt): Option<AstNode> = self.parse_statement() else {
                self.pos += 1;
                continue;
            };
            stmts.push(stmt);
        }
        AstNode::Script { children: stmts }
    }

    fn parse_statement(&mut self) -> Option<AstNode> {
        let start: usize = self.pos;
        let mut children: Vec<AstNode> = Vec::new();
        let mut text_buf: String = String::new();
        let mut pipeline_stages: Vec<AstNode> = Vec::new();
        let mut current_stage_text: String = String::new();
        while self.pos < self.tokens.len() {
            let tok: &Token = &self.tokens[self.pos];
            match tok.kind {
                TokenKind::Eof | TokenKind::Newline | TokenKind::Semicolon => {
                    self.pos += 1;
                    break;
                }
                TokenKind::Pipe => {
                    if !current_stage_text.trim().is_empty() {
                        pipeline_stages.push(AstNode::Raw {
                            text: current_stage_text.trim().to_owned(),
                        });
                    }
                    current_stage_text.clear();
                    self.pos += 1;
                    continue;
                }
                TokenKind::Variable => {
                    children.push(AstNode::Variable {
                        name: tok.text.clone(),
                    });
                    text_buf.push_str(&tok.text);
                    current_stage_text.push_str(&tok.text);
                    self.pos += 1;
                }
                TokenKind::StringDq | TokenKind::StringSq => {
                    let quote: char = if tok.kind == TokenKind::StringDq {
                        '"'
                    } else {
                        '\''
                    };
                    let stripped: String = tok.text.trim_matches(quote).to_owned();
                    children.push(AstNode::StringLiteral {
                        value: stripped,
                        quoted: quote,
                    });
                    text_buf.push_str(&tok.text);
                    current_stage_text.push_str(&tok.text);
                    self.pos += 1;
                }
                TokenKind::Number => {
                    let Ok(v): std::result::Result<i64, std::num::ParseIntError> =
                        tok.text.parse::<i64>()
                    else {
                        text_buf.push_str(&tok.text);
                        current_stage_text.push_str(&tok.text);
                        self.pos += 1;
                        continue;
                    };
                    children.push(AstNode::Number { value: v });
                    text_buf.push_str(&tok.text);
                    current_stage_text.push_str(&tok.text);
                    self.pos += 1;
                }
                _ => {
                    text_buf.push_str(&tok.text);
                    current_stage_text.push_str(&tok.text);
                    self.pos += 1;
                }
            }
        }
        if !current_stage_text.trim().is_empty() {
            pipeline_stages.push(AstNode::Raw {
                text: current_stage_text.trim().to_owned(),
            });
        }
        if start == self.pos {
            return None;
        }
        if pipeline_stages.len() >= 2 {
            return Some(AstNode::Pipeline {
                stages: pipeline_stages,
            });
        }
        Some(AstNode::Statement {
            text: text_buf.trim().to_owned(),
            children,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_assignment() {
        let src: &[u8] = b"$x = 1\n$y = 'hi'\n";
        let ast: Ast = parse_ast(src);
        assert!(ast.statement_count >= 2);
    }

    #[test]
    fn parses_pipeline() {
        let src: &[u8] = b"Get-Process | Where-Object { $_.CPU -gt 1 } | Select-Object Name\n";
        let ast: Ast = parse_ast(src);
        assert!(matches!(
            &ast.root,
            AstNode::Script { children } if children.iter().any(|c: &AstNode| matches!(c, AstNode::Pipeline { .. }))
        ));
    }

    #[test]
    fn overflowing_number_does_not_become_zero() {
        let ast: Ast = parse_ast(b"999999999999999999999999999999999999\n");
        let has_zero_number: bool = match &ast.root {
            AstNode::Script { children } => children.iter().any(|node: &AstNode| match node {
                AstNode::Statement { children, .. } => children
                    .iter()
                    .any(|child: &AstNode| matches!(child, AstNode::Number { value: 0 })),
                _ => false,
            }),
            _ => true,
        };
        assert!(!has_zero_number, "{:?}", ast.root);
    }
}
