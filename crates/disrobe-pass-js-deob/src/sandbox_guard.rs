use std::ops::ControlFlow;

pub(crate) const MAX_SYNTACTIC_NESTING_DEPTH: usize = 600;

pub(crate) const MAX_OPERATOR_CHAIN: usize = 600;

pub(crate) const MAX_EXPRESSION_DEPTH: usize = 28_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Code,
    SingleQuote,
    DoubleQuote,
    Template,
    LineComment,
    BlockComment,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    Code(u8),
}

fn scan_code(script: &str, mut visit: impl FnMut(Token) -> ControlFlow<()>) {
    let bytes: &[u8] = script.as_bytes();
    let mut mode: Mode = Mode::Code;
    let mut escaped: bool = false;
    let mut prev: u8 = 0;
    let mut depth: usize = 0;
    let mut template_depths: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        let token: Option<Token> = match mode {
            Mode::SingleQuote | Mode::DoubleQuote => {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if (mode == Mode::SingleQuote && b == b'\'')
                    || (mode == Mode::DoubleQuote && b == b'"')
                {
                    mode = Mode::Code;
                }
                None
            }
            Mode::Template => {
                if escaped {
                    escaped = false;
                    None
                } else if b == b'\\' {
                    escaped = true;
                    None
                } else if b == b'`' {
                    mode = Mode::Code;
                    None
                } else if b == b'$' && bytes.get(i + 1) == Some(&b'{') {
                    depth = depth.saturating_add(1);
                    template_depths.push(depth);
                    mode = Mode::Code;
                    i = i.saturating_add(1);
                    Some(Token::Open)
                } else {
                    None
                }
            }
            Mode::LineComment => {
                if b == b'\n' {
                    mode = Mode::Code;
                }
                None
            }
            Mode::BlockComment => {
                if prev == b'*' && b == b'/' {
                    mode = Mode::Code;
                }
                None
            }
            Mode::Code => match b {
                b'\'' => {
                    mode = Mode::SingleQuote;
                    None
                }
                b'"' => {
                    mode = Mode::DoubleQuote;
                    None
                }
                b'`' => {
                    mode = Mode::Template;
                    None
                }
                b'/' if bytes.get(i + 1) == Some(&b'/') => {
                    mode = Mode::LineComment;
                    None
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    mode = Mode::BlockComment;
                    None
                }
                b'(' | b'[' | b'{' => {
                    depth = depth.saturating_add(1);
                    Some(Token::Open)
                }
                b')' | b']' => {
                    depth = depth.saturating_sub(1);
                    Some(Token::Close)
                }
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if template_depths
                        .last()
                        .is_some_and(|open: &usize| open.saturating_sub(1) == depth)
                    {
                        template_depths.pop();
                        mode = Mode::Template;
                    }
                    Some(Token::Close)
                }
                _ => Some(Token::Code(b)),
            },
        };
        if let Some(token) = token
            && visit(token).is_break()
        {
            return;
        }
        prev = b;
        i += 1;
    }
}

const fn is_operator(b: u8) -> bool {
    matches!(
        b,
        b'+' | b'-' | b'*' | b'%' | b'&' | b'|' | b'^' | b'<' | b'>'
    )
}

const fn is_expression_operator(b: u8) -> bool {
    is_operator(b) || matches!(b, b'!' | b'~' | b'=' | b'?')
}

#[must_use]
pub(crate) fn max_bracket_nesting(script: &str) -> usize {
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    scan_code(script, |token: Token| {
        match token {
            Token::Open => {
                depth = depth.saturating_add(1);
                max_depth = max_depth.max(depth);
            }
            Token::Close => depth = depth.saturating_sub(1),
            Token::Code(_) => {}
        }
        if max_depth > MAX_SYNTACTIC_NESTING_DEPTH {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    max_depth
}

#[must_use]
pub(crate) fn max_operator_chain(script: &str) -> usize {
    let mut run: usize = 0;
    let mut max_run: usize = 0;
    scan_code(script, |token: Token| {
        match token {
            Token::Code(b) if is_operator(b) => {
                run = run.saturating_add(1);
                max_run = max_run.max(run);
            }
            Token::Open | Token::Close | Token::Code(b';' | b',') => run = 0,
            Token::Code(_) => {}
        }
        if max_run > MAX_OPERATOR_CHAIN {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    max_run
}

#[must_use]
pub(crate) fn max_expression_depth(script: &str) -> usize {
    let mut level_operators: Vec<usize> = vec![0];
    let mut open_operators: usize = 0;
    let mut max_depth: usize = 0;
    scan_code(script, |token: Token| {
        match token {
            Token::Open => level_operators.push(0),
            Token::Close => {
                if level_operators.len() > 1
                    && let Some(closed) = level_operators.pop()
                {
                    open_operators = open_operators.saturating_sub(closed);
                }
            }
            Token::Code(b';' | b',') => {
                if let Some(current) = level_operators.last_mut() {
                    open_operators = open_operators.saturating_sub(*current);
                    *current = 0;
                }
            }
            Token::Code(b) if is_expression_operator(b) => {
                if let Some(current) = level_operators.last_mut() {
                    *current = current.saturating_add(1);
                    open_operators = open_operators.saturating_add(1);
                }
            }
            Token::Code(_) => {}
        }
        max_depth = max_depth.max(open_operators.saturating_add(level_operators.len()));
        if max_depth > MAX_EXPRESSION_DEPTH {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    max_depth
}

#[must_use]
pub(crate) fn nesting_is_safe(script: &str) -> bool {
    max_bracket_nesting(script) <= MAX_SYNTACTIC_NESTING_DEPTH
        && max_operator_chain(script) <= MAX_OPERATOR_CHAIN
        && max_expression_depth(script) <= MAX_EXPRESSION_DEPTH
}

#[must_use]
pub(crate) fn nesting_is_safe_for_capture(script: &str) -> bool {
    max_bracket_nesting(script) <= MAX_SYNTACTIC_NESTING_DEPTH
        && max_expression_depth(script) <= MAX_EXPRESSION_DEPTH
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn flat_code_has_low_depth() {
        assert!(max_bracket_nesting("var x = 1; foo(bar, baz);") <= 1);
    }

    #[test]
    fn counts_genuine_nesting() {
        assert_eq!(max_bracket_nesting("((([])))"), 4);
    }

    #[test]
    fn ignores_brackets_in_single_quotes() {
        assert_eq!(max_bracket_nesting("'(((((('"), 0);
    }

    #[test]
    fn ignores_brackets_in_double_quotes() {
        assert_eq!(max_bracket_nesting("\"[[[[\""), 0);
    }

    #[test]
    fn ignores_brackets_in_template_literals() {
        assert_eq!(max_bracket_nesting("`((((`"), 0);
    }

    #[test]
    fn counts_brackets_in_template_substitutions() {
        let nested: String = format!("`${{{}}}`", "(".repeat(MAX_SYNTACTIC_NESTING_DEPTH + 1));
        assert!(max_bracket_nesting(&nested) > MAX_SYNTACTIC_NESTING_DEPTH);
        assert!(!nesting_is_safe(&nested));
    }

    #[test]
    fn ignores_brackets_in_line_comment() {
        assert_eq!(max_bracket_nesting("// (((((\nx"), 0);
    }

    #[test]
    fn ignores_brackets_in_block_comment() {
        assert_eq!(max_bracket_nesting("/* ((((( */ x"), 0);
    }

    #[test]
    fn escaped_quote_does_not_exit_string() {
        assert_eq!(max_bracket_nesting(r"'\'((((' "), 0);
    }

    #[test]
    fn short_circuits_above_bound() {
        let deep: String = "(".repeat(MAX_SYNTACTIC_NESTING_DEPTH + 100);
        assert!(max_bracket_nesting(&deep) > MAX_SYNTACTIC_NESTING_DEPTH);
        assert!(!nesting_is_safe(&deep));
    }

    #[test]
    fn at_bound_is_safe() {
        let at_bound: String = "(".repeat(MAX_SYNTACTIC_NESTING_DEPTH);
        assert!(nesting_is_safe(&at_bound));
    }

    #[test]
    fn long_operator_chain_is_unsafe() {
        let chain: String = "1".to_owned() + "+1".repeat(MAX_OPERATOR_CHAIN + 50).as_str();
        assert!(max_operator_chain(&chain) > MAX_OPERATOR_CHAIN);
        assert!(!nesting_is_safe(&chain));
    }

    #[test]
    fn operators_inside_strings_do_not_count() {
        let s: String = format!("'{}'", "+".repeat(MAX_OPERATOR_CHAIN + 50));
        assert_eq!(max_operator_chain(&s), 0);
    }

    #[test]
    fn operand_chains_count_across_brackets() {
        let chain: String =
            "(![]+[])".to_owned() + "+(![]+[])".repeat(MAX_EXPRESSION_DEPTH).as_str();
        assert!(max_operator_chain(&chain) <= 2);
        assert!(max_expression_depth(&chain) > MAX_EXPRESSION_DEPTH);
        assert!(!nesting_is_safe(&chain));
        assert!(!nesting_is_safe_for_capture(&chain));
    }

    #[test]
    fn expression_depth_adds_the_chains_of_enclosing_levels() {
        assert_eq!(max_expression_depth("a+b+(c+d)"), 5);
        assert_eq!(max_expression_depth("a+b; c+d"), 2);
        assert_eq!(max_expression_depth("f(a+b, c)"), 3);
        assert_eq!(max_expression_depth("'+++' + `${a+b}`"), 4);
    }

    #[test]
    fn operator_run_resets_on_separator() {
        let stmt: String = "a+b+c;".repeat(500);
        assert!(max_operator_chain(&stmt) <= 2);
        assert!(nesting_is_safe(&stmt));
    }
}
