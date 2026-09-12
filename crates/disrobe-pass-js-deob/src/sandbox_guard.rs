pub(crate) const MAX_SYNTACTIC_NESTING_DEPTH: usize = 600;

pub(crate) const MAX_OPERATOR_CHAIN: usize = 600;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Code,
    SingleQuote,
    DoubleQuote,
    Template,
    LineComment,
    BlockComment,
}

#[must_use]
pub(crate) fn max_bracket_nesting(script: &str) -> usize {
    let mut mode: Mode = Mode::Code;
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut escaped: bool = false;
    let mut prev: u8 = 0;
    let mut template_depths: Vec<usize> = Vec::new();
    let bytes: &[u8] = script.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match mode {
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
            }
            Mode::Template => {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'`' {
                    mode = Mode::Code;
                } else if b == b'$' && bytes.get(i + 1) == Some(&b'{') {
                    depth = depth.saturating_add(1);
                    if depth > max_depth {
                        max_depth = depth;
                        if max_depth > MAX_SYNTACTIC_NESTING_DEPTH {
                            return max_depth;
                        }
                    }
                    template_depths.push(depth);
                    mode = Mode::Code;
                    i = i.saturating_add(1);
                }
            }
            Mode::LineComment => {
                if b == b'\n' {
                    mode = Mode::Code;
                }
            }
            Mode::BlockComment => {
                if prev == b'*' && b == b'/' {
                    mode = Mode::Code;
                }
            }
            Mode::Code => match b {
                b'\'' => mode = Mode::SingleQuote,
                b'"' => mode = Mode::DoubleQuote,
                b'`' => mode = Mode::Template,
                b'/' if bytes.get(i + 1) == Some(&b'/') => mode = Mode::LineComment,
                b'/' if bytes.get(i + 1) == Some(&b'*') => mode = Mode::BlockComment,
                b'(' | b'[' | b'{' => {
                    depth = depth.saturating_add(1);
                    if depth > max_depth {
                        max_depth = depth;
                        if max_depth > MAX_SYNTACTIC_NESTING_DEPTH {
                            return max_depth;
                        }
                    }
                }
                b')' | b']' => depth = depth.saturating_sub(1),
                b'}' => {
                    depth = depth.saturating_sub(1);
                    let template_depth: Option<usize> = template_depths.last().copied();
                    if template_depth.is_some_and(|open: usize| open.saturating_sub(1) == depth) {
                        template_depths.pop();
                        mode = Mode::Template;
                    }
                }
                _ => {}
            },
        }
        prev = b;
        i += 1;
    }
    max_depth
}

#[must_use]
pub(crate) fn max_operator_chain(script: &str) -> usize {
    let mut mode: Mode = Mode::Code;
    let mut run: usize = 0;
    let mut max_run: usize = 0;
    let mut escaped: bool = false;
    let mut prev: u8 = 0;
    let mut brace_depth: usize = 0;
    let mut template_depths: Vec<usize> = Vec::new();
    let bytes: &[u8] = script.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match mode {
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
            }
            Mode::Template => {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'`' {
                    mode = Mode::Code;
                } else if b == b'$' && bytes.get(i + 1) == Some(&b'{') {
                    brace_depth = brace_depth.saturating_add(1);
                    template_depths.push(brace_depth);
                    mode = Mode::Code;
                    i = i.saturating_add(1);
                }
            }
            Mode::LineComment => {
                if b == b'\n' {
                    mode = Mode::Code;
                }
            }
            Mode::BlockComment => {
                if prev == b'*' && b == b'/' {
                    mode = Mode::Code;
                }
            }
            Mode::Code => match b {
                b'\'' => mode = Mode::SingleQuote,
                b'"' => mode = Mode::DoubleQuote,
                b'`' => mode = Mode::Template,
                b'/' if bytes.get(i + 1) == Some(&b'/') => mode = Mode::LineComment,
                b'/' if bytes.get(i + 1) == Some(&b'*') => mode = Mode::BlockComment,
                b'+' | b'-' | b'*' | b'%' | b'&' | b'|' | b'^' | b'<' | b'>' => {
                    run = run.saturating_add(1);
                    if run > max_run {
                        max_run = run;
                        if max_run > MAX_OPERATOR_CHAIN {
                            return max_run;
                        }
                    }
                }
                b'{' => {
                    brace_depth = brace_depth.saturating_add(1);
                    run = 0;
                }
                b'}' => {
                    brace_depth = brace_depth.saturating_sub(1);
                    let template_depth: Option<usize> = template_depths.last().copied();
                    if template_depth
                        .is_some_and(|open: usize| open.saturating_sub(1) == brace_depth)
                    {
                        template_depths.pop();
                        mode = Mode::Template;
                    }
                    run = 0;
                }
                b';' | b'(' | b')' | b'[' | b']' | b',' => run = 0,
                _ => {}
            },
        }
        prev = b;
        i += 1;
    }
    max_run
}

pub(crate) const MAX_CAPTURE_OPERATOR_CHAIN: usize = 200_000;

#[must_use]
pub(crate) fn nesting_is_safe(script: &str) -> bool {
    max_bracket_nesting(script) <= MAX_SYNTACTIC_NESTING_DEPTH
        && max_operator_chain(script) <= MAX_OPERATOR_CHAIN
}

#[must_use]
pub(crate) fn nesting_is_safe_for_capture(script: &str) -> bool {
    max_bracket_nesting(script) <= MAX_SYNTACTIC_NESTING_DEPTH
        && max_operator_chain(script) <= MAX_CAPTURE_OPERATOR_CHAIN
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
    fn operator_run_resets_on_separator() {
        let stmt: String = "a+b+c;".repeat(500);
        assert!(max_operator_chain(&stmt) <= 2);
        assert!(nesting_is_safe(&stmt));
    }
}
