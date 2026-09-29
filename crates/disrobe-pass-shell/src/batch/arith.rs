use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Num(i64),
    Var(usize),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Shl,
    Shr,
    LParen,
    RParen,
}

const MAX_ARITH_DEPTH: usize = 256;

#[must_use]
pub fn eval(expr: &str, env: &BTreeMap<String, String>) -> Option<i64> {
    let mut names: Vec<String> = Vec::new();
    let tokens: Vec<Tok> = lex(expr, &mut names)?;
    let mut parser: Parser<'_> = Parser {
        tokens: &tokens,
        pos: 0,
        names: &names,
        env,
        depth: 0,
    };
    let value: i64 = parser.parse_expr(0)?;
    if parser.pos == tokens.len() {
        Some(value)
    } else {
        None
    }
}

fn lex(expr: &str, names: &mut Vec<String>) -> Option<Vec<Tok>> {
    let chars: Vec<char> = expr.chars().collect();
    let mut out: Vec<Tok> = Vec::new();
    let mut i: usize = 0;
    while i < chars.len() {
        let c: char = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            '-' => {
                out.push(Tok::Minus);
                i += 1;
            }
            '*' => {
                out.push(Tok::Star);
                i += 1;
            }
            '/' => {
                out.push(Tok::Slash);
                i += 1;
            }
            '%' => {
                out.push(Tok::Percent);
                i += 1;
            }
            '&' => {
                out.push(Tok::Amp);
                i += 1;
            }
            '|' => {
                out.push(Tok::Pipe);
                i += 1;
            }
            '^' => {
                out.push(Tok::Caret);
                i += 1;
            }
            '~' => {
                out.push(Tok::Tilde);
                i += 1;
            }
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '<' if chars.get(i + 1) == Some(&'<') => {
                out.push(Tok::Shl);
                i += 2;
            }
            '>' if chars.get(i + 1) == Some(&'>') => {
                out.push(Tok::Shr);
                i += 2;
            }
            '<' | '>' => return None,
            '0'..='9' => {
                let (value, used): (i64, usize) = lex_number(&chars[i..])?;
                out.push(Tok::Num(value));
                i += used;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start: usize = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let name: String = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .to_ascii_uppercase();
                let idx: usize = names
                    .iter()
                    .position(|n: &String| n == &name)
                    .unwrap_or_else(|| {
                        names.push(name);
                        names.len() - 1
                    });
                out.push(Tok::Var(idx));
            }
            _ => return None,
        }
    }
    Some(out)
}

fn lex_number(chars: &[char]) -> Option<(i64, usize)> {
    if chars.first() == Some(&'0') && matches!(chars.get(1), Some('x' | 'X')) {
        let mut j: usize = 2;
        while j < chars.len() && chars[j].is_ascii_hexdigit() {
            j += 1;
        }
        if j == 2 {
            return None;
        }
        let s: String = chars[2..j].iter().collect();
        let word: u32 = u64::from_str_radix(&s, 16)
            .ok()
            .and_then(|v: u64| u32::try_from(v).ok())
            .unwrap_or(u32::MAX);
        return Some((i64::from(word.cast_signed()), j));
    }
    let mut j: usize = 0;
    while j < chars.len() && chars[j].is_ascii_digit() {
        j += 1;
    }
    let s: String = chars[..j].iter().collect();
    let radix: u32 = if s.len() > 1 && s.starts_with('0') {
        8
    } else {
        10
    };
    let value: i32 = i32::from_str_radix(&s, radix).ok()?;
    Some((i64::from(value), j))
}

fn env_number(raw: &str) -> Option<i64> {
    let chars: Vec<char> = raw.trim().chars().collect();
    let (negative, digits): (bool, &[char]) = match chars.split_first() {
        Some(('-', rest)) => (true, rest),
        _ => (false, chars.as_slice()),
    };
    let (value, used): (i64, usize) = lex_number(digits)?;
    if used != digits.len() {
        return None;
    }
    Some(if negative {
        word(value).wrapping_neg().into()
    } else {
        value
    })
}

const fn word(value: i64) -> i32 {
    value as i32
}

struct Parser<'a> {
    tokens: &'a [Tok],
    pos: usize,
    names: &'a [String],
    env: &'a BTreeMap<String, String>,
    depth: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<Tok> {
        self.tokens.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<Tok> {
        let t: Option<Tok> = self.peek();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_expr(&mut self, min_bp: u8) -> Option<i64> {
        self.depth += 1;
        if self.depth > MAX_ARITH_DEPTH {
            self.depth -= 1;
            return None;
        }
        let value: Option<i64> = self.parse_expr_inner(min_bp);
        self.depth -= 1;
        value
    }

    fn parse_expr_inner(&mut self, min_bp: u8) -> Option<i64> {
        let mut lhs: i64 = self.parse_unary()?;
        while let Some(op) = self.peek() {
            let Some((lbp, rbp)): Option<(u8, u8)> = binding_power(op) else {
                break;
            };
            if lbp < min_bp {
                break;
            }
            self.bump();
            let rhs: i64 = self.parse_expr(rbp)?;
            lhs = apply(op, lhs, rhs)?;
        }
        Some(lhs)
    }

    fn parse_unary(&mut self) -> Option<i64> {
        self.depth += 1;
        if self.depth > MAX_ARITH_DEPTH {
            self.depth -= 1;
            return None;
        }
        let value: Option<i64> = self.parse_unary_inner();
        self.depth -= 1;
        value
    }

    fn parse_unary_inner(&mut self) -> Option<i64> {
        match self.peek() {
            Some(Tok::Minus) => {
                self.bump();
                let v: i64 = self.parse_unary()?;
                Some(i64::from(word(v).wrapping_neg()))
            }
            Some(Tok::Plus) => {
                self.bump();
                self.parse_unary()
            }
            Some(Tok::Tilde) => {
                self.bump();
                let v: i64 = self.parse_unary()?;
                Some(i64::from(!word(v)))
            }
            _ => self.parse_atom(),
        }
    }

    fn parse_atom(&mut self) -> Option<i64> {
        match self.bump()? {
            Tok::Num(n) => Some(n),
            Tok::Var(idx) => {
                let name: &String = self.names.get(idx)?;
                let raw: &String = self.env.get(name)?;
                env_number(raw)
            }
            Tok::LParen => {
                let v: i64 = self.parse_expr(0)?;
                if self.bump()? == Tok::RParen {
                    Some(v)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

const fn binding_power(op: Tok) -> Option<(u8, u8)> {
    let bp: (u8, u8) = match op {
        Tok::Pipe => (1, 2),
        Tok::Caret => (3, 4),
        Tok::Amp => (5, 6),
        Tok::Shl | Tok::Shr => (7, 8),
        Tok::Plus | Tok::Minus => (9, 10),
        Tok::Star | Tok::Slash | Tok::Percent => (11, 12),
        _ => return None,
    };
    Some(bp)
}

fn apply(op: Tok, lhs: i64, rhs: i64) -> Option<i64> {
    let (a, b): (i32, i32) = (word(lhs), word(rhs));
    let value: i32 = match op {
        Tok::Plus => a.wrapping_add(b),
        Tok::Minus => a.wrapping_sub(b),
        Tok::Star => a.wrapping_mul(b),
        Tok::Slash => a.checked_div(b).or_else(|| (b == -1).then_some(a))?,
        Tok::Percent => a.checked_rem(b).or_else(|| (b == -1).then_some(0))?,
        Tok::Amp => a & b,
        Tok::Pipe => a | b,
        Tok::Caret => a ^ b,
        Tok::Shl => {
            let count: u32 = b.cast_unsigned();
            if count >= i32::BITS { 0 } else { a << count }
        }
        Tok::Shr => a >> b.cast_unsigned().min(i32::BITS - 1),
        _ => return None,
    };
    Some(i64::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn set_a_arithmetic_is_32_bit_as_cmd_computes_it() {
        for (expr, expected) in [
            ("2147483647+1", Some(-2_147_483_648)),
            ("0x7fffffff*2", Some(-2)),
            ("(-2147483647-1)/-1", Some(-2_147_483_648)),
            ("1<<31", Some(-2_147_483_648)),
            ("1<<32", Some(0)),
            ("1<<33", Some(0)),
            ("1<<-1", Some(0)),
            ("-1>>40", Some(-1)),
            ("64>>32", Some(0)),
            ("-8>>1", Some(-4)),
            ("7%-2", Some(1)),
            ("-7/2", Some(-3)),
            ("0xFFFFFFFF", Some(-1)),
            ("0x80000000", Some(-2_147_483_648)),
            ("0x100000000", Some(-1)),
            ("017777777777", Some(2_147_483_647)),
            ("037777777777", None),
            ("2147483648", None),
            ("-2147483648", None),
            ("~0", Some(-1)),
        ] {
            assert_eq!(eval(expr, &empty()), expected, "set /a {expr}");
        }
    }

    #[test]
    fn folds_precedence() {
        assert_eq!(eval("2+3*4", &empty()), Some(14));
        assert_eq!(eval("(2+3)*4", &empty()), Some(20));
    }

    #[test]
    fn folds_bitwise_and_shift() {
        assert_eq!(eval("1 << 4", &empty()), Some(16));
        assert_eq!(eval("0xFF & 0x0F", &empty()), Some(15));
        assert_eq!(eval("12 ^ 10", &empty()), Some(6));
    }

    #[test]
    fn reads_variables() {
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        env.insert("X".to_owned(), "5".to_owned());
        env.insert("Y".to_owned(), "3".to_owned());
        assert_eq!(eval("X*Y+1", &env), Some(16));
    }

    #[test]
    fn octal_and_hex_literals() {
        assert_eq!(eval("010", &empty()), Some(8));
        assert_eq!(eval("0x10", &empty()), Some(16));
    }

    #[test]
    fn unary_minus_and_not() {
        assert_eq!(eval("-5", &empty()), Some(-5));
        assert_eq!(eval("~0", &empty()), Some(-1));
    }

    #[test]
    fn division_by_zero_is_none() {
        assert_eq!(eval("1/0", &empty()), None);
    }

    #[test]
    fn unknown_var_is_none() {
        assert_eq!(eval("NOTSET+1", &empty()), None);
    }

    #[test]
    fn deeply_nested_parens_does_not_overflow() {
        let depth: usize = 50_000;
        let expr: String = format!("{}1{}", "(".repeat(depth), ")".repeat(depth));
        assert_eq!(eval(&expr, &empty()), None);
    }

    #[test]
    fn long_unary_chain_does_not_overflow() {
        let expr: String = format!("{}7", "-".repeat(50_000));
        assert_eq!(eval(&expr, &empty()), None);
    }

    #[test]
    fn bounded_depth_still_evaluates() {
        assert_eq!(eval("(((((9)))))", &empty()), Some(9));
        assert_eq!(eval("---4", &empty()), Some(-4));
    }
}
