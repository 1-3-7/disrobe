pub(crate) fn evaluate_arithmetic(s: &str, steps: &mut Vec<String>) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    let mut evaluated: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'$'
            && i + 2 < bytes.len()
            && bytes[i + 1] == b'('
            && bytes[i + 2] == b'('
            && let Some(end) = find_matching_dollar_dparen(bytes, i + 3)
        {
            let inner: &str = std::str::from_utf8(&bytes[i + 3..end]).unwrap_or("");
            if let Some(value) = eval_arith(inner) {
                out.extend_from_slice(value.to_string().as_bytes());
                evaluated += 1;
                i = end + 2;
                continue;
            }
        }
        if bytes[i] == b'$'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'['
            && let Some(end) = find_matching_dollar_bracket(bytes, i + 2)
        {
            let inner: &str = std::str::from_utf8(&bytes[i + 2..end]).unwrap_or("");
            if let Some(value) = eval_arith(inner) {
                out.extend_from_slice(value.to_string().as_bytes());
                evaluated += 1;
                i = end + 1;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    if evaluated > 0 {
        steps.push(format!("eval-arithmetic:{evaluated}"));
    }
    String::from_utf8(out).unwrap_or_else(|_: std::string::FromUtf8Error| s.to_owned())
}

fn find_matching_dollar_dparen(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: usize = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b')' {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn find_matching_dollar_bracket(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: usize = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'[' {
            depth += 1;
        } else if b == b']' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn eval_arith(expr: &str) -> Option<i64> {
    let cleaned: String = strip_arith_noise(expr);
    let mut parser: ArithParser<'_> = ArithParser::new(&cleaned);
    let value: i64 = parser.parse_expression()?;
    parser.skip_ws();
    if parser.pos < parser.src.len() {
        return None;
    }
    Some(value)
}

fn strip_arith_noise(expr: &str) -> String {
    let mut out: String = String::with_capacity(expr.len());
    let bytes: &[u8] = expr.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'"' {
            i += 1;
            continue;
        }
        if b == b'$' {
            let mut j: usize = i + 1;
            if j < bytes.len() && bytes[j] == b'{' {
                let mut depth: usize = 1;
                j += 1;
                while j < bytes.len() && depth > 0 {
                    if bytes[j] == b'\\' && j + 1 < bytes.len() {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == b'{' {
                        depth += 1;
                    } else if bytes[j] == b'}' {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            if j < bytes.len() && matches!(bytes[j], b'@' | b'*' | b'#' | b'?' | b'!') {
                i = j + 1;
                continue;
            }
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > i + 1 {
                i = j;
                continue;
            }
            i += 1;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

#[derive(Debug)]
struct ArithParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> ArithParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            src: s.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len()
            && matches!(self.src[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.src.get(self.pos).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_expression(&mut self) -> Option<i64> {
        self.parse_bitor()
    }

    fn parse_bitor(&mut self) -> Option<i64> {
        let mut left: i64 = self.parse_bitxor()?;
        loop {
            self.skip_ws();
            if self.pos + 1 < self.src.len()
                && self.src[self.pos] == b'|'
                && self.src[self.pos + 1] != b'|'
            {
                self.pos += 1;
                let right: i64 = self.parse_bitxor()?;
                left |= right;
            } else {
                break;
            }
        }
        Some(left)
    }

    fn parse_bitxor(&mut self) -> Option<i64> {
        let mut left: i64 = self.parse_bitand()?;
        while self.eat(b'^') {
            let right: i64 = self.parse_bitand()?;
            left ^= right;
        }
        Some(left)
    }

    fn parse_bitand(&mut self) -> Option<i64> {
        let mut left: i64 = self.parse_shift()?;
        loop {
            self.skip_ws();
            if self.pos + 1 < self.src.len()
                && self.src[self.pos] == b'&'
                && self.src[self.pos + 1] != b'&'
            {
                self.pos += 1;
                let right: i64 = self.parse_shift()?;
                left &= right;
            } else {
                break;
            }
        }
        Some(left)
    }

    fn parse_shift(&mut self) -> Option<i64> {
        let mut left: i64 = self.parse_add()?;
        loop {
            self.skip_ws();
            if self.pos + 1 < self.src.len()
                && self.src[self.pos] == b'<'
                && self.src[self.pos + 1] == b'<'
            {
                self.pos += 2;
                let right: i64 = self.parse_add()?;
                left <<= right;
            } else if self.pos + 1 < self.src.len()
                && self.src[self.pos] == b'>'
                && self.src[self.pos + 1] == b'>'
            {
                self.pos += 2;
                let right: i64 = self.parse_add()?;
                left >>= right;
            } else {
                break;
            }
        }
        Some(left)
    }

    fn parse_add(&mut self) -> Option<i64> {
        let mut left: i64 = self.parse_mul()?;
        loop {
            self.skip_ws();
            if self.eat(b'+') {
                let right: i64 = self.parse_mul()?;
                left = left.wrapping_add(right);
            } else if self.eat(b'-') {
                let right: i64 = self.parse_mul()?;
                left = left.wrapping_sub(right);
            } else {
                break;
            }
        }
        Some(left)
    }

    fn parse_mul(&mut self) -> Option<i64> {
        let mut left: i64 = self.parse_unary()?;
        loop {
            self.skip_ws();
            if self.eat(b'*') {
                let right: i64 = self.parse_unary()?;
                left = left.wrapping_mul(right);
            } else if self.eat(b'/') {
                let right: i64 = self.parse_unary()?;
                if right == 0 {
                    return None;
                }
                left = left.wrapping_div(right);
            } else if self.eat(b'%') {
                let right: i64 = self.parse_unary()?;
                if right == 0 {
                    return None;
                }
                left = left.wrapping_rem(right);
            } else {
                break;
            }
        }
        Some(left)
    }

    fn parse_unary(&mut self) -> Option<i64> {
        self.skip_ws();
        if self.eat(b'-') {
            return Some(self.parse_unary()?.wrapping_neg());
        }
        if self.eat(b'+') {
            return self.parse_unary();
        }
        if self.eat(b'~') {
            return Some(!self.parse_unary()?);
        }
        if self.eat(b'!') {
            let v: i64 = self.parse_unary()?;
            return Some(i64::from(v == 0));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Option<i64> {
        self.skip_ws();
        if self.eat(b'(') {
            let v: i64 = self.parse_expression()?;
            self.skip_ws();
            if !self.eat(b')') {
                return None;
            }
            return Some(v);
        }
        self.parse_number()
    }

    fn parse_number(&mut self) -> Option<i64> {
        self.skip_ws();
        let start: usize = self.pos;
        while self.pos < self.src.len()
            && (self.src[self.pos].is_ascii_alphanumeric()
                || self.src[self.pos] == b'_'
                || self.src[self.pos] == b'#'
                || self.src[self.pos] == b'@')
        {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        let token: &str = std::str::from_utf8(&self.src[start..self.pos]).ok()?;
        if let Some(idx) = token.find('#') {
            let base: u32 = token[..idx].parse::<u32>().ok()?;
            if !(2..=64).contains(&base) {
                return None;
            }
            let digits: &str = &token[idx + 1..];
            let mut value: i64 = 0;
            for ch in digits.chars() {
                let d: i64 = i64::from(bash_arith_digit(ch, base)?);
                value = value.checked_mul(i64::from(base))?.checked_add(d)?;
            }
            return Some(value);
        }
        if let Some(rest) = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
        {
            return i64::from_str_radix(rest, 16).ok();
        }
        if token.starts_with('0')
            && token.len() > 1
            && token.chars().all(|c: char| ('0'..='7').contains(&c))
        {
            return i64::from_str_radix(token, 8).ok();
        }
        token.parse::<i64>().ok()
    }
}

fn bash_arith_digit(ch: char, base: u32) -> Option<u32> {
    let v: u32 = match ch {
        '0'..='9' => ch as u32 - '0' as u32,
        'a'..='z' => 10 + (ch as u32 - 'a' as u32),
        'A'..='Z' => {
            if base <= 36 {
                10 + (ch as u32 - 'A' as u32)
            } else {
                36 + (ch as u32 - 'A' as u32)
            }
        }
        '_' => 62,
        '@' => 63,
        _ => return None,
    };
    if v >= base {
        return None;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_base_n_literals() {
        let mut steps: Vec<String> = Vec::new();
        let out: String = evaluate_arithmetic("$(( 2#100 ))", &mut steps);
        assert_eq!(out, "4");
    }

    #[test]
    fn evaluates_legacy_bracket_form() {
        let mut steps: Vec<String> = Vec::new();
        let out: String = evaluate_arithmetic("base6$[ 2#100 ]", &mut steps);
        assert_eq!(out, "base64");
    }

    #[test]
    fn handles_quoted_digits_and_dollar_at() {
        let mut steps: Vec<String> = Vec::new();
        let out: String = evaluate_arithmetic(r##"$[ (("7"#"0"*"$@"29#1)+2#100) ]"##, &mut steps);
        assert_eq!(out, "4");
    }
}
