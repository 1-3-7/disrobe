const MAX_DEPTH: usize = 256;
const MAX_OUTPUT: usize = 1 << 16;

const PRIMITIVES: [Option<&str>; 23] = [
    Some("char"),
    Some("bool"),
    Some("creal"),
    Some("double"),
    Some("real"),
    Some("float"),
    Some("byte"),
    Some("ubyte"),
    Some("int"),
    Some("ireal"),
    Some("uint"),
    Some("long"),
    Some("ulong"),
    None,
    Some("ifloat"),
    Some("idouble"),
    Some("cfloat"),
    Some("cdouble"),
    Some("short"),
    Some("ushort"),
    Some("wchar"),
    Some("void"),
    Some("dchar"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IsDelegate {
    No,
    Yes,
}

struct Demangler<'a> {
    buf: &'a [u8],
    pos: usize,
    out: String,
    brp: usize,
    depth: usize,
    top_qualified: Option<String>,
    top_params: Option<String>,
}

impl<'a> Demangler<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            out: String::new(),
            brp: usize::MAX,
            depth: 0,
            top_qualified: None,
            top_params: None,
        }
    }

    fn front(&self) -> u8 {
        self.buf.get(self.pos).copied().unwrap_or(0)
    }

    fn peek(&self, n: usize) -> u8 {
        self.pos
            .checked_add(n)
            .and_then(|idx: usize| self.buf.get(idx))
            .copied()
            .unwrap_or(0)
    }

    const fn pop(&mut self) -> Option<()> {
        if self.pos < self.buf.len() {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn pop_n(&mut self, n: usize) -> Option<()> {
        for _ in 0..n {
            self.pop()?;
        }
        Some(())
    }

    fn put(&mut self, s: &str) -> Option<()> {
        if self.out.len().saturating_add(s.len()) > MAX_OUTPUT {
            return None;
        }
        self.out.push_str(s);
        Some(())
    }

    fn put_char(&mut self, c: char) -> Option<()> {
        if self.out.len() >= MAX_OUTPUT {
            return None;
        }
        self.out.push(c);
        Some(())
    }

    fn match_char(&mut self, c: u8) -> bool {
        if self.front() == c {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn match_str(&mut self, s: &[u8]) -> bool {
        let save: usize = self.pos;
        for &b in s {
            if !self.match_char(b) {
                self.pos = save;
                return false;
            }
        }
        true
    }

    const fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            None
        } else {
            Some(())
        }
    }

    const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

const fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

impl Demangler<'_> {
    fn decode_backref_at(&self, mut p: usize) -> usize {
        const BASE: usize = 26;
        let mut n: usize = 0;
        loop {
            let t: u8 = self.buf.get(p).copied().unwrap_or(0);
            p += 1;
            if !t.is_ascii_uppercase() {
                if !t.is_ascii_lowercase() {
                    return 0;
                }
                return n
                    .checked_mul(BASE)
                    .and_then(|value: usize| value.checked_add(usize::from(t - b'a')))
                    .unwrap_or(0);
            }
            n = match n
                .checked_mul(BASE)
                .and_then(|value: usize| value.checked_add(usize::from(t - b'A')))
            {
                Some(value) => value,
                None => return 0,
            };
            if p.saturating_sub(self.pos) > 12 {
                return 0;
            }
        }
    }

    fn decode_backref(&mut self) -> usize {
        const BASE: usize = 26;
        let mut n: usize = 0;
        let mut guard: usize = 0;
        loop {
            let t: u8 = self.front();
            self.pos += 1;
            if !t.is_ascii_uppercase() {
                if !t.is_ascii_lowercase() {
                    return 0;
                }
                return n
                    .checked_mul(BASE)
                    .and_then(|value: usize| value.checked_add(usize::from(t - b'a')))
                    .unwrap_or(0);
            }
            n = match n
                .checked_mul(BASE)
                .and_then(|value: usize| value.checked_add(usize::from(t - b'A')))
            {
                Some(value) => value,
                None => return 0,
            };
            guard += 1;
            if guard > 12 {
                return 0;
            }
        }
    }

    fn peek_backref(&self) -> u8 {
        let n: usize = self.decode_backref_at(self.pos + 1);
        if n == 0 || n > self.pos {
            return 0;
        }
        self.buf.get(self.pos - n).copied().unwrap_or(0)
    }

    fn slice_number(&mut self) -> &'_ [u8] {
        let beg: usize = self.pos;
        while is_digit(self.front()) {
            self.pos += 1;
        }
        &self.buf[beg..self.pos]
    }

    fn decode_number(&mut self) -> Option<usize> {
        let mut n: usize = 0;
        if !is_digit(self.front()) {
            return None;
        }
        while is_digit(self.front()) {
            let d: usize = usize::from(self.front() - b'0');
            n = n.checked_mul(10)?.checked_add(d)?;
            self.pos += 1;
        }
        Some(n)
    }

    fn is_symbol_name_front(&self) -> Option<bool> {
        let val: u8 = self.front();
        if is_digit(val) || val == b'_' {
            return Some(true);
        }
        if val != b'Q' {
            return Some(false);
        }
        let bref: u8 = self.peek_backref();
        if bref == 0 {
            return None;
        }
        Some(is_digit(bref))
    }

    fn parse_lname(&mut self) -> Option<()> {
        self.enter()?;
        let r: Option<()> = self.parse_lname_inner();
        self.leave();
        r
    }

    fn parse_lname_inner(&mut self) -> Option<()> {
        if self.front() == b'Q' {
            let ref_pos: usize = self.pos;
            self.pop()?;
            let n: usize = self.decode_backref();
            if n == 0 || n > ref_pos {
                return None;
            }
            let save_pos: usize = self.pos;
            self.pos = ref_pos - n;
            let r: Option<()> = self.parse_lname();
            self.pos = save_pos;
            return r;
        }
        let n: usize = self.decode_number()?;
        if n == 0 {
            return self.put("__anonymous");
        }
        if n > self.buf.len() || self.pos.checked_add(n)? > self.buf.len() {
            return None;
        }
        let start: usize = self.pos;
        let end: usize = self.pos.checked_add(n)?;
        let raw: &[u8] = &self.buf[start..end];
        self.pos = end;
        let text: &str = std::str::from_utf8(raw).ok()?;
        self.put(text)
    }

    fn parse_qualified_name(&mut self) -> Option<()> {
        self.enter()?;
        let mut n: usize = 0;
        loop {
            if n > 0 {
                self.put_char('.')?;
            }
            n += 1;
            self.parse_symbol_name()?;
            let _: (String, usize) = self.parse_function_type_no_return(false)?;
            match self.is_symbol_name_front() {
                None => {
                    self.leave();
                    return None;
                }
                Some(false) => break,
                Some(true) => {}
            }
        }
        self.leave();
        Some(())
    }

    fn parse_symbol_name(&mut self) -> Option<()> {
        match self.front() {
            b'_' => self.parse_template_instance_name(false),
            b'0'..=b'9' => {
                if self.may_be_template_instance_name() {
                    let save_out: usize = self.out.len();
                    let save_pos: usize = self.pos;
                    let save_brp: usize = self.brp;
                    if self.parse_template_instance_name(true).is_some() {
                        return Some(());
                    }
                    self.out.truncate(save_out);
                    self.pos = save_pos;
                    self.brp = save_brp;
                }
                self.parse_lname()
            }
            b'Q' => self.parse_lname(),
            _ => None,
        }
    }

    fn may_be_template_instance_name(&self) -> bool {
        let mut p: usize = self.pos;
        let mut n: usize = 0;
        let mut saw: bool = false;
        while p < self.buf.len() && is_digit(self.buf[p]) {
            n = match n
                .checked_mul(10)
                .and_then(|v: usize| v.checked_add(usize::from(self.buf[p] - b'0')))
            {
                Some(v) => v,
                None => return false,
            };
            p += 1;
            saw = true;
        }
        if !saw {
            return false;
        }
        n >= 5
            && self.buf.get(p) == Some(&b'_')
            && self.buf.get(p + 1) == Some(&b'_')
            && self.buf.get(p + 2) == Some(&b'T')
    }

    fn parse_template_instance_name(&mut self, has_number: bool) -> Option<()> {
        self.enter()?;
        let sav: usize = self.pos;
        let save_brp: usize = self.brp;
        let save_out: usize = self.out.len();
        let r: Option<()> = self.parse_template_instance_inner(has_number);
        if r.is_none() {
            self.pos = sav;
            self.brp = save_brp;
            self.out.truncate(save_out);
        }
        self.leave();
        r
    }

    fn parse_template_instance_inner(&mut self, has_number: bool) -> Option<()> {
        let declared: usize = if has_number { self.decode_number()? } else { 0 };
        let beg: usize = self.pos;
        if !self.match_str(b"__T") {
            return None;
        }
        self.parse_lname()?;
        self.put("!(")?;
        self.parse_template_args()?;
        if !self.match_char(b'Z') {
            return None;
        }
        if has_number && self.pos - beg != declared {
            return None;
        }
        self.put_char(')')
    }

    fn parse_template_args(&mut self) -> Option<()> {
        self.enter()?;
        let mut n: usize = 0;
        loop {
            if self.front() == b'H' {
                self.pop()?;
            }
            match self.front() {
                b'T' => {
                    self.pop()?;
                    self.put_comma(n)?;
                    self.parse_type()?;
                }
                b'V' => {
                    self.pop()?;
                    self.put_comma(n)?;
                    let mut t: u8 = self.front();
                    if t == b'Q' {
                        t = self.peek_backref();
                        if t == 0 {
                            self.leave();
                            return None;
                        }
                    }
                    let silent_out: usize = self.out.len();
                    self.parse_type()?;
                    let name: String = self.out.split_off(silent_out);
                    self.parse_value(&name, t)?;
                }
                b'S' => {
                    self.pop()?;
                    self.put_comma(n)?;
                    self.parse_template_symbol_arg()?;
                }
                b'X' => {
                    self.pop()?;
                    self.put_comma(n)?;
                    self.parse_lname()?;
                }
                _ => {
                    self.leave();
                    return Some(());
                }
            }
            n += 1;
        }
    }

    fn parse_template_symbol_arg(&mut self) -> Option<()> {
        if self.may_be_mangled_name_arg() {
            let save_out: usize = self.out.len();
            let save_pos: usize = self.pos;
            let save_brp: usize = self.brp;
            if self.parse_mangled_name_arg().is_some() {
                return Some(());
            }
            self.out.truncate(save_out);
            self.pos = save_pos;
            self.brp = save_brp;
        }
        if is_digit(self.front()) && is_digit(self.peek(1)) {
            let save_out: usize = self.out.len();
            let save_pos: usize = self.pos;
            let save_brp: usize = self.brp;
            let mut qlen: usize = self.decode_number()? / 10;
            self.pos = save_pos;
            if self.pos > 0 {
                self.pos -= 1;
            }
            let mut p: usize = self.pos;
            while qlen > 0 {
                if self.parse_qualified_name().is_some() && self.pos == p + qlen {
                    return Some(());
                }
                qlen /= 10;
                if p == 0 {
                    break;
                }
                p -= 1;
                self.pos = p;
                self.out.truncate(save_out);
                self.brp = save_brp;
            }
            self.pos = save_pos;
            self.out.truncate(save_out);
            self.brp = save_brp;
        }
        self.parse_qualified_name()
    }

    fn may_be_mangled_name_arg(&self) -> bool {
        let mut p: usize = self.pos;
        if is_digit(self.buf.get(p).copied().unwrap_or(0)) {
            let mut n: usize = 0;
            while p < self.buf.len() && is_digit(self.buf[p]) {
                n = match n
                    .checked_mul(10)
                    .and_then(|v: usize| v.checked_add(usize::from(self.buf[p] - b'0')))
                {
                    Some(v) => v,
                    None => return false,
                };
                p += 1;
            }
            self.buf.get(p) == Some(&b'_') && self.buf.get(p + 1) == Some(&b'D') && n >= 4
        } else {
            self.buf.get(p) == Some(&b'_') && self.buf.get(p + 1) == Some(&b'D')
        }
    }

    fn parse_mangled_name_arg(&mut self) -> Option<()> {
        let consume: usize = if is_digit(self.front()) {
            self.decode_number()?
        } else {
            0
        };
        self.parse_mangled_name(false, consume)
    }

    fn parse_function_type_no_return(&mut self, keep_attr: bool) -> Option<(String, usize)> {
        let prev_pos: usize = self.pos;
        let prev_out: usize = self.out.len();
        let prev_brp: usize = self.brp;

        if self.front() == b'M' {
            self.pop()?;
            let mods: u16 = self.parse_modifier();
            if keep_attr {
                self.put(&type_ctors_text(mods))?;
            }
        }
        if is_call_convention(self.front()) {
            let mut err: bool = false;
            self.parse_call_convention(&mut err);
            if !err {
                let attributes: u16 = self.parse_func_attr(&mut err);
                if !err {
                    if keep_attr {
                        self.put(&func_attrs_text(attributes))?;
                    }
                    let attr: String = if keep_attr {
                        self.out[prev_out..].to_owned()
                    } else {
                        String::new()
                    };
                    self.put_char('(')?;
                    if self.parse_func_arguments().is_some() {
                        self.put_char(')')?;
                        return Some((attr, prev_out));
                    }
                }
            }
            self.pos = prev_pos;
            self.out.truncate(prev_out);
            self.brp = prev_brp;
        }
        Some((String::new(), prev_out))
    }

    fn parse_mangled_name(&mut self, display_type: bool, limit: usize) -> Option<()> {
        self.enter()?;
        let r: Option<()> = self.parse_mangled_name_inner(display_type, limit);
        self.leave();
        r
    }

    fn parse_mangled_name_inner(&mut self, display_type: bool, limit: usize) -> Option<()> {
        let end: usize = self.pos.saturating_add(limit);
        self.match_char(b'_');
        if !self.match_char(b'D') {
            return None;
        }
        loop {
            let beg: usize = self.out.len();
            let mut attr_len: usize = 0;
            let mut attr_start: usize = beg;
            loop {
                if attr_len != 0 {
                    let attr_end: usize = attr_start + attr_len;
                    if attr_end <= self.out.len()
                        && self.out.is_char_boundary(attr_start)
                        && self.out.is_char_boundary(attr_end)
                    {
                        self.out.replace_range(attr_start..attr_end, "");
                    }
                }
                if beg != self.out.len() {
                    self.put_char('.')?;
                }
                self.parse_symbol_name()?;
                let (attr, start): (String, usize) =
                    self.parse_function_type_no_return(display_type)?;
                attr_len = attr.len();
                attr_start = start;
                match self.is_symbol_name_front() {
                    None => return None,
                    Some(false) => break,
                    Some(true) => {}
                }
            }
            let name_beg: usize = if display_type && attr_len != 0 {
                let attr_end: usize = attr_start + attr_len;
                self.shift_to_front(attr_start, attr_end);
                beg + attr_len
            } else {
                beg
            };
            let name_end: usize = self.out.len();
            if self.front() == b'M' {
                self.pop()?;
            }
            if display_type && self.top_qualified.is_none() && name_end <= self.out.len() {
                let name_with_args: &str = &self.out[name_beg..name_end];
                let (qual, params): (String, Option<String>) =
                    split_name_and_params(name_with_args);
                self.top_qualified = Some(qual);
                self.top_params = params;
            }
            let last_len: usize = self.out.len();
            self.parse_type()?;
            if display_type {
                if self.out.len() > last_len {
                    self.put_char(' ')?;
                }
                self.shift_to_end(name_beg, name_end);
            } else {
                self.out.truncate(last_len);
            }
            if self.pos >= self.buf.len() || (limit != 0 && self.pos >= end) {
                return Some(());
            }
            match self.front() {
                b'T' | b'V' | b'S' | b'Z' => return Some(()),
                _ => {}
            }
            self.put_char('.')?;
        }
    }

    fn shift_to_front(&mut self, start: usize, end: usize) {
        if start >= end
            || end > self.out.len()
            || !self.out.is_char_boundary(start)
            || !self.out.is_char_boundary(end)
        {
            return;
        }
        let chunk: String = self.out[start..end].to_owned();
        self.out.replace_range(start..end, "");
        self.out.insert_str(0, &chunk);
    }

    fn shift_to_end(&mut self, start: usize, end: usize) {
        if start >= end
            || end > self.out.len()
            || !self.out.is_char_boundary(start)
            || !self.out.is_char_boundary(end)
        {
            return;
        }
        let chunk: String = self.out[start..end].to_owned();
        self.out.replace_range(start..end, "");
        self.out.push_str(&chunk);
    }

    fn parse_type(&mut self) -> Option<()> {
        self.enter()?;
        let r: Option<()> = self.parse_type_inner();
        self.leave();
        r
    }

    fn parse_type_inner(&mut self) -> Option<()> {
        let t: u8 = self.front();
        match t {
            b'Q' => self.parse_backref_type(false),
            b'O' => {
                self.pop()?;
                self.put("shared(")?;
                self.parse_type()?;
                self.put_char(')')
            }
            b'x' => {
                self.pop()?;
                self.put("const(")?;
                self.parse_type()?;
                self.put_char(')')
            }
            b'y' => {
                self.pop()?;
                self.put("immutable(")?;
                self.parse_type()?;
                self.put_char(')')
            }
            b'N' => {
                self.pop()?;
                match self.front() {
                    b'n' => {
                        self.pop()?;
                        self.put("noreturn")
                    }
                    b'g' => {
                        self.pop()?;
                        self.put("inout(")?;
                        self.parse_type()?;
                        self.put_char(')')
                    }
                    b'h' => {
                        self.pop()?;
                        self.put("__vector(")?;
                        self.parse_type()?;
                        self.put_char(')')
                    }
                    _ => None,
                }
            }
            b'A' => {
                self.pop()?;
                self.parse_type()?;
                self.put("[]")
            }
            b'G' => {
                self.pop()?;
                let num: Vec<u8> = self.slice_number().to_vec();
                self.parse_type()?;
                self.put_char('[')?;
                self.put(std::str::from_utf8(&num).ok()?)?;
                self.put_char(']')
            }
            b'H' => {
                self.pop()?;
                let key_beg: usize = self.out.len();
                self.parse_type()?;
                let key: String = self.out.split_off(key_beg);
                self.parse_type()?;
                self.put_char('[')?;
                self.put(&key)?;
                self.put_char(']')
            }
            b'P' => {
                self.pop()?;
                self.parse_type()?;
                self.put_char('*')
            }
            b'F' | b'U' | b'W' | b'V' | b'R' => self.parse_type_function(IsDelegate::No),
            b'C' | b'S' | b'E' | b'T' | b'I' => {
                self.pop()?;
                self.parse_qualified_name()
            }
            b'D' => {
                self.pop()?;
                let mods: u16 = self.parse_modifier();
                if self.front() == b'Q' {
                    self.parse_backref_type(true)?;
                } else {
                    self.parse_type_function(IsDelegate::Yes)?;
                }
                self.emit_type_ctors_suffix(mods)
            }
            b'n' | b'B' | b'Z' => {
                self.pop()?;
                Some(())
            }
            b'a'..=b'w' => {
                self.pop()?;
                let prim: &str = PRIMITIVES[(t - b'a') as usize]?;
                self.put(prim)
            }
            b'z' => {
                self.pop()?;
                match self.front() {
                    b'i' => {
                        self.pop()?;
                        self.put("cent")
                    }
                    b'k' => {
                        self.pop()?;
                        self.put("ucent")
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn parse_backref_type(&mut self, delegate: bool) -> Option<()> {
        if self.pos == self.brp {
            return None;
        }
        let ref_pos: usize = self.pos;
        self.pop()?;
        let n: usize = self.decode_backref();
        if n == 0 || n > self.pos {
            return None;
        }
        let save_pos: usize = self.pos;
        let save_brp: usize = self.brp;
        self.pos = ref_pos - n;
        self.brp = ref_pos;
        let r: Option<()> = if delegate {
            self.parse_type_function(IsDelegate::Yes)
        } else {
            self.parse_type()
        };
        self.pos = save_pos;
        self.brp = save_brp;
        r
    }

    fn parse_call_convention(&mut self, err: &mut bool) {
        match self.front() {
            b'F' => {
                self.pos += 1;
            }
            b'U' => {
                self.pos += 1;
                let _ = self.put("extern (C) ");
            }
            b'W' => {
                self.pos += 1;
                let _ = self.put("extern (Windows) ");
            }
            b'R' => {
                self.pos += 1;
                let _ = self.put("extern (C++) ");
            }
            _ => *err = true,
        }
    }

    fn parse_modifier(&mut self) -> u16 {
        match self.front() {
            b'y' => {
                self.pos += 1;
                TC_IMMUTABLE
            }
            b'O' => {
                self.pos += 1;
                let mut res: u16 = TC_SHARED;
                if self.front() == b'x' {
                    self.pos += 1;
                    res |= TC_CONST;
                } else if self.front() == b'N' && self.peek(1) == b'g' {
                    self.pos += 2;
                    res |= TC_INOUT;
                    if self.front() == b'x' {
                        self.pos += 1;
                        res |= TC_CONST;
                    }
                }
                res
            }
            b'N' => {
                if self.peek(1) != b'g' {
                    return TC_NONE;
                }
                self.pos += 2;
                let mut res: u16 = TC_INOUT;
                if self.front() == b'x' {
                    self.pos += 1;
                    res |= TC_CONST;
                }
                res
            }
            b'x' => {
                self.pos += 1;
                TC_CONST
            }
            _ => TC_NONE,
        }
    }

    fn parse_func_attr(&mut self, err: &mut bool) -> u16 {
        let mut result: u16 = 0;
        while self.front() == b'N' {
            self.pos += 1;
            match self.front() {
                b'a' => {
                    self.pos += 1;
                    result |= FA_PURE;
                }
                b'b' => {
                    self.pos += 1;
                    result |= FA_NOTHROW;
                }
                b'c' => {
                    self.pos += 1;
                    result |= FA_REF;
                }
                b'd' => {
                    self.pos += 1;
                    result |= FA_PROPERTY;
                }
                b'e' => {
                    self.pos += 1;
                    result |= FA_TRUSTED;
                }
                b'f' => {
                    self.pos += 1;
                    result |= FA_SAFE;
                }
                b'g' | b'h' | b'k' | b'n' => {
                    self.pos -= 1;
                    return result;
                }
                b'i' => {
                    self.pos += 1;
                    result |= FA_NOGC;
                }
                b'j' => {
                    self.pos += 1;
                    if self.peek(0) == b'N' && self.peek(1) == b'l' {
                        result |= FA_RETURN_SCOPE;
                        self.pos += 2;
                    } else {
                        result |= FA_RETURN;
                    }
                }
                b'l' => {
                    self.pos += 1;
                    if self.peek(0) == b'N' && self.peek(1) == b'j' {
                        result |= FA_SCOPE_RETURN;
                        self.pos += 2;
                    } else {
                        result |= FA_SCOPE;
                    }
                }
                b'm' => {
                    self.pos += 1;
                    result |= FA_LIVE;
                }
                _ => {
                    *err = true;
                    return 0;
                }
            }
        }
        result
    }

    fn parse_func_arguments(&mut self) -> Option<()> {
        let mut n: usize = 0;
        loop {
            match self.front() {
                b'X' => {
                    self.pop()?;
                    return self.put("...");
                }
                b'Y' => {
                    self.pop()?;
                    return self.put(", ...");
                }
                b'Z' => {
                    self.pop()?;
                    return Some(());
                }
                _ => {}
            }
            self.put_comma(n)?;
            n += 1;

            let mut npops: usize = 0;
            if self.front() == b'M' && self.peek(1) == b'N' && self.peek(2) == b'k' {
                let c3: u8 = self.peek(3);
                if c3 == b'J' {
                    self.put("scope return out ")?;
                    npops = 4;
                } else if c3 == b'K' {
                    self.put("scope return ref ")?;
                    npops = 4;
                }
            } else if self.front() == b'N' && self.peek(1) == b'k' {
                let c2: u8 = self.peek(2);
                if c2 == b'J' {
                    self.put("return out ")?;
                    npops = 3;
                } else if c2 == b'K' {
                    self.put("return ref ")?;
                    npops = 3;
                } else if c2 == b'M' {
                    let c3: u8 = self.peek(3);
                    if c3 == b'J' {
                        self.put("return scope out ")?;
                        npops = 4;
                    } else if c3 == b'K' {
                        self.put("return scope ref ")?;
                        npops = 4;
                    } else {
                        self.put("return scope ")?;
                        npops = 3;
                    }
                }
            }
            self.pop_n(npops)?;

            if self.front() == b'M' {
                self.pop()?;
                self.put("scope ")?;
            }
            if self.front() == b'N' {
                self.pop()?;
                if self.front() == b'k' {
                    self.pop()?;
                    self.put("return ")?;
                } else {
                    self.pos -= 1;
                }
            }

            match self.front() {
                b'I' => {
                    self.pop()?;
                    self.put("in ")?;
                    if self.front() == b'K' {
                        self.pop()?;
                        self.put("ref ")?;
                    }
                    self.parse_type()?;
                }
                b'K' => {
                    self.pop()?;
                    self.put("ref ")?;
                    self.parse_type()?;
                }
                b'J' => {
                    self.pop()?;
                    self.put("out ")?;
                    self.parse_type()?;
                }
                b'L' => {
                    self.pop()?;
                    self.put("lazy ")?;
                    self.parse_type()?;
                }
                _ => {
                    self.parse_type()?;
                }
            }
        }
    }

    fn parse_type_function(&mut self, isdg: IsDelegate) -> Option<()> {
        self.enter()?;
        let r: Option<()> = self.parse_type_function_inner(isdg);
        self.leave();
        r
    }

    fn parse_type_function_inner(&mut self, isdg: IsDelegate) -> Option<()> {
        let beg: usize = self.out.len();
        let mut err: bool = false;
        self.parse_call_convention(&mut err);
        if err {
            return None;
        }
        let attributes: u16 = self.parse_func_attr(&mut err);
        if err {
            return None;
        }
        let argbeg: usize = self.out.len();
        self.put(if isdg == IsDelegate::Yes {
            "delegate"
        } else {
            "function"
        })?;
        self.put_char('(')?;
        self.parse_func_arguments()?;
        self.put_char(')')?;
        self.emit_func_attrs_suffix(attributes)?;

        let retbeg: usize = self.out.len();
        self.parse_type()?;
        self.put_char(' ')?;
        self.shift_range(argbeg, retbeg);
        let _ = beg;
        Some(())
    }

    fn shift_range(&mut self, from: usize, to: usize) {
        if from > to || to > self.out.len() {
            return;
        }
        if !self.out.is_char_boundary(from) || !self.out.is_char_boundary(to) {
            return;
        }
        let middle: String = self.out[from..to].to_owned();
        let tail: String = self.out[to..].to_owned();
        self.out.truncate(from);
        self.out.push_str(&tail);
        self.out.push_str(&middle);
    }

    fn parse_value(&mut self, name: &str, type_char: u8) -> Option<()> {
        self.enter()?;
        let r: Option<()> = self.parse_value_inner(name, type_char);
        self.leave();
        r
    }

    fn parse_value_inner(&mut self, name: &str, type_char: u8) -> Option<()> {
        match self.front() {
            b'n' => {
                self.pop()?;
                self.put("null")
            }
            b'i' => {
                self.pop()?;
                if !is_digit(self.front()) {
                    return None;
                }
                self.parse_integer_value(type_char)
            }
            b'0'..=b'9' => self.parse_integer_value(type_char),
            b'N' => {
                self.pop()?;
                self.put_char('-')?;
                self.parse_integer_value(type_char)
            }
            b'e' => {
                self.pop()?;
                self.parse_real()
            }
            b'c' => {
                self.pop()?;
                self.parse_real()?;
                self.put_char('+')?;
                if !self.match_char(b'c') {
                    return None;
                }
                self.parse_real()?;
                self.put_char('i')
            }
            b'a' | b'w' | b'd' => self.parse_string_value(),
            b'A' => {
                if type_char == b'H' {
                    return self.parse_assoc_array_value();
                }
                self.pop()?;
                self.put_char('[')?;
                let n: usize = self.decode_number()?;
                for i in 0..n {
                    self.put_comma(i)?;
                    self.parse_value("", 0)?;
                }
                self.put_char(']')
            }
            b'H' => self.parse_assoc_array_value(),
            b'S' => {
                self.pop()?;
                if !name.is_empty() {
                    self.put(name)?;
                }
                self.put_char('(')?;
                let n: usize = self.decode_number()?;
                for i in 0..n {
                    self.put_comma(i)?;
                    self.parse_value("", 0)?;
                }
                self.put_char(')')
            }
            b'f' => {
                self.pop()?;
                self.parse_mangled_name(false, 1)
            }
            _ => None,
        }
    }

    fn parse_assoc_array_value(&mut self) -> Option<()> {
        self.pop()?;
        self.put_char('[')?;
        let n: usize = self.decode_number()?;
        for i in 0..n {
            self.put_comma(i)?;
            self.parse_value("", 0)?;
            self.put_char(':')?;
            self.parse_value("", 0)?;
        }
        self.put_char(']')
    }

    fn parse_string_value(&mut self) -> Option<()> {
        let width: u8 = self.front();
        self.pop()?;
        let n: usize = self.decode_number()?;
        if !self.match_char(b'_') {
            return None;
        }
        self.put_char('"')?;
        for _ in 0..n {
            let high: u8 = ascii_hex(self.front())?;
            self.pop()?;
            let low: u8 = ascii_hex(self.front())?;
            self.pop()?;
            let byte: u8 = (high << 4) | low;
            if (b' '..=b'~').contains(&byte) {
                self.put_char(byte as char)?;
            } else {
                self.put("\\x")?;
                self.put(&format!("{byte:02x}"))?;
            }
        }
        self.put_char('"')?;
        if width != b'a' {
            self.put_char(width as char)?;
        }
        Some(())
    }

    fn parse_integer_value(&mut self, type_char: u8) -> Option<()> {
        match type_char {
            b'b' => {
                let num: usize = self.decode_number()?;
                self.put(if num == 0 { "false" } else { "true" })
            }
            b'a' | b'u' | b'w' => {
                let num: usize = self.decode_number()?;
                if let Some(escaped) = char_value_escape(num) {
                    return self.put(escaped);
                }
                match type_char {
                    b'a' => {
                        if (0x20..0x7f).contains(&num) {
                            self.put_char('\'')?;
                            self.put_char(num as u8 as char)?;
                            return self.put_char('\'');
                        }
                        self.put("\\x")?;
                        self.put(&format!("{num:02x}"))
                    }
                    b'u' => {
                        self.put("'\\u")?;
                        self.put(&format!("{num:04x}"))?;
                        self.put_char('\'')
                    }
                    _ => {
                        self.put("'\\U")?;
                        self.put(&format!("{num:08x}"))?;
                        self.put_char('\'')
                    }
                }
            }
            b'h' | b't' | b'k' => {
                let num: Vec<u8> = self.slice_number().to_vec();
                if num.is_empty() {
                    return None;
                }
                self.put(std::str::from_utf8(&num).ok()?)?;
                self.put_char('u')
            }
            b'l' => {
                let num: Vec<u8> = self.slice_number().to_vec();
                if num.is_empty() {
                    return None;
                }
                self.put(std::str::from_utf8(&num).ok()?)?;
                self.put_char('L')
            }
            b'm' => {
                let num: Vec<u8> = self.slice_number().to_vec();
                if num.is_empty() {
                    return None;
                }
                self.put(std::str::from_utf8(&num).ok()?)?;
                self.put("uL")
            }
            _ => {
                let num: Vec<u8> = self.slice_number().to_vec();
                if num.is_empty() {
                    return None;
                }
                let s: &str = std::str::from_utf8(&num).ok()?;
                self.put(s)
            }
        }
    }

    fn parse_real(&mut self) -> Option<()> {
        if self.match_str(b"INF") {
            return self.put("real.infinity");
        }
        if self.match_str(b"NINF") {
            return self.put("-real.infinity");
        }
        if self.match_str(b"NAN") {
            return self.put("real.nan");
        }
        let negative: bool = self.match_char(b'N');
        if !self.front().is_ascii_hexdigit() {
            return None;
        }
        let beg: usize = self.pos;
        while self.front().is_ascii_hexdigit() {
            self.pos += 1;
        }
        let mantissa: &str = std::str::from_utf8(&self.buf[beg..self.pos]).ok()?;
        let lead: &str = mantissa.get(..1)?;
        let frac: &str = mantissa.get(1..)?;
        let sign: &str = if negative { "-" } else { "" };
        if self.match_char(b'P') {
            let exp_neg: bool = self.match_char(b'N');
            let exp_beg: usize = self.pos;
            while is_digit(self.front()) {
                self.pos += 1;
            }
            let exp: &str = std::str::from_utf8(&self.buf[exp_beg..self.pos]).ok()?;
            let esign: &str = if exp_neg { "-" } else { "" };
            return self.put(&format!("{sign}0x{lead}.{frac}p{esign}{exp}"));
        }
        self.put(&format!("{sign}0x{lead}.{frac}"))
    }

    fn put_comma(&mut self, n: usize) -> Option<()> {
        if n != 0 {
            self.put(", ")?;
        }
        Some(())
    }

    fn emit_func_attrs_suffix(&mut self, attrs: u16) -> Option<()> {
        for (flag, name) in FUNC_ATTR_NAMES {
            if attrs & flag != 0 {
                self.put_char(' ')?;
                self.put(name)?;
            }
        }
        Some(())
    }

    fn emit_type_ctors_suffix(&mut self, mods: u16) -> Option<()> {
        for (flag, name) in TYPE_CTOR_NAMES {
            if mods & flag != 0 {
                self.put_char(' ')?;
                self.put(name)?;
            }
        }
        Some(())
    }
}

const TC_NONE: u16 = 0;
const TC_CONST: u16 = 1 << 0;
const TC_IMMUTABLE: u16 = 1 << 1;
const TC_SHARED: u16 = 1 << 2;
const TC_INOUT: u16 = 1 << 3;

const TYPE_CTOR_NAMES: [(u16, &str); 4] = [
    (TC_IMMUTABLE, "immutable"),
    (TC_INOUT, "inout"),
    (TC_SHARED, "shared"),
    (TC_CONST, "const"),
];

const FA_PURE: u16 = 1 << 0;
const FA_NOTHROW: u16 = 1 << 1;
const FA_REF: u16 = 1 << 2;
const FA_PROPERTY: u16 = 1 << 3;
const FA_TRUSTED: u16 = 1 << 4;
const FA_SAFE: u16 = 1 << 5;
const FA_NOGC: u16 = 1 << 6;
const FA_RETURN: u16 = 1 << 7;
const FA_SCOPE: u16 = 1 << 8;
const FA_LIVE: u16 = 1 << 9;
const FA_RETURN_SCOPE: u16 = 1 << 10;
const FA_SCOPE_RETURN: u16 = 1 << 11;

const FUNC_ATTR_NAMES: [(u16, &str); 12] = [
    (FA_PURE, "pure"),
    (FA_NOTHROW, "nothrow"),
    (FA_REF, "ref"),
    (FA_PROPERTY, "@property"),
    (FA_NOGC, "@nogc"),
    (FA_RETURN, "return"),
    (FA_SCOPE, "scope"),
    (FA_RETURN_SCOPE, "return scope"),
    (FA_SCOPE_RETURN, "scope return"),
    (FA_LIVE, "@live"),
    (FA_TRUSTED, "@trusted"),
    (FA_SAFE, "@safe"),
];

const fn is_call_convention(ch: u8) -> bool {
    matches!(ch, b'F' | b'U' | b'V' | b'W' | b'R')
}

fn func_attrs_text(attrs: u16) -> String {
    let mut out: String = String::new();
    for (flag, name) in FUNC_ATTR_NAMES {
        if attrs & flag != 0 {
            out.push_str(name);
            out.push(' ');
        }
    }
    out
}

fn type_ctors_text(mods: u16) -> String {
    let mut out: String = String::new();
    for (flag, name) in TYPE_CTOR_NAMES {
        if mods & flag != 0 {
            out.push_str(name);
            out.push(' ');
        }
    }
    out
}

const fn char_value_escape(num: usize) -> Option<&'static str> {
    match num {
        0x27 => Some("'\\''"),
        0x5c => Some("'\\\\'"),
        0x07 => Some("'\\a'"),
        0x08 => Some("'\\b'"),
        0x0c => Some("'\\f'"),
        0x0a => Some("'\\n'"),
        0x0d => Some("'\\r'"),
        0x09 => Some("'\\t'"),
        0x0b => Some("'\\v'"),
        _ => None,
    }
}

const fn ascii_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DResult {
    pub demangled: String,
    pub qualified: String,
    pub params: Vec<String>,
}

fn split_name_and_params(name_with_args: &str) -> (String, Option<String>) {
    let bytes: &[u8] = name_with_args.as_bytes();
    let mut depth: i32 = 0;
    let mut last_open: Option<usize> = None;
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'!' if bytes.get(i + 1) == Some(&b'(') => {
                let mut d: i32 = 1;
                i += 2;
                while i < bytes.len() && d > 0 {
                    match bytes[i] {
                        b'(' => d += 1,
                        b')' => d -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                continue;
            }
            b'(' => {
                if depth == 0 {
                    last_open = Some(i);
                }
                depth += 1;
            }
            b')' => depth = (depth - 1).max(0),
            _ => {}
        }
        i += 1;
    }
    last_open.map_or_else(
        || (name_with_args.to_owned(), None),
        |idx: usize| {
            let qual: String = name_with_args[..idx].to_owned();
            let params: &str = name_with_args[idx..]
                .strip_prefix('(')
                .and_then(|s: &str| s.strip_suffix(')'))
                .unwrap_or("");
            (qual, Some(params.to_owned()))
        },
    )
}

#[must_use]
pub(crate) fn demangle_d_result(mangled: &str) -> Option<DResult> {
    if !mangled.starts_with("_D") {
        return None;
    }
    let mut d: Demangler<'_> = Demangler::new(mangled.as_bytes());
    d.parse_mangled_name(true, 0)?;
    if d.pos < d.buf.len() {
        return None;
    }
    if d.out.is_empty() {
        return None;
    }
    let qualified: String = d.top_qualified.unwrap_or_else(|| d.out.clone());
    let params: Vec<String> = d
        .top_params
        .as_deref()
        .map(split_top_level_commas)
        .unwrap_or_default();
    Some(DResult {
        demangled: d.out,
        qualified,
        params,
    })
}

fn split_top_level_commas(inner: &str) -> Vec<String> {
    if inner.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut depth: i32 = 0;
    let mut start: usize = 0;
    let bytes: &[u8] = inner.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = (depth - 1).max(0),
            b',' if depth == 0 => {
                let seg: &str = inner[start..i].trim();
                if !seg.is_empty() {
                    out.push(seg.to_owned());
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail: &str = inner[start..].trim();
    if !tail.is_empty() {
        out.push(tail.to_owned());
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn dm(s: &str) -> String {
        let Some(r): Option<DResult> = demangle_d_result(s) else {
            panic!("failed to demangle {s}");
        };
        r.demangled
    }

    #[test]
    fn member_function_with_return_and_param() {
        assert_eq!(
            dm("_D5hello7Greeter3fibMFlZl"),
            "long hello.Greeter.fib(long)"
        );
    }

    #[test]
    fn nested_module_checkedint_template_with_backrefs() {
        assert_eq!(
            dm("_D4core10checkedint__T4adduZQgFNaNbNiNfmmKbZm"),
            "pure nothrow @nogc @safe ulong core.checkedint.addu!().addu(ulong, ulong, ref bool)"
        );
    }

    #[test]
    fn template_instance_with_type_arg_and_backref_param() {
        assert_eq!(
            dm("_D3std3utf__T6strideTAaZQlFNaNfQkZk"),
            "pure @safe uint std.utf.stride!(char[]).stride(char[])"
        );
    }

    #[test]
    fn internal_init_symbol() {
        assert_eq!(
            dm("_D3std3utf12UTFException6__initZ"),
            "std.utf.UTFException.__init"
        );
    }

    #[test]
    fn primitive_function() {
        assert_eq!(
            dm("_D3std3utf10strideImplFNaNeamZk"),
            "pure @trusted uint std.utf.strideImpl(char, ulong)"
        );
    }

    #[test]
    fn rejects_non_d() {
        assert!(demangle_d_result("main").is_none());
        assert!(demangle_d_result("_ZN5hello3fibE3int").is_none());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn wide_character_literal_does_not_truncate_to_scalar() {
        let mut d: Demangler<'_> = Demangler::new(b"4294967329");
        assert!(d.parse_integer_value(b'a').is_some());
        assert_eq!(d.out, "\\x100000021");
    }
}
