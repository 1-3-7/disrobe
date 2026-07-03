use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbOpcode {
    Move,
    LoadK,
    LoadBool,
    LoadBoolC,
    LoadNil,
    GetGlobal,
    GetUpval,
    SetUpval,
    GetTable,
    SetGlobal,
    SetTable,
    NewTable,
    Self_,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Unm,
    Not,
    Len,
    Concat,
    Jmp,
    Eq,
    Lt,
    Le,
    Compare(CmpForm),
    Test,
    TestC,
    Call(CallForm),
    TailCall,
    Return(RetForm),
    ForLoop,
    ForPrep,
    TForLoop,
    SetList,
    Closure,
    ClosureNu,
    Vararg,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallForm {
    pub b: ArgForm,
    pub c: RetCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmpForm {
    pub op: CmpOp,
    pub jump_when_true: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    #[must_use]
    pub const fn lua_symbol(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "~=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgForm {
    Fixed,
    Two,
    None,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetCount {
    Fixed,
    None,
    Top,
    One,
    Single,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetForm {
    Fixed,
    Two,
    Three,
    None,
    Top,
}

impl IbOpcode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Move => "Move",
            Self::LoadK => "LoadK",
            Self::LoadBool => "LoadBool",
            Self::LoadBoolC => "LoadBoolC",
            Self::LoadNil => "LoadNil",
            Self::GetGlobal => "GetGlobal",
            Self::GetUpval => "GetUpval",
            Self::SetUpval => "SetUpval",
            Self::GetTable => "GetTable",
            Self::SetGlobal => "SetGlobal",
            Self::SetTable => "SetTable",
            Self::NewTable => "NewTable",
            Self::Self_ => "Self",
            Self::Add => "Add",
            Self::Sub => "Sub",
            Self::Mul => "Mul",
            Self::Div => "Div",
            Self::Mod => "Mod",
            Self::Pow => "Pow",
            Self::Unm => "Unm",
            Self::Not => "Not",
            Self::Len => "Len",
            Self::Concat => "Concat",
            Self::Jmp => "Jmp",
            Self::Eq => "Eq",
            Self::Lt => "Lt",
            Self::Le => "Le",
            Self::Compare(_) => "Compare",
            Self::Test => "Test",
            Self::TestC => "TestC",
            Self::Call(_) => "Call",
            Self::TailCall => "TailCall",
            Self::Return(_) => "Return",
            Self::ForLoop => "ForLoop",
            Self::ForPrep => "ForPrep",
            Self::TForLoop => "TForLoop",
            Self::SetList => "SetList",
            Self::Closure => "Closure",
            Self::ClosureNu => "ClosureNU",
            Self::Vararg => "Vararg",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tk {
    Num,
    Name,
    Op,
    Str,
}

#[derive(Debug, Clone)]
struct Token {
    kind: Tk,
    text: String,
}

fn tokenize(src: &str) -> Vec<Token> {
    let bytes: &[u8] = src.as_bytes();
    let mut out: Vec<Token> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' {
            let quote: u8 = b;
            let start: usize = i;
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if i < bytes.len() {
                i += 1;
            }
            out.push(Token {
                kind: Tk::Str,
                text: src[start..i.min(src.len())].to_owned(),
            });
            continue;
        }
        if b.is_ascii_digit() {
            let start: usize = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            out.push(Token {
                kind: Tk::Num,
                text: src[start..i].to_owned(),
            });
            continue;
        }
        if b == b'_' || b.is_ascii_alphabetic() {
            let start: usize = i;
            while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            out.push(Token {
                kind: Tk::Name,
                text: src[start..i].to_owned(),
            });
            continue;
        }
        let two: &str = if i + 2 <= src.len() {
            &src[i..i + 2]
        } else {
            ""
        };
        if matches!(two, "<=" | ">=" | "==" | "~=" | "..") {
            out.push(Token {
                kind: Tk::Op,
                text: two.to_owned(),
            });
            i += 2;
            continue;
        }
        out.push(Token {
            kind: Tk::Op,
            text: src[i..=i].to_owned(),
        });
        i += 1;
    }
    out
}

struct LoopInfo {
    dispatch_start: usize,
    inst_var: String,
    ip_var: String,
    enum_var: String,
}

#[allow(clippy::expect_used)]
fn find_wrap_vars(body: &str) -> (Option<String>, Option<String>) {
    let re_call: Regex = Regex::new(r"(\w+)\(\w+\(\),\{\s*\},\w+\(\)\)").expect("wrap call regex");
    let Some(call): Option<regex::Captures<'_>> = re_call.captures(body) else {
        return (None, None);
    };
    let wrap_name: String = call
        .get(1)
        .map_or(String::new(), |m: regex::Match<'_>| m.as_str().to_owned());
    let patterns: [String; 3] = [
        format!(
            r"function\s+{}\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)",
            regex::escape(&wrap_name)
        ),
        format!(
            r"{}\s*=\s*function\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)",
            regex::escape(&wrap_name)
        ),
        r"function\s+\w+\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)".to_owned(),
    ];
    for pat in &patterns {
        let Ok(sig_re) = Regex::new(pat.as_str()) else {
            continue;
        };
        for caps in sig_re.captures_iter(body) {
            let upvalues: String = caps
                .get(2)
                .map_or(String::new(), |m: regex::Match<'_>| m.as_str().to_owned());
            let env: String = caps
                .get(3)
                .map_or(String::new(), |m: regex::Match<'_>| m.as_str().to_owned());
            if !upvalues.is_empty() && !env.is_empty() {
                return (Some(upvalues), Some(env));
            }
        }
    }
    (None, None)
}

fn find_loop(t: &[Token]) -> Option<LoopInfo> {
    let n: usize = t.len();
    let mut i: usize = 0;
    while i + 14 < n {
        if t[i].text == "while" && t[i + 1].text == "true" && t[i + 2].text == "do" {
            let j: usize = i + 3;
            let inst_fetch: bool = t[j].kind == Tk::Name
                && t[j + 1].text == "="
                && t[j + 2].kind == Tk::Name
                && t[j + 3].text == "["
                && t[j + 4].kind == Tk::Name
                && t[j + 5].text == "]"
                && t[j + 6].text == ";";
            if inst_fetch {
                let inst_var: String = t[j].text.clone();
                let ip_var: String = t[j + 4].text.clone();
                let ai: usize = j + 7;
                let enum_fetch: bool = t[ai].kind == Tk::Name
                    && t[ai + 1].text == "="
                    && t[ai + 2].text == inst_var
                    && t[ai + 3].text == "["
                    && t[ai + 4].text == "1"
                    && t[ai + 5].text == "]"
                    && t[ai + 6].text == ";";
                if enum_fetch {
                    return Some(LoopInfo {
                        dispatch_start: ai + 7,
                        inst_var,
                        ip_var,
                        enum_var: t[ai].text.clone(),
                    });
                }
            }
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone, Copy)]
struct Constraint {
    relop: u8,
    num: i64,
    truth: bool,
}

struct Walker<'a> {
    t: &'a [Token],
    enum_var: &'a str,
    i: usize,
    end: usize,
    leaves: Vec<(Vec<Constraint>, usize, usize)>,
    steps: usize,
}

impl Walker<'_> {
    fn at(&self, k: usize) -> &str {
        self.t
            .get(self.i + k)
            .map_or("", |tok: &Token| tok.text.as_str())
    }
    fn skip_semis(&mut self) {
        while self.i < self.t.len() && self.t[self.i].text == ";" {
            self.i += 1;
        }
    }
    fn enum_cond(&self) -> Option<(u8, i64, usize)> {
        let head: &str = self.at(0);
        if head != "if" && head != "elseif" {
            return None;
        }
        let mut k: usize = self.i + 1;
        let mut paren: bool = false;
        if self.t.get(k).map(|x: &Token| x.text.as_str()) == Some("(") {
            paren = true;
            k += 1;
        }
        if self.t.get(k).map(|x: &Token| x.text.as_str()) != Some(self.enum_var) {
            return None;
        }
        let relop_text: &str = self.t.get(k + 1).map_or("", |x: &Token| x.text.as_str());
        let relop: u8 = match relop_text {
            "<=" => 0,
            "<" => 1,
            ">" => 2,
            ">=" => 3,
            "==" => 4,
            _ => return None,
        };
        let num_tok: &Token = self.t.get(k + 2)?;
        if num_tok.kind != Tk::Num {
            return None;
        }
        let num: i64 = num_tok.text.parse::<i64>().ok()?;
        k += 3;
        if paren {
            if self.t.get(k).map(|x: &Token| x.text.as_str()) != Some(")") {
                return None;
            }
            k += 1;
        }
        if self.t.get(k).map(|x: &Token| x.text.as_str()) != Some("then") {
            return None;
        }
        Some((relop, num, k + 1))
    }
    fn block_terminator(&self, start: usize) -> usize {
        let mut depth: i64 = 0;
        let mut i: usize = start;
        let mut pending_do: bool = false;
        while i < self.end {
            let v: &str = self.t[i].text.as_str();
            match v {
                "for" | "while" => {
                    depth += 1;
                    pending_do = true;
                }
                "if" | "function" => depth += 1,
                "do" => {
                    if pending_do {
                        pending_do = false;
                    } else {
                        depth += 1;
                    }
                }
                "end" => {
                    if depth == 0 {
                        return i;
                    }
                    depth -= 1;
                }
                "else" | "elseif" if depth == 0 => return i,
                _ => {}
            }
            i += 1;
        }
        self.end
    }
    fn parse(&mut self, constraints: &[Constraint]) -> Result<()> {
        self.steps += 1;
        if self.steps > 1 << 20 {
            return Err(Error::BootstrapEmulationFailed("dispatch walk runaway"));
        }
        self.skip_semis();
        let Some((relop, num, after)): Option<(u8, i64, usize)> = self.enum_cond() else {
            let start: usize = self.i;
            let term: usize = self.block_terminator(self.i);
            self.leaves.push((constraints.to_vec(), start, term));
            self.i = term;
            return Ok(());
        };
        self.i = after;
        let mut then_cons: Vec<Constraint> = constraints.to_vec();
        then_cons.push(Constraint {
            relop,
            num,
            truth: true,
        });
        self.parse(&then_cons)?;
        self.skip_semis();
        let next: &str = self.at(0);
        let mut else_cons: Vec<Constraint> = constraints.to_vec();
        else_cons.push(Constraint {
            relop,
            num,
            truth: false,
        });
        if relop == 0 {
            if next == "else" {
                self.i += 1;
                self.parse(&else_cons)?;
            } else if next == "elseif" {
                self.parse(&else_cons)?;
            }
            return Ok(());
        }
        if next == "else" {
            self.i += 1;
            self.parse(&else_cons)?;
            self.skip_semis();
            if self.at(0) == "end" {
                self.i += 1;
            }
        } else if next == "elseif" {
            self.parse(&else_cons)?;
            self.skip_semis();
            if self.at(0) == "end" {
                self.i += 1;
            }
        }
        Ok(())
    }
}

fn solve(constraints: &[Constraint], max_enum: i64) -> Option<i64> {
    for v in 0..=max_enum {
        let mut ok: bool = true;
        for c in constraints {
            let r: bool = match c.relop {
                0 => v <= c.num,
                1 => v < c.num,
                2 => v > c.num,
                3 => v >= c.num,
                _ => v == c.num,
            };
            if r != c.truth {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(v);
        }
    }
    None
}

pub fn recover_opcode_map(body: &str, max_enum: u16) -> Result<BTreeMap<u16, IbOpcode>> {
    let full: BTreeMap<u16, Vec<IbOpcode>> = recover_opcode_table(body, max_enum)?;
    Ok(full
        .into_iter()
        .map(|(k, v): (u16, Vec<IbOpcode>)| (k, v.into_iter().next().unwrap_or(IbOpcode::Unknown)))
        .collect())
}

pub fn recover_opcode_table(body: &str, max_enum: u16) -> Result<BTreeMap<u16, Vec<IbOpcode>>> {
    let tokens: Vec<Token> = tokenize(body);
    let info: LoopInfo = find_loop(&tokens).ok_or(Error::BootstrapEmulationFailed(
        "vm dispatch loop not found",
    ))?;
    let mut end: usize = tokens.len();
    let mut i: usize = info.dispatch_start;
    while i + 4 < tokens.len() {
        if tokens[i].text == info.ip_var
            && tokens[i + 1].text == "="
            && tokens[i + 2].text == info.ip_var
            && tokens[i + 3].text == "+"
            && tokens[i + 4].text == "1"
            && tokens.get(i + 5).map(|t: &Token| t.text.as_str()) != Some(";")
        {
            end = i;
        }
        i += 1;
    }
    let mut walker: Walker<'_> = Walker {
        t: &tokens,
        enum_var: &info.enum_var,
        i: info.dispatch_start,
        end,
        leaves: Vec::new(),
        steps: 0,
    };
    walker.parse(&[])?;
    let (raw_upval, _raw_env): (Option<String>, Option<String>) = find_wrap_vars(body);
    let stk_var: Option<String> = detect_stk_var(&walker, &tokens, &info.inst_var);
    let upval_var: Option<String> = match (&raw_upval, &stk_var) {
        (Some(u), Some(s)) if u != s => Some(u.clone()),
        (Some(u), None) => Some(u.clone()),
        _ => None,
    };
    let mut map: BTreeMap<u16, Vec<IbOpcode>> = BTreeMap::new();
    for (cons, start, leaf_end) in &walker.leaves {
        if let Some(ev) = solve(cons, i64::from(max_enum)) {
            let canon_body: String = canon(&tokens[*start..*leaf_end], &info.inst_var);
            let ops: Vec<IbOpcode> = classify_handler(
                &tokens[*start..*leaf_end],
                &canon_body,
                &info,
                upval_var.as_deref(),
            );
            if let Ok(idx) = u16::try_from(ev) {
                map.entry(idx).or_insert(ops);
            }
        }
    }
    Ok(map)
}

fn classify_handler(
    body_tokens: &[Token],
    canon_body: &str,
    info: &LoopInfo,
    upval_var: Option<&str>,
) -> Vec<IbOpcode> {
    if let Some(parts) = split_super_operator(canon_body, &info.ip_var, &info.inst_var) {
        let mut ops: Vec<IbOpcode> = Vec::with_capacity(parts.len());
        for part in parts {
            ops.push(fingerprint_str(&part, upval_var));
        }
        return ops;
    }
    vec![fingerprint(body_tokens, &info.inst_var, upval_var)]
}

fn split_super_operator(canon_body: &str, ip_var: &str, inst_var: &str) -> Option<Vec<String>> {
    let marker_re: Regex = Regex::new(&format!(
        r"{ip}={ip}\+1;{inst}=\w+\[{ip}\];",
        ip = regex::escape(ip_var),
        inst = regex::escape(inst_var)
    ))
    .ok()?;
    let (stripped, scratch): (String, Vec<String>) = strip_super_locals(canon_body);
    let parts: Vec<&str> = marker_re.split(&stripped).collect();
    if parts.len() < 2 {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|s: &&str| normalize_hoisted_fragment(s, &scratch))
            .collect(),
    )
}

fn strip_super_locals(body: &str) -> (String, Vec<String>) {
    let mut rest: &str = body;
    let mut scratch: Vec<String> = Vec::new();
    while let Some(after_local) = rest.strip_prefix("local") {
        let mut end: usize = 0;
        let chars: &[u8] = after_local.as_bytes();
        while end < chars.len() {
            let b: u8 = chars[end];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b',' {
                end += 1;
            } else {
                break;
            }
        }
        if end == 0 || after_local.as_bytes().get(end) != Some(&b';') {
            break;
        }
        let names: &str = &after_local[..end];
        if names.contains('=') {
            break;
        }
        for name in names.split(',') {
            if !name.is_empty() {
                scratch.push(name.to_owned());
            }
        }
        rest = &after_local[end + 1..];
    }
    (rest.to_owned(), scratch)
}

fn normalize_hoisted_fragment(fragment: &str, scratch: &[String]) -> String {
    for name in scratch {
        let assign: String = format!("{name}=A");
        if let Some(rem) = fragment.strip_prefix(&assign)
            && rem
                .as_bytes()
                .first()
                .is_none_or(|b: &u8| !b.is_ascii_alphanumeric() && *b != b'_')
        {
            return format!("local{name}=A{rem}");
        }
    }
    fragment.to_owned()
}

fn detect_stk_var(walker: &Walker<'_>, tokens: &[Token], inst_var: &str) -> Option<String> {
    let fp_ref: &Fingerprints = fp();
    for (_, start, leaf_end) in &walker.leaves {
        let b: String = canon(&tokens[*start..*leaf_end], inst_var);
        if let Some(c) = fp_ref.move_re.captures(&b) {
            let lhs: &str = c.get(1).map_or("", |m: regex::Match<'_>| m.as_str());
            let rhs: &str = c.get(2).map_or("", |m: regex::Match<'_>| m.as_str());
            if lhs == rhs && !lhs.is_empty() {
                return Some(lhs.to_owned());
            }
        }
    }
    None
}

fn canon(body: &[Token], inst_var: &str) -> String {
    let mut out: String = String::new();
    let mut i: usize = 0;
    while i < body.len() {
        if body[i].text == inst_var
            && body.get(i + 1).map(|x: &Token| x.text.as_str()) == Some("[")
            && body.get(i + 3).map(|x: &Token| x.text.as_str()) == Some("]")
            && body.get(i + 2).map(|x: &Token| x.kind) == Some(Tk::Num)
        {
            let idx: &str = &body[i + 2].text;
            let tag: &str = match idx {
                "1" => "ENUM",
                "2" => "A",
                "3" => "B",
                "4" => "C",
                _ => "",
            };
            if !tag.is_empty() {
                out.push_str(tag);
                i += 4;
                continue;
            }
        }
        out.push_str(&body[i].text);
        i += 1;
    }
    out
}

struct Fingerprints {
    arith_rr: Regex,
    arith_kr: Regex,
    arith_rk: Regex,
    arith_kk: Regex,
    move_re: Regex,
    getglobal: Regex,
    loadk: Regex,
    loadbool: Regex,
    loadbool_c: Regex,
    loadnil: Regex,
    unm: Regex,
    not_re: Regex,
    len_re: Regex,
    jmp: Regex,
    cmp_reg: Regex,
    cmp_full: Regex,
    test: Regex,
    test_c: Regex,
    gettable_rr: Regex,
    gettable_rk: Regex,
    settable: Regex,
    setglobal: Regex,
    newtable: Regex,
    self_re: Regex,
    for_bind: Regex,
    closure_nu: Regex,
    call_a: Regex,
    call_unpack: Regex,
}

impl Fingerprints {
    #[allow(clippy::expect_used)]
    fn new() -> Self {
        let r = |p: &str| Regex::new(p).expect("static fingerprint regex");
        Self {
            arith_rr: r(r"^(\w+)\[A\]=(\w+)\[B\]([-+*/%^])(\w+)\[C\];$"),
            arith_kr: r(r"^(\w+)\[A\]=B([-+*/%^])(\w+)\[C\];$"),
            arith_rk: r(r"^(\w+)\[A\]=(\w+)\[B\]([-+*/%^])C;$"),
            arith_kk: r(r"^(\w+)\[A\]=B([-+*/%^])C;$"),
            move_re: r(r"^(\w+)\[A\]=(\w+)\[B\];$"),
            getglobal: r(r"^(\w+)\[A\]=(\w+)\[B\];$"),
            loadk: r(r"^\w+\[A\]=B;$"),
            loadbool: r(r"^\w+\[A\]=\(B~=0\);$"),
            loadbool_c: r(r"^\w+\[A\]=\(B~=0\);\w+=\w+\+1;$"),
            loadnil: r(r"for\w+=A,Bdo\w+\[\w+\]=nil;?end"),
            unm: r(r"^\w+\[A\]=-\w+\[B\];$"),
            not_re: r(r"^\w+\[A\]=\(not\w+\[B\]\);$"),
            len_re: r(r"^\w+\[A\]=#\w+\[B\];$"),
            jmp: r(r"^\w+=B;$"),
            cmp_reg: r(r"if\(?\w+\[A\](<=|<|==|~=)\w*\[?[BC]?\]?\)?then\w+=\w+\+1"),
            cmp_full: r(
                r"^if\(?\w+\[A\](==|~=|<=|>=|<|>)(?:\w+\[[BC]\]|[BC])\)?then(.*?)else(.*?)end;?$",
            ),
            test: r(r"if\w+\[A\]then\w+=\w+\+1;else\w+=B;end"),
            test_c: r(r"ifnot\w+\[A\]then\w+=\w+\+1;else\w+=B;end"),
            gettable_rr: r(r"^(\w+)\[A\]=(\w+)\[B\]\[(\w+)\[C\]\];$"),
            gettable_rk: r(r"^(\w+)\[A\]=(\w+)\[B\]\[C\];$"),
            settable: r(r"^\w+\[A\]\[(\w+\[B\]|B)\]=(\w+\[C\]|C);$"),
            setglobal: r(r"^(\w+)\[B\]=(\w+)\[A\];$"),
            newtable: r(r"^\w+\[A\]=\{\};$"),
            self_re: r(r"\w+\[A\+1\]=\w+;"),
            for_bind: r(r"^local(\w+)=A;"),
            closure_nu: r(r"=\w+\(\w*\[?B\]?[^)]*,nil,\w+\)"),
            call_a: r(r"\w+\[A\]\(|\w+\[\w+\]\("),
            call_unpack: r(r"\w+\(\w+\(\w+,"),
        }
    }
}

fn fp() -> &'static Fingerprints {
    static FP: OnceLock<Fingerprints> = OnceLock::new();
    FP.get_or_init(Fingerprints::new)
}

fn arith_op(sym: &str) -> IbOpcode {
    match sym {
        "+" => IbOpcode::Add,
        "-" => IbOpcode::Sub,
        "*" => IbOpcode::Mul,
        "/" => IbOpcode::Div,
        "%" => IbOpcode::Mod,
        "^" => IbOpcode::Pow,
        _ => IbOpcode::Unknown,
    }
}

fn cmp_op(sym: &str) -> IbOpcode {
    match sym {
        "<=" => IbOpcode::Le,
        "<" => IbOpcode::Lt,
        "==" => IbOpcode::Eq,
        "~=" => IbOpcode::Eq,
        _ => IbOpcode::Unknown,
    }
}

fn cmp_symbol(sym: &str) -> Option<CmpOp> {
    Some(match sym {
        "==" => CmpOp::Eq,
        "~=" => CmpOp::Ne,
        "<" => CmpOp::Lt,
        "<=" => CmpOp::Le,
        ">" => CmpOp::Gt,
        ">=" => CmpOp::Ge,
        _ => return None,
    })
}

fn classify_compare(b: &str) -> Option<CmpForm> {
    let f: &Fingerprints = fp();
    let caps: regex::Captures<'_> = f.cmp_full.captures(b)?;
    let op: CmpOp = cmp_symbol(caps.get(1)?.as_str())?;
    let then_branch: &str = caps.get(2)?.as_str();
    let else_branch: &str = caps.get(3)?.as_str();
    let then_skips: bool = branch_is_pc_increment(then_branch);
    let else_skips: bool = branch_is_pc_increment(else_branch);
    let then_jumps: bool = branch_is_jump(then_branch);
    let else_jumps: bool = branch_is_jump(else_branch);
    if then_skips && else_jumps {
        Some(CmpForm {
            op,
            jump_when_true: false,
        })
    } else if then_jumps && else_skips {
        Some(CmpForm {
            op,
            jump_when_true: true,
        })
    } else {
        None
    }
}

fn branch_is_pc_increment(branch: &str) -> bool {
    let trimmed: &str = branch.trim_matches(';');
    trimmed.ends_with("+1")
}

fn branch_is_jump(branch: &str) -> bool {
    let trimmed: &str = branch.trim_matches(';');
    trimmed.ends_with("=B")
}

fn fingerprint(body: &[Token], inst_var: &str, upval_var: Option<&str>) -> IbOpcode {
    let b: String = canon(body, inst_var);
    fingerprint_str(&b, upval_var)
}

fn fingerprint_str(b: &str, upval_var: Option<&str>) -> IbOpcode {
    let b: String = b.to_owned();
    let f: &Fingerprints = fp();

    if b.contains("doreturn") {
        return IbOpcode::Return(return_form(&b));
    }
    if b.starts_with("local") && b.contains("__index") && b.contains("__newindex") {
        return IbOpcode::Closure;
    }
    if let Some(up) = upval_var {
        if let Some(c) = f.move_re.captures(&b) {
            let rhs: &str = c.get(2).map_or("", |m: regex::Match<'_>| m.as_str());
            if rhs == up {
                return IbOpcode::GetUpval;
            }
        }
        if let Some(c) = f.setglobal.captures(&b) {
            let lhs: &str = c.get(1).map_or("", |m: regex::Match<'_>| m.as_str());
            if lhs == up {
                return IbOpcode::SetUpval;
            }
        }
    }
    if let Some(c) = f.for_bind.captures(&b) {
        let var: &str = c.get(1).map_or("", |m: regex::Match<'_>| m.as_str());
        let p1: String = format!("{var}+1");
        let p2: String = format!("{var}+2");
        let p3: String = format!("{var}+3");
        if b.contains(&p1) && b.contains(&p2) && b.contains(&p3) {
            let idx_step: String = format!("[{var}]+");
            let reassign: String = format!("[{var}]=");
            if b.contains(&idx_step) && b.contains(&reassign) && b.contains("if") {
                return IbOpcode::ForLoop;
            }
            return IbOpcode::ForPrep;
        }
    }
    if f.jmp.is_match(&b) {
        return IbOpcode::Jmp;
    }
    if let Some(c) = f.move_re.captures(&b) {
        let lhs: &str = c.get(1).map_or("", |m: regex::Match<'_>| m.as_str());
        let rhs: &str = c.get(2).map_or("", |m: regex::Match<'_>| m.as_str());
        return if lhs == rhs {
            IbOpcode::Move
        } else {
            IbOpcode::GetGlobal
        };
    }
    let _ = &f.getglobal;
    if f.loadk.is_match(&b) {
        return IbOpcode::LoadK;
    }
    if f.loadbool_c.is_match(&b) {
        return IbOpcode::LoadBoolC;
    }
    if f.loadbool.is_match(&b) {
        return IbOpcode::LoadBool;
    }
    if f.loadnil.is_match(&b) {
        return IbOpcode::LoadNil;
    }
    if let Some(c) = f.arith_rr.captures(&b) {
        return arith_op(c.get(3).map_or("", |m: regex::Match<'_>| m.as_str()));
    }
    if let Some(c) = f.arith_kr.captures(&b) {
        return arith_op(c.get(2).map_or("", |m: regex::Match<'_>| m.as_str()));
    }
    if let Some(c) = f.arith_rk.captures(&b) {
        return arith_op(c.get(3).map_or("", |m: regex::Match<'_>| m.as_str()));
    }
    if let Some(c) = f.arith_kk.captures(&b) {
        return arith_op(c.get(2).map_or("", |m: regex::Match<'_>| m.as_str()));
    }
    if f.unm.is_match(&b) {
        return IbOpcode::Unm;
    }
    if f.not_re.is_match(&b) {
        return IbOpcode::Not;
    }
    if f.len_re.is_match(&b) {
        return IbOpcode::Len;
    }
    if b.contains("..") && b.contains("for") {
        return IbOpcode::Concat;
    }
    if f.test_c.is_match(&b) {
        return IbOpcode::TestC;
    }
    if f.test.is_match(&b) {
        return IbOpcode::Test;
    }
    if let Some(form) = classify_compare(&b) {
        return IbOpcode::Compare(form);
    }
    if let Some(c) = f.cmp_reg.captures(&b) {
        return cmp_op(c.get(1).map_or("", |m: regex::Match<'_>| m.as_str()));
    }
    if f.gettable_rr.is_match(&b) || f.gettable_rk.is_match(&b) {
        return IbOpcode::GetTable;
    }
    if f.settable.is_match(&b) {
        return IbOpcode::SetTable;
    }
    if f.setglobal.is_match(&b) {
        return IbOpcode::SetGlobal;
    }
    if f.newtable.is_match(&b) {
        return IbOpcode::NewTable;
    }
    if f.self_re.is_match(&b) && b.contains("[A]=") {
        return IbOpcode::Self_;
    }
    if is_tforloop(&b) {
        return IbOpcode::TForLoop;
    }
    if is_setlist(&b) {
        return IbOpcode::SetList;
    }
    if f.closure_nu.is_match(&b) {
        return IbOpcode::ClosureNu;
    }
    if f.call_a.is_match(&b) || f.call_unpack.is_match(&b) {
        return IbOpcode::Call(call_form(&b));
    }
    IbOpcode::Unknown
}

fn is_tforloop(b: &str) -> bool {
    let v: &str = bound_local(b).unwrap_or("A");
    let iter_call: String = format!("[{v}+1],");
    b.contains("={") && b.contains(&iter_call) && b.contains("for") && b.contains("=1,")
}

fn is_setlist(b: &str) -> bool {
    if b.contains("Insert") || b.contains("[#") {
        return true;
    }
    let v: &str = bound_local(b).unwrap_or("A");
    let loop_start: String = format!("={v}+1,");
    if let Some(p) = b.find(&loop_start) {
        let tail: &str = &b[p..];
        let inserts: bool =
            tail.contains("do") && tail.contains('(') && tail.contains(",e[") && tail.contains(")");
        let no_index_read: bool = !tail.contains("=t[") && !tail.contains('{');
        return inserts && no_index_read;
    }
    false
}

fn bound_local(b: &str) -> Option<&str> {
    let rest: &str = b.strip_prefix("local").unwrap_or(b);
    let eq: usize = rest.find("=A")?;
    let v: &str = &rest[..eq];
    if v.is_empty()
        || !v
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(v)
}

fn return_form(b: &str) -> RetForm {
    if b == "doreturnend;" || b == "doreturnend" {
        return RetForm::None;
    }
    let v: &str = bound_local(b).unwrap_or("A");
    let two: String = format!("doreturn{v}[{v}]end").replace("[A][A]", "[A]");
    let two_a: String = "doreturne[A]end".to_owned();
    let three1: String = format!("[{v}],");
    let three2: String = format!("[{v}+1]end");
    let top1: String = format!(",{v},Top)");
    let fixed1: String = format!(",{v},{v}+");
    if b.contains(&top1) || b.contains(",A,Top)") {
        return RetForm::Top;
    }
    if (b.contains(&three1) && b.contains(&three2))
        || (b.contains("[A],") && b.contains("[A+1]end"))
    {
        return RetForm::Three;
    }
    if b.contains(&fixed1) || b.contains(",A,A+") {
        return RetForm::Fixed;
    }
    let _ = (&two, &two_a);
    let single_ret: String = format!("doreturn{v}[{v}]end");
    if (b.contains(&single_ret) || b == "doreturne[A]end" || b.ends_with("[A]end"))
        && !b.contains(',')
    {
        return RetForm::Two;
    }
    RetForm::Fixed
}

fn call_form(b: &str) -> CallForm {
    let v: &str = bound_local(b).unwrap_or("A");
    let arg: ArgForm = detect_arg_form(b, v);
    let ret: RetCount = if multi_result_call(b, v) || top_capture(b, v) {
        RetCount::None
    } else if result_loop(b, v) {
        RetCount::Fixed
    } else if assigns_self(b, v) {
        RetCount::Single
    } else {
        RetCount::One
    };
    CallForm { b: arg, c: ret }
}

fn multi_result_call(b: &str, v: &str) -> bool {
    let select_wrap: bool = b.contains("=f(l[") || b.contains("=f(e[");
    let top_calc: bool = b.contains(&format!("+{v}-1")) || b.contains(&format!("+{v};"));
    let spread: bool = b.contains("for") && b.contains(&format!("={v},"));
    select_wrap && top_calc && spread
}

fn detect_arg_form(b: &str, v: &str) -> ArgForm {
    let none_marker: String = format!("[{v}]()");
    if b.contains(&none_marker) {
        return ArgForm::None;
    }
    let unpack_prefix: String = format!(",{v}+1,");
    if let Some(p) = b.find(&unpack_prefix) {
        let tail: &str = &b[p + unpack_prefix.len()..];
        let third: String = tail
            .chars()
            .take_while(|c: &char| *c != ')')
            .collect::<String>();
        if third == "B" {
            return ArgForm::Fixed;
        }
        return ArgForm::Top;
    }
    let two_marker: String = format!("[{v}+1])");
    if b.contains(&two_marker) {
        return ArgForm::Two;
    }
    ArgForm::Fixed
}

fn top_capture(b: &str, v: &str) -> bool {
    b.contains("Top=") || (b.contains(",n=") && b.contains(&format!("c=n+{v}")))
}

fn result_loop(b: &str, v: &str) -> bool {
    let table_then_loop: bool =
        b.contains("={") && b.contains("};") && b.contains("for") && b.contains("=t[");
    let edx: bool = b.contains("Results") && b.contains("Edx");
    let for_c: bool = b.contains("for") && b.contains(",Cdo") && b.contains(&format!("[{v}+1"));
    table_then_loop || edx || for_c
}

fn assigns_self(b: &str, v: &str) -> bool {
    let pat: String = format!("[{v}]=");
    if let Some(p) = b.find(&pat) {
        let tail: &str = &b[p + pat.len()..];
        return tail.contains(&format!("[{v}]("));
    }
    false
}
