#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_pass_js_deob::{AstUnminifyStats, UnminifyStats, try_unminify_ast, unminify};
use disrobe_testkit::{CommandSpec, ToolOutput, XorShift64, tool_output};

const SEED_COUNT: u64 = 300;
const SEEDS_PER_TEST: u64 = 75;
const REWRITTEN_FLOOR: usize = 300;
const SEED_DOMAIN: u64 = 0x756E_6D69_6E69_6679;
const NODE_BACKSTOP: Duration = Duration::from_mins(1);
const PINNED_DIR: &str = "tests/fixtures/unminify_generated";
const MUTATIONS: &[(&str, &str)] = &[
    (" * ", " + "),
    (" + ", " - "),
    (" - ", " + "),
    (" < ", " >= "),
    (" === ", " !== "),
];

const COMMA: u8 = 1;
const ASSIGN: u8 = 2;
const CONDITIONAL: u8 = 3;
const NULLISH: u8 = 4;
const OR: u8 = 5;
const AND: u8 = 6;
const BIT_OR: u8 = 7;
const BIT_XOR: u8 = 8;
const BIT_AND: u8 = 9;
const EQUALITY: u8 = 10;
const RELATIONAL: u8 = 11;
const SHIFT: u8 = 12;
const ADDITIVE: u8 = 13;
const MULTIPLICATIVE: u8 = 14;
const UNARY: u8 = 16;
const POSTFIX: u8 = 17;
const CALL: u8 = 18;
const PRIMARY: u8 = 19;

#[derive(Debug, Clone)]
struct Ex {
    text: String,
    prec: u8,
}

impl Ex {
    fn new(text: impl Into<String>, prec: u8) -> Self {
        Self {
            text: text.into(),
            prec,
        }
    }

    fn at(&self, min: u8) -> String {
        if self.prec < min {
            format!("({})", self.text)
        } else {
            self.text.clone()
        }
    }

    fn nullish_operand(&self) -> String {
        if self.prec == OR || self.prec == AND || self.prec < NULLISH {
            format!("({})", self.text)
        } else {
            self.text.clone()
        }
    }
}

fn binary(left: &Ex, op: &str, right: &Ex) -> Ex {
    let prec: u8 = match op {
        "||" => OR,
        "&&" => AND,
        "|" => BIT_OR,
        "^" => BIT_XOR,
        "&" => BIT_AND,
        "==" | "!=" | "===" | "!==" => EQUALITY,
        "<" | "<=" | ">" | ">=" => RELATIONAL,
        "<<" | ">>" | ">>>" => SHIFT,
        "+" | "-" => ADDITIVE,
        "*" | "/" | "%" => MULTIPLICATIVE,
        other => panic!("unknown binary operator {other}"),
    };
    Ex::new(
        format!("{} {op} {}", left.at(prec), right.at(prec + 1)),
        prec,
    )
}

fn unary(op: &str, operand: &Ex) -> Ex {
    let inner: String = operand.at(UNARY);
    let needs_space: bool = op.chars().all(char::is_alphabetic)
        || (op == "-" && inner.starts_with('-'))
        || (op == "+" && inner.starts_with('+'));
    let text: String = if needs_space {
        format!("{op} {inner}")
    } else {
        format!("{op}{inner}")
    };
    Ex::new(text, UNARY)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Int,
    Str,
    Nullable,
    Arr,
    Obj,
    Counter,
    Pair,
}

#[derive(Debug, Clone)]
struct Var {
    name: String,
    ty: Ty,
    mutable: bool,
}

#[derive(Debug, Clone)]
enum Jump {
    Loop(Option<String>),
    Block(String),
}

struct Gen {
    rng: XorShift64,
    out: String,
    indent: usize,
    scopes: Vec<Vec<Var>>,
    next_name: usize,
    jumps: Vec<Jump>,
}

impl Gen {
    fn new(seed: u64) -> Self {
        Self {
            rng: XorShift64::new(seed ^ SEED_DOMAIN),
            out: String::new(),
            indent: 0,
            scopes: vec![Vec::new()],
            next_name: 0,
            jumps: Vec::new(),
        }
    }

    fn pick(&mut self, bound: usize) -> usize {
        self.rng.below_usize(bound)
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.pick(100) < percent
    }

    fn fresh(&mut self, prefix: &str) -> String {
        let name: String = format!("{prefix}{}", self.next_name);
        self.next_name += 1;
        name
    }

    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.out.push_str("  ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn declare(&mut self, name: &str, ty: Ty, mutable: bool) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.push(Var {
                name: name.to_owned(),
                ty,
                mutable,
            });
        }
    }

    fn visible(&self, ty: Ty, need_mutable: bool) -> Vec<String> {
        self.scopes
            .iter()
            .flatten()
            .filter(|var: &&Var| var.ty == ty && (var.mutable || !need_mutable))
            .map(|var: &Var| var.name.clone())
            .collect()
    }

    fn choose(&mut self, ty: Ty, need_mutable: bool) -> Option<String> {
        let names: Vec<String> = self.visible(ty, need_mutable);
        if names.is_empty() {
            return None;
        }
        let index: usize = self.pick(names.len());
        names.into_iter().nth(index)
    }

    fn redundant_parens(&mut self, ex: Ex) -> Ex {
        if ex.prec < PRIMARY && self.chance(8) {
            return Ex::new(format!("({})", ex.text), PRIMARY);
        }
        ex
    }

    fn literal_int(&mut self) -> Ex {
        let value: usize = self.pick(20);
        match self.pick(8) {
            0 => Ex::new(format!("0x{value:x}"), PRIMARY),
            1 => Ex::new("!0", UNARY),
            2 => Ex::new("!1", UNARY),
            3 => Ex::new(format!("{value}e0"), PRIMARY),
            _ => Ex::new(value.to_string(), PRIMARY),
        }
    }

    fn int_atom(&mut self) -> Ex {
        if self.chance(55)
            && let Some(name) = self.choose(Ty::Int, false)
        {
            return Ex::new(name, PRIMARY);
        }
        self.literal_int()
    }

    fn int_expr(&mut self, depth: usize) -> Ex {
        let ex: Ex = self.int_expr_inner(depth);
        self.redundant_parens(ex)
    }

    fn int_expr_inner(&mut self, depth: usize) -> Ex {
        if depth == 0 {
            return self.int_atom();
        }
        let next: usize = depth - 1;
        match self.pick(17) {
            0 | 1 => self.int_atom(),
            2 => {
                let op: &str = ["+", "-", "*"][self.pick(3)];
                let left: Ex = self.int_expr(next);
                let right: Ex = self.int_expr(next);
                binary(&left, op, &right)
            }
            3 => {
                let op: &str = ["&", "|", "^", "<<", ">>", ">>>"][self.pick(6)];
                let left: Ex = self.int_expr(next);
                let right: Ex = if op.starts_with('<') || op.starts_with('>') {
                    Ex::new((1 + self.pick(4)).to_string(), PRIMARY)
                } else {
                    self.int_expr(next)
                };
                binary(&left, op, &right)
            }
            4 => {
                let left: Ex = self.int_expr(next);
                let right: Ex = Ex::new((2 + self.pick(5)).to_string(), PRIMARY);
                binary(&left, "%", &right)
            }
            5 => {
                let op: &str = ["-", "~", "+", "!"][self.pick(4)];
                let operand: Ex = self.int_expr(next);
                unary(op, &operand)
            }
            6 => match self.choose(Ty::Int, true) {
                Some(name) => match self.pick(4) {
                    0 => Ex::new(format!("++{name}"), UNARY),
                    1 => Ex::new(format!("--{name}"), UNARY),
                    2 => Ex::new(format!("{name}++"), POSTFIX),
                    _ => Ex::new(format!("{name}--"), POSTFIX),
                },
                None => self.int_atom(),
            },
            7 => match self.choose(Ty::Int, true) {
                Some(name) => {
                    let op: &str = ["=", "+=", "-=", "*=", "|="][self.pick(5)];
                    let value: Ex = self.int_expr(next);
                    Ex::new(format!("{name} {op} {}", value.at(ASSIGN)), ASSIGN)
                }
                None => self.int_atom(),
            },
            8 => {
                let first: Ex = self.int_expr(next);
                let second: Ex = self.int_expr(next);
                Ex::new(
                    format!("{}, {}", first.at(ASSIGN), second.at(ASSIGN)),
                    COMMA,
                )
            }
            9 => {
                let test: Ex = self.cond_expr(next);
                let yes: Ex = self.int_expr(next);
                let no: Ex = self.int_expr(next);
                Ex::new(
                    format!(
                        "{} ? {} : {}",
                        test.at(NULLISH),
                        yes.at(ASSIGN),
                        no.at(ASSIGN)
                    ),
                    CONDITIONAL,
                )
            }
            10 => {
                let op: &str = ["&&", "||"][self.pick(2)];
                let left: Ex = self.int_expr(next);
                let right: Ex = self.int_expr(next);
                binary(&left, op, &right)
            }
            11 => {
                let nullable: Ex = self.nullable_expr();
                let fallback: Ex = self.int_expr(next);
                Ex::new(
                    format!("{} ?? {}", nullable.nullish_operand(), fallback.at(BIT_OR)),
                    NULLISH,
                )
            }
            12 => self.member_int(),
            13 => self.call_int(next),
            14 => self.compare_expr(next),
            15 => match self.pick(4) {
                0 => {
                    let text: Ex = self.str_expr(next);
                    Ex::new(format!("{}.length", text.at(CALL)), CALL)
                }
                1 => {
                    let base: Ex = self.int_expr(next);
                    Ex::new(format!("Math.pow({}, 2)", base.at(ASSIGN)), CALL)
                }
                2 => {
                    let left: Ex = self.int_expr(next);
                    let right: Ex = self.int_expr(next);
                    Ex::new(
                        format!("Math.max({}, {})", left.at(ASSIGN), right.at(ASSIGN)),
                        CALL,
                    )
                }
                _ => {
                    let value: Ex = self.int_expr(next);
                    let literal: Ex = self.literal_int();
                    Ex::new(
                        format!("{}, {}", unary("void", &value).text, literal.at(ASSIGN)),
                        COMMA,
                    )
                }
            },
            _ => {
                let value: Ex = self.int_expr(next);
                match self.pick(3) {
                    0 => Ex::new(
                        format!("(function () {{ return {}; }})()", value.at(COMMA)),
                        CALL,
                    ),
                    1 => Ex::new(format!("(() => {})()", value.at(ASSIGN)), CALL),
                    _ => Ex::new(
                        format!("!function () {{ return {}; }}()", value.at(COMMA)),
                        UNARY,
                    ),
                }
            }
        }
    }

    fn member_int(&mut self) -> Ex {
        if self.chance(50)
            && let Some(array) = self.choose(Ty::Arr, false)
        {
            return match self.pick(4) {
                0 => Ex::new(format!("{array}.length"), CALL),
                1 => Ex::new(format!("{array}[\"length\"]"), CALL),
                _ => Ex::new(format!("{array}[{}]", self.pick(3)), CALL),
            };
        }
        if let Some(object) = self.choose(Ty::Obj, false) {
            let key: &str = ["p", "q"][self.pick(2)];
            return if self.chance(50) {
                Ex::new(format!("{object}.{key}"), CALL)
            } else {
                Ex::new(format!("{object}[\"{key}\"]"), CALL)
            };
        }
        self.int_atom()
    }

    fn call_int(&mut self, depth: usize) -> Ex {
        if self.chance(50)
            && let Some(counter) = self.choose(Ty::Counter, false)
        {
            return Ex::new(format!("{counter}()"), CALL);
        }
        if let Some(pair) = self.choose(Ty::Pair, false) {
            let left: Ex = self.int_expr(depth);
            let right: Ex = self.int_expr(depth);
            return Ex::new(
                format!("{pair}({}, {})", left.at(ASSIGN), right.at(ASSIGN)),
                CALL,
            );
        }
        self.int_atom()
    }

    fn compare_expr(&mut self, depth: usize) -> Ex {
        let op: &str = ["<", "<=", ">", ">=", "===", "!==", "==", "!="][self.pick(8)];
        let left: Ex = self.int_expr(depth);
        let right: Ex = self.int_expr(depth);
        binary(&left, op, &right)
    }

    fn cond_expr(&mut self, depth: usize) -> Ex {
        let ex: Ex = match self.pick(5) {
            0 => {
                let inner: Ex = self.cond_expr(depth.saturating_sub(1));
                let other: Ex = self.cond_expr(depth.saturating_sub(1));
                let op: &str = ["&&", "||"][self.pick(2)];
                let joined: Ex = binary(&inner, op, &other);
                unary("!", &joined)
            }
            1 => self.int_expr(depth),
            2 => {
                let nullable: Ex = self.nullable_expr();
                let op: &str = ["==", "!=", "===", "!=="][self.pick(4)];
                let other: &str = ["null", "void 0", "undefined"][self.pick(3)];
                let other_prec: u8 = if other == "void 0" { UNARY } else { PRIMARY };
                binary(&nullable, op, &Ex::new(other, other_prec))
            }
            _ => self.compare_expr(depth),
        };
        ex
    }

    fn nullable_expr(&mut self) -> Ex {
        if self.chance(60)
            && let Some(name) = self.choose(Ty::Nullable, false)
        {
            return Ex::new(name, PRIMARY);
        }
        match self.pick(4) {
            0 => Ex::new("null", PRIMARY),
            1 => Ex::new("void 0", UNARY),
            2 => Ex::new("undefined", PRIMARY),
            _ => self.literal_int(),
        }
    }

    fn str_literal(&mut self) -> Ex {
        let word: &str = ["a", "bc", "x y", "q", "Zed", ""][self.pick(6)];
        if self.chance(50) {
            Ex::new(format!("'{word}'"), PRIMARY)
        } else {
            Ex::new(format!("\"{word}\""), PRIMARY)
        }
    }

    fn str_expr(&mut self, depth: usize) -> Ex {
        let ex: Ex = self.str_expr_inner(depth);
        self.redundant_parens(ex)
    }

    fn str_expr_inner(&mut self, depth: usize) -> Ex {
        if depth == 0 {
            if self.chance(50)
                && let Some(name) = self.choose(Ty::Str, false)
            {
                return Ex::new(name, PRIMARY);
            }
            return self.str_literal();
        }
        let next: usize = depth - 1;
        match self.pick(11) {
            0 | 1 => self.str_expr(0),
            2 => {
                let number: Ex = self.int_expr(next);
                let text: Ex = self.str_expr(next);
                Ex::new(
                    format!("`t${{{}}}-${{{}}}`", number.at(COMMA), text.at(COMMA)),
                    PRIMARY,
                )
            }
            3 => {
                let left: Ex = self.str_expr(next);
                let right: Ex = self.str_expr(next);
                binary(&left, "+", &right)
            }
            4 => {
                let left: Ex = self.str_literal();
                let right: Ex = self.str_literal();
                binary(&left, "+", &right)
            }
            5 => {
                let text: Ex = self.str_expr(next);
                let number: Ex = self.int_expr(next);
                binary(&text, "+", &number)
            }
            6 => {
                let operand: Ex = match self.pick(3) {
                    0 => self.int_expr(next),
                    1 => self.str_expr(next),
                    _ => self.nullable_expr(),
                };
                unary("typeof", &operand)
            }
            7 => {
                let number: Ex = self.int_expr(next);
                Ex::new(format!("String({})", number.at(ASSIGN)), CALL)
            }
            8 => {
                let test: Ex = self.cond_expr(next);
                let yes: Ex = self.str_expr(next);
                let no: Ex = self.str_expr(next);
                Ex::new(
                    format!(
                        "{} ? {} : {}",
                        test.at(NULLISH),
                        yes.at(ASSIGN),
                        no.at(ASSIGN)
                    ),
                    CONDITIONAL,
                )
            }
            9 => {
                let left: Ex = self.int_expr(next);
                let right: Ex = self.str_expr(next);
                Ex::new(
                    format!("[{}, {}].join(\"-\")", left.at(ASSIGN), right.at(ASSIGN)),
                    CALL,
                )
            }
            _ => match (self.choose(Ty::Arr, false), self.choose(Ty::Obj, false)) {
                (Some(array), _) if self.chance(50) => {
                    Ex::new(format!("JSON.stringify({array})"), CALL)
                }
                (_, Some(object)) => Ex::new(format!("JSON.stringify({object})"), CALL),
                _ => {
                    let text: Ex = self.str_expr(next);
                    Ex::new(format!("{}.toUpperCase()", text.at(CALL)), CALL)
                }
            },
        }
    }

    fn print_stmt(&mut self) {
        let text: String = match self.pick(5) {
            0 => {
                let value: Ex = self.int_expr(3);
                format!("console.log({});", value.at(ASSIGN))
            }
            1 => {
                let value: Ex = self.str_expr(2);
                format!("console.log({});", value.at(ASSIGN))
            }
            2 => {
                let number: Ex = self.int_expr(2);
                let text: Ex = self.str_expr(1);
                format!("console.log({}, {});", number.at(ASSIGN), text.at(ASSIGN))
            }
            3 => {
                let nullable: Ex = self.nullable_expr();
                format!(
                    "console.log({}, {} ?? \"dflt\");",
                    unary("typeof", &nullable).text,
                    nullable.nullish_operand()
                )
            }
            _ => {
                let value: Ex = self.cond_expr(2);
                format!("console.log(\"c\", {});", value.at(ASSIGN))
            }
        };
        self.line(&text);
    }

    fn decl_stmt(&mut self) {
        let keyword: &str = ["var", "let", "const"][self.pick(3)];
        match self.pick(8) {
            0..=2 => {
                if keyword == "var" && self.chance(50) {
                    let first: String = self.fresh("v");
                    let second: String = self.fresh("v");
                    let a: Ex = self.int_expr(2);
                    let b: Ex = self.int_expr(2);
                    self.line(&format!(
                        "var {first} = {}, {second} = {};",
                        a.at(ASSIGN),
                        b.at(ASSIGN)
                    ));
                    self.declare(&first, Ty::Int, true);
                    self.declare(&second, Ty::Int, true);
                } else {
                    let name: String = self.fresh("v");
                    let value: Ex = self.int_expr(2);
                    self.line(&format!("{keyword} {name} = {};", value.at(ASSIGN)));
                    self.declare(&name, Ty::Int, keyword != "const");
                }
            }
            3 => {
                let name: String = self.fresh("s");
                let value: Ex = self.str_expr(2);
                self.line(&format!("const {name} = {};", value.at(ASSIGN)));
                self.declare(&name, Ty::Str, false);
            }
            4 => {
                let name: String = self.fresh("n");
                let value: Ex = self.nullable_expr();
                let decl_keyword: &str = if keyword == "const" { "let" } else { keyword };
                self.line(&format!("{decl_keyword} {name} = {};", value.at(ASSIGN)));
                self.declare(&name, Ty::Nullable, true);
            }
            5 => {
                let name: String = self.fresh("arr");
                let a: Ex = self.int_expr(1);
                let b: Ex = self.int_expr(1);
                let c: Ex = self.int_expr(1);
                self.line(&format!(
                    "const {name} = [{}, {}, {}];",
                    a.at(ASSIGN),
                    b.at(ASSIGN),
                    c.at(ASSIGN)
                ));
                self.declare(&name, Ty::Arr, false);
            }
            6 => {
                let name: String = self.fresh("o");
                let p: Ex = self.int_expr(1);
                let q: Ex = self.int_expr(1);
                self.line(&format!(
                    "const {name} = {{ p: {}, \"q\": {} }};",
                    p.at(ASSIGN),
                    q.at(ASSIGN)
                ));
                self.declare(&name, Ty::Obj, false);
            }
            _ => {
                if self.chance(50) {
                    let name: String = self.fresh("cnt");
                    let start: Ex = self.int_expr(1);
                    self.line(&format!(
                        "const {name} = makeCounter({});",
                        start.at(ASSIGN)
                    ));
                    self.declare(&name, Ty::Counter, false);
                } else {
                    let name: String = self.fresh("pair");
                    match self.pick(3) {
                        0 => self.line(&format!("const {name} = (a, b) => a * 2 - b;")),
                        1 => self.line(&format!(
                            "const {name} = function (a, b) {{ return a > b ? a - b : b - a; }};"
                        )),
                        _ => self.line(&format!(
                            "const {name} = (a, b) => {{ let t = a; t += b; return t % 7; }};"
                        )),
                    }
                    self.declare(&name, Ty::Pair, false);
                }
            }
        }
    }

    fn mutate_stmt(&mut self) {
        let text: String = match self.pick(6) {
            0 => match self.choose(Ty::Int, true) {
                Some(name) => {
                    let op: &str = ["=", "+=", "-=", "^="][self.pick(4)];
                    let value: Ex = self.int_expr(2);
                    format!("{name} {op} {};", value.at(ASSIGN))
                }
                None => return self.print_stmt(),
            },
            1 => match self.choose(Ty::Int, true) {
                Some(name) => {
                    let other: Ex = self.int_expr(1);
                    let value: String = other.at(ASSIGN);
                    self.choose(Ty::Int, true).map_or_else(
                        || format!("{name}--, console.log({value});"),
                        |second: String| format!("{name}++, {second} = {value};"),
                    )
                }
                None => return self.print_stmt(),
            },
            2 => match self.choose(Ty::Arr, false) {
                Some(array) => {
                    let value: Ex = self.int_expr(2);
                    if self.chance(50) {
                        format!("{array}[{}] = {};", self.pick(3), value.at(ASSIGN))
                    } else {
                        format!("{array}.push({});", value.at(ASSIGN))
                    }
                }
                None => return self.print_stmt(),
            },
            3 => match self.choose(Ty::Obj, false) {
                Some(object) => {
                    let value: Ex = self.int_expr(2);
                    if self.chance(50) {
                        format!("{object}.p = {};", value.at(ASSIGN))
                    } else {
                        format!("{object}[\"q\"] += {};", value.at(ASSIGN))
                    }
                }
                None => return self.print_stmt(),
            },
            4 => match self.choose(Ty::Nullable, true) {
                Some(name) => {
                    let value: Ex = self.nullable_expr();
                    let fallback: Ex = self.int_expr(1);
                    if self.chance(50) {
                        format!("{name} = {};", value.at(ASSIGN))
                    } else {
                        format!("{name} ??= {};", fallback.at(ASSIGN))
                    }
                }
                None => return self.print_stmt(),
            },
            _ => {
                let test: Ex = self.cond_expr(2);
                let yes: Ex = self.int_expr(2);
                let no: Ex = self.int_expr(2);
                match self.pick(3) {
                    0 => format!(
                        "{} ? console.log({}) : console.log({});",
                        test.at(NULLISH),
                        yes.at(ASSIGN),
                        no.at(ASSIGN)
                    ),
                    1 => format!(
                        "{} && console.log(\"and\", {});",
                        test.at(AND),
                        yes.at(ASSIGN)
                    ),
                    _ => {
                        let guard: String = test.at(OR);
                        let assigned: String = yes.at(ASSIGN);
                        let logged: String = no.at(ASSIGN);
                        self.choose(Ty::Int, true).map_or_else(
                            || format!("{guard} || console.log(\"or\", {logged});"),
                            |name: String| format!("{guard} || ({name} = {assigned});"),
                        )
                    }
                }
            }
        };
        self.line(&text);
    }

    fn block(&mut self, depth: usize, count: usize) {
        self.indent += 1;
        self.scopes.push(Vec::new());
        for _ in 0..count {
            self.stmt(depth);
        }
        self.scopes.pop();
        self.indent -= 1;
    }

    fn jump_stmt(&mut self) -> bool {
        if self.jumps.is_empty() {
            return false;
        }
        let index: usize = self.pick(self.jumps.len());
        let target: Jump = self.jumps[index].clone();
        let innermost_loop: bool = self
            .jumps
            .iter()
            .rposition(|jump: &Jump| matches!(jump, Jump::Loop(_)))
            == Some(index);
        let test: String = self.cond_expr(1).at(COMMA);
        let text: String = match target {
            Jump::Block(label) => format!("if ({test}) break {label};"),
            Jump::Loop(label) => {
                let verb: &str = if self.chance(50) { "break" } else { "continue" };
                match label {
                    Some(label) if !innermost_loop || self.chance(50) => {
                        format!("if ({test}) {verb} {label};")
                    }
                    _ if innermost_loop => format!("if ({test}) {verb};"),
                    _ => return false,
                }
            }
        };
        self.line(&text);
        true
    }

    fn loop_stmt(&mut self, depth: usize) {
        let label: Option<String> = if self.chance(30) {
            Some(self.fresh("L"))
        } else {
            None
        };
        let prefix: String = label
            .as_ref()
            .map_or_else(String::new, |label: &String| format!("{label}: "));
        let bound: usize = 1 + self.pick(4);
        let counter: String = self.fresh("i");
        let body: usize = 1 + self.pick(3);
        match self.pick(4) {
            0 => {
                self.line(&format!(
                    "{prefix}for (let {counter} = 0; {counter} < {bound}; {counter}++) {{"
                ));
                self.scopes.push(vec![Var {
                    name: counter,
                    ty: Ty::Int,
                    mutable: false,
                }]);
            }
            1 => {
                self.line(&format!("let {counter} = {bound};"));
                self.declare(&counter, Ty::Int, false);
                self.line(&format!("{prefix}while ({counter}-- > 0) {{"));
                self.scopes.push(Vec::new());
            }
            2 => {
                self.line(&format!("let {counter} = 0;"));
                self.declare(&counter, Ty::Int, false);
                self.line(&format!("{prefix}for (;;) {{"));
                self.indent += 1;
                self.line(&format!("if (++{counter} > {bound}) break;"));
                self.indent -= 1;
                self.scopes.push(Vec::new());
            }
            _ => {
                self.line(&format!("let {counter} = 0;"));
                self.declare(&counter, Ty::Int, false);
                self.line(&format!("{prefix}do {{"));
                self.scopes.push(Vec::new());
                self.jumps.push(Jump::Loop(label));
                self.block(depth, body);
                self.jumps.pop();
                self.scopes.pop();
                self.line(&format!("}} while (++{counter} < {bound});"));
                return;
            }
        }
        self.jumps.push(Jump::Loop(label));
        self.block(depth, body);
        self.jumps.pop();
        self.scopes.pop();
        self.line("}");
    }

    fn if_stmt(&mut self, depth: usize) {
        let test: String = self.cond_expr(2).at(COMMA);
        if self.chance(30) {
            self.line(&format!("if ({test})"));
            self.indent += 1;
            self.scopes.push(Vec::new());
            self.mutate_stmt();
            self.scopes.pop();
            self.indent -= 1;
            return;
        }
        self.line(&format!("if ({test}) {{"));
        let count: usize = 1 + self.pick(2);
        self.block(depth, count);
        if self.chance(40) {
            let other: String = self.cond_expr(2).at(COMMA);
            self.line(&format!("}} else if ({other}) {{"));
            self.block(depth, 1);
        }
        if self.chance(50) {
            self.line("} else {");
            let count: usize = 1 + self.pick(2);
            self.block(depth, count);
        }
        self.line("}");
    }

    fn try_stmt(&mut self, depth: usize) {
        self.line("try {");
        self.indent += 1;
        self.scopes.push(Vec::new());
        self.stmt(depth);
        let test: String = self.cond_expr(1).at(COMMA);
        let thrown: String = if self.chance(50) {
            self.int_expr(1).at(COMMA)
        } else {
            self.str_expr(1).at(COMMA)
        };
        self.line(&format!("if ({test}) throw {thrown};"));
        self.stmt(depth);
        self.scopes.pop();
        self.indent -= 1;
        let err: String = self.fresh("err");
        self.line(&format!("}} catch ({err}) {{"));
        self.indent += 1;
        self.line(&format!("console.log(\"caught\", {err});"));
        self.indent -= 1;
        if self.chance(60) {
            self.line("} finally {");
            let saved: Vec<Jump> = std::mem::take(&mut self.jumps);
            self.block(0, 1);
            self.jumps = saved;
        }
        self.line("}");
    }

    fn labeled_block(&mut self, depth: usize) {
        let label: String = self.fresh("B");
        self.line(&format!("{label}: {{"));
        self.jumps.push(Jump::Block(label));
        self.indent += 1;
        self.scopes.push(Vec::new());
        self.stmt(depth);
        self.jump_stmt();
        self.stmt(depth);
        self.scopes.pop();
        self.indent -= 1;
        self.jumps.pop();
        self.line("}");
    }

    fn stmt(&mut self, depth: usize) {
        let choice: usize = self.pick(if depth == 0 { 6 } else { 11 });
        match choice {
            0 | 1 => self.print_stmt(),
            2 | 3 => self.decl_stmt(),
            4 | 5 => {
                if !(self.chance(40) && self.jump_stmt()) {
                    self.mutate_stmt();
                }
            }
            6 | 7 => self.loop_stmt(depth - 1),
            8 => self.if_stmt(depth - 1),
            9 => self.try_stmt(depth - 1),
            _ => self.labeled_block(depth - 1),
        }
    }

    fn function_decl(&mut self) {
        let name: String = self.fresh("fn");
        let saved: Vec<Jump> = std::mem::take(&mut self.jumps);
        self.line(&format!("function {name}(a, b) {{"));
        self.scopes.push(vec![
            Var {
                name: "a".to_owned(),
                ty: Ty::Int,
                mutable: true,
            },
            Var {
                name: "b".to_owned(),
                ty: Ty::Int,
                mutable: true,
            },
        ]);
        self.indent += 1;
        let statements: usize = 1 + self.pick(3);
        for _ in 0..statements {
            self.stmt(1);
        }
        let test: String = self.cond_expr(1).at(COMMA);
        let early: String = self.int_expr(2).at(COMMA);
        self.line(&format!("if ({test}) return {early};"));
        let result: String = self.int_expr(2).at(COMMA);
        self.line(&format!("return {result};"));
        self.indent -= 1;
        self.scopes.pop();
        self.line("}");
        self.jumps = saved;
        self.declare(&name, Ty::Pair, false);
    }

    fn program(mut self) -> String {
        self.line(
            "function makeCounter(start) { let c = start; return function () { return c++; }; }",
        );
        let wrapped: usize = self.pick(3);
        match wrapped {
            0 => self.line("(function () {"),
            1 => self.line("!function () {"),
            _ => {}
        }
        if wrapped < 2 {
            self.indent += 1;
        }
        let seed_name: String = self.fresh("v");
        let seed_value: usize = 3 + self.pick(9);
        self.line(&format!("var {seed_name} = {seed_value};"));
        self.declare(&seed_name, Ty::Int, true);
        let functions: usize = self.pick(3);
        for _ in 0..functions {
            self.function_decl();
        }
        let statements: usize = 8 + self.pick(8);
        for _ in 0..statements {
            self.stmt(3);
        }
        self.line(&format!("console.log(\"end\", {seed_name} * 7 + 3);"));
        match wrapped {
            0 => {
                self.indent -= 1;
                self.line("})();");
            }
            1 => {
                self.indent -= 1;
                self.line("}();");
            }
            _ => {}
        }
        self.out
    }
}

fn generate(seed: u64) -> String {
    Gen::new(seed).program()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Run {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_node(program: &str) -> Run {
    let output: ToolOutput = tool_output(
        CommandSpec::new("node", NODE_BACKSTOP)
            .arg("-")
            .stdin(program.as_bytes().to_vec()),
    )
    .expect("node is required on PATH to execute the generated programs");
    assert!(!output.timed_out, "node timed out on:\n{program}");
    Run {
        success: output.success,
        stdout: output.stdout_text(),
        stderr: output.stderr_text(),
    }
}

struct Recovered {
    text_stage: String,
    ast_stage: Option<String>,
    rule_activity: u64,
}

fn counter_total(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Number(number) => number.as_u64().unwrap_or(0),
        serde_json::Value::Object(fields) => fields.values().map(counter_total).sum(),
        serde_json::Value::Array(items) => items.iter().map(counter_total).sum(),
        _ => 0,
    }
}

fn recover(source: &str) -> Recovered {
    let (text_stage, text_stats): (String, UnminifyStats) = unminify(source);
    let mut rule_activity: u64 =
        counter_total(&serde_json::to_value(&text_stats).expect("stats serialize"));
    let ast_stage: Option<String> = match try_unminify_ast(&text_stage) {
        Ok((recovered, ast_stats)) => {
            let ast_stats: AstUnminifyStats = ast_stats;
            rule_activity +=
                counter_total(&serde_json::to_value(&ast_stats).expect("stats serialize"));
            Some(recovered)
        }
        Err(_) => None,
    };
    Recovered {
        text_stage,
        ast_stage,
        rule_activity,
    }
}

fn grade(label: &str, expected: &Run, program: &str) -> Result<(), String> {
    let observed: Run = run_node(program);
    if observed.success == expected.success && observed.stdout == expected.stdout {
        return Ok(());
    }
    Err(format!(
        "{label}: output diverged\n--- expected (success={})\n{}\n--- observed (success={})\n{}\n--- stderr\n{}\n--- program\n{program}",
        expected.success, expected.stdout, observed.success, observed.stdout, observed.stderr
    ))
}

fn grade_source(label: &str, source: &str) -> Result<bool, String> {
    let expected: Run = run_node(source);
    if !expected.success {
        return Err(format!(
            "{label}: the generated program itself fails under node\n{}\n{source}",
            expected.stderr
        ));
    }
    let recovered: Recovered = recover(source);
    grade(
        &format!("{label} text stage"),
        &expected,
        &recovered.text_stage,
    )?;
    if let Some(ast_stage) = &recovered.ast_stage {
        grade(&format!("{label} ast stage"), &expected, ast_stage)?;
    }
    Ok(recovered.rule_activity > 0)
}

fn grade_seeds(first: u64) {
    let mut failures: Vec<String> = Vec::new();
    for seed in first..first + SEEDS_PER_TEST {
        let source: String = generate(seed);
        if let Err(failure) = grade_source(&format!("seed {seed}"), &source) {
            failures.push(failure);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn generated_programs_keep_their_output_seeds_0_to_74() {
    grade_seeds(0);
}

#[test]
fn generated_programs_keep_their_output_seeds_75_to_149() {
    grade_seeds(75);
}

#[test]
fn generated_programs_keep_their_output_seeds_150_to_224() {
    grade_seeds(150);
}

#[test]
fn generated_programs_keep_their_output_seeds_225_to_299() {
    grade_seeds(225);
}

#[test]
fn the_seed_range_is_covered_by_the_graded_tests() {
    assert_eq!(SEED_COUNT, 4 * SEEDS_PER_TEST);
}

#[test]
fn generation_is_deterministic_and_the_rules_rewrite_most_programs() {
    let mut rewritten: usize = 0;
    for seed in 0..SEED_COUNT {
        let source: String = generate(seed);
        assert_eq!(source, generate(seed), "seed {seed} is not deterministic");
        if recover(&source).rule_activity > 0 {
            rewritten += 1;
        }
    }
    assert!(
        rewritten >= REWRITTEN_FLOOR,
        "only {rewritten} of {SEED_COUNT} generated programs were rewritten by unminify, so the \
         differential would grade the identity transform"
    );
}

const TERSER_VERSION: &str = "5.51.2";
const TERSER_SEEDS: u64 = 300;
const TERSER_KNOWN_DIVERGENT: [u64; 0] = [];
const TERSER_REWRITTEN_FLOOR: usize = 298;
const TERSER_BACKSTOP: Duration = Duration::from_mins(5);
const TERSER_DRIVER: &str = r#"const fs = require("fs");
const { minify } = require(process.argv[2]);
(async () => {
  for (const file of process.argv.slice(3)) {
    const out = await minify(fs.readFileSync(file, "utf8"), {
      compress: { passes: 2 },
      mangle: { toplevel: true },
      toplevel: true,
    });
    fs.writeFileSync(file + ".min.js", out.code);
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
"#;

fn terser_package() -> PathBuf {
    let package: PathBuf = std::env::var_os("DISROBE_TERSER").map(PathBuf::from).expect(
        "DISROBE_TERSER must name the terser 5.51.2 package directory (node_modules/terser); see \
         .developer/TOOLS.md",
    );
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(package.join("package.json"))
            .expect("DISROBE_TERSER must contain terser's package.json"),
    )
    .expect("terser's package.json parses");
    assert_eq!(
        manifest["name"].as_str(),
        Some("terser"),
        "DISROBE_TERSER does not name the terser package"
    );
    assert_eq!(
        manifest["version"].as_str(),
        Some(TERSER_VERSION),
        "DISROBE_TERSER names a terser other than the pinned {TERSER_VERSION}"
    );
    package
}

fn minify_with_terser(sources: &[(u64, String)]) -> Vec<(u64, String)> {
    let package: PathBuf = terser_package();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_js_terser_lane")
            .expect("create a terser scratch directory");
    let driver: PathBuf = scratch.path().join("minify.cjs");
    fs::write(&driver, TERSER_DRIVER).expect("write the terser driver");
    let mut command: CommandSpec = CommandSpec::new("node", TERSER_BACKSTOP)
        .arg(driver.as_os_str())
        .arg(package.as_os_str());
    for (seed, source) in sources {
        let file: PathBuf = scratch.path().join(format!("seed{seed}.js"));
        fs::write(&file, source).expect("write a generated program");
        command = command.arg(file.as_os_str());
    }
    let output: ToolOutput = tool_output(command).expect("node runs the terser driver");
    assert!(
        output.success,
        "terser {TERSER_VERSION} failed to minify the generated programs:\n{}",
        output.stderr_text()
    );
    sources
        .iter()
        .map(|(seed, _): &(u64, String)| {
            let minified: String =
                fs::read_to_string(scratch.path().join(format!("seed{seed}.js.min.js")))
                    .expect("terser wrote every minified program");
            (*seed, minified)
        })
        .collect()
}

#[test]
fn terser_minified_programs_keep_their_output_through_unminify() {
    let sources: Vec<(u64, String)> = (0..TERSER_SEEDS)
        .map(|seed: u64| (seed, generate(seed)))
        .collect();
    let minified: Vec<(u64, String)> = minify_with_terser(&sources);
    let mut divergent: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    let mut rewritten: usize = 0;
    for ((seed, source), (_, packed)) in sources.iter().zip(&minified) {
        let expected: Run = run_node(source);
        assert!(
            expected.success,
            "seed {seed}: the generated program fails under node"
        );
        assert_eq!(
            run_node(packed),
            expected,
            "seed {seed}: terser {TERSER_VERSION} changed the program's output, so the lane \
             cannot grade unminify on it:\n{packed}"
        );
        let recovered: Recovered = recover(packed);
        if recovered.rule_activity > 0 {
            rewritten += 1;
        }
        let graded: Result<(), String> = grade(
            &format!("seed {seed} text stage"),
            &expected,
            &recovered.text_stage,
        )
        .and_then(|()| match &recovered.ast_stage {
            Some(ast_stage) => grade(&format!("seed {seed} ast stage"), &expected, ast_stage),
            None => Ok(()),
        });
        if let Err(failure) = graded {
            divergent.insert(*seed, failure);
        }
    }
    assert!(
        rewritten >= TERSER_REWRITTEN_FLOOR,
        "unminify rewrote only {rewritten} of {TERSER_SEEDS} terser-minified programs, so the lane \
         would grade the identity transform"
    );
    let pinned: std::collections::BTreeSet<u64> = TERSER_KNOWN_DIVERGENT.into_iter().collect();
    let found: std::collections::BTreeSet<u64> = divergent.keys().copied().collect();
    let regressed: Vec<u64> = found.difference(&pinned).copied().collect();
    let fixed: Vec<u64> = pinned.difference(&found).copied().collect();
    let shown: Vec<&str> = divergent
        .iter()
        .filter(|(seed, _): &(&u64, &String)| !pinned.contains(seed))
        .map(|(_, failure): (&u64, &String)| failure.as_str())
        .take(4)
        .collect();
    assert!(
        regressed.is_empty() && fixed.is_empty(),
        "{} of {TERSER_SEEDS} terser-minified programs changed behaviour through unminify; the \
         divergent set must equal TERSER_KNOWN_DIVERGENT exactly, which only ever shrinks. Newly \
         divergent: {regressed:?}. Now recovered, remove from TERSER_KNOWN_DIVERGENT: {fixed:?}.\n{}",
        divergent.len(),
        shown.join("\n\n")
    );
}

struct ChangingMutation {
    seed: u64,
    expected: Run,
    recovered: String,
    mutated: String,
}

fn first_changing_mutation() -> Option<ChangingMutation> {
    for seed in 0..SEED_COUNT {
        let source: String = generate(seed);
        let expected: Run = run_node(&source);
        let recovered: Recovered = recover(&source);
        let final_text: String = recovered.ast_stage.unwrap_or(recovered.text_stage);
        for (from, to) in MUTATIONS {
            let Some(at) = final_text.rfind(from) else {
                continue;
            };
            let mut mutated: String = final_text.clone();
            mutated.replace_range(at..at + from.len(), to);
            let observed: Run = run_node(&mutated);
            if observed.success && observed.stdout != expected.stdout {
                return Some(ChangingMutation {
                    seed,
                    expected,
                    recovered: final_text,
                    mutated,
                });
            }
        }
    }
    None
}

#[test]
fn a_one_operator_mutation_of_a_recovered_program_fails_the_grade() {
    let found: Option<ChangingMutation> = first_changing_mutation();
    assert!(
        found.is_some(),
        "no single-operator mutation of any recovered program changed its output"
    );
    let Some(case) = found else {
        unreachable!("the assertion above has already failed the test");
    };
    let seed: u64 = case.seed;
    assert!(
        grade("mutation", &case.expected, &case.mutated).is_err(),
        "seed {seed}: the grade accepted a program whose output changed"
    );
    assert!(
        grade("unmutated", &case.expected, &case.recovered).is_ok(),
        "seed {seed}: the unmutated recovery must pass the same grade"
    );
}

fn pinned_cases() -> Vec<PathBuf> {
    let dir: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(PINNED_DIR);
    let mut cases: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", dir.display()))
        .map(|entry: std::io::Result<fs::DirEntry>| entry.expect("directory entry").path())
        .filter(|path: &PathBuf| path.extension().is_some_and(|ext| ext == "js"))
        .collect();
    cases.sort();
    cases
}

#[test]
fn pinned_minimal_shapes_keep_their_output() {
    let cases: Vec<PathBuf> = pinned_cases();
    assert!(!cases.is_empty(), "the pinned minimal shapes are missing");
    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let source: String = fs::read_to_string(case)
            .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", case.display()));
        let label: String = case.display().to_string();
        match grade_source(&label, &source) {
            Ok(true) => {}
            Ok(false) => failures.push(format!(
                "{label}: unminify no longer rewrites this pinned shape, so it grades nothing"
            )),
            Err(failure) => failures.push(failure),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
