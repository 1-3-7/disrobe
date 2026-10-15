use std::collections::BTreeSet;

use disrobe_core::neutralize::{
    Anchor, MAX_PATCH_LENGTH, NeutralizationPlan, NeutralizeError, Patch, Refusal, RuntimeCheck,
};
use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast as oast;
use oxc_ast::visit::walk;
use oxc_parser::Parser;
use oxc_semantic::ScopeFlags;
use oxc_span::{GetSpan, SourceType, Span};
use thiserror::Error;

use crate::sandbox_guard::nesting_is_safe;

pub const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SITES: usize = 1024;
const MAX_EVIDENCE_CHARS: usize = 96;
const MAX_CONCAT_DEPTH: usize = 32;
const EPOCH_MILLIS_FLOOR: f64 = 1.0e11;
const INTEGRITY_DIGEST_FLOOR: f64 = 4_294_967_296.0;
const DOCUMENT_NAME_SIGNATURE: [f64; 8] = [7.0, 116.0, 5.0, 101.0, 3.0, 117.0, 0.0, 100.0];
const CONSOLE_METHODS: [&str; 7] = [
    "log",
    "warn",
    "info",
    "error",
    "exception",
    "table",
    "trace",
];
const TRAP_TEXTS: [&str; 3] = ["debugger", "debu", "while (true) {}"];
const HOST_PROBE_GLOBALS: [&str; 11] = [
    "window",
    "document",
    "navigator",
    "process",
    "global",
    "require",
    "module",
    "self",
    "importScripts",
    "Deno",
    "Bun",
];

const PATTERN_OBFUSCATOR_IO_DOMAIN_LOCK: &str = "obfuscator.io domainLock: document/domain/location/hostname name signatures, then a location write when no allowed domain matched";
const PATTERN_DOMAIN_LOCK: &str =
    "location.hostname/host/href/origin or document.domain tested before a trap branch";
const PATTERN_HOST_PROBE: &str = "typeof window/document/navigator/process probe or navigator.webdriver/process.versions read before a trap branch";
const PATTERN_DATE_LOCK: &str =
    "Date.now() or new Date() compared with an epoch-millisecond constant before a trap branch";
const PATTERN_INTEGRITY: &str =
    "digest of a function's own source compared with an embedded constant, trapping on mismatch";
const PATTERN_DEBUGGER_STATEMENT: &str = "debugger statement";
const PATTERN_CONSTRUCTED_TRAP: &str =
    "Function-constructor body text 'debugger', 'debu' + 'gger' or 'while (true) {}'";
const PATTERN_CONSOLE_HIJACK: &str =
    "console object aliased as X = X || {} and its methods overwritten inside a loop";
const PATTERN_RATCHET: &str =
    "obfuscator.io debugProtection ratchet (counter / counter with counter % 20)";

const RISK_TEST_CONSTANT: &str = "the test becomes a constant that selects the non-trap branch; side effects inside the test no longer run and the script behaves as if the check passed";
const RISK_BLANK_BRANCH: &str = "the trap branch body becomes whitespace; the test still runs, so a test that throws on this host still throws";
const RISK_DEBUGGER: &str =
    "the debugger keyword becomes whitespace and leaves an empty statement; nothing else changes";
const RISK_CONSTRUCTED_TRAP: &str = "the constructed body text becomes a line comment of the same length, so the Function-built trap runs as an empty function";
const RISK_CONSOLE: &str = "the method overwrite becomes the constant 0; the silent stand-ins are still built but never installed on console";
const RISK_INTEGRITY: &str = "the digest comparison becomes a constant true; an edited function body runs instead of trapping and real tampering is no longer reported";

#[derive(Debug, Error)]
pub enum JsNeutralizeError {
    #[error(
        "DR-JSDEOB-0020: the script holds {observed} bytes, above the {maximum}-byte neutralization scan limit"
    )]
    TooLarge { observed: usize, maximum: usize },

    #[error(
        "DR-JSDEOB-0021: the script nests deeper than the parser safety limits, so no neutralization plan is made"
    )]
    TooDeep,

    #[error("DR-JSDEOB-0022: the script does not parse, so no neutralization plan is made: {0}")]
    Parse(String),

    #[error(
        "DR-JSDEOB-0023: the script holds more than {maximum} anti-analysis sites; the plan is refused rather than truncated"
    )]
    TooManySites { maximum: usize },

    #[error("DR-JSDEOB-0024: the neutralization plan rejected a patch: {0}")]
    Plan(#[from] NeutralizeError),
}

#[derive(Debug, Clone)]
struct Site {
    check: RuntimeCheck,
    start: usize,
    end: usize,
    replacement: Vec<u8>,
    pattern: &'static str,
    risk: &'static str,
}

#[derive(Debug, Clone)]
struct Declined {
    check: RuntimeCheck,
    start: usize,
    end: usize,
    pattern: &'static str,
    reason: String,
}

pub fn plan_js_neutralization(source: &str) -> Result<NeutralizationPlan, JsNeutralizeError> {
    if source.len() > MAX_SCAN_BYTES {
        return Err(JsNeutralizeError::TooLarge {
            observed: source.len(),
            maximum: MAX_SCAN_BYTES,
        });
    }
    if !nesting_is_safe(source) {
        return Err(JsNeutralizeError::TooDeep);
    }
    let allocator: Allocator = Allocator::default();
    let program: oast::Program<'_> = parse(&allocator, source)?;

    let mut prescan: Prescan<'_> = Prescan {
        source,
        integrity_hashers: BTreeSet::new(),
        countermeasures: BTreeSet::new(),
        signature_functions: BTreeSet::new(),
        matchers: Vec::new(),
        first_ratchet: None,
    };
    prescan.visit_program(&program);

    let mut scanner: Scanner<'_, '_> = Scanner {
        source,
        prescan: &prescan,
        frames: vec![Frame::default()],
        sites: Vec::new(),
        declined: Vec::new(),
        overflow: false,
    };
    scanner.visit_program(&program);
    scanner.close_frame();
    if scanner.overflow {
        return Err(JsNeutralizeError::TooManySites { maximum: MAX_SITES });
    }
    if let Some(at) = prescan.first_ratchet
        && !scanner
            .sites
            .iter()
            .any(|site: &Site| site.pattern == PATTERN_CONSTRUCTED_TRAP)
    {
        scanner.declined.push(Declined {
            check: RuntimeCheck::JsDebuggerTrap,
            start: at,
            end: at,
            pattern: PATTERN_RATCHET,
            reason: "the ratchet is present but its debugger and while-loop texts are not plain string literals (an encoded string array holds them); run `deob` first and plan the recovered script".to_owned(),
        });
    }
    build_plan(source, scanner.sites, scanner.declined)
}

fn parse<'a>(
    allocator: &'a Allocator,
    source: &'a str,
) -> Result<oast::Program<'a>, JsNeutralizeError> {
    let script: oxc_parser::ParserReturn<'a> =
        Parser::new(allocator, source, SourceType::cjs()).parse();
    if !script.panicked && script.errors.is_empty() {
        return Ok(script.program);
    }
    let module: oxc_parser::ParserReturn<'a> =
        Parser::new(allocator, source, SourceType::mjs()).parse();
    if !module.panicked && module.errors.is_empty() {
        return Ok(module.program);
    }
    let message: String = script
        .errors
        .first()
        .map_or_else(|| "the parser stopped".to_owned(), ToString::to_string);
    Err(JsNeutralizeError::Parse(message))
}

fn build_plan(
    source: &str,
    mut sites: Vec<Site>,
    declined: Vec<Declined>,
) -> Result<NeutralizationPlan, JsNeutralizeError> {
    sites.sort_by(|a: &Site, b: &Site| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut plan: NeutralizationPlan = NeutralizationPlan::new(source.as_bytes());
    let mut covered_until: usize = 0;
    for site in sites {
        if site.start < covered_until {
            continue;
        }
        covered_until = site.end;
        plan.push_patch(Patch {
            id: format!("{}-{:x}", site.check.label(), site.start),
            check: site.check,
            anchor: anchor(source, site.start, site.end, site.pattern),
            file_offset: site.start as u64,
            original: source.as_bytes()[site.start..site.end].to_vec(),
            replacement: site.replacement,
            risk: site.risk.to_owned(),
        })?;
    }
    for refused in declined {
        plan.refusals.push(Refusal {
            check: refused.check,
            anchor: anchor(source, refused.start, refused.end, refused.pattern),
            reason: refused.reason,
        });
    }
    Ok(plan)
}

fn anchor(source: &str, start: usize, end: usize, pattern: &str) -> Anchor {
    let snippet: String = source
        .get(start..end)
        .unwrap_or_default()
        .chars()
        .take(MAX_EVIDENCE_CHARS)
        .map(|c: char| if c.is_control() { ' ' } else { c })
        .collect();
    Anchor {
        address: start as u64,
        instruction: snippet,
        pattern: pattern.to_owned(),
    }
}

fn blank(original: &[u8]) -> Vec<u8> {
    original
        .iter()
        .map(|b: &u8| if matches!(b, b'\n' | b'\r') { *b } else { b' ' })
        .collect()
}

fn constant_over(original: &[u8], value: u8) -> Vec<u8> {
    let mut out: Vec<u8> = blank(original);
    if let Some(first) = out.first_mut() {
        *first = value;
    }
    out
}

fn comment_literal(original: &[u8]) -> Option<Vec<u8>> {
    let quote: u8 = *original.first()?;
    if original.len() < 4 || !matches!(quote, b'\'' | b'"') || original.last() != Some(&quote) {
        return None;
    }
    let mut out: Vec<u8> = vec![b' '; original.len()];
    out[0] = quote;
    out[1] = b'/';
    out[2] = b'/';
    out[original.len() - 1] = quote;
    Some(out)
}

const fn span_range(span: Span) -> (usize, usize) {
    (span.start as usize, span.end as usize)
}

fn property_name<'a>(member: &'a oast::MemberExpression<'a>) -> Option<&'a str> {
    match member {
        oast::MemberExpression::StaticMemberExpression(m) => Some(m.property.name.as_str()),
        oast::MemberExpression::ComputedMemberExpression(m) => match &m.expression {
            oast::Expression::StringLiteral(s) => Some(s.value.as_str()),
            _ => None,
        },
        oast::MemberExpression::PrivateFieldExpression(_) => None,
    }
}

fn member_object<'a>(member: &'a oast::MemberExpression<'a>) -> &'a oast::Expression<'a> {
    match member {
        oast::MemberExpression::StaticMemberExpression(m) => &m.object,
        oast::MemberExpression::ComputedMemberExpression(m) => &m.object,
        oast::MemberExpression::PrivateFieldExpression(m) => &m.object,
    }
}

fn identifier_name<'a>(expr: &'a oast::Expression<'a>) -> Option<&'a str> {
    match expr.without_parentheses() {
        oast::Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

fn names_location(expr: &oast::Expression<'_>) -> bool {
    match expr.without_parentheses() {
        oast::Expression::Identifier(id) => id.name == "location",
        other => other
            .as_member_expression()
            .and_then(property_name)
            .is_some_and(|name: &str| name == "location"),
    }
}

fn const_truthy(expr: &oast::Expression<'_>) -> Option<bool> {
    match expr.without_parentheses() {
        oast::Expression::BooleanLiteral(b) => Some(b.value),
        oast::Expression::NumericLiteral(n) => Some(n.value != 0.0 && !n.value.is_nan()),
        oast::Expression::StringLiteral(s) => Some(!s.value.is_empty()),
        oast::Expression::ArrayExpression(_) | oast::Expression::ObjectExpression(_) => Some(true),
        oast::Expression::UnaryExpression(u) if u.operator == oast::UnaryOperator::LogicalNot => {
            const_truthy(&u.argument).map(|v: bool| !v)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Exit {
    Quiet,
    Loud,
}

fn is_redirect_write(expr: &oast::Expression<'_>, double_member_redirect: bool) -> bool {
    let oast::Expression::AssignmentExpression(assign) = expr.without_parentheses() else {
        return false;
    };
    let Some(target) = assign.left.as_member_expression() else {
        return false;
    };
    if property_name(target).is_some_and(|name: &str| name == "location")
        || (property_name(target).is_some_and(|name: &str| name == "href")
            && names_location(member_object(target)))
    {
        return true;
    }
    double_member_redirect
        && matches!(target, oast::MemberExpression::ComputedMemberExpression(_))
        && matches!(
            member_object(target).without_parentheses(),
            oast::Expression::ComputedMemberExpression(_)
        )
}

#[derive(Clone, Copy)]
struct ExitRules<'c> {
    double_member_redirect: bool,
    countermeasures: &'c BTreeSet<String>,
}

fn terminator(stmt: &oast::Statement<'_>, rules: ExitRules<'_>) -> Option<Exit> {
    match stmt {
        oast::Statement::ReturnStatement(ret) => match &ret.argument {
            None => Some(Exit::Quiet),
            Some(oast::Expression::Identifier(id)) if id.name == "undefined" => Some(Exit::Quiet),
            Some(oast::Expression::UnaryExpression(u))
                if u.operator == oast::UnaryOperator::Void =>
            {
                Some(Exit::Quiet)
            }
            Some(_) => None,
        },
        oast::Statement::ThrowStatement(_) | oast::Statement::DebuggerStatement(_) => {
            Some(Exit::Loud)
        }
        oast::Statement::WhileStatement(w) => {
            (const_truthy(&w.test) == Some(true)).then_some(Exit::Loud)
        }
        oast::Statement::DoWhileStatement(w) => {
            (const_truthy(&w.test) == Some(true)).then_some(Exit::Loud)
        }
        oast::Statement::ForStatement(f) => f.test.is_none().then_some(Exit::Loud),
        oast::Statement::ExpressionStatement(e) => {
            let expr: &oast::Expression<'_> = e.expression.without_parentheses();
            if is_redirect_write(expr, rules.double_member_redirect) {
                return Some(Exit::Loud);
            }
            let oast::Expression::CallExpression(call) = expr else {
                return None;
            };
            match call.callee.without_parentheses() {
                oast::Expression::Identifier(id) => (call.arguments.is_empty()
                    && rules.countermeasures.contains(id.name.as_str()))
                .then_some(Exit::Loud),
                callee => {
                    let member: &oast::MemberExpression<'_> = callee.as_member_expression()?;
                    let name: &str = property_name(member)?;
                    let object: &oast::Expression<'_> = member_object(member);
                    let exits: bool = (matches!(name, "exit" | "abort")
                        && identifier_name(object) == Some("process"))
                        || (matches!(name, "replace" | "assign" | "reload")
                            && names_location(object));
                    exits.then_some(Exit::Loud)
                }
            }
        }
        _ => None,
    }
}

fn branch_exit(stmt: &oast::Statement<'_>, rules: ExitRules<'_>) -> Option<Exit> {
    let oast::Statement::BlockStatement(block) = stmt else {
        return terminator(stmt, rules);
    };
    sequence_exit(&block.body, rules)
}

fn sequence_exit(body: &[oast::Statement<'_>], rules: ExitRules<'_>) -> Option<Exit> {
    let (last, rest): (&oast::Statement<'_>, &[oast::Statement<'_>]) = body.split_last()?;
    let last_exit: Exit = terminator(last, rules)?;
    let mut announced: bool = false;
    for earlier in rest {
        match terminator(earlier, rules) {
            Some(_) => {}
            None if matches!(earlier, oast::Statement::ExpressionStatement(_)) => announced = true,
            None => return None,
        }
    }
    if announced && last_exit == Exit::Quiet {
        Some(Exit::Loud)
    } else {
        Some(last_exit)
    }
}

struct HasherCall<'h> {
    hashers: &'h BTreeSet<String>,
    found: bool,
}

impl<'a> Visit<'a> for HasherCall<'_> {
    fn visit_call_expression(&mut self, call: &oast::CallExpression<'a>) {
        if identifier_name(&call.callee).is_some_and(|name: &str| self.hashers.contains(name)) {
            self.found = true;
            return;
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_function(&mut self, _func: &oast::Function<'a>, _flags: ScopeFlags) {}

    fn visit_arrow_function_expression(&mut self, _arrow: &oast::ArrowFunctionExpression<'a>) {}
}

struct Prescan<'s> {
    source: &'s str,
    integrity_hashers: BTreeSet<String>,
    countermeasures: BTreeSet<String>,
    signature_functions: BTreeSet<u32>,
    matchers: Vec<(u32, usize)>,
    first_ratchet: Option<usize>,
}

impl<'a> Visit<'a> for Prescan<'_> {
    fn visit_function(&mut self, func: &oast::Function<'a>, flags: ScopeFlags) {
        if let (Some(id), Some(body)) = (&func.id, &func.body) {
            let (start, end): (usize, usize) = span_range(body.span);
            let text: &str = self.source.get(start..end).unwrap_or_default();
            if text.contains("toString") && text.contains("replace") {
                self.integrity_hashers.insert(id.name.to_string());
            }
            let rules: ExitRules<'_> = ExitRules {
                double_member_redirect: false,
                countermeasures: &BTreeSet::new(),
            };
            if sequence_exit(&body.statements, rules) == Some(Exit::Loud) {
                self.countermeasures.insert(id.name.to_string());
            }
        }
        self.matchers.push((func.span.start, 0));
        walk::walk_function(self, func, flags);
        self.matchers.pop();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &oast::ArrowFunctionExpression<'a>) {
        self.matchers.push((arrow.span.start, 0));
        walk::walk_arrow_function_expression(self, arrow);
        self.matchers.pop();
    }

    fn visit_numeric_literal(&mut self, lit: &oast::NumericLiteral<'a>) {
        let Some((owner, matched)) = self.matchers.last_mut() else {
            return;
        };
        let value: u64 = lit.value.to_bits();
        let next: usize = if value == DOCUMENT_NAME_SIGNATURE[*matched].to_bits() {
            *matched + 1
        } else {
            usize::from(value == DOCUMENT_NAME_SIGNATURE[0].to_bits())
        };
        if next == DOCUMENT_NAME_SIGNATURE.len() {
            self.signature_functions.insert(*owner);
            *matched = 0;
        } else {
            *matched = next;
        }
    }

    fn visit_binary_expression(&mut self, expr: &oast::BinaryExpression<'a>) {
        if expr.operator == oast::BinaryOperator::Division
            && let (Some(left), Some(right)) =
                (identifier_name(&expr.left), identifier_name(&expr.right))
            && left == right
        {
            self.first_ratchet.get_or_insert(expr.span.start as usize);
        }
        walk::walk_binary_expression(self, expr);
    }
}

#[derive(Debug, Default)]
struct Frame {
    signature: bool,
    hashed_bindings: BTreeSet<String>,
    console_alias: Option<String>,
    console_alias_named: bool,
    console_methods: bool,
    loop_depth: usize,
    console_writes: Vec<(usize, usize)>,
}

struct Scanner<'s, 'p> {
    source: &'s str,
    prescan: &'p Prescan<'s>,
    frames: Vec<Frame>,
    sites: Vec<Site>,
    declined: Vec<Declined>,
    overflow: bool,
}

#[derive(Debug, Default)]
struct TestProbe {
    host: bool,
    domain: bool,
    date_call: bool,
    epoch_literal: bool,
}

impl TestProbe {
    fn member(&mut self, member: &oast::MemberExpression<'_>) {
        let Some(name) = property_name(member) else {
            return;
        };
        let object: &oast::Expression<'_> = member_object(member);
        let object_name: Option<&str> = identifier_name(object);
        let object_property: Option<&str> = object.as_member_expression().and_then(property_name);
        if matches!(name, "hostname" | "host" | "href" | "origin") && names_location(object) {
            self.domain = true;
        }
        if name == "domain"
            && (object_name == Some("document") || object_property == Some("document"))
        {
            self.domain = true;
        }
        if (name == "webdriver" && object_name == Some("navigator"))
            || (matches!(name, "versions" | "release") && object_name == Some("process"))
        {
            self.host = true;
        }
        if matches!(name, "now" | "getTime") && (object_name == Some("Date") || name == "getTime") {
            self.date_call = true;
        }
    }
}

impl<'a> Visit<'a> for TestProbe {
    fn visit_unary_expression(&mut self, expr: &oast::UnaryExpression<'a>) {
        if expr.operator == oast::UnaryOperator::Typeof
            && identifier_name(&expr.argument)
                .is_some_and(|name: &str| HOST_PROBE_GLOBALS.contains(&name))
        {
            self.host = true;
        }
        walk::walk_unary_expression(self, expr);
    }

    fn visit_member_expression(&mut self, member: &oast::MemberExpression<'a>) {
        self.member(member);
        walk::walk_member_expression(self, member);
    }

    fn visit_new_expression(&mut self, expr: &oast::NewExpression<'a>) {
        if identifier_name(&expr.callee) == Some("Date") {
            self.date_call = true;
        }
        walk::walk_new_expression(self, expr);
    }

    fn visit_numeric_literal(&mut self, lit: &oast::NumericLiteral<'a>) {
        if lit.value >= EPOCH_MILLIS_FLOOR {
            self.epoch_literal = true;
        }
    }
}

impl Scanner<'_, '_> {
    fn frame(&mut self) -> &mut Frame {
        if self.frames.is_empty() {
            self.frames.push(Frame::default());
        }
        let last: usize = self.frames.len() - 1;
        &mut self.frames[last]
    }

    fn open_frame(&mut self, start: u32) {
        self.frames.push(Frame {
            signature: self.prescan.signature_functions.contains(&start),
            ..Frame::default()
        });
    }

    fn close_frame(&mut self) {
        let Some(frame) = self.frames.pop() else {
            return;
        };
        if frame.console_alias.is_none() || !(frame.console_alias_named || frame.console_methods) {
            return;
        }
        for (start, end) in frame.console_writes {
            self.site_or_decline(
                RuntimeCheck::JsConsoleHijack,
                start,
                end,
                PATTERN_CONSOLE_HIJACK,
                RISK_CONSOLE,
                |original: &[u8]| constant_over(original, b'0'),
            );
        }
    }

    fn site_or_decline(
        &mut self,
        check: RuntimeCheck,
        start: usize,
        end: usize,
        pattern: &'static str,
        risk: &'static str,
        replace: impl FnOnce(&[u8]) -> Vec<u8>,
    ) {
        let Some(original) = self.source.as_bytes().get(start..end) else {
            return;
        };
        if original.is_empty() || self.overflow {
            return;
        }
        if self.sites.len() + self.declined.len() >= MAX_SITES {
            self.overflow = true;
            return;
        }
        if original.len() > MAX_PATCH_LENGTH {
            self.declined.push(Declined {
                check,
                start,
                end,
                pattern,
                reason: format!(
                    "the site spans {} bytes, above the {MAX_PATCH_LENGTH}-byte patch cap",
                    original.len()
                ),
            });
            return;
        }
        let replacement: Vec<u8> = replace(original);
        self.sites.push(Site {
            check,
            start,
            end,
            replacement,
            pattern,
            risk,
        });
    }

    fn hashed_binding(&self, name: &str) -> bool {
        self.frames
            .iter()
            .rev()
            .any(|frame: &Frame| frame.hashed_bindings.contains(name))
    }

    fn is_integrity_test(&self, test: &oast::Expression<'_>) -> bool {
        let oast::Expression::BinaryExpression(bin) = test.without_parentheses() else {
            return false;
        };
        if !matches!(
            bin.operator,
            oast::BinaryOperator::Equality
                | oast::BinaryOperator::StrictEquality
                | oast::BinaryOperator::Inequality
                | oast::BinaryOperator::StrictInequality
        ) {
            return false;
        }
        let pair: [(&oast::Expression<'_>, &oast::Expression<'_>); 2] =
            [(&bin.left, &bin.right), (&bin.right, &bin.left)];
        pair.iter().any(|(name, digest)| {
            identifier_name(name).is_some_and(|n: &str| self.hashed_binding(n))
                && matches!(digest.without_parentheses(), oast::Expression::NumericLiteral(n) if n.value >= INTEGRITY_DIGEST_FLOOR)
        })
    }

    fn classify_if(
        &self,
        stmt: &oast::IfStatement<'_>,
    ) -> Option<(RuntimeCheck, &'static str, bool)> {
        let signature: bool = self
            .frames
            .last()
            .is_some_and(|frame: &Frame| frame.signature);
        let rules: ExitRules<'_> = ExitRules {
            double_member_redirect: true,
            countermeasures: &self.prescan.countermeasures,
        };
        if signature
            && branch_exit(&stmt.consequent, rules) == Some(Exit::Loud)
            && stmt.alternate.is_none()
        {
            return Some((
                RuntimeCheck::JsDomainLock,
                PATTERN_OBFUSCATOR_IO_DOMAIN_LOCK,
                true,
            ));
        }
        if self.is_integrity_test(&stmt.test) {
            return Some((RuntimeCheck::JsIntegrityHash, PATTERN_INTEGRITY, true));
        }
        let mut probe: TestProbe = TestProbe::default();
        probe.visit_expression(&stmt.test);
        if probe.domain {
            Some((RuntimeCheck::JsDomainLock, PATTERN_DOMAIN_LOCK, true))
        } else if probe.date_call && probe.epoch_literal {
            Some((RuntimeCheck::JsDateLock, PATTERN_DATE_LOCK, true))
        } else if probe.host {
            Some((
                RuntimeCheck::JsHostEnvironmentProbe,
                PATTERN_HOST_PROBE,
                false,
            ))
        } else {
            None
        }
    }

    fn plan_if(&mut self, stmt: &oast::IfStatement<'_>) {
        if const_truthy(&stmt.test).is_some() {
            return;
        }
        let Some((check, pattern, quiet_exit_counts)) = self.classify_if(stmt) else {
            return;
        };
        let rules: ExitRules<'_> = ExitRules {
            double_member_redirect: check == RuntimeCheck::JsDomainLock,
            countermeasures: &self.prescan.countermeasures,
        };
        let counts = |exit: Option<Exit>| -> bool {
            match exit {
                Some(Exit::Loud) => true,
                Some(Exit::Quiet) => quiet_exit_counts,
                None => false,
            }
        };
        let consequent_traps: bool = counts(branch_exit(&stmt.consequent, rules));
        let alternate_traps: bool = stmt
            .alternate
            .as_ref()
            .is_some_and(|alt: &oast::Statement<'_>| counts(branch_exit(alt, rules)));
        let take_consequent: bool = match (consequent_traps, alternate_traps) {
            (true, false) => false,
            (false, true) => true,
            _ => return,
        };
        let risk: &'static str = if check == RuntimeCheck::JsIntegrityHash {
            RISK_INTEGRITY
        } else {
            RISK_TEST_CONSTANT
        };
        let (test_start, test_end): (usize, usize) = span_range(stmt.test.span());
        if test_end - test_start <= MAX_PATCH_LENGTH {
            let value: u8 = if take_consequent { b'1' } else { b'0' };
            self.site_or_decline(
                check,
                test_start,
                test_end,
                pattern,
                risk,
                |original: &[u8]| constant_over(original, value),
            );
            return;
        }
        if take_consequent || stmt.alternate.is_some() {
            self.declined.push(Declined {
                check,
                start: test_start,
                end: test_end,
                pattern,
                reason: format!(
                    "the test spans {} bytes, above the {MAX_PATCH_LENGTH}-byte patch cap, and both branches hold code, so blanking one branch would drop real behaviour",
                    test_end - test_start
                ),
            });
            return;
        }
        match &stmt.consequent {
            oast::Statement::BlockStatement(block) => {
                let (start, end): (usize, usize) = span_range(block.span);
                self.site_or_decline(
                    check,
                    start + 1,
                    end.saturating_sub(1),
                    pattern,
                    RISK_BLANK_BRANCH,
                    blank,
                );
            }
            single => {
                let (start, end): (usize, usize) = span_range(single.span());
                self.site_or_decline(
                    check,
                    start,
                    end,
                    pattern,
                    RISK_BLANK_BRANCH,
                    |original: &[u8]| {
                        let mut out: Vec<u8> = blank(original);
                        out[0] = b';';
                        out
                    },
                );
            }
        }
    }

    fn trap_literals(&mut self, expr: &oast::Expression<'_>, depth: usize) {
        if depth > MAX_CONCAT_DEPTH {
            return;
        }
        match expr.without_parentheses() {
            oast::Expression::StringLiteral(lit) => self.trap_literal(lit),
            oast::Expression::BinaryExpression(bin)
                if bin.operator == oast::BinaryOperator::Addition =>
            {
                self.trap_literals(&bin.left, depth + 1);
                self.trap_literals(&bin.right, depth + 1);
            }
            _ => {}
        }
    }

    fn trap_literal(&mut self, lit: &oast::StringLiteral<'_>) {
        if !TRAP_TEXTS.contains(&lit.value.as_str()) {
            return;
        }
        let (start, end): (usize, usize) = span_range(lit.span);
        let Some(replacement) = self
            .source
            .as_bytes()
            .get(start..end)
            .and_then(comment_literal)
        else {
            return;
        };
        self.site_or_decline(
            RuntimeCheck::JsDebuggerTrap,
            start,
            end,
            PATTERN_CONSTRUCTED_TRAP,
            RISK_CONSTRUCTED_TRAP,
            |_: &[u8]| replacement,
        );
    }
}

fn is_constructor_call(callee: &oast::Expression<'_>) -> bool {
    let callee: &oast::Expression<'_> = callee.without_parentheses();
    if identifier_name(callee) == Some("Function") {
        return true;
    }
    let Some(member) = callee.as_member_expression() else {
        return false;
    };
    property_name(member) == Some("constructor")
        || matches!(
            member_object(member).without_parentheses(),
            oast::Expression::FunctionExpression(_) | oast::Expression::ArrowFunctionExpression(_)
        )
}

fn console_alias_target<'a>(init: &'a oast::Expression<'a>, source: &str) -> Option<bool> {
    let oast::Expression::AssignmentExpression(assign) = init.without_parentheses() else {
        return None;
    };
    if assign.operator != oast::AssignmentOperator::Assign {
        return None;
    }
    let target: &oast::MemberExpression<'_> = assign.left.as_member_expression()?;
    let oast::Expression::LogicalExpression(logical) = assign.right.without_parentheses() else {
        return None;
    };
    if logical.operator != oast::LogicalOperator::Or {
        return None;
    }
    let oast::Expression::ObjectExpression(fallback) = logical.right.without_parentheses() else {
        return None;
    };
    if !fallback.properties.is_empty() {
        return None;
    }
    let (ts, te): (usize, usize) = span_range(target.span());
    let (ls, le): (usize, usize) = span_range(logical.left.span());
    let target_text: &str = source.get(ts..te)?;
    (target_text == source.get(ls..le)?).then(|| property_name(target) == Some("console"))
}

impl<'a> Visit<'a> for Scanner<'_, '_> {
    fn visit_function(&mut self, func: &oast::Function<'a>, flags: ScopeFlags) {
        self.open_frame(func.span.start);
        walk::walk_function(self, func, flags);
        self.close_frame();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &oast::ArrowFunctionExpression<'a>) {
        self.open_frame(arrow.span.start);
        walk::walk_arrow_function_expression(self, arrow);
        self.close_frame();
    }

    fn visit_for_statement(&mut self, stmt: &oast::ForStatement<'a>) {
        self.frame().loop_depth += 1;
        walk::walk_for_statement(self, stmt);
        self.frame().loop_depth -= 1;
    }

    fn visit_for_in_statement(&mut self, stmt: &oast::ForInStatement<'a>) {
        self.frame().loop_depth += 1;
        walk::walk_for_in_statement(self, stmt);
        self.frame().loop_depth -= 1;
    }

    fn visit_for_of_statement(&mut self, stmt: &oast::ForOfStatement<'a>) {
        self.frame().loop_depth += 1;
        walk::walk_for_of_statement(self, stmt);
        self.frame().loop_depth -= 1;
    }

    fn visit_while_statement(&mut self, stmt: &oast::WhileStatement<'a>) {
        self.frame().loop_depth += 1;
        walk::walk_while_statement(self, stmt);
        self.frame().loop_depth -= 1;
    }

    fn visit_do_while_statement(&mut self, stmt: &oast::DoWhileStatement<'a>) {
        self.frame().loop_depth += 1;
        walk::walk_do_while_statement(self, stmt);
        self.frame().loop_depth -= 1;
    }

    fn visit_variable_declarator(&mut self, decl: &oast::VariableDeclarator<'a>) {
        if let (oast::BindingPatternKind::BindingIdentifier(id), Some(init)) =
            (&decl.id.kind, &decl.init)
        {
            let name: String = id.name.to_string();
            if let Some(named) = console_alias_target(init, self.source) {
                let frame: &mut Frame = self.frame();
                frame.console_alias = Some(name.clone());
                frame.console_alias_named = named;
            }
            let mut calls: HasherCall<'_> = HasherCall {
                hashers: &self.prescan.integrity_hashers,
                found: false,
            };
            if !calls.hashers.is_empty() {
                calls.visit_expression(init);
            }
            if calls.found {
                self.frame().hashed_bindings.insert(name);
            }
        }
        walk::walk_variable_declarator(self, decl);
    }

    fn visit_array_expression(&mut self, array: &oast::ArrayExpression<'a>) {
        let literals: Vec<&str> = array
            .elements
            .iter()
            .filter_map(|element: &oast::ArrayExpressionElement<'a>| match element {
                oast::ArrayExpressionElement::StringLiteral(s) => Some(s.value.as_str()),
                _ => None,
            })
            .collect();
        if array.elements.len() == CONSOLE_METHODS.len()
            && !literals.is_empty()
            && literals
                .iter()
                .all(|value: &&str| CONSOLE_METHODS.contains(value))
        {
            self.frame().console_methods = true;
        }
        if self.prescan.first_ratchet.is_some() {
            for element in &array.elements {
                if let oast::ArrayExpressionElement::StringLiteral(lit) = element {
                    self.trap_literal(lit);
                }
            }
        }
        walk::walk_array_expression(self, array);
    }

    fn visit_assignment_expression(&mut self, assign: &oast::AssignmentExpression<'a>) {
        if assign.operator == oast::AssignmentOperator::Assign
            && let Some(oast::MemberExpression::ComputedMemberExpression(target)) =
                assign.left.as_member_expression()
            && let Some(object) = identifier_name(&target.object)
        {
            let frame: &mut Frame = self.frame();
            if frame.loop_depth > 0 && frame.console_alias.as_deref() == Some(object) {
                let (start, end): (usize, usize) = span_range(assign.span);
                frame.console_writes.push((start, end));
            }
        }
        walk::walk_assignment_expression(self, assign);
    }

    fn visit_call_expression(&mut self, call: &oast::CallExpression<'a>) {
        if is_constructor_call(&call.callee)
            && let Some(first) = call
                .arguments
                .first()
                .and_then(oast::Argument::as_expression)
        {
            self.trap_literals(first, 0);
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_debugger_statement(&mut self, stmt: &oast::DebuggerStatement) {
        let start: usize = stmt.span.start as usize;
        self.site_or_decline(
            RuntimeCheck::JsDebuggerTrap,
            start,
            start + "debugger".len(),
            PATTERN_DEBUGGER_STATEMENT,
            RISK_DEBUGGER,
            blank,
        );
    }

    fn visit_if_statement(&mut self, stmt: &oast::IfStatement<'a>) {
        self.plan_if(stmt);
        walk::walk_if_statement(self, stmt);
    }
}
