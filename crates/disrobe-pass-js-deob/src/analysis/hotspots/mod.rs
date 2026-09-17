mod predicates;

use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, CallExpression, Expression, NewExpression,
    ObjectExpression, ObjectProperty, StaticMemberExpression,
};
use oxc_ast::visit::walk;
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};
use serde::Serialize;

use predicates::{
    LineIndex, arg_expression, disables_tls, find_object_argument, ident_name,
    is_any_global_object, is_global_object, is_location_target, is_process_env, is_static_string,
    is_string_valued, member_callee, object_has_true_flag, property_key_name, static_string_value,
    unwrap_paren,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HotspotRule {
    DynamicCodeExecution,
    WeakHash,
    WeakCipher,
    InsecureCipherMode,
    InsecureTls,
    CookieMissingHttpOnly,
    CookieMissingSecure,
    DomXss,
}

impl HotspotRule {
    #[must_use]
    pub const fn sonar_id(self) -> &'static str {
        match self {
            Self::DynamicCodeExecution => "S1523",
            Self::WeakHash => "S4790",
            Self::WeakCipher => "S5547",
            Self::InsecureCipherMode => "S5542",
            Self::InsecureTls => "S4830",
            Self::CookieMissingHttpOnly => "S3330",
            Self::CookieMissingSecure => "S2092",
            Self::DomXss => "S5696",
        }
    }

    #[must_use]
    pub const fn severity(self) -> HotspotSeverity {
        match self {
            Self::InsecureTls => HotspotSeverity::Critical,
            Self::DynamicCodeExecution | Self::WeakCipher | Self::DomXss => HotspotSeverity::High,
            Self::WeakHash
            | Self::InsecureCipherMode
            | Self::CookieMissingHttpOnly
            | Self::CookieMissingSecure => HotspotSeverity::Medium,
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::DynamicCodeExecution,
            Self::WeakHash,
            Self::WeakCipher,
            Self::InsecureCipherMode,
            Self::InsecureTls,
            Self::CookieMissingHttpOnly,
            Self::CookieMissingSecure,
            Self::DomXss,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HotspotSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HotspotSpan {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HotspotFinding {
    pub rule: HotspotRule,
    pub rule_id: &'static str,
    pub severity: HotspotSeverity,
    pub message: String,
    pub span: HotspotSpan,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone)]
pub struct HotspotConfig {
    disabled: BTreeSet<HotspotRule>,
}

impl Default for HotspotConfig {
    fn default() -> Self {
        Self::all()
    }
}

impl HotspotConfig {
    #[must_use]
    pub const fn all() -> Self {
        Self {
            disabled: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn without(mut self, rule: HotspotRule) -> Self {
        self.disabled.insert(rule);
        self
    }

    #[must_use]
    pub fn is_enabled(&self, rule: HotspotRule) -> bool {
        !self.disabled.contains(&rule)
    }
}

#[must_use]
pub fn analyze_hotspots(source: &str) -> Vec<HotspotFinding> {
    analyze_hotspots_with(source, &HotspotConfig::all())
}

#[must_use]
pub fn analyze_hotspots_with(source: &str, config: &HotspotConfig) -> Vec<HotspotFinding> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return Vec::new();
    }
    let mut visitor: HotspotVisitor<'_> = HotspotVisitor {
        config,
        raw: Vec::new(),
    };
    visitor.visit_program(&parsed.program);

    let index: LineIndex = LineIndex::new(source);
    let mut seen: BTreeSet<(HotspotRule, u32, u32)> = BTreeSet::new();
    let mut findings: Vec<HotspotFinding> = Vec::with_capacity(visitor.raw.len());
    for raw in visitor.raw {
        let key: (HotspotRule, u32, u32) = (raw.rule, raw.start, raw.end);
        if !seen.insert(key) {
            continue;
        }
        let (line, column): (u32, u32) = index.line_col(raw.start);
        findings.push(HotspotFinding {
            rule: raw.rule,
            rule_id: raw.rule.sonar_id(),
            severity: raw.rule.severity(),
            message: raw.message,
            span: HotspotSpan {
                start: raw.start,
                end: raw.end,
            },
            line,
            column,
        });
    }
    findings.sort_by(|a, b| {
        a.span
            .start
            .cmp(&b.span.start)
            .then_with(|| a.rule.cmp(&b.rule))
    });
    findings
}

struct RawFinding {
    rule: HotspotRule,
    start: u32,
    end: u32,
    message: String,
}

struct HotspotVisitor<'c> {
    config: &'c HotspotConfig,
    raw: Vec<RawFinding>,
}

impl<'a> Visit<'a> for HotspotVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.check_call(call);
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        self.check_new(new_expr);
        walk::walk_new_expression(self, new_expr);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        self.check_assignment(assign);
        walk::walk_assignment_expression(self, assign);
    }

    fn visit_object_property(&mut self, prop: &ObjectProperty<'a>) {
        self.check_object_property(prop);
        walk::walk_object_property(self, prop);
    }

    fn visit_static_member_expression(&mut self, member: &StaticMemberExpression<'a>) {
        self.check_member(member);
        walk::walk_static_member_expression(self, member);
    }
}

impl HotspotVisitor<'_> {
    fn push(&mut self, rule: HotspotRule, span: Span, message: impl Into<String>) {
        if !self.config.is_enabled(rule) {
            return;
        }
        self.raw.push(RawFinding {
            rule,
            start: span.start,
            end: span.end,
            message: message.into(),
        });
    }

    fn check_call(&mut self, call: &CallExpression<'_>) {
        let callee: &Expression<'_> = unwrap_paren(&call.callee);
        if let Some(name) = ident_name(callee) {
            match name {
                "eval" => self.push(
                    HotspotRule::DynamicCodeExecution,
                    call.span,
                    "eval() runs a string as code; review this dynamic execution sink for injected input",
                ),
                "Function" => self.push(
                    HotspotRule::DynamicCodeExecution,
                    call.span,
                    "the Function constructor compiles a string into code; review this dynamic execution sink",
                ),
                "setTimeout" | "setInterval" => self.check_implied_eval(call, name),
                "createHash" => self.check_hash_call(call),
                "createCipheriv" | "createCipher" | "createDecipheriv" | "createDecipher" => {
                    self.check_cipher_call(call);
                }
                _ => {}
            }
        }
        if let Some((object, prop)) = member_callee(callee) {
            match prop {
                "setTimeout" | "setInterval" => self.check_implied_eval(call, prop),
                "createHash" => self.check_hash_call(call),
                "createCipheriv" | "createCipher" | "createDecipheriv" | "createDecipher" => {
                    self.check_cipher_call(call);
                }
                "write" | "writeln" if is_global_object(object, "document") => {
                    self.check_document_write(call, prop);
                }
                "insertAdjacentHTML" => self.check_insert_adjacent(call),
                "cookie" => self.check_cookie_call(call),
                _ => {}
            }
        }
    }

    fn check_implied_eval(&mut self, call: &CallExpression<'_>, name: &str) {
        let Some(first): Option<&Expression<'_>> = arg_expression(&call.arguments, 0) else {
            return;
        };
        if is_string_valued(first) {
            self.push(
                HotspotRule::DynamicCodeExecution,
                call.span,
                format!("passing a string to {name} runs it as code like eval; review this dynamic execution sink"),
            );
        }
    }

    fn check_hash_call(&mut self, call: &CallExpression<'_>) {
        let Some(first): Option<&Expression<'_>> = arg_expression(&call.arguments, 0) else {
            return;
        };
        let Some(algo): Option<String> = static_string_value(first) else {
            return;
        };
        let lowered: String = algo.to_ascii_lowercase();
        if matches!(lowered.as_str(), "md5" | "md4" | "md2" | "sha1" | "sha-1") {
            self.push(
                HotspotRule::WeakHash,
                call.span,
                format!("{algo} is a broken hash; review this hashing for a stronger algorithm such as SHA-256"),
            );
        }
    }

    fn check_cipher_call(&mut self, call: &CallExpression<'_>) {
        let Some(first): Option<&Expression<'_>> = arg_expression(&call.arguments, 0) else {
            return;
        };
        let Some(algo): Option<String> = static_string_value(first) else {
            return;
        };
        let lowered: String = algo.to_ascii_lowercase();
        if lowered.contains("des") || lowered.contains("rc4") || lowered.contains("rc2") {
            self.push(
                HotspotRule::WeakCipher,
                call.span,
                format!("{algo} is a weak cipher; review this encryption for a strong algorithm such as AES-GCM"),
            );
        }
        if lowered.contains("ecb") {
            self.push(
                HotspotRule::InsecureCipherMode,
                call.span,
                format!(
                    "{algo} uses ECB mode which leaks plaintext structure; review this cipher mode"
                ),
            );
        }
    }

    fn check_document_write(&mut self, call: &CallExpression<'_>, prop: &str) {
        let dynamic: bool = call
            .arguments
            .iter()
            .filter_map(Argument::as_expression)
            .any(|expr: &Expression<'_>| !is_static_string(expr));
        if dynamic {
            self.push(
                HotspotRule::DomXss,
                call.span,
                format!("document.{prop} with dynamic content is a DOM-XSS sink; review the source of this value"),
            );
        }
    }

    fn check_insert_adjacent(&mut self, call: &CallExpression<'_>) {
        let Some(html): Option<&Expression<'_>> = arg_expression(&call.arguments, 1) else {
            return;
        };
        if !is_static_string(html) {
            self.push(
                HotspotRule::DomXss,
                call.span,
                "insertAdjacentHTML with dynamic content is a DOM-XSS sink; review the source of this value",
            );
        }
    }

    fn check_cookie_call(&mut self, call: &CallExpression<'_>) {
        let Some(options): Option<&ObjectExpression<'_>> = find_object_argument(call) else {
            return;
        };
        if !object_has_true_flag(options, "httpOnly") {
            self.push(
                HotspotRule::CookieMissingHttpOnly,
                call.span,
                "cookie is set without the httpOnly flag; review this cookie for script-theft exposure",
            );
        }
        if !object_has_true_flag(options, "secure") {
            self.push(
                HotspotRule::CookieMissingSecure,
                call.span,
                "cookie is set without the secure flag; review this cookie for plaintext-transport exposure",
            );
        }
    }

    fn check_member(&mut self, member: &StaticMemberExpression<'_>) {
        if ident_name(&member.object) != Some("CryptoJS") {
            return;
        }
        match member.property.name.as_str() {
            "MD5" | "SHA1" => self.push(
                HotspotRule::WeakHash,
                member.span,
                format!(
                    "CryptoJS.{} is a broken hash; review this hashing for a stronger algorithm such as SHA-256",
                    member.property.name
                ),
            ),
            "DES" | "TripleDES" | "RC4" | "RC2" => self.push(
                HotspotRule::WeakCipher,
                member.span,
                format!(
                    "CryptoJS.{} is a weak cipher; review this encryption for a strong algorithm such as AES-GCM",
                    member.property.name
                ),
            ),
            _ => {}
        }
    }

    fn check_new(&mut self, new_expr: &NewExpression<'_>) {
        if ident_name(unwrap_paren(&new_expr.callee)) == Some("Function") {
            self.push(
                HotspotRule::DynamicCodeExecution,
                new_expr.span,
                "the Function constructor compiles a string into code; review this dynamic execution sink",
            );
        }
    }

    fn check_assignment(&mut self, assign: &AssignmentExpression<'_>) {
        match &assign.left {
            AssignmentTarget::StaticMemberExpression(member) => {
                let prop: &str = member.property.name.as_str();
                self.check_sink_property(prop, &member.object, &assign.right, assign.span);
            }
            AssignmentTarget::ComputedMemberExpression(member) => {
                if let Some(prop) = static_string_value(&member.expression) {
                    self.check_sink_property(&prop, &member.object, &assign.right, assign.span);
                }
            }
            AssignmentTarget::AssignmentTargetIdentifier(ident)
                if ident.name == "location" && !is_static_string(&assign.right) =>
            {
                self.push(
                    HotspotRule::DomXss,
                    assign.span,
                    "assigning dynamic input to location navigates to an attacker-controlled URL; review the source of this value",
                );
            }
            _ => {}
        }
    }

    fn check_sink_property(
        &mut self,
        prop: &str,
        object: &Expression<'_>,
        right: &Expression<'_>,
        span: Span,
    ) {
        match prop {
            "innerHTML" | "outerHTML" if !is_static_string(right) => self.push(
                HotspotRule::DomXss,
                span,
                format!("assigning dynamic content to {prop} is a DOM-XSS sink; review the source of this value"),
            ),
            "location" if is_any_global_object(object) && !is_static_string(right) => {
                self.push(
                    HotspotRule::DomXss,
                    span,
                    "assigning dynamic input to location navigates to an attacker-controlled URL; review the source of this value",
                );
            }
            "href" if is_location_target(object) && !is_static_string(right) => self.push(
                HotspotRule::DomXss,
                span,
                "assigning dynamic input to location.href navigates to an attacker-controlled URL; review the source of this value",
            ),
            "NODE_TLS_REJECT_UNAUTHORIZED" if is_process_env(object) && disables_tls(right) => self
                .push(
                    HotspotRule::InsecureTls,
                    span,
                    "setting NODE_TLS_REJECT_UNAUTHORIZED to 0 disables TLS certificate verification; review this configuration",
                ),
            _ => {}
        }
    }

    fn check_object_property(&mut self, prop: &ObjectProperty<'_>) {
        if property_key_name(&prop.key).as_deref() == Some("rejectUnauthorized")
            && matches!(&prop.value, Expression::BooleanLiteral(lit) if !lit.value)
        {
            self.push(
                HotspotRule::InsecureTls,
                prop.span,
                "rejectUnauthorized:false disables TLS certificate verification; review this configuration",
            );
        }
    }
}
