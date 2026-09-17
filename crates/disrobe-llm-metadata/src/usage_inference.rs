use std::collections::BTreeMap;

use disrobe_core::recovery::ConfidenceTier;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::capability::MetadataCapability;
use crate::category::Category;
use crate::shape::{make_signature_entry, make_signature_param, make_signatures_value};
use crate::trait_def::LlmMetadataEmitter;

pub const INFERENCE_PASS: &str = "disrobe-resym-usage-inference";
pub const INFERENCE_SUPPORTS: &[Category] = &[Category::Signatures, Category::Types];

pub const MAX_FUNCTIONS: usize = 65_536;
pub const MAX_VARIABLES_PER_FN: usize = 4_096;
pub const MAX_OBSERVATIONS_PER_VAR: usize = 16_384;
const MAX_OBSERVATIONS_PER_VAR_U32: u32 = 16_384;
const MAX_DECLARED_TYPE_BYTES: usize = 256;
const INTEGER_TYPE_NAMES: &[&str] = &[
    "int", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "isize", "usize", "long", "short",
    "byte", "integer",
];
const FLOAT_TYPE_NAMES: &[&str] = &["float", "double", "f32", "f64", "real"];
const BOOLEAN_TYPE_NAMES: &[&str] = &["bool", "boolean"];
const STRING_TYPE_NAMES: &[&str] = &["string", "str", "&str", "char*", "const char*"];
const POINTER_TYPE_NAMES: &[&str] = &["void*", "void *"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageObservation {
    StringConcat,
    StringFormat,
    StringIndexByName,
    IntegerArith,
    BitwiseArith,
    ShiftArith,
    FloatArith,
    FloatDivision,
    BooleanLogic,
    FieldAccess,
    ArrayIndex,
    PointerDeref,
    PointerArith,
    NullCheck,
    OrderedComparison,
    EqualityComparison,
    LengthQuery,
    CalledAsFunction,
}

impl UsageObservation {
    #[inline]
    #[must_use]
    pub const fn pins_string(self) -> bool {
        matches!(
            self,
            Self::StringConcat | Self::StringFormat | Self::StringIndexByName
        )
    }

    #[inline]
    #[must_use]
    pub const fn pins_integer(self) -> bool {
        matches!(
            self,
            Self::IntegerArith | Self::BitwiseArith | Self::ShiftArith
        )
    }

    #[inline]
    #[must_use]
    pub const fn pins_float(self) -> bool {
        matches!(self, Self::FloatArith | Self::FloatDivision)
    }

    #[inline]
    #[must_use]
    pub const fn pins_struct_pointer(self) -> bool {
        matches!(self, Self::FieldAccess)
    }

    #[inline]
    #[must_use]
    pub const fn pins_array(self) -> bool {
        matches!(self, Self::ArrayIndex)
    }

    #[inline]
    #[must_use]
    pub const fn pins_pointer(self) -> bool {
        matches!(self, Self::PointerDeref | Self::PointerArith)
    }

    #[inline]
    #[must_use]
    pub const fn pins_function(self) -> bool {
        matches!(self, Self::CalledAsFunction)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "of")]
pub enum InferredType {
    Integer,
    Float,
    Boolean,
    String,
    Pointer,
    Array(Box<Self>),
    StructPointer,
    Function,
    Unknown,
}

impl InferredType {
    #[must_use]
    pub fn native(&self) -> Option<String> {
        let s: &str = match self {
            Self::Integer => "int",
            Self::Float => "float",
            Self::Boolean => "bool",
            Self::String => "string",
            Self::Pointer => "void*",
            Self::StructPointer => "struct*",
            Self::Function => "fn",
            Self::Array(inner) => {
                let elem: String = inner.native().unwrap_or_else(|| "unknown".to_owned());
                return Some(format!("{elem}[]"));
            }
            Self::Unknown => return None,
        };
        Some(s.to_owned())
    }

    #[inline]
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvidenceTally {
    string_weight: u32,
    integer_weight: u32,
    float_weight: u32,
    boolean_weight: u32,
    struct_pointer_weight: u32,
    array_weight: u32,
    pointer_weight: u32,
    function_weight: u32,
    ordered_comparison: bool,
    equality_comparison: bool,
    length_query: bool,
    null_check: bool,
    total: u32,
}

impl EvidenceTally {
    const fn empty() -> Self {
        Self {
            string_weight: 0,
            integer_weight: 0,
            float_weight: 0,
            boolean_weight: 0,
            struct_pointer_weight: 0,
            array_weight: 0,
            pointer_weight: 0,
            function_weight: 0,
            ordered_comparison: false,
            equality_comparison: false,
            length_query: false,
            null_check: false,
            total: 0,
        }
    }

    const fn record(&mut self, obs: UsageObservation) {
        self.total = self.total.saturating_add(1);
        if obs.pins_string() {
            self.string_weight = self.string_weight.saturating_add(1);
        }
        if obs.pins_integer() {
            self.integer_weight = self.integer_weight.saturating_add(1);
        }
        if obs.pins_float() {
            self.float_weight = self.float_weight.saturating_add(1);
        }
        if obs.pins_struct_pointer() {
            self.struct_pointer_weight = self.struct_pointer_weight.saturating_add(1);
        }
        if obs.pins_array() {
            self.array_weight = self.array_weight.saturating_add(1);
        }
        if obs.pins_pointer() {
            self.pointer_weight = self.pointer_weight.saturating_add(1);
        }
        if obs.pins_function() {
            self.function_weight = self.function_weight.saturating_add(1);
        }
        match obs {
            UsageObservation::BooleanLogic => {
                self.boolean_weight = self.boolean_weight.saturating_add(1);
            }
            UsageObservation::OrderedComparison => self.ordered_comparison = true,
            UsageObservation::EqualityComparison => self.equality_comparison = true,
            UsageObservation::LengthQuery => self.length_query = true,
            UsageObservation::NullCheck => self.null_check = true,
            _ => {}
        }
    }

    fn distinct_strong_families(&self) -> u32 {
        u32::from(self.string_weight > 0)
            + u32::from(self.integer_weight > 0)
            + u32::from(self.float_weight > 0)
            + u32::from(self.struct_pointer_weight > 0)
            + u32::from(self.array_weight > 0)
            + u32::from(self.function_weight > 0)
    }

    fn resolve(&self) -> InferredType {
        if self.total == 0 {
            return InferredType::Unknown;
        }

        let strong_families: u32 = self.distinct_strong_families();

        if self.struct_pointer_weight > 0 {
            if strong_families > 1 && self.pointer_weight == 0 {
                return InferredType::Unknown;
            }
            return InferredType::StructPointer;
        }

        if self.array_weight > 0 {
            if self.string_weight > 0 || self.float_weight > 0 || self.function_weight > 0 {
                return InferredType::Unknown;
            }
            return InferredType::Array(Box::new(InferredType::Unknown));
        }

        if self.function_weight > 0 {
            if strong_families > 1 {
                return InferredType::Unknown;
            }
            return InferredType::Function;
        }

        if self.string_weight > 0 {
            if self.integer_weight > 0 || self.float_weight > 0 || self.pointer_weight > 0 {
                return InferredType::Unknown;
            }
            return InferredType::String;
        }

        if self.float_weight > 0 {
            if self.integer_weight > 0 {
                return InferredType::Unknown;
            }
            return InferredType::Float;
        }

        if self.integer_weight > 0 {
            if self.pointer_weight > 0 {
                return InferredType::Unknown;
            }
            return InferredType::Integer;
        }

        if self.pointer_weight > 0 {
            return InferredType::Pointer;
        }

        if self.boolean_weight > 0 {
            return InferredType::Boolean;
        }

        InferredType::Unknown
    }
}

#[derive(Debug, Clone)]
pub struct VariableUsage {
    name: String,
    declared_type: Option<String>,
    callee_arg_type: Option<InferredType>,
    tally: EvidenceTally,
}

impl VariableUsage {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            declared_type: None,
            callee_arg_type: None,
            tally: EvidenceTally::empty(),
        }
    }

    #[must_use]
    pub fn with_declared_type(mut self, declared: impl Into<String>) -> Self {
        self.declared_type = Some(declared.into());
        self
    }

    #[must_use]
    pub fn passed_to_typed_parameter(mut self, callee_slot_type: InferredType) -> Self {
        if !callee_slot_type.is_unknown() {
            self.callee_arg_type = Some(callee_slot_type);
        }
        self
    }

    pub const fn observe(&mut self, obs: UsageObservation) -> &mut Self {
        if self.tally.total < MAX_OBSERVATIONS_PER_VAR_U32 {
            self.tally.record(obs);
        }
        self
    }

    #[must_use]
    pub const fn observed(mut self, obs: UsageObservation) -> Self {
        self.observe(obs);
        self
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn infer(&self) -> InferredType {
        if let Some(declared) = self.declared_type.as_deref() {
            return parse_declared_type(declared);
        }
        let from_usage: InferredType = self.tally.resolve();
        match (&from_usage, &self.callee_arg_type) {
            (InferredType::Unknown, Some(callee)) => callee.clone(),
            (inferred, Some(callee)) if inferred != callee => InferredType::Unknown,
            (inferred, _) => inferred.clone(),
        }
    }
}

#[must_use]
fn parse_declared_type(declared: &str) -> InferredType {
    let trimmed: &str = declared.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_DECLARED_TYPE_BYTES {
        return InferredType::Unknown;
    }
    if trimmed.ends_with("[]") {
        return InferredType::Array(Box::new(InferredType::Unknown));
    }
    if matches_declared_type(trimmed, INTEGER_TYPE_NAMES) {
        InferredType::Integer
    } else if matches_declared_type(trimmed, FLOAT_TYPE_NAMES) {
        InferredType::Float
    } else if matches_declared_type(trimmed, BOOLEAN_TYPE_NAMES) {
        InferredType::Boolean
    } else if matches_declared_type(trimmed, STRING_TYPE_NAMES) {
        InferredType::String
    } else if matches_declared_type(trimmed, POINTER_TYPE_NAMES) {
        InferredType::Pointer
    } else {
        InferredType::Unknown
    }
}

fn matches_declared_type(declared: &str, names: &[&str]) -> bool {
    names
        .iter()
        .any(|candidate: &&str| declared.eq_ignore_ascii_case(candidate))
}

#[derive(Debug, Clone)]
pub struct FunctionUsage {
    name: String,
    parameters: Vec<VariableUsage>,
    locals: Vec<VariableUsage>,
    return_value: Option<VariableUsage>,
}

impl FunctionUsage {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parameters: Vec::new(),
            locals: Vec::new(),
            return_value: None,
        }
    }

    pub fn add_parameter(&mut self, param: VariableUsage) -> &mut Self {
        if self.parameters.len() < MAX_VARIABLES_PER_FN {
            self.parameters.push(param);
        }
        self
    }

    #[must_use]
    pub fn parameter(mut self, param: VariableUsage) -> Self {
        self.add_parameter(param);
        self
    }

    pub fn add_local(&mut self, local: VariableUsage) -> &mut Self {
        if self.locals.len() < MAX_VARIABLES_PER_FN {
            self.locals.push(local);
        }
        self
    }

    #[must_use]
    pub fn local(mut self, local: VariableUsage) -> Self {
        self.add_local(local);
        self
    }

    #[must_use]
    pub fn returning(mut self, return_value: VariableUsage) -> Self {
        self.return_value = Some(return_value);
        self
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn infer_return_type(&self) -> InferredType {
        self.return_value
            .as_ref()
            .map_or(InferredType::Unknown, VariableUsage::infer)
    }

    #[must_use]
    pub fn inferred_parameters(&self) -> Vec<(String, InferredType)> {
        self.parameters
            .iter()
            .map(|p: &VariableUsage| (p.name().to_owned(), p.infer()))
            .collect()
    }

    #[must_use]
    fn signature_entry(&self) -> Json {
        let params: Vec<Json> = self
            .parameters
            .iter()
            .map(|p: &VariableUsage| {
                let inferred: InferredType = p.infer();
                make_signature_param(p.name(), inferred.native(), None, "positional")
            })
            .collect();
        let ret: InferredType = self.infer_return_type();
        make_signature_entry(self.name(), ret.native(), params, Vec::new(), Vec::new())
    }
}

#[derive(Debug, Clone, Default)]
pub struct UsageInferenceEngine {
    functions: Vec<FunctionUsage>,
}

impl UsageInferenceEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            functions: Vec::new(),
        }
    }

    pub fn add_function(&mut self, function: FunctionUsage) -> &mut Self {
        if self.functions.len() < MAX_FUNCTIONS {
            self.functions.push(function);
        }
        self
    }

    #[must_use]
    pub fn function(mut self, function: FunctionUsage) -> Self {
        self.add_function(function);
        self
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    #[must_use]
    pub fn signatures(&self) -> Option<Json> {
        if self.functions.is_empty() {
            return None;
        }
        let entries: Vec<Json> = self
            .functions
            .iter()
            .map(FunctionUsage::signature_entry)
            .collect();
        Some(make_signatures_value(entries))
    }

    #[must_use]
    pub fn types(&self) -> Option<Json> {
        let mut named_types: Vec<Json> = Vec::new();
        for function in &self.functions {
            for var in function.parameters.iter().chain(function.locals.iter()) {
                let inferred: InferredType = var.infer();
                if matches!(inferred, InferredType::StructPointer) {
                    named_types.push(serde_json::json!({
                        "name": format!("{}::{}", function.name(), var.name()),
                        "shape": "struct*",
                    }));
                }
            }
        }
        if named_types.is_empty() {
            return None;
        }
        Some(serde_json::json!({ "named_types": named_types }))
    }

    #[must_use]
    pub fn confidence_for(&self, function: &str, variable: &str) -> Option<ConfidenceTier> {
        let func: &FunctionUsage = self.functions.iter().find(|f| f.name() == function)?;
        let var: &VariableUsage = func
            .parameters
            .iter()
            .chain(func.locals.iter())
            .find(|v| v.name() == variable)?;
        let inferred: InferredType = var.infer();
        Some(tier_for(&inferred, &var.tally))
    }

    #[must_use]
    pub fn summary(&self) -> BTreeMap<String, BTreeMap<String, Option<String>>> {
        let mut out: BTreeMap<String, BTreeMap<String, Option<String>>> = BTreeMap::new();
        for function in &self.functions {
            let mut per_fn: BTreeMap<String, Option<String>> = BTreeMap::new();
            for (name, inferred) in function.inferred_parameters() {
                per_fn.insert(name, inferred.native());
            }
            per_fn.insert("<return>".to_owned(), function.infer_return_type().native());
            out.insert(function.name().to_owned(), per_fn);
        }
        out
    }
}

const fn tier_for(inferred: &InferredType, tally: &EvidenceTally) -> ConfidenceTier {
    if inferred.is_unknown() {
        return ConfidenceTier::Skeleton;
    }
    if tally.total >= 2 {
        ConfidenceTier::Semantic
    } else {
        ConfidenceTier::Partial
    }
}

impl LlmMetadataEmitter for UsageInferenceEngine {
    fn metadata_capability(&self) -> MetadataCapability {
        MetadataCapability::new(INFERENCE_PASS, "0.0.0", INFERENCE_SUPPORTS)
    }

    fn emit_signatures(&self) -> Option<Json> {
        self.signatures()
    }

    fn emit_types(&self) -> Option<Json> {
        self.types()
    }
}
