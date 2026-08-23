use std::borrow::Cow;

use serde::Serialize;
use wasmparser::{ExternalKind, FunctionBody, Parser, Payload, ValType, Validator, WasmFeatures};

use crate::error::{AtomicMemoryRefusal, Error, Result};
use crate::signature::{FunctionSig, ModuleSignatures, extract_signatures};
use crate::ssa::{CallSignatures, OpKind, SsaFunction, UnOp, build_ssa_with_calls};
use crate::types::{
    BaseOrigin, NamedField, NamedType, RecoveredStorageType, RecoveredType, TypeRecoveryRefusal,
    synthesize_named_types,
};

const MAX_TYPESCRIPT_MODULE_FUNCTIONS: usize = 4096;
const MAX_TYPESCRIPT_MODULE_EXPORTS: usize = 65_536;
const MAX_TYPESCRIPT_EXPORT_NAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LiftTarget {
    Rust,
    TypeScript,
    Wat,
    C,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiftResult {
    pub target: LiftTarget,
    pub pseudo_source: String,
    pub blocks_emitted: usize,
    pub coverage: LiftCoverage,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeScriptModuleLift {
    pub source: String,
    pub functions_emitted: usize,
    pub exported_functions: Vec<String>,
    pub coverage: LiftCoverage,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LiftCoverage {
    pub total_ops: usize,
    pub translated_ops: usize,
    pub untranslated: Vec<String>,
}

impl LiftCoverage {
    #[inline]
    #[must_use]
    pub const fn fully_recovered(&self) -> bool {
        self.untranslated.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.total_ops == 0 {
            return 1.0;
        }
        self.translated_ops as f64 / self.total_ops as f64
    }

    pub(crate) const fn record_translated(&mut self) {
        self.total_ops += 1;
        self.translated_ops += 1;
    }

    pub(crate) fn record_untranslated(&mut self, mnemonic: impl Into<String>) {
        self.total_ops += 1;
        self.untranslated.push(mnemonic.into());
    }
}

#[must_use]
pub const fn rust_runtime_prelude() -> &'static str {
    RUST_PRELUDE
}

#[must_use]
pub const fn typescript_runtime_prelude() -> &'static str {
    TS_PRELUDE
}

#[must_use]
pub fn lift_function_body(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    target: LiftTarget,
) -> LiftResult {
    match target {
        LiftTarget::Rust => lift_body_high(body, sig, callees, LiftTarget::Rust, HighLang::Rust),
        LiftTarget::TypeScript => lift_body_high(
            body,
            sig,
            callees,
            LiftTarget::TypeScript,
            HighLang::TypeScript,
        ),
        LiftTarget::C => crate::lift_c::lift_function_body_c(body, sig, callees),
        LiftTarget::Wat => crate::lift_wat::lift_function_body_wat(body, sig),
    }
}

struct RecoveredTypeSurface {
    declarations: String,
    parameter_names: Vec<(usize, &'static str)>,
}

impl RecoveredTypeSurface {
    const fn empty() -> Self {
        Self {
            declarations: String::new(),
            parameter_names: Vec::new(),
        }
    }

    fn refusal(refusal: TypeRecoveryRefusal) -> Self {
        Self {
            declarations: render_recovered_type_refusal(refusal),
            parameter_names: Vec::new(),
        }
    }

    fn enrich_signature<'a>(&self, signature: &'a FunctionSig) -> Cow<'a, FunctionSig> {
        let mut enriched: Option<FunctionSig> = None;
        for (parameter_index, recovered_name) in &self.parameter_names {
            if *parameter_index >= signature.params.len() {
                continue;
            }
            if signature
                .local_names
                .get(*parameter_index)
                .is_some_and(Option::is_some)
            {
                continue;
            }
            let enriched: &mut FunctionSig = enriched.get_or_insert_with(|| signature.clone());
            let required_len: usize = parameter_index.saturating_add(1);
            if enriched.local_names.len() < required_len {
                enriched.local_names.resize(required_len, None);
            }
            let Some(name): Option<&mut Option<String>> =
                enriched.local_names.get_mut(*parameter_index)
            else {
                continue;
            };
            if name.is_none() {
                *name = Some((*recovered_name).to_owned());
            }
        }
        enriched.map_or_else(|| Cow::Borrowed(signature), Cow::Owned)
    }
}

struct PreparedModuleLift {
    signatures: ModuleSignatures,
    callees: CalleeNames,
}

impl PreparedModuleLift {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signatures: ModuleSignatures = extract_signatures(bytes)?;
        let callees: CalleeNames = CalleeNames::from_signatures(bytes, &signatures);
        Ok(Self {
            signatures,
            callees,
        })
    }

    fn defined_function_count(&self) -> usize {
        self.signatures.defined().len()
    }

    fn try_lift(
        &self,
        bytes: &[u8],
        defined_function_index: usize,
        target: LiftTarget,
    ) -> Result<LiftResult> {
        let sig: &FunctionSig = self
            .signatures
            .defined()
            .get(defined_function_index)
            .ok_or_else(|| {
                Error::Parse(format!(
                    "defined function index {defined_function_index} is unavailable"
                ))
            })?;
        let module: &crate::structured::ModuleCtx = self
            .callees
            .module_ctx()
            .ok_or(AtomicMemoryRefusal::MissingModuleContext)?;
        let body: FunctionBody<'_> = module.function_body(bytes, defined_function_index)?;
        let recovered: RecoveredTypeSurface =
            self.recovered_type_surface(bytes, &body, sig, defined_function_index, target);
        let enriched_signature: Cow<'_, FunctionSig> = recovered.enrich_signature(sig);
        let mut lifted: LiftResult =
            try_lift_function_body(&body, enriched_signature.as_ref(), &self.callees, target)?;
        if !recovered.declarations.is_empty() {
            lifted.pseudo_source = format!("{}\n{}", recovered.declarations, lifted.pseudo_source);
        }
        Ok(lifted)
    }

    fn recovered_type_surface(
        &self,
        bytes: &[u8],
        body: &FunctionBody<'_>,
        sig: &FunctionSig,
        defined_function_index: usize,
        target: LiftTarget,
    ) -> RecoveredTypeSurface {
        if target == LiftTarget::Wat {
            return RecoveredTypeSurface::empty();
        }
        if !has_recoverable_memory_access(body) {
            return RecoveredTypeSurface::empty();
        }
        match crate::memory64::scan_memories(bytes) {
            Ok(report) if report.uses_memory64 => {
                return RecoveredTypeSurface::refusal(TypeRecoveryRefusal::Memory64);
            }
            Ok(_) => {}
            Err(_) => {
                return RecoveredTypeSurface::refusal(TypeRecoveryRefusal::UnsupportedSsa);
            }
        }
        let Ok(cfg): Result<crate::cfg::FunctionCfg> = crate::cfg::build_function_cfg(body) else {
            return RecoveredTypeSurface::refusal(TypeRecoveryRefusal::UnsupportedSsa);
        };
        let call_signatures: CallSignatures =
            CallSignatures::new(self.signatures.call_signatures());
        let Ok(ssa): Result<SsaFunction> =
            build_ssa_with_calls(&cfg, body, &sig.params, &call_signatures)
        else {
            return RecoveredTypeSurface::refusal(TypeRecoveryRefusal::UnsupportedSsa);
        };
        let recovered: crate::types::RecoveredTypes = match crate::recover_types_full(bytes, &ssa) {
            Ok(recovered) => recovered,
            Err(crate::RecoveredTypesError::Memory(refusal)) => {
                return RecoveredTypeSurface::refusal(refusal);
            }
            Err(crate::RecoveredTypesError::Gc(_)) => {
                return RecoveredTypeSurface::refusal(TypeRecoveryRefusal::UnsupportedSsa);
            }
        };
        let named: Vec<NamedType> = synthesize_named_types(&recovered.memory_aggregates);
        let declarations: String =
            match render_recovered_type_declarations(&named, defined_function_index, target) {
                Ok(declarations) => declarations,
                Err(refusal) => return RecoveredTypeSurface::refusal(refusal),
            };
        let parameter_names: Vec<(usize, &'static str)> = recovered
            .memory_aggregates
            .iter()
            .filter_map(|(origin, recovered_type): &(BaseOrigin, RecoveredType)| {
                let BaseOrigin::Param(parameter_index) = origin else {
                    return None;
                };
                let parameter_index: usize = usize::try_from(*parameter_index).ok()?;
                if parameter_index >= sig.params.len() {
                    return None;
                }
                Some((parameter_index, recovered_parameter_role(recovered_type)))
            })
            .collect();
        RecoveredTypeSurface {
            declarations,
            parameter_names,
        }
    }
}

const fn recovered_parameter_role(recovered_type: &RecoveredType) -> &'static str {
    match recovered_type {
        RecoveredType::Struct { .. } => "record_address",
        RecoveredType::Array { elem_size: 1, .. }
        | RecoveredType::TypedArray {
            elem: RecoveredStorageType::I8,
            ..
        } => "bytes_address",
        RecoveredType::Array { .. } | RecoveredType::TypedArray { .. } => "items_address",
        RecoveredType::Scalar(_) | RecoveredType::StorageScalar(_) => "value_address",
    }
}

fn render_recovered_type_refusal(refusal: TypeRecoveryRefusal) -> String {
    format!(
        "// {}: {}; recovered type declarations are unavailable\n\n",
        refusal.code(),
        refusal.message()
    )
}

fn has_recoverable_memory_access(body: &FunctionBody<'_>) -> bool {
    let Ok(mut operators): std::result::Result<wasmparser::OperatorsReader<'_>, _> =
        body.get_operators_reader()
    else {
        return false;
    };
    while !operators.eof() {
        let Ok(operator): std::result::Result<wasmparser::Operator<'_>, _> = operators.read()
        else {
            return false;
        };
        if crate::ssa::load_descriptor(&operator).is_some()
            || crate::ssa::store_descriptor(&operator).is_some()
        {
            return true;
        }
    }
    false
}

fn render_recovered_type_declarations(
    named_types: &[NamedType],
    defined_function_index: usize,
    target: LiftTarget,
) -> std::result::Result<String, TypeRecoveryRefusal> {
    let mut out: String = String::new();
    for named_type in named_types {
        let name: String = recovered_declaration_name(named_type, defined_function_index);
        match (target, named_type) {
            (LiftTarget::Rust, NamedType::Struct { fields, .. }) => {
                let layout: Vec<(u32, &NamedField)> = checked_layout(fields)?;
                crate::push_string_fmt(&mut out, format_args!("#[repr(C)]\nstruct {name} {{\n"));
                for (padding, field) in layout {
                    if padding > 0 {
                        crate::push_string_fmt(
                            &mut out,
                            format_args!(
                                "    disrobe_padding_{}: [u8; {padding}],\n",
                                field.offset
                            ),
                        );
                    }
                    crate::push_string_fmt(
                        &mut out,
                        format_args!("    {}: {},\n", field.name, recovered_rust_type(field.kind)),
                    );
                }
                out.push_str("}\n\n");
            }
            (LiftTarget::Rust, NamedType::Array { elem, count, .. }) => {
                let declaration: String = count.map_or_else(
                    || format!("[{}]", recovered_rust_type(*elem)),
                    |value: u32| format!("[{}; {value}]", recovered_rust_type(*elem)),
                );
                crate::push_string_fmt(&mut out, format_args!("type {name} = {declaration};\n\n"));
            }
            (LiftTarget::Rust, NamedType::Scalar { kind, .. }) => {
                crate::push_string_fmt(
                    &mut out,
                    format_args!("type {name} = {};\n\n", recovered_rust_type(*kind)),
                );
            }
            (LiftTarget::C, NamedType::Struct { fields, .. }) => {
                let layout: Vec<(u32, &NamedField)> = checked_layout(fields)?;
                out.push_str("typedef struct {\n");
                for (padding, field) in layout {
                    if padding > 0 {
                        crate::push_string_fmt(
                            &mut out,
                            format_args!(
                                "    uint8_t disrobe_padding_{}[{padding}];\n",
                                field.offset
                            ),
                        );
                    }
                    crate::push_string_fmt(
                        &mut out,
                        format_args!("    {} {};\n", recovered_c_type(field.kind), field.name),
                    );
                }
                crate::push_string_fmt(&mut out, format_args!("}} {name};\n\n"));
            }
            (LiftTarget::C, NamedType::Array { elem, count, .. }) => {
                let count: String = count.map_or_else(String::new, |value: u32| value.to_string());
                crate::push_string_fmt(
                    &mut out,
                    format_args!("typedef {} {name}[{count}];\n\n", recovered_c_type(*elem)),
                );
            }
            (LiftTarget::C, NamedType::Scalar { kind, .. }) => {
                crate::push_string_fmt(
                    &mut out,
                    format_args!("typedef {} {name};\n\n", recovered_c_type(*kind)),
                );
            }
            (LiftTarget::TypeScript, NamedType::Struct { fields, .. }) => {
                crate::push_string_fmt(&mut out, format_args!("export interface {name} {{\n"));
                for field in fields {
                    crate::push_string_fmt(
                        &mut out,
                        format_args!(
                            "    readonly {}: {};\n",
                            field.name,
                            recovered_typescript_type(field.kind)
                        ),
                    );
                }
                out.push_str("}\n\n");
            }
            (LiftTarget::TypeScript, NamedType::Array { elem, .. }) => {
                crate::push_string_fmt(
                    &mut out,
                    format_args!(
                        "export type {name} = ReadonlyArray<{}>;\n\n",
                        recovered_typescript_type(*elem)
                    ),
                );
            }
            (LiftTarget::TypeScript, NamedType::Scalar { kind, .. }) => {
                crate::push_string_fmt(
                    &mut out,
                    format_args!(
                        "export type {name} = {};\n\n",
                        recovered_typescript_type(*kind)
                    ),
                );
            }
            (LiftTarget::Wat, _) => {}
        }
    }
    Ok(out)
}

fn checked_layout(
    fields: &[NamedField],
) -> std::result::Result<Vec<(u32, &NamedField)>, TypeRecoveryRefusal> {
    let mut cursor: u32 = 0;
    let mut layout: Vec<(u32, &NamedField)> = Vec::with_capacity(fields.len());
    for field in fields {
        let offset: u32 =
            u32::try_from(field.offset).map_err(|_| TypeRecoveryRefusal::UnrepresentableLayout)?;
        let alignment: u32 =
            recovered_alignment(field.kind).ok_or(TypeRecoveryRefusal::UnrepresentableLayout)?;
        if offset < cursor || !offset.is_multiple_of(alignment) {
            return Err(TypeRecoveryRefusal::UnrepresentableLayout);
        }
        let padding: u32 = offset - cursor;
        cursor = offset
            .checked_add(field.width)
            .ok_or(TypeRecoveryRefusal::UnrepresentableLayout)?;
        layout.push((padding, field));
    }
    Ok(layout)
}

const fn recovered_alignment(kind: RecoveredStorageType) -> Option<u32> {
    match kind {
        RecoveredStorageType::I8 => Some(1),
        RecoveredStorageType::I16 => Some(2),
        RecoveredStorageType::I32 | RecoveredStorageType::F32 => Some(4),
        RecoveredStorageType::I64 | RecoveredStorageType::F64 => Some(8),
        RecoveredStorageType::V128 => None,
    }
}

fn recovered_declaration_name(named_type: &NamedType, defined_function_index: usize) -> String {
    let kind: &str = match named_type {
        NamedType::Struct { .. } => "Struct",
        NamedType::Array { .. } => "Array",
        NamedType::Scalar { .. } => "Scalar",
    };
    let suffix: Option<&str> = named_type
        .type_name()
        .strip_prefix("Struct_")
        .or_else(|| named_type.type_name().strip_prefix("Array_"))
        .or_else(|| named_type.type_name().strip_prefix("Scalar_"));
    let Some(suffix): Option<&str> = suffix else {
        return format!(
            "Disrobe{kind}Function{defined_function_index}{}",
            upper_camel_suffix(named_type.type_name())
        );
    };
    format!(
        "Disrobe{kind}Function{defined_function_index}{}",
        upper_camel_suffix(suffix)
    )
}

fn upper_camel_suffix(value: &str) -> String {
    let mut chars: std::str::Chars<'_> = value.chars();
    let Some(first): Option<char> = chars.next() else {
        return String::new();
    };
    first.to_uppercase().chain(chars).collect()
}

const fn recovered_rust_type(kind: RecoveredStorageType) -> &'static str {
    match kind {
        RecoveredStorageType::I8 => "u8",
        RecoveredStorageType::I16 => "u16",
        RecoveredStorageType::I32 => "i32",
        RecoveredStorageType::I64 => "i64",
        RecoveredStorageType::F32 => "f32",
        RecoveredStorageType::F64 => "f64",
        RecoveredStorageType::V128 => "i128",
    }
}

const fn recovered_c_type(kind: RecoveredStorageType) -> &'static str {
    match kind {
        RecoveredStorageType::I8 => "uint8_t",
        RecoveredStorageType::I16 => "uint16_t",
        RecoveredStorageType::I32 => "int32_t",
        RecoveredStorageType::I64 => "int64_t",
        RecoveredStorageType::F32 => "float",
        RecoveredStorageType::F64 => "double",
        RecoveredStorageType::V128 => "v128_t",
    }
}

const fn recovered_typescript_type(kind: RecoveredStorageType) -> &'static str {
    match kind {
        RecoveredStorageType::I64 | RecoveredStorageType::V128 => "bigint",
        RecoveredStorageType::I8
        | RecoveredStorageType::I16
        | RecoveredStorageType::I32
        | RecoveredStorageType::F32
        | RecoveredStorageType::F64 => "number",
    }
}

pub fn try_lift_function_from_module(
    bytes: &[u8],
    defined_function_index: usize,
    target: LiftTarget,
) -> Result<LiftResult> {
    PreparedModuleLift::from_bytes(bytes)?.try_lift(bytes, defined_function_index, target)
}

pub fn try_lift_functions_from_module(bytes: &[u8], target: LiftTarget) -> Result<Vec<LiftResult>> {
    let prepared: PreparedModuleLift = PreparedModuleLift::from_bytes(bytes)?;
    let function_count: usize = prepared.defined_function_count();
    let mut results: Vec<LiftResult> = Vec::with_capacity(function_count);
    for defined_function_index in 0..function_count {
        results.push(prepared.try_lift(bytes, defined_function_index, target)?);
    }
    Ok(results)
}

pub fn try_lift_typescript_module(bytes: &[u8]) -> Result<TypeScriptModuleLift> {
    let mut validator: Validator = Validator::new_with_features(WasmFeatures::default());
    validator
        .validate_all(bytes)
        .map_err(|error| Error::Parse(format!("invalid WebAssembly module: {error}")))?;
    let prepared: PreparedModuleLift = PreparedModuleLift::from_bytes(bytes)?;
    let function_count: usize = prepared.defined_function_count();
    if function_count > MAX_TYPESCRIPT_MODULE_FUNCTIONS {
        return Err(AtomicMemoryRefusal::FunctionCount {
            actual: function_count,
            limit: MAX_TYPESCRIPT_MODULE_FUNCTIONS,
        }
        .into());
    }
    let module: &crate::structured::ModuleCtx = prepared
        .callees
        .module_ctx()
        .ok_or(AtomicMemoryRefusal::MissingModuleContext)?;
    let memory64: bool = module.fixed_shared_memory_is_64()?;
    let mut signatures: Vec<FunctionSig> = prepared.signatures.defined().to_vec();
    for (function_index, signature) in signatures.iter_mut().enumerate() {
        signature.name = format!("disrobeWasmFunction{function_index}");
        signature.local_names.clear();
    }
    let callees: CalleeNames = CalleeNames::from_module(
        bytes,
        signatures
            .iter()
            .map(|signature: &FunctionSig| signature.name.clone())
            .collect(),
        prepared.signatures.call_signatures(),
        prepared.signatures.type_signatures(),
    );
    for (function_index, signature) in signatures.iter().enumerate() {
        let actual: usize = signature.results.len();
        if actual > 1 {
            return Err(AtomicMemoryRefusal::ResultCount {
                function_index,
                actual,
                limit: 1,
            }
            .into());
        }
    }
    let mut lifted_functions: Vec<String> = Vec::with_capacity(function_count);
    let mut recovered_declarations: String = String::new();
    let mut coverage: LiftCoverage = LiftCoverage::default();
    for (defined_function_index, signature) in signatures.iter().enumerate() {
        let module: &crate::structured::ModuleCtx = prepared
            .callees
            .module_ctx()
            .ok_or(AtomicMemoryRefusal::MissingModuleContext)?;
        let body: FunctionBody<'_> = module.function_body(bytes, defined_function_index)?;
        let recovered: RecoveredTypeSurface = prepared.recovered_type_surface(
            bytes,
            &body,
            signature,
            defined_function_index,
            LiftTarget::TypeScript,
        );
        recovered_declarations.push_str(&recovered.declarations);
        let enriched_signature: Cow<'_, FunctionSig> = recovered.enrich_signature(signature);
        let (pseudo_source, blocks_emitted, function_coverage): (String, usize, LiftCoverage) =
            crate::structured::lift_body_structured_typescript_module(
                &body,
                enriched_signature.as_ref(),
                &callees,
            )?;
        let lifted: LiftResult = LiftResult {
            target: LiftTarget::TypeScript,
            pseudo_source,
            blocks_emitted,
            coverage: function_coverage,
        };
        coverage.total_ops = coverage
            .total_ops
            .checked_add(lifted.coverage.total_ops)
            .ok_or_else(|| Error::Parse("TypeScript module operation count overflow".to_owned()))?;
        coverage.translated_ops = coverage
            .translated_ops
            .checked_add(lifted.coverage.translated_ops)
            .ok_or_else(|| Error::Parse("TypeScript module recovery count overflow".to_owned()))?;
        coverage.untranslated.extend(lifted.coverage.untranslated);
        let function_source: String = lifted
            .pseudo_source
            .strip_prefix("export function ")
            .map_or_else(
                || lifted.pseudo_source.clone(),
                |body: &str| format!("function {body}"),
            );
        lifted_functions.push(function_source);
    }
    let imported_function_count: usize = prepared.signatures.imported_function_count();
    let mut export_bindings: Vec<(String, String, usize)> = Vec::new();
    for (function_index, export_name) in exact_typescript_function_exports(bytes)? {
        let Some(defined_function_index): Option<usize> =
            (function_index as usize).checked_sub(imported_function_count)
        else {
            continue;
        };
        let Some(signature): Option<&FunctionSig> = signatures.get(defined_function_index) else {
            continue;
        };
        if export_name == "memory" {
            return Err(AtomicMemoryRefusal::ReservedExportName {
                function_index: defined_function_index,
            }
            .into());
        }
        export_bindings.push((export_name, signature.name.clone(), defined_function_index));
    }
    let exported_functions: Vec<String> = export_bindings
        .iter()
        .map(|(name, _, _): &(String, String, usize)| name.clone())
        .collect();
    let runtime_start: usize = TS_PRELUDE
        .find("const WASM_LOGICAL_MEMORY_BYTE_LENGTH: number")
        .ok_or_else(|| {
            Error::Parse("TypeScript runtime memory boundary is unavailable".to_owned())
        })?;
    let runtime: &str = TS_PRELUDE
        .get(runtime_start..)
        .ok_or_else(|| Error::Parse("TypeScript runtime memory boundary is invalid".to_owned()))?;
    let mut source: String = String::from("import { writeSync } from \"node:fs\";\n\n");
    source.push_str(&recovered_declarations);
    source.push_str(
        "export type LiftedInstance = Readonly<{\n  readonly memory: WebAssembly.Memory;\n",
    );
    for (export_name, _, defined_function_index) in &export_bindings {
        let export_literal: String =
            serde_json::to_string(export_name).map_err(|error| Error::Parse(error.to_string()))?;
        let signature: &FunctionSig = prepared
            .signatures
            .defined()
            .get(*defined_function_index)
            .ok_or_else(|| Error::Parse("TypeScript export signature is unavailable".to_owned()))?;
        crate::push_string_fmt(&mut source, format_args!("  readonly {export_literal}: ("));
        for (parameter_index, parameter_type) in signature.params.iter().enumerate() {
            if parameter_index > 0 {
                source.push_str(", ");
            }
            crate::push_string_fmt(
                &mut source,
                format_args!(
                    "p{parameter_index}: {}",
                    crate::structured::typescript_type(*parameter_type)
                ),
            );
        }
        let result_type: &str = signature.results.first().map_or("void", |value_type| {
            crate::structured::typescript_type(*value_type)
        });
        crate::push_string_fmt(&mut source, format_args!(") => {result_type};\n"));
    }
    source.push_str(
        "}>;\nexport type InstantiateOptions = Readonly<{ memories?: readonly [WebAssembly.Memory?] }>;\n\nexport const instantiate = (options: InstantiateOptions = {}): LiftedInstance => {\n  const supplied: WebAssembly.Memory | undefined = options.memories?.[0];\n",
    );
    if memory64 {
        source.push_str(
            "  const memoryValue: unknown = supplied ?? Reflect.construct(WebAssembly.Memory, [{ initial: 1n, maximum: 1n, shared: true, address: \"i64\" }]);\n  if (!(memoryValue instanceof WebAssembly.Memory)) throw new TypeError(\"lifted WebAssembly memory construction failed\");\n  const memory: WebAssembly.Memory = memoryValue;\n",
        );
    } else {
        source.push_str(
            "  const memory: WebAssembly.Memory = supplied ?? new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true, address: \"i32\" });\n",
        );
    }
    source.push_str(
        "  const memoryBufferValue: unknown = memory.buffer;\n  if (!(memoryBufferValue instanceof SharedArrayBuffer)) throw new TypeError(\"lifted WebAssembly memory must be shared\");\n  if (memoryBufferValue.byteLength < 65536) throw new RangeError(\"lifted WebAssembly memory is smaller than one page\");\n  const WASM_MEMORY_BUFFER: SharedArrayBuffer = memoryBufferValue;\n",
    );
    for line in runtime.lines() {
        source.push_str("  ");
        source.push_str(line);
        source.push('\n');
    }
    for function_source in &lifted_functions {
        for line in function_source.lines() {
            source.push_str("  ");
            source.push_str(line);
            source.push('\n');
        }
    }
    source.push_str("  return { memory");
    for (export_name, local_name, _) in &export_bindings {
        let export_literal: String =
            serde_json::to_string(export_name).map_err(|error| Error::Parse(error.to_string()))?;
        crate::push_string_fmt(
            &mut source,
            format_args!(", [{export_literal}]: {local_name}"),
        );
    }
    source.push_str(" };\n};\n");
    Ok(TypeScriptModuleLift {
        source,
        functions_emitted: lifted_functions.len(),
        exported_functions,
        coverage,
    })
}

fn exact_typescript_function_exports(bytes: &[u8]) -> Result<Vec<(u32, String)>> {
    let mut exports: Vec<(u32, String)> = Vec::new();
    let mut name_bytes: usize = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload
            .map_err(|error| Error::Parse(format!("invalid WebAssembly module: {error}")))?;
        let Payload::ExportSection(reader) = payload else {
            continue;
        };
        for export in reader {
            let export: wasmparser::Export<'_> = export
                .map_err(|error| Error::Parse(format!("invalid WebAssembly export: {error}")))?;
            if export.kind != ExternalKind::Func {
                continue;
            }
            let actual: usize = exports.len().saturating_add(1);
            if actual > MAX_TYPESCRIPT_MODULE_EXPORTS {
                return Err(AtomicMemoryRefusal::ExportCount {
                    actual,
                    limit: MAX_TYPESCRIPT_MODULE_EXPORTS,
                }
                .into());
            }
            name_bytes = name_bytes.checked_add(export.name.len()).ok_or(
                AtomicMemoryRefusal::ExportNameBytes {
                    actual: usize::MAX,
                    limit: MAX_TYPESCRIPT_EXPORT_NAME_BYTES,
                },
            )?;
            if name_bytes > MAX_TYPESCRIPT_EXPORT_NAME_BYTES {
                return Err(AtomicMemoryRefusal::ExportNameBytes {
                    actual: name_bytes,
                    limit: MAX_TYPESCRIPT_EXPORT_NAME_BYTES,
                }
                .into());
            }
            exports.push((export.index, export.name.to_owned()));
        }
    }
    Ok(exports)
}

fn try_lift_function_body(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    target: LiftTarget,
) -> Result<LiftResult> {
    let result: Result<LiftResult> = match target {
        LiftTarget::Rust => {
            try_lift_body_high(body, sig, callees, LiftTarget::Rust, HighLang::Rust)
        }
        LiftTarget::TypeScript => crate::structured::lift_body_structured_typescript_standalone(
            body, sig, callees,
        )
        .map(
            |(pseudo_source, blocks_emitted, coverage): (String, usize, LiftCoverage)| LiftResult {
                target: LiftTarget::TypeScript,
                pseudo_source,
                blocks_emitted,
                coverage,
            },
        ),
        LiftTarget::C => crate::lift_c::try_lift_function_body_c(body, sig, callees),
        LiftTarget::Wat => Ok(crate::lift_wat::lift_function_body_wat(body, sig)),
    };
    match result {
        Ok(result) => Ok(result),
        Err(error @ Error::AtomicMemoryModel(_)) => Err(error),
        Err(_) => Ok(lift_function_body(body, sig, callees, target)),
    }
}

fn lift_body_high(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    target: LiftTarget,
    lang: HighLang,
) -> LiftResult {
    match try_lift_body_high(body, sig, callees, target, lang) {
        Ok(result) => result,
        Err(Error::AtomicMemoryModel(reason)) => LiftResult {
            target,
            pseudo_source: atomic_memory_refusal_stub(
                sig,
                target,
                &Error::AtomicMemoryModel(reason).to_string(),
            ),
            blocks_emitted: 0,
            coverage: atomic_memory_refusal_coverage(),
        },
        Err(error) => LiftResult {
            target,
            pseudo_source: unliftable_stub(sig, target, &error.to_string()),
            blocks_emitted: 0,
            coverage: LiftCoverage {
                total_ops: 0,
                translated_ops: 0,
                untranslated: vec!["<parse-failure>".to_owned()],
            },
        },
    }
}

fn try_lift_body_high(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    target: LiftTarget,
    lang: HighLang,
) -> Result<LiftResult> {
    let (source, blocks_emitted, coverage): (String, usize, LiftCoverage) =
        crate::structured::lift_body_structured(body, sig, callees, lang)?;
    Ok(LiftResult {
        target,
        pseudo_source: source,
        blocks_emitted,
        coverage,
    })
}

pub(crate) fn atomic_memory_refusal_coverage() -> LiftCoverage {
    LiftCoverage {
        total_ops: 1,
        translated_ops: 0,
        untranslated: vec!["<unsupported-atomic-memory-model>".to_owned()],
    }
}

fn atomic_memory_refusal_stub(sig: &FunctionSig, target: LiftTarget, reason: &str) -> String {
    let mut source: String = String::new();
    match target {
        LiftTarget::Rust => {
            crate::push_string_fmt(&mut source, format_args!("pub fn {}(", sig.name));
            let params: std::iter::Enumerate<std::slice::Iter<'_, ValType>> =
                sig.params.iter().enumerate();
            for (index, ty) in params {
                if index > 0 {
                    source.push_str(", ");
                }
                crate::push_string_fmt(&mut source, format_args!("p{index}: {}", rust_type(*ty)));
            }
            source.push(')');
            let result: Option<&ValType> = sig.results.first();
            if let Some(result) = result {
                crate::push_string_fmt(&mut source, format_args!(" -> {}", rust_type(*result)));
            }
            source.push_str(" {\n");
            for index in 0..sig.params.len() {
                crate::push_string_line(&mut source, format_args!("    let _ = p{index};"));
            }
            crate::push_string_line(&mut source, format_args!("    panic!({reason:?});"));
            source.push_str("}\n");
        }
        LiftTarget::TypeScript => {
            crate::push_string_fmt(&mut source, format_args!("export function {}(", sig.name));
            let params: std::iter::Enumerate<std::slice::Iter<'_, ValType>> =
                sig.params.iter().enumerate();
            for (index, ty) in params {
                if index > 0 {
                    source.push_str(", ");
                }
                crate::push_string_fmt(&mut source, format_args!("p{index}: {}", ts_type(*ty)));
            }
            let result: &str = sig
                .results
                .first()
                .map_or("void", |ty: &ValType| ts_type(*ty));
            crate::push_string_line(&mut source, format_args!("): {result} {{"));
            crate::push_string_line(
                &mut source,
                format_args!("    throw new Error({reason:?});"),
            );
            source.push_str("}\n");
        }
        LiftTarget::Wat | LiftTarget::C => unreachable!("handled separately"),
    }
    source
}

fn unliftable_stub(sig: &FunctionSig, target: LiftTarget, reason: &str) -> String {
    let mut s: String = String::new();
    match target {
        LiftTarget::Rust => {
            crate::push_string_line(&mut s, format_args!("/// not lifted: {reason}"));
            crate::push_string_fmt(&mut s, format_args!("pub fn {}(", sig.name));
            for (i, ty) in sig.params.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                crate::push_string_fmt(&mut s, format_args!("p{i}: {}", rust_type(*ty)));
            }
            s.push(')');
            if let Some(ret) = sig.results.first() {
                crate::push_string_fmt(&mut s, format_args!(" -> {}", rust_type(*ret)));
            }
            s.push_str(" {\n");
            for i in 0..sig.params.len() {
                crate::push_string_line(&mut s, format_args!("    let _ = p{i};"));
            }
            if let Some(ret) = sig.results.first() {
                crate::push_string_line(&mut s, format_args!("    {}", zero_literal(*ret, target)));
            }
            s.push_str("}\n");
        }
        LiftTarget::TypeScript => {
            crate::push_string_line(&mut s, format_args!("// not lifted: {reason}"));
            crate::push_string_fmt(&mut s, format_args!("export function {}(", sig.name));
            for (i, ty) in sig.params.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                crate::push_string_fmt(&mut s, format_args!("p{i}: {}", ts_type(*ty)));
            }
            let ret: &str = sig.results.first().map_or("void", |t| ts_type(*t));
            crate::push_string_line(&mut s, format_args!("): {ret} {{"));
            if let Some(ret) = sig.results.first() {
                crate::push_string_line(
                    &mut s,
                    format_args!("    return {};", zero_literal(*ret, target)),
                );
            }
            s.push_str("}\n");
        }
        LiftTarget::Wat | LiftTarget::C => unreachable!("handled separately"),
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HighLang {
    Rust,
    TypeScript,
    C,
}

#[derive(Debug, Clone, Default)]
pub struct CalleeNames {
    names: Vec<String>,
    signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
    type_signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
    module: Option<Box<crate::structured::ModuleCtx>>,
}

impl CalleeNames {
    fn from_signatures(bytes: &[u8], signatures: &ModuleSignatures) -> Self {
        Self::from_module(
            bytes,
            signatures.callee_names(),
            signatures.call_signatures(),
            signatures.type_signatures(),
        )
    }

    #[inline]
    #[must_use]
    pub const fn new(names: Vec<String>) -> Self {
        Self {
            names,
            signatures: Vec::new(),
            type_signatures: Vec::new(),
            module: None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn with_signatures(
        names: Vec<String>,
        signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
        type_signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
    ) -> Self {
        Self {
            names,
            signatures,
            type_signatures,
            module: None,
        }
    }

    #[must_use]
    pub fn from_module(
        bytes: &[u8],
        names: Vec<String>,
        signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
        type_signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
    ) -> Self {
        Self {
            names,
            signatures,
            type_signatures,
            module: Some(Box::new(crate::structured::ModuleCtx::from_bytes(bytes))),
        }
    }

    #[must_use]
    pub fn with_module_context(mut self, bytes: &[u8]) -> Self {
        self.module = Some(Box::new(crate::structured::ModuleCtx::from_bytes(bytes)));
        self
    }

    pub(crate) fn module_ctx(&self) -> Option<&crate::structured::ModuleCtx> {
        self.module.as_deref()
    }

    #[must_use]
    pub(crate) fn resolve(&self, function_index: u32) -> String {
        self.names
            .get(function_index as usize)
            .cloned()
            .unwrap_or_else(|| format!("func_{function_index}"))
    }

    #[must_use]
    pub(crate) fn signature(&self, function_index: u32) -> (Vec<ValType>, Vec<ValType>) {
        self.signatures
            .get(function_index as usize)
            .cloned()
            .unwrap_or_else(|| (vec![ValType::I32], vec![ValType::I32]))
    }

    #[must_use]
    pub(crate) fn type_signature(&self, type_index: u32) -> (Vec<ValType>, Vec<ValType>) {
        self.type_signatures
            .get(type_index as usize)
            .cloned()
            .unwrap_or_else(|| (vec![ValType::I32], vec![ValType::I32]))
    }
}

const fn rust_type(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "u128",
        ValType::Ref(_) => "usize",
        ValType::I32 => "i32",
    }
}

const fn ts_type(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 | ValType::V128 => "bigint",
        ValType::I32 | ValType::F32 | ValType::F64 | ValType::Ref(_) => "number",
    }
}

fn zero_literal(ty: ValType, target: LiftTarget) -> String {
    match (target, ty) {
        (LiftTarget::Rust, ValType::I64) => "0i64".to_owned(),
        (LiftTarget::Rust, ValType::F32) => "0.0f32".to_owned(),
        (LiftTarget::Rust, ValType::F64) => "0.0f64".to_owned(),
        (LiftTarget::Rust, ValType::V128) => "0u128".to_owned(),
        (LiftTarget::Rust, _) => "0i32".to_owned(),
        (LiftTarget::TypeScript, ValType::I64 | ValType::V128) => "0n".to_owned(),
        (_, _) => "0".to_owned(),
    }
}

pub(crate) const fn rust_op_fn_name(kind: OpKind) -> &'static str {
    match kind {
        OpKind::I32Add => "wasm_i32_add",
        OpKind::I32Sub => "wasm_i32_sub",
        OpKind::I32Mul => "wasm_i32_mul",
        OpKind::I32DivS => "wasm_i32_div_s",
        OpKind::I32DivU => "wasm_i32_div_u",
        OpKind::I32RemS => "wasm_i32_rem_s",
        OpKind::I32RemU => "wasm_i32_rem_u",
        OpKind::I32And => "wasm_i32_and",
        OpKind::I32Or => "wasm_i32_or",
        OpKind::I32Xor => "wasm_i32_xor",
        OpKind::I32Shl => "wasm_i32_shl",
        OpKind::I32ShrU => "wasm_i32_shr_u",
        OpKind::I32ShrS => "wasm_i32_shr_s",
        OpKind::I32Rotl => "wasm_i32_rotl",
        OpKind::I32Rotr => "wasm_i32_rotr",
        OpKind::I32Eq => "wasm_i32_eq",
        OpKind::I32Ne => "wasm_i32_ne",
        OpKind::I32LtS => "wasm_i32_lt_s",
        OpKind::I32LtU => "wasm_i32_lt_u",
        OpKind::I32GtS => "wasm_i32_gt_s",
        OpKind::I32GtU => "wasm_i32_gt_u",
        OpKind::I32LeS => "wasm_i32_le_s",
        OpKind::I32LeU => "wasm_i32_le_u",
        OpKind::I32GeS => "wasm_i32_ge_s",
        OpKind::I32GeU => "wasm_i32_ge_u",
        OpKind::I64Add => "wasm_i64_add",
        OpKind::I64Sub => "wasm_i64_sub",
        OpKind::I64Mul => "wasm_i64_mul",
        OpKind::I64DivS => "wasm_i64_div_s",
        OpKind::I64DivU => "wasm_i64_div_u",
        OpKind::I64RemS => "wasm_i64_rem_s",
        OpKind::I64RemU => "wasm_i64_rem_u",
        OpKind::I64And => "wasm_i64_and",
        OpKind::I64Or => "wasm_i64_or",
        OpKind::I64Xor => "wasm_i64_xor",
        OpKind::I64Shl => "wasm_i64_shl",
        OpKind::I64ShrU => "wasm_i64_shr_u",
        OpKind::I64ShrS => "wasm_i64_shr_s",
        OpKind::I64Rotl => "wasm_i64_rotl",
        OpKind::I64Rotr => "wasm_i64_rotr",
        OpKind::I64Eq => "wasm_i64_eq",
        OpKind::I64Ne => "wasm_i64_ne",
        OpKind::I64LtS => "wasm_i64_lt_s",
        OpKind::I64LtU => "wasm_i64_lt_u",
        OpKind::I64GtS => "wasm_i64_gt_s",
        OpKind::I64GtU => "wasm_i64_gt_u",
        OpKind::I64LeS => "wasm_i64_le_s",
        OpKind::I64LeU => "wasm_i64_le_u",
        OpKind::I64GeS => "wasm_i64_ge_s",
        OpKind::I64GeU => "wasm_i64_ge_u",
        OpKind::F32Add => "wasm_f32_add",
        OpKind::F32Sub => "wasm_f32_sub",
        OpKind::F32Mul => "wasm_f32_mul",
        OpKind::F32Div => "wasm_f32_div",
        OpKind::F32Min => "wasm_f32_min",
        OpKind::F32Max => "wasm_f32_max",
        OpKind::F32Copysign => "wasm_f32_copysign",
        OpKind::F32Eq => "wasm_f32_eq",
        OpKind::F32Ne => "wasm_f32_ne",
        OpKind::F32Lt => "wasm_f32_lt",
        OpKind::F32Gt => "wasm_f32_gt",
        OpKind::F32Le => "wasm_f32_le",
        OpKind::F32Ge => "wasm_f32_ge",
        OpKind::F64Add => "wasm_f64_add",
        OpKind::F64Sub => "wasm_f64_sub",
        OpKind::F64Mul => "wasm_f64_mul",
        OpKind::F64Div => "wasm_f64_div",
        OpKind::F64Min => "wasm_f64_min",
        OpKind::F64Max => "wasm_f64_max",
        OpKind::F64Copysign => "wasm_f64_copysign",
        OpKind::F64Eq => "wasm_f64_eq",
        OpKind::F64Ne => "wasm_f64_ne",
        OpKind::F64Lt => "wasm_f64_lt",
        OpKind::F64Gt => "wasm_f64_gt",
        OpKind::F64Le => "wasm_f64_le",
        OpKind::F64Ge => "wasm_f64_ge",
    }
}

pub(crate) const fn rust_unop_fn_name(op: UnOp) -> &'static str {
    match op {
        UnOp::I32Eqz => "wasm_i32_eqz",
        UnOp::I64Eqz => "wasm_i64_eqz",
        UnOp::I32Clz => "wasm_i32_clz",
        UnOp::I32Ctz => "wasm_i32_ctz",
        UnOp::I32Popcnt => "wasm_i32_popcnt",
        UnOp::I64Clz => "wasm_i64_clz",
        UnOp::I64Ctz => "wasm_i64_ctz",
        UnOp::I64Popcnt => "wasm_i64_popcnt",
        UnOp::F32Abs => "wasm_f32_abs",
        UnOp::F32Neg => "wasm_f32_neg",
        UnOp::F32Ceil => "wasm_f32_ceil",
        UnOp::F32Floor => "wasm_f32_floor",
        UnOp::F32Trunc => "wasm_f32_trunc",
        UnOp::F32Nearest => "wasm_f32_nearest",
        UnOp::F32Sqrt => "wasm_f32_sqrt",
        UnOp::F64Abs => "wasm_f64_abs",
        UnOp::F64Neg => "wasm_f64_neg",
        UnOp::F64Ceil => "wasm_f64_ceil",
        UnOp::F64Floor => "wasm_f64_floor",
        UnOp::F64Trunc => "wasm_f64_trunc",
        UnOp::F64Nearest => "wasm_f64_nearest",
        UnOp::F64Sqrt => "wasm_f64_sqrt",
        UnOp::I32WrapI64 => "wasm_i32_wrap_i64",
        UnOp::I64ExtendI32S => "wasm_i64_extend_i32_s",
        UnOp::I64ExtendI32U => "wasm_i64_extend_i32_u",
        UnOp::I32Extend8S => "wasm_i32_extend8_s",
        UnOp::I32Extend16S => "wasm_i32_extend16_s",
        UnOp::I64Extend8S => "wasm_i64_extend8_s",
        UnOp::I64Extend16S => "wasm_i64_extend16_s",
        UnOp::I64Extend32S => "wasm_i64_extend32_s",
        UnOp::I32TruncF32S => "wasm_i32_trunc_f32_s",
        UnOp::I32TruncF32U => "wasm_i32_trunc_f32_u",
        UnOp::I32TruncF64S => "wasm_i32_trunc_f64_s",
        UnOp::I32TruncF64U => "wasm_i32_trunc_f64_u",
        UnOp::I64TruncF32S => "wasm_i64_trunc_f32_s",
        UnOp::I64TruncF32U => "wasm_i64_trunc_f32_u",
        UnOp::I64TruncF64S => "wasm_i64_trunc_f64_s",
        UnOp::I64TruncF64U => "wasm_i64_trunc_f64_u",
        UnOp::I32TruncSatF32S => "wasm_i32_trunc_sat_f32_s",
        UnOp::I32TruncSatF32U => "wasm_i32_trunc_sat_f32_u",
        UnOp::I32TruncSatF64S => "wasm_i32_trunc_sat_f64_s",
        UnOp::I32TruncSatF64U => "wasm_i32_trunc_sat_f64_u",
        UnOp::I64TruncSatF32S => "wasm_i64_trunc_sat_f32_s",
        UnOp::I64TruncSatF32U => "wasm_i64_trunc_sat_f32_u",
        UnOp::I64TruncSatF64S => "wasm_i64_trunc_sat_f64_s",
        UnOp::I64TruncSatF64U => "wasm_i64_trunc_sat_f64_u",
        UnOp::F32ConvertI32S => "wasm_f32_convert_i32_s",
        UnOp::F32ConvertI32U => "wasm_f32_convert_i32_u",
        UnOp::F32ConvertI64S => "wasm_f32_convert_i64_s",
        UnOp::F32ConvertI64U => "wasm_f32_convert_i64_u",
        UnOp::F64ConvertI32S => "wasm_f64_convert_i32_s",
        UnOp::F64ConvertI32U => "wasm_f64_convert_i32_u",
        UnOp::F64ConvertI64S => "wasm_f64_convert_i64_s",
        UnOp::F64ConvertI64U => "wasm_f64_convert_i64_u",
        UnOp::F32DemoteF64 => "wasm_f32_demote_f64",
        UnOp::F64PromoteF32 => "wasm_f64_promote_f32",
        UnOp::I32ReinterpretF32 => "wasm_i32_reinterpret_f32",
        UnOp::I64ReinterpretF64 => "wasm_i64_reinterpret_f64",
        UnOp::F32ReinterpretI32 => "wasm_f32_reinterpret_i32",
        UnOp::F64ReinterpretI64 => "wasm_f64_reinterpret_i64",
    }
}

const RUST_PRELUDE: &str = include_str!("prelude/rust.rs.txt");
const TS_PRELUDE: &str = include_str!("prelude/typescript.ts.txt");

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use wasmparser::ValType;

    use super::{FunctionSig, RecoveredTypeSurface};

    #[test]
    fn out_of_range_recovered_parameter_origin_cannot_extend_or_rename_the_signature() {
        let signature: FunctionSig = FunctionSig {
            name: "bounded".to_owned(),
            params: vec![ValType::I32],
            results: Vec::new(),
            exported: false,
            imported: false,
            local_names: Vec::new(),
        };
        let surface: RecoveredTypeSurface = RecoveredTypeSurface {
            declarations: String::new(),
            parameter_names: vec![(usize::MAX, "value_address")],
        };

        let enriched: Cow<'_, FunctionSig> = surface.enrich_signature(&signature);
        assert!(matches!(enriched, Cow::Borrowed(_)));
        assert!(enriched.local_names.is_empty());
    }
}
