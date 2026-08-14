use std::collections::BTreeSet;

use pdb::FallibleIterator as _;

use crate::error::Result;
use crate::pdb_cxx::catalog::TypeCatalog;
use crate::pdb_cxx::emit::OpaqueRefs;
use crate::pdb_cxx::functions::void_spelling;
use crate::pdb_cxx::names::{Deduper, sanitize_identifier};
use crate::pdb_cxx::spelling::{self, NOTYPE_INDEX, ResolvedSpelling, SpellError, TypeOp};
use crate::pdb_cxx::{
    CvCallingConvention, EmittedFunction, FunctionRejectReason, ModuleStreamCoverage,
    RejectedFunction, is_compiler_generated_symbol, pdb_err,
};

const MAX_MODULES: usize = 65_536;
const MAX_SYMBOLS_PER_MODULE: usize = 4_000_000;
const MAX_PROCEDURES: usize = 262_144;
const MAX_PARAMETERS: usize = 4_096;

const S_THUNK32_ST: u16 = 0x0206;
const S_LPROC32_ST: u16 = 0x100a;
const S_GPROC32_ST: u16 = 0x100b;
const S_THUNK32: u16 = 0x1102;
const S_SEPCODE: u16 = 0x1132;
const S_LPROC32: u16 = 0x110f;
const S_GPROC32: u16 = 0x1110;
const S_LPROC32_ID: u16 = 0x1146;
const S_GPROC32_ID: u16 = 0x1147;
const S_INLINESITE: u16 = 0x114d;
const S_LPROC32_DPC: u16 = 0x1155;
const S_LPROC32_DPC_ID: u16 = 0x1156;
const S_INLINESITE2: u16 = 0x115d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcedureIndexSpace {
    Type,
    Id,
}

const fn procedure_index_space(raw_kind: u16) -> Option<ProcedureIndexSpace> {
    match raw_kind {
        S_LPROC32 | S_GPROC32 | S_LPROC32_ST | S_GPROC32_ST | S_LPROC32_DPC => {
            Some(ProcedureIndexSpace::Type)
        }
        S_LPROC32_ID | S_GPROC32_ID | S_LPROC32_DPC_ID => Some(ProcedureIndexSpace::Id),
        _ => None,
    }
}

#[derive(Debug)]
pub(crate) struct ProcedureRecovery {
    pub(crate) functions: Vec<EmittedFunction>,
    pub(crate) rejected: Vec<RejectedFunction>,
    pub(crate) coverage: ModuleStreamCoverage,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProcedureIdentity {
    module: Option<String>,
    original_name: String,
    signature: String,
}

#[derive(Debug)]
struct RecoveredSignature {
    return_spelling: ResolvedSpelling,
    return_type: String,
    parameters: Vec<String>,
    varargs: bool,
    calling_convention: CvCallingConvention,
    keyword: &'static str,
}

type SignatureFailure = (FunctionRejectReason, String);
type SignatureResult = std::result::Result<RecoveredSignature, SignatureFailure>;

pub(crate) fn recover_module_procedures<'s, S: pdb::Source<'s> + 's>(
    pdb_file: &mut pdb::PDB<'s, S>,
    catalog: &TypeCatalog<'_>,
    emitted_type_indices: &BTreeSet<u32>,
    opaque_out: &mut OpaqueRefs,
) -> Result<ProcedureRecovery> {
    let debug_info: pdb::DebugInformation<'_> = pdb_file.debug_information().map_err(pdb_err)?;
    let mut module_iter: pdb::ModuleIter<'_> = debug_info.modules().map_err(pdb_err)?;

    let mut coverage: ModuleStreamCoverage = ModuleStreamCoverage::default();
    let mut functions: Vec<EmittedFunction> = Vec::new();
    let mut rejected: Vec<RejectedFunction> = Vec::new();
    let mut dedup: Deduper = Deduper::new();
    let mut seen: BTreeSet<ProcedureIdentity> = BTreeSet::new();

    while let Some(module) = module_iter.next().map_err(pdb_err)? {
        if coverage.modules_declared >= MAX_MODULES {
            break;
        }
        coverage.modules_declared += 1;
        let module_name: String = module.module_name().into_owned();
        let Some(module_info) = pdb_file.module_info(&module).map_err(pdb_err)? else {
            coverage.modules_without_symbol_streams += 1;
            continue;
        };
        let Ok(mut symbol_iter) = module_info.symbols() else {
            coverage.modules_with_unreadable_symbols += 1;
            continue;
        };
        coverage.modules_with_symbol_streams += 1;

        let mut symbols_read: usize = 0;
        loop {
            if symbols_read >= MAX_SYMBOLS_PER_MODULE {
                break;
            }
            let stepped: std::result::Result<Option<pdb::Symbol<'_>>, pdb::Error> =
                symbol_iter.next();
            let Ok(stepped) = stepped else {
                coverage.modules_with_unreadable_symbols += 1;
                break;
            };
            let Some(symbol) = stepped else {
                break;
            };
            symbols_read += 1;

            let raw_kind: u16 = symbol.raw_kind();
            match raw_kind {
                S_THUNK32 | S_THUNK32_ST => {
                    coverage.thunk_records_skipped += 1;
                    continue;
                }
                S_INLINESITE | S_INLINESITE2 => {
                    coverage.inline_site_records_skipped += 1;
                    continue;
                }
                S_SEPCODE => {
                    coverage.separated_code_records_skipped += 1;
                    continue;
                }
                _ => {}
            }
            let Some(index_space) = procedure_index_space(raw_kind) else {
                continue;
            };
            coverage.procedure_records_seen += 1;
            if functions.len() + rejected.len() >= MAX_PROCEDURES {
                break;
            }

            let Ok(pdb::SymbolData::Procedure(procedure)) = symbol.parse() else {
                rejected.push(RejectedFunction {
                    original_name: String::new(),
                    module: module_name.clone(),
                    type_index: 0,
                    reason: FunctionRejectReason::Malformed,
                    detail: format!(
                        "procedure record kind 0x{raw_kind:04x} did not parse as a procedure symbol"
                    ),
                });
                continue;
            };

            let original_name: String = procedure.name.to_string().into_owned();
            if is_compiler_generated_symbol(&original_name) {
                coverage.compiler_generated_records_skipped += 1;
                continue;
            }
            let type_index: u32 = procedure.type_index.0;

            if index_space == ProcedureIndexSpace::Id {
                rejected.push(RejectedFunction {
                    original_name,
                    module: module_name.clone(),
                    type_index,
                    reason: FunctionRejectReason::IdIndexedProcedureRecord,
                    detail: format!(
                        "record kind 0x{raw_kind:04x} indexes the ID stream (LF_FUNC_ID/LF_MFUNC_ID); \
                         resolution through the ID stream is not covered"
                    ),
                });
                continue;
            }

            let signature: RecoveredSignature = match resolve_procedure_signature(
                catalog,
                procedure.type_index,
                emitted_type_indices,
            ) {
                Ok(signature) => signature,
                Err((reason, detail)) => {
                    rejected.push(RejectedFunction {
                        original_name,
                        module: module_name.clone(),
                        type_index,
                        reason,
                        detail,
                    });
                    continue;
                }
            };

            let is_static: bool = !procedure.global;
            let identity: ProcedureIdentity = ProcedureIdentity {
                module: is_static.then(|| module_name.clone()),
                original_name: original_name.clone(),
                signature: render_signature(&signature, ""),
            };
            if !seen.insert(identity) {
                coverage.duplicate_records_folded += 1;
                continue;
            }

            opaque_out.extend(signature.return_spelling.opaque_refs.iter().cloned());
            let emitted_name: String = dedup.assign(&sanitize_identifier(&original_name));
            let declaration: String = format!("{};", render_signature(&signature, &emitted_name));
            functions.push(EmittedFunction {
                name: emitted_name,
                declaration,
                original_name,
                module: module_name.clone(),
                type_index,
                return_type: signature.return_type,
                parameters: signature.parameters,
                varargs: signature.varargs,
                calling_convention: signature.calling_convention,
                is_static,
            });
        }
    }

    Ok(ProcedureRecovery {
        functions,
        rejected,
        coverage,
    })
}

fn render_signature(signature: &RecoveredSignature, name: &str) -> String {
    let mut ops: Vec<TypeOp> = vec![TypeOp::Function {
        params: signature.parameters.clone(),
        varargs: signature.varargs,
        calling_convention: Some(signature.keyword),
    }];
    ops.extend(signature.return_spelling.ops.iter().cloned());
    let rendered: ResolvedSpelling = ResolvedSpelling {
        base_text: signature.return_spelling.base_text.clone(),
        ops,
        byte_size: None,
        degraded: false,
        bitfield: None,
        opaque_refs: Vec::new(),
        value_dependency: None,
    };
    rendered.declare(name)
}

fn resolve_procedure_signature(
    catalog: &TypeCatalog<'_>,
    type_index: pdb::TypeIndex,
    emitted_type_indices: &BTreeSet<u32>,
) -> SignatureResult {
    let data: pdb::TypeData<'_> = catalog.get(type_index).map_err(|e| {
        (
            FunctionRejectReason::Malformed,
            format!("type index 0x{:x} is not readable: {e}", type_index.0),
        )
    })?;
    let procedure: pdb::ProcedureType = match data {
        pdb::TypeData::Procedure(procedure) => procedure,
        pdb::TypeData::MemberFunction(_) => {
            return Err((
                FunctionRejectReason::MemberFunctionScope,
                format!(
                    "type index 0x{:x} is an LF_MFUNCTION member function; emitting it as a free declaration would drop its class scope and its implicit this parameter",
                    type_index.0
                ),
            ));
        }
        other => {
            return Err((
                FunctionRejectReason::TypeIndexNotAFunction,
                format!(
                    "type index 0x{:x} resolves to a {} record, not a function type",
                    type_index.0,
                    type_data_kind_name(&other)
                ),
            ));
        }
    };

    let calling_convention: CvCallingConvention =
        CvCallingConvention::from_raw(procedure.attributes.calling_convention());
    let Some(keyword) = calling_convention.keyword() else {
        return Err(match calling_convention {
            CvCallingConvention::Unknown(raw) => (
                FunctionRejectReason::UnknownCallingConvention,
                format!("calling convention byte 0x{raw:02x} is not a CV_call_e value"),
            ),
            known => (
                FunctionRejectReason::UnrepresentableCallingConvention,
                format!(
                    "calling convention {known:?} (CV_call_e 0x{:02x}) has no keyword this emitter can spell",
                    known.raw()
                ),
            ),
        });
    };

    let return_spelling: ResolvedSpelling = match procedure.return_type {
        Some(index) => resolve_component(catalog, index, emitted_type_indices)
            .map_err(|detail: String| (FunctionRejectReason::UnresolvedReturnType, detail))?,
        None => void_spelling(),
    };
    let return_type: String = return_spelling.declare_bare();

    let (parameters, varargs): (Vec<String>, bool) =
        resolve_parameters(catalog, &procedure, emitted_type_indices)?;

    Ok(RecoveredSignature {
        return_spelling,
        return_type,
        parameters,
        varargs,
        calling_convention,
        keyword,
    })
}

fn resolve_parameters(
    catalog: &TypeCatalog<'_>,
    procedure: &pdb::ProcedureType,
    emitted_type_indices: &BTreeSet<u32>,
) -> std::result::Result<(Vec<String>, bool), SignatureFailure> {
    let arglist_index: pdb::TypeIndex = procedure.argument_list;
    if arglist_index == NOTYPE_INDEX {
        return Ok((Vec::new(), false));
    }
    let data: pdb::TypeData<'_> = catalog.get(arglist_index).map_err(|e| {
        (
            FunctionRejectReason::Malformed,
            format!(
                "argument list type index 0x{:x} is not readable: {e}",
                arglist_index.0
            ),
        )
    })?;
    let pdb::TypeData::ArgumentList(list) = data else {
        return Err((
            FunctionRejectReason::Malformed,
            format!(
                "argument list type index 0x{:x} resolves to a {} record, not LF_ARGLIST",
                arglist_index.0,
                type_data_kind_name(&data)
            ),
        ));
    };
    let declared_count: usize = usize::from(procedure.parameter_count);
    if list.arguments.len() < declared_count {
        return Err((
            FunctionRejectReason::Malformed,
            format!(
                "LF_PROCEDURE declares {declared_count} parameters but LF_ARGLIST 0x{:x} supplies only {}",
                arglist_index.0,
                list.arguments.len()
            ),
        ));
    }
    if list.arguments.len() > MAX_PARAMETERS {
        return Err((
            FunctionRejectReason::Malformed,
            format!(
                "LF_ARGLIST 0x{:x} carries {} entries, beyond the bound of {MAX_PARAMETERS}",
                arglist_index.0,
                list.arguments.len()
            ),
        ));
    }

    let mut parameters: Vec<String> = Vec::with_capacity(list.arguments.len());
    let mut varargs: bool = false;
    let last: usize = list.arguments.len().saturating_sub(1);
    for (position, argument) in list.arguments.iter().enumerate() {
        if *argument == NOTYPE_INDEX {
            if position == last {
                varargs = true;
                continue;
            }
            return Err((
                FunctionRejectReason::Malformed,
                format!(
                    "LF_ARGLIST 0x{:x} carries the variadic marker at position {position} of {last}, not in trailing position",
                    arglist_index.0
                ),
            ));
        }
        let resolved: ResolvedSpelling =
            resolve_component(catalog, *argument, emitted_type_indices).map_err(
                |detail: String| {
                    (
                        FunctionRejectReason::UnresolvedParameterType,
                        format!("parameter {position}: {detail}"),
                    )
                },
            )?;
        parameters.push(resolved.declare_bare());
    }
    Ok((parameters, varargs))
}

fn resolve_component(
    catalog: &TypeCatalog<'_>,
    index: pdb::TypeIndex,
    emitted_type_indices: &BTreeSet<u32>,
) -> std::result::Result<ResolvedSpelling, String> {
    let spelling: ResolvedSpelling =
        spelling::resolve_spelling(catalog, index).map_err(|e: SpellError| match e {
            SpellError::AnonymousAggregate => format!(
                "type index 0x{:x} names an anonymous aggregate that has no spellable declaration",
                index.0
            ),
            SpellError::Pdb(err) => {
                format!("type index 0x{:x} is unresolvable: {err}", index.0)
            }
        })?;
    if spelling.degraded {
        return Err(format!(
            "type index 0x{:x} only resolves to a placeholder spelling; its concrete type is not recoverable",
            index.0
        ));
    }
    if let Some(dependency) = spelling.value_dependency
        && !emitted_type_indices.contains(&dependency)
    {
        return Err(format!(
            "type index 0x{:x} is used by value but its definition (type index 0x{dependency:x}) is not among the emitted types",
            index.0
        ));
    }
    Ok(spelling)
}

const fn type_data_kind_name(data: &pdb::TypeData<'_>) -> &'static str {
    match data {
        pdb::TypeData::Primitive(_) => "LF_PRIMITIVE",
        pdb::TypeData::Class(_) => "LF_CLASS/LF_STRUCTURE",
        pdb::TypeData::Member(_) => "LF_MEMBER",
        pdb::TypeData::MemberFunction(_) => "LF_MFUNCTION",
        pdb::TypeData::OverloadedMethod(_) => "LF_METHOD",
        pdb::TypeData::Method(_) => "LF_ONEMETHOD",
        pdb::TypeData::StaticMember(_) => "LF_STMEMBER",
        pdb::TypeData::Nested(_) => "LF_NESTTYPE",
        pdb::TypeData::BaseClass(_) => "LF_BCLASS",
        pdb::TypeData::VirtualBaseClass(_) => "LF_VBCLASS/LF_IVBCLASS",
        pdb::TypeData::VirtualFunctionTablePointer(_) => "LF_VFUNCTAB",
        pdb::TypeData::Procedure(_) => "LF_PROCEDURE",
        pdb::TypeData::Pointer(_) => "LF_POINTER",
        pdb::TypeData::Modifier(_) => "LF_MODIFIER",
        pdb::TypeData::Enumeration(_) => "LF_ENUM",
        pdb::TypeData::Enumerate(_) => "LF_ENUMERATE",
        pdb::TypeData::Array(_) => "LF_ARRAY",
        pdb::TypeData::Union(_) => "LF_UNION",
        pdb::TypeData::Bitfield(_) => "LF_BITFIELD",
        pdb::TypeData::FieldList(_) => "LF_FIELDLIST",
        pdb::TypeData::ArgumentList(_) => "LF_ARGLIST",
        pdb::TypeData::MethodList(_) => "LF_METHODLIST",
        _ => "unrecognized",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const FIXTURE_PDB: &[u8] = include_bytes!("../../tests/fixtures/pdb_cxx_recovery.pdb");

    #[test]
    fn a_real_member_function_type_is_rejected_instead_of_declared_as_a_free_function() {
        let cursor: Cursor<&[u8]> = Cursor::new(FIXTURE_PDB);
        let mut pdb_file: pdb::PDB<'_, Cursor<&[u8]>> =
            pdb::PDB::open(cursor).expect("open the compiler-built fixture pdb");
        let type_info: pdb::TypeInformation<'_> = pdb_file
            .type_information()
            .expect("read the fixture tpi stream");
        let catalog: TypeCatalog<'_> = TypeCatalog::build(&type_info).expect("build type catalog");

        let mut member_function_indices: Vec<pdb::TypeIndex> = Vec::new();
        let mut iter: pdb::TypeIter<'_> = type_info.iter();
        while let Some(item) = iter.next().expect("walk the fixture tpi stream") {
            if let Ok(pdb::TypeData::MemberFunction(_)) = item.parse() {
                member_function_indices.push(item.index());
            }
        }
        assert!(
            !member_function_indices.is_empty(),
            "the fixture declares `int Shape::area() const`, so its tpi must carry at least one LF_MFUNCTION record"
        );

        let emitted_type_indices: BTreeSet<u32> = BTreeSet::new();
        for index in member_function_indices {
            let outcome: SignatureResult =
                resolve_procedure_signature(&catalog, index, &emitted_type_indices);
            let Err((reason, detail)) = outcome else {
                panic!(
                    "LF_MFUNCTION 0x{:x} must be rejected, not resolved into a free-function signature",
                    index.0
                );
            };
            assert_eq!(
                reason,
                FunctionRejectReason::MemberFunctionScope,
                "LF_MFUNCTION 0x{:x} must be rejected for its class scope, got {detail}",
                index.0
            );
            assert!(
                detail.contains(&format!("0x{:x}", index.0)),
                "the rejection must carry the observed type index: {detail}"
            );
        }
    }

    #[test]
    fn procedure_record_kinds_map_to_their_index_space() {
        assert_eq!(
            procedure_index_space(S_GPROC32),
            Some(ProcedureIndexSpace::Type)
        );
        assert_eq!(
            procedure_index_space(S_LPROC32),
            Some(ProcedureIndexSpace::Type)
        );
        assert_eq!(
            procedure_index_space(S_LPROC32_ST),
            Some(ProcedureIndexSpace::Type)
        );
        assert_eq!(
            procedure_index_space(S_GPROC32_ST),
            Some(ProcedureIndexSpace::Type)
        );
        assert_eq!(
            procedure_index_space(S_LPROC32_DPC),
            Some(ProcedureIndexSpace::Type)
        );
        assert_eq!(
            procedure_index_space(S_GPROC32_ID),
            Some(ProcedureIndexSpace::Id)
        );
        assert_eq!(
            procedure_index_space(S_LPROC32_ID),
            Some(ProcedureIndexSpace::Id)
        );
        assert_eq!(
            procedure_index_space(S_LPROC32_DPC_ID),
            Some(ProcedureIndexSpace::Id)
        );
        assert_eq!(procedure_index_space(S_THUNK32), None);
        assert_eq!(procedure_index_space(S_SEPCODE), None);
        assert_eq!(procedure_index_space(S_INLINESITE), None);
    }

    #[test]
    fn calling_conventions_round_trip_through_their_cv_call_e_byte() {
        for raw in 0_u8..=255_u8 {
            assert_eq!(CvCallingConvention::from_raw(raw).raw(), raw);
        }
    }

    #[test]
    fn only_conventions_msvc_can_spell_carry_a_keyword() {
        assert_eq!(CvCallingConvention::NearC.keyword(), Some("__cdecl"));
        assert_eq!(CvCallingConvention::NearFast.keyword(), Some("__fastcall"));
        assert_eq!(
            CvCallingConvention::NearStdCall.keyword(),
            Some("__stdcall")
        );
        assert_eq!(CvCallingConvention::ThisCall.keyword(), Some("__thiscall"));
        assert_eq!(
            CvCallingConvention::NearVector.keyword(),
            Some("__vectorcall")
        );
        assert_eq!(CvCallingConvention::FarPascal.keyword(), None);
        assert_eq!(CvCallingConvention::ClrCall.keyword(), None);
        assert_eq!(CvCallingConvention::Swift.keyword(), None);
        assert_eq!(CvCallingConvention::Unknown(0x06).keyword(), None);
        assert_eq!(CvCallingConvention::Unknown(0xff).keyword(), None);
    }
}
