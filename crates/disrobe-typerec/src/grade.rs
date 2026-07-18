use std::collections::{BTreeMap, BTreeSet};

use crate::abi::{self, ArgLocation, Convention, FunctionCode, RecoveredProto, ReturnKind};
use crate::dwarf_gt::{
    AbiClass, DebugImage, GroundTruthAggregate, GroundTruthField, GroundTruthFunction,
    GroundTruthSignature, GroundTruthVar, GtReturn,
};
use crate::lattice::Width;
use crate::recover::{RecoveredObject, RecoveredScalar, TypedFunction, recover_function};
use crate::structrec::{FieldNameTier, RecoveredField, RecoveredStruct};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AxisScore {
    pub predicted: usize,
    pub correct: usize,
    pub total: usize,
}

impl AxisScore {
    #[must_use]
    pub fn precision(self) -> f64 {
        if self.predicted == 0 {
            1.0
        } else {
            f64::from(u32::try_from(self.correct).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.predicted).unwrap_or(u32::MAX))
        }
    }

    #[must_use]
    pub fn recall(self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            f64::from(u32::try_from(self.correct).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxisMismatch {
    pub function: String,
    pub variable: String,
    pub expected: String,
    pub got: String,
}

#[derive(Debug, Clone, Default)]
pub struct GradeReport {
    pub width: AxisScore,
    pub sign: AxisScore,
    pub total_vars: usize,
    pub mapped_vars: usize,
    pub sign_abstentions: usize,
    pub width_mismatches: Vec<AxisMismatch>,
    pub sign_mismatches: Vec<AxisMismatch>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdentityReport {
    pub variables: usize,
    pub mapped: usize,
    pub reused: usize,
    pub false_merges: usize,
    pub false_splits: usize,
}

impl IdentityReport {
    #[must_use]
    pub fn false_merge_rate(self) -> f64 {
        rate(self.false_merges, self.mapped)
    }

    #[must_use]
    pub fn false_split_rate(self) -> f64 {
        rate(self.false_splits, self.mapped)
    }
}

fn rate(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        f64::from(u32::try_from(count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }
}

#[must_use]
pub fn recover_image(image: &DebugImage) -> Vec<TypedFunction> {
    image
        .functions
        .iter()
        .map(|function: &GroundTruthFunction| {
            image
                .function_bytes(function)
                .map(|bytes: &[u8]| recover_function(bytes, function.low_pc))
                .unwrap_or_default()
        })
        .collect()
}

#[must_use]
pub fn grade_image(image: &DebugImage) -> GradeReport {
    let recovered: Vec<TypedFunction> = recover_image(image);
    grade_functions(&image.functions, &recovered)
}

#[must_use]
pub fn grade_functions(
    functions: &[GroundTruthFunction],
    recovered: &[TypedFunction],
) -> GradeReport {
    grade_with(
        functions,
        recovered,
        |recovery: &TypedFunction, var: &GroundTruthVar| recovery.slot(var.rbp_disp),
    )
}

#[must_use]
pub fn grade_functions_split(
    functions: &[GroundTruthFunction],
    recovered: &[TypedFunction],
) -> GradeReport {
    grade_with(functions, recovered, split_scalar)
}

fn grade_with(
    functions: &[GroundTruthFunction],
    recovered: &[TypedFunction],
    lookup: impl Fn(&TypedFunction, &GroundTruthVar) -> Option<RecoveredScalar>,
) -> GradeReport {
    let mut report: GradeReport = GradeReport::default();
    for (function, recovery) in functions.iter().zip(recovered.iter()) {
        for var in &function.vars {
            report.total_vars += 1;
            report.width.total += 1;
            report.sign.total += 1;
            let Some(scalar): Option<RecoveredScalar> = lookup(recovery, var) else {
                continue;
            };
            report.mapped_vars += 1;
            score_width(&mut report, function, var, scalar);
            score_sign(&mut report, function, var, scalar);
        }
    }
    report
}

fn split_scalar(recovery: &TypedFunction, var: &GroundTruthVar) -> Option<RecoveredScalar> {
    let mut objects: Vec<RecoveredObject> =
        recovery.objects_covering(var.rbp_disp, var.scope_lo, var.scope_hi);
    objects.sort_by_key(|object: &RecoveredObject| object.live_lo);
    objects.first().map(RecoveredObject::scalar)
}

#[must_use]
pub fn grade_identity(
    functions: &[GroundTruthFunction],
    recovered: &[TypedFunction],
) -> IdentityReport {
    let mut report: IdentityReport = IdentityReport::default();
    for (function, recovery) in functions.iter().zip(recovered.iter()) {
        grade_identity_one(&mut report, function, recovery);
    }
    report
}

fn grade_identity_one(
    report: &mut IdentityReport,
    function: &GroundTruthFunction,
    recovery: &TypedFunction,
) {
    for (position, var) in function.vars.iter().enumerate() {
        report.variables += 1;
        if shares_offset_with_other_type(function, position, var) {
            report.reused += 1;
        }
        let objects: Vec<RecoveredObject> =
            recovery.objects_covering(var.rbp_disp, var.scope_lo, var.scope_hi);
        if objects.is_empty() {
            continue;
        }
        report.mapped += 1;
        if objects.len() >= 2 {
            report.false_splits += 1;
        }
        if objects
            .iter()
            .any(|object: &RecoveredObject| covers_differently_typed(function, position, *object))
        {
            report.false_merges += 1;
        }
    }
}

fn shares_offset_with_other_type(
    function: &GroundTruthFunction,
    subject: usize,
    var: &GroundTruthVar,
) -> bool {
    for (other, candidate) in function.vars.iter().enumerate() {
        if other == subject {
            continue;
        }
        if candidate.rbp_disp == var.rbp_disp && differing_type(candidate, var) {
            return true;
        }
    }
    false
}

fn covers_differently_typed(
    function: &GroundTruthFunction,
    subject: usize,
    object: RecoveredObject,
) -> bool {
    let subject_var: &GroundTruthVar = &function.vars[subject];
    for (other, candidate) in function.vars.iter().enumerate() {
        if other == subject {
            continue;
        }
        if candidate.rbp_disp != object.rbp_disp {
            continue;
        }
        if object.covers(candidate.scope_lo, candidate.scope_hi)
            && differing_type(candidate, subject_var)
        {
            return true;
        }
    }
    false
}

fn differing_type(a: &GroundTruthVar, b: &GroundTruthVar) -> bool {
    if a.width != b.width {
        return true;
    }
    a.sign.is_determined() && b.sign.is_determined() && a.sign != b.sign
}

fn score_width(
    report: &mut GradeReport,
    gt: &GroundTruthFunction,
    var: &GroundTruthVar,
    recovered: RecoveredScalar,
) {
    if recovered.width == Width::Unknown {
        return;
    }
    report.width.predicted += 1;
    if recovered.width == var.width {
        report.width.correct += 1;
    } else {
        report.width_mismatches.push(AxisMismatch {
            function: gt.name.clone(),
            variable: var.name.clone(),
            expected: format!("{:?}", var.width),
            got: format!("{:?}", recovered.width),
        });
    }
}

fn score_sign(
    report: &mut GradeReport,
    gt: &GroundTruthFunction,
    var: &GroundTruthVar,
    recovered: RecoveredScalar,
) {
    if !recovered.sign.is_determined() {
        report.sign_abstentions += 1;
        return;
    }
    report.sign.predicted += 1;
    if recovered.sign == var.sign {
        report.sign.correct += 1;
    } else {
        report.sign_mismatches.push(AxisMismatch {
            function: gt.name.clone(),
            variable: var.name.clone(),
            expected: format!("{:?}", var.sign),
            got: format!("{:?}", recovered.sign),
        });
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NameGrade {
    pub typed_emitted: usize,
    pub typed_matched: usize,
    pub offset_emitted: usize,
}

impl NameGrade {
    #[must_use]
    pub fn typed_precision(self) -> f64 {
        if self.typed_emitted == 0 {
            1.0
        } else {
            f64::from(u32::try_from(self.typed_matched).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.typed_emitted).unwrap_or(u32::MAX))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StructGradeReport {
    pub offset: AxisScore,
    pub width: AxisScore,
    pub aggregates_total: usize,
    pub aggregates_mapped: usize,
    pub union_total: usize,
    pub union_correct: usize,
    pub names: NameGrade,
    pub missing_leaves: Vec<AxisMismatch>,
    pub spurious_leaves: Vec<AxisMismatch>,
}

#[must_use]
pub fn grade_struct_image(image: &DebugImage) -> StructGradeReport {
    let recovered: Vec<TypedFunction> = recover_image(image);
    grade_structs(&image.functions, &recovered)
}

#[must_use]
pub fn grade_structs(
    functions: &[GroundTruthFunction],
    recovered: &[TypedFunction],
) -> StructGradeReport {
    let mut report: StructGradeReport = StructGradeReport::default();
    for (function, recovery) in functions.iter().zip(recovered.iter()) {
        grade_structs_one(&mut report, function, recovery);
    }
    report
}

fn grade_structs_one(
    report: &mut StructGradeReport,
    function: &GroundTruthFunction,
    recovery: &TypedFunction,
) {
    for aggregate in &function.aggregates {
        report.aggregates_total += 1;
        if aggregate.is_union {
            report.union_total += 1;
        }
        let gt_offsets: BTreeSet<i64> = aggregate
            .fields
            .iter()
            .filter(|field: &&GroundTruthField| field.width != Width::Unknown)
            .map(|field: &GroundTruthField| field.offset)
            .collect();
        let gt_leaves: BTreeSet<(i64, Width)> = aggregate.field_slots();
        report.offset.total += gt_offsets.len();
        report.width.total += gt_leaves.len();

        let Some(recovered_struct): Option<&RecoveredStruct> =
            recovery.struct_at(aggregate.rbp_disp)
        else {
            for (offset, width) in &gt_leaves {
                report.missing_leaves.push(AxisMismatch {
                    function: function.name.clone(),
                    variable: format!("{}@{:#x}", aggregate.type_name, aggregate.rbp_disp),
                    expected: format!("{offset:#x}:{width:?}"),
                    got: "absent".to_owned(),
                });
            }
            continue;
        };
        report.aggregates_mapped += 1;
        if aggregate.is_union && recovered_struct.is_union {
            report.union_correct += 1;
        }
        let rec_offsets: BTreeSet<i64> = recovered_struct
            .fields
            .iter()
            .filter(|field: &&RecoveredField| field.width != Width::Unknown)
            .map(|field: &RecoveredField| field.offset)
            .collect();
        let rec_leaves: BTreeSet<(i64, Width)> = recovered_struct.field_slots();

        report.offset.correct += gt_offsets.intersection(&rec_offsets).count();
        report.width.correct += gt_leaves.intersection(&rec_leaves).count();
        for (offset, width) in gt_leaves.difference(&rec_leaves) {
            report.missing_leaves.push(AxisMismatch {
                function: function.name.clone(),
                variable: format!("{}@{:#x}", aggregate.type_name, aggregate.rbp_disp),
                expected: format!("{offset:#x}:{width:?}"),
                got: "absent".to_owned(),
            });
        }
        grade_field_names(report, aggregate, recovered_struct);
    }

    for recovered_struct in &recovery.structs {
        let matching: Option<&GroundTruthAggregate> =
            function
                .aggregates
                .iter()
                .find(|aggregate: &&GroundTruthAggregate| {
                    aggregate.rbp_disp == recovered_struct.rbp_disp
                });
        let rec_offsets: BTreeSet<i64> = recovered_struct
            .fields
            .iter()
            .filter(|field: &&RecoveredField| field.width != Width::Unknown)
            .map(|field: &RecoveredField| field.offset)
            .collect();
        let rec_leaves: BTreeSet<(i64, Width)> = recovered_struct.field_slots();
        report.offset.predicted += rec_offsets.len();
        report.width.predicted += rec_leaves.len();
        let gt_leaves: BTreeSet<(i64, Width)> =
            matching.map_or_else(BTreeSet::new, GroundTruthAggregate::field_slots);
        for (offset, width) in rec_leaves.difference(&gt_leaves) {
            report.spurious_leaves.push(AxisMismatch {
                function: function.name.clone(),
                variable: format!("slot {:#x}", recovered_struct.rbp_disp),
                expected: "absent".to_owned(),
                got: format!("{offset:#x}:{width:?}"),
            });
        }
    }
}

fn grade_field_names(
    report: &mut StructGradeReport,
    aggregate: &GroundTruthAggregate,
    recovered_struct: &RecoveredStruct,
) {
    for field in &recovered_struct.fields {
        match field.name_tier {
            FieldNameTier::Typed => {
                report.names.typed_emitted += 1;
                if aggregate.fields.iter().any(|gt: &GroundTruthField| {
                    gt.offset == field.offset && gt.width == field.width && gt.name == field.name
                }) {
                    report.names.typed_matched += 1;
                }
            }
            FieldNameTier::Offset => report.names.offset_emitted += 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SigGradeReport {
    pub arg_count: AxisScore,
    pub arg_regs: AxisScore,
    pub return_kind: AxisScore,
    pub functions_total: usize,
    pub functions_graded: usize,
    pub return_graded: usize,
    pub variadic_total: usize,
    pub variadic_correct: usize,
    pub sret_total: usize,
    pub sret_correct: usize,
    pub mismatches: Vec<AxisMismatch>,
}

#[must_use]
pub fn recover_protos_image(
    image: &DebugImage,
    convention: Convention,
) -> Vec<Option<RecoveredProto>> {
    let codes: Vec<FunctionCode<'_>> = function_codes(image);
    let protos: Vec<RecoveredProto> = abi::recover_protos(&codes, convention);
    let by_pc: BTreeMap<u64, RecoveredProto> = codes
        .iter()
        .zip(protos)
        .map(|(code, proto): (&FunctionCode<'_>, RecoveredProto)| (code.low_pc, proto))
        .collect();
    image
        .functions
        .iter()
        .map(|function: &GroundTruthFunction| by_pc.get(&function.low_pc).cloned())
        .collect()
}

fn function_codes(image: &DebugImage) -> Vec<FunctionCode<'_>> {
    image
        .functions
        .iter()
        .filter_map(|function: &GroundTruthFunction| {
            image
                .function_bytes(function)
                .map(|bytes: &[u8]| FunctionCode {
                    low_pc: function.low_pc,
                    bytes,
                })
        })
        .collect()
}

#[must_use]
pub fn called_functions(image: &DebugImage) -> BTreeSet<u64> {
    abi::called_targets(&function_codes(image))
}

#[must_use]
pub fn grade_signature_image(image: &DebugImage, convention: Convention) -> SigGradeReport {
    let protos: Vec<Option<RecoveredProto>> = recover_protos_image(image, convention);
    let called: BTreeSet<u64> = called_functions(image);
    grade_signatures(&image.functions, &protos, convention, &called)
}

#[must_use]
pub fn grade_signatures(
    functions: &[GroundTruthFunction],
    protos: &[Option<RecoveredProto>],
    convention: Convention,
    called: &BTreeSet<u64>,
) -> SigGradeReport {
    let mut report: SigGradeReport = SigGradeReport::default();
    for (function, proto_opt) in functions.iter().zip(protos.iter()) {
        let Some(sig): Option<&GroundTruthSignature> = function.signature.as_ref() else {
            continue;
        };
        if !sig.prototyped {
            continue;
        }
        report.functions_total += 1;
        let Some(proto): Option<&RecoveredProto> = proto_opt.as_ref() else {
            continue;
        };
        report.functions_graded += 1;
        grade_arg_count(&mut report, function, sig, proto);
        grade_arg_regs(&mut report, function, sig, proto, convention);
        grade_return(&mut report, function, sig, proto, called);
        grade_variadic(&mut report, sig, proto);
        grade_sret(&mut report, sig, proto);
    }
    report
}

fn grade_arg_count(
    report: &mut SigGradeReport,
    function: &GroundTruthFunction,
    sig: &GroundTruthSignature,
    proto: &RecoveredProto,
) {
    report.arg_count.total += 1;
    report.arg_count.predicted += 1;
    if proto.args.len() == sig.params.len() {
        report.arg_count.correct += 1;
    } else {
        report.mismatches.push(AxisMismatch {
            function: function.name.clone(),
            variable: "arg_count".to_owned(),
            expected: sig.params.len().to_string(),
            got: proto.args.len().to_string(),
        });
    }
}

fn grade_arg_regs(
    report: &mut SigGradeReport,
    function: &GroundTruthFunction,
    sig: &GroundTruthSignature,
    proto: &RecoveredProto,
    convention: Convention,
) {
    let expected: BTreeSet<ArgLocation> = expected_arg_registers(sig, convention);
    let got: BTreeSet<ArgLocation> = proto.arg_register_set();
    report.arg_regs.total += 1;
    report.arg_regs.predicted += 1;
    if expected == got {
        report.arg_regs.correct += 1;
    } else {
        report.mismatches.push(AxisMismatch {
            function: function.name.clone(),
            variable: "arg_regs".to_owned(),
            expected: format!("{expected:?}"),
            got: format!("{got:?}"),
        });
    }
}

fn grade_return(
    report: &mut SigGradeReport,
    function: &GroundTruthFunction,
    sig: &GroundTruthSignature,
    proto: &RecoveredProto,
    called: &BTreeSet<u64>,
) {
    if !called.contains(&function.low_pc) {
        return;
    }
    report.return_kind.total += 1;
    report.return_graded += 1;
    if proto.ret == ReturnKind::Unknown {
        return;
    }
    report.return_kind.predicted += 1;
    let expected: ReturnKind = expected_return(sig.ret);
    if proto.ret == expected {
        report.return_kind.correct += 1;
    } else {
        report.mismatches.push(AxisMismatch {
            function: function.name.clone(),
            variable: "return_kind".to_owned(),
            expected: format!("{expected:?}"),
            got: format!("{:?}", proto.ret),
        });
    }
}

const fn grade_variadic(
    report: &mut SigGradeReport,
    sig: &GroundTruthSignature,
    proto: &RecoveredProto,
) {
    if !sig.variadic && !proto.variadic {
        return;
    }
    report.variadic_total += 1;
    if sig.variadic == proto.variadic {
        report.variadic_correct += 1;
    }
}

fn grade_sret(report: &mut SigGradeReport, sig: &GroundTruthSignature, proto: &RecoveredProto) {
    if sig.ret != GtReturn::Sret {
        return;
    }
    report.sret_total += 1;
    if proto.sret {
        report.sret_correct += 1;
    }
}

#[must_use]
fn expected_arg_registers(
    sig: &GroundTruthSignature,
    convention: Convention,
) -> BTreeSet<ArgLocation> {
    let mut out: BTreeSet<ArgLocation> = BTreeSet::new();
    match convention {
        Convention::Win64 | Convention::Unknown => {
            let offset: usize = usize::from(sig.ret == GtReturn::Sret);
            for (index, class) in sig.params.iter().enumerate() {
                let position: usize = index + offset;
                if position < 4
                    && let Some(loc) = win64_location(*class, position)
                {
                    out.insert(loc);
                }
            }
        }
        Convention::SysVAmd64 => {
            let mut int_index: usize = usize::from(sig.ret == GtReturn::Sret);
            let mut sse_index: usize = 0;
            for class in &sig.params {
                match class {
                    AbiClass::Integer => {
                        if let Some(loc) = ArgLocation::int_register(convention, int_index) {
                            out.insert(loc);
                        }
                        int_index += 1;
                    }
                    AbiClass::Sse => {
                        if let Ok(index) = u8::try_from(sse_index) {
                            out.insert(ArgLocation::SseReg(index));
                        }
                        sse_index += 1;
                    }
                }
            }
        }
    }
    out
}

fn win64_location(class: AbiClass, position: usize) -> Option<ArgLocation> {
    match class {
        AbiClass::Integer => ArgLocation::int_register(Convention::Win64, position),
        AbiClass::Sse => u8::try_from(position).ok().map(ArgLocation::SseReg),
    }
}

const fn expected_return(ret: GtReturn) -> ReturnKind {
    match ret {
        GtReturn::Void => ReturnKind::Void,
        GtReturn::Integer => ReturnKind::IntRax,
        GtReturn::Sse => ReturnKind::Sse,
        GtReturn::Sret => ReturnKind::Sret,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::lattice::Sign;

    fn gt_var(name: &str, disp: i64, width: Width, sign: Sign) -> GroundTruthVar {
        GroundTruthVar {
            name: name.to_owned(),
            rbp_disp: disp,
            width,
            sign,
            scope_lo: 0x1000,
            scope_hi: 0x1010,
        }
    }

    fn gt_function() -> GroundTruthFunction {
        GroundTruthFunction {
            name: "f".to_owned(),
            low_pc: 0x1000,
            high_pc: 0x1010,
            vars: vec![
                gt_var("a", 16, Width::Dword, Sign::Signed),
                gt_var("b", 24, Width::Byte, Sign::Unsigned),
            ],
            aggregates: Vec::new(),
            signature: None,
        }
    }

    fn recovered(a: RecoveredScalar, b: RecoveredScalar) -> TypedFunction {
        let mut slots: BTreeMap<i64, RecoveredScalar> = BTreeMap::new();
        slots.insert(16, a);
        slots.insert(24, b);
        TypedFunction {
            rbp_slots: slots,
            objects: Vec::new(),
            structs: Vec::new(),
            has_frame_pointer: true,
            proto: None,
        }
    }

    #[test]
    fn perfect_recovery_scores_full_marks() {
        let rec: TypedFunction = recovered(
            RecoveredScalar {
                width: Width::Dword,
                sign: Sign::Signed,
                sign_conflict: false,
            },
            RecoveredScalar {
                width: Width::Byte,
                sign: Sign::Unsigned,
                sign_conflict: false,
            },
        );
        let report: GradeReport = grade_functions(&[gt_function()], &[rec]);
        assert!((report.width.precision() - 1.0).abs() < f64::EPSILON);
        assert!((report.width.recall() - 1.0).abs() < f64::EPSILON);
        assert!((report.sign.precision() - 1.0).abs() < f64::EPSILON);
        assert!((report.sign.recall() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn abstained_sign_lowers_recall_not_precision() {
        let rec: TypedFunction = recovered(
            RecoveredScalar {
                width: Width::Dword,
                sign: Sign::Signed,
                sign_conflict: false,
            },
            RecoveredScalar {
                width: Width::Byte,
                sign: Sign::Unknown,
                sign_conflict: false,
            },
        );
        let report: GradeReport = grade_functions(&[gt_function()], &[rec]);
        assert_eq!(report.sign.predicted, 1);
        assert_eq!(report.sign.correct, 1);
        assert_eq!(report.sign_abstentions, 1);
        assert!((report.sign.precision() - 1.0).abs() < f64::EPSILON);
        assert!((report.sign.recall() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn wrong_sign_is_detected_by_grader() {
        let rec: TypedFunction = recovered(
            RecoveredScalar {
                width: Width::Dword,
                sign: Sign::Unsigned,
                sign_conflict: false,
            },
            RecoveredScalar {
                width: Width::Byte,
                sign: Sign::Unsigned,
                sign_conflict: false,
            },
        );
        let report: GradeReport = grade_functions(&[gt_function()], &[rec]);
        assert!(report.sign.precision() < 1.0);
        assert_eq!(report.sign_mismatches.len(), 1);
    }

    fn reuse_function() -> GroundTruthFunction {
        GroundTruthFunction {
            name: "reuse".to_owned(),
            low_pc: 0x2000,
            high_pc: 0x2040,
            vars: vec![
                GroundTruthVar {
                    name: "a".to_owned(),
                    rbp_disp: 0,
                    width: Width::Qword,
                    sign: Sign::Signed,
                    scope_lo: 0x2000,
                    scope_hi: 0x2020,
                },
                GroundTruthVar {
                    name: "b".to_owned(),
                    rbp_disp: 0,
                    width: Width::Qword,
                    sign: Sign::Unsigned,
                    scope_lo: 0x2020,
                    scope_hi: 0x2040,
                },
            ],
            aggregates: Vec::new(),
            signature: None,
        }
    }

    fn object(rbp_disp: i64, sign: Sign, lo: u64, hi: u64) -> RecoveredObject {
        RecoveredObject {
            rbp_disp,
            width: Width::Qword,
            sign,
            sign_conflict: false,
            live_lo: lo,
            live_hi: hi,
            escaped: false,
        }
    }

    #[test]
    fn split_recovery_has_no_false_merge() {
        let function: GroundTruthFunction = reuse_function();
        let recovery: TypedFunction = TypedFunction {
            rbp_slots: BTreeMap::new(),
            objects: vec![
                object(0, Sign::Signed, 0x2004, 0x2010),
                object(0, Sign::Unsigned, 0x2024, 0x2030),
            ],
            structs: Vec::new(),
            has_frame_pointer: true,
            proto: None,
        };
        let report: IdentityReport = grade_identity(&[function], &[recovery]);
        assert_eq!(report.reused, 2);
        assert_eq!(report.false_merges, 0);
        assert_eq!(report.false_splits, 0);
        assert_eq!(report.mapped, 2);
    }

    #[test]
    fn merged_recovery_flags_false_merge() {
        let function: GroundTruthFunction = reuse_function();
        let recovery: TypedFunction = TypedFunction {
            rbp_slots: BTreeMap::new(),
            objects: vec![object(0, Sign::Unknown, 0x2004, 0x2030)],
            structs: Vec::new(),
            has_frame_pointer: true,
            proto: None,
        };
        let report: IdentityReport = grade_identity(&[function], &[recovery]);
        assert_eq!(report.false_merges, 2, "one object spans two typed vars");
        assert_eq!(report.false_splits, 0);
    }

    #[test]
    fn over_split_recovery_flags_false_split() {
        let function: GroundTruthFunction = gt_function();
        let recovery: TypedFunction = TypedFunction {
            rbp_slots: BTreeMap::new(),
            objects: vec![
                object(16, Sign::Signed, 0x1000, 0x1004),
                object(16, Sign::Signed, 0x1006, 0x100a),
            ],
            structs: Vec::new(),
            has_frame_pointer: true,
            proto: None,
        };
        let report: IdentityReport = grade_identity(&[function], &[recovery]);
        assert_eq!(report.false_splits, 1);
    }
}
