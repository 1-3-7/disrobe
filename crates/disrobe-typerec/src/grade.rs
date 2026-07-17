use crate::dwarf_gt::{DebugImage, GroundTruthFunction, GroundTruthVar};
use crate::lattice::Width;
use crate::recover::{RecoveredFunction, RecoveredObject, RecoveredScalar, recover_function};

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
pub fn recover_image(image: &DebugImage) -> Vec<RecoveredFunction> {
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
    let recovered: Vec<RecoveredFunction> = recover_image(image);
    grade_functions(&image.functions, &recovered)
}

#[must_use]
pub fn grade_functions(
    functions: &[GroundTruthFunction],
    recovered: &[RecoveredFunction],
) -> GradeReport {
    grade_with(
        functions,
        recovered,
        |recovery: &RecoveredFunction, var: &GroundTruthVar| recovery.slot(var.rbp_disp),
    )
}

#[must_use]
pub fn grade_functions_split(
    functions: &[GroundTruthFunction],
    recovered: &[RecoveredFunction],
) -> GradeReport {
    grade_with(functions, recovered, split_scalar)
}

fn grade_with(
    functions: &[GroundTruthFunction],
    recovered: &[RecoveredFunction],
    lookup: impl Fn(&RecoveredFunction, &GroundTruthVar) -> Option<RecoveredScalar>,
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

fn split_scalar(recovery: &RecoveredFunction, var: &GroundTruthVar) -> Option<RecoveredScalar> {
    let mut objects: Vec<RecoveredObject> =
        recovery.objects_covering(var.rbp_disp, var.scope_lo, var.scope_hi);
    objects.sort_by_key(|object: &RecoveredObject| object.live_lo);
    objects.first().map(RecoveredObject::scalar)
}

#[must_use]
pub fn grade_identity(
    functions: &[GroundTruthFunction],
    recovered: &[RecoveredFunction],
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
    recovery: &RecoveredFunction,
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
        if candidate.rbp_disp != object.offset {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::lattice::Sign;
    use std::collections::BTreeMap;

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
        }
    }

    fn recovered(a: RecoveredScalar, b: RecoveredScalar) -> RecoveredFunction {
        let mut slots: BTreeMap<i64, RecoveredScalar> = BTreeMap::new();
        slots.insert(16, a);
        slots.insert(24, b);
        RecoveredFunction {
            rbp_slots: slots,
            objects: Vec::new(),
            has_frame_pointer: true,
        }
    }

    #[test]
    fn perfect_recovery_scores_full_marks() {
        let rec: RecoveredFunction = recovered(
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
        let rec: RecoveredFunction = recovered(
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
        let rec: RecoveredFunction = recovered(
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
        }
    }

    fn object(offset: i64, sign: Sign, lo: u64, hi: u64) -> RecoveredObject {
        RecoveredObject {
            offset,
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
        let recovery: RecoveredFunction = RecoveredFunction {
            rbp_slots: BTreeMap::new(),
            objects: vec![
                object(0, Sign::Signed, 0x2004, 0x2010),
                object(0, Sign::Unsigned, 0x2024, 0x2030),
            ],
            has_frame_pointer: true,
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
        let recovery: RecoveredFunction = RecoveredFunction {
            rbp_slots: BTreeMap::new(),
            objects: vec![object(0, Sign::Unknown, 0x2004, 0x2030)],
            has_frame_pointer: true,
        };
        let report: IdentityReport = grade_identity(&[function], &[recovery]);
        assert_eq!(report.false_merges, 2, "one object spans two typed vars");
        assert_eq!(report.false_splits, 0);
    }

    #[test]
    fn over_split_recovery_flags_false_split() {
        let function: GroundTruthFunction = gt_function();
        let recovery: RecoveredFunction = RecoveredFunction {
            rbp_slots: BTreeMap::new(),
            objects: vec![
                object(16, Sign::Signed, 0x1000, 0x1004),
                object(16, Sign::Signed, 0x1006, 0x100a),
            ],
            has_frame_pointer: true,
        };
        let report: IdentityReport = grade_identity(&[function], &[recovery]);
        assert_eq!(report.false_splits, 1);
    }
}
