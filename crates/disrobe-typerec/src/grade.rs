use crate::dwarf_gt::{DebugImage, GroundTruthFunction};
use crate::lattice::Width;
use crate::recover::{RecoveredFunction, RecoveredScalar, recover_function};

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
    let mut report: GradeReport = GradeReport::default();
    for (function, recovery) in functions.iter().zip(recovered.iter()) {
        grade_one(&mut report, function, recovery);
    }
    report
}

fn grade_one(report: &mut GradeReport, gt: &GroundTruthFunction, recovery: &RecoveredFunction) {
    for var in &gt.vars {
        report.total_vars += 1;
        report.width.total += 1;
        report.sign.total += 1;
        let Some(recovered): Option<RecoveredScalar> = recovery.slot(var.rbp_disp) else {
            continue;
        };
        report.mapped_vars += 1;
        score_width(report, gt, var, recovered);
        score_sign(report, gt, var, recovered);
    }
}

fn score_width(
    report: &mut GradeReport,
    gt: &GroundTruthFunction,
    var: &crate::dwarf_gt::GroundTruthVar,
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
    var: &crate::dwarf_gt::GroundTruthVar,
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
    use crate::dwarf_gt::GroundTruthVar;
    use crate::lattice::Sign;
    use std::collections::BTreeMap;

    fn gt_function() -> GroundTruthFunction {
        GroundTruthFunction {
            name: "f".to_owned(),
            low_pc: 0x1000,
            high_pc: 0x1010,
            vars: vec![
                GroundTruthVar {
                    name: "a".to_owned(),
                    rbp_disp: 16,
                    width: Width::Dword,
                    sign: Sign::Signed,
                },
                GroundTruthVar {
                    name: "b".to_owned(),
                    rbp_disp: 24,
                    width: Width::Byte,
                    sign: Sign::Unsigned,
                },
            ],
        }
    }

    fn recovered(a: RecoveredScalar, b: RecoveredScalar) -> RecoveredFunction {
        let mut slots: BTreeMap<i64, RecoveredScalar> = BTreeMap::new();
        slots.insert(16, a);
        slots.insert(24, b);
        RecoveredFunction {
            rbp_slots: slots,
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
}
