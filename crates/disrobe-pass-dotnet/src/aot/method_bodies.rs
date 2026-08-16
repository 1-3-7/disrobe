use disrobe_pass_native::{PseudoAbi, recover_leaf_function_abi};

use super::{AotCodeRange, AotMethod, AotMethodBody};
use crate::pe::PeImage;

const MAX_METHOD_BODY_INPUT_BYTES: usize = 1024 * 1024;
const MAX_METHOD_BODY_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BODY_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_BODY_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_UNIQUE_METHOD_BODIES: usize = 65_536;
const MAX_REFUSAL_BYTES_PER_METHOD: usize = 128;

const fn invalid(range: AotCodeRange, reason: &'static str) -> crate::error::Error {
    crate::error::Error::InvalidAotMethodBody {
        offset: range.start_rva,
        reason,
    }
}

fn refused(range: AotCodeRange, reason: &'static str) -> AotMethodBody {
    AotMethodBody::Refused {
        reason: format!("DR-DOTNET-0039: RVA 0x{:X}: {reason}", range.start_rva),
    }
}

struct BodyBudget {
    unique_bodies: usize,
    input_bytes: usize,
    output_bytes: usize,
    reserved_output_bytes: usize,
}

impl BodyBudget {
    fn new(method_count: usize) -> crate::error::Result<Self> {
        let reserved_output_bytes: usize = method_count
            .checked_mul(MAX_REFUSAL_BYTES_PER_METHOD)
            .ok_or(invalid(
            AotCodeRange {
                start_rva: 0,
                end_rva: 0,
            },
            "method body refusal reservation overflowed",
        ))?;
        if reserved_output_bytes > MAX_TOTAL_BODY_OUTPUT_BYTES {
            return Err(invalid(
                AotCodeRange {
                    start_rva: 0,
                    end_rva: 0,
                },
                "method body refusal reservation exceeds the output limit",
            ));
        }
        Ok(Self {
            unique_bodies: 0,
            input_bytes: 0,
            output_bytes: 0,
            reserved_output_bytes,
        })
    }

    fn claim_input(&mut self, range: AotCodeRange, bytes: usize) -> Result<(), AotMethodBody> {
        if bytes > MAX_METHOD_BODY_INPUT_BYTES {
            return Err(refused(
                range,
                "method body exceeds the per-method input limit",
            ));
        }
        let Some(unique_bodies): Option<usize> = self.unique_bodies.checked_add(1) else {
            return Err(refused(range, "unique method body count overflowed"));
        };
        if unique_bodies > MAX_UNIQUE_METHOD_BODIES {
            return Err(refused(
                range,
                "unique method body count exceeds the parser limit",
            ));
        }
        let Some(input_bytes): Option<usize> = self.input_bytes.checked_add(bytes) else {
            return Err(refused(
                range,
                "aggregate method body input size overflowed",
            ));
        };
        if input_bytes > MAX_TOTAL_BODY_INPUT_BYTES {
            return Err(refused(
                range,
                "aggregate method body input exceeds the parser limit",
            ));
        }
        self.unique_bodies = unique_bodies;
        self.input_bytes = input_bytes;
        Ok(())
    }

    fn assign_outcome(
        &mut self,
        range: AotCodeRange,
        outcome: AotMethodBody,
        method_count: usize,
    ) -> crate::error::Result<AotMethodBody> {
        let reserved_for_group: usize = method_count
            .checked_mul(MAX_REFUSAL_BYTES_PER_METHOD)
            .ok_or_else(|| invalid(range, "method body group reservation overflowed"))?;
        self.reserved_output_bytes = self
            .reserved_output_bytes
            .checked_sub(reserved_for_group)
            .ok_or_else(|| invalid(range, "method body group reservation underflowed"))?;
        let candidate: AotMethodBody = if outcome_bytes(&outcome) > MAX_METHOD_BODY_OUTPUT_BYTES {
            refused(range, "pseudo-C exceeds the per-method output limit")
        } else {
            outcome
        };
        let candidate_bytes: usize = outcome_bytes(&candidate).saturating_mul(method_count);
        let candidate_total: usize = self
            .output_bytes
            .saturating_add(candidate_bytes)
            .saturating_add(self.reserved_output_bytes);
        if candidate_total <= MAX_TOTAL_BODY_OUTPUT_BYTES {
            self.output_bytes = self
                .output_bytes
                .checked_add(candidate_bytes)
                .ok_or_else(|| invalid(range, "aggregate method body output overflowed"))?;
            return Ok(candidate);
        }
        let refusal: AotMethodBody = refused(range, "aggregate method body output limit reached");
        let refusal_bytes: usize = outcome_bytes(&refusal)
            .checked_mul(method_count)
            .ok_or_else(|| invalid(range, "aggregate method body refusal size overflowed"))?;
        let refusal_total: usize = self
            .output_bytes
            .checked_add(refusal_bytes)
            .and_then(|bytes: usize| bytes.checked_add(self.reserved_output_bytes))
            .ok_or_else(|| invalid(range, "aggregate method body refusal output overflowed"))?;
        if refusal_total > MAX_TOTAL_BODY_OUTPUT_BYTES {
            return Err(invalid(
                range,
                "aggregate method body refusal output exceeds the reserved limit",
            ));
        }
        self.output_bytes = self
            .output_bytes
            .checked_add(refusal_bytes)
            .ok_or_else(|| invalid(range, "aggregate method body refusal output overflowed"))?;
        Ok(refusal)
    }
}

fn recover_body(
    image: &[u8],
    pe: &PeImage,
    range: AotCodeRange,
    budget: &mut BodyBudget,
) -> crate::error::Result<AotMethodBody> {
    let length_u32: u32 = range
        .end_rva
        .checked_sub(range.start_rva)
        .ok_or_else(|| invalid(range, "method body range is reversed"))?;
    let length: usize = usize::try_from(length_u32).map_err(|_: std::num::TryFromIntError| {
        invalid(range, "method body size does not fit usize")
    })?;
    if length == 0 {
        return Err(invalid(range, "method body range is empty"));
    }
    if let Err(outcome) = budget.claim_input(range, length) {
        return Ok(outcome);
    }
    let bytes: &[u8] = pe
        .slice_exact_file_backed_rva(image, range.start_rva, length)
        .ok_or_else(|| invalid(range, "method body is not entirely file backed"))?;
    let Some(base): Option<u64> = pe.image_base.checked_add(u64::from(range.start_rva)) else {
        return Ok(refused(range, "method virtual address overflowed"));
    };
    let recovery: disrobe_pass_native::LeafRecovery =
        match recover_leaf_function_abi(bytes, base, PseudoAbi::MsX64) {
            Ok(recovery) => recovery,
            Err(_error) => {
                return Ok(refused(
                    range,
                    "native pseudo-C lifter refused the instruction stream",
                ));
            }
        };
    Ok(AotMethodBody::Recovered {
        pseudo_c: recovery.source,
    })
}

const fn outcome_bytes(outcome: &AotMethodBody) -> usize {
    match outcome {
        AotMethodBody::Recovered { pseudo_c } => pseudo_c.len(),
        AotMethodBody::Refused { reason } => reason.len(),
    }
}

pub(super) fn attach_method_bodies(
    image: &[u8],
    pe: &PeImage,
    methods: &mut [AotMethod],
) -> crate::error::Result<()> {
    let method_count: usize = methods
        .iter()
        .filter(|method: &&AotMethod| method.code_range.is_some())
        .count();
    let mut ranges: Vec<(usize, AotCodeRange)> = Vec::new();
    ranges
        .try_reserve_exact(method_count)
        .map_err(|_: std::collections::TryReserveError| {
            crate::error::Error::InvalidAotMethodBody {
                offset: 0,
                reason: "method body assignment allocation failed",
            }
        })?;
    for (method_index, method) in methods.iter().enumerate() {
        if let Some(range) = method.code_range {
            ranges.push((method_index, range));
        }
    }
    ranges.sort_unstable_by_key(|(_method_index, range): &(usize, AotCodeRange)| *range);
    let mut assignments: Vec<(usize, AotMethodBody)> = Vec::new();
    assignments.try_reserve_exact(ranges.len()).map_err(
        |_: std::collections::TryReserveError| crate::error::Error::InvalidAotMethodBody {
            offset: 0,
            reason: "method body result allocation failed",
        },
    )?;
    let mut budget: BodyBudget = BodyBudget::new(ranges.len())?;
    let mut cursor: usize = 0;
    while cursor < ranges.len() {
        let range: AotCodeRange = ranges
            .get(cursor)
            .map(|(_method_index, range): &(usize, AotCodeRange)| *range)
            .ok_or_else(|| {
                invalid(
                    AotCodeRange {
                        start_rva: 0,
                        end_rva: 0,
                    },
                    "method body range index is absent",
                )
            })?;
        let mut group_end: usize = cursor;
        while group_end < ranges.len()
            && ranges.get(group_end).is_some_and(
                |(_method_index, candidate): &(usize, AotCodeRange)| *candidate == range,
            )
        {
            group_end = group_end
                .checked_add(1)
                .ok_or_else(|| invalid(range, "method body group cursor overflowed"))?;
        }
        let group_size: usize = group_end
            .checked_sub(cursor)
            .ok_or_else(|| invalid(range, "method body group size underflowed"))?;
        let recovered: AotMethodBody = recover_body(image, pe, range, &mut budget)?;
        let outcome: AotMethodBody = budget.assign_outcome(range, recovered, group_size)?;
        while cursor < group_end {
            let method_index: usize = ranges
                .get(cursor)
                .map(|(method_index, _range): &(usize, AotCodeRange)| *method_index)
                .ok_or_else(|| invalid(range, "method body assignment index is absent"))?;
            assignments.push((method_index, outcome.clone()));
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| invalid(range, "method body assignment cursor overflowed"))?;
        }
    }
    assignments
        .sort_unstable_by_key(|(method_index, _body): &(usize, AotMethodBody)| *method_index);
    for (method_index, body) in assignments {
        methods
            .get_mut(method_index)
            .ok_or(crate::error::Error::InvalidAotMethodBody {
                offset: 0,
                reason: "method body method index is absent",
            })?
            .body = Some(body);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AotCodeRange, AotMethod, AotMethodBody, BodyBudget, MAX_METHOD_BODY_OUTPUT_BYTES,
        MAX_TOTAL_BODY_OUTPUT_BYTES, PeImage, attach_method_bodies, outcome_bytes, refused,
    };
    use crate::pe::{PeBitness, SectionHeader};

    #[test]
    fn duplicate_ranges_apply_the_per_method_limit_before_aggregate_accounting()
    -> crate::error::Result<()> {
        const METHOD_COUNT: u32 = 5_000;
        let image: [u8; 4] = [0x8d, 0x04, 0x11, 0xc3];
        let pe: PeImage = PeImage {
            bitness: PeBitness::Pe32Plus,
            machine: 0x8664,
            number_of_sections: 1,
            timestamp: 0,
            characteristics: 0,
            entry_point_rva: 0,
            image_base: 0x0000_0001_4000_0000,
            data_directories: Vec::new(),
            sections: vec![SectionHeader {
                name: ".text".to_owned(),
                virtual_size: 4,
                virtual_address: 0x1000,
                raw_size: 4,
                raw_pointer: 0,
                characteristics: 0x2000_0000,
            }],
        };
        let range: AotCodeRange = AotCodeRange {
            start_rva: 0x1000,
            end_rva: 0x1004,
        };
        let mut methods: Vec<AotMethod> = (0..METHOD_COUNT)
            .map(|record_offset: u32| AotMethod {
                record_offset,
                name: "Add".to_owned(),
                signature: None,
                entrypoint_rva: Some(range.start_rva),
                code_range: Some(range),
                body: None,
            })
            .collect();

        attach_method_bodies(&image, &pe, &mut methods)?;

        assert_eq!(methods.len(), 5_000);
        assert!(methods.iter().all(|method: &AotMethod| matches!(
            method.body,
            Some(AotMethodBody::Recovered { .. })
        )));
        Ok(())
    }

    #[test]
    fn repeated_refusal_groups_are_charged_against_the_aggregate_limit() -> crate::error::Result<()>
    {
        const GROUP_SIZE: usize = 32_768;
        let first_range: AotCodeRange = AotCodeRange {
            start_rva: 0x1000,
            end_rva: 0x1004,
        };
        let second_range: AotCodeRange = AotCodeRange {
            start_rva: 0x2000,
            end_rva: 0x2004,
        };
        let mut budget: BodyBudget = BodyBudget::new(GROUP_SIZE * 2)?;
        let first: AotMethodBody = budget.assign_outcome(
            first_range,
            refused(first_range, "unsupported body"),
            GROUP_SIZE,
        )?;
        let second: AotMethodBody = budget.assign_outcome(
            second_range,
            refused(second_range, "unsupported body"),
            GROUP_SIZE,
        )?;

        assert!(matches!(first, AotMethodBody::Refused { .. }));
        assert!(matches!(second, AotMethodBody::Refused { .. }));
        let expected_output_bytes: usize = outcome_bytes(&first)
            .saturating_mul(GROUP_SIZE)
            .saturating_add(outcome_bytes(&second).saturating_mul(GROUP_SIZE));
        assert_eq!(budget.reserved_output_bytes, 0);
        assert_eq!(budget.output_bytes, expected_output_bytes);
        assert!(expected_output_bytes <= MAX_TOTAL_BODY_OUTPUT_BYTES);
        Ok(())
    }

    #[test]
    fn aggregate_limit_uses_a_charged_compact_refusal() -> crate::error::Result<()> {
        const FALLBACK_GROUP_SIZE: usize = 8;
        let fallback_range: AotCodeRange = AotCodeRange {
            start_rva: 0x3000,
            end_rva: 0x3004,
        };
        let trailing_range: AotCodeRange = AotCodeRange {
            start_rva: 0x4000,
            end_rva: 0x4004,
        };
        let mut budget: BodyBudget = BodyBudget::new(FALLBACK_GROUP_SIZE + 1)?;
        let fallback: AotMethodBody = budget.assign_outcome(
            fallback_range,
            AotMethodBody::Recovered {
                pseudo_c: "x".repeat(MAX_METHOD_BODY_OUTPUT_BYTES),
            },
            FALLBACK_GROUP_SIZE,
        )?;
        let trailing: AotMethodBody = budget.assign_outcome(
            trailing_range,
            refused(trailing_range, "unsupported body"),
            1,
        )?;

        assert_eq!(
            fallback,
            AotMethodBody::Refused {
                reason: "DR-DOTNET-0039: RVA 0x3000: aggregate method body output limit reached"
                    .to_owned(),
            }
        );
        let expected_output_bytes: usize = outcome_bytes(&fallback)
            .saturating_mul(FALLBACK_GROUP_SIZE)
            .saturating_add(outcome_bytes(&trailing));
        assert_eq!(budget.reserved_output_bytes, 0);
        assert_eq!(budget.output_bytes, expected_output_bytes);
        assert!(expected_output_bytes <= MAX_TOTAL_BODY_OUTPUT_BYTES);
        Ok(())
    }
}
