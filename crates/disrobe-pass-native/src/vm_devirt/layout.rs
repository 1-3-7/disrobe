use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextRole {
    Registers,
    ValueStack,
    StackPointer,
    ProgramCounter,
    Scratch,
    Bytecode,
}

impl ContextRole {
    pub const ALL: [Self; 6] = [
        Self::Registers,
        Self::ValueStack,
        Self::StackPointer,
        Self::ProgramCounter,
        Self::Scratch,
        Self::Bytecode,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Registers => "registers",
            Self::ValueStack => "value-stack",
            Self::StackPointer => "stack-pointer",
            Self::ProgramCounter => "program-counter",
            Self::Scratch => "scratch",
            Self::Bytecode => "bytecode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldEvidence {
    pub touched_at: u64,
    pub agreeing_observations: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextField {
    pub offset: u64,
    pub evidence: FieldEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmContextLayout {
    fields: BTreeMap<ContextRole, ContextField>,
}

impl VmContextLayout {
    #[must_use]
    pub fn field(&self, role: ContextRole) -> ContextField {
        self.fields[&role]
    }

    #[must_use]
    pub fn offset(&self, role: ContextRole) -> u64 {
        self.field(role).offset
    }

    #[must_use]
    pub fn roles(&self) -> [ContextRole; 6] {
        ContextRole::ALL
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutAbstention {
    pub missing: Vec<ContextRole>,
    pub conflicting: Vec<ContextRole>,
}

impl std::fmt::Display for LayoutAbstention {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let missing: Vec<&'static str> = self
            .missing
            .iter()
            .map(|role: &ContextRole| role.name())
            .collect();
        let conflicting: Vec<&'static str> = self
            .conflicting
            .iter()
            .map(|role: &ContextRole| role.name())
            .collect();
        write!(
            formatter,
            "vm context layout is incomplete: no evidence for [{}], contradictory evidence for [{}]",
            missing.join(", "),
            conflicting.join(", ")
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct VmContextLayoutBuilder {
    accepted: BTreeMap<ContextRole, ContextField>,
    conflicting: BTreeSet<ContextRole>,
}

impl VmContextLayoutBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            accepted: BTreeMap::new(),
            conflicting: BTreeSet::new(),
        }
    }

    pub fn observe(&mut self, role: ContextRole, offset: u64, evidence: FieldEvidence) {
        match self.accepted.get(&role) {
            Some(existing) if existing.offset != offset => {
                self.conflicting.insert(role);
            }
            Some(existing) => {
                let merged: ContextField = ContextField {
                    offset,
                    evidence: FieldEvidence {
                        touched_at: existing.evidence.touched_at,
                        agreeing_observations: existing
                            .evidence
                            .agreeing_observations
                            .saturating_add(evidence.agreeing_observations),
                    },
                };
                self.accepted.insert(role, merged);
            }
            None => {
                self.accepted
                    .insert(role, ContextField { offset, evidence });
            }
        }
    }

    pub fn finish(self) -> Result<VmContextLayout, LayoutAbstention> {
        let conflicting: Vec<ContextRole> = self.conflicting.into_iter().collect();
        let missing: Vec<ContextRole> = ContextRole::ALL
            .into_iter()
            .filter(|role: &ContextRole| !self.accepted.contains_key(role))
            .collect();
        if !missing.is_empty() || !conflicting.is_empty() {
            return Err(LayoutAbstention {
                missing,
                conflicting,
            });
        }
        Ok(VmContextLayout {
            fields: self.accepted,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn evidence(at: u64) -> FieldEvidence {
        FieldEvidence {
            touched_at: at,
            agreeing_observations: 1,
        }
    }

    fn complete_builder() -> VmContextLayoutBuilder {
        let mut builder: VmContextLayoutBuilder = VmContextLayoutBuilder::new();
        for (index, role) in ContextRole::ALL.into_iter().enumerate() {
            builder.observe(role, index as u64 * 8, evidence(0x1000 + index as u64));
        }
        builder
    }

    #[test]
    fn a_complete_layout_needs_every_role() {
        let layout: VmContextLayout = complete_builder().finish().expect("all roles observed");
        for (index, role) in ContextRole::ALL.into_iter().enumerate() {
            assert_eq!(layout.offset(role), index as u64 * 8);
        }
    }

    #[test]
    fn a_missing_role_abstains_and_names_it() {
        let mut builder: VmContextLayoutBuilder = VmContextLayoutBuilder::new();
        for (index, role) in ContextRole::ALL.into_iter().enumerate() {
            if role == ContextRole::Scratch {
                continue;
            }
            builder.observe(role, index as u64 * 8, evidence(0x1000));
        }
        let abstention: LayoutAbstention =
            builder.finish().expect_err("scratch was never observed");
        assert_eq!(abstention.missing, vec![ContextRole::Scratch]);
        assert!(abstention.conflicting.is_empty());
        assert!(abstention.to_string().contains("scratch"), "{abstention}");
    }

    #[test]
    fn every_role_is_individually_required() {
        for withheld in ContextRole::ALL {
            let mut builder: VmContextLayoutBuilder = VmContextLayoutBuilder::new();
            for (index, role) in ContextRole::ALL.into_iter().enumerate() {
                if role == withheld {
                    continue;
                }
                builder.observe(role, index as u64 * 8, evidence(0x1000));
            }
            let abstention: LayoutAbstention = match builder.finish() {
                Ok(_) => panic!("withholding {} must abstain", withheld.name()),
                Err(error) => error,
            };
            assert_eq!(
                abstention.missing,
                vec![withheld],
                "withholding {} must name exactly that role",
                withheld.name()
            );
        }
    }

    #[test]
    fn contradictory_offsets_abstain_rather_than_taking_either() {
        let mut builder: VmContextLayoutBuilder = complete_builder();
        builder.observe(ContextRole::ValueStack, 0x99, evidence(0x2000));
        let abstention: LayoutAbstention = builder
            .finish()
            .expect_err("two offsets for one role cannot both be right");
        assert_eq!(abstention.conflicting, vec![ContextRole::ValueStack]);
        assert!(abstention.missing.is_empty());
    }

    #[test]
    fn agreeing_observations_accumulate_without_moving_the_offset() {
        let mut builder: VmContextLayoutBuilder = complete_builder();
        builder.observe(ContextRole::Registers, 0, evidence(0x3000));
        let layout: VmContextLayout = builder.finish().expect("agreement is not conflict");
        let field: ContextField = layout.field(ContextRole::Registers);
        assert_eq!(field.offset, 0);
        assert_eq!(field.evidence.agreeing_observations, 2);
        assert_eq!(field.evidence.touched_at, 0x1000);
    }
}
