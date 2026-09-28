#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use disrobe_pass_native::{LeafRecovery, PseudoAbi, recover_leaf_function_abi};

const BASE: u64 = 0x1000;

const PARITY: &str = "parity condition over integer flags";
const SIGNED_AFTER_ADD: &str = "signed order over add flags";
const MASKED_TEST: &str = "masked test read beyond zero or nonzero";
const RESULT_ONLY: &str = "result-only flags read beyond sign or zero";
const FLOAT_COMPARE: &str = "signed, sign or overflow condition over a float compare";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cc {
    O,
    No,
    B,
    Ae,
    E,
    Ne,
    Be,
    A,
    S,
    Ns,
    P,
    Np,
    L,
    Ge,
    Le,
    G,
}

const ALL_CC: [Cc; 16] = [
    Cc::O,
    Cc::No,
    Cc::B,
    Cc::Ae,
    Cc::E,
    Cc::Ne,
    Cc::Be,
    Cc::A,
    Cc::S,
    Cc::Ns,
    Cc::P,
    Cc::Np,
    Cc::L,
    Cc::Ge,
    Cc::Le,
    Cc::G,
];

impl Cc {
    const fn nibble(self) -> u8 {
        match self {
            Self::O => 0x0,
            Self::No => 0x1,
            Self::B => 0x2,
            Self::Ae => 0x3,
            Self::E => 0x4,
            Self::Ne => 0x5,
            Self::Be => 0x6,
            Self::A => 0x7,
            Self::S => 0x8,
            Self::Ns => 0x9,
            Self::P => 0xa,
            Self::Np => 0xb,
            Self::L => 0xc,
            Self::Ge => 0xd,
            Self::Le => 0xe,
            Self::G => 0xf,
        }
    }

    const fn parity(self) -> bool {
        matches!(self, Self::P | Self::Np)
    }

    const fn signed_order(self) -> bool {
        matches!(self, Self::L | Self::Ge | Self::Le | Self::G)
    }

    const fn zero(self) -> bool {
        matches!(self, Self::E | Self::Ne)
    }

    const fn sign_or_zero(self) -> bool {
        matches!(self, Self::E | Self::Ne | Self::S | Self::Ns)
    }

    const fn float_ordered(self) -> bool {
        matches!(
            self,
            Self::E | Self::Ne | Self::B | Self::Ae | Self::Be | Self::A | Self::P | Self::Np
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setter {
    CmpImm,
    CmpMem,
    Add,
    TestSelf,
    TestMask,
    And,
    Ucomisd,
}

const ALL_SETTERS: [Setter; 7] = [
    Setter::CmpImm,
    Setter::CmpMem,
    Setter::Add,
    Setter::TestSelf,
    Setter::TestMask,
    Setter::And,
    Setter::Ucomisd,
];

impl Setter {
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::CmpImm => &[0x83, 0xff, 0x07],
            Self::CmpMem => &[0x39, 0x72, 0x08],
            Self::Add => &[0x01, 0xf7],
            Self::TestSelf => &[0x85, 0xff],
            Self::TestMask => &[0xf7, 0xc7, 0x10, 0x00, 0x00, 0x00],
            Self::And => &[0x21, 0xf7],
            Self::Ucomisd => &[0x66, 0x0f, 0x2e, 0xc1],
        }
    }

    const fn refusal(self, cc: Cc) -> Option<&'static str> {
        match self {
            Self::Ucomisd => {
                if cc.float_ordered() {
                    None
                } else {
                    Some(FLOAT_COMPARE)
                }
            }
            _ if cc.parity() => Some(PARITY),
            Self::CmpImm | Self::CmpMem | Self::TestSelf => None,
            Self::Add => {
                if cc.signed_order() {
                    Some(SIGNED_AFTER_ADD)
                } else {
                    None
                }
            }
            Self::TestMask => {
                if cc.zero() {
                    None
                } else {
                    Some(MASKED_TEST)
                }
            }
            Self::And => {
                if cc.sign_or_zero() {
                    None
                } else {
                    Some(RESULT_ONLY)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consumer {
    Jcc,
    Setcc,
    Cmovcc,
}

const ALL_CONSUMERS: [Consumer; 3] = [Consumer::Jcc, Consumer::Setcc, Consumer::Cmovcc];

fn function_bytes(setter: Setter, consumer: Consumer, cc: Cc) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    match consumer {
        Consumer::Jcc => {
            code.extend_from_slice(setter.bytes());
            code.extend_from_slice(&[0x70 | cc.nibble(), 0x06]);
            code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
            code.extend_from_slice(&[0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3]);
        }
        Consumer::Setcc => {
            code.extend_from_slice(setter.bytes());
            code.extend_from_slice(&[0x0f, 0x90 | cc.nibble(), 0xc0]);
            code.extend_from_slice(&[0x0f, 0xb6, 0xc0, 0xc3]);
        }
        Consumer::Cmovcc => {
            code.extend_from_slice(&[0x89, 0xc8]);
            code.extend_from_slice(setter.bytes());
            code.extend_from_slice(&[0x41, 0x0f, 0x40 | cc.nibble(), 0xc0, 0xc3]);
        }
    }
    code
}

#[test]
fn every_x86_condition_code_is_admitted_or_refused_by_name() {
    let mut refused: usize = 0;
    let mut rendered: usize = 0;
    for setter in ALL_SETTERS {
        for consumer in ALL_CONSUMERS {
            for cc in ALL_CC {
                let code: Vec<u8> = function_bytes(setter, consumer, cc);
                let case: String = format!("{setter:?} {consumer:?} {cc:?}");
                let lifted: Result<LeafRecovery, disrobe_pass_native::Error> =
                    recover_leaf_function_abi(&code, BASE, PseudoAbi::SysV);
                match (setter.refusal(cc), lifted) {
                    (Some(reason), Err(error)) => {
                        let message: String = error.to_string();
                        assert!(
                            message.contains("not sound against tracked flags")
                                && message.contains(reason),
                            "{case}: refusal must name `{reason}`, got `{message}`"
                        );
                        refused += 1;
                    }
                    (Some(reason), Ok(recovery)) => panic!(
                        "{case}: expected a refusal naming `{reason}`, lifted:\n{}",
                        recovery.source
                    ),
                    (None, Ok(recovery)) => {
                        assert!(
                            !recovery.source.trim().is_empty(),
                            "{case}: admitted condition rendered no source"
                        );
                        rendered += 1;
                    }
                    (None, Err(error)) => {
                        panic!("{case}: admitted condition failed to lift: {error}")
                    }
                }
            }
        }
    }
    assert_eq!(refused, 138);
    assert_eq!(rendered, 198);
}
