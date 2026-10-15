use serde::Serialize;

use crate::expr::{Expr, Val, as_const};
use crate::u256::U256;

const IMPLEMENTATION_SLOT: &str =
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT: &str = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const BEACON_SLOT: &str = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const PROXIABLE_SLOT: &str = "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7";
const ZEPPELINOS_SLOT: &str = "7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";

const MINIMAL_PREFIX: [u8; 10] = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
const MINIMAL_SUFFIX: [u8; 15] = [
    0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3,
];
const PUSH0_PREFIX: [u8; 9] = [0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x73];
const PUSH0_SUFFIX: [u8; 15] = [
    0x5a, 0xf4, 0x3d, 0x5f, 0x5f, 0x3e, 0x5f, 0x3d, 0x91, 0x60, 0x2a, 0x57, 0xfd, 0x5b, 0xf3,
];

fn parse_slot(text: &str) -> U256 {
    let mut bytes: [u8; 32] = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let pair: &str = &text[index * 2..index * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).unwrap_or(0);
    }
    U256::from_be_bytes(bytes)
}

#[must_use]
pub fn slot_name(slot: U256) -> Option<&'static str> {
    [
        (IMPLEMENTATION_SLOT, "EIP1967_IMPLEMENTATION_SLOT"),
        (ADMIN_SLOT, "EIP1967_ADMIN_SLOT"),
        (BEACON_SLOT, "EIP1967_BEACON_SLOT"),
        (PROXIABLE_SLOT, "ERC1822_PROXIABLE_SLOT"),
        (ZEPPELINOS_SLOT, "ZEPPELINOS_IMPLEMENTATION_SLOT"),
    ]
    .into_iter()
    .find(|(hex, _): &(&str, &str)| parse_slot(hex) == slot)
    .map(|(_, name): (&str, &'static str)| name)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Proxy {
    Eip1167 {
        implementation: String,
    },
    Eip7511 {
        implementation: String,
    },
    StorageSlot {
        slot: String,
        standard: Option<&'static str>,
    },
    FixedDelegate {
        implementation: String,
    },
    DynamicDelegate,
}

fn address(bytes: &[u8]) -> String {
    format!("0x{}", crate::hex_digits(bytes))
}

#[must_use]
pub fn minimal_proxy(code: &[u8]) -> Option<Proxy> {
    if code.len() == MINIMAL_PREFIX.len() + 20 + MINIMAL_SUFFIX.len()
        && code.starts_with(&MINIMAL_PREFIX)
        && code.ends_with(&MINIMAL_SUFFIX)
    {
        return Some(Proxy::Eip1167 {
            implementation: address(&code[MINIMAL_PREFIX.len()..MINIMAL_PREFIX.len() + 20]),
        });
    }
    if code.len() == PUSH0_PREFIX.len() + 20 + PUSH0_SUFFIX.len()
        && code.starts_with(&PUSH0_PREFIX)
        && code.ends_with(&PUSH0_SUFFIX)
    {
        return Some(Proxy::Eip7511 {
            implementation: address(&code[PUSH0_PREFIX.len()..PUSH0_PREFIX.len() + 20]),
        });
    }
    None
}

fn strip_mask(value: &Val) -> &Val {
    match &value.expr {
        Expr::Bin(crate::expr::BinOp::And, inner, mask)
            if as_const(mask).and_then(U256::low_mask_bits) == Some(160) =>
        {
            inner
        }
        _ => value,
    }
}

#[must_use]
pub(crate) fn from_delegate(target: &Val) -> Proxy {
    let target: &Val = strip_mask(target);
    match &target.expr {
        Expr::Sload(slot) => match as_const(slot) {
            Some(constant) => Proxy::StorageSlot {
                slot: constant.to_string(),
                standard: slot_name(constant),
            },
            None => Proxy::DynamicDelegate,
        },
        Expr::Const(constant) => Proxy::FixedDelegate {
            implementation: address(&constant.to_be_bytes()[12..]),
        },
        _ => Proxy::DynamicDelegate,
    }
}
