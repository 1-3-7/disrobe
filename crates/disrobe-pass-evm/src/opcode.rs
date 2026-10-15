use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fork {
    Frontier,
    Homestead,
    Byzantium,
    Constantinople,
    Istanbul,
    London,
    Paris,
    Shanghai,
    Cancun,
    Osaka,
}

impl Fork {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Frontier => "frontier",
            Self::Homestead => "homestead",
            Self::Byzantium => "byzantium",
            Self::Constantinople => "constantinople",
            Self::Istanbul => "istanbul",
            Self::London => "london",
            Self::Paris => "paris",
            Self::Shanghai => "shanghai",
            Self::Cancun => "cancun",
            Self::Osaka => "osaka",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpInfo {
    pub name: &'static str,
    pub inputs: u8,
    pub outputs: u8,
    pub fork: Fork,
}

const fn op(name: &'static str, inputs: u8, outputs: u8, fork: Fork) -> OpInfo {
    OpInfo {
        name,
        inputs,
        outputs,
        fork,
    }
}

const PUSH_NAMES: [&str; 33] = [
    "PUSH0", "PUSH1", "PUSH2", "PUSH3", "PUSH4", "PUSH5", "PUSH6", "PUSH7", "PUSH8", "PUSH9",
    "PUSH10", "PUSH11", "PUSH12", "PUSH13", "PUSH14", "PUSH15", "PUSH16", "PUSH17", "PUSH18",
    "PUSH19", "PUSH20", "PUSH21", "PUSH22", "PUSH23", "PUSH24", "PUSH25", "PUSH26", "PUSH27",
    "PUSH28", "PUSH29", "PUSH30", "PUSH31", "PUSH32",
];
const DUP_NAMES: [&str; 16] = [
    "DUP1", "DUP2", "DUP3", "DUP4", "DUP5", "DUP6", "DUP7", "DUP8", "DUP9", "DUP10", "DUP11",
    "DUP12", "DUP13", "DUP14", "DUP15", "DUP16",
];
const SWAP_NAMES: [&str; 16] = [
    "SWAP1", "SWAP2", "SWAP3", "SWAP4", "SWAP5", "SWAP6", "SWAP7", "SWAP8", "SWAP9", "SWAP10",
    "SWAP11", "SWAP12", "SWAP13", "SWAP14", "SWAP15", "SWAP16",
];
const LOG_NAMES: [&str; 5] = ["LOG0", "LOG1", "LOG2", "LOG3", "LOG4"];

#[must_use]
pub const fn info(opcode: u8) -> Option<OpInfo> {
    use Fork::{
        Byzantium, Cancun, Constantinople, Frontier, Homestead, Istanbul, London, Osaka, Paris,
        Shanghai,
    };
    match opcode {
        0x00 => Some(op("STOP", 0, 0, Frontier)),
        0x01 => Some(op("ADD", 2, 1, Frontier)),
        0x02 => Some(op("MUL", 2, 1, Frontier)),
        0x03 => Some(op("SUB", 2, 1, Frontier)),
        0x04 => Some(op("DIV", 2, 1, Frontier)),
        0x05 => Some(op("SDIV", 2, 1, Frontier)),
        0x06 => Some(op("MOD", 2, 1, Frontier)),
        0x07 => Some(op("SMOD", 2, 1, Frontier)),
        0x08 => Some(op("ADDMOD", 3, 1, Frontier)),
        0x09 => Some(op("MULMOD", 3, 1, Frontier)),
        0x0a => Some(op("EXP", 2, 1, Frontier)),
        0x0b => Some(op("SIGNEXTEND", 2, 1, Frontier)),
        0x10 => Some(op("LT", 2, 1, Frontier)),
        0x11 => Some(op("GT", 2, 1, Frontier)),
        0x12 => Some(op("SLT", 2, 1, Frontier)),
        0x13 => Some(op("SGT", 2, 1, Frontier)),
        0x14 => Some(op("EQ", 2, 1, Frontier)),
        0x15 => Some(op("ISZERO", 1, 1, Frontier)),
        0x16 => Some(op("AND", 2, 1, Frontier)),
        0x17 => Some(op("OR", 2, 1, Frontier)),
        0x18 => Some(op("XOR", 2, 1, Frontier)),
        0x19 => Some(op("NOT", 1, 1, Frontier)),
        0x1a => Some(op("BYTE", 2, 1, Frontier)),
        0x1b => Some(op("SHL", 2, 1, Constantinople)),
        0x1c => Some(op("SHR", 2, 1, Constantinople)),
        0x1d => Some(op("SAR", 2, 1, Constantinople)),
        0x1e => Some(op("CLZ", 1, 1, Osaka)),
        0x20 => Some(op("KECCAK256", 2, 1, Frontier)),
        0x30 => Some(op("ADDRESS", 0, 1, Frontier)),
        0x31 => Some(op("BALANCE", 1, 1, Frontier)),
        0x32 => Some(op("ORIGIN", 0, 1, Frontier)),
        0x33 => Some(op("CALLER", 0, 1, Frontier)),
        0x34 => Some(op("CALLVALUE", 0, 1, Frontier)),
        0x35 => Some(op("CALLDATALOAD", 1, 1, Frontier)),
        0x36 => Some(op("CALLDATASIZE", 0, 1, Frontier)),
        0x37 => Some(op("CALLDATACOPY", 3, 0, Frontier)),
        0x38 => Some(op("CODESIZE", 0, 1, Frontier)),
        0x39 => Some(op("CODECOPY", 3, 0, Frontier)),
        0x3a => Some(op("GASPRICE", 0, 1, Frontier)),
        0x3b => Some(op("EXTCODESIZE", 1, 1, Frontier)),
        0x3c => Some(op("EXTCODECOPY", 4, 0, Frontier)),
        0x3d => Some(op("RETURNDATASIZE", 0, 1, Byzantium)),
        0x3e => Some(op("RETURNDATACOPY", 3, 0, Byzantium)),
        0x3f => Some(op("EXTCODEHASH", 1, 1, Constantinople)),
        0x40 => Some(op("BLOCKHASH", 1, 1, Frontier)),
        0x41 => Some(op("COINBASE", 0, 1, Frontier)),
        0x42 => Some(op("TIMESTAMP", 0, 1, Frontier)),
        0x43 => Some(op("NUMBER", 0, 1, Frontier)),
        0x44 => Some(op("PREVRANDAO", 0, 1, Paris)),
        0x45 => Some(op("GASLIMIT", 0, 1, Frontier)),
        0x46 => Some(op("CHAINID", 0, 1, Istanbul)),
        0x47 => Some(op("SELFBALANCE", 0, 1, Istanbul)),
        0x48 => Some(op("BASEFEE", 0, 1, London)),
        0x49 => Some(op("BLOBHASH", 1, 1, Cancun)),
        0x4a => Some(op("BLOBBASEFEE", 0, 1, Cancun)),
        0x50 => Some(op("POP", 1, 0, Frontier)),
        0x51 => Some(op("MLOAD", 1, 1, Frontier)),
        0x52 => Some(op("MSTORE", 2, 0, Frontier)),
        0x53 => Some(op("MSTORE8", 2, 0, Frontier)),
        0x54 => Some(op("SLOAD", 1, 1, Frontier)),
        0x55 => Some(op("SSTORE", 2, 0, Frontier)),
        0x56 => Some(op("JUMP", 1, 0, Frontier)),
        0x57 => Some(op("JUMPI", 2, 0, Frontier)),
        0x58 => Some(op("PC", 0, 1, Frontier)),
        0x59 => Some(op("MSIZE", 0, 1, Frontier)),
        0x5a => Some(op("GAS", 0, 1, Frontier)),
        0x5b => Some(op("JUMPDEST", 0, 0, Frontier)),
        0x5c => Some(op("TLOAD", 1, 1, Cancun)),
        0x5d => Some(op("TSTORE", 2, 0, Cancun)),
        0x5e => Some(op("MCOPY", 3, 0, Cancun)),
        0x5f => Some(op("PUSH0", 0, 1, Shanghai)),
        0x60..=0x7f => Some(op(PUSH_NAMES[(opcode - 0x5f) as usize], 0, 1, Frontier)),
        0x80..=0x8f => {
            let depth: u8 = opcode - 0x80 + 1;
            Some(op(
                DUP_NAMES[(opcode - 0x80) as usize],
                depth,
                depth + 1,
                Frontier,
            ))
        }
        0x90..=0x9f => {
            let depth: u8 = opcode - 0x90 + 2;
            Some(op(
                SWAP_NAMES[(opcode - 0x90) as usize],
                depth,
                depth,
                Frontier,
            ))
        }
        0xa0..=0xa4 => Some(op(
            LOG_NAMES[(opcode - 0xa0) as usize],
            2 + (opcode - 0xa0),
            0,
            Frontier,
        )),
        0xf0 => Some(op("CREATE", 3, 1, Frontier)),
        0xf1 => Some(op("CALL", 7, 1, Frontier)),
        0xf2 => Some(op("CALLCODE", 7, 1, Frontier)),
        0xf3 => Some(op("RETURN", 2, 0, Frontier)),
        0xf4 => Some(op("DELEGATECALL", 6, 1, Homestead)),
        0xf5 => Some(op("CREATE2", 4, 1, Constantinople)),
        0xfa => Some(op("STATICCALL", 6, 1, Byzantium)),
        0xfd => Some(op("REVERT", 2, 0, Byzantium)),
        0xfe => Some(op("INVALID", 0, 0, Frontier)),
        0xff => Some(op("SELFDESTRUCT", 1, 0, Frontier)),
        _ => None,
    }
}

#[must_use]
pub const fn immediate_len(opcode: u8) -> usize {
    match opcode {
        0x60..=0x7f => (opcode - 0x5f) as usize,
        _ => 0,
    }
}

#[must_use]
pub const fn ends_block(opcode: u8) -> bool {
    matches!(opcode, 0x00 | 0x56 | 0x57 | 0xf3 | 0xfd | 0xfe | 0xff) || info(opcode).is_none()
}

#[must_use]
pub const fn no_fallthrough(opcode: u8) -> bool {
    matches!(opcode, 0x00 | 0x56 | 0xf3 | 0xfd | 0xfe | 0xff) || info(opcode).is_none()
}

pub const JUMPDEST: u8 = 0x5b;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;

#[cfg(test)]
mod tests {
    use super::{Fork, immediate_len, info};

    #[test]
    fn table_covers_cancun_and_osaka_opcodes() {
        let expected: [(u8, &str, Fork); 7] = [
            (0x5f, "PUSH0", Fork::Shanghai),
            (0x5c, "TLOAD", Fork::Cancun),
            (0x5d, "TSTORE", Fork::Cancun),
            (0x5e, "MCOPY", Fork::Cancun),
            (0x49, "BLOBHASH", Fork::Cancun),
            (0x4a, "BLOBBASEFEE", Fork::Cancun),
            (0x1e, "CLZ", Fork::Osaka),
        ];
        for (byte, name, fork) in expected {
            let found = info(byte);
            assert_eq!(found.map(|op| op.name), Some(name));
            assert_eq!(found.map(|op| op.fork), Some(fork));
        }
        assert_eq!(immediate_len(0x7f), 32);
        assert_eq!(immediate_len(0x5f), 0);
        assert!(info(0xe0).is_none());
        assert!(info(0xef).is_none());
        assert_eq!(info(0x9f).map(|op| (op.inputs, op.outputs)), Some((17, 17)));
        assert_eq!(info(0x8f).map(|op| (op.inputs, op.outputs)), Some((16, 17)));
        let defined: usize = (0..=255u8)
            .filter(|byte: &u8| info(*byte).is_some())
            .count();
        assert_eq!(defined, 150);
    }
}
