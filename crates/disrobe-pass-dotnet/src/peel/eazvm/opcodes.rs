#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilOp {
    Nop,
    LdargN(u8),
    LdargS,
    StargS,
    LdlocN(u8),
    StlocN(u8),
    LdlocS,
    StlocS,
    Ldnull,
    LdcI4M1,
    LdcI4N(u8),
    LdcI4S,
    LdcI4,
    Dup,
    Pop,
    Call,
    Ret,
    BrS,
    BrfalseS,
    BrtrueS,
    BeqS,
    BgeS,
    BgtS,
    BleS,
    BltS,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Ldstr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CilOperand {
    None,
    InlineI8,
    InlineI32,
    VarByte,
    VarWord,
    ShortBranch,
    InlineMember,
    InlineString,
}

impl CilOp {
    #[must_use]
    pub const fn operand(self) -> CilOperand {
        match self {
            Self::LdcI4S => CilOperand::InlineI8,
            Self::LdcI4 => CilOperand::InlineI32,
            Self::LdargS | Self::StargS | Self::LdlocS | Self::StlocS => CilOperand::VarByte,
            Self::BrS
            | Self::BrfalseS
            | Self::BrtrueS
            | Self::BeqS
            | Self::BgeS
            | Self::BgtS
            | Self::BleS
            | Self::BltS => CilOperand::ShortBranch,
            Self::Call => CilOperand::InlineMember,
            Self::Ldstr => CilOperand::InlineString,
            _ => CilOperand::None,
        }
    }

    #[must_use]
    pub const fn is_branch(self) -> bool {
        matches!(self.operand(), CilOperand::ShortBranch)
    }

    #[must_use]
    pub const fn is_terminator(self) -> bool {
        matches!(self, Self::Ret | Self::BrS)
    }

    #[must_use]
    pub const fn handler_key(self) -> &'static str {
        match self {
            Self::Nop => "nop",
            Self::LdargN(0) => "ldarg.0",
            Self::LdargN(1) => "ldarg.1",
            Self::LdargN(2) => "ldarg.2",
            Self::LdargN(_) => "ldarg.3",
            Self::LdargS => "ldarg.s",
            Self::StargS => "starg.s",
            Self::LdlocN(0) => "ldloc.0",
            Self::LdlocN(1) => "ldloc.1",
            Self::LdlocN(2) => "ldloc.2",
            Self::LdlocN(_) => "ldloc.3",
            Self::StlocN(0) => "stloc.0",
            Self::StlocN(1) => "stloc.1",
            Self::StlocN(2) => "stloc.2",
            Self::StlocN(_) => "stloc.3",
            Self::LdlocS => "ldloc.s",
            Self::StlocS => "stloc.s",
            Self::Ldnull => "ldnull",
            Self::LdcI4M1 => "ldc.i4.m1",
            Self::LdcI4N(0) => "ldc.i4.0",
            Self::LdcI4N(1) => "ldc.i4.1",
            Self::LdcI4N(2) => "ldc.i4.2",
            Self::LdcI4N(3) => "ldc.i4.3",
            Self::LdcI4N(4) => "ldc.i4.4",
            Self::LdcI4N(5) => "ldc.i4.5",
            Self::LdcI4N(6) => "ldc.i4.6",
            Self::LdcI4N(7) => "ldc.i4.7",
            Self::LdcI4N(_) => "ldc.i4.8",
            Self::LdcI4S => "ldc.i4.s",
            Self::LdcI4 => "ldc.i4",
            Self::Dup => "dup",
            Self::Pop => "pop",
            Self::Call => "call",
            Self::Ret => "ret",
            Self::BrS => "br.s",
            Self::BrfalseS => "brfalse.s",
            Self::BrtrueS => "brtrue.s",
            Self::BeqS => "beq.s",
            Self::BgeS => "bge.s",
            Self::BgtS => "bgt.s",
            Self::BleS => "ble.s",
            Self::BltS => "blt.s",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Rem => "rem",
            Self::Ldstr => "ldstr",
        }
    }

    #[must_use]
    pub fn from_handler_key(key: &str) -> Option<Self> {
        let op: Self = match key {
            "nop" => Self::Nop,
            "ldarg.0" => Self::LdargN(0),
            "ldarg.1" => Self::LdargN(1),
            "ldarg.2" => Self::LdargN(2),
            "ldarg.3" => Self::LdargN(3),
            "ldarg.s" => Self::LdargS,
            "starg.s" => Self::StargS,
            "ldloc.0" => Self::LdlocN(0),
            "ldloc.1" => Self::LdlocN(1),
            "ldloc.2" => Self::LdlocN(2),
            "ldloc.3" => Self::LdlocN(3),
            "stloc.0" => Self::StlocN(0),
            "stloc.1" => Self::StlocN(1),
            "stloc.2" => Self::StlocN(2),
            "stloc.3" => Self::StlocN(3),
            "ldloc.s" => Self::LdlocS,
            "stloc.s" => Self::StlocS,
            "ldnull" => Self::Ldnull,
            "ldc.i4.m1" => Self::LdcI4M1,
            "ldc.i4.0" => Self::LdcI4N(0),
            "ldc.i4.1" => Self::LdcI4N(1),
            "ldc.i4.2" => Self::LdcI4N(2),
            "ldc.i4.3" => Self::LdcI4N(3),
            "ldc.i4.4" => Self::LdcI4N(4),
            "ldc.i4.5" => Self::LdcI4N(5),
            "ldc.i4.6" => Self::LdcI4N(6),
            "ldc.i4.7" => Self::LdcI4N(7),
            "ldc.i4.8" => Self::LdcI4N(8),
            "ldc.i4.s" => Self::LdcI4S,
            "ldc.i4" => Self::LdcI4,
            "dup" => Self::Dup,
            "pop" => Self::Pop,
            "call" => Self::Call,
            "ret" => Self::Ret,
            "br.s" => Self::BrS,
            "brfalse.s" => Self::BrfalseS,
            "brtrue.s" => Self::BrtrueS,
            "beq.s" => Self::BeqS,
            "bge.s" => Self::BgeS,
            "bgt.s" => Self::BgtS,
            "ble.s" => Self::BleS,
            "blt.s" => Self::BltS,
            "add" => Self::Add,
            "sub" => Self::Sub,
            "mul" => Self::Mul,
            "div" => Self::Div,
            "rem" => Self::Rem,
            "ldstr" => Self::Ldstr,
            _ => return None,
        };
        Some(op)
    }
}

#[must_use]
pub fn read_int32_special(bytes: &[u8], pos: usize) -> Option<i32> {
    let b: &[u8] = bytes.get(pos..pos.checked_add(4)?)?;
    let value: u32 = (u32::from(b[3]) << 24)
        | u32::from(b[2])
        | (u32::from(b[1]) << 8)
        | (u32::from(b[0]) << 16);
    Some(value.cast_signed())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn handler_key_round_trips() {
        for key in [
            "nop",
            "ldarg.0",
            "ldarg.s",
            "stloc.s",
            "ldc.i4",
            "ldc.i4.s",
            "add",
            "br.s",
            "blt.s",
            "call",
            "ret",
            "ldstr",
            "ldc.i4.m1",
            "ldc.i4.8",
        ] {
            let op: CilOp = CilOp::from_handler_key(key).expect("known key");
            assert_eq!(op.handler_key(), key, "round trip {key}");
        }
    }

    #[test]
    fn int32_special_matches_jumble() {
        let mut buf: [u8; 4] = [0u8; 4];
        let value: u32 = 0x1234_5678;
        buf[0] = (value >> 16) as u8;
        buf[1] = (value >> 8) as u8;
        buf[2] = value as u8;
        buf[3] = (value >> 24) as u8;
        assert_eq!(read_int32_special(&buf, 0), Some(value.cast_signed()));
    }

    #[test]
    fn branch_and_terminator_classification() {
        assert!(CilOp::BltS.is_branch());
        assert!(CilOp::BrS.is_terminator());
        assert!(CilOp::Ret.is_terminator());
        assert!(!CilOp::Add.is_branch());
    }
}
