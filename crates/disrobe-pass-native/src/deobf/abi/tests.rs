use super::*;

const BASE: u64 = 0x1_4000;

fn run(bitness: u32, bytes: &[u8]) -> AbiInference {
    infer(bitness, BASE, bytes, BASE).expect("function window must infer")
}

mod sysv64 {
    use super::*;

    const F_VOID: &[u8] = &[0x31, 0xC0, 0xC3];
    const F_VOID_NORET: &[u8] = &[0xC3];
    const F_ONE: &[u8] = &[0x8D, 0x47, 0x01, 0xC3];
    const F_TWO: &[u8] = &[0x89, 0xF8, 0x29, 0xF0, 0xC3];
    const F_THREE: &[u8] = &[0x8D, 0x04, 0x37, 0x01, 0xD0, 0xC3];
    const F_FOUR: &[u8] = &[0x01, 0xFE, 0x8D, 0x04, 0x0A, 0x01, 0xF0, 0xC3];
    const F_FIVE: &[u8] = &[
        0x01, 0xFE, 0x8D, 0x04, 0x0A, 0x01, 0xF0, 0x44, 0x01, 0xC0, 0xC3,
    ];
    const F_SIX: &[u8] = &[
        0x01, 0xFE, 0x8D, 0x04, 0x0A, 0x01, 0xF0, 0x44, 0x01, 0xC0, 0x44, 0x01, 0xC8, 0xC3,
    ];
    const F_LONG_TWO: &[u8] = &[0x48, 0x89, 0xF8, 0x48, 0x0F, 0xAF, 0xC6, 0xC3];
    const F_FP_TWO: &[u8] = &[0xF2, 0x0F, 0x58, 0xC1, 0xC3];
    const F_BRANCH: &[u8] = &[0x89, 0xF0, 0x39, 0xF7, 0x0F, 0x4F, 0xC7, 0xC3];

    #[test]
    fn void_void_has_zero_args_and_no_return_value() {
        let got: AbiInference = run(64, F_VOID_NORET);
        assert_eq!(got.arg_count, ArgCount::Exact(0));
        assert_eq!(got.returns_value, ReturnKind::Void);
        assert!(got.param_regs.is_empty());
    }

    #[test]
    fn value_returning_void_arg_fn() {
        let got: AbiInference = run(64, F_VOID);
        assert_eq!(got.arg_count, ArgCount::Exact(0));
        assert_eq!(got.returns_value, ReturnKind::Value);
    }

    #[test]
    fn one_arg_is_sysv_rdi() {
        let got: AbiInference = run(64, F_ONE);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert_eq!(got.arg_count, ArgCount::Exact(1));
        assert_eq!(got.param_regs, vec!["rdi".to_owned()]);
        assert_eq!(got.returns_value, ReturnKind::Value);
    }

    #[test]
    fn two_args_are_sysv_rdi_rsi() {
        let got: AbiInference = run(64, F_TWO);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert_eq!(got.arg_count, ArgCount::Exact(2));
        assert_eq!(got.param_regs, vec!["rdi".to_owned(), "rsi".to_owned()]);
    }

    #[test]
    fn three_args_are_sysv() {
        let got: AbiInference = run(64, F_THREE);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert_eq!(got.arg_count, ArgCount::Exact(3));
    }

    #[test]
    fn four_args_are_sysv() {
        let got: AbiInference = run(64, F_FOUR);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert!(matches!(got.arg_count, ArgCount::Exact(n) if n >= 3));
    }

    #[test]
    fn five_args_are_sysv() {
        let got: AbiInference = run(64, F_FIVE);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert!(matches!(got.arg_count, ArgCount::Exact(n) if n >= 3));
    }

    #[test]
    fn six_args_are_sysv() {
        let got: AbiInference = run(64, F_SIX);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert!(matches!(got.arg_count, ArgCount::Exact(n) if n >= 3));
    }

    #[test]
    fn long_two_args_are_sysv() {
        let got: AbiInference = run(64, F_LONG_TWO);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert_eq!(got.arg_count, ArgCount::Exact(2));
        assert_eq!(got.returns_value, ReturnKind::Value);
    }

    #[test]
    fn fp_only_is_unknown_abi_but_counts_args() {
        let got: AbiInference = run(64, F_FP_TWO);
        assert_eq!(got.abi, CallingConvention::Unknown);
        assert!(matches!(got.arg_count, ArgCount::AtLeast(n) if n >= 2));
        assert_eq!(got.returns_value, ReturnKind::Value);
    }

    #[test]
    fn branch_fn_recovers_two_args_across_blocks() {
        let got: AbiInference = run(64, F_BRANCH);
        assert_eq!(got.abi, CallingConvention::SysV64);
        assert_eq!(got.arg_count, ArgCount::Exact(2));
        assert_eq!(got.returns_value, ReturnKind::Value);
    }
}

mod ms64 {
    use super::*;

    const F_VOID_NORET: &[u8] = &[0xC3];
    const F_ONE: &[u8] = &[0x8D, 0x41, 0x01, 0xC3];
    const F_TWO: &[u8] = &[0x89, 0xC8, 0x29, 0xD0, 0xC3];
    const F_THREE: &[u8] = &[0x8D, 0x04, 0x11, 0x44, 0x01, 0xC0, 0xC3];
    const F_FOUR: &[u8] = &[0x01, 0xD1, 0x43, 0x8D, 0x04, 0x08, 0x01, 0xC8, 0xC3];
    const F_LONG_TWO: &[u8] = &[0x89, 0xC8, 0x0F, 0xAF, 0xC2, 0xC3];
    const F_BRANCH: &[u8] = &[0x89, 0xD0, 0x39, 0xD1, 0x0F, 0x4F, 0xC1, 0xC3];

    #[test]
    fn void_void_has_zero_args() {
        let got: AbiInference = run(64, F_VOID_NORET);
        assert_eq!(got.arg_count, ArgCount::Exact(0));
        assert_eq!(got.returns_value, ReturnKind::Void);
    }

    #[test]
    fn one_arg_is_ms_rcx() {
        let got: AbiInference = run(64, F_ONE);
        assert_eq!(got.abi, CallingConvention::Microsoft64);
        assert_eq!(got.arg_count, ArgCount::Exact(1));
        assert_eq!(got.param_regs, vec!["rcx".to_owned()]);
    }

    #[test]
    fn two_args_are_ms_rcx_rdx() {
        let got: AbiInference = run(64, F_TWO);
        assert_eq!(got.abi, CallingConvention::Microsoft64);
        assert_eq!(got.arg_count, ArgCount::Exact(2));
        assert_eq!(got.param_regs, vec!["rcx".to_owned(), "rdx".to_owned()]);
    }

    #[test]
    fn three_args_are_ms() {
        let got: AbiInference = run(64, F_THREE);
        assert_eq!(got.abi, CallingConvention::Microsoft64);
        assert_eq!(got.arg_count, ArgCount::Exact(3));
    }

    #[test]
    fn four_args_are_ms() {
        let got: AbiInference = run(64, F_FOUR);
        assert_eq!(got.abi, CallingConvention::Microsoft64);
        assert!(matches!(got.arg_count, ArgCount::Exact(n) if n >= 3));
    }

    #[test]
    fn long_two_args_are_ms() {
        let got: AbiInference = run(64, F_LONG_TWO);
        assert_eq!(got.abi, CallingConvention::Microsoft64);
        assert_eq!(got.arg_count, ArgCount::Exact(2));
    }

    #[test]
    fn branch_fn_recovers_two_ms_args() {
        let got: AbiInference = run(64, F_BRANCH);
        assert_eq!(got.abi, CallingConvention::Microsoft64);
        assert_eq!(got.arg_count, ArgCount::Exact(2));
        assert_eq!(got.returns_value, ReturnKind::Value);
    }
}

mod x86_32 {
    use super::*;

    const C_TWO: &[u8] = &[0x8B, 0x44, 0x24, 0x04, 0x2B, 0x44, 0x24, 0x08, 0xC3];
    const S_THREE: &[u8] = &[
        0x8B, 0x44, 0x24, 0x08, 0x03, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x0C, 0xC2, 0x0C, 0x00,
    ];
    const FC_TWO: &[u8] = &[0x8D, 0x42, 0xFF, 0x0F, 0xAF, 0xC1, 0xC3];
    const FC_THREE: &[u8] = &[0x8D, 0x04, 0x11, 0x03, 0x44, 0x24, 0x04, 0xC2, 0x04, 0x00];
    const S_VOID: &[u8] = &[0xC3];

    #[test]
    fn cdecl_bare_ret_two_stack_args() {
        let got: AbiInference = run(32, C_TWO);
        assert_eq!(got.abi, CallingConvention::Cdecl);
        assert_eq!(got.arg_count, ArgCount::Exact(2));
        assert_eq!(got.returns_value, ReturnKind::Value);
    }

    #[test]
    fn stdcall_ret_imm_three_stack_args() {
        let got: AbiInference = run(32, S_THREE);
        assert_eq!(got.abi, CallingConvention::Stdcall);
        assert_eq!(got.arg_count, ArgCount::Exact(3));
    }

    #[test]
    fn fastcall_two_register_args() {
        let got: AbiInference = run(32, FC_TWO);
        assert_eq!(got.abi, CallingConvention::Fastcall);
        assert!(matches!(got.arg_count, ArgCount::AtLeast(n) | ArgCount::Exact(n) if n >= 2));
        assert_eq!(got.param_regs, vec!["ecx".to_owned(), "edx".to_owned()]);
    }

    #[test]
    fn fastcall_two_register_plus_one_stack_arg() {
        let got: AbiInference = run(32, FC_THREE);
        assert_eq!(got.abi, CallingConvention::Fastcall);
        assert_eq!(got.arg_count, ArgCount::Exact(3));
    }

    #[test]
    fn zero_arg_callee_void_has_no_return_value() {
        let got: AbiInference = run(32, S_VOID);
        assert_eq!(got.arg_count, ArgCount::Exact(0));
        assert_eq!(got.returns_value, ReturnKind::Void);
    }
}

mod conservatism {
    use super::*;

    #[test]
    fn lone_rdx_read_is_unknown_not_a_confident_guess() {
        let lone_rdx: &[u8] = &[0x89, 0xD0, 0xC3];
        let got: AbiInference = run(64, lone_rdx);
        assert_eq!(
            got.abi,
            CallingConvention::Unknown,
            "rdx without rdi/rsi (sysv) or rcx (ms) before it is ambiguous"
        );
    }

    #[test]
    fn gap_in_sysv_sequence_is_unknown() {
        let rdi_then_rcx: &[u8] = &[0x89, 0xF8, 0x01, 0xC8, 0xC3];
        let got: AbiInference = run(64, rdi_then_rcx);
        assert_eq!(got.abi, CallingConvention::Unknown);
    }
}
