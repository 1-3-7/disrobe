use std::collections::BTreeSet;

use disrobe_core::neutralize::{Anchor, NeutralizedCheck, RuntimeCheck};

use crate::stub_emu::{CpuMode, Memory, Reg, Regs};

pub const MAX_NEUTRALIZED_EVENTS: usize = 256;
pub const MAX_VEH_HANDLERS: usize = 16;

const TICK_START_MS: u64 = 0x0012_3456;
const TICK_STEP_MS: u64 = 16;
const PERF_COUNTER_START: u64 = 0x0000_0001_0000_0000;
const PERF_COUNTER_STEP: u64 = 1_000;
const PERF_FREQUENCY_HZ: u64 = 10_000_000;
const VEH_HANDLE_BASE: u64 = 0x7F00_0000;
const PSEUDO_CURRENT_PROCESS: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const PSEUDO_CURRENT_THREAD: u64 = 0xFFFF_FFFF_FFFF_FFFE;
const PSEUDO_PROCESS_ID: u64 = 0x1234;
const PSEUDO_THREAD_ID: u64 = 0x1238;
const STATUS_SUCCESS: u64 = 0;
const STATUS_PORT_NOT_SET: u64 = 0xC000_0353;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xC000_0004;
const PROCESS_DEBUG_PORT: u64 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: u64 = 0x1E;
const PROCESS_DEBUG_FLAGS: u64 = 0x1F;
const THREAD_HIDE_FROM_DEBUGGER: u64 = 0x11;
const MAX_INFO_FILL_BYTES: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiOutcome {
    Handled,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ApiSandbox {
    tick_ms: u64,
    perf_counter: u64,
    events: Vec<NeutralizedCheck>,
    events_seen: BTreeSet<(RuntimeCheck, u64)>,
    events_dropped: u64,
    veh_registrations: Vec<(bool, u64)>,
    veh_count: usize,
    api_calls: u64,
}

impl Default for ApiSandbox {
    fn default() -> Self {
        Self::new()
    }
}

struct CallFrame {
    mode: CpuMode,
    return_to: u64,
}

impl CallFrame {
    fn arg(&self, regs: &Regs, mem: &Memory, index: usize) -> u64 {
        match self.mode {
            CpuMode::Bits32 => {
                let sp: u64 = regs.get(Reg::Rsp);
                mem.read_u32(sp.wrapping_add(4 * index as u64))
                    .map_or(0, u64::from)
            }
            CpuMode::Bits64 => match index {
                0 => regs.get(Reg::Rcx),
                1 => regs.get(Reg::Rdx),
                2 => regs.get(Reg::R8),
                3 => regs.get(Reg::R9),
                _ => {
                    let sp: u64 = regs.get(Reg::Rsp);
                    mem.read_u64(sp.wrapping_add(8 * index as u64)).unwrap_or(0)
                }
            },
        }
    }

    fn finish(&self, regs: &mut Regs, args: usize, result: u64) {
        match self.mode {
            CpuMode::Bits32 => {
                regs.write_sized(Reg::Rax, result & 0xFFFF_FFFF, 32);
                regs.write_sized(Reg::Rdx, result >> 32, 32);
                let sp: u64 = regs.get(Reg::Rsp);
                regs.set(Reg::Rsp, sp.wrapping_add(4 * args as u64));
            }
            CpuMode::Bits64 => regs.set(Reg::Rax, result),
        }
    }

    fn write_ptr(&self, mem: &mut Memory, addr: u64, value: u64) {
        if addr == 0 {
            return;
        }
        let _ = match self.mode {
            CpuMode::Bits32 => mem.write_u32(addr, value as u32),
            CpuMode::Bits64 => mem.write_u64(addr, value),
        };
    }
}

impl ApiSandbox {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tick_ms: TICK_START_MS,
            perf_counter: PERF_COUNTER_START,
            events: Vec::new(),
            events_seen: BTreeSet::new(),
            events_dropped: 0,
            veh_registrations: Vec::new(),
            veh_count: 0,
            api_calls: 0,
        }
    }

    #[must_use]
    pub fn events(&self) -> &[NeutralizedCheck] {
        &self.events
    }

    #[must_use]
    pub const fn events_dropped(&self) -> u64 {
        self.events_dropped
    }

    #[must_use]
    pub const fn api_calls(&self) -> u64 {
        self.api_calls
    }

    pub fn take_veh_registrations(&mut self) -> Vec<(bool, u64)> {
        std::mem::take(&mut self.veh_registrations)
    }

    fn record(&mut self, check: RuntimeCheck, address: u64, instruction: &str, pattern: String) {
        if !self.events_seen.insert((check, address)) {
            return;
        }
        if self.events.len() >= MAX_NEUTRALIZED_EVENTS {
            self.events_dropped = self.events_dropped.saturating_add(1);
            return;
        }
        self.events.push(NeutralizedCheck {
            check,
            anchor: Anchor {
                address,
                instruction: instruction.to_owned(),
                pattern,
            },
            outcome: "served the not-debugged value inside the emulator sandbox".to_owned(),
        });
    }

    pub fn dispatch(
        &mut self,
        name: &str,
        mode: CpuMode,
        regs: &mut Regs,
        mem: &mut Memory,
    ) -> ApiOutcome {
        let frame: CallFrame = CallFrame {
            mode,
            return_to: regs.rip,
        };
        let site: u64 = frame.return_to;
        let call_text: String = format!("call {name}");
        match name {
            "IsDebuggerPresent" => {
                self.record(
                    RuntimeCheck::IsDebuggerPresent,
                    site,
                    &call_text,
                    "kernel32!IsDebuggerPresent returned FALSE".to_owned(),
                );
                frame.finish(regs, 0, 0);
            }
            "CheckRemoteDebuggerPresent" => {
                let out_ptr: u64 = frame.arg(regs, mem, 1);
                let _ = mem.write_u32(out_ptr, 0);
                self.record(
                    RuntimeCheck::CheckRemoteDebuggerPresent,
                    site,
                    &call_text,
                    "kernel32!CheckRemoteDebuggerPresent wrote FALSE and succeeded".to_owned(),
                );
                frame.finish(regs, 2, 1);
            }
            "NtQueryInformationProcess" | "ZwQueryInformationProcess" => {
                let class: u64 = frame.arg(regs, mem, 1);
                let buffer: u64 = frame.arg(regs, mem, 2);
                let length: u64 = frame.arg(regs, mem, 3);
                let return_length: u64 = frame.arg(regs, mem, 4);
                let status: u64 = self.query_information_process(
                    &frame, site, &call_text, class, buffer, length, mem,
                );
                frame.write_ptr(mem, return_length, length.min(MAX_INFO_FILL_BYTES));
                frame.finish(regs, 5, status);
            }
            "NtSetInformationThread" | "ZwSetInformationThread" => {
                let class: u64 = frame.arg(regs, mem, 1);
                if class == THREAD_HIDE_FROM_DEBUGGER {
                    self.record(
                        RuntimeCheck::NtSetInformationThreadHideFromDebugger,
                        site,
                        &call_text,
                        "ntdll!NtSetInformationThread(ThreadHideFromDebugger) accepted without effect"
                            .to_owned(),
                    );
                }
                frame.finish(regs, 4, STATUS_SUCCESS);
            }
            "OutputDebugStringA" | "OutputDebugStringW" => {
                self.record(
                    RuntimeCheck::OutputDebugString,
                    site,
                    &call_text,
                    format!("kernel32!{name} swallowed, last error left untouched"),
                );
                frame.finish(regs, 1, 0);
            }
            "GetTickCount" | "timeGetTime" => {
                let value: u64 = self.next_tick();
                self.record(
                    RuntimeCheck::TickCountDelta,
                    site,
                    &call_text,
                    format!("{name} served pinned tick {value:#x} (+{TICK_STEP_MS} ms per call)"),
                );
                frame.finish(regs, 0, value & 0xFFFF_FFFF);
            }
            "GetTickCount64" => {
                let value: u64 = self.next_tick();
                self.record(
                    RuntimeCheck::TickCountDelta,
                    site,
                    &call_text,
                    format!(
                        "GetTickCount64 served pinned tick {value:#x} (+{TICK_STEP_MS} ms per call)"
                    ),
                );
                frame.finish(regs, 0, value);
            }
            "QueryPerformanceCounter" => {
                let out_ptr: u64 = frame.arg(regs, mem, 0);
                let value: u64 = self.perf_counter;
                self.perf_counter = self.perf_counter.wrapping_add(PERF_COUNTER_STEP);
                let _ = mem.write_u64(out_ptr, value);
                self.record(
                    RuntimeCheck::PerformanceCounterDelta,
                    site,
                    &call_text,
                    format!(
                        "QueryPerformanceCounter served pinned counter {value:#x} (+{PERF_COUNTER_STEP} per call)"
                    ),
                );
                frame.finish(regs, 1, 1);
            }
            "QueryPerformanceFrequency" => {
                let out_ptr: u64 = frame.arg(regs, mem, 0);
                let _ = mem.write_u64(out_ptr, PERF_FREQUENCY_HZ);
                frame.finish(regs, 1, 1);
            }
            "AddVectoredExceptionHandler" | "RtlAddVectoredExceptionHandler" => {
                let first: bool = frame.arg(regs, mem, 0) != 0;
                let handler: u64 = frame.arg(regs, mem, 1);
                let handle: u64 = if self.veh_count < MAX_VEH_HANDLERS && handler != 0 {
                    self.veh_count += 1;
                    self.veh_registrations.push((first, handler));
                    self.record(
                        RuntimeCheck::VectoredExceptionHandler,
                        site,
                        &call_text,
                        format!("vectored handler {handler:#x} registered (first={first})"),
                    );
                    VEH_HANDLE_BASE + self.veh_count as u64
                } else {
                    0
                };
                frame.finish(regs, 2, handle);
            }
            "RemoveVectoredExceptionHandler" | "RtlRemoveVectoredExceptionHandler" => {
                frame.finish(regs, 1, 1);
            }
            "GetCurrentProcess" => frame.finish(regs, 0, PSEUDO_CURRENT_PROCESS),
            "GetCurrentThread" => frame.finish(regs, 0, PSEUDO_CURRENT_THREAD),
            "GetCurrentProcessId" => frame.finish(regs, 0, PSEUDO_PROCESS_ID),
            "GetCurrentThreadId" => frame.finish(regs, 0, PSEUDO_THREAD_ID),
            _ => return ApiOutcome::Unknown,
        }
        self.api_calls = self.api_calls.saturating_add(1);
        ApiOutcome::Handled
    }

    fn next_tick(&mut self) -> u64 {
        let value: u64 = self.tick_ms;
        self.tick_ms = self.tick_ms.wrapping_add(TICK_STEP_MS);
        value
    }

    #[allow(clippy::too_many_arguments)]
    fn query_information_process(
        &mut self,
        frame: &CallFrame,
        site: u64,
        call_text: &str,
        class: u64,
        buffer: u64,
        length: u64,
        mem: &mut Memory,
    ) -> u64 {
        let ptr_len: u64 = u64::from(frame.mode.ptr_size());
        match class {
            PROCESS_DEBUG_PORT => {
                if length < ptr_len {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                frame.write_ptr(mem, buffer, 0);
                self.record(
                    RuntimeCheck::NtQueryInformationProcessDebugPort,
                    site,
                    call_text,
                    "ProcessDebugPort answered 0 (no debug port)".to_owned(),
                );
                STATUS_SUCCESS
            }
            PROCESS_DEBUG_OBJECT_HANDLE => {
                if length < ptr_len {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                frame.write_ptr(mem, buffer, 0);
                self.record(
                    RuntimeCheck::NtQueryInformationProcessDebugObjectHandle,
                    site,
                    call_text,
                    "ProcessDebugObjectHandle answered NULL with STATUS_PORT_NOT_SET".to_owned(),
                );
                STATUS_PORT_NOT_SET
            }
            PROCESS_DEBUG_FLAGS => {
                if length < 4 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let _ = mem.write_u32(buffer, 1);
                self.record(
                    RuntimeCheck::NtQueryInformationProcessDebugFlags,
                    site,
                    call_text,
                    "ProcessDebugFlags answered 1 (NoDebugInherit, no debugger)".to_owned(),
                );
                STATUS_SUCCESS
            }
            _ => {
                let fill: u64 = length.min(MAX_INFO_FILL_BYTES);
                for i in 0..fill {
                    let _ = mem.write_u8(buffer.wrapping_add(i), 0);
                }
                STATUS_SUCCESS
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::stub_emu::Perm;

    fn stack32(args: &[u32]) -> (Regs, Memory) {
        let mut regs: Regs = Regs::new(CpuMode::Bits32);
        let mut mem: Memory = Memory::new();
        mem.map(0x1_0000, 0x2000, Perm::RW).unwrap();
        let sp: u64 = 0x1_1000;
        for (i, a) in args.iter().enumerate() {
            mem.write_u32(sp + 4 * i as u64, *a).unwrap();
        }
        regs.set(Reg::Rsp, sp);
        regs.rip = 0x40_1234;
        (regs, mem)
    }

    #[test]
    fn is_debugger_present_returns_false_and_records_the_call_site() {
        let mut api: ApiSandbox = ApiSandbox::new();
        let (mut regs, mut mem): (Regs, Memory) = stack32(&[]);
        regs.set(Reg::Rax, 0xFFFF_FFFF);
        assert_eq!(
            api.dispatch("IsDebuggerPresent", CpuMode::Bits32, &mut regs, &mut mem),
            ApiOutcome::Handled
        );
        assert_eq!(regs.get(Reg::Rax), 0);
        assert_eq!(api.events().len(), 1);
        assert_eq!(api.events()[0].check, RuntimeCheck::IsDebuggerPresent);
        assert_eq!(api.events()[0].anchor.address, 0x40_1234);
    }

    #[test]
    fn stdcall_cleanup_matches_the_argument_count() {
        let mut api: ApiSandbox = ApiSandbox::new();
        let (mut regs, mut mem): (Regs, Memory) = stack32(&[0xFFFF_FFFF, 0x1_1800]);
        mem.write_u32(0x1_1800, 1).unwrap();
        let sp_before: u64 = regs.get(Reg::Rsp);
        api.dispatch(
            "CheckRemoteDebuggerPresent",
            CpuMode::Bits32,
            &mut regs,
            &mut mem,
        );
        assert_eq!(regs.get(Reg::Rsp), sp_before + 8);
        assert_eq!(regs.get(Reg::Rax), 1, "the call succeeds");
        assert_eq!(
            mem.read_u32(0x1_1800).unwrap(),
            0,
            "the out flag reads FALSE"
        );
    }

    #[test]
    fn debug_port_queries_answer_not_debugged_per_class() {
        let mut api: ApiSandbox = ApiSandbox::new();
        for (class, expect_status, expect_value) in [
            (7u32, 0u64, 0u32),
            (0x1E, STATUS_PORT_NOT_SET, 0),
            (0x1F, 0, 1),
        ] {
            let (mut regs, mut mem): (Regs, Memory) =
                stack32(&[0xFFFF_FFFF, class, 0x1_1800, 4, 0x1_1900]);
            mem.write_u32(0x1_1800, 0xDEAD_BEEF).unwrap();
            api.dispatch(
                "NtQueryInformationProcess",
                CpuMode::Bits32,
                &mut regs,
                &mut mem,
            );
            assert_eq!(regs.get(Reg::Rax), expect_status, "class {class:#x}");
            assert_eq!(
                mem.read_u32(0x1_1800).unwrap(),
                expect_value,
                "class {class:#x}"
            );
            assert_eq!(mem.read_u32(0x1_1900).unwrap(), 4);
        }
        let checks: BTreeSet<RuntimeCheck> = api.events().iter().map(|e| e.check).collect();
        assert_eq!(
            checks,
            BTreeSet::from([
                RuntimeCheck::NtQueryInformationProcessDebugPort,
                RuntimeCheck::NtQueryInformationProcessDebugObjectHandle,
                RuntimeCheck::NtQueryInformationProcessDebugFlags,
            ])
        );
    }

    #[test]
    fn a_short_debug_port_buffer_is_a_length_mismatch_not_a_write() {
        let mut api: ApiSandbox = ApiSandbox::new();
        let (mut regs, mut mem): (Regs, Memory) = stack32(&[0xFFFF_FFFF, 7, 0x1_1800, 2, 0]);
        mem.write_u32(0x1_1800, 0xDEAD_BEEF).unwrap();
        api.dispatch(
            "NtQueryInformationProcess",
            CpuMode::Bits32,
            &mut regs,
            &mut mem,
        );
        assert_eq!(regs.get(Reg::Rax), STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(mem.read_u32(0x1_1800).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn timers_are_monotonic_and_pinned() {
        let mut api: ApiSandbox = ApiSandbox::new();
        let (mut regs, mut mem): (Regs, Memory) = stack32(&[]);
        api.dispatch("GetTickCount", CpuMode::Bits32, &mut regs, &mut mem);
        let first: u64 = regs.get(Reg::Rax);
        api.dispatch("GetTickCount", CpuMode::Bits32, &mut regs, &mut mem);
        let second: u64 = regs.get(Reg::Rax);
        assert_eq!(first, TICK_START_MS);
        assert_eq!(second, TICK_START_MS + TICK_STEP_MS);

        let (mut regs, mut mem): (Regs, Memory) = stack32(&[0x1_1800]);
        api.dispatch(
            "QueryPerformanceCounter",
            CpuMode::Bits32,
            &mut regs,
            &mut mem,
        );
        assert_eq!(mem.read_u64(0x1_1800).unwrap(), PERF_COUNTER_START);
        assert_eq!(regs.get(Reg::Rax), 1);
        let (mut regs, mut mem): (Regs, Memory) = stack32(&[0x1_1800]);
        api.dispatch(
            "QueryPerformanceFrequency",
            CpuMode::Bits32,
            &mut regs,
            &mut mem,
        );
        assert_eq!(mem.read_u64(0x1_1800).unwrap(), PERF_FREQUENCY_HZ);
    }

    #[test]
    fn win64_arguments_come_from_registers_and_nothing_is_popped() {
        let mut api: ApiSandbox = ApiSandbox::new();
        let mut regs: Regs = Regs::new(CpuMode::Bits64);
        let mut mem: Memory = Memory::new();
        mem.map(0x1_0000, 0x2000, Perm::RW).unwrap();
        regs.set(Reg::Rsp, 0x1_1000);
        regs.set(Reg::Rcx, 0xFFFF_FFFF_FFFF_FFFF);
        regs.set(Reg::Rdx, 0x1_1800);
        mem.write_u32(0x1_1800, 7).unwrap();
        api.dispatch(
            "CheckRemoteDebuggerPresent",
            CpuMode::Bits64,
            &mut regs,
            &mut mem,
        );
        assert_eq!(regs.get(Reg::Rsp), 0x1_1000);
        assert_eq!(mem.read_u32(0x1_1800).unwrap(), 0);
        assert_eq!(regs.get(Reg::Rax), 1);
    }

    #[test]
    fn vectored_registration_is_capped_and_handed_to_the_cpu() {
        let mut api: ApiSandbox = ApiSandbox::new();
        for i in 0..(MAX_VEH_HANDLERS + 4) {
            let (mut regs, mut mem): (Regs, Memory) = stack32(&[1, 0x50_0000 + i as u32]);
            regs.rip = 0x40_1000 + i as u64 * 8;
            api.dispatch(
                "AddVectoredExceptionHandler",
                CpuMode::Bits32,
                &mut regs,
                &mut mem,
            );
            let handle: u64 = regs.get(Reg::Rax);
            if i < MAX_VEH_HANDLERS {
                assert_ne!(handle, 0, "registration {i} within the cap succeeds");
            } else {
                assert_eq!(handle, 0, "registration {i} past the cap is refused");
            }
        }
        let pending: Vec<(bool, u64)> = api.take_veh_registrations();
        assert_eq!(pending.len(), MAX_VEH_HANDLERS);
        assert!(api.take_veh_registrations().is_empty());
    }

    #[test]
    fn events_are_deduplicated_per_site_and_capped() {
        let mut api: ApiSandbox = ApiSandbox::new();
        for _ in 0..3 {
            let (mut regs, mut mem): (Regs, Memory) = stack32(&[]);
            api.dispatch("IsDebuggerPresent", CpuMode::Bits32, &mut regs, &mut mem);
        }
        assert_eq!(api.events().len(), 1, "same site records once");
        for i in 0..(MAX_NEUTRALIZED_EVENTS + 10) {
            let (mut regs, mut mem): (Regs, Memory) = stack32(&[]);
            regs.rip = 0x50_0000 + i as u64;
            api.dispatch("IsDebuggerPresent", CpuMode::Bits32, &mut regs, &mut mem);
        }
        assert_eq!(api.events().len(), MAX_NEUTRALIZED_EVENTS);
        assert_eq!(api.events_dropped(), 11);
    }

    #[test]
    fn unknown_names_are_left_to_the_enclosing_host() {
        let mut api: ApiSandbox = ApiSandbox::new();
        let (mut regs, mut mem): (Regs, Memory) = stack32(&[]);
        assert_eq!(
            api.dispatch("VirtualAlloc", CpuMode::Bits32, &mut regs, &mut mem),
            ApiOutcome::Unknown
        );
        assert!(api.events().is_empty());
    }
}
