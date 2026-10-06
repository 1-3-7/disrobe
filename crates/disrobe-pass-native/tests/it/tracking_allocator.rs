#![expect(
    unsafe_code,
    reason = "the consolidated test binary needs one counting global allocator"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! {
    static ATTEMPTED_ALLOCATION_PEAK: Cell<usize> = const { Cell::new(0) };
    static SUCCESSFUL_ALLOCATION_PEAK: Cell<Option<usize>> = const { Cell::new(None) };
    static PROCESS_ALLOCATION_TRACKING: Cell<bool> = const { Cell::new(false) };
}

static PROCESS_ALLOCATION_PEAK: AtomicUsize = AtomicUsize::new(0);

pub fn reset_attempted_allocation_peak() {
    let _ = ATTEMPTED_ALLOCATION_PEAK.try_with(|peak: &Cell<usize>| peak.set(0));
}

pub fn attempted_allocation_peak() -> usize {
    ATTEMPTED_ALLOCATION_PEAK
        .try_with(Cell::get)
        .unwrap_or_default()
}

pub fn start_successful_allocation_tracking() {
    let _ = SUCCESSFUL_ALLOCATION_PEAK.try_with(|peak: &Cell<Option<usize>>| peak.set(Some(0)));
}

pub fn finish_successful_allocation_tracking() -> usize {
    SUCCESSFUL_ALLOCATION_PEAK
        .try_with(Cell::take)
        .ok()
        .flatten()
        .unwrap_or_default()
}

pub fn reset_process_allocation_peak() {
    PROCESS_ALLOCATION_PEAK.store(0, Ordering::Relaxed);
}

pub fn start_process_allocation_tracking() {
    let _ = PROCESS_ALLOCATION_TRACKING.try_with(|tracking: &Cell<bool>| tracking.set(true));
}

pub fn process_allocation_peak() -> usize {
    PROCESS_ALLOCATION_PEAK.load(Ordering::Relaxed)
}

fn record_attempt(size: usize) {
    let _ = ATTEMPTED_ALLOCATION_PEAK.try_with(|peak: &Cell<usize>| {
        if size > peak.get() {
            peak.set(size);
        }
    });
    if PROCESS_ALLOCATION_TRACKING
        .try_with(Cell::get)
        .unwrap_or(false)
    {
        PROCESS_ALLOCATION_PEAK.fetch_max(size, Ordering::Relaxed);
    }
}

fn record_success(size: usize) {
    let _ = SUCCESSFUL_ALLOCATION_PEAK.try_with(|peak: &Cell<Option<usize>>| {
        if let Some(largest) = peak.get() {
            peak.set(Some(largest.max(size)));
        }
    });
}

struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_attempt(layout.size());
        let pointer: *mut u8 = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_success(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_attempt(layout.size());
        let pointer: *mut u8 = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_success(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_attempt(new_size);
        let replacement: *mut u8 = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            record_success(new_size);
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
