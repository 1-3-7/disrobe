mod defrag;
mod sandbox_unwrap;
mod stub_detect;

pub use defrag::{DefragStats, HeapRegion, defragment, recover_heap_regions};
pub use sandbox_unwrap::{
    ProbeSource, UnresolvedReason, UnresolvedStub, UnwrapReport, UnwrappedSegment,
    unwrap_decryption,
};
pub use stub_detect::{StubInfo, detect_decrypt_stubs};
