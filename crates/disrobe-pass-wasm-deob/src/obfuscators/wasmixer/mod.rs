mod defrag;
mod sandbox_unwrap;
mod stub_detect;

pub use defrag::{DefragStats, HeapRegion, defragment, recover_heap_regions};
pub use sandbox_unwrap::{
    MAX_DECRYPT_OUTPUT, MAX_DECRYPT_SPAN, MAX_STUBS_PER_MODULE, ProbeSource, UnresolvedReason,
    UnresolvedStub, UnwrapReport, UnwrappedSegment, unwrap_decryption,
};
pub use stub_detect::{StubInfo, detect_decrypt_stubs};
