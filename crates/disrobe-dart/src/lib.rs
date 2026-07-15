#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod error;
pub mod graph;
mod header;
pub mod inventory;
mod layout;
mod limits;
mod locator;
mod recovery;
pub mod stream;

pub use error::{Error, Result};
pub use graph::{ClusterSummary, SnapshotSummary};
pub use header::{
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
    DART_3_12_2_SNAPSHOT_COMPATIBILITY_HASH, DART_SNAPSHOT_MAGIC, SnapshotHeader, SnapshotKind,
    SupportStatus, parse_snapshot_header, support_status,
};
pub use inventory::{
    ClassInventory, DartInventory, FieldInventory, InventoryCounts, LibraryInventory,
    MethodInventory,
};
pub use layout::{
    ClassDeclarationLayout, ClusterLayout, ClusterLayoutEntry,
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT, DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
    DeclarationLayouts, FieldDeclarationLayout, FunctionDeclarationLayout, LAYOUT_DESCRIPTORS,
    LayoutDescriptor, LibraryDeclarationLayout, PatchClassDeclarationLayout,
    has_layout_compatibility_hash, layout_descriptor,
};
pub use limits::RecoveryLimits;
pub use locator::{DartBlobKind, SnapshotBlob, locate_snapshot_blobs};
pub use recovery::{
    BlobSizes, NameMode, ObfuscationHint, RecoveryOptions, RecoveryReport, RecoveryStatus,
    recover_elf, recover_standalone,
};
