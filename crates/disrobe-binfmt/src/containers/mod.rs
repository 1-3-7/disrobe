pub mod appimage;
pub mod cpio;
pub mod cramfs;
pub mod docker;
pub mod ext4;
pub mod flatpak;
pub mod innosetup;
pub mod installshield;
pub mod msi;
pub mod msix;
pub mod nsis;
pub mod oci;
pub mod ostree;
pub mod partition;
pub mod snap;
pub mod squashfs;
pub mod vhd;
pub mod vhdx;
pub mod wim;

pub use appimage::{AppImageLayout, parse_appimage};
pub use cpio::{CpioArchive, CpioEntry, CpioVariant, detect_cpio_variant, parse_cpio};
pub use cramfs::detect_cramfs;
pub use docker::{DockerManifest, parse_docker_manifest};
pub use ext4::detect_ext4;
pub use flatpak::flatpak_external_hint;
pub use innosetup::innosetup_external_hint;
pub use installshield::installshield_external_hint;
pub use msi::{MsiSummary, parse_msi_minimal};
pub use msix::{MsixManifest, parse_appx_manifest};
pub use nsis::{NsisHeader, detect_nsis};
pub use oci::{OciManifest, parse_oci_index, parse_oci_manifest};
pub use ostree::ostree_external_hint;
pub use partition::{
    GptHeader, GptPartition, GptTable, MbrPartition, MbrTable, parse_gpt, parse_gpt_header,
    parse_mbr,
};
pub use snap::detect_snap;
pub use squashfs::{SquashfsSuperblock, parse_squashfs_superblock};
pub use vhd::{
    VhdDiskType, VhdDynamicHeader, VhdFooter, VhdGeometry, VhdImage, parse_vhd, parse_vhd_footer,
};
pub use vhdx::{VhdxHeader, VhdxImage, VhdxMetadata, VhdxRegion, parse_vhdx};
pub use wim::{WimArchive, WimCompression, WimHeader, WimImageEntry, WimResource, parse_wim};
