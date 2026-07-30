use super::DelphiEra;
use super::image::PeView;

#[derive(Debug, Clone, Copy)]
pub(super) struct VmtLayout {
    pub era: DelphiEra,
    pub ptr_size: u64,
    pub self_ptr_abs: u64,
    pub intf_table: i64,
    pub type_info: i64,
    pub field_table: i64,
    pub method_table: i64,
    pub dynamic_table: i64,
    pub class_name: i64,
    pub instance_size: i64,
    pub parent: i64,
}

pub(super) const LAYOUT_LEGACY32: VmtLayout = VmtLayout {
    era: DelphiEra::Legacy32,
    ptr_size: 4,
    self_ptr_abs: 76,
    intf_table: -72,
    type_info: -60,
    field_table: -56,
    method_table: -52,
    dynamic_table: -48,
    class_name: -44,
    instance_size: -40,
    parent: -36,
};

pub(super) const LAYOUT_MODERN32: VmtLayout = VmtLayout {
    era: DelphiEra::Modern32,
    ptr_size: 4,
    self_ptr_abs: 88,
    intf_table: -84,
    type_info: -72,
    field_table: -68,
    method_table: -64,
    dynamic_table: -60,
    class_name: -56,
    instance_size: -52,
    parent: -48,
};

pub(super) const LAYOUT_MODERN64: VmtLayout = VmtLayout {
    era: DelphiEra::Modern64,
    ptr_size: 8,
    self_ptr_abs: 176,
    intf_table: -168,
    type_info: -144,
    field_table: -136,
    method_table: -128,
    dynamic_table: -120,
    class_name: -112,
    instance_size: -104,
    parent: -96,
};

pub(super) fn variants_for(view: &PeView<'_>) -> &'static [VmtLayout] {
    if view.is_64() {
        &[LAYOUT_MODERN64]
    } else {
        &[LAYOUT_LEGACY32, LAYOUT_MODERN32]
    }
}

pub(super) fn add_signed(base: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub(delta.unsigned_abs())
    }
}
