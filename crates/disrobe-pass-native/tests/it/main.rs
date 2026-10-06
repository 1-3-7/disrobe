#[path = "../aarch64_grade/battery.rs"]
#[allow(clippy::expect_used)]
mod battery;

#[path = "../common/mod.rs"]
mod common;

#[path = "../support/compiler_toolchain.rs"]
#[allow(clippy::panic, clippy::redundant_pub_crate)]
mod compiler_toolchain;

#[path = "../support/hostile_inputs.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod hostile_inputs;

#[path = "../support/native_entry_points.rs"]
#[allow(clippy::redundant_pub_crate)]
mod native_entry_points;

#[path = "../support/object_symbol.rs"]
#[allow(clippy::redundant_pub_crate)]
mod object_symbol;

#[path = "../support/oracle_demand.rs"]
mod oracle_demand;

#[path = "../support/packer_fixture.rs"]
#[allow(clippy::panic, clippy::redundant_pub_crate, dead_code)]
mod packer_fixture;

#[path = "../support/prerequisite.rs"]
#[allow(clippy::panic, clippy::redundant_pub_crate, dead_code)]
mod prerequisite;

#[path = "../support/vm_layout_generator.rs"]
mod vm_layout_generator;

pub mod tracking_allocator;

#[path = "../formats/main.rs"]
mod formats;

#[path = "../hostile/main.rs"]
mod hostile;

#[path = "../lifting/main.rs"]
mod lifting;

#[path = "../oracles/main.rs"]
mod oracles;

#[path = "../packers/main.rs"]
mod packers;

#[path = "../stub_pack_oracle_roundtrip.rs"]
mod stub_pack_oracle_roundtrip;
