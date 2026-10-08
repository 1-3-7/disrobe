#![allow(clippy::duplicate_mod)]

#[path = "../adversarial_resilience.rs"]
mod adversarial_resilience;

#[path = "../declared_size_bounds.rs"]
mod declared_size_bounds;

#[path = "../fuzz_archives.rs"]
mod fuzz_archives;

#[path = "../fuzz_decoders.rs"]
mod fuzz_decoders;

#[path = "../fuzz_filesystems.rs"]
mod fuzz_filesystems;

#[path = "../fuzz_resilience.rs"]
mod fuzz_resilience;
