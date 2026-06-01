_default:
    @just --list

# build all crates
build:
    cargo build --workspace

# run all tests
test:
    cargo test --workspace

# run clippy (deny warnings)
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# format check
fmt-check:
    cargo fmt --all -- --check

# format in place
fmt:
    cargo fmt --all

# full pre-push check (what CI runs)
check: fmt-check lint test
    cargo deny check
    typos

# run benchmarks
bench:
    cargo bench --workspace

# generate test corpus samples (see corpus/generate.sh or corpus/generate.ps1)
corpus:
    bash corpus/generate.sh

# run fuzz targets for N seconds each
fuzz seconds='60':
    cargo +nightly fuzz run chain_driver -- -max_total_time={{seconds}}
    cargo +nightly fuzz run chain_spec_parser -- -max_total_time={{seconds}}

# check for outdated dependencies
outdated:
    cargo outdated --workspace

# audit for known vulnerabilities
audit:
    cargo audit
