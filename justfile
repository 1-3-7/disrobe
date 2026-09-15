_default:
    @just --list

build:
    cargo build --workspace

test:
    cargo test --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings

fmt-check:
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

check: fmt-check lint test
    cargo deny check
    typos

bench:
    cargo bench --workspace

corpus:
    bash corpus/generate.sh

fuzz seconds='60':
    cargo +nightly fuzz run chain_driver -- -max_total_time={{seconds}}
    cargo +nightly fuzz run chain_spec_parser -- -max_total_time={{seconds}}

outdated:
    cargo outdated --workspace

audit:
    cargo audit
