# Contributing to md2core

Thank you for your interest in contributing!

## Prerequisites

- **Rust stable** (1.75 or later) — install via [rustup](https://rustup.rs/)

## Building

```sh
cargo build
cargo build --release   # optimized binary → target/release/minidump-2-core
```

## Running tests

```sh
cargo test --all
```

## Code style

Format and lint before submitting:

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
```

The project enforces `#![forbid(unsafe_code)]`. No unsafe code will be accepted.

## Adding a test

Integration tests live in `tests/`. Add a new file (e.g., `tests/my_feature_tests.rs`)
or extend an existing one. Unit tests belong in the relevant `src/` module using the
standard `#[cfg(test)]` inline module.

For tests that require a real minidump file, add a minimal `.dmp` fixture to
`test_files/` and load it with `include_bytes!` or a file path.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes — keep commits focused and atomic.
3. Ensure `cargo test --all`, `cargo fmt --check`, and `cargo clippy` all pass.
4. Open a PR using the provided template.
5. A maintainer will review within a few business days.

If you are fixing a bug, please include a regression test. If you are adding a
feature, update `CHANGELOG.md` under `[Unreleased]`.
