//! Safe Rust port of Breakpad's `minidump-2-core` tool.
//!
//! The crate exposes a small library so the conversion pipeline can be reused
//! by tests and downstream callers. The companion binary in `src/main.rs`
//! drives a CLI compatible with the original C++ tool.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod augment;
pub mod core_writer;
pub mod elf;
pub mod error;
pub mod linux_maps;
pub mod model;
pub mod notes;
pub mod regs;
pub mod rust_minidump;

pub use error::Md2CoreError;
