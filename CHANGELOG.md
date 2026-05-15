# Changelog

All notable changes to this project will be documented in this file.

### Added

- Initial safe Rust port of Breakpad's `minidump-2-core` tool
- Supported target architectures: x86, x86-64, ARM, AArch64, MIPS, MIPS64
- `-o / --output <FILE>` flag to write the core file to a path instead of stdout
- `--sobasedir <DIR>` flag to replace module directory prefixes for relocated libraries
- `--mangle-sonames 1` flag to prefix each SO name with its build-id GUID
- `-v / --verbose` flag that prints per-stream diagnostics (stream names, sizes, thread and module counts) to stderr
- `#![forbid(unsafe_code)]` — zero unsafe blocks throughout the codebase
- Typed error handling via `thiserror` (`Md2CoreError` enum)
- CLI via `clap` 4 with `--derive`
- Reconstruction of `NT_PRSTATUS`, `NT_PRPSINFO`, `NT_SIGINFO`, `NT_FPREGSET`, and `NT_FILE` ELF notes
- `/proc/<pid>/maps` stream augmentation to refine memory mappings
- `DT_DEBUG` patching in `.dynamic` so GDB can walk the shared-library link map
- Integration test suite covering model layout, note alignment, ELF headers, register serialization, maps parsing, augmentation, and minidump parsing

### Fixed

- Synthesized `NT_AUXV` for PIE dumps so GDB computes the correct executable displacement
- Reconstructed `link_map` entries now carry the correct `l_ld` so GDB resolves shared-library symbols at the right addresses
- DSO debug synthesis no longer hard-requires the main executable to be present on disk

