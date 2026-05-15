# minidump2core

[![CI](https://img.shields.io/github/actions/workflow/status/spavlenko/minidump2core/ci.yml?branch=main&label=CI)](https://github.com/spavlenko/minidump2core/actions)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

A safe Rust port of Breakpad's [`minidump-2-core`](https://chromium.googlesource.com/breakpad/breakpad/+/refs/heads/main/src/tools/linux/minidump2core/minidump-2-core.cc) tool.

Reads a Linux or Android Breakpad minidump (`.dmp`) file and converts it into an ELF core file that GDB, LLDB, and other debuggers can open directly.

## Features

- Produces ELF core files compatible with the original C++ tool
- Supports x86, x86-64, ARM, AArch64, MIPS, and MIPS64 targets
- Reconstructs `NT_PRSTATUS`, `NT_PRPSINFO`, `NT_SIGINFO`, `NT_FPREGSET`, and `NT_FILE` notes
- Augments memory mappings from an embedded `/proc/<pid>/maps` stream when present
- Patches `DT_DEBUG` in `.dynamic` so GDB can walk the shared-library link map
- `#![forbid(unsafe_code)]` — zero unsafe blocks

## Installation

```sh
git clone https://github.com/spavlenko/minidump2core
cd minidump2core
cargo build --release
```

The binary is written to `target/release/minidump-2-core`. You can also install
it into `~/.cargo/bin` with:

```sh
cargo install --path .
```

## Usage

```
minidump-2-core [OPTIONS] <MINIDUMP>
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output <FILE>` | Write core file to `FILE` instead of stdout |
| `--sobasedir <DIR>` | Replace module directory prefixes with `DIR` |
| `--mangle-sonames 1` | Prefix each SO name with its build-id GUID |
| `-v, --verbose` | Print stream traversal and augmentation diagnostics to stderr |

### Examples

```sh
# Write core to file
minidump-2-core -o crash.core crash.dmp

# Pipe directly into gdb
minidump-2-core crash.dmp | gdb ./my_binary /dev/stdin

# With a sobasedir for relocated libraries
minidump-2-core --sobasedir /symbols/libs -o crash.core crash.dmp
```

## Library

The conversion pipeline is also available as a library crate:

```rust
use minidump2core::rust_minidump::{read_process_from_path, ConvertOptions};
use minidump2core::augment::augment_process;
use minidump2core::core_writer::write_core;

let options = ConvertOptions { mangle_sonames: false, so_base_dir: None, verbose: false };
let mut process = read_process_from_path("crash.dmp", &options)?;
augment_process(&mut process, false)?;
write_core(&process, &mut output)?;
```

### Module overview

| Module | Responsibility |
|--------|---------------|
| `rust_minidump` | Parses a minidump via `rust-minidump` into `CrashedProcess` |
| `augment` | Applies `/proc/<pid>/maps` data to refine memory mappings |
| `core_writer` | Serializes `CrashedProcess` to an ELF core byte stream |
| `elf` | ELF header and program header serialization |
| `notes` | ELF note (`PT_NOTE`) construction and serialization |
| `model` | Core data types: `Architecture`, `MemoryMapping`, `MappingPermissions`, `PrStatus`, `PrPsInfo` |
| `regs` | CPU context → Linux `user_regs_struct` / `user_fpregs_struct` conversion |
| `linux_maps` | `/proc/<pid>/maps` text format parser |
| `error` | `minidump2coreError` enum |

## Supported architectures

| Architecture | ELF class | `e_machine` |
|---|---|---|
| x86 | ELF32 | `EM_386` (3) |
| x86-64 | ELF64 | `EM_X86_64` (62) |
| ARM | ELF32 | `EM_ARM` (40) |
| AArch64 | ELF64 | `EM_AARCH64` (183) |
| MIPS | ELF32 | `EM_MIPS` (8) |
| MIPS64 | ELF64 | `EM_MIPS` (8) |

## Testing

```sh
cargo test
```

Tests are organized as integration tests under `tests/`:

| File | Coverage |
|------|----------|
| `model_tests.rs` | `build_prpsinfo` byte layout per architecture |
| `notes_tests.rs` | Note name/descriptor 4-byte alignment padding |
| `elf_tests.rs` | ELF header fields, program header field offsets (ELF32 vs ELF64) |
| `regs_tests.rs` | Register serialization order for x86 and x86-64 |
| `linux_maps_tests.rs` | `/proc/<pid>/maps` parsing, `looks_like_linux_maps` detection |
| `augment_tests.rs` | Memory mapping augmentation and splitting |
| `rust_minidump_tests.rs` | CPU/OS detection, unsupported-system errors |

## Differences from the C++ tool

- Written in safe Rust with no `unsafe` blocks
- Uses [`rust-minidump`](https://github.com/rust-minidump/rust-minidump) for minidump parsing instead of Breakpad's own reader
- Error handling uses typed errors (`minidump2coreError`) rather than `fprintf`/`exit`
- The `-v` verbose flag prints per-stream diagnostics to stderr (stream names, sizes, thread/module counts)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, coding guidelines, and how to submit a pull request.

## License

The reference C++ implementation is part of [Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/) and is licensed under the BSD 3-Clause License. This Rust port carries the same license — see [LICENSE](LICENSE).
