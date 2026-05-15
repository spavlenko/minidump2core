//! Adapter layer between [`rust-minidump`](minidump) and md2core's
//! `CrashedProcess` model.
//!
//! Stream parsing is delegated to `rust-minidump` wherever it offers a typed
//! representation; only Linux-specific notes that the upstream crate does not
//! expose (auxv, cmdline, dso debug) are decoded by hand.

use std::ops::Deref;
use std::path::Path;

use minidump::system_info::{Cpu, Os};
use minidump::{
    Minidump, MinidumpException, MinidumpLinuxMaps, MinidumpModule, MinidumpModuleList,
    MinidumpSystemInfo, MinidumpThreadList,
};
use minidump_common::format::{
    DSO_DEBUG_32, DSO_DEBUG_64, LINK_MAP_32, LINK_MAP_64, MINIDUMP_STREAM_TYPE,
};
use procfs_core::process::MMapPath;
use scroll::{LE, Pread};

use crate::error::Md2CoreError;
use crate::linux_maps::{looks_like_linux_maps, parse_linux_maps};
use crate::model::{
    Architecture, CrashedProcess, DsoDebug, LinkMapEntry, Mapping, MappingPermissions,
    ThreadSnapshot,
};

/// Caller-provided knobs that mirror the C++ tool's command-line flags.
#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    /// Substitute module file names with `<basedir>` + basename, or
    /// `/var/lib/breakpad/<guid>-<basename><basename>` if `basedir` is `None`.
    pub mangle_sonames: bool,
    /// Custom base directory for mangled SO names.
    pub so_base_dir: Option<String>,
    /// Print stream traversal diagnostics to stderr.
    pub verbose: bool,
}

/// Reads a minidump from disk and converts the supported streams.
///
/// # Errors
///
/// Returns an error if the file cannot be read or if the minidump format is invalid or unsupported.
pub fn read_process_from_path(
    path: impl AsRef<Path>,
    options: &ConvertOptions,
) -> Result<CrashedProcess, Md2CoreError> {
    // Read the file once so we can give both `rust-minidump` and our DSO
    // walker the same backing slice. Using a plain `Vec<u8>` instead of mmap
    // keeps the path portable to platforms where mmap is awkward (Windows
    // tests, sandboxed Android runners) and avoids a second open of the file.
    let bytes = std::fs::read(path)?;
    let dump = Minidump::read(bytes.as_slice())?;
    read_process_from_minidump(&dump, &bytes, options)
}

/// Converts a parsed [`Minidump`] into the `CrashedProcess` low-level model.
///
/// `full_file` must be the same byte slice the [`Minidump`] was parsed from;
/// it is required to walk the link-map array referenced by an
/// `MD_LINUX_DSO_DEBUG` stream because that data lives outside the stream's
/// own descriptor.
///
/// # Errors
///
/// Returns an error if any required stream is missing, malformed, or uses an
/// unsupported OS/CPU combination.
pub fn read_process_from_minidump<'a, T>(
    dump: &'a Minidump<'a, T>,
    full_file: &[u8],
    options: &ConvertOptions,
) -> Result<CrashedProcess, Md2CoreError>
where
    T: Deref<Target = [u8]> + 'a,
{
    let v = options.verbose;

    let system_info = dump.get_stream::<MinidumpSystemInfo>()?;
    let architecture = architecture_from_system_info(&system_info)?;
    if v {
        eprintln!(
            "md2core: system info: os={}, cpu={}",
            system_info.os, system_info.cpu
        );
    }
    let mut process = CrashedProcess::new(architecture);

    ingest_linux_streams(dump, &mut process, v)?;

    ingest_threads(dump, &mut process, &system_info, v);

    // Modules — supplement mappings, build signature substitutions.
    match dump.get_stream::<MinidumpModuleList>() {
        Ok(modules) => {
            if v {
                eprintln!("md2core: module list: {} modules", modules.iter().count());
                for m in modules.iter() {
                    eprintln!("md2core:   {:#018x}  {}", m.raw.base_of_image, m.name);
                }
            }
            ingest_modules(&mut process, &modules, options);
        }
        Err(_) => {
            if v {
                eprintln!("md2core: module list: not present");
            }
        }
    }

    ingest_exception(dump, &mut process, &system_info, v);

    // Set PID from the crashing thread (or first thread if no exception).
    // On Linux the main thread's TID == the process's PID.
    let pid = process
        .crashing_tid
        .or_else(|| process.threads().first().map(|t| t.tid))
        .unwrap_or(0);
    process.set_pid(pid);

    // DSO debug — link_map reconstruction.
    if let Some(bytes) = optional_raw_stream(dump, MINIDUMP_STREAM_TYPE::LinuxDsoDebug)? {
        if v {
            eprintln!("md2core: MD_LINUX_DSO_DEBUG: {} bytes", bytes.len());
        }
        process.dso_debug = parse_dso_debug(architecture, bytes, full_file)?;
        if v {
            eprintln!(
                "md2core: DSO debug: {} link_map entries",
                process.dso_debug.link_map.len(),
            );
        }
    } else {
        if v {
            eprintln!("md2core: MD_LINUX_DSO_DEBUG: not present");
        }
        // Fall back: synthesize r_debug from the on-disk executable so GDB can
        // auto-load shared libraries without needing add-symbol-file.
        if let Ok(modules) = dump.get_stream::<MinidumpModuleList>() {
            if let Some(dso) = synthesize_dso_debug(architecture, &modules, &process.signatures, v)
            {
                process.dso_debug = dso;
            }

            // Synthesize NT_AUXV (AT_PHDR + AT_ENTRY) so GDB can compute the
            // PIE exec_displacement and apply the correct symbol base address.
            // Without this, GDB shows symbols at their ELF-file vaddrs (no
            // relocation applied) and the SVR4 r_debug solib discovery fails.
            if process.auxv().is_empty()
                && let Some(auxv) = build_synthetic_auxv(architecture, &modules)
            {
                if v {
                    eprintln!("md2core: synthesized NT_AUXV ({} bytes)", auxv.len());
                }
                process.set_auxv(auxv);
            }
        }
    }

    Ok(process)
}

fn ingest_linux_streams<'a, T>(
    dump: &'a Minidump<'a, T>,
    process: &mut CrashedProcess,
    v: bool,
) -> Result<(), Md2CoreError>
where
    T: Deref<Target = [u8]> + 'a,
{
    // Memory mappings from MD_LINUX_MAPS (preferred).
    match dump.get_stream::<MinidumpLinuxMaps<'_>>() {
        Ok(maps) => {
            let mappings = mappings_from_minidump_linux_maps(&maps)?;
            if v {
                eprintln!(
                    "md2core: MD_LINUX_MAPS: {} file-backed mappings",
                    mappings.len()
                );
            }
            for mapping in mappings {
                process.insert_mapping(mapping);
            }
        }
        Err(_) => {
            if v {
                eprintln!("md2core: MD_LINUX_MAPS: not present");
            }
        }
    }

    // MD_LINUX_AUXV — sometimes contains maps text instead.
    if let Some(auxv) = optional_raw_stream(dump, MINIDUMP_STREAM_TYPE::LinuxAuxv)? {
        if looks_like_linux_maps(auxv) {
            if v {
                eprintln!("md2core: MD_LINUX_AUXV: contains maps text, parsing as mappings");
            }
            for mapping in parse_linux_maps(auxv)? {
                process.insert_mapping(mapping);
            }
        } else {
            if v {
                eprintln!("md2core: MD_LINUX_AUXV: {} bytes", auxv.len());
            }
            process.set_auxv(auxv.to_vec());
        }
    } else if v {
        eprintln!("md2core: MD_LINUX_AUXV: not present");
    }

    // MD_LINUX_CMD_LINE — drives prpsinfo's pr_fname/pr_psargs.
    if let Some(cmdline) = optional_raw_stream(dump, MINIDUMP_STREAM_TYPE::LinuxCmdLine)? {
        if v {
            let display = String::from_utf8_lossy(cmdline);
            eprintln!("md2core: MD_LINUX_CMD_LINE: {}", display.trim_matches('\0'));
        }
        process.apply_cmdline(cmdline);
    } else if v {
        eprintln!("md2core: MD_LINUX_CMD_LINE: not present");
    }

    Ok(())
}

fn ingest_threads<'a, T>(
    dump: &'a Minidump<'a, T>,
    process: &mut CrashedProcess,
    system_info: &MinidumpSystemInfo,
    v: bool,
) where
    T: Deref<Target = [u8]> + 'a,
{
    match dump.get_stream::<MinidumpThreadList<'_>>() {
        Ok(threads) => {
            if v {
                eprintln!("md2core: thread list: {} threads", threads.threads.len());
            }
            let memory = dump.get_memory().unwrap_or_default();
            for thread in &threads.threads {
                let stack = thread
                    .stack_memory(&memory)
                    .map(|s| s.bytes().to_vec())
                    .unwrap_or_default();
                if v {
                    eprintln!(
                        "md2core:   thread {:#010x}: stack {:#x}..{:#x} ({} bytes)",
                        thread.raw.thread_id,
                        thread.raw.stack.start_of_memory_range,
                        thread.raw.stack.start_of_memory_range + stack.len() as u64,
                        stack.len(),
                    );
                }
                let context = thread
                    .context(system_info, None)
                    .map(|cow| cow.into_owned().raw);
                process.add_thread(ThreadSnapshot {
                    tid: thread.raw.thread_id,
                    stack_address: thread.raw.stack.start_of_memory_range,
                    stack,
                    context,
                });
            }
        }
        Err(_) => {
            if v {
                eprintln!("md2core: thread list: not present");
            }
        }
    }
}

fn ingest_exception<'a, T>(
    dump: &'a Minidump<'a, T>,
    process: &mut CrashedProcess,
    system_info: &MinidumpSystemInfo,
    v: bool,
) where
    T: Deref<Target = [u8]> + 'a,
{
    match dump.get_stream::<MinidumpException<'_>>() {
        Ok(exception) => {
            if v {
                eprintln!(
                    "md2core: exception: thread={:#010x} signal={}",
                    exception.thread_id, exception.raw.exception_record.exception_code,
                );
            }
            process.crashing_tid = Some(exception.thread_id);
            process.fatal_signal =
                i32::from_ne_bytes(exception.raw.exception_record.exception_code.to_ne_bytes());
            process.exception_context = exception
                .context(system_info, None)
                .map(|cow| cow.into_owned().raw);
        }
        Err(_) => {
            if v {
                eprintln!("md2core: exception: not present");
            }
        }
    }
}

/// Returns a raw stream when present; absent streams produce `None`.
///
/// # Errors
///
/// Returns an error if the stream exists but cannot be decoded.
pub fn optional_raw_stream<'a, T>(
    dump: &'a Minidump<'a, T>,
    stream_type: MINIDUMP_STREAM_TYPE,
) -> Result<Option<&'a [u8]>, Md2CoreError>
where
    T: Deref<Target = [u8]> + 'a,
{
    match dump.get_raw_stream(stream_type as u32) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(minidump::Error::StreamNotFound) => Ok(None),
        Err(error) => Err(Md2CoreError::MinidumpRead(error)),
    }
}

/// Validates the minidump OS and converts rust-minidump's CPU enum to
/// md2core's architecture enum.
///
/// # Errors
///
/// Returns an error if the OS is not Linux/Android/NaCl, or if the CPU is unsupported.
pub fn architecture_from_system_info(
    system_info: &MinidumpSystemInfo,
) -> Result<Architecture, Md2CoreError> {
    architecture_from_cpu_os(system_info.cpu, system_info.os)
}

/// Converts rust-minidump's CPU/OS pair to a supported md2core architecture.
///
/// # Errors
///
/// Returns an error if the OS is not Linux/Android/NaCl, or if the CPU is unsupported.
pub fn architecture_from_cpu_os(cpu: Cpu, os: Os) -> Result<Architecture, Md2CoreError> {
    if !matches!(os, Os::Linux | Os::NaCl | Os::Android) {
        return Err(Md2CoreError::UnsupportedSystem {
            os: os.to_string(),
            cpu: cpu.to_string(),
        });
    }
    match cpu {
        Cpu::X86 => Ok(Architecture::X86),
        Cpu::X86_64 => Ok(Architecture::X86_64),
        Cpu::Arm => Ok(Architecture::Arm),
        Cpu::Arm64 => Ok(Architecture::Aarch64),
        Cpu::Mips => Ok(Architecture::Mips),
        Cpu::Mips64 => Ok(Architecture::Mips64),
        _ => Err(Md2CoreError::UnsupportedSystem {
            os: os.to_string(),
            cpu: cpu.to_string(),
        }),
    }
}

/// Converts rust-minidump's typed Linux maps stream into md2core mappings.
///
/// # Errors
///
/// Returns an error if any map entry cannot be converted into a valid address range.
pub fn mappings_from_minidump_linux_maps(
    maps: &MinidumpLinuxMaps<'_>,
) -> Result<Vec<Mapping>, Md2CoreError> {
    maps.by_addr()
        .filter_map(|map_info| match &map_info.map.pathname {
            MMapPath::Path(path) => Some((map_info, path.to_string_lossy().into_owned())),
            _ => None,
        })
        .filter(|(_, filename)| filename.starts_with('/'))
        .map(|(map_info, filename)| {
            let permissions = MappingPermissions::new(
                map_info.is_readable(),
                map_info.is_writable(),
                map_info.is_executable(),
            );
            Mapping::new(map_info.map.address.0, map_info.map.address.1, permissions)
                .map(|mapping| mapping.with_file(filename, map_info.map.offset))
        })
        .collect()
}

fn ingest_modules(
    process: &mut CrashedProcess,
    modules: &MinidumpModuleList,
    options: &ConvertOptions,
) {
    for module in modules.iter() {
        // We prefer richer data from MD_LINUX_MAPS; only synthesize a mapping
        // for modules we have not already seen.
        let base = module.raw.base_of_image;
        let size = u64::from(module.raw.size_of_image);
        let name = signature_for(module, options);
        if size > 0
            && let Ok(mapping) = Mapping::new(base, base + size, MappingPermissions::read_only())
        {
            // Attach the module filename so NT_FILE gets an entry for this
            // module when MD_LINUX_MAPS is absent or doesn't cover it.
            process.insert_mapping_if_absent(mapping.with_file(name.clone(), 0));
        }

        process.signatures.insert(base, name);
    }

    // If no cmdline stream was present (pr_fname still zeroed), use the first
    // module that looks like a main executable (no ".so" suffix).
    for module in modules.iter() {
        let basename = module.name.rsplit('/').next().unwrap_or(&module.name);
        if !looks_like_shared_lib(basename) {
            process.apply_module_name_fallback(&module.name);
            break;
        }
    }
}

fn signature_for(module: &MinidumpModule, options: &ConvertOptions) -> String {
    let filename = &module.name;
    let basename = filename.rsplit('/').next().unwrap_or(filename);

    // --sobasedir rewrites the path to <dir>/<basename> regardless of
    // --mangle-sonames so that gdb can locate .so files on the local machine.
    if let Some(dir) = &options.so_base_dir {
        return format!("{}/{basename}", dir.trim_end_matches('/'));
    }

    if !options.mangle_sonames {
        return filename.clone();
    }

    // --mangle-sonames: prefix with the build-id GUID.
    let guid =
        guid_from_module(module).unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".into());
    if guid == "00000000-0000-0000-0000-000000000000" {
        return filename.clone();
    }
    // C++ behavior: prefix becomes "/var/lib/breakpad/<guid>-<basename>"
    // and the basename is then concatenated again. Preserved verbatim.
    format!("/var/lib/breakpad/{guid}-{basename}{basename}")
}

fn guid_from_module(module: &MinidumpModule) -> Option<String> {
    use minidump::CodeView;
    match module.codeview_info.as_ref()? {
        CodeView::Pdb70(pdb) => {
            let g = &pdb.signature;
            Some(format!(
                "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                g.data1,
                g.data2,
                g.data3,
                g.data4[0],
                g.data4[1],
                g.data4[2],
                g.data4[3],
                g.data4[4],
                g.data4[5],
                g.data4[6],
                g.data4[7],
            ))
        }
        _ => None,
    }
}

/// Returns `true` when `basename` looks like a dynamic library name
/// (e.g. `libc.so.6`, `libfoo.so`, `linux-vdso.so.1`).
fn looks_like_shared_lib(basename: &str) -> bool {
    // Match names that end with ".so" or ".so.<digits...>" anywhere in the suffix.
    // Examples that match: libc.so.6, libm.so, linux-vdso.so.1
    // Examples that don't: test_app_cmd, my_binary
    let bytes = basename.as_bytes();
    // Walk backwards: skip a trailing version string like ".6" then look for ".so".
    let mut i = bytes.len();
    // Optional trailing version: skip trailing ".<decimal>" segments
    loop {
        // Find the last '.'
        let dot_pos = bytes[..i].iter().rposition(|&b| b == b'.');
        let Some(pos) = dot_pos else { return false };
        let suffix = &bytes[pos + 1..i];
        if suffix == b"so" {
            return true;
        }
        if suffix.iter().all(u8::is_ascii_digit) {
            i = pos; // strip this version segment and keep looking
        } else {
            return false;
        }
    }
}

/// Attempts to synthesize a [`DsoDebug`] from the module list when the minidump
/// has no `MD_LINUX_DSO_DEBUG` stream.
///
/// Strategy:
/// 1. Find the first non-library module in the module list (the main executable).
///    The executable does *not* need to be accessible on disk; the link map is
///    built from the minidump module list regardless.
/// 2. If the executable *is* accessible, read its ELF `PT_DYNAMIC` section so
///    `DT_DEBUG` can be patched to point GDB at the rebuilt link map.
/// 3. Build a `link_map` from all modules with correct `l_ld` values.
///    GDB's `lm_addr_check` computes the solib load displacement as
///    `l_ld − file_PT_DYNAMIC_vaddr`.  When `l_ld = 0` this yields a large
///    negative displacement and all symbol lookups land at wrong addresses.
///    Reading each module's ELF (if accessible) and computing
///    `l_ld = load_base + PT_DYNAMIC_vaddr` fixes this.
fn synthesize_dso_debug(
    arch: Architecture,
    modules: &MinidumpModuleList,
    signatures: &std::collections::BTreeMap<u64, String>,
    v: bool,
) -> Option<DsoDebug> {
    // Find the first non-library module.  No disk access required here.
    let (exe_base, exe_path) = modules.iter().find_map(|m| {
        let basename = m.name.rsplit('/').next().unwrap_or(&m.name);
        if looks_like_shared_lib(basename) {
            return None;
        }
        Some((m.raw.base_of_image, m.name.clone()))
    })?;

    // Try to read PT_DYNAMIC from the executable.  If the file is not locally
    // accessible (analysing a dump from another machine), fall back to an
    // estimated load_bias and skip DT_DEBUG patching.
    let (dynamic_data, dynamic_addr, load_bias) =
        read_executable_dynamic(arch, &exe_path, exe_base)
            .unwrap_or_else(|| (Vec::new(), 0, exe_base));

    if v {
        eprintln!(
            "md2core: synthesize DSO debug: exe={exe_path} load_bias={load_bias:#x} \
             _DYNAMIC@{dynamic_addr:#x} ({} bytes)",
            dynamic_data.len()
        );
    }

    // Build link_map with correct l_ld for each module.
    // l_ld = load_base + PT_DYNAMIC_vaddr (derived from the module's ELF file
    // when accessible).  Returns 0 for modules whose files cannot be read;
    // those modules will have degraded symbol resolution in GDB.
    let link_map: Vec<LinkMapEntry> = modules
        .iter()
        .map(|m| {
            let addr = m.raw.base_of_image;
            // `name` is the signatures-resolved path (respects --sobasedir).
            let name = signatures
                .get(&addr)
                .cloned()
                .unwrap_or_else(|| m.name.clone());
            // Use the resolved `name` (not the raw `m.name`) so that
            // --sobasedir-rewritten paths are tried.  Also falls back to
            // standard system library directories for bare sonames.
            let ld = elf_dynamic_runtime_addr(arch, &name, addr).unwrap_or(0);
            LinkMapEntry { addr, ld, name }
        })
        .collect();

    if v {
        eprintln!(
            "md2core: synthesize DSO debug: {} link_map entries",
            link_map.len()
        );
    }

    Some(DsoDebug {
        version: 1,
        brk: 0,
        ldbase: load_bias,
        dynamic: dynamic_addr,
        link_map,
        dynamic_data,
    })
}

/// Returns the runtime address of the `_DYNAMIC` segment for the ELF module
/// loaded at `load_base`, or `None` when the file cannot be read.
///
/// GDB stores this value as `l_ld` in the `link_map` struct.  Its
/// `lm_addr_check` function derives the solib load displacement as:
///
/// ```text
/// displacement = l_ld − file_PT_DYNAMIC_vaddr
/// ```
///
/// When `l_ld = 0` this becomes `−file_PT_DYNAMIC_vaddr` (wrong sign),
/// placing all symbol lookups at garbage addresses.  Providing the correct
/// value fixes symbol resolution without requiring core memory at those
/// addresses.
fn elf_dynamic_runtime_addr(arch: Architecture, path: &str, load_base: u64) -> Option<u64> {
    // Try to locate the file.  If `path` is not found directly, fall back to
    // searching for the basename in standard system library directories.  This
    // handles both bare names ("libc.so.6") and --sobasedir-rewritten paths
    // ("/app/dir/libc.so.6") when the app dir contains only app-specific libs.
    let bytes = if std::fs::metadata(path).is_ok() {
        std::fs::read(path).ok()?
    } else {
        const SYSTEM_LIB_DIRS: &[&str] = &[
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib",
            "/lib/x86_64-linux-gnu",
            "/lib",
        ];
        let basename = path.rsplit('/').next().unwrap_or(path);
        let mut found = None;
        for dir in SYSTEM_LIB_DIRS {
            let candidate = format!("{dir}/{basename}");
            if let Ok(b) = std::fs::read(&candidate) {
                found = Some(b);
                break;
            }
        }
        found?
    };
    if bytes.get(..4) != Some(b"\x7fELF") {
        return None;
    }
    let is_64 = bytes.get(4).copied()? == 2;
    if is_64 != arch.is_64bit() {
        return None;
    }

    let (e_phoff, e_phentsize, e_phnum) = if is_64 {
        (
            usize::try_from(read_u64_le(&bytes, 32)?).ok()?,
            read_u16_le(&bytes, 54)? as usize,
            read_u16_le(&bytes, 56)? as usize,
        )
    } else {
        (
            read_u32_le(&bytes, 28)? as usize,
            read_u16_le(&bytes, 42)? as usize,
            read_u16_le(&bytes, 44)? as usize,
        )
    };

    let mut first_load_vaddr: Option<u64> = None;
    let mut dyn_vaddr: Option<u64> = None;

    for i in 0..e_phnum {
        let o = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        let p_type = read_u32_le(&bytes, o)?;
        let p_vaddr = if is_64 {
            read_u64_le(&bytes, o + 16)?
        } else {
            u64::from(read_u32_le(&bytes, o + 8)?)
        };
        match p_type {
            1 /* PT_LOAD */ => { first_load_vaddr.get_or_insert(p_vaddr); }
            2 /* PT_DYNAMIC */ => { dyn_vaddr = Some(p_vaddr); }
            _ => {}
        }
    }

    let load_bias = load_base.checked_sub(first_load_vaddr?)?;
    load_bias.checked_add(dyn_vaddr?)
}

/// Reads the `PT_DYNAMIC` segment from an ELF executable at `exe_path` that
/// was loaded at `load_base`.
///
/// Returns `(dynamic_bytes, runtime_dynamic_addr, load_bias)` on success.
/// All errors are silently suppressed and produce `None`.
fn read_executable_dynamic(
    arch: Architecture,
    exe_path: &str,
    load_base: u64,
) -> Option<(Vec<u8>, u64, u64)> {
    let bytes = std::fs::read(exe_path).ok()?;
    if bytes.get(..4) != Some(b"\x7fELF") {
        return None;
    }
    let is_64 = bytes.get(4).copied()? == 2;
    if is_64 != arch.is_64bit() {
        return None;
    }

    let (e_phoff, e_phentsize, e_phnum) = if is_64 {
        (
            usize::try_from(read_u64_le(&bytes, 32)?).ok()?,
            read_u16_le(&bytes, 54)? as usize,
            read_u16_le(&bytes, 56)? as usize,
        )
    } else {
        (
            read_u32_le(&bytes, 28)? as usize,
            read_u16_le(&bytes, 42)? as usize,
            read_u16_le(&bytes, 44)? as usize,
        )
    };

    let mut first_load_vaddr: Option<u64> = None;
    let mut dyn_info: Option<(u64, u64, u64)> = None; // (file_off, vaddr, size)

    for i in 0..e_phnum {
        let o = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        let p_type = read_u32_le(&bytes, o)?;
        let (p_offset, p_vaddr, p_filesz) = if is_64 {
            (
                read_u64_le(&bytes, o + 8)?,
                read_u64_le(&bytes, o + 16)?,
                read_u64_le(&bytes, o + 32)?,
            )
        } else {
            (
                u64::from(read_u32_le(&bytes, o + 4)?),
                u64::from(read_u32_le(&bytes, o + 8)?),
                u64::from(read_u32_le(&bytes, o + 16)?),
            )
        };
        match p_type {
            1 /* PT_LOAD */ => {
                first_load_vaddr.get_or_insert(p_vaddr);
            }
            2 /* PT_DYNAMIC */ => {
                dyn_info = Some((p_offset, p_vaddr, p_filesz));
            }
            _ => {}
        }
    }

    let first_load_vaddr = first_load_vaddr?;
    let (dyn_file_off, dyn_vaddr, dyn_size) = dyn_info?;
    let load_bias = load_base.checked_sub(first_load_vaddr)?;
    let runtime_dyn = dyn_vaddr.checked_add(load_bias)?;

    let start = usize::try_from(dyn_file_off).ok()?;
    let end = start.checked_add(usize::try_from(dyn_size).ok()?)?;
    if end > bytes.len() {
        return None;
    }

    Some((bytes[start..end].to_vec(), runtime_dyn, load_bias))
}

// ---------------------------------------------------------------------------
// Byte-level helpers for safe little-endian reads from a byte slice.
// ---------------------------------------------------------------------------

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    bytes
        .get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    bytes
        .get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Builds a minimal synthetic `NT_AUXV` payload containing `AT_PHDR` and
/// `AT_ENTRY`, which GDB needs to compute `exec_displacement` for PIE
/// executables loaded from coredumps.
///
/// Without these entries GDB assumes displacement = 0 and shows symbols at
/// their ELF-file virtual addresses rather than their runtime addresses.
fn build_synthetic_auxv(arch: Architecture, modules: &MinidumpModuleList) -> Option<Vec<u8>> {
    // Find the main executable: first non-.so module with an on-disk path.
    let (exe_base, exe_path) = modules.iter().find_map(|m| {
        let basename = m.name.rsplit('/').next().unwrap_or(&m.name);
        if looks_like_shared_lib(basename) {
            return None;
        }
        if std::fs::metadata(&m.name).is_err() {
            return None;
        }
        Some((m.raw.base_of_image, m.name.clone()))
    })?;

    let bytes = std::fs::read(&exe_path).ok()?;
    if bytes.get(..4) != Some(b"\x7fELF") {
        return None;
    }
    let is_64 = bytes.get(4).copied()? == 2;
    if is_64 != arch.is_64bit() {
        return None;
    }

    let e_entry: u64 = if is_64 {
        read_u64_le(&bytes, 24)?
    } else {
        u64::from(read_u32_le(&bytes, 24)?)
    };

    let (e_phoff, e_phentsize, e_phnum) = if is_64 {
        (
            usize::try_from(read_u64_le(&bytes, 32)?).ok()?,
            read_u16_le(&bytes, 54)? as usize,
            read_u16_le(&bytes, 56)? as usize,
        )
    } else {
        (
            read_u32_le(&bytes, 28)? as usize,
            read_u16_le(&bytes, 42)? as usize,
            read_u16_le(&bytes, 44)? as usize,
        )
    };

    let mut first_load_vaddr: Option<u64> = None;
    let mut pt_phdr_vaddr: Option<u64> = None;

    for i in 0..e_phnum {
        let o = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        let p_type = read_u32_le(&bytes, o)?;
        let p_vaddr = if is_64 {
            read_u64_le(&bytes, o + 16)?
        } else {
            u64::from(read_u32_le(&bytes, o + 8)?)
        };
        match p_type {
            1 /* PT_LOAD */ => { first_load_vaddr.get_or_insert(p_vaddr); }
            6 /* PT_PHDR */ => { pt_phdr_vaddr = Some(p_vaddr); }
            _ => {}
        }
    }

    let first_load_vaddr = first_load_vaddr?;
    let load_bias = exe_base.checked_sub(first_load_vaddr)?;

    // AT_PHDR: runtime address of the program-header table.
    let phdr_vaddr = pt_phdr_vaddr.unwrap_or(e_phoff as u64);
    let at_phdr = load_bias.checked_add(phdr_vaddr)?;
    let at_entry = load_bias.checked_add(e_entry)?;

    let word = arch.long_size();
    let mut out = Vec::with_capacity(3 * 2 * word);

    // Each auxv entry is { a_type, a_val }, both word-sized, little-endian.
    if is_64 {
        for (typ, val) in [(3u64, at_phdr), (9u64, at_entry), (0u64, 0u64)] {
            out.extend_from_slice(&typ.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
    } else {
        // For 32-bit ELF, AT_ values and load addresses are 32-bit by construction.
        let at_phdr32 = u32::try_from(at_phdr).ok()?;
        let at_entry32 = u32::try_from(at_entry).ok()?;
        for (typ, val) in [(3u32, at_phdr32), (9u32, at_entry32), (0u32, 0u32)] {
            out.extend_from_slice(&typ.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
    }

    Some(out)
}

/// `MDRVA` sentinel from the minidump format meaning "no link map present".
const INVALID_MD_RVA: u32 = u32::MAX;

/// Parses an `MD_LINUX_DSO_DEBUG` stream using the typed structs from
/// [`minidump_common::format`]. The layout depends on the dump's pointer width.
fn parse_dso_debug(
    arch: Architecture,
    bytes: &[u8],
    full_file: &[u8],
) -> Result<DsoDebug, Md2CoreError> {
    if arch.is_64bit() {
        let header_size = std::mem::size_of::<DSO_DEBUG_64>();
        if bytes.len() < header_size {
            return Ok(DsoDebug::default());
        }
        let header: DSO_DEBUG_64 = bytes.pread_with(0, LE)?;
        let dynamic_data = bytes[header_size..].to_vec();
        let link_map = read_link_map_64(full_file, header.map, header.dso_count)?;
        Ok(DsoDebug {
            version: header.version,
            brk: header.brk,
            ldbase: header.ldbase,
            dynamic: header.dynamic,
            link_map,
            dynamic_data,
        })
    } else {
        let header_size = std::mem::size_of::<DSO_DEBUG_32>();
        if bytes.len() < header_size {
            return Ok(DsoDebug::default());
        }
        let header: DSO_DEBUG_32 = bytes.pread_with(0, LE)?;
        let dynamic_data = bytes[header_size..].to_vec();
        let link_map = read_link_map_32(full_file, header.map, header.dso_count)?;
        Ok(DsoDebug {
            version: header.version,
            brk: u64::from(header.brk),
            ldbase: u64::from(header.ldbase),
            dynamic: u64::from(header.dynamic),
            link_map,
            dynamic_data,
        })
    }
}

fn read_link_map_64(
    full_file: &[u8],
    map_rva: u32,
    dso_count: u32,
) -> Result<Vec<LinkMapEntry>, Md2CoreError> {
    if map_rva == INVALID_MD_RVA {
        return Ok(Vec::new());
    }
    let entry_size = std::mem::size_of::<LINK_MAP_64>();
    let mut entries = Vec::with_capacity(dso_count as usize);
    for i in 0..dso_count as usize {
        let Some(off) = (map_rva as usize).checked_add(i * entry_size) else {
            break;
        };
        if off + entry_size > full_file.len() {
            break;
        }
        let entry: LINK_MAP_64 = full_file.pread_with(off, LE)?;
        let name = read_md_ascii_string(full_file, entry.name).unwrap_or_default();
        entries.push(LinkMapEntry {
            addr: entry.addr,
            ld: entry.ld,
            name,
        });
    }
    Ok(entries)
}

fn read_link_map_32(
    full_file: &[u8],
    map_rva: u32,
    dso_count: u32,
) -> Result<Vec<LinkMapEntry>, Md2CoreError> {
    if map_rva == INVALID_MD_RVA {
        return Ok(Vec::new());
    }
    let entry_size = std::mem::size_of::<LINK_MAP_32>();
    let mut entries = Vec::with_capacity(dso_count as usize);
    for i in 0..dso_count as usize {
        let Some(off) = (map_rva as usize).checked_add(i * entry_size) else {
            break;
        };
        if off + entry_size > full_file.len() {
            break;
        }
        let entry: LINK_MAP_32 = full_file.pread_with(off, LE)?;
        let name = read_md_ascii_string(full_file, entry.name).unwrap_or_default();
        entries.push(LinkMapEntry {
            addr: u64::from(entry.addr),
            ld: u64::from(entry.ld),
            name,
        });
    }
    Ok(entries)
}

/// Reads an ASCII `MDString` (UTF-16LE, ASCII-only payload) from `full_file`
/// at the given RVA. Returns `None` if the descriptor is truncated.
fn read_md_ascii_string(full_file: &[u8], rva: u32) -> Option<String> {
    let off = rva as usize;
    let byte_len = full_file.pread_with::<u32>(off, LE).ok()? as usize;
    let start = off.checked_add(4)?;
    let end = start.checked_add(byte_len)?;
    if end > full_file.len() {
        return None;
    }
    let mut out = String::with_capacity(byte_len / 2);
    for chunk in full_file[start..end].chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        let c = char::from_u32(u32::from(unit))
            .filter(char::is_ascii)
            .unwrap_or('?');
        out.push(c);
    }
    Some(out)
}
