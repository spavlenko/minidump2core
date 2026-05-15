use std::collections::BTreeMap;

use minidump::MinidumpRawContext;

use crate::error::Md2CoreError;

/// Default page size used by Breakpad's md2core mapping augmentation.
pub const DEFAULT_PAGE_SIZE: u64 = 4096;

/// Supported target architecture for the generated ELF core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X86_64,
    /// 32-bit ARM.
    Arm,
    /// 64-bit ARM.
    Aarch64,
    /// 32-bit MIPS o32.
    Mips,
    /// 64-bit MIPS n64.
    Mips64,
}

impl Architecture {
    /// Returns the ELF class (`ELFCLASS32` = 1 / `ELFCLASS64` = 2).
    #[must_use]
    pub const fn elf_class(self) -> u8 {
        match self {
            Self::X86 | Self::Arm | Self::Mips => 1,
            Self::X86_64 | Self::Aarch64 | Self::Mips64 => 2,
        }
    }

    /// Returns the ELF `e_machine` constant.
    #[must_use]
    pub const fn elf_machine(self) -> u16 {
        match self {
            Self::X86 => 3,                 // EM_386
            Self::X86_64 => 62,             // EM_X86_64
            Self::Arm => 40,                // EM_ARM
            Self::Aarch64 => 183,           // EM_AARCH64
            Self::Mips | Self::Mips64 => 8, // EM_MIPS
        }
    }

    /// Returns true when the target is a 64-bit ELF class.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.elf_class() == 2
    }

    /// Word size of `unsigned long` for prstatus/prpsinfo layouts.
    #[must_use]
    pub const fn long_size(self) -> usize {
        if self.is_64bit() { 8 } else { 4 }
    }

    /// Whether `pr_uid`/`pr_gid` are 32-bit on this arch (matching Breakpad).
    #[must_use]
    pub const fn prpsinfo_uid_is_u32(self) -> bool {
        matches!(self, Self::X86_64 | Self::Mips | Self::Mips64,)
    }

    /// Short human-readable name for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Aarch64 => "aarch64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
        }
    }
}

/// ELF load-segment permissions decoded from `/proc/<pid>/maps`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MappingPermissions {
    read: bool,
    write: bool,
    execute: bool,
}

impl MappingPermissions {
    /// Creates a permission set from explicit bits.
    #[must_use]
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    /// Creates readable and writable permissions for synthetic data mappings.
    #[must_use]
    pub const fn read_write() -> Self {
        Self::new(true, true, false)
    }

    /// Read-only permissions used as a fallback for module mappings discovered
    /// via `MD_MODULE_LIST_STREAM` without companion `/proc/.../maps`.
    #[must_use]
    pub const fn read_only() -> Self {
        Self::new(true, false, false)
    }

    /// Returns true when the mapping is readable.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.read
    }
    /// Returns true when the mapping is writable.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.write
    }
    /// Returns true when the mapping is executable.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.execute
    }

    /// Converts this set to ELF `p_flags` bits.
    #[must_use]
    pub const fn to_elf_flags(self) -> u32 {
        let mut flags = 0;
        if self.execute {
            flags |= 1;
        }
        if self.write {
            flags |= 2;
        }
        if self.read {
            flags |= 4;
        }
        flags
    }
}

/// One virtual memory mapping that will become an ELF `PT_LOAD` program header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// Inclusive start virtual address.
    pub start_address: u64,
    /// Exclusive end virtual address.
    pub end_address: u64,
    /// File offset reported by Linux maps.
    pub offset: u64,
    /// ELF permissions for this mapping.
    pub permissions: MappingPermissions,
    /// Optional file backing path.
    pub filename: Option<String>,
    /// Optional bytes included in the core file for this mapping.
    pub data: Vec<u8>,
}

impl Mapping {
    /// Creates an anonymous mapping with no associated core-file bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `start_address >= end_address`.
    pub fn new(
        start_address: u64,
        end_address: u64,
        permissions: MappingPermissions,
    ) -> Result<Self, Md2CoreError> {
        if start_address >= end_address {
            return Err(Md2CoreError::InvalidAddressRange {
                start: start_address,
                end: end_address,
            });
        }
        Ok(Self {
            start_address,
            end_address,
            offset: 0,
            permissions,
            filename: None,
            data: Vec::new(),
        })
    }

    /// Returns true when `addr` lies inside this mapping.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.start_address <= addr && addr < self.end_address
    }

    /// Attaches a file backing path and file offset.
    #[must_use]
    pub fn with_file(mut self, filename: String, offset: u64) -> Self {
        self.filename = Some(filename);
        self.offset = offset;
        self
    }
}

/// Raw thread snapshot captured from a minidump stream.
#[derive(Debug, Clone)]
pub struct ThreadSnapshot {
    /// Linux thread id.
    pub tid: u32,
    /// Virtual address where `stack` starts.
    pub stack_address: u64,
    /// Captured stack bytes.
    pub stack: Vec<u8>,
    /// Parsed CPU context for this thread, if available.
    pub context: Option<MinidumpRawContext>,
}

/// Process information used to populate the ELF `NT_PRPSINFO` note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Short executable basename, matching `pr_fname[16]`.
    pub filename: [u8; 16],
    /// Flattened command line, matching `pr_psargs[80]`.
    pub arguments: [u8; 80],
    /// Process ID used for `pr_pid` in the prpsinfo note.
    pub pid: u32,
}

impl ProcessInfo {
    /// Creates an empty process info record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filename: [0; 16],
            arguments: [0; 80],
            pid: 0,
        }
    }

    /// Sets `pr_fname` and `pr_psargs` from the basename of `module_path` when
    /// no command-line stream was available (i.e. `filename` is still zeroed).
    pub fn apply_module_name_fallback(&mut self, module_path: &str) {
        if self.filename != [0u8; 16] {
            return; // already set by cmdline stream
        }
        let basename = module_path.rsplit('/').next().unwrap_or(module_path);
        let bytes = basename.as_bytes();
        let copy_len = bytes.len().min(15);
        self.filename[..copy_len].copy_from_slice(&bytes[..copy_len]);
        if self.arguments == [0u8; 80] {
            let arg_len = bytes.len().min(79);
            self.arguments[..arg_len].copy_from_slice(&bytes[..arg_len]);
        }
    }

    /// Applies Breakpad's command-line normalization rules.
    pub fn apply_cmdline(&mut self, cmdline: &[u8]) {
        let Some(end) = cmdline.iter().position(|byte| *byte == 0 || *byte == b' ') else {
            return;
        };

        self.filename = [0; 16];
        self.arguments = [0; 80];

        let binary_start = cmdline[..end]
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(0, |pos| pos + 1);
        let binary_name = &cmdline[binary_start..end];
        copy_truncated(&mut self.filename[..15], binary_name);

        let arg_len = cmdline.len().min(79);
        self.arguments[..arg_len].copy_from_slice(&cmdline[..arg_len]);
        for byte in &mut self.arguments[..arg_len] {
            if *byte == 0 {
                *byte = b' ';
            }
        }
    }
}

impl Default for ProcessInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Subset of `MD_LINUX_DSO_DEBUG` data needed to rebuild an `r_debug` link map.
#[derive(Debug, Clone, Default)]
pub struct DsoDebug {
    /// `r_debug.r_version`.
    pub version: u32,
    /// Address of the dynamic linker break-handler.
    pub brk: u64,
    /// Base address of the dynamic loader.
    pub ldbase: u64,
    /// Address of the executable's `_DYNAMIC` array (matches `r_debug.r_ldbase` use).
    pub dynamic: u64,
    /// Per-DSO link map entries.
    pub link_map: Vec<LinkMapEntry>,
    /// Bytes of the executable's `_DYNAMIC` array, if captured.
    pub dynamic_data: Vec<u8>,
}

/// One entry in the dynamic linker's link map.
#[derive(Debug, Clone)]
pub struct LinkMapEntry {
    /// Load address of the DSO.
    pub addr: u64,
    /// Address of the DSO's `_DYNAMIC` array.
    pub ld: u64,
    /// File name (from minidump or substituted by signature mangling).
    pub name: String,
}

/// Mutable core-conversion state collected from minidump streams.
#[derive(Debug, Clone)]
pub struct CrashedProcess {
    architecture: Architecture,
    /// Memory mappings ordered by start address.
    pub(crate) mappings: BTreeMap<u64, Mapping>,
    /// Thread snapshots.
    pub(crate) threads: Vec<ThreadSnapshot>,
    /// Raw auxiliary vector bytes.
    pub(crate) auxv: Vec<u8>,
    /// Process info note payload data.
    pub(crate) process_info: ProcessInfo,
    /// Thread id of the crashing thread, if known.
    pub crashing_tid: Option<u32>,
    /// CPU context from the exception record for the crashing thread, if available.
    pub exception_context: Option<MinidumpRawContext>,
    /// Fatal signal number associated with the crash, if known.
    pub fatal_signal: i32,
    /// Optional DSO debug data for `r_debug` reconstruction.
    pub dso_debug: DsoDebug,
    /// Mapping module-name overrides keyed by base address (used by `-i` /
    /// `--mangle-sonames` to substitute symbol-server style names).
    pub signatures: BTreeMap<u64, String>,
}

impl CrashedProcess {
    /// Creates a process model for a validated target architecture.
    #[must_use]
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            mappings: BTreeMap::new(),
            threads: Vec::new(),
            auxv: Vec::new(),
            process_info: ProcessInfo::new(),
            crashing_tid: None,
            exception_context: None,
            fatal_signal: 0,
            dso_debug: DsoDebug::default(),
            signatures: BTreeMap::new(),
        }
    }

    /// Returns the architecture selected during system validation.
    #[must_use]
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }
    /// Returns the ordered mapping table.
    #[must_use]
    pub fn mappings(&self) -> &BTreeMap<u64, Mapping> {
        &self.mappings
    }
    /// Mutable access to the mapping table for late-stage augmentation.
    pub fn mappings_mut(&mut self) -> &mut BTreeMap<u64, Mapping> {
        &mut self.mappings
    }
    /// Inserts or replaces one mapping by its start address. If the address
    /// already exists, the existing entry is preserved (matching Breakpad's
    /// preference for `MD_LINUX_MAPS` over `MD_MODULE_LIST_STREAM`).
    pub fn insert_mapping(&mut self, mapping: Mapping) {
        self.mappings.insert(mapping.start_address, mapping);
    }
    /// Inserts a mapping only if no mapping at that start address exists.
    pub fn insert_mapping_if_absent(&mut self, mapping: Mapping) {
        self.mappings
            .entry(mapping.start_address)
            .or_insert(mapping);
    }
    /// Appends a thread snapshot.
    pub fn add_thread(&mut self, thread: ThreadSnapshot) {
        self.threads.push(thread);
    }
    /// Returns all thread snapshots.
    #[must_use]
    pub fn threads(&self) -> &[ThreadSnapshot] {
        &self.threads
    }
    /// Sets the raw auxiliary vector bytes.
    pub fn set_auxv(&mut self, auxv: Vec<u8>) {
        self.auxv = auxv;
    }
    /// Returns the raw auxiliary vector bytes.
    #[must_use]
    pub fn auxv(&self) -> &[u8] {
        &self.auxv
    }
    /// Updates process info from the Linux command-line stream.
    pub fn apply_cmdline(&mut self, cmdline: &[u8]) {
        self.process_info.apply_cmdline(cmdline);
    }
    /// Sets the process ID used in `NT_PRPSINFO`.
    pub fn set_pid(&mut self, pid: u32) {
        self.process_info.pid = pid;
    }
    /// Sets `pr_fname`/`pr_psargs` from a module path when cmdline is absent.
    pub fn apply_module_name_fallback(&mut self, module_path: &str) {
        self.process_info.apply_module_name_fallback(module_path);
    }
    /// Returns process info note data.
    #[must_use]
    pub const fn process_info(&self) -> &ProcessInfo {
        &self.process_info
    }
}

/// Aligns `value` upward to the next multiple of `alignment`.
///
/// # Errors
///
/// Returns an error if `alignment` is zero or if the alignment overflows `u64`.
pub fn align_up(value: u64, alignment: u64) -> Result<u64, Md2CoreError> {
    if alignment == 0 {
        return Err(Md2CoreError::InvalidAlignment);
    }
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(alignment - remainder)
        .ok_or(Md2CoreError::IntegerOverflow("aligned value"))
}

/// Aligns `value` downward to a multiple of `alignment`.
///
/// # Errors
///
/// Returns an error if `alignment` is zero.
pub fn align_down(value: u64, alignment: u64) -> Result<u64, Md2CoreError> {
    if alignment == 0 {
        return Err(Md2CoreError::InvalidAlignment);
    }
    Ok(value - (value % alignment))
}

pub(crate) fn padded_vec(
    prefix_len: usize,
    data: &[u8],
    alignment: usize,
) -> Result<Vec<u8>, Md2CoreError> {
    if alignment == 0 {
        return Err(Md2CoreError::InvalidAlignment);
    }
    let initial_len = prefix_len
        .checked_add(data.len())
        .ok_or(Md2CoreError::IntegerOverflow("padded data length"))?;
    let padding = (alignment - (initial_len % alignment)) % alignment;
    let final_len = initial_len
        .checked_add(padding)
        .ok_or(Md2CoreError::IntegerOverflow("padded data length"))?;

    let mut padded = Vec::with_capacity(final_len);
    padded.resize(prefix_len, 0);
    padded.extend_from_slice(data);
    padded.resize(final_len, 0);
    Ok(padded)
}

fn copy_truncated(destination: &mut [u8], source: &[u8]) {
    let len = destination.len().min(source.len());
    destination[..len].copy_from_slice(&source[..len]);
}
