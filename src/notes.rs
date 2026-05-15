//! ELF note serialization for the core file's `PT_NOTE` segment.
//!
//! Each note is encoded as: `Nhdr (12)` + `name + NUL padded to 4` +
//! `descriptor padded to 4`. We always use 4-byte alignment, matching what
//! the Linux kernel and GDB consume regardless of ELF class.

use std::io::Write;

use std::collections::BTreeMap;

use crate::elf::NoteHeader;
use crate::error::Md2CoreError;
use crate::model::{Architecture, DEFAULT_PAGE_SIZE, Mapping, ProcessInfo};

const NOTE_ALIGN: usize = 4;

/// Serialized ELF note (header + name + descriptor + alignment padding).
pub struct Note {
    /// Final byte image of the note ready to be written into `PT_NOTE`.
    pub bytes: Vec<u8>,
}

impl Note {
    /// Builds a note from a name (without trailing NUL) and a descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the note header fails.
    ///
    /// # Panics
    ///
    /// Panics if the name or descriptor exceeds `u32::MAX` bytes (impossible in practice).
    pub fn build(name: &[u8], n_type: u32, desc: &[u8]) -> Result<Self, Md2CoreError> {
        // Note name in ELF is stored with the NUL terminator counted in
        // `n_namesz`. Our `CORE_NAME`/`LINUX_NAME` constants already include it.
        let mut name_bytes = name.to_vec();
        if name_bytes.last() != Some(&0) {
            name_bytes.push(0);
        }
        let n_namesz = u32::try_from(name_bytes.len()).expect("note name too large");
        let n_descsz = u32::try_from(desc.len()).expect("note descriptor too large");

        let mut out = Vec::new();
        let header = NoteHeader {
            n_namesz,
            n_descsz,
            n_type,
        };
        header.write(&mut out)?;
        out.extend_from_slice(&name_bytes);
        pad_to(&mut out, NOTE_ALIGN);
        out.extend_from_slice(desc);
        pad_to(&mut out, NOTE_ALIGN);
        Ok(Self { bytes: out })
    }

    /// Writes the note into `out`.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to `out` fails.
    pub fn write<W: Write>(&self, out: &mut W) -> Result<(), Md2CoreError> {
        out.write_all(&self.bytes)?;
        Ok(())
    }
}

fn pad_to(out: &mut Vec<u8>, align: usize) {
    let rem = out.len() % align;
    if rem != 0 {
        out.resize(out.len() + (align - rem), 0);
    }
}

// --- NT_PRPSINFO -----------------------------------------------------------

/// Builds the `NT_PRPSINFO` descriptor for the given architecture.
#[must_use]
pub fn build_prpsinfo(arch: Architecture, info: &ProcessInfo) -> Vec<u8> {
    let mut out = vec![0u8]; // pr_state
    out.push(b'R'); // pr_sname
    out.push(0); // pr_zomb
    out.push(0); // pr_nice
    let long = arch.long_size();
    pad(&mut out, long);
    push_long(&mut out, 0, long); // pr_flag

    if arch.prpsinfo_uid_is_u32() {
        out.extend_from_slice(&0u32.to_le_bytes()); // pr_uid
        out.extend_from_slice(&0u32.to_le_bytes()); // pr_gid
    } else {
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
    }

    out.extend_from_slice(&i32::from_ne_bytes(info.pid.to_ne_bytes()).to_le_bytes()); // pr_pid
    out.extend_from_slice(&0i32.to_le_bytes()); // pr_ppid
    out.extend_from_slice(&0i32.to_le_bytes()); // pr_pgrp
    out.extend_from_slice(&0i32.to_le_bytes()); // pr_sid
    out.extend_from_slice(&info.filename);
    out.extend_from_slice(&info.arguments);
    out
}

// --- NT_PRSTATUS -----------------------------------------------------------

/// Builds the `NT_PRSTATUS` descriptor.
///
/// `fp_valid` corresponds to `pr_fpvalid` and must be `true` only when an
/// `NT_FPREGSET` note will accompany this status (matches the Linux kernel
/// convention used by GDB).
#[must_use]
pub fn build_prstatus(
    arch: Architecture,
    tid: u32,
    fatal_signal: i32,
    pr_reg: &[u8],
    fp_valid: bool,
) -> Vec<u8> {
    let long = arch.long_size();
    let mut out = Vec::new();

    // elf_siginfo: { si_signo, si_code, si_errno } each i32
    out.extend_from_slice(&fatal_signal.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());

    // pr_cursig (i16) + alignment padding to next `long`
    out.extend_from_slice(
        &i16::try_from(fatal_signal)
            .unwrap_or(i16::MAX)
            .to_le_bytes(),
    );
    pad(&mut out, long);

    push_long(&mut out, 0, long); // pr_sigpend
    push_long(&mut out, 0, long); // pr_sighold

    out.extend_from_slice(&i32::from_ne_bytes(tid.to_ne_bytes()).to_le_bytes()); // pr_pid
    out.extend_from_slice(&0i32.to_le_bytes()); // pr_ppid
    out.extend_from_slice(&0i32.to_le_bytes()); // pr_pgrp
    out.extend_from_slice(&0i32.to_le_bytes()); // pr_sid

    // 4 timevals (utime, stime, cutime, cstime), each two longs.
    for _ in 0..8 {
        push_long(&mut out, 0, long);
    }

    // pr_reg
    out.extend_from_slice(pr_reg);

    // pr_fpvalid: i32 — set to 1 only when an NT_FPREGSET note will follow,
    // matching the kernel's convention so GDB does not look for absent FP regs.
    let fp_valid_flag = i32::from(fp_valid);
    out.extend_from_slice(&fp_valid_flag.to_le_bytes());
    pad(&mut out, long);
    out
}

// --- NT_FILE -------------------------------------------------------------

/// Builds the `NT_FILE` descriptor payload from the process's named mappings.
///
/// The note format (from `fs/binfmt_elf.c`) is:
/// ```text
/// long count      -- number of mapped files
/// long page_size  -- file offset units
/// [count] × { long start; long end; long file_ofs }
/// [count] × NUL-terminated filename
/// ```
/// Only mappings that have an associated filename are included, matching the
/// C++ commit 417f5dbd that introduced `NT_FILE` support.
///
/// # Errors
///
/// Returns an error if a 32-bit note field cannot represent a mapping value.
pub fn build_nt_file_payload(
    arch: Architecture,
    mappings: &BTreeMap<u64, Mapping>,
) -> Result<Vec<u8>, Md2CoreError> {
    let word = arch.long_size();
    let entries: Vec<(&Mapping, &str)> = mappings
        .values()
        .filter_map(|mapping| {
            mapping
                .filename
                .as_deref()
                .map(|filename| (mapping, filename))
        })
        .collect();

    let names_len: usize = entries
        .iter()
        .map(|(_, filename)| filename.len() + 1) // +1 for NUL
        .sum();
    let mut out = Vec::with_capacity(2 * word + entries.len() * 3 * word + names_len);

    let entry_count = u64::try_from(entries.len())
        .map_err(|_| Md2CoreError::IntegerOverflow("NT_FILE entry count"))?;
    try_push_long(&mut out, entry_count, word, "NT_FILE entry count")?;
    try_push_long(&mut out, DEFAULT_PAGE_SIZE, word, "NT_FILE page size")?;

    for (mapping, _) in &entries {
        try_push_long(
            &mut out,
            mapping.start_address,
            word,
            "NT_FILE mapping start",
        )?;
        try_push_long(&mut out, mapping.end_address, word, "NT_FILE mapping end")?;
        // NT_FILE stores offsets in PAGE units (kernel vm_pgoff); GDB multiplies
        // by page_size to recover the byte offset.
        let page_ofs = mapping.offset / DEFAULT_PAGE_SIZE;
        try_push_long(&mut out, page_ofs, word, "NT_FILE mapping offset")?;
    }
    for (_, filename) in &entries {
        out.extend_from_slice(filename.as_bytes());
        out.push(0); // NUL terminator
    }
    Ok(out)
}

fn try_push_long(
    out: &mut Vec<u8>,
    value: u64,
    size: usize,
    field: &'static str,
) -> Result<(), Md2CoreError> {
    if size == 8 {
        out.extend_from_slice(&value.to_le_bytes());
    } else {
        let value = u32::try_from(value).map_err(|_| Md2CoreError::IntegerOverflow(field))?;
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

fn push_long(out: &mut Vec<u8>, value: u64, size: usize) {
    if size == 8 {
        out.extend_from_slice(&value.to_le_bytes());
    } else {
        out.extend_from_slice(&value.to_le_bytes()[..4]);
    }
}

fn pad(out: &mut Vec<u8>, align: usize) {
    let rem = out.len() % align;
    if rem != 0 {
        out.resize(out.len() + (align - rem), 0);
    }
}
