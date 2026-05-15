//! Top-level ELF core file writer. Mirrors the layout produced by Breakpad's
//! `minidump-2-core.cc`:
//!
//! ```text
//! Ehdr | Phdr (PT_NOTE) | Phdr * N (PT_LOAD) | PT_NOTE bytes | PT_LOAD bytes ...
//! ```
//!
//! The note ordering is `NT_PRPSINFO`, `NT_AUXV`, then a `NT_PRSTATUS`
//! (`+ NT_FPREGSET` and `+ NT_PRXFPREG` on x86 family) for the crashing
//! thread first, followed by the remaining threads.

use std::io::Write;

use crate::elf::{
    note_types, ElfHeader, ProgramHeader, CORE_NAME, LINUX_NAME, PT_LOAD, PT_NOTE,
};
use crate::error::Md2CoreError;
use crate::model::{Architecture, CrashedProcess, ThreadSnapshot, DEFAULT_PAGE_SIZE};
use minidump::MinidumpRawContext;
use crate::notes::{build_nt_file_payload, build_prpsinfo, build_prstatus, Note};
use crate::regs::{to_fpregset, to_pr_reg, to_prxfpreg};

/// Writes the full ELF core image for `process` to `out`.
pub fn write_core<W: Write>(process: &CrashedProcess, out: &mut W) -> Result<(), Md2CoreError> {
    let arch = process.architecture();

    // 1. Pre-build all note bytes so we know PT_NOTE's filesz.
    let note_bytes = build_note_segment(process)?;

    // 2. Compute layout.
    let phnum = 1 /* PT_NOTE */ + process.mappings().len();
    let phnum_u16 = u16::try_from(phnum).map_err(|_| {
        Md2CoreError::IntegerOverflow("phnum exceeds u16")
    })?;

    let header = ElfHeader {
        class: arch.elf_class(),
        machine: arch.elf_machine(),
        phnum: phnum_u16,
    };
    let ehdr_size = header.size() as u64;
    let phdr_size = header.phdr_size() as u64;

    let phdr_table_size = phdr_size * phnum as u64;
    let pt_note_offset = ehdr_size + phdr_table_size;
    let pt_note_filesz = note_bytes.len() as u64;
    let pt_note_end = pt_note_offset + pt_note_filesz;

    // PT_LOAD segments are aligned to a page boundary in the file. C++ pads
    // PT_NOTE up to the next `p_align` (4096) boundary so PT_LOAD data starts
    // page-aligned in the file.
    let load_align = pt_load_alignment();
    let note_pad = match pt_note_end % load_align {
        0 => 0,
        rem => load_align - rem,
    };
    let mut load_offset = pt_note_end + note_pad;

    // 3. Write Ehdr + Phdrs.
    header.write(out)?;

    // PT_NOTE phdr
    ProgramHeader {
        p_type: PT_NOTE,
        p_flags: 0,
        p_offset: pt_note_offset,
        p_filesz: pt_note_filesz,
        p_memsz: 0,
        p_paddr: 0,
        p_vaddr: 0,
        p_align: 0,
    }
    .write(out, header.class)?;

    // PT_LOAD phdrs
    for mapping in process.mappings().values() {
        let memsz = mapping.end_address - mapping.start_address;
        let (p_offset, p_filesz);
        if mapping.data.is_empty() {
            p_offset = 0;
            p_filesz = 0;
        } else {
            p_offset = load_offset;
            p_filesz = mapping.data.len() as u64;
            load_offset += p_filesz;
        }
        // Mappings discovered via MD_MODULE_LIST_STREAM lack permissions in
        // the C++ tool (encoded as 0xFFFFFFFF) and fall back to PF_R.
        let p_flags = if mapping.permissions == crate::model::MappingPermissions::default() {
            // default (all-false) is treated as "no permission info" — emit PF_R.
            // Note: legitimate "no permission" mappings cannot be loaded anyway.
            4
        } else {
            mapping.permissions.to_elf_flags()
        };
        ProgramHeader {
            p_type: PT_LOAD,
            p_flags,
            p_offset,
            p_filesz,
            p_memsz: memsz,
            p_paddr: 0,
            p_vaddr: mapping.start_address,
            p_align: load_align,
        }
        .write(out, header.class)?;
    }

    // 4. Write the PT_NOTE bytes.
    out.write_all(&note_bytes)?;

    // 5. Pad to PT_LOAD alignment.
    if note_pad > 0 {
        let zeros = vec![0u8; note_pad as usize];
        out.write_all(&zeros)?;
    }

    // 6. Write each PT_LOAD's captured bytes.
    for mapping in process.mappings().values() {
        if !mapping.data.is_empty() {
            out.write_all(&mapping.data)?;
        }
    }

    Ok(())
}

const fn pt_load_alignment() -> u64 {
    DEFAULT_PAGE_SIZE
}

fn build_note_segment(process: &CrashedProcess) -> Result<Vec<u8>, Md2CoreError> {
    let arch = process.architecture();
    let mut out = Vec::new();

    // NT_PRPSINFO
    let prpsinfo = build_prpsinfo(arch, process.process_info());
    Note::build(CORE_NAME, note_types::NT_PRPSINFO, &prpsinfo)?.write(&mut out)?;

    // NT_AUXV
    Note::build(CORE_NAME, note_types::NT_AUXV, process.auxv())?.write(&mut out)?;

    // NT_FILE — lets GDB validate PIE displacement and locate .so symbol files
    // automatically, matching C++ commit 417f5dbd.
    let nt_file = build_nt_file_payload(arch, process.mappings());
    Note::build(CORE_NAME, note_types::NT_FILE, &nt_file)?.write(&mut out)?;

    // NT_PRSTATUS for crashing thread first, then the rest.
    let crashing = process.crashing_tid;
    let mut ordered: Vec<&ThreadSnapshot> = Vec::with_capacity(process.threads().len());
    if let Some(tid) = crashing {
        if let Some(t) = process.threads().iter().find(|t| t.tid == tid) {
            ordered.push(t);
        }
    }
    for thread in process.threads() {
        if Some(thread.tid) != crashing {
            ordered.push(thread);
        }
    }

    for (index, thread) in ordered.iter().enumerate() {
        let signal = if index == 0 { process.fatal_signal } else { 0 };
        let context_override = if index == 0 { process.exception_context.as_ref() } else { None };
        write_thread_notes(arch, thread, signal, context_override, &mut out)?;
    }

    Ok(out)
}

fn write_thread_notes(
    arch: Architecture,
    thread: &ThreadSnapshot,
    fatal_signal: i32,
    context_override: Option<&MinidumpRawContext>,
    out: &mut Vec<u8>,
) -> Result<(), Md2CoreError> {
    let context = context_override.or(thread.context.as_ref());
    let Some(context) = context else {
        return Ok(());
    };
    let pr_reg = to_pr_reg(arch, context)?;
    let fp = to_fpregset(arch, context);
    let prstatus = build_prstatus(arch, thread.tid, fatal_signal, &pr_reg, fp.is_some());
    Note::build(CORE_NAME, note_types::NT_PRSTATUS, &prstatus)?.write(out)?;

    if let Some(fp) = fp {
        Note::build(CORE_NAME, note_types::NT_FPREGSET, &fp)?.write(out)?;
    }
    if let Some(xfp) = to_prxfpreg(arch, context) {
        Note::build(LINUX_NAME, note_types::NT_PRXFPREG, &xfp)?.write(out)?;
    }
    Ok(())
}
