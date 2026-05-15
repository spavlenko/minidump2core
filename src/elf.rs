//! Minimal ELF constants and writers for emitting ELF core files.
//!
//! Only the structures md2core needs (`Ehdr`, `Phdr`, `Nhdr`) are implemented,
//! always serialized in little-endian. All Linux/Android target architectures
//! md2core supports use little-endian; the original C++ tool also relied on a
//! single endianness because it ran natively on the target host. Re-encoding
//! in little-endian here keeps the output deterministic and lets the Rust port
//! cross-emit cores for any supported architecture.

use std::io::Write;

use crate::error::Md2CoreError;

// --- ELF e_ident bytes ------------------------------------------------------
const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

/// `e_type` value for core dumps.
pub const ET_CORE: u16 = 4;
/// `p_type` value for `PT_LOAD` segments.
pub const PT_LOAD: u32 = 1;
/// `p_type` value for `PT_NOTE` segments.
pub const PT_NOTE: u32 = 4;

/// ELF note descriptor types we emit.
pub mod note_types {
    /// Process status (general-purpose registers, signal info, pids, times).
    pub const NT_PRSTATUS: u32 = 1;
    /// FPU registers.
    pub const NT_FPREGSET: u32 = 2;
    /// Process info (executable name, command line, uids).
    pub const NT_PRPSINFO: u32 = 3;
    /// Auxiliary vector.
    pub const NT_AUXV: u32 = 6;
    /// File-backed memory mappings (PIE displacement + automatic so-file detection in GDB).
    pub const NT_FILE: u32 = 0x4649_4c45;
    /// x86 extended FP registers.
    pub const NT_PRXFPREG: u32 = 0x46e6_2b7f;
}

/// Note name prefix used by GNU/Linux core notes.
pub const CORE_NAME: &[u8] = b"CORE\0";
/// Note name prefix used by `NT_PRXFPREG`.
pub const LINUX_NAME: &[u8] = b"LINUX\0";

/// Representation of an ELF executable header that can produce either an ELF32
/// or ELF64 byte image.
#[derive(Debug, Clone, Copy)]
pub struct ElfHeader {
    /// 1 for ELFCLASS32, 2 for ELFCLASS64.
    pub class: u8,
    /// `e_machine` value.
    pub machine: u16,
    /// `e_phnum` value (program header count).
    pub phnum: u16,
}

impl ElfHeader {
    /// Returns the on-disk size of the header for the configured class.
    #[must_use]
    pub const fn size(self) -> u32 {
        if self.class == 2 { 64 } else { 52 }
    }

    /// Returns the on-disk size of one program header for the configured class.
    #[must_use]
    pub const fn phdr_size(self) -> u16 {
        if self.class == 2 { 56 } else { 32 }
    }

    /// Writes the executable header into `out` in little-endian byte order.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to `out` fails.
    pub fn write<W: Write>(&self, out: &mut W) -> Result<(), Md2CoreError> {
        let mut e_ident = [0u8; 16];
        e_ident[..4].copy_from_slice(&ELFMAG);
        e_ident[4] = self.class;
        e_ident[5] = ELFDATA2LSB;
        e_ident[6] = EV_CURRENT;
        out.write_all(&e_ident)?;
        out.write_all(&ET_CORE.to_le_bytes())?;
        out.write_all(&self.machine.to_le_bytes())?;
        out.write_all(&u32::from(EV_CURRENT).to_le_bytes())?;

        let ehsize = u64::from(self.size());
        let phentsize = u64::from(self.phdr_size());
        let shentsize: u64 = if self.class == 2 { 64 } else { 40 };

        if self.class == 2 {
            // e_entry, e_phoff, e_shoff (all u64)
            out.write_all(&0u64.to_le_bytes())?;
            out.write_all(&ehsize.to_le_bytes())?;
            out.write_all(&0u64.to_le_bytes())?;
        } else {
            out.write_all(&0u32.to_le_bytes())?;
            out.write_all(&u32::try_from(ehsize).unwrap_or(0).to_le_bytes())?;
            out.write_all(&0u32.to_le_bytes())?;
        }

        out.write_all(&0u32.to_le_bytes())?; // e_flags
        out.write_all(&u16::try_from(ehsize).unwrap_or(0).to_le_bytes())?; // e_ehsize
        out.write_all(&u16::try_from(phentsize).unwrap_or(0).to_le_bytes())?;
        out.write_all(&self.phnum.to_le_bytes())?;
        out.write_all(&u16::try_from(shentsize).unwrap_or(0).to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?; // e_shnum
        out.write_all(&0u16.to_le_bytes())?; // e_shstrndx
        Ok(())
    }
}

/// One ELF program header entry. Fields use 64-bit storage; the writer rejects
/// values that cannot be represented in `ELFCLASS32`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramHeader {
    /// `p_type` (`PT_NOTE` / `PT_LOAD`).
    pub p_type: u32,
    /// `p_flags`.
    pub p_flags: u32,
    /// File offset of the segment's data.
    pub p_offset: u64,
    /// Virtual address of the segment.
    pub p_vaddr: u64,
    /// Physical address (unused, set to 0).
    pub p_paddr: u64,
    /// Size of the segment data in the file.
    pub p_filesz: u64,
    /// Size of the segment in memory.
    pub p_memsz: u64,
    /// Required alignment.
    pub p_align: u64,
}

impl ProgramHeader {
    /// Writes the header into `out` matching the chosen ELF class.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to `out` fails.
    pub fn write<W: Write>(&self, out: &mut W, class: u8) -> Result<(), Md2CoreError> {
        if class == 2 {
            out.write_all(&self.p_type.to_le_bytes())?;
            out.write_all(&self.p_flags.to_le_bytes())?;
            out.write_all(&self.p_offset.to_le_bytes())?;
            out.write_all(&self.p_vaddr.to_le_bytes())?;
            out.write_all(&self.p_paddr.to_le_bytes())?;
            out.write_all(&self.p_filesz.to_le_bytes())?;
            out.write_all(&self.p_memsz.to_le_bytes())?;
            out.write_all(&self.p_align.to_le_bytes())?;
        } else {
            out.write_all(&self.p_type.to_le_bytes())?;
            out.write_all(&elf32_word(self.p_offset, "ELF32 p_offset")?.to_le_bytes())?;
            out.write_all(&elf32_word(self.p_vaddr, "ELF32 p_vaddr")?.to_le_bytes())?;
            out.write_all(&elf32_word(self.p_paddr, "ELF32 p_paddr")?.to_le_bytes())?;
            out.write_all(&elf32_word(self.p_filesz, "ELF32 p_filesz")?.to_le_bytes())?;
            out.write_all(&elf32_word(self.p_memsz, "ELF32 p_memsz")?.to_le_bytes())?;
            out.write_all(&self.p_flags.to_le_bytes())?;
            out.write_all(&elf32_word(self.p_align, "ELF32 p_align")?.to_le_bytes())?;
        }
        Ok(())
    }
}

fn elf32_word(value: u64, field: &'static str) -> Result<u32, Md2CoreError> {
    u32::try_from(value).map_err(|_| Md2CoreError::IntegerOverflow(field))
}

/// ELF note header (`Elf32_Nhdr` / `Elf64_Nhdr` — both 12 bytes, identical).
#[derive(Debug, Clone, Copy)]
pub struct NoteHeader {
    /// Length in bytes of the note name including the trailing NUL.
    pub n_namesz: u32,
    /// Length in bytes of the note descriptor.
    pub n_descsz: u32,
    /// Note type.
    pub n_type: u32,
}

impl NoteHeader {
    /// Writes the 12-byte note header to `out`.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to `out` fails.
    pub fn write<W: Write>(&self, out: &mut W) -> Result<(), Md2CoreError> {
        out.write_all(&self.n_namesz.to_le_bytes())?;
        out.write_all(&self.n_descsz.to_le_bytes())?;
        out.write_all(&self.n_type.to_le_bytes())?;
        Ok(())
    }
}

/// Pads `bytes` upward to the next multiple of `align` with zeros.
#[must_use]
pub fn align_to(bytes: usize, align: usize) -> usize {
    let rem = bytes % align;
    if rem == 0 { 0 } else { align - rem }
}
