use md2core::Md2CoreError;
use md2core::elf::{ElfHeader, PT_LOAD, ProgramHeader};

// --- Group 3: ElfHeader::write correctness ---

/// ELF64 header must start with the ELF magic, set class=2, data=1 (LE),
/// and use type=4 (`ET_CORE`) at bytes 16–17.
#[test]
fn elf64_header_magic_and_class() {
    let header = ElfHeader {
        class: 2,
        machine: 62,
        phnum: 0,
    };
    let mut buf = Vec::new();
    header.write(&mut buf).unwrap();

    // ELF magic: \x7fELF
    assert_eq!(&buf[0..4], b"\x7fELF", "ELF magic mismatch");
    // EI_CLASS = 2 (ELFCLASS64)
    assert_eq!(buf[4], 2, "EI_CLASS should be 2 for 64-bit");
    // EI_DATA = 1 (ELFDATA2LSB, little-endian)
    assert_eq!(buf[5], 1, "EI_DATA should be 1 (little-endian)");
    // e_type at bytes 16–17: ET_CORE = 4, little-endian
    assert_eq!(
        &buf[16..18],
        &4u16.to_le_bytes(),
        "e_type should be ET_CORE (4)"
    );
}

/// ELF64 phentsize (`e_phentsize`) must equal 56.
#[test]
fn elf64_phentsize_is_56() {
    let header = ElfHeader {
        class: 2,
        machine: 62,
        phnum: 3,
    };
    let mut buf = Vec::new();
    header.write(&mut buf).unwrap();

    // e_phentsize is at a fixed offset in the ELF64 header.
    // Layout: e_ident(16) + e_type(2) + e_machine(2) + e_version(4)
    //       + e_entry(8) + e_phoff(8) + e_shoff(8) + e_flags(4)
    //       + e_ehsize(2) + e_phentsize(2)
    // Offset = 16+2+2+4+8+8+8+4+2 = 54
    let phentsize = u16::from_le_bytes([buf[54], buf[55]]);
    assert_eq!(phentsize, 56, "ELF64 e_phentsize must be 56");
}

/// ELF32 phentsize (`e_phentsize`) must equal 32.
#[test]
fn elf32_phentsize_is_32() {
    let header = ElfHeader {
        class: 1,
        machine: 3,
        phnum: 3,
    };
    let mut buf = Vec::new();
    header.write(&mut buf).unwrap();

    // ELF32 layout: e_ident(16) + e_type(2) + e_machine(2) + e_version(4)
    //             + e_entry(4) + e_phoff(4) + e_shoff(4) + e_flags(4)
    //             + e_ehsize(2) + e_phentsize(2)
    // Offset = 16+2+2+4+4+4+4+4+2 = 42
    let phentsize = u16::from_le_bytes([buf[42], buf[43]]);
    assert_eq!(phentsize, 32, "ELF32 e_phentsize must be 32");
}

/// `e_phoff` must equal `e_ehsize`: program headers start immediately after the ELF header.
#[test]
fn elf_phoff_equals_ehsize() {
    // Test for ELF64.
    let header64 = ElfHeader {
        class: 2,
        machine: 62,
        phnum: 2,
    };
    let mut buf64 = Vec::new();
    header64.write(&mut buf64).unwrap();

    // ELF64: e_phoff at offset 32 (8-byte value), e_ehsize at offset 52 (2-byte value).
    // e_ident(16) + e_type(2) + e_machine(2) + e_version(4) + e_entry(8) + e_phoff(8) = 40
    // So e_phoff is at bytes 32..40.
    let e_phoff = u64::from_le_bytes(buf64[32..40].try_into().unwrap());
    let e_ehsize = u64::from(u16::from_le_bytes([buf64[52], buf64[53]]));
    assert_eq!(e_phoff, e_ehsize, "ELF64 e_phoff must equal e_ehsize");
    assert_eq!(e_ehsize, 64, "ELF64 e_ehsize must be 64");

    // Test for ELF32.
    let header32 = ElfHeader {
        class: 1,
        machine: 3,
        phnum: 2,
    };
    let mut buf32 = Vec::new();
    header32.write(&mut buf32).unwrap();

    // ELF32: e_phoff at offset 28 (4-byte value).
    // e_ident(16) + e_type(2) + e_machine(2) + e_version(4) + e_entry(4) + e_phoff(4)
    // e_phoff starts at byte 28.
    let e_phoff32 = u64::from(u32::from_le_bytes(buf32[28..32].try_into().unwrap()));
    let e_ehsize32 = u64::from(u16::from_le_bytes([buf32[40], buf32[41]]));
    assert_eq!(e_phoff32, e_ehsize32, "ELF32 e_phoff must equal e_ehsize");
    assert_eq!(e_ehsize32, 52, "ELF32 e_ehsize must be 52");
}

// --- Group 4: ProgramHeader::write ELF32 vs ELF64 flags offset ---

/// In ELF64, `p_flags` immediately follows `p_type` at offset 4.
#[test]
fn phdr_elf64_flags_at_offset_4() {
    let phdr = ProgramHeader {
        p_type: PT_LOAD,
        p_flags: 0x5, // PF_R | PF_X
        p_offset: 0,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: 0,
        p_memsz: 0,
        p_align: 0x1000,
    };
    let mut buf = Vec::new();
    phdr.write(&mut buf, 2).unwrap();

    assert_eq!(
        &buf[4..8],
        &0x5u32.to_le_bytes(),
        "ELF64 p_flags should be at offset 4"
    );
}

/// In ELF32, `p_flags` comes after `p_filesz` and `p_memsz`, at offset 24.
/// ELF32 Phdr layout:
///   `p_type`(4) + `p_offset`(4) + `p_vaddr`(4) + `p_paddr`(4) + `p_filesz`(4) + `p_memsz`(4) = 24
///   then `p_flags`(4) at offset 24.
#[test]
fn phdr_elf32_flags_at_offset_24() {
    let phdr = ProgramHeader {
        p_type: PT_LOAD,
        p_flags: 0x5, // PF_R | PF_X
        p_offset: 0,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: 0,
        p_memsz: 0,
        p_align: 0x1000,
    };
    let mut buf = Vec::new();
    phdr.write(&mut buf, 1).unwrap();

    assert_eq!(
        &buf[24..28],
        &0x5u32.to_le_bytes(),
        "ELF32 p_flags should be at offset 24"
    );
}

#[test]
fn phdr_elf32_rejects_unrepresentable_offsets() {
    let phdr = ProgramHeader {
        p_type: PT_LOAD,
        p_offset: u64::from(u32::MAX) + 1,
        ..Default::default()
    };
    let mut buf = Vec::new();

    let result = phdr.write(&mut buf, 1);

    assert!(
        matches!(result, Err(Md2CoreError::IntegerOverflow("ELF32 p_offset"))),
        "ELF32 p_offset overflow should be reported, got {result:?}"
    );
}
