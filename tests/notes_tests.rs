use md2core::model::Architecture;
use md2core::notes::{Note, build_prstatus};

// --- Group 2: Note::build alignment padding ---

/// Name length that is not a multiple of 4 triggers padding.
/// "AB\0" is 3 bytes; padded to 4 bytes (1 pad byte after name section).
/// The serialized note must have total length divisible by 4.
#[test]
fn note_name_padded_to_4_bytes() {
    // Name "AB" → stored as "AB\0" (3 bytes) → padded to 4.
    let note = Note::build(b"AB", 1, b"desc").unwrap();
    // Header=12, name_section=4 (3 bytes + 1 pad), desc_section=4 (4 bytes, already aligned)
    assert_eq!(note.bytes.len(), 12 + 4 + 4, "total size should be 20");
    assert_eq!(
        note.bytes.len() % 4,
        0,
        "total length must be 4-byte aligned"
    );

    // The name stored in the output should be "AB\0" starting at byte 12.
    assert_eq!(&note.bytes[12..15], b"AB\0");
    // Padding byte after the name.
    assert_eq!(note.bytes[15], 0, "pad byte after name should be zero");
}

/// Descriptor length not a multiple of 4 must be padded.
/// "xyz" is 3 bytes → padded section = 4 bytes (1 pad byte appended).
#[test]
fn note_desc_padded_to_4_bytes() {
    // Name "CORE\0" is 5 bytes → padded to 8.
    let note = Note::build(b"CORE", 3, b"xyz").unwrap();
    // Header=12, name_section=8 ("CORE\0" 5 bytes → pad to 8), desc_section=4 ("xyz" 3 bytes → pad to 4)
    assert_eq!(note.bytes.len(), 12 + 8 + 4, "total size should be 24");
    assert_eq!(note.bytes.len() % 4, 0);

    // Descriptor is "xyz" at byte 12+8=20.
    assert_eq!(&note.bytes[20..23], b"xyz");
    // Pad byte.
    assert_eq!(note.bytes[23], 0);
}

/// When both name and descriptor are already 4-byte aligned, no extra bytes added.
/// "CORE\0" = 5 bytes → pads to 8; descriptor "ABCD" = 4 bytes, already aligned.
#[test]
fn note_already_aligned_no_extra_padding() {
    // Name "GNU\0" = 4 bytes, already aligned.
    // Descriptor = 4 bytes, already aligned.
    let note = Note::build(b"GNU", 1, b"ABCD").unwrap();
    // Header=12, name="GNU\0"=4 bytes (already aligned, no pad), desc=4 bytes.
    assert_eq!(
        note.bytes.len(),
        12 + 4 + 4,
        "no extra padding should be added"
    );
    assert_eq!(note.bytes.len() % 4, 0);

    assert_eq!(&note.bytes[12..16], b"GNU\0");
    assert_eq!(&note.bytes[16..20], b"ABCD");
}

#[test]
fn x86_64_prstatus_is_struct_aligned() {
    let pr_reg = vec![0; 216];
    let prstatus = build_prstatus(Architecture::X86_64, 1, 11, &pr_reg, true);

    assert_eq!(prstatus.len(), 336);
}
