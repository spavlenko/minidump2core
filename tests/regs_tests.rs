use md2core::model::Architecture;
use md2core::regs::to_pr_reg;
use minidump::MinidumpRawContext;
use minidump::format as md;

// --- Group 5: x86_gpregs and amd64_gpregs register order ---

/// Linux i386 `user_regs_struct` layout emitted by `x86_gpregs`:
///   [0]  ebx   [1]  ecx   [2]  edx   [3]  esi
///   [4]  edi   [5]  ebp   [6]  eax   [7]  ds
///   [8]  es    [9]  fs    [10] gs    [11] `orig_eax` (= eax)
///   [12] eip   [13] cs    [14] eflags [15] esp
///   [16] ss
/// eip is at index 12 → byte offset 12 × 4 = 48.
#[test]
fn x86_gpregs_eip_at_expected_offset() {
    let ctx = md::CONTEXT_X86 {
        eip: 0xDEAD_BEEF,
        ..Default::default()
    };

    let bytes = to_pr_reg(Architecture::X86, &MinidumpRawContext::X86(ctx)).unwrap();
    assert_eq!(bytes.len(), 68, "x86 pr_reg must be 68 bytes");

    let eip = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
    assert_eq!(eip, 0xDEAD_BEEF, "eip should be at byte offset 48");
}

/// Linux `x86_64` `user_regs_struct` layout emitted by `amd64_gpregs`:
///   [0] r15 — first register in the Linux struct, so offset 0.
#[test]
fn amd64_gpregs_r15_at_offset_0() {
    let ctx = md::CONTEXT_AMD64 {
        r15: 1,
        ..Default::default()
    };

    let bytes = to_pr_reg(Architecture::X86_64, &MinidumpRawContext::Amd64(ctx)).unwrap();
    assert_eq!(bytes.len(), 216, "amd64 pr_reg must be 216 bytes");

    let r15 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    assert_eq!(r15, 1, "r15 should be at byte offset 0");
}

/// Breakpad reuses `eax` for `orig_eax` (slot index 11, byte offset 44).
/// Setting only eax to a non-zero value should make both the eax slot (index 6)
/// and the `orig_eax` slot (index 11) equal to that value.
#[test]
fn x86_gpregs_orig_eax_equals_eax() {
    let ctx = md::CONTEXT_X86 {
        eax: 0x1234_5678,
        ..Default::default()
    };

    let bytes = to_pr_reg(Architecture::X86, &MinidumpRawContext::X86(ctx)).unwrap();

    let eax = u32::from_le_bytes(bytes[24..28].try_into().unwrap()); // index 6
    let orig_eax = u32::from_le_bytes(bytes[44..48].try_into().unwrap()); // index 11
    assert_eq!(eax, 0x1234_5678);
    assert_eq!(orig_eax, 0x1234_5678, "orig_eax should equal eax");
}

#[test]
fn mips_o32_gpregs_preserve_low_32_bits() {
    let mut iregs = [0; 32];
    iregs[0] = 0xFFFF_FFFF_1234_5678;
    let ctx = md::CONTEXT_MIPS {
        iregs,
        ..Default::default()
    };

    let bytes = to_pr_reg(Architecture::Mips, &MinidumpRawContext::Mips(ctx)).unwrap();

    let first_register = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    assert_eq!(first_register, 0x1234_5678);
}
