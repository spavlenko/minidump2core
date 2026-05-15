use md2core::model::{Architecture, ProcessInfo};
use md2core::notes::build_prpsinfo;

// --- Group 1: build_prpsinfo byte layout ---

/// `AArch64` uses u16 for `pr_uid` and `pr_gid` (`prpsinfo_uid_is_u32` returns false).
/// Prefix layout (`AArch64`, `long_size` = 8):
///   `pr_state`(1) + `pr_sname`(1) + `pr_zomb`(1) + `pr_nice`(1) = 4 bytes
///   pad to next 8-byte boundary → 4 pad bytes → total 8
///   `pr_flag` (8 bytes) → total 16
///   `pr_uid` (u16, 2 bytes) at offset 16
///   `pr_gid` (u16, 2 bytes) at offset 18
#[test]
fn prpsinfo_aarch64_uid_gid_are_u16() {
    let info = ProcessInfo::new();
    let bytes = build_prpsinfo(Architecture::Aarch64, &info);

    assert!(
        bytes.len() > 20,
        "descriptor too short: {} bytes",
        bytes.len()
    );
    // uid = 0, encoded as u16 (2 bytes)
    assert_eq!(
        &bytes[16..18],
        &0u16.to_le_bytes(),
        "pr_uid at offset 16 should be u16 (2 bytes)"
    );
    // gid = 0, encoded as u16 (2 bytes)
    assert_eq!(
        &bytes[18..20],
        &0u16.to_le_bytes(),
        "pr_gid at offset 18 should be u16 (2 bytes)"
    );
    // Verify total size: 8 (header+pad) + 8 (pr_flag) + 2 (uid) + 2 (gid)
    //                  + 16 (pids) + 16 (filename) + 80 (args) = 132
    assert_eq!(
        bytes.len(),
        132,
        "AArch64 prpsinfo descriptor should be 132 bytes"
    );
}

/// `X86_64` uses u32 for `pr_uid` and `pr_gid` (`prpsinfo_uid_is_u32` returns true).
/// Prefix layout (`X86_64`, `long_size` = 8):
///   `pr_state`(1) + `pr_sname`(1) + `pr_zomb`(1) + `pr_nice`(1) = 4 bytes
///   pad to next 8-byte boundary → 4 pad bytes → total 8
///   `pr_flag` (8 bytes) → total 16
///   `pr_uid` (u32, 4 bytes) at offset 16
///   `pr_gid` (u32, 4 bytes) at offset 20
#[test]
fn prpsinfo_x86_64_uid_gid_are_u32() {
    let info = ProcessInfo::new();
    let bytes = build_prpsinfo(Architecture::X86_64, &info);

    assert!(
        bytes.len() > 24,
        "descriptor too short: {} bytes",
        bytes.len()
    );
    assert_eq!(
        &bytes[16..20],
        &0u32.to_le_bytes(),
        "pr_uid at offset 16 should be u32 (4 bytes)"
    );
    assert_eq!(
        &bytes[20..24],
        &0u32.to_le_bytes(),
        "pr_gid at offset 20 should be u32 (4 bytes)"
    );
    // Verify total size: 8 + 8 + 4 + 4 + 16 + 16 + 80 = 136
    assert_eq!(
        bytes.len(),
        136,
        "X86_64 prpsinfo descriptor should be 136 bytes"
    );
}

/// `AArch64` (u16 uid/gid) and `X86_64` (u32 uid/gid) have different descriptor sizes.
/// Both share `long_size` = 8, but uid+gid size differs: 4 vs 8 bytes → total differs by 4.
#[test]
fn prpsinfo_descriptor_sizes_differ_by_arch() {
    let info = ProcessInfo::new();
    let x86_bytes = build_prpsinfo(Architecture::X86, &info);
    let x86_64_bytes = build_prpsinfo(Architecture::X86_64, &info);
    let aarch64_bytes = build_prpsinfo(Architecture::Aarch64, &info);

    // X86 uses 4-byte longs + u16 uid/gid → smaller than X86_64.
    assert_ne!(
        x86_bytes.len(),
        x86_64_bytes.len(),
        "X86 and X86_64 prpsinfo descriptors must have different sizes"
    );

    // AArch64 uses 8-byte longs but u16 uid/gid; X86_64 uses 8-byte longs + u32 uid/gid.
    assert_ne!(
        x86_64_bytes.len(),
        aarch64_bytes.len(),
        "X86_64 and AArch64 prpsinfo descriptors should have different sizes (u32 vs u16 uid/gid)"
    );

    assert_eq!(x86_64_bytes.len(), 136);
    assert_eq!(aarch64_bytes.len(), 132);
}
