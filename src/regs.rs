//! Per-architecture register serialization for the ELF `NT_PRSTATUS` and
//! `NT_FPREGSET` notes.
//!
//! Each `to_pr_reg` function returns the bytes that occupy the `pr_reg`
//! field of `elf_prstatus` for that architecture (the layout that GDB and
//! crash analysis tools expect). FP-register notes are produced where the
//! original C++ tool wrote them (x86, `x86_64`). For other architectures we
//! omit the FP note rather than emit something GDB would misinterpret.

use minidump::MinidumpRawContext;
use minidump::format as md;

use crate::error::Md2CoreError;
use crate::model::Architecture;

/// Bytes for the `pr_reg` field of `elf_prstatus`.
///
/// # Errors
///
/// Returns an error if `arch` does not match the type of `context`.
pub fn to_pr_reg(
    arch: Architecture,
    context: &MinidumpRawContext,
) -> Result<Vec<u8>, Md2CoreError> {
    match (arch, context) {
        (Architecture::X86, MinidumpRawContext::X86(ctx)) => Ok(x86_gpregs(ctx)),
        (Architecture::X86_64, MinidumpRawContext::Amd64(ctx)) => Ok(amd64_gpregs(ctx)),
        (Architecture::Arm, MinidumpRawContext::Arm(ctx)) => Ok(arm_gpregs(ctx)),
        (Architecture::Aarch64, MinidumpRawContext::Arm64(ctx)) => Ok(arm64_gpregs_new(ctx)),
        (Architecture::Aarch64, MinidumpRawContext::OldArm64(ctx)) => Ok(arm64_gpregs_old(ctx)),
        (Architecture::Mips, MinidumpRawContext::Mips(ctx)) => Ok(mips_gpregs(ctx, false)),
        (Architecture::Mips64, MinidumpRawContext::Mips(ctx)) => Ok(mips_gpregs(ctx, true)),
        _ => Err(Md2CoreError::ContextMismatch {
            expected: arch.as_str(),
            found: context_arch_name(context),
        }),
    }
}

/// Optional FP-register payload for the `NT_FPREGSET` note.
#[must_use]
pub fn to_fpregset(arch: Architecture, context: &MinidumpRawContext) -> Option<Vec<u8>> {
    match (arch, context) {
        (Architecture::X86, MinidumpRawContext::X86(ctx)) => Some(x86_fpregs(ctx)),
        (Architecture::X86_64, MinidumpRawContext::Amd64(ctx)) => amd64_fpregs(ctx),
        _ => None,
    }
}

/// Optional `NT_PRXFPREG` payload (x86 only).
#[must_use]
pub fn to_prxfpreg(arch: Architecture, context: &MinidumpRawContext) -> Option<Vec<u8>> {
    if let (Architecture::X86, MinidumpRawContext::X86(ctx)) = (arch, context) {
        Some(x86_fpxregs(ctx))
    } else {
        None
    }
}

fn context_arch_name(context: &MinidumpRawContext) -> &'static str {
    match context {
        MinidumpRawContext::X86(_) => "x86",
        MinidumpRawContext::Amd64(_) => "x86_64",
        MinidumpRawContext::Arm(_) => "arm",
        MinidumpRawContext::Arm64(_) | MinidumpRawContext::OldArm64(_) => "aarch64",
        MinidumpRawContext::Mips(_) => "mips",
        MinidumpRawContext::Ppc(_) => "ppc",
        MinidumpRawContext::Ppc64(_) => "ppc64",
        MinidumpRawContext::Sparc(_) => "sparc",
    }
}

// === x86 ====================================================================

/// Linux i386 `user_regs_struct`: 17 `long` (4-byte) words = 68 bytes.
fn x86_gpregs(ctx: &md::CONTEXT_X86) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    for value in [
        ctx.ebx, ctx.ecx, ctx.edx, ctx.esi, ctx.edi, ctx.ebp, ctx.eax, ctx.ds, ctx.es, ctx.fs,
        ctx.gs, ctx.eax, // orig_eax (Breakpad reuses eax)
        ctx.eip, ctx.cs, ctx.eflags, ctx.esp, ctx.ss,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// Linux i386 `user_fpregs_struct`: 7 `long` words + 20 `long` ST entries = 108 bytes.
fn x86_fpregs(ctx: &md::CONTEXT_X86) -> Vec<u8> {
    let mut out = Vec::with_capacity(108);
    let f = &ctx.float_save;
    for v in [
        f.control_word,
        f.status_word,
        f.tag_word,
        f.error_offset,
        f.error_selector,
        f.data_offset,
        f.data_selector,
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&f.register_area);
    out
}

/// Linux i386 `user_fpxregs_struct` (`NT_PRXFPREG`): 512 bytes derived from
/// `CONTEXT_X86::extended_registers`, with header fields rewritten to match
/// glibc's `user_fpxregs_struct` (4 shorts + 6 u32 + 128 + 128 + 224 padding).
fn x86_fpxregs(ctx: &md::CONTEXT_X86) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    let f = &ctx.float_save;
    let ext = &ctx.extended_registers;
    out.extend_from_slice(&u16::try_from(f.control_word).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&u16::try_from(f.status_word).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&u16::try_from(f.tag_word).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&u16_le(ext, 6).to_le_bytes()); // fop
    out.extend_from_slice(&u32::from(u16_le(ext, 8)).to_le_bytes()); // fip
    out.extend_from_slice(&u32::from(u16_le(ext, 12)).to_le_bytes()); // fcs
    out.extend_from_slice(&u32::from(u16_le(ext, 16)).to_le_bytes()); // foo
    out.extend_from_slice(&u32::from(u16_le(ext, 20)).to_le_bytes()); // fos
    out.extend_from_slice(&u32_le(ext, 24).to_le_bytes()); // mxcsr
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&ext[32..32 + 128]); // st_space
    out.extend_from_slice(&ext[160..160 + 128]); // xmm_space
    // padding[56] longs = 224 bytes
    out.resize(512, 0);
    out
}

fn u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

// === x86_64 =================================================================

/// Linux `x86_64` `user_regs_struct`: 27 u64 = 216 bytes.
fn amd64_gpregs(ctx: &md::CONTEXT_AMD64) -> Vec<u8> {
    let mut out = Vec::with_capacity(216);
    for value in [
        ctx.r15,
        ctx.r14,
        ctx.r13,
        ctx.r12,
        ctx.rbp,
        ctx.rbx,
        ctx.r11,
        ctx.r10,
        ctx.r9,
        ctx.r8,
        ctx.rax,
        ctx.rcx,
        ctx.rdx,
        ctx.rsi,
        ctx.rdi,
        ctx.rax, // orig_rax
        ctx.rip,
        u64::from(ctx.cs),
        u64::from(ctx.eflags),
        ctx.rsp,
        u64::from(ctx.ss),
        0, // fs_base (not in minidump)
        0, // gs_base
        u64::from(ctx.ds),
        u64::from(ctx.es),
        u64::from(ctx.fs),
        u64::from(ctx.gs),
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// Linux `x86_64` `user_fpregs_struct`: 512 bytes total.
/// Layout: 4 u16 + rip(u64) + rdp(u64) + mxcsr(u32) + `mxcr_mask`(u32)
///        + `st_space`[32 u32] + `xmm_space`[64 u32] + padding[24 u32].
fn amd64_fpregs(ctx: &md::CONTEXT_AMD64) -> Option<Vec<u8>> {
    use scroll::Pread;
    let xmm: md::XMM_SAVE_AREA32 = ctx.float_save.as_ref().pread_with(0, scroll::LE).ok()?;
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&xmm.control_word.to_le_bytes());
    out.extend_from_slice(&xmm.status_word.to_le_bytes());
    let ftw = u16::from(xmm.tag_word) | (u16::from(xmm.reserved1) << 8);
    out.extend_from_slice(&ftw.to_le_bytes());
    out.extend_from_slice(&xmm.error_opcode.to_le_bytes());
    // x87_ip and x87_dp are u64 reconstructions (fip/fcs and foo/fos in legacy x87).
    let x87_ip = u64::from(xmm.error_offset);
    let x87_data_ptr = u64::from(xmm.data_offset);
    out.extend_from_slice(&x87_ip.to_le_bytes());
    out.extend_from_slice(&x87_data_ptr.to_le_bytes());
    out.extend_from_slice(&xmm.mx_csr.to_le_bytes());
    out.extend_from_slice(&xmm.mx_csr_mask.to_le_bytes());
    for fr in xmm.float_registers {
        out.extend_from_slice(&fr.to_le_bytes());
    }
    for xr in xmm.xmm_registers {
        out.extend_from_slice(&xr.to_le_bytes());
    }
    out.resize(512, 0);
    Some(out)
}

// === ARM 32 =================================================================

/// Linux arm `user_regs` (also called `user_pt_regs`): 18 u32 = 72 bytes.
fn arm_gpregs(ctx: &md::CONTEXT_ARM) -> Vec<u8> {
    let mut out = Vec::with_capacity(72);
    for r in &ctx.iregs[..16] {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out.extend_from_slice(&ctx.cpsr.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ORIG_r0
    out
}

// === AArch64 ================================================================

/// Linux aarch64 `user_pt_regs`: 31 u64 (regs) + sp + pc + pstate = 272 bytes.
fn arm64_gpregs_new(ctx: &md::CONTEXT_ARM64) -> Vec<u8> {
    let mut out = Vec::with_capacity(272);
    for r in &ctx.iregs {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out.extend_from_slice(&ctx.sp.to_le_bytes());
    out.extend_from_slice(&ctx.pc.to_le_bytes());
    out.extend_from_slice(&u64::from(ctx.cpsr).to_le_bytes());
    out
}

fn arm64_gpregs_old(ctx: &md::CONTEXT_ARM64_OLD) -> Vec<u8> {
    let mut out = Vec::with_capacity(272);
    for r in &ctx.iregs {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out.extend_from_slice(&ctx.sp.to_le_bytes());
    out.extend_from_slice(&ctx.pc.to_le_bytes());
    out.extend_from_slice(&u64::from(ctx.cpsr).to_le_bytes());
    out
}

// === MIPS ===================================================================

/// Linux MIPS `elf_gregset_t`: 45 elements. Slot widths follow the ABI
/// (`u32` for o32, `u64` for n64).
///
/// Layout per `arch/mips/include/uapi/asm/reg.h`:
/// - slots [0..6) zero (reserved)
/// - slots [6..38) ← regs[0..32]
/// - slot 38 ← lo, slot 39 ← hi
/// - slot 40 ← epc, slot 41 ← badvaddr
/// - slot 42 ← status, slot 43 ← cause, slot 44 ← unused
fn mips_gpregs(ctx: &md::CONTEXT_MIPS, n64: bool) -> Vec<u8> {
    let slot = if n64 { 8 } else { 4 };
    let mut out = vec![0u8; 45 * slot];
    let mut put = |index: usize, value: u64| {
        let off = index * slot;
        if n64 {
            out[off..off + 8].copy_from_slice(&value.to_le_bytes());
        } else {
            out[off..off + 4].copy_from_slice(&value.to_le_bytes()[..4]);
        }
    };
    for (i, r) in ctx.iregs.iter().enumerate() {
        put(6 + i, *r);
    }
    put(38, ctx.mdlo);
    put(39, ctx.mdhi);
    put(40, ctx.epc);
    put(41, ctx.badvaddr);
    put(42, u64::from(ctx.status));
    put(43, u64::from(ctx.cause));
    out
}
