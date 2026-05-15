use md2core::Md2CoreError;
use md2core::model::Architecture;
use md2core::rust_minidump::architecture_from_cpu_os;
use minidump::system_info::{Cpu, Os};

#[test]
fn maps_supported_linux_cpu_to_architecture() {
    assert_eq!(
        architecture_from_cpu_os(Cpu::X86_64, Os::Linux),
        Ok(Architecture::X86_64)
    );
    assert_eq!(
        architecture_from_cpu_os(Cpu::Arm64, Os::NaCl),
        Ok(Architecture::Aarch64)
    );
}

#[test]
fn rejects_non_linux_minidumps() {
    assert_eq!(
        architecture_from_cpu_os(Cpu::X86_64, Os::Windows),
        Err(Md2CoreError::UnsupportedSystem {
            os: "windows".to_owned(),
            cpu: "amd64".to_owned(),
        })
    );
}

// --- Group 8: CPU/OS coverage ---

#[test]
fn maps_x86_cpu_to_architecture() {
    assert_eq!(
        architecture_from_cpu_os(Cpu::X86, Os::Linux),
        Ok(Architecture::X86)
    );
}

#[test]
fn maps_arm_cpu_to_architecture() {
    assert_eq!(
        architecture_from_cpu_os(Cpu::Arm, Os::Linux),
        Ok(Architecture::Arm)
    );
}

#[test]
fn maps_mips_cpu_to_architecture() {
    assert_eq!(
        architecture_from_cpu_os(Cpu::Mips, Os::Linux),
        Ok(Architecture::Mips)
    );
}

#[test]
fn maps_mips64_cpu_to_architecture() {
    assert_eq!(
        architecture_from_cpu_os(Cpu::Mips64, Os::Linux),
        Ok(Architecture::Mips64)
    );
}

#[test]
fn unsupported_cpu_returns_error() {
    let result = architecture_from_cpu_os(Cpu::Ppc, Os::Linux);
    assert!(
        matches!(result, Err(Md2CoreError::UnsupportedSystem { .. })),
        "Ppc CPU should return UnsupportedSystem, got: {result:?}"
    );
}

#[test]
fn rejects_macos_minidumps() {
    let result = architecture_from_cpu_os(Cpu::X86_64, Os::MacOs);
    assert_eq!(
        result,
        Err(Md2CoreError::UnsupportedSystem {
            os: "mac".to_owned(),
            cpu: "amd64".to_owned(),
        })
    );
}
