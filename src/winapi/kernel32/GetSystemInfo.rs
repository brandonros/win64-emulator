use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use windows_sys::Win32::System::SystemInformation::SYSTEM_INFO;
use crate::emulation::memory;

/*
GetSystemInfo function (sysinfoapi.h)
02/22/2024
Retrieves information about the current system.

To retrieve accurate information for an application running on WOW64, call the GetNativeSystemInfo function.

Syntax
C++

Copy
VOID GetSystemInfo(
  [out] LPSYSTEM_INFO lpSystemInfo
);
Parameters
[out] lpSystemInfo

A pointer to a SYSTEM_INFO structure that receives the information.

Return value
None

Requirements
*/

pub fn GetSystemInfo(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // VOID GetSystemInfo(
    //   [out] LPSYSTEM_INFO lpSystemInfo  // RCX
    // )
    
    let lp_system_info = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[GetSystemInfo] lpSystemInfo: 0x{:x}", lp_system_info);
    
    // Check for NULL pointer
    if lp_system_info == 0 {
        log::error!("[GetSystemInfo] NULL lpSystemInfo pointer");
        return Ok(()); // GetSystemInfo returns void, just return
    }
    
    // Create a SYSTEM_INFO structure with typical x64 values
    let system_info = SYSTEM_INFO {
        Anonymous: windows_sys::Win32::System::SystemInformation::SYSTEM_INFO_0 {
            dwOemId: 0, // Not used in modern Windows
        },
        dwPageSize: 0x1000, // 4096 bytes (standard page size)
        lpMinimumApplicationAddress: 0x10000 as *mut _, // Typical minimum address
        lpMaximumApplicationAddress: 0x00007FFFFFFFFFFF as *mut _, // Typical max for user-mode x64
        dwActiveProcessorMask: 0xFF, // 8 processors active (bits 0-7 set)
        dwNumberOfProcessors: 8, // 8 logical processors
        dwProcessorType: 8664, // PROCESSOR_AMD_X8664 (AMD64/Intel64)
        dwAllocationGranularity: 0x10000, // 64KB allocation granularity
        wProcessorLevel: 6, // Intel processor level
        wProcessorRevision: 0x3A09, // Example revision (varies by CPU)
    };
    
    // Write the SYSTEM_INFO structure to the provided address
    memory::write_struct(emu, lp_system_info, &system_info)?;
    
    log::info!("[GetSystemInfo] Wrote SYSTEM_INFO structure:");
    log::info!("  dwPageSize: 0x{:x}", system_info.dwPageSize);
    log::info!("  lpMinimumApplicationAddress: 0x{:x}", system_info.lpMinimumApplicationAddress as u64);
    log::info!("  lpMaximumApplicationAddress: 0x{:x}", system_info.lpMaximumApplicationAddress as u64);
    log::info!("  dwActiveProcessorMask: 0x{:x}", system_info.dwActiveProcessorMask);
    log::info!("  dwNumberOfProcessors: {}", system_info.dwNumberOfProcessors);
    log::info!("  dwProcessorType: {} (AMD64/Intel64)", system_info.dwProcessorType);
    log::info!("  dwAllocationGranularity: 0x{:x}", system_info.dwAllocationGranularity);
    log::info!("  wProcessorLevel: {}", system_info.wProcessorLevel);
    log::info!("  wProcessorRevision: 0x{:x}", system_info.wProcessorRevision);
    
    log::warn!("[GetSystemInfo] Mock implementation - returned typical x64 system values");
    
    // GetSystemInfo returns void, no need to set RAX
    
    Ok(())
}