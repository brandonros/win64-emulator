use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use windows_sys::Win32::System::SystemInformation::{OSVERSIONINFOA, OSVERSIONINFOEXA};

use crate::emulation::memory;

pub fn GetVersionExA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to OSVERSIONINFO structure from RCX register
    let version_info_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[GetVersionExA] version_info_ptr: 0x{:x}", version_info_ptr);
    
    if version_info_ptr > 0 {
        // Read the dwOSVersionInfoSize field to determine which structure to use
        let mut size_bytes = [0u8; 4];
        emu.mem_read(version_info_ptr, &mut size_bytes)?;
        let info_size = u32::from_le_bytes(size_bytes);
        
        if info_size == std::mem::size_of::<OSVERSIONINFOEXA>() as u32 {
            // Caller expects OSVERSIONINFOEXA
            let mock_version_info_ex = OSVERSIONINFOEXA {
                dwOSVersionInfoSize: info_size,
                dwMajorVersion: 10,        // Windows 10
                dwMinorVersion: 0,         // Windows 10
                dwBuildNumber: 19045,      // Windows 10 22H2
                dwPlatformId: 2,           // VER_PLATFORM_WIN32_NT
                szCSDVersion: [0; 128],    // Empty service pack string
                wServicePackMajor: 0,
                wServicePackMinor: 0,
                wSuiteMask: 0x100,         // VER_SUITE_SINGLEUSERTS
                wProductType: 1,           // VER_NT_WORKSTATION
                wReserved: 0,
            };
            
            memory::write_struct(emu, version_info_ptr, &mock_version_info_ex)?;
        } else if info_size == std::mem::size_of::<OSVERSIONINFOA>() as u32 {
            // Caller expects OSVERSIONINFOA
            let mock_version_info = OSVERSIONINFOA {
                dwOSVersionInfoSize: info_size,
                dwMajorVersion: 10,        // Windows 10
                dwMinorVersion: 0,         // Windows 10
                dwBuildNumber: 19045,      // Windows 10 22H2
                dwPlatformId: 2,           // VER_PLATFORM_WIN32_NT
                szCSDVersion: [0; 128],    // Empty service pack string
            };
            
            memory::write_struct(emu, version_info_ptr, &mock_version_info)?;
        } else {
            log::warn!("[GetVersionExA] Invalid dwOSVersionInfoSize: {}", info_size);
            // Return FALSE on invalid size
            emu.reg_write(RegisterX86::RAX, 0)?;
            return Ok(());
        }
    }
    
    // Set return value to TRUE (1) in RAX to indicate success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}