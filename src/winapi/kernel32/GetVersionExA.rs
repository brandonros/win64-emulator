use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOA;

use crate::emulation::memory;

pub fn GetVersionExA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to OSVERSIONINFOA structure from RCX register
    let version_info_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[GetVersionExA] version_info_ptr: 0x{:x}", version_info_ptr);
    
    if version_info_ptr > 0 {
        // Mock Windows 10 version info
        let mock_version_info = OSVERSIONINFOA {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOA>() as u32,
            dwMajorVersion: 10,        // Windows 10
            dwMinorVersion: 0,         // Windows 10
            dwBuildNumber: 19045,      // Windows 10 22H2
            dwPlatformId: 2,           // VER_PLATFORM_WIN32_NT
            szCSDVersion: [0; 128],    // Empty service pack string
        };
        
        memory::write_struct(emu, version_info_ptr, &mock_version_info)?;
    }
    
    // Set return value to TRUE (1) in RAX to indicate success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}