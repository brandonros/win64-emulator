use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use windows_sys::Win32::System::Threading::STARTUPINFOA;

use crate::winapi::structures;

pub fn GetStartupInfoA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to STARTUPINFO structure from RCX register
    let startup_info_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[GetStartupInfoA] startup_info_ptr: 0x{:x}", startup_info_ptr);
    
    if startup_info_ptr > 0 {
        let mock_startup_info = STARTUPINFOA {
            cb: std::mem::size_of::<STARTUPINFOA>() as u32,  // Correct size
            lpReserved: std::ptr::null_mut(),
            lpDesktop: std::ptr::null_mut(),
            lpTitle: std::ptr::null_mut(),
            dwX: 10,
            dwY: 10,
            dwXSize: 300,
            dwYSize: 200,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: 0,  // or use specific STARTUPINFOW_FLAGS if needed
            wShowWindow: 1,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: std::ptr::null_mut(),
            hStdOutput: std::ptr::null_mut(),
            hStdError: std::ptr::null_mut(),
        };
        structures::write_struct(emu, startup_info_ptr, &mock_startup_info)?;
    }
    
    Ok(())
}