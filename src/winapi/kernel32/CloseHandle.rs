use unicorn_engine::{Unicorn, RegisterX86};

use crate::winapi;

pub fn CloseHandle(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL CloseHandle(
    //   HANDLE hObject
    // )
    
    let h_object = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[CloseHandle] hObject: 0x{:x}", h_object);

    // Check for invalid handle values
    match h_object {
        0 => {
            // NULL handle
            log::warn!("[CloseHandle] Attempting to close NULL handle");
            winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
            emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE for failure
            return Ok(());
        },
        0xFFFFFFFFFFFFFFFF => {
            // INVALID_HANDLE_VALUE (-1)
            log::warn!("[CloseHandle] Attempting to close INVALID_HANDLE_VALUE");
            winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
            emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE for failure
            return Ok(());
        },
        0x10 | 0x14 | 0x18 => {
            // Standard handles (stdin, stdout, stderr)
            // These are pseudo-handles and shouldn't actually be closed
            log::warn!("[CloseHandle] Attempting to close standard handle: 0x{:x}", h_object);
            
            // Windows allows closing standard handles but they remain valid
            // We'll simulate this by succeeding but logging a warning
            log::info!("[CloseHandle] Standard handle close simulated (handle remains valid)");
            emu.reg_write(RegisterX86::RAX, 1)?; // Return TRUE for success
            return Ok(());
        },
        _ => {
            // Other handles - check if it's a known valid handle
            // For simulation purposes, we'll accept a limited range of "valid" handles
            if h_object >= 0x100 && h_object <= 0x1000 {
                log::info!("[CloseHandle] Closing handle: 0x{:x}", h_object);
                emu.reg_write(RegisterX86::RAX, 1)?; // Return TRUE for success
            } else {
                log::warn!("[CloseHandle] Unknown/invalid handle: 0x{:x}", h_object);
                winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
                emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE for failure
            }
        }
    }
    
    Ok(())
}