use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;

pub fn GetWindowsDirectoryW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get parameters from registers (x64 calling convention)
    let lp_buffer = emu.reg_read(X86Register::RCX)?;
    let u_size = emu.reg_read(X86Register::RDX)? as u32;
    
    log::debug!("[GetWindowsDirectoryW] buffer: 0x{:x}, size: {} wide characters", lp_buffer, u_size);
    
    // Simple mock Windows directory path
    let windows_dir = "C:\\Windows";
    let windows_dir_wide_len = windows_dir.encode_utf16().count() as u32;
    let required_size = windows_dir_wide_len + 1; // +1 for null terminator
    
    // If buffer is null, return 0 (error)
    if lp_buffer == 0 {
        log::warn!("[GetWindowsDirectoryW] NULL buffer provided");
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // If size is 0, return required size
    if u_size == 0 {
        emu.reg_write(X86Register::RAX, required_size as u64)?;
        return Ok(());
    }
    
    // If buffer too small, return required size
    if u_size < required_size {
        log::warn!("[GetWindowsDirectoryW] Buffer too small: {} < {} wide characters", u_size, required_size);
        emu.reg_write(X86Register::RAX, required_size as u64)?;
        return Ok(());
    }
    
    // Write the wide string to memory
    memory::write_wide_string_to_memory(emu, lp_buffer, windows_dir)?;
    
    // Return the length of string written (not including null terminator, in wide characters)
    emu.reg_write(X86Register::RAX, windows_dir_wide_len as u64)?;
    
    log::debug!("[GetWindowsDirectoryW] Returned path: {}", windows_dir);
    
    Ok(())
}
