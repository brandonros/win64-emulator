use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;

pub fn GetWindowsDirectoryA(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get parameters from registers (x64 calling convention)
    let lp_buffer = emu.reg_read(X86Register::RCX)?;
    let u_size = emu.reg_read(X86Register::RDX)? as u32;
    
    log::debug!("[GetWindowsDirectoryA] buffer: 0x{:x}, size: {}", lp_buffer, u_size);
    
    // Simple mock Windows directory path
    let windows_dir = "C:\\Windows";
    let required_size = (windows_dir.len() + 1) as u32; // +1 for null terminator
    
    // If buffer is null, return 0 (error)
    if lp_buffer == 0 {
        log::warn!("[GetWindowsDirectoryA] NULL buffer provided");
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
        log::warn!("[GetWindowsDirectoryA] Buffer too small: {} < {}", u_size, required_size);
        emu.reg_write(X86Register::RAX, required_size as u64)?;
        return Ok(());
    }
    
    // Write the string to memory
    memory::write_string_to_memory(emu, lp_buffer, windows_dir)?;
    
    // Return the length of string written (not including null terminator)
    let chars_written = windows_dir.len() as u32;
    emu.reg_write(X86Register::RAX, chars_written as u64)?;
    
    log::debug!("[GetWindowsDirectoryA] Returned path: {}", windows_dir);
    
    Ok(())
}
