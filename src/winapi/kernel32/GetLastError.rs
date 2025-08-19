use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::{TEB_BASE, TEB_LAST_ERROR_VALUE_OFFSET};

pub fn GetLastError(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD GetLastError(void) - no parameters
    // Returns the last error value from TEB
    
    // Read LastErrorValue from TEB at offset 0x68
    let error_addr = TEB_BASE + TEB_LAST_ERROR_VALUE_OFFSET;
    let mut error_bytes = [0u8; 4];
    emu.mem_read(error_addr, &mut error_bytes)?;
    let last_error = u32::from_le_bytes(error_bytes);
    
    // Return error code in RAX (EAX for 32-bit value)
    emu.reg_write(RegisterX86::RAX, last_error as u64)?;
    
    log::info!("kernel32!GetLastError() -> 0x{:x}", last_error);
    
    Ok(())
}