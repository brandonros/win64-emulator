use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::{TEB_BASE, TEB_LAST_ERROR_VALUE_OFFSET};

pub fn SetLastError(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // void SetLastError(DWORD dwErrCode)
    // dwErrCode in RCX (x64 calling convention)
    
    // Get the error code from RCX
    let error_code = emu.reg_read(RegisterX86::RCX)? as u32;
    
    // Write error code to TEB
    let error_addr = TEB_BASE + TEB_LAST_ERROR_VALUE_OFFSET;
    emu.mem_write(error_addr, &error_code.to_le_bytes())?;
    
    // SetLastError returns void, no return value needed
    
    log::info!("kernel32!SetLastError(0x{:x})", error_code);
    
    Ok(())
}