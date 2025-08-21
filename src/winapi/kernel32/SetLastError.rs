use unicorn_engine::{Unicorn, RegisterX86};

use crate::winapi;

pub fn SetLastError(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // void SetLastError(DWORD dwErrCode)
    // dwErrCode in RCX (x64 calling convention)
    
    // Get the error code from RCX
    let error_code = emu.reg_read(RegisterX86::RCX)? as u32;
    
    // Write error code to TEB
    winapi::set_last_error(emu, error_code)?;

    // SetLastError returns void, no return value needed
    
    log::info!("kernel32!SetLastError(0x{:x})", error_code);
    
    Ok(())
}