use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

use crate::winapi;

pub fn SetLastError(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // void SetLastError(DWORD dwErrCode)
    // dwErrCode in RCX (x64 calling convention)
    
    // Get the error code from RCX
    let error_code = emu.reg_read(X86Register::RCX)? as u32;
    
    // Write error code to TEB
    winapi::set_last_error(emu, error_code)?;

    // SetLastError returns void, no return value needed
    
    log::info!("kernel32!SetLastError(0x{:x})", error_code);
    
    Ok(())
}