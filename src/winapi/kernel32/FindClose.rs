use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn FindClose(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let h_find_file = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[FindClose] Closing find handle: 0x{:x}, returning 1 (success)", h_find_file);
    
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}