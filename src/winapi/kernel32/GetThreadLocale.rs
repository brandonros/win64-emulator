use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn GetThreadLocale(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Return US English locale (0x0409)
    // Format: 0x0409 = MAKELCID(LANG_ENGLISH, SUBLANG_ENGLISH_US)
    let lcid = 0x0409u32;
    
    log::debug!("[GetThreadLocale] Returning locale: 0x{:04X} (en-US)", lcid);
    
    // Return value in EAX
    emu.reg_write(X86Register::RAX, lcid as u64)?;
    
    Ok(())
}