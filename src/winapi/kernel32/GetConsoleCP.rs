use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn GetConsoleCP(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // GetConsoleCP takes no parameters and returns the console input code page
    
    // Common code pages:
    // 437 = OEM United States
    // 850 = OEM Multilingual Latin 1
    // 1252 = Windows-1252 (Latin 1)
    // 65001 = UTF-8
    let code_page: u64 = 437; // Using OEM US as typical console code page
    
    log::info!("[GetConsoleCP] Returning console input code page: {}", code_page);
    
    // Set the return value in RAX register
    emu.reg_write(X86Register::RAX, code_page)?;
    
    Ok(())
}