use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn GetConsoleOutputCP(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // GetConsoleOutputCP takes no parameters and returns the console output code page
    
    // Common code pages:
    // 437 = OEM United States
    // 850 = OEM Multilingual Latin 1
    // 1252 = Windows-1252 (Latin 1)
    // 65001 = UTF-8
    let code_page: u64 = 437; // Using OEM US, typically matches GetConsoleCP
    
    log::info!("[GetConsoleOutputCP] Returning console output code page: {}", code_page);
    
    // Set the return value in RAX register
    emu.reg_write(X86Register::RAX, code_page)?;
    
    Ok(())
}