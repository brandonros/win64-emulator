use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn GetACP(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // GetACP takes no parameters and returns the code page identifier in RAX
    
    // 1252 = Windows-1252 (Latin 1) - most common Western European code page
    // You could also use:
    // - 437 (OEM United States)
    // - 65001 (UTF-8)
    let code_page: u64 = 1252;
    
    log::info!("[GetACP] Returning code page: {}", code_page);
    
    // Set the return value in RAX register
    emu.reg_write(X86Register::RAX, code_page)?;
    
    Ok(())
}
