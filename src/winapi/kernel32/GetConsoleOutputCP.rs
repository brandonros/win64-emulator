use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetConsoleOutputCP(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // GetConsoleOutputCP takes no parameters and returns the console output code page
    
    // Common code pages:
    // 437 = OEM United States
    // 850 = OEM Multilingual Latin 1
    // 1252 = Windows-1252 (Latin 1)
    // 65001 = UTF-8
    let code_page: u64 = 437; // Using OEM US, typically matches GetConsoleCP
    
    log::info!("[GetConsoleOutputCP] Returning console output code page: {}", code_page);
    
    // Set the return value in RAX register
    emu.reg_write(RegisterX86::RAX, code_page)?;
    
    Ok(())
}